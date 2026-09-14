//! The relay's actual run loop, factored out of the `dante-relay` binary so a
//! `dante serve` client can embed the exact same relay — listener, ledger
//! replica, mailbox, optional TURN, optional libp2p federation — instead of
//! requiring a second, separately-run process. See `dante-cli`'s
//! `--also-relay` for the embedding side; the standalone binary's `main.rs`
//! is now just argv parsing plus a call to [`run`].

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use dante_ledger::LedgerParams;
use dante_net::transport::serve;
use tokio::net::TcpListener;

use crate::state::{now_ms, IcePolicy, Limits, RelayHandler, RelayState};
use crate::turn_server::TurnServer;

pub const DEFAULT_LISTEN: &str = "0.0.0.0:9944";
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);
/// Cap on distinct channel gossip topics a relay subscribes to. `FetchChannel`
/// for an unknown channel drives a subscription, so without a ceiling a stream
/// of unknown ids grows gossip-mesh state without bound. Generous — a real
/// relay sequences far fewer channels than this.
#[cfg(feature = "p2p")]
const MAX_CHAN_SUBS: usize = 16_384;

/// Everything needed to run a relay node — standalone (the `dante-relay`
/// binary) or embedded (a `dante serve --also-relay` client). Mirrors the
/// binary's CLI flags one-to-one.
#[derive(Clone)]
pub struct RunConfig {
    pub listen: String,
    pub min_pow_bits: Option<u8>,
    /// Argon2 memory-cost floor (KiB) a PoW proof must meet. Defaults to the
    /// registration puzzle; `--min-pow-bits` drops it to 0 unless pinned here.
    pub min_pow_m_cost_kib: Option<u32>,
    /// Argon2 time-cost floor.
    pub min_pow_t_cost: Option<u32>,
    pub ice: IcePolicy,
    /// `host:port` to run an in-process TURN server on (UDP).
    pub turn_listen: Option<String>,
    /// Public IP the TURN server advertises as its relayed address.
    pub turn_public_ip: Option<String>,
    /// libp2p bootstrap multiaddrs handed to `p2p`-enabled clients.
    pub p2p_bootstrap: Vec<String>,
    /// If set (feature `p2p`), also accept clients over a libp2p
    /// `/dante/relay/1` stream, listening on this multiaddr
    /// (e.g. `/ip4/0.0.0.0/tcp/4020`).
    pub p2p_listen: Option<String>,
    /// Hex-encoded 32-byte ed25519 seed for the relay's libp2p identity, so its
    /// PeerId is stable across restarts. Random (ephemeral) if omitted.
    pub p2p_seed: Option<String>,
    /// Operator opt-in for the relay-side link unfurler (feature `unfurl`):
    /// the relay fetches a linked URL's metadata on a client's behalf, so
    /// the client's own IP never reaches the linked site. Off by default —
    /// see `docs/THREAT_MODEL.md` §4 for the trust-model trade-off. No
    /// effect if the crate was not built with the `unfurl` feature.
    pub allow_unfurl: bool,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN.to_string(),
            min_pow_bits: None,
            min_pow_m_cost_kib: None,
            min_pow_t_cost: None,
            ice: IcePolicy::default(),
            turn_listen: None,
            turn_public_ip: None,
            p2p_bootstrap: Vec::new(),
            p2p_listen: None,
            p2p_seed: None,
            allow_unfurl: false,
        }
    }
}

/// Run a relay node until its listener(s) fail. Does not install a Ctrl-C
/// handler — the caller (the binary's `main`, or a client embedding this)
/// decides how the process as a whole shuts down; `tokio::select!` this
/// future against whatever else needs to run alongside it.
pub async fn run(mut cfg: RunConfig) -> anyhow::Result<()> {
    // Optional in-process TURN server. Kept alive for the lifetime of `run`.
    let mut _turn = None;
    if let Some(listen) = cfg.turn_listen.clone() {
        let secret = cfg
            .ice
            .turn_secret
            .clone()
            .context("--turn-listen requires --turn-secret")?;
        let port = listen
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .context("--turn-listen must be HOST:PORT")?;
        let public_ip: std::net::IpAddr = cfg
            .turn_public_ip
            .clone()
            .or_else(|| {
                listen
                    .rsplit_once(':')
                    .map(|(h, _)| h.to_string())
                    .filter(|h| {
                        h.parse::<std::net::IpAddr>()
                            .map(|ip| !ip.is_unspecified())
                            .unwrap_or(false)
                    })
            })
            .context("give --turn-public-ip (or a concrete IP in --turn-listen)")?
            .parse()
            .context("--turn-public-ip is not an IP address")?;

        _turn = Some(TurnServer::start(&listen, public_ip, "dante", secret).await?);
        let url = format!("turn:{public_ip}:{port}");
        if !cfg.ice.turn.iter().any(|u| u == &url) {
            cfg.ice.turn.push(url.clone());
        }
        tracing::info!(%listen, %url, "in-process TURN server running");
    }

    let mut params = LedgerParams::default();
    if let Some(bits) = cfg.min_pow_bits {
        params.min_announce_pow_bits = bits;
        params.min_liveness_pow_bits = bits.saturating_sub(4).max(1);
        // `--min-pow-bits` is the "this is a dev/test network" switch. A lowered
        // bit floor is meaningless if the Argon2 cost floor still demands
        // registration-strength hashing, so drop that too unless the operator
        // pinned it explicitly.
        params.min_pow_m_cost_kib = cfg.min_pow_m_cost_kib.unwrap_or(0);
        params.min_pow_t_cost = cfg.min_pow_t_cost.unwrap_or(0);
        tracing::warn!(
            bits,
            m_cost_kib = params.min_pow_m_cost_kib,
            t_cost = params.min_pow_t_cost,
            "PoW floor lowered from the default -- for local testing only"
        );
    } else {
        if let Some(m) = cfg.min_pow_m_cost_kib {
            params.min_pow_m_cost_kib = m;
        }
        if let Some(t) = cfg.min_pow_t_cost {
            params.min_pow_t_cost = t;
        }
    }

    let mut relay_state = RelayState::new(params, Limits::default());
    if !cfg.ice.stun.is_empty() || !cfg.ice.turn.is_empty() {
        tracing::info!(
            stun = cfg.ice.stun.len(),
            turn = cfg.ice.turn.len(),
            turn_creds = cfg.ice.turn_secret.is_some(),
            "advertising ICE servers for calls"
        );
    }
    relay_state.set_ice_policy(cfg.ice);
    if cfg.allow_unfurl {
        if cfg!(feature = "unfurl") {
            tracing::info!(
                "relay-side link unfurler enabled: this relay will fetch link previews on clients' behalf"
            );
            relay_state.set_unfurl_enabled(true);
        } else {
            tracing::warn!(
                "--allow-relay-unfurl set, but this binary was not built with the `unfurl` feature — ignored"
            );
        }
    }
    #[cfg(feature = "p2p")]
    let p2p_bootstrap = cfg.p2p_bootstrap.clone();
    if !cfg.p2p_bootstrap.is_empty() {
        tracing::info!(
            count = cfg.p2p_bootstrap.len(),
            "offering libp2p bootstrap peers"
        );
        relay_state.set_p2p_bootstrap(cfg.p2p_bootstrap);
    }
    let handler = Arc::new(RelayHandler::new(relay_state));

    // Background housekeeping. Kept as a branch of the `select!` below rather
    // than a detached `tokio::spawn`: a caller that embeds `run()` (see
    // `dante serve --also-relay`) and needs to stop it again can just abort
    // the `JoinHandle` this whole function's task runs as. A detached spawn
    // would survive that abort and leak.
    let maintenance = {
        let handler = Arc::clone(&handler);
        async move {
            let mut tick = tokio::time::interval(MAINTENANCE_INTERVAL);
            loop {
                tick.tick().await;
                let now = now_ms();
                let (dropped, evaporated) = handler.state().lock().await.maintain(now);
                if dropped > 0 || evaporated > 0 {
                    tracing::info!(dropped, evaporated, "maintenance");
                }
            }
        }
    };

    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("binding {}", cfg.listen))?;
    tracing::info!(listen = %cfg.listen, "relay listening");

    #[cfg(feature = "p2p")]
    let p2p_task = {
        let handler = Arc::clone(&handler);
        let boot = p2p_bootstrap;
        async move {
            let Some(addr) = cfg.p2p_listen.clone() else {
                return std::future::pending::<anyhow::Result<()>>().await;
            };
            let seed = match &cfg.p2p_seed {
                Some(hex) => parse_seed(hex).context("--p2p-seed must be 64 hex chars")?,
                None => dante_crypto::random_array::<32>(),
            };
            serve_p2p(handler, &addr, seed, &boot).await
        }
    };
    #[cfg(not(feature = "p2p"))]
    let p2p_task = std::future::pending::<anyhow::Result<()>>();

    tokio::select! {
        r = serve(listener, handler) => { r?; }
        r = p2p_task => { r?; }
        _ = maintenance => {}
    }
    Ok(())
}

/// Serve inbound `/dante/relay/1` requests over libp2p through the same
/// [`RelayHandler`] the TCP listener uses.
#[cfg(feature = "p2p")]
async fn serve_p2p(
    handler: Arc<RelayHandler>,
    listen: &str,
    seed: [u8; 32],
    bootstrap: &[String],
) -> anyhow::Result<()> {
    use dante_net::transport::RequestHandler;
    use dante_net::wire::{Request, Response};

    let (node, mut events, mut inbound) =
        dante_p2p::Node::spawn(&seed).map_err(|e| anyhow::anyhow!("p2p node: {e}"))?;
    node.listen_str(listen)
        .await
        .map_err(|e| anyhow::anyhow!("p2p listen {listen}: {e}"))?;
    // Peer with sibling relays so the DHT (and provider records) span the whole
    // relay set, not just this node.
    for b in bootstrap {
        if let Err(e) = node.dial_str(b).await {
            tracing::warn!(addr = %b, error = %e, "p2p: sibling relay dial failed");
        }
    }
    let _ = node.bootstrap().await;
    // Announce on the DHT that we serve `/dante/relay/1` so `--relay dht`
    // clients can discover us. libp2p republishes it automatically.
    node.start_providing(dante_p2p::RELAY_CAPABILITY.to_vec())
        .await
        .ok();
    // Federation: fold every ledger record heard on the gossip topic into our
    // replica, and re-broadcast every record we accept, so sibling relays
    // converge without any direct relay-to-relay protocol.
    for t in [
        dante_p2p::LEDGER_TOPIC,
        dante_p2p::PREKEY_TOPIC,
        dante_p2p::MAILBOX_TOPIC,
        dante_p2p::KEYPKG_TOPIC,
    ] {
        node.subscribe(t).await.ok();
    }
    // Gossip has no history, so pull each sibling's ledger once on startup;
    // gossip then keeps replicas live from here.
    for b in bootstrap {
        match backfill_ledger_from(node.clone(), b, Arc::clone(&handler)).await {
            Ok(n) if n > 0 => {
                tracing::info!(sibling = %b, records = n, "relay federation: backfilled")
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(sibling = %b, error = %e, "relay federation: backfill failed"),
        }
    }

    let pid = node.peer_id();
    let mut flush = tokio::time::interval(Duration::from_secs(2));
    // Channels whose gossip topic we're subscribed to.
    let mut chan_subs: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();

    loop {
        tokio::select! {
            ev = events.recv() => match ev {
                Some(dante_p2p::Event::Listening(a)) => {
                    tracing::info!(
                        multiaddr = %format!("{a}/p2p/{pid}"),
                        "relay libp2p endpoint"
                    );
                }
                Some(dante_p2p::Event::Message { topic, data, .. })
                    if topic == dante_p2p::LEDGER_TOPIC =>
                {
                    let accepted = handler
                        .state()
                        .lock()
                        .await
                        .ingest_gossiped_record(&data, now_ms());
                    if accepted {
                        tracing::debug!("relay federation: accepted a gossiped ledger record");
                    }
                }
                Some(dante_p2p::Event::Message { topic, data, .. })
                    if topic == dante_p2p::PREKEY_TOPIC =>
                {
                    handler.state().lock().await.ingest_gossiped_prekey(data);
                }
                Some(dante_p2p::Event::Message { topic, data, .. })
                    if topic == dante_p2p::MAILBOX_TOPIC =>
                {
                    handler
                        .state()
                        .lock()
                        .await
                        .ingest_gossiped_envelope(data, now_ms());
                }
                Some(dante_p2p::Event::Message { topic, data, .. })
                    if topic == dante_p2p::KEYPKG_TOPIC =>
                {
                    handler.state().lock().await.ingest_gossiped_keypackage(&data);
                }
                Some(dante_p2p::Event::Message { topic, data, .. }) => {
                    if let Some(cid) = dante_p2p::parse_channel_topic(&topic) {
                        match ChanGossip::decode(&data) {
                            Some(ChanGossip::Frame {
                                seq,
                                identity,
                                sig,
                                blob,
                            }) => {
                                handler.state().lock().await.ingest_gossiped_channel_frame(
                                    cid,
                                    seq,
                                    blob,
                                    identity,
                                    sig,
                                    now_ms(),
                                );
                            }
                            Some(ChanGossip::Roster {
                                server_root,
                                version,
                                members,
                                sig,
                            }) => {
                                handler.state().lock().await.ingest_gossiped_channel_roster(
                                    cid,
                                    server_root,
                                    version,
                                    members,
                                    sig,
                                );
                            }
                            None => {}
                        }
                    }
                }
                Some(_) => {}
                None => return Ok(()), // node event loop stopped
            },
            _ = flush.tick() => {
                let (records, prekeys, envelopes, keypkgs, frames, rosters, backfill) = {
                    let mut st = handler.state().lock().await;
                    (
                        st.take_ledger_outbox(),
                        st.take_prekey_outbox(),
                        st.take_mbox_outbox(),
                        st.take_keypkg_outbox(),
                        st.take_channel_outbox(),
                        st.take_channel_roster_outbox(),
                        st.take_channel_backfill(),
                    )
                };
                // The items above are already gone from `RelayState` — this is
                // the only copy left. Encoding channel payloads and deciding
                // what to (re)subscribe to is synchronous, so do it inline;
                // the actual `.publish()` awaits go through a detached task
                // below so that cancelling this `select!` branch (e.g. the
                // sibling `serve(...)` branch resolving first, or an embedding
                // client's `--also-relay` toggle aborting this whole future)
                // can't drop a batch mid-flush and silently lose it — see
                // CANCELSAFETY-001.
                let mut chan_payloads: Vec<(String, Vec<u8>)> = Vec::new();
                for (cid, seq, blob, identity, sig) in frames {
                    if chan_subs.len() < MAX_CHAN_SUBS && chan_subs.insert(cid) {
                        let _ = node.subscribe(&chan_gossip_topic(&cid)).await;
                    }
                    let payload = ChanGossip::Frame {
                        seq,
                        identity,
                        sig,
                        blob,
                    }
                    .encode();
                    chan_payloads.push((chan_gossip_topic(&cid), payload));
                }
                for (cid, server_root, version, members, sig) in rosters {
                    if chan_subs.len() < MAX_CHAN_SUBS && chan_subs.insert(cid) {
                        let _ = node.subscribe(&chan_gossip_topic(&cid)).await;
                    }
                    let payload = ChanGossip::Roster {
                        server_root,
                        version,
                        members,
                        sig,
                    }
                    .encode();
                    chan_payloads.push((chan_gossip_topic(&cid), payload));
                }
                {
                    let node = node.clone();
                    tokio::spawn(async move {
                        for blob in records {
                            let _ = node.publish(dante_p2p::LEDGER_TOPIC, blob).await;
                        }
                        for blob in prekeys {
                            let _ = node.publish(dante_p2p::PREKEY_TOPIC, blob).await;
                        }
                        for blob in envelopes {
                            let _ = node.publish(dante_p2p::MAILBOX_TOPIC, blob).await;
                        }
                        for blob in keypkgs {
                            let _ = node.publish(dante_p2p::KEYPKG_TOPIC, blob).await;
                        }
                        for (topic, payload) in chan_payloads {
                            let _ = node.publish(&topic, payload).await;
                        }
                    });
                }
                // Subscribe (cheap) here, but do the sibling fetches — which dial
                // and round-trip, and stall on an unresponsive peer — off the
                // event loop, so backfill never blocks inbound requests/gossip.
                let mut to_fetch = Vec::new();
                for cid in backfill {
                    if chan_subs.len() < MAX_CHAN_SUBS && chan_subs.insert(cid) {
                        let _ = node.subscribe(&chan_gossip_topic(&cid)).await;
                    }
                    to_fetch.push(cid);
                }
                if !to_fetch.is_empty() {
                    let node = node.clone();
                    let handler = Arc::clone(&handler);
                    let siblings = bootstrap.to_vec();
                    tokio::spawn(async move {
                        for cid in to_fetch {
                            for b in &siblings {
                                match fetch_channel_from(node.clone(), b, cid).await {
                                    Ok(rows) if !rows.is_empty() => {
                                        let n = rows.len();
                                        handler
                                            .state()
                                            .lock()
                                            .await
                                            .adopt_channel_log(cid, rows, now_ms());
                                        tracing::info!(
                                            sibling = %b, frames = n,
                                            "relay federation: adopted a sibling channel log"
                                        );
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    });
                }
            }
            req = inbound.recv() => {
                let Some(req) = req else { return Ok(()); };
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    let ip = peer_pseudo_ip(&req.peer);
                    let resp = match Request::decode(&req.body) {
                        Ok(r) => handler.handle(r, ip).await,
                        Err(e) => Response::Error(format!("bad request: {e}")),
                    };
                    req.respond(resp.encode()).await;
                });
            }
        }
    }
}

/// Pull a sibling relay's whole ledger over `/dante/relay/1` and fold it into
/// our replica. Returns how many records were newly accepted.
#[cfg(feature = "p2p")]
async fn backfill_ledger_from(
    node: dante_p2p::Node,
    sibling_addr: &str,
    handler: Arc<RelayHandler>,
) -> anyhow::Result<u64> {
    use dante_net::transport::Client;
    use dante_net::wire::{Request, Response};

    let mut client = Client::connect_p2p(node, sibling_addr)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let size = match client.request(&Request::GetTreeHead).await {
        Ok(Response::TreeHead { size, .. }) => size,
        Ok(other) => anyhow::bail!("unexpected reply to GetTreeHead: {other:?}"),
        Err(e) => anyhow::bail!("{e}"),
    };
    let mut accepted = 0u64;
    let mut from = 0u64;
    while from < size {
        let to = (from + 256).min(size);
        let blobs = match client.request(&Request::GetRecords { from, to }).await {
            Ok(Response::Records(b)) => b,
            Ok(other) => anyhow::bail!("unexpected reply to GetRecords: {other:?}"),
            Err(e) => anyhow::bail!("{e}"),
        };
        if blobs.is_empty() {
            break;
        }
        let mut st = handler.state().lock().await;
        for blob in &blobs {
            if st.ingest_gossiped_record(blob, now_ms()) {
                accepted += 1;
            }
        }
        from = to;
    }
    Ok(accepted)
}

/// The channel's gossip topic (shared with clients).
#[cfg(feature = "p2p")]
fn chan_gossip_topic(channel_id: &[u8; 32]) -> String {
    dante_p2p::channel_topic(channel_id)
}

/// One message on a channel's gossip topic (`dante/chan/<hex>`, shared with
/// clients): either a content frame or a roster update. Distinguished by a
/// leading tag byte so the two payload shapes never collide — a channel's
/// content and its membership are gossiped on the same per-channel topic to
/// avoid a second global topic and the extra subscribe bookkeeping that
/// would need.
#[cfg(feature = "p2p")]
enum ChanGossip {
    /// Mirrors `Request::PostToChannel`'s fields — `identity`/`sig` ride
    /// along so a sibling can verify authorship itself (see
    /// `RelayState::ingest_gossiped_channel_frame`) instead of trusting
    /// whoever gossiped it.
    Frame {
        seq: u64,
        identity: [u8; 32],
        sig: [u8; 64],
        blob: Vec<u8>,
    },
    /// Mirrors `Request::SetChannelRoster`'s fields, so a sibling that never
    /// receives `SetChannelRoster` directly (client requests are pinned to
    /// one relay per channel) can still build its own copy and enforce
    /// membership on gossiped frames.
    Roster {
        server_root: [u8; 32],
        version: u64,
        members: Vec<[u8; 32]>,
        sig: [u8; 64],
    },
}

#[cfg(feature = "p2p")]
impl ChanGossip {
    const TAG_FRAME: u8 = 0;
    const TAG_ROSTER: u8 = 1;

    fn encode(&self) -> Vec<u8> {
        let mut w = dante_proto::enc::Writer::new();
        match self {
            ChanGossip::Frame {
                seq,
                identity,
                sig,
                blob,
            } => {
                w.u8(Self::TAG_FRAME)
                    .u64(*seq)
                    .fixed(identity)
                    .fixed(sig)
                    .bytes(blob);
            }
            ChanGossip::Roster {
                server_root,
                version,
                members,
                sig,
            } => {
                w.u8(Self::TAG_ROSTER)
                    .fixed(server_root)
                    .u64(*version)
                    .fixed(sig)
                    .u32(members.len() as u32);
                for m in members {
                    w.fixed(m);
                }
            }
        }
        w.into_vec()
    }

    fn decode(data: &[u8]) -> Option<Self> {
        let mut r = dante_proto::enc::Reader::new(data);
        let out = match r.u8().ok()? {
            Self::TAG_FRAME => ChanGossip::Frame {
                seq: r.u64().ok()?,
                identity: r.fixed::<32>().ok()?,
                sig: r.fixed::<64>().ok()?,
                blob: r.bytes().ok()?.to_vec(),
            },
            Self::TAG_ROSTER => {
                let server_root = r.fixed::<32>().ok()?;
                let version = r.u64().ok()?;
                let sig = r.fixed::<64>().ok()?;
                let n = r.u32().ok()? as usize;
                if n > r.remaining() / 32 {
                    return None;
                }
                let mut members = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    members.push(r.fixed::<32>().ok()?);
                }
                ChanGossip::Roster {
                    server_root,
                    version,
                    members,
                    sig,
                }
            }
            _ => return None,
        };
        r.finish().ok()?;
        Some(out)
    }
}

/// Pull one channel's whole log from a sibling relay over `/dante/relay/1`,
/// verbatim (seqs preserved).
#[cfg(feature = "p2p")]
async fn fetch_channel_from(
    node: dante_p2p::Node,
    sibling_addr: &str,
    channel_id: [u8; 32],
) -> anyhow::Result<Vec<(u64, Vec<u8>)>> {
    use dante_net::transport::Client;
    use dante_net::wire::{Request, Response};

    let mut client = Client::connect_p2p(node, sibling_addr)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut out = Vec::new();
    let mut since = 0u64;
    loop {
        let rows = match client
            .request(&Request::FetchChannel {
                channel_id,
                since_seq: since,
            })
            .await
        {
            Ok(Response::ChannelLog(r)) => r,
            Ok(other) => anyhow::bail!("unexpected reply to FetchChannel: {other:?}"),
            Err(e) => anyhow::bail!("{e}"),
        };
        if rows.is_empty() {
            break;
        }
        since = rows.iter().map(|(s, _)| *s).max().unwrap_or(since);
        out.extend(rows);
        if out.len() > 100_000 {
            break;
        }
    }
    Ok(out)
}

/// A stable synthetic ULA-v6 address per libp2p peer, so the relay's per-IP
/// rate limiting still buckets p2p clients by sender. Not routable — a key only.
#[cfg(feature = "p2p")]
fn peer_pseudo_ip(peer: &dante_p2p::PeerId) -> std::net::IpAddr {
    let bytes = peer.to_bytes();
    let mut ip = [0u8; 16];
    for (i, b) in bytes.iter().rev().take(15).enumerate() {
        ip[15 - i] = *b;
    }
    ip[0] = 0xfd; // fd00::/8 unique-local
    std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip))
}

/// Parse 64 hex chars into a 32-byte seed.
#[cfg(feature = "p2p")]
fn parse_seed(hex: &str) -> anyhow::Result<[u8; 32]> {
    let hex = hex.trim();
    // `hex.len()` counts bytes, not chars — a 64-*byte* string containing
    // multi-byte UTF-8 (fewer than 64 actual chars) would pass this check
    // and then panic the fixed 2-byte-wide slices below on a non-char
    // boundary. Requiring every char to be an ASCII hex digit guarantees
    // 1 byte == 1 char, so byte indexing is safe from here on.
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("expected 64 hex chars, got {}", hex.len());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

#[cfg(all(test, feature = "p2p"))]
mod tests {
    use super::{parse_seed, ChanGossip};

    /// `--p2p-seed` is operator-supplied but still untrusted-shaped input;
    /// a 64-*byte* string containing multi-byte UTF-8 used to panic the
    /// fixed 2-byte-wide hex slices instead of returning a clean error.
    #[test]
    fn parse_seed_rejects_non_ascii_without_panicking() {
        // U+4E2D ('中') is 3 bytes in UTF-8, so a leading one followed by 61
        // ASCII chars is 64 bytes total but the very first 2-byte-wide slice
        // (offset 0..2) lands mid-character.
        let s = format!("中{}", "a".repeat(61));
        assert_eq!(s.len(), 64);
        assert!(parse_seed(&s).is_err());
    }

    #[test]
    fn chan_gossip_frame_roundtrips() {
        let msg = ChanGossip::Frame {
            seq: 42,
            identity: [1u8; 32],
            sig: [2u8; 64],
            blob: vec![9, 9, 9],
        };
        match ChanGossip::decode(&msg.encode()) {
            Some(ChanGossip::Frame {
                seq,
                identity,
                sig,
                blob,
            }) => {
                assert_eq!(seq, 42);
                assert_eq!(identity, [1u8; 32]);
                assert_eq!(sig, [2u8; 64]);
                assert_eq!(blob, vec![9, 9, 9]);
            }
            _ => panic!("decode failed or wrong variant"),
        }
    }

    #[test]
    fn chan_gossip_roster_roundtrips_including_empty_members() {
        for members in [vec![[3u8; 32], [4u8; 32]], vec![]] {
            let msg = ChanGossip::Roster {
                server_root: [5u8; 32],
                version: 7,
                members: members.clone(),
                sig: [6u8; 64],
            };
            match ChanGossip::decode(&msg.encode()) {
                Some(ChanGossip::Roster {
                    server_root,
                    version,
                    members: got,
                    sig,
                }) => {
                    assert_eq!(server_root, [5u8; 32]);
                    assert_eq!(version, 7);
                    assert_eq!(got, members);
                    assert_eq!(sig, [6u8; 64]);
                }
                _ => panic!("decode failed or wrong variant"),
            }
        }
    }

    #[test]
    fn chan_gossip_rejects_garbage_and_a_bad_tag() {
        assert!(ChanGossip::decode(&[]).is_none());
        assert!(ChanGossip::decode(&[9u8; 10]).is_none()); // unknown tag
        assert!(ChanGossip::decode(&[0u8]).is_none()); // truncated Frame
    }
}
