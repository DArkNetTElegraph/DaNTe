//! `dante-relay` — a community-run DaNTe relay node.
//!
//! Holds a ledger replica and a sealed-sender mailbox, and speaks the
//! `dante-net` request/response protocol over framed TCP. A relay sees only
//! ciphertext, recipient hints, sizes, and timing (see
//! `docs/THREAT_MODEL.md` adversary A3).
//!
//! Usage: `dante-relay [--listen ADDR] [--min-pow-bits N]`.

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use dante_ledger::LedgerParams;
use dante_net::transport::serve;
use dante_relay::state::{now_ms, IcePolicy, Limits, RelayHandler, RelayState};
use dante_relay::turn_server::TurnServer;
use tokio::net::TcpListener;

const DEFAULT_LISTEN: &str = "0.0.0.0:9944";
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);

struct Args {
    listen: String,
    min_pow_bits: Option<u8>,
    /// Argon2 memory-cost floor (KiB) a PoW proof must meet. Defaults to the
    /// registration puzzle; `--min-pow-bits` drops it to 0 unless pinned here.
    min_pow_m_cost_kib: Option<u32>,
    /// Argon2 time-cost floor.
    min_pow_t_cost: Option<u32>,
    ice: IcePolicy,
    /// `host:port` to run an in-process TURN server on (UDP).
    turn_listen: Option<String>,
    /// Public IP the TURN server advertises as its relayed address.
    turn_public_ip: Option<String>,
    /// libp2p bootstrap multiaddrs handed to `p2p`-enabled clients.
    p2p_bootstrap: Vec<String>,
    /// If set (feature `p2p`), also accept clients over a libp2p
    /// `/dante/relay/1` stream, listening on this multiaddr
    /// (e.g. `/ip4/0.0.0.0/tcp/4020`).
    #[cfg_attr(not(feature = "p2p"), allow(dead_code))]
    p2p_listen: Option<String>,
    /// Hex-encoded 32-byte ed25519 seed for the relay's libp2p identity, so its
    /// PeerId is stable across restarts. Random (ephemeral) if omitted.
    #[cfg_attr(not(feature = "p2p"), allow(dead_code))]
    p2p_seed: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dante_relay=info,dante_net=info".into()),
        )
        .init();

    let mut args = parse_args();

    // Optional in-process TURN server. Kept alive for the process lifetime.
    let mut _turn = None;
    if let Some(listen) = args.turn_listen.clone() {
        let secret = args
            .ice
            .turn_secret
            .clone()
            .context("--turn-listen requires --turn-secret")?;
        let port = listen
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .context("--turn-listen must be HOST:PORT")?;
        let public_ip: std::net::IpAddr = args
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
        if !args.ice.turn.iter().any(|u| u == &url) {
            args.ice.turn.push(url.clone());
        }
        tracing::info!(%listen, %url, "in-process TURN server running");
    }

    let mut params = LedgerParams::default();
    if let Some(bits) = args.min_pow_bits {
        params.min_announce_pow_bits = bits;
        params.min_liveness_pow_bits = bits.saturating_sub(4).max(1);
        // `--min-pow-bits` is the "this is a dev/test network" switch. A lowered
        // bit floor is meaningless if the Argon2 cost floor still demands
        // registration-strength hashing, so drop that too unless the operator
        // pinned it explicitly.
        params.min_pow_m_cost_kib = args.min_pow_m_cost_kib.unwrap_or(0);
        params.min_pow_t_cost = args.min_pow_t_cost.unwrap_or(0);
        tracing::warn!(
            bits,
            m_cost_kib = params.min_pow_m_cost_kib,
            t_cost = params.min_pow_t_cost,
            "PoW floor lowered from the default -- for local testing only"
        );
    } else {
        if let Some(m) = args.min_pow_m_cost_kib {
            params.min_pow_m_cost_kib = m;
        }
        if let Some(t) = args.min_pow_t_cost {
            params.min_pow_t_cost = t;
        }
    }

    let mut relay_state = RelayState::new(params, Limits::default());
    if !args.ice.stun.is_empty() || !args.ice.turn.is_empty() {
        tracing::info!(
            stun = args.ice.stun.len(),
            turn = args.ice.turn.len(),
            turn_creds = args.ice.turn_secret.is_some(),
            "advertising ICE servers for calls"
        );
    }
    relay_state.set_ice_policy(args.ice);
    #[cfg(feature = "p2p")]
    let p2p_bootstrap = args.p2p_bootstrap.clone();
    if !args.p2p_bootstrap.is_empty() {
        tracing::info!(
            count = args.p2p_bootstrap.len(),
            "offering libp2p bootstrap peers"
        );
        relay_state.set_p2p_bootstrap(args.p2p_bootstrap);
    }
    let handler = Arc::new(RelayHandler::new(relay_state));

    // Background housekeeping.
    {
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(MAINTENANCE_INTERVAL);
            loop {
                tick.tick().await;
                let now = now_ms();
                let (dropped, evaporated) = handler.state().lock().await.maintain(now);
                if dropped > 0 || evaporated > 0 {
                    tracing::info!(dropped, evaporated, "maintenance");
                }
            }
        });
    }

    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("binding {}", args.listen))?;
    tracing::info!(listen = %args.listen, "dante-relay listening");

    #[cfg(feature = "p2p")]
    let p2p_task = {
        let handler = Arc::clone(&handler);
        let boot = p2p_bootstrap;
        async move {
            let Some(addr) = args.p2p_listen.clone() else {
                return std::future::pending::<anyhow::Result<()>>().await;
            };
            let seed = match &args.p2p_seed {
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
        _ = tokio::signal::ctrl_c() => { tracing::info!("shutting down"); }
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
                        "dante-relay libp2p endpoint"
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
                    if let Some((cid, seq, blob)) = parse_chan_gossip(&topic, &data) {
                        handler
                            .state()
                            .lock()
                            .await
                            .ingest_gossiped_channel_frame(cid, seq, blob, now_ms());
                    }
                }
                Some(_) => {}
                None => return Ok(()), // node event loop stopped
            },
            _ = flush.tick() => {
                let (records, prekeys, envelopes, keypkgs, frames, backfill) = {
                    let mut st = handler.state().lock().await;
                    (
                        st.take_ledger_outbox(),
                        st.take_prekey_outbox(),
                        st.take_mbox_outbox(),
                        st.take_keypkg_outbox(),
                        st.take_channel_outbox(),
                        st.take_channel_backfill(),
                    )
                };
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
                for (cid, seq, blob) in frames {
                    if chan_subs.insert(cid) {
                        let _ = node.subscribe(&chan_gossip_topic(&cid)).await;
                    }
                    let mut payload = seq.to_le_bytes().to_vec();
                    payload.extend_from_slice(&blob);
                    let _ = node.publish(&chan_gossip_topic(&cid), payload).await;
                }
                for cid in backfill {
                    if chan_subs.insert(cid) {
                        let _ = node.subscribe(&chan_gossip_topic(&cid)).await;
                    }
                    for b in bootstrap {
                        match fetch_channel_from(node.clone(), b, cid).await {
                            Ok(rows) if !rows.is_empty() => {
                                let n = rows.len();
                                handler.state().lock().await.adopt_channel_log(cid, rows, now_ms());
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

/// Parse a `dante/chan/<hex>` gossip message into `(channel_id, seq, frame)`.
#[cfg(feature = "p2p")]
fn parse_chan_gossip(topic: &str, data: &[u8]) -> Option<([u8; 32], u64, Vec<u8>)> {
    let cid = dante_p2p::parse_channel_topic(topic)?;
    if data.len() < 8 {
        return None;
    }
    let seq = u64::from_le_bytes(data[..8].try_into().ok()?);
    Some((cid, seq, data[8..].to_vec()))
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
    if hex.len() != 64 {
        anyhow::bail!("expected 64 hex chars, got {}", hex.len());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

fn parse_args() -> Args {
    let mut listen = DEFAULT_LISTEN.to_string();
    let mut min_pow_bits = None;
    let mut min_pow_m_cost_kib = None;
    let mut min_pow_t_cost = None;
    let mut ice = IcePolicy {
        turn_ttl_secs: 3600,
        ..Default::default()
    };
    let mut turn_listen = None;
    let mut turn_public_ip = None;
    let mut p2p_bootstrap = Vec::new();
    let mut p2p_listen = None;
    let mut p2p_seed = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--listen" | "-l" => {
                if let Some(v) = it.next() {
                    listen = v;
                }
            }
            "--min-pow-bits" => {
                min_pow_bits = it.next().and_then(|v| v.parse().ok());
            }
            "--min-pow-m-cost-kib" => {
                min_pow_m_cost_kib = it.next().and_then(|v| v.parse().ok());
            }
            "--min-pow-t-cost" => {
                min_pow_t_cost = it.next().and_then(|v| v.parse().ok());
            }
            "--stun" => {
                if let Some(v) = it.next() {
                    ice.stun.push(v);
                }
            }
            "--turn" => {
                if let Some(v) = it.next() {
                    ice.turn.push(v);
                }
            }
            "--turn-secret" => {
                // Prefer DANTE_TURN_SECRET: an argv secret is visible in
                // `ps`/`/proc/<pid>/cmdline` and shell history to any local user.
                ice.turn_secret = it.next().filter(|s| !s.is_empty());
                eprintln!(
                    "warning: --turn-secret is visible in the process list; \
                     prefer the DANTE_TURN_SECRET environment variable"
                );
            }
            "--turn-ttl" => {
                if let Some(n) = it.next().and_then(|v| v.parse().ok()) {
                    ice.turn_ttl_secs = n;
                }
            }
            "--turn-listen" => {
                turn_listen = it.next();
            }
            "--turn-public-ip" => {
                turn_public_ip = it.next();
            }
            "--p2p-bootstrap" => {
                if let Some(v) = it.next() {
                    p2p_bootstrap.extend(
                        v.split(',')
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned),
                    );
                }
            }
            "--p2p-listen" => {
                p2p_listen = it.next();
            }
            "--p2p-seed" => {
                p2p_seed = it.next();
            }
            "--help" | "-h" => {
                eprintln!(
                    "usage: dante-relay [--listen ADDR] [--min-pow-bits N]\n  \
                     [--min-pow-m-cost-kib N] [--min-pow-t-cost N]  (Argon2 cost floor)\n  \
                     [--stun URL ...] [--turn URL ...] [--turn-secret STR] [--turn-ttl SECS]\n  \
                     [--turn-listen HOST:PORT] [--turn-public-ip IP]  (run an in-process TURN server)\n  \
                     [--p2p-bootstrap MULTIADDR,...]  (libp2p bootstrap peers offered to p2p clients)\n  \
                     [--p2p-listen MULTIADDR] [--p2p-seed HEX32]  (serve clients over libp2p; feature p2p)\n  \
                     the TURN secret is read from DANTE_TURN_SECRET (preferred) or --turn-secret\n  \
                     defaults: --listen {DEFAULT_LISTEN}, PoW floor from LedgerParams::default()"
                );
                std::process::exit(0);
            }
            _ => {}
        }
    }
    // The TURN secret is best supplied out-of-band via the environment so it
    // never lands in argv; a `--turn-secret` on the command line still wins if
    // both are set (the operator asked for it explicitly).
    if ice.turn_secret.is_none() {
        ice.turn_secret = std::env::var("DANTE_TURN_SECRET")
            .ok()
            .filter(|s| !s.is_empty());
    }
    // Sibling relays may also be supplied out of band so a distro / systemd
    // unit doesn't need to bake them into the command line.
    if let Ok(env) = std::env::var("DANTE_BOOTSTRAP") {
        for a in env
            .split([',', ' ', '\t', '\n'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if !p2p_bootstrap.iter().any(|x| x == a) {
                p2p_bootstrap.push(a.to_string());
            }
        }
    }
    Args {
        listen,
        min_pow_bits,
        min_pow_m_cost_kib,
        min_pow_t_cost,
        ice,
        turn_listen,
        turn_public_ip,
        p2p_bootstrap,
        p2p_listen,
        p2p_seed,
    }
}
