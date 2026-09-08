//! Relay state and request handling.

use std::net::IpAddr;

use async_trait::async_trait;
use dante_ledger::{Ledger, LedgerParams, MemoryStore};
use dante_net::{
    mailbox::Mailbox,
    ratelimit::KeyedRateLimiter,
    transport::RequestHandler,
    wire::{IceCfg, Request, Response},
};
use dante_proto::{record::RecordKind, Envelope, Record};
use tokio::sync::Mutex;

/// Wall-clock Unix milliseconds.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Per-IP rate limits (token buckets: capacity, refill/sec).
pub struct Limits {
    /// `IdentityAnnounce` submissions.
    pub announce: (f64, f64),
    /// Other record submissions.
    pub record: (f64, f64),
    /// Envelope deposits.
    pub deposit: (f64, f64),
    /// Read/query endpoints (fetches, log/blob reads, tree head). These return
    /// far more than they cost to request, so they need a ceiling of their own.
    pub read: (f64, f64),
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // 10 / hour (docs/PROTOCOL.md §3), with a small burst.
            announce: (5.0, 10.0 / 3600.0),
            // 30 / minute.
            record: (30.0, 0.5),
            // 60 / minute.
            deposit: (120.0, 1.0),
            // Reads are frequent and legitimate (poll loops), so keep this
            // generous: a 240 burst, 60 / second sustained. Enough that no
            // honest client notices, low enough to cap amplification abuse.
            read: (240.0, 60.0),
        }
    }
}

/// ICE servers this relay hands out (via `Request::GetIceConfig`) so clients on
/// this network can do NAT traversal for calls. All empty by default: with no
/// STUN/TURN a call only connects between peers that can reach each other
/// directly.
#[derive(Clone, Default)]
pub struct IcePolicy {
    /// `stun:` URLs (no credentials).
    pub stun: Vec<String>,
    /// `turn:` / `turns:` URLs.
    pub turn: Vec<String>,
    /// Shared secret for minting time-limited TURN credentials. This is the
    /// standard **coturn `use-auth-secret`** scheme (`username = "{expiry}"`,
    /// `credential = base64(HMAC-SHA1(secret, username))`), so it works with a
    /// stock coturn *and* with this relay's own `--turn-listen` server. `None`
    /// → no TURN handed out.
    pub turn_secret: Option<String>,
    /// How long a minted TURN credential is valid (seconds).
    pub turn_ttl_secs: u64,
}

/// Everything a relay mutates.
pub struct RelayState {
    ledger: Ledger<MemoryStore>,
    mailbox: Mailbox,
    /// `identity_id` -> latest published, encoded `PreKeyBundle`.
    prekeys: std::collections::HashMap<[u8; 32], Vec<u8>>,
    /// `identity_id` -> queue of published MLS `KeyPackage`s (opaque). Handed
    /// out one per fetch; the last one is kept and reused as a last resort.
    key_packages: std::collections::HashMap<[u8; 32], std::collections::VecDeque<Vec<u8>>>,
    /// `SHA-256(bytes)` -> (ciphertext blob, deposited_ms). File chunks.
    blobs: std::collections::HashMap<[u8; 32], (Vec<u8>, u64)>,
    blob_bytes: usize,
    /// `channel_id` -> the channel's append-only log. Opaque E2E channel
    /// messages; the relay never reads them.
    channels: std::collections::HashMap<[u8; 32], ChannelLog>,
    /// Running total of channel-log blob bytes, bounded by [`CHANNEL_STORE_CAP`].
    channel_bytes: usize,
    /// `topic` -> ephemeral signals `(blob, deposited_ms)`. Typing indicators
    /// and the like: never persisted, swept aggressively by TTL.
    signals: std::collections::HashMap<[u8; 32], Vec<(Vec<u8>, u64)>>,
    announce_rl: KeyedRateLimiter<IpAddr>,
    record_rl: KeyedRateLimiter<IpAddr>,
    deposit_rl: KeyedRateLimiter<IpAddr>,
    read_rl: KeyedRateLimiter<IpAddr>,
    max_get_records: u64,
    ice: IcePolicy,
    /// libp2p bootstrap multiaddrs handed to clients: operator-seeded entries
    /// (no TTL) first, then self-reported by clients `(addr, last_seen_ms)`.
    p2p_seed: Vec<String>,
    p2p_reported: std::collections::VecDeque<(String, u64)>,
}

/// Cap on client-reported p2p bootstrap addresses kept.
const MAX_P2P_REPORTED: usize = 64;
/// A reported p2p address is dropped this long after it was last seen.
const P2P_REPORTED_TTL_MS: u64 = 60 * 60 * 1000;
/// Largest p2p multiaddr string accepted.
const MAX_P2P_ADDR_LEN: usize = 256;
/// Most p2p addresses returned from one `GetP2pPeers`.
const MAX_P2P_PEERS_REPLY: usize = 16;

/// Total blob-store budget (all file chunks). 128 MiB.
const BLOB_STORE_CAP: usize = 128 * 1024 * 1024;
/// A blob is dropped this long after it was stored.
const BLOB_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// Per-channel message retention (oldest dropped past this).
const MAX_CHANNEL_ENTRIES: usize = 5_000;
/// An ephemeral signal is dropped this long after it arrives.
const SIGNAL_TTL_MS: u64 = 12_000;
/// Cap on buffered signals per topic (bounds a spammer).
const MAX_SIGNALS_PER_TOPIC: usize = 64;
/// Largest accepted signal payload.
const MAX_SIGNAL_BYTES: usize = 4 * 1024;
/// Cap on stored MLS KeyPackages per identity (bounds a spammer).
const MAX_KEYPKGS_PER_IDENTITY: usize = 32;
/// Largest accepted MLS KeyPackage.
const MAX_KEYPKG_BYTES: usize = 16 * 1024;
/// Largest accepted published `PreKeyBundle`. Also bounds the allocation a
/// later `GetPrekeys` decode can be driven to (the decoder reserves per the
/// bundle's own length fields), so an oversized bundle can't be an OOM lever.
const MAX_PREKEY_BYTES: usize = 16 * 1024;
/// Cap on distinct identities holding a stored prekey bundle. The key is
/// unauthenticated (an attacker picks arbitrary ids), so bound the map.
const MAX_PREKEY_IDENTITIES: usize = 100_000;
/// Cap on distinct identities holding stored MLS KeyPackages.
const MAX_KEYPKG_IDENTITIES: usize = 100_000;
/// Cap on distinct channels the relay logs for.
const MAX_CHANNELS: usize = 100_000;
/// Largest accepted single channel-log frame.
const MAX_CHANNEL_BLOB_BYTES: usize = 1024 * 1024;
/// Global budget across all channel logs. 128 MiB.
const CHANNEL_STORE_CAP: usize = 128 * 1024 * 1024;
/// Byte budget for one `FetchChannel` reply, kept under the transport frame cap
/// so a full channel can't build an unsendable response.
const MAX_CHANNEL_FETCH_BYTES: usize = 7 * 1024 * 1024;

/// `(next_seq, entries)` where each entry is `(seq, blob, ts_ms)`.
type ChannelLog = (u64, Vec<(u64, Vec<u8>, u64)>);

impl RelayState {
    /// Fresh relay state.
    pub fn new(params: LedgerParams, limits: Limits) -> Self {
        Self {
            ledger: Ledger::new(MemoryStore::default(), params),
            mailbox: Mailbox::new(),
            prekeys: std::collections::HashMap::new(),
            key_packages: std::collections::HashMap::new(),
            blobs: std::collections::HashMap::new(),
            blob_bytes: 0,
            channels: std::collections::HashMap::new(),
            channel_bytes: 0,
            signals: std::collections::HashMap::new(),
            announce_rl: KeyedRateLimiter::new(limits.announce.0, limits.announce.1),
            record_rl: KeyedRateLimiter::new(limits.record.0, limits.record.1),
            deposit_rl: KeyedRateLimiter::new(limits.deposit.0, limits.deposit.1),
            read_rl: KeyedRateLimiter::new(limits.read.0, limits.read.1),
            max_get_records: 512,
            ice: IcePolicy::default(),
            p2p_seed: Vec::new(),
            p2p_reported: std::collections::VecDeque::new(),
        }
    }

    /// Set the ICE servers this relay advertises for calls.
    pub fn set_ice_policy(&mut self, ice: IcePolicy) {
        self.ice = ice;
    }

    /// Operator-provided libp2p bootstrap multiaddrs, always offered to clients
    /// that ask (via `Request::GetP2pPeers`).
    pub fn set_p2p_bootstrap(&mut self, addrs: Vec<String>) {
        self.p2p_seed = addrs
            .into_iter()
            .filter(|a| !a.is_empty() && a.len() <= MAX_P2P_ADDR_LEN)
            .collect();
    }

    /// Periodic housekeeping: expire mailbox entries, evaporate stale
    /// identities, shrink the rate-limit tables. Returns
    /// `(envelopes_dropped, identities_evaporated)`.
    pub fn maintain(&mut self, now: u64) -> (usize, usize) {
        let dropped = self.mailbox.gc(now);
        let evaporated = self.ledger.evaporate(now).len();
        for rl in [
            &mut self.announce_rl,
            &mut self.record_rl,
            &mut self.deposit_rl,
            &mut self.read_rl,
        ] {
            rl.sweep(now, 3_600_000);
        }
        let mut freed = 0usize;
        self.blobs.retain(|_, (bytes, at)| {
            let keep = now.saturating_sub(*at) <= BLOB_TTL_MS;
            if !keep {
                freed += bytes.len();
            }
            keep
        });
        self.blob_bytes -= freed;

        for (_, entries) in self.channels.values_mut() {
            entries.retain(|(_, _, ts)| now.saturating_sub(*ts) <= BLOB_TTL_MS);
        }
        self.channels.retain(|_, (_, entries)| !entries.is_empty());
        // Resync the byte counter from the surviving entries (authoritative, so
        // incremental drift can't accumulate).
        self.channel_bytes = self
            .channels
            .values()
            .flat_map(|(_, entries)| entries.iter())
            .map(|(_, blob, _)| blob.len())
            .sum();

        self.p2p_reported
            .retain(|(_, ts)| now.saturating_sub(*ts) <= P2P_REPORTED_TTL_MS);

        for sigs in self.signals.values_mut() {
            sigs.retain(|(_, ts)| now.saturating_sub(*ts) <= SIGNAL_TTL_MS);
        }
        self.signals.retain(|_, sigs| !sigs.is_empty());

        (dropped, evaporated)
    }

    fn handle(&mut self, req: Request, ip: IpAddr, now: u64) -> Response {
        match req {
            Request::Ping => Response::Pong,

            Request::GetTreeHead => {
                if !self.read_rl.check(&ip, now, 1.0) {
                    return Response::Error("rate limited".into());
                }
                let h = self.ledger.head();
                Response::TreeHead {
                    size: h.size,
                    root: h.root,
                }
            }

            Request::GetRecords { from, to } => {
                if !self.read_rl.check(&ip, now, 1.0) {
                    return Response::Error("rate limited".into());
                }
                let len = self.ledger.len() as u64;
                let from = from.min(len);
                let to = to.min(len).min(from + self.max_get_records);
                let mut out = Vec::new();
                for i in from..to {
                    if let Some(rec) = self.ledger.record(i as usize) {
                        out.push(rec.encode());
                    }
                }
                Response::Records(out)
            }

            Request::SubmitRecord(blob) => {
                let Ok(rec) = Record::decode(&blob) else {
                    return Response::Error("undecodable record".into());
                };
                let rl = if rec.kind == RecordKind::IdentityAnnounce {
                    &mut self.announce_rl
                } else {
                    &mut self.record_rl
                };
                if !rl.check(&ip, now, 1.0) {
                    return Response::Error("rate limited".into());
                }
                match self.ledger.append(rec, now) {
                    Ok(_) => Response::Ok,
                    Err(e) => Response::Error(format!("rejected: {e}")),
                }
            }

            Request::Deposit(blob) => {
                let Ok(env) = Envelope::decode(&blob) else {
                    return Response::Error("undecodable envelope".into());
                };
                if !self.deposit_rl.check(&ip, now, 1.0) {
                    return Response::Error("rate limited".into());
                }
                match self.mailbox.deposit(env, now) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error(format!("rejected: {e}")),
                }
            }

            Request::Fetch { hints, since_ms } => {
                if !self.read_rl.check(&ip, now, 1.0) {
                    return Response::Error("rate limited".into());
                }
                let hints: Vec<[u8; 8]> = hints.into_iter().take(32).collect();
                let envs = self
                    .mailbox
                    .fetch(&hints, since_ms, now)
                    .iter()
                    .map(Envelope::encode)
                    .collect();
                Response::Envelopes(envs)
            }

            Request::PublishPrekeys(blob) => {
                if !self.record_rl.check(&ip, now, 1.0) {
                    return Response::Error("rate limited".into());
                }
                if blob.len() > MAX_PREKEY_BYTES {
                    return Response::Error("prekey bundle too large".into());
                }
                // The bundle's `identity_id` is its first 32 bytes; the relay
                // stores the blob opaquely and the recipient re-validates.
                match blob.get(..32).and_then(|s| <[u8; 32]>::try_from(s).ok()) {
                    Some(id) => {
                        // Refuse a brand-new id once the map is full; an
                        // existing id may always refresh its own bundle.
                        if !self.prekeys.contains_key(&id)
                            && self.prekeys.len() >= MAX_PREKEY_IDENTITIES
                        {
                            return Response::Error("prekey directory full".into());
                        }
                        self.prekeys.insert(id, blob);
                        Response::Ok
                    }
                    None => Response::Error("malformed prekey bundle".into()),
                }
            }

            Request::GetPrekeys(id) => {
                if !self.read_rl.check(&ip, now, 1.0) {
                    return Response::Error("rate limited".into());
                }
                // Hand out at most one one-time prekey per fetch and shrink our
                // stored copy, so two initiators never receive the same OTP
                // (which would make the second X3DH handshake fail). When the
                // OTPs run out, callers fall back to an OTP-less X3DH.
                let Some(stored) = self.prekeys.get(&id) else {
                    return Response::Prekeys(None);
                };
                match dante_dm::PreKeyBundle::decode(stored) {
                    Ok(mut bundle) if !bundle.otps.is_empty() => {
                        let handed = bundle.otps.remove(0);
                        let remaining = bundle.encode();
                        let mut one = bundle;
                        one.otps = vec![handed];
                        let out = one.encode();
                        self.prekeys.insert(id, remaining);
                        Response::Prekeys(Some(out))
                    }
                    _ => Response::Prekeys(Some(stored.clone())),
                }
            }

            Request::PublishKeyPackages {
                identity,
                key_packages,
            } => {
                // One rate-limit charge for the whole batch.
                if !self.record_rl.check(&ip, now, 1.0) {
                    return Response::Error("rate limited".into());
                }
                if key_packages
                    .iter()
                    .any(|kp| kp.is_empty() || kp.len() > MAX_KEYPKG_BYTES)
                {
                    return Response::Error("bad key package".into());
                }
                if !self.key_packages.contains_key(&identity)
                    && self.key_packages.len() >= MAX_KEYPKG_IDENTITIES
                {
                    return Response::Error("key package directory full".into());
                }
                let q = self.key_packages.entry(identity).or_default();
                for kp in key_packages {
                    q.push_back(kp);
                }
                while q.len() > MAX_KEYPKGS_PER_IDENTITY {
                    q.pop_front();
                }
                Response::Ok
            }

            Request::GetKeyPackage(id) => {
                if !self.read_rl.check(&ip, now, 1.0) {
                    return Response::Error("rate limited".into());
                }
                let out = match self.key_packages.get_mut(&id) {
                    // More than one queued: consume the oldest.
                    Some(q) if q.len() > 1 => q.pop_front(),
                    // Exactly one: keep it as a reusable last resort.
                    Some(q) => q.front().cloned(),
                    None => None,
                };
                Response::KeyPackage(out)
            }

            Request::PutBlob(bytes) => {
                if !self.deposit_rl.check(&ip, now, 1.0) {
                    return Response::Error("rate limited".into());
                }
                let hash = dante_crypto::hash::sha256(&bytes);
                if !self.blobs.contains_key(&hash) {
                    if self.blob_bytes + bytes.len() > BLOB_STORE_CAP {
                        return Response::Error("blob store full".into());
                    }
                    self.blob_bytes += bytes.len();
                    self.blobs.insert(hash, (bytes, now));
                }
                Response::Ok
            }

            Request::GetBlob(hash) => {
                if !self.read_rl.check(&ip, now, 1.0) {
                    return Response::Error("rate limited".into());
                }
                Response::Blob(self.blobs.get(&hash).map(|(b, _)| b.clone()))
            }

            Request::PostToChannel { channel_id, blob } => {
                if !self.deposit_rl.check(&ip, now, 1.0) {
                    return Response::Error("rate limited".into());
                }
                if blob.len() > MAX_CHANNEL_BLOB_BYTES {
                    return Response::Error("channel frame too large".into());
                }
                if !self.channels.contains_key(&channel_id)
                    && self.channels.len() >= MAX_CHANNELS
                {
                    return Response::Error("channel directory full".into());
                }
                if self.channel_bytes.saturating_add(blob.len()) > CHANNEL_STORE_CAP {
                    return Response::Error("channel store full".into());
                }
                let added = blob.len();
                let (next_seq, entries) =
                    self.channels.entry(channel_id).or_insert((1, Vec::new()));
                let seq = *next_seq;
                *next_seq += 1;
                entries.push((seq, blob, now));
                let mut removed = 0usize;
                if entries.len() > MAX_CHANNEL_ENTRIES {
                    let excess = entries.len() - MAX_CHANNEL_ENTRIES;
                    for (_, b, _) in entries.drain(..excess) {
                        removed += b.len();
                    }
                }
                self.channel_bytes = self.channel_bytes.saturating_add(added) - removed;
                Response::Posted(seq)
            }

            Request::FetchChannel {
                channel_id,
                since_seq,
            } => {
                if !self.read_rl.check(&ip, now, 1.0) {
                    return Response::Error("rate limited".into());
                }
                // Cap the reply so a large log can't build an unsendable frame.
                let mut used = 0usize;
                let out = self
                    .channels
                    .get(&channel_id)
                    .map(|(_, entries)| {
                        entries
                            .iter()
                            .filter(|(seq, _, _)| *seq > since_seq)
                            .take_while(|(_, blob, _)| {
                                used += blob.len();
                                used <= MAX_CHANNEL_FETCH_BYTES
                            })
                            .map(|(seq, blob, _)| (*seq, blob.clone()))
                            .collect()
                    })
                    .unwrap_or_default();
                Response::ChannelLog(out)
            }

            Request::PostSignal { topic, blob } => {
                if !self.deposit_rl.check(&ip, now, 1.0) {
                    return Response::Error("rate limited".into());
                }
                if blob.len() > MAX_SIGNAL_BYTES {
                    return Response::Error("signal too large".into());
                }
                let sigs = self.signals.entry(topic).or_default();
                sigs.retain(|(_, ts)| now.saturating_sub(*ts) <= SIGNAL_TTL_MS);
                sigs.push((blob, now));
                if sigs.len() > MAX_SIGNALS_PER_TOPIC {
                    let excess = sigs.len() - MAX_SIGNALS_PER_TOPIC;
                    sigs.drain(..excess);
                }
                Response::Ok
            }

            Request::FetchSignals { topic } => {
                let out = self
                    .signals
                    .get(&topic)
                    .map(|sigs| {
                        sigs.iter()
                            .filter(|(_, ts)| now.saturating_sub(*ts) <= SIGNAL_TTL_MS)
                            .map(|(blob, _)| blob.clone())
                            .collect()
                    })
                    .unwrap_or_default();
                Response::Signals(out)
            }

            Request::GetIceConfig => {
                let mut out = Vec::new();
                if !self.ice.stun.is_empty() {
                    out.push(IceCfg {
                        urls: self.ice.stun.clone(),
                        ..Default::default()
                    });
                }
                if let (Some(secret), false) = (&self.ice.turn_secret, self.ice.turn.is_empty()) {
                    let ttl = std::time::Duration::from_secs(self.ice.turn_ttl_secs.max(60));
                    if let Ok((username, credential)) =
                        turn::auth::generate_long_term_credentials(secret, ttl)
                    {
                        out.push(IceCfg {
                            urls: self.ice.turn.clone(),
                            username,
                            credential,
                        });
                    }
                }
                Response::IceConfig(out)
            }

            Request::AnnounceP2p(addrs) => {
                if !self.deposit_rl.check(&ip, now, 1.0) {
                    return Response::Error("rate limited".into());
                }
                for addr in addrs {
                    if addr.is_empty() || addr.len() > MAX_P2P_ADDR_LEN || !addr.starts_with('/') {
                        continue;
                    }
                    if let Some(e) = self.p2p_reported.iter_mut().find(|(a, _)| *a == addr) {
                        e.1 = now;
                    } else {
                        self.p2p_reported.push_back((addr, now));
                        while self.p2p_reported.len() > MAX_P2P_REPORTED {
                            self.p2p_reported.pop_front();
                        }
                    }
                }
                Response::Ok
            }

            Request::GetP2pPeers => {
                let mut out = self.p2p_seed.clone();
                for (addr, ts) in self.p2p_reported.iter().rev() {
                    if out.len() >= MAX_P2P_PEERS_REPLY {
                        break;
                    }
                    if now.saturating_sub(*ts) <= P2P_REPORTED_TTL_MS && !out.contains(addr) {
                        out.push(addr.clone());
                    }
                }
                Response::P2pPeers(out)
            }
        }
    }
}

/// The `RequestHandler` the TCP server calls; wraps [`RelayState`] in a mutex.
pub struct RelayHandler {
    state: Mutex<RelayState>,
}

impl RelayHandler {
    /// Wrap `state`.
    pub fn new(state: RelayState) -> Self {
        Self {
            state: Mutex::new(state),
        }
    }

    /// Access the inner state (for the maintenance task).
    pub fn state(&self) -> &Mutex<RelayState> {
        &self.state
    }
}

#[async_trait]
impl RequestHandler for RelayHandler {
    async fn handle(&self, req: Request, peer_ip: IpAddr) -> Response {
        let now = now_ms();
        self.state.lock().await.handle(req, peer_ip, now)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use dante_crypto::pow::Difficulty;
    use dante_identity::{
        records::{IdentityAnnounce, LivenessProof},
        Identity,
    };

    use super::*;

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    const D: Difficulty = Difficulty {
        m_cost_kib: 32,
        t_cost: 1,
        bits: 8,
    };

    fn state() -> RelayState {
        RelayState::new(
            LedgerParams {
                min_announce_pow_bits: 8,
                min_liveness_pow_bits: 8,
                ..Default::default()
            },
            Limits::default(),
        )
    }

    #[test]
    fn submit_record_then_serve_it_back() {
        let mut s = state();
        let id = Identity::generate(1_000);
        let rec = IdentityAnnounce::build(&id, "", D).to_record(&id, 1_000);

        assert_eq!(
            s.handle(Request::SubmitRecord(rec.encode()), IP, 1_000),
            Response::Ok
        );
        match s.handle(Request::GetTreeHead, IP, 1_000) {
            Response::TreeHead { size, .. } => assert_eq!(size, 1),
            other => panic!("{other:?}"),
        }
        match s.handle(Request::GetRecords { from: 0, to: 1 }, IP, 1_000) {
            Response::Records(v) => assert_eq!(v, vec![rec.encode()]),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn get_ice_config_mints_coturn_style_turn_credentials() {
        let mut s = state();
        // No policy -> empty list.
        assert_eq!(
            s.handle(Request::GetIceConfig, IP, 1_000),
            Response::IceConfig(vec![])
        );

        s.set_ice_policy(IcePolicy {
            stun: vec!["stun:s.example:3478".into()],
            turn: vec!["turn:t.example:3478".into()],
            turn_secret: Some("shared-secret".into()),
            turn_ttl_secs: 600,
        });
        let Response::IceConfig(list) = s.handle(Request::GetIceConfig, IP, 1_000_000) else {
            panic!("wrong response");
        };
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].urls, vec!["stun:s.example:3478".to_string()]);
        assert!(list[0].username.is_empty());

        let turn = &list[1];
        // coturn `use-auth-secret`: username is the expiry (a Unix seconds
        // number), credential is base64(HMAC-SHA1(secret, username)).
        let expiry: u64 = turn.username.parse().expect("numeric expiry username");
        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(expiry > now_s && expiry <= now_s + 601);
        assert_eq!(turn.credential.len(), 28, "base64 of a 20-byte SHA-1 HMAC");
    }

    #[test]
    fn rejected_record_returns_error() {
        let mut s = state();
        let id = Identity::generate(0);
        // liveness before announce -> ledger rejects
        let rec = LivenessProof::build(&id, 2_000, D).to_record(&id, 2_000);
        assert!(matches!(
            s.handle(Request::SubmitRecord(rec.encode()), IP, 2_000),
            Response::Error(_)
        ));
    }

    #[test]
    fn announce_rate_limit_kicks_in() {
        let mut s = state();
        // capacity 5; the 6th distinct announce from one IP is throttled
        for i in 0..5 {
            let id = Identity::generate(i);
            let rec = IdentityAnnounce::build(&id, "", D).to_record(&id, 1_000);
            assert_eq!(
                s.handle(Request::SubmitRecord(rec.encode()), IP, 1_000),
                Response::Ok
            );
        }
        let id = Identity::generate(99);
        let rec = IdentityAnnounce::build(&id, "", D).to_record(&id, 1_000);
        assert!(matches!(
            s.handle(Request::SubmitRecord(rec.encode()), IP, 1_000),
            Response::Error(m) if m.contains("rate")
        ));
    }

    #[test]
    fn deposit_and_fetch_envelope() {
        use dante_crypto::{agree::AgreeSecret, hash::sha256, sign::SignSecret};

        let mut s = state();
        let sender = SignSecret::generate();
        let rid = sha256(b"bob");
        let rik = AgreeSecret::generate().public().to_bytes();
        let env = Envelope::seal(&rid, &rik, &sender, b"hello", 1_000, 60_000).unwrap();
        let hint = env.recipient_hint;

        assert_eq!(
            s.handle(Request::Deposit(env.encode()), IP, 1_000),
            Response::Ok
        );
        match s.handle(
            Request::Fetch {
                hints: vec![hint],
                since_ms: 0,
            },
            IP,
            1_500,
        ) {
            Response::Envelopes(v) => assert_eq!(v.len(), 1),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn get_prekeys_hands_out_one_otp_per_fetch() {
        use dante_dm::{PreKeyBundle, PreKeySecrets};
        use dante_identity::Identity;

        let mut s = state();
        let id = Identity::generate(7);
        let bundle = PreKeySecrets::generate(3).bundle(&id);
        let key = bundle.identity_id;
        assert_eq!(
            s.handle(Request::PublishPrekeys(bundle.encode()), IP, 0),
            Response::Ok
        );

        let mut seen = std::collections::HashSet::new();
        for _ in 0..3 {
            match s.handle(Request::GetPrekeys(key), IP, 0) {
                Response::Prekeys(Some(b)) => {
                    let got = PreKeyBundle::decode(&b).unwrap();
                    assert_eq!(got.otps.len(), 1, "exactly one OTP per fetch");
                    assert!(seen.insert(got.otps[0]), "OTP never repeats");
                }
                other => panic!("{other:?}"),
            }
        }
        // Exhausted: still serves the bundle, now without any OTP.
        match s.handle(Request::GetPrekeys(key), IP, 0) {
            Response::Prekeys(Some(b)) => {
                assert!(PreKeyBundle::decode(&b).unwrap().otps.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn key_packages_are_handed_out_once_then_reused_as_last_resort() {
        let mut s = state();
        let id = [42u8; 32];

        assert_eq!(
            s.handle(
                Request::PublishKeyPackages {
                    identity: id,
                    key_packages: vec![b"kp-a".to_vec(), b"kp-b".to_vec()],
                },
                IP,
                0
            ),
            Response::Ok
        );

        // First fetch consumes the oldest.
        assert_eq!(
            s.handle(Request::GetKeyPackage(id), IP, 0),
            Response::KeyPackage(Some(b"kp-a".to_vec()))
        );
        // Only one left: it is served but kept.
        for _ in 0..3 {
            assert_eq!(
                s.handle(Request::GetKeyPackage(id), IP, 0),
                Response::KeyPackage(Some(b"kp-b".to_vec()))
            );
        }
        // Unknown identity.
        assert_eq!(
            s.handle(Request::GetKeyPackage([0u8; 32]), IP, 0),
            Response::KeyPackage(None)
        );
    }

    #[test]
    fn p2p_bootstrap_addresses_are_seeded_reported_and_expire() {
        let mut s = state();
        s.set_p2p_bootstrap(vec!["/ip4/10.0.0.1/tcp/4001/p2p/seed".into()]);

        // A client reports its address.
        assert_eq!(
            s.handle(
                Request::AnnounceP2p(vec!["/ip4/1.2.3.4/tcp/4001/p2p/alice".into()]),
                IP,
                1_000,
            ),
            Response::Ok
        );
        // GetP2pPeers returns the seed first, then the reported one.
        let Response::P2pPeers(list) = s.handle(Request::GetP2pPeers, IP, 2_000) else {
            panic!("expected P2pPeers");
        };
        assert!(list.contains(&"/ip4/10.0.0.1/tcp/4001/p2p/seed".to_string()));
        assert!(list.contains(&"/ip4/1.2.3.4/tcp/4001/p2p/alice".to_string()));

        // Junk (no leading slash) is ignored.
        s.handle(
            Request::AnnounceP2p(vec!["not-a-multiaddr".into()]),
            IP,
            3_000,
        );
        let Response::P2pPeers(list) = s.handle(Request::GetP2pPeers, IP, 3_000) else {
            panic!();
        };
        assert!(!list.iter().any(|a| a == "not-a-multiaddr"));

        // The reported address ages out after an hour; the seed stays.
        s.maintain(1_000 + 60 * 60 * 1000 + 1);
        let Response::P2pPeers(list) = s.handle(Request::GetP2pPeers, IP, 999_999_999) else {
            panic!();
        };
        assert_eq!(list, vec!["/ip4/10.0.0.1/tcp/4001/p2p/seed".to_string()]);
    }

    #[test]
    fn signals_are_buffered_read_without_draining_and_expire() {
        let mut s = state();
        let topic = [7u8; 32];

        assert_eq!(
            s.handle(
                Request::PostSignal {
                    topic,
                    blob: vec![1, 2, 3],
                },
                IP,
                1_000,
            ),
            Response::Ok
        );

        // Two independent readers both see it (no drain-on-read).
        for t in [1_100u64, 1_200] {
            match s.handle(Request::FetchSignals { topic }, IP, t) {
                Response::Signals(v) => assert_eq!(v, vec![vec![1, 2, 3]]),
                other => panic!("{other:?}"),
            }
        }

        // Past the TTL it is gone.
        match s.handle(
            Request::FetchSignals { topic },
            IP,
            1_000 + SIGNAL_TTL_MS + 1,
        ) {
            Response::Signals(v) => assert!(v.is_empty()),
            other => panic!("{other:?}"),
        }
        s.maintain(1_000 + SIGNAL_TTL_MS + 1);
        assert!(s.signals.is_empty());
    }

    #[test]
    fn read_endpoints_are_rate_limited() {
        let mut s = state();
        let (cap, _) = Limits::default().read;
        // Drain the burst with cheap reads at a single instant...
        let mut ok = 0;
        for _ in 0..(cap as usize) {
            if !matches!(s.handle(Request::GetTreeHead, IP, 1_000), Response::Error(_)) {
                ok += 1;
            }
        }
        assert_eq!(ok, cap as usize);
        // ...the next same-instant read is refused.
        assert!(matches!(
            s.handle(Request::GetBlob([0u8; 32]), IP, 1_000),
            Response::Error(_)
        ));
    }

    #[test]
    fn oversized_prekey_and_channel_frames_are_rejected() {
        let mut s = state();
        // A prekey bundle above the cap is refused, so a later GetPrekeys can't
        // be driven to over-allocate on decode.
        assert!(matches!(
            s.handle(Request::PublishPrekeys(vec![0u8; MAX_PREKEY_BYTES + 1]), IP, 0),
            Response::Error(_)
        ));
        // An over-large channel frame is refused up front.
        assert!(matches!(
            s.handle(
                Request::PostToChannel {
                    channel_id: [1u8; 32],
                    blob: vec![0u8; MAX_CHANNEL_BLOB_BYTES + 1],
                },
                IP,
                0,
            ),
            Response::Error(_)
        ));
    }

    #[test]
    fn channel_bytes_accounting_stays_consistent() {
        let mut s = state();
        let ch = [9u8; 32];
        for _ in 0..3u64 {
            assert!(matches!(
                s.handle(
                    Request::PostToChannel {
                        channel_id: ch,
                        blob: vec![7u8; 1000],
                    },
                    IP,
                    1_000,
                ),
                Response::Posted(_)
            ));
        }
        assert_eq!(s.channel_bytes, 3000);
        // A FetchChannel returns the log without disturbing the counter.
        let _ = s.handle(
            Request::FetchChannel {
                channel_id: ch,
                since_seq: 0,
            },
            IP,
            2_000,
        );
        assert_eq!(s.channel_bytes, 3000);
        // After the retention window, maintain resyncs it to zero.
        s.maintain(1_000 + BLOB_TTL_MS + 1);
        assert_eq!(s.channel_bytes, 0);
    }

    #[test]
    fn oversized_signal_rejected() {
        let mut s = state();
        assert!(matches!(
            s.handle(
                Request::PostSignal {
                    topic: [1u8; 32],
                    blob: vec![0u8; MAX_SIGNAL_BYTES + 1],
                },
                IP,
                0,
            ),
            Response::Error(_)
        ));
    }

    #[test]
    fn maintain_evaporates_and_gcs() {
        let mut s = state();
        let id = Identity::generate(0);
        let rec = IdentityAnnounce::build(&id, "", D).to_record(&id, 0);
        s.handle(Request::SubmitRecord(rec.encode()), IP, 0);

        let far = dante_ledger::IDENTITY_TTL_MS + 10;
        let (_dropped, evaporated) = s.maintain(far);
        assert_eq!(evaporated, 1);
        assert!(!s.ledger.is_live(&id.sign_public().to_bytes()));
    }
}
