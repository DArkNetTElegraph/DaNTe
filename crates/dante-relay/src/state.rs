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

#[cfg(feature = "sfu")]
use crate::sfu::SfuRooms;

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
    /// Encoded ledger records accepted since the last drain, for a federated
    /// relay to re-broadcast on the gossip topic so replicas converge. Bounded;
    /// only drained by `serve_p2p`, so a relay with no `--p2p-listen` just lets
    /// the newest few sit here.
    ledger_outbox: std::collections::VecDeque<Vec<u8>>,
    /// `(channel_id, seq, blob)` for locally-posted channel frames a federated
    /// relay should re-broadcast so sibling replicas converge.
    channel_outbox: std::collections::VecDeque<([u8; 32], u64, Vec<u8>)>,
    /// Channels a client asked to `FetchChannel` that this relay has no log
    /// for — `serve_p2p` pulls them from siblings once.
    channel_backfill: std::collections::VecDeque<[u8; 32]>,
    /// Membership mirror of `channel_backfill` for O(1) dedup — the queue is
    /// scanned per `FetchChannel` for an unknown channel, which is only
    /// read-rate-limited, so a linear scan under the state mutex is a lever.
    channel_backfill_set: std::collections::HashSet<[u8; 32]>,
    /// Prekey bundles published here since the last drain, for a federated
    /// relay to share so a client on any relay can start a session with any
    /// identity. Bounded.
    prekey_outbox: std::collections::VecDeque<Vec<u8>>,
    /// Envelopes deposited here since the last drain, to replicate to siblings.
    mbox_outbox: std::collections::VecDeque<Vec<u8>>,
    /// `SHA-256` of every envelope we've deposited or replicated — so a
    /// gossiped copy (including our own echo) isn't stored twice. Bounded.
    mbox_seen: std::collections::HashSet<[u8; 32]>,
    /// `identity[32] ‖ last-resort keypackage` for identities that published
    /// KeyPackages here since the last drain, to share with siblings.
    keypkg_outbox: std::collections::VecDeque<Vec<u8>>,
}

/// Cap on the pending ledger re-broadcast queue.
const LEDGER_OUTBOX_CAP: usize = 1024;

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

/// `(next_seq, local_writer, entries)` — `entries` is `(seq, blob, ts_ms)`,
/// kept sorted by `seq`. `local_writer` is set once a client `PostToChannel`s
/// here: that makes this relay the channel's sequencer, and it then ignores
/// gossiped frames (a relay that has only ever replicated stays a follower).
type ChannelLog = (u64, bool, Vec<(u64, Vec<u8>, u64)>);
/// Cap on the pending channel re-broadcast / backfill queues.
const CHANNEL_FED_QUEUE_CAP: usize = 4096;

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
            ledger_outbox: std::collections::VecDeque::new(),
            channel_outbox: std::collections::VecDeque::new(),
            channel_backfill: std::collections::VecDeque::new(),
            channel_backfill_set: std::collections::HashSet::new(),
            prekey_outbox: std::collections::VecDeque::new(),
            mbox_outbox: std::collections::VecDeque::new(),
            mbox_seen: std::collections::HashSet::new(),
            keypkg_outbox: std::collections::VecDeque::new(),
        }
    }

    /// Fold a ledger record heard from a peer relay over gossip into this
    /// replica. No rate limiting (it is relay-to-relay); the ledger's own
    /// acceptance rules dedup and reject. Returns whether it was newly
    /// accepted (and therefore queued for onward re-broadcast).
    pub fn ingest_gossiped_record(&mut self, blob: &[u8], now: u64) -> bool {
        let Ok(rec) = Record::decode(blob) else {
            return false;
        };
        if self.ledger.append(rec, now).is_ok() {
            self.queue_rebroadcast(blob.to_vec());
            true
        } else {
            false
        }
    }

    fn queue_rebroadcast(&mut self, blob: Vec<u8>) {
        self.ledger_outbox.push_back(blob);
        while self.ledger_outbox.len() > LEDGER_OUTBOX_CAP {
            self.ledger_outbox.pop_front();
        }
    }

    /// Take the records accepted since the last call, for `serve_p2p` to
    /// publish on the ledger gossip topic.
    pub fn take_ledger_outbox(&mut self) -> Vec<Vec<u8>> {
        self.ledger_outbox.drain(..).collect()
    }

    /// Locally-posted channel frames to re-broadcast on `dante/chan/<id>`.
    pub fn take_channel_outbox(&mut self) -> Vec<([u8; 32], u64, Vec<u8>)> {
        self.channel_outbox.drain(..).collect()
    }

    /// Channels a client asked for that this relay lacks — pull them from
    /// siblings.
    pub fn take_channel_backfill(&mut self) -> Vec<[u8; 32]> {
        self.channel_backfill_set.clear();
        self.channel_backfill.drain(..).collect()
    }

    /// Prekey bundles published here since the last call, to gossip to siblings.
    pub fn take_prekey_outbox(&mut self) -> Vec<Vec<u8>> {
        self.prekey_outbox.drain(..).collect()
    }

    /// Envelopes deposited here since the last call, to replicate to siblings.
    pub fn take_mbox_outbox(&mut self) -> Vec<Vec<u8>> {
        self.mbox_outbox.drain(..).collect()
    }

    /// KeyPackage-share messages (`identity ‖ kp`) since the last call.
    pub fn take_keypkg_outbox(&mut self) -> Vec<Vec<u8>> {
        self.keypkg_outbox.drain(..).collect()
    }

    /// Adopt a sibling's last-resort KeyPackage for `identity` — but only if we
    /// hold none of our own (our locally-published single-use KeyPackages
    /// always take priority; this is purely the cross-relay fallback).
    pub fn ingest_gossiped_keypackage(&mut self, msg: &[u8]) -> bool {
        if msg.len() < 33 || msg.len() > 32 + MAX_KEYPKG_BYTES {
            return false;
        }
        let id: [u8; 32] = msg[..32].try_into().unwrap();
        let kp = msg[32..].to_vec();
        if !self.key_packages.contains_key(&id) && self.key_packages.len() >= MAX_KEYPKG_IDENTITIES
        {
            return false;
        }
        let q = self.key_packages.entry(id).or_default();
        if q.is_empty() {
            q.push_back(kp);
            true
        } else {
            false
        }
    }

    fn note_envelope(&mut self, blob: &[u8]) {
        if self.mbox_seen.len() > 16_384 {
            self.mbox_seen.clear();
        }
        self.mbox_seen.insert(dante_crypto::hash::sha256(blob));
    }

    /// Store a sealed-sender envelope replicated from a sibling relay. Skips a
    /// copy we already hold (dedup by SHA-256). Not rate limited (relay-to-
    /// relay); the mailbox's own caps still apply. Returns whether it was
    /// stored.
    pub fn ingest_gossiped_envelope(&mut self, blob: Vec<u8>, now: u64) -> bool {
        let h = dante_crypto::hash::sha256(&blob);
        if self.mbox_seen.contains(&h) {
            return false;
        }
        let Ok(env) = Envelope::decode(&blob) else {
            return false;
        };
        match self.mailbox.deposit(env, now) {
            Ok(()) => {
                self.note_envelope(&blob);
                true
            }
            Err(_) => false,
        }
    }

    /// Fold a prekey bundle heard from a sibling relay. Latest-wins, keyed by
    /// the bundle's leading 32-byte identity id. Returns whether it was stored.
    ///
    /// One-time prekeys are **stripped** before storing: OTP consumption
    /// (`GetPrekeys` popping one) happens on the origin relay only and is not
    /// federated, so if siblings also served OTPs two initiators could receive
    /// the same one, breaking X3DH's one-time-use invariant. A sibling therefore
    /// serves the OTP-less bundle (the signed-prekey fallback X3DH already
    /// defines); a client that needs an OTP reaches the origin relay.
    pub fn ingest_gossiped_prekey(&mut self, blob: Vec<u8>) -> bool {
        if blob.len() > MAX_PREKEY_BYTES {
            return false;
        }
        let Some(id) = blob.get(..32).and_then(|s| <[u8; 32]>::try_from(s).ok()) else {
            return false;
        };
        if !self.prekeys.contains_key(&id) && self.prekeys.len() >= MAX_PREKEY_IDENTITIES {
            return false;
        }
        // Strip the OTPs so this sibling never double-spends one.
        let stored = match dante_dm::PreKeyBundle::decode(&blob) {
            Ok(mut bundle) if !bundle.otps.is_empty() => {
                bundle.otps.clear();
                bundle.encode()
            }
            Ok(_) => blob,          // already OTP-less
            Err(_) => return false, // undecodable — don't store a bad bundle
        };
        self.prekeys.insert(id, stored);
        true
    }

    /// Fold a channel-log frame heard on `dante/chan/<id>` into our replica.
    /// Ignored if we sequence this channel ourselves (`local_writer`), if the
    /// seq is already present, or if the frame is oversized. Returns whether it
    /// was stored (so `serve_p2p` can subscribe / re-broadcast).
    pub fn ingest_gossiped_channel_frame(
        &mut self,
        channel_id: [u8; 32],
        seq: u64,
        blob: Vec<u8>,
        now: u64,
    ) -> bool {
        if blob.len() > MAX_CHANNEL_BLOB_BYTES {
            return false;
        }
        if !self.channels.contains_key(&channel_id) && self.channels.len() >= MAX_CHANNELS {
            return false;
        }
        if self.channel_bytes.saturating_add(blob.len()) > CHANNEL_STORE_CAP {
            return false;
        }
        let entry = self
            .channels
            .entry(channel_id)
            .or_insert((1, false, Vec::new()));
        if entry.1 {
            // We think we sequence this channel. If a sibling has produced a
            // frame at or past our next slot, the client set has rendezvous-
            // hashed the channel onto it (e.g. we flapped and a follower was
            // promoted) — step down and fold, rather than fork the log.
            if seq < entry.0 {
                return false; // still ours, and this is old news
            }
            entry.1 = false;
        }
        if entry.2.iter().any(|(s, _, _)| *s == seq) {
            return false; // already have it
        }
        let added = blob.len();
        let pos = entry.2.partition_point(|(s, _, _)| *s < seq);
        entry.2.insert(pos, (seq, blob, now));
        entry.0 = entry.0.max(seq + 1);
        let mut removed = 0usize;
        if entry.2.len() > MAX_CHANNEL_ENTRIES {
            let excess = entry.2.len() - MAX_CHANNEL_ENTRIES;
            for (_, b, _) in entry.2.drain(..excess) {
                removed += b.len();
            }
        }
        self.channel_bytes = self.channel_bytes.saturating_add(added) - removed;
        true
    }

    /// Install a sibling's channel log verbatim (seqs preserved) for a channel
    /// we don't yet have. No-op if we already sequence or hold it.
    pub fn adopt_channel_log(
        &mut self,
        channel_id: [u8; 32],
        entries: Vec<(u64, Vec<u8>)>,
        now: u64,
    ) {
        if self.channels.contains_key(&channel_id) {
            return;
        }
        if self.channels.len() >= MAX_CHANNELS {
            return;
        }
        let mut rows: Vec<(u64, Vec<u8>, u64)> = entries
            .into_iter()
            .filter(|(_, b)| b.len() <= MAX_CHANNEL_BLOB_BYTES)
            .map(|(s, b)| (s, b, now))
            .collect();
        rows.sort_by_key(|(s, _, _)| *s);
        rows.dedup_by_key(|(s, _, _)| *s);
        let bytes: usize = rows.iter().map(|(_, b, _)| b.len()).sum();
        if self.channel_bytes.saturating_add(bytes) > CHANNEL_STORE_CAP {
            return;
        }
        let next = rows.last().map_or(1, |(s, _, _)| s + 1);
        self.channel_bytes += bytes;
        self.channels.insert(channel_id, (next, false, rows));
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

        for (_, _, entries) in self.channels.values_mut() {
            entries.retain(|(_, _, ts)| now.saturating_sub(*ts) <= BLOB_TTL_MS);
        }
        self.channels
            .retain(|_, (_, _, entries)| !entries.is_empty());
        // Resync the byte counter from the surviving entries (authoritative, so
        // incremental drift can't accumulate).
        self.channel_bytes = self
            .channels
            .values()
            .flat_map(|(_, _, entries)| entries.iter())
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
                    Ok(_) => {
                        self.queue_rebroadcast(blob);
                        Response::Ok
                    }
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
                    Ok(()) => {
                        self.note_envelope(&blob);
                        self.mbox_outbox.push_back(blob);
                        while self.mbox_outbox.len() > LEDGER_OUTBOX_CAP {
                            self.mbox_outbox.pop_front();
                        }
                        Response::Ok
                    }
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
                        self.prekeys.insert(id, blob.clone());
                        self.prekey_outbox.push_back(blob);
                        while self.prekey_outbox.len() > LEDGER_OUTBOX_CAP {
                            self.prekey_outbox.pop_front();
                        }
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
                // Share only the reusable last-resort KeyPackage with siblings.
                if let Some(last) = q.back().cloned() {
                    let mut msg = identity.to_vec();
                    msg.extend_from_slice(&last);
                    self.keypkg_outbox.push_back(msg);
                    while self.keypkg_outbox.len() > LEDGER_OUTBOX_CAP {
                        self.keypkg_outbox.pop_front();
                    }
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
                if !self.channels.contains_key(&channel_id) && self.channels.len() >= MAX_CHANNELS {
                    return Response::Error("channel directory full".into());
                }
                if self.channel_bytes.saturating_add(blob.len()) > CHANNEL_STORE_CAP {
                    return Response::Error("channel store full".into());
                }
                let added = blob.len();
                let (next_seq, local, entries) =
                    self.channels
                        .entry(channel_id)
                        .or_insert((1, false, Vec::new()));
                *local = true; // a client posted here → we sequence this channel
                let seq = *next_seq;
                *next_seq += 1;
                entries.push((seq, blob.clone(), now));
                let mut removed = 0usize;
                if entries.len() > MAX_CHANNEL_ENTRIES {
                    let excess = entries.len() - MAX_CHANNEL_ENTRIES;
                    for (_, b, _) in entries.drain(..excess) {
                        removed += b.len();
                    }
                }
                self.channel_bytes = self.channel_bytes.saturating_add(added) - removed;
                self.channel_outbox.push_back((channel_id, seq, blob));
                while self.channel_outbox.len() > CHANNEL_FED_QUEUE_CAP {
                    self.channel_outbox.pop_front();
                }
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
                let out = match self.channels.get(&channel_id) {
                    Some((_, _, entries)) => entries
                        .iter()
                        .filter(|(seq, _, _)| *seq > since_seq)
                        .take_while(|(_, blob, _)| {
                            used += blob.len();
                            used <= MAX_CHANNEL_FETCH_BYTES
                        })
                        .map(|(seq, blob, _)| (*seq, blob.clone()))
                        .collect(),
                    None => {
                        // Federation: a channel we've never seen — ask siblings
                        // for it so the next poll can serve it.
                        if self.channel_backfill.len() < CHANNEL_FED_QUEUE_CAP
                            && self.channel_backfill_set.insert(channel_id)
                        {
                            self.channel_backfill.push_back(channel_id);
                        }
                        Vec::new()
                    }
                };
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

            // SFU signalling is intercepted by `RelayHandler` before the state
            // sees it. Reaching here means this relay was built without the
            // `sfu` feature.
            Request::SfuJoin { .. }
            | Request::SfuIce { .. }
            | Request::SfuPull { .. }
            | Request::SfuLeave { .. } => Response::Error("sfu not supported".into()),
        }
    }
}

/// The `RequestHandler` the TCP server calls; wraps [`RelayState`] in a mutex.
pub struct RelayHandler {
    state: Mutex<RelayState>,
    #[cfg(feature = "sfu")]
    sfu: SfuRooms,
}

impl RelayHandler {
    /// Wrap `state`.
    pub fn new(state: RelayState) -> Self {
        Self {
            state: Mutex::new(state),
            #[cfg(feature = "sfu")]
            sfu: SfuRooms::new(),
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
        // SFU joins await WebRTC negotiation, so they are served here rather
        // than under the relay-state lock.
        #[cfg(feature = "sfu")]
        if let Some(response) = self.sfu.handle(&req, peer_ip, now).await {
            return response;
        }
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
                min_pow_m_cost_kib: 0,
                min_pow_t_cost: 0,
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
    fn federation_folds_a_gossiped_record_and_queues_it_once() {
        let id = Identity::generate(1_000);
        let rec = IdentityAnnounce::build(&id, "", D).to_record(&id, 1_000);
        let blob = rec.encode();

        // A record the operator submitted is queued for re-broadcast.
        let mut a = state();
        assert_eq!(
            a.handle(Request::SubmitRecord(blob.clone()), IP, 1_000),
            Response::Ok
        );
        assert_eq!(a.take_ledger_outbox(), vec![blob.clone()]);
        assert!(a.take_ledger_outbox().is_empty(), "drained");

        // A sibling relay hears it over gossip: folded in, queued for onward
        // relay, and a second copy is a no-op (ledger rejects the dup).
        let mut b = state();
        assert!(b.ingest_gossiped_record(&blob, 1_000));
        assert_eq!(b.take_ledger_outbox(), vec![blob.clone()]);
        assert!(
            !b.ingest_gossiped_record(&blob, 1_000),
            "dup not re-accepted"
        );
        assert!(b.take_ledger_outbox().is_empty());
        match b.handle(Request::GetTreeHead, IP, 1_000) {
            Response::TreeHead { size, .. } => assert_eq!(size, 1),
            other => panic!("{other:?}"),
        }
        // Garbage is ignored.
        assert!(!b.ingest_gossiped_record(b"not a record", 1_000));
    }

    #[test]
    fn channel_federation_replicates_and_a_writer_steps_down_when_overtaken() {
        let cid = [7u8; 32];

        // Relay A: a client posts here, so A sequences the channel and queues
        // the frame for re-broadcast.
        let mut a = state();
        assert_eq!(
            a.handle(
                Request::PostToChannel {
                    channel_id: cid,
                    blob: b"frame-1".to_vec(),
                },
                IP,
                1_000
            ),
            Response::Posted(1)
        );
        assert_eq!(a.take_channel_outbox(), vec![(cid, 1, b"frame-1".to_vec())]);
        // A is the writer: a stale gossiped frame (seq below our next slot) is
        // ignored and A keeps sequencing.
        assert!(!a.ingest_gossiped_channel_frame(cid, 1, b"dup".to_vec(), 1_000));
        assert_eq!(
            a.handle(
                Request::PostToChannel {
                    channel_id: cid,
                    blob: b"frame-2".to_vec(),
                },
                IP,
                1_000
            ),
            Response::Posted(2)
        );
        let _ = a.take_channel_outbox();
        // But a sibling frame at/past our next slot means the client set has
        // re-homed the channel: A steps down, folds it, and stops sequencing.
        assert!(a.ingest_gossiped_channel_frame(cid, 3, b"sibling-3".to_vec(), 1_000));
        assert_eq!(
            a.handle(
                Request::FetchChannel {
                    channel_id: cid,
                    since_seq: 2,
                },
                IP,
                1_000,
            ),
            Response::ChannelLog(vec![(3, b"sibling-3".to_vec())])
        );

        // Relay B: pure follower. It folds the gossiped frame in at the same
        // seq, so a client polling B sees A's ordering verbatim.
        let mut b = state();
        assert!(b.ingest_gossiped_channel_frame(cid, 1, b"frame-1".to_vec(), 1_000));
        assert!(
            !b.ingest_gossiped_channel_frame(cid, 1, b"other".to_vec(), 1_000),
            "seq already present"
        );
        assert!(b.ingest_gossiped_channel_frame(cid, 3, b"frame-3".to_vec(), 1_000));
        match b.handle(
            Request::FetchChannel {
                channel_id: cid,
                since_seq: 0,
            },
            IP,
            1_000,
        ) {
            Response::ChannelLog(rows) => {
                assert_eq!(
                    rows,
                    vec![(1, b"frame-1".to_vec()), (3, b"frame-3".to_vec())]
                );
            }
            other => panic!("{other:?}"),
        }

        // A `FetchChannel` for an unknown channel queues a backfill request.
        let mut c = state();
        let _ = c.handle(
            Request::FetchChannel {
                channel_id: [9u8; 32],
                since_seq: 0,
            },
            IP,
            1_000,
        );
        assert_eq!(c.take_channel_backfill(), vec![[9u8; 32]]);
        c.adopt_channel_log(
            [9u8; 32],
            vec![(5, b"x".to_vec()), (6, b"y".to_vec())],
            1_000,
        );
        match c.handle(
            Request::FetchChannel {
                channel_id: [9u8; 32],
                since_seq: 4,
            },
            IP,
            1_000,
        ) {
            Response::ChannelLog(rows) => {
                assert_eq!(rows, vec![(5, b"x".to_vec()), (6, b"y".to_vec())])
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn repeated_fetch_of_an_unknown_channel_queues_one_backfill() {
        let mut c = state();
        for t in 0..5u64 {
            let _ = c.handle(
                Request::FetchChannel {
                    channel_id: [4u8; 32],
                    since_seq: 0,
                },
                IP,
                1_000 + t,
            );
        }
        // Deduped, not one entry per request.
        assert_eq!(c.take_channel_backfill(), vec![[4u8; 32]]);
    }

    #[test]
    fn a_gossiped_prekey_is_stored_without_its_otps() {
        use dante_dm::x3dh::PreKeySecrets;
        use dante_dm::PreKeyBundle;
        let mut s = state();
        let id = Identity::generate(0);
        let bundle = PreKeySecrets::generate(3).bundle(&id);
        assert_eq!(bundle.otps.len(), 3);
        assert!(s.ingest_gossiped_prekey(bundle.encode()));
        // A client fetching from this sibling gets an OTP-less bundle, so the
        // sibling can never hand out an OTP the origin already spent.
        match s.handle(Request::GetPrekeys(*id.id().as_bytes()), IP, 0) {
            Response::Prekeys(Some(out)) => {
                assert!(PreKeyBundle::decode(&out).unwrap().otps.is_empty());
            }
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
            if !matches!(
                s.handle(Request::GetTreeHead, IP, 1_000),
                Response::Error(_)
            ) {
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
            s.handle(
                Request::PublishPrekeys(vec![0u8; MAX_PREKEY_BYTES + 1]),
                IP,
                0
            ),
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
