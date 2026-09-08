//! Store-and-forward mailbox for sealed-sender [`Envelope`]s, keyed by
//! `recipient_hint`.
//!
//! A relay holds one of these. It sees only hints, sizes, and timing — never
//! sender or recipient identities.

use std::collections::HashMap;

use dante_proto::Envelope;

use crate::error::NetError;

/// Hard cap on an envelope's TTL, regardless of what the depositor asked for.
pub const MAX_TTL_MS: u32 = 14 * 24 * 60 * 60 * 1000; // 14 days

/// How far ahead of the relay's clock a `deposited_ms` may sit. `is_expired`
/// computes `now - deposited_ms`, so a future timestamp (e.g. `u64::MAX`) would
/// saturate to 0 and keep the envelope from ever expiring or being GC'd. Reject
/// anything beyond a generous skew.
pub const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000; // 5 minutes

/// Largest stored envelope. `Envelope::decode` does not check the payload
/// against [`dante_proto::envelope::SIZE_BUCKETS`], so without this a depositor
/// could store an arbitrarily large (up to the 8 MiB frame) payload. A real
/// payload is the biggest bucket (1 MiB) plus sealing overhead (ephemeral key,
/// length prefix, AEAD tag); 256 bytes of slack covers it.
pub const MAX_ENVELOPE_BYTES: usize = 1_048_576 + 256;

/// Global cap on total bytes held across all hints.
pub const MAX_MAILBOX_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Cap on pending envelopes under any single recipient hint, so one victim's
/// (publicly computable) hint cannot be flooded without bound.
pub const MAX_HINT_DEPTH: usize = 512;

/// Byte budget for one [`Mailbox::fetch`] response, kept safely under the
/// transport frame cap so a full mailbox can never build an unsendable reply
/// that drops the connection and starves the recipient.
pub const MAX_FETCH_BYTES: usize = 7 * 1024 * 1024;
const _: () = assert!(MAX_FETCH_BYTES < crate::transport::MAX_FRAME as usize);

/// Approximate stored size of an envelope: the payload dominates; the rest is a
/// small fixed header (hint, size class, timestamps, framing).
fn env_size(e: &Envelope) -> usize {
    e.payload.len() + 28
}

/// A hint-keyed collection of pending envelopes.
#[derive(Default)]
pub struct Mailbox {
    by_hint: HashMap<[u8; 8], Vec<Envelope>>,
    count: usize,
    bytes: usize,
}

impl Mailbox {
    /// An empty mailbox.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total pending envelopes.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the mailbox is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Accept an envelope for later delivery. Rejects one that is already
    /// expired, timestamped in the future, over-TTL, over-size, or that would
    /// overflow a per-hint or global capacity limit.
    pub fn deposit(&mut self, env: Envelope, now_ms: u64) -> Result<(), NetError> {
        if env.ttl_ms > MAX_TTL_MS {
            return Err(NetError::RejectedEnvelope("ttl exceeds the relay maximum"));
        }
        if env.deposited_ms > now_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
            return Err(NetError::RejectedEnvelope("deposited_ms is in the future"));
        }
        if env.is_expired(now_ms) {
            return Err(NetError::RejectedEnvelope("already expired"));
        }
        let size = env_size(&env);
        if size > MAX_ENVELOPE_BYTES {
            return Err(NetError::RejectedEnvelope(
                "envelope exceeds the size limit",
            ));
        }
        if self.bytes.saturating_add(size) > MAX_MAILBOX_BYTES {
            return Err(NetError::RejectedEnvelope("mailbox is full"));
        }
        let slot = self.by_hint.entry(env.recipient_hint).or_default();
        if slot.len() >= MAX_HINT_DEPTH {
            return Err(NetError::RejectedEnvelope("recipient mailbox is full"));
        }
        slot.push(env);
        self.count += 1;
        self.bytes += size;
        Ok(())
    }

    /// Non-expired envelopes for any of `hints` deposited at or after
    /// `since_ms`, oldest first. Does not remove them (delivery is idempotent;
    /// GC or an explicit ack clears them).
    /// Stops once [`MAX_FETCH_BYTES`] would be exceeded so the encoded response
    /// always fits a transport frame; the client advances `since_ms` and picks
    /// up the rest on its next call (delivery is idempotent).
    pub fn fetch(&self, hints: &[[u8; 8]], since_ms: u64, now_ms: u64) -> Vec<Envelope> {
        let mut out = Vec::new();
        let mut used = 0usize;
        'hints: for hint in hints {
            if let Some(list) = self.by_hint.get(hint) {
                for env in list {
                    if env.deposited_ms >= since_ms && !env.is_expired(now_ms) {
                        used += env_size(env);
                        if used > MAX_FETCH_BYTES {
                            break 'hints;
                        }
                        out.push(env.clone());
                    }
                }
            }
        }
        out.sort_by_key(|e| e.deposited_ms);
        out
    }

    /// Drop expired envelopes. Returns how many were removed.
    pub fn gc(&mut self, now_ms: u64) -> usize {
        let mut removed = 0;
        let mut freed = 0usize;
        self.by_hint.retain(|_, list| {
            list.retain(|e| {
                let keep = !e.is_expired(now_ms);
                if !keep {
                    removed += 1;
                    freed += env_size(e);
                }
                keep
            });
            !list.is_empty()
        });
        self.count -= removed;
        self.bytes = self.bytes.saturating_sub(freed);
        removed
    }
}

#[cfg(test)]
mod tests {
    use dante_crypto::{agree::AgreeSecret, hash::sha256, sign::SignSecret};
    use dante_proto::envelope::recipient_hint;

    use super::*;

    fn env_for(
        id: &[u8; 32],
        ik_pub: &[u8; 32],
        sender: &SignSecret,
        at: u64,
        ttl: u32,
    ) -> Envelope {
        Envelope::seal(id, ik_pub, sender, b"m", at, ttl).unwrap()
    }

    #[test]
    fn deposit_fetch_by_hint() {
        let mut mb = Mailbox::new();
        let sender = SignSecret::generate();
        let rid = sha256(b"recipient");
        let rik = AgreeSecret::generate();
        let e = env_for(&rid, &rik.public().to_bytes(), &sender, 1_000, 60_000);
        let hint = e.recipient_hint;
        mb.deposit(e, 1_000).unwrap();

        assert_eq!(mb.fetch(&[hint], 0, 1_500).len(), 1);
        assert_eq!(mb.fetch(&[[9u8; 8]], 0, 1_500).len(), 0);
        // since filter
        assert_eq!(mb.fetch(&[hint], 2_000, 2_500).len(), 0);
    }

    #[test]
    fn rejects_expired_and_overlong_ttl() {
        let mut mb = Mailbox::new();
        let sender = SignSecret::generate();
        let rid = sha256(b"r");
        let rik = AgreeSecret::generate().public().to_bytes();

        let expired = env_for(&rid, &rik, &sender, 100, 50);
        assert!(mb.deposit(expired, 1_000).is_err());

        let greedy = env_for(&rid, &rik, &sender, 1_000, MAX_TTL_MS + 1);
        assert!(mb.deposit(greedy, 1_000).is_err());
    }

    #[test]
    fn gc_removes_expired() {
        let mut mb = Mailbox::new();
        let sender = SignSecret::generate();
        let rid = sha256(b"r");
        let rik = AgreeSecret::generate().public().to_bytes();
        mb.deposit(env_for(&rid, &rik, &sender, 1_000, 500), 1_000)
            .unwrap();
        mb.deposit(env_for(&rid, &rik, &sender, 1_000, 100_000), 1_000)
            .unwrap();
        assert_eq!(mb.len(), 2);
        assert_eq!(mb.gc(2_000), 1);
        assert_eq!(mb.len(), 1);
    }

    #[test]
    fn rejects_a_future_timestamp_so_nothing_is_immortal() {
        let mut mb = Mailbox::new();
        let sender = SignSecret::generate();
        let rid = sha256(b"r");
        let rik = AgreeSecret::generate().public().to_bytes();
        // A depositor claiming a far-future deposit time used to defeat GC,
        // because `now - deposited_ms` saturated to 0 forever.
        let immortal = env_for(&rid, &rik, &sender, u64::MAX, 1_000);
        assert!(mb.deposit(immortal, 1_000).is_err());
        assert_eq!(mb.len(), 0);
    }

    #[test]
    fn enforces_per_hint_depth_and_frees_bytes_on_gc() {
        let mut mb = Mailbox::new();
        let sender = SignSecret::generate();
        let rid = sha256(b"victim");
        let rik = AgreeSecret::generate().public().to_bytes();
        let hint = env_for(&rid, &rik, &sender, 1_000, 60_000).recipient_hint;
        for _ in 0..MAX_HINT_DEPTH {
            mb.deposit(env_for(&rid, &rik, &sender, 1_000, 60_000), 1_000)
                .unwrap();
        }
        // One past the per-hint cap is refused, not stored unbounded.
        assert!(mb
            .deposit(env_for(&rid, &rik, &sender, 1_000, 60_000), 1_000)
            .is_err());
        assert_eq!(mb.fetch(&[hint], 0, 1_500).len(), MAX_HINT_DEPTH);
        // Expiry frees the accounting so fresh deposits are accepted again.
        assert_eq!(mb.gc(1_000 + 60_001), MAX_HINT_DEPTH);
        assert!(mb
            .deposit(env_for(&rid, &rik, &sender, 200_000, 60_000), 200_000)
            .is_ok());
    }

    #[test]
    fn hint_helper_matches_sealed_envelope() {
        let sender = SignSecret::generate();
        let rid = sha256(b"r");
        let rik = AgreeSecret::generate().public().to_bytes();
        let e = env_for(&rid, &rik, &sender, 5 * 86_400_000, 1_000);
        assert_eq!(e.recipient_hint, recipient_hint(&rid, 5 * 86_400_000));
    }
}
