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

/// A hint-keyed collection of pending envelopes.
#[derive(Default)]
pub struct Mailbox {
    by_hint: HashMap<[u8; 8], Vec<Envelope>>,
    count: usize,
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
    /// expired or whose TTL exceeds [`MAX_TTL_MS`].
    pub fn deposit(&mut self, env: Envelope, now_ms: u64) -> Result<(), NetError> {
        if env.ttl_ms > MAX_TTL_MS {
            return Err(NetError::RejectedEnvelope("ttl exceeds the relay maximum"));
        }
        if env.is_expired(now_ms) {
            return Err(NetError::RejectedEnvelope("already expired"));
        }
        self.by_hint
            .entry(env.recipient_hint)
            .or_default()
            .push(env);
        self.count += 1;
        Ok(())
    }

    /// Non-expired envelopes for any of `hints` deposited at or after
    /// `since_ms`, oldest first. Does not remove them (delivery is idempotent;
    /// GC or an explicit ack clears them).
    pub fn fetch(&self, hints: &[[u8; 8]], since_ms: u64, now_ms: u64) -> Vec<Envelope> {
        let mut out = Vec::new();
        for hint in hints {
            if let Some(list) = self.by_hint.get(hint) {
                for env in list {
                    if env.deposited_ms >= since_ms && !env.is_expired(now_ms) {
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
        self.by_hint.retain(|_, list| {
            let before = list.len();
            list.retain(|e| !e.is_expired(now_ms));
            removed += before - list.len();
            !list.is_empty()
        });
        self.count -= removed;
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
    fn hint_helper_matches_sealed_envelope() {
        let sender = SignSecret::generate();
        let rid = sha256(b"r");
        let rik = AgreeSecret::generate().public().to_bytes();
        let e = env_for(&rid, &rik, &sender, 5 * 86_400_000, 1_000);
        assert_eq!(e.recipient_hint, recipient_hint(&rid, 5 * 86_400_000));
    }
}
