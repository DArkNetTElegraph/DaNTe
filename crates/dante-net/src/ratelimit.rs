//! Token-bucket rate limiting, keyed (e.g. by source IP or `/24`).
//!
//! Time is passed in explicitly (`now_ms`) so this is deterministic and
//! testable; the caller supplies a monotonic clock.

use std::{collections::HashMap, hash::Hash};

/// A single token bucket.
#[derive(Clone, Copy, Debug)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_ms: f64,
    last_ms: u64,
}

impl TokenBucket {
    /// `capacity` tokens, refilling at `per_sec` tokens per second, starting
    /// full at `now_ms`.
    pub fn new(capacity: f64, per_sec: f64, now_ms: u64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_per_ms: per_sec / 1000.0,
            last_ms: now_ms,
        }
    }

    /// Try to take `n` tokens. Returns whether it succeeded.
    pub fn try_take(&mut self, now_ms: u64, n: f64) -> bool {
        let elapsed = now_ms.saturating_sub(self.last_ms) as f64;
        self.tokens = (self.tokens + elapsed * self.refill_per_ms).min(self.capacity);
        self.last_ms = now_ms;
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

/// A collection of token buckets, one per key.
pub struct KeyedRateLimiter<K> {
    buckets: HashMap<K, TokenBucket>,
    capacity: f64,
    per_sec: f64,
}

impl<K: Eq + Hash + Clone> KeyedRateLimiter<K> {
    /// Each key gets `capacity` tokens refilling at `per_sec`/s.
    pub fn new(capacity: f64, per_sec: f64) -> Self {
        Self {
            buckets: HashMap::new(),
            capacity,
            per_sec,
        }
    }

    /// Charge `n` tokens against `key`. Returns whether the request is allowed.
    pub fn check(&mut self, key: &K, now_ms: u64, n: f64) -> bool {
        self.buckets
            .entry(key.clone())
            .or_insert_with(|| TokenBucket::new(self.capacity, self.per_sec, now_ms))
            .try_take(now_ms, n)
    }

    /// Drop buckets that have been full and idle since before `now_ms - idle_ms`
    /// (keeps the map from growing without bound).
    pub fn sweep(&mut self, now_ms: u64, idle_ms: u64) {
        let cap = self.capacity;
        self.buckets.retain(|_, b| {
            let mut b2 = *b;
            b2.try_take(now_ms, 0.0);
            !(b2.tokens >= cap && now_ms.saturating_sub(b.last_ms) > idle_ms)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_burst_then_throttles_then_refills() {
        let mut b = TokenBucket::new(10.0, 10.0, 0); // 10 cap, 10/s
        for _ in 0..10 {
            assert!(b.try_take(0, 1.0));
        }
        assert!(!b.try_take(0, 1.0)); // empty
        assert!(b.try_take(500, 1.0)); // +5 tokens after 500ms
        assert!(!b.try_take(500, 5.0)); // only ~4 left
    }

    #[test]
    fn keyed_limiter_isolates_keys() {
        let mut rl = KeyedRateLimiter::<u32>::new(2.0, 1.0);
        assert!(rl.check(&1, 0, 1.0));
        assert!(rl.check(&1, 0, 1.0));
        assert!(!rl.check(&1, 0, 1.0)); // key 1 exhausted
        assert!(rl.check(&2, 0, 1.0)); // key 2 unaffected
    }

    #[test]
    fn sweep_drops_idle_full_buckets() {
        let mut rl = KeyedRateLimiter::<u32>::new(5.0, 5.0);
        rl.check(&1, 0, 1.0); // used, will refill to full by t=1000
        rl.check(&2, 0, 5.0); // fully drained at t=0
        rl.sweep(10_000, 1_000);
        // key 1 refilled to full and idle -> dropped; key 2 also refilled to
        // full by now and idle -> dropped
        assert!(rl.check(&1, 10_000, 5.0)); // fresh full bucket
    }
}
