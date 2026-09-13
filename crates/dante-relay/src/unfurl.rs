//! Opt-in relay-side link unfurler (feature `unfurl`).
//!
//! Off by default, same as `--turn-listen` and the `sfu` feature: enabling
//! this means the relay itself makes an outbound HTTPS request on a client's
//! behalf (so the client's own IP never reaches the linked site), and the
//! relay operator now learns which URL was asked about. See
//! `docs/THREAT_MODEL.md` §4.
//!
//! The fetch itself is `dante_net::unfurl` — the same SSRF-guarded fetcher
//! `dante-cli`'s own local unfurler uses, so this and the client-local path
//! share one implementation rather than two copies of security-critical
//! code.
//!
//! Requests are handled by [`crate::state::RelayHandler`] before they reach
//! the relay state, because a fetch is real network I/O and must not block
//! (or be blocked by) the state lock.

use std::net::IpAddr;
use std::sync::Mutex;

use dante_net::ratelimit::KeyedRateLimiter;
use dante_net::wire::{Request, Response};

/// Per-IP unfurl request budget: `(capacity, refill/sec)`. Deliberately
/// tight — each request is an outbound fetch this relay performs on the
/// caller's behalf, unlike a cheap wire round-trip, so a flood here is a
/// flood of outbound traffic from the relay's own IP.
const RATE: (f64, f64) = (10.0, 1.0);
/// Matches `dante_net::unfurl::unfurl`'s own URL-length rejection — checked
/// here too so an oversized URL is refused before it even reaches the rate
/// limiter or a DNS lookup.
const MAX_URL_BYTES: usize = 2048;

/// Gate for the relay-side unfurler: the operator's on/off switch plus its
/// own rate limit, independent of every other request type's limits.
pub struct UnfurlGate {
    enabled: bool,
    rl: Mutex<KeyedRateLimiter<IpAddr>>,
}

impl UnfurlGate {
    /// `enabled` is the operator's current opt-in choice
    /// (`RelayState::unfurl_enabled`) at construction time.
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            rl: Mutex::new(KeyedRateLimiter::new(RATE.0, RATE.1)),
        }
    }

    /// Serve an unfurl request, or `None` if it is not one.
    pub async fn handle(&self, req: &Request, ip: IpAddr, now_ms: u64) -> Option<Response> {
        let Request::UnfurlLink(url) = req else {
            return None;
        };
        if !self.enabled {
            return Some(Response::Error("unfurl: not enabled on this relay".into()));
        }
        if url.len() > MAX_URL_BYTES {
            return Some(Response::Error("unfurl: url too long".into()));
        }
        if !self.allow(ip, now_ms) {
            return Some(Response::Error("unfurl: rate limited".into()));
        }
        Some(match dante_net::unfurl::unfurl(url).await {
            Ok(p) => Response::UnfurlPreview {
                url: p.url,
                site: p.site,
                title: p.title,
                description: p.description,
                image_data_uri: p.image_data_uri.unwrap_or_default(),
            },
            Err(e) => Response::Error(format!("unfurl: {e}")),
        })
    }

    /// Charge one token against `ip`.
    fn allow(&self, ip: IpAddr, now_ms: u64) -> bool {
        self.rl
            .lock()
            .expect("unfurl rate limiter poisoned")
            .check(&ip, now_ms, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    #[tokio::test]
    async fn disabled_by_default_refuses_without_attempting_a_fetch() {
        let gate = UnfurlGate::new(false);
        let r = gate
            .handle(
                &Request::UnfurlLink("http://127.0.0.1:1/x".into()),
                ip(),
                1_000,
            )
            .await
            .unwrap();
        assert_eq!(
            r,
            Response::Error("unfurl: not enabled on this relay".into())
        );
    }

    #[tokio::test]
    async fn oversized_url_is_rejected_before_the_rate_limiter() {
        let gate = UnfurlGate::new(true);
        let long = "http://example.org/".to_string() + &"a".repeat(3000);
        let r = gate
            .handle(&Request::UnfurlLink(long), ip(), 1_000)
            .await
            .unwrap();
        assert_eq!(r, Response::Error("unfurl: url too long".into()));
    }

    #[tokio::test]
    async fn a_flood_from_one_ip_is_refused() {
        let gate = UnfurlGate::new(true);
        // The SSRF guard refuses this target instantly (no real network
        // wait), so the loop below exercises the rate limiter, not a slow
        // fetch: burst through the whole budget, then the next one must be
        // refused for rate, not for the (also true) SSRF reason.
        let url = "http://127.0.0.1:1/x".to_string();
        let mut rate_limited = false;
        for _ in 0..(RATE.0 as u32 + 2) {
            let r = gate
                .handle(&Request::UnfurlLink(url.clone()), ip(), 1_000)
                .await
                .unwrap();
            if r == Response::Error("unfurl: rate limited".into()) {
                rate_limited = true;
                break;
            }
        }
        assert!(
            rate_limited,
            "a flood from one IP must eventually be rate limited"
        );
    }

    #[tokio::test]
    async fn not_an_unfurl_request_is_none() {
        let gate = UnfurlGate::new(true);
        assert!(gate.handle(&Request::Ping, ip(), 0).await.is_none());
    }
}
