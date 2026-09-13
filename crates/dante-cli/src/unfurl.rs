//! Opt-in link-preview unfurler for `dante serve`.
//!
//! The SSRF-guarded fetch/scrape implementation lives in
//! `dante_net::unfurl` — shared with `dante-relay`'s opt-in relay-side
//! unfurler, so the two SSRF-critical code paths cannot diverge. Fetching a
//! URL's metadata reveals this machine's IP address to the linked site; the
//! feature is **off by default** and is enabled per session by the SPA
//! (`POST /api/embeds`).
pub use dante_net::unfurl::{fetch, unfurl, Preview};
