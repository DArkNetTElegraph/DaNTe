//! Shared library surface for the `dante` CLI binary and the desktop shell
//! (`apps/dante-desktop`).
//!
//! It exposes [`serve`] — the engine wrapped in a tiny localhost HTTP/JSON API
//! plus an embedded single-file SPA — and the two small helpers `serve` needs.
//! The interactive `chat` client and the argument plumbing live in the binary
//! (`src/main.rs`), which also depends on this crate.

pub mod serve;
pub mod unfurl;

use anyhow::Result;
use dante_identity::id::IdentityId;

/// Unix time in milliseconds (0 if the clock is before the epoch).
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Parse a Crockford-base32 fingerprint or a 24-word phrase into the raw
/// `IdentityId` bytes.
pub fn parse_fingerprint(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    let id = if s.contains(' ') {
        IdentityId::from_words(s)
    } else {
        IdentityId::from_base32(s)
    }
    .map_err(|_| anyhow::anyhow!("not a valid base32 or word-phrase fingerprint"))?;
    Ok(*id.as_bytes())
}
