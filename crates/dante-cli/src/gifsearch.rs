//! Opt-in GIF search for `dante serve` (Tenor or Giphy).
//!
//! Off unless the operator sets `TENOR_API_KEY` or `GIPHY_API_KEY` **and** the
//! user flips the session toggle (`POST /api/gifsearch/toggle`, re-asserted by
//! the SPA on every load, same pattern as the link-preview toggle in
//! [`crate::unfurl`]) — searching a third-party API reveals the query text and
//! this machine's IP to that party, so it must be a deliberate choice, not a
//! default.
//!
//! Search only ever contacts the configured provider's own fixed API host —
//! the query string is the only client-controlled input, there is no
//! client-supplied URL to guard. Fetching a chosen result (to store it as a
//! blob before sending) *is* client-directed by URL, so that step additionally
//! checks the host against an allowlist of the two providers' known CDN
//! domains before running it through [`crate::unfurl::fetch`]'s existing
//! SSRF-guarded, capped, timed-out HTTP client.

use std::time::Duration;

use serde_json::Value;
use tokio::time::Instant;

use crate::unfurl::fetch;

const MAX_RESULTS: u8 = 24;
const SEARCH_BUDGET: Duration = Duration::from_secs(6);
const FETCH_BUDGET: Duration = Duration::from_secs(8);
const MAX_SEARCH_BODY: usize = 512 * 1024;
/// A chosen GIF's bytes, capped the same as a sticker image.
pub const MAX_GIF_BYTES: usize = 512 * 1024;

/// One search result: enough to render a thumbnail and, if picked, fetch the
/// full image.
#[derive(serde::Serialize)]
pub struct GifResult {
    pub id: String,
    pub preview_url: String,
    pub full_url: String,
    pub width: u32,
    pub height: u32,
}

/// Which provider is configured, from the operator's environment. `None` if
/// neither key is set — the feature is simply unavailable, not degraded.
pub enum Provider {
    Tenor(String),
    Giphy(String),
}

impl Provider {
    pub fn from_env() -> Option<Self> {
        if let Ok(k) = std::env::var("TENOR_API_KEY") {
            if !k.is_empty() {
                return Some(Provider::Tenor(k));
            }
        }
        if let Ok(k) = std::env::var("GIPHY_API_KEY") {
            if !k.is_empty() {
                return Some(Provider::Giphy(k));
            }
        }
        None
    }

    pub fn name(&self) -> &'static str {
        match self {
            Provider::Tenor(_) => "tenor",
            Provider::Giphy(_) => "giphy",
        }
    }
}

/// Search `provider` for `query`, returning up to [`MAX_RESULTS`] results.
pub async fn search(provider: &Provider, query: &str) -> Result<Vec<GifResult>, String> {
    if query.is_empty() || query.len() > 100 {
        return Err("query must be 1..=100 characters".into());
    }
    let q = urlencode(query);
    let url = match provider {
        Provider::Tenor(key) => format!(
            "https://tenor.googleapis.com/v2/search?q={q}&key={key}&client_key=dante\
             &limit={MAX_RESULTS}&media_filter=tinygif,gif&contentfilter=medium"
        ),
        Provider::Giphy(key) => format!(
            "https://api.giphy.com/v1/gifs/search?api_key={key}&q={q}\
             &limit={MAX_RESULTS}&rating=g"
        ),
    };
    let deadline = Instant::now() + SEARCH_BUDGET;
    let (_, body, _) = fetch(&url, deadline, MAX_SEARCH_BODY, Some("application/json")).await?;
    let json: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    Ok(match provider {
        Provider::Tenor(_) => parse_tenor(&json),
        Provider::Giphy(_) => parse_giphy(&json),
    })
}

fn parse_tenor(json: &Value) -> Vec<GifResult> {
    json["results"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| {
            let id = r["id"].as_str()?.to_owned();
            let full = &r["media_formats"]["gif"];
            let preview = &r["media_formats"]["tinygif"];
            Some(GifResult {
                id,
                preview_url: preview["url"].as_str().or(full["url"].as_str())?.to_owned(),
                full_url: full["url"].as_str()?.to_owned(),
                width: full["dims"][0].as_u64().unwrap_or(0) as u32,
                height: full["dims"][1].as_u64().unwrap_or(0) as u32,
            })
        })
        .take(MAX_RESULTS as usize)
        .collect()
}

fn parse_giphy(json: &Value) -> Vec<GifResult> {
    json["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| {
            let id = r["id"].as_str()?.to_owned();
            let full = &r["images"]["original"];
            let preview = &r["images"]["fixed_height_small"];
            Some(GifResult {
                id,
                preview_url: preview["url"].as_str().or(full["url"].as_str())?.to_owned(),
                full_url: full["url"].as_str()?.to_owned(),
                width: full["width"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                height: full["height"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
            })
        })
        .take(MAX_RESULTS as usize)
        .collect()
}

/// Whether `url`'s host is a known GIF-CDN domain for one of the two
/// supported providers. Checked before ever fetching a client-supplied URL —
/// [`fetch`]'s own public-IP resolution guard still applies underneath this,
/// this is the tighter, additional allowlist.
fn allowed_host(url: &str) -> bool {
    let Some(host) = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .map(|h| h.rsplit_once('@').map_or(h, |(_, h)| h))
        .map(|h| h.rsplit_once(':').map_or(h, |(h, _)| h))
    else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    for suffix in [".tenor.com", ".giphy.com"] {
        if host == suffix[1..] || host.ends_with(suffix) {
            return true;
        }
    }
    false
}

/// Fetch a chosen result's full GIF bytes, ready to store as a blob. Rejects
/// anything not on the CDN allowlist or over [`MAX_GIF_BYTES`].
pub async fn fetch_gif(url: &str) -> Result<Vec<u8>, String> {
    if !allowed_host(url) {
        return Err("not a recognised GIF provider host".into());
    }
    let deadline = Instant::now() + FETCH_BUDGET;
    let (_, body, content_type) = fetch(url, deadline, MAX_GIF_BYTES, None).await?;
    if !content_type.starts_with("image/") {
        return Err(format!("unexpected content type: {content_type}"));
    }
    Ok(body)
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_allowlist_rejects_lookalikes_and_non_cdn_hosts() {
        assert!(allowed_host("https://media.tenor.com/abc.gif"));
        assert!(allowed_host("https://media1.tenor.com/abc.gif"));
        assert!(allowed_host("https://i.giphy.com/abc.gif"));
        assert!(!allowed_host("https://tenor.com.evil.example/abc.gif"));
        assert!(!allowed_host(
            "https://evil.example/abc.gif?host=media.tenor.com"
        ));
        assert!(!allowed_host("http://127.0.0.1/abc.gif"));
        assert!(!allowed_host("not a url"));
    }

    #[test]
    fn urlencode_escapes_spaces_and_symbols() {
        assert_eq!(urlencode("cat gif"), "cat%20gif");
        assert_eq!(urlencode("a&b=c"), "a%26b%3Dc");
        assert_eq!(urlencode("safe-Chars_9.~"), "safe-Chars_9.~");
    }
}
