//! Client-side consumption of the public relay directory
//! (`relays/registry.toml`, published as a status JSON by
//! `dante-relay-check` — see `relays/README.md`).
//!
//! That file is explicit that the registry "is not how DaNTe discovers
//! relays to talk to at runtime." This module is what changes that: given
//! one or more directory URLs, fetch each one's published relay list, ping
//! every entry for real from wherever this process actually runs (never
//! trust the published `latency_ms` — that was measured from a GitHub
//! Actions runner, not from here), and hand back whichever answered fastest.
//!
//! More than one directory URL matters for the same reason it never made
//! sense to have exactly one relay: the GitHub Pages page is one host that
//! can be taken down or blocked. A second, independently-hosted mirror
//! serving the same JSON shape means losing one source doesn't cost you the
//! feature — it just costs you the entries only that source knew about.

use std::time::Duration;

use serde::Deserialize;

/// The status JSON `dante-relay-check` publishes to GitHub Pages. Only the
/// fields this module actually uses — extra fields in the real document
/// (`checked_at_unix_ms`, `online_count`, ...) are ignored by serde, not
/// rejected.
#[derive(Deserialize)]
struct StatusDoc {
    #[serde(default)]
    relays: Vec<RelayEntry>,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
struct RelayEntry {
    name: String,
    addr: String,
}

/// A relay this process personally reached, with its own measured latency.
#[derive(Debug, Clone)]
pub struct Reachable {
    pub name: String,
    pub addr: String,
    pub latency: Duration,
}

/// How long to wait for one directory source's JSON.
const FETCH_TIMEOUT: Duration = Duration::from_secs(8);
/// Cap on a directory response — it's a small JSON list, not a file upload.
const FETCH_CAP: usize = 1024 * 1024;
/// How long to wait for one relay's ping before writing it off as
/// unreachable from here.
const PING_TIMEOUT: Duration = Duration::from_secs(5);

/// The compiled-in directory source. `--directory` / `DANTE_RELAY_DIRECTORY`
/// add to this rather than replace it, same pattern as `DANTE_BOOTSTRAP` —
/// so a second mirror is additive, never a foot-gun that silently drops the
/// default.
pub const DEFAULT_DIRECTORY: &str = "https://darknettelegraph.github.io/DaNTe/status.json";

/// Fetch every `urls` source, merge their relay lists (de-duplicated by
/// `addr`, first source wins the display name), and ping each one for real.
/// Returns every relay that actually answered, sorted fastest first — never
/// just the winner, so a caller can show the full ranking or fail over to
/// the second choice if the first drops between this check and connecting.
pub async fn rank_reachable(urls: &[String]) -> Vec<Reachable> {
    let mut seen = std::collections::HashSet::new();
    let mut candidates = Vec::new();
    for url in urls {
        let Ok(doc) = fetch_status(url).await else {
            continue;
        };
        for r in doc.relays {
            if seen.insert(r.addr.clone()) {
                candidates.push(r);
            }
        }
    }
    rank_candidates(candidates).await
}

/// The actual ping-and-sort, split out from [`rank_reachable`] so it's
/// testable against real local listeners instead of the public directory.
async fn rank_candidates(candidates: Vec<RelayEntry>) -> Vec<Reachable> {
    // Genuinely concurrent, not one-at-a-time: with a 5s per-ping timeout,
    // pinging a dozen directory entries sequentially could take a minute.
    let mut pings = tokio::task::JoinSet::new();
    for r in candidates {
        pings.spawn(async move {
            dante_net::sync::ping(&r.addr, PING_TIMEOUT)
                .await
                .ok()
                .map(|latency| Reachable {
                    name: r.name,
                    addr: r.addr,
                    latency,
                })
        });
    }
    let mut reachable = Vec::new();
    while let Some(res) = pings.join_next().await {
        if let Ok(Some(r)) = res {
            reachable.push(r);
        }
    }
    reachable.sort_by_key(|r| r.latency);
    reachable
}

async fn fetch_status(url: &str) -> Result<StatusDoc, String> {
    let deadline = tokio::time::Instant::now() + FETCH_TIMEOUT;
    let (_final_url, body, _ct) =
        dante_net::unfurl::fetch(url, deadline, FETCH_CAP, Some("application/json"), None).await?;
    serde_json::from_slice(&body).map_err(|e| e.to_string())
}
