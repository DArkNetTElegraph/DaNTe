//! Checks every relay in the opt-in registry (`relays/registry.toml`) and
//! writes a status document a static page can render.
//!
//! The registry is a plain list relay operators add themselves to via a PR —
//! nothing here discovers or scans for relays on its own, which would mean
//! fingerprinting operators (onion relay operators especially) who never
//! agreed to be public. This only ever contacts an address someone chose to
//! list.
//!
//! "Online" means a real protocol round trip succeeded: `Request::Ping` ->
//! `Response::Pong` over the same framed-TCP wire a client uses. That is a
//! genuine external-reachability check, run from wherever this binary
//! executes (CI, by default) — not merely "is a socket accepting
//! connections," which is close to worthless as a test for something an ISP
//! without public IPv4 could never satisfy in the first place.
//!
//! Not covered yet: relays reachable only over Tor. Checking those needs a
//! SOCKS5 proxy to a running Tor daemon in whatever environment runs this,
//! which is real extra infrastructure a first version deliberately leaves out
//! rather than guess at. They can still be listed in the registry; they will
//! just show as unchecked here.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use dante_net::{transport::Client, wire::Request, wire::Response};
use serde::{Deserialize, Serialize};

/// How long to wait for a connection + one round trip before giving up.
const PER_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(8);
/// Attempts before declaring a relay offline. A lone failure on a scheduled
/// check is often just a transient blip on the runner's own network path;
/// this keeps the published status from flapping on those.
const ATTEMPTS: u32 = 2;
const RETRY_DELAY: Duration = Duration::from_secs(2);

#[derive(Debug, Deserialize)]
struct Registry {
    #[serde(default, rename = "relay")]
    relays: Vec<RelayEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct RelayEntry {
    name: String,
    addr: String,
    /// Not published — a way for the status page's maintainer to reach an
    /// operator about a relay that has been down a while. Read but never
    /// serialised back out.
    #[serde(default)]
    #[allow(dead_code)]
    contact: Option<String>,
}

#[derive(Debug, Serialize)]
struct RelayStatus {
    name: String,
    addr: String,
    online: bool,
    /// Only meaningful when `online`; the last successful attempt's latency.
    latency_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct StatusDoc {
    checked_at_unix_ms: u64,
    online_count: usize,
    total_count: usize,
    relays: Vec<RelayStatus>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let registry_path = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("relays/registry.toml"));
    let out_path = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("status.json"));

    let raw = std::fs::read_to_string(&registry_path)
        .with_context(|| format!("reading {}", registry_path.display()))?;
    let registry: Registry =
        toml::from_str(&raw).with_context(|| format!("parsing {}", registry_path.display()))?;

    let mut relays = Vec::with_capacity(registry.relays.len());
    for entry in &registry.relays {
        eprintln!("checking {} ({}) ...", entry.name, entry.addr);
        let result = check_one(&entry.addr).await;
        match &result {
            Some(ms) => eprintln!("  online, {ms}ms"),
            None => eprintln!("  offline (after {ATTEMPTS} attempts)"),
        }
        relays.push(RelayStatus {
            name: entry.name.clone(),
            addr: entry.addr.clone(),
            online: result.is_some(),
            latency_ms: result,
        });
    }

    let online_count = relays.iter().filter(|r| r.online).count();
    let doc = StatusDoc {
        checked_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        online_count,
        total_count: relays.len(),
        relays,
    };

    let json = serde_json::to_string_pretty(&doc)?;
    std::fs::write(&out_path, json).with_context(|| format!("writing {}", out_path.display()))?;
    eprintln!(
        "{}/{} relays online -> {}",
        doc.online_count,
        doc.total_count,
        out_path.display()
    );
    Ok(())
}

/// One relay: `Client::connect` then a single `Ping`, retried up to
/// `ATTEMPTS` times. Returns the successful attempt's latency in
/// milliseconds, or `None` if every attempt failed.
async fn check_one(addr: &str) -> Option<u64> {
    for attempt in 1..=ATTEMPTS {
        let started = Instant::now();
        let outcome = tokio::time::timeout(PER_ATTEMPT_TIMEOUT, ping(addr)).await;
        match outcome {
            Ok(Ok(())) => return Some(started.elapsed().as_millis() as u64),
            Ok(Err(e)) => eprintln!("  attempt {attempt}/{ATTEMPTS} failed: {e}"),
            Err(_) => eprintln!("  attempt {attempt}/{ATTEMPTS} timed out"),
        }
        if attempt != ATTEMPTS {
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }
    None
}

async fn ping(addr: &str) -> Result<()> {
    let mut client = Client::connect(addr).await?;
    match client.request(&Request::Ping).await? {
        Response::Pong => Ok(()),
        other => anyhow::bail!("unexpected response to Ping: {other:?}"),
    }
}
