//! Checks every relay in the opt-in registry (`relays/registry.toml`), then
//! follows each one's reported federation peers outward, and writes a status
//! document a static page can render.
//!
//! The registry is a plain list relay operators add themselves to via a PR —
//! nothing here *scans* for relays on its own, which would mean
//! fingerprinting operators (onion relay operators especially) who never
//! agreed to be public. But once at least one relay in a federated cluster is
//! listed, this does follow the graph outward from it: a listed relay is
//! asked (`Request::GetP2pPeers`) for the addresses it already knows about —
//! its own `--p2p-bootstrap` config, plus whatever other peers have recently
//! announced to it — and each new one found is verified and published too, up
//! to a bounded depth and total count. One PR can surface a whole federated
//! cluster instead of needing one per relay. What this still can't do, and
//! nothing can: reveal a relay nobody federates with and nobody has listed —
//! discovery only ever follows from something already known, which is why a
//! torrent swarm needs a tracker or DHT bootstrap node too, not just peers.
//!
//! "Online" means a real protocol round trip succeeded: `Request::Ping` ->
//! `Response::Pong`, over the same wire a client uses — plain framed TCP for
//! a registry entry, or the actual libp2p connection for a discovered
//! multiaddr. That is a genuine external-reachability check, run from
//! wherever this binary executes (CI, by default) — not merely "is a socket
//! accepting connections," which is close to worthless as a test for
//! something an ISP without public IPv4 could never satisfy in the first
//! place. A discovered peer is verified exactly the same way as a listed
//! one — what a relay *reports* about its peers is never published
//! unverified; it is only ever used as a lead to go check.
//!
//! Not covered yet: relays reachable only over Tor. Checking those needs a
//! SOCKS5 proxy to a running Tor daemon in whatever environment runs this,
//! which is real extra infrastructure a first version deliberately leaves out
//! rather than guess at. They can still be listed in the registry; they will
//! just show as unchecked here.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use dante_net::{
    transport::Client,
    wire::{Request, Response},
};
use serde::{Deserialize, Serialize};

/// How long to wait for a connection + one round trip before giving up.
const PER_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(8);
/// Attempts before declaring a relay offline. A lone failure on a scheduled
/// check is often just a transient blip on the runner's own network path;
/// this keeps the published status from flapping on those.
const ATTEMPTS: u32 = 2;
const RETRY_DELAY: Duration = Duration::from_secs(2);

/// How many hops out from a listed relay to follow reported peers. Depth 0 is
/// the registry entries themselves. Bounded so a misconfigured or hostile
/// relay reporting a huge peer list can't turn one PR into an unbounded crawl.
const MAX_DEPTH: u32 = 3;
/// Total relays (listed + discovered) this run will ever check, regardless of
/// how many peers get reported. The same safety bound from the other side.
const MAX_TOTAL_RELAYS: usize = 100;

#[derive(Debug, Deserialize)]
struct Registry {
    #[serde(default, rename = "relay")]
    relays: Vec<RelayEntry>,
    /// A relay's own operator did not necessarily agree to be published just
    /// because someone *else's* relay federates with them and got listed.
    /// This is the opt-out for exactly that: a peer id (or exact multiaddr)
    /// here is never checked, never published, and never crawled past, no
    /// matter how many listed relays report it. See relays/README.md.
    #[serde(default, rename = "exclude")]
    excludes: Vec<ExcludeEntry>,
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
    /// `"dedicated"` (a homelab box, VPS, or anything meant to stay up) or
    /// `"user"` (someone's regular `dante serve --also-relay`, online only
    /// while they happen to be chatting). Defaults to `"dedicated"` — the
    /// established meaning of a registry entry before this field existed.
    /// Purely descriptive: the check itself doesn't treat the two
    /// differently, but the page groups by it so an intermittent "user" relay
    /// going offline overnight doesn't read the same as a VPS actually down.
    /// See relays/README.md.
    #[serde(default)]
    kind: Option<String>,
}

/// `RelayEntry::kind`, defaulted and normalised to one of `"dedicated"` /
/// `"user"` — an unrecognised value falls back to `"dedicated"` rather than
/// failing the whole check run over one PR's typo.
fn relay_kind(entry: &RelayEntry) -> String {
    match entry.kind.as_deref() {
        Some("user") => "user".to_string(),
        _ => "dedicated".to_string(),
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ExcludeEntry {
    /// The libp2p peer id (the part after the last `/p2p/` in a multiaddr) or
    /// the exact address to exclude. Matching on the peer id is what makes
    /// this durable across a relay changing IP/port — its identity doesn't.
    addr: String,
}

#[derive(Debug, Serialize)]
struct RelayStatus {
    name: String,
    addr: String,
    online: bool,
    /// Only meaningful when `online`; the last successful attempt's latency.
    latency_ms: Option<u64>,
    /// `None` for a directly-listed (registry) relay. Otherwise the name of
    /// the relay whose reported peer list led here — never more than one
    /// hop's worth, even at depth > 1, so the page can show the actual
    /// federation edge without walking a full path.
    discovered_via: Option<String>,
    /// `"dedicated"` / `"user"` for a registry entry (see `RelayEntry::kind`),
    /// or `"federated"` for anything found only by crawling a listed relay's
    /// reported peers — it was never registered with a kind of its own, so
    /// there is nothing to report beyond "some relay this one federates
    /// with".
    kind: String,
}

#[derive(Debug, Serialize)]
struct StatusDoc {
    checked_at_unix_ms: u64,
    online_count: usize,
    total_count: usize,
    /// Registry entries with `kind = "dedicated"` (or no `kind` at all).
    dedicated_count: usize,
    /// Registry entries with `kind = "user"`.
    user_count: usize,
    /// Entries found only via federation crawl, not directly registered.
    federated_count: usize,
    relays: Vec<RelayStatus>,
}

/// One item in the crawl frontier.
struct Pending {
    name: String,
    addr: String,
    discovered_via: Option<String>,
    depth: u32,
    kind: String,
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

    // One libp2p node for the whole run, reused for every discovered-peer
    // dial. Cheap to spawn (a background task behind a channel handle) and
    // needs no stable identity — it never receives inbound connections, it
    // only ever dials out to verify a lead.
    let p2p_seed = dante_crypto::random_array::<32>();
    let (p2p_node, _events, _inbound) =
        dante_p2p::Node::spawn(&p2p_seed).context("spawning the p2p node used for discovery")?;

    // A key that survives a relay changing IP/port: its peer id where it has
    // one, else the address verbatim (a registry entry's plain `host:port`
    // has no peer id to fall back to, but nothing excludes those by peer id
    // anyway — exclusion exists for discovered multiaddrs).
    let excluded: HashSet<String> = registry
        .excludes
        .iter()
        .map(|e| exclusion_key(&e.addr))
        .collect();

    let mut relays: Vec<RelayStatus> = Vec::new();
    let mut seen_addrs: HashSet<String> = HashSet::new();
    let mut frontier: VecDeque<Pending> = VecDeque::new();

    for entry in &registry.relays {
        if excluded.contains(&exclusion_key(&entry.addr)) {
            eprintln!(
                "skipping {} ({}): also present in [[exclude]]",
                entry.name, entry.addr
            );
            continue;
        }
        seen_addrs.insert(entry.addr.clone());
        frontier.push_back(Pending {
            name: entry.name.clone(),
            addr: entry.addr.clone(),
            discovered_via: None,
            depth: 0,
            kind: relay_kind(entry),
        });
    }

    while let Some(item) = frontier.pop_front() {
        if relays.len() >= MAX_TOTAL_RELAYS {
            eprintln!("hit MAX_TOTAL_RELAYS ({MAX_TOTAL_RELAYS}), stopping the crawl early");
            break;
        }

        let label = match &item.discovered_via {
            None => item.name.clone(),
            Some(via) => format!("{} (discovered via {via})", item.name),
        };
        eprintln!("checking {label} ({}) ...", item.addr);

        let (latency, peers) = check_and_discover(&p2p_node, &item.addr).await;
        match &latency {
            Some(ms) => eprintln!("  online, {ms}ms, reports {} peer(s)", peers.len()),
            None => eprintln!("  offline (after {ATTEMPTS} attempts)"),
        }

        let online = latency.is_some();
        relays.push(RelayStatus {
            name: item.name.clone(),
            addr: item.addr.clone(),
            online,
            latency_ms: latency,
            discovered_via: item.discovered_via.clone(),
            kind: item.kind.clone(),
        });

        if online && item.depth < MAX_DEPTH {
            for peer_addr in peers {
                if seen_addrs.len() >= MAX_TOTAL_RELAYS {
                    break;
                }
                if excluded.contains(&exclusion_key(&peer_addr)) {
                    eprintln!("  skipping reported peer {peer_addr}: present in [[exclude]]");
                    continue;
                }
                if seen_addrs.insert(peer_addr.clone()) {
                    frontier.push_back(Pending {
                        name: display_name_for(&peer_addr),
                        addr: peer_addr,
                        discovered_via: Some(item.name.clone()),
                        depth: item.depth + 1,
                        kind: "federated".to_string(),
                    });
                }
            }
        }
    }

    let online_count = relays.iter().filter(|r| r.online).count();
    let dedicated_count = relays.iter().filter(|r| r.kind == "dedicated").count();
    let user_count = relays.iter().filter(|r| r.kind == "user").count();
    let federated_count = relays.iter().filter(|r| r.kind == "federated").count();
    let doc = StatusDoc {
        checked_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        online_count,
        total_count: relays.len(),
        dedicated_count,
        user_count,
        federated_count,
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

/// One relay: connect (plain TCP for a `host:port` registry address, libp2p
/// for a `/...` discovered multiaddr), `Ping`, retried up to `ATTEMPTS`
/// times. On success, also asks for `GetP2pPeers` on the same connection —
/// best-effort; a relay with nothing to report, or one that errors on the
/// request, just yields no leads, it doesn't affect the online verdict.
///
/// Returns `(latency of the successful attempt in ms, reported peer addrs)`.
async fn check_and_discover(node: &dante_p2p::Node, addr: &str) -> (Option<u64>, Vec<String>) {
    for attempt in 1..=ATTEMPTS {
        let started = Instant::now();
        let outcome = tokio::time::timeout(PER_ATTEMPT_TIMEOUT, connect_and_ping(node, addr)).await;
        match outcome {
            Ok(Ok(mut client)) => {
                let latency = started.elapsed().as_millis() as u64;
                let peers = tokio::time::timeout(PER_ATTEMPT_TIMEOUT, get_peers(&mut client))
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or_default();
                return (Some(latency), peers);
            }
            Ok(Err(e)) => eprintln!("  attempt {attempt}/{ATTEMPTS} failed: {e}"),
            Err(_) => eprintln!("  attempt {attempt}/{ATTEMPTS} timed out"),
        }
        if attempt != ATTEMPTS {
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }
    (None, Vec::new())
}

/// Dial `addr` and confirm it with a `Ping`. A libp2p multiaddr (what a
/// discovered peer reports) always starts with `/`; anything else is treated
/// as a plain `host:port` relay address, matching what the registry holds.
async fn connect_and_ping(node: &dante_p2p::Node, addr: &str) -> Result<Client> {
    let mut client = if addr.starts_with('/') {
        Client::connect_p2p(node.clone(), addr).await?
    } else {
        Client::connect(addr).await?
    };
    match client.request(&Request::Ping).await? {
        Response::Pong => Ok(client),
        other => anyhow::bail!("unexpected response to Ping: {other:?}"),
    }
}

async fn get_peers(client: &mut Client) -> Result<Vec<String>> {
    match client.request(&Request::GetP2pPeers).await? {
        Response::P2pPeers(list) => Ok(list),
        other => anyhow::bail!("unexpected response to GetP2pPeers: {other:?}"),
    }
}

/// The key an `[[exclude]]` entry is matched against: the libp2p peer id if
/// the address carries one (the part after the last `/p2p/`), else the
/// address verbatim. A discovered multiaddr's peer id survives the relay
/// moving IP/port; a plain registry `host:port` has no peer id, so it's
/// matched on the literal string instead.
fn exclusion_key(addr: &str) -> String {
    match addr.rsplit_once("/p2p/") {
        Some((_, peer_id)) if !peer_id.is_empty() => peer_id.to_string(),
        _ => addr.to_string(),
    }
}

/// A short, human-readable label for a discovered multiaddr, since it has no
/// registry-assigned name. Prefers the `/ip4|ip6/HOST/tcp/PORT` prefix most
/// multiaddrs carry; falls back to a truncated form of the whole thing for
/// anything unusual (e.g. `/dns/...`) rather than failing to display it.
fn display_name_for(multiaddr: &str) -> String {
    let parts: Vec<&str> = multiaddr.split('/').filter(|s| !s.is_empty()).collect();
    // ["ip4", "1.2.3.4", "tcp", "9945", "p2p", "12D3Koo..."]
    if parts.len() >= 4 && (parts[0] == "ip4" || parts[0] == "ip6" || parts[0] == "dns") {
        return format!("{}:{}", parts[1], parts[3]);
    }
    if multiaddr.len() <= 40 {
        multiaddr.to_string()
    } else {
        format!("{}…", &multiaddr[..40])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_defaults_to_dedicated_when_absent_or_unrecognised() {
        let toml = r#"
            [[relay]]
            name = "a"
            addr = "a.example:9944"

            [[relay]]
            name = "b"
            addr = "b.example:9944"
            kind = "user"

            [[relay]]
            name = "c"
            addr = "c.example:9944"
            kind = "typo-should-fall-back"
        "#;
        let reg: Registry = toml::from_str(toml).unwrap();
        assert_eq!(relay_kind(&reg.relays[0]), "dedicated");
        assert_eq!(relay_kind(&reg.relays[1]), "user");
        assert_eq!(relay_kind(&reg.relays[2]), "dedicated");
    }
}
