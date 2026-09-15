//! An interactive operator console for `dante-relay`: live stats, known
//! federation peers, and a way to add one without restarting.
//!
//! Only active when stdin is a real terminal. A relay managed by systemd has
//! no TTY on stdin at all, so this is a no-op there — running it under
//! `screen`/`tmux` instead is what turns it on, by design, not by flag: the
//! same binary behaves as a plain headless daemon or an interactive console
//! depending only on how it's attached.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

use crate::state::{now_ms, RelayHandler};

/// The public relay directory this relay's own address can be checked
/// against — the same one `dante-cli`'s `--relay auto` consumes. Kept as a
/// literal here rather than shared with `dante-cli`, since pulling that crate
/// in as a dependency of the relay binary just for one constant string would
/// be a strange direction for the dependency graph to point.
const DIRECTORY_URL: &str = "https://darknettelegraph.github.io/DaNTe/status.json";

/// What the console needs that isn't already reachable through
/// [`RelayHandler`] — process-lifetime and p2p-wiring context set up once in
/// [`crate::run::run`].
pub struct Console {
    pub started_at: Instant,
    pub conn_count: Arc<AtomicUsize>,
    pub listen: String,
    pub p2p_enabled: bool,
    pub p2p_bootstrap: Vec<String>,
    /// Send a multiaddr here to have the live p2p task dial it. `None` (or a
    /// dropped receiver) just means "p2p isn't running" — every caller checks
    /// `p2p_enabled` first and reports that plainly rather than hanging.
    pub p2p_dial_tx: Option<mpsc::Sender<String>>,
}

/// This future is raced as a branch of the same `tokio::select!` that runs
/// the relay's actual serving loop (see `run::run`) — so it must NEVER
/// resolve for a reason that isn't "the whole relay should stop," or winning
/// that race tears down the TCP listener and federation task right along
/// with it. Concretely: a headless run (no TTY on stdin — the systemd case)
/// and an operator closing their attached console (EOF/Ctrl-D on a real
/// terminal) both have to idle forever here instead of returning, the same
/// way the `maintenance` loop never returns and `p2p_task` parks on
/// `std::future::pending` when p2p isn't configured.
pub async fn run(handler: Arc<RelayHandler>, console: Console) {
    if std::io::stdin().is_terminal() {
        println!("dante-relay console -- type /help for commands.");
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        loop {
            print!("relay> ");
            std::io::stdout().flush().ok();
            let Ok(Some(line)) = lines.next_line().await else {
                break;
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.splitn(2, char::is_whitespace);
            let cmd = parts.next().unwrap_or("");
            let arg = parts.next().unwrap_or("").trim();
            match cmd {
                "/help" | "help" => print_help(),
                "/stats" | "stats" => print_stats(&handler, &console).await,
                "/peers" | "peers" => print_peers(&handler, &console).await,
                "/peer" => match arg.split_once(char::is_whitespace) {
                    Some(("add", addr)) => add_peer(&console, addr.trim().to_string()).await,
                    _ => println!("usage: /peer add <multiaddr>"),
                },
                "/registry" | "registry" => check_registry(arg, &console).await,
                _ => println!("unknown command {cmd:?} -- try /help"),
            }
        }
    }
    std::future::pending::<()>().await;
}

fn print_help() {
    println!(
        "/stats               uptime, connections, storage, process CPU/memory\n\
         /peers               configured and known federation neighbors\n\
         /peer add <multiaddr>  dial a new federation neighbor right now\n\
         /registry [addr]     check whether addr (default: this relay's own --listen) \
is in the public directory\n\
         /help                this text"
    );
}

async fn print_stats(handler: &RelayHandler, console: &Console) {
    let stats = handler.state().lock().await.stats();
    let uptime = console.started_at.elapsed();
    let conns = console.conn_count.load(Ordering::Relaxed);
    println!("uptime:         {}", fmt_duration(uptime));
    println!("connections:    {conns} active (TCP)");
    println!("identities:     {}", stats.identities);
    println!("channels:       {}", stats.channels);
    println!("mailbox:        {} envelope(s)", stats.mailbox_entries);
    println!("file blobs:     {}", fmt_bytes(stats.blob_bytes as u64));
    println!("channel store:  {}", fmt_bytes(stats.channel_bytes as u64));
    match process_usage() {
        Some(u) => {
            let avg_pct = if uptime.as_secs_f64() > 0.0 {
                (u.cpu_seconds / uptime.as_secs_f64() * 100.0).min(999.9)
            } else {
                0.0
            };
            println!(
                "process:        {:.1}s CPU time ({:.1}% average since start), {} RSS",
                u.cpu_seconds,
                avg_pct,
                fmt_bytes(u.rss_bytes)
            );
        }
        None => println!("process:        CPU/memory usage unavailable on this platform"),
    }
}

async fn print_peers(handler: &RelayHandler, console: &Console) {
    println!("listening:      {} (TCP)", console.listen);
    if !console.p2p_enabled {
        println!("federation:     disabled (start with --p2p-listen to federate)");
        return;
    }
    println!("federation:     enabled");
    if console.p2p_bootstrap.is_empty() {
        println!("configured neighbors (--p2p-bootstrap): none");
    } else {
        println!("configured neighbors (--p2p-bootstrap):");
        for b in &console.p2p_bootstrap {
            println!("  {b}");
        }
    }
    let known = handler.state().lock().await.known_p2p_peers(now_ms());
    println!(
        "known federation peers (configured + self-reported): {}",
        known.len()
    );
    for k in &known {
        println!("  {k}");
    }
}

async fn add_peer(console: &Console, addr: String) {
    if addr.is_empty() {
        println!("usage: /peer add <multiaddr>");
        return;
    }
    if !console.p2p_enabled {
        println!("p2p federation is disabled on this relay (start with --p2p-listen to enable it)");
        return;
    }
    let Some(tx) = &console.p2p_dial_tx else {
        println!("p2p task isn't running -- can't dial");
        return;
    };
    match tx.send(addr.clone()).await {
        Ok(()) => println!("dialing {addr} ..."),
        Err(_) => println!("p2p task has stopped -- can't dial"),
    }
}

async fn check_registry(arg: &str, console: &Console) {
    let addr = if arg.is_empty() {
        console.listen.clone()
    } else {
        arg.to_string()
    };
    println!("checking {DIRECTORY_URL} for {addr} ...");
    match fetch_directory_addrs().await {
        Ok(addrs) if addrs.iter().any(|a| a == &addr) => {
            println!("published: {addr} is listed in the public relay directory");
        }
        Ok(_) => println!(
            "not published yet: {addr} is not in the public relay directory. \
             See relays/README.md to add it via a PR."
        ),
        Err(e) => println!("could not check the directory: {e}"),
    }
}

#[derive(serde::Deserialize)]
struct StatusDoc {
    #[serde(default)]
    relays: Vec<RelayEntry>,
}

#[derive(serde::Deserialize)]
struct RelayEntry {
    addr: String,
}

async fn fetch_directory_addrs() -> Result<Vec<String>, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let (_url, body, _ct) = dante_net::unfurl::fetch(
        DIRECTORY_URL,
        deadline,
        1024 * 1024,
        Some("application/json"),
        None,
    )
    .await?;
    let doc: StatusDoc = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    Ok(doc.relays.into_iter().map(|r| r.addr).collect())
}

fn fmt_duration(d: Duration) -> String {
    let s = d.as_secs();
    let (h, m, s) = (s / 3600, (s % 3600) / 60, s % 60);
    if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut n = bytes as f64;
    let mut unit = 0;
    while n >= 1024.0 && unit < UNITS.len() - 1 {
        n /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{n:.1} {}", UNITS[unit])
    }
}

struct ProcessUsage {
    cpu_seconds: f64,
    rss_bytes: u64,
}

/// CPU time and RSS from `/proc/self/{stat,status}`. Linux-only: there's no
/// portable way to get either without a dependency (`sysinfo` et al.) whose
/// only job here would be one number in an operator console, which doesn't
/// justify the added dependency-review and supply-chain surface. Every
/// realistic deployment target for this binary (VPS, homelab box) is Linux;
/// elsewhere this just reports "unavailable" rather than guessing.
#[cfg(target_os = "linux")]
fn process_usage() -> Option<ProcessUsage> {
    // USER_HZ (clock ticks/sec) is 100 on every mainstream Linux kernel
    // config this project targets. Getting it exactly right needs libc's
    // sysconf(_SC_CLK_TCK), which isn't worth a new dependency for a stat
    // that's already an approximation ("average since start"), not a
    // precision measurement.
    const CLK_TCK: f64 = 100.0;

    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    // `comm` (the 2nd field) is parenthesized and may itself contain spaces
    // or parens, so split on the *last* ')' rather than tokenizing from the
    // start — everything after it is fixed-format, whitespace-separated.
    let after_name = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = after_name.split_whitespace().collect();
    // `after_name` starts at field 3 (state), so utime (field 14) is index
    // 11 and stime (field 15) is index 12 here.
    let utime: f64 = fields.get(11)?.parse().ok()?;
    let stime: f64 = fields.get(12)?.parse().ok()?;

    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let rss_kb: u64 = status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))?
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;

    Some(ProcessUsage {
        cpu_seconds: (utime + stime) / CLK_TCK,
        rss_bytes: rss_kb * 1024,
    })
}

#[cfg(not(target_os = "linux"))]
fn process_usage() -> Option<ProcessUsage> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_bytes_picks_a_sensible_unit() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(2048), "2.0 KiB");
        assert_eq!(fmt_bytes(5 * 1024 * 1024), "5.0 MiB");
    }

    #[test]
    fn fmt_duration_omits_leading_zero_units() {
        assert_eq!(fmt_duration(Duration::from_secs(5)), "5s");
        assert_eq!(fmt_duration(Duration::from_secs(65)), "1m 5s");
        assert_eq!(fmt_duration(Duration::from_secs(3665)), "1h 1m 5s");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_usage_reads_this_actual_process() {
        // This test binary is itself a running Linux process, so this is a
        // real read of /proc, not a mock -- confirms the field-offset math
        // against the real, current kernel's /proc/self/stat shape.
        let usage = process_usage().expect("this process's own /proc/self/stat");
        assert!(usage.cpu_seconds >= 0.0);
        assert!(usage.rss_bytes > 0, "a running test process has some RSS");
    }
}
