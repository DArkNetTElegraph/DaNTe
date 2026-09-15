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
        let hud_rows = terminal_rows().filter(|&r| r > 3);
        if let Some(rows) = hud_rows {
            // DECSTBM: restrict scrolling to everything but the last row, so
            // ordinary output (the prompt, command replies) scrolls in rows
            // 1..rows-1 exactly like normal, while the last row is reserved
            // for a status line nothing else ever writes to. This is the
            // same trick `less`/`vim`/tmux's own status bar use -- not a
            // real TUI, no raw mode, no new dependency: plain ANSI, and
            // ordinary `println!` above it keeps working unmodified.
            print!("\x1b[1;{}r\x1b[1;1H", rows - 1);
            std::io::stdout().flush().ok();
        }
        println!("dante-relay console -- type /help for commands.");
        if hud_rows.is_some() {
            println!("(live stats pinned to the bottom line, updating every second)");
        } else {
            println!("(terminal size unavailable -- run /stats for a one-shot snapshot)");
        }

        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        print!("relay> ");
        std::io::stdout().flush().ok();

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if let Some(rows) = hud_rows {
                        redraw_pinned_line(&handler, &console, rows).await;
                    }
                }
                next = lines.next_line() => {
                    let Ok(Some(line)) = next else { break; };
                    let line = line.trim();
                    if line.is_empty() {
                        print!("relay> ");
                        std::io::stdout().flush().ok();
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
                    print!("relay> ");
                    std::io::stdout().flush().ok();
                }
            }
        }
        if hud_rows.is_some() {
            reset_terminal();
        }
    }
    std::future::pending::<()>().await;
}

/// Terminal row count via `stty size`, which reads it from whatever tty is
/// on this process's own stdin. There's no portable way to ask the terminal
/// this without an ioctl, and this crate forbids unsafe code entirely
/// (`#![forbid(unsafe_code)]` at the crate root) -- a subprocess is the only
/// route left, and it's cheap and one-shot (called once at console start,
/// not per redraw). `None` on anything that isn't a real, queryable
/// terminal, or if `stty` isn't installed.
fn terminal_rows() -> Option<u16> {
    // `Command::output()` defaults a child's stdin to `Stdio::null()`, not
    // inherited -- without overriding it here, `stty` has no controlling
    // terminal to query at all and fails every time, regardless of whether
    // *this* process actually has one.
    let out = std::process::Command::new("stty")
        .arg("size")
        .stdin(std::process::Stdio::inherit())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.split_whitespace().next()?.parse().ok()
}

/// Undoes the scroll-region restriction from [`run`], unconditionally and
/// harmlessly even if it was never set (not a terminal, `stty` unavailable,
/// etc. -- printing this to a plain pipe or a terminal never put in that
/// mode does nothing). Called on every *graceful* exit path: the console
/// loop ending here, and `dante-relay`'s own Ctrl-C handler in `main.rs`.
/// Not run on a hard kill (SIGKILL, a panic that aborts the process) --
/// like any program that does this (tmux included), recovery there is
/// `reset` or `tput reset` in the shell, a standard, well-known fix.
///
/// A live terminal *resize* while the console is running isn't handled
/// (that needs a SIGWINCH handler, which needs re-querying `stty size` and
/// re-issuing the DECSTBM sequence -- deliberately out of scope here); if
/// an operator resizes their window mid-session the pinned line can end up
/// misplaced until they reconnect.
pub fn reset_terminal() {
    print!("\x1b[r");
    let _ = std::io::stdout().flush();
}

/// Redraws the single pinned status line at the bottom of the terminal
/// (row `rows`) without disturbing whatever the operator is currently
/// typing above it: save cursor, jump to the last row, clear it, print,
/// restore cursor -- all in one write so nothing else can interleave with
/// it mid-sequence.
async fn redraw_pinned_line(handler: &RelayHandler, console: &Console, rows: u16) {
    let stats = handler.state().lock().await.stats();
    let uptime = console.started_at.elapsed();
    let conns = console.conn_count.load(Ordering::Relaxed);
    let cpu_ram = match (process_usage(), host_ram_and_load()) {
        (Some(p), Some((ram_pct, load_1m))) => format!(
            " | proc {} RSS | host RAM {ram_pct:.0}% | load {load_1m:.2}",
            fmt_bytes(p.rss_bytes)
        ),
        (Some(p), None) => format!(" | proc {} RSS", fmt_bytes(p.rss_bytes)),
        _ => String::new(),
    };
    let line = format!(
        "[dante-relay] up {} | {conns} conn | {} id | {} ch{cpu_ram}",
        fmt_duration(uptime),
        stats.identities,
        stats.channels,
    );
    print!("\x1b7\x1b[{rows};1H\x1b[2K{line}\x1b8");
    std::io::stdout().flush().ok();
}

fn print_help() {
    println!(
        "/stats               uptime, connections, storage, process + host CPU/RAM/disk\n\
         /peers               configured and known federation neighbors\n\
         /peer add <multiaddr>  dial a new federation neighbor right now\n\
         /registry [addr]     check whether addr (default: this relay's own --listen) \
is in the public directory\n\
         /help                this text\n\n\
         A one-line summary is already pinned to the bottom of this terminal, \
updating every second -- /stats gives the full breakdown on demand."
    );
}

async fn print_stats(handler: &RelayHandler, console: &Console) {
    print!("{}", render_stats(handler, console).await);
}

/// Formats the same content `/stats` prints, as a string rather than direct
/// `println!`s -- so `/watch` can clear the screen and redraw it in place
/// without duplicating a second copy of this text.
async fn render_stats(handler: &RelayHandler, console: &Console) -> String {
    let stats = handler.state().lock().await.stats();
    let uptime = console.started_at.elapsed();
    let conns = console.conn_count.load(Ordering::Relaxed);
    let mut out = String::new();
    use std::fmt::Write as _;
    let _ = writeln!(out, "uptime:         {}", fmt_duration(uptime));
    let _ = writeln!(out, "connections:    {conns} active (TCP)");
    let _ = writeln!(out, "identities:     {}", stats.identities);
    let _ = writeln!(out, "channels:       {}", stats.channels);
    let _ = writeln!(out, "mailbox:        {} envelope(s)", stats.mailbox_entries);
    let _ = writeln!(
        out,
        "file blobs:     {}",
        fmt_bytes(stats.blob_bytes as u64)
    );
    let _ = writeln!(
        out,
        "channel store:  {}",
        fmt_bytes(stats.channel_bytes as u64)
    );
    match process_usage() {
        Some(u) => {
            let avg_pct = if uptime.as_secs_f64() > 0.0 {
                (u.cpu_seconds / uptime.as_secs_f64() * 100.0).min(999.9)
            } else {
                0.0
            };
            let _ = writeln!(
                out,
                "this process:   {:.1}s CPU time ({:.1}% average since start), {} RSS",
                u.cpu_seconds,
                avg_pct,
                fmt_bytes(u.rss_bytes)
            );
        }
        None => {
            let _ = writeln!(out, "this process:   CPU/memory usage unavailable here");
        }
    }
    match host_usage().await {
        Some(h) => {
            let _ = writeln!(
                out,
                "host CPU load:  {:.2} 1m / {:.2} 5m / {:.2} 15m ({} core(s))",
                h.load_1m, h.load_5m, h.load_15m, h.cpu_cores
            );
            let _ = writeln!(
                out,
                "host RAM:       {} used / {} total ({:.0}%)",
                fmt_bytes(h.ram_used_bytes),
                fmt_bytes(h.ram_total_bytes),
                pct(h.ram_used_bytes, h.ram_total_bytes)
            );
            match (h.disk_used_bytes, h.disk_total_bytes) {
                (Some(used), Some(total)) => {
                    let _ = writeln!(
                        out,
                        "host disk (.):  {} used / {} total ({:.0}%)",
                        fmt_bytes(used),
                        fmt_bytes(total),
                        pct(used, total)
                    );
                }
                _ => {
                    let _ = writeln!(out, "host disk (.):  unavailable (`df` not found?)");
                }
            }
        }
        None => {
            let _ = writeln!(out, "host CPU/RAM:   unavailable on this platform");
        }
    }
    out
}

fn pct(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        used as f64 / total as f64 * 100.0
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

struct HostUsage {
    ram_used_bytes: u64,
    ram_total_bytes: u64,
    load_1m: f64,
    load_5m: f64,
    load_15m: f64,
    cpu_cores: usize,
    disk_used_bytes: Option<u64>,
    disk_total_bytes: Option<u64>,
}

/// RAM (used/total bytes) and 1/5/15-minute load averages plus core count,
/// from `/proc/meminfo` and `/proc/loadavg` -- no subprocess, so this is
/// cheap enough to call every second from the pinned status line as well as
/// from the fuller `/stats` breakdown.
#[cfg(target_os = "linux")]
fn ram_and_load() -> Option<(u64, u64, f64, f64, f64, usize)> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let field = |key: &str| -> Option<u64> {
        meminfo
            .lines()
            .find_map(|l| l.strip_prefix(key))?
            .trim()
            .trim_end_matches(" kB")
            .trim()
            .parse()
            .ok()
    };
    let mem_total_kb = field("MemTotal:")?;
    // MemAvailable (not MemFree) is what actually matters: it already
    // accounts for reclaimable page/slab cache, which on a Linux box is
    // usually most of "free" memory and isn't memory under real pressure.
    let mem_available_kb = field("MemAvailable:")?;
    let ram_total_bytes = mem_total_kb * 1024;
    let ram_used_bytes = ram_total_bytes.saturating_sub(mem_available_kb * 1024);

    let loadavg = std::fs::read_to_string("/proc/loadavg").ok()?;
    let mut parts = loadavg.split_whitespace();
    let load_1m: f64 = parts.next()?.parse().ok()?;
    let load_5m: f64 = parts.next()?.parse().ok()?;
    let load_15m: f64 = parts.next()?.parse().ok()?;

    let cpu_cores = std::fs::read_to_string("/proc/cpuinfo")
        .map(|s| {
            s.lines()
                .filter(|l| l.starts_with("processor"))
                .count()
                .max(1)
        })
        .unwrap_or(1);

    Some((
        ram_used_bytes,
        ram_total_bytes,
        load_1m,
        load_5m,
        load_15m,
        cpu_cores,
    ))
}
#[cfg(not(target_os = "linux"))]
fn ram_and_load() -> Option<(u64, u64, f64, f64, f64, usize)> {
    None
}

/// `(RAM used %, 1-minute load average)` -- the two host numbers cheap and
/// small enough to belong on the pinned status line, refreshed every
/// second. Full detail (RAM in bytes, all three load windows, disk) is
/// `/stats`'s job, not the HUD's.
fn host_ram_and_load() -> Option<(f64, f64)> {
    let (used, total, load_1m, _5m, _15m, _cores) = ram_and_load()?;
    Some((pct(used, total), load_1m))
}

/// The whole machine's load, not just this process's -- the operator's real
/// question is usually "is the box this relay lives on about to fall over,"
/// which `process_usage` alone can't answer (a relay can look fine while a
/// neighboring process eats the disk).
#[cfg(target_os = "linux")]
async fn host_usage() -> Option<HostUsage> {
    let (ram_used_bytes, ram_total_bytes, load_1m, load_5m, load_15m, cpu_cores) = ram_and_load()?;

    // `df` in a blocking task: it's a subprocess spawn + wait, which would
    // otherwise briefly block whichever tokio worker thread polls this.
    // `/stats` calls this once per invocation, so the cost is bounded --
    // unlike the pinned line, which deliberately does NOT call this (see
    // `host_ram_and_load`) precisely to avoid spawning `df` every second.
    let (disk_used_bytes, disk_total_bytes) = tokio::task::spawn_blocking(disk_usage_here)
        .await
        .unwrap_or((None, None));

    Some(HostUsage {
        ram_used_bytes,
        ram_total_bytes,
        load_1m,
        load_5m,
        load_15m,
        cpu_cores,
        disk_used_bytes,
        disk_total_bytes,
    })
}

/// Disk usage of the filesystem holding the current working directory, via
/// `df -Pk .` (POSIX output format, so the column layout is stable). Not the
/// relay's own storage specifically -- everything it holds is in memory, not
/// on disk -- this is "how full is the disk this process happens to live
/// on," which is what an operator actually wants to know before that disk
/// fills up and takes down everything else on the box too.
#[cfg(target_os = "linux")]
fn disk_usage_here() -> (Option<u64>, Option<u64>) {
    let out = match std::process::Command::new("df").args(["-Pk", "."]).output() {
        Ok(o) if o.status.success() => o.stdout,
        _ => return (None, None),
    };
    let text = String::from_utf8_lossy(&out);
    let Some(data_line) = text.lines().nth(1) else {
        return (None, None);
    };
    let cols: Vec<&str> = data_line.split_whitespace().collect();
    // Filesystem, 1024-blocks, Used, Available, Use%, Mounted-on.
    let Some(total_kb) = cols.get(1).and_then(|s| s.parse::<u64>().ok()) else {
        return (None, None);
    };
    let Some(used_kb) = cols.get(2).and_then(|s| s.parse::<u64>().ok()) else {
        return (None, None);
    };
    (Some(used_kb * 1024), Some(total_kb * 1024))
}

#[cfg(not(target_os = "linux"))]
async fn host_usage() -> Option<HostUsage> {
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
