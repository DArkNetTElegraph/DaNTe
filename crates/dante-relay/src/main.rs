//! `dante-relay` — a community-run DaNTe relay node.
//!
//! Holds a ledger replica and a sealed-sender mailbox, and speaks the
//! `dante-net` request/response protocol over framed TCP. A relay sees only
//! ciphertext, recipient hints, sizes, and timing (see
//! `docs/THREAT_MODEL.md` adversary A3).
//!
//! Usage: `dante-relay [--listen ADDR] [--min-pow-bits N]`.
//!
//! This binary is just argv parsing over [`dante_relay::run`] — the same
//! entry point a `dante serve --also-relay` client embeds in-process, so a
//! desktop user can opt in to being a relay for others without running a
//! second program.

use dante_relay::{RunConfig, DEFAULT_LISTEN};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dante_relay=info,dante_net=info".into()),
        )
        .init();

    let cfg = parse_args();

    tokio::select! {
        r = dante_relay::run(cfg) => { r?; }
        _ = tokio::signal::ctrl_c() => { tracing::info!("shutting down"); }
    }
    Ok(())
}

fn parse_args() -> RunConfig {
    let mut cfg = RunConfig {
        ice: dante_relay::state::IcePolicy {
            turn_ttl_secs: 3600,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--listen" | "-l" => {
                if let Some(v) = it.next() {
                    cfg.listen = v;
                }
            }
            "--min-pow-bits" => {
                cfg.min_pow_bits = it.next().and_then(|v| v.parse().ok());
            }
            "--min-pow-m-cost-kib" => {
                cfg.min_pow_m_cost_kib = it.next().and_then(|v| v.parse().ok());
            }
            "--min-pow-t-cost" => {
                cfg.min_pow_t_cost = it.next().and_then(|v| v.parse().ok());
            }
            "--stun" => {
                if let Some(v) = it.next() {
                    cfg.ice.stun.push(v);
                }
            }
            "--turn" => {
                if let Some(v) = it.next() {
                    cfg.ice.turn.push(v);
                }
            }
            "--turn-secret" => {
                // Prefer DANTE_TURN_SECRET: an argv secret is visible in
                // `ps`/`/proc/<pid>/cmdline` and shell history to any local user.
                cfg.ice.turn_secret = it.next().filter(|s| !s.is_empty());
                eprintln!(
                    "warning: --turn-secret is visible in the process list; \
                     prefer the DANTE_TURN_SECRET environment variable"
                );
            }
            "--turn-ttl" => {
                if let Some(n) = it.next().and_then(|v| v.parse().ok()) {
                    cfg.ice.turn_ttl_secs = n;
                }
            }
            "--turn-listen" => {
                cfg.turn_listen = it.next();
            }
            "--turn-public-ip" => {
                cfg.turn_public_ip = it.next();
            }
            "--p2p-bootstrap" => {
                if let Some(v) = it.next() {
                    cfg.p2p_bootstrap.extend(
                        v.split(',')
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned),
                    );
                }
            }
            "--p2p-listen" => {
                cfg.p2p_listen = it.next();
            }
            "--p2p-seed" => {
                cfg.p2p_seed = it.next();
            }
            "--help" | "-h" => {
                eprintln!(
                    "usage: dante-relay [--listen ADDR] [--min-pow-bits N]\n  \
                     [--min-pow-m-cost-kib N] [--min-pow-t-cost N]  (Argon2 cost floor)\n  \
                     [--stun URL ...] [--turn URL ...] [--turn-secret STR] [--turn-ttl SECS]\n  \
                     [--turn-listen HOST:PORT] [--turn-public-ip IP]  (run an in-process TURN server)\n  \
                     [--p2p-bootstrap MULTIADDR,...]  (libp2p bootstrap peers offered to p2p clients)\n  \
                     [--p2p-listen MULTIADDR] [--p2p-seed HEX32]  (serve clients over libp2p; feature p2p)\n  \
                     the TURN secret is read from DANTE_TURN_SECRET (preferred) or --turn-secret\n  \
                     defaults: --listen {DEFAULT_LISTEN}, PoW floor from LedgerParams::default()"
                );
                std::process::exit(0);
            }
            _ => {}
        }
    }
    // The TURN secret is best supplied out-of-band via the environment so it
    // never lands in argv; a `--turn-secret` on the command line still wins if
    // both are set (the operator asked for it explicitly).
    if cfg.ice.turn_secret.is_none() {
        cfg.ice.turn_secret = std::env::var("DANTE_TURN_SECRET")
            .ok()
            .filter(|s| !s.is_empty());
    }
    // Sibling relays may also be supplied out of band so a distro / systemd
    // unit doesn't need to bake them into the command line.
    if let Ok(env) = std::env::var("DANTE_BOOTSTRAP") {
        for a in env
            .split([',', ' ', '\t', '\n'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if !cfg.p2p_bootstrap.iter().any(|x| x == a) {
                cfg.p2p_bootstrap.push(a.to_string());
            }
        }
    }
    cfg
}
