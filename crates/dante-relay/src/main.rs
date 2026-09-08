//! `dante-relay` — a community-run DaNTe relay node.
//!
//! Holds a ledger replica and a sealed-sender mailbox, and speaks the
//! `dante-net` request/response protocol over framed TCP. A relay sees only
//! ciphertext, recipient hints, sizes, and timing (see
//! `docs/THREAT_MODEL.md` adversary A3).
//!
//! Usage: `dante-relay [--listen ADDR] [--min-pow-bits N]`.

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use dante_ledger::LedgerParams;
use dante_net::transport::serve;
use dante_relay::state::{now_ms, IcePolicy, Limits, RelayHandler, RelayState};
use dante_relay::turn_server::TurnServer;
use tokio::net::TcpListener;

const DEFAULT_LISTEN: &str = "0.0.0.0:9944";
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);

struct Args {
    listen: String,
    min_pow_bits: Option<u8>,
    ice: IcePolicy,
    /// `host:port` to run an in-process TURN server on (UDP).
    turn_listen: Option<String>,
    /// Public IP the TURN server advertises as its relayed address.
    turn_public_ip: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dante_relay=info,dante_net=info".into()),
        )
        .init();

    let mut args = parse_args();

    // Optional in-process TURN server. Kept alive for the process lifetime.
    let mut _turn = None;
    if let Some(listen) = args.turn_listen.clone() {
        let secret = args
            .ice
            .turn_secret
            .clone()
            .context("--turn-listen requires --turn-secret")?;
        let port = listen
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .context("--turn-listen must be HOST:PORT")?;
        let public_ip: std::net::IpAddr = args
            .turn_public_ip
            .clone()
            .or_else(|| {
                listen
                    .rsplit_once(':')
                    .map(|(h, _)| h.to_string())
                    .filter(|h| {
                        h.parse::<std::net::IpAddr>()
                            .map(|ip| !ip.is_unspecified())
                            .unwrap_or(false)
                    })
            })
            .context("give --turn-public-ip (or a concrete IP in --turn-listen)")?
            .parse()
            .context("--turn-public-ip is not an IP address")?;

        _turn = Some(TurnServer::start(&listen, public_ip, "dante", secret).await?);
        let url = format!("turn:{public_ip}:{port}");
        if !args.ice.turn.iter().any(|u| u == &url) {
            args.ice.turn.push(url.clone());
        }
        tracing::info!(%listen, %url, "in-process TURN server running");
    }

    let mut params = LedgerParams::default();
    if let Some(bits) = args.min_pow_bits {
        params.min_announce_pow_bits = bits;
        params.min_liveness_pow_bits = bits.saturating_sub(4).max(1);
        tracing::warn!(
            bits,
            "PoW floor lowered from the default -- for local testing only"
        );
    }

    let mut relay_state = RelayState::new(params, Limits::default());
    if !args.ice.stun.is_empty() || !args.ice.turn.is_empty() {
        tracing::info!(
            stun = args.ice.stun.len(),
            turn = args.ice.turn.len(),
            turn_creds = args.ice.turn_secret.is_some(),
            "advertising ICE servers for calls"
        );
    }
    relay_state.set_ice_policy(args.ice);
    let handler = Arc::new(RelayHandler::new(relay_state));

    // Background housekeeping.
    {
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(MAINTENANCE_INTERVAL);
            loop {
                tick.tick().await;
                let now = now_ms();
                let (dropped, evaporated) = handler.state().lock().await.maintain(now);
                if dropped > 0 || evaporated > 0 {
                    tracing::info!(dropped, evaporated, "maintenance");
                }
            }
        });
    }

    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("binding {}", args.listen))?;
    tracing::info!(listen = %args.listen, "dante-relay listening");

    tokio::select! {
        r = serve(listener, handler) => { r?; }
        _ = tokio::signal::ctrl_c() => { tracing::info!("shutting down"); }
    }
    Ok(())
}

fn parse_args() -> Args {
    let mut listen = DEFAULT_LISTEN.to_string();
    let mut min_pow_bits = None;
    let mut ice = IcePolicy {
        turn_ttl_secs: 3600,
        ..Default::default()
    };
    let mut turn_listen = None;
    let mut turn_public_ip = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--listen" | "-l" => {
                if let Some(v) = it.next() {
                    listen = v;
                }
            }
            "--min-pow-bits" => {
                min_pow_bits = it.next().and_then(|v| v.parse().ok());
            }
            "--stun" => {
                if let Some(v) = it.next() {
                    ice.stun.push(v);
                }
            }
            "--turn" => {
                if let Some(v) = it.next() {
                    ice.turn.push(v);
                }
            }
            "--turn-secret" => {
                ice.turn_secret = it.next().filter(|s| !s.is_empty());
            }
            "--turn-ttl" => {
                if let Some(n) = it.next().and_then(|v| v.parse().ok()) {
                    ice.turn_ttl_secs = n;
                }
            }
            "--turn-listen" => {
                turn_listen = it.next();
            }
            "--turn-public-ip" => {
                turn_public_ip = it.next();
            }
            "--help" | "-h" => {
                eprintln!(
                    "usage: dante-relay [--listen ADDR] [--min-pow-bits N]\n  \
                     [--stun URL ...] [--turn URL ...] [--turn-secret STR] [--turn-ttl SECS]\n  \
                     [--turn-listen HOST:PORT] [--turn-public-ip IP]  (run an in-process TURN server)\n  \
                     defaults: --listen {DEFAULT_LISTEN}, PoW floor from LedgerParams::default()"
                );
                std::process::exit(0);
            }
            _ => {}
        }
    }
    Args {
        listen,
        min_pow_bits,
        ice,
        turn_listen,
        turn_public_ip,
    }
}
