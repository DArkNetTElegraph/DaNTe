//! DaNTe desktop shell.
//!
//! This is deliberately thin: it starts the exact same engine-behind-HTTP
//! service that `dante serve` runs (`dante_cli::serve`) on an ephemeral
//! localhost port, then opens a native window pointed at it. The web UI, the
//! JSON API, onboarding, and every feature come from `dante-cli` unchanged — the
//! desktop build only replaces "open this URL in your browser" with a real
//! window and (later) native menus, notifications, and auto-update.
//!
//! Config comes from the environment, matching `dante serve`:
//!   DANTE_HOME        directory for the keystore + encrypted state
//!                     (default: $HOME/.dante)
//!   DANTE_RELAY       comma-separated relay endpoints (default 127.0.0.1:9944)
//!   DANTE_PASSPHRASE  if set and a keystore already exists, unlock it at
//!                     startup; otherwise the window shows the onboarding flow
//!   DANTE_POW_BITS    proof-of-work difficulty for our own records (default 20)

mod audio;

use std::path::PathBuf;

use anyhow::{Context, Result};
use dante_core::Engine;
use dante_crypto::pow::Difficulty;
use dante_identity::keystore;
use dante_ledger::LedgerParams;
use tokio::net::TcpListener;

fn dante_home() -> PathBuf {
    if let Ok(h) = std::env::var("DANTE_HOME") {
        return PathBuf::from(h);
    }
    let base = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(base).join(".dante")
}

struct Prepared {
    listener: TcpListener,
    port: u16,
    existing: Option<Engine>,
    boot: dante_cli::serve::Bootstrap,
}

async fn prepare() -> Result<Prepared> {
    let home = dante_home();
    std::fs::create_dir_all(&home).with_context(|| format!("creating {}", home.display()))?;
    let keystore_path = home.join("identity.keystore");
    let store_path = Some(home.join("state.bin"));

    let relay = std::env::var("DANTE_RELAY").unwrap_or_else(|_| "127.0.0.1:9944".into());
    let bits: u8 = std::env::var("DANTE_POW_BITS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let params = LedgerParams {
        min_announce_pow_bits: bits,
        min_liveness_pow_bits: bits.saturating_sub(4).max(1),
        ..Default::default()
    };
    let pow = Difficulty {
        m_cost_kib: 4_096,
        t_cost: 1,
        bits,
    };

    // Unlock up front only if we can; otherwise the page onboards.
    let existing = match (keystore_path.exists(), std::env::var("DANTE_PASSPHRASE")) {
        (true, Ok(pass)) => {
            let bytes = std::fs::read(&keystore_path)?;
            let identity = keystore::open(&bytes, pass.as_bytes())?;
            Some(Engine::connect(identity, &relay, params, pow, store_path.clone()).await?)
        }
        _ => None,
    };

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("binding a localhost port for the UI")?;
    let port = listener.local_addr()?.port();

    Ok(Prepared {
        listener,
        port,
        existing,
        boot: dante_cli::serve::Bootstrap {
            relay,
            keystore_path,
            store_path,
            params,
            pow,
        },
    })
}

fn main() -> Result<()> {
    let Prepared {
        listener,
        port,
        existing,
        boot,
    } = tauri::async_runtime::block_on(prepare())?;

    tauri::async_runtime::spawn(async move {
        if let Err(e) = dante_cli::serve::run_on(existing, listener, boot).await {
            eprintln!("dante-desktop: UI service exited: {e:#}");
        }
    });

    // Bridge the OS mic/speaker to whichever 1:1 call is connected. Runs on its
    // own thread (cpal streams are !Send) and talks to the service above over
    // localhost HTTP.
    let _audio = audio::spawn(port);

    let url = format!("http://127.0.0.1:{port}/");
    tauri::Builder::default()
        .setup(move |app| {
            tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::External(url.parse().expect("valid localhost URL")),
            )
            .title("DaNTe")
            .inner_size(1100.0, 720.0)
            .min_inner_size(800.0, 500.0)
            .build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .map_err(|e| anyhow::anyhow!("tauri runtime: {e}"))
}
