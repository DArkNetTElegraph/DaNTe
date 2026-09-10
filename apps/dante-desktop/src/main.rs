//! DaNTe desktop shell.
//!
//! This is deliberately thin: it starts the exact same engine-behind-HTTP
//! service that `dante serve` runs (`dante_cli::serve`) on an ephemeral
//! localhost port, then points a native window at it. The web UI, the JSON API,
//! onboarding, and every feature come from `dante-cli` unchanged.
//!
//! What the desktop build adds on top is the native layer:
//!
//! - **A window that appears immediately.** Startup is not fast — dialling
//!   relays, decrypting the local store, rebuilding MLS state per channel and
//!   solving the registration proof-of-work are each separately slow. Doing
//!   that *before* opening a window, as this shell used to, means the user
//!   double-clicks and stares at nothing. Now the window opens first and the
//!   engine reports each [`BootStep`] into it as it happens.
//! - **Tray icon**, so closing the window keeps you online instead of silently
//!   dropping you off the network.
//! - **OS notifications** for messages that arrive while you are not looking.
//! - **Mic/speaker bridge** for calls (`audio`), which a plain webview cannot do.
//!
//! Config comes from the environment, matching `dante serve`:
//!   DANTE_HOME        directory for the keystore + encrypted state
//!                     (default: $HOME/.dante)
//!   DANTE_RELAY       comma-separated relay endpoints (default 127.0.0.1:9944)
//!   DANTE_PASSPHRASE  if set and a keystore already exists, unlock it at
//!                     startup; otherwise the window shows the onboarding flow
//!   DANTE_POW_BITS    proof-of-work difficulty for our own records (default 20)

mod audio;
mod localapi;
mod notify;
mod tray;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use dante_core::{BootStep, Engine};
use dante_crypto::pow::Difficulty;
use dante_identity::keystore;
use dante_ledger::LedgerParams;
use serde_json::json;
use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindowBuilder};
use tokio::net::TcpListener;

/// Where the real UI lives once the engine is up. Set as soon as the port is
/// bound; the boot screen is swapped for it when startup finishes.
struct AppUrl(Mutex<Option<String>>);

fn dante_home() -> PathBuf {
    if let Ok(h) = std::env::var("DANTE_HOME") {
        return PathBuf::from(h);
    }
    let base = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE")) // Windows
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(base).join(".dante")
}

struct Prepared {
    listener: TcpListener,
    port: u16,
    existing: Option<Engine>,
    boot: dante_cli::serve::Bootstrap,
}

/// Bind the UI port and, if we can unlock a keystore without asking, connect
/// the engine. Reports progress as it goes.
async fn prepare(progress: dante_core::BootProgress) -> Result<Prepared> {
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

    // Unlock up front only if we can; otherwise the page onboards and the
    // engine is connected later by `serve` itself.
    let existing = match (keystore_path.exists(), std::env::var("DANTE_PASSPHRASE")) {
        (true, Ok(pass)) => {
            let bytes = std::fs::read(&keystore_path)?;
            let identity = keystore::open(&bytes, pass.as_bytes())?;
            Some(
                Engine::connect_with_progress(
                    identity,
                    &relay,
                    params,
                    pow,
                    store_path.clone(),
                    Some(&progress),
                )
                .await?,
            )
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
            progress: Some(progress),
        },
    })
}

/// Render one step for the boot screen. The label is written here rather than
/// in JS so the UI stays a dumb renderer of whatever the engine reports.
fn step_payload(step: &BootStep) -> serde_json::Value {
    let (id, label, detail) = match step {
        BootStep::DiscoveringRelays { bootstrap } => (
            "discovering",
            "Finding relays".to_string(),
            format!("asking {bootstrap} bootstrap node(s) on the DHT"),
        ),
        BootStep::ConnectingRelay { endpoints } => (
            "connecting",
            "Connecting to the network".to_string(),
            if *endpoints > 1 {
                format!("{endpoints} relays, first to answer wins")
            } else {
                "contacting the relay".to_string()
            },
        ),
        BootStep::RelayConnected => ("connected", "Relay connected".to_string(), String::new()),
        BootStep::OpeningStore => (
            "store",
            "Unlocking local data".to_string(),
            "decrypting your message history".to_string(),
        ),
        BootStep::RestoringState {
            channels,
            conversations,
        } => (
            "restoring",
            "Restoring your servers".to_string(),
            format!("{channels} channel(s), {conversations} conversation(s)"),
        ),
        BootStep::FetchingIce => (
            "ice",
            "Setting up voice".to_string(),
            "fetching STUN/TURN servers".to_string(),
        ),
        BootStep::PublishingKeyPackage => (
            "keypackage",
            "Publishing call keys".to_string(),
            "so others can add you to group calls".to_string(),
        ),
        BootStep::Announcing { pow_bits } => (
            "announcing",
            "Proving identity".to_string(),
            format!("solving {pow_bits}-bit proof-of-work — the slow one"),
        ),
        BootStep::PublishingPrekeys => (
            "prekeys",
            "Publishing your keys".to_string(),
            "so people can start conversations with you".to_string(),
        ),
        BootStep::Syncing => (
            "syncing",
            "Syncing the ledger".to_string(),
            "catching up on what you missed".to_string(),
        ),
        BootStep::Ready => ("ready", "Ready".to_string(), String::new()),
        BootStep::Failed { error } => ("failed", "Startup failed".to_string(), error.clone()),
        // `BootStep` is `#[non_exhaustive]`: a step added in the core must not
        // stop the desktop build, and an unknown step is still worth showing.
        other => ("step", format!("{other:?}"), String::new()),
    };
    json!({ "step": id, "label": label, "detail": detail })
}

/// The boot screen's escape hatch: startup failed, but local data still works,
/// so let the user in anyway.
#[tauri::command]
fn open_app_anyway(app: AppHandle) {
    show_app(&app);
}

/// Swap the boot screen for the real UI.
fn show_app(app: &AppHandle) {
    let url = app.state::<AppUrl>().0.lock().ok().and_then(|u| u.clone());
    let Some(url) = url else { return };
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    match url.parse() {
        Ok(parsed) => {
            if let Err(e) = window.navigate(parsed) {
                eprintln!("dante-desktop: could not open the UI: {e}");
            }
        }
        Err(e) => eprintln!("dante-desktop: bad UI url {url}: {e}"),
    }
}

fn main() -> Result<()> {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .manage(AppUrl(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![open_app_anyway])
        .setup(|app| {
            // The window comes up first, before any engine work, so startup is
            // something you watch rather than something you wait out.
            let window =
                WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                    .title("DaNTe")
                    .inner_size(1100.0, 720.0)
                    .min_inner_size(800.0, 500.0)
                    .center()
                    .build()?;

            tray::hide_on_close(&window);
            tray::install(app)?;

            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = start(handle.clone()).await {
                    eprintln!("dante-desktop: startup failed: {e:#}");
                    let _ = handle.emit(
                        "boot",
                        step_payload(&BootStep::Failed {
                            error: e.to_string(),
                        }),
                    );
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .map_err(|e| anyhow::anyhow!("tauri runtime: {e}"))
}

/// Everything that happens behind the boot screen.
async fn start(app: AppHandle) -> Result<()> {
    // Every step the engine reports becomes an event on the boot screen. The
    // `Ready` / `Failed` steps also drive the swap to the real UI, so the
    // window changes the moment the engine says it can.
    let sink: dante_core::BootProgress = {
        let app = app.clone();
        Arc::new(move |step: BootStep| {
            let _ = app.emit("boot", step_payload(&step));
            if matches!(step, BootStep::Ready) {
                show_app(&app);
            }
        })
    };

    let Prepared {
        listener,
        port,
        existing,
        boot,
    } = prepare(sink).await?;

    *app.state::<AppUrl>().0.lock().unwrap() = Some(format!("http://127.0.0.1:{port}/"));

    // Bridge the OS mic/speaker to whichever call is connected, and watch for
    // messages worth a notification. Both talk to the service over localhost.
    let _audio = audio::spawn(port);
    notify::spawn(app.clone(), port);

    // If there was no keystore to unlock, the page onboards: there is no
    // startup left to narrate, so show it right away.
    if existing.is_none() {
        show_app(&app);
    }

    dante_cli::serve::run_on(existing, listener, boot)
        .await
        .map_err(|e| anyhow::anyhow!("UI service exited: {e:#}"))
}
