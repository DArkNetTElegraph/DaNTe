//! Auto-update: check the release manifest, offer it in the UI, and install
//! on request.
//!
//! The updater plugin (`tauri-plugin-updater`) does the actual network fetch
//! and signature verification; this module is just the glue between it and
//! the webview — storing the `Update` a check finds so a later, separate
//! command can act on it (the JS side only ever gets a version string in
//! the event payload, never the `Update` value itself), and turning
//! "found an update" into the `dante://update-available` event
//! `crates/dante-cli/web/index.html`'s `setupDesktopUpdatePrompt` listens
//! for.

use std::sync::Mutex;

use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_updater::{Update, UpdaterExt};

/// The most recently found update, if any and not yet installed. Holding at
/// most one is deliberate: a check that finds nothing, or a second check
/// while one is already pending, should not need special-casing on the JS
/// side — there is exactly one "the" update to install at any time.
#[derive(Default)]
pub struct PendingUpdate(Mutex<Option<Update>>);

/// Check for an update; if one is found, store it and tell the UI. Safe to
/// call repeatedly (a timer and the menu item both do) — an error or "no
/// update" is only logged, never surfaced as a failure to the user, since
/// an unreachable manifest (offline, GitHub down) isn't something worth
/// interrupting anyone over.
pub async fn check_for_updates(app: AppHandle) {
    let updater = match app.updater() {
        Ok(u) => u,
        Err(e) => {
            eprintln!("dante-desktop: updater unavailable: {e}");
            return;
        }
    };
    match updater.check().await {
        Ok(Some(update)) => {
            let version = update.version.clone();
            eprintln!("dante-desktop: update {version} available");
            *app.state::<PendingUpdate>().0.lock().unwrap() = Some(update);
            let _ = app.emit(
                "dante://update-available",
                serde_json::json!({ "version": version }),
            );
        }
        Ok(None) => eprintln!("dante-desktop: no update available"),
        Err(e) => eprintln!("dante-desktop: update check failed: {e}"),
    }
}

/// Download, verify, and install the update [`check_for_updates`] found and
/// stashed, then restart into it. Errors (network failure mid-download, a
/// signature that doesn't verify) are handed back to the caller — the JS
/// side shows them inline in the toast rather than this module deciding how
/// to surface them.
#[tauri::command]
pub async fn install_pending_update(app: AppHandle) -> Result<(), String> {
    let update = app
        .state::<PendingUpdate>()
        .0
        .lock()
        .unwrap()
        .take()
        .ok_or_else(|| "no update is pending".to_string())?;
    update
        .download_and_install(|_chunk, _total| {}, || {})
        .await
        .map_err(|e| e.to_string())?;
    // The installer has already replaced this build's files on disk;
    // nothing left to do here but hand off to the new one.
    app.request_restart();
    Ok(())
}
