//! Native application menu bar (App/File/Edit/Window), separate from the
//! tray menu in `tray.rs`. macOS renders this in the top-of-screen bar;
//! Windows and Linux render it as the window's own menu bar — Tauri 2's
//! `tauri::menu` API is unified across all three, unlike Tauri 1.
//!
//! Every item except "Check for Updates…" is a [`PredefinedMenuItem`]: Tauri
//! wires its behaviour (quit, close the focused window, cut/copy/paste into
//! the focused webview element, minimize, fullscreen) into the platform menu
//! itself, so there is no custom `on_menu_event` handling to get wrong for
//! those — unlike the tray menu, which does need one for its own actions.

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::App;

/// Check for an update and log the result. Does not install one: the updater
/// plugin is wired (see `apps/dante-desktop/Cargo.toml` and `tauri.conf.json`)
/// but has no real signing key behind it yet — every check will either fail
/// to reach a real manifest or fail signature verification against the
/// placeholder pubkey, by design, until a maintainer wires a real keypair
/// into the release workflow. See the README's "Auto-update" section.
async fn check_for_updates(app: tauri::AppHandle) {
    use tauri_plugin_updater::UpdaterExt;
    let updater = match app.updater() {
        Ok(u) => u,
        Err(e) => {
            eprintln!("dante-desktop: updater unavailable: {e}");
            return;
        }
    };
    match updater.check().await {
        Ok(Some(update)) => {
            eprintln!(
                "dante-desktop: update {} available (not installed — no install-prompt UI yet)",
                update.version
            );
        }
        Ok(None) => eprintln!("dante-desktop: no update available"),
        Err(e) => eprintln!("dante-desktop: update check failed: {e}"),
    }
}

/// Build and attach the application menu bar.
pub fn install(app: &App) -> tauri::Result<()> {
    let sep = PredefinedMenuItem::separator(app)?;

    // macOS convention: the first menu carries the app's own name and hosts
    // About/Hide/Quit. Non-macOS folds Quit into File instead, but Tauri's
    // unified menu API places this submenu correctly per platform either way.
    let about = PredefinedMenuItem::about(app, Some("About DaNTe"), None)?;
    let check_updates = MenuItem::with_id(
        app,
        "check_updates",
        "Check for Updates…",
        true,
        None::<&str>,
    )?;
    let hide = PredefinedMenuItem::hide(app, Some("Hide DaNTe"))?;
    let hide_others = PredefinedMenuItem::hide_others(app, None)?;
    let show_all = PredefinedMenuItem::show_all(app, None)?;
    let quit = PredefinedMenuItem::quit(app, Some("Quit DaNTe"))?;
    let app_menu = Submenu::with_items(
        app,
        "DaNTe",
        true,
        &[
            &about,
            &check_updates,
            &sep,
            &hide,
            &hide_others,
            &show_all,
            &sep,
            &quit,
        ],
    )?;

    // "Close Window" fires the same window-close request the OS titlebar
    // button does, so it goes through `tray::hide_on_close`'s interception
    // and hides to the tray rather than quitting — consistent with this
    // being a chat client that stays connected when the window closes.
    let close_window = PredefinedMenuItem::close_window(app, Some("Close Window"))?;
    let file_menu = Submenu::with_items(app, "File", true, &[&close_window])?;

    let undo = PredefinedMenuItem::undo(app, None)?;
    let redo = PredefinedMenuItem::redo(app, None)?;
    let cut = PredefinedMenuItem::cut(app, None)?;
    let copy = PredefinedMenuItem::copy(app, None)?;
    let paste = PredefinedMenuItem::paste(app, None)?;
    let select_all = PredefinedMenuItem::select_all(app, None)?;
    let edit_menu = Submenu::with_items(
        app,
        "Edit",
        true,
        &[&undo, &redo, &sep, &cut, &copy, &paste, &select_all],
    )?;

    let minimize = PredefinedMenuItem::minimize(app, None)?;
    let fullscreen = PredefinedMenuItem::fullscreen(app, None)?;
    let window_menu = Submenu::with_items(app, "Window", true, &[&minimize, &fullscreen])?;

    let menu = Menu::with_items(app, &[&app_menu, &file_menu, &edit_menu, &window_menu])?;
    app.set_menu(menu)?;

    app.on_menu_event(|app, event| {
        if event.id().as_ref() == "check_updates" {
            let handle = app.clone();
            tauri::async_runtime::spawn(check_for_updates(handle));
        }
    });

    Ok(())
}
