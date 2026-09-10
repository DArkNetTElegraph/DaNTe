//! Native OS notifications for messages that arrive while you are not looking.
//!
//! The web UI already badges unread counts and retitles the tab, but a desktop
//! app is expected to reach you when it is behind another window or minimised
//! to the tray. This polls the same localhost API the page uses
//! (`GET /api/messages?since=`) and raises a system notification for anything
//! addressed to you.
//!
//! Deliberately quiet:
//! - nothing fires while the window is focused — you can already see it;
//! - your own outgoing lines never notify;
//! - a burst is collapsed into one summary rather than N toasts;
//! - message *text* stays out of the body unless the window is merely
//!   unfocused rather than hidden, so a locked-screen preview cannot leak a
//!   conversation. Hidden/tray → sender only.

use std::time::Duration;

use serde_json::Value;
use tauri::{AppHandle, Manager};
use tauri_plugin_notification::NotificationExt;

/// Poll interval. The engine's own tick is 700ms, so this adds little.
const POLL: Duration = Duration::from_millis(1200);

/// More than this many new messages in one poll and we summarise instead of
/// listing them.
const BURST: usize = 3;

/// Start the watcher against the local service on `port`.
pub fn spawn(app: AppHandle, port: u16) {
    std::thread::Builder::new()
        .name("dante-notify".into())
        .spawn(move || run(app, port))
        .expect("spawn dante notification thread");
}

fn run(app: AppHandle, port: u16) {
    // Start from "now": whatever is already in the log was there before the app
    // opened, and replaying history as notifications would be obnoxious.
    let mut cursor = latest_seq(port).unwrap_or(0);

    loop {
        std::thread::sleep(POLL);

        let items = match fetch(port, cursor) {
            Some(v) => v,
            None => continue,
        };
        if items.is_empty() {
            continue;
        }
        if let Some(max) = items.iter().filter_map(|i| i["seq"].as_u64()).max() {
            cursor = cursor.max(max);
        }

        // Focused means you are already reading it.
        let (visible, focused) = window_state(&app);
        if focused {
            continue;
        }

        let worth: Vec<&Value> = items.iter().filter(|i| notifiable(i)).collect();
        if worth.is_empty() {
            continue;
        }

        if worth.len() > BURST {
            notify(&app, "DaNTe", &format!("{} new messages", worth.len()));
            continue;
        }

        for item in worth {
            let (title, body) = describe(item, visible);
            notify(&app, &title, &body);
        }
    }
}

/// Whether the main window is (visible, focused). A window that is hidden to
/// the tray is neither.
fn window_state(app: &AppHandle) -> (bool, bool) {
    match app.get_webview_window("main") {
        Some(w) => (
            w.is_visible().unwrap_or(false),
            w.is_focused().unwrap_or(false),
        ),
        None => (false, false),
    }
}

/// Only real inbound conversation is worth interrupting for. System lines,
/// edits, presence and our own sent messages are not.
fn notifiable(item: &Value) -> bool {
    let kind = item["kind"].as_str().unwrap_or("");
    if !matches!(kind, "message" | "channel" | "file") {
        return false;
    }
    let from = item["from"].as_str().unwrap_or("");
    // `serve` labels our own lines "you"; a system line has no peer/channel.
    if from.is_empty() || from == "you" {
        return false;
    }
    if kind == "message" && item["peer"].as_str().unwrap_or("").is_empty() {
        return false; // a sys line rendered in the DM log
    }
    true
}

/// `(title, body)` for one item. `visible` gates whether message text is shown
/// at all — see the module note on previews.
fn describe(item: &Value, visible: bool) -> (String, String) {
    let from = item["from"].as_str().unwrap_or("someone");
    let kind = item["kind"].as_str().unwrap_or("");

    let title = match kind {
        "channel" => {
            let ch = item["channel_name"].as_str().unwrap_or("a channel");
            format!("{from} in #{ch}")
        }
        _ => from.to_string(),
    };

    if kind == "file" {
        let name = item["filename"].as_str().unwrap_or("a file");
        return (title, format!("sent {name}"));
    }
    if !visible {
        return (title, "sent you a message".into());
    }

    let text = item["text"].as_str().unwrap_or("");
    let mut body: String = text.chars().take(140).collect();
    if text.chars().count() > 140 {
        body.push('…');
    }
    if body.trim().is_empty() {
        body = "sent you a message".into();
    }
    (title, body)
}

fn notify(app: &AppHandle, title: &str, body: &str) {
    // A notification that cannot be shown (permission denied, no daemon) must
    // never take the app down with it.
    if let Err(e) = app.notification().builder().title(title).body(body).show() {
        eprintln!("dante-desktop: notification failed: {e}");
    }
}

fn fetch(port: u16, since: u64) -> Option<Vec<Value>> {
    let raw =
        crate::localapi::http(port, "GET", &format!("/api/messages?since={since}"), "").ok()?;
    match serde_json::from_str::<Value>(&raw).ok()? {
        Value::Array(v) => Some(v),
        _ => None,
    }
}

/// Highest `seq` currently in the log, so a fresh start does not replay.
fn latest_seq(port: u16) -> Option<u64> {
    Some(
        fetch(port, 0)?
            .iter()
            .filter_map(|i| i["seq"].as_u64())
            .max()
            .unwrap_or(0),
    )
}
