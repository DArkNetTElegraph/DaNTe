# dante-desktop

The DaNTe engine + web UI in a native window, via [Tauri 2](https://tauri.app).

It is a **thin shell**: on launch it starts the same engine-behind-HTTP service
that `dante serve` runs (`dante_cli::serve`) on an ephemeral `127.0.0.1` port,
then points a webview at it. Every feature — onboarding, DMs, servers/channels,
roles, reactions, custom emoji, contacts, block list, safety numbers — comes
from `crates/dante-cli` unchanged. The desktop build's job over time is the
*native* layer: window/menus, OS notifications, tray, deep links, auto-update.

One native piece is already here: **`src/audio.rs`** bridges the OS microphone
and speaker to a live 1:1 call. It runs on its own thread (`cpal` streams are
`!Send`), captures + encodes Opus with `crates/dante-audio`, and exchanges
frames with the local service over `POST`/`GET /api/call/audio`. It starts the
mic only while a call is in state `connected` and drops it when the call ends.
This is why `dante-audio` is a dependency here and not in `dante-cli` — it links
`libopus` and the platform audio stack, absent from CI.

## Why it's detached from the workspace

Tauri needs system libraries the CI/dev container doesn't have
(`webkit2gtk-4.1` + `libsoup-3` on Linux, WebView2 on Windows, WKWebView on
macOS). So this crate has its own `[workspace]` and is **not** a member of the
root workspace — `cargo build --workspace` at the repo root skips it. Build it
explicitly from this directory.

## Prerequisites

- Rust ≥ 1.85
- The Tauri CLI: `cargo install tauri-cli --version '^2'` (gives `cargo tauri`)
- Platform WebView deps — see
  <https://tauri.app/start/prerequisites/>. On Debian/Ubuntu:
  ```
  sudo apt install libwebkit2gtk-4.1-dev libsoup-3.0-dev \
                   build-essential curl wget file libssl-dev \
                   libayatana-appindicator3-dev librsvg2-dev
  ```
- An icon at `icons/icon.png` (any square PNG; `cargo tauri icon path/to.png`
  regenerates the full set). A placeholder is fine for `cargo tauri dev`.

## Run

```sh
cd apps/dante-desktop
cargo tauri dev
```

Configuration is read from the environment (same names as `dante serve`):

| var | default | meaning |
|---|---|---|
| `DANTE_HOME` | `$HOME/.dante` | keystore + encrypted state directory |
| `DANTE_RELAY` | `127.0.0.1:9944` | comma-separated relay endpoints (failover) |
| `DANTE_PASSPHRASE` | *(unset)* | if set and a keystore exists, unlock at startup; otherwise the window shows the create/import flow |
| `DANTE_POW_BITS` | `20` | proof-of-work difficulty for our own ledger records |

You need a relay reachable at `DANTE_RELAY` — run one with
`cargo run -p dante-relay -- --listen 127.0.0.1:9944` from the repo root.

## Build a bundle

```sh
cargo tauri build
```

Produces platform installers under `target/release/bundle/`.
