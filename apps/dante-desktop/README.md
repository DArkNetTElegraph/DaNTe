# dante-desktop

The DaNTe engine + web UI in a native window, via [Tauri 2](https://tauri.app).

It is a **thin shell**: on launch it starts the same engine-behind-HTTP service
that `dante serve` runs (`dante_cli::serve`) on an ephemeral `127.0.0.1` port,
then points a webview at it. Every feature — onboarding, DMs, servers/channels,
roles, reactions, custom emoji, contacts, block list, safety numbers — comes
from `crates/dante-cli` unchanged. The desktop build's job over time is the
*native* layer: window/menus, OS notifications, tray, deep links, auto-update.

Two native pieces are already here: **`src/menu.rs`** builds the application
menu bar (About/Hide/Quit, Close Window, Edit, Window) — the OS menu bar on
macOS, the window's own on Windows and Linux, via Tauri 2's unified
`tauri::menu` API — and **`src/audio.rs`** bridges the OS microphone
and speaker to live calls — 1:1 and group. It runs on its own thread (`cpal`
streams are `!Send`), captures + encodes Opus once with `crates/dante-audio`,
fans the frames out to every `connected` leg in `/api/calls`, decodes each leg
with its own Opus decoder, and plays a summed mix. The mic opens only while at
least one leg is connected and is released when the last one ends. This is why
`dante-audio` is a dependency here and not in `dante-cli` — it links `libopus`
and the platform audio stack, which the workspace build does not assume.

## Why it's detached from the workspace

Tauri and the audio bridge need system libraries a bare workspace build should
not assume (`webkit2gtk-4.1` + `libsoup-3` and the ALSA/libopus stack on Linux;
WebView2/WASAPI on Windows; WKWebView/CoreAudio on macOS). So this crate has its
own `[workspace]` and is **not** a member of the root workspace —
`cargo build --workspace` at the repo root skips it. Build it explicitly from
this directory. CI builds it in a dedicated Linux/Windows/macOS job with its own
fmt and clippy, so the detachment cannot hide a break.

## Prerequisites

- Rust ≥ 1.91 (the OpenMLS floor `dante-core` declares)
- The Tauri CLI: `cargo install tauri-cli --version '^2'` (gives `cargo tauri`)
- Platform WebView deps — see
  <https://tauri.app/start/prerequisites/>. On Debian/Ubuntu:
  ```
  sudo apt install libwebkit2gtk-4.1-dev libsoup-3.0-dev \
                   build-essential curl wget file libssl-dev \
                   libayatana-appindicator3-dev librsvg2-dev
  ```
  On Fedora:
  ```
  sudo dnf install webkit2gtk4.1-devel libsoup3-devel gtk3-devel \
                   librsvg2-devel libappindicator-gtk3-devel \
                   opus-devel alsa-lib-devel openssl-devel
  ```
  The audio bridge additionally links **libopus** and the platform audio stack
  (`libopus-dev` + `libasound2-dev` on Debian, in the Fedora list above).

  On **Windows** nothing needs installing — WebView2 ships with the OS and the
  audio backend is WASAPI — but `audiopus_sys` has no system libopus to find,
  so it builds the vendored copy with CMake. That copy still declares
  `cmake_minimum_required(VERSION <3.5)`, which CMake 4 refuses outright, so
  set CMake's documented escape hatch before building:
  ```
  $env:CMAKE_POLICY_VERSION_MINIMUM = "3.5"
  ```
  CI sets the same variable. It can go away once `audiopus_sys` ships a libopus
  that configures under CMake 4 unaided.

  On **macOS** nothing needs installing for the webview or audio backend
  either — WKWebView and CoreAudio both ship with the OS — but, as on
  Windows, `audiopus_sys` has no system libopus to find on a fresh machine.
  Installing one via Homebrew lets it link that instead of building the
  vendored copy from source:
  ```
  brew install pkg-config opus
  ```
  CI does the same. Skip this and the build still works — it falls back to
  the vendored CMake build, which needs the same
  `CMAKE_POLICY_VERSION_MINIMUM` escape hatch as Windows.
- Nothing else: `icons/icon.png` is committed (a 512x512 mesh mark). It is the
  *source* icon — `generate_context!` embeds it, so the crate will not compile
  without one. `cargo tauri icon icons/icon.png` regenerates the full platform
  set (`.ico` / `.icns` / the sized PNGs); those are generated artefacts and
  stay untracked. Replace the source with real artwork whenever you have it.

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

Group calls use the peer-to-peer mesh. The relay-hosted SFU offered by
`dante serve --sfu` is deliberately not available here: the native audio
bridge has no SFrame layer, so the relay would receive plaintext Opus. See
[`docs/SFU.md`](../../docs/SFU.md).

## Build a bundle

```sh
cargo tauri icon icons/icon.png   # regenerate the full platform icon set first
cargo tauri build
```

Produces platform installers under `target/release/bundle/` (`.dmg`/`.app` on
macOS, `.msi`/`.exe` (NSIS) on Windows, `.deb`/`.rpm`/`.AppImage` on Linux).

## Release

Pushing a `v*` tag runs `.github/workflows/release.yml`, whose `desktop-bundle`
job does exactly the two commands above on all three platforms and attaches
the resulting installers to the GitHub release, alongside the CLI/relay
binaries from `linux-x86_64`'s job (see
[`docs/REPRODUCIBLE_BUILDS.md`](../../docs/REPRODUCIBLE_BUILDS.md) for those).

**These bundles are unsigned.** Tauri's bundler runs unmodified with no
signing secrets configured, so:

- **macOS** Gatekeeper blocks the `.app` on first launch ("cannot be opened
  because the developer cannot be verified") until the user right-click →
  Open's past it once, or the maintainer notarizes releases.
- **Windows** SmartScreen shows an "unrecognized app" warning until the
  maintainer buys and wires in an Authenticode certificate.
- **Linux** packages are unaffected — neither `.deb`/`.rpm` nor `.AppImage`
  require a signature to install, though a repository could still want one.

Real code-signing needs the maintainer to provision certificates this project
does not have and this repo's CI cannot generate on its own:

- an Apple Developer ID application certificate + a notarization credential
  (an app-specific password or an App Store Connect API key), for macOS;
- a Windows code-signing (Authenticode) certificate, for the `.msi`/`.exe`.

Tauri's own [code-signing guide](https://tauri.app/distribute/sign/) documents
the exact environment variables its bundler reads once those exist (for
macOS: `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`,
`APPLE_SIGNING_IDENTITY`, plus notarization credentials). Nothing here reads
them yet — wiring them into `desktop-bundle` as GitHub secrets is a deliberate
follow-up, not an oversight, because getting the plumbing subtly wrong (a
secret that's silently never read) is worse than an honestly-unsigned build
that says so.
