#!/usr/bin/env bash
# One-shot setup + launch for Linux: detects your distro, installs the Rust
# toolchain and whatever system packages are needed, builds DaNTe, starts a
# local relay (unless you point it at one you already have), and launches
# either the browser-based `dante serve` UI or the native desktop app.
#
# This automates the manual steps in README.md ("Building") and
# apps/dante-desktop/README.md ("Prerequisites") — read those if you'd rather
# do it by hand, or if this script refuses your distro.
#
# Usage: bash scripts/setup-linux.sh [OPTIONS]
set -euo pipefail

ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

if [ -t 1 ]; then
  c_info=$'\033[1;34m'; c_warn=$'\033[1;33m'; c_err=$'\033[1;31m'; c_off=$'\033[0m'
else
  c_info=""; c_warn=""; c_err=""; c_off=""
fi
info() { printf '%s==>%s %s\n' "$c_info" "$c_off" "$1"; }
warn() { printf '%s==>%s %s\n' "$c_warn" "$c_off" "$1" >&2; }
die()  { printf '%s==>%s %s\n' "$c_err" "$c_off" "$1" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: bash scripts/setup-linux.sh [OPTIONS]

  --cli          Build & run the CLI + `dante serve` web UI. Default when
                 the terminal isn't interactive (e.g. piped from curl); asked
                 interactively otherwise.
  --desktop      Build & run the native Tauri desktop app instead. Installs
                 the platform WebView/GTK/audio dev packages too — a bigger
                 install than --cli.
  --relay ADDR   Connect to an existing relay instead of starting a local one
                 (e.g. --relay 203.0.113.5:9944, or an .onion address).
                 Default: start `dante-relay --listen 127.0.0.1:9944` so a
                 first run is fully self-contained.
  --build-only   Install requirements and build, but don't launch anything.
  --skip-deps    Don't touch system packages at all (you've already got
                 them, or you're re-running after a first successful setup).
  --yes, -y      Don't ask for confirmation before installing packages.
  --help, -h     This message.

DaNTe runs no infrastructure of its own — the relay this script starts is
YOUR relay, on your machine, exactly like docs/RUNNING_A_RELAY.md describes.
EOF
}

MODE=""
RELAY_ADDR=""
ASSUME_YES=0
BUILD_ONLY=0
SKIP_DEPS=0

while [ $# -gt 0 ]; do
  case "$1" in
    --cli) MODE="cli" ;;
    --desktop) MODE="desktop" ;;
    --relay) RELAY_ADDR="${2:?--relay needs an address}"; shift ;;
    --build-only) BUILD_ONLY=1 ;;
    --skip-deps) SKIP_DEPS=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --help|-h) usage; exit 0 ;;
    *) die "Unknown option: $1 (see --help)" ;;
  esac
  shift
done

confirm() {
  [ "$ASSUME_YES" = 1 ] && return 0
  if [ ! -t 0 ]; then
    warn "Non-interactive shell — assuming yes for: $1"
    return 0
  fi
  printf '%s [Y/n] ' "$1"
  read -r reply
  case "$reply" in
    [nN]*) return 1 ;;
    *) return 0 ;;
  esac
}

# ---------- 1. must be Linux ----------
[ "$(uname -s)" = "Linux" ] || die "This script is for Linux. macOS: 'brew install opus pkg-config', then rustup.rs and apps/dante-desktop/README.md. Windows: scripts/setup-windows.ps1."

# ---------- 2. detect distro family ----------
if [ ! -r /etc/os-release ]; then
  die "No /etc/os-release — can't detect your distro. Install Rust (https://rustup.rs) and the packages listed in README.md / apps/dante-desktop/README.md by hand."
fi
# shellcheck disable=SC1091
. /etc/os-release
distro_id="${ID:-unknown}"
distro_like="${ID_LIKE:-}"

family=""
case " $distro_id $distro_like " in
  *" fedora "*|*" rhel "*|*" centos "*) family="fedora" ;;
  *" arch "*|*" manjaro "*) family="arch" ;;
  *" debian "*|*" ubuntu "*) family="debian" ;;
  *)
    die "Unrecognized distro (ID='$distro_id', ID_LIKE='$distro_like'). Supported: Fedora, Arch, Debian/Ubuntu and their derivatives (e.g. Manjaro, Pop!_OS, Linux Mint). Install manually — see README.md."
    ;;
esac
info "Detected $distro_id (package family: $family)"

pkg_install() {
  case "$family" in
    fedora) sudo dnf install -y "$@" ;;
    arch) sudo pacman -S --needed --noconfirm "$@" ;;
    debian) sudo apt-get update -qq && sudo apt-get install -y "$@" ;;
  esac
}

# ---------- 3. pick a mode ----------
if [ -z "$MODE" ]; then
  if [ -t 0 ]; then
    printf 'Set up (1) CLI + browser UI, or (2) native desktop app? [1] '
    read -r reply
    case "$reply" in
      2) MODE="desktop" ;;
      *) MODE="cli" ;;
    esac
  else
    MODE="cli"
  fi
fi
info "Mode: $MODE"

# ---------- 4. system packages ----------
# Package names per docs/RUNNING_A_RELAY.md's build note and
# apps/dante-desktop/README.md's Prerequisites section. Arch's aren't
# documented there (no official Arch install steps exist yet) — these are
# the standard `extra`-repo names as of this writing; if a rename has
# happened since, `pacman -Ss <name>` will find the current one.
base_pkgs=()
desktop_pkgs=()
case "$family" in
  fedora)
    base_pkgs=(gcc gcc-c++ make pkgconf-pkg-config openssl-devel curl git)
    desktop_pkgs=(webkit2gtk4.1-devel libsoup3-devel gtk3-devel librsvg2-devel
                  libappindicator-gtk3-devel opus-devel alsa-lib-devel)
    ;;
  arch)
    base_pkgs=(base-devel pkgconf openssl curl git)
    desktop_pkgs=(webkit2gtk-4.1 libsoup3 gtk3 librsvg libayatana-appindicator
                  opus alsa-lib)
    ;;
  debian)
    base_pkgs=(build-essential pkg-config libssl-dev curl git)
    desktop_pkgs=(libwebkit2gtk-4.1-dev libsoup-3.0-dev
                  libayatana-appindicator3-dev librsvg2-dev libopus-dev
                  libasound2-dev)
    ;;
esac

if [ "$SKIP_DEPS" = 1 ]; then
  info "Skipping system package install (--skip-deps)."
else
  want=("${base_pkgs[@]}")
  [ "$MODE" = desktop ] && want+=("${desktop_pkgs[@]}")
  info "System packages needed: ${want[*]}"
  if confirm "Install these via your package manager (needs sudo)?"; then
    pkg_install "${want[@]}"
  else
    warn "Skipping package install — the build may fail if something's missing."
  fi
fi

# ---------- 5. Rust toolchain ----------
if command -v cargo >/dev/null 2>&1; then
  info "Rust already installed: $(rustc --version)"
else
  info "Rust not found."
  confirm "Install it now via rustup (https://rustup.rs)?" || die "Rust is required to build DaNTe."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile default
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi
# rust-toolchain.toml pins the exact version this repo builds with; rustup
# fetches it automatically on the first `cargo` invocation below, so there's
# nothing else to pin here.

# ---------- 6. build ----------
if [ "$MODE" = desktop ]; then
  command -v cargo-tauri >/dev/null 2>&1 || {
    info "Installing the Tauri CLI (cargo install tauri-cli)..."
    cargo install tauri-cli --version '^2' --locked
  }
  if [ "$BUILD_ONLY" = 1 ]; then
    info "Building desktop app bundles (apps/dante-desktop)..."
    ( cd apps/dante-desktop && cargo tauri icon icons/icon.png && cargo tauri build )
    info "Done — installers are under apps/dante-desktop/target/release/bundle/"
    exit 0
  fi
else
  info "Building dante-cli and dante-relay (release)..."
  cargo build --release -p dante-cli -p dante-relay
  if [ "$BUILD_ONLY" = 1 ]; then
    info "Done — binaries are at target/release/dante and target/release/dante-relay"
    exit 0
  fi
fi

# ---------- 7. launch ----------
relay_pid=""
cleanup() {
  if [ -n "$relay_pid" ]; then
    kill "$relay_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

if [ -z "$RELAY_ADDR" ]; then
  RELAY_ADDR="127.0.0.1:9944"
  info "Starting a local relay on $RELAY_ADDR (Ctrl-C stops both it and the app)..."
  ./target/release/dante-relay --listen "$RELAY_ADDR" &
  relay_pid=$!
  sleep 1
else
  info "Using existing relay at $RELAY_ADDR"
fi

if [ "$MODE" = desktop ]; then
  info "Launching the desktop app..."
  ( cd apps/dante-desktop && DANTE_RELAY="$RELAY_ADDR" cargo tauri dev )
else
  info "Launching dante serve — open the URL it prints below in your browser."
  ./target/release/dante serve --relay "$RELAY_ADDR"
fi
