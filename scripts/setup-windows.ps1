<#
.SYNOPSIS
  One-shot setup + launch for Windows: checks/installs the Rust toolchain,
  the MSVC build tools Rust needs, and (for the desktop app) the Tauri CLI
  and WebView2 runtime, builds DaNTe, starts a local relay (unless you point
  it at one you already have), and launches either the browser-based
  `dante serve` UI or the native desktop app.

  This automates the manual steps in README.md ("Building") and
  apps/dante-desktop/README.md ("Prerequisites") — read those if you'd
  rather do it by hand.

.PARAMETER Mode
  "cli" (default) builds & runs the CLI + `dante serve` web UI. "desktop"
  builds & runs the native Tauri app instead — a bigger install (WebView2,
  vendored libopus via CMake).

.PARAMETER Relay
  Connect to an existing relay instead of starting a local one, e.g.
  -Relay 203.0.113.5:9944. Default: start `dante-relay --listen
  127.0.0.1:9944` so a first run is fully self-contained.

.PARAMETER BuildOnly
  Install requirements and build, but don't launch anything.

.PARAMETER SkipDeps
  Don't install anything — assume Rust, MSVC tools, and (for -Mode desktop)
  WebView2/Tauri CLI are already present.

.PARAMETER Yes
  Don't ask for confirmation before installing anything.

.EXAMPLE
  .\scripts\setup-windows.ps1
.EXAMPLE
  .\scripts\setup-windows.ps1 -Mode desktop -Yes
.EXAMPLE
  .\scripts\setup-windows.ps1 -Relay 203.0.113.5:9944
#>
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingWriteHost', '',
    Justification = 'Interactive setup script: colored status/warning/error lines to the console are the intended UX for a human running this by hand, not a data stream another command consumes.'
)]
param(
    [ValidateSet("cli", "desktop")]
    [string]$Mode,
    [string]$Relay,
    [switch]$BuildOnly,
    [switch]$SkipDeps,
    [switch]$Yes
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Info($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Warn($msg) { Write-Host "==> $msg" -ForegroundColor Yellow }
function Die($msg) { Write-Host "==> $msg" -ForegroundColor Red; exit 1 }

function Confirm([string]$prompt) {
    if ($Yes) { return $true }
    if (-not [Environment]::UserInteractive) {
        Warn "Non-interactive session — assuming yes for: $prompt"
        return $true
    }
    $reply = Read-Host "$prompt [Y/n]"
    return -not ($reply -match '^[nN]')
}

# ---------- 1. must be Windows ----------
if (-not $IsWindows -and $PSVersionTable.PSVersion.Major -ge 6) {
    Die "This script is for Windows. Linux: scripts/setup-linux.sh. macOS: 'brew install opus pkg-config', then rustup.rs and apps/dante-desktop/README.md."
}

# ---------- 2. pick a mode ----------
if (-not $Mode) {
    if ([Environment]::UserInteractive) {
        $reply = Read-Host "Set up (1) CLI + browser UI, or (2) native desktop app? [1]"
        $Mode = if ($reply -eq "2") { "desktop" } else { "cli" }
    } else {
        $Mode = "cli"
    }
}
Info "Mode: $Mode"

# ---------- 3. winget availability ----------
$haveWinget = [bool](Get-Command winget -ErrorAction SilentlyContinue)
if (-not $haveWinget -and -not $SkipDeps) {
    Warn "winget isn't available — this script can still check requirements, but can't auto-install anything missing. Install winget (App Installer, from the Microsoft Store) or pass -SkipDeps and install manually."
}

function Install-WithWinget([string]$id, [string]$displayName) {
    if (-not $haveWinget) {
        Warn "$displayName is missing and winget isn't available. Install it manually, then re-run."
        return
    }
    if (Confirm "Install $displayName via winget ($id)?") {
        winget install --id $id --silent --accept-package-agreements --accept-source-agreements
    } else {
        Warn "Skipping $displayName — the build may fail without it."
    }
}

# ---------- 4. Rust toolchain ----------
if (Get-Command cargo -ErrorAction SilentlyContinue) {
    Info "Rust already installed: $(rustc --version)"
} elseif (-not $SkipDeps) {
    Info "Rust not found."
    if (Confirm "Install it now via rustup?") {
        $rustupExe = Join-Path $env:TEMP "rustup-init.exe"
        Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupExe
        & $rustupExe -y --profile default --default-host x86_64-pc-windows-msvc
        Remove-Item $rustupExe -ErrorAction SilentlyContinue
        $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
    } else {
        Die "Rust is required to build DaNTe."
    }
} else {
    Die "Rust not found and -SkipDeps was given."
}
# rust-toolchain.toml pins the exact version this repo builds with; rustup
# fetches it automatically on the first `cargo` invocation below, so there's
# nothing else to pin here.

# ---------- 5. MSVC build tools (the C linker Rust needs on Windows) ----------
# link.exe only exists on PATH inside a "Developer" shell, so probe via
# vswhere (ships with any VS/Build Tools install) instead of Get-Command.
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$haveMsvc = $false
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath
    $haveMsvc = [bool]$vsPath
}
if ($haveMsvc) {
    Info "MSVC build tools already installed."
} elseif (-not $SkipDeps) {
    Warn "MSVC build tools (the C++ linker Rust needs) not found."
    Install-WithWinget "Microsoft.VisualStudio.2022.BuildTools" "Visual Studio Build Tools (C++ workload)"
    Warn "If this just installed for the first time, close and reopen this shell before continuing — PATH/registry changes need a fresh process."
} else {
    Warn "MSVC build tools not found and -SkipDeps was given — the build may fail."
}

# ---------- 6. desktop-only extras ----------
if ($Mode -eq "desktop") {
    # audiopus_sys vendors libopus and configures it with CMake; the vendored
    # copy's CMakeLists predates CMake 4's minimum-version floor. See
    # apps/dante-desktop/README.md's Prerequisites section.
    $env:CMAKE_POLICY_VERSION_MINIMUM = "3.5"

    $webview2Key = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    $haveWebView2 = Test-Path $webview2Key
    if ($haveWebView2) {
        Info "WebView2 runtime already installed."
    } elseif (-not $SkipDeps) {
        Warn "WebView2 runtime not found (usually ships with Windows 10/11 — this may be a stripped install)."
        Install-WithWinget "Microsoft.EdgeWebView2Runtime" "WebView2 runtime"
    }

    if (-not (Get-Command cargo-tauri -ErrorAction SilentlyContinue)) {
        Info "Installing the Tauri CLI (cargo install tauri-cli)..."
        cargo install tauri-cli --version '^2' --locked
    }
}

# ---------- 7. build ----------
if ($Mode -eq "desktop") {
    if ($BuildOnly) {
        Info "Building desktop app bundles (apps\dante-desktop)..."
        Push-Location "apps\dante-desktop"
        try {
            cargo tauri icon icons\icon.png
            cargo tauri build
        } finally {
            Pop-Location
        }
        Info "Done — installers are under apps\dante-desktop\target\release\bundle\"
        exit 0
    }
} else {
    Info "Building dante-cli and dante-relay (release)..."
    cargo build --release -p dante-cli -p dante-relay
    if ($BuildOnly) {
        Info "Done — binaries are at target\release\dante.exe and target\release\dante-relay.exe"
        exit 0
    }
}

# ---------- 8. launch ----------
$relayProc = $null
try {
    if (-not $Relay) {
        $Relay = "127.0.0.1:9944"
        Info "Starting a local relay on $Relay (Ctrl-C stops both it and the app)..."
        $relayProc = Start-Process -FilePath ".\target\release\dante-relay.exe" `
            -ArgumentList "--listen", $Relay -PassThru -NoNewWindow
        Start-Sleep -Seconds 1
    } else {
        Info "Using existing relay at $Relay"
    }

    if ($Mode -eq "desktop") {
        Info "Launching the desktop app..."
        $env:DANTE_RELAY = $Relay
        Push-Location "apps\dante-desktop"
        try {
            cargo tauri dev
        } finally {
            Pop-Location
        }
    } else {
        Info "Launching dante serve — open the URL it prints below in your browser."
        & ".\target\release\dante.exe" serve --relay $Relay
    }
} finally {
    if ($relayProc -and -not $relayProc.HasExited) {
        Stop-Process -Id $relayProc.Id -Force -ErrorAction SilentlyContinue
    }
}
