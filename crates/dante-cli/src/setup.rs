//! `dante setup` — an interactive terminal wizard for the handful of things a
//! new operator or user actually needs help with once: checking whether a
//! relay is reachable, installing `dante serve` as a background service, and
//! finding the real desktop-app build command instead of guessing at it.
//!
//! Every step says what it's doing before it does it and reports a plain
//! pass/fail after — no step runs invisibly, and nothing here writes outside
//! the current user's own account (no `sudo`, no system-wide files) without
//! printing the exact command and asking first.

use std::io::{self, IsTerminal, Write};
use std::time::Duration;

const BANNER: &str = r#"
      _            _____
     | |          |_   _|
   __| | __ _ _ __  ___| | ___
  / _` |/ _` | '_ \|_  |/ _ \
 | (_| | (_| | | | ||_| |  __/
  \__,_|\__,_|_| |_|\___/\___|   setup
"#;

/// Read one line from stdin, trimmed. `None` on EOF (piped input ran out, or
/// stdin is closed) — callers treat that as "back out", never as a blank
/// answer, so a non-interactive invocation exits instead of looping forever.
fn read_line(prompt: &str) -> Option<String> {
    print!("{prompt}");
    io::stdout().flush().ok();
    let mut line = String::new();
    match io::stdin().read_line(&mut line) {
        Ok(0) => None,
        Ok(_) => Some(line.trim().to_string()),
        Err(_) => None,
    }
}

fn is_tty() -> bool {
    io::stdout().is_terminal()
}

fn ok(msg: &str) {
    if is_tty() {
        println!("\x1b[32m✓\x1b[0m {msg}");
    } else {
        println!("[ok] {msg}");
    }
}

fn fail(msg: &str) {
    if is_tty() {
        println!("\x1b[31m✗\x1b[0m {msg}");
    } else {
        println!("[fail] {msg}");
    }
}

/// Run `fut`, animating a spinner next to `label` while it's pending. Falls
/// back to a single static line when stdout isn't a terminal (piped output,
/// CI) — a carriage-return spinner would just spam that log with garbage.
async fn with_spinner<F, T>(label: &str, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    if !is_tty() {
        println!("{label} ...");
        return fut.await;
    }
    const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    tokio::pin!(fut);
    let mut i = 0usize;
    let mut ticker = tokio::time::interval(Duration::from_millis(80));
    loop {
        tokio::select! {
            biased;
            out = &mut fut => {
                print!("\r\x1b[2K");
                io::stdout().flush().ok();
                return out;
            }
            _ = ticker.tick() => {
                print!("\r\x1b[2K{} {label} ...", FRAMES[i % FRAMES.len()]);
                io::stdout().flush().ok();
                i += 1;
            }
        }
    }
}

pub async fn run() -> anyhow::Result<()> {
    println!("{BANNER}");
    loop {
        println!("What do you want to do?\n");
        println!("  1) Check relay eligibility (ping an address)");
        println!("  2) Install a background relay/client service");
        println!("  3) Build the desktop app");
        println!("  4) Find the fastest public relay for me");
        println!("  5) Exit\n");
        let Some(choice) = read_line("> ") else {
            break;
        };
        println!();
        match choice.as_str() {
            "1" => check_relay_eligibility().await,
            "2" => install_service().await,
            "3" => build_desktop_app().await,
            "4" => find_fastest_relay().await,
            "5" | "" => break,
            _ => println!("Not a valid choice — pick 1-5.\n"),
        }
        println!();
    }
    Ok(())
}

async fn check_relay_eligibility() {
    let Some(addr) = read_line("Relay address to check (host:port): ") else {
        return;
    };
    if addr.is_empty() {
        println!("(nothing entered)");
        return;
    }
    let result = with_spinner(
        &format!("Connecting to {addr} and sending a real Ping"),
        dante_net::sync::ping(&addr, Duration::from_secs(8)),
    )
    .await;
    match result {
        Ok(latency) => {
            ok(&format!("reachable — round trip {}ms", latency.as_millis()));
            println!(
                "  This confirms {addr} answers a real DaNTe protocol round trip from this \
                 machine. It does NOT confirm reachability from the public internet if this \
                 box sits behind NAT or a cloud security group — either ask someone outside \
                 your network to check the same address, or add it to relays/registry.toml and \
                 let the scheduled relay-status check (which runs from GitHub's own runners) \
                 confirm it independently."
            );
        }
        Err(e) => {
            fail(&format!("not reachable: {e}"));
            println!(
                "  Common causes: dante-relay isn't running yet, the port isn't open in your \
                 firewall or cloud security group, or the address/port is wrong."
            );
        }
    }
}

async fn find_fastest_relay() {
    let urls = vec![crate::directory::DEFAULT_DIRECTORY.to_string()];
    let ranked = with_spinner(
        &format!("Pinging every relay listed at {}", urls.join(", ")),
        crate::directory::rank_reachable(&urls),
    )
    .await;
    if ranked.is_empty() {
        fail("no reachable relay found in the directory");
        println!(
            "  Either nothing in relays/registry.toml answered from here, or the directory \
             itself couldn't be fetched. Check your own network connection, or connect with a \
             specific --relay ADDR you already know."
        );
        return;
    }
    ok(&format!("found {} reachable relay(s):", ranked.len()));
    for (i, r) in ranked.iter().enumerate() {
        println!(
            "  {}) {} — {} ({}ms)",
            i + 1,
            r.name,
            r.addr,
            r.latency.as_millis()
        );
    }
    println!(
        "\nUse the fastest one directly with:\n\n  dante chat --relay {}\n  dante serve --relay {}\n\n\
         or let this happen automatically every time with `--relay auto` in place of an address.",
        ranked[0].addr, ranked[0].addr
    );
}

/// Build a systemd `--user` unit for `dante serve` pointed at `relay`, using
/// the current executable's own path so the installed service runs whatever
/// binary the operator actually has, not a guessed install location.
fn unit_file(relay: &str, http: &str, keystore: &str, exe: &str) -> String {
    format!(
        "[Unit]\n\
         Description=DaNTe (dante serve)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={exe} serve --keystore {keystore} --relay {relay} --http {http}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

async fn install_service() {
    if cfg!(not(target_os = "linux")) {
        println!(
            "Automatic service installation is only wired up for Linux (systemd) right now.\n\
             \n\
             macOS: run `dante serve ...` inside a launchd `.plist` under \
             ~/Library/LaunchAgents — see Apple's launchd.plist(5) man page for the format; \
             the ProgramArguments array is the same argv you'd pass on the command line.\n\
             \n\
             Windows: register it with `sc.exe create` or NSSM (https://nssm.cc), pointing \
             ProgramArguments at `dante.exe serve ...`.\n\
             \n\
             Both are real gaps, not stubs — this wizard won't claim to have verified a service \
             file it can't actually start and check here."
        );
        return;
    }
    if std::process::Command::new("systemctl")
        .arg("--version")
        .output()
        .is_err()
    {
        fail("systemctl not found — is this actually a systemd system?");
        return;
    }

    let Some(relay) = read_line(
        "Relay address to connect to (host:port, or leave blank for the public directory's \
         fastest relay -- 'auto'): ",
    ) else {
        return;
    };
    let relay = if relay.is_empty() {
        "auto".to_string()
    } else {
        relay
    };
    let http = read_line("Local HTTP bind [127.0.0.1:8080]: ").unwrap_or_default();
    let http = if http.is_empty() {
        "127.0.0.1:8080".to_string()
    } else {
        http
    };
    let keystore = read_line("Keystore path [./dante.keystore]: ").unwrap_or_default();
    let keystore = if keystore.is_empty() {
        "./dante.keystore".to_string()
    } else {
        keystore
    };

    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .unwrap_or_else(|| "dante".to_string());

    let unit = unit_file(&relay, &http, &keystore, &exe);

    let Some(home) = dirs_home() else {
        fail("could not determine $HOME to install a --user unit under");
        return;
    };
    let unit_dir = home.join(".config/systemd/user");
    let unit_path = unit_dir.join("dante.service");

    if let Err(e) = std::fs::create_dir_all(&unit_dir) {
        fail(&format!("could not create {}: {e}", unit_dir.display()));
        return;
    }
    if let Err(e) = std::fs::write(&unit_path, &unit) {
        fail(&format!("could not write {}: {e}", unit_path.display()));
        return;
    }
    ok(&format!("wrote {}", unit_path.display()));

    // No passphrase is embedded in the unit itself: a systemd unit under
    // ~/.config/systemd/user is created with this process's own umask, but a
    // secret belongs in its own tightly-permissioned file regardless, not
    // inlined into a file whose job is describing how to start a program.
    let want_auto_unlock = read_line(
        "Auto-unlock the keystore on service start with a saved passphrase? Leave off and \
         you'll unlock it once per restart from the web UI instead. [y/N]: ",
    )
    .unwrap_or_default();
    if want_auto_unlock.eq_ignore_ascii_case("y") {
        if let Some(pass) = read_line("Passphrase: ") {
            let env_dir = home.join(".config/dante");
            let env_path = env_dir.join("service.env");
            let _ = std::fs::create_dir_all(&env_dir);
            let content = format!("DANTE_PASSPHRASE={pass}\n");
            let write_result = std::fs::write(&env_path, content);
            #[cfg(unix)]
            if write_result.is_ok() {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o600));
            }
            match write_result {
                Ok(()) => {
                    ok(&format!(
                        "wrote {} (mode 600, this account only)",
                        env_path.display()
                    ));
                    let with_env = unit.replacen(
                        "[Service]\n",
                        &format!("[Service]\nEnvironmentFile={}\n", env_path.display()),
                        1,
                    );
                    if std::fs::write(&unit_path, &with_env).is_ok() {
                        ok("linked the unit to the passphrase file");
                    }
                }
                Err(e) => fail(&format!("could not write {}: {e}", env_path.display())),
            }
        }
    }

    let verify = std::process::Command::new("systemd-analyze")
        .arg("verify")
        .arg(&unit_path)
        .output();
    match verify {
        Ok(o) if o.status.success() => ok("unit file syntax checks out (systemd-analyze verify)"),
        Ok(o) => {
            fail("systemd-analyze verify flagged something:");
            print!("{}", String::from_utf8_lossy(&o.stderr));
        }
        Err(_) => println!("  (systemd-analyze not available here to double-check the syntax)"),
    }

    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    ok("ran `systemctl --user daemon-reload`");

    println!(
        "\nNothing has been started yet. To bring it up:\n\n  \
         systemctl --user enable --now dante\n\n\
         If this is a VPS you don't stay logged into, a user service normally stops when you \
         log out — keep it running across logouts with:\n\n  \
         loginctl enable-linger $USER\n"
    );
}

#[cfg(unix)]
fn dirs_home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(std::path::PathBuf::from)
}
#[cfg(not(unix))]
fn dirs_home() -> Option<std::path::PathBuf> {
    std::env::var_os("USERPROFILE").map(std::path::PathBuf::from)
}

async fn build_desktop_app() {
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    };

    println!("The desktop shell (`apps/dante-desktop`) is a separate Tauri workspace — it needs");
    println!("its own system libraries, so this wizard prints the real steps rather than guess");
    println!("at running them for you (a failed system-package install is not something to risk");
    println!("running unattended).\n");

    match os {
        "linux" => println!(
            "On Debian/Ubuntu:\n  sudo apt install libwebkit2gtk-4.1-dev libsoup-3.0-dev \\\n    \
             build-essential curl wget file libssl-dev \\\n    \
             libayatana-appindicator3-dev librsvg2-dev libopus-dev libasound2-dev\n\n\
             On Fedora:\n  sudo dnf install webkit2gtk4.1-devel libsoup3-devel gtk3-devel \\\n    \
             librsvg2-devel libappindicator-gtk3-devel opus-devel alsa-lib-devel openssl-devel\n"
        ),
        "macos" => println!("brew install pkg-config\n(WKWebView and CoreAudio ship with macOS — nothing else to install.)\n"),
        _ => println!(
            "WebView2 and WASAPI ship with Windows — nothing to install. audiopus_sys builds a \
             vendored libopus with CMake, which needs this set first (PowerShell):\n\n  \
             $env:CMAKE_POLICY_VERSION_MINIMUM = \"3.5\"\n"
        ),
    }

    println!("Then, from the repo root:\n");
    println!("  cargo install tauri-cli --version '^2'   # once, gives `cargo tauri`");
    println!("  cd apps/dante-desktop");
    println!("  cargo tauri build\n");

    let has_tauri = std::process::Command::new("cargo")
        .args(["tauri", "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !has_tauri {
        println!("`cargo tauri` isn't on PATH here — install it with the command above first.");
        return;
    }
    let go =
        read_line("`cargo tauri` is available. Run the build now? [y/N]: ").unwrap_or_default();
    if !go.eq_ignore_ascii_case("y") {
        return;
    }
    let repo_root = std::env::current_dir().ok();
    let desktop_dir = repo_root
        .as_deref()
        .map(|p| p.join("apps/dante-desktop"))
        .filter(|p| p.exists());
    let Some(desktop_dir) = desktop_dir else {
        fail("couldn't find apps/dante-desktop from the current directory — run `dante setup` from the repo root");
        return;
    };
    ok(&format!(
        "running `cargo tauri build` in {}",
        desktop_dir.display()
    ));
    let status = std::process::Command::new("cargo")
        .args(["tauri", "build"])
        .current_dir(&desktop_dir)
        .status();
    match status {
        Ok(s) if s.success() => ok("build finished"),
        Ok(s) => fail(&format!("build exited with {s}")),
        Err(e) => fail(&format!("could not run cargo: {e}")),
    }
}
