//! `dante` — a headless DaNTe client for development and demos.
//!
//! ```text
//! dante gen  --out KEYSTORE                       # generate an identity
//! dante fp   --keystore KEYSTORE                  # print the fingerprint
//! dante chat --keystore KEYSTORE --relay ADDR     # interactive session
//!            [--pow-bits N] [--hint NAME]
//! ```
//!
//! The keystore passphrase is read from `DANTE_PASSPHRASE`.
//!
//! In `chat`, lines starting with `/` are commands:
//! `/to <fingerprint>`, `/whoami`, `/peer`, `/quit`. Any other line is sent as
//! a message to the current peer.

use std::{collections::HashMap, time::Duration};

use anyhow::{Context, Result};
use dante_core::Engine;
use dante_crypto::{pow::Difficulty, sign::SignPublic};
use dante_dm::PreKeySecrets;
use dante_identity::{id::IdentityId, keystore, Identity};
use dante_ledger::LedgerParams;
use tokio::io::{AsyncBufReadExt, BufReader};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn passphrase() -> Result<String> {
    std::env::var("DANTE_PASSPHRASE").context("set DANTE_PASSPHRASE to the keystore passphrase")
}

fn arg_value(args: &HashMap<String, String>, key: &str) -> Result<String> {
    args.get(key)
        .cloned()
        .with_context(|| format!("missing --{key}"))
}

fn parse_flags(mut it: impl Iterator<Item = String>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    while let Some(a) = it.next() {
        if let Some(name) = a.strip_prefix("--") {
            if let Some((k, v)) = name.split_once('=') {
                out.insert(k.to_string(), v.to_string());
            } else {
                out.insert(name.to_string(), it.next().unwrap_or_default());
            }
        }
    }
    out
}

fn short_fp(idk: &[u8; 32]) -> String {
    match SignPublic::from_bytes(idk) {
        Ok(pk) => IdentityId::of(&pk)
            .to_base32()
            .split('-')
            .next()
            .unwrap_or("????")
            .to_string(),
        Err(_) => "????".to_string(),
    }
}

fn parse_fingerprint(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    let id = if s.contains(' ') {
        IdentityId::from_words(s)
    } else {
        IdentityId::from_base32(s)
    }
    .map_err(|_| anyhow::anyhow!("not a valid base32 or word-phrase fingerprint"))?;
    Ok(*id.as_bytes())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dante_cli=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let flags = parse_flags(args);

    match cmd.as_str() {
        "gen" => cmd_gen(&flags),
        "fp" => cmd_fp(&flags),
        "chat" => cmd_chat(&flags).await,
        _ => {
            eprintln!(
                "usage:\n  dante gen  --out KEYSTORE\n  dante fp   --keystore KEYSTORE\n  \
                 dante chat --keystore KEYSTORE --relay ADDR [--pow-bits N] [--hint NAME]"
            );
            std::process::exit(2);
        }
    }
}

fn cmd_gen(flags: &HashMap<String, String>) -> Result<()> {
    let out = arg_value(flags, "out")?;
    let pass = passphrase()?;
    let identity = Identity::generate(now_ms());
    let bytes = keystore::seal(&identity, pass.as_bytes())?;
    std::fs::write(&out, bytes).with_context(|| format!("writing {out}"))?;
    println!("identity written to {out}");
    println!("fingerprint (base32): {}", identity.id().to_base32());
    println!("fingerprint (words):  {}", identity.id().to_words());
    Ok(())
}

fn load_identity(flags: &HashMap<String, String>) -> Result<Identity> {
    let path = arg_value(flags, "keystore")?;
    let bytes = std::fs::read(&path).with_context(|| format!("reading {path}"))?;
    Ok(keystore::open(&bytes, passphrase()?.as_bytes())?)
}

fn cmd_fp(flags: &HashMap<String, String>) -> Result<()> {
    let id = load_identity(flags)?.id();
    println!("base32: {}", id.to_base32());
    println!("words:  {}", id.to_words());
    Ok(())
}

async fn cmd_chat(flags: &HashMap<String, String>) -> Result<()> {
    let identity = load_identity(flags)?;
    let relay = arg_value(flags, "relay")?;
    let hint = flags.get("hint").cloned().unwrap_or_default();
    let bits: u8 = flags
        .get("pow-bits")
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);

    let params = LedgerParams {
        min_announce_pow_bits: bits,
        min_liveness_pow_bits: bits.saturating_sub(4).max(1),
        ..Default::default()
    };
    let difficulty = Difficulty {
        m_cost_kib: 16_384,
        t_cost: 2,
        bits,
    };

    eprintln!("connecting to relay {relay} ...");
    let mut engine = Engine::connect(
        identity,
        PreKeySecrets::generate(50),
        &relay,
        params,
        difficulty,
    )
    .await?;
    let my_fp = engine.identity().id().to_base32();

    eprintln!("announcing (solving proof of work, {bits} bits) ...");
    engine.announce(&hint, now_ms()).await?;
    engine.publish_prekeys().await?;
    engine.sync(now_ms()).await?;

    println!("you are {my_fp}");
    println!(
        "commands: /to <fingerprint>   /file <path>   /whoami   /peer   /quit\n\
         (received files are written to ./dante-recv-<name>)"
    );

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let mut peer: Option<[u8; 32]> = None;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let now = now_ms();
                let _ = engine.sync(now).await;
                match engine.receive_all(now).await {
                    Ok(items) => {
                        for item in items {
                            match item {
                                dante_core::Inbound::Message(m) => {
                                    println!("<{}> {}", short_fp(&m.from_idk), m.text);
                                }
                                dante_core::Inbound::File { from_idk, filename, data } => {
                                    let safe = filename
                                        .rsplit(['/', '\\'])
                                        .next()
                                        .unwrap_or("file")
                                        .replace(['/', '\\', '\0'], "_");
                                    let out = format!("dante-recv-{safe}");
                                    match std::fs::write(&out, &data) {
                                        Ok(()) => println!(
                                            "<{}> sent file \"{}\" ({} bytes) -> {}",
                                            short_fp(&from_idk), filename, data.len(), out
                                        ),
                                        Err(e) => eprintln!("could not save received file: {e}"),
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!("receive error: {e}"),
                }
            }
            line = lines.next_line() => {
                match line {
                    Ok(Some(l)) => {
                        if handle_line(&mut engine, &mut peer, &l).await? {
                            break;
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    eprintln!("bye");
    Ok(())
}

/// Returns `Ok(true)` to quit.
async fn handle_line(engine: &mut Engine, peer: &mut Option<[u8; 32]>, line: &str) -> Result<bool> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(false);
    }
    if let Some(rest) = line.strip_prefix('/') {
        let mut parts = rest.splitn(2, char::is_whitespace);
        match parts.next().unwrap_or_default() {
            "quit" | "q" => return Ok(true),
            "whoami" => println!("you are {}", engine.identity().id().to_base32()),
            "peer" => match peer {
                Some(p) => println!("peer: {}", IdentityId::from_bytes(*p).to_base32()),
                None => println!("no peer set (use /to <fingerprint>)"),
            },
            "to" => match parts.next() {
                Some(fp) => match parse_fingerprint(fp) {
                    Ok(id) => {
                        *peer = Some(id);
                        println!("peer set to {}", IdentityId::from_bytes(id).to_base32());
                    }
                    Err(e) => println!("bad fingerprint: {e}"),
                },
                None => println!("usage: /to <fingerprint>"),
            },
            "file" => match (*peer, parts.next()) {
                (Some(p), Some(path)) => match std::fs::read(path) {
                    Ok(data) => {
                        let name = std::path::Path::new(path)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("file");
                        match engine.send_file(&p, name, &data, now_ms()).await {
                            Ok(()) => println!("sent \"{name}\" ({} bytes)", data.len()),
                            Err(e) => println!("send failed: {e}"),
                        }
                    }
                    Err(e) => println!("cannot read {path}: {e}"),
                },
                (None, _) => println!("set a peer first: /to <fingerprint>"),
                (_, None) => println!("usage: /file <path>"),
            },
            other => println!("unknown command: /{other}"),
        }
        return Ok(false);
    }

    let Some(p) = *peer else {
        println!("set a peer first: /to <fingerprint>");
        return Ok(false);
    };
    match engine.send_dm(&p, line, now_ms()).await {
        Ok(()) => {}
        Err(dante_core::CoreError::UnknownPeer) => {
            bail_soft("peer not in your ledger yet — they must announce; try again shortly")
        }
        Err(e) => bail_soft(&format!("send failed: {e}")),
    }
    Ok(false)
}

fn bail_soft(msg: &str) {
    println!("{msg}");
}
