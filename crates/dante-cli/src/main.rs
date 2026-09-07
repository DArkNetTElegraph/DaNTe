//! `dante` — a headless DaNTe client for development and demos.
//!
//! ```text
//! dante gen   --out KEYSTORE                       # generate an identity
//! dante fp    --keystore KEYSTORE                  # print the fingerprint
//! dante chat  --keystore KEYSTORE --relay ADDR     # interactive terminal session
//! dante serve --keystore KEYSTORE --relay ADDR     # local web UI
//!             [--http 127.0.0.1:8080] [--pow-bits N] [--hint NAME]
//! ```
//!
//! The keystore passphrase is read from `DANTE_PASSPHRASE`.
//!
//! In `chat`, lines starting with `/` are commands:
//! `/to <fingerprint>`, `/file <path>`, `/whoami`, `/peer`, `/quit`.

mod serve;

use std::{collections::HashMap, time::Duration};

use anyhow::{Context, Result};
use dante_core::Engine;
use dante_crypto::{pow::Difficulty, sign::SignPublic};
use dante_identity::{id::IdentityId, keystore, Identity};
use dante_ledger::LedgerParams;
use tokio::io::{AsyncBufReadExt, BufReader};

pub(crate) fn now_ms() -> u64 {
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

pub(crate) fn parse_fingerprint(s: &str) -> Result<[u8; 32]> {
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
        "serve" => cmd_serve(&flags).await,
        _ => {
            eprintln!(
                "usage:\n  dante gen   --out KEYSTORE\n  dante fp    --keystore KEYSTORE\n  \
                 dante chat  --keystore KEYSTORE --relay ADDR [--pow-bits N] [--hint NAME]\n  \
                 dante serve --keystore KEYSTORE --relay ADDR [--http 127.0.0.1:8080] [--pow-bits N]"
            );
            std::process::exit(2);
        }
    }
}

async fn cmd_serve(flags: &HashMap<String, String>) -> Result<()> {
    let engine = connect_engine(flags).await?;
    let http = flags
        .get("http")
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());
    serve::run(engine, &http).await
}

/// Shared connect + params logic for `chat` and `serve`.
async fn connect_engine(flags: &HashMap<String, String>) -> Result<Engine> {
    let identity = load_identity(flags)?;
    let relay = arg_value(flags, "relay")?;
    let bits: u8 = flags
        .get("pow-bits")
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let params = LedgerParams {
        min_announce_pow_bits: bits,
        min_liveness_pow_bits: bits.saturating_sub(4).max(1),
        ..Default::default()
    };
    // Light Argon2 cost for the local dev path; the deployed network's PoW
    // floor comes from LedgerParams::default() (64 MiB, t=3, 20 bits).
    let difficulty = Difficulty {
        m_cost_kib: 4_096,
        t_cost: 1,
        bits,
    };

    // Encrypted local store: <keystore>.state by default, --state to override,
    // --no-state to run stateless.
    let store_path = if flags.contains_key("no-state") {
        None
    } else if let Some(p) = flags.get("state") {
        Some(std::path::PathBuf::from(p))
    } else {
        Some(std::path::PathBuf::from(format!(
            "{}.state",
            arg_value(flags, "keystore")?
        )))
    };

    eprintln!("connecting to relay {relay} (proof of work: {bits} bits) ...");
    Ok(Engine::connect(identity, &relay, params, difficulty, store_path).await?)
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
    let hint = flags.get("hint").cloned().unwrap_or_default();
    let mut engine = connect_engine(flags).await?;
    let my_fp = engine.identity().id().to_base32();

    if engine.announce_if_stale(&hint, now_ms()).await? {
        eprintln!("announced.");
    } else {
        eprintln!("resumed (announced recently; no proof of work).");
    }
    engine.publish_prekeys().await?;
    engine.sync(now_ms()).await?;

    println!("you are {my_fp}");
    if !engine.history().is_empty() {
        println!(
            "-- {} earlier message(s) in this store --",
            engine.history().len()
        );
        for h in engine.history() {
            let who = if h.outgoing {
                "you".to_string()
            } else {
                short_fp(&h.peer_idk)
            };
            match &h.kind {
                dante_core::HistoryKind::Text(t) => println!("<{who}> {t}"),
                dante_core::HistoryKind::File { filename, size } => {
                    println!("<{who}> [file: {filename} ({size} bytes)]")
                }
            }
        }
    }
    if !engine.channels().is_empty() {
        println!("channels:");
        for c in engine.channels() {
            println!(
                "  #{}  {} / {}",
                IdentityId::from_bytes(c.channel_id).to_base32(),
                c.server_name,
                c.channel_name
            );
        }
    }
    if !engine.channel_history().is_empty() {
        println!(
            "-- {} earlier channel message(s) in this store --",
            engine.channel_history().len()
        );
        for e in engine.channel_history() {
            let who = if e.outgoing {
                "you".to_string()
            } else {
                IdentityId::from_bytes(e.sender)
                    .to_base32()
                    .split('-')
                    .next()
                    .unwrap_or("")
                    .to_string()
            };
            println!(
                "[#{}] <{}> {}",
                IdentityId::from_bytes(e.channel_id)
                    .to_base32()
                    .split('-')
                    .next()
                    .unwrap_or(""),
                who,
                e.text
            );
        }
    }
    println!(
        "commands: /to <fp|#chan>  /server <name>  /channel <root> <name>  \
         /invitelink #<chan> [days] [uses]  /redeem <link>  /kick #<chan> <fp>  \
         /invite #<chan> <fp>  /channels  /file <path>  /whoami  /quit"
    );

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let mut save_tick = tokio::time::interval(Duration::from_secs(15));
    let mut peer: Option<Target> = None;

    loop {
        tokio::select! {
            _ = save_tick.tick() => { let _ = engine.persist(); }
            _ = tick.tick() => {
                let now = now_ms();
                let _ = engine.sync(now).await;
                match engine.poll_channels(now).await {
                    Ok(msgs) => for m in msgs {
                        println!("[#{}] <{}> {}",
                            IdentityId::from_bytes(m.channel_id).to_base32().split('-').next().unwrap_or(""),
                            IdentityId::from_bytes(m.sender).to_base32().split('-').next().unwrap_or(""),
                            m.text);
                    }
                    Err(e) => eprintln!("channel poll error: {e}"),
                }
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
    if let Err(e) = engine.persist() {
        eprintln!("warning: could not save state: {e}");
    }
    eprintln!("bye");
    Ok(())
}

/// The current send target: a DM peer or a channel.
#[derive(Clone, Copy)]
pub(crate) enum Target {
    /// A DM peer, by `IdentityId`.
    Peer([u8; 32]),
    /// A channel, by channel id.
    Channel([u8; 32]),
}

/// Returns `Ok(true)` to quit.
async fn handle_line(engine: &mut Engine, target: &mut Option<Target>, line: &str) -> Result<bool> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(false);
    }
    if let Some(rest) = line.strip_prefix('/') {
        let mut parts = rest.splitn(3, char::is_whitespace);
        let cmd = parts.next().unwrap_or_default();
        let a = parts.next();
        let b = parts.next();
        match cmd {
            "quit" | "q" => return Ok(true),
            "whoami" => println!("you are {}", engine.identity().id().to_base32()),
            "peer" => match target {
                Some(Target::Peer(p)) => {
                    println!("peer: {}", IdentityId::from_bytes(*p).to_base32())
                }
                Some(Target::Channel(c)) => {
                    println!("channel: #{}", IdentityId::from_bytes(*c).to_base32())
                }
                None => println!("no target set (/to <fingerprint> or /to #<channel-id>)"),
            },
            "to" => match a {
                Some(s) if s.starts_with('#') => match parse_fingerprint(&s[1..]) {
                    Ok(id) => {
                        *target = Some(Target::Channel(id));
                        println!("channel set to #{}", IdentityId::from_bytes(id).to_base32());
                    }
                    Err(e) => println!("bad channel id: {e}"),
                },
                Some(s) => match parse_fingerprint(s) {
                    Ok(id) => {
                        *target = Some(Target::Peer(id));
                        println!("peer set to {}", IdentityId::from_bytes(id).to_base32());
                    }
                    Err(e) => println!("bad fingerprint: {e}"),
                },
                None => println!("usage: /to <fingerprint>   or   /to #<channel-id>"),
            },
            "server" => match a {
                Some(name) => match engine.create_server(name, now_ms()).await {
                    Ok(root) => println!(
                        "server \"{name}\" created; root {}",
                        IdentityId::from_bytes(root).to_base32()
                    ),
                    Err(e) => println!("create failed: {e}"),
                },
                None => println!("usage: /server <name>"),
            },
            "channel" => match (a, b) {
                (Some(sfp), Some(name)) => match parse_fingerprint(sfp) {
                    Ok(root) => match engine.create_channel(&root, name, true) {
                        Ok(id) => println!(
                            "channel \"{name}\" -> #{}",
                            IdentityId::from_bytes(id).to_base32()
                        ),
                        Err(e) => println!("create failed: {e}"),
                    },
                    Err(e) => println!("bad server root: {e}"),
                },
                _ => println!("usage: /channel <server-root> <name>"),
            },
            "invite" => match (a, b) {
                (Some(chan), Some(fp)) => {
                    let chan = chan.strip_prefix('#').unwrap_or(chan);
                    match (parse_fingerprint(chan), parse_fingerprint(fp)) {
                        (Ok(cid), Ok(pid)) => {
                            match engine.invite_to_channel(&cid, &pid, now_ms()).await {
                                Ok(()) => println!("invited"),
                                Err(e) => println!("invite failed: {e}"),
                            }
                        }
                        _ => println!("bad channel id or fingerprint"),
                    }
                }
                _ => println!("usage: /invite #<channel-id> <fingerprint>"),
            },
            "invitelink" => match a {
                Some(chan) => {
                    let chan = chan.strip_prefix('#').unwrap_or(chan);
                    let mut rest = b.unwrap_or("").split_whitespace();
                    let days: f64 = rest.next().and_then(|s| s.parse().ok()).unwrap_or(7.0);
                    let uses: u32 = rest.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                    match parse_fingerprint(chan) {
                        Ok(cid) => {
                            let ttl = (days * 86_400_000.0) as u64;
                            match engine.create_invite_link(&cid, ttl, uses, now_ms()) {
                                Ok(link) => println!("{link}"),
                                Err(e) => println!("could not create link: {e}"),
                            }
                        }
                        Err(e) => println!("bad channel id: {e}"),
                    }
                }
                None => println!("usage: /invitelink #<channel-id> [days] [max-uses]"),
            },
            "redeem" => match a {
                Some(link) => {
                    let full = b.map_or_else(|| link.to_string(), |b| format!("{link} {b}"));
                    match engine.redeem_invite(full.trim(), now_ms()).await {
                        Ok(()) => println!("redeemed — you'll join once the host is online"),
                        Err(e) => println!("redeem failed: {e}"),
                    }
                }
                None => println!("usage: /redeem <invite-link>"),
            },
            "kick" => match (a, b) {
                (Some(chan), Some(fp)) => {
                    let chan = chan.strip_prefix('#').unwrap_or(chan);
                    match (parse_fingerprint(chan), parse_fingerprint(fp)) {
                        (Ok(cid), Ok(mid)) => {
                            match engine.remove_from_channel(&cid, &mid, now_ms()).await {
                                Ok(()) => println!("removed"),
                                Err(e) => println!("remove failed: {e}"),
                            }
                        }
                        _ => println!("bad channel id or fingerprint"),
                    }
                }
                _ => println!("usage: /kick #<channel-id> <fingerprint>"),
            },
            "channels" => {
                for c in engine.channels() {
                    println!(
                        "  #{}  {} / {}",
                        IdentityId::from_bytes(c.channel_id).to_base32(),
                        c.server_name,
                        c.channel_name
                    );
                }
            }
            "file" => match (*target, a) {
                (Some(Target::Peer(p)), Some(path)) => match std::fs::read(path) {
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
                (Some(Target::Channel(_)), _) => println!("files are DM-only for now"),
                (None, _) => println!("set a peer first: /to <fingerprint>"),
                (_, None) => println!("usage: /file <path>"),
            },
            other => println!("unknown command: /{other}"),
        }
        return Ok(false);
    }

    match *target {
        Some(Target::Peer(p)) => match engine.send_dm(&p, line, now_ms()).await {
            Ok(()) => {}
            Err(dante_core::CoreError::UnknownPeer) => {
                bail_soft("peer not in your ledger yet — they must announce; try again shortly")
            }
            Err(e) => bail_soft(&format!("send failed: {e}")),
        },
        Some(Target::Channel(c)) => {
            if let Err(e) = engine.send_channel(&c, line, now_ms()).await {
                bail_soft(&format!("channel send failed: {e}"));
            }
        }
        None => println!("set a target: /to <fingerprint>   or   /to #<channel-id>"),
    }
    Ok(false)
}

fn bail_soft(msg: &str) {
    println!("{msg}");
}
