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
//! The keystore passphrase is read from `DANTE_PASSPHRASE`. `--relay` accepts a
//! comma-separated list of `host:port` endpoints; the client uses the first
//! reachable one and fails over to the rest if the connection drops.
//!
//! Built with `--features p2p`, `--relay` also accepts a libp2p multiaddr
//! (`/ip4/…/tcp/N/p2p/<peer-id>`) — the relay wire then rides a `/dante/relay/1`
//! stream — or the literal `dht` with `--bootstrap <multiaddr,...>`, which
//! enters the DHT and discovers relays from their `dante/relay/v1` provider
//! records. `chat`/`serve` also accept `--p2p` / `--p2p-listen <multiaddr>` to
//! run a node for the DHT key-directory + ledger-gossip fallback.
//!
//! In `chat`, lines starting with `/` are commands:
//! `/to <fingerprint>`, `/file <path>`, `/whoami`, `/peer`, `/quit`.

use std::{collections::HashMap, time::Duration};

use anyhow::{Context, Result};
use dante_cli::{now_ms, parse_fingerprint, serve};
use dante_core::Engine;
use dante_crypto::{pow::Difficulty, sign::SignPublic};
use dante_identity::{id::IdentityId, keystore, Identity};
use dante_ledger::LedgerParams;
use tokio::io::{AsyncBufReadExt, BufReader};

fn passphrase() -> Result<String> {
    std::env::var("DANTE_PASSPHRASE").context("set DANTE_PASSPHRASE to the keystore passphrase")
}

fn arg_value(args: &HashMap<String, String>, key: &str) -> Result<String> {
    args.get(key)
        .cloned()
        .with_context(|| format!("missing --{key}"))
}

/// The `--relay` value, translating the discovery aliases `dht` / `p2p` (and a
/// bare `--bootstrap` with no `--relay`) into
/// `p2p-discover:<bootstrap-multiaddr,...>` that `Engine::connect` understands.
///
/// Bootstrap multiaddrs come from `--bootstrap`, then the `DANTE_BOOTSTRAP`
/// environment variable (comma/space-separated), then the compiled-in
/// [`DEFAULT_BOOTSTRAP`] — so a distro or an operator can point at a network
/// without a flag, and once well-known addresses exist a bare `dante serve`
/// needs no relay config at all.
/// Merged DHT bootstrap multiaddrs: `--bootstrap`, then `DANTE_BOOTSTRAP`,
/// then the compiled-in [`DEFAULT_BOOTSTRAP`]; de-duplicated, order preserved.
fn bootstrap_list(flags: &HashMap<String, String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |s: &str| {
        for a in s
            .split([',', ' ', '\t', '\n'])
            .map(str::trim)
            .filter(|a| !a.is_empty())
        {
            let a = a.to_string();
            if !out.contains(&a) {
                out.push(a);
            }
        }
    };
    if let Some(b) = flags.get("bootstrap") {
        push(b);
    }
    if let Ok(env) = std::env::var("DANTE_BOOTSTRAP") {
        push(&env);
    }
    for a in DEFAULT_BOOTSTRAP {
        push(a);
    }
    out
}

fn relay_endpoint(flags: &HashMap<String, String>) -> Result<String> {
    let boot = bootstrap_list(flags).join(",");

    let relay = match flags.get("relay") {
        Some(r) => r.clone(),
        None if !boot.is_empty() => "dht".to_string(),
        None => anyhow::bail!(
            "missing --relay (or --bootstrap / DANTE_BOOTSTRAP for DHT relay discovery)"
        ),
    };
    if relay == "dht" || relay == "p2p" {
        if boot.is_empty() {
            anyhow::bail!(
                "--relay {relay} needs bootstrap multiaddrs (--bootstrap or DANTE_BOOTSTRAP)"
            );
        }
        Ok(format!("p2p-discover:{boot}"))
    } else {
        Ok(relay)
    }
}

/// Compiled-in DHT bootstrap multiaddrs. Empty until a DaNTe network with
/// well-known entry points is deployed; `--bootstrap` / `DANTE_BOOTSTRAP`
/// override or extend it.
const DEFAULT_BOOTSTRAP: &[&str] = &[];

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

/// Lowercase hex of a 16-byte DM message id.
fn hex16(id: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in id {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parse 32 hex chars back to a 16-byte DM message id.
fn parse_hex16(s: &str) -> Option<[u8; 16]> {
    let s = s.trim();
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
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
        "bot" => cmd_bot(&flags).await,
        "revoke" => cmd_revoke(&flags).await,
        _ => {
            eprintln!(
                "usage:\n  dante gen    --out KEYSTORE\n  dante fp     --keystore KEYSTORE\n  \
                 dante chat   --keystore KEYSTORE --relay ADDR [--pow-bits N] [--hint NAME]\n  \
                 dante serve  --keystore KEYSTORE --relay ADDR [--http 127.0.0.1:8080] [--pow-bits N]\n  \
                 dante bot    --keystore KEYSTORE --relay ADDR [--name NAME] [--auto-join] [--pow-bits N]\n  \
                 dante revoke --keystore KEYSTORE --relay ADDR [--reason compromised|superseded|retired] --yes"
            );
            std::process::exit(2);
        }
    }
}

async fn cmd_serve(flags: &HashMap<String, String>) -> Result<()> {
    use std::path::PathBuf;

    let http = flags
        .get("http")
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let relay = relay_endpoint(flags)?;
    let bits: u8 = flags
        .get("pow-bits")
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let params = LedgerParams {
        min_announce_pow_bits: bits,
        min_liveness_pow_bits: bits.saturating_sub(4).max(1),
        // Match the light dev solver below; a deployed network keeps the
        // Default (REGISTRATION-strength) Argon2 floor.
        min_pow_m_cost_kib: 4_096,
        min_pow_t_cost: 1,
        ..Default::default()
    };
    let pow = Difficulty {
        m_cost_kib: 4_096,
        t_cost: 1,
        bits,
    };
    let keystore_path = PathBuf::from(
        flags
            .get("keystore")
            .cloned()
            .unwrap_or_else(|| "dante.keystore".to_string()),
    );
    let store_path = if flags.contains_key("no-state") {
        None
    } else if let Some(p) = flags.get("state") {
        Some(PathBuf::from(p))
    } else {
        Some(PathBuf::from(format!("{}.state", keystore_path.display())))
    };

    // If the keystore already exists and DANTE_PASSPHRASE is set, open it up
    // front; otherwise the web page's onboarding flow creates / unlocks one.
    let existing = match (keystore_path.exists(), std::env::var("DANTE_PASSPHRASE")) {
        (true, Ok(pass)) => {
            let bytes = std::fs::read(&keystore_path)
                .with_context(|| format!("reading {}", keystore_path.display()))?;
            let identity = keystore::open(&bytes, pass.as_bytes())?;
            eprintln!("connecting to relay {relay} (proof of work: {bits} bits) ...");
            let mut e = Engine::connect(identity, &relay, params, pow, store_path.clone()).await?;
            maybe_enable_p2p(&mut e, flags).await;
            Some(e)
        }
        _ => None,
    };

    let boot = serve::Bootstrap {
        relay,
        keystore_path,
        store_path,
        params,
        pow,
    };
    serve::run(existing, &http, boot).await
}

/// Shared connect + params logic for `chat` and `serve`.
async fn connect_engine(flags: &HashMap<String, String>) -> Result<Engine> {
    let identity = load_identity(flags)?;
    let relay = relay_endpoint(flags)?;
    let bits: u8 = flags
        .get("pow-bits")
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let params = LedgerParams {
        min_announce_pow_bits: bits,
        min_liveness_pow_bits: bits.saturating_sub(4).max(1),
        // Match the light dev solver below; a deployed network keeps the
        // Default (REGISTRATION-strength) Argon2 floor.
        min_pow_m_cost_kib: 4_096,
        min_pow_t_cost: 1,
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
    let mut engine = Engine::connect(identity, &relay, params, difficulty, store_path).await?;
    maybe_enable_p2p(&mut engine, flags).await;
    Ok(engine)
}

/// Bring up an optional libp2p node when `--p2p` (listen on `/ip4/0.0.0.0/tcp/0`)
/// or `--p2p-listen <multiaddr>` is passed; `--bootstrap a,b,c` gives peer
/// multiaddrs to dial. Best-effort — a failure just logs and leaves the engine
/// on the relay alone.
#[cfg(feature = "p2p")]
async fn maybe_enable_p2p(engine: &mut Engine, flags: &HashMap<String, String>) {
    let listen = flags.get("p2p-listen").map(String::as_str);
    if listen.is_none() && !flags.contains_key("p2p") {
        return;
    }
    let listen = listen.unwrap_or("/ip4/0.0.0.0/tcp/0");
    let boot = bootstrap_list(flags);
    match engine.enable_p2p(listen, &boot).await {
        Ok(addrs) => {
            eprintln!(
                "p2p node up (peer id {})",
                engine.p2p_peer_id().unwrap_or_default()
            );
            for a in addrs {
                eprintln!("  p2p dial addr: {a}");
            }
        }
        Err(e) => eprintln!("p2p disabled: {e}"),
    }
}

#[cfg(not(feature = "p2p"))]
async fn maybe_enable_p2p(_engine: &mut Engine, flags: &HashMap<String, String>) {
    if flags.contains_key("p2p") || flags.contains_key("p2p-listen") {
        eprintln!("--p2p ignored: this binary was built without the `p2p` feature (rebuild with `--features p2p`)");
    }
}

async fn cmd_revoke(flags: &HashMap<String, String>) -> Result<()> {
    use dante_core::RevokeReason;

    let reason = match flags.get("reason").map(String::as_str) {
        Some("compromised") => RevokeReason::Compromised,
        Some("superseded") => RevokeReason::Superseded,
        Some("retired") => RevokeReason::Retired,
        None | Some("unspecified") => RevokeReason::Unspecified,
        Some(other) => anyhow::bail!("unknown --reason {other:?}"),
    };
    if !flags.contains_key("yes") {
        anyhow::bail!(
            "revocation is permanent and cannot be undone. \
             Re-run with --yes to confirm."
        );
    }

    let mut engine = connect_engine(flags).await?;
    let fp = engine.identity().id().to_base32();
    engine.announce_if_stale("", now_ms()).await?;
    engine.sync(now_ms()).await?;
    engine.revoke_identity(reason, now_ms()).await?;
    engine.sync(now_ms()).await?;
    engine.persist()?;
    println!("identity {fp} revoked ({reason:?}). It can no longer be messaged.");
    Ok(())
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
         /vchannel <root> <name>  /vc join|leave #<chan>  \
         /invitelink #<chan> [days] [uses]  /redeem <link>  \
         /kick|/ban #<chan> <fp>  /unban <root> <fp>  \
         /autokick <root> <days|off>  /roles <root>  /role <root> <name> [kick|mute|manage]  \
         /assignrole <root> <fp> <id> [remove]  /joinpw <root> <pw|off> [current]  \
         /emoji <root> <name> <path|remove>  /sticker <root> <name> <path|remove>  \
         /sound <root> <name> <path|remove>  \
         /renamechannel #<chan> <name>  \
         /discover  /publish <root> <on|off> [summary]  /joindisc <root> [pw]  \
         /react #<chan> <seq> <emoji> [-]  /pin|/unpin #<chan> <seq>  /pins #<chan>  \
         /editdm <fp> <msg-id> <text>  /deldm <fp> <msg-id>  /forward <#chan|fp> <origin> <text>  \
         /invite #<chan> <fp>  /acceptinvite #<chan>  /declineinvite #<chan>  \
         /channels  /file <path>  /whoami  /quit"
    );

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let mut save_tick = tokio::time::interval(Duration::from_secs(15));
    let mut peer: Option<Target> = None;
    let mut voice_sig = String::new();

    loop {
        tokio::select! {
            _ = save_tick.tick() => { let _ = engine.persist(); }
            _ = tick.tick() => {
                let now = now_ms();
                #[cfg(feature = "p2p")]
                let _ = engine.poll_p2p(now).await;
                let _ = engine.sync(now).await;
                match engine.poll_channels(now).await {
                    Ok(msgs) => for m in msgs {
                        let fwd = m.forwarded_from.as_deref()
                            .map(|o| format!("[\u{21aa} fwd from {o}] ")).unwrap_or_default();
                        println!("[#{} {}] <{}> {}{}",
                            IdentityId::from_bytes(m.channel_id).to_base32().split('-').next().unwrap_or(""),
                            m.seq,
                            IdentityId::from_bytes(m.sender).to_base32().split('-').next().unwrap_or(""),
                            fwd, m.text);
                    }
                    Err(e) => eprintln!("channel poll error: {e}"),
                }
                for r in engine.take_reactions() {
                    println!("  {} {} {}",
                        if r.removed { "－" } else { "＋" }, r.emoji,
                        IdentityId::from_bytes(r.member).to_base32().split('-').next().unwrap_or(""));
                }
                for e in engine.take_edits() {
                    let cid = IdentityId::from_bytes(e.channel_id).to_base32();
                    let cid = cid.split('-').next().unwrap_or("");
                    if e.deleted {
                        println!("  [#{cid} {}] (message deleted)", e.target_seq);
                    } else {
                        println!("  [#{cid} {}] (edited) {}", e.target_seq, e.text.unwrap_or_default());
                    }
                }
                for p in engine.take_pins() {
                    let cid = IdentityId::from_bytes(p.channel_id).to_base32();
                    let cid = cid.split('-').next().unwrap_or("");
                    println!("  [#{cid} {}] {}", p.target_seq,
                        if p.pinned { "\u{1f4cc} pinned" } else { "unpinned" });
                }
                for e in engine.take_dm_edits() {
                    let who = short_fp(&e.peer_idk);
                    let mid = hex16(&e.msg_id);
                    if e.deleted {
                        println!("  <{who}> ({mid}) (message deleted)");
                    } else {
                        println!("  <{who}> ({mid}) (edited) {}", e.text.unwrap_or_default());
                    }
                }
                match engine.receive_all(now).await {
                    Ok(items) => {
                        for item in items {
                            match item {
                                dante_core::Inbound::Message(m) => {
                                    if m.msg_id == [0u8; 16] {
                                        println!("<{}> {}", short_fp(&m.from_idk), m.text);
                                    } else {
                                        println!("<{}> ({}) {}", short_fp(&m.from_idk), hex16(&m.msg_id), m.text);
                                    }
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
                                dante_core::Inbound::IncomingCall { from_idk } => {
                                    println!("\u{1f4de} {} is calling — /answer or /hangup <their fingerprint>",
                                        short_fp(&from_idk));
                                }
                                dante_core::Inbound::CallEnded { from_idk } => {
                                    println!("\u{1f4de} call with {} ended", short_fp(&from_idk));
                                }
                                dante_core::Inbound::GroupCallInvite { channel_id, from_idk } => {
                                    // The full base32 id is what `/groupcall join` parses.
                                    let cid = IdentityId::from_bytes(channel_id).to_base32();
                                    println!("\u{1f4de} {} invited you to a group call — /groupcall join #{cid}",
                                        short_fp(&from_idk));
                                }
                                dante_core::Inbound::GroupCallMembersChanged { channel_id } => {
                                    println!("\u{1f4de} group call #{} membership changed",
                                        IdentityId::from_bytes(channel_id).to_base32().split('-').next().unwrap_or(""));
                                }
                                // WebRTC signalling (voice channels and 1:1 calls)
                                // is browser-only; the terminal client has no
                                // media path.
                                dante_core::Inbound::VoiceSignal { .. } => {}
                                dante_core::Inbound::CallSignal { .. } => {}
                                dante_core::Inbound::ChannelBacklog { entries, .. } => {
                                    for (_who, _at, text) in entries {
                                        println!("  · {text}");
                                    }
                                }
                                dante_core::Inbound::ChannelInvite {
                                    channel_id, channel_name, server_name, ..
                                } => {
                                    // Print the full base32 id — that is what
                                    // `/acceptinvite` / `/declineinvite` parse.
                                    let cid = IdentityId::from_bytes(channel_id).to_base32();
                                    println!(
                                        "\u{1f4e8} invited to #{channel_name} in {server_name} — \
                                         /acceptinvite #{cid} or /declineinvite #{cid}",
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!("receive error: {e}"),
                }
                for u in engine.poll_calls(now).await.unwrap_or_default() {
                    println!("\u{1f4de} call {} -> {:?}",
                        IdentityId::from_bytes(u.peer).to_base32().split('-').next().unwrap_or(""),
                        u.state);
                }
                let _ = engine.poll_group_calls(now).await;
                let _ = engine.send_voice_presence(now).await;
                let vps = engine.poll_voice(now).await;
                let sig: String = vps.iter()
                    .filter(|v| !v.members.is_empty())
                    .map(|v| format!("{}:{}", IdentityId::from_bytes(v.channel_id).to_base32(), v.members.len()))
                    .collect::<Vec<_>>().join("|");
                if sig != voice_sig {
                    voice_sig = sig;
                    for vp in &vps {
                        if vp.members.is_empty() { continue; }
                        let cid = IdentityId::from_bytes(vp.channel_id).to_base32();
                        let who: Vec<String> = vp.members.iter()
                            .map(|m| IdentityId::from_bytes(*m).to_base32().split('-').next().unwrap_or("").to_string())
                            .collect();
                        println!("\u{1f50a} #{} — {}",
                            cid.split('-').next().unwrap_or(""), who.join(", "));
                    }
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

/// Headless bot bridge: a line-delimited JSON protocol on stdio. Each stdin
/// line is one command object (`{"cmd":"send","channel":"…","text":"…"}`);
/// each stdout line is one event object (`{"event":"message",…}`). The bot is
/// an ordinary DaNTe identity — nothing here is bot-specific at the protocol
/// level; this is just `dante-core` driven programmatically.
///
/// Commands: `whoami`, `announce {name}`, `channels`, `join {invite[,password]}`,
/// `accept {channel}`, `send {channel,text}`, `reply {channel,seq,text}`,
/// `react {channel,seq,emoji[,remove]}`, `dm {to,text}`.
/// Events: `ready`, `channel`, `message`, `dm`, `invite`, `joining`,
/// `accepted`, `sent`, `reacted`, `dm_sent`, `announced`, `whoami`,
/// `channels`, `join_requested`, `error`.
async fn cmd_bot(flags: &HashMap<String, String>) -> Result<()> {
    let name = flags
        .get("name")
        .cloned()
        .unwrap_or_else(|| "bot".to_string());
    let auto_join = flags.contains_key("auto-join");
    let mut engine = connect_engine(flags).await?;
    let my_fp = engine.identity().id().to_base32();
    let my_head = my_fp.split('-').next().unwrap_or(&my_fp).to_string();

    engine.announce_if_stale(&name, now_ms()).await?;
    engine.publish_prekeys().await?;
    engine.sync(now_ms()).await?;

    bot_emit(&serde_json::json!({
        "event": "ready", "fingerprint": my_fp, "name": name, "auto_join": auto_join,
    }));
    for c in engine.channels() {
        bot_emit(&serde_json::json!({
            "event": "channel",
            "channel": IdentityId::from_bytes(c.channel_id).to_base32(),
            "channel_name": c.channel_name,
            "server": c.server_name,
        }));
    }

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut tick = tokio::time::interval(Duration::from_millis(400));
    let mut save_tick = tokio::time::interval(Duration::from_secs(10));
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    let term = async {
        match sigterm.as_mut() {
            Some(s) => {
                s.recv().await;
            }
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(term);

    loop {
        tokio::select! {
            _ = save_tick.tick() => { let _ = engine.persist(); }
            _ = tokio::signal::ctrl_c() => break,
            _ = &mut term => break,
            _ = tick.tick() => {
                let now = now_ms();
                #[cfg(feature = "p2p")]
                let _ = engine.poll_p2p(now).await;
                let _ = engine.sync(now).await;

                if let Ok(msgs) = engine.poll_channels(now).await {
                    for m in msgs {
                        let mention = m.text.contains(&format!("@{my_fp}"))
                            || m.text.contains(&format!("@{my_head}"));
                        bot_emit(&serde_json::json!({
                            "event": "message",
                            "channel": IdentityId::from_bytes(m.channel_id).to_base32(),
                            "seq": m.seq,
                            "from": IdentityId::from_bytes(m.sender).to_base32(),
                            "text": m.text,
                            "reply_to": m.reply_to,
                            "mention": mention,
                        }));
                    }
                }
                if let Ok(items) = engine.receive_all(now).await {
                    // A Welcome / backlog changes channel membership — checkpoint
                    // it now rather than waiting for the periodic save.
                    if !items.is_empty() {
                        let _ = engine.persist();
                    }
                    for item in items {
                        match item {
                            dante_core::Inbound::Message(m) => bot_emit(&serde_json::json!({
                                "event": "dm",
                                "from": IdentityId::from_bytes(m.from_idk).to_base32(),
                                "text": m.text,
                            })),
                            dante_core::Inbound::ChannelInvite {
                                channel_id, channel_name, server_name, from_idk,
                            } => {
                                let cid = IdentityId::from_bytes(channel_id).to_base32();
                                if auto_join {
                                    match engine.accept_channel_invite(&channel_id, now).await {
                                        Ok(()) => bot_emit(&serde_json::json!({
                                            "event": "joining", "channel": cid,
                                            "channel_name": channel_name, "server": server_name,
                                        })),
                                        Err(e) => bot_err(&e.to_string()),
                                    }
                                } else {
                                    bot_emit(&serde_json::json!({
                                        "event": "invite", "channel": cid,
                                        "channel_name": channel_name, "server": server_name,
                                        "from": IdentityId::from_bytes(from_idk).to_base32(),
                                    }));
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            line = lines.next_line() => {
                match line {
                    Ok(Some(l)) => {
                        let l = l.trim();
                        if !l.is_empty() {
                            if let Err(e) = handle_bot_cmd(&mut engine, l).await {
                                bot_err(&e);
                            }
                        }
                    }
                    _ => break,   // EOF or read error -> shut down
                }
            }
        }
    }

    let _ = engine.persist();
    Ok(())
}

/// Print one JSON event, newline-terminated, flushed.
fn bot_emit(v: &serde_json::Value) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

fn bot_err(message: &str) {
    bot_emit(&serde_json::json!({ "event": "error", "message": message }));
}

async fn handle_bot_cmd(engine: &mut Engine, line: &str) -> std::result::Result<(), String> {
    let v: serde_json::Value = serde_json::from_str(line).map_err(|e| format!("bad json: {e}"))?;
    let cmd = v
        .get("cmd")
        .and_then(|c| c.as_str())
        .ok_or("missing \"cmd\"")?;
    let now = now_ms();
    let get = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let chan = |k: &str| -> std::result::Result<[u8; 32], String> {
        parse_fingerprint(v.get(k).and_then(|x| x.as_str()).unwrap_or(""))
            .map_err(|_| format!("bad {k}"))
    };
    let seq_of = || {
        v.get("seq")
            .and_then(|x| x.as_u64())
            .ok_or("missing \"seq\"".to_string())
    };

    match cmd {
        "whoami" => bot_emit(&serde_json::json!({
            "event": "whoami", "fingerprint": engine.identity().id().to_base32(),
        })),
        "announce" => {
            let name = get("name");
            engine
                .announce(&name, now)
                .await
                .map_err(|e| e.to_string())?;
            bot_emit(&serde_json::json!({ "event": "announced", "name": name }));
        }
        "channels" => {
            let list: Vec<_> = engine
                .channels()
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "channel": IdentityId::from_bytes(c.channel_id).to_base32(),
                        "channel_name": c.channel_name,
                        "server": c.server_name,
                    })
                })
                .collect();
            bot_emit(&serde_json::json!({ "event": "channels", "channels": list }));
        }
        "join" => {
            let link = get("invite");
            let pw = v.get("password").and_then(|x| x.as_str());
            engine
                .redeem_invite(link.trim(), pw, now)
                .await
                .map_err(|e| e.to_string())?;
            bot_emit(&serde_json::json!({ "event": "join_requested" }));
        }
        "accept" => {
            let ch = chan("channel")?;
            engine
                .accept_channel_invite(&ch, now)
                .await
                .map_err(|e| e.to_string())?;
            bot_emit(&serde_json::json!({ "event": "accepted", "channel": get("channel") }));
        }
        "send" => {
            let ch = chan("channel")?;
            let seq = engine
                .send_channel(&ch, &get("text"), now)
                .await
                .map_err(|e| e.to_string())?;
            bot_emit(
                &serde_json::json!({ "event": "sent", "channel": get("channel"), "seq": seq }),
            );
        }
        "reply" => {
            let ch = chan("channel")?;
            let target = seq_of()?;
            let seq = engine
                .send_channel_reply(&ch, target, &get("text"), now)
                .await
                .map_err(|e| e.to_string())?;
            bot_emit(
                &serde_json::json!({ "event": "sent", "channel": get("channel"), "seq": seq }),
            );
        }
        "react" => {
            let ch = chan("channel")?;
            let target = seq_of()?;
            let remove = v.get("remove").and_then(|x| x.as_bool()).unwrap_or(false);
            engine
                .send_react(&ch, target, &get("emoji"), remove, now)
                .await
                .map_err(|e| e.to_string())?;
            bot_emit(&serde_json::json!({ "event": "reacted" }));
        }
        "dm" => {
            let to = parse_fingerprint(&get("to")).map_err(|e| e.to_string())?;
            engine
                .send_dm(&to, &get("text"), now)
                .await
                .map_err(|e| e.to_string())?;
            bot_emit(&serde_json::json!({ "event": "dm_sent", "to": get("to") }));
        }
        other => return Err(format!("unknown cmd: {other}")),
    }
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
            "safety" => {
                let who = a.map(str::to_string).or_else(|| match target {
                    Some(Target::Peer(p)) => Some(IdentityId::from_bytes(*p).to_base32()),
                    _ => None,
                });
                match who.as_deref() {
                    Some(w) => match parse_fingerprint(w) {
                        Ok(id) => match engine.safety_number(&id) {
                            Some(num) => {
                                let mark = if engine.is_verified(&id) {
                                    "verified"
                                } else {
                                    "NOT verified — compare out of band, then /verify"
                                };
                                println!("safety number with {w}:\n  {num}\n  [{mark}]");
                            }
                            None => println!("unknown or revoked identity"),
                        },
                        Err(e) => println!("bad fingerprint: {e}"),
                    },
                    None => println!("usage: /safety <fingerprint>   (or set a peer with /to)"),
                }
            }
            "verify" => match a {
                Some(fp) => match parse_fingerprint(fp) {
                    Ok(id) => {
                        let on = !matches!(b, Some(s) if s.eq_ignore_ascii_case("off"));
                        match engine.set_verified(&id, on) {
                            Ok(()) => println!(
                                "{} marked {}",
                                IdentityId::from_bytes(id).to_base32(),
                                if on { "verified" } else { "unverified" }
                            ),
                            Err(e) => println!("failed: {e}"),
                        }
                    }
                    Err(e) => println!("bad fingerprint: {e}"),
                },
                None => println!("usage: /verify <fingerprint> [off]"),
            },
            "contacts" => {
                let list = engine.contacts();
                if list.is_empty() {
                    println!("(no contacts)");
                }
                for (id, c) in list {
                    let fp = IdentityId::from_bytes(id).to_base32();
                    let v = if engine.is_verified(&id) { " ✓" } else { "" };
                    if c.petname.is_empty() {
                        println!("  {fp}{v}");
                    } else {
                        println!("  {} — {fp}{v}", c.petname);
                    }
                }
            }
            "contact" => match a {
                Some(fp) => match parse_fingerprint(fp) {
                    Ok(id) => {
                        if matches!(b, Some(s) if s.eq_ignore_ascii_case("remove")) {
                            engine.remove_contact(&id);
                            println!("removed");
                        } else {
                            engine.add_contact(&id, b.unwrap_or(""), now_ms());
                            println!("saved");
                        }
                    }
                    Err(e) => println!("bad fingerprint: {e}"),
                },
                None => {
                    println!("usage: /contact <fingerprint> [petname]   |   /contact <fp> remove")
                }
            },
            "blocked" => {
                let list = engine.blocked();
                if list.is_empty() {
                    println!("(nobody blocked)");
                }
                for id in list {
                    println!("  {}", IdentityId::from_bytes(id).to_base32());
                }
            }
            "call" | "answer" | "hangup" => match a {
                Some(fp) => match parse_fingerprint(fp) {
                    Ok(id) => {
                        let r = match cmd {
                            "call" => engine.start_call(&id, now_ms()).await,
                            "answer" => engine.accept_call(&id, now_ms()).await,
                            _ => engine.hangup(&id, now_ms()).await,
                        };
                        match r {
                            Ok(()) => println!("\u{1f4de} {cmd} ok"),
                            Err(e) => println!("{cmd} failed: {e}"),
                        }
                    }
                    Err(e) => println!("bad fingerprint: {e}"),
                },
                None => println!("usage: /{cmd} <fingerprint>"),
            },
            "groupcall" => {
                let mut parts = a.unwrap_or("").split_whitespace();
                let sub = parts.next().unwrap_or("");
                let chan = parts.next().map(|c| c.strip_prefix('#').unwrap_or(c));
                match (sub, chan) {
                    ("start" | "join" | "leave", Some(c)) => match parse_fingerprint(c) {
                        Ok(cid) => {
                            let r = match sub {
                                "start" => engine.start_group_call(&cid, now_ms()).await,
                                "join" => engine.join_group_call(&cid, now_ms()).await,
                                _ => engine.leave_group_call(&cid, now_ms()).await,
                            };
                            match r {
                                Ok(()) => println!("\u{1f4de} group call {sub} ok"),
                                Err(e) => println!("group call {sub} failed: {e}"),
                            }
                        }
                        Err(e) => println!("bad channel id: {e}"),
                    },
                    _ => println!("usage: /groupcall start|join|leave #<channel>"),
                }
            }
            "vc" | "voice" => {
                let mut parts = a.unwrap_or("").split_whitespace();
                let sub = parts.next().unwrap_or("");
                let chan = parts.next().map(|c| c.strip_prefix('#').unwrap_or(c));
                match (sub, chan) {
                    ("join" | "leave", Some(c)) => match parse_fingerprint(c) {
                        Ok(cid) => {
                            let r = if sub == "join" {
                                engine.join_voice_channel(&cid, now_ms()).await
                            } else {
                                engine.leave_voice_channel(&cid, now_ms()).await
                            };
                            match r {
                                Ok(()) => println!("\u{1f50a} voice {sub} ok"),
                                Err(e) => println!("voice {sub} failed: {e}"),
                            }
                        }
                        Err(e) => println!("bad channel id: {e}"),
                    },
                    _ => println!("usage: /vc join|leave #<voice-channel>"),
                }
            }
            "block" | "unblock" => match a {
                Some(fp) => match parse_fingerprint(fp) {
                    Ok(id) => {
                        if cmd == "block" {
                            engine.block(&id);
                            println!("blocked");
                        } else {
                            engine.unblock(&id);
                            println!("unblocked");
                        }
                    }
                    Err(e) => println!("bad fingerprint: {e}"),
                },
                None => println!("usage: /{cmd} <fingerprint>"),
            },
            "server" => match a {
                Some(name) => match engine.create_server(name, now_ms()).await {
                    Ok(root) => {
                        // Every server starts with an always-there #general.
                        let _ = engine.create_channel(&root, "general", true, None);
                        println!(
                            "server \"{name}\" created with #general; root {}",
                            IdentityId::from_bytes(root).to_base32()
                        );
                    }
                    Err(e) => println!("create failed: {e}"),
                },
                None => println!("usage: /server <name>"),
            },
            "channel" => match (a, b) {
                (Some(sfp), Some(spec)) => match parse_fingerprint(sfp) {
                    Ok(root) => {
                        let name = spec.trim();
                        match engine.create_channel(&root, name, true, None) {
                            Ok(id) => println!(
                                "channel \"{name}\" -> #{}",
                                IdentityId::from_bytes(id).to_base32()
                            ),
                            Err(e) => println!("create failed: {e}"),
                        }
                    }
                    Err(e) => println!("bad server root: {e}"),
                },
                _ => println!("usage: /channel <server-root> <name>"),
            },
            "vchannel" => match (a, b) {
                (Some(sfp), Some(name)) => match parse_fingerprint(sfp) {
                    Ok(root) => match engine.create_voice_channel(&root, name.trim(), true) {
                        Ok(id) => println!(
                            "\u{1f50a} voice channel \"{}\" -> #{}",
                            name.trim(),
                            IdentityId::from_bytes(id).to_base32()
                        ),
                        Err(e) => println!("create failed: {e}"),
                    },
                    Err(e) => println!("bad server root: {e}"),
                },
                _ => println!("usage: /vchannel <server-root> <name>"),
            },
            "invite" => match (a, b) {
                (Some(chan), Some(fp)) => {
                    let chan = chan.strip_prefix('#').unwrap_or(chan);
                    match (parse_fingerprint(chan), parse_fingerprint(fp)) {
                        (Ok(cid), Ok(pid)) => {
                            match engine.invite_to_channel(&cid, &pid, now_ms()).await {
                                Ok(()) => println!("invitation sent — they must accept"),
                                Err(e) => println!("invite failed: {e}"),
                            }
                        }
                        _ => println!("bad channel id or fingerprint"),
                    }
                }
                _ => println!("usage: /invite #<channel-id> <fingerprint>"),
            },
            "acceptinvite" | "declineinvite" => match a {
                Some(chan) => {
                    let chan = chan.strip_prefix('#').unwrap_or(chan);
                    match parse_fingerprint(chan) {
                        Ok(cid) => {
                            let res = if cmd == "acceptinvite" {
                                engine.accept_channel_invite(&cid, now_ms()).await
                            } else {
                                engine.decline_channel_invite(&cid, now_ms()).await
                            };
                            match res {
                                Ok(()) => println!("done"),
                                Err(e) => println!("failed: {e}"),
                            }
                        }
                        Err(e) => println!("bad channel id: {e}"),
                    }
                }
                None => println!("usage: /{cmd} #<channel-id>"),
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
                    let pw = b.map(str::trim).filter(|s| !s.is_empty());
                    match engine.redeem_invite(link.trim(), pw, now_ms()).await {
                        Ok(()) => println!("redeemed — you'll join once the host is online"),
                        Err(e) => println!("redeem failed: {e}"),
                    }
                }
                None => println!("usage: /redeem <invite-link> [password]"),
            },
            "joinpw" => match (a, b) {
                (Some(root), Some(spec_rest)) => match parse_fingerprint(root) {
                    Ok(sr) => {
                        let mut it = spec_rest.split_whitespace();
                        let spec = it.next().unwrap_or("");
                        let current = it.next();
                        let pw = (spec != "off" && spec != "0").then_some(spec);
                        match engine.set_join_password(&sr, pw, current) {
                            Ok(()) => println!(
                                "{}",
                                if pw.is_some() {
                                    "join password set"
                                } else {
                                    "join password cleared"
                                }
                            ),
                            Err(e) => println!("failed: {e}"),
                        }
                    }
                    Err(e) => println!("bad server root: {e}"),
                },
                _ => println!("usage: /joinpw <server-root> <password|off> [current-password]"),
            },
            "autokick" => match (a, b) {
                (Some(root), Some(spec)) => match parse_fingerprint(root) {
                    Ok(sr) => {
                        let window = if spec.eq_ignore_ascii_case("off") || spec == "0" {
                            None
                        } else {
                            spec.parse::<f64>().ok().map(|d| (d * 86_400_000.0) as u64)
                        };
                        match window {
                            None if spec.eq_ignore_ascii_case("off") || spec == "0" => {
                                match engine.set_auto_kick(&sr, None) {
                                    Ok(()) => println!("auto-kick disabled"),
                                    Err(e) => println!("failed: {e}"),
                                }
                            }
                            Some(w) => match engine.set_auto_kick(&sr, Some(w)) {
                                Ok(()) => println!("auto-kick after {spec} day(s) of inactivity"),
                                Err(e) => println!("failed: {e}"),
                            },
                            None => println!("usage: /autokick <server-root> <days|off>"),
                        }
                    }
                    Err(e) => println!("bad server root: {e}"),
                },
                _ => println!("usage: /autokick <server-root> <days|off>"),
            },
            "react" => match (a, b) {
                (Some(chan), Some(rest)) => {
                    let chan = chan.strip_prefix('#').unwrap_or(chan);
                    let mut it = rest.split_whitespace();
                    match (
                        parse_fingerprint(chan),
                        it.next().and_then(|s| s.parse::<u64>().ok()),
                    ) {
                        (Ok(cid), Some(seq)) => {
                            let emoji = it.next().unwrap_or("👍");
                            let remove = it.next() == Some("-");
                            match engine.send_react(&cid, seq, emoji, remove, now_ms()).await {
                                Ok(()) => println!("reacted"),
                                Err(e) => println!("failed: {e}"),
                            }
                        }
                        _ => println!("usage: /react #<chan> <seq> <emoji> [-]"),
                    }
                }
                _ => println!("usage: /react #<chan> <seq> <emoji> [-]"),
            },
            "edit" | "delete" => match (a, b) {
                (Some(chan), Some(rest)) => {
                    let chan = chan.strip_prefix('#').unwrap_or(chan);
                    let (seq_str, new_text) = match rest.split_once(char::is_whitespace) {
                        Some((s, t)) => (s, t),
                        None => (rest, ""),
                    };
                    match (parse_fingerprint(chan), seq_str.parse::<u64>()) {
                        (Ok(cid), Ok(seq)) => {
                            if cmd == "edit" && new_text.is_empty() {
                                println!("usage: /edit #<chan> <seq> <new text>");
                            } else {
                                let r = if cmd == "delete" {
                                    engine.delete_channel_message(&cid, seq, now_ms()).await
                                } else {
                                    engine
                                        .edit_channel_message(&cid, seq, new_text, now_ms())
                                        .await
                                };
                                match r {
                                    Ok(()) => println!("{cmd} ok"),
                                    Err(e) => println!("{cmd} failed: {e}"),
                                }
                            }
                        }
                        _ => println!(
                            "usage: /{cmd} #<chan> <seq>{}",
                            if cmd == "edit" { " <new text>" } else { "" }
                        ),
                    }
                }
                _ => println!(
                    "usage: /{cmd} #<chan> <seq>{}",
                    if cmd == "edit" { " <new text>" } else { "" }
                ),
            },
            "pin" | "unpin" => match (a, b) {
                (Some(chan), Some(seq_str)) => {
                    let chan = chan.strip_prefix('#').unwrap_or(chan);
                    match (parse_fingerprint(chan), seq_str.trim().parse::<u64>()) {
                        (Ok(cid), Ok(seq)) => {
                            let r = if cmd == "pin" {
                                engine.pin_channel_message(&cid, seq, now_ms()).await
                            } else {
                                engine.unpin_channel_message(&cid, seq, now_ms()).await
                            };
                            match r {
                                Ok(()) => println!("{cmd} ok"),
                                Err(e) => println!("{cmd} failed: {e}"),
                            }
                        }
                        _ => println!("usage: /{cmd} #<chan> <seq>"),
                    }
                }
                _ => println!("usage: /{cmd} #<chan> <seq>"),
            },
            "editdm" | "deldm" => match (a, b) {
                (Some(fp), rest) => {
                    let (mid_str, new_text) =
                        match rest.and_then(|r| r.split_once(char::is_whitespace)) {
                            Some((m, t)) => (m, t),
                            None => (rest.unwrap_or(""), ""),
                        };
                    match (parse_fingerprint(fp), parse_hex16(mid_str)) {
                        (Ok(pid), Some(mid)) => {
                            let r = if cmd == "deldm" {
                                engine.delete_dm(&pid, &mid, now_ms()).await
                            } else if new_text.is_empty() {
                                println!("usage: /editdm <fp> <msg-id> <new text>");
                                return Ok(false);
                            } else {
                                engine.edit_dm(&pid, &mid, new_text, now_ms()).await
                            };
                            match r {
                                Ok(()) => println!("{cmd} ok"),
                                Err(e) => println!("{cmd} failed: {e}"),
                            }
                        }
                        _ => println!(
                            "usage: /{cmd} <fp> <msg-id>{}",
                            if cmd == "editdm" { " <new text>" } else { "" }
                        ),
                    }
                }
                _ => println!(
                    "usage: /{cmd} <fp> <msg-id>{}",
                    if cmd == "editdm" { " <new text>" } else { "" }
                ),
            },
            "forward" => match (a, b) {
                (Some(dest), Some(rest)) => {
                    let (origin, text) = match rest.split_once(char::is_whitespace) {
                        Some((o, t)) if !t.is_empty() => (o, t),
                        _ => {
                            println!("usage: /forward <#chan|fp> <origin> <text>");
                            return Ok(false);
                        }
                    };
                    if let Some(chan) = dest.strip_prefix('#') {
                        match parse_fingerprint(chan) {
                            Ok(cid) => match engine
                                .forward_to_channel(&cid, origin, text, now_ms())
                                .await
                            {
                                Ok(_) => println!("forwarded"),
                                Err(e) => println!("forward failed: {e}"),
                            },
                            Err(e) => println!("bad channel: {e}"),
                        }
                    } else {
                        match parse_fingerprint(dest) {
                            Ok(pid) => {
                                let body = format!("\u{21aa} Forwarded from {origin}\n{text}");
                                match engine.send_dm(&pid, &body, now_ms()).await {
                                    Ok(_) => println!("forwarded"),
                                    Err(e) => println!("forward failed: {e}"),
                                }
                            }
                            Err(e) => println!("bad fingerprint: {e}"),
                        }
                    }
                }
                _ => println!("usage: /forward <#chan|fp> <origin> <text>"),
            },
            "pins" => match a {
                Some(chan) => {
                    let chan = chan.strip_prefix('#').unwrap_or(chan);
                    match parse_fingerprint(chan) {
                        Ok(cid) => {
                            let pins = engine.pinned_messages(&cid);
                            if pins.is_empty() {
                                println!("(no pinned messages)");
                            }
                            for p in pins {
                                println!(
                                    "  seq {}  pinned by {}",
                                    p.target_seq,
                                    IdentityId::from_bytes(p.by)
                                        .to_base32()
                                        .split('-')
                                        .next()
                                        .unwrap_or("")
                                );
                            }
                        }
                        Err(e) => println!("bad channel: {e}"),
                    }
                }
                None => println!("usage: /pins #<chan>"),
            },
            "reply" => match (a, b) {
                (Some(chan), Some(rest)) => {
                    let chan = chan.strip_prefix('#').unwrap_or(chan);
                    match rest.split_once(char::is_whitespace) {
                        Some((seq_str, text)) if !text.is_empty() => {
                            match (parse_fingerprint(chan), seq_str.parse::<u64>()) {
                                (Ok(cid), Ok(seq)) => {
                                    match engine.send_channel_reply(&cid, seq, text, now_ms()).await
                                    {
                                        Ok(_) => println!("replied"),
                                        Err(e) => println!("reply failed: {e}"),
                                    }
                                }
                                _ => println!("usage: /reply #<chan> <seq> <text>"),
                            }
                        }
                        _ => println!("usage: /reply #<chan> <seq> <text>"),
                    }
                }
                _ => println!("usage: /reply #<chan> <seq> <text>"),
            },
            "discover" => {
                let list = engine.discoverable_servers();
                if list.is_empty() {
                    println!("(no public servers — try /discover again after a sync)");
                }
                for s in list {
                    println!(
                        "  {}  {}{}",
                        IdentityId::from_bytes(s.server_root).to_base32(),
                        s.name,
                        if s.summary.is_empty() {
                            String::new()
                        } else {
                            format!(" — {}", s.summary)
                        }
                    );
                }
            }
            "publish" => match (a, b) {
                (Some(root), Some(rest)) => match parse_fingerprint(root) {
                    Ok(sr) => {
                        let mut it = rest.splitn(2, char::is_whitespace);
                        let on = matches!(it.next(), Some("on"));
                        let summary = it.next().unwrap_or("");
                        match engine
                            .set_discoverable(&sr, on, summary, vec![], now_ms())
                            .await
                        {
                            Ok(()) => {
                                println!(
                                    "{}",
                                    if on {
                                        "listed on discovery"
                                    } else {
                                        "unlisted"
                                    }
                                )
                            }
                            Err(e) => println!("failed: {e}"),
                        }
                    }
                    Err(e) => println!("bad server root: {e}"),
                },
                _ => println!("usage: /publish <server-root> <on|off> [summary]"),
            },
            "joindisc" => match a {
                Some(root) => match parse_fingerprint(root) {
                    Ok(sr) => {
                        let pw = b.map(str::trim).filter(|s| !s.is_empty());
                        match engine.join_discovered(&sr, pw, now_ms()).await {
                            Ok(()) => println!("joining — wait for the host to be online"),
                            Err(e) => println!("failed: {e}"),
                        }
                    }
                    Err(e) => println!("bad server root: {e}"),
                },
                None => println!("usage: /joindisc <server-root> [password]"),
            },
            "roles" => match a {
                Some(root) => match parse_fingerprint(root) {
                    Ok(sr) => match engine.server_policy(&sr) {
                        Some(p) => {
                            println!("roles for server (v{}):", p.version);
                            for r in &p.roles {
                                println!(
                                    "  [{}] {}  allow={:#x} deny={:#x} rank={}",
                                    r.id, r.name, r.allow, r.deny, r.rank
                                );
                            }
                        }
                        None => println!("no policy known for that server"),
                    },
                    Err(e) => println!("bad server root: {e}"),
                },
                None => println!("usage: /roles <server-root>"),
            },
            "role" => match (a, b) {
                (Some(root), Some(rest)) => match parse_fingerprint(root) {
                    Ok(sr) => {
                        let mut it = rest.split_whitespace();
                        let name = it.next().unwrap_or("role");
                        let mut allow = 0u32;
                        let mut deny = 0u32;
                        for flag in it {
                            match flag {
                                "kick" => allow |= dante_core::roles::PERM_KICK,
                                "mute" | "nosend" => deny |= dante_core::roles::PERM_SEND,
                                "manage" => {
                                    allow |= dante_core::roles::PERM_MANAGE_CHANNELS
                                        | dante_core::roles::PERM_MANAGE_ROLES
                                }
                                _ => {}
                            }
                        }
                        match engine
                            .set_role(&sr, None, name, allow, deny, 10, now_ms())
                            .await
                        {
                            Ok(id) => println!("role \"{name}\" -> id {id}"),
                            Err(e) => println!("failed: {e}"),
                        }
                    }
                    Err(e) => println!("bad server root: {e}"),
                },
                _ => println!("usage: /role <server-root> <name> [kick] [mute] [manage]"),
            },
            "emoji" => match (a, b) {
                (Some(root), Some(rest)) => match parse_fingerprint(root) {
                    Ok(sr) => {
                        let mut it = rest.split_whitespace();
                        let name = it.next().unwrap_or("");
                        let arg = it.next().unwrap_or("");
                        let res = if arg.eq_ignore_ascii_case("remove") || arg == "-" {
                            engine.remove_server_emoji(&sr, name, now_ms()).await
                        } else {
                            match std::fs::read(arg) {
                                Ok(img) => engine.set_server_emoji(&sr, name, &img, now_ms()).await,
                                Err(e) => {
                                    println!("cannot read {arg}: {e}");
                                    return Ok(false);
                                }
                            }
                        };
                        match res {
                            Ok(()) => println!("emoji :{name}: updated"),
                            Err(e) => println!("failed: {e}"),
                        }
                    }
                    Err(e) => println!("bad server root: {e}"),
                },
                _ => println!("usage: /emoji <server-root> <name> <image-path|remove>"),
            },
            "sticker" => match (a, b) {
                (Some(root), Some(rest)) => match parse_fingerprint(root) {
                    Ok(sr) => {
                        let mut it = rest.split_whitespace();
                        let name = it.next().unwrap_or("");
                        let arg = it.next().unwrap_or("");
                        let res = if arg.eq_ignore_ascii_case("remove") || arg == "-" {
                            engine.remove_server_sticker(&sr, name, now_ms()).await
                        } else {
                            match std::fs::read(arg) {
                                Ok(img) => {
                                    engine.set_server_sticker(&sr, name, &img, now_ms()).await
                                }
                                Err(e) => {
                                    println!("cannot read {arg}: {e}");
                                    return Ok(false);
                                }
                            }
                        };
                        match res {
                            Ok(()) => println!("sticker :{name}: updated"),
                            Err(e) => println!("failed: {e}"),
                        }
                    }
                    Err(e) => println!("bad server root: {e}"),
                },
                _ => println!("usage: /sticker <server-root> <name> <image-path|remove>"),
            },
            "sound" => match (a, b) {
                (Some(root), Some(rest)) => match parse_fingerprint(root) {
                    Ok(sr) => {
                        let mut it = rest.split_whitespace();
                        let name = it.next().unwrap_or("");
                        let arg = it.next().unwrap_or("");
                        let res = if arg.eq_ignore_ascii_case("remove") || arg == "-" {
                            engine.remove_server_sound(&sr, name, now_ms()).await
                        } else {
                            match std::fs::read(arg) {
                                Ok(clip) => {
                                    engine.set_server_sound(&sr, name, &clip, now_ms()).await
                                }
                                Err(e) => {
                                    println!("cannot read {arg}: {e}");
                                    return Ok(false);
                                }
                            }
                        };
                        match res {
                            Ok(()) => println!("sound :{name}: updated"),
                            Err(e) => println!("failed: {e}"),
                        }
                    }
                    Err(e) => println!("bad server root: {e}"),
                },
                _ => println!("usage: /sound <server-root> <name> <audio-path|remove>"),
            },
            "assignrole" => match (a, b) {
                (Some(root), Some(rest)) => {
                    let mut it = rest.split_whitespace();
                    match (
                        parse_fingerprint(root),
                        it.next().map(parse_fingerprint),
                        it.next().and_then(|s| s.parse::<u16>().ok()),
                    ) {
                        (Ok(sr), Some(Ok(mid)), Some(rid)) => {
                            let add = it.next() != Some("remove");
                            match engine.assign_role(&sr, &mid, rid, add, now_ms()).await {
                                Ok(()) => {
                                    println!("{}", if add { "assigned" } else { "unassigned" })
                                }
                                Err(e) => println!("failed: {e}"),
                            }
                        }
                        _ => println!("usage: /assignrole <server-root> <fp> <role-id> [remove]"),
                    }
                }
                _ => println!("usage: /assignrole <server-root> <fp> <role-id> [remove]"),
            },
            "kick" | "ban" => match (a, b) {
                (Some(chan), Some(spec)) => {
                    let chan = chan.strip_prefix('#').unwrap_or(chan);
                    let fp = spec.split_whitespace().next().unwrap_or("");
                    match (parse_fingerprint(chan), parse_fingerprint(fp)) {
                        (Ok(cid), Ok(mid)) => {
                            let ban = cmd == "ban";
                            match engine.request_kick(&cid, &mid, ban, now_ms()).await {
                                Ok(()) => println!(
                                    "{} from the server",
                                    if ban { "banned" } else { "kicked" }
                                ),
                                Err(e) => println!("failed: {e}"),
                            }
                        }
                        _ => println!("bad channel id or fingerprint"),
                    }
                }
                _ => println!("usage: /{cmd} #<any-server-channel> <fingerprint>"),
            },
            "unban" => match (a, b) {
                (Some(root), Some(fp)) => match (parse_fingerprint(root), parse_fingerprint(fp)) {
                    (Ok(sr), Ok(mid)) => {
                        if engine.unban_from_server(&sr, &mid) {
                            println!("unbanned");
                        } else {
                            println!("that identity was not banned");
                        }
                    }
                    _ => println!("bad server root or fingerprint"),
                },
                _ => println!("usage: /unban <server-root> <fingerprint>"),
            },
            "leave" => match a {
                Some(chan) => {
                    let chan = chan.strip_prefix('#').unwrap_or(chan);
                    match parse_fingerprint(chan) {
                        Ok(cid) => match engine.leave_channel(&cid, now_ms()).await {
                            Ok(()) => {
                                if matches!(target, Some(Target::Channel(c)) if *c == cid) {
                                    *target = None;
                                }
                                println!("left");
                            }
                            Err(e) => println!("leave failed: {e}"),
                        },
                        Err(e) => println!("bad channel id: {e}"),
                    }
                }
                None => println!("usage: /leave #<channel-id>"),
            },
            "delchannel" => match a {
                Some(chan) => {
                    let chan = chan.strip_prefix('#').unwrap_or(chan);
                    match parse_fingerprint(chan) {
                        Ok(cid) => match engine.delete_channel(&cid, now_ms()).await {
                            Ok(()) => {
                                if matches!(target, Some(Target::Channel(c)) if *c == cid) {
                                    *target = None;
                                }
                                println!("channel deleted");
                            }
                            Err(e) => println!("failed: {e}"),
                        },
                        Err(e) => println!("bad channel id: {e}"),
                    }
                }
                None => println!("usage: /delchannel #<channel-id>"),
            },
            "renamechannel" => match (a, b) {
                (Some(chan), Some(name)) => {
                    let chan = chan.strip_prefix('#').unwrap_or(chan);
                    match parse_fingerprint(chan) {
                        Ok(cid) => match engine.rename_channel(&cid, name, now_ms()).await {
                            Ok(()) => println!("channel renamed to #{name}"),
                            Err(e) => println!("failed: {e}"),
                        },
                        Err(e) => println!("bad channel id: {e}"),
                    }
                }
                _ => println!("usage: /renamechannel #<channel-id> <new-name>"),
            },
            "delserver" => match a {
                Some(root) => match parse_fingerprint(root) {
                    Ok(sr) => match engine.delete_server(&sr, now_ms()).await {
                        Ok(()) => println!("server deleted and delisted"),
                        Err(e) => println!("failed: {e}"),
                    },
                    Err(e) => println!("bad server root: {e}"),
                },
                None => println!("usage: /delserver <server-root>"),
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
            Ok(mid) => println!("  (sent, id {})", hex16(&mid)),
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
