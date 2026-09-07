//! `dante serve` — run the engine behind a tiny local HTTP UI.
//!
//! Single user, localhost only. A minimal hand-rolled HTTP/1.1 handler serves
//! the embedded SPA and a JSON API:
//! `GET /api/me`, `GET /api/messages?since=N`, `GET /api/channels`,
//! `POST /api/send {to,text}` (`to` may be a fingerprint or `#<channel-id>`),
//! `POST /api/server {name}`, `POST /api/channel {server,name}`,
//! `POST /api/invite {channel,peer}`, `POST /api/invite-link
//! {channel,ttl_secs,max_uses}`, `POST /api/redeem {link}`, `POST /api/remove
//! {channel,member}`, `POST /api/autokick {server,days}`, `GET
//! /api/policy?server=`, `POST /api/role {server,id,name,allow,deny,rank}`,
//! `POST /api/roleassign {server,member,role_id,add}`, `POST /api/joinpw
//! {server,password}`, `GET /api/typing`, `POST /api/typing {to}`,
//! `GET /api/state`, `POST /api/onboard {mode,passphrase,blob}`,
//! `GET /api/discover`, `POST /api/discover {server,on,summary,tags}`,
//! `POST /api/discover/join {server,password}`, `GET /api/reactions`,
//! `POST /api/react {channel,seq,emoji,remove}`,
//! `GET /api/safety?peer=`, `POST /api/verify {peer,verified}`.
//!
//! `serve` can start with no identity: the page then shows a create / unlock /
//! import flow and connects the engine when it completes.

use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{Context, Result};
use dante_core::{Engine, Inbound, TypingScope};
use dante_crypto::pow::Difficulty;
use dante_identity::{backup, id::IdentityId, keystore, Identity};
use dante_ledger::LedgerParams;
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, Mutex},
};

use crate::{now_ms, parse_fingerprint};

const INDEX_HTML: &str = include_str!("../web/index.html");
const INBOX_CAP: usize = 500;
/// A typing signal is shown for this long after the last keystroke it carries.
const TYPING_FRESH_MS: u64 = 4_000;

/// A request from the HTTP side to the single engine task. The reply carries a
/// string (an id / root on success, or an error message).
enum Cmd {
    Send {
        to: String,
        text: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    CreateServer {
        name: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    CreateChannel {
        server: String,
        name: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    Invite {
        channel: String,
        peer: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    InviteLink {
        channel: String,
        ttl_secs: u64,
        max_uses: u32,
        reply: oneshot::Sender<Result<String, String>>,
    },
    Redeem {
        link: String,
        password: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    JoinPw {
        server: String,
        password: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    RemoveMember {
        channel: String,
        member: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    AutoKick {
        server: String,
        days: f64,
        reply: oneshot::Sender<Result<String, String>>,
    },
    SetRole {
        server: String,
        id: Option<u16>,
        name: String,
        allow: u32,
        deny: u32,
        rank: u16,
        reply: oneshot::Sender<Result<String, String>>,
    },
    AssignRole {
        server: String,
        member: String,
        role_id: u16,
        add: bool,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Return the server's role policy as a ready JSON string.
    GetPolicy {
        server: [u8; 32],
        reply: oneshot::Sender<String>,
    },
    Discover {
        server: String,
        on: bool,
        summary: String,
        tags: Vec<String>,
        reply: oneshot::Sender<Result<String, String>>,
    },
    DiscoverJoin {
        server: String,
        password: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// The public discovery directory as a ready JSON array.
    DiscoverList { reply: oneshot::Sender<String> },
    React {
        channel: String,
        target_seq: u64,
        emoji: String,
        remove: bool,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Fire-and-forget: broadcast an "I am typing" signal to `to`.
    Typing { to: String },
    /// The DM pair's safety number + verification state as a ready JSON object.
    Safety {
        peer: [u8; 32],
        reply: oneshot::Sender<String>,
    },
    /// Set/clear safety-number verification for a DM peer.
    Verify {
        peer: String,
        on: bool,
        reply: oneshot::Sender<Result<String, String>>,
    },
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Item {
    Message {
        seq: u64,
        from: String,
        text: String,
    },
    File {
        seq: u64,
        from: String,
        filename: String,
        size: usize,
        saved: String,
    },
    Channel {
        seq: u64,
        channel: String,
        channel_name: String,
        from: String,
        text: String,
        /// The relay-log seq — what reactions point at; `0` for our own echo.
        ref_seq: u64,
    },
}

impl Item {
    fn seq(&self) -> u64 {
        match self {
            Item::Message { seq, .. } | Item::File { seq, .. } | Item::Channel { seq, .. } => *seq,
        }
    }
}

#[derive(Clone, Serialize)]
struct ChanView {
    id: String,
    name: String,
    server: String,
    /// Base32 of the owning server's root key — what `POST /api/channel` wants.
    root: String,
    /// Auto-kick window for this server in days; `0` = off.
    auto_kick_days: u64,
}

/// Everything `serve` needs to build the engine once the user has an identity.
pub struct Bootstrap {
    pub relay: String,
    pub keystore_path: PathBuf,
    pub store_path: Option<PathBuf>,
    pub params: LedgerParams,
    pub pow: Difficulty,
}

struct Shared {
    inbox: Mutex<VecDeque<Item>>,
    channels: Mutex<Vec<ChanView>>,
    /// Recently-seen typers: `(who label, last-seen ms)`. Pruned on read.
    typing: Mutex<Vec<(String, u64)>>,
    /// `target_seq -> emoji -> set of member labels`. Live-session only.
    reactions: Mutex<
        std::collections::HashMap<
            u64,
            std::collections::HashMap<String, std::collections::HashSet<String>>,
        >,
    >,
    /// Monotonic id stamped on every inbox item, drawn by both the engine tick
    /// loop and command handlers so the SPA's `since` cursor never regresses.
    next_seq: AtomicU64,
    /// `(fingerprint, word-phrase)`; empty until an identity is set up.
    me: Mutex<(String, String)>,
    /// True once the engine is connected and the tick loop is running.
    ready: AtomicBool,
    cmd: mpsc::Sender<Cmd>,
    /// How to connect the engine after onboarding.
    boot: Bootstrap,
    /// The command receiver, handed to the engine task when it starts.
    pending_rx: Mutex<Option<mpsc::Receiver<Cmd>>>,
}

impl Shared {
    fn next(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::Relaxed) + 1
    }
}

/// Full base32 fingerprint from raw id bytes (channel ids, channel senders,
/// which are already `IdentityId` bytes).
fn id_b32(bytes: &[u8; 32]) -> String {
    IdentityId::from_bytes(*bytes).to_base32()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 || s.is_empty() {
        return None;
    }
    let b = s.as_bytes();
    (0..b.len() / 2)
        .map(|i| {
            let hi = (b[2 * i] as char).to_digit(16)?;
            let lo = (b[2 * i + 1] as char).to_digit(16)?;
            Some(((hi << 4) | lo) as u8)
        })
        .collect()
}

/// Label for a channel sender (bytes are already an `IdentityId`).
fn short_id(bytes: &[u8; 32]) -> String {
    id_b32(bytes)
}

/// Label for a DM peer, whose stored bytes are an Ed25519 identity key that
/// must be hashed into an `IdentityId` first.
fn short_fp(idk: &[u8; 32]) -> String {
    use dante_crypto::sign::SignPublic;
    match SignPublic::from_bytes(idk) {
        Ok(pk) => IdentityId::of(&pk).to_base32(),
        Err(_) => "????".into(),
    }
}

fn parse_target(to: &str) -> Result<(bool, [u8; 32]), String> {
    match to.strip_prefix('#') {
        Some(rest) => parse_fingerprint(rest)
            .map(|id| (true, id))
            .map_err(|e| e.to_string()),
        None => parse_fingerprint(to)
            .map(|id| (false, id))
            .map_err(|e| e.to_string()),
    }
}

/// Entry point for the `serve` subcommand. `existing` is `Some` when a keystore
/// was already loaded; `None` starts the page in onboarding mode.
pub async fn run(existing: Option<Engine>, http_addr: &str, boot: Bootstrap) -> Result<()> {
    let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>(32);
    let shared = Arc::new(Shared {
        inbox: Mutex::new(VecDeque::new()),
        channels: Mutex::new(Vec::new()),
        typing: Mutex::new(Vec::new()),
        reactions: Mutex::new(std::collections::HashMap::new()),
        next_seq: AtomicU64::new(0),
        me: Mutex::new((String::new(), String::new())),
        ready: AtomicBool::new(false),
        cmd: cmd_tx,
        boot,
        pending_rx: Mutex::new(Some(cmd_rx)),
    });

    let listener = TcpListener::bind(http_addr)
        .await
        .with_context(|| format!("binding {http_addr}"))?;

    if let Some(engine) = existing {
        {
            let id = engine.identity().id();
            *shared.me.lock().await = (id.to_base32(), id.to_words());
        }
        shared.ready.store(true, Ordering::Relaxed);
        let rx = shared.pending_rx.lock().await.take().unwrap();
        tokio::spawn(engine_task(engine, Arc::clone(&shared), rx));
        eprintln!("dante UI on http://{http_addr}");
    } else {
        eprintln!("dante UI on http://{http_addr}  (open it to create or import an identity)");
    }

    loop {
        let (stream, _) = listener.accept().await?;
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            if let Err(e) = serve_conn(stream, shared).await {
                tracing::debug!(error = %e, "http connection ended");
            }
        });
    }
}

/// Connect the engine with `identity` using the stored bootstrap params and
/// start the tick loop. Returns `(fingerprint, words)`.
async fn connect_and_start(
    shared: Arc<Shared>,
    identity: Identity,
) -> Result<(String, String), String> {
    if shared.ready.load(Ordering::Relaxed) {
        return Err("already set up".into());
    }
    let b = &shared.boot;
    let engine = Engine::connect(identity, &b.relay, b.params, b.pow, b.store_path.clone())
        .await
        .map_err(|e| e.to_string())?;
    let out = {
        let id = engine.identity().id();
        (id.to_base32(), id.to_words())
    };
    let rx = shared
        .pending_rx
        .lock()
        .await
        .take()
        .ok_or("engine already starting")?;
    *shared.me.lock().await = out.clone();
    shared.ready.store(true, Ordering::Relaxed);
    tokio::spawn(engine_task(engine, Arc::clone(&shared), rx));
    Ok(out)
}

async fn engine_task(
    mut engine: Engine,
    engine_shared: Arc<Shared>,
    mut cmd_rx: mpsc::Receiver<Cmd>,
) {
    // Replay stored history.
    {
        let mut inbox = engine_shared.inbox.lock().await;
        for h in engine.history() {
            let seq = engine_shared.next();
            let from = if h.outgoing {
                "you".to_string()
            } else {
                short_fp(&h.peer_idk)
            };
            inbox.push_back(match &h.kind {
                dante_core::HistoryKind::Text(t) => Item::Message {
                    seq,
                    from,
                    text: t.clone(),
                },
                dante_core::HistoryKind::File { filename, size } => Item::File {
                    seq,
                    from,
                    filename: filename.clone(),
                    size: *size as usize,
                    saved: String::new(),
                },
            });
        }

        let names: std::collections::HashMap<[u8; 32], String> = engine
            .channels()
            .into_iter()
            .map(|c| (c.channel_id, c.channel_name))
            .collect();
        for e in engine.channel_history() {
            inbox.push_back(Item::Channel {
                seq: engine_shared.next(),
                channel: id_b32(&e.channel_id),
                channel_name: names.get(&e.channel_id).cloned().unwrap_or_default(),
                from: if e.outgoing {
                    "you".to_string()
                } else {
                    short_id(&e.sender)
                },
                text: e.text.clone(),
                ref_seq: 0,
            });
        }
    }

    {
        let mut reacts = engine_shared.reactions.lock().await;
        for r in engine.reaction_snapshot() {
            reacts
                .entry(r.target_seq)
                .or_default()
                .entry(r.emoji)
                .or_default()
                .insert(short_id(&r.member));
        }
    }

    eprintln!("announcing to the relay ...");
    if let Err(e) = async {
        engine.announce_if_stale("", now_ms()).await?;
        engine.publish_prekeys().await?;
        engine.sync(now_ms()).await?;
        Ok::<_, dante_core::CoreError>(())
    }
    .await
    {
        eprintln!("engine startup error: {e}");
    } else {
        eprintln!("ready");
    }
    refresh_channels(&engine, &engine_shared).await;

    let mut tick = tokio::time::interval(Duration::from_millis(700));
    let mut save_tick = tokio::time::interval(Duration::from_secs(15));
    let mut sweep_tick = tokio::time::interval(Duration::from_secs(120));
    // Last inbound message time per sender label. A real message supersedes
    // any typing signal that predates it (the relay keeps serving the stale
    // signal for a few seconds, which otherwise flashes "is typing" right
    // after the message lands).
    let mut last_msg_ms: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    loop {
        tokio::select! {
            _ = save_tick.tick() => { let _ = engine.persist(); }

            _ = sweep_tick.tick() => {
                if let Ok(kicked) = engine.sweep_inactive_members(now_ms()).await {
                    for k in kicked {
                        eprintln!("auto-kicked inactive member {}", id_b32(&k));
                    }
                    refresh_channels(&engine, &engine_shared).await;
                }
            }

            Some(cmd) = cmd_rx.recv() => {
                handle_cmd(&mut engine, &engine_shared, cmd).await;
                refresh_channels(&engine, &engine_shared).await;
            }

            _ = tick.tick() => {
                let now = now_ms();
                let _ = engine.sync(now).await;

                if let Ok(msgs) = engine.poll_channels(now).await {
                    let mut inbox = engine_shared.inbox.lock().await;
                    for m in msgs {
                        let from = short_id(&m.sender);
                        last_msg_ms.insert(from.clone(), now);
                        inbox.push_back(Item::Channel {
                            seq: engine_shared.next(),
                            channel: id_b32(&m.channel_id),
                            channel_name: m.channel_name,
                            from,
                            text: m.text,
                            ref_seq: m.seq,
                        });
                        while inbox.len() > INBOX_CAP { inbox.pop_front(); }
                    }
                }

                {
                    let reacts = engine.take_reactions();
                    if !reacts.is_empty() {
                        let mut map = engine_shared.reactions.lock().await;
                        for r in reacts {
                            let who = short_id(&r.member);
                            let set = map.entry(r.target_seq).or_default().entry(r.emoji).or_default();
                            if r.removed { set.remove(&who); } else { set.insert(who); }
                        }
                        map.retain(|_, e| { e.retain(|_, s| !s.is_empty()); !e.is_empty() });
                    }
                }

                if let Ok(items) = engine.receive_all(now).await {
                    let mut inbox = engine_shared.inbox.lock().await;
                    for it in items {
                        let seq = engine_shared.next();
                        let entry = match it {
                            Inbound::Message(m) => {
                                let from = short_fp(&m.from_idk);
                                last_msg_ms.insert(from.clone(), now);
                                Item::Message { seq, from, text: m.text }
                            }
                            Inbound::File { from_idk, filename, data } => {
                                let safe = filename.rsplit(['/', '\\']).next().unwrap_or("file")
                                    .replace(['/', '\\', '\0'], "_");
                                let saved = format!("dante-recv-{safe}");
                                let _ = std::fs::write(&saved, &data);
                                let from = short_fp(&from_idk);
                                last_msg_ms.insert(from.clone(), now);
                                Item::File { seq, from, filename, size: data.len(), saved }
                            }
                        };
                        inbox.push_back(entry);
                        while inbox.len() > INBOX_CAP { inbox.pop_front(); }
                    }
                }

                if let Ok(events) = engine.poll_typing(now).await {
                    let mut typing = engine_shared.typing.lock().await;
                    for ev in events {
                        let who = match ev.scope {
                            TypingScope::Dm(_) => short_fp(&ev.who),
                            TypingScope::Channel(_) => short_id(&ev.who),
                        };
                        // Drop a signal that predates this sender's last
                        // actual message — they typed, then sent, and the
                        // relay is still serving the stale "typing".
                        if ev.at_ms <= last_msg_ms.get(&who).copied().unwrap_or(0) {
                            continue;
                        }
                        // Key freshness off the signal's own timestamp so a
                        // still-served-but-stale signal ages out on time.
                        match typing.iter_mut().find(|(w, _)| *w == who) {
                            Some(e) => e.1 = e.1.max(ev.at_ms),
                            None => typing.push((who, ev.at_ms)),
                        }
                    }
                    typing.retain(|(_, at)| now.saturating_sub(*at) <= TYPING_FRESH_MS);
                }
                last_msg_ms.retain(|_, t| now.saturating_sub(*t) <= 60_000);

                refresh_channels(&engine, &engine_shared).await;
            }
        }
    }
}

async fn refresh_channels(engine: &Engine, shared: &Shared) {
    let views: Vec<ChanView> = engine
        .channels()
        .into_iter()
        .map(|c| ChanView {
            id: id_b32(&c.channel_id),
            name: c.channel_name,
            server: c.server_name,
            root: id_b32(&c.server_root),
            auto_kick_days: engine
                .auto_kick_window(&c.server_root)
                .map(|ms| ms / 86_400_000)
                .unwrap_or(0),
        })
        .collect();
    *shared.channels.lock().await = views;
}

async fn handle_cmd(engine: &mut Engine, shared: &Shared, cmd: Cmd) {
    match cmd {
        Cmd::Send { to, text, reply } => {
            let r = match parse_target(&to) {
                Ok((true, id)) => engine
                    .send_channel(&id, &text, now_ms())
                    .await
                    .map(|_| "ok".into())
                    .map_err(|e| e.to_string()),
                Ok((false, id)) => engine
                    .send_dm(&id, &text, now_ms())
                    .await
                    .map(|_| "ok".into())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e),
            };
            if let Ok("ok") = r.as_deref() {
                if let Some(rest) = to.strip_prefix('#') {
                    if let Ok(id) = parse_fingerprint(rest) {
                        shared.inbox.lock().await.push_back(Item::Channel {
                            seq: shared.next(),
                            channel: id_b32(&id),
                            channel_name: String::new(),
                            from: "you".into(),
                            text,
                            ref_seq: 0,
                        });
                    }
                }
            }
            let _ = reply.send(r);
        }
        Cmd::CreateServer { name, reply } => {
            let r = engine
                .create_server(&name, now_ms())
                .await
                .map(|root| id_b32(&root))
                .map_err(|e| e.to_string());
            let _ = reply.send(r);
        }
        Cmd::CreateChannel {
            server,
            name,
            reply,
        } => {
            let r = match parse_fingerprint(&server) {
                Ok(root) => engine
                    .create_channel(&root, &name, true)
                    .map(|id| id_b32(&id))
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::Invite {
            channel,
            peer,
            reply,
        } => {
            let channel = channel.strip_prefix('#').unwrap_or(&channel);
            let r = match (parse_fingerprint(channel), parse_fingerprint(&peer)) {
                (Ok(cid), Ok(pid)) => engine
                    .invite_to_channel(&cid, &pid, now_ms())
                    .await
                    .map(|_| "ok".into())
                    .map_err(|e| e.to_string()),
                _ => Err("bad channel id or fingerprint".into()),
            };
            let _ = reply.send(r);
        }
        Cmd::InviteLink {
            channel,
            ttl_secs,
            max_uses,
            reply,
        } => {
            let channel = channel.strip_prefix('#').unwrap_or(&channel);
            let r = match parse_fingerprint(channel) {
                Ok(cid) => engine
                    .create_invite_link(&cid, ttl_secs.saturating_mul(1000), max_uses, now_ms())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::Redeem {
            link,
            password,
            reply,
        } => {
            let pw = (!password.is_empty()).then_some(password.as_str());
            let r = engine
                .redeem_invite(&link, pw, now_ms())
                .await
                .map(|_| "ok".into())
                .map_err(|e| e.to_string());
            let _ = reply.send(r);
        }
        Cmd::JoinPw {
            server,
            password,
            reply,
        } => {
            let r = match parse_fingerprint(&server) {
                Ok(root) => engine
                    .set_join_password(&root, (!password.is_empty()).then_some(password.as_str()))
                    .map(|_| "ok".into())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::RemoveMember {
            channel,
            member,
            reply,
        } => {
            let channel = channel.strip_prefix('#').unwrap_or(&channel);
            let r = match (parse_fingerprint(channel), parse_fingerprint(&member)) {
                (Ok(cid), Ok(mid)) => engine
                    .request_kick(&cid, &mid, now_ms())
                    .await
                    .map(|_| "ok".into())
                    .map_err(|e| e.to_string()),
                _ => Err("bad channel id or fingerprint".into()),
            };
            let _ = reply.send(r);
        }
        Cmd::SetRole {
            server,
            id,
            name,
            allow,
            deny,
            rank,
            reply,
        } => {
            let r = match parse_fingerprint(&server) {
                Ok(root) => engine
                    .set_role(&root, id, &name, allow, deny, rank, now_ms())
                    .await
                    .map(|rid| rid.to_string())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::AssignRole {
            server,
            member,
            role_id,
            add,
            reply,
        } => {
            let r = match (parse_fingerprint(&server), parse_fingerprint(&member)) {
                (Ok(root), Ok(mid)) => engine
                    .assign_role(&root, &mid, role_id, add, now_ms())
                    .await
                    .map(|_| "ok".into())
                    .map_err(|e| e.to_string()),
                _ => Err("bad server root or fingerprint".into()),
            };
            let _ = reply.send(r);
        }
        Cmd::Discover {
            server,
            on,
            summary,
            tags,
            reply,
        } => {
            let r = match parse_fingerprint(&server) {
                Ok(root) => engine
                    .set_discoverable(&root, on, &summary, tags, now_ms())
                    .await
                    .map(|_| "ok".into())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::DiscoverJoin {
            server,
            password,
            reply,
        } => {
            let pw = (!password.is_empty()).then_some(password.as_str());
            let r = match parse_fingerprint(&server) {
                Ok(root) => engine
                    .join_discovered(&root, pw, now_ms())
                    .await
                    .map(|_| "ok".into())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::DiscoverList { reply } => {
            let list: Vec<_> = engine
                .discoverable_servers()
                .into_iter()
                .map(|s| {
                    serde_json::json!({
                        "root": id_b32(&s.server_root),
                        "name": s.name,
                        "summary": s.summary,
                        "tags": s.tags,
                    })
                })
                .collect();
            let _ = reply.send(serde_json::to_string(&list).unwrap_or_else(|_| "[]".into()));
        }
        Cmd::React {
            channel,
            target_seq,
            emoji,
            remove,
            reply,
        } => {
            let channel = channel.strip_prefix('#').unwrap_or(&channel);
            let r = match parse_fingerprint(channel) {
                Ok(cid) => engine
                    .send_react(&cid, target_seq, &emoji, remove, now_ms())
                    .await
                    .map(|_| "ok".into())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::GetPolicy { server, reply } => {
            let json = match engine.server_policy(&server) {
                Some(p) => {
                    let roles: Vec<_> = p
                        .roles
                        .iter()
                        .map(|r| {
                            serde_json::json!({
                                "id": r.id, "name": r.name,
                                "allow": r.allow, "deny": r.deny, "rank": r.rank,
                            })
                        })
                        .collect();
                    let assignments: Vec<_> = p
                        .assignments
                        .iter()
                        .map(|(m, ids)| serde_json::json!({ "member": id_b32(m), "roles": ids }))
                        .collect();
                    let me = *engine.identity().id().as_bytes();
                    serde_json::json!({
                        "version": p.version,
                        "owner": id_b32(&p.owner_id),
                        "roles": roles,
                        "assignments": assignments,
                        "me_perms": engine.member_perms(&server, &me),
                    })
                    .to_string()
                }
                None => "{}".to_string(),
            };
            let _ = reply.send(json);
        }
        Cmd::Safety { peer, reply } => {
            let json = match engine.safety_number(&peer) {
                Some(number) => serde_json::json!({
                    "available": true,
                    "number": number,
                    "verified": engine.is_verified(&peer),
                })
                .to_string(),
                None => serde_json::json!({ "available": false }).to_string(),
            };
            let _ = reply.send(json);
        }
        Cmd::Verify { peer, on, reply } => {
            let r = match parse_fingerprint(&peer) {
                Ok(id) => engine
                    .set_verified(&id, on)
                    .map(|_| if on { "verified" } else { "cleared" }.to_string())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::AutoKick {
            server,
            days,
            reply,
        } => {
            let r = match parse_fingerprint(&server) {
                Ok(root) => {
                    let window = (days > 0.0).then_some((days * 86_400_000.0) as u64);
                    engine
                        .set_auto_kick(&root, window)
                        .map(|_| "ok".into())
                        .map_err(|e| e.to_string())
                }
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::Typing { to } => match parse_target(&to) {
            Ok((true, id)) => {
                let _ = engine.send_typing_channel(&id, now_ms()).await;
            }
            Ok((false, id)) => {
                let _ = engine.send_typing_dm(&id, now_ms()).await;
            }
            Err(_) => {}
        },
    }
}

/// Render the design's typing-indicator rule over the currently-fresh typers.
fn typing_text(entries: &[(String, u64)], now: u64) -> String {
    let mut who: Vec<&str> = entries
        .iter()
        .filter(|(_, seen)| now.saturating_sub(*seen) <= TYPING_FRESH_MS)
        .map(|(w, _)| w.as_str())
        .collect();
    who.sort_unstable();
    who.dedup();
    match who.as_slice() {
        [] => String::new(),
        [a] => format!("{a} is typing…"),
        [a, b] => format!("{a} and {b} are typing…"),
        [a, b, c] => format!("{a}, {b} and {c} are typing…"),
        _ => "several people are typing…".to_string(),
    }
}

async fn serve_conn(mut stream: TcpStream, shared: Arc<Shared>) -> Result<()> {
    let mut buf = Vec::with_capacity(2048);
    let head_end = loop {
        let mut chunk = [0u8; 2048];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 64 * 1024 {
            return respond(&mut stream, 413, "text/plain", b"headers too large").await;
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));

    let content_length: usize = lines
        .clone()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse().ok())
        })
        .flatten()
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }

    match (method, path) {
        ("GET", "/") => {
            respond(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                INDEX_HTML.as_bytes(),
            )
            .await
        }

        ("GET", "/api/me") => {
            let (fp, words) = shared.me.lock().await.clone();
            let body = serde_json::json!({ "fingerprint": fp, "words": words }).to_string();
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("GET", "/api/state") => {
            let ready = shared.ready.load(Ordering::Relaxed);
            let fp = shared.me.lock().await.0.clone();
            let body = serde_json::json!({
                "ready": ready,
                "fingerprint": fp,
                "has_keystore": shared.boot.keystore_path.exists(),
            })
            .to_string();
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("POST", "/api/onboard") => {
            #[derive(serde::Deserialize)]
            struct Req {
                mode: String,
                passphrase: String,
                #[serde(default)]
                blob: String,
            }
            if shared.ready.load(Ordering::Relaxed) {
                return respond(&mut stream, 409, "text/plain", b"already set up").await;
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            if r.passphrase.len() < 6 {
                return respond(&mut stream, 400, "text/plain", b"passphrase too short").await;
            }
            let identity = match r.mode.as_str() {
                "create" => Ok(Identity::generate(now_ms())),
                "unlock" => std::fs::read(&shared.boot.keystore_path)
                    .map_err(|_| "no keystore file to unlock".to_string())
                    .and_then(|bytes| {
                        keystore::open(&bytes, r.passphrase.as_bytes())
                            .map_err(|_| "wrong passphrase".to_string())
                    }),
                "import" => match hex_bytes(&r.blob) {
                    Some(bytes) => keystore::open(&bytes, r.passphrase.as_bytes())
                        .or_else(|_| backup::import(&bytes, r.passphrase.as_bytes()))
                        .map_err(|_| "could not open that blob with this passphrase".to_string()),
                    None => Err("recovery blob is not valid hex".to_string()),
                },
                _ => Err("mode must be create, unlock or import".to_string()),
            };
            let identity = match identity {
                Ok(id) => id,
                Err(e) => return respond(&mut stream, 400, "text/plain", e.as_bytes()).await,
            };

            // Persist the keystore so the next run loads it directly.
            match keystore::seal(&identity, r.passphrase.as_bytes()) {
                Ok(sealed) => {
                    if let Err(e) = std::fs::write(&shared.boot.keystore_path, sealed) {
                        return respond(&mut stream, 500, "text/plain", e.to_string().as_bytes())
                            .await;
                    }
                }
                Err(_) => return respond(&mut stream, 500, "text/plain", b"seal failed").await,
            }
            let backup_hex = backup::export(&identity, r.passphrase.as_bytes())
                .ok()
                .map(|b| to_hex(&b))
                .unwrap_or_default();

            match connect_and_start(Arc::clone(&shared), identity).await {
                Ok((fp, words)) => {
                    let out = serde_json::json!({
                        "fingerprint": fp, "words": words, "backup": backup_hex,
                    })
                    .to_string();
                    respond(&mut stream, 200, "application/json", out.as_bytes()).await
                }
                Err(e) => respond(&mut stream, 502, "text/plain", e.as_bytes()).await,
            }
        }

        ("GET", "/api/channels") => {
            let chans = shared.channels.lock().await;
            let body = serde_json::to_string(&*chans).unwrap_or_else(|_| "[]".into());
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("GET", "/api/typing") => {
            let text = {
                let mut typing = shared.typing.lock().await;
                let now = now_ms();
                typing.retain(|(_, seen)| now.saturating_sub(*seen) <= TYPING_FRESH_MS);
                typing_text(&typing, now)
            };
            let body = serde_json::json!({ "text": text }).to_string();
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("POST", "/api/typing") => {
            #[derive(serde::Deserialize)]
            struct Req {
                to: String,
            }
            if let Ok(r) = serde_json::from_slice::<Req>(&body) {
                let _ = shared.cmd.send(Cmd::Typing { to: r.to }).await;
            }
            respond(&mut stream, 200, "application/json", b"{\"ok\":\"ok\"}").await
        }

        ("GET", "/api/messages") => {
            let since: u64 = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("since=").and_then(|v| v.parse().ok()))
                .unwrap_or(0);
            let inbox = shared.inbox.lock().await;
            let items: Vec<&Item> = inbox.iter().filter(|i| i.seq() > since).collect();
            let body = serde_json::to_string(&items).unwrap_or_else(|_| "[]".into());
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("POST", "/api/send") => {
            #[derive(serde::Deserialize)]
            struct Req {
                to: String,
                text: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::Send {
                to: r.to,
                text: r.text,
                reply,
            })
            .await
        }

        ("POST", "/api/server") => {
            #[derive(serde::Deserialize)]
            struct Req {
                name: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::CreateServer {
                name: r.name,
                reply,
            })
            .await
        }

        ("POST", "/api/channel") => {
            #[derive(serde::Deserialize)]
            struct Req {
                server: String,
                name: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::CreateChannel {
                server: r.server,
                name: r.name,
                reply,
            })
            .await
        }

        ("POST", "/api/invite") => {
            #[derive(serde::Deserialize)]
            struct Req {
                channel: String,
                peer: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::Invite {
                channel: r.channel,
                peer: r.peer,
                reply,
            })
            .await
        }

        ("POST", "/api/invite-link") => {
            #[derive(serde::Deserialize)]
            struct Req {
                channel: String,
                #[serde(default = "default_ttl")]
                ttl_secs: u64,
                #[serde(default)]
                max_uses: u32,
            }
            fn default_ttl() -> u64 {
                7 * 24 * 3600
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::InviteLink {
                channel: r.channel,
                ttl_secs: r.ttl_secs,
                max_uses: r.max_uses,
                reply,
            })
            .await
        }

        ("POST", "/api/redeem") => {
            #[derive(serde::Deserialize)]
            struct Req {
                link: String,
                #[serde(default)]
                password: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::Redeem {
                link: r.link,
                password: r.password,
                reply,
            })
            .await
        }

        ("GET", "/api/reactions") => {
            let map = shared.reactions.lock().await;
            let obj: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .map(|(seq, emojis)| {
                    let arr: Vec<_> = emojis
                        .iter()
                        .map(|(e, by)| {
                            let mut v: Vec<&String> = by.iter().collect();
                            v.sort();
                            serde_json::json!({ "emoji": e, "count": by.len(), "by": v })
                        })
                        .collect();
                    (seq.to_string(), serde_json::Value::Array(arr))
                })
                .collect();
            let body = serde_json::Value::Object(obj).to_string();
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("POST", "/api/react") => {
            #[derive(serde::Deserialize)]
            struct Req {
                channel: String,
                seq: u64,
                emoji: String,
                #[serde(default)]
                remove: bool,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::React {
                channel: r.channel,
                target_seq: r.seq,
                emoji: r.emoji,
                remove: r.remove,
                reply,
            })
            .await
        }

        ("GET", "/api/discover") => {
            let (tx, rx) = oneshot::channel();
            if shared
                .cmd
                .send(Cmd::DiscoverList { reply: tx })
                .await
                .is_err()
            {
                return respond(&mut stream, 500, "text/plain", b"engine gone").await;
            }
            let body = rx.await.unwrap_or_else(|_| "[]".into());
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("POST", "/api/discover") => {
            #[derive(serde::Deserialize)]
            struct Req {
                server: String,
                on: bool,
                #[serde(default)]
                summary: String,
                #[serde(default)]
                tags: Vec<String>,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::Discover {
                server: r.server,
                on: r.on,
                summary: r.summary,
                tags: r.tags,
                reply,
            })
            .await
        }

        ("POST", "/api/discover/join") => {
            #[derive(serde::Deserialize)]
            struct Req {
                server: String,
                #[serde(default)]
                password: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::DiscoverJoin {
                server: r.server,
                password: r.password,
                reply,
            })
            .await
        }

        ("POST", "/api/joinpw") => {
            #[derive(serde::Deserialize)]
            struct Req {
                server: String,
                #[serde(default)]
                password: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::JoinPw {
                server: r.server,
                password: r.password,
                reply,
            })
            .await
        }

        ("POST", "/api/remove") => {
            #[derive(serde::Deserialize)]
            struct Req {
                channel: String,
                member: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::RemoveMember {
                channel: r.channel,
                member: r.member,
                reply,
            })
            .await
        }

        ("POST", "/api/autokick") => {
            #[derive(serde::Deserialize)]
            struct Req {
                server: String,
                #[serde(default)]
                days: f64,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::AutoKick {
                server: r.server,
                days: r.days,
                reply,
            })
            .await
        }

        ("GET", "/api/safety") => {
            let peer = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("peer="))
                .unwrap_or("");
            let body = match parse_fingerprint(peer) {
                Ok(id) => {
                    let (tx, rx) = oneshot::channel();
                    if shared
                        .cmd
                        .send(Cmd::Safety {
                            peer: id,
                            reply: tx,
                        })
                        .await
                        .is_err()
                    {
                        return respond(&mut stream, 500, "text/plain", b"engine gone").await;
                    }
                    rx.await.unwrap_or_else(|_| "{\"available\":false}".into())
                }
                Err(_) => "{\"available\":false}".into(),
            };
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("POST", "/api/verify") => {
            #[derive(serde::Deserialize)]
            struct Req {
                peer: String,
                #[serde(default)]
                verified: bool,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::Verify {
                peer: r.peer,
                on: r.verified,
                reply,
            })
            .await
        }

        ("GET", "/api/policy") => {
            let root = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("server="))
                .unwrap_or("");
            let body = match parse_fingerprint(root) {
                Ok(sr) => {
                    let (tx, rx) = oneshot::channel();
                    if shared
                        .cmd
                        .send(Cmd::GetPolicy {
                            server: sr,
                            reply: tx,
                        })
                        .await
                        .is_err()
                    {
                        return respond(&mut stream, 500, "text/plain", b"engine gone").await;
                    }
                    rx.await.unwrap_or_else(|_| "{}".into())
                }
                Err(_) => "{}".into(),
            };
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("POST", "/api/role") => {
            #[derive(serde::Deserialize)]
            struct Req {
                server: String,
                #[serde(default)]
                id: u16,
                name: String,
                #[serde(default)]
                allow: u32,
                #[serde(default)]
                deny: u32,
                #[serde(default)]
                rank: u16,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::SetRole {
                server: r.server,
                id: (r.id != 0).then_some(r.id),
                name: r.name,
                allow: r.allow,
                deny: r.deny,
                rank: r.rank,
                reply,
            })
            .await
        }

        ("POST", "/api/roleassign") => {
            #[derive(serde::Deserialize)]
            struct Req {
                server: String,
                member: String,
                role_id: u16,
                #[serde(default)]
                add: bool,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::AssignRole {
                server: r.server,
                member: r.member,
                role_id: r.role_id,
                add: r.add,
                reply,
            })
            .await
        }

        _ => respond(&mut stream, 404, "text/plain", b"not found").await,
    }
}

async fn dispatch(
    stream: &mut TcpStream,
    shared: &Shared,
    make: impl FnOnce(oneshot::Sender<Result<String, String>>) -> Cmd,
) -> Result<()> {
    let (tx, rx) = oneshot::channel();
    if shared.cmd.send(make(tx)).await.is_err() {
        return respond(stream, 500, "text/plain", b"engine gone").await;
    }
    match rx.await {
        Ok(Ok(s)) => {
            respond(
                stream,
                200,
                "application/json",
                format!("{{\"ok\":{s:?}}}").as_bytes(),
            )
            .await
        }
        Ok(Err(e)) => respond(stream, 502, "text/plain", e.as_bytes()).await,
        Err(_) => respond(stream, 500, "text/plain", b"no reply").await,
    }
}

async fn respond(stream: &mut TcpStream, code: u16, ctype: &str, body: &[u8]) -> Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Status",
    };
    // The page is one self-contained file with inline script/style and only
    // same-origin fetches — lock everything else down so an injected string
    // can't pull in an external script or exfiltrate to another origin.
    const SEC: &str = "Content-Security-Policy: default-src 'none'; \
         script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
         connect-src 'self'; img-src 'self' data:; base-uri 'none'; \
         form-action 'none'; frame-ancestors 'none'\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\n\
         X-Frame-Options: DENY\r\n";
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n{SEC}Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{typing_text, TYPING_FRESH_MS};

    const NOW: u64 = 1_000_000;

    fn e(names: &[&str], age: u64) -> Vec<(String, u64)> {
        names
            .iter()
            .map(|n| (n.to_string(), NOW.saturating_sub(age)))
            .collect()
    }

    #[test]
    fn typing_text_applies_the_coalescing_rule() {
        assert_eq!(typing_text(&e(&[], 0), NOW), "");
        assert_eq!(typing_text(&e(&["A"], 0), NOW), "A is typing…");
        assert_eq!(typing_text(&e(&["A", "B"], 0), NOW), "A and B are typing…");
        assert_eq!(
            typing_text(&e(&["A", "B", "C"], 0), NOW),
            "A, B and C are typing…"
        );
        assert_eq!(
            typing_text(&e(&["A", "B", "C", "D"], 0), NOW),
            "several people are typing…"
        );
        // Stale entries are ignored.
        assert_eq!(typing_text(&e(&["A"], TYPING_FRESH_MS + 1), NOW), "");
        // Duplicates collapse.
        assert_eq!(typing_text(&e(&["A", "A"], 0), NOW), "A is typing…");
    }
}
