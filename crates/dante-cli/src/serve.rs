//! `dante serve` — run the engine behind a tiny local HTTP UI.
//!
//! Single user, localhost only. A minimal hand-rolled HTTP/1.1 handler serves
//! the embedded SPA and a JSON API:
//! `GET /api/me`, `GET /api/messages?since=N`, `GET /api/channels`,
//! `POST /api/send {to,text}` (`to` may be a fingerprint or `#<channel-id>`),
//! `POST /api/server {name}`, `POST /api/channel {server,name}`,
//! `POST /api/invite {channel,peer}`, `GET /api/typing`,
//! `POST /api/typing {to}`.

use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{Context, Result};
use dante_core::{Engine, Inbound, TypingScope};
use dante_identity::id::IdentityId;
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
    /// Fire-and-forget: broadcast an "I am typing" signal to `to`.
    Typing { to: String },
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
}

struct Shared {
    inbox: Mutex<VecDeque<Item>>,
    channels: Mutex<Vec<ChanView>>,
    /// Recently-seen typers: `(who label, last-seen ms)`. Pruned on read.
    typing: Mutex<Vec<(String, u64)>>,
    /// Monotonic id stamped on every inbox item, drawn by both the engine tick
    /// loop and command handlers so the SPA's `since` cursor never regresses.
    next_seq: AtomicU64,
    me_fingerprint: String,
    me_words: String,
    cmd: mpsc::Sender<Cmd>,
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

/// Entry point for the `serve` subcommand.
pub async fn run(engine: Engine, http_addr: &str) -> Result<()> {
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Cmd>(32);
    let shared = Arc::new(Shared {
        inbox: Mutex::new(VecDeque::new()),
        channels: Mutex::new(Vec::new()),
        typing: Mutex::new(Vec::new()),
        next_seq: AtomicU64::new(0),
        me_fingerprint: engine.identity().id().to_base32(),
        me_words: engine.identity().id().to_words(),
        cmd: cmd_tx,
    });

    let listener = TcpListener::bind(http_addr)
        .await
        .with_context(|| format!("binding {http_addr}"))?;
    eprintln!(
        "dante UI on http://{http_addr}  (you are {})",
        shared.me_fingerprint
    );

    let engine_shared = Arc::clone(&shared);
    tokio::spawn(async move {
        let mut engine = engine;

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
                });
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
        // Last inbound message time per sender label. A real message supersedes
        // any typing signal that predates it (the relay keeps serving the stale
        // signal for a few seconds, which otherwise flashes "is typing" right
        // after the message lands).
        let mut last_msg_ms: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        loop {
            tokio::select! {
                _ = save_tick.tick() => { let _ = engine.persist(); }

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
                            });
                            while inbox.len() > INBOX_CAP { inbox.pop_front(); }
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
    });

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

async fn refresh_channels(engine: &Engine, shared: &Shared) {
    let views: Vec<ChanView> = engine
        .channels()
        .into_iter()
        .map(|c| ChanView {
            id: id_b32(&c.channel_id),
            name: c.channel_name,
            server: c.server_name,
            root: id_b32(&c.server_root),
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
            let body = serde_json::json!({
                "fingerprint": shared.me_fingerprint,
                "words": shared.me_words,
            })
            .to_string();
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
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
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Status",
    };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
