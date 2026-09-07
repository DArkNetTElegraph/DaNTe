//! `dante serve` — run the engine behind a tiny local HTTP UI.
//!
//! Single user, localhost only. A minimal hand-rolled HTTP/1.1 handler serves
//! the embedded SPA and a JSON API:
//! `GET /api/me`, `GET /api/messages?since=N`, `POST /api/send {to,text}`.

use std::{collections::VecDeque, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use dante_core::{Engine, Inbound};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, Mutex},
};

use crate::{now_ms, parse_fingerprint};

const INDEX_HTML: &str = include_str!("../web/index.html");
const INBOX_CAP: usize = 500;

enum Cmd {
    Send {
        to: String,
        text: String,
        reply: oneshot::Sender<Result<(), String>>,
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
}

impl Item {
    fn seq(&self) -> u64 {
        match self {
            Item::Message { seq, .. } | Item::File { seq, .. } => *seq,
        }
    }
}

struct Shared {
    inbox: Mutex<VecDeque<Item>>,
    me_fingerprint: String,
    me_words: String,
    cmd: mpsc::Sender<Cmd>,
}

fn short_fp(idk: &[u8; 32]) -> String {
    use dante_crypto::sign::SignPublic;
    use dante_identity::id::IdentityId;
    match SignPublic::from_bytes(idk) {
        Ok(pk) => IdentityId::of(&pk).to_base32(),
        Err(_) => "????".into(),
    }
}

/// Entry point for the `serve` subcommand.
pub async fn run(engine: Engine, http_addr: &str) -> Result<()> {
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Cmd>(32);
    let shared = Arc::new(Shared {
        inbox: Mutex::new(VecDeque::new()),
        me_fingerprint: engine.identity().id().to_base32(),
        me_words: engine.identity().id().to_words(),
        cmd: cmd_tx,
    });

    // Bind and start serving HTTP immediately so the UI is up while the engine
    // does its (possibly slow) announce.
    let listener = TcpListener::bind(http_addr)
        .await
        .with_context(|| format!("binding {http_addr}"))?;
    eprintln!(
        "dante UI on http://{http_addr}  (you are {})",
        shared.me_fingerprint
    );

    // The engine lives in exactly one task.
    let engine_shared = Arc::clone(&shared);
    tokio::spawn(async move {
        let mut engine = engine;
        let mut seq: u64 = 0;

        // Replay stored history into the inbox so the SPA shows past messages.
        {
            let mut inbox = engine_shared.inbox.lock().await;
            for h in engine.history() {
                seq += 1;
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

        let mut tick = tokio::time::interval(Duration::from_secs(2));
        let mut save_tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = save_tick.tick() => { let _ = engine.persist(); }
                Some(cmd) = cmd_rx.recv() => match cmd {
                    Cmd::Send { to, text, reply } => {
                        let r = match parse_fingerprint(&to) {
                            Ok(id) => engine.send_dm(&id, &text, now_ms()).await.map_err(|e| e.to_string()),
                            Err(e) => Err(e.to_string()),
                        };
                        let _ = reply.send(r);
                    }
                },
                _ = tick.tick() => {
                    let _ = engine.sync(now_ms()).await;
                    if let Ok(items) = engine.receive_all(now_ms()).await {
                        let mut inbox = engine_shared.inbox.lock().await;
                        for it in items {
                            seq += 1;
                            let entry = match it {
                                Inbound::Message(m) => Item::Message {
                                    seq, from: short_fp(&m.from_idk), text: m.text,
                                },
                                Inbound::File { from_idk, filename, data } => {
                                    let safe = filename.rsplit(['/', '\\']).next().unwrap_or("file")
                                        .replace(['/', '\\', '\0'], "_");
                                    let saved = format!("dante-recv-{safe}");
                                    let _ = std::fs::write(&saved, &data);
                                    Item::File {
                                        seq, from: short_fp(&from_idk), filename,
                                        size: data.len(), saved,
                                    }
                                }
                            };
                            inbox.push_back(entry);
                            while inbox.len() > INBOX_CAP { inbox.pop_front(); }
                        }
                    }
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
            struct SendReq {
                to: String,
                text: String,
            }
            let Ok(req) = serde_json::from_slice::<SendReq>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            let (tx, rx) = oneshot::channel();
            if shared
                .cmd
                .send(Cmd::Send {
                    to: req.to,
                    text: req.text,
                    reply: tx,
                })
                .await
                .is_err()
            {
                return respond(&mut stream, 500, "text/plain", b"engine gone").await;
            }
            match rx.await {
                Ok(Ok(())) => respond(&mut stream, 200, "text/plain", b"ok").await,
                Ok(Err(e)) => respond(&mut stream, 502, "text/plain", e.as_bytes()).await,
                Err(_) => respond(&mut stream, 500, "text/plain", b"no reply").await,
            }
        }

        _ => respond(&mut stream, 404, "text/plain", b"not found").await,
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
