//! Microphone / speaker bridge for 1:1 calls.
//!
//! The engine already carries **Opus frames** end to end over the call's SRTP
//! audio track; `dante serve` exposes that as `GET /api/call/audio?peer=` (drain
//! received frames) and `POST /api/call/audio {peer,frames_hex,ms}` (send). This
//! module is the last mile the browser can't do from a plain webview: capture
//! the OS microphone, encode Opus, push it to the local service, and play back
//! whatever the call delivers.
//!
//! It runs on its own OS thread — `cpal::Stream` is `!Send`, so the capture and
//! playback streams must be created and dropped on one thread that never hands
//! them across a task boundary. The thread talks to the already-running
//! `dante-cli` service over localhost HTTP (tiny JSON, `Connection: close`), so
//! it needs no access to the `Engine` that moved into the serve task.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use dante_audio::{Capture, OpusCodec, Playback, FRAME_MS};
use serde_json::Value;

/// Spawn the bridge against the local UI service on `port`. The returned handle
/// can be ignored; the thread lives for the process.
pub fn spawn(port: u16) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("dante-audio-bridge".into())
        .spawn(move || run(port))
        .expect("spawn dante-audio bridge thread")
}

fn run(port: u16) {
    let mut codec = match OpusCodec::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("dante-audio: codec init failed, calls will be silent: {e}");
            return;
        }
    };

    let mut streams: Option<(Capture, Playback)> = None;
    let mut peer: Option<String> = None;
    let mut last_poll = Instant::now() - Duration::from_secs(1);
    let mut device_warned = false;

    loop {
        // Refresh which call (if any) is connected, ~2x/second.
        if last_poll.elapsed() >= Duration::from_millis(500) {
            last_poll = Instant::now();
            let next = connected_call(port);
            if next != peer {
                match &next {
                    Some(p) => eprintln!("dante-audio: call {p} connected — mic/speaker on"),
                    None => eprintln!("dante-audio: call ended — mic/speaker off"),
                }
                peer = next;
            }
        }

        match (peer.is_some(), streams.is_some()) {
            (true, false) => match (Capture::start(), Playback::start()) {
                (Ok(cap), Ok(play)) => {
                    streams = Some((cap, play));
                    device_warned = false;
                }
                (cap, play) => {
                    if !device_warned {
                        eprintln!(
                            "dante-audio: no usable audio device (in: {:?}, out: {:?})",
                            cap.err(),
                            play.err()
                        );
                        device_warned = true;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            },
            (false, true) => streams = None, // dropping stops the OS streams
            _ => {}
        }

        let (Some(p), Some((cap, play))) = (peer.as_deref(), streams.as_ref()) else {
            std::thread::sleep(Duration::from_millis(150));
            continue;
        };

        // Mic -> call. Batch whatever the capture ring has queued so a slow HTTP
        // round-trip doesn't fall behind real time.
        let mut hexes: Vec<String> = Vec::new();
        while let Some(pcm) = cap.try_frame() {
            match codec.encode(&pcm) {
                Ok(opus) => hexes.push(to_hex(&opus)),
                Err(e) => eprintln!("dante-audio: encode failed: {e}"),
            }
            if hexes.len() >= 25 {
                break;
            }
        }
        if !hexes.is_empty() {
            let payload = serde_json::json!({ "peer": p, "frames_hex": hexes, "ms": FRAME_MS });
            if let Err(e) = http(port, "POST", "/api/call/audio", &payload.to_string()) {
                eprintln!("dante-audio: send failed: {e}");
            }
        }

        // Call -> speaker.
        match http(port, "GET", &format!("/api/call/audio?peer={p}"), "") {
            Ok(body) => {
                for opus in frames_from_json(&body) {
                    match codec.decode(&opus) {
                        Ok(pcm) => play.play(&pcm),
                        Err(e) => eprintln!("dante-audio: decode failed: {e}"),
                    }
                }
            }
            Err(e) => eprintln!("dante-audio: recv failed: {e}"),
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The peer fingerprint of the one call in state `connected`, if any.
fn connected_call(port: u16) -> Option<String> {
    let body = http(port, "GET", "/api/calls", "").ok()?;
    let rows: Value = serde_json::from_str(&body).ok()?;
    rows.as_array()?.iter().find_map(|row| {
        (row.get("state")?.as_str()? == "connected")
            .then(|| row.get("peer")?.as_str().map(str::to_string))
            .flatten()
    })
}

/// Opus packets from a `{"frames":["<hex>",…]}` body.
fn frames_from_json(body: &str) -> Vec<Vec<u8>> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    v.get("frames")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|f| f.as_str())
                .filter(|h| !h.is_empty())
                .filter_map(from_hex)
                .collect()
        })
        .unwrap_or_default()
}

// --- tiny localhost HTTP, so the bridge needs no HTTP client dependency ---

fn http(port: u16, method: &str, path: &str, body: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_millis(1500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(1500)))?;
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    Ok(raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or(raw))
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_opus_frames_from_recv_json() {
        let body = r#"{"frames":["01ff","abcd",""]}"#;
        assert_eq!(
            frames_from_json(body),
            vec![vec![0x01, 0xff], vec![0xab, 0xcd]]
        );
        assert!(frames_from_json(r#"{"frames":[]}"#).is_empty());
        assert!(frames_from_json("not json").is_empty());
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0u8, 1, 15, 16, 255, 128];
        assert_eq!(from_hex(&to_hex(&bytes)).unwrap(), bytes);
        assert!(from_hex("abc").is_none());
    }
}
