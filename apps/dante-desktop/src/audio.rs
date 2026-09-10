//! Microphone / speaker bridge for calls — 1:1 and group.
//!
//! The engine already carries **Opus frames** end to end over each call leg's
//! SRTP audio track; `dante serve` exposes that as `GET /api/call/audio?peer=`
//! (drain received frames) and `POST /api/call/audio {peer,frames_hex,ms}`
//! (send). This module is the last mile the browser can't do from a plain
//! webview: capture the OS microphone once, fan the encoded frames out to
//! every connected leg, decode each leg with its own Opus decoder, and play
//! back a summed mix.
//!
//! For a 1:1 call there is one leg; for a group call the engine keeps a full
//! mesh, so `/api/calls` lists one `connected` row per participant and this
//! bridge drives them all.
//!
//! It runs on its own OS thread — `cpal::Stream` is `!Send`, so the capture and
//! playback streams must be created and dropped on one thread that never hands
//! them across a task boundary. The thread talks to the already-running
//! `dante-cli` service over localhost HTTP (tiny JSON, `Connection: close`), so
//! it needs no access to the `Engine` that moved into the serve task.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::localapi::http;

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
    let mut mic = match OpusCodec::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("dante-audio: codec init failed, calls will be silent: {e}");
            return;
        }
    };

    let mut streams: Option<(Capture, Playback)> = None;
    // One decoder per remote peer — Opus decoder state is per stream.
    let mut decoders: HashMap<String, OpusCodec> = HashMap::new();
    let mut peers: Vec<String> = Vec::new();
    let mut last_poll = Instant::now() - Duration::from_secs(1);
    let mut device_warned = false;

    loop {
        // Refresh the set of connected legs (1:1 call or every leg of a group
        // call), ~2x/second.
        if last_poll.elapsed() >= Duration::from_millis(500) {
            last_poll = Instant::now();
            let next = connected_peers(port);
            if next != peers {
                eprintln!("dante-audio: {} connected leg(s)", next.len());
                decoders.retain(|k, _| next.contains(k));
                peers = next;
            }
        }

        match (peers.is_empty(), streams.is_some()) {
            (false, false) => match (Capture::start(), Playback::start()) {
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
            (true, true) => streams = None, // no legs — release the devices
            _ => {}
        }

        let (Some((cap, play)), false) = (streams.as_ref(), peers.is_empty()) else {
            std::thread::sleep(Duration::from_millis(150));
            continue;
        };

        // Mic -> every connected leg. Encode once; fan the frames out.
        let mut hexes: Vec<String> = Vec::new();
        while let Some(pcm) = cap.try_frame() {
            match mic.encode(&pcm) {
                Ok(opus) => hexes.push(to_hex(&opus)),
                Err(e) => eprintln!("dante-audio: encode failed: {e}"),
            }
            if hexes.len() >= 25 {
                break;
            }
        }
        if !hexes.is_empty() {
            for p in &peers {
                let payload = serde_json::json!({ "peer": p, "frames_hex": hexes, "ms": FRAME_MS });
                if let Err(e) = http(port, "POST", "/api/call/audio", &payload.to_string()) {
                    eprintln!("dante-audio: send to {p} failed: {e}");
                }
            }
        }

        // Every leg -> a summed mix -> the speaker.
        let mut mix: Vec<i32> = Vec::new();
        for p in &peers {
            let dec = decoders.entry(p.clone()).or_insert_with(|| {
                OpusCodec::new().expect("second OpusCodec init should not fail")
            });
            let Ok(body) = http(port, "GET", &format!("/api/call/audio?peer={p}"), "") else {
                continue;
            };
            let mut at = 0usize;
            for opus in frames_from_json(&body) {
                match dec.decode(&opus) {
                    Ok(pcm) => {
                        if mix.len() < at + pcm.len() {
                            mix.resize(at + pcm.len(), 0);
                        }
                        for (i, s) in pcm.iter().enumerate() {
                            mix[at + i] += i32::from(*s);
                        }
                        at += pcm.len();
                    }
                    Err(e) => eprintln!("dante-audio: decode from {p} failed: {e}"),
                }
            }
        }
        if !mix.is_empty() {
            let clamped: Vec<i16> = mix
                .iter()
                .map(|s| (*s).clamp(i16::MIN as i32, i16::MAX as i32) as i16)
                .collect();
            play.play(&clamped);
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Every call leg currently in state `connected` (a 1:1 call, or each leg of a
/// group-call mesh).
fn connected_peers(port: u16) -> Vec<String> {
    let Ok(body) = http(port, "GET", "/api/calls", "") else {
        return Vec::new();
    };
    let Ok(rows) = serde_json::from_str::<Value>(&body) else {
        return Vec::new();
    };
    rows.as_array()
        .map(|arr| {
            arr.iter()
                .filter(|r| r.get("state").and_then(Value::as_str) == Some("connected"))
                .filter_map(|r| r.get("peer").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
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
