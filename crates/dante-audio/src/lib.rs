//! Opus codec + OS capture/playback for DaNTe 1:1 calls.
//!
//! `dante-voice` already carries **Opus frames** end to end over the call's
//! SRTP audio track (`Call::push_audio` / `CallEvent::RemoteAudio`, surfaced by
//! `dante_core::Engine::{send_call_audio, take_call_audio}`). This crate is the
//! last mile: turn microphone PCM into Opus frames and Opus frames back into
//! speaker PCM.
//!
//! It is **detached from the workspace** because it links `libopus` and the
//! platform audio stack, which the CI container lacks. Build it on a real host.
//!
//! ## Wiring it to a call
//!
//! ```no_run
//! # async fn demo(engine: &mut dante_core::Engine, peer: [u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
//! use dante_audio::{OpusCodec, Capture, Playback, FRAME_MS};
//!
//! let mut codec = OpusCodec::new()?;
//! let capture = Capture::start()?;   // mic -> 20 ms i16 mono @ 48 kHz
//! let playback = Playback::start()?; // 20 ms i16 mono @ 48 kHz -> speaker
//!
//! loop {
//!     // outbound: mic frame -> Opus -> the call
//!     if let Some(pcm) = capture.try_frame() {
//!         let opus = codec.encode(&pcm)?;
//!         engine.send_call_audio(&peer, &opus, FRAME_MS).await?;
//!     }
//!     // inbound: Opus frames from the call -> PCM -> speaker
//!     for opus in engine.take_call_audio(&peer) {
//!         playback.play(&codec.decode(&opus)?);
//!     }
//!     tokio::time::sleep(std::time::Duration::from_millis(5)).await;
//! }
//! # }
//! ```

use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use crossbeam_channel::{Receiver, Sender};

/// Call audio is 48 kHz mono; one frame is 20 ms = 960 samples.
pub const SAMPLE_RATE: u32 = 48_000;
/// Channels (mono).
pub const CHANNELS: usize = 1;
/// Frame duration in milliseconds — what `Engine::send_call_audio` wants.
pub const FRAME_MS: u32 = 20;
/// Samples per 20 ms frame at 48 kHz mono.
pub const FRAME_SAMPLES: usize = (SAMPLE_RATE as usize / 1000) * FRAME_MS as usize;

/// Anything that can go wrong here.
#[derive(Debug, thiserror::Error)]
pub enum AudioError {
    /// The Opus library rejected an encode/decode.
    #[error("opus: {0}")]
    Opus(#[from] opus::Error),
    /// No input or output device.
    #[error("no audio device: {0}")]
    NoDevice(&'static str),
    /// cpal failed to build or start a stream.
    #[error("audio stream: {0}")]
    Stream(String),
}

/// Opus encoder + decoder for one call. Not `Sync`; own one per call, driven
/// from a single task.
pub struct OpusCodec {
    enc: opus::Encoder,
    dec: opus::Decoder,
    buf: Vec<u8>,
}

impl OpusCodec {
    /// A fresh codec configured for voice (48 kHz mono, VoIP application).
    pub fn new() -> Result<Self, AudioError> {
        let enc = opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip)?;
        let dec = opus::Decoder::new(SAMPLE_RATE, opus::Channels::Mono)?;
        Ok(Self {
            enc,
            dec,
            buf: vec![0u8; 4000],
        })
    }

    /// Encode one 20 ms frame (`FRAME_SAMPLES` `i16` samples) to an Opus packet.
    pub fn encode(&mut self, pcm: &[i16]) -> Result<Vec<u8>, AudioError> {
        let n = self.enc.encode(pcm, &mut self.buf)?;
        Ok(self.buf[..n].to_vec())
    }

    /// Decode one Opus packet back to `FRAME_SAMPLES` `i16` samples. An empty
    /// packet is treated as packet loss (Opus fills with concealment).
    pub fn decode(&mut self, opus: &[u8]) -> Result<Vec<i16>, AudioError> {
        let mut out = vec![0i16; FRAME_SAMPLES];
        let n = self.dec.decode(opus, &mut out, false)?;
        out.truncate(n);
        Ok(out)
    }
}

/// Microphone capture: resamples nothing — assumes the default input config can
/// give 48 kHz; if not, it takes whatever the device offers and the frames may
/// be a different length (the codec still handles 10/20/40/60 ms).
pub struct Capture {
    rx: Receiver<Vec<i16>>,
    _stream: cpal::Stream,
}

impl Capture {
    /// Open the default input device and start delivering ~20 ms `i16` frames.
    pub fn start() -> Result<Self, AudioError> {
        let host = cpal::default_host();
        let device = host
            .default_input_device()
            .ok_or(AudioError::NoDevice("input"))?;
        let config = device
            .default_input_config()
            .map_err(|e| AudioError::Stream(e.to_string()))?;
        let (tx, rx): (Sender<Vec<i16>>, Receiver<Vec<i16>>) = crossbeam_channel::bounded(64);
        let acc = Arc::new(Mutex::new(Vec::<i16>::with_capacity(FRAME_SAMPLES * 2)));

        let acc2 = Arc::clone(&acc);
        let err_fn = |e| eprintln!("dante-audio capture error: {e}");
        let stream = match config.sample_format() {
            cpal::SampleFormat::F32 => device.build_input_stream(
                &config.into(),
                move |data: &[f32], _| {
                    let mut a = acc2.lock().unwrap();
                    for &s in data {
                        a.push((s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16);
                    }
                    while a.len() >= FRAME_SAMPLES {
                        let frame: Vec<i16> = a.drain(..FRAME_SAMPLES).collect();
                        let _ = tx.try_send(frame);
                    }
                },
                err_fn,
                None,
            ),
            cpal::SampleFormat::I16 => device.build_input_stream(
                &config.into(),
                move |data: &[i16], _| {
                    let mut a = acc2.lock().unwrap();
                    a.extend_from_slice(data);
                    while a.len() >= FRAME_SAMPLES {
                        let frame: Vec<i16> = a.drain(..FRAME_SAMPLES).collect();
                        let _ = tx.try_send(frame);
                    }
                },
                err_fn,
                None,
            ),
            other => return Err(AudioError::Stream(format!("unsupported sample format {other:?}"))),
        }
        .map_err(|e| AudioError::Stream(e.to_string()))?;
        stream.play().map_err(|e| AudioError::Stream(e.to_string()))?;
        Ok(Self {
            rx,
            _stream: stream,
        })
    }

    /// The next captured frame, if one is ready.
    pub fn try_frame(&self) -> Option<Vec<i16>> {
        self.rx.try_recv().ok()
    }
}

/// Speaker playback: hand it decoded `i16` frames and they queue for output.
pub struct Playback {
    tx: Sender<i16>,
    _stream: cpal::Stream,
}

impl Playback {
    /// Open the default output device.
    pub fn start() -> Result<Self, AudioError> {
        let host = cpal::default_host();
        let device = host
            .default_output_device()
            .ok_or(AudioError::NoDevice("output"))?;
        let config = device
            .default_output_config()
            .map_err(|e| AudioError::Stream(e.to_string()))?;
        let channels = config.channels() as usize;
        let (tx, rx): (Sender<i16>, Receiver<i16>) = crossbeam_channel::bounded(SAMPLE_RATE as usize);

        let err_fn = |e| eprintln!("dante-audio playback error: {e}");
        let stream = match config.sample_format() {
            cpal::SampleFormat::F32 => device.build_output_stream(
                &config.into(),
                move |out: &mut [f32], _| {
                    for frame in out.chunks_mut(channels) {
                        let s = rx.try_recv().unwrap_or(0);
                        let f = s as f32 / i16::MAX as f32;
                        for ch in frame.iter_mut() {
                            *ch = f;
                        }
                    }
                },
                err_fn,
                None,
            ),
            cpal::SampleFormat::I16 => device.build_output_stream(
                &config.into(),
                move |out: &mut [i16], _| {
                    for frame in out.chunks_mut(channels) {
                        let s = rx.try_recv().unwrap_or(0);
                        for ch in frame.iter_mut() {
                            *ch = s;
                        }
                    }
                },
                err_fn,
                None,
            ),
            other => return Err(AudioError::Stream(format!("unsupported sample format {other:?}"))),
        }
        .map_err(|e| AudioError::Stream(e.to_string()))?;
        stream.play().map_err(|e| AudioError::Stream(e.to_string()))?;
        Ok(Self {
            tx,
            _stream: stream,
        })
    }

    /// Queue a decoded frame for the speaker (drops samples if the buffer is
    /// full — better a glitch than unbounded latency).
    pub fn play(&self, pcm: &[i16]) {
        for &s in pcm {
            let _ = self.tx.try_send(s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opus_round_trips_a_tone() {
        let mut codec = OpusCodec::new().unwrap();
        // 440 Hz sine, one 20 ms frame.
        let pcm: Vec<i16> = (0..FRAME_SAMPLES)
            .map(|i| {
                let t = i as f32 / SAMPLE_RATE as f32;
                (0.3 * (2.0 * std::f32::consts::PI * 440.0 * t).sin() * i16::MAX as f32) as i16
            })
            .collect();

        let packet = codec.encode(&pcm).unwrap();
        assert!(!packet.is_empty() && packet.len() < 400, "sane opus packet");

        let back = codec.decode(&packet).unwrap();
        assert_eq!(back.len(), FRAME_SAMPLES);

        // Lossy, but energy should be in the same ballpark (within ~6 dB).
        let energy = |s: &[i16]| s.iter().map(|&x| (x as f64).powi(2)).sum::<f64>().sqrt();
        let ratio = energy(&back) / energy(&pcm);
        assert!(ratio > 0.5 && ratio < 2.0, "round-trip energy ratio {ratio}");
    }

    #[test]
    fn empty_packet_is_concealment_not_an_error() {
        let mut codec = OpusCodec::new().unwrap();
        let frame = codec.decode(&[]).unwrap();
        assert_eq!(frame.len(), FRAME_SAMPLES);
    }
}
