//! 1:1 voice/media calls for DaNTe.
//!
//! This crate owns only the **media transport**: a WebRTC [`Call`] with DTLS-SRTP
//! and a reliable control [`DataChannel`]. It is deliberately signalling-agnostic
//! — the SDP offer/answer and the trickled ICE candidates are opaque strings the
//! caller ships over whatever channel it likes. `dante-core` sends them inside
//! sealed-sender, sender-authenticated ratchet DMs (`Content::Call*`), which is
//! what makes a 1:1 call end-to-end secure: the SDP carries the DTLS certificate
//! fingerprint, so a relay that cannot forge a ratchet message cannot substitute
//! its own DTLS identity for a man-in-the-middle.
//!
//! Group calls are assembled in `dante-core`: each leg is one of these calls,
//! and the per-epoch media key comes from the channel's MLS group
//! (`dante-mls`). Audio capture / playback (cpal + Opus) lives in the detached
//! `dante-audio` crate used by the desktop shell. This crate establishes the
//! encrypted pipe and the control channel; `send_ctl` already carries in-call
//! state (mute/hold) and, in tests, a connectivity probe.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use rtc::media_stream::MediaStreamTrack;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc_media::Sample;
use tokio::sync::{mpsc, Mutex};
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::media_stream::track_local::static_sample::TrackLocalStaticSample;
use webrtc::media_stream::track_remote::{TrackRemote, TrackRemoteEvent};
use webrtc::peer_connection::{
    MediaEngine, PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler,
    RTCConfigurationBuilder, RTCIceCandidateInit, RTCIceServer, RTCPeerConnectionIceEvent,
    RTCPeerConnectionState, RTCSessionDescription, SettingEngineBuilder,
};

/// Opus in `register_default_codecs`: 48 kHz stereo, dynamic payload type 111.
const OPUS_PT: u8 = 111;
const AUDIO_SSRC: u32 = 0x5A_11_CE_01;

/// A STUN or TURN server for ICE. `username` / `credential` are empty for STUN.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IceServer {
    /// e.g. `stun:stun.example.org:3478` or `turn:turn.example.org:3478?transport=udp`.
    pub urls: Vec<String>,
    /// TURN username (empty for STUN).
    pub username: String,
    /// TURN credential (empty for STUN).
    pub credential: String,
}

/// Anything that can go wrong setting up or driving a call.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VoiceError {
    /// The underlying WebRTC stack returned an error.
    #[error("webrtc: {0}")]
    Rtc(String),
    /// The control data channel is not open.
    #[error("call control channel not ready")]
    NotReady,
}

impl From<webrtc::error::Error> for VoiceError {
    fn from(e: webrtc::error::Error) -> Self {
        VoiceError::Rtc(e.to_string())
    }
}

/// Coarse connection state, mirroring `RTCPeerConnectionState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallState {
    /// Not yet connected.
    New,
    /// ICE / DTLS in progress.
    Connecting,
    /// Media path is up.
    Connected,
    /// Temporarily lost; may recover.
    Disconnected,
    /// Permanently failed.
    Failed,
    /// Closed by either side.
    Closed,
}

impl From<RTCPeerConnectionState> for CallState {
    fn from(s: RTCPeerConnectionState) -> Self {
        match s {
            RTCPeerConnectionState::New | RTCPeerConnectionState::Unspecified => CallState::New,
            RTCPeerConnectionState::Connecting => CallState::Connecting,
            RTCPeerConnectionState::Connected => CallState::Connected,
            RTCPeerConnectionState::Disconnected => CallState::Disconnected,
            RTCPeerConnectionState::Failed => CallState::Failed,
            RTCPeerConnectionState::Closed => CallState::Closed,
            _ => CallState::New,
        }
    }
}

/// Something the call wants its owner to act on.
#[derive(Clone, Debug)]
pub enum CallEvent {
    /// A locally-gathered ICE candidate to relay to the peer. An empty string
    /// signals end-of-gathering (relay it too — the peer treats it as a no-op).
    LocalIce(String),
    /// The connection state changed.
    State(CallState),
    /// The control data channel is now open — [`Call::send_ctl`] will work.
    CtlOpen,
    /// A message arrived on the control data channel.
    Ctl(Vec<u8>),
    /// One Opus frame (the RTP payload) received from the peer's audio track.
    /// Feed it to a decoder + speaker.
    RemoteAudio(Vec<u8>),
}

type DcSlot = Arc<Mutex<Option<Arc<dyn DataChannel>>>>;

/// A single 1:1 call.
pub struct Call {
    pc: Arc<dyn PeerConnection>,
    dc: DcSlot,
    audio: Option<Arc<TrackLocalStaticSample>>,
    events: mpsc::UnboundedReceiver<CallEvent>,
}

struct Handler {
    tx: mpsc::UnboundedSender<CallEvent>,
    dc: DcSlot,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for Handler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        let s = event
            .candidate
            .to_json()
            .map(|j| j.candidate)
            .unwrap_or_default();
        let _ = self.tx.send(CallEvent::LocalIce(s));
    }

    async fn on_ice_gathering_state_change(
        &self,
        state: webrtc::peer_connection::RTCIceGatheringState,
    ) {
        if state == webrtc::peer_connection::RTCIceGatheringState::Complete {
            let _ = self.tx.send(CallEvent::LocalIce(String::new()));
        }
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        let _ = self.tx.send(CallEvent::State(state.into()));
    }

    async fn on_data_channel(&self, data_channel: Arc<dyn DataChannel>) {
        *self.dc.lock().await = Some(Arc::clone(&data_channel));
        pump_dc(data_channel, self.tx.clone());
    }

    async fn on_track(&self, track: Arc<dyn TrackRemote>) {
        pump_track(track, self.tx.clone());
    }
}

/// Forward the peer's inbound audio-track RTP payloads as [`CallEvent::RemoteAudio`].
fn pump_track(track: Arc<dyn TrackRemote>, tx: mpsc::UnboundedSender<CallEvent>) {
    tokio::spawn(async move {
        while let Some(ev) = track.poll().await {
            match ev {
                TrackRemoteEvent::OnRtpPacket(pkt) => {
                    if tx
                        .send(CallEvent::RemoteAudio(pkt.payload.to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
                TrackRemoteEvent::OnEnded => break,
                _ => {}
            }
        }
    });
}

/// Minimum Opus bitrate for DaNTe voice, advertised in the SDP and applied by
/// the encoder (`dante-audio`). Voice-grade Opus defaults to ~24–32 kbps; this
/// asks for full-band 64 kbps so calls and voice channels sound clear.
pub const MIN_VOICE_BITRATE: u32 = 64_000;

/// Build the local Opus audio track (48 kHz stereo, PT 111, fixed SSRC).
fn opus_track() -> Result<Arc<TrackLocalStaticSample>, VoiceError> {
    // Keep this matching `register_default_codecs`' Opus entry so `add_track`
    // negotiates cleanly; the higher bitrate is signalled by `tune_opus` on the
    // outbound SDP and applied by the encoder (`dante-audio`).
    let codec = RTCRtpCodec {
        mime_type: "audio/opus".to_owned(),
        clock_rate: 48_000,
        channels: 2,
        sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
        rtcp_feedback: vec![],
    };
    let mst = MediaStreamTrack::new(
        "dante".to_owned(),
        "dante-audio".to_owned(),
        "voice".to_owned(),
        RtpCodecKind::Audio,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(AUDIO_SSRC),
                ..Default::default()
            },
            codec,
            ..Default::default()
        }],
    );
    Ok(Arc::new(
        TrackLocalStaticSample::new(Instant::now(), mst).map_err(VoiceError::from)?,
    ))
}

/// Raise the Opus quality on a generated SDP: register-default-codecs advertises
/// a bare `useinbandfec=1`, which lets the encoder sit at ~24–32 kbps. Add the
/// stereo + `maxaveragebitrate` fmtp params so both ends agree on full-band
/// [`MIN_VOICE_BITRATE`]. Only touches the `a=fmtp:` line for the Opus payload
/// type — safe to feed back into `set_local_description`.
fn tune_opus(sdp: &str) -> String {
    // Find the Opus dynamic payload type from its rtpmap line.
    let pt = sdp.lines().find_map(|l| {
        l.strip_prefix("a=rtpmap:").and_then(|rest| {
            let (pt, codec) = rest.split_once(' ')?;
            codec
                .to_ascii_lowercase()
                .starts_with("opus/")
                .then(|| pt.to_owned())
        })
    });
    let Some(pt) = pt else { return sdp.to_owned() };
    let fmtp_prefix = format!("a=fmtp:{pt} ");
    let rtpmap_prefix = format!("a=rtpmap:{pt} ");
    let mabr = MIN_VOICE_BITRATE.to_string();
    let wanted: [(&str, &str); 4] = [
        ("useinbandfec", "1"),
        ("stereo", "1"),
        ("sprop-stereo", "1"),
        ("maxaveragebitrate", &mabr),
    ];
    let apply = |params: &str| -> String {
        let mut kvs: Vec<String> = params
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        for (k, v) in &wanted {
            let key_eq = format!("{k}=");
            match kvs.iter_mut().find(|p| p.starts_with(&key_eq)) {
                Some(slot) => *slot = format!("{k}={v}"),
                None => kvs.push(format!("{k}={v}")),
            }
        }
        format!("{fmtp_prefix}{}", kvs.join(";"))
    };

    let has_fmtp = sdp.lines().any(|l| l.starts_with(&fmtp_prefix));
    let mut out: Vec<String> = Vec::with_capacity(sdp.lines().count() + 1);
    for line in sdp.lines() {
        if let Some(params) = line.strip_prefix(&fmtp_prefix) {
            out.push(apply(params));
        } else {
            out.push(line.to_owned());
            if !has_fmtp && line.starts_with(&rtpmap_prefix) {
                out.push(apply(""));
            }
        }
    }
    // SDP lines are CRLF-terminated, including a trailing one.
    let mut s = out.join("\r\n");
    s.push_str("\r\n");
    s
}

/// Spawn a task that forwards inbound control-channel messages as [`CallEvent::Ctl`].
fn pump_dc(dc: Arc<dyn DataChannel>, tx: mpsc::UnboundedSender<CallEvent>) {
    tokio::spawn(async move {
        while let Some(ev) = dc.poll().await {
            let out = match ev {
                DataChannelEvent::OnOpen => CallEvent::CtlOpen,
                DataChannelEvent::OnMessage(m) => CallEvent::Ctl(m.data.to_vec()),
                DataChannelEvent::OnClose => break,
                _ => continue,
            };
            if tx.send(out).is_err() {
                break;
            }
        }
    });
}

type Built = (
    Arc<dyn PeerConnection>,
    DcSlot,
    Arc<TrackLocalStaticSample>,
    mpsc::UnboundedSender<CallEvent>,
    mpsc::UnboundedReceiver<CallEvent>,
);

async fn build_pc(ice: &[IceServer]) -> Result<Built, VoiceError> {
    let (tx, rx) = mpsc::unbounded_channel();
    let dc: DcSlot = Arc::new(Mutex::new(None));

    // With no ICE servers a call only connects between peers that can reach each
    // other directly (same host / LAN). STUN adds server-reflexive candidates
    // (each peer's public ip:port); TURN adds a relayed path for symmetric NAT.
    let servers: Vec<RTCIceServer> = ice
        .iter()
        .map(|s| RTCIceServer {
            urls: s.urls.clone(),
            username: s.username.clone(),
            credential: s.credential.clone(),
        })
        .collect();
    let config = RTCConfigurationBuilder::default()
        .with_ice_servers(servers)
        .build();
    let setting = SettingEngineBuilder::default()
        .with_include_loopback_candidate(true)
        .build();

    let mut media = MediaEngine::default();
    media.register_default_codecs().map_err(VoiceError::from)?;

    let pc = PeerConnectionBuilder::<&str>::new()
        .with_configuration(config)
        .with_setting_engine(setting)
        .with_media_engine(media)
        .with_handler(Arc::new(Handler {
            tx: tx.clone(),
            dc: Arc::clone(&dc),
        }))
        .with_udp_addrs(vec!["0.0.0.0:0"])
        .build()
        .await?;
    let pc: Arc<dyn PeerConnection> = Arc::new(pc);

    let audio = opus_track()?;
    pc.add_track(audio.clone()).await?;

    Ok((pc, dc, audio, tx, rx))
}

impl Call {
    /// Caller side with no ICE servers (direct / LAN only).
    pub async fn offer() -> Result<(Call, String), VoiceError> {
        Self::offer_with(&[]).await
    }

    /// Callee side with no ICE servers.
    pub async fn answer(offer_sdp: &str) -> Result<(Call, String), VoiceError> {
        Self::answer_with(offer_sdp, &[]).await
    }

    /// Caller side: build the connection and the control channel using `ice`
    /// (STUN/TURN), return the call plus the SDP **offer** to hand to the peer.
    pub async fn offer_with(ice: &[IceServer]) -> Result<(Call, String), VoiceError> {
        Self::offer_inner(0, ice).await
    }

    /// Caller side for a participant that will talk to an SFU: like
    /// [`Call::offer_with`], but the offer also advertises `recv_slots`
    /// **receive-only** audio m-lines. An SDP answer cannot add media sections
    /// the offer did not carry, so an SFU participant must offer one receive
    /// slot per possible source up front (`room_size - 1` for a room it
    /// starts in). The default 1:1 flow uses [`Call::offer_with`] with none.
    pub async fn offer_for_sfu(
        recv_slots: usize,
        ice: &[IceServer],
    ) -> Result<(Call, String), VoiceError> {
        Self::offer_inner(recv_slots, ice).await
    }

    async fn offer_inner(
        recv_slots: usize,
        ice: &[IceServer],
    ) -> Result<(Call, String), VoiceError> {
        let (pc, dc, audio, tx, events) = build_pc(ice).await?;

        let channel = pc.create_data_channel("dante", None).await?;
        *dc.lock().await = Some(Arc::clone(&channel));
        pump_dc(channel, tx);

        for _ in 0..recv_slots {
            pc.add_transceiver_from_kind(
                RtpCodecKind::Audio,
                Some(RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Recvonly,
                    ..Default::default()
                }),
            )
            .await?;
        }

        let offer = pc.create_offer(None).await?;
        pc.set_local_description(offer.clone()).await?;
        // webrtc-rs rejects a munged *local* description, so raise the Opus
        // quality only on the copy the peer receives — the encoder bitrate
        // (dante-audio) is the real lever; this signals the ceiling.
        Ok((
            Call {
                pc,
                dc,
                audio: Some(audio),
                events,
            },
            tune_opus(&offer.sdp),
        ))
    }

    /// Callee side: apply a received **offer** with `ice` servers, return the
    /// call plus the SDP **answer**. The caller's control channel arrives via
    /// `on_data_channel`.
    pub async fn answer_with(
        offer_sdp: &str,
        ice: &[IceServer],
    ) -> Result<(Call, String), VoiceError> {
        let (pc, dc, audio, _tx, events) = build_pc(ice).await?;
        pc.set_remote_description(RTCSessionDescription::offer(offer_sdp.to_owned())?)
            .await?;
        let answer = pc.create_answer(None).await?;
        pc.set_local_description(answer.clone()).await?;
        Ok((
            Call {
                pc,
                dc,
                audio: Some(audio),
                events,
            },
            tune_opus(&answer.sdp),
        ))
    }

    /// Caller side: apply the peer's **answer**.
    pub async fn set_answer(&self, answer_sdp: &str) -> Result<(), VoiceError> {
        self.pc
            .set_remote_description(RTCSessionDescription::answer(answer_sdp.to_owned())?)
            .await?;
        Ok(())
    }

    /// Feed a trickled ICE candidate from the peer. Empty string = no-op.
    pub async fn add_ice(&self, candidate: &str) -> Result<(), VoiceError> {
        if candidate.is_empty() {
            return Ok(());
        }
        self.pc
            .add_ice_candidate(RTCIceCandidateInit {
                candidate: candidate.to_owned(),
                ..Default::default()
            })
            .await?;
        Ok(())
    }

    /// Send one Opus frame (`ms` = its duration, e.g. 20) on the audio track.
    /// No-op if the call has no audio track.
    pub async fn push_audio(&self, opus: &[u8], ms: u32) -> Result<(), VoiceError> {
        let Some(track) = &self.audio else {
            return Ok(());
        };
        let sample = Sample {
            data: Bytes::copy_from_slice(opus),
            timestamp: Instant::now(),
            duration: Duration::from_millis(u64::from(ms)),
            packet_timestamp: 0,
            prev_dropped_packets: 0,
            prev_padding_packets: 0,
        };
        track
            .write_sample(AUDIO_SSRC, OPUS_PT, &sample, &[])
            .await
            .map_err(VoiceError::from)
    }

    /// Send bytes on the reliable control channel (mute/hold state, probes).
    pub async fn send_ctl(&self, data: &[u8]) -> Result<(), VoiceError> {
        let guard = self.dc.lock().await;
        let dc = guard.as_ref().ok_or(VoiceError::NotReady)?;
        dc.send(BytesMut::from(data)).await?;
        Ok(())
    }

    /// The next event (ICE to relay, state change, inbound control message), or
    /// `None` once the call is dropped.
    pub async fn next_event(&mut self) -> Option<CallEvent> {
        self.events.recv().await
    }

    /// Non-blocking drain of one pending event, for pollers that cannot await.
    pub fn try_event(&mut self) -> Option<CallEvent> {
        self.events.try_recv().ok()
    }

    /// Tear the call down.
    pub async fn close(&self) {
        let _ = self.pc.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tune_opus_raises_the_bitrate_and_keeps_other_params() {
        let sdp = "v=0\r\n\
            m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
            a=rtpmap:111 opus/48000/2\r\n\
            a=fmtp:111 minptime=10;useinbandfec=1\r\n\
            a=rtpmap:9 G722/8000\r\n";
        let out = tune_opus(sdp);
        let fmtp = out.lines().find(|l| l.starts_with("a=fmtp:111 ")).unwrap();
        assert!(fmtp.contains("maxaveragebitrate=64000"), "{fmtp}");
        assert!(fmtp.contains("stereo=1"));
        assert!(fmtp.contains("minptime=10"), "existing params kept: {fmtp}");
        // The non-Opus codec line is untouched.
        assert!(out.contains("a=rtpmap:9 G722/8000"));
    }

    #[test]
    fn tune_opus_adds_an_fmtp_line_when_absent() {
        let sdp = "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=rtpmap:111 opus/48000/2\r\n";
        let out = tune_opus(sdp);
        assert!(out
            .lines()
            .any(|l| l.starts_with("a=fmtp:111 ") && l.contains("maxaveragebitrate=64000")));
    }

    #[test]
    fn tune_opus_is_a_noop_without_opus() {
        let sdp = "m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=rtpmap:96 VP8/90000\r\n";
        assert_eq!(tune_opus(sdp), sdp);
    }
}
