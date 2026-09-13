//! An SFU (selective forwarding unit) media component for large DaNTe voice
//! rooms.
//!
//! The full-mesh group call every participant runs today needs one DTLS-SRTP
//! connection per other participant; this component replaces that with one
//! connection per participant to the SFU, which forwards each speaker's RTP to
//! the others. It forwards **opaque payloads**: no decode, no re-encode, and no
//! access to the SFrame (`DSF1 ‖ AES-GCM`) key that protects call audio.
//!
//! Surface: [`Sfu::new`] fixes a room size, [`Sfu::add_peer`] consumes a
//! participant's SDP offer and returns a slot plus the SDP answer,
//! [`Sfu::add_ice`] feeds trickled candidates, and the event receiver returned
//! by [`Sfu::new`] carries the SFU's own candidates and per-slot connection
//! states back out.
//!
//! This crate is deliberately **not wired into any binary yet** — the default
//! client path is still the mesh. The design and the trust-boundary rules are
//! in [`docs/SFU.md`](../../docs/SFU.md); see the crate README for exactly
//! what is proven and what is not.
//!
//! Forwarding detail: a participant must offer one receive-only audio m-line
//! per other slot (see `dante_voice::Call::offer_for_sfu`); the SFU's answer
//! puts one outgoing track on each, with the SSRC pre-allocated for that
//! source slot ([`slot_ssrc`]). Each received RTP packet is rewritten to the
//! sender's slot SSRC and written to that source's track on every *other*
//! participant's connection. Sequence numbers, timestamps, payload type and
//! payload bytes are untouched.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use dante_net::ratelimit::TokenBucket;
use rtc::interceptor::{NackGeneratorBuilder, NackResponderBuilder, Registry, Slot};
use rtc::media_stream::MediaStreamTrack;
use rtc::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
    TYPE_RTCP_FB_NACK,
};
use tokio::sync::mpsc;
use webrtc::media_stream::track_local::static_rtp::TrackLocalStaticRTP;
use webrtc::media_stream::track_local::TrackLocal;
use webrtc::media_stream::track_remote::{TrackRemote, TrackRemoteEvent};
use webrtc::peer_connection::{
    MediaEngine, PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler,
    RTCConfigurationBuilder, RTCIceCandidateInit, RTCIceServer, RTCPeerConnectionIceEvent,
    RTCPeerConnectionState, RTCSessionDescription, SettingEngineBuilder,
};

/// A STUN or TURN server for ICE. `username` / `credential` are empty for
/// STUN. Deliberately not `webrtc`'s own `RTCIceServer` (converted to one
/// internally, in [`add_peer`]) — this keeps callers (`dante-relay`) from
/// needing a direct dependency on the `webrtc` crate just to describe three
/// strings; the same shape as `dante_voice::IceServer`, kept independent
/// rather than shared since the two crates don't otherwise depend on
/// each other.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IceServer {
    /// e.g. `stun:stun.example.org:3478` or `turn:turn.example.org:3478?transport=udp`.
    pub urls: Vec<String>,
    /// TURN username (empty for STUN).
    pub username: String,
    /// TURN credential (empty for STUN).
    pub credential: String,
}

/// SSRC base the SFU assigns to source slots: slot `s` gets
/// `SFU_SSRC_BASE + s`. Distinct from the participants' own SSRCs, so a
/// forwarded stream is unambiguous on every leg.
pub const SFU_SSRC_BASE: u32 = 0xDA07_0000;

/// The SSRC the SFU uses for the stream that originates in `slot`.
pub fn slot_ssrc(slot: usize) -> u32 {
    SFU_SSRC_BASE + slot as u32
}

/// Anything that can go wrong setting up or driving the SFU.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SfuError {
    /// The underlying WebRTC stack returned an error.
    #[error("webrtc: {0}")]
    Rtc(String),
    /// Every slot is taken.
    #[error("SFU room is full")]
    Full,
    /// No participant occupies that slot.
    #[error("no SFU peer in slot {0}")]
    NoSuchPeer(usize),
}

impl From<webrtc::error::Error> for SfuError {
    fn from(e: webrtc::error::Error) -> Self {
        SfuError::Rtc(e.to_string())
    }
}

/// Coarse per-participant connection state, mirroring `RTCPeerConnectionState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
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

impl From<RTCPeerConnectionState> for PeerState {
    fn from(s: RTCPeerConnectionState) -> Self {
        match s {
            RTCPeerConnectionState::New | RTCPeerConnectionState::Unspecified => PeerState::New,
            RTCPeerConnectionState::Connecting => PeerState::Connecting,
            RTCPeerConnectionState::Connected => PeerState::Connected,
            RTCPeerConnectionState::Disconnected => PeerState::Disconnected,
            RTCPeerConnectionState::Failed => PeerState::Failed,
            RTCPeerConnectionState::Closed => PeerState::Closed,
            _ => PeerState::New,
        }
    }
}

/// Something the SFU wants its host to act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SfuEvent {
    /// A locally-gathered ICE candidate for `slot`'s participant to apply. An
    /// empty string signals end-of-gathering (hand it over too; it is a no-op).
    Ice {
        /// Which participant this candidate belongs to.
        slot: usize,
        /// The candidate string, or empty at end-of-gathering.
        candidate: String,
    },
    /// `slot`'s connection state changed.
    State {
        /// Which participant changed.
        slot: usize,
        /// The new state.
        state: PeerState,
    },
}

/// Subscriber slot -> that PC's outgoing track for every source slot.
type OutgoingMap = Arc<Mutex<HashMap<usize, Arc<Vec<Option<Arc<TrackLocalStaticRTP>>>>>>>;

struct Peer {
    pc: Arc<dyn PeerConnection>,
}

struct Handler {
    slot: usize,
    events: mpsc::UnboundedSender<SfuEvent>,
    outgoing: OutgoingMap,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for Handler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        let candidate = event
            .candidate
            .to_json()
            .map(|j| j.candidate)
            .unwrap_or_default();
        let _ = self.events.send(SfuEvent::Ice {
            slot: self.slot,
            candidate,
        });
    }

    async fn on_ice_gathering_state_change(
        &self,
        state: webrtc::peer_connection::RTCIceGatheringState,
    ) {
        if state == webrtc::peer_connection::RTCIceGatheringState::Complete {
            let _ = self.events.send(SfuEvent::Ice {
                slot: self.slot,
                candidate: String::new(),
            });
        }
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        let _ = self.events.send(SfuEvent::State {
            slot: self.slot,
            state: state.into(),
        });
    }

    async fn on_track(&self, track: Arc<dyn TrackRemote>) {
        let source = self.slot;
        let outgoing = Arc::clone(&self.outgoing);
        tokio::spawn(async move { forward_track(source, track, outgoing).await });
    }
}

/// Per-source forwarding budget: Opus at the FEC-heavy settings this SFU
/// negotiates runs a little over 64 kbps, so this leaves generous headroom
/// while still bounding what one participant (buggy, compromised, or
/// deliberately abusive) can force the SFU to fan out to every other
/// subscriber's downlink.
const SOURCE_BITRATE_CAP_BYTES_PER_SEC: f64 = 32_000.0;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Forward every RTP packet received from `source` to each *other*
/// subscriber's outgoing track for that source. Only the SSRC is rewritten;
/// the payload (the SFrame ciphertext) is passed through byte for byte.
///
/// Packets beyond [`SOURCE_BITRATE_CAP_BYTES_PER_SEC`] for this source are
/// dropped rather than forwarded: a single over-budget sender loses audio
/// quality for itself, but never eats into another participant's fan-out.
///
/// The drop happens before the packet ever reaches a subscriber's outgoing
/// track, so it never enters that track's NACK send buffer either — a
/// subscriber that notices the gap will NACK for a sequence number the SFU
/// can never answer. Harmless (the responder just doesn't reply, same as
/// any other genuinely-lost packet), but worth knowing: under a real flood,
/// this is where the extra NACK traffic comes from.
async fn forward_track(source: usize, track: Arc<dyn TrackRemote>, outgoing: OutgoingMap) {
    let mut budget = TokenBucket::new(
        SOURCE_BITRATE_CAP_BYTES_PER_SEC,
        SOURCE_BITRATE_CAP_BYTES_PER_SEC,
        now_ms(),
    );
    while let Some(event) = track.poll().await {
        let TrackRemoteEvent::OnRtpPacket(mut pkt) = event else {
            continue;
        };
        if !budget.try_take(now_ms(), pkt.payload.len() as f64) {
            continue;
        }
        pkt.header.ssrc = slot_ssrc(source);

        // Snapshot the destination tracks without holding a lock across an
        // await: the registry changes only when a participant joins.
        let targets: Vec<Arc<TrackLocalStaticRTP>> = {
            let map = outgoing.lock().expect("SFU outgoing map poisoned");
            map.iter()
                .filter(|(subscriber, _)| **subscriber != source)
                .filter_map(|(_, tracks)| tracks[source].as_ref().map(Arc::clone))
                .collect()
        };
        for out in targets {
            // A subscriber still negotiating rejects the write; the next
            // packet retries, which is the correct early-drop behaviour.
            let _ = out.write_rtp(pkt.clone()).await;
        }
    }
}

/// Enable RTCP NACK loss recovery for audio.
///
/// `rtc::peer_connection::configuration::interceptor_registry`'s own
/// `register_default_interceptors` only advertises the `nack` RTCP feedback
/// capability for `RtpCodecKind::Video` — this SFU is audio-only, so calling
/// it verbatim would install the NACK interceptors without ever declaring
/// the capability Opus needs to use them (`stream_supports_nack` gates on the
/// negotiated per-codec feedback list, not merely on the interceptor being
/// present). Registering it here for `Audio` instead closes the gap the
/// crate docs used to flag as unaddressed: a leg that drops a packet now
/// gets it retransmitted from the sender's own buffer — the SFU's buffer for
/// a subscriber leg, or the original participant's for the SFU's own inbound
/// leg — rather than relying on Opus FEC alone.
///
/// Duplicated (not shared) in `dante_voice`'s own `configure_audio_nack` —
/// see that crate's `src/lib.rs`. Deliberate: sharing it would make
/// `dante-sfu` depend on `dante-voice` in production, not just in this
/// crate's own tests, which is backwards (the server-side forwarder
/// depending on the 1:1-call crate `dante-core` composes alongside it). If
/// you change one copy, change the other.
///
/// `with_size(64)`, not the builder's own default of 1024: the responder's
/// buffer holds full RTP packets per *outgoing* stream, and this SFU opens
/// one such stream per other participant on every subscriber's connection —
/// `MAX_ROOMS` bounding the relay's media-plane memory (see its doc comment
/// in `dante-relay`) stops being true if each of those streams reserves 16x
/// more than it needs. 64 packets is ~1.3s of 20ms Opus frames, comfortably
/// past the RTT a NACK round-trip needs on any real network.
fn configure_audio_nack(registry: Registry, media: &mut MediaEngine) -> Registry {
    media.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_NACK.to_owned(),
            parameter: String::new(),
        },
        RtpCodecKind::Audio,
    );
    registry
        .with(
            Slot::NackResponder,
            NackResponderBuilder::new().with_size(64).build(),
        )
        .with(Slot::NackGenerator, NackGeneratorBuilder::new().build())
}

/// One pre-packetized outgoing track for the source in `slot`.
fn outgoing_track(slot: usize) -> Result<Arc<TrackLocalStaticRTP>, SfuError> {
    let codec = RTCRtpCodec {
        mime_type: "audio/opus".to_owned(),
        clock_rate: 48_000,
        channels: 2,
        sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
        rtcp_feedback: vec![],
    };
    let mst = MediaStreamTrack::new(
        "dante-sfu".to_owned(),
        format!("sfu-src-{slot}"),
        format!("sfu-src-{slot}"),
        RtpCodecKind::Audio,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(slot_ssrc(slot)),
                ..Default::default()
            },
            codec,
            ..Default::default()
        }],
    );
    Ok(Arc::new(TrackLocalStaticRTP::new(mst)))
}

/// A selective forwarding unit for one voice room.
///
/// The room size is fixed at construction: every participant's answer
/// pre-allocates one outgoing track per other slot, so participants can join
/// at any time without renegotiating anyone else's connection. Slots with no
/// participant simply stay silent.
pub struct Sfu {
    room_size: usize,
    peers: Vec<Option<Peer>>,
    events_tx: mpsc::UnboundedSender<SfuEvent>,
    outgoing: OutgoingMap,
    /// STUN/TURN servers offered to every participant's `PeerConnection`.
    /// Empty by default, matching the project's "no project-run
    /// infrastructure" stance — the *operator* decides whether to configure
    /// any (same `IceServer` shape and source as ordinary calls), not this
    /// crate. With none, the SFU only offers host candidates, so it must be
    /// reachable directly (a public IP or a full-cone port mapping); STUN
    /// lets participants discover the SFU's public address if it is behind
    /// NAT, TURN gives a relayed fallback if direct reachability fails
    /// outright.
    ice_servers: Vec<IceServer>,
}

impl Sfu {
    /// Create an empty room with `room_size` slots, offering `ice_servers` to
    /// every participant's connection (may be empty — host candidates only),
    /// plus the event receiver that carries [`SfuEvent`]s (ICEs to hand back,
    /// state changes).
    pub fn new(
        room_size: usize,
        ice_servers: Vec<IceServer>,
    ) -> (Self, mpsc::UnboundedReceiver<SfuEvent>) {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        (
            Self {
                room_size,
                peers: (0..room_size).map(|_| None).collect(),
                events_tx,
                outgoing: Arc::new(Mutex::new(HashMap::new())),
                ice_servers,
            },
            events_rx,
        )
    }

    /// How many slots the room has.
    pub fn room_size(&self) -> usize {
        self.room_size
    }

    /// How many slots are occupied.
    pub fn peers(&self) -> usize {
        self.peers.iter().filter(|p| p.is_some()).count()
    }

    /// Whether no participant occupies any slot.
    pub fn is_empty(&self) -> bool {
        self.peers.iter().all(Option::is_none)
    }

    /// Close and free `slot`. Any packet already being forwarded to it just
    /// fails its write and is dropped.
    pub async fn remove_peer(&mut self, slot: usize) -> Result<(), SfuError> {
        let peer = self
            .peers
            .get_mut(slot)
            .and_then(Option::take)
            .ok_or(SfuError::NoSuchPeer(slot))?;
        self.outgoing
            .lock()
            .expect("SFU outgoing map poisoned")
            .remove(&slot);
        peer.pc.close().await?;
        Ok(())
    }

    /// Admit the next participant. `offer_sdp` is the participant's offer;
    /// returns the slot it was given and the answer SDP to hand back. ICE
    /// candidates for it arrive on the [`Sfu::new`] event receiver.
    pub async fn add_peer(&mut self, offer_sdp: &str) -> Result<(usize, String), SfuError> {
        let slot = self
            .peers
            .iter()
            .position(Option::is_none)
            .ok_or(SfuError::Full)?;

        // One outgoing track per other slot, ready before the answer so the
        // SDP already carries every possible source.
        let mut outgoing: Vec<Option<Arc<TrackLocalStaticRTP>>> =
            Vec::with_capacity(self.room_size);
        for s in 0..self.room_size {
            outgoing.push(if s == slot {
                None
            } else {
                Some(outgoing_track(s)?)
            });
        }
        let outgoing = Arc::new(outgoing);

        let servers: Vec<RTCIceServer> = self
            .ice_servers
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
        media.register_default_codecs().map_err(SfuError::from)?;
        let registry = configure_audio_nack(Registry::new(), &mut media);

        let pc = PeerConnectionBuilder::<&str>::new()
            .with_configuration(config)
            .with_setting_engine(setting)
            .with_media_engine(media)
            .with_interceptor_registry(registry)
            .with_handler(Arc::new(Handler {
                slot,
                events: self.events_tx.clone(),
                outgoing: Arc::clone(&self.outgoing),
            }))
            .with_udp_addrs(vec!["0.0.0.0:0"])
            .build()
            .await?;
        let pc: Arc<dyn PeerConnection> = Arc::new(pc);

        for track in outgoing.iter().flatten() {
            let local = Arc::clone(track) as Arc<dyn TrackLocal>;
            pc.add_track(local).await?;
            // Drain RTCP feedback for this outgoing track so the internal
            // channel never backs up. v0 does not act on it (audio-only).
            let track = Arc::clone(track);
            tokio::spawn(async move { while track.poll().await.is_some() {} });
        }

        pc.set_remote_description(RTCSessionDescription::offer(offer_sdp.to_owned())?)
            .await?;
        let answer = pc.create_answer(None).await?;
        pc.set_local_description(answer.clone()).await?;

        self.outgoing
            .lock()
            .expect("SFU outgoing map poisoned")
            .insert(slot, outgoing);
        self.peers[slot] = Some(Peer { pc });
        Ok((slot, answer.sdp))
    }

    /// Feed a trickled ICE candidate from `slot`'s participant. Empty strings
    /// (end-of-gathering) are a no-op.
    pub async fn add_ice(&self, slot: usize, candidate: &str) -> Result<(), SfuError> {
        let peer = self
            .peers
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(SfuError::NoSuchPeer(slot))?;
        if candidate.is_empty() {
            return Ok(());
        }
        peer.pc
            .add_ice_candidate(RTCIceCandidateInit {
                candidate: candidate.to_owned(),
                ..Default::default()
            })
            .await?;
        Ok(())
    }

    /// Tear every participant's connection down.
    pub async fn close(&self) {
        for peer in self.peers.iter().flatten() {
            let _ = peer.pc.close().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_bitrate_cap_admits_a_steady_sender_but_drops_a_flood() {
        let mut budget = TokenBucket::new(
            SOURCE_BITRATE_CAP_BYTES_PER_SEC,
            SOURCE_BITRATE_CAP_BYTES_PER_SEC,
            0,
        );
        // A steady sender at (just under) the cap, spread over a second in
        // 20ms frames — the size a real Opus packet is — is never dropped.
        let per_frame = (SOURCE_BITRATE_CAP_BYTES_PER_SEC / 50.0) * 0.9;
        for tick in 1..=50u64 {
            assert!(
                budget.try_take(tick * 20, per_frame),
                "frame {tick} should fit the budget"
            );
        }
        // A sender blasting a whole second's budget in one packet gets some
        // through and the rest dropped, not an unbounded burst forwarded.
        let mut allowed = 0;
        let mut dropped = 0;
        for _ in 0..10 {
            if budget.try_take(1_020, SOURCE_BITRATE_CAP_BYTES_PER_SEC) {
                allowed += 1;
            } else {
                dropped += 1;
            }
        }
        assert!(allowed <= 1, "at most one full-budget burst fits");
        assert!(dropped > 0, "the flood is bounded, not forwarded in full");
    }

    #[tokio::test]
    async fn audio_nack_is_negotiated_so_a_dropped_packet_can_be_recovered() {
        // `register_default_interceptors` upstream only advertises `nack` for
        // video; a real SFU offer/answer exchange for our audio-only room
        // must still end up with `nack` in the negotiated SDP, or the NACK
        // interceptors we install never actually engage (they gate on the
        // negotiated per-codec feedback, not on merely being present).
        let (_call, offer) = dante_voice::Call::offer_for_sfu(1, &[]).await.unwrap();
        let (mut sfu, _events) = Sfu::new(2, vec![]);
        let (_slot, answer) = sfu.add_peer(&offer).await.unwrap();
        assert!(
            answer.to_lowercase().contains("nack"),
            "answer SDP should negotiate nack RTCP feedback for audio:\n{answer}"
        );
    }
}
