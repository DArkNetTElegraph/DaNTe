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
//! Group calls need per-epoch keys from the channel's MLS group and are not here
//! yet. Audio capture / playback (cpal + Opus) is also a later layer — this
//! establishes the encrypted pipe and the control channel; `send_ctl` already
//! carries in-call state (mute/hold) and, in tests, a connectivity probe.

use std::sync::Arc;

use bytes::BytesMut;
use tokio::sync::{mpsc, Mutex};
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
    RTCIceCandidateInit, RTCIceServer, RTCPeerConnectionIceEvent, RTCPeerConnectionState,
    RTCSessionDescription, SettingEngineBuilder,
};

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
}

type DcSlot = Arc<Mutex<Option<Arc<dyn DataChannel>>>>;

/// A single 1:1 call.
pub struct Call {
    pc: Arc<dyn PeerConnection>,
    dc: DcSlot,
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

    let pc = PeerConnectionBuilder::<&str>::new()
        .with_configuration(config)
        .with_setting_engine(setting)
        .with_handler(Arc::new(Handler {
            tx: tx.clone(),
            dc: Arc::clone(&dc),
        }))
        .with_udp_addrs(vec!["0.0.0.0:0"])
        .build()
        .await?;

    Ok((Arc::new(pc), dc, tx, rx))
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
        let (pc, dc, tx, events) = build_pc(ice).await?;

        let channel = pc.create_data_channel("dante", None).await?;
        *dc.lock().await = Some(Arc::clone(&channel));
        pump_dc(channel, tx);

        let offer = pc.create_offer(None).await?;
        pc.set_local_description(offer.clone()).await?;
        Ok((Call { pc, dc, events }, offer.sdp))
    }

    /// Callee side: apply a received **offer** with `ice` servers, return the
    /// call plus the SDP **answer**. The caller's control channel arrives via
    /// `on_data_channel`.
    pub async fn answer_with(
        offer_sdp: &str,
        ice: &[IceServer],
    ) -> Result<(Call, String), VoiceError> {
        let (pc, dc, _tx, events) = build_pc(ice).await?;
        pc.set_remote_description(RTCSessionDescription::offer(offer_sdp.to_owned())?)
            .await?;
        let answer = pc.create_answer(None).await?;
        pc.set_local_description(answer.clone()).await?;
        Ok((Call { pc, dc, events }, answer.sdp))
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
