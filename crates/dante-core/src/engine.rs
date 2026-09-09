//! [`Engine`] — one client's whole world: an identity, a local ledger replica,
//! a relay connection, prekeys, live DM sessions, and (optionally) an encrypted
//! on-disk store so all of that survives a restart.

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use dante_crypto::{
    aead,
    hash::{sha256, sha512},
    pow::Difficulty,
    random_array,
    sign::{SignPublic, SignSecret},
};
use dante_dm::{Content, FileManifest, Packet, PreKeyBundle, PreKeySecrets, Session};
use dante_identity::{
    id::IdentityId,
    records::{IdentityAnnounce, IdentityRevoke, LivenessProof, RevokeReason},
    Identity,
};
use dante_ledger::{
    server::{ServerDelist, ServerRegister},
    Ledger, LedgerParams, MemoryStore,
};
use dante_mls::{self as mls};
use dante_net::{sync, transport::Client};
use dante_proto::{envelope::recipient_hint, Envelope, Record};
use dante_voice::{Call, CallEvent, CallState, IceServer};

use crate::{
    channel::{self, ChannelControl, ChannelInfo, ChannelMessage},
    error::CoreError,
    roles::{self, ServerPolicy},
    store::{self, ChannelHistoryEntry, HistoryEntry, HistoryKind, PersistedState},
};

/// Domain for the per-epoch key that AEAD-seals channel typing signals.
const CHANNEL_SIGNAL_LABEL: &str = "dante/channel-signal/v1";
/// MLS-exporter label for voice-channel presence beacons.
const VOICE_PRESENCE_LABEL: &str = "dante/voice-presence/v1";
/// A presence beacon older than this is treated as "left".
const VOICE_PRESENCE_TTL_MS: u64 = 15_000;

/// Default envelope TTL for DMs: 7 days.
pub const DM_TTL_MS: u32 = 7 * 24 * 60 * 60 * 1000;

/// Re-announce / re-prove liveness only if the last one is older than this.
pub const REANNOUNCE_AFTER_MS: u64 = 24 * 60 * 60 * 1000;

/// Cap on persisted seen-envelope tags.
const SEEN_CAP: usize = 5000;

/// Cap on persisted channel-history lines (oldest dropped first).
const CHANNEL_HISTORY_CAP: usize = 2000;

/// One-time-prekey pool is refilled to this before each publish.
const PREKEY_POOL_TARGET: usize = 50;

/// Domain separator for the human-comparable safety number of a DM pair.
const SAFETY_NUMBER_DOMAIN: &[u8] = b"dante/safety-number/v1";

/// Standing reaction state: `channel_id -> target_seq -> emoji -> members`.
type ReactionMap = HashMap<[u8; 32], HashMap<u64, HashMap<String, HashSet<[u8; 32]>>>>;

/// A reaction pending a fold-in: `(channel_id, target_seq, emoji, member, removed)`.
type PendingReaction = ([u8; 32], u64, String, [u8; 32], bool);

/// Standing edit/delete state for channel messages: `channel_id -> seq -> state`.
type EditMap = HashMap<[u8; 32], HashMap<u64, MsgEdit>>;

/// Per-message edit / delete tracking. `author` is recorded when the original
/// text message is seen; only that identity's edit or delete is honoured.
#[derive(Clone, Debug)]
struct MsgEdit {
    author: [u8; 32],
    /// `Some` once the message has been edited (the current text).
    text: Option<String>,
    /// `true` once the message has been deleted.
    deleted: bool,
}

/// Standing edit/delete state for direct messages: `peer_idk -> msg_id -> state`.
type DmEditMap = HashMap<[u8; 32], HashMap<[u8; 16], DmMsgEdit>>;

/// Per-DM edit / delete tracking. Authorisation is structural: an edit is only
/// applied against a `history` entry in the same conversation and direction as
/// the original message, so only the original sender's change lands.
#[derive(Clone, Debug, Default)]
struct DmMsgEdit {
    /// `Some` once the message has been edited (the current text).
    text: Option<String>,
    /// `true` once the message has been withdrawn.
    deleted: bool,
}

/// A live direct-message edit/delete the UI folds into its view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmEdit {
    /// The peer whose conversation this message is in (their Ed25519 key).
    pub peer_idk: [u8; 32],
    /// The message id (`store::HistoryEntry::msg_id`).
    pub msg_id: [u8; 16],
    /// The new text (`None` for a delete).
    pub text: Option<String>,
    /// `true` if the message was withdrawn.
    pub deleted: bool,
}

/// One hit from [`Engine::search`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchHit {
    /// True for a channel message, false for a DM.
    pub is_channel: bool,
    /// `IdentityId` of the DM peer, or the `channel_id`.
    pub scope: [u8; 32],
    /// The DM peer's Ed25519 key (zero for a channel hit).
    pub scope_idk: [u8; 32],
    /// Channel display name (empty for a DM hit).
    pub scope_name: String,
    /// Sender: `IdentityId` bytes (the DM peer, or the channel member).
    pub sender: [u8; 32],
    /// Whether we sent it.
    pub outgoing: bool,
    /// The matching message text.
    pub text: String,
    /// Wall-clock time (Unix ms).
    pub ts_ms: u64,
}

/// Standing pinned-message state: `channel_id -> seq -> pin`.
type PinMap = HashMap<[u8; 32], HashMap<u64, PinInfo>>;

/// A pinned channel message.
#[derive(Clone, Copy, Debug)]
struct PinInfo {
    /// Who pinned it (the channel host or the message's author).
    by: [u8; 32],
    /// When it was pinned (Unix ms).
    at_ms: u64,
}

/// A pin / unpin the UI folds into its view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelPin {
    /// The channel the message is in.
    pub channel_id: [u8; 32],
    /// The relay-log `seq` of the pinned message.
    pub target_seq: u64,
    /// Who pinned it.
    pub by: [u8; 32],
    /// When it was pinned (Unix ms).
    pub at_ms: u64,
    /// `true` for a pin, `false` for an unpin.
    pub pinned: bool,
}

/// A live edit/delete the UI folds into its view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelEdit {
    /// The channel the message is in.
    pub channel_id: [u8; 32],
    /// The relay-log `seq` of the message.
    pub target_seq: u64,
    /// The new text (`None` if this is a delete).
    pub text: Option<String>,
    /// `true` if the message was deleted.
    pub deleted: bool,
}

/// Max bytes of a contact petname.
const PETNAME_MAX: usize = 64;
/// Max display length kept for an invite's (untrusted) channel/server name.
const INVITE_NAME_MAX: usize = 64;
/// Cap on pending channel invites held at once. Anyone who can DM us can send
/// `ChannelControl::Invite`, so the map must be bounded.
const MAX_PENDING_INVITES: usize = 256;

/// A saved contact: a local, private label for another identity. Never leaves
/// the device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    /// The user's private nickname for this identity (may be empty).
    pub petname: String,
    /// When the contact was first added (Unix ms).
    pub added_ms: u64,
}

/// Resolve an Ed25519 identity key to its stable `IdentityId` bytes (falls back
/// to the raw key if it is malformed).
fn idk_to_id(idk: &[u8; 32]) -> [u8; 32] {
    SignPublic::from_bytes(idk)
        .map(|pk| *IdentityId::of(&pk).as_bytes())
        .unwrap_or(*idk)
}

/// TTL on a typing signal's carrier envelope. Deliberately short: a stale
/// "is typing" is worse than a missing one.
const TYPING_TTL_MS: u32 = 10_000;

/// Domain tag for the shared per-conversation typing-signal topic.
const DM_TYPING_TOPIC_DOMAIN: &[u8] = b"dante/typing/dm/v1";

/// A decrypted inbound direct message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedDm {
    /// The sender's Ed25519 identity key.
    pub from_idk: [u8; 32],
    /// The plaintext.
    pub text: String,
    /// The message's conversation id, for a later edit / delete. All-zero if
    /// the sender's client is too old to support editing.
    pub msg_id: [u8; 16],
}

/// Where a typing signal belongs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypingScope {
    /// A 1:1 conversation with the peer whose Ed25519 identity key this is.
    Dm([u8; 32]),
    /// A channel, by `channel_id`.
    Channel([u8; 32]),
}

/// An ephemeral "someone is typing" event. Not persisted; the caller shows it
/// for a few seconds and then forgets it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypingEvent {
    /// The conversation the signal is for.
    pub scope: TypingScope,
    /// The typer: an Ed25519 identity key for `Dm`, a member id for `Channel`.
    pub who: [u8; 32],
    /// When the signal was created (its carrier's `deposited_ms`, AEAD-bound).
    /// Freshness is judged from this, not from when it was fetched, so a signal
    /// stops showing a few seconds after the last keystroke even though the
    /// relay keeps serving it until its TTL.
    pub at_ms: u64,
}

/// Something decrypted from the relay: a text message or a fully reassembled
/// file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inbound {
    /// A text message.
    Message(ReceivedDm),
    /// A received file.
    File {
        /// Sender's Ed25519 identity key.
        from_idk: [u8; 32],
        /// The sender-declared filename (display only — never used as a path).
        filename: String,
        /// The decrypted file bytes.
        data: Vec<u8>,
    },
    /// The peer is calling. Answer with [`Engine::accept_call`] or decline with
    /// [`Engine::hangup`].
    IncomingCall {
        /// Caller's Ed25519 identity key.
        from_idk: [u8; 32],
    },
    /// The peer hung up / declined.
    CallEnded {
        /// The other party's Ed25519 identity key.
        from_idk: [u8; 32],
    },
    /// Someone started (or added us to) a group call in a channel we are in.
    /// Answer with [`Engine::join_group_call`] or ignore it.
    GroupCallInvite {
        /// The channel the call belongs to.
        channel_id: [u8; 32],
        /// The inviter's Ed25519 identity key.
        from_idk: [u8; 32],
    },
    /// A channel group call we are in changed membership (someone joined or
    /// left). Re-read [`Engine::group_call_peers`] /
    /// [`Engine::group_call_key`].
    GroupCallMembersChanged {
        /// The channel the call belongs to.
        channel_id: [u8; 32],
    },
    /// A plaintext snapshot of a channel's recent messages, handed to us by the
    /// host on join (MLS forward secrecy hides the pre-join log). Oldest first.
    ChannelBacklog {
        /// The channel the snapshot belongs to.
        channel_id: [u8; 32],
        /// `(sender member id, Unix ms, text)`.
        entries: Vec<([u8; 32], u64, String)>,
    },
    /// A WebRTC signalling blob for a voice-channel mesh leg, relayed from
    /// another participant's browser. The engine does not interpret it.
    VoiceSignal {
        /// The voice channel this leg belongs to.
        channel_id: [u8; 32],
        /// The other participant's Ed25519 identity key.
        from_idk: [u8; 32],
        /// 0 offer, 1 answer, 2 ICE, 3 bye.
        kind: u8,
        /// The opaque payload (SDP or ICE candidate line).
        data: String,
    },
    /// A host has offered us a channel. Nothing happens until we call
    /// [`Engine::accept_channel_invite`] or [`Engine::decline_channel_invite`].
    ChannelInvite {
        /// The channel we're being invited to.
        channel_id: [u8; 32],
        /// The inviter's Ed25519 identity key.
        from_idk: [u8; 32],
        /// Display name of the channel.
        channel_name: String,
        /// Display name of the server.
        server_name: String,
    },
}

/// One channel group call this client is in. The MLS member state is persisted
/// (`store::StoredGroupCall`) so a restart resumes the call at the same epoch
/// rather than leaving a ghost leaf and rejoining.
pub(crate) struct GroupCall {
    /// This client's MLS view of the call group. Its exporter secret is the
    /// per-epoch media key ([`Engine::group_call_key`]); membership changes
    /// rotate it.
    mls: mls::Member,
}

/// A call state transition surfaced by [`Engine::poll_calls`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallUpdate {
    /// The peer's `IdentityId` bytes.
    pub peer: [u8; 32],
    /// The new state.
    pub state: CallState,
}

fn voice_err(e: dante_voice::VoiceError) -> CoreError {
    CoreError::Voice(e.to_string())
}

fn mls_err(e: mls::MlsError) -> CoreError {
    CoreError::Voice(format!("mls: {e}"))
}

/// One channel this client belongs to, backed by an MLS group.
pub(crate) struct ChannelSession {
    pub info: ChannelInfo,
    /// This client's MLS view of the channel group.
    pub mls: mls::Member,
    /// Cached member `IdentityId`s (mirrors `mls.members()`; kept for the UI
    /// member list and quick membership checks).
    pub roster: HashSet<[u8; 32]>,
    /// Last consumed channel-log sequence.
    pub last_seq: u64,
    /// Members the host has ejected: `member -> when (Unix ms)`. Used to hide
    /// their still-cached backlog messages after removal.
    pub removed: HashMap<[u8; 32], u64>,
    /// Outer AEAD key wrapping every log frame, for a password-protected
    /// channel. `None` = unprotected (frames posted raw).
    pub log_key: Option<[u8; 32]>,
}

impl ChannelSession {
    /// Refresh `roster` from the live MLS membership.
    fn resync_roster(&mut self) {
        self.roster = self
            .mls
            .members()
            .into_iter()
            .filter_map(|(_, id)| <[u8; 32]>::try_from(id).ok())
            .collect();
    }

    /// The leaf index of `member` in the MLS group, if present.
    fn leaf_of(&self, member: &[u8; 32]) -> Option<u32> {
        self.mls
            .members()
            .into_iter()
            .find(|(_, id)| id.as_slice() == member)
            .map(|(leaf, _)| leaf)
    }
}

/// AEAD-seal a channel side-band signal under a `label`-derived key from the
/// group's current epoch secret. Frame: `member(32) || nonce(24) || ciphertext`.
fn seal_channel_signal(
    member: &mls::Member,
    me: &[u8; 32],
    channel_id: &[u8; 32],
    label: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let key = member.export_key(label, 32).map_err(mls_err)?;
    let key: [u8; 32] = key[..32].try_into().unwrap();
    let nonce = random_array::<24>();
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(channel_id);
    aad.extend_from_slice(me);
    let ct = aead::xchacha_seal(&key, &nonce, plaintext, &aad);
    let mut out = Vec::with_capacity(56 + ct.len());
    out.extend_from_slice(me);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Recover `(sender IdentityId, plaintext)` from a channel side-band frame.
fn open_channel_signal(
    member: &mls::Member,
    channel_id: &[u8; 32],
    label: &str,
    blob: &[u8],
) -> Option<([u8; 32], Vec<u8>)> {
    if blob.len() < 56 {
        return None;
    }
    let sender: [u8; 32] = blob[..32].try_into().ok()?;
    let nonce: [u8; 24] = blob[32..56].try_into().ok()?;
    let ct = &blob[56..];
    let key = member.export_key(label, 32).ok()?;
    let key: [u8; 32] = key[..32].try_into().ok()?;
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(channel_id);
    aad.extend_from_slice(&sender);
    let pt = aead::xchacha_open(&key, &nonce, ct, &aad).ok()?;
    Some((sender, pt))
}

/// A snapshot of who is currently in a voice channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoicePresence {
    /// The voice channel.
    pub channel_id: [u8; 32],
    /// `IdentityId` bytes of the members whose presence beacon is still fresh,
    /// sorted, including ourselves when we are connected.
    pub members: Vec<[u8; 32]>,
}

/// A server this client hosts (holds the root key).
pub(crate) struct HostedServer {
    pub name: String,
    pub root: SignSecret,
    pub channels: Vec<[u8; 32]>,
    /// If set, [`Engine::sweep_inactive_members`] removes any channel member
    /// whose identity has had no ledger activity for this many ms. Off by
    /// default.
    pub auto_kick_ms: Option<u64>,
    /// `SHA-256("dante/join-pw/v1" || server_root || password)` — a second
    /// factor the host checks before honouring an invite-link redemption.
    pub join_pw_hash: Option<[u8; 32]>,
    /// Identities banned from this server: refused re-entry by every add path
    /// ([`Engine::mls_add_member`] rejects them). Persisted.
    pub banned: HashSet<[u8; 32]>,
    /// PoW over `server_root` (from [`ServerRegister::challenge`]), solved once
    /// at creation and replayed on every re-registration. Persisted.
    pub register_pow: dante_crypto::pow::PowProof,
}

/// Size classes channel-log plaintexts are padded to, so the relay learns only
/// a coarse bucket instead of the exact message length.
const CHANNEL_PAD_LADDER: [usize; 8] = [64, 256, 1024, 4096, 16_384, 65_536, 262_144, 1_048_576];

/// `be(len) || plaintext || zero-fill` to the next [`CHANNEL_PAD_LADDER`] class.
fn pad_channel(pt: &[u8]) -> Vec<u8> {
    let need = 4 + pt.len();
    let bucket = CHANNEL_PAD_LADDER
        .iter()
        .copied()
        .find(|&b| b >= need)
        .unwrap_or(need);
    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(&(pt.len() as u32).to_be_bytes());
    out.extend_from_slice(pt);
    out.resize(bucket, 0);
    out
}

/// Recover the real plaintext from a [`pad_channel`] frame.
fn unpad_channel(b: &[u8]) -> Option<&[u8]> {
    let n = u32::from_be_bytes(b.get(..4)?.try_into().ok()?) as usize;
    b.get(4..4 + n)
}

/// The proof a joiner must present for a password-gated server.
fn join_pw_hash(server_root: &[u8; 32], pw: &str) -> [u8; 32] {
    let mut buf = Vec::with_capacity(64 + pw.len());
    buf.extend_from_slice(b"dante/join-pw/v1");
    buf.extend_from_slice(server_root);
    buf.extend_from_slice(pw.as_bytes());
    sha256(&buf)
}

/// The client engine.
pub struct Engine {
    identity: Identity,
    prekeys: PreKeySecrets,
    ledger: Ledger<MemoryStore>,
    client: Client,
    sessions: HashMap<[u8; 32], Session>,
    channels: HashMap<[u8; 32], ChannelSession>,
    hosted: HashMap<[u8; 32], HostedServer>,
    seen_envelopes: HashSet<[u8; 32]>,
    history: Vec<HistoryEntry>,
    channel_history: Vec<ChannelHistoryEntry>,
    /// Channels the host removed us from since the last `take_evicted_channels`
    /// — `(channel_id, server_root, server_name)`. Not persisted.
    evicted_channels: Vec<([u8; 32], [u8; 32], String)>,
    /// `(channel_id, member IdentityId)` pairs the host has offered a direct
    /// invite to and is waiting on an accept for. Not persisted — a restart
    /// just means the invitee must be re-invited.
    invites_sent: HashSet<([u8; 32], [u8; 32])>,
    /// Channel invites we've received and not yet answered:
    /// `channel_id -> (inviter idk, channel_name, server_name)`. Not persisted.
    invites_received: HashMap<[u8; 32], ([u8; 32], String, String)>,
    /// Redemption counts for invite tokens we minted, keyed by token nonce.
    invite_uses: HashMap<[u8; 8], u32>,
    /// Role configuration per server_root: the one we sign for servers we host,
    /// the latest verified broadcast for servers we have joined.
    server_policies: HashMap<[u8; 32], ServerPolicy>,
    /// Reactions seen since the last `take_reactions()` — the live delta the
    /// UI folds into its view.
    new_reactions: Vec<crate::channel::ChannelReaction>,
    /// Standing reaction state, `channel_id -> target_seq -> emoji -> members`.
    /// Persisted: the channel log is only re-polled from `last_seq`, so a
    /// restart would otherwise lose every reaction.
    channel_reactions: ReactionMap,
    /// Standing edit/delete state for channel messages. Persisted for the same
    /// reason as `channel_reactions`.
    channel_edits: EditMap,
    /// Edits/deletes seen since the last `take_edits()` — the live UI delta.
    new_edits: Vec<ChannelEdit>,
    /// Standing pinned-message state. Persisted for the same reason as
    /// `channel_reactions` (the log is only re-polled from `last_seq`).
    channel_pins: PinMap,
    /// Pins/unpins seen since the last `take_pins()` — the live UI delta.
    new_pins: Vec<ChannelPin>,
    /// Standing edit/delete state for direct messages. Persisted; the relay
    /// mailbox is fetched only forward of `last_fetch_since_ms`, so a restart
    /// would otherwise lose every DM edit.
    dm_edits: DmEditMap,
    /// DM edits/deletes seen since the last `take_dm_edits()` — the UI delta.
    new_dm_edits: Vec<DmEdit>,
    /// DM peers whose safety number the user confirmed out-of-band, keyed by
    /// stable `IdentityId` bytes and pinned to the peer `idk` that was verified
    /// (so a later key rotation drops back to unverified). Persisted.
    verified_peers: HashMap<[u8; 32], [u8; 32]>,
    /// The user's saved contacts, keyed by stable `IdentityId` bytes. Persisted.
    contacts: HashMap<[u8; 32], Contact>,
    /// Blocked identities (by stable `IdentityId` bytes): their DMs, channel
    /// messages and typing signals are dropped on receipt, and the client
    /// refuses to DM them. Persisted.
    blocked: HashSet<[u8; 32]>,
    /// STUN/TURN servers used for new calls. Set at runtime; not persisted.
    ice_servers: Vec<IceServer>,
    /// Active 1:1 calls, keyed by peer `IdentityId` bytes. Ephemeral.
    calls: HashMap<[u8; 32], Call>,
    /// Opus frames received on each call's audio track, awaiting a decoder.
    inbound_audio: HashMap<[u8; 32], std::collections::VecDeque<Vec<u8>>>,
    /// Received call offers awaiting an accept/decline, `peer -> offer SDP`.
    pending_call_offers: HashMap<[u8; 32], String>,
    /// Last-seen connection state per active call.
    call_states: HashMap<[u8; 32], CallState>,
    /// Active channel group calls, keyed by `channel_id`. Ephemeral. The media
    /// legs to each participant live in `calls` (a full mesh of 1:1 calls).
    group_calls: HashMap<[u8; 32], GroupCall>,
    /// MLS KeyPackage private material we have published to the relay so peers
    /// can add us to their group calls, newest last. Ephemeral.
    mls_pending: Vec<mls::Pending>,
    /// Group-call Welcomes received but not yet joined:
    /// `channel_id -> (inviter id, welcome blob)`. Ephemeral.
    pending_group_calls: HashMap<[u8; 32], ([u8; 32], Vec<u8>)>,
    /// Voice channels we are trying to connect to: a `GroupCallWelcome` for one
    /// of these is joined automatically rather than surfaced as an invite.
    voice_join_intent: HashSet<[u8; 32]>,
    /// Relay endpoints this engine may use, preference order. The first is the
    /// one embedded in invite links and server-discovery records; the whole
    /// list is the client's failover set.
    relay_addrs: Vec<String>,
    /// Optional libp2p node: a decentralised key-directory fallback. `None`
    /// unless [`enable_p2p`](Engine::enable_p2p) ran. Feature `p2p`.
    #[cfg(feature = "p2p")]
    p2p: Option<crate::p2p::P2p>,
    /// The libp2p node backing the relay transport when `relay_addr` was a
    /// multiaddr. Kept alive so its driver task stays up; `None` for a TCP
    /// relay.
    #[cfg(feature = "p2p")]
    #[allow(dead_code)]
    transport_node: Option<dante_p2p::Node>,
    /// When we last re-advertised our p2p addresses to the relay.
    #[cfg(feature = "p2p")]
    last_p2p_announce_ms: u64,
    /// Channel-log frames heard over gossipsub since the last `poll_channels`,
    /// per channel: `(relay-log seq, opaque frame)`. Best-effort acceleration;
    /// the relay's ordered log is the source of truth.
    #[cfg(feature = "p2p")]
    channel_gossip: HashMap<[u8; 32], Vec<(u64, Vec<u8>)>>,
    /// Channels whose gossip topic we have already subscribed to.
    #[cfg(feature = "p2p")]
    subscribed_channels: HashSet<[u8; 32]>,
    /// `(channel_id, seq)` for messages already surfaced early via a gossip
    /// frame, so the authoritative relay copy doesn't re-emit them.
    #[cfg(feature = "p2p")]
    gossip_shown: HashSet<([u8; 32], u64)>,
    pow: Difficulty,
    /// Position in the relay's ordered record log that the next [`sync`] should
    /// resume from. Tracked separately from `ledger.len()` because records can
    /// also enter the local replica out of band (gossip, feature `p2p`), which
    /// would otherwise make `sync` skip relay records. Not persisted — the
    /// ledger replica is rebuilt from the relay on each start.
    relay_ledger_cursor: u64,
    last_fetch_since_ms: u64,
    last_announce_ms: u64,
    /// The `display_hint` we last announced with, so `my_username` works before
    /// the announce round-trips back through `sync`. Not persisted (the ledger
    /// replica carries it once synced).
    announced_name: Option<String>,
    store_path: Option<PathBuf>,
    dirty: bool,
}

impl Engine {
    /// Connect to a relay and build an engine around `identity`, restoring
    /// prior state from `store_path` if that file exists (otherwise a fresh
    /// prekey set is generated). `pow` is the difficulty for this client's own
    /// announce/liveness records; it must meet the network's floor.
    ///
    /// `relay_addr` may be a comma- or whitespace-separated list of `host:port`
    /// endpoints; the client connects to the first reachable one and fails over
    /// to the rest if the connection drops. With the `p2p` feature an entry may
    /// instead be a libp2p multiaddr ending `/p2p/<peer-id>`, in which case the
    /// relay wire rides a `/dante/relay/1` stream to that peer.
    pub async fn connect(
        identity: Identity,
        relay_addr: &str,
        params: LedgerParams,
        pow: Difficulty,
        store_path: Option<PathBuf>,
    ) -> Result<Self, CoreError> {
        #[cfg(feature = "p2p")]
        let mut transport_node = None;
        // When the transport is libp2p, the same node also carries DHT prekeys
        // and ledger / channel gossip.
        #[cfg(feature = "p2p")]
        let mut adopted_p2p: Option<crate::p2p::P2p> = None;

        // `p2p-discover:<bootstrap-multiaddr,...>` — enter the DHT and find
        // relays from their `dante/relay/v1` provider records.
        let discover_bootstrap = relay_addr.strip_prefix("p2p-discover:");

        let relay_addrs: Vec<String> = discover_bootstrap
            .unwrap_or(relay_addr)
            .split([',', ' ', '\t', '\n'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();

        let client = if discover_bootstrap.is_some() {
            #[cfg(feature = "p2p")]
            {
                let (node, events, _inbound) = dante_p2p::Node::spawn(&identity.p2p_node_seed())
                    .map_err(|e| CoreError::P2p(e.to_string()))?;
                let _ = node.listen_str("/ip4/0.0.0.0/tcp/0").await;
                let c = Client::connect_p2p_discover(node.clone(), &relay_addrs).await?;
                adopted_p2p = Some(Self::adopt_transport_node(node.clone(), events).await);
                transport_node = Some(node);
                c
            }
            #[cfg(not(feature = "p2p"))]
            {
                return Err(CoreError::P2p(
                    "p2p relay discovery requested but this build lacks the p2p feature".into(),
                ));
            }
        } else if let Some(ma) = relay_addrs.iter().find(|a| a.starts_with('/')) {
            #[cfg(feature = "p2p")]
            {
                let (node, events, _inbound) = dante_p2p::Node::spawn(&identity.p2p_node_seed())
                    .map_err(|e| CoreError::P2p(e.to_string()))?;
                // A listen address lets the DHT route and lets the relay dial us
                // back; harmless if it fails (request-response still works).
                let _ = node.listen_str("/ip4/0.0.0.0/tcp/0").await;
                let c = Client::connect_p2p(node.clone(), ma).await?;
                adopted_p2p = Some(Self::adopt_transport_node(node.clone(), events).await);
                transport_node = Some(node);
                c
            }
            #[cfg(not(feature = "p2p"))]
            {
                return Err(CoreError::P2p(format!(
                    "relay endpoint {ma} is a libp2p multiaddr but this build lacks the p2p feature"
                )));
            }
        } else {
            Client::connect_multi(&relay_addrs).await?
        };

        let restored = match &store_path {
            Some(p) => store::load(p, &identity)?,
            None => None,
        };

        let mut engine = Self {
            prekeys: PreKeySecrets::generate(50),
            identity,
            ledger: Ledger::new(MemoryStore::default(), params),
            client,
            sessions: HashMap::new(),
            channels: HashMap::new(),
            hosted: HashMap::new(),
            seen_envelopes: HashSet::new(),
            history: Vec::new(),
            channel_history: Vec::new(),
            evicted_channels: Vec::new(),
            invites_sent: HashSet::new(),
            invites_received: HashMap::new(),
            invite_uses: HashMap::new(),
            server_policies: HashMap::new(),
            new_reactions: Vec::new(),
            channel_reactions: HashMap::new(),
            channel_edits: HashMap::new(),
            new_edits: Vec::new(),
            channel_pins: HashMap::new(),
            new_pins: Vec::new(),
            dm_edits: HashMap::new(),
            new_dm_edits: Vec::new(),
            verified_peers: HashMap::new(),
            contacts: HashMap::new(),
            blocked: HashSet::new(),
            ice_servers: Vec::new(),
            calls: HashMap::new(),
            inbound_audio: HashMap::new(),
            pending_call_offers: HashMap::new(),
            call_states: HashMap::new(),
            group_calls: HashMap::new(),
            mls_pending: Vec::new(),
            pending_group_calls: HashMap::new(),
            voice_join_intent: HashSet::new(),
            relay_addrs,
            #[cfg(feature = "p2p")]
            p2p: adopted_p2p,
            #[cfg(feature = "p2p")]
            transport_node,
            #[cfg(feature = "p2p")]
            last_p2p_announce_ms: 0,
            #[cfg(feature = "p2p")]
            channel_gossip: HashMap::new(),
            #[cfg(feature = "p2p")]
            subscribed_channels: HashSet::new(),
            #[cfg(feature = "p2p")]
            gossip_shown: HashSet::new(),
            pow,
            relay_ledger_cursor: 0,
            last_fetch_since_ms: 0,
            last_announce_ms: 0,
            announced_name: None,
            store_path,
            dirty: false,
        };

        if let Some(s) = restored {
            engine.prekeys = PreKeySecrets::import(s.prekeys);
            engine.sessions = s
                .sessions
                .into_iter()
                .map(|(idk, st)| (idk, Session::import(st)))
                .collect();
            engine.seen_envelopes = s.seen_envelopes.into_iter().collect();
            engine.history = s.history;
            engine.channel_history = s.channel_history;
            engine.invite_uses = s.invite_uses.into_iter().collect();
            engine.last_fetch_since_ms = s.last_fetch_since_ms;
            engine.last_announce_ms = s.last_announce_ms;
            let mut removed_by_chan: HashMap<[u8; 32], HashMap<[u8; 32], u64>> = HashMap::new();
            for (chan, member, at) in s.channel_removed {
                removed_by_chan.entry(chan).or_default().insert(member, at);
            }
            for c in s.channels {
                let removed = removed_by_chan
                    .remove(&c.info.channel_id)
                    .unwrap_or_default();
                let mls = match mls::Member::import(&c.mls) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::warn!(
                            channel = %IdentityId::from_bytes(c.info.channel_id).to_base32(),
                            error = %e,
                            "dropping a channel whose MLS state could not be restored"
                        );
                        continue;
                    }
                };
                engine.channels.insert(
                    c.info.channel_id,
                    ChannelSession {
                        info: c.info,
                        mls,
                        roster: c.roster.into_iter().collect(),
                        last_seq: c.last_seq,
                        removed,
                        log_key: c.log_key,
                    },
                );
            }
            for gc in s.group_calls {
                if !engine.channels.contains_key(&gc.channel_id) {
                    continue; // the channel itself didn't restore — drop the call
                }
                match mls::Member::import(&gc.mls) {
                    Ok(m) => {
                        engine
                            .group_calls
                            .insert(gc.channel_id, GroupCall { mls: m });
                    }
                    Err(e) => tracing::warn!(
                        channel = %IdentityId::from_bytes(gc.channel_id).to_base32(),
                        error = %e,
                        "dropping a group call whose MLS state could not be restored"
                    ),
                }
            }
            for blob in s.server_policies {
                if let Ok(p) = ServerPolicy::decode(&blob) {
                    if p.verify().is_ok() {
                        engine.server_policies.insert(p.server_root, p);
                    }
                }
            }
            for (chan, seq, emoji, member) in s.channel_reactions {
                engine
                    .channel_reactions
                    .entry(chan)
                    .or_default()
                    .entry(seq)
                    .or_default()
                    .entry(emoji)
                    .or_default()
                    .insert(member);
            }
            for se in s.channel_edits {
                engine
                    .channel_edits
                    .entry(se.channel_id)
                    .or_default()
                    .insert(
                        se.seq,
                        MsgEdit {
                            author: se.author,
                            text: (!se.deleted && !se.text.is_empty()).then_some(se.text),
                            deleted: se.deleted,
                        },
                    );
            }
            for sp in s.channel_pins {
                engine
                    .channel_pins
                    .entry(sp.channel_id)
                    .or_default()
                    .insert(
                        sp.seq,
                        PinInfo {
                            by: sp.by,
                            at_ms: sp.at_ms,
                        },
                    );
            }
            for de in s.dm_edits {
                engine.dm_edits.entry(de.peer_idk).or_default().insert(
                    de.msg_id,
                    DmMsgEdit {
                        text: (!de.deleted && !de.text.is_empty()).then_some(de.text),
                        deleted: de.deleted,
                    },
                );
            }
            engine.verified_peers = s.verified_peers.into_iter().collect();
            engine.contacts = s
                .contacts
                .into_iter()
                .map(|(id, petname, added_ms)| (id, Contact { petname, added_ms }))
                .collect();
            engine.blocked = s.blocked.into_iter().collect();
            let autokick: HashMap<[u8; 32], u64> = s.server_autokick.into_iter().collect();
            let joinpw: HashMap<[u8; 32], [u8; 32]> = s.server_join_pw.into_iter().collect();
            let mut bans: HashMap<[u8; 32], HashSet<[u8; 32]>> = s
                .server_bans
                .into_iter()
                .map(|(root, ids)| (root, ids.into_iter().collect()))
                .collect();
            let mut reg_pow: HashMap<[u8; 32], dante_crypto::pow::PowProof> = s
                .server_register_pow
                .into_iter()
                .map(|p| {
                    (
                        p.root,
                        dante_crypto::pow::PowProof {
                            m_cost_kib: p.m_cost_kib,
                            t_cost: p.t_cost,
                            difficulty: p.difficulty,
                            nonce: p.nonce,
                        },
                    )
                })
                .collect();
            for h in s.hosted {
                // A blob from before this field re-solves the (server_root-bound)
                // proof once, lazily.
                let register_pow = reg_pow.remove(&h.root_pub).unwrap_or_else(|| {
                    dante_crypto::pow::solve(&ServerRegister::challenge(&h.root_pub), engine.pow)
                });
                engine.hosted.insert(
                    h.root_pub,
                    HostedServer {
                        auto_kick_ms: autokick.get(&h.root_pub).copied(),
                        join_pw_hash: joinpw.get(&h.root_pub).copied(),
                        banned: bans.remove(&h.root_pub).unwrap_or_default(),
                        register_pow,
                        name: h.name,
                        root: SignSecret::from_bytes(&h.root_secret),
                        channels: h.channels,
                    },
                );
            }
        }

        // Learn this network's ICE servers (STUN, short-lived TURN creds) from
        // the relay, so calls can traverse NAT. Best-effort.
        if let Ok(cfg) = sync::get_ice_config(&mut engine.client).await {
            engine.ice_servers = cfg
                .into_iter()
                .map(|c| IceServer {
                    urls: c.urls,
                    username: c.username,
                    credential: c.credential,
                })
                .collect();
        }

        // Publish an MLS KeyPackage so peers can add us to their group calls.
        // Best-effort.
        let _ = engine.refresh_mls_key_package().await;

        Ok(engine)
    }

    fn my_member_id(&self) -> [u8; 32] {
        *self.identity.id().as_bytes()
    }

    /// The relay endpoint advertised to others (invite links, discovery). Always
    /// present — [`Engine::connect`] rejects an empty relay list.
    fn primary_relay(&self) -> &str {
        self.relay_addrs.first().map(String::as_str).unwrap_or("")
    }

    /// The relay endpoints this client will use, in failover order.
    pub fn relay_endpoints(&self) -> &[String] {
        &self.relay_addrs
    }

    /// This identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Conversation history restored from and appended to the local store.
    pub fn history(&self) -> &[HistoryEntry] {
        &self.history
    }

    /// Channel history restored from and appended to the local store, oldest
    /// first.
    pub fn channel_history(&self) -> &[ChannelHistoryEntry] {
        &self.channel_history
    }

    /// Case-insensitive substring search across stored DM and channel text,
    /// newest first, at most `limit` hits.
    pub fn search(&self, query: &str, limit: usize) -> Vec<SearchHit> {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return Vec::new();
        }
        let mut hits: Vec<SearchHit> = Vec::new();

        for e in self.history.iter().rev() {
            if let HistoryKind::Text(t) = &e.kind {
                if t.to_lowercase().contains(&q) {
                    hits.push(SearchHit {
                        is_channel: false,
                        scope: idk_to_id(&e.peer_idk),
                        scope_idk: e.peer_idk,
                        scope_name: String::new(),
                        sender: idk_to_id(&e.peer_idk),
                        outgoing: e.outgoing,
                        text: t.clone(),
                        ts_ms: e.ts_ms,
                    });
                    if hits.len() >= limit {
                        return hits;
                    }
                }
            }
        }

        let names: HashMap<[u8; 32], String> = self
            .channels
            .values()
            .map(|c| (c.info.channel_id, c.info.channel_name.clone()))
            .collect();
        for e in self.channel_history.iter().rev() {
            if e.text.to_lowercase().contains(&q) {
                hits.push(SearchHit {
                    is_channel: true,
                    scope: e.channel_id,
                    scope_idk: [0u8; 32],
                    scope_name: names.get(&e.channel_id).cloned().unwrap_or_default(),
                    sender: e.sender,
                    outgoing: e.outgoing,
                    text: e.text.clone(),
                    ts_ms: e.ts_ms,
                });
                if hits.len() >= limit {
                    break;
                }
            }
        }

        hits.sort_by_key(|h| std::cmp::Reverse(h.ts_ms));
        hits.truncate(limit);
        hits
    }

    /// Flush state to the store file if anything changed since the last flush.
    /// A no-op when no store path was configured.
    pub fn persist(&mut self) -> Result<(), CoreError> {
        let Some(path) = self.store_path.clone() else {
            return Ok(());
        };
        if !self.dirty {
            return Ok(());
        }
        let mut seen: Vec<[u8; 32]> = self.seen_envelopes.iter().copied().collect();
        if seen.len() > SEEN_CAP {
            seen.drain(..seen.len() - SEEN_CAP);
        }
        let state = PersistedState {
            prekeys: self.prekeys.export(),
            sessions: self
                .sessions
                .iter()
                .map(|(k, s)| (*k, s.export()))
                .collect(),
            channels: self
                .channels
                .values()
                .map(|c| store::StoredChannel {
                    info: c.info.clone(),
                    mls: c.mls.export().unwrap_or_default(),
                    roster: c.roster.iter().copied().collect(),
                    last_seq: c.last_seq,
                    log_key: c.log_key,
                })
                .collect(),
            hosted: self
                .hosted
                .iter()
                .map(|(root_pub, h)| store::StoredHostedServer {
                    root_pub: *root_pub,
                    name: h.name.clone(),
                    root_secret: h.root.to_bytes(),
                    channels: h.channels.clone(),
                })
                .collect(),
            history: self.history.clone(),
            channel_history: self.channel_history.clone(),
            invite_uses: self.invite_uses.iter().map(|(k, v)| (*k, *v)).collect(),
            channel_removed: self
                .channels
                .iter()
                .flat_map(|(cid, c)| c.removed.iter().map(move |(m, at)| (*cid, *m, *at)))
                .collect(),
            server_autokick: self
                .hosted
                .iter()
                .filter_map(|(root, h)| h.auto_kick_ms.map(|ms| (*root, ms)))
                .collect(),
            server_join_pw: self
                .hosted
                .iter()
                .filter_map(|(root, h)| h.join_pw_hash.map(|hash| (*root, hash)))
                .collect(),
            server_policies: self.server_policies.values().map(|p| p.encode()).collect(),
            channel_reactions: self
                .channel_reactions
                .iter()
                .flat_map(|(cid, by_seq)| {
                    by_seq.iter().flat_map(move |(seq, by_emoji)| {
                        by_emoji.iter().flat_map(move |(emoji, members)| {
                            members.iter().map(move |m| (*cid, *seq, emoji.clone(), *m))
                        })
                    })
                })
                .collect(),
            verified_peers: self
                .verified_peers
                .iter()
                .map(|(id, idk)| (*id, *idk))
                .collect(),
            contacts: self
                .contacts
                .iter()
                .map(|(id, c)| (*id, c.petname.clone(), c.added_ms))
                .collect(),
            blocked: self.blocked.iter().copied().collect(),
            channel_edits: self
                .channel_edits
                .iter()
                .flat_map(|(cid, by_seq)| {
                    by_seq
                        .iter()
                        .filter(|(_, e)| e.text.is_some() || e.deleted)
                        .map(move |(seq, e)| store::StoredEdit {
                            channel_id: *cid,
                            seq: *seq,
                            author: e.author,
                            text: e.text.clone().unwrap_or_default(),
                            deleted: e.deleted,
                        })
                })
                .collect(),
            channel_pins: self
                .channel_pins
                .iter()
                .flat_map(|(cid, by_seq)| {
                    by_seq.iter().map(move |(seq, p)| store::StoredPin {
                        channel_id: *cid,
                        seq: *seq,
                        by: p.by,
                        at_ms: p.at_ms,
                    })
                })
                .collect(),
            dm_msg_ids: self.history.iter().map(|e| e.msg_id).collect(),
            dm_edits: self
                .dm_edits
                .iter()
                .flat_map(|(peer, by_id)| {
                    by_id
                        .iter()
                        .filter(|(_, e)| e.text.is_some() || e.deleted)
                        .map(move |(msg_id, e)| store::StoredDmEdit {
                            peer_idk: *peer,
                            msg_id: *msg_id,
                            text: e.text.clone().unwrap_or_default(),
                            deleted: e.deleted,
                        })
                })
                .collect(),
            seen_envelopes: seen,
            last_announce_ms: self.last_announce_ms,
            last_fetch_since_ms: self.last_fetch_since_ms,
            server_bans: self
                .hosted
                .iter()
                .filter(|(_, h)| !h.banned.is_empty())
                .map(|(root, h)| (*root, h.banned.iter().copied().collect()))
                .collect(),
            server_register_pow: self
                .hosted
                .iter()
                .map(|(root, h)| store::StoredServerPow {
                    root: *root,
                    m_cost_kib: h.register_pow.m_cost_kib,
                    t_cost: h.register_pow.t_cost,
                    difficulty: h.register_pow.difficulty,
                    nonce: h.register_pow.nonce,
                })
                .collect(),
            group_calls: self
                .group_calls
                .iter()
                .filter_map(|(cid, gc)| {
                    gc.mls.export().ok().map(|mls| store::StoredGroupCall {
                        channel_id: *cid,
                        mls,
                    })
                })
                .collect(),
        };
        store::save(&path, &self.identity, &state)?;
        self.dirty = false;
        Ok(())
    }

    /// Pull new ledger records from the relay into the local replica. Returns
    /// how many were accepted.
    pub async fn sync(&mut self, now_ms: u64) -> Result<u64, CoreError> {
        let from = self.relay_ledger_cursor;
        let ledger = &mut self.ledger;
        let (new_cursor, accepted) =
            sync::pull_records(&mut self.client, from, now_ms, 256, |rec: Record, now| {
                ledger.append(rec, now).is_ok()
            })
            .await?;
        self.relay_ledger_cursor = new_cursor;
        Ok(accepted)
    }

    /// Announce this identity to the ledger (builds the PoW). The record lands
    /// in the local replica on the next [`Engine::sync`], keeping the replica a
    /// strict prefix of the relay's log.
    pub async fn announce(&mut self, display_hint: &str, now_ms: u64) -> Result<(), CoreError> {
        let rec = IdentityAnnounce::build(&self.identity, display_hint, self.pow)
            .to_record(&self.identity, now_ms);
        sync::submit_record(&mut self.client, &rec).await?;
        self.gossip_record(&rec).await;
        self.last_announce_ms = now_ms;
        if !display_hint.is_empty() {
            self.announced_name = Some(display_hint.to_owned());
        }
        self.dirty = true;
        Ok(())
    }

    /// Our own self-chosen username (`display_hint` from our `IdentityAnnounce`),
    /// or `None` if we announced without one.
    pub fn my_username(&self) -> Option<String> {
        self.announced_name.clone().or_else(|| {
            self.ledger
                .display_name_by_id(&self.my_member_id())
                .map(str::to_owned)
        })
    }

    /// The self-asserted username for another identity, by its `IdentityId`
    /// bytes (fingerprint). Non-unique and unverified — display only.
    pub fn username_of(&self, identity_id: &[u8; 32]) -> Option<String> {
        self.ledger
            .display_name_by_id(identity_id)
            .map(str::to_owned)
    }

    /// Every identity we know a self-asserted username for, as
    /// `(IdentityId bytes, name)` — for a client's display-name cache.
    pub fn known_usernames(&self) -> Vec<([u8; 32], String)> {
        self.ledger.usernames()
    }

    /// Publish a fresh liveness proof.
    pub async fn prove_liveness(&mut self, now_ms: u64) -> Result<(), CoreError> {
        let rec = LivenessProof::build(&self.identity, now_ms, self.pow)
            .to_record(&self.identity, now_ms);
        sync::submit_record(&mut self.client, &rec).await?;
        self.gossip_record(&rec).await;
        self.last_announce_ms = now_ms;
        self.dirty = true;
        Ok(())
    }

    /// Permanently revoke this identity on the ledger. After the record is
    /// accepted the chain takes no further records and resolves to no usable
    /// key network-wide: peers can no longer start a session with it, and any
    /// server it hosts is delisted. Irreversible — there is no un-revoke.
    pub async fn revoke_identity(
        &mut self,
        reason: RevokeReason,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let rec = IdentityRevoke::build(&self.identity, reason).to_record(&self.identity, now_ms);
        sync::submit_record(&mut self.client, &rec).await?;
        self.gossip_record(&rec).await;
        self.dirty = true;
        Ok(())
    }

    /// Wrap the libp2p node used for the relay transport so it also carries
    /// DHT prekeys and ledger / channel gossip. Briefly drains `Listening`
    /// events so we can advertise our own dial address.
    #[cfg(feature = "p2p")]
    async fn adopt_transport_node(
        node: dante_p2p::Node,
        mut events: tokio::sync::mpsc::Receiver<dante_p2p::Event>,
    ) -> crate::p2p::P2p {
        let mut addrs = Vec::new();
        while let Ok(Some(ev)) =
            tokio::time::timeout(std::time::Duration::from_millis(400), events.recv()).await
        {
            if let dante_p2p::Event::Listening(a) = ev {
                addrs.push(a.to_string());
            }
        }
        crate::p2p::P2p::adopt(node, events, addrs).await
    }

    /// Post a channel-log frame to the relay and, when p2p is on, fan it out
    /// over the channel's gossip topic. Returns the relay-log `seq`.
    async fn post_channel_frame(
        &mut self,
        channel_id: &[u8; 32],
        frame: &[u8],
    ) -> Result<u64, CoreError> {
        let seq = sync::post_to_channel(&mut self.client, channel_id, frame).await?;
        #[cfg(feature = "p2p")]
        if let Some(p2p) = &self.p2p {
            p2p.publish_channel(channel_id, seq, frame).await;
        }
        Ok(seq)
    }

    /// Test hook: pretend a `(seq, frame)` for `channel_id` arrived over
    /// channel gossip, so a test can exercise the merge path in `poll_channels`
    /// (including a hostile frame) without standing up a real gossip mesh.
    #[cfg(all(test, feature = "p2p"))]
    pub(crate) fn inject_channel_gossip(&mut self, channel_id: [u8; 32], seq: u64, frame: Vec<u8>) {
        self.channel_gossip
            .entry(channel_id)
            .or_default()
            .push((seq, frame));
    }

    /// Test hook: the highest channel-log seq this client has consumed.
    #[cfg(test)]
    pub(crate) fn channel_last_seq(&self, channel_id: &[u8; 32]) -> u64 {
        self.channels.get(channel_id).map_or(0, |c| c.last_seq)
    }

    /// Fan a just-submitted ledger record out to peers over gossipsub. No-op
    /// unless the `p2p` feature is on and a node is running.
    async fn gossip_record(&self, rec: &Record) {
        #[cfg(feature = "p2p")]
        if let Some(p2p) = &self.p2p {
            p2p.publish_ledger(rec.encode()).await;
        }
        #[cfg(not(feature = "p2p"))]
        let _ = rec;
    }

    /// Fold ledger records heard from peers over gossipsub into the local
    /// replica. Returns how many were newly accepted. Best-effort; the relay
    /// [`sync`](Engine::sync) remains the authoritative path. Feature `p2p`.
    #[cfg(feature = "p2p")]
    pub async fn poll_p2p(&mut self, now_ms: u64) -> u64 {
        if self.p2p.is_none() {
            return 0;
        }
        // Keep our bootstrap advertisement fresh on the relay (~10 min).
        if now_ms.saturating_sub(self.last_p2p_announce_ms) > 600_000 {
            let addrs = self.p2p_dial_addrs();
            if !addrs.is_empty() {
                let _ = sync::announce_p2p(&mut self.client, &addrs).await;
            }
            self.last_p2p_announce_ms = now_ms;
        }
        // Subscribe any channel whose gossip topic we don't have yet.
        let want: Vec<[u8; 32]> = self
            .channels
            .keys()
            .filter(|id| !self.subscribed_channels.contains(*id))
            .copied()
            .collect();
        for id in want {
            if let Some(p2p) = &self.p2p {
                p2p.subscribe_channel(&id).await;
            }
            self.subscribed_channels.insert(id);
        }

        let (blobs, frames) = match self.p2p.as_mut() {
            Some(p2p) => (p2p.drain_ledger_records(), p2p.drain_channel_frames()),
            None => return 0,
        };
        for (cid, seq, frame) in frames {
            if !self.channels.contains_key(&cid) {
                continue;
            }
            let buf = self.channel_gossip.entry(cid).or_default();
            buf.push((seq, frame));
            // Bound the buffer if `poll_channels` isn't keeping up.
            if buf.len() > 256 {
                let drop = buf.len() - 256;
                buf.drain(..drop);
            }
        }
        let mut accepted = 0;
        for blob in blobs {
            if let Ok(rec) = Record::decode(&blob) {
                if self.ledger.append(rec, now_ms).is_ok() {
                    accepted += 1;
                }
            }
        }
        accepted
    }

    /// Whether the ledger has seen a revocation for `idk` (any key in its
    /// chain). A client should refuse to encrypt to a revoked identity.
    pub fn is_revoked(&self, idk: &[u8; 32]) -> bool {
        self.ledger.is_revoked(idk)
    }

    /// The human-comparable "safety number" for the DM pair (this identity and
    /// `peer_id`): 60 decimal digits in 12 space-separated groups of 5, derived
    /// from `SHA-512(domain || min(idk) || max(idk))` over the two current
    /// signing keys. Order-independent, so both ends display the same string.
    /// `None` if the peer is unknown or revoked. Read it aloud / scan it out of
    /// band; a match rules out a MITM'd key exchange.
    pub fn safety_number(&self, peer_id: &[u8; 32]) -> Option<String> {
        let peer_idk = self.ledger.idk_for_id(peer_id)?;
        let mine = self.identity.sign_public().to_bytes();
        let (lo, hi) = if mine <= peer_idk {
            (mine, peer_idk)
        } else {
            (peer_idk, mine)
        };
        let mut buf = Vec::with_capacity(SAFETY_NUMBER_DOMAIN.len() + 64);
        buf.extend_from_slice(SAFETY_NUMBER_DOMAIN);
        buf.extend_from_slice(&lo);
        buf.extend_from_slice(&hi);
        let h = sha512(&buf);

        let mut groups = Vec::with_capacity(12);
        for chunk in h[..60].as_chunks::<5>().0 {
            let mut v = 0u64;
            for &b in chunk {
                v = (v << 8) | u64::from(b);
            }
            groups.push(format!("{:05}", v % 100_000));
        }
        Some(groups.join(" "))
    }

    /// Mark (or clear) `peer_id` as safety-number-verified. When setting it, the
    /// peer's current `idk` is pinned; a subsequent key rotation makes
    /// [`Engine::is_verified`] report `false` again until re-verified.
    pub fn set_verified(&mut self, peer_id: &[u8; 32], verified: bool) -> Result<(), CoreError> {
        if verified {
            let idk = self
                .ledger
                .idk_for_id(peer_id)
                .ok_or(CoreError::UnknownPeer)?;
            self.verified_peers.insert(*peer_id, idk);
        } else {
            self.verified_peers.remove(peer_id);
        }
        self.dirty = true;
        Ok(())
    }

    /// Add a contact (or update its petname if it already exists). `petname` is
    /// trimmed and capped at [`PETNAME_MAX`] bytes; it may be empty.
    pub fn add_contact(&mut self, peer_id: &[u8; 32], petname: &str, now_ms: u64) {
        let petname = petname.trim();
        let petname: String = petname.chars().take(PETNAME_MAX).collect();
        match self.contacts.get_mut(peer_id) {
            Some(c) => c.petname = petname,
            None => {
                self.contacts.insert(
                    *peer_id,
                    Contact {
                        petname,
                        added_ms: now_ms,
                    },
                );
            }
        }
        self.dirty = true;
    }

    /// Forget a contact. The petname is dropped; conversation history is not.
    pub fn remove_contact(&mut self, peer_id: &[u8; 32]) {
        if self.contacts.remove(peer_id).is_some() {
            self.dirty = true;
        }
    }

    /// The saved contacts, sorted by petname (then fingerprint bytes).
    pub fn contacts(&self) -> Vec<([u8; 32], Contact)> {
        let mut out: Vec<_> = self
            .contacts
            .iter()
            .map(|(id, c)| (*id, c.clone()))
            .collect();
        out.sort_by(|a, b| {
            a.1.petname
                .to_lowercase()
                .cmp(&b.1.petname.to_lowercase())
                .then(a.0.cmp(&b.0))
        });
        out
    }

    /// This identity's private label for `peer_id`, if saved and non-empty.
    pub fn petname(&self, peer_id: &[u8; 32]) -> Option<&str> {
        self.contacts
            .get(peer_id)
            .map(|c| c.petname.as_str())
            .filter(|s| !s.is_empty())
    }

    /// Whether `peer_id` is a saved contact.
    pub fn is_contact(&self, peer_id: &[u8; 32]) -> bool {
        self.contacts.contains_key(peer_id)
    }

    /// Block an identity: its inbound DMs, channel messages and typing signals
    /// are dropped, and [`Engine::send_dm`] to it refuses. Local only.
    pub fn block(&mut self, peer_id: &[u8; 32]) {
        if self.blocked.insert(*peer_id) {
            self.dirty = true;
        }
    }

    /// Unblock an identity.
    pub fn unblock(&mut self, peer_id: &[u8; 32]) {
        if self.blocked.remove(peer_id) {
            self.dirty = true;
        }
    }

    /// Whether `peer_id` is blocked.
    pub fn is_blocked(&self, peer_id: &[u8; 32]) -> bool {
        self.blocked.contains(peer_id)
    }

    /// The blocked identities, sorted.
    pub fn blocked(&self) -> Vec<[u8; 32]> {
        let mut v: Vec<_> = self.blocked.iter().copied().collect();
        v.sort_unstable();
        v
    }

    // ---- 1:1 voice calls ------------------------------------------------------
    //
    // Signalling rides sealed-sender ratchet DMs (`Content::Call*`); the media
    // path is WebRTC / DTLS-SRTP established peer-to-peer. Because the SDP (which
    // carries the DTLS fingerprint) travels inside a sender-authenticated
    // message, a relay cannot MITM the media. Group calls await MLS.

    /// Place a call to `peer_id`: build the WebRTC offer and DM it. Drive the
    /// handshake afterwards with [`Engine::receive_all`] + [`Engine::poll_calls`].
    pub async fn start_call(&mut self, peer_id: &[u8; 32], now_ms: u64) -> Result<(), CoreError> {
        if self.blocked.contains(peer_id) {
            return Err(CoreError::Blocked);
        }
        if self.calls.contains_key(peer_id) {
            return Err(CoreError::Voice(
                "a call with this peer is already active".into(),
            ));
        }
        let (call, offer) = Call::offer_with(&self.ice_servers)
            .await
            .map_err(voice_err)?;
        self.calls.insert(*peer_id, call);
        self.call_states.insert(*peer_id, CallState::New);
        self.send_content(peer_id, Content::CallOffer(offer), now_ms)
            .await
    }

    /// Accept a call announced by [`Inbound::IncomingCall`]: build the answer
    /// and DM it back.
    pub async fn accept_call(&mut self, peer_id: &[u8; 32], now_ms: u64) -> Result<(), CoreError> {
        let offer = self
            .pending_call_offers
            .remove(peer_id)
            .ok_or(CoreError::Voice("no pending call from that peer".into()))?;
        let (call, answer) = Call::answer_with(&offer, &self.ice_servers)
            .await
            .map_err(voice_err)?;
        self.calls.insert(*peer_id, call);
        self.call_states.insert(*peer_id, CallState::New);
        self.send_content(peer_id, Content::CallAnswer(answer), now_ms)
            .await
    }

    /// Hang up (or decline) the call with `peer_id`. Best-effort — always
    /// clears local state.
    pub async fn hangup(&mut self, peer_id: &[u8; 32], now_ms: u64) -> Result<(), CoreError> {
        self.pending_call_offers.remove(peer_id);
        self.call_states.remove(peer_id);
        self.inbound_audio.remove(peer_id);
        if let Some(call) = self.calls.remove(peer_id) {
            call.close().await;
        }
        let _ = self.send_content(peer_id, Content::CallEnd, now_ms).await;
        Ok(())
    }

    /// Pump every active call: relay locally-gathered ICE candidates to the peer
    /// (as `Content::CallIce` DMs) and return the connection-state transitions
    /// seen since the last call.
    pub async fn poll_calls(&mut self, now_ms: u64) -> Result<Vec<CallUpdate>, CoreError> {
        let peers: Vec<[u8; 32]> = self.calls.keys().copied().collect();
        let mut ice: Vec<([u8; 32], String)> = Vec::new();
        let mut updates: Vec<CallUpdate> = Vec::new();
        for peer in peers {
            while let Some(ev) = self.calls.get_mut(&peer).and_then(Call::try_event) {
                match ev {
                    CallEvent::LocalIce(c) => ice.push((peer, c)),
                    CallEvent::State(state) => {
                        self.call_states.insert(peer, state);
                        updates.push(CallUpdate { peer, state });
                    }
                    CallEvent::RemoteAudio(frame) => {
                        let q = self.inbound_audio.entry(peer).or_default();
                        q.push_back(frame);
                        while q.len() > 200 {
                            q.pop_front();
                        }
                    }
                    CallEvent::CtlOpen | CallEvent::Ctl(_) => {}
                }
            }
        }
        for (peer, cand) in ice {
            let _ = self
                .send_content(&peer, Content::CallIce(cand), now_ms)
                .await;
        }
        Ok(updates)
    }

    /// Current state of the call with `peer_id`, if any.
    pub fn call_state(&self, peer_id: &[u8; 32]) -> Option<CallState> {
        self.call_states.get(peer_id).copied()
    }

    /// Set the STUN/TURN servers used when *starting* future calls (calls
    /// already in progress keep their config).
    pub fn set_ice_servers(&mut self, servers: Vec<IceServer>) {
        self.ice_servers = servers;
    }

    /// The configured STUN/TURN servers.
    pub fn ice_servers(&self) -> &[IceServer] {
        &self.ice_servers
    }

    /// Whether a call with `peer_id` is active (connecting or connected).
    pub fn in_call(&self, peer_id: &[u8; 32]) -> bool {
        self.calls.contains_key(peer_id)
    }

    /// Send one Opus frame (`ms` = its duration, e.g. 20) on the call's audio
    /// track. A capture layer (cpal + Opus, `dante-audio`) drives this.
    pub async fn send_call_audio(
        &self,
        peer_id: &[u8; 32],
        opus: &[u8],
        ms: u32,
    ) -> Result<(), CoreError> {
        let call = self
            .calls
            .get(peer_id)
            .ok_or(CoreError::Voice("no active call".into()))?;
        call.push_audio(opus, ms).await.map_err(voice_err)
    }

    /// Drain the Opus frames received on `peer_id`'s audio track since the last
    /// call (collected by [`Engine::poll_calls`]). Feed them to a decoder +
    /// speaker.
    pub fn take_call_audio(&mut self, peer_id: &[u8; 32]) -> Vec<Vec<u8>> {
        self.inbound_audio
            .get_mut(peer_id)
            .map(|q| q.drain(..).collect())
            .unwrap_or_default()
    }

    // ---- Channel group calls (MLS-keyed, full-mesh media) -------------------
    //
    // A group call is an MLS group (for a shared, membership-bound key that
    // rotates on every join/leave — `group_call_key`) plus a full mesh of the
    // existing 1:1 `Call`s for the media itself (each leg is its own
    // DTLS-SRTP). Handshake messages (Welcome, Commit) ride sealed-sender DMs.

    /// How many unused MLS KeyPackages to keep published so peers can add this
    /// identity to channels / group calls. Each is single-use.
    const MLS_KEYPKG_POOL: usize = 12;

    /// Try every outstanding published-KeyPackage private half against a
    /// Welcome, returning the joined [`mls::Member`] and keeping the rest.
    fn try_join_pending(&mut self, welcome: &[u8]) -> Option<mls::Member> {
        let mut kept: Vec<mls::Pending> = Vec::with_capacity(self.mls_pending.len());
        let mut joined: Option<mls::Member> = None;
        for pending in std::mem::take(&mut self.mls_pending) {
            if joined.is_some() {
                kept.push(pending);
                continue;
            }
            match pending.join(welcome) {
                Ok(m) => joined = Some(m),
                Err((p, _)) => kept.push(*p),
            }
        }
        self.mls_pending = kept;
        joined
    }

    /// Top the published-KeyPackage pool back up to [`MLS_KEYPKG_POOL`]. Each
    /// KeyPackage can be used to join exactly one group, so a member that joins
    /// several channels needs several. Called at connect and after each join.
    pub async fn refresh_mls_key_package(&mut self) -> Result<(), CoreError> {
        let me = self.my_member_id();
        let mut fresh = Vec::new();
        while self.mls_pending.len() + fresh.len() < Self::MLS_KEYPKG_POOL {
            let (pending, kp) = mls::Member::publish_key_package(&me).map_err(mls_err)?;
            self.mls_pending.push(pending);
            fresh.push(kp.0);
        }
        if !fresh.is_empty() {
            sync::publish_key_packages(&mut self.client, &me, fresh).await?;
        }
        while self.mls_pending.len() > Self::MLS_KEYPKG_POOL * 2 {
            self.mls_pending.remove(0);
        }
        Ok(())
    }

    /// Start a group call in a channel: create the MLS group, add every other
    /// roster member that has a published KeyPackage, DM them the Welcome, and
    /// open a media leg to each. Drive it with [`Engine::receive_all`] +
    /// [`Engine::poll_calls`] + [`Engine::poll_group_calls`].
    pub async fn start_group_call(
        &mut self,
        channel_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        if !self.channels.contains_key(channel_id) {
            return Err(CoreError::UnknownChannel);
        }
        if self.group_calls.contains_key(channel_id) {
            return Err(CoreError::Voice("already in this group call".into()));
        }
        let me = self.my_member_id();
        let others: Vec<[u8; 32]> = self.channels[channel_id]
            .roster
            .iter()
            .copied()
            .filter(|m| *m != me)
            .collect();

        let mut mls_member = mls::Member::create(&me, channel_id).map_err(mls_err)?;

        let mut kps: Vec<mls::KeyPkg> = Vec::new();
        let mut invited: Vec<[u8; 32]> = Vec::new();
        for m in &others {
            if let Ok(Some(bytes)) = sync::get_key_package(&mut self.client, m).await {
                kps.push(mls::KeyPkg(bytes));
                invited.push(*m);
            }
        }

        if !kps.is_empty() {
            let hs = mls_member.add(&kps).map_err(mls_err)?;
            let welcome = hs
                .welcome
                .ok_or_else(|| CoreError::Voice("MLS add produced no Welcome".into()))?;
            for m in &invited {
                let _ = self
                    .send_content(
                        m,
                        Content::GroupCallWelcome {
                            channel_id: *channel_id,
                            blob: welcome.clone(),
                        },
                        now_ms,
                    )
                    .await;
            }
        }

        self.group_calls
            .insert(*channel_id, GroupCall { mls: mls_member });
        self.reconcile_group_legs(channel_id, now_ms).await;
        self.dirty = true;
        Ok(())
    }

    /// Join a group call we were invited to (an [`Inbound::GroupCallInvite`]).
    pub async fn join_group_call(
        &mut self,
        channel_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let (_from, welcome) = self
            .pending_group_calls
            .remove(channel_id)
            .ok_or_else(|| CoreError::Voice("no pending invite for that channel".into()))?;
        if self.group_calls.contains_key(channel_id) {
            return Err(CoreError::Voice("already in this group call".into()));
        }

        let member = self.try_join_pending(&welcome).ok_or_else(|| {
            CoreError::Voice("no KeyPackage matched the Welcome (re-publish and retry)".into())
        })?;

        self.group_calls
            .insert(*channel_id, GroupCall { mls: member });
        let _ = self.refresh_mls_key_package().await;
        self.reconcile_group_legs(channel_id, now_ms).await;
        self.dirty = true;
        Ok(())
    }

    /// Leave a group call: tear down every media leg and tell the other members
    /// to rekey without us.
    pub async fn leave_group_call(
        &mut self,
        channel_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let Some(gc) = self.group_calls.remove(channel_id) else {
            return Ok(());
        };
        let me = self.my_member_id();
        let peers: Vec<[u8; 32]> = gc
            .mls
            .members()
            .into_iter()
            .filter_map(|(_, id)| <[u8; 32]>::try_from(id).ok())
            .filter(|id| *id != me)
            .collect();
        for p in &peers {
            let _ = self.hangup(p, now_ms).await;
            let _ = self
                .send_content(
                    p,
                    Content::GroupCallLeave {
                        channel_id: *channel_id,
                    },
                    now_ms,
                )
                .await;
        }
        self.dirty = true;
        Ok(())
    }

    /// Open a media leg to every MLS member of `channel_id`'s call we do not yet
    /// have one with. Glare-free: the lower identity id sends the offer, the
    /// higher one auto-accepts in [`Engine::receive_all`].
    async fn reconcile_group_legs(&mut self, channel_id: &[u8; 32], now_ms: u64) {
        let me = self.my_member_id();
        let Some(gc) = self.group_calls.get(channel_id) else {
            return;
        };
        let targets: Vec<[u8; 32]> = gc
            .mls
            .members()
            .into_iter()
            .filter_map(|(_, id)| <[u8; 32]>::try_from(id).ok())
            .filter(|id| *id != me && me < *id && !self.calls.contains_key(id))
            .collect();
        for t in targets {
            let _ = self.start_call(&t, now_ms).await;
        }
    }

    /// Whether `id` is an MLS member of some active group call (so an incoming
    /// call offer from them is a media leg to auto-accept, not a fresh 1:1).
    fn is_group_call_member(&self, id: &[u8; 32]) -> bool {
        self.group_calls
            .values()
            .any(|gc| gc.mls.members().iter().any(|(_, m)| m.as_slice() == id))
    }

    /// The MLS members of `channel_id`'s group call other than us.
    pub fn group_call_peers(&self, channel_id: &[u8; 32]) -> Vec<[u8; 32]> {
        let me = self.my_member_id();
        self.group_calls
            .get(channel_id)
            .map(|gc| {
                gc.mls
                    .members()
                    .into_iter()
                    .filter_map(|(_, id)| <[u8; 32]>::try_from(id).ok())
                    .filter(|id| *id != me)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The per-epoch group-call media key for `channel_id`, if we are in the
    /// call. Every member in the same epoch derives the same 32 bytes; it
    /// rotates on every join/leave.
    pub fn group_call_key(&self, channel_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.group_calls.get(channel_id)?.mls.call_key().ok()
    }

    /// The MLS epoch of `channel_id`'s group call, if we are in it. Bumps on
    /// every membership change; a client keys an SFrame layer off `(key,
    /// epoch)` and re-derives when the epoch moves.
    pub fn group_call_epoch(&self, channel_id: &[u8; 32]) -> Option<u64> {
        self.group_calls.get(channel_id).map(|gc| gc.mls.epoch())
    }

    /// Whether we are in `channel_id`'s group call.
    pub fn in_group_call(&self, channel_id: &[u8; 32]) -> bool {
        self.group_calls.contains_key(channel_id)
    }

    /// Channels we hold an unanswered group-call invite for.
    pub fn pending_group_call_channels(&self) -> Vec<[u8; 32]> {
        self.pending_group_calls.keys().copied().collect()
    }

    // ---- voice channels ---------------------------------------------------

    /// Relay signal topic for a voice channel's presence beacons (distinct from
    /// the channel's typing topic, which is `channel_id` itself).
    fn voice_presence_topic(channel_id: &[u8; 32]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(VOICE_PRESENCE_LABEL.len() + 32);
        buf.extend_from_slice(VOICE_PRESENCE_LABEL.as_bytes());
        buf.extend_from_slice(channel_id);
        sha256(&buf)
    }

    /// Connect to a voice channel's persistent group call. If nobody is in the
    /// room we open it; otherwise we ask the members present to add us and the
    /// resulting Welcome is joined automatically on the next
    /// [`receive_all`](Engine::receive_all).
    pub async fn join_voice_channel(
        &mut self,
        channel_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let ch = self
            .channels
            .get(channel_id)
            .ok_or(CoreError::UnknownChannel)?;
        if !ch.info.voice {
            return Err(CoreError::Channel("not a voice channel"));
        }
        if self.in_group_call(channel_id) {
            return Ok(());
        }
        if self.pending_group_calls.contains_key(channel_id) {
            return self.join_group_call(channel_id, now_ms).await;
        }

        let me = self.my_member_id();
        let present: Vec<[u8; 32]> = self
            .voice_participants(channel_id, now_ms)
            .await
            .into_iter()
            .filter(|m| *m != me)
            .collect();

        if present.is_empty() {
            // Open the room *solo* — unlike `start_group_call`, a voice channel
            // does not pre-invite every member; they join on demand and are
            // added via `GroupCallJoinRequest`.
            let member = mls::Member::create(&me, channel_id).map_err(mls_err)?;
            self.group_calls
                .insert(*channel_id, GroupCall { mls: member });
            let _ = self.refresh_mls_key_package().await;
            // Announce presence right away so a near-simultaneous joiner sees us
            // and asks to be added rather than opening a second room.
            let _ = self.send_voice_presence(now_ms).await;
            return Ok(());
        }
        self.voice_join_intent.insert(*channel_id);
        for m in &present {
            let _ = self
                .send_content(
                    m,
                    Content::GroupCallJoinRequest {
                        channel_id: *channel_id,
                    },
                    now_ms,
                )
                .await;
        }
        Ok(())
    }

    /// Disconnect from a voice channel's group call.
    pub async fn leave_voice_channel(
        &mut self,
        channel_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        self.voice_join_intent.remove(channel_id);
        self.leave_group_call(channel_id, now_ms).await
    }

    /// Relay one WebRTC signalling blob to another voice-channel participant.
    /// The browsers own the peer connection; the engine is a dumb pipe. `to` is
    /// the peer's `IdentityId` bytes; `kind` is 0 offer / 1 answer / 2 ICE /
    /// 3 bye / 4 soundboard trigger (`data` = hex blob hash).
    pub async fn send_voice_signal(
        &mut self,
        to: &[u8; 32],
        channel_id: &[u8; 32],
        kind: u8,
        data: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        self.send_content(
            to,
            Content::VoiceSignal {
                channel_id: *channel_id,
                kind,
                data: data.to_owned(),
            },
            now_ms,
        )
        .await
    }

    /// Post a presence beacon for every voice channel we are currently
    /// connected to. Call each tick.
    pub async fn send_voice_presence(&mut self, now_ms: u64) -> Result<(), CoreError> {
        let me = self.my_member_id();
        let connected: Vec<[u8; 32]> = self
            .channels
            .iter()
            .filter(|(cid, c)| c.info.voice && self.group_calls.contains_key(*cid))
            .map(|(cid, _)| *cid)
            .collect();
        for cid in connected {
            let blob = {
                let Some(ch) = self.channels.get(&cid) else {
                    continue;
                };
                match seal_channel_signal(
                    &ch.mls,
                    &me,
                    &cid,
                    VOICE_PRESENCE_LABEL,
                    &now_ms.to_be_bytes(),
                ) {
                    Ok(b) => b,
                    Err(_) => continue,
                }
            };
            let topic = Self::voice_presence_topic(&cid);
            let _ = sync::post_signal(&mut self.client, &topic, &blob).await;
        }
        Ok(())
    }

    /// Read the fresh presence beacons for one voice channel — who is in the
    /// room right now (sorted `IdentityId` bytes, plus ourselves if connected).
    pub async fn voice_participants(
        &mut self,
        channel_id: &[u8; 32],
        now_ms: u64,
    ) -> Vec<[u8; 32]> {
        let mut out = std::collections::BTreeSet::new();
        if self.group_calls.contains_key(channel_id) {
            out.insert(self.my_member_id());
        }
        let topic = Self::voice_presence_topic(channel_id);
        if let Ok(blobs) = sync::fetch_signals(&mut self.client, &topic).await {
            if let Some(ch) = self.channels.get(channel_id) {
                for blob in blobs {
                    let Some((member, pt)) =
                        open_channel_signal(&ch.mls, channel_id, VOICE_PRESENCE_LABEL, &blob)
                    else {
                        continue;
                    };
                    if pt.len() < 8 || self.blocked.contains(&member) {
                        continue;
                    }
                    let at = u64::from_be_bytes(pt[..8].try_into().unwrap());
                    if now_ms.saturating_sub(at) <= VOICE_PRESENCE_TTL_MS {
                        out.insert(member);
                    }
                }
            }
        }
        out.into_iter().collect()
    }

    /// Presence for every voice channel we belong to. Call each tick alongside
    /// [`send_voice_presence`](Engine::send_voice_presence).
    pub async fn poll_voice(&mut self, now_ms: u64) -> Vec<VoicePresence> {
        let voice_channels: Vec<[u8; 32]> = self
            .channels
            .iter()
            .filter(|(_, c)| c.info.voice)
            .map(|(cid, _)| *cid)
            .collect();
        let mut out = Vec::new();
        for cid in voice_channels {
            let members = self.voice_participants(&cid, now_ms).await;
            out.push(VoicePresence {
                channel_id: cid,
                members,
            });
        }
        out
    }

    /// Reconcile the media mesh for every active group call. Call each tick,
    /// alongside [`Engine::poll_calls`].
    pub async fn poll_group_calls(&mut self, now_ms: u64) -> Result<(), CoreError> {
        let ids: Vec<[u8; 32]> = self.group_calls.keys().copied().collect();
        for id in ids {
            self.reconcile_group_legs(&id, now_ms).await;
        }
        Ok(())
    }

    /// Whether `peer_id` is verified **and** still on the key that was verified.
    pub fn is_verified(&self, peer_id: &[u8; 32]) -> bool {
        match (
            self.verified_peers.get(peer_id),
            self.ledger.idk_for_id(peer_id),
        ) {
            (Some(pinned), Some(current)) => pinned == &current,
            _ => false,
        }
    }

    /// Announce on first run, then only re-prove liveness once a day — a
    /// restored client that announced recently skips the PoW entirely.
    pub async fn announce_if_stale(
        &mut self,
        display_hint: &str,
        now_ms: u64,
    ) -> Result<bool, CoreError> {
        if now_ms.saturating_sub(self.last_announce_ms) <= REANNOUNCE_AFTER_MS {
            return Ok(false);
        }
        if self.last_announce_ms == 0 {
            self.announce(display_hint, now_ms).await?;
        } else {
            self.prove_liveness(now_ms).await?;
        }
        Ok(true)
    }

    /// Publish this identity's prekey bundle to the relay.
    pub async fn publish_prekeys(&mut self) -> Result<(), CoreError> {
        // Refill the one-time-prekey pool before every publish. The relay hands
        // out one OTP per fetch, so without this a client that accepted a few
        // first-contacts would eventually publish an OTP-less bundle.
        if self.prekeys.replenish(PREKEY_POOL_TARGET) > 0 {
            self.dirty = true;
        }
        let bundle = self.prekeys.bundle(&self.identity).encode();
        sync::publish_prekeys(&mut self.client, &bundle).await?;
        #[cfg(feature = "p2p")]
        if let Some(p2p) = &self.p2p {
            p2p.put_prekey(&self.my_member_id(), &bundle).await;
        }
        Ok(())
    }

    /// Start an optional libp2p node so the DHT can serve as a decentralised
    /// key-directory fallback alongside the relay. `listen` is a multiaddr
    /// (e.g. `/ip4/0.0.0.0/tcp/0`); `bootstrap` is a list of peer multiaddrs
    /// each ending `/p2p/<peer-id>`. Returns this node's own dialable addresses.
    /// Best-effort: on failure the engine keeps working over the relay alone.
    #[cfg(feature = "p2p")]
    pub async fn enable_p2p(
        &mut self,
        listen: &str,
        bootstrap: &[String],
    ) -> Result<Vec<String>, CoreError> {
        // A libp2p relay transport already brought up a node; reuse it rather
        // than run a second swarm.
        if self.p2p.is_some() {
            let addrs = self.p2p_dial_addrs();
            let _ = sync::announce_p2p(&mut self.client, &addrs).await;
            return Ok(addrs);
        }
        // Merge the caller's bootstrap list with peers the relay knows about.
        let mut boot: Vec<String> = bootstrap.to_vec();
        if let Ok(from_relay) = sync::get_p2p_peers(&mut self.client).await {
            for p in from_relay {
                if !boot.contains(&p) {
                    boot.push(p);
                }
            }
        }

        let p2p = crate::p2p::P2p::start(&self.identity.p2p_node_seed(), listen, &boot).await?;
        // Seed the DHT with our current bundle right away.
        let bundle = self.prekeys.bundle(&self.identity).encode();
        p2p.put_prekey(&self.my_member_id(), &bundle).await;
        let addrs = p2p.dial_addrs();
        // Let the relay hand our address to other clients as a bootstrap peer.
        // `poll_p2p` refreshes this periodically.
        let _ = sync::announce_p2p(&mut self.client, &addrs).await;
        self.p2p = Some(p2p);
        Ok(addrs)
    }

    /// This client's libp2p `PeerId`, if [`enable_p2p`](Engine::enable_p2p) ran.
    #[cfg(feature = "p2p")]
    pub fn p2p_peer_id(&self) -> Option<String> {
        self.p2p.as_ref().map(|p| p.peer_id())
    }

    /// This client's dialable libp2p multiaddrs, if p2p is enabled.
    #[cfg(feature = "p2p")]
    pub fn p2p_dial_addrs(&self) -> Vec<String> {
        self.p2p
            .as_ref()
            .map(|p| p.dial_addrs())
            .unwrap_or_default()
    }

    /// Resolve a peer's prekey bundle straight from the DHT (skips the relay).
    /// `None` if p2p is not enabled or the record is not found. Exposed mainly
    /// for tests and diagnostics.
    #[cfg(feature = "p2p")]
    pub async fn dht_prekey(&self, peer_id: &[u8; 32]) -> Option<Vec<u8>> {
        self.p2p.as_ref()?.get_prekey(peer_id).await
    }

    // ---- channels / servers -------------------------------------------------

    /// Channels this client currently belongs to.
    pub fn channels(&self) -> Vec<ChannelInfo> {
        self.channels.values().map(|c| c.info.clone()).collect()
    }

    /// The live MLS membership of a channel we're in — `IdentityId` bytes,
    /// including ourselves. Empty if we don't have the channel.
    pub fn channel_roster(&self, channel_id: &[u8; 32]) -> Vec<[u8; 32]> {
        self.channels
            .get(channel_id)
            .map(|c| c.roster.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Channels the host has removed us from since the last call —
    /// `(channel_id, server_root, server_name)`. Drains the queue.
    pub fn take_evicted_channels(&mut self) -> Vec<([u8; 32], [u8; 32], String)> {
        std::mem::take(&mut self.evicted_channels)
    }

    /// Create a server: mint a root key, register it on the ledger. Returns the
    /// `server_root` public key (also its display handle).
    pub async fn create_server(&mut self, name: &str, now_ms: u64) -> Result<[u8; 32], CoreError> {
        let root = SignSecret::generate();
        let server_root = root.public().to_bytes();
        // Server roots aren't PoW'd identities, so the directory record carries
        // its own proof of work. Bound to `server_root` only — solved once here,
        // replayed on every later re-registration.
        let register_pow =
            dante_crypto::pow::solve(&ServerRegister::challenge(&server_root), self.pow);
        let reg = ServerRegister {
            server_root,
            name: name.chars().take(64).collect(),
            summary: String::new(),
            tags: vec![],
            entry_relays: vec![],
            discoverable: false,
            invite: String::new(),
            pow: register_pow,
        };
        let rec = reg.to_record(now_ms, |m| root.sign(m));
        sync::submit_record(&mut self.client, &rec).await?;
        self.server_policies.insert(
            server_root,
            ServerPolicy::genesis(&root, self.my_member_id(), now_ms),
        );
        self.hosted.insert(
            server_root,
            HostedServer {
                name: name.to_owned(),
                root,
                channels: vec![],
                auto_kick_ms: None,
                join_pw_hash: None,
                banned: HashSet::new(),
                register_pow,
            },
        );
        self.dirty = true;
        Ok(server_root)
    }

    /// Create a channel in a server this client hosts. Returns the channel id.
    ///
    /// `password`, if given, content-protects the channel: every relay-log
    /// frame is wrapped in an outer AEAD keyed by `Argon2id(password)`, so the
    /// `channel_id` alone (e.g. leaked to a relay) does not grant read access.
    pub fn create_channel(
        &mut self,
        server_root: &[u8; 32],
        name: &str,
        private: bool,
        password: Option<&str>,
    ) -> Result<[u8; 32], CoreError> {
        self.create_channel_inner(server_root, name, private, password, false)
    }

    /// Create a **voice** channel: members join a persistent group call keyed by
    /// the channel id ([`join_voice_channel`](Engine::join_voice_channel))
    /// instead of exchanging text.
    pub fn create_voice_channel(
        &mut self,
        server_root: &[u8; 32],
        name: &str,
        private: bool,
    ) -> Result<[u8; 32], CoreError> {
        self.create_channel_inner(server_root, name, private, None, true)
    }

    fn create_channel_inner(
        &mut self,
        server_root: &[u8; 32],
        name: &str,
        private: bool,
        password: Option<&str>,
        voice: bool,
    ) -> Result<[u8; 32], CoreError> {
        let server_name = self
            .hosted
            .get(server_root)
            .ok_or(CoreError::NotServerHost)?
            .name
            .clone();
        let channel_id = random_array::<32>();
        let me = self.my_member_id();
        let mls = mls::Member::create(&me, &channel_id).map_err(mls_err)?;
        let log_key = password
            .filter(|p| !p.is_empty())
            .map(|p| channel::derive_log_key(server_root, &channel_id, p));
        let info = ChannelInfo {
            server_root: *server_root,
            server_name,
            channel_id,
            channel_name: name.to_owned(),
            private,
            host_id: me,
            voice,
        };
        let mut roster = HashSet::new();
        roster.insert(me);
        self.channels.insert(
            channel_id,
            ChannelSession {
                info,
                mls,
                roster,
                last_seq: 0,
                removed: HashMap::new(),
                log_key,
            },
        );
        self.hosted
            .get_mut(server_root)
            .unwrap()
            .channels
            .push(channel_id);
        self.dirty = true;
        Ok(channel_id)
    }

    /// Build a channel-log frame, applying the outer password wrapper if the
    /// channel has one.
    fn wrap_channel_frame(&self, channel_id: &[u8; 32], tag: u8, payload: &[u8]) -> Vec<u8> {
        let framed = channel::frame(tag, payload);
        match self.channels.get(channel_id).and_then(|c| c.log_key) {
            Some(k) => channel::wrap(&k, channel_id, &framed),
            None => framed,
        }
    }

    /// Add `peer_id` to a channel (host only): commit an MLS add to the channel
    /// log and DM the joiner the Welcome (plus the current role policy). The
    /// peer must have a published MLS KeyPackage — i.e. have connected at least
    /// once.
    pub async fn invite_to_channel(
        &mut self,
        channel_id: &[u8; 32],
        peer_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let (channel_name, server_name) = {
            let ch = self
                .channels
                .get(channel_id)
                .ok_or(CoreError::UnknownChannel)?;
            if !self.hosted.contains_key(&ch.info.server_root) {
                return Err(CoreError::NotServerHost);
            }
            (ch.info.channel_name.clone(), ch.info.server_name.clone())
        };
        // Offer only — the recipient must accept before anything is added. A
        // direct invite silently pulling someone into a group leaks that they
        // hold this identity to whoever knows their fingerprint.
        self.invites_sent.insert((*channel_id, *peer_id));
        let inv = ChannelControl::Invite {
            channel_id: *channel_id,
            channel_name,
            server_name,
        };
        self.send_content(peer_id, Content::Channel(inv.encode()), now_ms)
            .await
    }

    /// Accept a channel invite surfaced by [`Inbound::ChannelInvite`]. Sends the
    /// host our acceptance; the MLS Welcome then follows over the same DM.
    pub async fn accept_channel_invite(
        &mut self,
        channel_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let inviter = self
            .invites_received
            .get(channel_id)
            .map(|(idk, _, _)| *idk)
            .ok_or(CoreError::Channel("no pending invite for that channel"))?;
        let host_id = idk_to_id(&inviter);
        let acc = ChannelControl::InviteAccept {
            channel_id: *channel_id,
        };
        self.send_content(&host_id, Content::Channel(acc.encode()), now_ms)
            .await
        // Leave the pending entry until the Welcome lands so the UI keeps its
        // display info; the MlsWelcome handler clears it.
    }

    /// Decline a pending channel invite; tells the host so it drops its record.
    pub async fn decline_channel_invite(
        &mut self,
        channel_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let Some((inviter, _, _)) = self.invites_received.remove(channel_id) else {
            return Ok(());
        };
        self.dirty = true;
        let dec = ChannelControl::InviteDecline {
            channel_id: *channel_id,
        };
        let _ = self
            .send_content(&idk_to_id(&inviter), Content::Channel(dec.encode()), now_ms)
            .await;
        Ok(())
    }

    /// Channel invites we've received and not yet answered —
    /// `(channel_id, channel_name, server_name)`.
    pub fn pending_channel_invites(&self) -> Vec<([u8; 32], String, String)> {
        self.invites_received
            .iter()
            .map(|(cid, (_, cn, sn))| (*cid, cn.clone(), sn.clone()))
            .collect()
    }

    /// Host side of adding one member: fetch their KeyPackage, commit the MLS
    /// add to the channel log, and DM them the Welcome + policy.
    async fn mls_add_member(
        &mut self,
        channel_id: &[u8; 32],
        peer_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        // A server ban blocks every add path — direct invite, link redeem,
        // re-admit.
        {
            let root = self
                .channels
                .get(channel_id)
                .map(|c| c.info.server_root)
                .ok_or(CoreError::UnknownChannel)?;
            if self
                .hosted
                .get(&root)
                .is_some_and(|h| h.banned.contains(peer_id))
            {
                return Err(CoreError::Channel(
                    "that identity is banned from this server",
                ));
            }
        }
        let kp = sync::get_key_package(&mut self.client, peer_id)
            .await?
            .ok_or(CoreError::Channel(
                "that identity has no published MLS KeyPackage — they must connect first",
            ))?;

        let (commit, welcome, info, since_seq, server_root, log_key) = {
            let ch = self
                .channels
                .get_mut(channel_id)
                .ok_or(CoreError::UnknownChannel)?;
            let hs = ch.mls.add(&[mls::KeyPkg(kp)]).map_err(mls_err)?;
            let welcome = hs
                .welcome
                .ok_or_else(|| CoreError::Voice("MLS add produced no Welcome".into()))?;
            ch.resync_roster();
            (
                hs.commit,
                welcome,
                ch.info.clone(),
                ch.last_seq,
                ch.info.server_root,
                ch.log_key,
            )
        };

        let frame = self.wrap_channel_frame(channel_id, channel::FRAME_COMMIT, &commit);
        self.post_channel_frame(channel_id, &frame).await?;

        let wc = ChannelControl::MlsWelcome {
            info,
            welcome,
            since_seq,
            log_key: log_key.unwrap_or([0u8; 32]),
        };
        self.send_content(peer_id, Content::Channel(wc.encode()), now_ms)
            .await?;
        if let Some(policy) = self.server_policies.get(&server_root).cloned() {
            let pol = ChannelControl::Policy {
                policy: policy.encode(),
            };
            let _ = self
                .send_content(peer_id, Content::Channel(pol.encode()), now_ms)
                .await;
        }

        // Share a plaintext snapshot of recent messages — the joiner can't
        // decrypt the log from before their MLS epoch.
        let entries: Vec<([u8; 32], u64, String)> = self
            .channel_history
            .iter()
            .filter(|e| &e.channel_id == channel_id)
            .rev()
            .take(200)
            .map(|e| (e.sender, e.ts_ms, e.text.clone()))
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        if !entries.is_empty() {
            let hist = ChannelControl::History {
                channel_id: *channel_id,
                entries,
            };
            let _ = self
                .send_content(peer_id, Content::Channel(hist.encode()), now_ms)
                .await;
        }
        self.dirty = true;
        Ok(())
    }

    /// Mint a shareable invite link for a channel this client hosts. `ttl_ms`
    /// is how long the link stays valid; `max_uses` of `0` means unlimited.
    pub fn create_invite_link(
        &self,
        channel_id: &[u8; 32],
        ttl_ms: u64,
        max_uses: u32,
        now_ms: u64,
    ) -> Result<String, CoreError> {
        let ch = self
            .channels
            .get(channel_id)
            .ok_or(CoreError::UnknownChannel)?;
        let host = self
            .hosted
            .get(&ch.info.server_root)
            .ok_or(CoreError::NotServerHost)?;
        let token = crate::invite::InviteToken::mint(
            &host.root,
            self.my_member_id(),
            *channel_id,
            self.primary_relay(),
            now_ms.saturating_add(ttl_ms),
            max_uses,
            random_array::<8>(),
        );
        Ok(token.to_link())
    }

    /// Redeem an invite link: verify it locally, then DM the host a request to
    /// be added (with `password` if the server is password-gated). Joining
    /// completes when the host's `Invite` arrives on a later
    /// [`Engine::receive_all`].
    pub async fn redeem_invite(
        &mut self,
        link: &str,
        password: Option<&str>,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let token = crate::invite::InviteToken::from_link(link)?;
        token.verify()?;
        if token.is_expired(now_ms) {
            return Err(CoreError::Invite("expired"));
        }
        if self.channels.contains_key(&token.channel_id) {
            return Ok(()); // already a member
        }
        let host_id = token.host_id;
        let redeem = ChannelControl::Redeem {
            token: token.encode(),
            pw: password.unwrap_or("").to_owned(),
        };
        self.send_content(&host_id, Content::Channel(redeem.encode()), now_ms)
            .await
    }

    /// Set (or clear, with `None`) the join password for a server this client
    /// hosts. It gates invite-link redemption; direct invites bypass it.
    ///
    /// If a password is already set, `current` must carry it — an empty or wrong
    /// `current` is rejected. When no password is set yet, `current` is ignored.
    pub fn set_join_password(
        &mut self,
        server_root: &[u8; 32],
        password: Option<&str>,
        current: Option<&str>,
    ) -> Result<(), CoreError> {
        let h = self
            .hosted
            .get_mut(server_root)
            .ok_or(CoreError::NotServerHost)?;
        if let Some(existing) = h.join_pw_hash {
            let ok =
                current.is_some_and(|c| !c.is_empty() && join_pw_hash(server_root, c) == existing);
            if !ok {
                return Err(CoreError::Channel("current join password does not match"));
            }
        }
        h.join_pw_hash = password.map(|pw| join_pw_hash(server_root, pw));
        self.dirty = true;
        Ok(())
    }

    /// Whether a server we host requires a join password.
    pub fn has_join_password(&self, server_root: &[u8; 32]) -> bool {
        self.hosted
            .get(server_root)
            .is_some_and(|h| h.join_pw_hash.is_some())
    }

    /// List / unlist a server we host on the public discovery directory. When
    /// listing, an unlimited `dante-invite:` link for the server's first
    /// channel is minted and embedded so anyone can join. Re-submits a signed
    /// `ServerRegister` record to the ledger.
    pub async fn set_discoverable(
        &mut self,
        server_root: &[u8; 32],
        discoverable: bool,
        summary: &str,
        tags: Vec<String>,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let h = self
            .hosted
            .get(server_root)
            .ok_or(CoreError::NotServerHost)?;
        let name = h.name.clone();
        let first_channel = h.channels.first().copied();

        let invite = if discoverable {
            let ch = first_channel.ok_or(CoreError::Channel("create a channel first"))?;
            // ~10 years, unlimited uses.
            self.create_invite_link(&ch, 315_360_000_000, 0, now_ms)?
        } else {
            String::new()
        };

        let root_bytes = self.hosted[server_root].root.to_bytes();
        let root = SignSecret::from_bytes(&root_bytes);
        let reg = ServerRegister {
            server_root: *server_root,
            name: name.chars().take(64).collect(),
            summary: summary.chars().take(280).collect(),
            tags: tags
                .into_iter()
                .map(|t| t.chars().take(32).collect())
                .take(8)
                .collect(),
            entry_relays: self.relay_addrs.iter().take(8).cloned().collect(),
            discoverable,
            invite,
            // Replay the create-time proof — it's bound to `server_root` only.
            pow: self.hosted[server_root].register_pow,
        };
        let rec = reg.to_record(now_ms, |m| root.sign(m));
        sync::submit_record(&mut self.client, &rec).await?;
        self.dirty = true;
        Ok(())
    }

    /// Public servers currently on the discovery directory (call
    /// [`Engine::sync`] first to refresh the local replica).
    pub fn discoverable_servers(&self) -> Vec<ServerRegister> {
        self.ledger.discoverable_servers()
    }

    /// Join a server found via [`Engine::discoverable_servers`] by redeeming the
    /// invite link it published.
    pub async fn join_discovered(
        &mut self,
        server_root: &[u8; 32],
        password: Option<&str>,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let link = self
            .ledger
            .discoverable_servers()
            .into_iter()
            .find(|s| s.server_root == *server_root)
            .map(|s| s.invite)
            .filter(|i| !i.is_empty())
            .ok_or(CoreError::Channel("that server has no public join link"))?;
        self.redeem_invite(&link, password, now_ms).await
    }

    /// Eject a member from a channel this client hosts: commit an MLS remove to
    /// the channel log. Every remaining member applies the commit and the group
    /// rekeys (O(log n)); the removed member is evicted and can no longer read
    /// the channel. Re-admitting them later works (a fresh KeyPackage).
    pub async fn remove_from_channel(
        &mut self,
        channel_id: &[u8; 32],
        member_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        if *member_id == self.my_member_id() {
            return Err(CoreError::Channel("cannot remove yourself"));
        }
        let commit = {
            let ch = self
                .channels
                .get_mut(channel_id)
                .ok_or(CoreError::UnknownChannel)?;
            if !self.hosted.contains_key(&ch.info.server_root) {
                return Err(CoreError::NotServerHost);
            }
            let Some(leaf) = ch.leaf_of(member_id) else {
                return Ok(()); // not a member (already gone)
            };
            let hs = ch.mls.remove(&[leaf]).map_err(mls_err)?;
            ch.removed.insert(*member_id, now_ms);
            ch.resync_roster();
            hs.commit
        };
        self.dirty = true;

        let frame = self.wrap_channel_frame(channel_id, channel::FRAME_COMMIT, &commit);
        self.post_channel_frame(channel_id, &frame).await?;
        Ok(())
    }

    /// Remove `member` from every channel of a server we host, and (with
    /// `ban`) add them to the server's persistent ban list so they can't be
    /// re-invited or redeem a link. Host only. `#general` is included — there is
    /// no "in the server but no channels" state.
    pub async fn kick_from_server(
        &mut self,
        server_root: &[u8; 32],
        member: &[u8; 32],
        ban: bool,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let h = self
            .hosted
            .get(server_root)
            .ok_or(CoreError::NotServerHost)?;
        if *member == self.my_member_id() {
            return Err(CoreError::Channel("cannot remove yourself"));
        }
        let channels: Vec<[u8; 32]> = h.channels.clone();
        for cid in channels {
            // Only channels the member is actually in; `remove_from_channel` is
            // a no-op otherwise.
            if self
                .channels
                .get(&cid)
                .is_some_and(|c| c.roster.contains(member))
            {
                let _ = self.remove_from_channel(&cid, member, now_ms).await;
            }
        }
        if ban {
            if let Some(h) = self.hosted.get_mut(server_root) {
                h.banned.insert(*member);
            }
        }
        self.dirty = true;
        Ok(())
    }

    /// Lift a ban. Host only. Returns whether the identity was banned.
    pub fn unban_from_server(&mut self, server_root: &[u8; 32], member: &[u8; 32]) -> bool {
        let removed = self
            .hosted
            .get_mut(server_root)
            .is_some_and(|h| h.banned.remove(member));
        if removed {
            self.dirty = true;
        }
        removed
    }

    /// Identities banned from a server we host.
    pub fn server_bans(&self, server_root: &[u8; 32]) -> Vec<[u8; 32]> {
        self.hosted
            .get(server_root)
            .map(|h| h.banned.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Delete a channel this client hosts: DM every member a
    /// [`ChannelControl::Closed`] and drop it locally. The relay log expires on
    /// its own.
    pub async fn delete_channel(
        &mut self,
        channel_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let (server_root, members) = {
            let ch = self
                .channels
                .get(channel_id)
                .ok_or(CoreError::UnknownChannel)?;
            if !self.hosted.contains_key(&ch.info.server_root) {
                return Err(CoreError::NotServerHost);
            }
            if ch.info.channel_name.eq_ignore_ascii_case("general") {
                return Err(CoreError::Channel("#general cannot be deleted"));
            }
            let me = self.my_member_id();
            let members: Vec<[u8; 32]> = ch.roster.iter().copied().filter(|m| *m != me).collect();
            (ch.info.server_root, members)
        };

        let msg = Content::Channel(
            ChannelControl::Closed {
                channel_id: *channel_id,
            }
            .encode(),
        );
        for m in members {
            let _ = self.send_content(&m, msg.clone(), now_ms).await;
        }

        self.channels.remove(channel_id);
        if let Some(h) = self.hosted.get_mut(&server_root) {
            h.channels.retain(|c| c != channel_id);
        }
        self.dirty = true;
        Ok(())
    }

    /// Rename a channel in a server this client hosts. Updates the local name
    /// and DMs every member a [`ChannelControl::Renamed`] so their display
    /// name tracks it. `#general` (a server's first, always-there channel)
    /// can't be renamed.
    pub async fn rename_channel(
        &mut self,
        channel_id: &[u8; 32],
        name: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let name: String = name.trim().chars().take(64).collect();
        if name.is_empty() {
            return Err(CoreError::Channel("channel name cannot be empty"));
        }
        let members = {
            let ch = self
                .channels
                .get(channel_id)
                .ok_or(CoreError::UnknownChannel)?;
            if !self.hosted.contains_key(&ch.info.server_root) {
                return Err(CoreError::NotServerHost);
            }
            if ch.info.channel_name.eq_ignore_ascii_case("general") {
                return Err(CoreError::Channel("#general cannot be renamed"));
            }
            let me = self.my_member_id();
            ch.roster
                .iter()
                .copied()
                .filter(|m| *m != me)
                .collect::<Vec<_>>()
        };

        self.channels.get_mut(channel_id).unwrap().info.channel_name = name.clone();
        let msg = Content::Channel(
            ChannelControl::Renamed {
                channel_id: *channel_id,
                name,
            }
            .encode(),
        );
        for m in members {
            let _ = self.send_content(&m, msg.clone(), now_ms).await;
        }
        self.dirty = true;
        Ok(())
    }

    /// Tear down a server this client hosts: close every one of its channels
    /// and publish a `ServerDelist` record so it drops out of discovery.
    pub async fn delete_server(
        &mut self,
        server_root: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let root_secret = self
            .hosted
            .get(server_root)
            .ok_or(CoreError::NotServerHost)?
            .root
            .to_bytes();
        let channels: Vec<[u8; 32]> = self.hosted[server_root].channels.clone();
        for c in &channels {
            let _ = self.delete_channel(c, now_ms).await;
        }
        // `delete_channel` refuses #general; the whole server is going away, so
        // drop whatever it left behind (and tell members it closed).
        for c in &channels {
            if let Some(ch) = self.channels.remove(c) {
                let me = self.my_member_id();
                let msg = Content::Channel(ChannelControl::Closed { channel_id: *c }.encode());
                for m in ch.roster.iter().copied().filter(|m| *m != me) {
                    let _ = self.send_content(&m, msg.clone(), now_ms).await;
                }
            }
        }

        let root = SignSecret::from_bytes(&root_secret);
        let rec = ServerDelist {
            server_root: *server_root,
        }
        .to_record(now_ms, |m| root.sign(m));
        sync::submit_record(&mut self.client, &rec).await?;

        self.hosted.remove(server_root);
        self.server_policies.remove(server_root);
        self.dirty = true;
        Ok(())
    }

    /// Leave a channel this client joined. Tells the host with a
    /// [`ChannelControl::Leave`] (the host commits the MLS removal so post-leave
    /// messages stay private) and drops all local state for the channel. The
    /// host cannot "leave" its own server this way.
    pub async fn leave_channel(
        &mut self,
        channel_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let (server_root, host_id) = {
            let ch = self
                .channels
                .get(channel_id)
                .ok_or(CoreError::UnknownChannel)?;
            (ch.info.server_root, ch.info.host_id)
        };
        if self.hosted.contains_key(&server_root) {
            return Err(CoreError::Channel(
                "you host this server — delete the channel instead",
            ));
        }

        let msg = Content::Channel(
            ChannelControl::Leave {
                channel_id: *channel_id,
            }
            .encode(),
        );
        let _ = self.send_content(&host_id, msg, now_ms).await;

        self.channels.remove(channel_id);
        // Drop the server's policy if we no longer share any of its channels.
        let still_in = self
            .channels
            .values()
            .any(|c| c.info.server_root == server_root);
        if !still_in {
            self.server_policies.remove(&server_root);
        }
        self.dirty = true;
        Ok(())
    }

    /// Set (or clear, with `None`) the inactivity auto-kick window for a server
    /// this client hosts. When set, [`Engine::sweep_inactive_members`] removes
    /// channel members whose identity has had no ledger activity for `window_ms`.
    pub fn set_auto_kick(
        &mut self,
        server_root: &[u8; 32],
        window_ms: Option<u64>,
    ) -> Result<(), CoreError> {
        let h = self
            .hosted
            .get_mut(server_root)
            .ok_or(CoreError::NotServerHost)?;
        h.auto_kick_ms = window_ms;
        self.dirty = true;
        Ok(())
    }

    /// The configured auto-kick window for a hosted server, if any.
    pub fn auto_kick_window(&self, server_root: &[u8; 32]) -> Option<u64> {
        self.hosted.get(server_root).and_then(|h| h.auto_kick_ms)
    }

    /// For every hosted server with an auto-kick window, remove channel members
    /// whose identity has had no ledger activity within the window (or has
    /// evaporated / is unknown). Returns the ids removed. Call periodically;
    /// keep the local ledger replica fresh with [`Engine::sync`] first.
    pub async fn sweep_inactive_members(
        &mut self,
        now_ms: u64,
    ) -> Result<Vec<[u8; 32]>, CoreError> {
        let me = self.my_member_id();
        let mut victims: Vec<([u8; 32], [u8; 32])> = Vec::new();
        for (root, h) in &self.hosted {
            let Some(window) = h.auto_kick_ms else {
                continue;
            };
            for chan_id in &h.channels {
                let Some(ch) = self.channels.get(chan_id) else {
                    continue;
                };
                if ch.info.server_root != *root {
                    continue;
                }
                for m in &ch.roster {
                    if *m == me || ch.removed.contains_key(m) {
                        continue;
                    }
                    let inactive = match self.ledger.idk_for_id(m) {
                        None => true, // unknown / evaporated
                        Some(idk) => self
                            .ledger
                            .last_activity(&idk)
                            .is_none_or(|t| now_ms.saturating_sub(t) > window),
                    };
                    if inactive {
                        victims.push((*chan_id, *m));
                    }
                }
            }
        }
        let mut removed = Vec::with_capacity(victims.len());
        for (chan_id, member) in victims {
            if self
                .remove_from_channel(&chan_id, &member, now_ms)
                .await
                .is_ok()
            {
                removed.push(member);
            }
        }
        Ok(removed)
    }

    // ---- roles / permissions ---------------------------------------------

    /// The role configuration for a server we host or have joined.
    pub fn server_policy(&self, server_root: &[u8; 32]) -> Option<&ServerPolicy> {
        self.server_policies.get(server_root)
    }

    /// Effective permission mask for `member` on a server (0 if unknown).
    pub fn member_perms(&self, server_root: &[u8; 32], member: &[u8; 32]) -> u32 {
        self.server_policies
            .get(server_root)
            .map_or(roles::PERM_DEFAULT, |p| p.effective_perms(member))
    }

    /// Create (id `None`) or update a role on a server we host, then broadcast
    /// the new policy. Returns the role id.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_role(
        &mut self,
        server_root: &[u8; 32],
        id: Option<u16>,
        name: &str,
        allow: u32,
        deny: u32,
        rank: u16,
        now_ms: u64,
    ) -> Result<u16, CoreError> {
        let (mut roles_vec, assignments, emojis, stickers, sounds, owner, version, root) =
            self.policy_draft(server_root)?;
        let id = id.unwrap_or_else(|| roles_vec.iter().map(|r| r.id).max().unwrap_or(0) + 1);
        match roles_vec.iter_mut().find(|r| r.id == id) {
            Some(r) => {
                r.name = name.to_owned();
                r.allow = allow;
                r.deny = deny;
                r.rank = rank;
            }
            None => roles_vec.push(crate::roles::Role {
                id,
                name: name.to_owned(),
                allow,
                deny,
                rank,
            }),
        }
        self.commit_policy(
            *server_root,
            &root,
            owner,
            version,
            roles_vec,
            assignments,
            emojis,
            stickers,
            sounds,
            now_ms,
        )
        .await?;
        Ok(id)
    }

    /// Delete a role (and strip it from every assignment) on a hosted server.
    pub async fn delete_role(
        &mut self,
        server_root: &[u8; 32],
        role_id: u16,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let (mut roles_vec, mut assignments, emojis, stickers, sounds, owner, version, root) =
            self.policy_draft(server_root)?;
        roles_vec.retain(|r| r.id != role_id);
        for (_, ids) in &mut assignments {
            ids.retain(|i| *i != role_id);
        }
        assignments.retain(|(_, ids)| !ids.is_empty());
        self.commit_policy(
            *server_root,
            &root,
            owner,
            version,
            roles_vec,
            assignments,
            emojis,
            stickers,
            sounds,
            now_ms,
        )
        .await
    }

    /// Give (`add`) or take (`!add`) a role from a member on a hosted server.
    pub async fn assign_role(
        &mut self,
        server_root: &[u8; 32],
        member: &[u8; 32],
        role_id: u16,
        add: bool,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let (roles_vec, mut assignments, emojis, stickers, sounds, owner, version, root) =
            self.policy_draft(server_root)?;
        if add && !roles_vec.iter().any(|r| r.id == role_id) {
            return Err(CoreError::Channel("no such role"));
        }
        match assignments.iter_mut().find(|(m, _)| m == member) {
            Some((_, ids)) => {
                if add {
                    if !ids.contains(&role_id) {
                        ids.push(role_id);
                    }
                } else {
                    ids.retain(|i| *i != role_id);
                }
            }
            None if add => assignments.push((*member, vec![role_id])),
            None => {}
        }
        assignments.retain(|(_, ids)| !ids.is_empty());
        self.commit_policy(
            *server_root,
            &root,
            owner,
            version,
            roles_vec,
            assignments,
            emojis,
            stickers,
            sounds,
            now_ms,
        )
        .await
    }

    /// Add or replace a custom emoji on a hosted server. `image` is stored
    /// **unencrypted** on the relay blob store (keyed by its SHA-256); the
    /// shortcode -> hash mapping rides the signed `ServerPolicy`. `name` is the
    /// bare shortcode (no colons), ASCII `[a-z0-9_]`, <= `EMOJI_NAME_MAX`.
    pub async fn set_server_emoji(
        &mut self,
        server_root: &[u8; 32],
        name: &str,
        image: &[u8],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        if !roles::valid_emoji_name(name) {
            return Err(CoreError::Channel("bad emoji name"));
        }
        if image.is_empty() || image.len() > 1024 * 1024 {
            return Err(CoreError::Channel("emoji image must be 1..=1024 KiB"));
        }
        let is_png = image.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
        let is_jpeg = image.starts_with(&[0xff, 0xd8, 0xff]);
        if !is_png && !is_jpeg {
            return Err(CoreError::Channel("emoji image must be a PNG or JPEG"));
        }
        let (roles_vec, assignments, mut emojis, stickers, sounds, owner, version, root) =
            self.policy_draft(server_root)?;
        // Keep the emoji / sticker / sound shortcodes one namespace (the other
        // two setters already reject cross-collisions).
        if stickers.iter().any(|(n, _)| n == name) {
            return Err(CoreError::Channel("a sticker already uses that name"));
        }
        if sounds.iter().any(|(n, _)| n == name) {
            return Err(CoreError::Channel(
                "a soundboard clip already uses that name",
            ));
        }
        if !emojis.iter().any(|(n, _)| n == name) && emojis.len() >= roles::MAX_SERVER_EMOJIS {
            return Err(CoreError::Channel("server emoji limit reached"));
        }
        sync::put_blob(&mut self.client, image).await?;
        let hash = sha256(image);
        match emojis.iter_mut().find(|(n, _)| n == name) {
            Some(e) => e.1 = hash,
            None => emojis.push((name.to_owned(), hash)),
        }
        self.commit_policy(
            *server_root,
            &root,
            owner,
            version,
            roles_vec,
            assignments,
            emojis,
            stickers,
            sounds,
            now_ms,
        )
        .await
    }

    /// Drop a custom emoji from a hosted server (the blob is left to expire).
    pub async fn remove_server_emoji(
        &mut self,
        server_root: &[u8; 32],
        name: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let (roles_vec, assignments, mut emojis, stickers, sounds, owner, version, root) =
            self.policy_draft(server_root)?;
        let before = emojis.len();
        emojis.retain(|(n, _)| n != name);
        if emojis.len() == before {
            return Err(CoreError::Channel("no such emoji"));
        }
        self.commit_policy(
            *server_root,
            &root,
            owner,
            version,
            roles_vec,
            assignments,
            emojis,
            stickers,
            sounds,
            now_ms,
        )
        .await
    }

    /// The custom emoji known for a server (hosted or joined), `(shortcode, hash)`.
    pub fn server_emojis(&self, server_root: &[u8; 32]) -> Vec<(String, [u8; 32])> {
        self.server_policies
            .get(server_root)
            .map(|p| p.emojis.clone())
            .unwrap_or_default()
    }

    /// Add or replace a sticker on a hosted server. Like [`Engine::set_server_emoji`]
    /// but the image budget is larger (a sticker fills more of the message) and
    /// GIF / WebP are allowed for animation. `name` shares the emoji-shortcode
    /// charset and may not collide with an existing emoji on the same server.
    pub async fn set_server_sticker(
        &mut self,
        server_root: &[u8; 32],
        name: &str,
        image: &[u8],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        if !roles::valid_emoji_name(name) {
            return Err(CoreError::Channel("bad sticker name"));
        }
        if image.is_empty() || image.len() > 512 * 1024 {
            return Err(CoreError::Channel("sticker image must be 1..=512 KiB"));
        }
        let is_png = image.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
        let is_jpeg = image.starts_with(&[0xff, 0xd8, 0xff]);
        let is_gif = image.starts_with(b"GIF87a") || image.starts_with(b"GIF89a");
        let is_webp = image.len() > 12 && &image[0..4] == b"RIFF" && &image[8..12] == b"WEBP";
        if !is_png && !is_jpeg && !is_gif && !is_webp {
            return Err(CoreError::Channel(
                "sticker image must be PNG, JPEG, GIF or WebP",
            ));
        }
        let (roles_vec, assignments, emojis, mut stickers, sounds, owner, version, root) =
            self.policy_draft(server_root)?;
        if emojis.iter().any(|(n, _)| n == name) {
            return Err(CoreError::Channel("a custom emoji already uses that name"));
        }
        if !stickers.iter().any(|(n, _)| n == name) && stickers.len() >= roles::MAX_SERVER_STICKERS
        {
            return Err(CoreError::Channel("server sticker limit reached"));
        }
        sync::put_blob(&mut self.client, image).await?;
        let hash = sha256(image);
        match stickers.iter_mut().find(|(n, _)| n == name) {
            Some(s) => s.1 = hash,
            None => stickers.push((name.to_owned(), hash)),
        }
        self.commit_policy(
            *server_root,
            &root,
            owner,
            version,
            roles_vec,
            assignments,
            emojis,
            stickers,
            sounds,
            now_ms,
        )
        .await
    }

    /// Drop a sticker from a hosted server (the blob is left to expire).
    pub async fn remove_server_sticker(
        &mut self,
        server_root: &[u8; 32],
        name: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let (roles_vec, assignments, emojis, mut stickers, sounds, owner, version, root) =
            self.policy_draft(server_root)?;
        let before = stickers.len();
        stickers.retain(|(n, _)| n != name);
        if stickers.len() == before {
            return Err(CoreError::Channel("no such sticker"));
        }
        self.commit_policy(
            *server_root,
            &root,
            owner,
            version,
            roles_vec,
            assignments,
            emojis,
            stickers,
            sounds,
            now_ms,
        )
        .await
    }

    /// The stickers known for a server (hosted or joined), `(name, hash)`.
    pub fn server_stickers(&self, server_root: &[u8; 32]) -> Vec<(String, [u8; 32])> {
        self.server_policies
            .get(server_root)
            .map(|p| p.stickers.clone())
            .unwrap_or_default()
    }

    /// Add or replace a soundboard clip on a hosted server. Like a sticker but
    /// the blob is a short audio clip (OGG / MP3 / WAV, <= 256 KiB) that a
    /// member plays into a voice channel. `name` shares the emoji-shortcode
    /// charset and may not collide with an emoji or sticker on the same server.
    pub async fn set_server_sound(
        &mut self,
        server_root: &[u8; 32],
        name: &str,
        audio: &[u8],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        if !roles::valid_emoji_name(name) {
            return Err(CoreError::Channel("bad sound name"));
        }
        if audio.is_empty() || audio.len() > 256 * 1024 {
            return Err(CoreError::Channel("sound clip must be 1..=256 KiB"));
        }
        let is_ogg = audio.starts_with(b"OggS");
        let is_wav = audio.len() > 12 && &audio[0..4] == b"RIFF" && &audio[8..12] == b"WAVE";
        let is_mp3 = audio.starts_with(b"ID3")
            || audio.starts_with(&[0xff, 0xfb])
            || audio.starts_with(&[0xff, 0xf3])
            || audio.starts_with(&[0xff, 0xf2]);
        if !is_ogg && !is_wav && !is_mp3 {
            return Err(CoreError::Channel("sound clip must be OGG, MP3 or WAV"));
        }
        let (roles_vec, assignments, emojis, stickers, mut sounds, owner, version, root) =
            self.policy_draft(server_root)?;
        if emojis.iter().any(|(n, _)| n == name) || stickers.iter().any(|(n, _)| n == name) {
            return Err(CoreError::Channel(
                "an emoji or sticker already uses that name",
            ));
        }
        if !sounds.iter().any(|(n, _)| n == name) && sounds.len() >= roles::MAX_SERVER_SOUNDS {
            return Err(CoreError::Channel("server soundboard limit reached"));
        }
        sync::put_blob(&mut self.client, audio).await?;
        let hash = sha256(audio);
        match sounds.iter_mut().find(|(n, _)| n == name) {
            Some(s) => s.1 = hash,
            None => sounds.push((name.to_owned(), hash)),
        }
        self.commit_policy(
            *server_root,
            &root,
            owner,
            version,
            roles_vec,
            assignments,
            emojis,
            stickers,
            sounds,
            now_ms,
        )
        .await
    }

    /// Drop a soundboard clip from a hosted server (the blob is left to expire).
    pub async fn remove_server_sound(
        &mut self,
        server_root: &[u8; 32],
        name: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let (roles_vec, assignments, emojis, stickers, mut sounds, owner, version, root) =
            self.policy_draft(server_root)?;
        let before = sounds.len();
        sounds.retain(|(n, _)| n != name);
        if sounds.len() == before {
            return Err(CoreError::Channel("no such sound"));
        }
        self.commit_policy(
            *server_root,
            &root,
            owner,
            version,
            roles_vec,
            assignments,
            emojis,
            stickers,
            sounds,
            now_ms,
        )
        .await
    }

    /// The soundboard clips known for a server (hosted or joined), `(name, hash)`.
    pub fn server_sounds(&self, server_root: &[u8; 32]) -> Vec<(String, [u8; 32])> {
        self.server_policies
            .get(server_root)
            .map(|p| p.sounds.clone())
            .unwrap_or_default()
    }

    /// Fetch a blob (custom-emoji image, …) from the relay by its SHA-256.
    pub async fn fetch_blob(&mut self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, CoreError> {
        Ok(sync::get_blob(&mut self.client, hash).await?)
    }

    /// Remove `member` from the server that `channel_id` belongs to (and,
    /// with `ban`, block their return). If we host it, act directly; otherwise
    /// — with `PERM_KICK` — DM the host a `KickRequest`. Staff (a member with
    /// `PERM_KICK`/`PERM_MANAGE_ROLES`) and the owner can only be removed by
    /// the owner.
    pub async fn request_kick(
        &mut self,
        channel_id: &[u8; 32],
        member: &[u8; 32],
        ban: bool,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let server_root = self
            .channels
            .get(channel_id)
            .ok_or(CoreError::UnknownChannel)?
            .info
            .server_root;
        let me = self.my_member_id();
        let owner = self
            .server_policies
            .get(&server_root)
            .map(|p| p.owner_id)
            .ok_or(CoreError::Channel(
                "no server policy — cannot reach the host",
            ))?;
        if *member == owner {
            return Err(CoreError::Channel("cannot remove the server owner"));
        }
        let target_is_staff = self.member_perms(&server_root, member)
            & (roles::PERM_KICK | roles::PERM_MANAGE_ROLES)
            != 0;
        if target_is_staff && me != owner {
            return Err(CoreError::Channel("only the owner can remove staff"));
        }
        if self.hosted.contains_key(&server_root) {
            return self
                .kick_from_server(&server_root, member, ban, now_ms)
                .await;
        }
        // A ban needs PERM_BAN; a plain kick needs PERM_KICK (mirrors the host's
        // check on the receiving end).
        let required = if ban {
            roles::PERM_BAN
        } else {
            roles::PERM_KICK
        };
        if self.member_perms(&server_root, &me) & required == 0 {
            return Err(CoreError::Channel(if ban {
                "you lack the ban permission"
            } else {
                "you lack the kick permission"
            }));
        }
        let req = ChannelControl::KickRequest {
            channel_id: *channel_id,
            member: *member,
            ban,
        };
        self.send_content(&owner, Content::Channel(req.encode()), now_ms)
            .await
    }

    /// Pull the mutable parts of a hosted server's policy plus a fresh copy of
    /// its signing key.
    #[allow(clippy::type_complexity)]
    fn policy_draft(
        &self,
        server_root: &[u8; 32],
    ) -> Result<
        (
            Vec<crate::roles::Role>,
            Vec<([u8; 32], Vec<u16>)>,
            Vec<(String, [u8; 32])>,
            Vec<(String, [u8; 32])>,
            Vec<(String, [u8; 32])>,
            [u8; 32],
            u64,
            SignSecret,
        ),
        CoreError,
    > {
        let root_bytes = self
            .hosted
            .get(server_root)
            .ok_or(CoreError::NotServerHost)?
            .root
            .to_bytes();
        let p = self
            .server_policies
            .get(server_root)
            .ok_or(CoreError::NotServerHost)?;
        Ok((
            p.roles.clone(),
            p.assignments.clone(),
            p.emojis.clone(),
            p.stickers.clone(),
            p.sounds.clone(),
            p.owner_id,
            p.version,
            SignSecret::from_bytes(&root_bytes),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn commit_policy(
        &mut self,
        server_root: [u8; 32],
        root: &SignSecret,
        owner: [u8; 32],
        prev_version: u64,
        roles_vec: Vec<crate::roles::Role>,
        assignments: Vec<([u8; 32], Vec<u16>)>,
        emojis: Vec<(String, [u8; 32])>,
        stickers: Vec<(String, [u8; 32])>,
        sounds: Vec<(String, [u8; 32])>,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let np = ServerPolicy::signed(
            root,
            owner,
            prev_version + 1,
            roles_vec,
            assignments,
            emojis,
            stickers,
            sounds,
            now_ms,
        );
        self.server_policies.insert(server_root, np);
        self.dirty = true;
        self.broadcast_policy(&server_root, now_ms).await
    }

    /// DM the current policy to every member of every channel of `server_root`.
    async fn broadcast_policy(
        &mut self,
        server_root: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let Some(policy) = self.server_policies.get(server_root).cloned() else {
            return Ok(());
        };
        let blob = ChannelControl::Policy {
            policy: policy.encode(),
        }
        .encode();
        let me = self.my_member_id();
        let mut targets: HashSet<[u8; 32]> = HashSet::new();
        for ch in self.channels.values() {
            if ch.info.server_root == *server_root {
                targets.extend(ch.roster.iter().copied().filter(|m| *m != me));
            }
        }
        for t in targets {
            let _ = self
                .send_content(&t, Content::Channel(blob.clone()), now_ms)
                .await;
        }
        Ok(())
    }

    /// Send a text message to a channel. Returns the relay-log `seq` it was
    /// assigned (the handle for a later [`edit_channel_message`] /
    /// [`delete_channel_message`]).
    pub async fn send_channel(
        &mut self,
        channel_id: &[u8; 32],
        text: &str,
        now_ms: u64,
    ) -> Result<u64, CoreError> {
        self.send_channel_content(channel_id, Content::Text(text.to_owned()), text, now_ms)
            .await
    }

    /// Send a text message to a channel as a reply to the message at
    /// `target_seq`. Returns the new message's relay-log `seq`.
    pub async fn send_channel_reply(
        &mut self,
        channel_id: &[u8; 32],
        target_seq: u64,
        text: &str,
        now_ms: u64,
    ) -> Result<u64, CoreError> {
        self.send_channel_content(
            channel_id,
            Content::Reply {
                target_seq,
                text: text.to_owned(),
            },
            text,
            now_ms,
        )
        .await
    }

    /// Forward a message into a channel. `origin` is a display label of the
    /// original author (fingerprint or petname). The result is an ordinary
    /// channel message — editable, deletable, pinnable — tagged as forwarded.
    /// Returns the new message's relay-log `seq`.
    pub async fn forward_to_channel(
        &mut self,
        channel_id: &[u8; 32],
        origin: &str,
        text: &str,
        now_ms: u64,
    ) -> Result<u64, CoreError> {
        self.send_channel_content(
            channel_id,
            Content::Forward {
                origin: origin.to_owned(),
                text: text.to_owned(),
            },
            text,
            now_ms,
        )
        .await
    }

    async fn send_channel_content(
        &mut self,
        channel_id: &[u8; 32],
        content: Content,
        history_text: &str,
        now_ms: u64,
    ) -> Result<u64, CoreError> {
        let ct = {
            let ch = self
                .channels
                .get_mut(channel_id)
                .ok_or(CoreError::UnknownChannel)?;
            ch.mls
                .encrypt(&pad_channel(&content.encode()))
                .map_err(mls_err)?
        };
        let frame = self.wrap_channel_frame(channel_id, channel::FRAME_APP, &ct);
        let seq = self.post_channel_frame(channel_id, &frame).await?;
        let me = self.my_member_id();
        // Record our authorship so we can edit / delete this message later
        // (we never see our own message come back through `poll_channels`).
        if seq != 0 {
            self.channel_edits
                .entry(*channel_id)
                .or_default()
                .entry(seq)
                .or_insert(MsgEdit {
                    author: me,
                    text: None,
                    deleted: false,
                });
        }
        self.push_channel_history(ChannelHistoryEntry {
            channel_id: *channel_id,
            sender: me,
            outgoing: true,
            ts_ms: now_ms,
            text: history_text.to_owned(),
        });
        self.dirty = true;
        Ok(seq)
    }

    /// Replace the text of one of our earlier channel messages. `target_seq` is
    /// the value [`send_channel`] returned. Only the original author's edit is
    /// honoured by other members.
    pub async fn edit_channel_message(
        &mut self,
        channel_id: &[u8; 32],
        target_seq: u64,
        new_text: &str,
        _now_ms: u64,
    ) -> Result<(), CoreError> {
        self.post_channel_edit(channel_id, target_seq, Some(new_text.to_owned()))
            .await
    }

    /// Withdraw one of our earlier channel messages.
    pub async fn delete_channel_message(
        &mut self,
        channel_id: &[u8; 32],
        target_seq: u64,
        _now_ms: u64,
    ) -> Result<(), CoreError> {
        self.post_channel_edit(channel_id, target_seq, None).await
    }

    async fn post_channel_edit(
        &mut self,
        channel_id: &[u8; 32],
        target_seq: u64,
        new_text: Option<String>,
    ) -> Result<(), CoreError> {
        let me = self.my_member_id();
        match self
            .channel_edits
            .get(channel_id)
            .and_then(|m| m.get(&target_seq))
        {
            Some(e) if e.author != me => {
                return Err(CoreError::Channel("you can only edit your own messages"))
            }
            Some(e) if e.deleted => return Err(CoreError::Channel("that message was deleted")),
            Some(_) => {}
            None => {
                return Err(CoreError::Channel(
                    "unknown message (or sent before restart)",
                ))
            }
        }

        let content = match &new_text {
            Some(t) => Content::Edit {
                target_seq,
                text: t.clone(),
            },
            None => Content::Delete { target_seq },
        };
        let ct = {
            let ch = self
                .channels
                .get_mut(channel_id)
                .ok_or(CoreError::UnknownChannel)?;
            ch.mls
                .encrypt(&pad_channel(&content.encode()))
                .map_err(mls_err)?
        };
        let frame = self.wrap_channel_frame(channel_id, channel::FRAME_APP, &ct);
        self.post_channel_frame(channel_id, &frame).await?;
        self.apply_channel_edit(*channel_id, target_seq, me, new_text);
        Ok(())
    }

    /// Apply an edit / delete to the standing state and queue the UI delta.
    /// `new_text: None` = delete. No-op unless `by` authored the message.
    fn apply_channel_edit(
        &mut self,
        channel_id: [u8; 32],
        target_seq: u64,
        by: [u8; 32],
        new_text: Option<String>,
    ) {
        let Some(entry) = self
            .channel_edits
            .get_mut(&channel_id)
            .and_then(|m| m.get_mut(&target_seq))
        else {
            return;
        };
        if entry.author != by || entry.deleted {
            return;
        }
        match new_text {
            Some(t) => {
                entry.text = Some(t.clone());
                self.new_edits.push(ChannelEdit {
                    channel_id,
                    target_seq,
                    text: Some(t),
                    deleted: false,
                });
            }
            None => {
                entry.text = None;
                entry.deleted = true;
                self.new_edits.push(ChannelEdit {
                    channel_id,
                    target_seq,
                    text: None,
                    deleted: true,
                });
            }
        }
        self.dirty = true;
    }

    /// Drain the edits/deletes seen since the last call (own and inbound).
    pub fn take_edits(&mut self) -> Vec<ChannelEdit> {
        std::mem::take(&mut self.new_edits)
    }

    /// The current edit/delete state, one [`ChannelEdit`] per changed message.
    /// Used to re-seed a fresh view on startup.
    pub fn edit_snapshot(&self) -> Vec<ChannelEdit> {
        let mut out = Vec::new();
        for (cid, by_seq) in &self.channel_edits {
            for (seq, e) in by_seq {
                if e.deleted {
                    out.push(ChannelEdit {
                        channel_id: *cid,
                        target_seq: *seq,
                        text: None,
                        deleted: true,
                    });
                } else if let Some(t) = &e.text {
                    out.push(ChannelEdit {
                        channel_id: *cid,
                        target_seq: *seq,
                        text: Some(t.clone()),
                        deleted: false,
                    });
                }
            }
        }
        out
    }

    /// Pin one of a channel's messages. Allowed for the channel host or the
    /// message's original author. `target_seq` is a value [`send_channel`]
    /// returned or a `seq` seen on an inbound [`ChannelMessage`].
    pub async fn pin_channel_message(
        &mut self,
        channel_id: &[u8; 32],
        target_seq: u64,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        self.post_channel_pin(channel_id, target_seq, false, now_ms)
            .await
    }

    /// Remove a pin. Same permissions as [`pin_channel_message`].
    pub async fn unpin_channel_message(
        &mut self,
        channel_id: &[u8; 32],
        target_seq: u64,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        self.post_channel_pin(channel_id, target_seq, true, now_ms)
            .await
    }

    async fn post_channel_pin(
        &mut self,
        channel_id: &[u8; 32],
        target_seq: u64,
        unpin: bool,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let me = self.my_member_id();
        if !self.may_pin(channel_id, target_seq, &me) {
            return Err(CoreError::Channel(
                "only the channel host or the message author can pin",
            ));
        }
        if unpin == !self.is_pinned(channel_id, target_seq) {
            // Nothing to do (already in the requested state); still cheap to
            // broadcast, but skip the redundant log entry.
            return Ok(());
        }
        let ct = {
            let ch = self
                .channels
                .get_mut(channel_id)
                .ok_or(CoreError::UnknownChannel)?;
            ch.mls
                .encrypt(&pad_channel(&Content::Pin { target_seq, unpin }.encode()))
                .map_err(mls_err)?
        };
        let frame = self.wrap_channel_frame(channel_id, channel::FRAME_APP, &ct);
        self.post_channel_frame(channel_id, &frame).await?;
        self.apply_channel_pin(*channel_id, target_seq, me, unpin, now_ms);
        Ok(())
    }

    /// Whether `who` may pin/unpin `target_seq` in `channel_id`.
    fn may_pin(&self, channel_id: &[u8; 32], target_seq: u64, who: &[u8; 32]) -> bool {
        let is_host = self
            .channels
            .get(channel_id)
            .is_some_and(|c| c.info.host_id == *who);
        let is_author = self
            .channel_edits
            .get(channel_id)
            .and_then(|m| m.get(&target_seq))
            .is_some_and(|e| e.author == *who);
        is_host || is_author
    }

    fn is_pinned(&self, channel_id: &[u8; 32], target_seq: u64) -> bool {
        self.channel_pins
            .get(channel_id)
            .is_some_and(|m| m.contains_key(&target_seq))
    }

    /// Fold one pin / unpin into the standing map and queue the UI delta.
    /// No-op unless `by` is the host or the message author.
    fn apply_channel_pin(
        &mut self,
        channel_id: [u8; 32],
        target_seq: u64,
        by: [u8; 32],
        unpin: bool,
        at_ms: u64,
    ) {
        if !self.may_pin(&channel_id, target_seq, &by) {
            return;
        }
        let by_seq = self.channel_pins.entry(channel_id).or_default();
        if unpin {
            if by_seq.remove(&target_seq).is_none() {
                return;
            }
            if by_seq.is_empty() {
                self.channel_pins.remove(&channel_id);
            }
        } else {
            by_seq.insert(target_seq, PinInfo { by, at_ms });
        }
        self.new_pins.push(ChannelPin {
            channel_id,
            target_seq,
            by,
            at_ms,
            pinned: !unpin,
        });
        self.dirty = true;
    }

    /// Drain the pins/unpins seen since the last call (own and inbound).
    pub fn take_pins(&mut self) -> Vec<ChannelPin> {
        std::mem::take(&mut self.new_pins)
    }

    /// Every currently pinned message, as a `pinned: true` [`ChannelPin`] each.
    /// Used to seed a fresh view on startup.
    pub fn pin_snapshot(&self) -> Vec<ChannelPin> {
        let mut out = Vec::new();
        for (cid, by_seq) in &self.channel_pins {
            for (seq, p) in by_seq {
                out.push(ChannelPin {
                    channel_id: *cid,
                    target_seq: *seq,
                    by: p.by,
                    at_ms: p.at_ms,
                    pinned: true,
                });
            }
        }
        out
    }

    /// The pinned messages of one channel, oldest `seq` first.
    pub fn pinned_messages(&self, channel_id: &[u8; 32]) -> Vec<ChannelPin> {
        let mut out: Vec<ChannelPin> = self
            .channel_pins
            .get(channel_id)
            .into_iter()
            .flat_map(|m| {
                m.iter().map(|(seq, p)| ChannelPin {
                    channel_id: *channel_id,
                    target_seq: *seq,
                    by: p.by,
                    at_ms: p.at_ms,
                    pinned: true,
                })
            })
            .collect();
        out.sort_by_key(|p| p.target_seq);
        out
    }

    fn push_channel_history(&mut self, e: ChannelHistoryEntry) {
        self.channel_history.push(e);
        if self.channel_history.len() > CHANNEL_HISTORY_CAP {
            let overflow = self.channel_history.len() - CHANNEL_HISTORY_CAP;
            self.channel_history.drain(..overflow);
        }
    }

    /// Poll every channel's relay log: apply MLS Commits from the host, and
    /// return newly decrypted messages (excluding our own).
    pub async fn poll_channels(&mut self, now_ms: u64) -> Result<Vec<ChannelMessage>, CoreError> {
        let me = self.my_member_id();
        let ids: Vec<[u8; 32]> = self.channels.keys().copied().collect();
        let mut out = Vec::new();
        let mut new_history = Vec::new();
        let mut new_reacts: Vec<PendingReaction> = Vec::new();
        #[allow(clippy::type_complexity)]
        let mut pending_edits: Vec<([u8; 32], u64, [u8; 32], Option<String>)> = Vec::new();
        let mut pending_pins: Vec<([u8; 32], u64, [u8; 32], bool)> = Vec::new();
        let mut evicted: Vec<([u8; 32], [u8; 32], String)> = Vec::new();
        for id in ids {
            let since = self.channels[&id].last_seq;
            let relay = sync::fetch_channel(&mut self.client, &id, since).await?;

            // `(seq, frame, from_relay)`. Merge in gossip frames — but ONLY the
            // immediately-next seq, and a gossip frame never advances
            // `last_seq`. Otherwise a channel member could gossip a junk frame
            // at `since+1` and make us skip the real one the relay has.
            let mut entries: Vec<(u64, Vec<u8>, bool)> =
                relay.into_iter().map(|(s, b)| (s, b, true)).collect();
            #[cfg(feature = "p2p")]
            if let Some(buf) = self.channel_gossip.remove(&id) {
                for (seq, frame) in buf {
                    if seq == since + 1 {
                        entries.push((seq, frame, false));
                    }
                }
            }
            // Relay frames sort first for equal seq, so `dedup_by_key` keeps
            // the authoritative copy and drops any gossip duplicate.
            entries.sort_by(|a, b| a.0.cmp(&b.0).then(b.2.cmp(&a.2)));
            entries.dedup_by_key(|(s, _, _)| *s);

            for (seq, blob, from_relay) in entries {
                let Some(ch) = self.channels.get_mut(&id) else {
                    continue;
                };
                if !from_relay && seq <= ch.last_seq {
                    continue; // already consumed
                }
                if from_relay {
                    ch.last_seq = ch.last_seq.max(seq);
                }
                // Strip the outer password wrapper first, if this channel has one.
                let inner: std::borrow::Cow<'_, [u8]> = match ch.log_key {
                    Some(k) => match channel::unwrap(&k, &id, &blob) {
                        Some(v) => std::borrow::Cow::Owned(v),
                        None => continue, // wrong key / corrupt — skip
                    },
                    None => std::borrow::Cow::Borrowed(&blob[..]),
                };
                let Some((tag, payload)) = channel::unframe(&inner) else {
                    continue;
                };
                let host_id = ch.info.host_id;
                let processed = ch.mls.process_from(payload, Some(&host_id));
                let _ = tag; // both tags route through process_from
                match processed {
                    Ok(mls::Processed::EpochChanged) => {
                        ch.resync_roster();
                        if !ch.roster.contains(&me) {
                            evicted.push((id, ch.info.server_root, ch.info.server_name.clone()));
                        }
                        self.dirty = true;
                    }
                    Ok(mls::Processed::Application { sender, plaintext }) => {
                        let Ok(sender) = <[u8; 32]>::try_from(sender) else {
                            continue;
                        };
                        if ch.removed.contains_key(&sender) || self.blocked.contains(&sender) {
                            continue;
                        }
                        // Roles: drop messages from a member without PERM_SEND.
                        if self
                            .server_policies
                            .get(&ch.info.server_root)
                            .is_some_and(|p| p.effective_perms(&sender) & roles::PERM_SEND == 0)
                        {
                            continue;
                        }
                        match unpad_channel(&plaintext).map(Content::decode) {
                            Some(Ok(
                                c @ (Content::Text(_)
                                | Content::Reply { .. }
                                | Content::Forward { .. }),
                            )) => {
                                let (text, reply_to, forwarded_from) = match c {
                                    Content::Text(t) => (t, None, None),
                                    Content::Reply { target_seq, text } => {
                                        (text, Some(target_seq), None)
                                    }
                                    Content::Forward { origin, text } => (text, None, Some(origin)),
                                    _ => unreachable!(),
                                };
                                self.channel_edits
                                    .entry(id)
                                    .or_default()
                                    .entry(seq)
                                    .or_insert(MsgEdit {
                                        author: sender,
                                        text: None,
                                        deleted: false,
                                    });
                                // If we already surfaced this seq from a gossip
                                // frame, the authoritative relay copy just
                                // confirms it — don't emit it twice.
                                #[cfg(feature = "p2p")]
                                let already_shown =
                                    from_relay && self.gossip_shown.remove(&(id, seq));
                                #[cfg(not(feature = "p2p"))]
                                let already_shown = false;
                                #[cfg(feature = "p2p")]
                                if !from_relay {
                                    self.gossip_shown.insert((id, seq));
                                    if self.gossip_shown.len() > 4096 {
                                        self.gossip_shown.clear();
                                    }
                                }
                                if !already_shown {
                                    new_history.push(ChannelHistoryEntry {
                                        channel_id: id,
                                        sender,
                                        outgoing: false,
                                        ts_ms: now_ms,
                                        text: text.clone(),
                                    });
                                    out.push(ChannelMessage {
                                        channel_id: id,
                                        channel_name: ch.info.channel_name.clone(),
                                        sender,
                                        text,
                                        seq,
                                        reply_to,
                                        forwarded_from,
                                    });
                                }
                            }
                            Some(Ok(Content::Reaction {
                                target_seq,
                                emoji,
                                remove,
                            })) => {
                                new_reacts.push((id, target_seq, emoji, sender, remove));
                            }
                            Some(Ok(Content::Edit { target_seq, text })) => {
                                pending_edits.push((id, target_seq, sender, Some(text)));
                            }
                            Some(Ok(Content::Delete { target_seq })) => {
                                pending_edits.push((id, target_seq, sender, None));
                            }
                            Some(Ok(Content::Pin { target_seq, unpin })) => {
                                pending_pins.push((id, target_seq, sender, unpin));
                            }
                            _ => {}
                        }
                    }
                    Ok(mls::Processed::Ignored) => {}
                    Err(e) => tracing::debug!(error = %e, "undecryptable channel log entry"),
                }
            }
        }
        for (cid, root, name) in evicted {
            self.channels.remove(&cid);
            self.evicted_channels.push((cid, root, name));
        }
        for (cid, seq, emoji, member, removed) in new_reacts {
            self.record_reaction(cid, seq, emoji, member, removed);
        }
        for (cid, tseq, by, new_text) in pending_edits {
            self.apply_channel_edit(cid, tseq, by, new_text);
        }
        for (cid, tseq, by, unpin) in pending_pins {
            self.apply_channel_pin(cid, tseq, by, unpin, now_ms);
        }
        if !out.is_empty() {
            for e in new_history {
                self.push_channel_history(e);
            }
            self.dirty = true;
        }
        Ok(out)
    }

    /// React to a channel message (or remove your reaction). The reaction rides
    /// the channel's log like a normal message.
    pub async fn send_react(
        &mut self,
        channel_id: &[u8; 32],
        target_seq: u64,
        emoji: &str,
        remove: bool,
        _now_ms: u64,
    ) -> Result<(), CoreError> {
        let ct = {
            let ch = self
                .channels
                .get_mut(channel_id)
                .ok_or(CoreError::UnknownChannel)?;
            ch.mls
                .encrypt(&pad_channel(
                    &Content::Reaction {
                        target_seq,
                        emoji: emoji.to_owned(),
                        remove,
                    }
                    .encode(),
                ))
                .map_err(mls_err)?
        };
        let frame = self.wrap_channel_frame(channel_id, channel::FRAME_APP, &ct);
        self.post_channel_frame(channel_id, &frame).await?;
        let me = self.my_member_id();
        self.record_reaction(*channel_id, target_seq, emoji.to_owned(), me, remove);
        Ok(())
    }

    /// Drain the reactions seen since the last call (own and inbound).
    pub fn take_reactions(&mut self) -> Vec<crate::channel::ChannelReaction> {
        std::mem::take(&mut self.new_reactions)
    }

    /// The full standing reaction state, one [`ChannelReaction`] per
    /// `(channel, message, emoji, member)` currently held (all `removed:
    /// false`). Used to seed a fresh view on startup.
    pub fn reaction_snapshot(&self) -> Vec<crate::channel::ChannelReaction> {
        let mut out = Vec::new();
        for (cid, by_seq) in &self.channel_reactions {
            for (seq, by_emoji) in by_seq {
                for (emoji, members) in by_emoji {
                    for m in members {
                        out.push(crate::channel::ChannelReaction {
                            channel_id: *cid,
                            target_seq: *seq,
                            emoji: emoji.clone(),
                            member: *m,
                            removed: false,
                        });
                    }
                }
            }
        }
        out
    }

    /// Fold one reaction into the standing map and queue it for the next
    /// [`Engine::take_reactions`].
    fn record_reaction(
        &mut self,
        channel_id: [u8; 32],
        target_seq: u64,
        emoji: String,
        member: [u8; 32],
        removed: bool,
    ) {
        let by_seq = self.channel_reactions.entry(channel_id).or_default();
        let slot = by_seq.entry(target_seq).or_default();
        if removed {
            if let Some(set) = slot.get_mut(&emoji) {
                set.remove(&member);
                if set.is_empty() {
                    slot.remove(&emoji);
                }
            }
            if slot.is_empty() {
                by_seq.remove(&target_seq);
            }
        } else {
            slot.entry(emoji.clone()).or_default().insert(member);
        }
        self.new_reactions.push(crate::channel::ChannelReaction {
            channel_id,
            target_seq,
            emoji,
            member,
            removed,
        });
        self.dirty = true;
    }

    async fn handle_channel_control(
        &mut self,
        from: &[u8; 32],
        blob: &[u8],
        now_ms: u64,
        out: &mut Vec<Inbound>,
    ) -> Result<(), CoreError> {
        match ChannelControl::decode(blob)? {
            ChannelControl::MlsWelcome {
                info,
                welcome,
                since_seq,
                log_key,
            } => {
                let channel_id = info.channel_id;
                self.invites_received.remove(&channel_id);
                if self.channels.contains_key(&channel_id) {
                    return Ok(());
                }
                let Some(mls) = self.try_join_pending(&welcome) else {
                    tracing::debug!("no KeyPackage matched a channel Welcome");
                    return Ok(());
                };
                let roster: HashSet<[u8; 32]> = mls
                    .members()
                    .into_iter()
                    .filter_map(|(_, id)| <[u8; 32]>::try_from(id).ok())
                    .collect();
                self.channels.insert(
                    channel_id,
                    ChannelSession {
                        info,
                        mls,
                        roster,
                        last_seq: since_seq,
                        removed: HashMap::new(),
                        log_key: (log_key != [0u8; 32]).then_some(log_key),
                    },
                );
                let _ = self.refresh_mls_key_package().await;
                self.dirty = true;
            }
            ChannelControl::Redeem { token, pw } => {
                let token = crate::invite::InviteToken::decode(&token)?;
                token.verify()?;
                if token.is_expired(now_ms) || token.host_id != self.my_member_id() {
                    return Ok(());
                }
                let Some(ch) = self.channels.get(&token.channel_id) else {
                    return Ok(());
                };
                if ch.info.server_root != token.server_root
                    || !self.hosted.contains_key(&token.server_root)
                {
                    return Ok(());
                }
                if let Some(want) = self.hosted[&token.server_root].join_pw_hash {
                    if join_pw_hash(&token.server_root, &pw) != want {
                        return Ok(());
                    }
                }
                let used = *self.invite_uses.get(&token.nonce).unwrap_or(&0);
                if token.max_uses != 0 && used >= token.max_uses {
                    return Ok(());
                }
                let Ok(pk) = SignPublic::from_bytes(from) else {
                    return Ok(());
                };
                let redeemer_id = *IdentityId::of(&pk).as_bytes();
                self.invite_uses.insert(token.nonce, used + 1);
                self.dirty = true;
                self.mls_add_member(&token.channel_id, &redeemer_id, now_ms)
                    .await?;
                if let Some(ch) = self.channels.get_mut(&token.channel_id) {
                    ch.removed.remove(&redeemer_id);
                }
            }
            ChannelControl::Closed { channel_id } => {
                let is_host = self
                    .channels
                    .get(&channel_id)
                    .is_some_and(|c| c.info.host_id == idk_to_id(from));
                if is_host {
                    let server_root = self.channels[&channel_id].info.server_root;
                    self.channels.remove(&channel_id);
                    if !self
                        .channels
                        .values()
                        .any(|c| c.info.server_root == server_root)
                    {
                        self.server_policies.remove(&server_root);
                    }
                    self.dirty = true;
                }
            }
            ChannelControl::Renamed { channel_id, name } => {
                if let Some(c) = self.channels.get_mut(&channel_id) {
                    if c.info.host_id == idk_to_id(from) {
                        c.info.channel_name = name.chars().take(64).collect();
                        self.dirty = true;
                    }
                }
            }
            ChannelControl::History {
                channel_id,
                entries,
            } => {
                // Only from the channel's host, and only once (ignore if we
                // already have backlog for this channel).
                let from_host = self
                    .channels
                    .get(&channel_id)
                    .is_some_and(|c| c.info.host_id == idk_to_id(from));
                let already = self
                    .channel_history
                    .iter()
                    .any(|e| e.channel_id == channel_id);
                if from_host && !already && !entries.is_empty() {
                    let me = self.my_member_id();
                    for (sender, ts_ms, text) in &entries {
                        self.push_channel_history(ChannelHistoryEntry {
                            channel_id,
                            sender: *sender,
                            outgoing: *sender == me,
                            ts_ms: *ts_ms,
                            text: text.clone(),
                        });
                    }
                    self.dirty = true;
                    out.push(Inbound::ChannelBacklog {
                        channel_id,
                        entries,
                    });
                }
            }
            ChannelControl::Invite {
                channel_id,
                channel_name,
                server_name,
            } => {
                // Already a member — ignore.
                if self.channels.contains_key(&channel_id) {
                    return Ok(());
                }
                // First invite for a channel wins: a later sender who merely
                // knows the channel_id must not overwrite a pending invite and
                // silently redirect where the accept is sent.
                if self.invites_received.contains_key(&channel_id) {
                    return Ok(());
                }
                // Bound the map against invite spam from anyone who can DM us.
                if self.invites_received.len() >= MAX_PENDING_INVITES {
                    return Ok(());
                }
                // Clamp the untrusted display strings.
                let channel_name: String = channel_name.chars().take(INVITE_NAME_MAX).collect();
                let server_name: String = server_name.chars().take(INVITE_NAME_MAX).collect();
                self.invites_received.insert(
                    channel_id,
                    (*from, channel_name.clone(), server_name.clone()),
                );
                self.dirty = true;
                out.push(Inbound::ChannelInvite {
                    channel_id,
                    from_idk: *from,
                    channel_name,
                    server_name,
                });
            }
            ChannelControl::InviteAccept { channel_id } => {
                let member = idk_to_id(from);
                // Only add someone we actually invited — an unsolicited accept
                // must not join anyone.
                if self.invites_sent.remove(&(channel_id, member)) {
                    match self.mls_add_member(&channel_id, &member, now_ms).await {
                        Ok(()) => {
                            if let Some(ch) = self.channels.get_mut(&channel_id) {
                                ch.removed.remove(&member);
                            }
                        }
                        Err(e) => tracing::debug!(error = %e, "invite accept: MLS add failed"),
                    }
                }
            }
            ChannelControl::InviteDecline { channel_id } => {
                self.invites_sent.remove(&(channel_id, idk_to_id(from)));
            }
            ChannelControl::Policy { policy } => {
                let Ok(p) = ServerPolicy::decode(&policy) else {
                    return Ok(());
                };
                if p.verify().is_err() {
                    return Ok(());
                }
                let newer = self
                    .server_policies
                    .get(&p.server_root)
                    .is_none_or(|cur| p.version > cur.version);
                if newer {
                    self.server_policies.insert(p.server_root, p);
                    self.dirty = true;
                }
            }
            ChannelControl::KickRequest {
                channel_id,
                member,
                ban,
            } => {
                let Some(server_root) = self.channels.get(&channel_id).map(|c| c.info.server_root)
                else {
                    return Ok(());
                };
                if !self.hosted.contains_key(&server_root) {
                    return Ok(());
                }
                let Ok(pk) = SignPublic::from_bytes(from) else {
                    return Ok(());
                };
                let requester = *IdentityId::of(&pk).as_bytes();
                let owner = self.server_policies.get(&server_root).map(|p| p.owner_id);
                // Staff (kick / manage-roles power) can only be removed by the
                // owner; the owner is never removable this way.
                let target_is_staff = self.member_perms(&server_root, &member)
                    & (roles::PERM_KICK | roles::PERM_MANAGE_ROLES)
                    != 0;
                let requester_is_owner = owner == Some(requester);
                if Some(member) == owner {
                    return Ok(());
                }
                // A ban is strictly stronger than a kick, so it needs its own
                // permission — otherwise any PERM_KICK moderator could
                // permanently ban members.
                let required = if ban {
                    roles::PERM_BAN
                } else {
                    roles::PERM_KICK
                };
                if self.member_perms(&server_root, &requester) & required != 0
                    && (requester_is_owner || !target_is_staff)
                {
                    self.kick_from_server(&server_root, &member, ban, now_ms)
                        .await?;
                }
            }
            ChannelControl::Leave { channel_id } => {
                let Some(server_root) = self.channels.get(&channel_id).map(|c| c.info.server_root)
                else {
                    return Ok(());
                };
                let Ok(pk) = SignPublic::from_bytes(from) else {
                    return Ok(());
                };
                let leaver = *IdentityId::of(&pk).as_bytes();
                if self.hosted.contains_key(&server_root)
                    && leaver != self.my_member_id()
                    && self
                        .channels
                        .get(&channel_id)
                        .is_some_and(|c| c.roster.contains(&leaver))
                {
                    // Anyone may remove themselves — no permission check.
                    self.remove_from_channel(&channel_id, &leaver, now_ms)
                        .await?;
                }
                // Non-hosts ignore it; the host's `Remove` broadcast follows.
            }
        }
        Ok(())
    }

    /// Send a text DM to the identity whose fingerprint (`IdentityId` bytes) is
    /// `peer_id`. Establishes a session on first contact, fetching the peer's
    /// prekeys from the relay; thereafter ratchets forward.
    ///
    /// The peer must be present in the local ledger replica ([`Engine::sync`]).
    /// Returns the new message's conversation id — the handle for a later
    /// [`edit_dm`](Engine::edit_dm) / [`delete_dm`](Engine::delete_dm).
    pub async fn send_dm(
        &mut self,
        peer_id: &[u8; 32],
        text: &str,
        now_ms: u64,
    ) -> Result<[u8; 16], CoreError> {
        let id = random_array::<16>();
        self.send_content(
            peer_id,
            Content::TextId {
                text: text.to_owned(),
                id,
            },
            now_ms,
        )
        .await?;
        Ok(id)
    }

    /// Replace the text of a direct message we sent. `msg_id` is the value
    /// [`send_dm`](Engine::send_dm) returned.
    pub async fn edit_dm(
        &mut self,
        peer_id: &[u8; 32],
        msg_id: &[u8; 16],
        new_text: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        self.post_dm_edit(peer_id, msg_id, Some(new_text.to_owned()), now_ms)
            .await
    }

    /// Withdraw a direct message we sent.
    pub async fn delete_dm(
        &mut self,
        peer_id: &[u8; 32],
        msg_id: &[u8; 16],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        self.post_dm_edit(peer_id, msg_id, None, now_ms).await
    }

    async fn post_dm_edit(
        &mut self,
        peer_id: &[u8; 32],
        msg_id: &[u8; 16],
        new_text: Option<String>,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let peer_idk = self
            .ledger
            .idk_for_id(peer_id)
            .ok_or(CoreError::UnknownPeer)?;
        // We may only edit an outgoing text message of ours in this conversation.
        let known = self.history.iter().any(|e| {
            e.outgoing
                && e.peer_idk == peer_idk
                && e.msg_id == *msg_id
                && matches!(e.kind, HistoryKind::Text(_))
        });
        if !known {
            return Err(CoreError::Message(
                "unknown message (or sent before restart)",
            ));
        }
        if self
            .dm_edits
            .get(&peer_idk)
            .and_then(|m| m.get(msg_id))
            .is_some_and(|e| e.deleted)
        {
            return Err(CoreError::Message("that message was deleted"));
        }
        let content = match &new_text {
            Some(t) => Content::DmEdit {
                target: *msg_id,
                text: t.clone(),
            },
            None => Content::DmDelete { target: *msg_id },
        };
        self.send_content(peer_id, content, now_ms).await?;
        self.apply_dm_edit(peer_idk, *msg_id, new_text);
        Ok(())
    }

    /// Fold a DM edit / delete into the standing state and queue the UI delta.
    fn apply_dm_edit(&mut self, peer_idk: [u8; 32], msg_id: [u8; 16], new_text: Option<String>) {
        let entry = self
            .dm_edits
            .entry(peer_idk)
            .or_default()
            .entry(msg_id)
            .or_default();
        if entry.deleted {
            return;
        }
        match new_text {
            Some(t) => {
                entry.text = Some(t.clone());
                self.new_dm_edits.push(DmEdit {
                    peer_idk,
                    msg_id,
                    text: Some(t),
                    deleted: false,
                });
            }
            None => {
                entry.text = None;
                entry.deleted = true;
                self.new_dm_edits.push(DmEdit {
                    peer_idk,
                    msg_id,
                    text: None,
                    deleted: true,
                });
            }
        }
        self.dirty = true;
    }

    /// True if `msg_id` names a message the peer `from` sent us in this
    /// conversation — the only thing an inbound `DmEdit` / `DmDelete` may touch.
    fn dm_target_matches(&self, from: &[u8; 32], msg_id: &[u8; 16]) -> bool {
        self.history.iter().any(|e| {
            !e.outgoing
                && e.peer_idk == *from
                && e.msg_id == *msg_id
                && matches!(e.kind, HistoryKind::Text(_))
        })
    }

    /// Drain the DM edits/deletes seen since the last call (own and inbound).
    pub fn take_dm_edits(&mut self) -> Vec<DmEdit> {
        std::mem::take(&mut self.new_dm_edits)
    }

    /// The current DM edit/delete state, one [`DmEdit`] per changed message.
    /// Used to re-seed a fresh view on startup.
    pub fn dm_edit_snapshot(&self) -> Vec<DmEdit> {
        let mut out = Vec::new();
        for (peer, by_id) in &self.dm_edits {
            for (msg_id, e) in by_id {
                if e.deleted {
                    out.push(DmEdit {
                        peer_idk: *peer,
                        msg_id: *msg_id,
                        text: None,
                        deleted: true,
                    });
                } else if let Some(t) = &e.text {
                    out.push(DmEdit {
                        peer_idk: *peer,
                        msg_id: *msg_id,
                        text: Some(t.clone()),
                        deleted: false,
                    });
                }
            }
        }
        out
    }

    /// Send a file DM: the ciphertext chunks go to the relay blob store, the
    /// [`FileManifest`] goes through the ratchet like any other message.
    pub async fn send_file(
        &mut self,
        peer_id: &[u8; 32],
        filename: &str,
        data: &[u8],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let (manifest, chunks) = FileManifest::build(&self.identity, filename, data);
        for chunk in &chunks {
            sync::put_blob(&mut self.client, chunk).await?;
        }
        self.send_content(peer_id, Content::File(manifest), now_ms)
            .await
    }

    /// The shared relay topic both ends of a DM derive for typing signals:
    /// `SHA-256(domain || min(idk) || max(idk))`. Order-independent so either
    /// party computes the same value; opaque to the relay.
    fn dm_typing_topic(&self, peer_idk: &[u8; 32]) -> [u8; 32] {
        let mine = self.identity.sign_public().to_bytes();
        let (lo, hi) = if mine <= *peer_idk {
            (mine, *peer_idk)
        } else {
            (*peer_idk, mine)
        };
        let mut buf = Vec::with_capacity(DM_TYPING_TOPIC_DOMAIN.len() + 64);
        buf.extend_from_slice(DM_TYPING_TOPIC_DOMAIN);
        buf.extend_from_slice(&lo);
        buf.extend_from_slice(&hi);
        sha256(&buf)
    }

    /// Broadcast a short-lived "I am typing" signal to a DM peer. Stateless:
    /// it seals a fresh sealed-sender envelope (no ratchet step, nothing
    /// persisted) and posts it to the pair's ephemeral relay topic. Callers
    /// gate this on a user setting and rate-limit it.
    pub async fn send_typing_dm(
        &mut self,
        peer_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let peer_idk = self
            .ledger
            .idk_for_id(peer_id)
            .ok_or(CoreError::UnknownPeer)?;
        let peer_ik = self
            .ledger
            .agreement_key(&peer_idk)
            .ok_or(CoreError::UnknownPeer)?;
        let topic = self.dm_typing_topic(&peer_idk);
        let env = Envelope::seal_with(
            peer_id,
            &peer_ik,
            self.identity.sign_public().to_bytes(),
            &Content::Typing.encode(),
            now_ms,
            TYPING_TTL_MS,
            |m| self.identity.sign(m),
        )?;
        sync::post_signal(&mut self.client, &topic, &env.encode()).await?;
        Ok(())
    }

    /// Broadcast a short-lived "I am typing" signal to a channel. Stateless:
    /// AEAD-sealed under the channel group's current epoch secret, so it never
    /// touches the message log and nothing is persisted.
    pub async fn send_typing_channel(
        &mut self,
        channel_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let me = self.my_member_id();
        let blob = {
            let ch = self
                .channels
                .get(channel_id)
                .ok_or(CoreError::UnknownChannel)?;
            let mut pt = now_ms.to_be_bytes().to_vec();
            pt.extend_from_slice(&Content::Typing.encode());
            seal_channel_signal(&ch.mls, &me, channel_id, CHANNEL_SIGNAL_LABEL, &pt)?
        };
        sync::post_signal(&mut self.client, channel_id, &blob).await?;
        Ok(())
    }

    /// Poll for inbound typing signals across every open DM and channel.
    /// Ephemeral: the result is a snapshot, nothing is stored, and re-polling
    /// re-reports a signal that is still within its TTL on the relay.
    pub async fn poll_typing(&mut self, _now_ms: u64) -> Result<Vec<TypingEvent>, CoreError> {
        let ik = self.identity.agreement_secret();
        let peer_idks: Vec<[u8; 32]> = self.sessions.keys().copied().collect();
        let mut out = Vec::new();
        for peer_idk in peer_idks {
            let topic = self.dm_typing_topic(&peer_idk);
            let blobs = sync::fetch_signals(&mut self.client, &topic).await?;
            for blob in blobs {
                let Ok(env) = Envelope::decode(&blob) else {
                    continue;
                };
                // Our own signal is sealed to the peer, so `open` fails for us.
                let Ok(sealed) = env.open(&ik) else { continue };
                if sealed.sender_idk != peer_idk {
                    continue;
                }
                if self.blocked.contains(&idk_to_id(&sealed.sender_idk)) {
                    continue;
                }
                if let Ok(Content::Typing) = Content::decode(&sealed.inner) {
                    out.push(TypingEvent {
                        scope: TypingScope::Dm(peer_idk),
                        who: sealed.sender_idk,
                        at_ms: env.deposited_ms,
                    });
                }
            }
        }

        let me = self.my_member_id();
        let channel_ids: Vec<[u8; 32]> = self.channels.keys().copied().collect();
        for channel_id in channel_ids {
            let blobs = sync::fetch_signals(&mut self.client, &channel_id).await?;
            let Some(ch) = self.channels.get(&channel_id) else {
                continue;
            };
            for blob in blobs {
                let Some((member, pt)) =
                    open_channel_signal(&ch.mls, &channel_id, CHANNEL_SIGNAL_LABEL, &blob)
                else {
                    continue;
                };
                if member == me || pt.len() < 8 || self.blocked.contains(&member) {
                    continue;
                }
                let at_ms = u64::from_be_bytes(pt[..8].try_into().unwrap());
                if let Ok(Content::Typing) = Content::decode(&pt[8..]) {
                    out.push(TypingEvent {
                        scope: TypingScope::Channel(channel_id),
                        who: member,
                        at_ms,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Fetch a peer's prekey bundle: the relay first, then (with the `p2p`
    /// feature and a node running) the DHT.
    async fn fetch_prekey_bundle(&mut self, peer_id: &[u8; 32]) -> Result<Vec<u8>, CoreError> {
        match sync::get_prekeys(&mut self.client, peer_id).await {
            Ok(Some(blob)) => return Ok(blob),
            Ok(None) => {}
            Err(e) => {
                #[cfg(not(feature = "p2p"))]
                return Err(e.into());
                #[cfg(feature = "p2p")]
                tracing::debug!(error = %e, "relay prekey fetch failed; trying the DHT");
            }
        }
        #[cfg(feature = "p2p")]
        if let Some(p2p) = &self.p2p {
            if let Some(blob) = p2p.get_prekey(peer_id).await {
                return Ok(blob);
            }
        }
        Err(CoreError::NoPrekeys)
    }

    async fn send_content(
        &mut self,
        peer_id: &[u8; 32],
        content: Content,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        if self.blocked.contains(peer_id)
            && matches!(
                content,
                Content::Text(_) | Content::TextId { .. } | Content::File(_)
            )
        {
            return Err(CoreError::Blocked);
        }
        let peer_idk = self
            .ledger
            .idk_for_id(peer_id)
            .ok_or(CoreError::UnknownPeer)?;
        let peer_id = *peer_id;
        let peer_ik = self
            .ledger
            .agreement_key(&peer_idk)
            .ok_or(CoreError::UnknownPeer)?;
        let (history_kind, history_id) = match &content {
            Content::Text(t) => (Some(HistoryKind::Text(t.clone())), [0u8; 16]),
            Content::TextId { text, id } => (Some(HistoryKind::Text(text.clone())), *id),
            Content::File(m) => (
                Some(HistoryKind::File {
                    filename: m.filename.clone(),
                    size: m.total_size,
                }),
                [0u8; 16],
            ),
            Content::Channel(_) => (None, [0u8; 16]), // control traffic, not conversation
            // Control-only payloads never become conversation history.
            Content::Typing
            | Content::Reaction { .. }
            | Content::CallOffer(_)
            | Content::CallAnswer(_)
            | Content::CallIce(_)
            | Content::CallEnd
            | Content::GroupCallWelcome { .. }
            | Content::GroupCallCommit { .. }
            | Content::GroupCallLeave { .. }
            | Content::Edit { .. }
            | Content::Delete { .. }
            | Content::Reply { .. }
            | Content::Pin { .. }
            | Content::DmEdit { .. }
            | Content::DmDelete { .. }
            | Content::Forward { .. }
            | Content::GroupCallJoinRequest { .. }
            | Content::VoiceSignal { .. } => (None, [0u8; 16]),
        };
        let plaintext = content.encode();

        let packet = if let Some(session) = self.sessions.get_mut(&peer_idk) {
            Packet::Message(session.encrypt(&plaintext)?)
        } else {
            let blob = self.fetch_prekey_bundle(&peer_id).await?;
            let bundle = PreKeyBundle::decode(&blob)?;
            if bundle.idk_pub != peer_idk || bundle.identity_id != peer_id {
                return Err(CoreError::BadPeerPrekeys);
            }
            bundle.verify().map_err(|_| CoreError::BadPeerPrekeys)?;
            let (session, init) = Session::initiate(&self.identity, &bundle, &plaintext)?;
            self.sessions.insert(peer_idk, session);
            Packet::Init(init)
        };

        let inner = packet.encode();
        let env = Envelope::seal_with(
            &peer_id,
            &peer_ik,
            self.identity.sign_public().to_bytes(),
            &inner,
            now_ms,
            DM_TTL_MS,
            |m| self.identity.sign(m),
        )?;
        sync::deposit(&mut self.client, &env).await?;
        if let Some(kind) = history_kind {
            self.history.push(HistoryEntry {
                peer_idk,
                outgoing: true,
                ts_ms: now_ms,
                kind,
                msg_id: history_id,
            });
        }
        self.dirty = true;
        Ok(())
    }

    /// Poll the relay and return any newly decrypted messages / files.
    /// Convenience wrapper returning only text messages.
    pub async fn receive(&mut self, now_ms: u64) -> Result<Vec<ReceivedDm>, CoreError> {
        Ok(self
            .receive_all(now_ms)
            .await?
            .into_iter()
            .filter_map(|i| match i {
                Inbound::Message(m) => Some(m),
                _ => None,
            })
            .collect())
    }

    /// Poll the relay for inbound envelopes; decrypt messages and reassemble
    /// files (fetching their chunks from the blob store).
    pub async fn receive_all(&mut self, now_ms: u64) -> Result<Vec<Inbound>, CoreError> {
        let my_id = *self.identity.id().as_bytes();
        let hints = [
            recipient_hint(&my_id, now_ms),
            recipient_hint(
                &my_id,
                now_ms.saturating_sub(dante_proto::envelope::EPOCH_MS),
            ),
            recipient_hint(
                &my_id,
                now_ms.saturating_add(dante_proto::envelope::EPOCH_MS),
            ),
        ];
        let envelopes = sync::fetch(&mut self.client, &hints, self.last_fetch_since_ms).await?;

        let ik = self.identity.agreement_secret();
        let mut out = Vec::new();
        let mut consumed_prekey = false;
        for env in envelopes {
            let tag = sha256(&env.encode());
            if !self.seen_envelopes.insert(tag) {
                continue;
            }
            let Ok(sealed) = env.open(&ik) else { continue };
            let Ok(packet) = Packet::decode(&sealed.inner) else {
                continue;
            };
            let from = sealed.sender_idk;
            if self.blocked.contains(&idk_to_id(&from)) {
                continue;
            }
            consumed_prekey |= matches!(packet, Packet::Init(_));

            let plaintext = match self.decrypt_packet(&from, packet) {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(error = %e, "dropping undecryptable inbound packet");
                    continue;
                }
            };
            match Content::decode(&plaintext) {
                Ok(Content::Text(text)) => {
                    self.history.push(HistoryEntry {
                        peer_idk: from,
                        outgoing: false,
                        ts_ms: now_ms,
                        kind: HistoryKind::Text(text.clone()),
                        msg_id: [0u8; 16],
                    });
                    out.push(Inbound::Message(ReceivedDm {
                        from_idk: from,
                        text,
                        msg_id: [0u8; 16],
                    }));
                }
                Ok(Content::TextId { text, id }) => {
                    self.history.push(HistoryEntry {
                        peer_idk: from,
                        outgoing: false,
                        ts_ms: now_ms,
                        kind: HistoryKind::Text(text.clone()),
                        msg_id: id,
                    });
                    out.push(Inbound::Message(ReceivedDm {
                        from_idk: from,
                        text,
                        msg_id: id,
                    }));
                }
                Ok(Content::DmEdit { target, text }) => {
                    if self.dm_target_matches(&from, &target) {
                        self.apply_dm_edit(from, target, Some(text));
                    }
                }
                Ok(Content::DmDelete { target }) => {
                    if self.dm_target_matches(&from, &target) {
                        self.apply_dm_edit(from, target, None);
                    }
                }
                Ok(Content::File(manifest)) => match self.fetch_file(manifest).await {
                    Ok((filename, data)) => {
                        self.history.push(HistoryEntry {
                            peer_idk: from,
                            outgoing: false,
                            ts_ms: now_ms,
                            kind: HistoryKind::File {
                                filename: filename.clone(),
                                size: data.len() as u64,
                            },
                            msg_id: [0u8; 16],
                        });
                        out.push(Inbound::File {
                            from_idk: from,
                            filename,
                            data,
                        });
                    }
                    Err(e) => tracing::debug!(error = %e, "dropping file with a failed transfer"),
                },
                Ok(Content::Channel(blob)) => {
                    if let Err(e) = self
                        .handle_channel_control(&from, &blob, now_ms, &mut out)
                        .await
                    {
                        tracing::debug!(error = %e, "dropping channel-control message");
                    }
                }
                Ok(Content::CallOffer(sdp)) => {
                    let id = idk_to_id(&from);
                    self.pending_call_offers.insert(id, sdp);
                    if self.is_group_call_member(&id) {
                        // A media leg of a call we are already in — accept it
                        // without prompting the user again.
                        if let Err(e) = self.accept_call(&id, now_ms).await {
                            tracing::debug!(error = %e, "group-call leg auto-accept failed");
                        }
                    } else {
                        out.push(Inbound::IncomingCall { from_idk: from });
                    }
                }
                Ok(Content::CallAnswer(sdp)) => {
                    if let Some(call) = self.calls.get(&idk_to_id(&from)) {
                        if let Err(e) = call.set_answer(&sdp).await {
                            tracing::debug!(error = %e, "bad call answer");
                        }
                    }
                }
                Ok(Content::CallIce(cand)) => {
                    if let Some(call) = self.calls.get(&idk_to_id(&from)) {
                        let _ = call.add_ice(&cand).await;
                    }
                }
                Ok(Content::CallEnd) => {
                    let id = idk_to_id(&from);
                    self.pending_call_offers.remove(&id);
                    self.call_states.remove(&id);
                    self.inbound_audio.remove(&id);
                    if let Some(call) = self.calls.remove(&id) {
                        call.close().await;
                    }
                    out.push(Inbound::CallEnded { from_idk: from });
                }
                Ok(Content::GroupCallWelcome { channel_id, blob }) => {
                    // Only for a channel we are actually in.
                    if self.channels.contains_key(&channel_id) {
                        self.pending_group_calls
                            .insert(channel_id, (idk_to_id(&from), blob));
                        if self.voice_join_intent.remove(&channel_id) {
                            // We asked to join this voice channel — connect now.
                            match self.join_group_call(&channel_id, now_ms).await {
                                Ok(()) => {
                                    let _ = self.send_voice_presence(now_ms).await;
                                    out.push(Inbound::GroupCallMembersChanged { channel_id });
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "voice auto-join failed");
                                }
                            }
                        } else {
                            out.push(Inbound::GroupCallInvite {
                                channel_id,
                                from_idk: from,
                            });
                        }
                    }
                }
                Ok(Content::GroupCallJoinRequest { channel_id }) => {
                    let requester = idk_to_id(&from);
                    // Only the lowest-id current participant admits the joiner,
                    // so N members don't all add at once.
                    let issue = match self.group_calls.get(&channel_id) {
                        Some(gc) => {
                            let me = self.my_member_id();
                            let mut ids: Vec<[u8; 32]> = gc
                                .mls
                                .members()
                                .into_iter()
                                .filter_map(|(_, id)| <[u8; 32]>::try_from(id).ok())
                                .filter(|id| *id != requester)
                                .collect();
                            ids.sort_unstable();
                            ids.first() == Some(&me)
                        }
                        None => false,
                    };
                    if issue {
                        if let Ok(Some(kp)) =
                            sync::get_key_package(&mut self.client, &requester).await
                        {
                            let hs = self
                                .group_calls
                                .get_mut(&channel_id)
                                .and_then(|gc| gc.mls.add(&[mls::KeyPkg(kp)]).ok());
                            if let Some(hs) = hs {
                                if let Some(welcome) = hs.welcome {
                                    let _ = self
                                        .send_content(
                                            &requester,
                                            Content::GroupCallWelcome {
                                                channel_id,
                                                blob: welcome,
                                            },
                                            now_ms,
                                        )
                                        .await;
                                }
                                let others = self.group_call_peers(&channel_id);
                                for p in others.iter().filter(|p| **p != requester) {
                                    let _ = self
                                        .send_content(
                                            p,
                                            Content::GroupCallCommit {
                                                channel_id,
                                                blob: hs.commit.clone(),
                                            },
                                            now_ms,
                                        )
                                        .await;
                                }
                                self.reconcile_group_legs(&channel_id, now_ms).await;
                                out.push(Inbound::GroupCallMembersChanged { channel_id });
                            }
                        }
                    }
                }
                Ok(Content::GroupCallCommit { channel_id, blob }) => {
                    let advanced = match self.group_calls.get_mut(&channel_id) {
                        Some(gc) => match gc.mls.process(&blob) {
                            Ok(_) => true,
                            Err(e) => {
                                tracing::debug!(error = %e, "bad group-call commit");
                                false
                            }
                        },
                        None => false,
                    };
                    if advanced {
                        self.dirty = true;
                        self.reconcile_group_legs(&channel_id, now_ms).await;
                        out.push(Inbound::GroupCallMembersChanged { channel_id });
                    }
                }
                Ok(Content::GroupCallLeave { channel_id }) => {
                    let leaver = idk_to_id(&from);
                    let _ = self.hangup(&leaver, now_ms).await;
                    // The lowest-id remaining member issues the removal Commit,
                    // so N members don't all commit a removal at once.
                    let (issue, leaf, remaining) = match self.group_calls.get(&channel_id) {
                        Some(gc) => {
                            let me = self.my_member_id();
                            let members = gc.mls.members();
                            let leaf = members
                                .iter()
                                .find(|(_, id)| id.as_slice() == leaver)
                                .map(|(l, _)| *l);
                            let remaining: Vec<[u8; 32]> = members
                                .iter()
                                .filter_map(|(_, id)| <[u8; 32]>::try_from(id.clone()).ok())
                                .filter(|id| *id != leaver)
                                .collect();
                            let lowest = remaining.iter().min().copied();
                            (lowest == Some(me), leaf, remaining)
                        }
                        None => (false, None, Vec::new()),
                    };
                    if let (true, Some(leaf)) = (issue, leaf) {
                        let commit = self
                            .group_calls
                            .get_mut(&channel_id)
                            .and_then(|gc| gc.mls.remove(&[leaf]).ok())
                            .map(|hs| hs.commit);
                        if let Some(commit) = commit {
                            let me = self.my_member_id();
                            for p in remaining.iter().filter(|p| **p != me) {
                                let _ = self
                                    .send_content(
                                        p,
                                        Content::GroupCallCommit {
                                            channel_id,
                                            blob: commit.clone(),
                                        },
                                        now_ms,
                                    )
                                    .await;
                            }
                        }
                    }
                    if self.group_calls.contains_key(&channel_id) {
                        out.push(Inbound::GroupCallMembersChanged { channel_id });
                    }
                }
                Ok(Content::VoiceSignal {
                    channel_id,
                    kind,
                    data,
                }) => {
                    out.push(Inbound::VoiceSignal {
                        channel_id,
                        from_idk: from,
                        kind,
                        data,
                    });
                }
                // Typing / reactions / edits / forwards are channel-scoped,
                // never delivered by DM.
                Ok(
                    Content::Typing
                    | Content::Reaction { .. }
                    | Content::Edit { .. }
                    | Content::Delete { .. }
                    | Content::Reply { .. }
                    | Content::Pin { .. }
                    | Content::Forward { .. },
                ) => {}
                Err(e) => tracing::debug!(error = %e, "dropping malformed content"),
            }
            self.dirty = true;
        }
        self.last_fetch_since_ms = now_ms.saturating_sub(2 * dante_proto::envelope::EPOCH_MS);
        // A first-contact packet consumed one of our one-time prekeys (locally,
        // and on the relay). Re-publish so the relay's copy tracks our remaining
        // set and later initiators still get a fresh OTP.
        if consumed_prekey {
            let _ = self.publish_prekeys().await;
        }
        Ok(out)
    }

    fn decrypt_packet(
        &mut self,
        from_idk: &[u8; 32],
        packet: Packet,
    ) -> Result<Vec<u8>, CoreError> {
        match packet {
            Packet::Init(init) => {
                let (session, plaintext) =
                    Session::accept(&self.identity, &mut self.prekeys, &init)?;
                self.sessions.insert(*from_idk, session);
                Ok(plaintext)
            }
            Packet::Message(msg) => {
                let session = self
                    .sessions
                    .get_mut(from_idk)
                    .ok_or(CoreError::NoSession)?;
                Ok(session.decrypt(&msg)?)
            }
        }
    }

    async fn fetch_file(&mut self, manifest: FileManifest) -> Result<(String, Vec<u8>), CoreError> {
        manifest.verify()?;
        let mut chunks = Vec::with_capacity(manifest.blob_hashes().len());
        for hash in manifest.blob_hashes() {
            let blob = sync::get_blob(&mut self.client, hash)
                .await?
                .ok_or(CoreError::MissingBlob)?;
            chunks.push(blob);
        }
        let data = manifest.reassemble(&chunks)?;
        Ok((manifest.filename.clone(), data))
    }

    /// Records currently in the local replica (for inspection / tests).
    pub fn ledger_len(&self) -> usize {
        self.ledger.len()
    }

    /// Whether `peer_idk` is a live identity in the local replica.
    pub fn knows(&self, peer_idk: &[u8; 32]) -> bool {
        self.ledger.is_live(peer_idk)
    }
}

#[cfg(test)]
mod pad_tests {
    use super::{pad_channel, unpad_channel, CHANNEL_PAD_LADDER};

    #[test]
    fn pad_roundtrips_and_snaps_to_a_bucket() {
        for len in [0usize, 1, 20, 60, 61, 250, 300, 5000] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let padded = pad_channel(&pt);
            assert!(CHANNEL_PAD_LADDER.contains(&padded.len()) || padded.len() == 4 + len);
            assert!(padded.len() >= 4 + len);
            assert_eq!(unpad_channel(&padded), Some(pt.as_slice()));
        }
    }

    #[test]
    fn unpad_rejects_a_bogus_length() {
        // claims 9999 bytes of payload in a 10-byte frame
        let mut b = 9999u32.to_be_bytes().to_vec();
        b.extend_from_slice(&[0u8; 6]);
        assert_eq!(unpad_channel(&b), None);
        assert_eq!(unpad_channel(&[1, 2]), None);
    }
}
