//! `dante serve` — run the engine behind a tiny local HTTP UI.
//!
//! Single user, localhost only. A minimal hand-rolled HTTP/1.1 handler serves
//! the embedded SPA and a JSON API. Everything under `/api/` is JSON over
//! `GET` / `POST`, grouped roughly as:
//!
//! - identity / onboarding: `/api/me`, `/api/state`, `/api/onboard`,
//!   `/api/resolve`, `/api/usernames`, `/api/avatars`, `/api/revoke`,
//!   `/api/safety`, `/api/verify`
//! - messaging: `/api/send`, `/api/edit`, `/api/dm/edit`, `/api/forward`,
//!   `/api/file`, `/api/recv-file`, `/api/messages`, `/api/stream` (SSE),
//!   `/api/typing`, `/api/react`, `/api/pin`, `/api/unfurl`, `/api/embeds`
//! - contacts / blocking / search: `/api/contacts`, `/api/contact`,
//!   `/api/block`, `/api/unblock`, `/api/search`
//! - servers & channels: `/api/server`, `/api/channel`,
//!   `/api/channel/rename`, `/api/channel/delete`, `/api/server/delete`,
//!   `/api/leave`, `/api/invite`, `/api/invite-link`, `/api/invites`,
//!   `/api/invite/accept`, `/api/invite/decline`, `/api/redeem`, `/api/joinpw`,
//!   `/api/role`, `/api/roleassign`, `/api/policy`, `/api/discover`,
//!   `/api/discover/join`, `/api/server/kick`, `/api/server/ban`,
//!   `/api/server/unban`, `/api/server/bans`, `/api/autokick`, `/api/remove`
//! - custom emoji / stickers / sounds: `/api/emoji`, `/api/sticker`,
//!   `/api/sound` (plus `/remove`)
//! - calls & voice: `/api/calls`, `/api/call`, `/api/call/accept`,
//!   `/api/call/hangup`, `/api/call/signal`, `/api/call/audio`, `/api/ice`,
//!   `/api/groupcalls`, `/api/groupcall/start|join|leave`, `/api/voice`,
//!   `/api/voice/join|leave|signal`, `/api/voice/key`
//!
//! File bodies are capped at 9 MiB. Mutations reject cross-site /
//! DNS-rebinding requests, and the SPA is served under a strict CSP.
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
        /// If set (channel target only), post as a reply to this relay-log seq.
        reply_to: Option<u64>,
        reply: oneshot::Sender<Result<String, String>>,
    },
    CreateServer {
        name: String,
        /// Optional join password to set on the new server.
        password: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    CreateChannel {
        server: String,
        name: String,
        voice: bool,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Rename a channel (host only; refused for #general).
    RenameChannel {
        channel: String,
        name: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Connect to / disconnect from a voice channel (`leave` when `join` false).
    Voice {
        channel: String,
        join: bool,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Edit (or, with empty text, delete) one of our channel messages.
    EditMsg {
        channel: String,
        seq: u64,
        text: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Edit (or, with empty text, delete) one of our direct messages.
    DmEdit {
        peer: String,
        /// Hex of the message's edit id.
        msg_id: String,
        text: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Forward a message (text + origin label) into a channel or DM.
    Forward {
        /// `#<channel-id>` or a peer fingerprint.
        to: String,
        origin: String,
        text: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Send a file to a DM peer (chunked encrypted transfer via the blob store).
    SendFile {
        peer: String,
        filename: String,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<String, String>>,
    },
    Invite {
        channel: String,
        peer: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Accept (`accept: true`) or decline a channel invite we received.
    InviteRespond {
        channel: String,
        accept: bool,
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
        /// The current join password, required when one is already set.
        current: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Relay a WebRTC signalling blob to another voice-channel participant.
    VoiceSignal {
        channel: String,
        to: String,
        kind: u8,
        data: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Relay a WebRTC signalling blob to the peer of a 1:1 DM call.
    CallSignal {
        to: String,
        kind: u8,
        data: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Remove a member from the whole server `channel` belongs to; `ban` also
    /// blocks their return.
    RemoveMember {
        channel: String,
        member: String,
        ban: bool,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Lift a server ban.
    Unban {
        server: String,
        member: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// The server's ban list as a ready JSON array of fingerprints.
    ServerBans {
        server: String,
        reply: oneshot::Sender<String>,
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
        /// Optional custom-emoji shortcode to render next to the role name.
        icon: Option<String>,
        reply: oneshot::Sender<Result<String, String>>,
    },
    AssignRole {
        server: String,
        member: String,
        role_id: u16,
        add: bool,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Set (non-empty `nickname`) or clear (empty) a member's nickname on a
    /// server. Host only.
    SetNickname {
        server: String,
        member: String,
        nickname: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Ask the host to set (non-empty `nickname`) or clear (empty) **our own**
    /// nickname on a server. Any member may call this; the sender can only
    /// ever name themselves.
    RequestNickname {
        server: String,
        nickname: String,
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
    /// `{ "<fingerprint>": "<username>", ... }` for every identity we know a
    /// self-asserted username for.
    Usernames { reply: oneshot::Sender<String> },
    /// `{ "<fingerprint>": "<blob hash hex>", ... }` for every identity with a
    /// global avatar in our ledger replica. The image itself is fetched from
    /// the existing blob proxy (`/api/emoji?hash=`).
    Avatars { reply: oneshot::Sender<String> },
    /// Channel invites we've received and not answered, as a ready JSON array.
    PendingInvites { reply: oneshot::Sender<String> },
    React {
        channel: String,
        target_seq: u64,
        emoji: String,
        remove: bool,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Pin (or, with `pinned:false`, unpin) a channel message.
    Pin {
        channel: String,
        seq: u64,
        pinned: bool,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// A channel's pinned messages as a ready JSON array.
    Pins {
        channel: [u8; 32],
        reply: oneshot::Sender<String>,
    },
    /// libp2p node status as a ready JSON object.
    P2pInfo { reply: oneshot::Sender<String> },
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
    /// Add/replace (`image = Some`) or remove (`image = None`) a custom emoji.
    Emoji {
        server: String,
        name: String,
        image: Option<Vec<u8>>,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Fetch a blob (custom-emoji image) by SHA-256.
    GetEmoji {
        hash: [u8; 32],
        reply: oneshot::Sender<Option<Vec<u8>>>,
    },
    /// Add/replace (`image = Some`) or remove (`image = None`) a sticker.
    Sticker {
        server: String,
        name: String,
        image: Option<Vec<u8>>,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Add/replace (`audio = Some`) or remove (`audio = None`) a soundboard clip.
    Sound {
        server: String,
        name: String,
        audio: Option<Vec<u8>>,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// The saved contacts as a ready JSON array.
    Contacts { reply: oneshot::Sender<String> },
    /// Add a contact / set its petname (`petname` may be empty).
    AddContact {
        peer: String,
        petname: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Forget a contact.
    RemoveContact {
        peer: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Leave a joined channel.
    Leave {
        channel: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Host: delete a channel (`server` empty) or a whole server (`channel`
    /// empty).
    Delete {
        channel: String,
        server: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// The blocked identities as a ready JSON array of fingerprints.
    Blocked { reply: oneshot::Sender<String> },
    /// Block (`on = true`) or unblock a peer.
    Block {
        peer: String,
        on: bool,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// 1:1 call action: `"start"`, `"accept"`, or `"hangup"`.
    Call {
        peer: String,
        action: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// The active calls as a ready JSON array.
    Calls { reply: oneshot::Sender<String> },
    /// The ICE servers the engine will use for calls, as a ready JSON array.
    Ice { reply: oneshot::Sender<String> },
    /// Push one or more Opus frames onto an active call's audio track.
    CallAudioSend {
        peer: String,
        frames: Vec<Vec<u8>>,
        ms: u32,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// Drain the Opus frames received on a call, as a ready JSON object
    /// `{"frames":["<hex>",…]}`.
    CallAudioRecv {
        peer: String,
        reply: oneshot::Sender<String>,
    },
    /// The channel group calls as a ready JSON array.
    GroupCalls { reply: oneshot::Sender<String> },
    /// Search stored DM + channel text; reply is a ready JSON array.
    Search {
        q: String,
        reply: oneshot::Sender<String>,
    },
    /// Permanently revoke this identity on the ledger.
    Revoke {
        reason: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// `start` | `join` | `leave` a channel's group call.
    GroupCall {
        channel: String,
        action: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    /// The current per-epoch media key for a voice channel we're connected to,
    /// so the SPA can run an SFrame layer over the mesh. Reply is a ready JSON
    /// object: `{"key":"<hex32>","epoch":N}` or `{}` if not in the call.
    VoiceKey {
        channel: String,
        reply: oneshot::Sender<String>,
    },
}

/// One row of the SPA's call panel.
#[derive(Clone, Serialize)]
struct CallRow {
    /// Peer fingerprint (base32) — also the DM target.
    peer: String,
    /// `ringing` | `calling` | `connecting` | `connected` | `disconnected` | `failed`.
    state: String,
    /// True while it is an unanswered inbound call.
    incoming: bool,
}

/// One row of the SPA's group-call panel.
#[derive(Clone, Serialize)]
struct GroupCallRow {
    /// Channel id (base32).
    channel: String,
    /// Channel display name.
    channel_name: String,
    /// True once we have joined (vs. only invited).
    joined: bool,
    /// Fingerprints of the other participants (MLS members) we can see — who
    /// the browser dials to build the real-audio mesh. Empty while only
    /// invited (we join the mesh, not merely observe it).
    participants: Vec<String>,
    /// Fingerprint of whoever invited us, if we are only invited.
    invited_by: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Item {
    Message {
        seq: u64,
        from: String,
        text: String,
        /// The other party's fingerprint (present for real DMs, not sys lines).
        #[serde(skip_serializing_if = "String::is_empty")]
        peer: String,
        /// Hex of the DM's edit id, empty when not editable.
        #[serde(skip_serializing_if = "String::is_empty")]
        msg_id: String,
    },
    File {
        seq: u64,
        from: String,
        filename: String,
        size: usize,
        saved: String,
        /// `/api/recv-file?id=…` for a file whose bytes we still hold this
        /// session, else empty (e.g. history replayed from disk).
        #[serde(default, skip_serializing_if = "String::is_empty")]
        url: String,
        /// Sniffed MIME so the SPA knows whether to render an `<img>`.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        mime: String,
    },
    Channel {
        seq: u64,
        channel: String,
        channel_name: String,
        from: String,
        text: String,
        /// The relay-log seq — what reactions / edits point at.
        ref_seq: u64,
        /// If this is a reply, the ref_seq of the message it replies to.
        #[serde(skip_serializing_if = "Option::is_none")]
        reply_to: Option<u64>,
        /// If forwarded in, a display label of the original author.
        #[serde(skip_serializing_if = "Option::is_none")]
        forwarded_from: Option<String>,
    },
    /// An edit or delete of an earlier channel message, folded by the SPA.
    ChannelEdit {
        seq: u64,
        channel: String,
        /// The relay-log seq of the message being changed.
        ref_seq: u64,
        /// New text, or empty when `deleted`.
        text: String,
        deleted: bool,
    },
    /// A pin or unpin of an earlier channel message, folded by the SPA.
    ChannelPin {
        seq: u64,
        channel: String,
        /// The relay-log seq of the message being (un)pinned.
        ref_seq: u64,
        /// Who pinned it (fingerprint).
        by: String,
        /// Unix ms when it was pinned.
        at_ms: u64,
        pinned: bool,
    },
    /// An edit or delete of an earlier direct message, folded by the SPA.
    DmEdit {
        seq: u64,
        /// The other party's fingerprint.
        peer: String,
        /// Hex of the message's edit id.
        msg_id: String,
        /// New text, or empty when `deleted`.
        text: String,
        deleted: bool,
    },
    /// A standalone notice for the notifications tray (e.g. "you were removed
    /// from a server"). Not tied to a conversation.
    Notice {
        seq: u64,
        /// Short category tag, e.g. "kicked".
        tag: String,
        text: String,
        /// Optional server fingerprint the notice refers to.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        scope: String,
    },
    /// A relayed WebRTC signalling blob for a voice-channel mesh leg. The SPA
    /// owns the peer connections; this just carries offer / answer / ICE / bye.
    VoiceSignal {
        seq: u64,
        /// The voice channel id (base32).
        channel: String,
        /// The other participant's fingerprint.
        from: String,
        /// 0 offer, 1 answer, 2 ICE, 3 bye.
        sig_kind: u8,
        /// The opaque payload (SDP or ICE candidate line).
        data: String,
    },
    /// A relayed WebRTC signalling blob for a 1:1 DM call. Same as
    /// [`Item::VoiceSignal`] but peer-scoped rather than channel-scoped.
    CallSignal {
        seq: u64,
        /// The peer's fingerprint.
        from: String,
        /// 0 offer, 1 answer, 2 ICE, 3 bye.
        sig_kind: u8,
        /// The opaque payload (SDP or ICE candidate line).
        data: String,
    },
}

impl Item {
    fn seq(&self) -> u64 {
        match self {
            Item::Message { seq, .. }
            | Item::File { seq, .. }
            | Item::Channel { seq, .. }
            | Item::ChannelEdit { seq, .. }
            | Item::ChannelPin { seq, .. }
            | Item::DmEdit { seq, .. }
            | Item::Notice { seq, .. }
            | Item::VoiceSignal { seq, .. }
            | Item::CallSignal { seq, .. } => *seq,
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
    /// A voice channel — members join a persistent call instead of chatting.
    #[serde(default)]
    voice: bool,
    /// Live MLS roster (fingerprints), including us. The authoritative member
    /// list — not inferred from who has spoken.
    #[serde(default)]
    members: Vec<String>,
}

/// One voice channel's live state for the SPA.
#[derive(Clone, Serialize, Default)]
struct VoiceRoom {
    /// Are we connected to this room?
    joined: bool,
    /// Fingerprints of everyone currently in the room.
    participants: Vec<String>,
}

/// Everything `serve` needs to build the engine once the user has an identity.
pub struct Bootstrap {
    pub relay: String,
    pub keystore_path: PathBuf,
    pub store_path: Option<PathBuf>,
    pub params: LedgerParams,
    pub pow: Difficulty,
    /// Set when this client was started with `--also-relay`: the address it
    /// listens on for other people's clients. Read-only display in the SPA's
    /// Network settings — flipping it means restarting with/without the flag,
    /// same as this client's other boot-time `--p2p`-style switches.
    pub also_relay_listen: Option<String>,
    /// Where to report startup steps, if anyone is showing them.
    ///
    /// `Engine::connect` reports its own half; the rest of startup — the
    /// registration proof-of-work, prekeys, the first sync — happens here, so
    /// a client that wants a complete picture has to be told from both places.
    /// `dante serve` leaves this `None` and prints to stderr instead; the
    /// desktop shell uses it to drive its boot screen.
    pub progress: Option<dante_core::BootProgress>,
}

/// Insertion order + `id -> (mime, bytes)` for received files kept this session.
type RecvFiles = (
    std::collections::VecDeque<String>,
    std::collections::HashMap<String, (String, Vec<u8>)>,
);

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
    /// Active 1:1 calls, keyed by peer fingerprint. Live-session only.
    calls: Mutex<std::collections::HashMap<String, CallRow>>,
    /// Channel group calls, keyed by channel id (base32). Live-session only.
    group_calls: Mutex<std::collections::HashMap<String, GroupCallRow>>,
    /// Voice channels, keyed by channel id (base32). Live-session only.
    voice: Mutex<std::collections::HashMap<String, VoiceRoom>>,
    /// Received file bytes we can still serve back this session (insertion
    /// order + `id -> (mime, bytes)`, oldest evicted past a cap).
    recv_files: Mutex<RecvFiles>,
    /// Monotonic id stamped on every inbox item, drawn by both the engine tick
    /// loop and command handlers so the SPA's `since` cursor never regresses.
    next_seq: AtomicU64,
    /// `(fingerprint, word-phrase)`; empty until an identity is set up.
    me: Mutex<(String, String)>,
    /// The username chosen at onboarding (`create`), announced on first connect.
    onboard_name: Mutex<String>,
    /// Our own display name once known (chosen at onboarding, or read back from
    /// the ledger for an unlocked / imported identity).
    my_name: Mutex<String>,
    /// True once the engine is connected and the tick loop is running.
    ready: AtomicBool,
    /// Opt-in link previews. Off by default; the SPA flips it per session
    /// (`POST /api/embeds`). Gates `POST /api/unfurl`, which reveals this
    /// machine's IP to linked sites.
    embeds: AtomicBool,
    cmd: mpsc::Sender<Cmd>,
    /// How to connect the engine after onboarding.
    boot: Bootstrap,
    /// The command receiver, handed to the engine task when it starts.
    pending_rx: Mutex<Option<mpsc::Receiver<Cmd>>>,
    /// The loopback authorities this server legitimately answers to, e.g.
    /// `["127.0.0.1:8080", "localhost:8080", "[::1]:8080"]`. Used to reject a
    /// forged `Host` (DNS-rebinding) or a cross-site `Origin` (CSRF). See
    /// [`request_is_local`].
    local_authorities: Vec<String>,
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

/// Best-effort image MIME from magic bytes; defaults to PNG.
fn sniff_image(b: &[u8]) -> &'static str {
    match b {
        [0x89, b'P', b'N', b'G', ..] => "image/png",
        [0xFF, 0xD8, 0xFF, ..] => "image/jpeg",
        [b'G', b'I', b'F', b'8', ..] => "image/gif",
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => "image/webp",
        _ => "image/png",
    }
}

/// Best-effort MIME for a soundboard clip, from magic bytes.
fn sniff_audio(b: &[u8]) -> &'static str {
    match b {
        [b'O', b'g', b'g', b'S', ..] => "audio/ogg",
        [b'I', b'D', b'3', ..] | [0xFF, 0xFB, ..] | [0xFF, 0xF3, ..] | [0xFF, 0xF2, ..] => {
            "audio/mpeg"
        }
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'A', b'V', b'E', ..] => "audio/wav",
        _ => "application/octet-stream",
    }
}

/// Best-effort MIME for any received file, from magic bytes.
fn sniff_mime(b: &[u8]) -> &'static str {
    match b {
        [0x89, b'P', b'N', b'G', ..] => "image/png",
        [0xFF, 0xD8, 0xFF, ..] => "image/jpeg",
        [b'G', b'I', b'F', b'8', ..] => "image/gif",
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => "image/webp",
        [0x25, 0x50, 0x44, 0x46, ..] => "application/pdf",
        _ => "application/octet-stream",
    }
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || s.is_empty() {
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

/// Minimal `application/x-www-form-urlencoded` value decode (`+` and `%XX`).
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let h = (b[i + 1] as char).to_digit(16);
                let l = (b[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (h, l) {
                    out.push(((h << 4) | l) as u8);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
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

/// Completes on the first SIGINT (ctrl-c) or, on unix, SIGTERM.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
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
/// was already loaded; `None` starts the page in onboarding mode. Binds
/// `http_addr` and serves forever.
pub async fn run(existing: Option<Engine>, http_addr: &str, boot: Bootstrap) -> Result<()> {
    let listener = TcpListener::bind(http_addr)
        .await
        .with_context(|| format!("binding {http_addr}"))?;
    run_on(existing, listener, boot).await
}

/// Like [`run`] but takes an already-bound listener — the desktop shell binds
/// an ephemeral port first so it can point the webview at it.
pub async fn run_on(
    existing: Option<Engine>,
    listener: TcpListener,
    boot: Bootstrap,
) -> Result<()> {
    let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>(32);
    let bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let local_authorities = loopback_authorities(bound_port);
    let shared = Arc::new(Shared {
        inbox: Mutex::new(VecDeque::new()),
        channels: Mutex::new(Vec::new()),
        typing: Mutex::new(Vec::new()),
        reactions: Mutex::new(std::collections::HashMap::new()),
        calls: Mutex::new(std::collections::HashMap::new()),
        group_calls: Mutex::new(std::collections::HashMap::new()),
        voice: Mutex::new(std::collections::HashMap::new()),
        recv_files: Mutex::new((
            std::collections::VecDeque::new(),
            std::collections::HashMap::new(),
        )),
        next_seq: AtomicU64::new(0),
        me: Mutex::new((String::new(), String::new())),
        onboard_name: Mutex::new(String::new()),
        my_name: Mutex::new(String::new()),
        ready: AtomicBool::new(false),
        embeds: AtomicBool::new(false),
        cmd: cmd_tx,
        boot,
        pending_rx: Mutex::new(Some(cmd_rx)),
        local_authorities,
    });

    let http_addr = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "127.0.0.1:?".into());

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
            let peer = short_fp(&h.peer_idk);
            inbox.push_back(match &h.kind {
                dante_core::HistoryKind::Text(t) => Item::Message {
                    seq,
                    from,
                    text: t.clone(),
                    peer,
                    msg_id: if h.msg_id == [0u8; 16] {
                        String::new()
                    } else {
                        to_hex(&h.msg_id)
                    },
                },
                dante_core::HistoryKind::File { filename, size } => Item::File {
                    seq,
                    from,
                    filename: filename.clone(),
                    size: *size as usize,
                    saved: String::new(),
                    url: String::new(),
                    mime: String::new(),
                },
            });
        }
        for e in engine.dm_edit_snapshot() {
            inbox.push_back(Item::DmEdit {
                seq: engine_shared.next(),
                peer: short_fp(&e.peer_idk),
                msg_id: to_hex(&e.msg_id),
                text: e.text.unwrap_or_default(),
                deleted: e.deleted,
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
                // Persisted now, so a replayed message keeps the id reactions,
                // pins and edits key on — and the reply / forward framing.
                ref_seq: e.seq,
                reply_to: e.reply_to,
                forwarded_from: e.forwarded_from.clone(),
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

    // Seed the SPA with any edits/deletes made before this restart.
    {
        let mut inbox = engine_shared.inbox.lock().await;
        for e in engine.edit_snapshot() {
            inbox.push_back(Item::ChannelEdit {
                seq: engine_shared.next(),
                channel: id_b32(&e.channel_id),
                ref_seq: e.target_seq,
                text: e.text.unwrap_or_default(),
                deleted: e.deleted,
            });
        }
        for p in engine.pin_snapshot() {
            inbox.push_back(Item::ChannelPin {
                seq: engine_shared.next(),
                channel: id_b32(&p.channel_id),
                ref_seq: p.target_seq,
                by: short_id(&p.by),
                at_ms: p.at_ms,
                pinned: p.pinned,
            });
        }
    }

    eprintln!("announcing to the relay ...");
    let onboard_name = engine_shared.onboard_name.lock().await.clone();
    let progress = engine_shared.boot.progress.clone();
    let step = |s: dante_core::BootStep| {
        if let Some(p) = &progress {
            p(s);
        }
    };
    if let Err(e) = async {
        step(dante_core::BootStep::Announcing {
            pow_bits: engine_shared.boot.pow.bits,
        });
        engine.announce_if_stale(&onboard_name, now_ms()).await?;
        step(dante_core::BootStep::PublishingPrekeys);
        engine.publish_prekeys().await?;
        step(dante_core::BootStep::Syncing);
        engine.sync(now_ms()).await?;
        Ok::<_, dante_core::CoreError>(())
    }
    .await
    {
        eprintln!("engine startup error: {e}");
        // The client stays up: most of the app works against local state, and
        // the tick loop keeps retrying. Say what broke rather than hanging on
        // a spinner that will never finish.
        step(dante_core::BootStep::Failed {
            error: e.to_string(),
        });
    } else {
        eprintln!("ready");
        step(dante_core::BootStep::Ready);
    }
    if let Some(name) = engine.my_username() {
        *engine_shared.my_name.lock().await = name;
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

            _ = shutdown_signal() => {
                match engine.persist() {
                    Ok(()) => eprintln!("state flushed; shutting down"),
                    Err(e) => eprintln!("WARNING: could not flush state on shutdown: {e}"),
                }
                std::process::exit(0);
            }

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
                #[cfg(feature = "p2p")]
                let _ = engine.poll_p2p(now).await;
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
                            reply_to: m.reply_to,
                            forwarded_from: m.forwarded_from,
                        });
                        while inbox.len() > INBOX_CAP { inbox.pop_front(); }
                    }
                }

                // The host removed us from a channel — tell the SPA to drop it
                // and post a notice.
                {
                    let evicted = engine.take_evicted_channels();
                    if !evicted.is_empty() {
                        // A server kick evicts many channels at once — one
                        // notice per server, not per channel.
                        let mut by_server: std::collections::HashMap<[u8; 32], String> =
                            std::collections::HashMap::new();
                        for (_cid, root, name) in evicted {
                            by_server.entry(root).or_insert(name);
                        }
                        let mut inbox = engine_shared.inbox.lock().await;
                        for (root, name) in by_server {
                            let where_ = if name.is_empty() {
                                format!("server {}", &id_b32(&root)[..9])
                            } else {
                                format!("{name} ({})", &id_b32(&root)[..9])
                            };
                            inbox.push_back(Item::Notice {
                                seq: engine_shared.next(),
                                tag: "kicked".into(),
                                text: format!("You were removed from {where_}."),
                                scope: id_b32(&root),
                            });
                        }
                        while inbox.len() > INBOX_CAP { inbox.pop_front(); }
                        drop(inbox);
                        refresh_channels(&engine, &engine_shared).await;
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

                {
                    let edits = engine.take_edits();
                    if !edits.is_empty() {
                        let mut inbox = engine_shared.inbox.lock().await;
                        for e in edits {
                            inbox.push_back(Item::ChannelEdit {
                                seq: engine_shared.next(),
                                channel: id_b32(&e.channel_id),
                                ref_seq: e.target_seq,
                                text: e.text.unwrap_or_default(),
                                deleted: e.deleted,
                            });
                            while inbox.len() > INBOX_CAP { inbox.pop_front(); }
                        }
                    }
                }

                {
                    let pins = engine.take_pins();
                    if !pins.is_empty() {
                        let mut inbox = engine_shared.inbox.lock().await;
                        for p in pins {
                            inbox.push_back(Item::ChannelPin {
                                seq: engine_shared.next(),
                                channel: id_b32(&p.channel_id),
                                ref_seq: p.target_seq,
                                by: short_id(&p.by),
                                at_ms: p.at_ms,
                                pinned: p.pinned,
                            });
                            while inbox.len() > INBOX_CAP { inbox.pop_front(); }
                        }
                    }
                }

                {
                    let dm_edits = engine.take_dm_edits();
                    if !dm_edits.is_empty() {
                        let mut inbox = engine_shared.inbox.lock().await;
                        for e in dm_edits {
                            inbox.push_back(Item::DmEdit {
                                seq: engine_shared.next(),
                                peer: short_fp(&e.peer_idk),
                                msg_id: to_hex(&e.msg_id),
                                text: e.text.unwrap_or_default(),
                                deleted: e.deleted,
                            });
                            while inbox.len() > INBOX_CAP { inbox.pop_front(); }
                        }
                    }
                }

                if let Ok(items) = engine.receive_all(now).await {
                    let mut inbox = engine_shared.inbox.lock().await;
                    for it in items {
                        // Backlog expands to one Item::Channel per message.
                        if let Inbound::ChannelBacklog { channel_id, entries } = it {
                            let ch = id_b32(&channel_id);
                            let me = *engine.identity().id().as_bytes();
                            for e in entries {
                                inbox.push_back(Item::Channel {
                                    seq: engine_shared.next(),
                                    channel: ch.clone(),
                                    channel_name: String::new(),
                                    from: if e.sender == me {
                                        "you".into()
                                    } else {
                                        short_id(&e.sender)
                                    },
                                    text: e.text,
                                    // Carries the relay-log seq now, so a
                                    // backfilled line gets the same hover
                                    // actions as a live one.
                                    ref_seq: e.seq,
                                    reply_to: None,
                                    forwarded_from: None,
                                });
                            }
                            while inbox.len() > INBOX_CAP { inbox.pop_front(); }
                            continue;
                        }
                        let seq = engine_shared.next();
                        let entry = match it {
                            Inbound::Message(m) => {
                                let from = short_fp(&m.from_idk);
                                last_msg_ms.insert(from.clone(), now);
                                Item::Message {
                                    seq,
                                    from: from.clone(),
                                    text: m.text,
                                    peer: from,
                                    msg_id: if m.msg_id == [0u8; 16] {
                                        String::new()
                                    } else {
                                        to_hex(&m.msg_id)
                                    },
                                }
                            }
                            Inbound::File { from_idk, filename, data } => {
                                // Held in memory and served back over
                                // /api/recv-file; deliberately NOT written to
                                // disk. This is a privacy tool — an incoming
                                // file must not silently land as plaintext in
                                // the working directory, where it outlives the
                                // session and is trivially recoverable.
                                let mime = sniff_mime(&data).to_owned();
                                let id = to_hex(&dante_crypto::hash::sha256(&data))[..16].to_owned();
                                {
                                    let mut rf = engine_shared.recv_files.lock().await;
                                    if !rf.1.contains_key(&id) {
                                        rf.1.insert(id.clone(), (mime.clone(), data.clone()));
                                        rf.0.push_back(id.clone());
                                        while rf.0.len() > 48 {
                                            if let Some(old) = rf.0.pop_front() { rf.1.remove(&old); }
                                        }
                                    }
                                }
                                let from = short_fp(&from_idk);
                                last_msg_ms.insert(from.clone(), now);
                                Item::File {
                                    seq, from, filename, size: data.len(), saved: String::new(),
                                    url: format!("/api/recv-file?id={id}"), mime,
                                }
                            }
                            Inbound::IncomingCall { from_idk } => {
                                let fp = short_fp(&from_idk);
                                engine_shared.calls.lock().await.insert(
                                    fp.clone(),
                                    CallRow { peer: fp.clone(), state: "ringing".into(), incoming: true },
                                );
                                Item::Message { seq, from: fp.clone(), text: "\u{1f4de} incoming call".into(), peer: fp, msg_id: String::new() }
                            }
                            Inbound::CallEnded { from_idk } => {
                                let fp = short_fp(&from_idk);
                                engine_shared.calls.lock().await.remove(&fp);
                                Item::Message { seq, from: fp.clone(), text: "\u{1f4de} call ended".into(), peer: fp, msg_id: String::new() }
                            }
                            Inbound::GroupCallInvite { channel_id, from_idk } => {
                                let fp = short_fp(&from_idk);
                                let key = id_b32(&channel_id);
                                engine_shared.group_calls.lock().await.insert(
                                    key.clone(),
                                    GroupCallRow {
                                        channel: key,
                                        channel_name: String::new(),
                                        joined: false,
                                        participants: Vec::new(),
                                        invited_by: Some(fp.clone()),
                                    },
                                );
                                Item::Message { seq, from: fp.clone(), text: "\u{1f4de} group call invite".into(), peer: fp, msg_id: String::new() }
                            }
                            Inbound::GroupCallMembersChanged { channel_id } => {
                                Item::Channel {
                                    seq,
                                    channel: id_b32(&channel_id),
                                    channel_name: String::new(),
                                    from: "system".into(),
                                    text: "\u{1f4de} group call membership changed".into(),
                                    ref_seq: 0,
                                    reply_to: None,
                                    forwarded_from: None,
                                }
                            }
                            Inbound::VoiceSignal { channel_id, from_idk, kind, data } => {
                                Item::VoiceSignal {
                                    seq,
                                    channel: id_b32(&channel_id),
                                    from: short_fp(&from_idk),
                                    sig_kind: kind,
                                    data,
                                }
                            }
                            Inbound::CallSignal { from_idk, kind, data } => {
                                Item::CallSignal {
                                    seq,
                                    from: short_fp(&from_idk),
                                    sig_kind: kind,
                                    data,
                                }
                            }
                            Inbound::ChannelInvite {
                                channel_id, from_idk, channel_name, server_name,
                            } => {
                                let who = short_fp(&from_idk);
                                Item::Notice {
                                    seq,
                                    tag: "invite".into(),
                                    text: format!(
                                        "{who} invited you to #{channel_name} in {server_name}"
                                    ),
                                    scope: id_b32(&channel_id),
                                }
                            }
                            Inbound::ChannelBacklog { .. } => unreachable!("handled above"),
                        };
                        inbox.push_back(entry);
                        while inbox.len() > INBOX_CAP { inbox.pop_front(); }
                    }
                }

                if let Ok(updates) = engine.poll_calls(now).await {
                    if !updates.is_empty() {
                        let mut calls = engine_shared.calls.lock().await;
                        for u in updates {
                            let fp = id_b32(&u.peer);
                            let state = format!("{:?}", u.state).to_lowercase();
                            let incoming = calls.get(&fp).map(|c| c.incoming).unwrap_or(false);
                            if state == "closed" {
                                calls.remove(&fp);
                            } else {
                                calls.insert(fp.clone(), CallRow { peer: fp, state, incoming });
                            }
                        }
                    }
                }

                let _ = engine.poll_group_calls(now).await;
                refresh_group_calls(&engine, &engine_shared).await;
                // Keep the member roster / channel list fresh every tick (a
                // membership Commit changes it without any explicit command).
                refresh_channels(&engine, &engine_shared).await;

                // Voice channels: beacon our presence, then refresh who's in each.
                let _ = engine.send_voice_presence(now).await;
                {
                    let vp = engine.poll_voice(now).await;
                    let mut rooms = engine_shared.voice.lock().await;
                    rooms.clear();
                    for p in vp {
                        rooms.insert(
                            id_b32(&p.channel_id),
                            VoiceRoom {
                                joined: engine.in_group_call(&p.channel_id),
                                participants: p.members.iter().map(short_id).collect(),
                            },
                        );
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
            voice: c.voice,
            members: engine
                .channel_roster(&c.channel_id)
                .iter()
                .map(id_b32)
                .collect(),
        })
        .collect();
    *shared.channels.lock().await = views;
}

/// Rebuild the group-call panel from live engine state. Rows the engine no
/// longer knows (call ended, invite consumed) are dropped; `invited_by` set by
/// the inbound handler is preserved.
async fn refresh_group_calls(engine: &Engine, shared: &Shared) {
    let names: std::collections::HashMap<[u8; 32], String> = engine
        .channels()
        .into_iter()
        .map(|c| (c.channel_id, c.channel_name))
        .collect();
    let mut rows = shared.group_calls.lock().await;
    let mut live: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (cid, name) in &names {
        if engine.in_group_call(cid) {
            let key = id_b32(cid);
            live.insert(key.clone());
            rows.insert(
                key.clone(),
                GroupCallRow {
                    channel: key,
                    channel_name: name.clone(),
                    joined: true,
                    participants: engine.group_call_peers(cid).iter().map(short_id).collect(),
                    invited_by: None,
                },
            );
        }
    }
    for cid in engine.pending_group_call_channels() {
        if engine.in_group_call(&cid) {
            continue;
        }
        let key = id_b32(&cid);
        live.insert(key.clone());
        let name = names.get(&cid).cloned().unwrap_or_default();
        rows.entry(key.clone())
            .and_modify(|r| {
                r.channel_name = name.clone();
                r.joined = false;
            })
            .or_insert(GroupCallRow {
                channel: key,
                channel_name: name,
                joined: false,
                participants: Vec::new(),
                invited_by: None,
            });
    }
    rows.retain(|k, _| live.contains(k));
}

/// Quick refresh of just the `joined` flag for each voice room (no relay round
/// trip). The participant lists are filled in by the tick loop's `poll_voice`.
async fn refresh_voice(engine: &Engine, shared: &Shared) {
    let voice: Vec<[u8; 32]> = engine
        .channels()
        .into_iter()
        .filter(|c| c.voice)
        .map(|c| c.channel_id)
        .collect();
    let mut rooms = shared.voice.lock().await;
    rooms.retain(|k, _| voice.iter().any(|c| id_b32(c) == *k));
    for c in &voice {
        rooms.entry(id_b32(c)).or_default().joined = engine.in_group_call(c);
    }
}

/// Re-mint a TURN credential once it is within this of expiring.
const ICE_REFRESH_MARGIN_SECS: u64 = 300;

/// Whether the ICE config is worth re-fetching from the relay.
///
/// A TURN credential is a coturn `use-auth-secret` token whose username is its
/// Unix-seconds expiry, so we can tell locally whether the one we hold still
/// has life in it. Only that case is worth a round trip:
///
/// - STUN never expires, so a STUN-only config is never re-fetched.
/// - An *empty* config is never re-fetched either. `Engine::connect` already
///   asked, and a relay with no ICE policy would answer empty every time —
///   which would put a relay round trip on every single call start, and with
///   it the risk of stalling the serialized engine loop behind an
///   unresponsive relay. A relay that gains a TURN config is picked up on the
///   next connect.
fn ice_needs_refresh(servers: &[dante_core::IceServer], now_secs: u64) -> bool {
    servers.iter().any(|s| {
        !s.username.is_empty()
            && s.username
                .parse::<u64>()
                .map_or(true, |expiry| expiry <= now_secs + ICE_REFRESH_MARGIN_SECS)
    })
}

/// The `GET /api/ice` body: the ICE servers the page hands `RTCPeerConnection`.
///
/// TURN rows carry their credentials. Without them a browser can only gather
/// host and srflx candidates, so a call between two peers behind symmetric NAT
/// never connects. The page already drives the whole engine over this
/// localhost API, and the credential is a short-lived coturn token that grants
/// nothing but relayed media, so exposing it here adds no authority.
fn ice_json(servers: &[dante_core::IceServer]) -> String {
    let rows: Vec<_> = servers
        .iter()
        .map(|s| {
            serde_json::json!({
                "urls": s.urls,
                "kind": if s.username.is_empty() { "stun" } else { "turn" },
                "username": s.username,
                "credential": s.credential,
            })
        })
        .collect();
    serde_json::Value::Array(rows).to_string()
}

async fn handle_cmd(engine: &mut Engine, shared: &Shared, cmd: Cmd) {
    match cmd {
        Cmd::Send {
            to,
            text,
            reply_to: send_reply_to,
            reply,
        } => {
            let mut channel_seq: Option<u64> = None;
            let r = match parse_target(&to) {
                Ok((true, id)) => {
                    let sent = match send_reply_to {
                        Some(t) => engine.send_channel_reply(&id, t, &text, now_ms()).await,
                        None => engine.send_channel(&id, &text, now_ms()).await,
                    };
                    match sent {
                        Ok(seq) => {
                            channel_seq = Some(seq);
                            Ok("ok".into())
                        }
                        Err(e) => Err(e.to_string()),
                    }
                }
                Ok((false, id)) => engine
                    .send_dm(&id, &text, now_ms())
                    .await
                    .map(|mid| to_hex(&mid))
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
                            ref_seq: channel_seq.unwrap_or(0),
                            reply_to: send_reply_to,
                            forwarded_from: None,
                        });
                    }
                }
            }
            let _ = reply.send(r);
        }
        Cmd::EditMsg {
            channel,
            seq,
            text,
            reply,
        } => {
            let channel = channel.strip_prefix('#').unwrap_or(&channel).to_string();
            let r = match parse_fingerprint(&channel) {
                Ok(cid) => {
                    let res = if text.is_empty() {
                        engine.delete_channel_message(&cid, seq, now_ms()).await
                    } else {
                        engine
                            .edit_channel_message(&cid, seq, &text, now_ms())
                            .await
                    };
                    res.map(|_| "ok".into()).map_err(|e| e.to_string())
                }
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::DmEdit {
            peer,
            msg_id,
            text,
            reply,
        } => {
            let r = match (parse_fingerprint(&peer), hex_bytes(&msg_id)) {
                (Ok(pid), Some(mid)) if mid.len() == 16 => {
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&mid);
                    let res = if text.is_empty() {
                        engine.delete_dm(&pid, &id, now_ms()).await
                    } else {
                        engine.edit_dm(&pid, &id, &text, now_ms()).await
                    };
                    res.map(|_| "ok".into()).map_err(|e| e.to_string())
                }
                _ => Err("bad peer or message id".to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::Forward {
            to,
            origin,
            text,
            reply,
        } => {
            let mut chan_echo: Option<([u8; 32], u64)> = None;
            let r = match parse_target(&to) {
                Ok((true, cid)) => match engine
                    .forward_to_channel(&cid, &origin, &text, now_ms())
                    .await
                {
                    Ok(seq) => {
                        chan_echo = Some((cid, seq));
                        Ok("ok".to_string())
                    }
                    Err(e) => Err(e.to_string()),
                },
                Ok((false, id)) => {
                    let body = format!("\u{21aa} Forwarded from {origin}\n{text}");
                    engine
                        .send_dm(&id, &body, now_ms())
                        .await
                        .map(|mid| to_hex(&mid))
                        .map_err(|e| e.to_string())
                }
                Err(e) => Err(e),
            };
            if let Some((cid, seq)) = chan_echo {
                shared.inbox.lock().await.push_back(Item::Channel {
                    seq: shared.next(),
                    channel: id_b32(&cid),
                    channel_name: String::new(),
                    from: "you".into(),
                    text: text.clone(),
                    ref_seq: seq,
                    reply_to: None,
                    forwarded_from: Some(origin.clone()),
                });
            }
            let _ = reply.send(r);
        }
        Cmd::SendFile {
            peer,
            filename,
            data,
            reply,
        } => {
            // No echo: the SPA renders the outgoing file optimistically, like a
            // sent DM text (serve only echoes channel messages).
            let r = match parse_fingerprint(&peer) {
                Ok(id) => engine
                    .send_file(&id, &filename, &data, now_ms())
                    .await
                    .map(|_| "ok".into())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::Pin {
            channel,
            seq,
            pinned,
            reply,
        } => {
            let channel = channel.strip_prefix('#').unwrap_or(&channel).to_string();
            let r = match parse_fingerprint(&channel) {
                Ok(cid) => {
                    let res = if pinned {
                        engine.pin_channel_message(&cid, seq, now_ms()).await
                    } else {
                        engine.unpin_channel_message(&cid, seq, now_ms()).await
                    };
                    res.map(|_| "ok".into()).map_err(|e| e.to_string())
                }
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::Pins { channel, reply } => {
            let pins: Vec<serde_json::Value> = engine
                .pinned_messages(&channel)
                .into_iter()
                .map(|p| {
                    serde_json::json!({
                        "ref_seq": p.target_seq,
                        "by": short_id(&p.by),
                        "at_ms": p.at_ms,
                    })
                })
                .collect();
            let _ = reply.send(serde_json::to_string(&pins).unwrap_or_else(|_| "[]".into()));
        }
        Cmd::P2pInfo { reply } => {
            #[cfg(feature = "p2p")]
            let body = match engine.p2p_peer_id() {
                Some(pid) => serde_json::json!({
                    "enabled": true,
                    "peer_id": pid,
                    "dial_addrs": engine.p2p_dial_addrs(),
                })
                .to_string(),
                None => "{\"enabled\":false}".to_string(),
            };
            #[cfg(not(feature = "p2p"))]
            let body = {
                let _ = &engine;
                "{\"enabled\":false,\"built\":false}".to_string()
            };
            let _ = reply.send(body);
        }
        Cmd::CreateServer {
            name,
            password,
            reply,
        } => {
            let r = async {
                let root = engine
                    .create_server(&name, now_ms())
                    .await
                    .map_err(|e| e.to_string())?;
                // Every server starts with a #general text channel that can't be
                // removed or converted — the always-there default.
                engine
                    .create_channel(&root, "general", true, None)
                    .map_err(|e| e.to_string())?;
                if !password.is_empty() {
                    engine
                        .set_join_password(&root, Some(password.as_str()), None)
                        .map_err(|e| e.to_string())?;
                }
                Ok::<_, String>(id_b32(&root))
            }
            .await;
            let _ = reply.send(r);
        }
        Cmd::CreateChannel {
            server,
            name,
            voice,
            reply,
        } => {
            let r = match parse_fingerprint(&server) {
                Ok(root) if voice => engine
                    .create_voice_channel(&root, &name, true)
                    .map(|id| id_b32(&id))
                    .map_err(|e| e.to_string()),
                Ok(root) => engine
                    .create_channel(&root, &name, true, None)
                    .map(|id| id_b32(&id))
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::RenameChannel {
            channel,
            name,
            reply,
        } => {
            let channel = channel.strip_prefix('#').unwrap_or(&channel);
            let r = match parse_fingerprint(channel) {
                Ok(cid) => engine
                    .rename_channel(&cid, &name, now_ms())
                    .await
                    .map(|_| "ok".into())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            refresh_channels(engine, shared).await;
            let _ = reply.send(r);
        }
        Cmd::Voice {
            channel,
            join,
            reply,
        } => {
            let channel = channel.strip_prefix('#').unwrap_or(&channel).to_string();
            let r = match parse_fingerprint(&channel) {
                Ok(cid) => {
                    let res = if join {
                        engine.join_voice_channel(&cid, now_ms()).await
                    } else {
                        engine.leave_voice_channel(&cid, now_ms()).await
                    };
                    res.map(|_| "ok".into()).map_err(|e| e.to_string())
                }
                Err(e) => Err(e.to_string()),
            };
            refresh_voice(engine, shared).await;
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
        Cmd::InviteRespond {
            channel,
            accept,
            reply,
        } => {
            let channel = channel.strip_prefix('#').unwrap_or(&channel);
            let r = match parse_fingerprint(channel) {
                Ok(cid) => {
                    let res = if accept {
                        engine.accept_channel_invite(&cid, now_ms()).await
                    } else {
                        engine.decline_channel_invite(&cid, now_ms()).await
                    };
                    res.map(|_| "ok".into()).map_err(|e| e.to_string())
                }
                Err(e) => Err(e.to_string()),
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
            current,
            reply,
        } => {
            let r = match parse_fingerprint(&server) {
                Ok(root) => engine
                    .set_join_password(
                        &root,
                        (!password.is_empty()).then_some(password.as_str()),
                        (!current.is_empty()).then_some(current.as_str()),
                    )
                    .map(|_| "ok".into())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::VoiceSignal {
            channel,
            to,
            kind,
            data,
            reply,
        } => {
            let channel = channel.strip_prefix('#').unwrap_or(&channel);
            let r = match (parse_fingerprint(channel), parse_fingerprint(&to)) {
                (Ok(cid), Ok(pid)) => engine
                    .send_voice_signal(&pid, &cid, kind, &data, now_ms())
                    .await
                    .map(|_| "ok".into())
                    .map_err(|e| e.to_string()),
                _ => Err("bad channel id or fingerprint".into()),
            };
            let _ = reply.send(r);
        }
        Cmd::CallSignal {
            to,
            kind,
            data,
            reply,
        } => {
            let r = match parse_fingerprint(&to) {
                Ok(pid) => engine
                    .send_call_signal(&pid, kind, &data, now_ms())
                    .await
                    .map(|_| "ok".into())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::RemoveMember {
            channel,
            member,
            ban,
            reply,
        } => {
            let channel = channel.strip_prefix('#').unwrap_or(&channel);
            let r = match (parse_fingerprint(channel), parse_fingerprint(&member)) {
                (Ok(cid), Ok(mid)) => engine
                    .request_kick(&cid, &mid, ban, now_ms())
                    .await
                    .map(|_| "ok".into())
                    .map_err(|e| e.to_string()),
                _ => Err("bad channel id or fingerprint".into()),
            };
            let _ = reply.send(r);
        }
        Cmd::Unban {
            server,
            member,
            reply,
        } => {
            let r = match (parse_fingerprint(&server), parse_fingerprint(&member)) {
                (Ok(sr), Ok(mid)) => {
                    engine.unban_from_server(&sr, &mid);
                    Ok("ok".into())
                }
                _ => Err("bad server root or fingerprint".into()),
            };
            let _ = reply.send(r);
        }
        Cmd::ServerBans { server, reply } => {
            let list: Vec<String> = match parse_fingerprint(&server) {
                Ok(sr) => engine.server_bans(&sr).iter().map(id_b32).collect(),
                Err(_) => vec![],
            };
            let _ = reply.send(serde_json::to_string(&list).unwrap_or_else(|_| "[]".into()));
        }
        Cmd::SetRole {
            server,
            id,
            name,
            allow,
            deny,
            rank,
            icon,
            reply,
        } => {
            let r = match parse_fingerprint(&server) {
                Ok(root) => engine
                    .set_role(
                        &root,
                        id,
                        &name,
                        allow,
                        deny,
                        rank,
                        icon.as_deref(),
                        now_ms(),
                    )
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
        Cmd::SetNickname {
            server,
            member,
            nickname,
            reply,
        } => {
            let r = match (parse_fingerprint(&server), parse_fingerprint(&member)) {
                (Ok(root), Ok(mid)) => {
                    let nick = (!nickname.is_empty()).then_some(nickname.as_str());
                    engine
                        .set_member_nickname(&root, &mid, nick, now_ms())
                        .await
                        .map(|_| "ok".into())
                        .map_err(|e| e.to_string())
                }
                _ => Err("bad server root or fingerprint".into()),
            };
            let _ = reply.send(r);
        }
        Cmd::RequestNickname {
            server,
            nickname,
            reply,
        } => {
            let r = match parse_fingerprint(&server) {
                // `request_nickname` is channel-scoped because the engine
                // resolves the server through a channel we belong to; any of
                // our channels on that server will do.
                Ok(root) => match engine
                    .channels()
                    .into_iter()
                    .find(|c| c.server_root == root)
                {
                    Some(chan) => {
                        let nick = (!nickname.is_empty()).then_some(nickname.as_str());
                        engine
                            .request_nickname(&chan.channel_id, nick, now_ms())
                            .await
                            .map(|_| "ok".into())
                            .map_err(|e| e.to_string())
                    }
                    None => Err("not a member of any channel on that server".into()),
                },
                Err(_) => Err("bad server root".into()),
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
        Cmd::Usernames { reply } => {
            // Keep our own cached name fresh once the ledger has caught up.
            if let Some(name) = engine.my_username() {
                *shared.my_name.lock().await = name;
            }
            let map: serde_json::Map<String, serde_json::Value> = engine
                .known_usernames()
                .into_iter()
                .map(|(id, name)| (id_b32(&id), serde_json::Value::String(name)))
                .collect();
            let _ = reply.send(serde_json::Value::Object(map).to_string());
        }
        Cmd::Avatars { reply } => {
            let map: serde_json::Map<String, serde_json::Value> = engine
                .known_avatars()
                .into_iter()
                .map(|(id, hash)| (id_b32(&id), serde_json::Value::String(to_hex(&hash))))
                .collect();
            let _ = reply.send(serde_json::Value::Object(map).to_string());
        }
        Cmd::PendingInvites { reply } => {
            let list: Vec<_> = engine
                .pending_channel_invites()
                .into_iter()
                .map(|(cid, cn, sn)| {
                    serde_json::json!({
                        "channel": id_b32(&cid),
                        "channel_name": cn,
                        "server_name": sn,
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
                                "icon": r.icon,
                            })
                        })
                        .collect();
                    let assignments: Vec<_> = p
                        .assignments
                        .iter()
                        .map(|(m, ids)| serde_json::json!({ "member": id_b32(m), "roles": ids }))
                        .collect();
                    let me = *engine.identity().id().as_bytes();
                    let emojis: Vec<_> = p
                        .emojis
                        .iter()
                        .map(|(n, h)| serde_json::json!({ "name": n, "hash": to_hex(h) }))
                        .collect();
                    let stickers: Vec<_> = p
                        .stickers
                        .iter()
                        .map(|(n, h)| serde_json::json!({ "name": n, "hash": to_hex(h) }))
                        .collect();
                    let sounds: Vec<_> = p
                        .sounds
                        .iter()
                        .map(|(n, h)| serde_json::json!({ "name": n, "hash": to_hex(h) }))
                        .collect();
                    let nicknames: serde_json::Map<String, serde_json::Value> = p
                        .nicknames
                        .iter()
                        .map(|(m, n)| (id_b32(m), serde_json::Value::String(n.clone())))
                        .collect();
                    serde_json::json!({
                        "version": p.version,
                        "owner": id_b32(&p.owner_id),
                        "roles": roles,
                        "assignments": assignments,
                        "emojis": emojis,
                        "stickers": stickers,
                        "sounds": sounds,
                        "nicknames": nicknames,
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
        Cmd::Emoji {
            server,
            name,
            image,
            reply,
        } => {
            let r = match parse_fingerprint(&server) {
                Ok(sr) => match image {
                    Some(bytes) => engine
                        .set_server_emoji(&sr, &name, &bytes, now_ms())
                        .await
                        .map(|_| "ok".into())
                        .map_err(|e| e.to_string()),
                    None => engine
                        .remove_server_emoji(&sr, &name, now_ms())
                        .await
                        .map(|_| "ok".into())
                        .map_err(|e| e.to_string()),
                },
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::GetEmoji { hash, reply } => {
            let blob = engine.fetch_blob(&hash).await.ok().flatten();
            let _ = reply.send(blob);
        }
        Cmd::Sticker {
            server,
            name,
            image,
            reply,
        } => {
            let r = match parse_fingerprint(&server) {
                Ok(sr) => match image {
                    Some(bytes) => engine
                        .set_server_sticker(&sr, &name, &bytes, now_ms())
                        .await
                        .map(|_| "ok".into())
                        .map_err(|e| e.to_string()),
                    None => engine
                        .remove_server_sticker(&sr, &name, now_ms())
                        .await
                        .map(|_| "ok".into())
                        .map_err(|e| e.to_string()),
                },
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::Sound {
            server,
            name,
            audio,
            reply,
        } => {
            let r = match parse_fingerprint(&server) {
                Ok(sr) => match audio {
                    Some(bytes) => engine
                        .set_server_sound(&sr, &name, &bytes, now_ms())
                        .await
                        .map(|_| "ok".into())
                        .map_err(|e| e.to_string()),
                    None => engine
                        .remove_server_sound(&sr, &name, now_ms())
                        .await
                        .map(|_| "ok".into())
                        .map_err(|e| e.to_string()),
                },
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::Contacts { reply } => {
            let rows: Vec<_> = engine
                .contacts()
                .into_iter()
                .map(|(id, c)| {
                    serde_json::json!({
                        "fp": id_b32(&id),
                        "petname": c.petname,
                        "added_ms": c.added_ms,
                        "verified": engine.is_verified(&id),
                    })
                })
                .collect();
            let _ = reply.send(serde_json::Value::Array(rows).to_string());
        }
        Cmd::AddContact {
            peer,
            petname,
            reply,
        } => {
            let r = match parse_fingerprint(&peer) {
                Ok(id) => {
                    engine.add_contact(&id, &petname, now_ms());
                    Ok("ok".into())
                }
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::RemoveContact { peer, reply } => {
            let r = match parse_fingerprint(&peer) {
                Ok(id) => {
                    engine.remove_contact(&id);
                    Ok("ok".into())
                }
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::Leave { channel, reply } => {
            let channel = channel.strip_prefix('#').unwrap_or(&channel);
            let r = match parse_fingerprint(channel) {
                Ok(cid) => engine
                    .leave_channel(&cid, now_ms())
                    .await
                    .map(|_| "ok".into())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::Delete {
            channel,
            server,
            reply,
        } => {
            let r = if !server.is_empty() {
                match parse_fingerprint(&server) {
                    Ok(sr) => engine
                        .delete_server(&sr, now_ms())
                        .await
                        .map(|_| "ok".into())
                        .map_err(|e| e.to_string()),
                    Err(e) => Err(e.to_string()),
                }
            } else {
                let channel = channel.strip_prefix('#').unwrap_or(&channel);
                match parse_fingerprint(channel) {
                    Ok(cid) => engine
                        .delete_channel(&cid, now_ms())
                        .await
                        .map(|_| "ok".into())
                        .map_err(|e| e.to_string()),
                    Err(e) => Err(e.to_string()),
                }
            };
            let _ = reply.send(r);
        }
        Cmd::Blocked { reply } => {
            let rows: Vec<_> = engine.blocked().into_iter().map(|id| id_b32(&id)).collect();
            let _ = reply.send(serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into()));
        }
        Cmd::Block { peer, on, reply } => {
            let r = match parse_fingerprint(&peer) {
                Ok(id) => {
                    if on {
                        engine.block(&id);
                    } else {
                        engine.unblock(&id);
                    }
                    Ok("ok".into())
                }
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::Calls { reply } => {
            let rows: Vec<_> = shared.calls.lock().await.values().cloned().collect();
            let _ = reply.send(serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into()));
        }
        Cmd::Ice { reply } => {
            // Only pay a relay round trip when the credential we hold is about
            // to lapse. This loop is serialized: a relay that accepts TCP but
            // never answers blocks every other command behind it for the
            // transport's 120s read timeout, and `/api/ice` sits on the call
            // start / voice join path. A timeout is not the fix — dropping a
            // `request` future mid-flight leaves the unread response in the
            // socket and desyncs the next one.
            if ice_needs_refresh(engine.ice_servers(), now_ms() / 1_000) {
                let _ = engine.refresh_ice_servers().await;
            }
            let _ = reply.send(ice_json(engine.ice_servers()));
        }
        Cmd::CallAudioSend {
            peer,
            frames,
            ms,
            reply,
        } => {
            let r = match parse_fingerprint(&peer) {
                Ok(id) => {
                    let mut out = Ok("ok".to_string());
                    for frame in &frames {
                        if let Err(e) = engine.send_call_audio(&id, frame, ms).await {
                            out = Err(e.to_string());
                            break;
                        }
                    }
                    out
                }
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::CallAudioRecv { peer, reply } => {
            let frames = match parse_fingerprint(&peer) {
                Ok(id) => engine
                    .take_call_audio(&id)
                    .iter()
                    .map(|f| to_hex(f))
                    .collect(),
                Err(_) => Vec::new(),
            };
            let _ = reply.send(serde_json::json!({ "frames": frames }).to_string());
        }
        Cmd::Call {
            peer,
            action,
            reply,
        } => {
            let now = now_ms();
            let r = match parse_fingerprint(&peer) {
                Ok(id) => {
                    let fp = id_b32(&id);
                    let res = match action.as_str() {
                        "start" => engine.start_call(&id, now).await,
                        "accept" => engine.accept_call(&id, now).await,
                        "hangup" => engine.hangup(&id, now).await,
                        _ => Err(dante_core::CoreError::Voice("unknown call action".into())),
                    };
                    match res {
                        Ok(()) => {
                            let mut calls = shared.calls.lock().await;
                            match action.as_str() {
                                "start" => {
                                    calls.insert(
                                        fp.clone(),
                                        CallRow {
                                            peer: fp,
                                            state: "calling".into(),
                                            incoming: false,
                                        },
                                    );
                                }
                                "accept" => {
                                    if let Some(c) = calls.get_mut(&fp) {
                                        c.state = "connecting".into();
                                        c.incoming = false;
                                    }
                                }
                                _ => {
                                    calls.remove(&fp);
                                }
                            }
                            Ok("ok".into())
                        }
                        Err(e) => Err(e.to_string()),
                    }
                }
                Err(e) => Err(e.to_string()),
            };
            let _ = reply.send(r);
        }
        Cmd::GroupCalls { reply } => {
            let rows: Vec<_> = shared.group_calls.lock().await.values().cloned().collect();
            let _ = reply.send(serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into()));
        }
        Cmd::VoiceKey { channel, reply } => {
            let channel = channel.strip_prefix('#').unwrap_or(&channel);
            let json = match parse_fingerprint(channel) {
                Ok(cid) => match (engine.group_call_key(&cid), engine.group_call_epoch(&cid)) {
                    (Some(key), Some(epoch)) => {
                        serde_json::json!({ "key": to_hex(&key), "epoch": epoch }).to_string()
                    }
                    _ => "{}".to_string(),
                },
                Err(_) => "{}".to_string(),
            };
            let _ = reply.send(json);
        }
        Cmd::Revoke { reason, reply } => {
            use dante_core::RevokeReason;
            let reason = match reason.as_str() {
                "compromised" => RevokeReason::Compromised,
                "superseded" => RevokeReason::Superseded,
                "retired" => RevokeReason::Retired,
                _ => RevokeReason::Unspecified,
            };
            let r = engine
                .revoke_identity(reason, now_ms())
                .await
                .map(|_| "ok".into())
                .map_err(|e| e.to_string());
            let _ = reply.send(r);
        }
        Cmd::Search { q, reply } => {
            let rows: Vec<_> = engine
                .search(&q, 100)
                .into_iter()
                .map(|h| {
                    serde_json::json!({
                        "channel": h.is_channel,
                        "scope": if h.is_channel { id_b32(&h.scope) } else { short_fp(&h.scope_idk) },
                        "scope_name": h.scope_name,
                        "from": if h.outgoing { "you".to_string() } else { short_id(&h.sender) },
                        "text": h.text,
                        "ts_ms": h.ts_ms,
                    })
                })
                .collect();
            let _ = reply.send(serde_json::Value::Array(rows).to_string());
        }
        Cmd::GroupCall {
            channel,
            action,
            reply,
        } => {
            let channel = channel.strip_prefix('#').unwrap_or(&channel).to_string();
            let now = now_ms();
            let r = match parse_fingerprint(&channel) {
                Ok(cid) => {
                    let res = match action.as_str() {
                        "start" => engine.start_group_call(&cid, now).await,
                        "join" => engine.join_group_call(&cid, now).await,
                        "leave" => engine.leave_group_call(&cid, now).await,
                        _ => Err(dante_core::CoreError::Voice(
                            "unknown group-call action".into(),
                        )),
                    };
                    match res {
                        Ok(()) => {
                            refresh_group_calls(engine, shared).await;
                            Ok("ok".into())
                        }
                        Err(e) => Err(e.to_string()),
                    }
                }
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

    // Reject a browser being aimed at this localhost API from another site
    // (CSRF) or via a rebound hostname (DNS rebinding) before reading any body.
    if !request_is_local(&head, method, &shared.local_authorities) {
        return respond(
            &mut stream,
            403,
            "text/plain",
            b"cross-origin request refused",
        )
        .await;
    }

    let content_length: usize = lines
        .clone()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse().ok())
        })
        .flatten()
        .unwrap_or(0);
    // `/api/file` carries raw file bytes; everything else is small JSON.
    const MAX_BODY: usize = 9 * 1024 * 1024;
    if content_length > MAX_BODY {
        return respond(&mut stream, 413, "text/plain", b"body too large").await;
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        let mut chunk = [0u8; 8192];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }

    match (method, path) {
        ("GET", "/") => {
            // Serve the SPA with a per-load nonce so its single inline <script>
            // runs under `script-src 'nonce-…'` instead of 'unsafe-inline'. An
            // injected inline script or `<img onerror=…>` then has no valid
            // nonce and is refused — defence in depth behind the input-side
            // escaping. (API/SSE responses keep the const CSP; they carry no
            // document that executes script.)
            let nonce = to_hex(&dante_crypto::random_array::<16>());
            let html = INDEX_HTML.replace("__DANTE_CSP_NONCE__", &nonce);
            let csp = format!(
                "Content-Security-Policy: default-src 'none'; script-src 'nonce-{nonce}'; \
                 style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data: blob:; \
                 media-src 'self' blob:; base-uri 'none'; form-action 'none'; \
                 frame-ancestors 'none'\r\n\
                 X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\
                 X-Frame-Options: DENY\r\n"
            );
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                 Content-Length: {}\r\n{csp}Connection: close\r\n\r\n",
                html.len()
            );
            stream.write_all(head.as_bytes()).await?;
            stream.write_all(html.as_bytes()).await?;
            stream.flush().await?;
            Ok(())
        }

        ("GET", "/api/me") => {
            let (fp, words) = shared.me.lock().await.clone();
            let username = shared.my_name.lock().await.clone();
            let body = serde_json::json!({
                "fingerprint": fp, "words": words, "username": username,
            })
            .to_string();
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("GET", "/api/usernames") => {
            let (tx, rx) = oneshot::channel();
            if shared.cmd.send(Cmd::Usernames { reply: tx }).await.is_err() {
                return respond(&mut stream, 503, "text/plain", b"engine down").await;
            }
            match rx.await {
                Ok(body) => respond(&mut stream, 200, "application/json", body.as_bytes()).await,
                Err(_) => respond(&mut stream, 503, "text/plain", b"engine down").await,
            }
        }

        ("GET", "/api/avatars") => {
            let (tx, rx) = oneshot::channel();
            if shared.cmd.send(Cmd::Avatars { reply: tx }).await.is_err() {
                return respond(&mut stream, 503, "text/plain", b"engine down").await;
            }
            match rx.await {
                Ok(body) => respond(&mut stream, 200, "application/json", body.as_bytes()).await,
                Err(_) => respond(&mut stream, 503, "text/plain", b"engine down").await,
            }
        }

        ("POST", "/api/resolve") => {
            #[derive(serde::Deserialize)]
            struct Req {
                peer: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            match parse_fingerprint(&r.peer) {
                Ok(id) => {
                    let body = serde_json::json!({ "fingerprint": id_b32(&id) }).to_string();
                    respond(&mut stream, 200, "application/json", body.as_bytes()).await
                }
                Err(_) => {
                    respond(
                        &mut stream,
                        400,
                        "text/plain",
                        b"not a valid fingerprint or 24-word phrase",
                    )
                    .await
                }
            }
        }

        ("GET", "/api/state") => {
            let ready = shared.ready.load(Ordering::Relaxed);
            let fp = shared.me.lock().await.0.clone();
            let relays: Vec<&str> = shared
                .boot
                .relay
                .split([',', ' ', '\t'])
                .filter(|s| !s.is_empty())
                .collect();
            let body = serde_json::json!({
                "ready": ready,
                "fingerprint": fp,
                "has_keystore": shared.boot.keystore_path.exists(),
                "relays": relays,
                "also_relay_listen": shared.boot.also_relay_listen,
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
                /// Chosen at registration (`create` mode); the announced
                /// display name. Ignored for unlock / import.
                #[serde(default)]
                username: String,
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
            if r.mode == "create" {
                let name: String = r.username.trim().chars().take(48).collect();
                *shared.onboard_name.lock().await = name.clone();
                *shared.my_name.lock().await = name;
            }

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
            let (text, who) = {
                let mut typing = shared.typing.lock().await;
                let now = now_ms();
                typing.retain(|(_, seen)| now.saturating_sub(*seen) <= TYPING_FRESH_MS);
                let mut who: Vec<String> = typing.iter().map(|(w, _)| w.clone()).collect();
                who.sort_unstable();
                who.dedup();
                (typing_text(&typing, now), who)
            };
            // `who` carries fingerprints so the SPA can render display names;
            // `text` stays as a fallback.
            let body = serde_json::json!({ "text": text, "who": who }).to_string();
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

        ("GET", "/api/stream") => sse_stream(&mut stream, &shared, query).await,

        ("POST", "/api/send") => {
            #[derive(serde::Deserialize)]
            struct Req {
                to: String,
                text: String,
                #[serde(default)]
                reply_to: Option<u64>,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::Send {
                to: r.to,
                text: r.text,
                reply_to: r.reply_to,
                reply,
            })
            .await
        }

        ("POST", "/api/edit") => {
            #[derive(serde::Deserialize)]
            struct Req {
                channel: String,
                seq: u64,
                /// New text; empty deletes the message.
                #[serde(default)]
                text: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::EditMsg {
                channel: r.channel,
                seq: r.seq,
                text: r.text,
                reply,
            })
            .await
        }

        ("POST", "/api/dm/edit") => {
            #[derive(serde::Deserialize)]
            struct Req {
                peer: String,
                msg_id: String,
                /// New text; empty deletes the message.
                #[serde(default)]
                text: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::DmEdit {
                peer: r.peer,
                msg_id: r.msg_id,
                text: r.text,
                reply,
            })
            .await
        }

        ("POST", "/api/forward") => {
            #[derive(serde::Deserialize)]
            struct Req {
                to: String,
                origin: String,
                text: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::Forward {
                to: r.to,
                origin: r.origin,
                text: r.text,
                reply,
            })
            .await
        }

        ("POST", "/api/file") => {
            // Raw body = file bytes; ?to=<fp>&name=<url-encoded filename>.
            let mut to = String::new();
            let mut name = String::from("file");
            for kv in query.split('&') {
                if let Some(v) = kv.strip_prefix("to=") {
                    to = percent_decode(v);
                } else if let Some(v) = kv.strip_prefix("name=") {
                    let d = percent_decode(v);
                    // display only, never a path
                    name = d
                        .rsplit(['/', '\\'])
                        .next()
                        .unwrap_or("file")
                        .replace('\0', "_");
                    if name.is_empty() {
                        name = "file".into();
                    }
                }
            }
            if body.is_empty() {
                return respond(&mut stream, 400, "text/plain", b"empty file").await;
            }
            dispatch(&mut stream, &shared, |reply| Cmd::SendFile {
                peer: to,
                filename: name,
                data: body,
                reply,
            })
            .await
        }

        ("POST", "/api/server") => {
            #[derive(serde::Deserialize)]
            struct Req {
                name: String,
                /// Optional join password for the new server.
                #[serde(default)]
                password: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::CreateServer {
                name: r.name,
                password: r.password,
                reply,
            })
            .await
        }

        ("POST", "/api/channel") => {
            #[derive(serde::Deserialize)]
            struct Req {
                server: String,
                name: String,
                /// Create a voice channel instead of a text one.
                #[serde(default)]
                voice: bool,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::CreateChannel {
                server: r.server,
                name: r.name,
                voice: r.voice,
                reply,
            })
            .await
        }

        ("POST", "/api/channel/rename") => {
            #[derive(serde::Deserialize)]
            struct Req {
                channel: String,
                name: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::RenameChannel {
                channel: r.channel,
                name: r.name,
                reply,
            })
            .await
        }

        ("GET", "/api/voice") => {
            let rooms = shared.voice.lock().await;
            let body = serde_json::to_string(&*rooms).unwrap_or_else(|_| "{}".into());
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("GET", "/api/voice/key") => {
            if !shared.ready.load(Ordering::Relaxed) {
                return respond(&mut stream, 200, "application/json", b"{}").await;
            }
            let channel = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("channel="))
                .unwrap_or("")
                .to_string();
            let (tx, rx) = oneshot::channel();
            if shared
                .cmd
                .send(Cmd::VoiceKey { channel, reply: tx })
                .await
                .is_err()
            {
                return respond(&mut stream, 500, "text/plain", b"engine gone").await;
            }
            let body = rx.await.unwrap_or_else(|_| "{}".into());
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("POST", "/api/voice/join") | ("POST", "/api/voice/leave") => {
            #[derive(serde::Deserialize)]
            struct Req {
                channel: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            let join = path.ends_with("join");
            dispatch(&mut stream, &shared, |reply| Cmd::Voice {
                channel: r.channel,
                join,
                reply,
            })
            .await
        }

        ("POST", "/api/voice/signal") => {
            #[derive(serde::Deserialize)]
            struct Req {
                channel: String,
                to: String,
                kind: u8,
                #[serde(default)]
                data: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::VoiceSignal {
                channel: r.channel,
                to: r.to,
                kind: r.kind,
                data: r.data,
                reply,
            })
            .await
        }

        ("POST", "/api/call/signal") => {
            #[derive(serde::Deserialize)]
            struct Req {
                to: String,
                kind: u8,
                #[serde(default)]
                data: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::CallSignal {
                to: r.to,
                kind: r.kind,
                data: r.data,
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

        ("GET", "/api/invites") => {
            let (tx, rx) = oneshot::channel();
            if shared
                .cmd
                .send(Cmd::PendingInvites { reply: tx })
                .await
                .is_err()
            {
                return respond(&mut stream, 503, "text/plain", b"engine down").await;
            }
            match rx.await {
                Ok(body) => respond(&mut stream, 200, "application/json", body.as_bytes()).await,
                Err(_) => respond(&mut stream, 503, "text/plain", b"engine down").await,
            }
        }

        ("POST", "/api/invite/accept") | ("POST", "/api/invite/decline") => {
            #[derive(serde::Deserialize)]
            struct Req {
                channel: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            let accept = path.ends_with("accept");
            dispatch(&mut stream, &shared, |reply| Cmd::InviteRespond {
                channel: r.channel,
                accept,
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

        ("GET", "/api/pins") => {
            let channel = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("channel="))
                .unwrap_or("");
            let body = match parse_fingerprint(channel) {
                Ok(cid) => {
                    let (tx, rx) = oneshot::channel();
                    if shared
                        .cmd
                        .send(Cmd::Pins {
                            channel: cid,
                            reply: tx,
                        })
                        .await
                        .is_err()
                    {
                        return respond(&mut stream, 500, "text/plain", b"engine gone").await;
                    }
                    rx.await.unwrap_or_else(|_| "[]".into())
                }
                Err(_) => "[]".into(),
            };
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("POST", "/api/pin") => {
            #[derive(serde::Deserialize)]
            struct Req {
                channel: String,
                seq: u64,
                /// `true` to pin, `false` to unpin.
                #[serde(default)]
                pinned: bool,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::Pin {
                channel: r.channel,
                seq: r.seq,
                pinned: r.pinned,
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

        ("GET", "/api/p2p") => {
            let (tx, rx) = oneshot::channel();
            if shared.cmd.send(Cmd::P2pInfo { reply: tx }).await.is_err() {
                return respond(&mut stream, 500, "text/plain", b"engine gone").await;
            }
            let body = rx
                .await
                .unwrap_or_else(|_| "{\"enabled\":false}".to_string());
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
                /// The current password, required when one is already set.
                #[serde(default)]
                current: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::JoinPw {
                server: r.server,
                password: r.password,
                current: r.current,
                reply,
            })
            .await
        }

        // `channel` is any channel of the target server; the member is removed
        // from all of them. `/api/remove` keeps working as a kick (ban:false).
        ("POST", "/api/remove") | ("POST", "/api/server/kick") | ("POST", "/api/server/ban") => {
            #[derive(serde::Deserialize)]
            struct Req {
                channel: String,
                member: String,
                #[serde(default)]
                ban: bool,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            let ban = r.ban || path.ends_with("ban");
            dispatch(&mut stream, &shared, |reply| Cmd::RemoveMember {
                channel: r.channel,
                member: r.member,
                ban,
                reply,
            })
            .await
        }

        ("POST", "/api/server/unban") => {
            #[derive(serde::Deserialize)]
            struct Req {
                server: String,
                member: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::Unban {
                server: r.server,
                member: r.member,
                reply,
            })
            .await
        }

        ("GET", "/api/server/bans") => {
            let server = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("server="))
                .map(percent_decode)
                .unwrap_or_default();
            let (tx, rx) = oneshot::channel();
            if shared
                .cmd
                .send(Cmd::ServerBans { server, reply: tx })
                .await
                .is_err()
            {
                return respond(&mut stream, 503, "text/plain", b"engine down").await;
            }
            match rx.await {
                Ok(body) => respond(&mut stream, 200, "application/json", body.as_bytes()).await,
                Err(_) => respond(&mut stream, 503, "text/plain", b"engine down").await,
            }
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

        ("GET", "/api/contacts") => {
            let (tx, rx) = oneshot::channel();
            if shared.cmd.send(Cmd::Contacts { reply: tx }).await.is_err() {
                return respond(&mut stream, 500, "text/plain", b"engine gone").await;
            }
            let body = rx.await.unwrap_or_else(|_| "[]".into());
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("POST", "/api/contact") => {
            #[derive(serde::Deserialize)]
            struct Req {
                peer: String,
                #[serde(default)]
                petname: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::AddContact {
                peer: r.peer,
                petname: r.petname,
                reply,
            })
            .await
        }

        ("POST", "/api/contact/remove") => {
            #[derive(serde::Deserialize)]
            struct Req {
                peer: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::RemoveContact {
                peer: r.peer,
                reply,
            })
            .await
        }

        ("POST", "/api/leave") => {
            #[derive(serde::Deserialize)]
            struct Req {
                channel: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::Leave {
                channel: r.channel,
                reply,
            })
            .await
        }

        ("POST", "/api/channel/delete") | ("POST", "/api/server/delete") => {
            #[derive(serde::Deserialize)]
            struct Req {
                #[serde(default)]
                channel: String,
                #[serde(default)]
                server: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            let is_server = path == "/api/server/delete";
            dispatch(&mut stream, &shared, |reply| Cmd::Delete {
                channel: if is_server { String::new() } else { r.channel },
                server: if is_server { r.server } else { String::new() },
                reply,
            })
            .await
        }

        ("GET", "/api/blocked") => {
            let (tx, rx) = oneshot::channel();
            if shared.cmd.send(Cmd::Blocked { reply: tx }).await.is_err() {
                return respond(&mut stream, 500, "text/plain", b"engine gone").await;
            }
            let body = rx.await.unwrap_or_else(|_| "[]".into());
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("POST", "/api/block") | ("POST", "/api/unblock") => {
            #[derive(serde::Deserialize)]
            struct Req {
                peer: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            let on = path == "/api/block";
            dispatch(&mut stream, &shared, |reply| Cmd::Block {
                peer: r.peer,
                on,
                reply,
            })
            .await
        }

        ("GET", "/api/calls") => {
            let (tx, rx) = oneshot::channel();
            if shared.cmd.send(Cmd::Calls { reply: tx }).await.is_err() {
                return respond(&mut stream, 500, "text/plain", b"engine gone").await;
            }
            let body = rx.await.unwrap_or_else(|_| "[]".into());
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("GET", "/api/ice") => {
            let (tx, rx) = oneshot::channel();
            if shared.cmd.send(Cmd::Ice { reply: tx }).await.is_err() {
                return respond(&mut stream, 500, "text/plain", b"engine gone").await;
            }
            let body = rx.await.unwrap_or_else(|_| "[]".into());
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("GET", "/api/call/audio") => {
            let peer = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("peer="))
                .unwrap_or("")
                .to_string();
            let (tx, rx) = oneshot::channel();
            if shared
                .cmd
                .send(Cmd::CallAudioRecv { peer, reply: tx })
                .await
                .is_err()
            {
                return respond(&mut stream, 500, "text/plain", b"engine gone").await;
            }
            let body = rx.await.unwrap_or_else(|_| "{\"frames\":[]}".into());
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("POST", "/api/call/audio") => {
            #[derive(serde::Deserialize)]
            struct Req {
                peer: String,
                /// One frame; or use `frames_hex` for a batch.
                #[serde(default)]
                frame_hex: String,
                #[serde(default)]
                frames_hex: Vec<String>,
                #[serde(default = "twenty")]
                ms: u32,
            }
            fn twenty() -> u32 {
                20
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            let hexes = if r.frames_hex.is_empty() {
                vec![r.frame_hex]
            } else {
                r.frames_hex
            };
            let mut frames = Vec::with_capacity(hexes.len());
            for h in hexes.iter().filter(|h| !h.is_empty()) {
                let Some(f) = hex_bytes(h) else {
                    return respond(&mut stream, 400, "text/plain", b"bad frame_hex").await;
                };
                frames.push(f);
            }
            dispatch(&mut stream, &shared, |reply| Cmd::CallAudioSend {
                peer: r.peer,
                frames,
                ms: r.ms,
                reply,
            })
            .await
        }

        ("POST", "/api/call") | ("POST", "/api/call/accept") | ("POST", "/api/call/hangup") => {
            #[derive(serde::Deserialize)]
            struct Req {
                peer: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            let action = match path {
                "/api/call/accept" => "accept",
                "/api/call/hangup" => "hangup",
                _ => "start",
            }
            .to_string();
            dispatch(&mut stream, &shared, |reply| Cmd::Call {
                peer: r.peer,
                action,
                reply,
            })
            .await
        }

        ("GET", "/api/groupcalls") => {
            let (tx, rx) = oneshot::channel();
            if shared
                .cmd
                .send(Cmd::GroupCalls { reply: tx })
                .await
                .is_err()
            {
                return respond(&mut stream, 500, "text/plain", b"engine gone").await;
            }
            let body = rx.await.unwrap_or_else(|_| "[]".into());
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("POST", "/api/revoke") => {
            #[derive(serde::Deserialize)]
            struct Req {
                #[serde(default)]
                reason: String,
                /// Must be `true` — a deliberate confirmation.
                #[serde(default)]
                confirm: bool,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            if !r.confirm {
                return respond(&mut stream, 400, "text/plain", b"revocation not confirmed").await;
            }
            dispatch(&mut stream, &shared, |reply| Cmd::Revoke {
                reason: r.reason,
                reply,
            })
            .await
        }

        ("GET", "/api/search") => {
            let q = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("q="))
                .map(percent_decode)
                .unwrap_or_default();
            let (tx, rx) = oneshot::channel();
            if shared.cmd.send(Cmd::Search { q, reply: tx }).await.is_err() {
                return respond(&mut stream, 500, "text/plain", b"engine gone").await;
            }
            let body = rx.await.unwrap_or_else(|_| "[]".into());
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("POST", "/api/groupcall/start")
        | ("POST", "/api/groupcall/join")
        | ("POST", "/api/groupcall/leave") => {
            #[derive(serde::Deserialize)]
            struct Req {
                channel: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            let action = match path {
                "/api/groupcall/join" => "join",
                "/api/groupcall/leave" => "leave",
                _ => "start",
            }
            .to_string();
            dispatch(&mut stream, &shared, |reply| Cmd::GroupCall {
                channel: r.channel,
                action,
                reply,
            })
            .await
        }

        ("GET", "/api/recv-file") => {
            let id = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("id="))
                .unwrap_or("");
            let hit = {
                let rf = shared.recv_files.lock().await;
                rf.1.get(id).cloned()
            };
            match hit {
                Some((mime, bytes)) => respond(&mut stream, 200, &mime, &bytes).await,
                None => respond(&mut stream, 404, "text/plain", b"not held").await,
            }
        }

        ("GET", "/api/emoji") => {
            let hex = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("hash="))
                .unwrap_or("");
            let Some(hash) = hex_bytes(hex)
                .filter(|b| b.len() == 32)
                .map(|b| <[u8; 32]>::try_from(b).unwrap())
            else {
                return respond(&mut stream, 400, "text/plain", b"bad hash").await;
            };
            let (tx, rx) = oneshot::channel();
            if shared
                .cmd
                .send(Cmd::GetEmoji { hash, reply: tx })
                .await
                .is_err()
            {
                return respond(&mut stream, 500, "text/plain", b"engine gone").await;
            }
            match rx.await.ok().flatten() {
                Some(bytes) => respond(&mut stream, 200, sniff_image(&bytes), &bytes).await,
                None => respond(&mut stream, 404, "text/plain", b"no such blob").await,
            }
        }

        ("POST", "/api/emoji") => {
            #[derive(serde::Deserialize)]
            struct Req {
                server: String,
                name: String,
                /// Hex-encoded image bytes.
                image_hex: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            let Some(image) = hex_bytes(&r.image_hex) else {
                return respond(&mut stream, 400, "text/plain", b"bad image_hex").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::Emoji {
                server: r.server,
                name: r.name,
                image: Some(image),
                reply,
            })
            .await
        }

        ("POST", "/api/emoji/remove") => {
            #[derive(serde::Deserialize)]
            struct Req {
                server: String,
                name: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::Emoji {
                server: r.server,
                name: r.name,
                image: None,
                reply,
            })
            .await
        }

        ("GET", "/api/sticker") => {
            let hex = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("hash="))
                .unwrap_or("");
            let Some(hash) = hex_bytes(hex)
                .filter(|b| b.len() == 32)
                .map(|b| <[u8; 32]>::try_from(b).unwrap())
            else {
                return respond(&mut stream, 400, "text/plain", b"bad hash").await;
            };
            let (tx, rx) = oneshot::channel();
            if shared
                .cmd
                .send(Cmd::GetEmoji { hash, reply: tx })
                .await
                .is_err()
            {
                return respond(&mut stream, 500, "text/plain", b"engine gone").await;
            }
            match rx.await.ok().flatten() {
                Some(bytes) => respond(&mut stream, 200, sniff_image(&bytes), &bytes).await,
                None => respond(&mut stream, 404, "text/plain", b"no such blob").await,
            }
        }

        ("POST", "/api/sticker") => {
            #[derive(serde::Deserialize)]
            struct Req {
                server: String,
                name: String,
                /// Hex-encoded image bytes.
                image_hex: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            let Some(image) = hex_bytes(&r.image_hex) else {
                return respond(&mut stream, 400, "text/plain", b"bad image_hex").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::Sticker {
                server: r.server,
                name: r.name,
                image: Some(image),
                reply,
            })
            .await
        }

        ("POST", "/api/sticker/remove") => {
            #[derive(serde::Deserialize)]
            struct Req {
                server: String,
                name: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::Sticker {
                server: r.server,
                name: r.name,
                image: None,
                reply,
            })
            .await
        }

        ("GET", "/api/sound") => {
            let hex = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("hash="))
                .unwrap_or("");
            let Some(hash) = hex_bytes(hex)
                .filter(|b| b.len() == 32)
                .map(|b| <[u8; 32]>::try_from(b).unwrap())
            else {
                return respond(&mut stream, 400, "text/plain", b"bad hash").await;
            };
            let (tx, rx) = oneshot::channel();
            if shared
                .cmd
                .send(Cmd::GetEmoji { hash, reply: tx })
                .await
                .is_err()
            {
                return respond(&mut stream, 500, "text/plain", b"engine gone").await;
            }
            match rx.await.ok().flatten() {
                Some(bytes) => respond(&mut stream, 200, sniff_audio(&bytes), &bytes).await,
                None => respond(&mut stream, 404, "text/plain", b"no such blob").await,
            }
        }

        ("POST", "/api/sound") => {
            #[derive(serde::Deserialize)]
            struct Req {
                server: String,
                name: String,
                /// Hex-encoded audio bytes.
                audio_hex: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            let Some(audio) = hex_bytes(&r.audio_hex) else {
                return respond(&mut stream, 400, "text/plain", b"bad audio_hex").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::Sound {
                server: r.server,
                name: r.name,
                audio: Some(audio),
                reply,
            })
            .await
        }

        ("POST", "/api/sound/remove") => {
            #[derive(serde::Deserialize)]
            struct Req {
                server: String,
                name: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::Sound {
                server: r.server,
                name: r.name,
                audio: None,
                reply,
            })
            .await
        }

        ("GET", "/api/embeds") => {
            let on = shared.embeds.load(Ordering::Relaxed);
            let body = format!("{{\"on\":{on}}}");
            respond(&mut stream, 200, "application/json", body.as_bytes()).await
        }

        ("POST", "/api/embeds") => {
            #[derive(serde::Deserialize)]
            struct Req {
                on: bool,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            shared.embeds.store(r.on, Ordering::Relaxed);
            respond(&mut stream, 200, "application/json", b"{\"ok\":\"ok\"}").await
        }

        ("POST", "/api/unfurl") => {
            #[derive(serde::Deserialize)]
            struct Req {
                url: String,
            }
            if !shared.embeds.load(Ordering::Relaxed) {
                return respond(
                    &mut stream,
                    403,
                    "application/json",
                    b"{\"error\":\"link previews are off\"}",
                )
                .await;
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            match crate::unfurl::unfurl(&r.url).await {
                Ok(p) => {
                    let json = serde_json::json!({
                        "url": p.url,
                        "site": p.site,
                        "title": p.title,
                        "description": p.description,
                        "image": p.image_data_uri,
                    })
                    .to_string();
                    respond(&mut stream, 200, "application/json", json.as_bytes()).await
                }
                Err(e) => {
                    let json = serde_json::json!({ "error": e }).to_string();
                    respond(&mut stream, 200, "application/json", json.as_bytes()).await
                }
            }
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
                #[serde(default)]
                icon: Option<String>,
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
                icon: r.icon.filter(|s| !s.is_empty()),
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

        ("POST", "/api/nickname") => {
            #[derive(serde::Deserialize)]
            struct Req {
                server: String,
                member: String,
                /// Empty clears the nickname.
                #[serde(default)]
                nickname: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::SetNickname {
                server: r.server,
                member: r.member,
                nickname: r.nickname,
                reply,
            })
            .await
        }

        ("POST", "/api/nickname/request") => {
            #[derive(serde::Deserialize)]
            struct Req {
                server: String,
                /// Empty clears the nickname.
                #[serde(default)]
                nickname: String,
            }
            let Ok(r) = serde_json::from_slice::<Req>(&body) else {
                return respond(&mut stream, 400, "text/plain", b"bad json").await;
            };
            dispatch(&mut stream, &shared, |reply| Cmd::RequestNickname {
                server: r.server,
                nickname: r.nickname,
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

/// The loopback authorities a server bound to `port` legitimately answers to.
/// A browser sends whichever form the user typed into the address bar, so all
/// three must be accepted; anything else in a `Host` header is a rebinding
/// attempt.
fn loopback_authorities(port: u16) -> Vec<String> {
    vec![
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ]
}

/// Case-insensitively fetch a single header value from a raw request head.
fn header_val<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// The authority (`host:port`) of an `Origin`/`Referer` URL, scheme stripped.
fn authority_of(url: &str) -> Option<&str> {
    let s = url.trim();
    let s = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
        .unwrap_or(s);
    let s = s.split('/').next().unwrap_or(s);
    (!s.is_empty()).then_some(s)
}

/// Guard against the browser being used as a confused deputy against this
/// localhost-only API. Two orthogonal checks, because a plain CSRF request and
/// a DNS-rebinding request fail in different places:
///
/// * **Host allowlist (every request).** A rebinding attacker resolves their
///   own domain to `127.0.0.1`, so the connection reaches us but carries
///   `Host: evil.example`. Refusing any `Host` outside our loopback authorities
///   makes the page cross-origin again, so the browser's same-origin policy
///   keeps the attacker out of the responses.
/// * **Cross-site refusal (mutating requests).** A plain CSRF `fetch`/form from
///   `evil.example` still connects with the real `Host: 127.0.0.1:port`, but the
///   browser attaches a truthful `Origin` (and/or `Sec-Fetch-Site`) that it will
///   not let script forge. A mutating request whose `Origin` is a different
///   authority, or which is tagged `Sec-Fetch-Site: cross-site`/`same-site`, is
///   refused. Requests from non-browser tooling (curl, the CLI) send neither
///   header and are allowed — they are not confused deputies.
fn request_is_local(head: &str, method: &str, authorities: &[String]) -> bool {
    // Host must be one of ours (or absent, as in HTTP/1.0 — then the other
    // checks still apply). A present-but-foreign Host is a rebinding attempt.
    if let Some(host) = header_val(head, "host") {
        if !authorities.iter().any(|a| a == host) {
            return false;
        }
    }
    // Reads (GET/HEAD) are not state-changing; the Host check above is enough to
    // stop rebinding from turning them same-origin.
    if method != "GET" && method != "HEAD" {
        if let Some(origin) = header_val(head, "origin") {
            // "null" (sandboxed/opaque origin) never matches — refuse it.
            match authority_of(origin) {
                Some(a) if authorities.iter().any(|x| x == a) => {}
                _ => return false,
            }
        }
        if let Some(site) = header_val(head, "sec-fetch-site") {
            if site.eq_ignore_ascii_case("cross-site") || site.eq_ignore_ascii_case("same-site") {
                return false;
            }
        }
    }
    true
}

/// Security headers for API and SSE responses. Only same-origin fetches are
/// allowed and everything else is locked down. These responses are not
/// documents, so their `script-src` never governs execution — the SPA document
/// itself (`GET /`) is served with a stricter, per-load `script-src 'nonce-…'`
/// CSP built inline in that handler, which is what actually gates inline script.
const SEC: &str = "Content-Security-Policy: default-src 'none'; \
     script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
     connect-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; base-uri 'none'; \
     form-action 'none'; frame-ancestors 'none'\r\n\
     X-Content-Type-Options: nosniff\r\n\
     Referrer-Policy: no-referrer\r\n\
     X-Frame-Options: DENY\r\n";

/// Server-Sent Events: hold the connection open and push every new inbox item
/// as it appears, so the SPA sees messages in ~150 ms instead of waiting for its
/// next poll. This is a server-side tail of `shared.inbox` (no changes to the
/// dozens of push sites); the SPA keeps its slow poll as a fallback for when the
/// stream drops. Returns when the client disconnects (a write fails).
async fn sse_stream(stream: &mut TcpStream, shared: &Shared, query: &str) -> Result<()> {
    let mut cursor: u64 = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("since="))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
         Cache-Control: no-cache\r\nX-Accel-Buffering: no\r\n{SEC}Connection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(b": open\n\n").await?;
    stream.flush().await?;

    let mut ticker = tokio::time::interval(Duration::from_millis(150));
    let mut idle: u32 = 0;
    loop {
        ticker.tick().await;
        let batch: Vec<String> = {
            let inbox = shared.inbox.lock().await;
            let fresh: Vec<&Item> = inbox.iter().filter(|it| it.seq() > cursor).collect();
            if let Some(last) = fresh.last() {
                cursor = last.seq();
            }
            fresh
                .iter()
                .map(|it| serde_json::to_string(it).unwrap_or_default())
                .collect()
        };
        if batch.is_empty() {
            idle += 1;
            if idle >= 100 {
                // ~15 s keep-alive so intermediaries don't reap an idle stream.
                idle = 0;
                stream.write_all(b": ping\n\n").await?;
                stream.flush().await?;
            }
            continue;
        }
        idle = 0;
        let mut out = String::with_capacity(batch.len() * 96);
        for j in batch {
            out.push_str("data: ");
            out.push_str(&j);
            out.push_str("\n\n");
        }
        stream.write_all(out.as_bytes()).await?;
        stream.flush().await?;
    }
}

async fn respond(stream: &mut TcpStream, code: u16, ctype: &str, body: &[u8]) -> Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Status",
    };
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
    use super::{
        ice_json, ice_needs_refresh, loopback_authorities, request_is_local, typing_text,
        TYPING_FRESH_MS,
    };

    const NOW: u64 = 1_000_000;

    fn head(lines: &[&str]) -> String {
        // Request line + headers, as `serve_conn` sees them.
        let mut s = String::from("POST /api/contact HTTP/1.1\r\n");
        for l in lines {
            s.push_str(l);
            s.push_str("\r\n");
        }
        s.push_str("\r\n");
        s
    }

    #[test]
    fn ice_is_refreshed_only_when_the_credential_is_near_expiry() {
        let now = 1_789_000_000u64;
        let turn = |expiry: u64| dante_core::IceServer {
            urls: vec!["turn:turn.example.org:3478".into()],
            username: expiry.to_string(),
            credential: "c2VjcmV0".into(),
        };
        let stun = dante_core::IceServer {
            urls: vec!["stun:stun.example.org:3478".into()],
            ..Default::default()
        };

        // Plenty of life left: serve the cached list, no relay round trip. The
        // engine loop is serialized, so this is what keeps a hung relay off
        // the call-start path.
        assert!(!ice_needs_refresh(&[turn(now + 3600)], now));
        // Inside the margin, and already lapsed.
        assert!(ice_needs_refresh(&[turn(now + 60)], now));
        assert!(ice_needs_refresh(&[turn(now - 1)], now));
        // STUN has no expiry, so a STUN-only config never triggers a fetch.
        assert!(!ice_needs_refresh(std::slice::from_ref(&stun), now));
        // Nothing learned: connect already asked, and re-asking would put a
        // relay round trip on every call start for a no-TURN deployment.
        assert!(!ice_needs_refresh(&[], now));
        // A username we cannot parse is treated as unknown, so refresh.
        assert!(ice_needs_refresh(
            &[dante_core::IceServer {
                urls: vec!["turn:turn.example.org:3478".into()],
                username: "not-a-timestamp".into(),
                credential: "x".into(),
            }],
            now
        ));
    }

    #[test]
    fn ice_json_carries_turn_credentials_to_the_page() {
        let servers = vec![
            dante_core::IceServer {
                urls: vec!["stun:stun.example.org:3478".into()],
                ..Default::default()
            },
            dante_core::IceServer {
                urls: vec!["turn:turn.example.org:3478?transport=udp".into()],
                username: "1789000000".into(),
                credential: "c2VjcmV0".into(),
            },
        ];
        let v: serde_json::Value = serde_json::from_str(&ice_json(&servers)).unwrap();

        assert_eq!(v[0]["kind"], "stun");
        assert_eq!(v[0]["username"], "");

        // Without these two fields the browser cannot allocate a relay
        // candidate, and a cross-NAT call never connects.
        assert_eq!(v[1]["kind"], "turn");
        assert_eq!(v[1]["username"], "1789000000");
        assert_eq!(v[1]["credential"], "c2VjcmV0");
    }

    #[test]
    fn csrf_guard_allows_the_legit_spa_and_local_tooling() {
        let auth = loopback_authorities(8080);
        // Same-origin browser POST from the served page.
        assert!(request_is_local(
            &head(&[
                "Host: 127.0.0.1:8080",
                "Origin: http://127.0.0.1:8080",
                "Sec-Fetch-Site: same-origin"
            ]),
            "POST",
            &auth,
        ));
        // The user typed `localhost` in the address bar.
        assert!(request_is_local(
            &head(&["Host: localhost:8080", "Origin: http://localhost:8080"]),
            "POST",
            &auth,
        ));
        // curl / CLI: correct Host, no Origin, no Sec-Fetch-Site.
        assert!(request_is_local(
            &head(&["Host: 127.0.0.1:8080"]),
            "POST",
            &auth
        ));
    }

    #[test]
    fn csrf_guard_blocks_cross_origin_and_rebinding() {
        let auth = loopback_authorities(8080);
        // Plain CSRF: real Host, foreign Origin.
        assert!(!request_is_local(
            &head(&["Host: 127.0.0.1:8080", "Origin: https://evil.example"]),
            "POST",
            &auth,
        ));
        // Plain CSRF that omits Origin but is tagged cross-site by the browser.
        assert!(!request_is_local(
            &head(&["Host: 127.0.0.1:8080", "Sec-Fetch-Site: cross-site"]),
            "POST",
            &auth,
        ));
        // DNS rebinding: attacker domain resolved to loopback → foreign Host.
        assert!(!request_is_local(
            &head(&["Host: evil.example", "Origin: http://evil.example"]),
            "POST",
            &auth,
        ));
        // A rebound GET (reads) is refused too, on the Host check alone.
        assert!(!request_is_local(
            &head(&["Host: evil.example"]),
            "GET",
            &auth
        ));
        // Opaque/sandboxed origin must not slip through.
        assert!(!request_is_local(
            &head(&["Host: 127.0.0.1:8080", "Origin: null"]),
            "POST",
            &auth,
        ));
    }

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
