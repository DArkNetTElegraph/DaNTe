//! Encrypted local state store.
//!
//! One file, rewritten atomically, holding everything a client needs to resume
//! a conversation without a fresh handshake: the prekey **secrets**, every
//! Double Ratchet session, message history, the seen-envelope set, and the
//! last announce / fetch cursors. Sealed with XChaCha20-Poly1305 under a key
//! derived (HKDF-SHA-256) from the identity's `ratchet_db_key`
//! (`docs/PROTOCOL.md` §1.2).

use std::{fs, io, path::Path};

use dante_crypto::{aead, kdf, random_array};
use dante_dm::{PreKeySecretsState, SessionState};
use dante_identity::Identity;
use dante_proto::enc::{Reader, WireError, Writer};

use crate::channel::ChannelInfo;

const MAGIC: &[u8; 13] = b"DANTE-STATE-1";
const KDF_INFO: &[u8] = b"dante/local-store/v1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 13 + SALT_LEN + NONCE_LEN;

/// A history record's payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoryKind {
    /// A text message.
    Text(String),
    /// A file transfer.
    File {
        /// Declared filename.
        filename: String,
        /// Byte length.
        size: u64,
    },
}

/// One line of conversation history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryEntry {
    /// The other party's Ed25519 identity key.
    pub peer_idk: [u8; 32],
    /// True if we sent it.
    pub outgoing: bool,
    /// Wall-clock time (Unix ms).
    pub ts_ms: u64,
    /// The message payload.
    pub kind: HistoryKind,
}

/// One line of channel history, oldest first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelHistoryEntry {
    /// Which channel it belongs to.
    pub channel_id: [u8; 32],
    /// The sender's group member id (`my_member_id` for our own messages).
    pub sender: [u8; 32],
    /// True if we sent it.
    pub outgoing: bool,
    /// Wall-clock time (Unix ms).
    pub ts_ms: u64,
    /// The message text.
    pub text: String,
}

/// A persisted channel membership.
pub struct StoredChannel {
    /// Channel description.
    pub info: ChannelInfo,
    /// The channel's MLS member state (`dante_mls::Member::export`).
    pub mls: Vec<u8>,
    /// Known member ids.
    pub roster: Vec<[u8; 32]>,
    /// Last consumed channel-log sequence number.
    pub last_seq: u64,
}

/// A persisted hosted-server record (holds the root secret).
pub struct StoredHostedServer {
    /// `server_root` public key.
    pub root_pub: [u8; 32],
    /// Display name.
    pub name: String,
    /// `server_root` secret — this is why the store is encrypted.
    pub root_secret: [u8; 32],
    /// Channel ids created under this server.
    pub channels: Vec<[u8; 32]>,
}

/// Everything persisted between runs.
pub struct PersistedState {
    /// The prekey secret halves.
    pub prekeys: PreKeySecretsState,
    /// `(peer_idk, session snapshot)`.
    pub sessions: Vec<([u8; 32], SessionState)>,
    /// Channel memberships.
    pub channels: Vec<StoredChannel>,
    /// Servers this client hosts.
    pub hosted: Vec<StoredHostedServer>,
    /// Conversation history, oldest first.
    pub history: Vec<HistoryEntry>,
    /// Channel history, oldest first.
    pub channel_history: Vec<ChannelHistoryEntry>,
    /// Redemption counts for invite tokens we minted (`nonce -> uses`).
    pub invite_uses: Vec<([u8; 8], u32)>,
    /// Ejected members: `(channel_id, member, removal issued_ms)`.
    pub channel_removed: Vec<([u8; 32], [u8; 32], u64)>,
    /// Per-hosted-server auto-kick window: `(server_root, window_ms)`.
    pub server_autokick: Vec<([u8; 32], u64)>,
    /// Per-hosted-server join-password hash: `(server_root, hash)`.
    pub server_join_pw: Vec<([u8; 32], [u8; 32])>,
    /// Encoded `roles::ServerPolicy` for each known server (hosted or joined).
    pub server_policies: Vec<Vec<u8>>,
    /// Standing channel reactions: `(channel_id, target_seq, emoji, member)`,
    /// one row per member who currently holds that reaction.
    pub channel_reactions: Vec<([u8; 32], u64, String, [u8; 32])>,
    /// Safety-number-verified DM peers: `(peer IdentityId, pinned idk)`.
    pub verified_peers: Vec<([u8; 32], [u8; 32])>,
    /// Saved contacts: `(peer IdentityId, petname, added_ms)`.
    pub contacts: Vec<([u8; 32], String, u64)>,
    /// Blocked identities (by `IdentityId` bytes).
    pub blocked: Vec<[u8; 32]>,
    /// Processed-envelope tags (deduplication).
    pub seen_envelopes: Vec<[u8; 32]>,
    /// When we last announced / proved liveness.
    pub last_announce_ms: u64,
    /// The mailbox `since` cursor.
    pub last_fetch_since_ms: u64,
}

/// Why a store file could not be read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// I/O error.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// The file is not a DaNTe store or is truncated.
    #[error("not a valid store file")]
    Malformed,
    /// The wrong identity (or a corrupt file): AEAD authentication failed.
    #[error("store could not be decrypted with this identity")]
    Decrypt,
    /// The decrypted payload did not parse.
    #[error("store payload is corrupt")]
    Payload(#[from] WireError),
}

fn derive_key(identity: &Identity, salt: &[u8; SALT_LEN]) -> [u8; 32] {
    let prk = kdf::extract(salt, identity.ratchet_db_key());
    let mut key = [0u8; 32];
    kdf::expand(&prk, KDF_INFO, &mut key).expect("32 <= 255*32");
    key
}

/// Write `state` to `path`, encrypted for `identity`. Writes to a temp file
/// then renames, so a crash mid-write leaves the previous store intact.
pub fn save(path: &Path, identity: &Identity, state: &PersistedState) -> Result<(), StoreError> {
    let salt = random_array::<SALT_LEN>();
    let nonce = random_array::<NONCE_LEN>();
    let key = derive_key(identity, &salt);
    let aad = [MAGIC.as_slice(), &salt].concat();
    let ciphertext = aead::xchacha_seal(&key, &nonce, &encode_state(state), &aad);

    let mut file = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    file.extend_from_slice(MAGIC);
    file.extend_from_slice(&salt);
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&ciphertext);

    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &file)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Load the store at `path` for `identity`. `Ok(None)` if the file is absent.
pub fn load(path: &Path, identity: &Identity) -> Result<Option<PersistedState>, StoreError> {
    let file = match fs::read(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if file.len() < HEADER_LEN || &file[..13] != MAGIC {
        return Err(StoreError::Malformed);
    }
    let salt: [u8; SALT_LEN] = file[13..13 + SALT_LEN].try_into().unwrap();
    let nonce: [u8; NONCE_LEN] = file[13 + SALT_LEN..HEADER_LEN].try_into().unwrap();
    let key = derive_key(identity, &salt);
    let aad = [MAGIC.as_slice(), &salt].concat();
    let plaintext = aead::xchacha_open(&key, &nonce, &file[HEADER_LEN..], &aad)
        .map_err(|_| StoreError::Decrypt)?;
    Ok(Some(decode_state(&plaintext)?))
}

fn encode_state(s: &PersistedState) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(s.last_announce_ms).u64(s.last_fetch_since_ms);
    w.bytes(&s.prekeys.encode());

    w.u32(s.sessions.len() as u32);
    for (idk, sess) in &s.sessions {
        w.fixed(idk).bytes(&sess.encode());
    }

    w.u32(s.channels.len() as u32);
    for c in &s.channels {
        w.bytes(&c.info.encode())
            .bytes(&c.mls)
            .u64(c.last_seq)
            .u32(c.roster.len() as u32);
        for m in &c.roster {
            w.fixed(m);
        }
    }

    w.u32(s.hosted.len() as u32);
    for h in &s.hosted {
        w.fixed(&h.root_pub)
            .string(&h.name)
            .fixed(&h.root_secret)
            .u32(h.channels.len() as u32);
        for c in &h.channels {
            w.fixed(c);
        }
    }

    w.u32(s.history.len() as u32);
    for h in &s.history {
        w.fixed(&h.peer_idk).bool(h.outgoing).u64(h.ts_ms);
        match &h.kind {
            HistoryKind::Text(t) => {
                w.u8(1).string(t);
            }
            HistoryKind::File { filename, size } => {
                w.u8(2).string(filename).u64(*size);
            }
        }
    }

    w.u32(s.seen_envelopes.len() as u32);
    for tag in &s.seen_envelopes {
        w.fixed(tag);
    }

    // Trailing optional sections, in order of introduction. `decode_state`
    // reads each only while bytes remain, so older stores still load.
    w.u32(s.channel_history.len() as u32);
    for e in &s.channel_history {
        w.fixed(&e.channel_id)
            .fixed(&e.sender)
            .bool(e.outgoing)
            .u64(e.ts_ms)
            .string(&e.text);
    }

    w.u32(s.invite_uses.len() as u32);
    for (nonce, uses) in &s.invite_uses {
        w.fixed(nonce).u32(*uses);
    }

    w.u32(s.channel_removed.len() as u32);
    for (chan, member, at) in &s.channel_removed {
        w.fixed(chan).fixed(member).u64(*at);
    }

    w.u32(s.server_autokick.len() as u32);
    for (root, ms) in &s.server_autokick {
        w.fixed(root).u64(*ms);
    }

    w.u32(s.server_policies.len() as u32);
    for p in &s.server_policies {
        w.bytes(p);
    }

    w.u32(s.server_join_pw.len() as u32);
    for (root, hash) in &s.server_join_pw {
        w.fixed(root).fixed(hash);
    }

    w.u32(s.channel_reactions.len() as u32);
    for (chan, seq, emoji, member) in &s.channel_reactions {
        w.fixed(chan).u64(*seq).string(emoji).fixed(member);
    }

    w.u32(s.verified_peers.len() as u32);
    for (id, idk) in &s.verified_peers {
        w.fixed(id).fixed(idk);
    }

    w.u32(s.contacts.len() as u32);
    for (id, petname, added_ms) in &s.contacts {
        w.fixed(id).string(petname).u64(*added_ms);
    }

    w.u32(s.blocked.len() as u32);
    for id in &s.blocked {
        w.fixed(id);
    }
    w.into_vec()
}

fn decode_state(bytes: &[u8]) -> Result<PersistedState, StoreError> {
    let mut r = Reader::new(bytes);
    let last_announce_ms = r.u64()?;
    let last_fetch_since_ms = r.u64()?;
    let prekeys = PreKeySecretsState::decode(r.bytes()?)?;

    let n = bounded_count(&mut r)?;
    let mut sessions = Vec::with_capacity(n);
    for _ in 0..n {
        let idk = r.fixed::<32>()?;
        let sess = SessionState::decode(r.bytes()?)?;
        sessions.push((idk, sess));
    }

    let n = bounded_count(&mut r)?;
    let mut channels = Vec::with_capacity(n);
    for _ in 0..n {
        let info = ChannelInfo::decode(r.bytes()?)?;
        let mls = r.bytes()?.to_vec();
        let last_seq = r.u64()?;
        let rc = bounded_count(&mut r)?;
        let mut roster = Vec::with_capacity(rc);
        for _ in 0..rc {
            roster.push(r.fixed::<32>()?);
        }
        channels.push(StoredChannel {
            info,
            mls,
            roster,
            last_seq,
        });
    }

    let n = bounded_count(&mut r)?;
    let mut hosted = Vec::with_capacity(n);
    for _ in 0..n {
        let root_pub = r.fixed::<32>()?;
        let name = r.string()?;
        let root_secret = r.fixed::<32>()?;
        let cc = bounded_count(&mut r)?;
        let mut chans = Vec::with_capacity(cc);
        for _ in 0..cc {
            chans.push(r.fixed::<32>()?);
        }
        hosted.push(StoredHostedServer {
            root_pub,
            name,
            root_secret,
            channels: chans,
        });
    }

    let n = bounded_count(&mut r)?;
    let mut history = Vec::with_capacity(n);
    for _ in 0..n {
        let peer_idk = r.fixed::<32>()?;
        let outgoing = r.bool()?;
        let ts_ms = r.u64()?;
        let kind = match r.u8()? {
            1 => HistoryKind::Text(r.string()?),
            2 => HistoryKind::File {
                filename: r.string()?,
                size: r.u64()?,
            },
            other => {
                return Err(WireError::BadDiscriminant {
                    ty: "HistoryKind",
                    value: other.into(),
                }
                .into())
            }
        };
        history.push(HistoryEntry {
            peer_idk,
            outgoing,
            ts_ms,
            kind,
        });
    }

    let n = bounded_count(&mut r)?;
    let mut seen_envelopes = Vec::with_capacity(n);
    for _ in 0..n {
        seen_envelopes.push(r.fixed::<32>()?);
    }

    let mut channel_history = Vec::new();
    if r.remaining() > 0 {
        let n = bounded_count(&mut r)?;
        channel_history.reserve(n);
        for _ in 0..n {
            channel_history.push(ChannelHistoryEntry {
                channel_id: r.fixed::<32>()?,
                sender: r.fixed::<32>()?,
                outgoing: r.bool()?,
                ts_ms: r.u64()?,
                text: r.string()?,
            });
        }
    }

    let mut invite_uses = Vec::new();
    if r.remaining() > 0 {
        let n = bounded_count(&mut r)?;
        invite_uses.reserve(n);
        for _ in 0..n {
            invite_uses.push((r.fixed::<8>()?, r.u32()?));
        }
    }

    let mut channel_removed = Vec::new();
    if r.remaining() > 0 {
        let n = bounded_count(&mut r)?;
        channel_removed.reserve(n);
        for _ in 0..n {
            channel_removed.push((r.fixed::<32>()?, r.fixed::<32>()?, r.u64()?));
        }
    }

    let mut server_autokick = Vec::new();
    if r.remaining() > 0 {
        let n = bounded_count(&mut r)?;
        server_autokick.reserve(n);
        for _ in 0..n {
            server_autokick.push((r.fixed::<32>()?, r.u64()?));
        }
    }

    let mut server_policies = Vec::new();
    if r.remaining() > 0 {
        let n = bounded_count(&mut r)?;
        server_policies.reserve(n);
        for _ in 0..n {
            server_policies.push(r.bytes()?.to_vec());
        }
    }

    let mut server_join_pw = Vec::new();
    if r.remaining() > 0 {
        let n = bounded_count(&mut r)?;
        server_join_pw.reserve(n);
        for _ in 0..n {
            server_join_pw.push((r.fixed::<32>()?, r.fixed::<32>()?));
        }
    }

    let mut channel_reactions = Vec::new();
    if r.remaining() > 0 {
        let n = bounded_count(&mut r)?;
        channel_reactions.reserve(n);
        for _ in 0..n {
            channel_reactions.push((r.fixed::<32>()?, r.u64()?, r.string()?, r.fixed::<32>()?));
        }
    }

    let mut verified_peers = Vec::new();
    if r.remaining() > 0 {
        let n = bounded_count(&mut r)?;
        verified_peers.reserve(n);
        for _ in 0..n {
            verified_peers.push((r.fixed::<32>()?, r.fixed::<32>()?));
        }
    }

    let mut contacts = Vec::new();
    if r.remaining() > 0 {
        let n = bounded_count(&mut r)?;
        contacts.reserve(n);
        for _ in 0..n {
            contacts.push((r.fixed::<32>()?, r.string()?, r.u64()?));
        }
    }

    let mut blocked = Vec::new();
    if r.remaining() > 0 {
        let n = bounded_count(&mut r)?;
        blocked.reserve(n);
        for _ in 0..n {
            blocked.push(r.fixed::<32>()?);
        }
    }

    r.finish()?;
    Ok(PersistedState {
        prekeys,
        sessions,
        channels,
        hosted,
        history,
        channel_history,
        invite_uses,
        channel_removed,
        server_autokick,
        server_join_pw,
        server_policies,
        channel_reactions,
        verified_peers,
        contacts,
        blocked,
        seen_envelopes,
        last_announce_ms,
        last_fetch_since_ms,
    })
}

fn bounded_count(r: &mut Reader<'_>) -> Result<usize, WireError> {
    let n = r.u32()? as usize;
    if n > r.remaining() {
        return Err(WireError::LengthTooLarge(n as u64));
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use dante_dm::{PreKeySecrets, Session};
    use dante_identity::Identity;

    use super::*;

    fn sample_session() -> ([u8; 32], SessionState) {
        let (alice, bob) = (Identity::generate(0), Identity::generate(0));
        let bundle = PreKeySecrets::generate(2).bundle(&bob);
        let (sess, _init) = Session::initiate(&alice, &bundle, b"hi").unwrap();
        (bob.sign_public().to_bytes(), sess.export())
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("dante-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.bin");
        let id = Identity::generate(1_700_000_000_000);

        let (peer, sess) = sample_session();
        let state = PersistedState {
            prekeys: PreKeySecrets::generate(4).export(),
            sessions: vec![(peer, sess)],
            channels: vec![],
            hosted: vec![],
            history: vec![HistoryEntry {
                peer_idk: peer,
                outgoing: true,
                ts_ms: 42,
                kind: HistoryKind::Text("hello".into()),
            }],
            channel_history: vec![ChannelHistoryEntry {
                channel_id: [7u8; 32],
                sender: [6u8; 32],
                outgoing: false,
                ts_ms: 77,
                text: "channel hello".into(),
            }],
            invite_uses: vec![([1u8; 8], 3), ([2u8; 8], 0)],
            channel_removed: vec![([7u8; 32], [6u8; 32], 55)],
            server_autokick: vec![([4u8; 32], 86_400_000)],
            server_policies: vec![vec![1, 2, 3], vec![]],
            server_join_pw: vec![([1u8; 32], [2u8; 32])],
            channel_reactions: vec![
                ([7u8; 32], 12, "👍".into(), [6u8; 32]),
                ([7u8; 32], 12, "🔥".into(), [5u8; 32]),
            ],
            verified_peers: vec![([3u8; 32], [4u8; 32])],
            contacts: vec![([5u8; 32], "alice".into(), 1_700_000_000_000)],
            blocked: vec![[2u8; 32], [9u8; 32]],
            seen_envelopes: vec![[9u8; 32], [8u8; 32]],
            last_announce_ms: 100,
            last_fetch_since_ms: 200,
        };
        save(&path, &id, &state).unwrap();

        let back = load(&path, &id).unwrap().unwrap();
        assert_eq!(back.sessions.len(), 1);
        assert_eq!(back.sessions[0].0, peer);
        assert_eq!(back.history, state.history);
        assert_eq!(back.channel_history, state.channel_history);
        assert_eq!(back.invite_uses, state.invite_uses);
        assert_eq!(back.channel_removed, state.channel_removed);
        assert_eq!(back.server_autokick, state.server_autokick);
        assert_eq!(back.server_policies, state.server_policies);
        assert_eq!(back.server_join_pw, state.server_join_pw);
        assert_eq!(back.channel_reactions, state.channel_reactions);
        assert_eq!(back.verified_peers, state.verified_peers);
        assert_eq!(back.contacts, state.contacts);
        assert_eq!(back.blocked, state.blocked);
        assert_eq!(back.seen_envelopes, state.seen_envelopes);
        assert_eq!(back.last_announce_ms, 100);
        assert_eq!(back.last_fetch_since_ms, 200);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_identity_cannot_open() {
        let dir = std::env::temp_dir().join(format!("dante-store-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.bin");

        let id = Identity::generate(0);
        let state = PersistedState {
            prekeys: PreKeySecrets::generate(1).export(),
            sessions: vec![],
            channels: vec![],
            hosted: vec![],
            history: vec![],
            channel_history: vec![],
            invite_uses: vec![],
            channel_removed: vec![],
            server_autokick: vec![],
            server_policies: vec![],
            server_join_pw: vec![],
            channel_reactions: vec![],
            verified_peers: vec![],
            contacts: vec![],
            blocked: vec![],
            seen_envelopes: vec![],
            last_announce_ms: 0,
            last_fetch_since_ms: 0,
        };
        save(&path, &id, &state).unwrap();
        assert!(matches!(
            load(&path, &Identity::generate(0)),
            Err(StoreError::Decrypt)
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_is_none() {
        let id = Identity::generate(0);
        assert!(load(Path::new("/nonexistent/dante/store"), &id)
            .unwrap()
            .is_none());
    }
}
