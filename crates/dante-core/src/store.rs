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

/// Everything persisted between runs.
pub struct PersistedState {
    /// The prekey secret halves.
    pub prekeys: PreKeySecretsState,
    /// `(peer_idk, session snapshot)`.
    pub sessions: Vec<([u8; 32], SessionState)>,
    /// Conversation history, oldest first.
    pub history: Vec<HistoryEntry>,
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
    w.into_vec()
}

fn decode_state(bytes: &[u8]) -> Result<PersistedState, WireError> {
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
                })
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
    r.finish()?;
    Ok(PersistedState {
        prekeys,
        sessions,
        history,
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
            history: vec![HistoryEntry {
                peer_idk: peer,
                outgoing: true,
                ts_ms: 42,
                kind: HistoryKind::Text("hello".into()),
            }],
            seen_envelopes: vec![[9u8; 32], [8u8; 32]],
            last_announce_ms: 100,
            last_fetch_since_ms: 200,
        };
        save(&path, &id, &state).unwrap();

        let back = load(&path, &id).unwrap().unwrap();
        assert_eq!(back.sessions.len(), 1);
        assert_eq!(back.sessions[0].0, peer);
        assert_eq!(back.history, state.history);
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
            history: vec![],
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
