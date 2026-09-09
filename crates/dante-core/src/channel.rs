//! Channel (server) wiring on top of `dante-mls`.
//!
//! A **server** is a `server_root` Ed25519 keypair (registered on the ledger).
//! A **channel** is a random 32-byte id backed by one MLS group (RFC 9420),
//! created by the server host. The host is the sole committer: it adds and
//! removes members with MLS Commits, which travel in the channel's relay log
//! interleaved with the encrypted messages (both opaque to the relay). A new
//! member receives an MLS **Welcome** over an authenticated DM
//! ([`ChannelControl::MlsWelcome`]) and then catches up from the log.
//!
//! A **password-protected** channel additionally wraps every log frame in an
//! outer XChaCha20-Poly1305 layer keyed by `Argon2id(password)` (see
//! [`derive_log_key`] / [`wrap`] / [`unwrap`]), so possession of the 32-byte
//! `channel_id` alone does not grant read access to the relay log — the
//! password-derived key is also required. MLS still handles member removal
//! underneath.

use dante_crypto::{aead, pwhash, random_array};
use dante_proto::enc::{Reader, WireError, Writer};

/// Public description of a channel a client belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelInfo {
    /// The owning server's root key.
    pub server_root: [u8; 32],
    /// Server display name.
    pub server_name: String,
    /// The channel's 32-byte id (also the relay-log key).
    pub channel_id: [u8; 32],
    /// Channel display name.
    pub channel_name: String,
    /// Whether the channel is private (omitted from any discovery).
    pub private: bool,
    /// `IdentityId` of the host — the only identity whose MLS Commits members
    /// honour on this channel.
    pub host_id: [u8; 32],
    /// A **voice** channel: members join a persistent group call keyed by
    /// `channel_id` instead of exchanging text. The MLS group underneath is
    /// still used for membership and the call key.
    pub voice: bool,
}

impl ChannelInfo {
    pub(crate) fn write(&self, w: &mut Writer) {
        w.fixed(&self.server_root)
            .string(&self.server_name)
            .fixed(&self.channel_id)
            .string(&self.channel_name)
            .bool(self.private)
            .fixed(&self.host_id)
            .bool(self.voice);
    }
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, WireError> {
        Ok(Self {
            server_root: r.fixed::<32>()?,
            server_name: r.string()?,
            channel_id: r.fixed::<32>()?,
            channel_name: r.string()?,
            private: r.bool()?,
            host_id: r.fixed::<32>()?,
            // trailing, added later — old records decode as a text channel
            voice: if r.remaining() >= 1 { r.bool()? } else { false },
        })
    }
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write(&mut w);
        w.into_vec()
    }
    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let v = Self::read(&mut r)?;
        r.finish()?;
        Ok(v)
    }
}

/// A control message exchanged between channel members over DM. Membership
/// changes themselves are MLS Commits carried in the channel log; these
/// messages set up or tear down a member's participation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelControl {
    /// The host welcomes a member into the channel's MLS group.
    MlsWelcome {
        /// The channel being joined (carries `host_id`, server metadata, name).
        info: ChannelInfo,
        /// The opaque MLS Welcome (a `dante_mls` handshake blob).
        welcome: Vec<u8>,
        /// The channel-log sequence the joiner should start reading from —
        /// the host's view at the time it committed the add.
        since_seq: u64,
        /// The outer log key for a password-protected channel, or all-zeros
        /// for an unprotected one (the joiner already proved knowledge of the
        /// password via `Redeem`, or was directly invited by the host).
        log_key: [u8; 32],
    },
    /// A joiner presents a signed invite token (and, if the server is
    /// password-gated, the password) to the host to be added.
    Redeem {
        /// Encoded [`crate::invite::InviteToken`].
        token: Vec<u8>,
        /// The server join password, or empty if none.
        pw: String,
    },
    /// The host broadcasts the current server role configuration.
    Policy {
        /// Encoded [`crate::roles::ServerPolicy`].
        policy: Vec<u8>,
    },
    /// A member with `PERM_KICK` asks the host to remove someone from the whole
    /// server (all its channels). `channel_id` only identifies which server.
    KickRequest {
        /// Any channel of the server whose member is being removed.
        channel_id: [u8; 32],
        /// The member to remove.
        member: [u8; 32],
        /// Also add them to the server's ban list (blocks re-joining).
        ban: bool,
    },
    /// A member tells the host it is leaving; the host commits its removal.
    Leave {
        /// The channel being left.
        channel_id: [u8; 32],
    },
    /// The host has deleted the whole channel; recipients drop it.
    Closed {
        /// The channel being closed.
        channel_id: [u8; 32],
    },
    /// The host renamed the channel; recipients update their display name.
    Renamed {
        /// The channel being renamed.
        channel_id: [u8; 32],
        /// The new display name.
        name: String,
    },
    /// The host hands a new member a plaintext snapshot of recent channel
    /// messages — MLS forward secrecy means they can't decrypt the log from
    /// before their epoch, so the host shares it directly over the DM.
    History {
        /// The channel the snapshot belongs to.
        channel_id: [u8; 32],
        /// `(sender member id, Unix ms, text)`, oldest first.
        entries: Vec<([u8; 32], u64, String)>,
    },
    /// The host offers the recipient a channel. Nothing is added until the
    /// recipient replies with [`InviteAccept`](ChannelControl::InviteAccept) —
    /// a direct invite must not silently pull someone into a group.
    Invite {
        /// The channel being offered.
        channel_id: [u8; 32],
        /// Display name of the channel.
        channel_name: String,
        /// Display name of the server it belongs to.
        server_name: String,
    },
    /// The recipient of an [`Invite`](ChannelControl::Invite) accepts. The host
    /// verifies it invited this identity, then MLS-adds them.
    InviteAccept {
        /// The channel the sender is accepting into.
        channel_id: [u8; 32],
    },
    /// The recipient of an [`Invite`](ChannelControl::Invite) declines; the host
    /// drops its pending record.
    InviteDecline {
        /// The channel the sender is declining.
        channel_id: [u8; 32],
    },
}

impl ChannelControl {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            ChannelControl::MlsWelcome {
                info,
                welcome,
                since_seq,
                log_key,
            } => {
                w.u8(1);
                info.write(&mut w);
                w.bytes(welcome).u64(*since_seq).fixed(log_key);
            }
            ChannelControl::Redeem { token, pw } => {
                w.u8(3).bytes(token).string(pw);
            }
            ChannelControl::Policy { policy } => {
                w.u8(5).bytes(policy);
            }
            ChannelControl::KickRequest {
                channel_id,
                member,
                ban,
            } => {
                w.u8(6).fixed(channel_id).fixed(member).bool(*ban);
            }
            ChannelControl::Leave { channel_id } => {
                w.u8(7).fixed(channel_id);
            }
            ChannelControl::Closed { channel_id } => {
                w.u8(8).fixed(channel_id);
            }
            ChannelControl::Renamed { channel_id, name } => {
                w.u8(9).fixed(channel_id).string(name);
            }
            ChannelControl::History {
                channel_id,
                entries,
            } => {
                w.u8(10).fixed(channel_id).u32(entries.len() as u32);
                for (sender, at_ms, text) in entries {
                    w.fixed(sender).u64(*at_ms).string(text);
                }
            }
            ChannelControl::Invite {
                channel_id,
                channel_name,
                server_name,
            } => {
                w.u8(11)
                    .fixed(channel_id)
                    .string(channel_name)
                    .string(server_name);
            }
            ChannelControl::InviteAccept { channel_id } => {
                w.u8(12).fixed(channel_id);
            }
            ChannelControl::InviteDecline { channel_id } => {
                w.u8(13).fixed(channel_id);
            }
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let out = match r.u8()? {
            1 => {
                let info = ChannelInfo::read(&mut r)?;
                let welcome = r.bytes()?.to_vec();
                let since_seq = r.u64()?;
                let log_key = r.fixed::<32>()?;
                ChannelControl::MlsWelcome {
                    info,
                    welcome,
                    since_seq,
                    log_key,
                }
            }
            3 => ChannelControl::Redeem {
                token: r.bytes()?.to_vec(),
                pw: r.string()?,
            },
            5 => ChannelControl::Policy {
                policy: r.bytes()?.to_vec(),
            },
            6 => ChannelControl::KickRequest {
                channel_id: r.fixed::<32>()?,
                member: r.fixed::<32>()?,
                ban: r.bool()?,
            },
            7 => ChannelControl::Leave {
                channel_id: r.fixed::<32>()?,
            },
            8 => ChannelControl::Closed {
                channel_id: r.fixed::<32>()?,
            },
            9 => ChannelControl::Renamed {
                channel_id: r.fixed::<32>()?,
                name: r.string()?,
            },
            10 => {
                let channel_id = r.fixed::<32>()?;
                let n = r.u32()? as usize;
                let mut entries = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    entries.push((r.fixed::<32>()?, r.u64()?, r.string()?));
                }
                ChannelControl::History {
                    channel_id,
                    entries,
                }
            }
            11 => ChannelControl::Invite {
                channel_id: r.fixed::<32>()?,
                channel_name: r.string()?,
                server_name: r.string()?,
            },
            12 => ChannelControl::InviteAccept {
                channel_id: r.fixed::<32>()?,
            },
            13 => ChannelControl::InviteDecline {
                channel_id: r.fixed::<32>()?,
            },
            other => {
                return Err(WireError::BadDiscriminant {
                    ty: "ChannelControl",
                    value: other.into(),
                })
            }
        };
        r.finish()?;
        Ok(out)
    }
}

/// A decrypted inbound channel message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelMessage {
    /// The channel it arrived on.
    pub channel_id: [u8; 32],
    /// The channel's display name.
    pub channel_name: String,
    /// The sender's `IdentityId` bytes.
    pub sender: [u8; 32],
    /// The message text.
    pub text: String,
    /// The relay-log sequence number — a stable id reactions/edits point at.
    pub seq: u64,
    /// If this message is a reply, the `seq` of the message it replies to.
    pub reply_to: Option<u64>,
    /// If this message was forwarded in, a display label of its origin
    /// (fingerprint or petname). Not authenticated — set by the forwarder.
    pub forwarded_from: Option<String>,
}

/// A decrypted emoji reaction to a channel message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelReaction {
    /// The channel it belongs to.
    pub channel_id: [u8; 32],
    /// The `seq` of the message being reacted to.
    pub target_seq: u64,
    /// The emoji.
    pub emoji: String,
    /// Who reacted (`IdentityId` bytes).
    pub member: [u8; 32],
    /// True if the reaction was withdrawn.
    pub removed: bool,
}

/// Channel-log frame tags: an application message vs. an MLS handshake Commit.
pub(crate) const FRAME_APP: u8 = 1;
pub(crate) const FRAME_COMMIT: u8 = 2;

/// Wrap an MLS payload for the channel log.
pub(crate) fn frame(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + payload.len());
    v.push(tag);
    v.extend_from_slice(payload);
    v
}

/// Split a channel-log frame into `(tag, payload)`.
pub(crate) fn unframe(blob: &[u8]) -> Option<(u8, &[u8])> {
    blob.split_first().map(|(t, rest)| (*t, rest))
}

const LOG_KEY_DOMAIN: &[u8] = b"dante/channel-content/v1";

/// Derive a channel's outer log key from its password. Deterministic in
/// `(server_root, channel_id, password)` so the host can regenerate it. Runs
/// Argon2id at keystore strength — the host does this once per channel.
pub(crate) fn derive_log_key(
    server_root: &[u8; 32],
    channel_id: &[u8; 32],
    password: &str,
) -> [u8; 32] {
    let mut salt = Vec::with_capacity(LOG_KEY_DOMAIN.len() + 64);
    salt.extend_from_slice(LOG_KEY_DOMAIN);
    salt.extend_from_slice(server_root);
    salt.extend_from_slice(channel_id);
    let mut key = [0u8; 32];
    pwhash::argon2id(password.as_bytes(), &salt, pwhash::KEYSTORE, &mut key)
        .expect("argon2id with 32-byte output and >=8-byte salt");
    key
}

/// Outer-wrap a channel-log frame under `log_key`: `nonce(24) || ct`.
pub(crate) fn wrap(log_key: &[u8; 32], channel_id: &[u8; 32], frame: &[u8]) -> Vec<u8> {
    let nonce = random_array::<24>();
    let ct = aead::xchacha_seal(log_key, &nonce, frame, channel_id);
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Reverse [`wrap`]. `None` if the blob is malformed or the key is wrong.
pub(crate) fn unwrap(log_key: &[u8; 32], channel_id: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 24 {
        return None;
    }
    let (nonce, ct) = blob.split_at(24);
    let nonce: [u8; 24] = nonce.try_into().ok()?;
    aead::xchacha_open(log_key, &nonce, ct, channel_id).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> ChannelInfo {
        ChannelInfo {
            server_root: [1u8; 32],
            server_name: "srv".into(),
            channel_id: [2u8; 32],
            channel_name: "general".into(),
            private: true,
            host_id: [9u8; 32],
            voice: false,
        }
    }

    #[test]
    fn info_roundtrip() {
        assert_eq!(ChannelInfo::decode(&info().encode()).unwrap(), info());
        let mut v = info();
        v.voice = true;
        assert_eq!(ChannelInfo::decode(&v.encode()).unwrap(), v);
    }

    #[test]
    fn info_without_the_voice_byte_decodes_as_text() {
        // A record written before voice channels existed: no trailing bool.
        let mut w = Writer::new();
        w.fixed(&[1u8; 32])
            .string("srv")
            .fixed(&[2u8; 32])
            .string("general")
            .bool(true)
            .fixed(&[9u8; 32]);
        let got = ChannelInfo::decode(&w.into_vec()).unwrap();
        assert!(!got.voice);
    }

    #[test]
    fn control_roundtrips() {
        for c in [
            ChannelControl::MlsWelcome {
                info: info(),
                welcome: vec![9, 9, 9],
                since_seq: 12,
                log_key: [7u8; 32],
            },
            ChannelControl::Redeem {
                token: vec![1, 2, 3],
                pw: "hunter2".into(),
            },
            ChannelControl::Policy { policy: vec![7] },
            ChannelControl::KickRequest {
                channel_id: [4u8; 32],
                member: [5u8; 32],
                ban: true,
            },
            ChannelControl::Leave {
                channel_id: [8u8; 32],
            },
            ChannelControl::Closed {
                channel_id: [8u8; 32],
            },
            ChannelControl::Renamed {
                channel_id: [8u8; 32],
                name: "off-topic".into(),
            },
            ChannelControl::History {
                channel_id: [8u8; 32],
                entries: vec![
                    ([1u8; 32], 111, "hi".into()),
                    ([2u8; 32], 222, "there".into()),
                ],
            },
            ChannelControl::Invite {
                channel_id: [8u8; 32],
                channel_name: "general".into(),
                server_name: "the lodge".into(),
            },
            ChannelControl::InviteAccept {
                channel_id: [8u8; 32],
            },
            ChannelControl::InviteDecline {
                channel_id: [8u8; 32],
            },
        ] {
            assert_eq!(ChannelControl::decode(&c.encode()).unwrap(), c);
        }
        assert!(ChannelControl::decode(&[14]).is_err());
    }

    #[test]
    fn frame_roundtrip() {
        let f = frame(FRAME_COMMIT, &[1, 2, 3]);
        assert_eq!(unframe(&f), Some((FRAME_COMMIT, &[1u8, 2, 3][..])));
        assert_eq!(unframe(&[]), None);
    }

    #[test]
    fn log_wrap_roundtrip_and_key_binding() {
        let sr = [3u8; 32];
        let cid = [4u8; 32];
        let k = derive_log_key(&sr, &cid, "hunter2");
        assert_eq!(k, derive_log_key(&sr, &cid, "hunter2"), "deterministic");
        assert_ne!(k, derive_log_key(&sr, &cid, "hunter3"));

        let msg = frame(FRAME_APP, b"secret channel message");
        let blob = wrap(&k, &cid, &msg);
        assert_eq!(unwrap(&k, &cid, &blob).as_deref(), Some(&msg[..]));
        // Wrong key or wrong channel id -> no read.
        assert_eq!(unwrap(&[0u8; 32], &cid, &blob), None);
        assert_eq!(unwrap(&k, &[9u8; 32], &blob), None);
        assert_eq!(unwrap(&k, &cid, &[0u8; 4]), None);
    }
}
