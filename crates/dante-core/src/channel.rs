//! Channel (server) wiring on top of `dante-mls`.
//!
//! A **server** is a `server_root` Ed25519 keypair (registered on the ledger).
//! A **channel** is a random 32-byte id backed by one MLS group (RFC 9420),
//! created by the server host. The host is the sole committer: it adds and
//! removes members with MLS Commits, which travel in the channel's relay log
//! interleaved with the encrypted messages (both opaque to the relay). A new
//! member receives an MLS **Welcome** over an authenticated DM
//! ([`ChannelControl::MlsWelcome`]) and then catches up from the log.

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
}

impl ChannelInfo {
    pub(crate) fn write(&self, w: &mut Writer) {
        w.fixed(&self.server_root)
            .string(&self.server_name)
            .fixed(&self.channel_id)
            .string(&self.channel_name)
            .bool(self.private)
            .fixed(&self.host_id);
    }
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, WireError> {
        Ok(Self {
            server_root: r.fixed::<32>()?,
            server_name: r.string()?,
            channel_id: r.fixed::<32>()?,
            channel_name: r.string()?,
            private: r.bool()?,
            host_id: r.fixed::<32>()?,
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
    /// A member with `PERM_KICK` asks the host to remove someone.
    KickRequest {
        /// The channel.
        channel_id: [u8; 32],
        /// The member to remove.
        member: [u8; 32],
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
            } => {
                w.u8(1);
                info.write(&mut w);
                w.bytes(welcome).u64(*since_seq);
            }
            ChannelControl::Redeem { token, pw } => {
                w.u8(3).bytes(token).string(pw);
            }
            ChannelControl::Policy { policy } => {
                w.u8(5).bytes(policy);
            }
            ChannelControl::KickRequest { channel_id, member } => {
                w.u8(6).fixed(channel_id).fixed(member);
            }
            ChannelControl::Leave { channel_id } => {
                w.u8(7).fixed(channel_id);
            }
            ChannelControl::Closed { channel_id } => {
                w.u8(8).fixed(channel_id);
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
                ChannelControl::MlsWelcome {
                    info,
                    welcome,
                    since_seq,
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
            },
            7 => ChannelControl::Leave {
                channel_id: r.fixed::<32>()?,
            },
            8 => ChannelControl::Closed {
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
    /// The relay-log sequence number — a stable id reactions point at.
    pub seq: u64,
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
        }
    }

    #[test]
    fn info_roundtrip() {
        assert_eq!(ChannelInfo::decode(&info().encode()).unwrap(), info());
    }

    #[test]
    fn control_roundtrips() {
        for c in [
            ChannelControl::MlsWelcome {
                info: info(),
                welcome: vec![9, 9, 9],
                since_seq: 12,
            },
            ChannelControl::Redeem {
                token: vec![1, 2, 3],
                pw: "hunter2".into(),
            },
            ChannelControl::Policy { policy: vec![7] },
            ChannelControl::KickRequest {
                channel_id: [4u8; 32],
                member: [5u8; 32],
            },
            ChannelControl::Leave {
                channel_id: [8u8; 32],
            },
            ChannelControl::Closed {
                channel_id: [8u8; 32],
            },
        ] {
            assert_eq!(ChannelControl::decode(&c.encode()).unwrap(), c);
        }
        assert!(ChannelControl::decode(&[9]).is_err());
    }

    #[test]
    fn frame_roundtrip() {
        let f = frame(FRAME_COMMIT, &[1, 2, 3]);
        assert_eq!(unframe(&f), Some((FRAME_COMMIT, &[1u8, 2, 3][..])));
        assert_eq!(unframe(&[]), None);
    }
}
