//! Channel (server) wiring on top of `dante-group`.
//!
//! A **server** is a `server_root` Ed25519 keypair (registered on the ledger).
//! A **channel** is a random 32-byte id; each member runs a
//! [`dante_group::Group`] for it. The server host is the key-distribution hub:
//! members ship their [`dante_group::SenderKeyBundle`] to each other over
//! authenticated DMs, carried inside [`ChannelControl`] messages
//! (`dante_dm::Content::Channel`). Channel messages themselves go to a per-
//! channel log on the relay (opaque; the relay never decrypts them).

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
}

impl ChannelInfo {
    fn write(&self, w: &mut Writer) {
        w.fixed(&self.server_root)
            .string(&self.server_name)
            .fixed(&self.channel_id)
            .string(&self.channel_name)
            .bool(self.private);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, WireError> {
        Ok(Self {
            server_root: r.fixed::<32>()?,
            server_name: r.string()?,
            channel_id: r.fixed::<32>()?,
            channel_name: r.string()?,
            private: r.bool()?,
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

/// A control message exchanged between channel members over DM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelControl {
    /// The host adds a member: everything needed to join, including every
    /// current member's sender-key bundle.
    Invite {
        /// The channel being joined.
        info: ChannelInfo,
        /// Current member ids (`IdentityId` bytes).
        roster: Vec<[u8; 32]>,
        /// Encoded `dante_group::SenderKeyBundle` for each roster member.
        bundles: Vec<Vec<u8>>,
    },
    /// One member hands another its (updated) sender key.
    KeyBundle {
        /// The channel.
        channel_id: [u8; 32],
        /// Encoded `dante_group::SenderKeyBundle`.
        bundle: Vec<u8>,
    },
    /// A joiner presents a signed invite token to the host to be added.
    Redeem {
        /// Encoded [`crate::invite::InviteToken`].
        token: Vec<u8>,
    },
}

impl ChannelControl {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            ChannelControl::Invite {
                info,
                roster,
                bundles,
            } => {
                w.u8(1);
                info.write(&mut w);
                w.u32(roster.len() as u32);
                for m in roster {
                    w.fixed(m);
                }
                w.u32(bundles.len() as u32);
                for b in bundles {
                    w.bytes(b);
                }
            }
            ChannelControl::KeyBundle { channel_id, bundle } => {
                w.u8(2).fixed(channel_id).bytes(bundle);
            }
            ChannelControl::Redeem { token } => {
                w.u8(3).bytes(token);
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
                let roster = read_fixed_list(&mut r)?;
                let bundles = read_bytes_list(&mut r)?;
                ChannelControl::Invite {
                    info,
                    roster,
                    bundles,
                }
            }
            2 => ChannelControl::KeyBundle {
                channel_id: r.fixed::<32>()?,
                bundle: r.bytes()?.to_vec(),
            },
            3 => ChannelControl::Redeem {
                token: r.bytes()?.to_vec(),
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
}

fn read_fixed_list(r: &mut Reader<'_>) -> Result<Vec<[u8; 32]>, WireError> {
    let n = r.u32()? as usize;
    if n > r.remaining() {
        return Err(WireError::LengthTooLarge(n as u64));
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(r.fixed::<32>()?);
    }
    Ok(out)
}

fn read_bytes_list(r: &mut Reader<'_>) -> Result<Vec<Vec<u8>>, WireError> {
    let n = r.u32()? as usize;
    if n > r.remaining() {
        return Err(WireError::LengthTooLarge(n as u64));
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(r.bytes()?.to_vec());
    }
    Ok(out)
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
        }
    }

    #[test]
    fn info_roundtrip() {
        assert_eq!(ChannelInfo::decode(&info().encode()).unwrap(), info());
    }

    #[test]
    fn control_roundtrips() {
        let invite = ChannelControl::Invite {
            info: info(),
            roster: vec![[3u8; 32], [4u8; 32]],
            bundles: vec![vec![9, 9], vec![1]],
        };
        assert_eq!(ChannelControl::decode(&invite.encode()).unwrap(), invite);

        let kb = ChannelControl::KeyBundle {
            channel_id: [7u8; 32],
            bundle: vec![5, 6, 7],
        };
        assert_eq!(ChannelControl::decode(&kb.encode()).unwrap(), kb);

        assert!(ChannelControl::decode(&[9]).is_err());
    }
}
