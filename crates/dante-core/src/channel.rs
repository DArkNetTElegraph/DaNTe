//! Channel (server) wiring on top of `dante-group`.
//!
//! A **server** is a `server_root` Ed25519 keypair (registered on the ledger).
//! A **channel** is a random 32-byte id; each member runs a
//! [`dante_group::Group`] for it. The server host is the key-distribution hub:
//! members ship their [`dante_group::SenderKeyBundle`] to each other over
//! authenticated DMs, carried inside [`ChannelControl`] messages
//! (`dante_dm::Content::Channel`). Channel messages themselves go to a per-
//! channel log on the relay (opaque; the relay never decrypts them).

use dante_crypto::{
    hash::sha256,
    sign::{SignPublic, SignSecret, SIG_LEN},
};
use dante_proto::enc::{Reader, WireError, Writer};

use crate::error::CoreError;

const REMOVE_SIG_DOMAIN: &[u8] = b"dante/channel-remove/v1";

/// A server-root-signed order to eject one member from a channel. Verifiable by
/// any member, so it can propagate member-to-member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoveOrder {
    /// The owning server's root public key (the signature verifier).
    pub server_root: [u8; 32],
    /// The channel the member is being removed from.
    pub channel_id: [u8; 32],
    /// `IdentityId` of the member to eject.
    pub member: [u8; 32],
    /// When the order was issued (Unix ms) — also its epoch, for dedup.
    pub issued_ms: u64,
    /// `server_root` over `SHA-256(REMOVE_SIG_DOMAIN || body)`.
    pub sig: [u8; SIG_LEN],
}

impl RemoveOrder {
    /// Mint and sign with the server root secret.
    pub fn mint(root: &SignSecret, channel_id: [u8; 32], member: [u8; 32], issued_ms: u64) -> Self {
        let mut o = Self {
            server_root: root.public().to_bytes(),
            channel_id,
            member,
            issued_ms,
            sig: [0u8; SIG_LEN],
        };
        o.sig = root.sign(&o.challenge());
        o
    }

    fn challenge(&self) -> [u8; 32] {
        let mut w = Writer::new();
        w.bytes(REMOVE_SIG_DOMAIN)
            .fixed(&self.server_root)
            .fixed(&self.channel_id)
            .fixed(&self.member)
            .u64(self.issued_ms);
        sha256(&w.into_vec())
    }

    /// Check the signature against the embedded server root key.
    pub fn verify(&self) -> Result<(), CoreError> {
        let pk = SignPublic::from_bytes(&self.server_root)
            .map_err(|_| CoreError::Invite("bad server key"))?;
        pk.verify(&self.challenge(), &self.sig)
            .map_err(|_| CoreError::Invite("bad remove-order signature"))
    }

    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.server_root)
            .fixed(&self.channel_id)
            .fixed(&self.member)
            .u64(self.issued_ms)
            .fixed(&self.sig);
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let out = Self {
            server_root: r.fixed::<32>()?,
            channel_id: r.fixed::<32>()?,
            member: r.fixed::<32>()?,
            issued_ms: r.u64()?,
            sig: r.fixed::<SIG_LEN>()?,
        };
        r.finish()?;
        Ok(out)
    }
}

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
    /// Eject a member: everyone drops them and rotates their own sender chain.
    Remove {
        /// Encoded [`RemoveOrder`].
        order: Vec<u8>,
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
            ChannelControl::Remove { order } => {
                w.u8(4).bytes(order);
            }
            ChannelControl::Policy { policy } => {
                w.u8(5).bytes(policy);
            }
            ChannelControl::KickRequest { channel_id, member } => {
                w.u8(6).fixed(channel_id).fixed(member);
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
            4 => ChannelControl::Remove {
                order: r.bytes()?.to_vec(),
            },
            5 => ChannelControl::Policy {
                policy: r.bytes()?.to_vec(),
            },
            6 => ChannelControl::KickRequest {
                channel_id: r.fixed::<32>()?,
                member: r.fixed::<32>()?,
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

        let rm = ChannelControl::Remove {
            order: vec![1, 2, 3, 4],
        };
        assert_eq!(ChannelControl::decode(&rm.encode()).unwrap(), rm);

        assert!(ChannelControl::decode(&[9]).is_err());
    }

    #[test]
    fn remove_order_sign_verify_roundtrip() {
        use dante_crypto::sign::SignSecret;
        let root = SignSecret::from_bytes(&[5u8; 32]);
        let o = RemoveOrder::mint(&root, [1u8; 32], [2u8; 32], 42);
        o.verify().unwrap();
        assert_eq!(RemoveOrder::decode(&o.encode()).unwrap(), o);

        let mut bad = o.clone();
        bad.member[0] ^= 1;
        assert!(bad.verify().is_err());

        let mut wrong = o.clone();
        wrong.server_root = SignSecret::from_bytes(&[6u8; 32]).public().to_bytes();
        assert!(wrong.verify().is_err());
    }
}
