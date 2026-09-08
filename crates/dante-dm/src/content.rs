//! [`Content`] — the application payload carried *inside* the ratchet (i.e. the
//! plaintext that [`crate::Session::encrypt`] seals). Distinct from
//! [`crate::Packet`], which is the transport framing (first contact vs. a
//! subsequent message).

use dante_proto::enc::{Reader, WireError, Writer};

use crate::file::FileManifest;

/// A decrypted direct-message payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    /// A UTF-8 text message.
    Text(String),
    /// A file offer: the manifest travels here; the ciphertext chunks are
    /// fetched separately from the relay blob store.
    File(FileManifest),
    /// A channel-control message (invite, sender-key exchange). The bytes are
    /// opaque to `dante-dm`; `dante-core` defines their shape.
    Channel(Vec<u8>),
    /// An ephemeral "I am typing" signal. Never persisted, never acknowledged;
    /// the receiver shows it for a few seconds and then forgets it. Sending is
    /// gated by a user setting; see `docs/DESIGN.md` Phase 8.
    Typing,
    /// An emoji reaction to another channel message, identified by its relay-log
    /// sequence number. `remove` toggles it off.
    Reaction {
        /// The `seq` of the message being reacted to.
        target_seq: u64,
        /// The emoji (a short UTF-8 string).
        emoji: String,
        /// True to withdraw a previously-added reaction.
        remove: bool,
    },
    /// A 1:1 call SDP **offer** (the caller starts a call). Carries the DTLS
    /// fingerprint, so riding the authenticated ratchet is what binds the media
    /// transport to this identity.
    CallOffer(String),
    /// The SDP **answer** to a `CallOffer`.
    CallAnswer(String),
    /// A trickled ICE candidate for the in-progress call (empty = end of
    /// gathering).
    CallIce(String),
    /// Hang up / decline the call.
    CallEnd,
    /// An MLS **Welcome** inviting the recipient into a channel's group call.
    /// `blob` is an opaque `dante_mls` handshake blob.
    GroupCallWelcome {
        /// The channel the group call belongs to.
        channel_id: [u8; 32],
        /// The opaque MLS Welcome.
        blob: Vec<u8>,
    },
    /// An MLS **Commit** advancing a channel group call's epoch (a member
    /// joined or left). Opaque `dante_mls` handshake blob.
    GroupCallCommit {
        /// The channel the group call belongs to.
        channel_id: [u8; 32],
        /// The opaque MLS Commit.
        blob: Vec<u8>,
    },
    /// The sender is leaving a channel's group call; remaining members drop
    /// their media leg to the sender and rekey the MLS group without them.
    GroupCallLeave {
        /// The channel the group call belongs to.
        channel_id: [u8; 32],
    },
    /// Replace the text of an earlier channel message (only its original
    /// author's edit is honoured). Rides the channel log like a normal message.
    Edit {
        /// The relay-log `seq` of the message being edited.
        target_seq: u64,
        /// The new text.
        text: String,
    },
    /// Withdraw an earlier channel message (only its original author's delete
    /// is honoured).
    Delete {
        /// The relay-log `seq` of the message being deleted.
        target_seq: u64,
    },
    /// A channel message posted as a reply to an earlier one. Otherwise a
    /// normal text message (editable / deletable like any other).
    Reply {
        /// The relay-log `seq` of the message being replied to.
        target_seq: u64,
        /// The reply text.
        text: String,
    },
    /// Pin (or, with `unpin`, un-pin) an earlier channel message. Rides the
    /// channel log; honoured from the channel host or the message's author.
    Pin {
        /// The relay-log `seq` of the message being pinned.
        target_seq: u64,
        /// True to remove an existing pin.
        unpin: bool,
    },
}

impl Content {
    /// Encode with a 1-byte discriminant.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Content::Text(s) => {
                w.u8(1).string(s);
            }
            Content::File(m) => {
                w.u8(2).bytes(&m.encode());
            }
            Content::Channel(b) => {
                w.u8(3).bytes(b);
            }
            Content::Typing => {
                w.u8(4);
            }
            Content::Reaction {
                target_seq,
                emoji,
                remove,
            } => {
                w.u8(5).u64(*target_seq).string(emoji).bool(*remove);
            }
            Content::CallOffer(s) => {
                w.u8(6).string(s);
            }
            Content::CallAnswer(s) => {
                w.u8(7).string(s);
            }
            Content::CallIce(s) => {
                w.u8(8).string(s);
            }
            Content::CallEnd => {
                w.u8(9);
            }
            Content::GroupCallWelcome { channel_id, blob } => {
                w.u8(10).fixed(channel_id).bytes(blob);
            }
            Content::GroupCallCommit { channel_id, blob } => {
                w.u8(11).fixed(channel_id).bytes(blob);
            }
            Content::GroupCallLeave { channel_id } => {
                w.u8(12).fixed(channel_id);
            }
            Content::Edit { target_seq, text } => {
                w.u8(13).u64(*target_seq).string(text);
            }
            Content::Delete { target_seq } => {
                w.u8(14).u64(*target_seq);
            }
            Content::Reply { target_seq, text } => {
                w.u8(15).u64(*target_seq).string(text);
            }
            Content::Pin { target_seq, unpin } => {
                w.u8(16).u64(*target_seq).bool(*unpin);
            }
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let out = match r.u8()? {
            1 => Content::Text(r.string()?),
            2 => Content::File(FileManifest::decode(r.bytes()?)?),
            3 => Content::Channel(r.bytes()?.to_vec()),
            4 => Content::Typing,
            5 => Content::Reaction {
                target_seq: r.u64()?,
                emoji: r.string()?,
                remove: r.bool()?,
            },
            6 => Content::CallOffer(r.string()?),
            7 => Content::CallAnswer(r.string()?),
            8 => Content::CallIce(r.string()?),
            9 => Content::CallEnd,
            10 => Content::GroupCallWelcome {
                channel_id: r.fixed::<32>()?,
                blob: r.bytes()?.to_vec(),
            },
            11 => Content::GroupCallCommit {
                channel_id: r.fixed::<32>()?,
                blob: r.bytes()?.to_vec(),
            },
            12 => Content::GroupCallLeave {
                channel_id: r.fixed::<32>()?,
            },
            13 => Content::Edit {
                target_seq: r.u64()?,
                text: r.string()?,
            },
            14 => Content::Delete {
                target_seq: r.u64()?,
            },
            15 => Content::Reply {
                target_seq: r.u64()?,
                text: r.string()?,
            },
            16 => Content::Pin {
                target_seq: r.u64()?,
                unpin: r.bool()?,
            },
            other => {
                return Err(WireError::BadDiscriminant {
                    ty: "dm::Content",
                    value: other.into(),
                })
            }
        };
        r.finish()?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use dante_identity::Identity;

    use super::*;

    #[test]
    fn text_roundtrip() {
        let c = Content::Text("hello".into());
        assert_eq!(Content::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn file_roundtrip() {
        let id = Identity::generate(0);
        let (m, _) = FileManifest::build(&id, "a.bin", &[1u8; 1000]);
        let c = Content::File(m);
        assert_eq!(Content::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn typing_roundtrip() {
        let c = Content::Typing;
        assert_eq!(Content::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn reaction_roundtrip() {
        let c = Content::Reaction {
            target_seq: 42,
            emoji: "🔥".into(),
            remove: true,
        };
        assert_eq!(Content::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn call_signalling_roundtrips() {
        for c in [
            Content::CallOffer("v=0\r\n...".into()),
            Content::CallAnswer("v=0\r\n...".into()),
            Content::CallIce("candidate:1 1 udp 2130706431 127.0.0.1 5000 typ host".into()),
            Content::CallEnd,
        ] {
            assert_eq!(Content::decode(&c.encode()).unwrap(), c);
        }
    }

    #[test]
    fn group_call_signalling_roundtrips() {
        for c in [
            Content::GroupCallWelcome {
                channel_id: [3u8; 32],
                blob: vec![1, 2, 3, 4],
            },
            Content::GroupCallCommit {
                channel_id: [4u8; 32],
                blob: vec![9, 9],
            },
            Content::GroupCallLeave {
                channel_id: [5u8; 32],
            },
        ] {
            assert_eq!(Content::decode(&c.encode()).unwrap(), c);
        }
    }

    #[test]
    fn edit_delete_reply_roundtrip() {
        for c in [
            Content::Edit {
                target_seq: 77,
                text: "fixed a typo".into(),
            },
            Content::Delete { target_seq: 42 },
            Content::Reply {
                target_seq: 12,
                text: "agreed".into(),
            },
            Content::Pin {
                target_seq: 5,
                unpin: false,
            },
            Content::Pin {
                target_seq: 5,
                unpin: true,
            },
        ] {
            assert_eq!(Content::decode(&c.encode()).unwrap(), c);
        }
    }

    #[test]
    fn bad_tag_rejected() {
        assert!(Content::decode(&[20]).is_err());
    }
}
