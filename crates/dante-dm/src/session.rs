//! [`Session`] — X3DH + Double Ratchet tied together, plus the wire types
//! [`InitMessage`] (first contact) and [`DmMessage`] (every message after).

use dante_identity::Identity;
use dante_proto::enc::{Reader, WireError, Writer};

use crate::{
    error::DmError,
    ratchet::{Header, Ratchet, RatchetState},
    x3dh::{self, PreKeyBundle, PreKeySecrets},
};

/// A single ratchet message: header + ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmMessage {
    /// Ratchet header.
    pub header: Header,
    /// XChaCha20-Poly1305 ciphertext (`ct || tag`).
    pub ciphertext: Vec<u8>,
}

impl DmMessage {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(44 + self.ciphertext.len());
        w.fixed(&self.header.encode()).bytes(&self.ciphertext);
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let header = Header::decode(&r.fixed::<40>()?)?;
        let ciphertext = r.bytes()?.to_vec();
        r.finish()?;
        Ok(Self { header, ciphertext })
    }
}

/// The first message of a conversation: the X3DH handshake plus the initiator's
/// first ratchet message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitMessage {
    /// Initiator's long-term X25519 key.
    pub ik_a_pub: [u8; 32],
    /// Initiator's ephemeral X25519 key.
    pub ek_a_pub: [u8; 32],
    /// One-time prekey consumed, if any.
    pub used_otp: Option<[u8; 32]>,
    /// The first ratchet message.
    pub first: DmMessage,
}

impl InitMessage {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.ik_a_pub).fixed(&self.ek_a_pub);
        match &self.used_otp {
            Some(o) => {
                w.bool(true).fixed(o);
            }
            None => {
                w.bool(false);
            }
        }
        w.bytes(&self.first.encode());
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let ik_a_pub = r.fixed::<32>()?;
        let ek_a_pub = r.fixed::<32>()?;
        let used_otp = if r.bool()? {
            Some(r.fixed::<32>()?)
        } else {
            None
        };
        let first = DmMessage::decode(r.bytes()?)?;
        r.finish()?;
        Ok(Self {
            ik_a_pub,
            ek_a_pub,
            used_otp,
            first,
        })
    }
}

/// What travels as the inner payload of a sealed-sender `Envelope` for a DM:
/// either the conversation-opening handshake or a subsequent message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    /// First contact.
    Init(InitMessage),
    /// Any message after the first.
    Message(DmMessage),
}

impl Packet {
    /// Encode with a 1-byte discriminant.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Packet::Init(m) => {
                w.u8(1).bytes(&m.encode());
            }
            Packet::Message(m) => {
                w.u8(2).bytes(&m.encode());
            }
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let out = match r.u8()? {
            1 => Packet::Init(InitMessage::decode(r.bytes()?)?),
            2 => Packet::Message(DmMessage::decode(r.bytes()?)?),
            other => {
                return Err(WireError::BadDiscriminant {
                    ty: "dm::Packet",
                    value: other.into(),
                })
            }
        };
        r.finish()?;
        Ok(out)
    }
}

/// An established 1:1 session. Not `Clone`: the ratchet is single-use state.
pub struct Session {
    ratchet: Ratchet,
    ad: Vec<u8>,
}

impl Session {
    /// Begin a conversation with the owner of `bundle`, encrypting
    /// `first_plaintext` as the opening message.
    pub fn initiate(
        me: &Identity,
        bundle: &PreKeyBundle,
        first_plaintext: &[u8],
    ) -> Result<(Self, InitMessage), DmError> {
        let hs = x3dh::initiator(me, bundle)?;
        let mut ratchet = Ratchet::init_alice(&hs.result.sk, &bundle.spk_pub)?;
        let (header, ciphertext) = ratchet.encrypt(first_plaintext, &hs.result.ad)?;
        let init = InitMessage {
            ik_a_pub: me.agree_public().to_bytes(),
            ek_a_pub: hs.ephemeral_pub,
            used_otp: hs.used_otp,
            first: DmMessage { header, ciphertext },
        };
        Ok((
            Self {
                ratchet,
                ad: hs.result.ad,
            },
            init,
        ))
    }

    /// Accept an inbound [`InitMessage`], consuming a one-time prekey if it
    /// names one. Returns the session and the decrypted opening plaintext.
    pub fn accept(
        me: &Identity,
        prekeys: &mut PreKeySecrets,
        init: &InitMessage,
    ) -> Result<(Self, Vec<u8>), DmError> {
        let (res, spk_secret) =
            x3dh::responder(me, prekeys, &init.ek_a_pub, &init.ik_a_pub, init.used_otp)?;
        let mut ratchet = Ratchet::init_bob(&res.sk, spk_secret);
        let plaintext = ratchet.decrypt(&init.first.header, &init.first.ciphertext, &res.ad)?;
        Ok((
            Self {
                ratchet,
                ad: res.ad,
            },
            plaintext,
        ))
    }

    /// Encrypt an application message.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<DmMessage, DmError> {
        let (header, ciphertext) = self.ratchet.encrypt(plaintext, &self.ad)?;
        Ok(DmMessage { header, ciphertext })
    }

    /// Decrypt an application message.
    pub fn decrypt(&mut self, msg: &DmMessage) -> Result<Vec<u8>, DmError> {
        self.ratchet.decrypt(&msg.header, &msg.ciphertext, &self.ad)
    }

    /// Snapshot for the encrypted local store. **Secret.**
    pub fn export(&self) -> SessionState {
        SessionState {
            ratchet: self.ratchet.export(),
            ad: self.ad.clone(),
        }
    }

    /// Restore a session from a snapshot.
    pub fn import(state: SessionState) -> Self {
        Self {
            ratchet: Ratchet::import(state.ratchet),
            ad: state.ad,
        }
    }
}

/// A serializable snapshot of a [`Session`].
#[derive(Clone, PartialEq, Eq)]
pub struct SessionState {
    /// The ratchet snapshot.
    pub ratchet: RatchetState,
    /// The session associated data (`IK_a || IK_b`).
    pub ad: Vec<u8>,
}

impl SessionState {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.ratchet.encode()).bytes(&self.ad);
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let ratchet = RatchetState::decode(r.bytes()?)?;
        let ad = r.bytes()?.to_vec();
        r.finish()?;
        Ok(Self { ratchet, ad })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Identity, Identity, PreKeySecrets, PreKeyBundle) {
        let alice = Identity::generate(0);
        let bob = Identity::generate(0);
        let bob_pks = PreKeySecrets::generate(4);
        let bundle = bob_pks.bundle(&bob);
        (alice, bob, bob_pks, bundle)
    }

    #[test]
    fn full_conversation() {
        let (alice, bob, mut bob_pks, bundle) = setup();

        let (mut a_sess, init) = Session::initiate(&alice, &bundle, b"hi bob, it's alice").unwrap();
        let wire = init.encode();
        let init2 = InitMessage::decode(&wire).unwrap();
        let (mut b_sess, opening) = Session::accept(&bob, &mut bob_pks, &init2).unwrap();
        assert_eq!(opening, b"hi bob, it's alice");

        // a few rounds, exercising encode/decode of each message
        for (i, text) in [b"m1".as_slice(), b"m2", b"m3", b"m4"].iter().enumerate() {
            let (from, to) = if i % 2 == 0 {
                (&mut a_sess, &mut b_sess)
            } else {
                (&mut b_sess, &mut a_sess)
            };
            let msg = from.encrypt(text).unwrap();
            let msg2 = DmMessage::decode(&msg.encode()).unwrap();
            assert_eq!(to.decrypt(&msg2).unwrap(), *text);
        }
    }

    #[test]
    fn wrong_recipient_cannot_accept() {
        let (alice, _bob, mut bob_pks, bundle) = setup();
        let (_a, init) = Session::initiate(&alice, &bundle, b"secret").unwrap();
        let mallory = Identity::generate(0);
        assert!(Session::accept(&mallory, &mut bob_pks, &init).is_err());
    }

    #[test]
    fn one_time_prekey_is_consumed_once() {
        let (alice, bob, mut bob_pks, bundle) = setup();
        let before = bob_pks.otps_remaining();
        let (_a, init) = Session::initiate(&alice, &bundle, b"x").unwrap();
        Session::accept(&bob, &mut bob_pks, &init).unwrap();
        assert_eq!(bob_pks.otps_remaining(), before - 1);
        // replaying the same init (same OTP) now fails
        assert!(Session::accept(&bob, &mut bob_pks, &init).is_err());
    }

    #[test]
    fn session_survives_export_import_and_keeps_ratcheting() {
        let (alice, bob, mut bob_pks, bundle) = setup();
        let (a, init) = Session::initiate(&alice, &bundle, b"m0").unwrap();
        let (b, first) = Session::accept(&bob, &mut bob_pks, &init).unwrap();
        assert_eq!(first, b"m0");

        // snapshot both, drop, restore -- exercising encode/decode
        let mut a = {
            let bytes = a.export().encode();
            drop(a);
            Session::import(SessionState::decode(&bytes).unwrap())
        };
        let mut b = {
            let bytes = b.export().encode();
            drop(b);
            Session::import(SessionState::decode(&bytes).unwrap())
        };

        let m1 = a.encrypt(b"after reload from alice").unwrap();
        assert_eq!(b.decrypt(&m1).unwrap(), b"after reload from alice");
        let m2 = b.encrypt(b"and a reply").unwrap();
        assert_eq!(a.decrypt(&m2).unwrap(), b"and a reply");
    }

    #[test]
    fn prekey_secrets_survive_export_import() {
        let pks = PreKeySecrets::generate(6);
        let state = pks.export();
        let restored =
            PreKeySecrets::import(x3dh::PreKeySecretsState::decode(&state.encode()).unwrap());
        assert_eq!(restored.otps_remaining(), 6);
        assert_eq!(restored.spk_public(), pks.spk_public());
    }

    #[test]
    fn packet_roundtrip_both_variants() {
        let (alice, bob, mut bob_pks, bundle) = setup();
        let (mut a_sess, init) = Session::initiate(&alice, &bundle, b"open").unwrap();
        let p = Packet::Init(init);
        assert_eq!(Packet::decode(&p.encode()).unwrap(), p);

        let Packet::Init(init) = p else {
            unreachable!()
        };
        Session::accept(&bob, &mut bob_pks, &init).unwrap();
        let msg = Packet::Message(a_sess.encrypt(b"next").unwrap());
        assert_eq!(Packet::decode(&msg.encode()).unwrap(), msg);
        assert!(Packet::decode(&[9, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn init_message_roundtrip_without_otp() {
        let alice = Identity::generate(0);
        let bob = Identity::generate(0);
        let bob_pks = PreKeySecrets::generate(0);
        let bundle = bob_pks.bundle(&bob);
        let (_a, init) = Session::initiate(&alice, &bundle, b"no otp").unwrap();
        assert!(init.used_otp.is_none());
        assert_eq!(InitMessage::decode(&init.encode()).unwrap(), init);
    }
}
