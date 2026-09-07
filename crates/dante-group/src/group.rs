//! A sender-keys group ratchet for channel messages.
//!
//! Each member keeps one **sender chain** per channel and hands its current
//! chain key to every other member over an authenticated pairwise DM (a
//! [`SenderKeyBundle`]). A message is encrypted with the sender's own chain,
//! and signed with the sender's per-group Ed25519 key so an insider who also
//! holds that chain key cannot forge messages as another member.
//!
//! Forward secrecy holds within a chain (keys are deleted after use). On a
//! member **removal**, every remaining member rotates its own chain and
//! redistributes, so the removed member cannot read subsequent messages —
//! O(n) rekey, weaker than MLS's O(log n) and without MLS's post-compromise
//! security. Migrating channels to MLS (RFC 9420) is planned; see
//! `docs/THREAT_MODEL.md`.

use std::collections::HashMap;

use dante_crypto::{
    aead, kdf,
    mac::hmac_sha256,
    random_array,
    sign::{SignPublic, SignSecret, SIG_LEN},
};
use dante_proto::enc::{Reader, Writer};
use zeroize::Zeroize;

use crate::error::GroupError;

/// A member's stable id within a group (its `IdentityId` bytes).
pub type MemberId = [u8; 32];

/// Maximum message keys skipped (and retained) across a gap in one chain.
pub const MAX_SKIP: u32 = 2000;

const MK_INFO: &[u8] = b"DaNTe/group/msg/v1";
const SIG_DOMAIN: &[u8] = b"dante/group/message/v1";

fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    (hmac_sha256(ck, &[0x02]), hmac_sha256(ck, &[0x01])) // (next_ck, mk)
}

fn message_keys(mk: &[u8; 32]) -> ([u8; 32], [u8; 24]) {
    let prk = kdf::extract(&[0u8; 32], mk);
    let mut out = [0u8; 56];
    kdf::expand(&prk, MK_INFO, &mut out).expect("56 <= 255*32");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    key.copy_from_slice(&out[..32]);
    nonce.copy_from_slice(&out[32..]);
    (key, nonce)
}

fn sig_challenge(
    group_id: &[u8; 32],
    sender: &MemberId,
    iteration: u32,
    ciphertext: &[u8],
) -> [u8; 32] {
    dante_crypto::hash::sha256_parts(&[
        SIG_DOMAIN,
        group_id,
        sender,
        &iteration.to_be_bytes(),
        ciphertext,
    ])
}

fn msg_aad(group_id: &[u8; 32], sender: &MemberId, iteration: u32) -> Vec<u8> {
    let mut w = Writer::with_capacity(68);
    w.fixed(group_id).fixed(sender).u32(iteration);
    w.into_vec()
}

/// What a member distributes so others can decrypt its channel messages.
/// **Contains a live chain key — send only over an authenticated DM.**
#[derive(Clone)]
pub struct SenderKeyBundle {
    /// The member this chain belongs to.
    pub member: MemberId,
    /// The member's per-group Ed25519 verification key.
    pub sig_pub: [u8; 32],
    /// The member's current chain key.
    pub chain_key: [u8; 32],
    /// The iteration `chain_key` is at.
    pub iteration: u32,
}

impl SenderKeyBundle {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(100);
        w.fixed(&self.member)
            .fixed(&self.sig_pub)
            .fixed(&self.chain_key)
            .u32(self.iteration);
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, GroupError> {
        let mut r = Reader::new(bytes);
        let member = r.fixed::<32>()?;
        let sig_pub = r.fixed::<32>()?;
        let chain_key = r.fixed::<32>()?;
        let iteration = r.u32()?;
        r.finish()?;
        Ok(Self {
            member,
            sig_pub,
            chain_key,
            iteration,
        })
    }
}

impl Drop for SenderKeyBundle {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}

/// A single encrypted channel message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMessage {
    /// Who sent it.
    pub sender: MemberId,
    /// The sender's chain iteration for this message.
    pub iteration: u32,
    /// `ct || tag`.
    pub ciphertext: Vec<u8>,
    /// Sender's per-group signature over [`sig_challenge`].
    pub sig: [u8; SIG_LEN],
}

impl GroupMessage {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(40 + self.ciphertext.len() + SIG_LEN);
        w.fixed(&self.sender)
            .u32(self.iteration)
            .bytes(&self.ciphertext)
            .fixed(&self.sig);
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, GroupError> {
        let mut r = Reader::new(bytes);
        let sender = r.fixed::<32>()?;
        let iteration = r.u32()?;
        let ciphertext = r.bytes()?.to_vec();
        let sig = r.fixed::<SIG_LEN>()?;
        r.finish()?;
        Ok(Self {
            sender,
            iteration,
            ciphertext,
            sig,
        })
    }
}

struct SenderState {
    sig: SignSecret,
    chain_key: [u8; 32],
    iteration: u32,
}

impl Drop for SenderState {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}

struct ReceiverState {
    sig_pub: SignPublic,
    chain_key: [u8; 32],
    iteration: u32,
    skipped: HashMap<u32, [u8; 32]>,
}

impl Drop for ReceiverState {
    fn drop(&mut self) {
        self.chain_key.zeroize();
        for mk in self.skipped.values_mut() {
            mk.zeroize();
        }
    }
}

/// One member's view of a channel: its own sender chain plus a receiver chain
/// for every other member it has a [`SenderKeyBundle`] for.
pub struct Group {
    group_id: [u8; 32],
    me: MemberId,
    sender: SenderState,
    receivers: HashMap<MemberId, ReceiverState>,
}

impl Group {
    /// Create a fresh view for `me` in channel `group_id`. Returns the view and
    /// the [`SenderKeyBundle`] to hand to every other member.
    pub fn create(group_id: [u8; 32], me: MemberId) -> (Self, SenderKeyBundle) {
        let sig = SignSecret::generate();
        let chain_key = random_array::<32>();
        let bundle = SenderKeyBundle {
            member: me,
            sig_pub: sig.public().to_bytes(),
            chain_key,
            iteration: 0,
        };
        let group = Self {
            group_id,
            me,
            sender: SenderState {
                sig,
                chain_key,
                iteration: 0,
            },
            receivers: HashMap::new(),
        };
        (group, bundle)
    }

    /// The channel id.
    pub fn group_id(&self) -> &[u8; 32] {
        &self.group_id
    }

    /// This member's id.
    pub fn me(&self) -> &MemberId {
        &self.me
    }

    /// Members we can currently decrypt (excludes ourselves).
    pub fn known_members(&self) -> impl Iterator<Item = &MemberId> {
        self.receivers.keys()
    }

    /// Install (or replace) a peer member's sender key from their bundle.
    pub fn upsert_member(&mut self, bundle: &SenderKeyBundle) -> Result<(), GroupError> {
        if bundle.member == self.me {
            return Ok(());
        }
        let sig_pub =
            SignPublic::from_bytes(&bundle.sig_pub).map_err(|_| GroupError::BadSignature)?;
        self.receivers.insert(
            bundle.member,
            ReceiverState {
                sig_pub,
                chain_key: bundle.chain_key,
                iteration: bundle.iteration,
                skipped: HashMap::new(),
            },
        );
        Ok(())
    }

    /// Remove a member and rotate our own chain. Returns our **new** bundle,
    /// which must be redistributed to the remaining members.
    pub fn remove_member(&mut self, member: &MemberId) -> SenderKeyBundle {
        self.receivers.remove(member);
        let new_key = random_array::<32>();
        self.sender.chain_key.zeroize();
        self.sender.chain_key = new_key;
        self.sender.iteration = 0;
        SenderKeyBundle {
            member: self.me,
            sig_pub: self.sender.sig.public().to_bytes(),
            chain_key: self.sender.chain_key,
            iteration: 0,
        }
    }

    /// Our current bundle (e.g. to send to a member who just joined).
    pub fn my_bundle(&self) -> SenderKeyBundle {
        SenderKeyBundle {
            member: self.me,
            sig_pub: self.sender.sig.public().to_bytes(),
            chain_key: self.sender.chain_key,
            iteration: self.sender.iteration,
        }
    }

    /// Encrypt `plaintext` as a channel message from us.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> GroupMessage {
        let (next_ck, mk) = kdf_ck(&self.sender.chain_key);
        let iteration = self.sender.iteration;
        self.sender.chain_key.zeroize();
        self.sender.chain_key = next_ck;
        self.sender.iteration += 1;

        let (key, nonce) = message_keys(&mk);
        let aad = msg_aad(&self.group_id, &self.me, iteration);
        let ciphertext = aead::xchacha_seal(&key, &nonce, plaintext, &aad);
        let sig = self.sender.sig.sign(&sig_challenge(
            &self.group_id,
            &self.me,
            iteration,
            &ciphertext,
        ));
        GroupMessage {
            sender: self.me,
            iteration,
            ciphertext,
            sig,
        }
    }

    /// Decrypt a channel message from another member.
    pub fn decrypt(&mut self, msg: &GroupMessage) -> Result<Vec<u8>, GroupError> {
        let rx = self
            .receivers
            .get_mut(&msg.sender)
            .ok_or(GroupError::UnknownMember)?;
        rx.sig_pub
            .verify(
                &sig_challenge(&self.group_id, &msg.sender, msg.iteration, &msg.ciphertext),
                &msg.sig,
            )
            .map_err(|_| GroupError::BadSignature)?;

        // A retained skipped key?
        if let Some(mk) = rx.skipped.remove(&msg.iteration) {
            return open(
                &mk,
                &self.group_id,
                &msg.sender,
                msg.iteration,
                &msg.ciphertext,
            );
        }
        if msg.iteration < rx.iteration {
            return Err(GroupError::TooOld);
        }
        if msg.iteration - rx.iteration > MAX_SKIP {
            return Err(GroupError::TooManySkipped);
        }

        // Advance the chain, retaining skipped message keys.
        let mut ck = rx.chain_key;
        while rx.iteration < msg.iteration {
            let (next_ck, mk) = kdf_ck(&ck);
            rx.skipped.insert(rx.iteration, mk);
            ck.zeroize();
            ck = next_ck;
            rx.iteration += 1;
        }
        let (next_ck, mk) = kdf_ck(&ck);
        ck.zeroize();
        rx.chain_key.zeroize();
        rx.chain_key = next_ck;
        rx.iteration += 1;

        open(
            &mk,
            &self.group_id,
            &msg.sender,
            msg.iteration,
            &msg.ciphertext,
        )
    }
}

fn open(
    mk: &[u8; 32],
    group_id: &[u8; 32],
    sender: &MemberId,
    iteration: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, GroupError> {
    let (key, nonce) = message_keys(mk);
    aead::xchacha_open(
        &key,
        &nonce,
        ciphertext,
        &msg_aad(group_id, sender, iteration),
    )
    .map_err(|_| GroupError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GID: [u8; 32] = [0x9a; 32];

    fn member(seed: u8) -> MemberId {
        dante_crypto::hash::sha256(&[seed; 32])
    }

    #[test]
    fn three_members_all_read_each_others_messages() {
        let (m0, m1, m2) = (member(0), member(1), member(2));
        let (mut g0, b0) = Group::create(GID, m0);
        let (mut g1, b1) = Group::create(GID, m1);
        let (mut g2, b2) = Group::create(GID, m2);
        for (g, others) in [
            (&mut g0, [&b1, &b2]),
            (&mut g1, [&b0, &b2]),
            (&mut g2, [&b0, &b1]),
        ] {
            for b in others {
                g.upsert_member(b).unwrap();
            }
        }

        let m = g0.encrypt(b"hello channel");
        assert_eq!(g1.decrypt(&m).unwrap(), b"hello channel");
        assert_eq!(g2.decrypt(&m).unwrap(), b"hello channel");

        let r = g2.encrypt(b"reply from m2");
        assert_eq!(g0.decrypt(&r).unwrap(), b"reply from m2");
        assert_eq!(g1.decrypt(&r).unwrap(), b"reply from m2");
    }

    #[test]
    fn out_of_order_and_skipped_messages() {
        let (mut a, ba) = Group::create(GID, member(0));
        let (mut b, bb) = Group::create(GID, member(1));
        a.upsert_member(&bb).unwrap();
        b.upsert_member(&ba).unwrap();

        let m0 = a.encrypt(b"0");
        let m1 = a.encrypt(b"1");
        let m2 = a.encrypt(b"2");
        assert_eq!(b.decrypt(&m2).unwrap(), b"2");
        assert_eq!(b.decrypt(&m0).unwrap(), b"0");
        assert_eq!(b.decrypt(&m1).unwrap(), b"1");
        // replay of a consumed key fails
        assert!(b.decrypt(&m0).is_err());
    }

    #[test]
    fn removed_member_cannot_read_new_messages() {
        let (m0, m1, m2) = (member(0), member(1), member(2));
        let (mut g0, b0) = Group::create(GID, m0);
        let (mut g1, b1) = Group::create(GID, m1);
        let (mut g2, b2) = Group::create(GID, m2);
        for (g, o) in [
            (&mut g0, [&b1, &b2]),
            (&mut g1, [&b0, &b2]),
            (&mut g2, [&b0, &b1]),
        ] {
            for b in o {
                g.upsert_member(b).unwrap();
            }
        }

        // everyone removes m2 and redistributes new chains
        let n0 = g0.remove_member(&m2);
        let n1 = g1.remove_member(&m2);
        g0.upsert_member(&n1).unwrap();
        g1.upsert_member(&n0).unwrap();

        let msg = g0.encrypt(b"secret after removal");
        assert_eq!(g1.decrypt(&msg).unwrap(), b"secret after removal");
        // g2 still has the OLD b0 chain; g0 is now on a new chain -> mismatch
        assert!(g2.decrypt(&msg).is_err());
    }

    #[test]
    fn insider_cannot_forge_as_another_member() {
        let (mut a, ba) = Group::create(GID, member(0));
        let (mut b, bb) = Group::create(GID, member(1));
        let (mut c, bc) = Group::create(GID, member(2));
        for (g, o) in [
            (&mut a, [&bb, &bc]),
            (&mut b, [&ba, &bc]),
            (&mut c, [&ba, &bb]),
        ] {
            for x in o {
                g.upsert_member(x).unwrap();
            }
        }
        // c holds a's chain key (from ba). Forge a message "as a".
        let mut forged = c.encrypt(b"i am totally alice");
        forged.sender = *a.me();
        // signature is still c's group key -> b rejects it against a's sig_pub
        assert!(matches!(b.decrypt(&forged), Err(GroupError::BadSignature)));
    }

    #[test]
    fn wire_roundtrips() {
        let (mut a, ba) = Group::create(GID, member(0));
        assert_eq!(
            SenderKeyBundle::decode(&ba.encode()).unwrap().member,
            ba.member
        );
        let m = a.encrypt(b"x");
        assert_eq!(GroupMessage::decode(&m.encode()).unwrap(), m);
    }
}
