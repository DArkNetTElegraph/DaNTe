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
//! security. Channels have since migrated to MLS (RFC 9420) in `dante-mls`;
//! this module is retired and kept only for the fuzz target. See
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
/// AAD domain for out-of-band ephemeral signals (typing indicators, etc.).
const SIGNAL_DOMAIN: &[u8] = b"dante/group/signal/v1";

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

fn signal_aad(group_id: &[u8; 32], sender: &MemberId) -> Vec<u8> {
    let mut w = Writer::with_capacity(SIGNAL_DOMAIN.len() + 64);
    w.bytes(SIGNAL_DOMAIN).fixed(group_id).fixed(sender);
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
    /// The member's **static** key for ephemeral out-of-band signals (typing
    /// indicators). Never advanced, so a signal does not touch the forward-
    /// secret message chain. Rotated only on a member removal.
    pub signal_key: [u8; 32],
}

impl SenderKeyBundle {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(132);
        w.fixed(&self.member)
            .fixed(&self.sig_pub)
            .fixed(&self.chain_key)
            .u32(self.iteration)
            .fixed(&self.signal_key);
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, GroupError> {
        let mut r = Reader::new(bytes);
        let member = r.fixed::<32>()?;
        let sig_pub = r.fixed::<32>()?;
        let chain_key = r.fixed::<32>()?;
        let iteration = r.u32()?;
        let signal_key = r.fixed::<32>()?;
        r.finish()?;
        Ok(Self {
            member,
            sig_pub,
            chain_key,
            iteration,
            signal_key,
        })
    }
}

impl Drop for SenderKeyBundle {
    fn drop(&mut self) {
        self.chain_key.zeroize();
        self.signal_key.zeroize();
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
    signal_key: [u8; 32],
}

impl Drop for SenderState {
    fn drop(&mut self) {
        self.chain_key.zeroize();
        self.signal_key.zeroize();
    }
}

struct ReceiverState {
    sig_pub: SignPublic,
    chain_key: [u8; 32],
    iteration: u32,
    skipped: HashMap<u32, [u8; 32]>,
    signal_key: [u8; 32],
}

impl Drop for ReceiverState {
    fn drop(&mut self) {
        self.chain_key.zeroize();
        self.signal_key.zeroize();
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
        let signal_key = random_array::<32>();
        let bundle = SenderKeyBundle {
            member: me,
            sig_pub: sig.public().to_bytes(),
            chain_key,
            iteration: 0,
            signal_key,
        };
        let group = Self {
            group_id,
            me,
            sender: SenderState {
                sig,
                chain_key,
                iteration: 0,
                signal_key,
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
                signal_key: bundle.signal_key,
            },
        );
        Ok(())
    }

    /// Remove a member and rotate our own chain (and signal key, so the removed
    /// member can no longer read our ephemeral signals either). Returns our
    /// **new** bundle, which must be redistributed to the remaining members.
    pub fn remove_member(&mut self, member: &MemberId) -> SenderKeyBundle {
        self.receivers.remove(member);
        let new_key = random_array::<32>();
        self.sender.chain_key.zeroize();
        self.sender.chain_key = new_key;
        self.sender.iteration = 0;
        self.sender.signal_key.zeroize();
        self.sender.signal_key = random_array::<32>();
        SenderKeyBundle {
            member: self.me,
            sig_pub: self.sender.sig.public().to_bytes(),
            chain_key: self.sender.chain_key,
            iteration: 0,
            signal_key: self.sender.signal_key,
        }
    }

    /// Our current bundle (e.g. to send to a member who just joined).
    pub fn my_bundle(&self) -> SenderKeyBundle {
        SenderKeyBundle {
            member: self.me,
            sig_pub: self.sender.sig.public().to_bytes(),
            chain_key: self.sender.chain_key,
            iteration: self.sender.iteration,
            signal_key: self.sender.signal_key,
        }
    }

    /// Reconstructed bundles for every *other* member we currently know, at
    /// their current chain position. Handing these to a new joiner keys them to
    /// the whole group at once (they still see only messages sent after they
    /// join — sender-keys has no history). The chain keys are live secrets:
    /// send only over authenticated DMs.
    pub fn peer_bundles(&self) -> Vec<SenderKeyBundle> {
        self.receivers
            .iter()
            .map(|(&member, r)| SenderKeyBundle {
                member,
                sig_pub: r.sig_pub.to_bytes(),
                chain_key: r.chain_key,
                iteration: r.iteration,
                signal_key: r.signal_key,
            })
            .collect()
    }

    /// AEAD-seal an ephemeral signal (e.g. a typing marker) under our static
    /// signal key. Does **not** advance any chain and touches no persisted
    /// state, so it is safe to send often. A member holding our
    /// [`SenderKeyBundle`] recovers `(our member id, plaintext)` via
    /// [`Group::open_signal`].
    pub fn seal_signal(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = random_array::<24>();
        let ct = aead::xchacha_seal(
            &self.sender.signal_key,
            &nonce,
            plaintext,
            &signal_aad(&self.group_id, &self.me),
        );
        let mut w = Writer::new();
        w.fixed(&self.me).fixed(&nonce).bytes(&ct);
        w.into_vec()
    }

    /// Open a signal blob against the sealing member's signal key. Returns the
    /// authenticated `(member, plaintext)`, or `None` if the blob is malformed,
    /// from an unknown member, or fails authentication.
    pub fn open_signal(&self, blob: &[u8]) -> Option<(MemberId, Vec<u8>)> {
        let mut r = Reader::new(blob);
        let member = r.fixed::<32>().ok()?;
        let nonce = r.fixed::<24>().ok()?;
        let ct = r.bytes().ok()?.to_vec();
        r.finish().ok()?;
        let key = if member == self.me {
            &self.sender.signal_key
        } else {
            &self.receivers.get(&member)?.signal_key
        };
        let pt = aead::xchacha_open(key, &nonce, &ct, &signal_aad(&self.group_id, &member)).ok()?;
        Some((member, pt))
    }

    /// Snapshot for the encrypted local store. **All secret.**
    pub fn export(&self) -> GroupState {
        GroupState {
            group_id: self.group_id,
            me: self.me,
            sender_sig_secret: self.sender.sig.to_bytes(),
            sender_chain_key: self.sender.chain_key,
            sender_iteration: self.sender.iteration,
            sender_signal_key: self.sender.signal_key,
            receivers: self
                .receivers
                .iter()
                .map(|(&m, r)| ReceiverSnapshot {
                    member: m,
                    sig_pub: r.sig_pub.to_bytes(),
                    chain_key: r.chain_key,
                    iteration: r.iteration,
                    skipped: r.skipped.iter().map(|(&n, &mk)| (n, mk)).collect(),
                    signal_key: r.signal_key,
                })
                .collect(),
        }
    }

    /// Restore a group view from a snapshot.
    pub fn import(s: &GroupState) -> Result<Self, GroupError> {
        let mut receivers = HashMap::new();
        for r in &s.receivers {
            receivers.insert(
                r.member,
                ReceiverState {
                    sig_pub: SignPublic::from_bytes(&r.sig_pub)
                        .map_err(|_| GroupError::BadSignature)?,
                    chain_key: r.chain_key,
                    iteration: r.iteration,
                    skipped: r.skipped.iter().copied().collect(),
                    signal_key: r.signal_key,
                },
            );
        }
        Ok(Self {
            group_id: s.group_id,
            me: s.me,
            sender: SenderState {
                sig: SignSecret::from_bytes(&s.sender_sig_secret),
                chain_key: s.sender_chain_key,
                iteration: s.sender_iteration,
                signal_key: s.sender_signal_key,
            },
            receivers,
        })
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

/// A serializable snapshot of a [`Group`].
#[derive(Clone)]
pub struct GroupState {
    group_id: [u8; 32],
    me: MemberId,
    sender_sig_secret: [u8; 32],
    sender_chain_key: [u8; 32],
    sender_iteration: u32,
    sender_signal_key: [u8; 32],
    receivers: Vec<ReceiverSnapshot>,
}

#[derive(Clone)]
struct ReceiverSnapshot {
    member: MemberId,
    sig_pub: [u8; 32],
    chain_key: [u8; 32],
    iteration: u32,
    skipped: Vec<(u32, [u8; 32])>,
    signal_key: [u8; 32],
}

impl GroupState {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.group_id)
            .fixed(&self.me)
            .fixed(&self.sender_sig_secret)
            .fixed(&self.sender_chain_key)
            .u32(self.sender_iteration)
            .u32(self.receivers.len() as u32);
        for r in &self.receivers {
            w.fixed(&r.member)
                .fixed(&r.sig_pub)
                .fixed(&r.chain_key)
                .u32(r.iteration)
                .u32(r.skipped.len() as u32);
            for (n, mk) in &r.skipped {
                w.u32(*n).fixed(mk);
            }
        }
        // Tail block (absent in snapshots written before signal keys existed):
        // our signal key, then one per receiver in the order emitted above.
        w.fixed(&self.sender_signal_key);
        for r in &self.receivers {
            w.fixed(&r.signal_key);
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, GroupError> {
        let mut r = Reader::new(bytes);
        let group_id = r.fixed::<32>()?;
        let me = r.fixed::<32>()?;
        let sender_sig_secret = r.fixed::<32>()?;
        let sender_chain_key = r.fixed::<32>()?;
        let sender_iteration = r.u32()?;
        let rc = bounded(&mut r)?;
        let mut receivers = Vec::with_capacity(rc);
        for _ in 0..rc {
            let member = r.fixed::<32>()?;
            let sig_pub = r.fixed::<32>()?;
            let chain_key = r.fixed::<32>()?;
            let iteration = r.u32()?;
            let sc = bounded(&mut r)?;
            let mut skipped = Vec::with_capacity(sc);
            for _ in 0..sc {
                skipped.push((r.u32()?, r.fixed::<32>()?));
            }
            receivers.push(ReceiverSnapshot {
                member,
                sig_pub,
                chain_key,
                iteration,
                skipped,
                signal_key: [0u8; 32],
            });
        }
        // Tail block; if this snapshot predates signal keys, mint fresh ones so
        // the group still loads (typing signals just won't interop until the
        // next bundle exchange refreshes them).
        let sender_signal_key = if r.remaining() > 0 {
            r.fixed::<32>()?
        } else {
            random_array::<32>()
        };
        for rcv in &mut receivers {
            rcv.signal_key = if r.remaining() > 0 {
                r.fixed::<32>()?
            } else {
                random_array::<32>()
            };
        }
        r.finish()?;
        Ok(Self {
            group_id,
            me,
            sender_sig_secret,
            sender_chain_key,
            sender_iteration,
            sender_signal_key,
            receivers,
        })
    }
}

impl Drop for GroupState {
    fn drop(&mut self) {
        self.sender_sig_secret.zeroize();
        self.sender_chain_key.zeroize();
        self.sender_signal_key.zeroize();
        for r in &mut self.receivers {
            r.chain_key.zeroize();
            r.signal_key.zeroize();
            for (_, mk) in &mut r.skipped {
                mk.zeroize();
            }
        }
    }
}

fn bounded(r: &mut Reader<'_>) -> Result<usize, dante_proto::enc::WireError> {
    let n = r.u32()? as usize;
    if n > r.remaining() {
        return Err(dante_proto::enc::WireError::LengthTooLarge(n as u64));
    }
    Ok(n)
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

    #[test]
    fn signals_seal_open_between_members_and_survive_reload() {
        let (mut a, ba) = Group::create(GID, member(0));
        let (mut b, bb) = Group::create(GID, member(1));
        a.upsert_member(&bb).unwrap();
        b.upsert_member(&ba).unwrap();

        let s = a.seal_signal(b"typing");
        assert_eq!(b.open_signal(&s).unwrap(), (*a.me(), b"typing".to_vec()));
        // Sealing does not advance the message chain.
        let m = a.encrypt(b"real message");
        assert_eq!(m.iteration, 0);
        assert_eq!(b.decrypt(&m).unwrap(), b"real message");

        // Signal keys ride the snapshot.
        let bytes = b.export().encode();
        drop(b);
        let b = Group::import(&GroupState::decode(&bytes).unwrap()).unwrap();
        assert_eq!(
            b.open_signal(&a.seal_signal(b"still typing")).unwrap().1,
            b"still typing"
        );
    }

    #[test]
    fn signal_from_unknown_member_or_tampered_blob_is_rejected() {
        let (a, ba) = Group::create(GID, member(0));
        let (mut b, _bb) = Group::create(GID, member(1));
        // b does not know a yet.
        assert!(b.open_signal(&a.seal_signal(b"x")).is_none());

        b.upsert_member(&ba).unwrap();
        let mut s = a.seal_signal(b"x");
        *s.last_mut().unwrap() ^= 1;
        assert!(b.open_signal(&s).is_none());
    }

    #[test]
    fn removed_member_loses_signal_access() {
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
        let old = g0.seal_signal(b"before");
        assert_eq!(g2.open_signal(&old).unwrap().1, b"before");

        let n0 = g0.remove_member(&m2);
        g1.upsert_member(&n0).unwrap();
        // g2 still holds g0's old signal key -> cannot open the new one.
        assert!(g2.open_signal(&g0.seal_signal(b"after")).is_none());
        assert_eq!(
            g1.open_signal(&g0.seal_signal(b"after")).unwrap().1,
            b"after"
        );
    }

    #[test]
    fn group_survives_export_import() {
        let (mut a, _ba) = Group::create(GID, member(0));
        let (mut b, bb) = Group::create(GID, member(1));
        let (mut c, bc) = Group::create(GID, member(2));
        a.upsert_member(&bb).unwrap();
        a.upsert_member(&bc).unwrap();
        b.upsert_member(&a.my_bundle()).unwrap();
        c.upsert_member(&a.my_bundle()).unwrap();

        let m1 = a.encrypt(b"one");
        assert_eq!(b.decrypt(&m1).unwrap(), b"one");

        let bytes = a.export().encode();
        drop(a);
        let mut a = Group::import(&GroupState::decode(&bytes).unwrap()).unwrap();

        let m2 = a.encrypt(b"two after reload");
        assert_eq!(b.decrypt(&m2).unwrap(), b"two after reload");
        assert_eq!(c.decrypt(&m2).unwrap(), b"two after reload");
    }
}
