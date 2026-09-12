//! The identity-related ledger record **bodies** (`docs/PROTOCOL.md` §2.2):
//! [`IdentityAnnounce`] (kind 1), [`LivenessProof`] (kind 2), [`KeyRotation`]
//! (kind 3), [`IdentityRevoke`] (kind 7), [`IdentityProfile`] (kind 8).
//!
//! Each body has:
//! - `encode` / `decode` over the [`dante_proto::enc`] codec,
//! - a `challenge` deriving its PoW / link-signature input,
//! - `build` (constructs and, where applicable, solves the PoW),
//! - `verify` (structural + PoW + key-binding checks; the envelope signature and
//!   any ledger-state lookup are the `dante-ledger` layer's job),
//! - `to_record` (wraps the body in a signed [`Record`]).

use dante_crypto::{
    hash::sha256_parts,
    pow::{self, Difficulty, PowProof},
    sign::{SignPublic, SIG_LEN},
};
use dante_proto::{
    enc::{Reader, Writer},
    pow as pow_wire,
    record::{Record, RecordKind},
};

use crate::{error::IdentityError, identity::Identity};

/// PoW-binding bucket width for liveness proofs (`docs/PROTOCOL.md` §2.3).
pub const LIVENESS_BUCKET_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Max bytes of a free-text `display_hint`.
pub const DISPLAY_HINT_MAX: usize = 64;

/// Max bytes of an [`IdentityProfile`] status/bio (UTF-8, no control
/// characters).
///
/// Long enough for a couple of sentences, short enough that the record stays
/// tiny on every replica and in gossip. Deliberately larger than a nickname
/// (32) or `display_hint` (64) — a status is prose, not a handle — and no
/// larger than a server `summary` (280).
pub const STATUS_MAX: usize = 256;

/// Whether `status` is a usable profile status: 1..=[`STATUS_MAX`] bytes and
/// no control characters. It is rendered as plain text next to the username,
/// so this keeps it from smuggling control sequences without otherwise
/// restricting the text.
pub fn valid_status(status: &str) -> bool {
    !status.is_empty() && status.len() <= STATUS_MAX && status.chars().all(|c| !c.is_control())
}

const ANNOUNCE_POW_DOMAIN: &[u8] = b"dante/pow/identity-announce/v1";
const LIVENESS_POW_DOMAIN: &[u8] = b"dante/pow/liveness/v1";
const ROTATION_LINK_DOMAIN: &[u8] = b"dante/key-rotation/link/v1";

/// Body of a `kind = 1` record: first announcement of an identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityAnnounce {
    /// The identity's long-term X25519 public key.
    pub ik_pub: [u8; 32],
    /// `idk` signature over `ik_pub`, binding the two keys.
    pub ik_sig: [u8; SIG_LEN],
    /// Proof of work over [`IdentityAnnounce::challenge`].
    pub pow: PowProof,
    /// Non-unique, untrusted free-text hint (≤ [`DISPLAY_HINT_MAX`] bytes).
    pub display_hint: String,
}

impl IdentityAnnounce {
    /// PoW challenge: `SHA-256(domain || idk_pub || ik_pub)`.
    pub fn challenge(idk_pub: &[u8; 32], ik_pub: &[u8; 32]) -> [u8; 32] {
        sha256_parts(&[ANNOUNCE_POW_DOMAIN, idk_pub, ik_pub])
    }

    /// Build and solve an announcement for `identity` (`difficulty`, e.g.
    /// [`pow::REGISTRATION`]). Blocks on the PoW search.
    pub fn build(identity: &Identity, display_hint: &str, difficulty: Difficulty) -> Self {
        let idk_pub = identity.sign_public().to_bytes();
        let ik_pub = identity.agree_public().to_bytes();
        Self {
            ik_pub,
            ik_sig: identity.sign(&ik_pub),
            pow: pow::solve(&Self::challenge(&idk_pub, &ik_pub), difficulty),
            display_hint: truncate_on_char_boundary(display_hint, DISPLAY_HINT_MAX).to_owned(),
        }
    }

    /// Verify the key binding and the PoW. `idk_pub` is the record's `author`;
    /// `min_pow_bits` / `min_pow_m_cost_kib` / `min_pow_t_cost` are the
    /// verifier's floor on the puzzle (see [`pow::verify`]).
    pub fn verify(
        &self,
        idk_pub: &SignPublic,
        min_pow_bits: u8,
        min_pow_m_cost_kib: u32,
        min_pow_t_cost: u32,
    ) -> Result<(), IdentityError> {
        if self.display_hint.len() > DISPLAY_HINT_MAX {
            return Err(IdentityError::FieldTooLong);
        }
        idk_pub
            .verify(&self.ik_pub, &self.ik_sig)
            .map_err(|_| IdentityError::BadSignature)?;
        pow::verify(
            &Self::challenge(&idk_pub.to_bytes(), &self.ik_pub),
            &self.pow,
            min_pow_bits,
            min_pow_m_cost_kib,
            min_pow_t_cost,
        )
        .map_err(|_| IdentityError::BadPow)
    }

    /// Encode the body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(32 + SIG_LEN + 25 + self.display_hint.len());
        w.fixed(&self.ik_pub).fixed(&self.ik_sig);
        pow_wire::write(&mut w, &self.pow);
        w.string(&self.display_hint);
        w.into_vec()
    }

    /// Decode the body (structural only).
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        let mut r = Reader::new(bytes);
        let ik_pub = r.fixed::<32>()?;
        let ik_sig = r.fixed::<SIG_LEN>()?;
        let pow = pow_wire::read(&mut r)?;
        let display_hint = r.string()?;
        r.finish()?;
        Ok(Self {
            ik_pub,
            ik_sig,
            pow,
            display_hint,
        })
    }

    /// Wrap in a signed record authored by `identity` at `created_ms`.
    pub fn to_record(&self, identity: &Identity, created_ms: u64) -> Record {
        seal(
            identity,
            RecordKind::IdentityAnnounce,
            self.encode(),
            created_ms,
        )
    }
}

/// Body of a `kind = 2` record: proof the identity is still active.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LivenessProof {
    /// Proof of work over [`LivenessProof::challenge`].
    pub pow: PowProof,
}

impl LivenessProof {
    /// PoW challenge:
    /// `SHA-256(domain || idk_pub || be(created_ms / LIVENESS_BUCKET_MS))`.
    pub fn challenge(idk_pub: &[u8; 32], created_ms: u64) -> [u8; 32] {
        let bucket = created_ms / LIVENESS_BUCKET_MS;
        sha256_parts(&[LIVENESS_POW_DOMAIN, idk_pub, &bucket.to_be_bytes()])
    }

    /// Build and solve a proof bound to `created_ms` (the enclosing record's
    /// timestamp).
    pub fn build(identity: &Identity, created_ms: u64, difficulty: Difficulty) -> Self {
        let challenge = Self::challenge(&identity.sign_public().to_bytes(), created_ms);
        Self {
            pow: pow::solve(&challenge, difficulty),
        }
    }

    /// Verify the PoW for `idk_pub` and record `created_ms`.
    pub fn verify(
        &self,
        idk_pub: &SignPublic,
        created_ms: u64,
        min_pow_bits: u8,
        min_pow_m_cost_kib: u32,
        min_pow_t_cost: u32,
    ) -> Result<(), IdentityError> {
        pow::verify(
            &Self::challenge(&idk_pub.to_bytes(), created_ms),
            &self.pow,
            min_pow_bits,
            min_pow_m_cost_kib,
            min_pow_t_cost,
        )
        .map_err(|_| IdentityError::BadPow)
    }

    /// Encode the body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(9);
        pow_wire::write(&mut w, &self.pow);
        w.into_vec()
    }

    /// Decode the body.
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        let mut r = Reader::new(bytes);
        let pow = pow_wire::read(&mut r)?;
        r.finish()?;
        Ok(Self { pow })
    }

    /// Wrap in a signed record authored by `identity` at `created_ms`.
    pub fn to_record(&self, identity: &Identity, created_ms: u64) -> Record {
        seal(
            identity,
            RecordKind::LivenessProof,
            self.encode(),
            created_ms,
        )
    }
}

/// Body of a `kind = 3` record: rotation to a new key pair, chained from the
/// old one. The record's `author`/`sig` are the **new** `idk`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRotation {
    /// The key being rotated away from — the current chain tip. Lets a verifier
    /// locate the old key without scanning every identity.
    pub prev_idk: [u8; 32],
    /// New Ed25519 identity key.
    pub new_idk: [u8; 32],
    /// New X25519 agreement key.
    pub new_ik: [u8; 32],
    /// `new_idk` signature over `new_ik`.
    pub new_ik_sig: [u8; SIG_LEN],
    /// **Old** `idk` signature over [`KeyRotation::link_challenge`] — the proof
    /// the same person controls both keys.
    pub link_sig: [u8; SIG_LEN],
}

impl KeyRotation {
    /// Input the old key signs to link itself to the new keys:
    /// `SHA-256(domain || prev_idk || new_idk || new_ik)`.
    pub fn link_challenge(prev_idk: &[u8; 32], new_idk: &[u8; 32], new_ik: &[u8; 32]) -> [u8; 32] {
        sha256_parts(&[ROTATION_LINK_DOMAIN, prev_idk, new_idk, new_ik])
    }

    /// Build a rotation from `old` to `new`.
    pub fn build(old: &Identity, new: &Identity) -> Self {
        let prev_idk = old.sign_public().to_bytes();
        let new_idk = new.sign_public().to_bytes();
        let new_ik = new.agree_public().to_bytes();
        Self {
            prev_idk,
            new_idk,
            new_ik,
            new_ik_sig: new.sign(&new_ik),
            link_sig: old.sign(&Self::link_challenge(&prev_idk, &new_idk, &new_ik)),
        }
    }

    /// Verify both signatures against the declared `prev_idk`: `new_ik` is bound
    /// to `new_idk`, and the previous key endorsed the new keys.
    pub fn verify(&self) -> Result<(), IdentityError> {
        let new_idk =
            SignPublic::from_bytes(&self.new_idk).map_err(|_| IdentityError::BadSignature)?;
        let prev_idk =
            SignPublic::from_bytes(&self.prev_idk).map_err(|_| IdentityError::BadSignature)?;
        new_idk
            .verify(&self.new_ik, &self.new_ik_sig)
            .map_err(|_| IdentityError::BadSignature)?;
        prev_idk
            .verify(
                &Self::link_challenge(&self.prev_idk, &self.new_idk, &self.new_ik),
                &self.link_sig,
            )
            .map_err(|_| IdentityError::BadSignature)
    }

    /// Encode the body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(32 + 32 + 32 + SIG_LEN + SIG_LEN);
        w.fixed(&self.prev_idk)
            .fixed(&self.new_idk)
            .fixed(&self.new_ik)
            .fixed(&self.new_ik_sig)
            .fixed(&self.link_sig);
        w.into_vec()
    }

    /// Decode the body.
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        let mut r = Reader::new(bytes);
        let prev_idk = r.fixed::<32>()?;
        let new_idk = r.fixed::<32>()?;
        let new_ik = r.fixed::<32>()?;
        let new_ik_sig = r.fixed::<SIG_LEN>()?;
        let link_sig = r.fixed::<SIG_LEN>()?;
        r.finish()?;
        Ok(Self {
            prev_idk,
            new_idk,
            new_ik,
            new_ik_sig,
            link_sig,
        })
    }

    /// Wrap in a signed record authored by the **new** identity at `created_ms`.
    pub fn to_record(&self, new_identity: &Identity, created_ms: u64) -> Record {
        debug_assert_eq!(self.new_idk, new_identity.sign_public().to_bytes());
        seal(
            new_identity,
            RecordKind::KeyRotation,
            self.encode(),
            created_ms,
        )
    }
}

/// Why an identity was revoked. Informational only — a verifier accepts the
/// revocation regardless of the reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokeReason {
    /// No reason given.
    Unspecified,
    /// The private key is believed compromised.
    Compromised,
    /// Replaced by a different identity (the user moved on).
    Superseded,
    /// The user is retiring the identity deliberately.
    Retired,
}

impl RevokeReason {
    /// Wire discriminant.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Unspecified => 0,
            Self::Compromised => 1,
            Self::Superseded => 2,
            Self::Retired => 3,
        }
    }

    /// Parse a wire discriminant (unknown values map to [`Self::Unspecified`]).
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Compromised,
            2 => Self::Superseded,
            3 => Self::Retired,
            _ => Self::Unspecified,
        }
    }
}

/// Body of a `kind = 7` record: permanent revocation of an identity. The
/// record's `author`/`sig` are the **current chain tip** `idk` — the only key
/// allowed to revoke it. Once accepted, the chain takes no further records
/// (no liveness, no rotation) and resolves to no usable key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityRevoke {
    /// The chain-tip `idk` being revoked. Must equal the record `author`.
    pub revoked_idk: [u8; 32],
    /// Why (informational).
    pub reason: RevokeReason,
}

impl IdentityRevoke {
    /// Build a revocation for `identity` (which must be the current chain tip).
    pub fn build(identity: &Identity, reason: RevokeReason) -> Self {
        Self {
            revoked_idk: identity.sign_public().to_bytes(),
            reason,
        }
    }

    /// Structural check: nothing beyond a well-formed key. Authorisation is the
    /// envelope signature by `author == revoked_idk`, enforced by the ledger.
    pub fn verify(&self) -> Result<(), IdentityError> {
        SignPublic::from_bytes(&self.revoked_idk).map_err(|_| IdentityError::BadSignature)?;
        Ok(())
    }

    /// Encode the body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(33);
        w.fixed(&self.revoked_idk).u8(self.reason.as_u8());
        w.into_vec()
    }

    /// Decode the body.
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        let mut r = Reader::new(bytes);
        let revoked_idk = r.fixed::<32>()?;
        let reason = RevokeReason::from_u8(r.u8()?);
        r.finish()?;
        Ok(Self {
            revoked_idk,
            reason,
        })
    }

    /// Wrap in a signed record authored by `identity` at `created_ms`.
    pub fn to_record(&self, identity: &Identity, created_ms: u64) -> Record {
        debug_assert_eq!(self.revoked_idk, identity.sign_public().to_bytes());
        seal(
            identity,
            RecordKind::IdentityRevoke,
            self.encode(),
            created_ms,
        )
    }
}

/// Body of a `kind = 8` record: mutable public identity state.
///
/// Currently one field — the global avatar. The record's `author`/`sig` are
/// the **current chain tip** `idk`, the only key allowed to change its chain's
/// profile; `dante-ledger` additionally requires a strictly increasing
/// `created_ms` per chain, so an older profile record cannot be replayed over
/// a newer one. There is deliberately no PoW: a profile change is a rare,
/// user-driven action, and the ledger's rate limiter plus the tip/monotonic
/// checks bound abuse without coupling it to liveness (see
/// [`crate::records`] — it does not refresh activity, or an identity could
/// dodge evaporation for free).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityProfile {
    /// SHA-256 of the avatar image on the relay blob store, or `None` to
    /// clear it. The image never rides the ledger — only this 32-byte pointer
    /// — so replicas and gossip stay small and clients fetch the bytes on
    /// demand from the content-addressed store.
    pub avatar_hash: Option<[u8; 32]>,
    /// Free-text status/bio shown next to the username, or `None` to clear it.
    /// Validated by [`valid_status`]; rendered as untrusted plain text.
    pub status: Option<String>,
}

impl IdentityProfile {
    /// Build a profile. `None` on either field clears it; a record always
    /// carries the full profile, so a caller that only wants to change one
    /// field passes the other one through unchanged (`dante-core`'s
    /// `publish_avatar` / `publish_status` do exactly that).
    pub fn new(avatar_hash: Option<[u8; 32]>, status: Option<String>) -> Self {
        Self {
            avatar_hash,
            status,
        }
    }

    /// Encode the body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(33 + 4 + self.status.as_ref().map_or(0, |s| s.len()));
        match &self.avatar_hash {
            Some(h) => {
                w.bool(true).fixed(h);
            }
            None => {
                w.bool(false);
            }
        }
        // Tail extension: the status is written only when present, so a
        // status-less profile — including every avatar-only record from the
        // first release — keeps the exact pre-status bytes. Presence is "there
        // are bytes left"; see `decode`.
        if let Some(s) = &self.status {
            w.string(s);
        }
        w.into_vec()
    }

    /// Decode the body. Tolerates both layouts: the pre-status one (body ends
    /// after the avatar) and the current one (optional trailing status).
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        let mut r = Reader::new(bytes);
        let avatar_hash = if r.bool()? {
            Some(r.fixed::<32>()?)
        } else {
            None
        };
        let status = if r.remaining() > 0 {
            let s = r.string()?;
            if !valid_status(&s) {
                return Err(IdentityError::BadStatus);
            }
            Some(s)
        } else {
            None
        };
        r.finish()?;
        Ok(Self {
            avatar_hash,
            status,
        })
    }

    /// Wrap in a signed record authored by `identity` at `created_ms`.
    pub fn to_record(&self, identity: &Identity, created_ms: u64) -> Record {
        seal(
            identity,
            RecordKind::IdentityProfile,
            self.encode(),
            created_ms,
        )
    }
}

/// A decoded identity-related record body, tagged by kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityRecord {
    /// A `kind = 1` body.
    Announce(IdentityAnnounce),
    /// A `kind = 2` body.
    Liveness(LivenessProof),
    /// A `kind = 3` body.
    KeyRotation(KeyRotation),
    /// A `kind = 7` body.
    Revoke(IdentityRevoke),
    /// A `kind = 8` body.
    Profile(IdentityProfile),
}

impl IdentityRecord {
    /// Decode `record.body` according to `record.kind`. Structural only — the
    /// caller verifies the envelope signature and body checks.
    pub fn from_record(record: &Record) -> Result<Self, IdentityError> {
        Ok(match record.kind {
            RecordKind::IdentityAnnounce => Self::Announce(IdentityAnnounce::decode(&record.body)?),
            RecordKind::LivenessProof => Self::Liveness(LivenessProof::decode(&record.body)?),
            RecordKind::KeyRotation => Self::KeyRotation(KeyRotation::decode(&record.body)?),
            RecordKind::IdentityRevoke => Self::Revoke(IdentityRevoke::decode(&record.body)?),
            RecordKind::IdentityProfile => Self::Profile(IdentityProfile::decode(&record.body)?),
            _ => return Err(IdentityError::WrongRecordKind),
        })
    }
}

fn seal(identity: &Identity, kind: RecordKind, body: Vec<u8>, created_ms: u64) -> Record {
    Record::seal_with(
        kind,
        body,
        identity.sign_public().to_bytes(),
        created_ms,
        |m| identity.sign(m),
    )
}

fn truncate_on_char_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use dante_crypto::pow::Difficulty;

    use super::*;

    const TEST_POW: Difficulty = Difficulty {
        m_cost_kib: 32,
        t_cost: 1,
        bits: 8,
    };

    #[test]
    fn announce_build_encode_decode_verify() {
        let id = Identity::generate(1_700_000_000_000);
        let ann = IdentityAnnounce::build(&id, "captain", TEST_POW);
        ann.verify(&id.sign_public(), 8, 0, 0).unwrap();
        assert_eq!(ann.ik_pub, id.agree_public().to_bytes());

        let back = IdentityAnnounce::decode(&ann.encode()).unwrap();
        assert_eq!(ann, back);
        back.verify(&id.sign_public(), 8, 0, 0).unwrap();
    }

    #[test]
    fn announce_rejects_wrong_author_downgrade_and_tamper() {
        let id = Identity::generate(0);
        let other = Identity::generate(0);
        let ann = IdentityAnnounce::build(&id, "", TEST_POW);
        assert!(ann.verify(&other.sign_public(), 8, 0, 0).is_err());
        assert!(matches!(
            ann.verify(&id.sign_public(), 16, 0, 0),
            Err(IdentityError::BadPow)
        ));

        let mut bad = ann.clone();
        bad.ik_pub[0] ^= 1;
        assert!(bad.verify(&id.sign_public(), 8, 0, 0).is_err());
    }

    #[test]
    fn announce_display_hint_truncated_on_char_boundary() {
        let id = Identity::generate(0);
        let ann = IdentityAnnounce::build(&id, &"é".repeat(40), TEST_POW);
        assert!(ann.display_hint.len() <= DISPLAY_HINT_MAX);
        assert!(ann.display_hint.chars().all(|c| c == 'é'));
    }

    #[test]
    fn liveness_build_encode_decode_and_bucket_binding() {
        let id = Identity::generate(0);
        let t = 1_700_000_000_000u64;
        let proof = LivenessProof::build(&id, t, TEST_POW);
        proof.verify(&id.sign_public(), t, 8, 0, 0).unwrap();
        proof.verify(&id.sign_public(), t + 1000, 8, 0, 0).unwrap(); // same 7-day bucket

        // The proof is bound to its 7-day bucket and must not verify in a later
        // one. A random PoW solution clears the 8-bit target for an unrelated
        // challenge with probability 1/256, so probe several future buckets:
        // binding is broken only if *none* of them reject.
        assert!(
            (1..=8u64).any(|k| proof
                .verify(&id.sign_public(), t + k * LIVENESS_BUCKET_MS, 8, 0, 0)
                .is_err()),
            "liveness proof verified in every probed future bucket"
        );

        let back = LivenessProof::decode(&proof.encode()).unwrap();
        assert_eq!(proof, back);
    }

    #[test]
    fn key_rotation_build_encode_decode_verify() {
        let old = Identity::generate(0);
        let new = Identity::generate(0);
        let rot = KeyRotation::build(&old, &new);
        rot.verify().unwrap();
        assert_eq!(rot.new_idk, new.sign_public().to_bytes());
        assert_eq!(rot.prev_idk, old.sign_public().to_bytes());

        let back = KeyRotation::decode(&rot.encode()).unwrap();
        assert_eq!(rot, back);
        back.verify().unwrap();

        // substituted prev_idk (link_sig no longer matches)
        let impostor = Identity::generate(0);
        let mut wrong_prev = rot.clone();
        wrong_prev.prev_idk = impostor.sign_public().to_bytes();
        assert!(wrong_prev.verify().is_err());
        // tampered new_ik
        let mut bad = rot.clone();
        bad.new_ik[0] ^= 1;
        assert!(bad.verify().is_err());
    }

    #[test]
    fn to_record_roundtrips_through_the_envelope() {
        let id = Identity::generate(1_234_000);
        let ann = IdentityAnnounce::build(&id, "x", TEST_POW);
        let rec = ann.to_record(&id, 1_234_000);

        assert_eq!(rec.kind, RecordKind::IdentityAnnounce);
        assert_eq!(rec.author, id.sign_public().to_bytes());
        rec.verify_signature().unwrap();

        match IdentityRecord::from_record(&rec).unwrap() {
            IdentityRecord::Announce(b) => {
                assert_eq!(b, ann);
                b.verify(&id.sign_public(), 8, 0, 0).unwrap();
            }
            _ => panic!("wrong variant"),
        }

        let bytes = rec.encode();
        assert_eq!(Record::decode(&bytes).unwrap(), rec);
    }

    #[test]
    fn key_rotation_record_is_authored_by_the_new_key() {
        let old = Identity::generate(0);
        let new = Identity::generate(0);
        let rec = KeyRotation::build(&old, &new).to_record(&new, 42);
        assert_eq!(rec.author, new.sign_public().to_bytes());
        rec.verify_signature().unwrap();
        match IdentityRecord::from_record(&rec).unwrap() {
            IdentityRecord::KeyRotation(b) => {
                assert_eq!(b.prev_idk, old.sign_public().to_bytes());
                b.verify().unwrap();
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn identity_revoke_roundtrips_and_is_self_authored() {
        let id = Identity::generate(0);
        let body = IdentityRevoke::build(&id, RevokeReason::Compromised);
        assert_eq!(body.revoked_idk, id.sign_public().to_bytes());

        let rec = body.to_record(&id, 99);
        assert_eq!(rec.kind, RecordKind::IdentityRevoke);
        assert_eq!(rec.author, id.sign_public().to_bytes());
        rec.verify_signature().unwrap();

        match IdentityRecord::from_record(&rec).unwrap() {
            IdentityRecord::Revoke(b) => {
                assert_eq!(b, body);
                b.verify().unwrap();
                assert_eq!(b.reason, RevokeReason::Compromised);
            }
            _ => panic!("wrong variant"),
        }
        assert_eq!(IdentityRevoke::decode(&body.encode()).unwrap(), body);
    }

    #[test]
    fn identity_profile_roundtrips_and_is_authored_by_the_signer() {
        let id = Identity::generate(0);
        let body = IdentityProfile::new(Some([7u8; 32]), Some("building a mesh".into()));
        let rec = body.to_record(&id, 42);
        assert_eq!(rec.kind, RecordKind::IdentityProfile);
        assert_eq!(rec.author, id.sign_public().to_bytes());
        rec.verify_signature().unwrap();

        match IdentityRecord::from_record(&rec).unwrap() {
            IdentityRecord::Profile(b) => assert_eq!(b, body),
            _ => panic!("wrong variant"),
        }
        assert_eq!(IdentityProfile::decode(&body.encode()).unwrap(), body);

        // Each field can stand alone.
        let status_only = IdentityProfile::new(None, Some("hi".into()));
        assert_eq!(
            IdentityProfile::decode(&status_only.encode()).unwrap(),
            status_only
        );
        let avatar_only = IdentityProfile::new(Some([8u8; 32]), None);
        assert_eq!(
            IdentityProfile::decode(&avatar_only.encode()).unwrap(),
            avatar_only
        );

        // Clearing is an explicit "none", and a status-less profile keeps the
        // one-byte pre-status layout (a zero hash is a different thing).
        let clear = IdentityProfile::new(None, None);
        assert_eq!(clear.encode(), vec![0u8]);
        assert_eq!(IdentityProfile::decode(&clear.encode()).unwrap(), clear);
        assert_ne!(
            clear.encode(),
            IdentityProfile::new(Some([0u8; 32]), None).encode()
        );
    }

    #[test]
    fn a_pre_status_kind_8_record_still_decodes() {
        // Byte for byte what the avatar-only encoder wrote: `bool(true)` + the
        // 32-byte hash, and `bool(false)` for no avatar. Built here by hand,
        // not by re-encoding with the new code, so this pins the old layout.
        let hash = [9u8; 32];
        let mut avatar_only = Vec::with_capacity(33);
        avatar_only.push(1);
        avatar_only.extend_from_slice(&hash);

        let decoded = IdentityProfile::decode(&avatar_only).unwrap();
        assert_eq!(decoded.avatar_hash, Some(hash));
        assert_eq!(decoded.status, None);

        let none = IdentityProfile::decode(&[0u8]).unwrap();
        assert_eq!(none.avatar_hash, None);
        assert_eq!(none.status, None);
        // A status-less profile re-encodes to the same old bytes.
        assert_eq!(decoded.encode(), avatar_only);

        // Through the envelope too: a manually sealed old body is a profile
        // with no status.
        let id = Identity::generate(0);
        let rec = Record::seal_with(
            RecordKind::IdentityProfile,
            avatar_only,
            id.sign_public().to_bytes(),
            7,
            |m| id.sign(m),
        );
        rec.verify_signature().unwrap();
        match IdentityRecord::from_record(&rec).unwrap() {
            IdentityRecord::Profile(p) => {
                assert_eq!(p.avatar_hash, Some(hash));
                assert_eq!(p.status, None);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn profile_status_is_validated_at_decode() {
        for bad in ["", "line\nbreak", "bell\u{7}"] {
            let p = IdentityProfile::new(None, Some(bad.into()));
            assert!(matches!(
                IdentityProfile::decode(&p.encode()),
                Err(IdentityError::BadStatus)
            ));
        }
        let long = "x".repeat(STATUS_MAX + 1);
        let p = IdentityProfile::new(None, Some(long));
        assert!(matches!(
            IdentityProfile::decode(&p.encode()),
            Err(IdentityError::BadStatus)
        ));

        assert!(valid_status("on a walk 🚶"));
        assert!(!valid_status(""));
        assert!(!valid_status("line\nbreak"));
        assert!(valid_status(&"é".repeat(STATUS_MAX / 2)));
    }

    #[test]
    fn revoke_reason_discriminants_are_total() {
        for r in [
            RevokeReason::Unspecified,
            RevokeReason::Compromised,
            RevokeReason::Superseded,
            RevokeReason::Retired,
        ] {
            assert_eq!(RevokeReason::from_u8(r.as_u8()), r);
        }
        assert_eq!(RevokeReason::from_u8(200), RevokeReason::Unspecified);
    }

    #[test]
    fn from_record_rejects_non_identity_kind() {
        let id = Identity::generate(0);
        let rec = Record::seal_with(
            RecordKind::ServerDelist,
            vec![0u8; 32],
            id.sign_public().to_bytes(),
            0,
            |m| id.sign(m),
        );
        assert!(matches!(
            IdentityRecord::from_record(&rec),
            Err(IdentityError::WrongRecordKind)
        ));
    }
}
