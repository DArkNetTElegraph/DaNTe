//! The `IdentityAnnounce` and `LivenessProof` bodies (`docs/PROTOCOL.md` §2.2),
//! their PoW challenge derivations, and their verification.
//!
//! These are the *bodies*. Phase 2 wraps them in the generic ledger `Record`
//! envelope (`author`, `created_ms`, `sig`) in `dante-proto` / `dante-ledger`;
//! `LivenessProof::challenge` already takes the envelope's `created_ms` so the
//! two compose without change.

use dante_crypto::{
    hash::sha256_parts,
    pow::{self, Difficulty, PowProof},
    sign::{SignPublic, SIG_LEN},
};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::{error::IdentityError, identity::Identity};

/// PoW-binding bucket width for liveness proofs (`docs/PROTOCOL.md` §2.3).
pub const LIVENESS_BUCKET_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Max bytes of a free-text `display_hint`.
pub const DISPLAY_HINT_MAX: usize = 64;

const ANNOUNCE_POW_DOMAIN: &[u8] = b"dante/pow/identity-announce/v1";
const LIVENESS_POW_DOMAIN: &[u8] = b"dante/pow/liveness/v1";

/// Body of a `kind = 1` ledger record: first announcement of an identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityAnnounce {
    /// The identity's long-term X25519 public key.
    pub ik_pub: [u8; 32],
    /// `idk` signature over `ik_pub`, proving the two keys belong together.
    #[serde(with = "BigArray")]
    pub ik_sig: [u8; SIG_LEN],
    /// Proof of work over [`IdentityAnnounce::challenge`].
    pub pow: PowProof,
    /// Non-unique, untrusted free-text hint (≤ [`DISPLAY_HINT_MAX`] bytes).
    pub display_hint: String,
}

impl IdentityAnnounce {
    /// The 32-byte PoW challenge: `SHA-256(domain || idk_pub || ik_pub)`.
    pub fn challenge(idk_pub: &[u8; 32], ik_pub: &[u8; 32]) -> [u8; 32] {
        sha256_parts(&[ANNOUNCE_POW_DOMAIN, idk_pub, ik_pub])
    }

    /// Build and solve an announcement for `identity`. Blocks on the PoW search
    /// (`difficulty`, e.g. [`pow::REGISTRATION`]).
    pub fn build(
        identity: &Identity,
        display_hint: &str,
        difficulty: Difficulty,
    ) -> Result<Self, IdentityError> {
        let idk_pub = identity.sign_public().to_bytes();
        let ik_pub = identity.agree_public().to_bytes();

        let hint = truncate_on_char_boundary(display_hint, DISPLAY_HINT_MAX).to_string();
        let pow = pow::solve(&Self::challenge(&idk_pub, &ik_pub), difficulty);

        Ok(Self {
            ik_pub,
            ik_sig: identity.sign(&ik_pub),
            pow,
            display_hint: hint,
        })
    }

    /// Verify the key binding and the PoW. `idk_pub` comes from the record's
    /// `author`; `min_pow_bits` is the verifier's difficulty floor.
    pub fn verify(&self, idk_pub: &SignPublic, min_pow_bits: u8) -> Result<(), IdentityError> {
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
        )
        .map_err(|_| IdentityError::BadPow)
    }
}

/// Body of a `kind = 2` ledger record: proof the identity is still active.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LivenessProof {
    /// Proof of work over [`LivenessProof::challenge`].
    pub pow: PowProof,
}

impl LivenessProof {
    /// The 32-byte PoW challenge:
    /// `SHA-256(domain || idk_pub || be(created_ms / LIVENESS_BUCKET_MS))`.
    pub fn challenge(idk_pub: &[u8; 32], created_ms: u64) -> [u8; 32] {
        let bucket = created_ms / LIVENESS_BUCKET_MS;
        sha256_parts(&[LIVENESS_POW_DOMAIN, idk_pub, &bucket.to_be_bytes()])
    }

    /// Build and solve a liveness proof bound to `created_ms` (the value the
    /// enclosing record will carry).
    pub fn build(identity: &Identity, created_ms: u64, difficulty: Difficulty) -> Self {
        let challenge = Self::challenge(&identity.sign_public().to_bytes(), created_ms);
        Self {
            pow: pow::solve(&challenge, difficulty),
        }
    }

    /// Verify the PoW for the given `idk_pub` and record `created_ms`.
    pub fn verify(
        &self,
        idk_pub: &SignPublic,
        created_ms: u64,
        min_pow_bits: u8,
    ) -> Result<(), IdentityError> {
        pow::verify(
            &Self::challenge(&idk_pub.to_bytes(), created_ms),
            &self.pow,
            min_pow_bits,
        )
        .map_err(|_| IdentityError::BadPow)
    }
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

    // Cheap PoW for tests.
    const TEST_POW: Difficulty = Difficulty {
        m_cost_kib: 32,
        t_cost: 1,
        bits: 8,
    };

    #[test]
    fn announce_build_verifies() {
        let id = Identity::generate(1_700_000_000_000);
        let ann = IdentityAnnounce::build(&id, "captain", TEST_POW).unwrap();
        ann.verify(&id.sign_public(), 8).unwrap();
        assert_eq!(ann.display_hint, "captain");
        assert_eq!(ann.ik_pub, id.agree_public().to_bytes());
    }

    #[test]
    fn announce_rejects_wrong_author_and_downgraded_pow() {
        let id = Identity::generate(0);
        let other = Identity::generate(0);
        let ann = IdentityAnnounce::build(&id, "", TEST_POW).unwrap();
        assert!(ann.verify(&other.sign_public(), 8).is_err());
        assert!(matches!(
            ann.verify(&id.sign_public(), 16),
            Err(IdentityError::BadPow)
        ));
    }

    #[test]
    fn announce_rejects_tampered_ik_pub() {
        let id = Identity::generate(0);
        let mut ann = IdentityAnnounce::build(&id, "", TEST_POW).unwrap();
        ann.ik_pub[0] ^= 1;
        assert!(ann.verify(&id.sign_public(), 8).is_err());
    }

    #[test]
    fn display_hint_is_truncated_on_a_char_boundary() {
        let id = Identity::generate(0);
        let long = "é".repeat(40); // 80 bytes
        let ann = IdentityAnnounce::build(&id, &long, TEST_POW).unwrap();
        assert!(ann.display_hint.len() <= DISPLAY_HINT_MAX);
        assert!(ann.display_hint.chars().all(|c| c == 'é'));
    }

    #[test]
    fn liveness_build_verifies_and_is_bucket_bound() {
        let id = Identity::generate(0);
        let t = 1_700_000_000_000u64;
        let proof = LivenessProof::build(&id, t, TEST_POW);
        proof.verify(&id.sign_public(), t, 8).unwrap();

        // Same 7-day bucket: still valid.
        proof.verify(&id.sign_public(), t + 1000, 8).unwrap();
        // A different bucket: challenge changes, PoW no longer matches.
        assert!(proof
            .verify(&id.sign_public(), t + LIVENESS_BUCKET_MS, 8)
            .is_err());
    }

    #[test]
    fn liveness_rejects_wrong_identity() {
        let id = Identity::generate(0);
        let other = Identity::generate(0);
        let t = 1_700_000_000_000u64;
        let proof = LivenessProof::build(&id, t, TEST_POW);
        assert!(proof.verify(&other.sign_public(), t, 8).is_err());
    }
}
