//! X25519 key agreement (RFC 7748).

use x25519_dalek::{PublicKey, StaticSecret};

use crate::{error::CryptoError, random_bytes};

/// Length of a serialized secret scalar.
pub const SECRET_LEN: usize = 32;
/// Length of a serialized public u-coordinate.
pub const PUBLIC_LEN: usize = 32;
/// Length of the agreed shared secret.
pub const SHARED_LEN: usize = 32;

/// An X25519 secret key. Zeroized on drop (via `StaticSecret`'s `zeroize`
/// feature).
#[derive(Clone)]
pub struct AgreeSecret(StaticSecret);

impl AgreeSecret {
    /// Generate a fresh key from the OS CSPRNG.
    pub fn generate() -> Self {
        Self(StaticSecret::from(random_bytes::<SECRET_LEN>()))
    }

    /// Load a key from 32 bytes. The scalar is clamped at use time, per RFC 7748.
    pub fn from_bytes(bytes: &[u8; SECRET_LEN]) -> Self {
        Self(StaticSecret::from(*bytes))
    }

    /// Serialize the 32-byte scalar as stored. Handle as secret material.
    pub fn to_bytes(&self) -> [u8; SECRET_LEN] {
        self.0.to_bytes()
    }

    /// The matching public key.
    pub fn public(&self) -> AgreePublic {
        AgreePublic(PublicKey::from(&self.0))
    }

    /// Diffie-Hellman with `their_public`.
    ///
    /// Rejects the all-zero output that a low-order input point would produce.
    pub fn agree(&self, their_public: &AgreePublic) -> Result<[u8; SHARED_LEN], CryptoError> {
        let shared = self.0.diffie_hellman(&their_public.0).to_bytes();
        if shared == [0u8; SHARED_LEN] {
            return Err(CryptoError::DegenerateAgreement);
        }
        Ok(shared)
    }
}

impl core::fmt::Debug for AgreeSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AgreeSecret").finish_non_exhaustive()
    }
}

/// An X25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AgreePublic(PublicKey);

impl AgreePublic {
    /// Parse a 32-byte public u-coordinate.
    pub fn from_bytes(bytes: &[u8; PUBLIC_LEN]) -> Self {
        Self(PublicKey::from(*bytes))
    }

    /// Serialize to 32 bytes.
    pub fn to_bytes(&self) -> [u8; PUBLIC_LEN] {
        self.0.to_bytes()
    }
}

impl core::fmt::Debug for AgreePublic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AgreePublic({:02x?})", self.to_bytes())
    }
}

/// The raw X25519 function: `scalar * point`, with RFC 7748 clamping applied to
/// `scalar`. Exposed mainly for conformance testing.
pub fn x25519_raw(scalar: [u8; 32], point: [u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(scalar, point)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    // RFC 7748, section 5.2.
    const S1: [u8; 32] = hex!("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    const U1: [u8; 32] = hex!("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    const O1: [u8; 32] = hex!("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

    const S2: [u8; 32] = hex!("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    const U2: [u8; 32] = hex!("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    const O2: [u8; 32] = hex!("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

    #[test]
    fn rfc7748_single_iteration_vectors() {
        assert_eq!(x25519_raw(S1, U1), O1);
        assert_eq!(x25519_raw(S2, U2), O2);
    }

    #[test]
    fn rfc7748_iterative_vector_1000() {
        // After 1 iteration: 422c8e7a...; after 1000: 684cf59b...
        let mut k = hex!("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = k;
        for i in 1..=1000 {
            let out = x25519_raw(k, u);
            u = k;
            k = out;
            if i == 1 {
                assert_eq!(
                    k,
                    hex!("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
                );
            }
        }
        assert_eq!(
            k,
            hex!("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }

    #[test]
    fn diffie_hellman_agrees_both_directions() {
        let a = AgreeSecret::generate();
        let b = AgreeSecret::generate();
        let ab = a.agree(&b.public()).unwrap();
        let ba = b.agree(&a.public()).unwrap();
        assert_eq!(ab, ba);
        assert_ne!(ab, [0u8; 32]);
    }

    #[test]
    fn low_order_point_is_rejected() {
        // All-zero u is a low-order point; agreement must abort.
        let a = AgreeSecret::generate();
        let zero = AgreePublic::from_bytes(&[0u8; 32]);
        assert!(matches!(
            a.agree(&zero),
            Err(CryptoError::DegenerateAgreement)
        ));
    }

    #[test]
    fn public_key_roundtrip() {
        let s = AgreeSecret::generate();
        let p = s.public();
        assert_eq!(AgreePublic::from_bytes(&p.to_bytes()), p);
    }
}
