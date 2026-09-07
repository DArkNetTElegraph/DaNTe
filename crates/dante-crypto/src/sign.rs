//! Ed25519 signatures (RFC 8032).
//!
//! Verification uses `verify_strict`, which rejects non-canonical `R`/`s` and
//! small-order public keys — the behaviour DaNTe wants for identity keys.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::{error::CryptoError, random_bytes};

/// Length of a serialized secret signing key.
pub const SECRET_LEN: usize = 32;
/// Length of a serialized public verifying key.
pub const PUBLIC_LEN: usize = 32;
/// Length of a serialized signature.
pub const SIG_LEN: usize = 64;

/// An Ed25519 secret key. Zeroized on drop (via `SigningKey`'s `zeroize`
/// feature).
#[derive(Clone)]
pub struct SignSecret(SigningKey);

impl SignSecret {
    /// Generate a fresh key from the OS CSPRNG.
    pub fn generate() -> Self {
        Self(SigningKey::from_bytes(&random_bytes::<SECRET_LEN>()))
    }

    /// Load a key from its 32-byte seed.
    pub fn from_bytes(bytes: &[u8; SECRET_LEN]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    /// Serialize the 32-byte seed. Handle the result as secret material.
    pub fn to_bytes(&self) -> [u8; SECRET_LEN] {
        self.0.to_bytes()
    }

    /// The matching public key.
    pub fn public(&self) -> SignPublic {
        SignPublic(self.0.verifying_key())
    }

    /// Sign `msg`.
    pub fn sign(&self, msg: &[u8]) -> [u8; SIG_LEN] {
        self.0.sign(msg).to_bytes()
    }
}

impl core::fmt::Debug for SignSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignSecret").finish_non_exhaustive()
    }
}

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignPublic(VerifyingKey);

impl SignPublic {
    /// Parse a 32-byte public key. Rejects non-canonical encodings.
    pub fn from_bytes(bytes: &[u8; PUBLIC_LEN]) -> Result<Self, CryptoError> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }

    /// Serialize to 32 bytes.
    pub fn to_bytes(&self) -> [u8; PUBLIC_LEN] {
        self.0.to_bytes()
    }

    /// Verify `sig` over `msg`. Uses strict verification.
    pub fn verify(&self, msg: &[u8], sig: &[u8; SIG_LEN]) -> Result<(), CryptoError> {
        let sig = Signature::from_bytes(sig);
        self.0
            .verify_strict(msg, &sig)
            .map_err(|_| CryptoError::BadSignature)
    }

    /// Verify without the strict small-order / canonical checks. Only for
    /// interoperating with vectors that predate `verify_strict`; do not use for
    /// DaNTe identity keys.
    pub fn verify_lenient(&self, msg: &[u8], sig: &[u8; SIG_LEN]) -> Result<(), CryptoError> {
        let sig = Signature::from_bytes(sig);
        self.0
            .verify(msg, &sig)
            .map_err(|_| CryptoError::BadSignature)
    }
}

impl core::fmt::Debug for SignPublic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SignPublic({})", hex_lower(&self.to_bytes()))
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    // RFC 8032, section 7.1.
    const T1_SECRET: [u8; 32] =
        hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    const T1_PUBLIC: [u8; 32] =
        hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const T1_SIG: [u8; 64] = hex!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );

    // RFC 8032, section 7.1, TEST 2 (1-byte message 0x72).
    const T2_SECRET: [u8; 32] =
        hex!("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    const T2_PUBLIC: [u8; 32] =
        hex!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    const T2_MSG: [u8; 1] = hex!("72");
    const T2_SIG: [u8; 64] = hex!(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    );

    #[test]
    fn rfc8032_public_key_derivation() {
        assert_eq!(
            SignSecret::from_bytes(&T1_SECRET).public().to_bytes(),
            T1_PUBLIC
        );
        assert_eq!(
            SignSecret::from_bytes(&T2_SECRET).public().to_bytes(),
            T2_PUBLIC
        );
    }

    #[test]
    fn rfc8032_signing_matches_vectors() {
        assert_eq!(SignSecret::from_bytes(&T1_SECRET).sign(b""), T1_SIG);
        assert_eq!(SignSecret::from_bytes(&T2_SECRET).sign(&T2_MSG), T2_SIG);
    }

    #[test]
    fn rfc8032_verification() {
        SignPublic::from_bytes(&T1_PUBLIC)
            .unwrap()
            .verify(b"", &T1_SIG)
            .unwrap();
        SignPublic::from_bytes(&T2_PUBLIC)
            .unwrap()
            .verify(&T2_MSG, &T2_SIG)
            .unwrap();
    }

    #[test]
    fn tampered_signature_and_message_are_rejected() {
        let pk = SignPublic::from_bytes(&T2_PUBLIC).unwrap();

        let mut bad_sig = T2_SIG;
        bad_sig[0] ^= 1;
        assert!(pk.verify(&T2_MSG, &bad_sig).is_err());

        assert!(pk.verify(b"different message", &T2_SIG).is_err());
    }

    #[test]
    fn roundtrip_random_key() {
        let sk = SignSecret::generate();
        let pk = sk.public();
        let sig = sk.sign(b"the treaty is signed");
        pk.verify(b"the treaty is signed", &sig).unwrap();

        let pk2 = SignPublic::from_bytes(&pk.to_bytes()).unwrap();
        assert_eq!(pk, pk2);

        let sk2 = SignSecret::from_bytes(&sk.to_bytes());
        assert_eq!(sk2.public(), pk);
    }
}
