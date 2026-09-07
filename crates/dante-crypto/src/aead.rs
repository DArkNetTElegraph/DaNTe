//! Authenticated encryption: XChaCha20-Poly1305 (default) and AES-256-GCM.
//!
//! Both take a caller-supplied nonce. **The caller is responsible for nonce
//! uniqueness per key** — reusing a `(key, nonce)` pair breaks confidentiality
//! for XChaCha20-Poly1305 and is catastrophic for AES-GCM. Higher layers derive
//! nonces from a counter or draw the 24-byte XChaCha nonce at random.

use aes_gcm::Aes256Gcm;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};

use crate::error::CryptoError;

/// AEAD key length (both ciphers).
pub const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length.
pub const XNONCE_LEN: usize = 24;
/// AES-256-GCM nonce length.
pub const GCM_NONCE_LEN: usize = 12;
/// Poly1305 / GCM authentication tag length, appended to every ciphertext.
pub const TAG_LEN: usize = 16;

/// Encrypt with XChaCha20-Poly1305. Output is `ciphertext || tag`.
pub fn xchacha_seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; XNONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("KEY_LEN is 32");
    cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption does not fail for in-memory inputs")
}

/// Decrypt and authenticate an XChaCha20-Poly1305 `ciphertext || tag`.
pub fn xchacha_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; XNONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("KEY_LEN is 32");
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadFailure)
}

/// Encrypt with AES-256-GCM. Output is `ciphertext || tag`.
pub fn aes256gcm_seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; GCM_NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("KEY_LEN is 32");
    cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-256-GCM encryption does not fail for in-memory inputs")
}

/// Decrypt and authenticate an AES-256-GCM `ciphertext || tag`.
pub fn aes256gcm_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; GCM_NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("KEY_LEN is 32");
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadFailure)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];
    const XN: [u8; 24] = [9u8; 24];
    const GN: [u8; 12] = [3u8; 12];

    #[test]
    fn xchacha_roundtrip_with_aad() {
        let ct = xchacha_seal(&KEY, &XN, b"envelope body", b"header");
        assert_ne!(ct, b"envelope body");
        assert_eq!(ct.len(), b"envelope body".len() + TAG_LEN);
        let pt = xchacha_open(&KEY, &XN, &ct, b"header").unwrap();
        assert_eq!(pt, b"envelope body");
    }

    #[test]
    fn xchacha_rejects_tamper_wrong_aad_wrong_key_wrong_nonce() {
        let ct = xchacha_seal(&KEY, &XN, b"secret", b"aad");

        let mut flipped = ct.clone();
        flipped[0] ^= 1;
        assert!(xchacha_open(&KEY, &XN, &flipped, b"aad").is_err());

        assert!(xchacha_open(&KEY, &XN, &ct, b"other aad").is_err());

        let mut other_key = KEY;
        other_key[0] ^= 1;
        assert!(xchacha_open(&other_key, &XN, &ct, b"aad").is_err());

        let mut other_nonce = XN;
        other_nonce[0] ^= 1;
        assert!(xchacha_open(&KEY, &other_nonce, &ct, b"aad").is_err());
    }

    #[test]
    fn aes256gcm_roundtrip_and_reject_tamper() {
        let ct = aes256gcm_seal(&KEY, &GN, b"secret", b"aad");
        assert_eq!(ct.len(), b"secret".len() + TAG_LEN);
        assert_eq!(aes256gcm_open(&KEY, &GN, &ct, b"aad").unwrap(), b"secret");

        let mut flipped = ct;
        flipped[2] ^= 8;
        assert!(aes256gcm_open(&KEY, &GN, &flipped, b"aad").is_err());
    }

    #[test]
    fn empty_plaintext_is_still_authenticated() {
        let ct = xchacha_seal(&KEY, &XN, b"", b"");
        assert_eq!(ct.len(), TAG_LEN);
        assert_eq!(xchacha_open(&KEY, &XN, &ct, b"").unwrap(), b"");
        let mut bad = ct;
        bad[0] ^= 1;
        assert!(xchacha_open(&KEY, &XN, &bad, b"").is_err());
    }
}
