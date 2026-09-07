//! The root / chain / message key-derivation functions of the Double Ratchet.

use dante_crypto::{kdf, mac::hmac_sha256};

const ROOT_INFO: &[u8] = b"DaNTe/DR/root/v1";
const MSG_INFO: &[u8] = b"DaNTe/DR/msg/v1";

/// `KDF_RK`: mix a fresh DH output into the root key, yielding a new root key
/// and a new chain key. HKDF-SHA-256 with `salt = rk`, `ikm = dh_out`.
pub fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let prk = kdf::extract(rk, dh_out);
    let mut out = [0u8; 64];
    kdf::expand(&prk, ROOT_INFO, &mut out).expect("64 <= 255*32");
    let mut new_rk = [0u8; 32];
    let mut new_ck = [0u8; 32];
    new_rk.copy_from_slice(&out[..32]);
    new_ck.copy_from_slice(&out[32..]);
    (new_rk, new_ck)
}

/// `KDF_CK`: advance a chain key, yielding the next chain key and this step's
/// message key. `mk = HMAC(ck, 0x01)`, `ck' = HMAC(ck, 0x02)`.
pub fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mk = hmac_sha256(ck, &[0x01]);
    let next_ck = hmac_sha256(ck, &[0x02]);
    (next_ck, mk)
}

/// Expand a message key into an XChaCha20-Poly1305 `(key, nonce)`.
pub fn message_keys(mk: &[u8; 32]) -> ([u8; 32], [u8; 24]) {
    let prk = kdf::extract(&[0u8; 32], mk);
    let mut out = [0u8; 56];
    kdf::expand(&prk, MSG_INFO, &mut out).expect("56 <= 255*32");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    key.copy_from_slice(&out[..32]);
    nonce.copy_from_slice(&out[32..]);
    (key, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_rk_is_deterministic_and_mixes_both_inputs() {
        let (rk1, ck1) = kdf_rk(&[1u8; 32], &[2u8; 32]);
        let (rk2, ck2) = kdf_rk(&[1u8; 32], &[2u8; 32]);
        assert_eq!((rk1, ck1), (rk2, ck2));
        assert_ne!(rk1, ck1);
        assert_ne!(kdf_rk(&[9u8; 32], &[2u8; 32]).0, rk1);
        assert_ne!(kdf_rk(&[1u8; 32], &[9u8; 32]).0, rk1);
    }

    #[test]
    fn kdf_ck_advances() {
        let ck0 = [7u8; 32];
        let (ck1, mk0) = kdf_ck(&ck0);
        let (ck2, mk1) = kdf_ck(&ck1);
        assert_ne!(ck0, ck1);
        assert_ne!(ck1, ck2);
        assert_ne!(mk0, mk1);
    }

    #[test]
    fn message_keys_distinct_key_and_nonce() {
        let (k, n) = message_keys(&[3u8; 32]);
        assert_ne!(&k[..24], &n[..]);
        assert_ne!(message_keys(&[4u8; 32]).0, k);
    }
}
