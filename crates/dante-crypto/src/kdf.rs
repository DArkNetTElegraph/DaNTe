//! HKDF-SHA-256 (RFC 5869).

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CryptoError;

/// Length of the extracted pseudorandom key (SHA-256 output).
pub const PRK_LEN: usize = 32;

/// HKDF-Extract: derive a pseudorandom key from input keying material.
///
/// `salt` may be empty (RFC 5869 then uses a string of `HashLen` zeros).
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; PRK_LEN] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; PRK_LEN];
    out.copy_from_slice(&prk);
    out
}

/// HKDF-Expand: stretch a PRK into `okm.len()` bytes bound to `info`.
///
/// Fails only if `okm.len() > 255 * 32`.
pub fn expand(prk: &[u8; PRK_LEN], info: &[u8], okm: &mut [u8]) -> Result<(), CryptoError> {
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| CryptoError::Kdf)?;
    hk.expand(info, okm).map_err(|_| CryptoError::Kdf)
}

/// One-shot Extract-then-Expand.
pub fn derive(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, okm).map_err(|_| CryptoError::Kdf)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    // RFC 5869, Appendix A.1 (SHA-256).
    const IKM: [u8; 22] = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const SALT: [u8; 13] = hex!("000102030405060708090a0b0c");
    const INFO: [u8; 10] = hex!("f0f1f2f3f4f5f6f7f8f9");
    const PRK: [u8; 32] = hex!("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    const OKM: [u8; 42] = hex!(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );

    #[test]
    fn rfc5869_test_case_1_extract() {
        assert_eq!(extract(&SALT, &IKM), PRK);
    }

    #[test]
    fn rfc5869_test_case_1_expand() {
        let mut okm = [0u8; 42];
        expand(&PRK, &INFO, &mut okm).unwrap();
        assert_eq!(okm, OKM);
    }

    #[test]
    fn rfc5869_test_case_1_one_shot() {
        let mut okm = [0u8; 42];
        derive(&SALT, &IKM, &INFO, &mut okm).unwrap();
        assert_eq!(okm, OKM);
    }

    #[test]
    fn expand_rejects_overlong_output() {
        let mut too_long = vec![0u8; 255 * 32 + 1];
        assert!(expand(&PRK, b"", &mut too_long).is_err());
    }
}
