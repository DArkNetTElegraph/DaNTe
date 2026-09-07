//! HMAC-SHA-256 (used by the Double Ratchet chain KDF).

use hmac::{
    digest::{FixedOutput, KeyInit, Update},
    Hmac,
};
use sha2::Sha256;

/// HMAC-SHA-256 of `msg` under `key`.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    Update::update(&mut mac, msg);
    mac.finalize_fixed().into()
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn rfc4231_test_case_2() {
        // key = "Jefe", data = "what do ya want for nothing?"
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
            hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    #[test]
    fn rfc4231_test_case_1() {
        assert_eq!(
            hmac_sha256(&[0x0b; 20], b"Hi There"),
            hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
    }
}
