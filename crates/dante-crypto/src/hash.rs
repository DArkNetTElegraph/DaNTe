//! SHA-2 hashes used across DaNTe (identity ids, PoW challenge binding,
//! safety numbers, Merkle leaves).

use sha2::{Digest, Sha256, Sha512};

/// SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// SHA-512.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize().into()
}

/// SHA-256 over the concatenation of `parts`, without allocating a joined
/// buffer.
pub fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn sha256_known_answers() {
        // FIPS 180-2 style well-known vectors.
        assert_eq!(
            sha256(b""),
            hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            sha256(b"abc"),
            hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn sha512_empty_known_answer() {
        assert_eq!(
            sha512(b""),
            hex!(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            )
        );
    }

    #[test]
    fn sha256_parts_matches_joined() {
        assert_eq!(sha256_parts(&[b"ab", b"c"]), sha256(b"abc"));
    }
}
