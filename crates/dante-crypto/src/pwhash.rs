//! Argon2id password hashing / key derivation from low-entropy secrets.
//!
//! Used to wrap the on-disk keystore and the encrypted key backup
//! (`docs/PROTOCOL.md` §1.2–1.3). Distinct from [`crate::pow`], which uses the
//! same function as a puzzle rather than a KDF.

use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::CryptoError;

/// Recommended keystore parameters: 256 MiB, 3 passes, 1 lane
/// (`docs/PROTOCOL.md` §1.2). Travels in the keystore file so it can be raised
/// later without breaking old files.
pub const KEYSTORE: Argon2idParams = Argon2idParams {
    m_cost_kib: 262_144,
    t_cost: 3,
    p_cost: 1,
};

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2idParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Time cost (passes).
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

/// Derive `out.len()` bytes from `password` and `salt` with Argon2id.
///
/// `salt` must be at least 8 bytes. `out` is typically 32 bytes (an AEAD key).
pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    params: Argon2idParams,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let p = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(out.len()),
    )
    .map_err(|_| CryptoError::Argon2("invalid parameters"))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(password, salt, out)
        .map_err(|_| CryptoError::Argon2("hash failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cheap parameters for tests.
    const FAST: Argon2idParams = Argon2idParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn deterministic_for_same_inputs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        argon2id(b"correct horse", b"saltsalt", FAST, &mut a).unwrap();
        argon2id(b"correct horse", b"saltsalt", FAST, &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn changes_with_password_and_salt() {
        let mut base = [0u8; 32];
        let mut diff_pw = [0u8; 32];
        let mut diff_salt = [0u8; 32];
        argon2id(b"pw", b"saltsalt", FAST, &mut base).unwrap();
        argon2id(b"pX", b"saltsalt", FAST, &mut diff_pw).unwrap();
        argon2id(b"pw", b"saltsalY", FAST, &mut diff_salt).unwrap();
        assert_ne!(base, diff_pw);
        assert_ne!(base, diff_salt);
    }

    #[test]
    fn short_salt_is_rejected() {
        let mut out = [0u8; 32];
        assert!(argon2id(b"pw", b"short", FAST, &mut out).is_err());
    }
}
