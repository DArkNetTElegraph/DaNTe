//! The single error type for this crate.

use thiserror::Error;

/// Anything that can go wrong in `dante-crypto`.
///
/// Deliberately coarse: callers should treat any variant as "the cryptographic
/// operation failed" and must not branch on the specific cause in a way an
/// attacker could observe through timing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// A key was the wrong length, not canonical, or otherwise unusable.
    #[error("invalid key encoding")]
    InvalidKey,

    /// A signature failed to verify.
    #[error("signature verification failed")]
    BadSignature,

    /// AEAD decryption failed authentication (wrong key, nonce, AAD, or tampered
    /// ciphertext).
    #[error("AEAD authentication failed")]
    AeadFailure,

    /// An X25519 agreement produced the all-zero output (non-contributory).
    #[error("key agreement produced a degenerate shared secret")]
    DegenerateAgreement,

    /// HKDF expansion was asked for an invalid output length.
    #[error("HKDF expansion failed")]
    Kdf,

    /// Argon2 could not be constructed or evaluated with the given parameters.
    #[error("argon2 evaluation failed: {0}")]
    Argon2(&'static str),

    /// A proof of work did not meet its stated difficulty.
    #[error("proof of work does not meet the required difficulty")]
    PowUnmetDifficulty,
}
