//! `dante-crypto` — cryptographic primitives for DaNTe.
//!
//! This crate holds primitives and thin, well-tested wrappers only. It performs
//! no I/O and encodes no application policy. Every wrapper is checked against
//! test vectors from the relevant RFC or reference implementation.
//!
//! Implemented so far (Phase 1):
//!
//! - [`sign`]  — Ed25519 signatures (RFC 8032)
//! - [`agree`] — X25519 key agreement (RFC 7748)
//! - [`aead`]  — XChaCha20-Poly1305 and AES-256-GCM (RFC 8439 / reference)
//! - [`kdf`]   — HKDF-SHA-256 (RFC 5869)
//! - [`pow`]   — the `argon2id-pow` memory-hard puzzle (`docs/PROTOCOL.md` §3)
//!
//! Still to come: Double Ratchet wrapper (Phase 4) and MLS wrapper over
//! `OpenMLS` (Phase 6).

mod error;

pub mod aead;
pub mod agree;
pub mod kdf;
pub mod pow;
pub mod sign;

pub use error::CryptoError;

/// Fill an `N`-byte array from the operating system CSPRNG.
///
/// Panics only if the OS RNG is unavailable, which on the platforms DaNTe
/// targets indicates the system is too broken to run.
pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut buf = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}
