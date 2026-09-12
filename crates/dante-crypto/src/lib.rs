//! `dante-crypto` — cryptographic primitives for DaNTe.
//!
//! This crate holds primitives and thin, well-tested wrappers only. It performs
//! no I/O and encodes no application policy. Wrappers are checked against test
//! vectors from the relevant RFC or reference implementation where published
//! vectors exist, and against round-trip / tamper tests otherwise.
//!
//! Implemented so far (Phase 1):
//!
//! - [`sign`]   — Ed25519 signatures (RFC 8032)
//! - [`agree`]  — X25519 key agreement (RFC 7748)
//! - [`aead`]   — XChaCha20-Poly1305 and AES-256-GCM (RFC 8439 / reference)
//! - [`kdf`]    — HKDF-SHA-256 (RFC 5869)
//! - [`mac`]    — HMAC-SHA-256 (RFC 4231)
//! - [`hash`]   — SHA-256 / SHA-512
//! - [`pwhash`] — Argon2id KDF for low-entropy secrets (keystore, key backup)
//! - [`pow`]    — the `argon2id-pow` memory-hard puzzle (`docs/PROTOCOL.md` §3)
//!
//! The Double Ratchet lives in `dante-dm` and the MLS (RFC 9420) wrapper in
//! `dante-mls`; both are built on these primitives.

mod error;

pub mod aead;
pub mod agree;
pub mod hash;
pub mod kdf;
pub mod mac;
pub mod pow;
pub mod pwhash;
pub mod sign;

pub use error::CryptoError;

/// Return an `N`-byte array filled from the operating system CSPRNG.
///
/// Panics only if the OS RNG is unavailable, which on the platforms DaNTe
/// targets indicates the system is too broken to run.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    fill_random(&mut buf);
    buf
}

/// Fill `buf` from the operating system CSPRNG. Same panic contract as
/// [`random_array`].
pub fn fill_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS CSPRNG unavailable");
}

pub(crate) use random_array as random_bytes;
