//! `dante-crypto` — cryptographic primitives for DaNTe.
//!
//! This crate holds primitives and thin, well-tested wrappers only. It performs
//! no I/O and encodes no application policy. Scope (implemented per phase):
//!
//! - X25519 key agreement, Ed25519 signatures
//! - AEAD: XChaCha20-Poly1305 (default), AES-256-GCM
//! - HKDF-SHA-256, Argon2id
//! - The `argon2id-pow` memory-hard proof-of-work puzzle
//! - Double Ratchet wrapper (1:1 sessions)
//! - MLS wrapper over `OpenMLS` (group sessions)
//!
//! Every primitive wrapper ships with test vectors from the relevant RFC or
//! reference implementation. See `../../docs/PROTOCOL.md` §3 and the threat
//! model's cryptographic posture section.

// Phase 1 begins implementation here.
