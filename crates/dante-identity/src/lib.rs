//! `dante-identity` — identity lifecycle for DaNTe.
//!
//! Scope:
//! - Generate the `(idk: Ed25519, ik: X25519)` identity keypair
//! - `IdentityId = H(idk_pub)` and its display fingerprints (Crockford base32
//!   + BIP39 word phrase) and safety numbers for contact verification
//! - The on-disk encrypted keystore (`KeystoreFile`, Argon2id-wrapped)
//! - Construction of `IdentityAnnounce` / `LivenessProof` bodies (incl. PoW)
//! - Encrypted key-backup export/import for recovery
//!
//! See `../../docs/PROTOCOL.md` §1.

// Phase 1 begins implementation here.
