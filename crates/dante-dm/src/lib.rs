//! `dante-dm` — end-to-end-encrypted 1:1 direct messages for DaNTe.
//!
//! Scope:
//! - `PreKeyBundle` publication and refresh
//! - X3DH session initiation against a fetched bundle
//! - Double Ratchet session state, per-message keys, skipped-key handling
//! - Chunked encrypted file transfer (per-file key, signed manifest)
//! - Encrypted local message store (`rusqlite`, key from the keystore)
//!
//! See `../../docs/PROTOCOL.md` §4.3. This is the Phase 4 MVP deliverable.

// Phase 4 begins implementation here.
