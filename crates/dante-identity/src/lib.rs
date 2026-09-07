//! `dante-identity` — identity lifecycle for DaNTe.
//!
//! - [`Identity`] — the `(idk: Ed25519, ik: X25519)` keypair plus a local
//!   message-store key, held in memory
//! - [`IdentityId`] — `SHA-256(idk_pub)`, with Crockford-base32 and BIP39
//!   word-phrase renderings and a pairwise [`id::safety_number`]
//! - [`keystore`] — the Argon2id-wrapped on-disk keystore (`docs/PROTOCOL.md`
//!   §1.2)
//! - [`backup`] — the passphrase-encrypted key backup for recovery (§1.3)
//! - [`records`] — the `IdentityAnnounce` / `LivenessProof` / `KeyRotation`
//!   ledger-record bodies, their PoW/link challenges, and `Record` wrapping
//!   (§2.2)

mod error;

pub mod backup;
pub mod id;
pub mod identity;
pub mod keystore;
pub mod records;

pub use error::IdentityError;
pub use id::IdentityId;
pub use identity::Identity;
pub use records::{
    IdentityAnnounce, IdentityRecord, IdentityRevoke, KeyRotation, LivenessProof, RevokeReason,
};
