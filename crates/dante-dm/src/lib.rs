//! `dante-dm` — end-to-end-encrypted 1:1 direct messages for DaNTe
//! (`docs/PROTOCOL.md` §4.3).
//!
//! - [`x3dh`] — the initial key agreement: [`PreKeyBundle`](x3dh::PreKeyBundle)
//!   / [`PreKeySecrets`](x3dh::PreKeySecrets), `initiator` / `responder`
//! - [`ratchet`] — the Signal [`Ratchet`](ratchet::Ratchet) (Double Ratchet,
//!   un-encrypted headers), forward secrecy + post-compromise security, skipped
//!   message keys up to `MAX_SKIP`
//! - [`session`] — [`Session`](session::Session) ties them together;
//!   [`InitMessage`](session::InitMessage) is first contact,
//!   [`DmMessage`](session::DmMessage) every message after
//!
//! Chunked encrypted file transfer and the local encrypted message store are
//! layered on top in a later step.

pub mod content;
pub mod error;
pub mod file;
pub mod kdf;
pub mod ratchet;
pub mod session;
pub mod x3dh;

pub use content::Content;
pub use error::DmError;
pub use file::{FileManifest, CHUNK_SIZE};
pub use ratchet::{Header, Ratchet, RatchetState, MAX_SKIP};
pub use session::{DmMessage, InitMessage, Packet, Session, SessionState};
pub use x3dh::{PreKeyBundle, PreKeySecrets, PreKeySecretsState};
