//! `dante-proto` — canonical wire types shared across the DaNTe network
//! boundary.
//!
//! - [`enc`]    — the deterministic length-prefixed binary codec every wire
//!   structure is built from
//! - [`record`] — the body-agnostic ledger [`Record`](record::Record) envelope
//!   (`docs/PROTOCOL.md` §2.1)
//! - [`merkle`] — RFC 6962 Merkle Tree Hash, inclusion proofs, consistency
//!   proofs
//! - [`head`]   — [`SignedTreeHead`](head::SignedTreeHead) for split-view
//!   detection (§2.4)
//! - [`pow`]    — wire codec for `dante_crypto::pow::PowProof`
//!
//! Body semantics live with the crate that owns them (`dante-identity` for
//! identity records, `dante-ledger` for the server registry and tombstones);
//! this crate only defines the envelope and the encoding.

pub mod enc;
pub mod head;
pub mod merkle;
pub mod pow;
pub mod record;

pub use enc::{Reader, WireError, Writer};
pub use head::{SignedTreeHead, TreeHead};
pub use record::{Record, RecordId, RecordKind, CLOCK_SKEW_MS, RECORD_VERSION};
