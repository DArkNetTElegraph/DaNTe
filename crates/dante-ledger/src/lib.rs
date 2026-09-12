//! `dante-ledger` — the verifiable append-only log ("the ledger").
//!
//! Not a blockchain: no mining, no global consensus. A single record is valid
//! if its signature verifies and it satisfies the acceptance rules
//! ([`Ledger::append`], `docs/PROTOCOL.md` §2.1); global integrity comes from an
//! RFC 6962 Merkle tree over the record encodings and from consistency proofs
//! between tree heads.
//!
//! - [`Ledger`] — record acceptance, identity/key-rotation chains, the server
//!   directory index, Merkle [`Ledger::head`] / [`Ledger::inclusion_proof`] /
//!   [`Ledger::consistency_proof`], and deterministic [`Ledger::evaporate`] GC.
//! - [`RecordStore`] / [`MemoryStore`] — pluggable storage of accepted records.
//! - [`server`] — `ServerRegister` / `ServerDelist` bodies (§2.2 kinds 4–5).
//! - [`tombstone`] — the node-generated `Tombstone` body (§2.3).
//!
//! Replication is not in this crate: accepted records gossip over the
//! `dante-p2p` ledger topic, sync by range in `dante-net::sync`, and relays
//! compare signed tree heads (`dante-relay`).

mod error;
mod ledger;

pub mod server;
pub mod tombstone;

pub use error::LedgerError;
pub use ledger::{Ledger, LedgerParams, MemoryStore, RecordStore, IDENTITY_TTL_MS};
pub use server::{ServerDelist, ServerId, ServerRegister};
pub use tombstone::Tombstone;
