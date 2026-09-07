//! `dante-ledger` — the verifiable log ("ledger") for DaNTe.
//!
//! Not a blockchain: no mining, no global consensus. A record is valid if its
//! signature verifies; global integrity comes from an RFC 6962-style Merkle tree
//! and consistency proofs between tree heads.
//!
//! Scope:
//! - Record acceptance rules (`../../docs/PROTOCOL.md` §2.1–2.2)
//! - Append-only Merkle tree; inclusion + consistency proofs
//! - Deterministic evaporation GC and tombstoning (§2.3)
//! - Replication / split-view detection state machine (§2.4)
//!
//! Storage-backend agnostic — the backend is injected by the caller.

// Phase 2 begins implementation here.
