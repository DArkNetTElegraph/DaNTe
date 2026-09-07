//! `dante-proto` — canonical wire types shared across the DaNTe network boundary.
//!
//! Owns the single deterministic serializer (canonical CBOR, per
//! `../../docs/PROTOCOL.md` §0). No other crate serializes wire types directly.
//! Contains data definitions only — record envelopes, the sealed-sender
//! `Envelope`, `PreKeyBundle`, `TreeHead`, `PowProof`, etc. — with no protocol
//! logic.

// Phase 2/3 begin implementation here.
