//! `dante-net` — the peer-to-peer networking layer for DaNTe.
//!
//! Scope:
//! - libp2p swarm: QUIC + TCP, Noise (`XX`), Yamux
//! - Kademlia DHT for peer / prekey-bundle / server lookup
//! - gossipsub for the ledger topic and (later) per-server topics
//! - request-response for mailbox fetch and ledger range sync
//! - the relay **client**: deposit/poll sealed-sender envelopes
//!
//! DHT key layout and the sealed-sender `Envelope` are specified in
//! `../../docs/PROTOCOL.md` §4.1–4.2.

// Phase 3 begins implementation here.
