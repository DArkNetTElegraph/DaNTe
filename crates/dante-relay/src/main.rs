//! `dante-relay` — a community-run DaNTe relay node.
//!
//! Responsibilities (Phase 3):
//! - Encrypted sealed-sender mailbox with per-envelope TTL
//! - Ledger replication and `TreeHead` gossip
//! - Per-IP / per-/24 rate limiting on `IdentityAnnounce`
//! Later: TURN and SFU roles for group voice/video.
//!
//! A relay sees only ciphertext plus coarse routing metadata. See
//! `../../docs/THREAT_MODEL.md` adversary A3.

fn main() {
    eprintln!("dante-relay: not yet implemented (Phase 3). See docs/DESIGN.md.");
    std::process::exit(1);
}
