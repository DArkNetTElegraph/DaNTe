//! `dante-group` — **retired** sender-keys ratchet for channel messages.
//!
//! Each member keeps its own sender chain per channel and shares the chain key
//! with other members over authenticated pairwise DMs. It provided forward
//! secrecy within a chain and removed a departed member's access on a rekey,
//! but not MLS's post-compromise security or O(log n) rekey — so channels moved
//! to `dante-mls` (RFC 9420). No workspace crate depends on this one; it is
//! kept only because the `fuzz` target `group_state` exercises its decoders.
//!
//! - [`Group`] — one member's per-channel view (own sender chain + a receiver
//!   chain per other member)
//! - [`SenderKeyBundle`] — a member's chain key, distributed over DM
//! - [`GroupMessage`] — one encrypted, signed channel message

pub mod error;
pub mod group;

#[cfg(test)]
mod proptests;

pub use error::GroupError;
pub use group::{Group, GroupMessage, GroupState, MemberId, SenderKeyBundle, MAX_SKIP};
