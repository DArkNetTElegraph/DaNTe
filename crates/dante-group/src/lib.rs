//! `dante-group` — group message encryption for DaNTe channels.
//!
//! A **sender-keys ratchet**: each member keeps its own sender chain per
//! channel and shares the chain key with other members over authenticated
//! pairwise DMs. Provides forward secrecy within a chain and removes a
//! departed member's access on a rekey; it does **not** provide MLS's
//! post-compromise security or O(log n) rekey. A migration of channels to MLS
//! (RFC 9420) is planned.
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
