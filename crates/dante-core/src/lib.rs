//! `dante-core` — the orchestration engine DaNTe clients drive.
//!
//! [`Engine`] owns one user's identity, a local [`dante_ledger`] replica, a
//! relay connection, prekeys, and live [`dante_dm`] sessions, and exposes a
//! small async API: [`Engine::announce`], [`Engine::publish_prekeys`],
//! [`Engine::sync`], [`Engine::send_dm`], [`Engine::receive`].
//!
//! It holds no UI concerns — `dante-cli` and the Tauri client are thin shells
//! over this crate.

pub mod channel;
pub mod engine;
pub mod error;
pub mod invite;
pub mod roles;
pub mod store;

pub use channel::{ChannelInfo, ChannelMessage, ChannelReaction};
pub use dante_identity::RevokeReason;
pub use dante_voice::{CallEvent, CallState, IceServer};
pub use engine::{
    CallUpdate, ChannelEdit, ChannelPin, Contact, Engine, Inbound, ReceivedDm, SearchHit,
    TypingEvent, TypingScope, DM_TTL_MS,
};
pub use error::CoreError;
pub use invite::InviteToken;
pub use roles::{Role, ServerPolicy};
pub use store::{ChannelHistoryEntry, HistoryEntry, HistoryKind};

#[cfg(test)]
mod e2e_tests;
