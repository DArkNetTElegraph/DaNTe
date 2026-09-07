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
pub mod store;

pub use channel::{ChannelInfo, ChannelMessage};
pub use engine::{Engine, Inbound, ReceivedDm, DM_TTL_MS};
pub use error::CoreError;
pub use store::{HistoryEntry, HistoryKind};

#[cfg(test)]
mod e2e_tests;
