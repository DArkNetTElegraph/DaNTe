//! `dante-relay` — a community-run DaNTe relay.
//!
//! [`state::RelayState`] is the whole node: a ledger replica plus a
//! sealed-sender mailbox, prekey / MLS key-package directories, a blob store,
//! per-channel ordered logs, and ephemeral signals, speaking the `dante-net`
//! protocol over framed TCP — and, with the default `p2p` feature, over libp2p
//! `/dante/relay/1` as well, with relay↔relay federation over gossipsub. It
//! can also run an in-process TURN server ([`turn_server::TurnServer`]) and
//! hands clients signed ICE config.
//!
//! The `dante-relay` binary wraps [`state::RelayHandler`] and adds argument
//! parsing, the maintenance loop, and the federation event loop.

pub mod run;
pub mod state;
pub mod turn_server;

pub use run::{run, RunConfig, DEFAULT_LISTEN};
