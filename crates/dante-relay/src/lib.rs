//! `dante-relay` — a community-run DaNTe relay: a ledger replica plus a
//! sealed-sender mailbox, speaking the `dante-net` protocol over framed TCP.
//!
//! The [`dante-relay`](../dante_relay/index.html) binary is a thin wrapper over
//! [`state::RelayHandler`].

pub mod run;
pub mod state;
pub mod turn_server;

pub use run::{run, RunConfig, DEFAULT_LISTEN};
