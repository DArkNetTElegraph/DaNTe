//! `dante-core` — the orchestration engine consumed by DaNTe clients.
//!
//! Ties [`dante_identity`], [`dante_ledger`], [`dante_net`] and [`dante_dm`]
//! together behind a task-oriented async API plus an event stream (new message,
//! contact verified, peer incompatible, ledger split-view detected, ...).
//!
//! Holds no UI concerns and no direct terminal/GUI output. Both `dante-cli` and
//! the Tauri client are thin shells over this crate.

// Phase 4/5 begin implementation here.
