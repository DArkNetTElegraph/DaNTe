//! `dante-net` — the transport and relay protocol for DaNTe.
//!
//! MVP topology: clients open a framed TCP connection to one or more
//! community-run **relays** and speak a small request/response protocol.
//!
//! - [`transport`] — framed TCP [`Client`](transport::Client) /
//!   [`serve`](transport::serve) / [`RequestHandler`](transport::RequestHandler)
//! - [`wire`] — the [`Request`](wire::Request) / [`Response`](wire::Response)
//!   messages
//! - [`mailbox`] — a relay's sealed-sender store-and-forward
//!   [`Mailbox`](mailbox::Mailbox)
//! - [`ratelimit`] — token-bucket [`KeyedRateLimiter`](ratelimit::KeyedRateLimiter)
//! - [`sync`] — client helpers: pull/submit ledger records, deposit/fetch
//!   envelopes
//!
//! A libp2p DHT + gossip overlay for multi-relay decentralisation is a later
//! phase; the protocol here is designed to run unchanged over it.

pub mod error;
pub mod mailbox;
pub mod ratelimit;
pub mod sync;
pub mod transport;
pub mod wire;

pub use error::NetError;
pub use mailbox::Mailbox;
pub use ratelimit::KeyedRateLimiter;
pub use transport::{serve, Client, RequestHandler, MAX_FRAME};
pub use wire::{Request, Response};
