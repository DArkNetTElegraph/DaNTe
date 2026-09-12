//! `dante-net` — the transport and relay protocol for DaNTe.
//!
//! MVP topology: clients open a framed TCP connection to one or more
//! community-run **relays** and speak a small request/response protocol.
//!
//! - [`transport`] — framed TCP [`Client`](transport::Client) /
//!   [`serve`](transport::serve) / [`RequestHandler`](transport::RequestHandler);
//!   with the `p2p` feature the same wire also rides a libp2p
//!   `/dante/relay/1` stream
//! - [`wire`] — the [`Request`](wire::Request) / [`Response`](wire::Response)
//!   messages
//! - [`mailbox`] — a relay's sealed-sender store-and-forward
//!   [`Mailbox`](mailbox::Mailbox)
//! - [`ratelimit`] — token-bucket [`KeyedRateLimiter`](ratelimit::KeyedRateLimiter)
//! - [`socks5`] — a minimal no-auth SOCKS5 client for dialling `.onion` relays
//!   through Tor
//! - [`sync`] — client helpers: pull/submit ledger records, deposit/fetch
//!   envelopes, prekeys, key packages, blobs, channel logs, signals, ICE config
//!
//! The libp2p DHT + gossip overlay lives in `dante-p2p`; this crate's wire runs
//! unchanged over it under the `p2p` feature.

pub mod error;
pub mod mailbox;
pub mod ratelimit;
pub mod socks5;
pub mod sync;
pub mod transport;
pub mod wire;

#[cfg(test)]
mod proptests;

pub use error::NetError;
pub use mailbox::Mailbox;
pub use ratelimit::KeyedRateLimiter;
pub use transport::{serve, Client, RequestHandler, MAX_FRAME};
pub use wire::{IceCfg, Request, Response};
