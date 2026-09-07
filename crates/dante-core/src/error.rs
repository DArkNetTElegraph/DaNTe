//! [`CoreError`].

use thiserror::Error;

/// An engine operation failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CoreError {
    /// Networking failed.
    #[error(transparent)]
    Net(#[from] dante_net::NetError),

    /// A DM session operation failed.
    #[error(transparent)]
    Dm(#[from] dante_dm::DmError),

    /// An identity/record operation failed.
    #[error(transparent)]
    Identity(#[from] dante_identity::IdentityError),

    /// A primitive failed.
    #[error(transparent)]
    Crypto(#[from] dante_crypto::CryptoError),

    /// A wire structure failed to decode.
    #[error(transparent)]
    Wire(#[from] dante_proto::enc::WireError),

    /// The peer's identity is not in the local ledger replica (sync first, or
    /// they have not announced).
    #[error("peer identity is not known to the ledger")]
    UnknownPeer,

    /// The relay had no prekey bundle for the peer.
    #[error("no prekey bundle published for that peer")]
    NoPrekeys,

    /// A fetched prekey bundle did not match the expected peer or failed its
    /// signature check.
    #[error("peer prekey bundle is inconsistent")]
    BadPeerPrekeys,

    /// A message arrived for a conversation we have no session for.
    #[error("no session for an inbound message")]
    NoSession,
}
