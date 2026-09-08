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

    /// An operation referenced a channel this client is not in.
    #[error("unknown channel")]
    UnknownChannel,

    /// A host-only operation was attempted for a server this client does not
    /// host.
    #[error("not the host of that server")]
    NotServerHost,

    /// A file's chunk is no longer in the relay blob store (expired).
    #[error("a file chunk is missing from the relay")]
    MissingBlob,

    /// The encrypted local store could not be read or written.
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),

    /// An invite link was malformed, forged, expired, or used up.
    #[error("invalid invite link: {0}")]
    Invite(&'static str),

    /// A channel membership operation was rejected.
    #[error("channel operation: {0}")]
    Channel(&'static str),

    /// A direct-message operation (e.g. edit / delete) was rejected.
    #[error("message operation: {0}")]
    Message(&'static str),

    /// The target identity is on this client's block list.
    #[error("that identity is blocked")]
    Blocked,

    /// Setting up or driving a WebRTC call failed.
    #[error("voice: {0}")]
    Voice(String),
}
