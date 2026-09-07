//! [`LedgerError`] — why a record was not accepted.

use thiserror::Error;

/// A record-acceptance or query failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LedgerError {
    /// `record.v` is not a version this build accepts.
    #[error("unsupported record version {0}")]
    UnsupportedVersion(u16),

    /// `created_ms` is further in the future than the allowed clock skew.
    #[error("record timestamp {created_ms} is beyond now ({now_ms}) + allowed skew")]
    TimestampInFuture {
        /// The record's claimed creation time.
        created_ms: u64,
        /// The verifier's current time.
        now_ms: u64,
    },

    /// The envelope signature did not verify under `record.author`.
    #[error("record signature is invalid")]
    BadSignature,

    /// A body failed to decode or failed its own checks.
    #[error(transparent)]
    Body(#[from] dante_identity::IdentityError),

    /// A wire structure failed to decode.
    #[error(transparent)]
    Wire(#[from] dante_proto::enc::WireError),

    /// A `Tombstone` record was submitted through `append`; tombstones are only
    /// produced by [`crate::Ledger::evaporate`].
    #[error("tombstone records cannot be appended directly")]
    TombstoneNotAllowed,

    /// An `IdentityAnnounce` for a key that is already an active identity.
    #[error("identity is already announced")]
    AlreadyAnnounced,

    /// A record refers to an identity the ledger has never seen announced.
    #[error("unknown identity")]
    UnknownIdentity,

    /// A record targets an identity that has evaporated (been tombstoned).
    #[error("identity has evaporated")]
    IdentityEvaporated,

    /// A record was signed by a key that is not the current tip of its chain.
    #[error("record is not signed by the current chain key")]
    NotChainTip,

    /// `record.author` disagrees with a key named in the body.
    #[error("record author does not match the body")]
    AuthorMismatch,

    /// `created_ms` is not strictly greater than the subject's newest record.
    #[error("record timestamp is not monotonic for its subject")]
    NonMonotonic,

    /// A `KeyRotation` names a `new_idk` that already belongs to an identity.
    #[error("the new key is already in use by another identity")]
    KeyAlreadyInUse,

    /// A `ServerDelist` (or update) referenced a server that was never
    /// registered.
    #[error("unknown server")]
    UnknownServer,

    /// A string/list field exceeded its maximum length.
    #[error("field exceeds its maximum length")]
    FieldTooLong,
}
