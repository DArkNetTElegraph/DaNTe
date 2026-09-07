//! [`GroupError`].

use thiserror::Error;

/// A group-messaging failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GroupError {
    /// A primitive failed.
    #[error(transparent)]
    Crypto(#[from] dante_crypto::CryptoError),

    /// A wire structure failed to decode.
    #[error(transparent)]
    Wire(#[from] dante_proto::enc::WireError),

    /// A message arrived from a member whose sender key we do not hold.
    #[error("unknown group member")]
    UnknownMember,

    /// The message signature did not verify against the member's group key.
    #[error("group message signature is invalid")]
    BadSignature,

    /// The message decrypted-authentication tag failed.
    #[error("group message failed to decrypt")]
    Decrypt,

    /// The message's iteration is behind a key we have already deleted.
    #[error("group message is too old (its key was already deleted)")]
    TooOld,

    /// The message would require skipping more than `MAX_SKIP` keys.
    #[error("too many skipped group messages")]
    TooManySkipped,
}
