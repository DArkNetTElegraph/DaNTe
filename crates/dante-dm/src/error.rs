//! [`DmError`].

use thiserror::Error;

/// A direct-message session failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DmError {
    /// A primitive failed.
    #[error(transparent)]
    Crypto(#[from] dante_crypto::CryptoError),

    /// A wire structure failed to decode.
    #[error(transparent)]
    Wire(#[from] dante_proto::enc::WireError),

    /// The signed prekey's signature did not verify under the peer's identity
    /// key.
    #[error("prekey bundle signature is invalid")]
    BadPrekeySignature,

    /// The initiator referenced a one-time prekey the responder does not hold.
    #[error("referenced one-time prekey is unknown")]
    UnknownOneTimePrekey,

    /// A message arrived that would require skipping more than `MAX_SKIP` keys.
    #[error("too many skipped messages")]
    TooManySkipped,

    /// The ratchet has no chain key for this direction yet.
    #[error("ratchet is not ready to {0}")]
    NotReady(&'static str),

    /// AEAD authentication failed on a ratchet message.
    #[error("message failed to decrypt")]
    Decrypt,

    /// A file-transfer manifest or chunk did not match its hash / signature.
    #[error("file transfer integrity check failed")]
    FileIntegrity,
}
