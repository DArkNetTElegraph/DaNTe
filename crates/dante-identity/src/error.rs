//! The error type for this crate.

use thiserror::Error;

/// Anything that can go wrong handling identities, keystores, or liveness
/// records.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// A primitive operation in [`dante_crypto`] failed.
    #[error(transparent)]
    Crypto(#[from] dante_crypto::CryptoError),

    /// A wire structure failed to decode.
    #[error(transparent)]
    Wire(#[from] dante_proto::enc::WireError),

    /// A [`dante_proto::Record`] was handed to an identity decoder but its
    /// `kind` is not an identity body.
    #[error("record kind does not carry an identity body")]
    WrongRecordKind,

    /// A fingerprint string (base32 or word phrase) did not decode to 32 bytes.
    #[error("malformed identity fingerprint")]
    BadFingerprint,

    /// The keystore/backup could not be opened: wrong passphrase, corruption, or
    /// a mismatched container context.
    #[error("keystore could not be opened (wrong passphrase or corrupt file)")]
    KeystoreOpen,

    /// The keystore/backup declared a version this build does not understand.
    #[error("unsupported keystore version {0}")]
    KeystoreVersion(u16),

    /// CBOR (de)serialization failed.
    #[error("serialization error")]
    Encoding,

    /// A `display_hint` / `name` field exceeded its length limit.
    #[error("field exceeds its maximum length")]
    FieldTooLong,

    /// An embedded signature did not verify.
    #[error("signature verification failed")]
    BadSignature,

    /// An embedded proof of work did not meet the required difficulty.
    #[error("proof of work is invalid")]
    BadPow,
}
