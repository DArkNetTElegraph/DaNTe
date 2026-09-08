//! Error type for `dante-mls`.

/// Anything that can go wrong driving an MLS group.
#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    /// The OpenMLS group operation failed.
    #[error("mls group: {0}")]
    Group(String),
    /// A TLS-codec (de)serialization failed.
    #[error("mls codec: {0}")]
    Codec(String),
    /// The crypto backend failed (e.g. key generation).
    #[error("mls crypto: {0}")]
    Crypto(String),
    /// A message of the wrong kind was handed to an entry point.
    #[error("mls: {0}")]
    Unexpected(&'static str),
}
