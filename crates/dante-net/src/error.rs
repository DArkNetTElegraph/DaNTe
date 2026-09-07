//! [`NetError`].

use thiserror::Error;

/// A networking failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NetError {
    /// Underlying socket I/O failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A frame's length prefix exceeded [`crate::transport::MAX_FRAME`].
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(u32),

    /// The peer closed the connection mid-frame.
    #[error("connection closed unexpectedly")]
    Closed,

    /// A wire message failed to decode.
    #[error("protocol decode error: {0}")]
    Decode(#[from] dante_proto::enc::WireError),

    /// The peer returned an error response.
    #[error("peer error: {0}")]
    Peer(String),

    /// The response was not the shape the request expected.
    #[error("unexpected response to {0}")]
    UnexpectedResponse(&'static str),

    /// A deposited envelope was already expired or its TTL was over the cap.
    #[error("envelope rejected: {0}")]
    RejectedEnvelope(&'static str),

    /// The client is being rate limited.
    #[error("rate limited")]
    RateLimited,
}
