//! The relay request/response protocol.
//!
//! One round trip per [`Request`]. Bodies are the raw canonical encodings of
//! [`dante_proto`] types (`Record`, `Envelope`) so this layer stays a thin
//! transport.

use dante_proto::enc::{Reader, WireError, Writer};

/// A client -> relay request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Liveness check.
    Ping,
    /// Submit an encoded `Record` for ledger acceptance.
    SubmitRecord(Vec<u8>),
    /// Ask for the relay's current ledger tree head.
    GetTreeHead,
    /// Ask for encoded records at store indices `[from, to)`.
    GetRecords {
        /// First index (inclusive).
        from: u64,
        /// End index (exclusive).
        to: u64,
    },
    /// Deposit an encoded `Envelope` into the mailbox.
    Deposit(Vec<u8>),
    /// Fetch mailbox envelopes for `hints` deposited at/after `since_ms`.
    Fetch {
        /// Recipient hints to poll (a small window of day-buckets).
        hints: Vec<[u8; 8]>,
        /// Only return envelopes deposited at or after this time.
        since_ms: u64,
    },
    /// Publish an encoded `dante_dm` `PreKeyBundle`, keyed by its `identity_id`.
    PublishPrekeys(Vec<u8>),
    /// Retrieve the published prekey bundle for an `identity_id`.
    GetPrekeys([u8; 32]),
    /// Store a ciphertext blob (a file chunk); the relay keys it by
    /// `SHA-256(bytes)` and returns [`Response::Ok`].
    PutBlob(Vec<u8>),
    /// Retrieve a blob by its `SHA-256`.
    GetBlob([u8; 32]),
    /// Append an (opaque, E2E-encrypted) message to a channel's log.
    PostToChannel {
        /// The channel id (a shared 32-byte capability).
        channel_id: [u8; 32],
        /// The encoded `dante_group::GroupMessage`.
        blob: Vec<u8>,
    },
    /// Read a channel's log from `since_seq` (exclusive).
    FetchChannel {
        /// The channel id.
        channel_id: [u8; 32],
        /// Return entries with sequence number greater than this.
        since_seq: u64,
    },
    /// Post an ephemeral, unlogged signal (e.g. a typing indicator) under a
    /// shared `topic`. The relay holds each for a few seconds only and never
    /// persists it. Fire-and-forget: the reply is [`Response::Ok`].
    PostSignal {
        /// A shared 32-byte capability (a `channel_id`, or a DM signal tag).
        topic: [u8; 32],
        /// The opaque, E2E-encrypted payload.
        blob: Vec<u8>,
    },
    /// Drain the currently-buffered signals for `topic`.
    FetchSignals {
        /// The shared topic to read.
        topic: [u8; 32],
    },
}

/// A relay -> client response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// Reply to [`Request::Ping`].
    Pong,
    /// Generic success with no payload.
    Ok,
    /// The request was refused; the string is a human-readable reason.
    Error(String),
    /// Reply to [`Request::GetTreeHead`].
    TreeHead {
        /// Number of records.
        size: u64,
        /// Merkle root.
        root: [u8; 32],
    },
    /// Reply to [`Request::GetRecords`]: encoded records in index order.
    Records(Vec<Vec<u8>>),
    /// Reply to [`Request::Fetch`]: encoded envelopes, oldest first.
    Envelopes(Vec<Vec<u8>>),
    /// Reply to [`Request::GetPrekeys`]: the encoded bundle, or `None`.
    Prekeys(Option<Vec<u8>>),
    /// Reply to [`Request::GetBlob`]: the blob, or `None`.
    Blob(Option<Vec<u8>>),
    /// Reply to [`Request::FetchChannel`]: `(seq, blob)` pairs in order.
    ChannelLog(Vec<(u64, Vec<u8>)>),
    /// Reply to [`Request::FetchSignals`]: opaque payloads, oldest first.
    Signals(Vec<Vec<u8>>),
}

const REQ_PING: u8 = 0;
const REQ_SUBMIT: u8 = 1;
const REQ_GET_HEAD: u8 = 2;
const REQ_GET_RECORDS: u8 = 3;
const REQ_DEPOSIT: u8 = 4;
const REQ_FETCH: u8 = 5;
const REQ_PUBLISH_PREKEYS: u8 = 6;
const REQ_GET_PREKEYS: u8 = 7;
const REQ_PUT_BLOB: u8 = 8;
const REQ_GET_BLOB: u8 = 9;
const REQ_POST_CHANNEL: u8 = 10;
const REQ_FETCH_CHANNEL: u8 = 11;
const REQ_POST_SIGNAL: u8 = 12;
const REQ_FETCH_SIGNALS: u8 = 13;

const RES_PONG: u8 = 0;
const RES_OK: u8 = 1;
const RES_ERROR: u8 = 2;
const RES_TREE_HEAD: u8 = 3;
const RES_RECORDS: u8 = 4;
const RES_ENVELOPES: u8 = 5;
const RES_PREKEYS: u8 = 6;
const RES_BLOB: u8 = 7;
const RES_CHANNEL_LOG: u8 = 8;
const RES_SIGNALS: u8 = 9;

fn write_blob_list(w: &mut Writer, blobs: &[Vec<u8>]) {
    w.u32(blobs.len() as u32);
    for b in blobs {
        w.bytes(b);
    }
}

fn read_blob_list(r: &mut Reader<'_>) -> Result<Vec<Vec<u8>>, WireError> {
    let n = r.u32()? as usize;
    if n > r.remaining() {
        return Err(WireError::LengthTooLarge(n as u64));
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(r.bytes()?.to_vec());
    }
    Ok(out)
}

impl Request {
    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Request::Ping => {
                w.u8(REQ_PING);
            }
            Request::SubmitRecord(rec) => {
                w.u8(REQ_SUBMIT).bytes(rec);
            }
            Request::GetTreeHead => {
                w.u8(REQ_GET_HEAD);
            }
            Request::GetRecords { from, to } => {
                w.u8(REQ_GET_RECORDS).u64(*from).u64(*to);
            }
            Request::Deposit(env) => {
                w.u8(REQ_DEPOSIT).bytes(env);
            }
            Request::Fetch { hints, since_ms } => {
                w.u8(REQ_FETCH).u32(hints.len() as u32);
                for h in hints {
                    w.fixed(h);
                }
                w.u64(*since_ms);
            }
            Request::PublishPrekeys(bundle) => {
                w.u8(REQ_PUBLISH_PREKEYS).bytes(bundle);
            }
            Request::GetPrekeys(id) => {
                w.u8(REQ_GET_PREKEYS).fixed(id);
            }
            Request::PutBlob(bytes) => {
                w.u8(REQ_PUT_BLOB).bytes(bytes);
            }
            Request::GetBlob(hash) => {
                w.u8(REQ_GET_BLOB).fixed(hash);
            }
            Request::PostToChannel { channel_id, blob } => {
                w.u8(REQ_POST_CHANNEL).fixed(channel_id).bytes(blob);
            }
            Request::FetchChannel {
                channel_id,
                since_seq,
            } => {
                w.u8(REQ_FETCH_CHANNEL).fixed(channel_id).u64(*since_seq);
            }
            Request::PostSignal { topic, blob } => {
                w.u8(REQ_POST_SIGNAL).fixed(topic).bytes(blob);
            }
            Request::FetchSignals { topic } => {
                w.u8(REQ_FETCH_SIGNALS).fixed(topic);
            }
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let tag = r.u8()?;
        let out = match tag {
            REQ_PING => Request::Ping,
            REQ_SUBMIT => Request::SubmitRecord(r.bytes()?.to_vec()),
            REQ_GET_HEAD => Request::GetTreeHead,
            REQ_GET_RECORDS => Request::GetRecords {
                from: r.u64()?,
                to: r.u64()?,
            },
            REQ_DEPOSIT => Request::Deposit(r.bytes()?.to_vec()),
            REQ_PUBLISH_PREKEYS => Request::PublishPrekeys(r.bytes()?.to_vec()),
            REQ_GET_PREKEYS => Request::GetPrekeys(r.fixed::<32>()?),
            REQ_PUT_BLOB => Request::PutBlob(r.bytes()?.to_vec()),
            REQ_GET_BLOB => Request::GetBlob(r.fixed::<32>()?),
            REQ_POST_CHANNEL => Request::PostToChannel {
                channel_id: r.fixed::<32>()?,
                blob: r.bytes()?.to_vec(),
            },
            REQ_FETCH_CHANNEL => Request::FetchChannel {
                channel_id: r.fixed::<32>()?,
                since_seq: r.u64()?,
            },
            REQ_POST_SIGNAL => Request::PostSignal {
                topic: r.fixed::<32>()?,
                blob: r.bytes()?.to_vec(),
            },
            REQ_FETCH_SIGNALS => Request::FetchSignals {
                topic: r.fixed::<32>()?,
            },
            REQ_FETCH => {
                let n = r.u32()? as usize;
                if n > r.remaining() {
                    return Err(WireError::LengthTooLarge(n as u64));
                }
                let mut hints = Vec::with_capacity(n);
                for _ in 0..n {
                    hints.push(r.fixed::<8>()?);
                }
                Request::Fetch {
                    hints,
                    since_ms: r.u64()?,
                }
            }
            other => {
                return Err(WireError::BadDiscriminant {
                    ty: "Request",
                    value: other.into(),
                })
            }
        };
        r.finish()?;
        Ok(out)
    }

    /// A short label for error messages.
    pub fn label(&self) -> &'static str {
        match self {
            Request::Ping => "Ping",
            Request::SubmitRecord(_) => "SubmitRecord",
            Request::GetTreeHead => "GetTreeHead",
            Request::GetRecords { .. } => "GetRecords",
            Request::Deposit(_) => "Deposit",
            Request::Fetch { .. } => "Fetch",
            Request::PublishPrekeys(_) => "PublishPrekeys",
            Request::GetPrekeys(_) => "GetPrekeys",
            Request::PutBlob(_) => "PutBlob",
            Request::GetBlob(_) => "GetBlob",
            Request::PostToChannel { .. } => "PostToChannel",
            Request::FetchChannel { .. } => "FetchChannel",
            Request::PostSignal { .. } => "PostSignal",
            Request::FetchSignals { .. } => "FetchSignals",
        }
    }
}

impl Response {
    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Response::Pong => {
                w.u8(RES_PONG);
            }
            Response::Ok => {
                w.u8(RES_OK);
            }
            Response::Error(msg) => {
                w.u8(RES_ERROR).string(msg);
            }
            Response::TreeHead { size, root } => {
                w.u8(RES_TREE_HEAD).u64(*size).fixed(root);
            }
            Response::Records(blobs) => {
                w.u8(RES_RECORDS);
                write_blob_list(&mut w, blobs);
            }
            Response::Envelopes(blobs) => {
                w.u8(RES_ENVELOPES);
                write_blob_list(&mut w, blobs);
            }
            Response::Prekeys(bundle) => {
                w.u8(RES_PREKEYS);
                match bundle {
                    Some(b) => {
                        w.bool(true).bytes(b);
                    }
                    None => {
                        w.bool(false);
                    }
                }
            }
            Response::Blob(blob) => {
                w.u8(RES_BLOB);
                match blob {
                    Some(b) => {
                        w.bool(true).bytes(b);
                    }
                    None => {
                        w.bool(false);
                    }
                }
            }
            Response::ChannelLog(entries) => {
                w.u8(RES_CHANNEL_LOG).u32(entries.len() as u32);
                for (seq, blob) in entries {
                    w.u64(*seq).bytes(blob);
                }
            }
            Response::Signals(blobs) => {
                w.u8(RES_SIGNALS);
                write_blob_list(&mut w, blobs);
            }
        }
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let tag = r.u8()?;
        let out = match tag {
            RES_PONG => Response::Pong,
            RES_OK => Response::Ok,
            RES_ERROR => Response::Error(r.string()?),
            RES_TREE_HEAD => Response::TreeHead {
                size: r.u64()?,
                root: r.fixed::<32>()?,
            },
            RES_RECORDS => Response::Records(read_blob_list(&mut r)?),
            RES_ENVELOPES => Response::Envelopes(read_blob_list(&mut r)?),
            RES_PREKEYS => Response::Prekeys(if r.bool()? {
                Some(r.bytes()?.to_vec())
            } else {
                None
            }),
            RES_BLOB => Response::Blob(if r.bool()? {
                Some(r.bytes()?.to_vec())
            } else {
                None
            }),
            RES_CHANNEL_LOG => {
                let n = r.u32()? as usize;
                if n > r.remaining() {
                    return Err(WireError::LengthTooLarge(n as u64));
                }
                let mut out = Vec::with_capacity(n);
                for _ in 0..n {
                    out.push((r.u64()?, r.bytes()?.to_vec()));
                }
                Response::ChannelLog(out)
            }
            RES_SIGNALS => Response::Signals(read_blob_list(&mut r)?),
            other => {
                return Err(WireError::BadDiscriminant {
                    ty: "Response",
                    value: other.into(),
                })
            }
        };
        r.finish()?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt_req(r: Request) {
        assert_eq!(Request::decode(&r.encode()).unwrap(), r);
    }
    fn rt_res(r: Response) {
        assert_eq!(Response::decode(&r.encode()).unwrap(), r);
    }

    #[test]
    fn requests_roundtrip() {
        rt_req(Request::Ping);
        rt_req(Request::SubmitRecord(vec![1, 2, 3]));
        rt_req(Request::GetTreeHead);
        rt_req(Request::GetRecords { from: 4, to: 9 });
        rt_req(Request::Deposit(vec![9; 40]));
        rt_req(Request::Fetch {
            hints: vec![[1u8; 8], [2u8; 8]],
            since_ms: 12345,
        });
        rt_req(Request::PublishPrekeys(vec![1, 2, 3]));
        rt_req(Request::GetPrekeys([7u8; 32]));
        rt_req(Request::PutBlob(vec![4, 5, 6, 7]));
        rt_req(Request::GetBlob([2u8; 32]));
        rt_req(Request::PostToChannel {
            channel_id: [3u8; 32],
            blob: vec![1, 2],
        });
        rt_req(Request::FetchChannel {
            channel_id: [4u8; 32],
            since_seq: 7,
        });
        rt_req(Request::PostSignal {
            topic: [5u8; 32],
            blob: vec![7, 7, 7],
        });
        rt_req(Request::FetchSignals { topic: [6u8; 32] });
    }

    #[test]
    fn responses_roundtrip() {
        rt_res(Response::Pong);
        rt_res(Response::Ok);
        rt_res(Response::Error("nope".into()));
        rt_res(Response::TreeHead {
            size: 7,
            root: [3u8; 32],
        });
        rt_res(Response::Records(vec![vec![1], vec![2, 2]]));
        rt_res(Response::Envelopes(vec![vec![]]));
        rt_res(Response::Prekeys(Some(vec![9, 9, 9])));
        rt_res(Response::Prekeys(None));
        rt_res(Response::Blob(Some(vec![1, 1])));
        rt_res(Response::Blob(None));
        rt_res(Response::ChannelLog(vec![(1, vec![9]), (2, vec![])]));
        rt_res(Response::Signals(vec![vec![1, 2], vec![]]));
    }

    #[test]
    fn unknown_tag_and_trailing_bytes_rejected() {
        assert!(Request::decode(&[99]).is_err());
        let mut b = Request::Ping.encode();
        b.push(0);
        assert!(Request::decode(&b).is_err());
    }
}
