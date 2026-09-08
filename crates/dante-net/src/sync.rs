//! Client-side helpers for pulling ledger records and mailbox envelopes from a
//! relay.

use dante_proto::{record::Record, Envelope};

use crate::{
    error::NetError,
    transport::Client,
    wire::{IceCfg, Request, Response},
};

/// Pull records the relay has that we don't, starting from log position
/// `local_len`, and feed them to `apply`.
///
/// `apply(record, now_ms)` should run the ledger's acceptance rules and return
/// `true` if the record was accepted. Returns `(new_cursor, accepted)`, where
/// `new_cursor` is the relay-log position the caller should resume from next
/// time — advance a persisted cursor to it, don't derive one from the local
/// ledger length (records can also arrive out of band, e.g. over gossip).
pub async fn pull_records<F>(
    client: &mut Client,
    local_len: u64,
    now_ms: u64,
    batch: u64,
    mut apply: F,
) -> Result<(u64, u64), NetError>
where
    F: FnMut(Record, u64) -> bool,
{
    let size = match client.request(&Request::GetTreeHead).await? {
        Response::TreeHead { size, .. } => size,
        _ => return Err(NetError::UnexpectedResponse("GetTreeHead")),
    };
    if size <= local_len {
        return Ok((local_len, 0));
    }

    let mut accepted = 0u64;
    let mut from = local_len;
    while from < size {
        let to = (from + batch).min(size);
        let blobs = match client.request(&Request::GetRecords { from, to }).await? {
            Response::Records(b) => b,
            _ => return Err(NetError::UnexpectedResponse("GetRecords")),
        };
        if blobs.is_empty() {
            break;
        }
        for blob in blobs {
            if let Ok(rec) = Record::decode(&blob) {
                if apply(rec, now_ms) {
                    accepted += 1;
                }
            }
        }
        from = to;
    }
    Ok((from, accepted))
}

/// Submit one encoded record to the relay for ledger acceptance.
pub async fn submit_record(client: &mut Client, record: &Record) -> Result<(), NetError> {
    match client
        .request(&Request::SubmitRecord(record.encode()))
        .await?
    {
        Response::Ok => Ok(()),
        other => Err(NetError::Peer(format!("SubmitRecord: {other:?}"))),
    }
}

/// Deposit one sealed envelope at the relay.
pub async fn deposit(client: &mut Client, env: &Envelope) -> Result<(), NetError> {
    match client.request(&Request::Deposit(env.encode())).await? {
        Response::Ok => Ok(()),
        other => Err(NetError::Peer(format!("Deposit: {other:?}"))),
    }
}

/// Publish an encoded prekey bundle to the relay.
pub async fn publish_prekeys(client: &mut Client, bundle: &[u8]) -> Result<(), NetError> {
    match client
        .request(&Request::PublishPrekeys(bundle.to_vec()))
        .await?
    {
        Response::Ok => Ok(()),
        other => Err(NetError::Peer(format!("PublishPrekeys: {other:?}"))),
    }
}

/// Retrieve a peer's encoded prekey bundle from the relay, if it has one.
pub async fn get_prekeys(
    client: &mut Client,
    identity_id: &[u8; 32],
) -> Result<Option<Vec<u8>>, NetError> {
    match client.request(&Request::GetPrekeys(*identity_id)).await? {
        Response::Prekeys(b) => Ok(b),
        _ => Err(NetError::UnexpectedResponse("GetPrekeys")),
    }
}

/// Publish MLS `KeyPackage`s (opaque bytes) for `identity` so other members can
/// add it to channels / group calls. Each is single-use.
pub async fn publish_key_packages(
    client: &mut Client,
    identity: &[u8; 32],
    key_packages: Vec<Vec<u8>>,
) -> Result<(), NetError> {
    match client
        .request(&Request::PublishKeyPackages {
            identity: *identity,
            key_packages,
        })
        .await?
    {
        Response::Ok => Ok(()),
        other => Err(NetError::Peer(format!("PublishKeyPackages: {other:?}"))),
    }
}

/// Take one published MLS `KeyPackage` for `identity`, if the relay has one.
pub async fn get_key_package(
    client: &mut Client,
    identity: &[u8; 32],
) -> Result<Option<Vec<u8>>, NetError> {
    match client.request(&Request::GetKeyPackage(*identity)).await? {
        Response::KeyPackage(kp) => Ok(kp),
        _ => Err(NetError::UnexpectedResponse("GetKeyPackage")),
    }
}

/// Store a ciphertext blob (a file chunk) at the relay. Idempotent.
pub async fn put_blob(client: &mut Client, bytes: &[u8]) -> Result<(), NetError> {
    match client.request(&Request::PutBlob(bytes.to_vec())).await? {
        Response::Ok => Ok(()),
        other => Err(NetError::Peer(format!("PutBlob: {other:?}"))),
    }
}

/// Retrieve a blob by its `SHA-256`, if the relay still holds it.
pub async fn get_blob(client: &mut Client, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, NetError> {
    match client.request(&Request::GetBlob(*hash)).await? {
        Response::Blob(b) => Ok(b),
        _ => Err(NetError::UnexpectedResponse("GetBlob")),
    }
}

/// Append an encoded channel message to a channel's relay log. Returns the
/// relay-log `seq` the message was assigned.
pub async fn post_to_channel(
    client: &mut Client,
    channel_id: &[u8; 32],
    blob: &[u8],
) -> Result<u64, NetError> {
    match client
        .request(&Request::PostToChannel {
            channel_id: *channel_id,
            blob: blob.to_vec(),
        })
        .await?
    {
        Response::Posted(seq) => Ok(seq),
        // Tolerate an older relay that still answers `Ok`.
        Response::Ok => Ok(0),
        other => Err(NetError::Peer(format!("PostToChannel: {other:?}"))),
    }
}

/// Read a channel's log after `since_seq`. Returns `(seq, blob)` pairs.
pub async fn fetch_channel(
    client: &mut Client,
    channel_id: &[u8; 32],
    since_seq: u64,
) -> Result<Vec<(u64, Vec<u8>)>, NetError> {
    match client
        .request(&Request::FetchChannel {
            channel_id: *channel_id,
            since_seq,
        })
        .await?
    {
        Response::ChannelLog(entries) => Ok(entries),
        _ => Err(NetError::UnexpectedResponse("FetchChannel")),
    }
}

/// Post an ephemeral signal (e.g. a typing indicator) under `topic`. The relay
/// keeps it for only a few seconds and never persists it. Fire-and-forget.
pub async fn post_signal(
    client: &mut Client,
    topic: &[u8; 32],
    blob: &[u8],
) -> Result<(), NetError> {
    match client
        .request(&Request::PostSignal {
            topic: *topic,
            blob: blob.to_vec(),
        })
        .await?
    {
        Response::Ok => Ok(()),
        other => Err(NetError::Peer(format!("PostSignal: {other:?}"))),
    }
}

/// Drain the currently-buffered signals for `topic`, oldest first.
pub async fn fetch_signals(
    client: &mut Client,
    topic: &[u8; 32],
) -> Result<Vec<Vec<u8>>, NetError> {
    match client
        .request(&Request::FetchSignals { topic: *topic })
        .await?
    {
        Response::Signals(blobs) => Ok(blobs),
        _ => Err(NetError::UnexpectedResponse("FetchSignals")),
    }
}

/// Ask the relay which ICE servers (STUN, and short-lived TURN credentials) to
/// use for calls on this network.
pub async fn get_ice_config(client: &mut Client) -> Result<Vec<IceCfg>, NetError> {
    match client.request(&Request::GetIceConfig).await? {
        Response::IceConfig(list) => Ok(list),
        _ => Err(NetError::UnexpectedResponse("GetIceConfig")),
    }
}

/// Fetch and decode mailbox envelopes for `hints` since `since_ms`.
pub async fn fetch(
    client: &mut Client,
    hints: &[[u8; 8]],
    since_ms: u64,
) -> Result<Vec<Envelope>, NetError> {
    let blobs = match client
        .request(&Request::Fetch {
            hints: hints.to_vec(),
            since_ms,
        })
        .await?
    {
        Response::Envelopes(b) => b,
        _ => return Err(NetError::UnexpectedResponse("Fetch")),
    };
    // Tolerate a malformed envelope rather than failing the whole batch.
    Ok(blobs
        .iter()
        .filter_map(|b| Envelope::decode(b).ok())
        .collect())
}
