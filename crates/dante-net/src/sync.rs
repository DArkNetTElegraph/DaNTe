//! Client-side helpers for pulling ledger records and mailbox envelopes from a
//! relay.

use dante_proto::{record::Record, Envelope};

use crate::{
    error::NetError,
    transport::Client,
    wire::{Request, Response},
};

/// Pull records the relay has that we don't, and feed them to `apply`.
///
/// `apply(record, now_ms)` should run the ledger's acceptance rules and return
/// `true` if the record was accepted. Returns `(fetched, accepted)`.
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
        return Ok((0, 0));
    }

    let (mut fetched, mut accepted) = (0u64, 0u64);
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
            fetched += 1;
            if let Ok(rec) = Record::decode(&blob) {
                if apply(rec, now_ms) {
                    accepted += 1;
                }
            }
        }
        from = to;
    }
    Ok((fetched, accepted))
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
