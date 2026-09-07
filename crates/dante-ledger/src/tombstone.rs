//! [`Tombstone`] — a `kind = 6` record written by [`crate::Ledger::evaporate`]
//! when an identity's newest activity is older than the TTL (`docs/PROTOCOL.md`
//! §2.3).
//!
//! Tombstones are **not** user-signed: they are produced deterministically by
//! every node's own GC from the same log and the same `now_ms`, so honest
//! replicas converge. Their `author` and `sig` are all-zero, and
//! [`crate::Ledger::append`] refuses to accept one from outside.

use dante_proto::{
    enc::{Reader, WireError, Writer},
    record::{Record, RecordKind, RECORD_VERSION},
};

/// The all-zero author of a node-generated record.
pub const NULL_AUTHOR: [u8; 32] = [0u8; 32];

/// Body of a `kind = 6` record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tombstone {
    /// The chain-root `idk` of the evaporated identity.
    pub subject: [u8; 32],
    /// The `now_ms` at which GC produced this tombstone.
    pub evaporated_ms: u64,
}

impl Tombstone {
    /// Encode the body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(40);
        w.fixed(&self.subject).u64(self.evaporated_ms);
        w.into_vec()
    }

    /// Decode the body.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let subject = r.fixed::<32>()?;
        let evaporated_ms = r.u64()?;
        r.finish()?;
        Ok(Self {
            subject,
            evaporated_ms,
        })
    }

    /// The unsigned record that carries this tombstone.
    pub fn to_record(&self) -> Record {
        Record {
            v: RECORD_VERSION,
            kind: RecordKind::Tombstone,
            body: self.encode(),
            author: NULL_AUTHOR,
            created_ms: self.evaporated_ms,
            sig: [0u8; 64],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_body_and_record() {
        let t = Tombstone {
            subject: [7u8; 32],
            evaporated_ms: 1_800_000_000_000,
        };
        assert_eq!(Tombstone::decode(&t.encode()).unwrap(), t);

        let rec = t.to_record();
        assert_eq!(rec.kind, RecordKind::Tombstone);
        assert_eq!(rec.author, NULL_AUTHOR);
        assert_eq!(rec.created_ms, t.evaporated_ms);
        let back = Record::decode(&rec.encode()).unwrap();
        assert_eq!(back, rec);
        assert_eq!(Tombstone::decode(&back.body).unwrap(), t);
    }
}
