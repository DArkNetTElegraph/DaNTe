//! Server-directory record bodies (`docs/PROTOCOL.md` §2.2 kinds 4 & 5).
//!
//! [`ServerRegister`] is the public entry for the discovery page;
//! [`ServerDelist`] removes it. Both are signed by the server's root key
//! (`record.author == server_root`). Name / summary / tags are non-unique,
//! untrusted display text.

use dante_crypto::hash::sha256;
use dante_proto::{
    enc::{Reader, WireError, Writer},
    record::{Record, RecordKind},
};

use crate::error::LedgerError;

/// A server's stable id: `SHA-256(server_root_pubkey)`.
pub type ServerId = [u8; 32];

/// Max lengths for the free-text fields.
pub const NAME_MAX: usize = 64;
/// Max summary length in bytes.
pub const SUMMARY_MAX: usize = 280;
/// Max number of tags.
pub const TAGS_MAX: usize = 8;
/// Max length of one tag in bytes.
pub const TAG_LEN_MAX: usize = 32;
/// Max number of entry-relay addresses.
pub const RELAYS_MAX: usize = 8;
/// Max length of one relay address in bytes.
pub const RELAY_LEN_MAX: usize = 256;

/// `SHA-256` of a server root public key.
pub fn server_id(server_root: &[u8; 32]) -> ServerId {
    sha256(server_root)
}

/// Body of a `kind = 4` record: public server-directory entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerRegister {
    /// Ed25519 root key of the server (also `record.author`).
    pub server_root: [u8; 32],
    /// Display name (non-unique, ≤ [`NAME_MAX`] bytes).
    pub name: String,
    /// Short description (≤ [`SUMMARY_MAX`] bytes).
    pub summary: String,
    /// Discovery tags (≤ [`TAGS_MAX`], each ≤ [`TAG_LEN_MAX`] bytes).
    pub tags: Vec<String>,
    /// libp2p multiaddrs to reach the server's entry relays
    /// (≤ [`RELAYS_MAX`], each ≤ [`RELAY_LEN_MAX`] bytes).
    pub entry_relays: Vec<String>,
    /// If false, the server is registered but omitted from the discovery page.
    pub discoverable: bool,
    /// A `dante-invite:` link a discovering client can redeem to join. Empty
    /// for a server that only admits people by direct invite.
    pub invite: String,
}

impl ServerRegister {
    /// This server's [`ServerId`].
    pub fn id(&self) -> ServerId {
        server_id(&self.server_root)
    }

    /// Enforce the field-length limits.
    pub fn validate(&self) -> Result<(), LedgerError> {
        let ok = self.name.len() <= NAME_MAX
            && self.summary.len() <= SUMMARY_MAX
            && self.tags.len() <= TAGS_MAX
            && self.tags.iter().all(|t| t.len() <= TAG_LEN_MAX)
            && self.entry_relays.len() <= RELAYS_MAX
            && self.entry_relays.iter().all(|r| r.len() <= RELAY_LEN_MAX)
            && self.invite.len() <= 2048;
        if ok {
            Ok(())
        } else {
            Err(LedgerError::FieldTooLong)
        }
    }

    /// Encode the body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.server_root)
            .string(&self.name)
            .string(&self.summary);
        w.u32(self.tags.len() as u32);
        for t in &self.tags {
            w.string(t);
        }
        w.u32(self.entry_relays.len() as u32);
        for r in &self.entry_relays {
            w.string(r);
        }
        w.bool(self.discoverable);
        // Trailing optional: absent in records written before invite links.
        if !self.invite.is_empty() {
            w.string(&self.invite);
        }
        w.into_vec()
    }

    /// Decode the body (structural only; call [`ServerRegister::validate`]).
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let server_root = r.fixed::<32>()?;
        let name = r.string()?;
        let summary = r.string()?;
        let tags = read_string_list(&mut r)?;
        let entry_relays = read_string_list(&mut r)?;
        let discoverable = r.bool()?;
        let invite = if r.remaining() > 0 {
            r.string()?
        } else {
            String::new()
        };
        r.finish()?;
        Ok(Self {
            server_root,
            name,
            summary,
            tags,
            entry_relays,
            discoverable,
            invite,
        })
    }

    /// Wrap in a record signed by the server root key.
    pub fn to_record<F>(&self, created_ms: u64, sign: F) -> Record
    where
        F: FnOnce(&[u8]) -> [u8; 64],
    {
        Record::seal_with(
            RecordKind::ServerRegister,
            self.encode(),
            self.server_root,
            created_ms,
            sign,
        )
    }
}

/// Body of a `kind = 5` record: removal of a prior [`ServerRegister`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerDelist {
    /// The server root key whose registration is withdrawn.
    pub server_root: [u8; 32],
}

impl ServerDelist {
    /// Encode the body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(32);
        w.fixed(&self.server_root);
        w.into_vec()
    }

    /// Decode the body.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let server_root = r.fixed::<32>()?;
        r.finish()?;
        Ok(Self { server_root })
    }

    /// Wrap in a record signed by the server root key.
    pub fn to_record<F>(&self, created_ms: u64, sign: F) -> Record
    where
        F: FnOnce(&[u8]) -> [u8; 64],
    {
        Record::seal_with(
            RecordKind::ServerDelist,
            self.encode(),
            self.server_root,
            created_ms,
            sign,
        )
    }
}

fn read_string_list(r: &mut Reader<'_>) -> Result<Vec<String>, WireError> {
    let count = r.u32()? as usize;
    // Bound the count by remaining input so a bogus length can't pre-allocate.
    if count > r.remaining() {
        return Err(WireError::LengthTooLarge(count as u64));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(r.string()?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ServerRegister {
        ServerRegister {
            server_root: [3u8; 32],
            name: "The Cartographers".into(),
            summary: "maps, mostly".into(),
            tags: vec!["maps".into(), "geo".into()],
            entry_relays: vec!["/dns4/relay.example/tcp/4001".into()],
            discoverable: true,
            invite: String::new(),
        }
    }

    #[test]
    fn register_roundtrip() {
        let s = sample();
        assert_eq!(ServerRegister::decode(&s.encode()).unwrap(), s);
        s.validate().unwrap();
    }

    #[test]
    fn delist_roundtrip() {
        let d = ServerDelist {
            server_root: [9u8; 32],
        };
        assert_eq!(ServerDelist::decode(&d.encode()).unwrap(), d);
    }

    #[test]
    fn validate_rejects_overlong_fields() {
        let mut s = sample();
        s.name = "x".repeat(NAME_MAX + 1);
        assert!(s.validate().is_err());

        let mut s = sample();
        s.tags = vec!["t".into(); TAGS_MAX + 1];
        assert!(s.validate().is_err());
    }

    #[test]
    fn decode_rejects_trailing_and_truncation() {
        let mut bytes = sample().encode();
        bytes.push(0);
        assert!(ServerRegister::decode(&bytes).is_err());
        assert!(ServerRegister::decode(&[0u8; 4]).is_err());
    }
}
