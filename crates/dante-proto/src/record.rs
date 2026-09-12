//! The ledger [`Record`] envelope (`docs/PROTOCOL.md` §2.1).
//!
//! A record is a signed, kind-tagged container. The envelope is
//! **body-agnostic**: `body` is opaque bytes and `kind` tells a consumer how to
//! parse them (identity, server registry, tombstone, …). Signature and id are
//! defined over the [canonical encoding](crate::enc).

use dante_crypto::{
    hash::sha256,
    sign::{SignPublic, SignSecret, SIG_LEN},
    CryptoError,
};

use crate::enc::{Reader, WireError, Writer};

/// Envelope schema version.
pub const RECORD_VERSION: u16 = 1;

/// Maximum accepted future clock skew for `created_ms` (`docs/PROTOCOL.md` §0).
pub const CLOCK_SKEW_MS: u64 = 300_000;

/// Content-addressed record id: `SHA-256(Record::encode())`.
pub type RecordId = [u8; 32];

/// The kind of a record's body.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordKind {
    /// First announcement of an identity (`dante-identity`).
    IdentityAnnounce,
    /// Periodic proof an identity is still active.
    LivenessProof,
    /// Rotation to a new identity/agreement key, chained from the old.
    KeyRotation,
    /// Public server-directory entry.
    ServerRegister,
    /// Removal of a prior `ServerRegister`.
    ServerDelist,
    /// Tombstone written when an identity evaporates.
    Tombstone,
    /// Explicit, permanent revocation of an identity by its own key.
    IdentityRevoke,
    /// Mutable public identity state owned by the live chain tip (currently
    /// the global avatar blob hash).
    IdentityProfile,
}

impl RecordKind {
    /// Wire discriminant.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::IdentityAnnounce => 1,
            Self::LivenessProof => 2,
            Self::KeyRotation => 3,
            Self::ServerRegister => 4,
            Self::ServerDelist => 5,
            Self::Tombstone => 6,
            Self::IdentityRevoke => 7,
            Self::IdentityProfile => 8,
        }
    }

    /// Parse a wire discriminant.
    pub fn from_u8(v: u8) -> Result<Self, WireError> {
        Ok(match v {
            1 => Self::IdentityAnnounce,
            2 => Self::LivenessProof,
            3 => Self::KeyRotation,
            4 => Self::ServerRegister,
            5 => Self::ServerDelist,
            6 => Self::Tombstone,
            7 => Self::IdentityRevoke,
            8 => Self::IdentityProfile,
            other => {
                return Err(WireError::BadDiscriminant {
                    ty: "RecordKind",
                    value: u64::from(other),
                })
            }
        })
    }
}

/// A signed ledger record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Record {
    /// Schema version; must be [`RECORD_VERSION`].
    pub v: u16,
    /// Body kind.
    pub kind: RecordKind,
    /// Opaque, kind-specific body bytes.
    pub body: Vec<u8>,
    /// Ed25519 public key of the signer.
    pub author: [u8; 32],
    /// Creation time, Unix milliseconds.
    pub created_ms: u64,
    /// Ed25519 signature by `author` over [`Record::signing_bytes`].
    pub sig: [u8; SIG_LEN],
}

impl Record {
    fn write_prefix(&self, w: &mut Writer) {
        w.u16(self.v)
            .u8(self.kind.as_u8())
            .bytes(&self.body)
            .fixed(&self.author)
            .u64(self.created_ms);
    }

    /// The bytes `sig` is computed over: the whole record except `sig`.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(15 + self.body.len() + 32);
        self.write_prefix(&mut w);
        w.into_vec()
    }

    /// The full canonical encoding, including `sig`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(15 + self.body.len() + 32 + SIG_LEN);
        self.write_prefix(&mut w);
        w.fixed(&self.sig);
        w.into_vec()
    }

    /// Decode a record. Does **not** verify the signature or `v`; call
    /// [`Record::verify_signature`] and check [`Record::v`].
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let v = r.u16()?;
        let kind = RecordKind::from_u8(r.u8()?)?;
        let body = r.bytes()?.to_vec();
        let author = r.fixed::<32>()?;
        let created_ms = r.u64()?;
        let sig = r.fixed::<SIG_LEN>()?;
        r.finish()?;
        Ok(Self {
            v,
            kind,
            body,
            author,
            created_ms,
            sig,
        })
    }

    /// `SHA-256` of the full encoding.
    pub fn id(&self) -> RecordId {
        sha256(&self.encode())
    }

    /// Build and sign a record with `author_sk` at `created_ms`.
    pub fn seal(kind: RecordKind, body: Vec<u8>, author_sk: &SignSecret, created_ms: u64) -> Self {
        Self::seal_with(kind, body, author_sk.public().to_bytes(), created_ms, |m| {
            author_sk.sign(m)
        })
    }

    /// Build and sign a record without handing this crate a secret key: the
    /// caller provides the `author` public key and a closure that produces an
    /// Ed25519 signature over the given bytes. Lets a higher layer keep its
    /// signing key encapsulated (e.g. `dante_identity::Identity`).
    pub fn seal_with<F>(
        kind: RecordKind,
        body: Vec<u8>,
        author: [u8; 32],
        created_ms: u64,
        sign: F,
    ) -> Self
    where
        F: FnOnce(&[u8]) -> [u8; SIG_LEN],
    {
        let mut rec = Self {
            v: RECORD_VERSION,
            kind,
            body,
            author,
            created_ms,
            sig: [0u8; SIG_LEN],
        };
        rec.sig = sign(&rec.signing_bytes());
        rec
    }

    /// Verify the envelope signature against `author`. Kind-specific body
    /// validation and clock-skew checks are the ledger layer's job.
    pub fn verify_signature(&self) -> Result<(), CryptoError> {
        let pk = SignPublic::from_bytes(&self.author)?;
        pk.verify(&self.signing_bytes(), &self.sig)
    }
}

#[cfg(test)]
mod tests {
    use dante_crypto::sign::SignSecret;

    use super::*;

    #[test]
    fn kind_discriminants_roundtrip() {
        for k in [
            RecordKind::IdentityAnnounce,
            RecordKind::LivenessProof,
            RecordKind::KeyRotation,
            RecordKind::ServerRegister,
            RecordKind::ServerDelist,
            RecordKind::Tombstone,
            RecordKind::IdentityRevoke,
            RecordKind::IdentityProfile,
        ] {
            assert_eq!(RecordKind::from_u8(k.as_u8()).unwrap(), k);
        }
        assert!(RecordKind::from_u8(0).is_err());
        assert!(RecordKind::from_u8(9).is_err());
    }

    #[test]
    fn seal_encode_decode_roundtrip() {
        let sk = SignSecret::generate();
        let rec = Record::seal(
            RecordKind::LivenessProof,
            vec![1, 2, 3, 4],
            &sk,
            1_700_000_000_000,
        );
        let bytes = rec.encode();
        let back = Record::decode(&bytes).unwrap();
        assert_eq!(rec, back);
        assert_eq!(back.v, RECORD_VERSION);
        back.verify_signature().unwrap();
    }

    #[test]
    fn signature_covers_every_field_but_sig() {
        let sk = SignSecret::generate();
        let base = Record::seal(RecordKind::ServerDelist, vec![9; 32], &sk, 42);

        for mutate in [
            (|r: &mut Record| r.v ^= 1) as fn(&mut Record),
            |r: &mut Record| r.kind = RecordKind::ServerRegister,
            |r: &mut Record| r.body[0] ^= 1,
            |r: &mut Record| r.author[0] ^= 1,
            |r: &mut Record| r.created_ms ^= 1,
        ] {
            let mut bad = base.clone();
            mutate(&mut bad);
            assert!(
                bad.verify_signature().is_err(),
                "mutation slipped past the signature"
            );
        }
    }

    #[test]
    fn id_is_deterministic_and_encoding_sensitive() {
        let sk = SignSecret::generate();
        let a = Record::seal(RecordKind::IdentityAnnounce, vec![0xAA], &sk, 1);
        let b = Record::seal(RecordKind::IdentityAnnounce, vec![0xAA], &sk, 1);
        assert_eq!(a.id(), b.id());

        let c = Record::seal(RecordKind::IdentityAnnounce, vec![0xAB], &sk, 1);
        assert_ne!(a.id(), c.id());
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let sk = SignSecret::generate();
        let mut bytes = Record::seal(RecordKind::Tombstone, vec![], &sk, 0).encode();
        bytes.push(0);
        assert_eq!(Record::decode(&bytes), Err(WireError::Trailing(1)));
    }

    #[test]
    fn wrong_author_fails_verification() {
        let sk = SignSecret::generate();
        let mut rec = Record::seal(RecordKind::LivenessProof, vec![1], &sk, 0);
        rec.author = SignSecret::generate().public().to_bytes();
        assert!(rec.verify_signature().is_err());
    }
}
