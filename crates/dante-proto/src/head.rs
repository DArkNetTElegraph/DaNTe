//! [`SignedTreeHead`] — a signer's attestation of "the ledger has this many
//! records and this Merkle root" (`docs/PROTOCOL.md` §2.4).
//!
//! Nodes gossip these; a recipient asks the signer for a
//! [`crate::merkle::consistency_proof`] between two heads and distrusts a signer
//! that cannot produce one (equivocation / split view).

use dante_crypto::{
    sign::{SignPublic, SignSecret, SIG_LEN},
    CryptoError,
};

use crate::{
    enc::{Reader, WireError, Writer},
    merkle::Hash,
};

/// Version tag for the tree-head signing domain.
pub const TREE_HEAD_VERSION: u16 = 1;

const SIGNING_DOMAIN: &[u8] = b"dante/tree-head/v1";

/// An unsigned tree head.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TreeHead {
    /// Number of records in the tree.
    pub size: u64,
    /// Merkle Tree Hash over those records' ids.
    pub root: Hash,
}

impl TreeHead {
    /// Bytes signed by a [`SignedTreeHead`]: `domain || version || size || root`.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(SIGNING_DOMAIN.len() + 2 + 8 + 32);
        w.fixed(SIGNING_DOMAIN)
            .u16(TREE_HEAD_VERSION)
            .u64(self.size)
            .fixed(&self.root);
        w.into_vec()
    }
}

/// A tree head with the signer's key and signature.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SignedTreeHead {
    /// The attested head.
    pub head: TreeHead,
    /// Ed25519 public key of the signer (a relay or peer).
    pub signer: [u8; 32],
    /// Signature over [`TreeHead::signing_bytes`].
    pub sig: [u8; SIG_LEN],
}

impl SignedTreeHead {
    /// Sign `head` with `signer_sk`.
    pub fn seal(head: TreeHead, signer_sk: &SignSecret) -> Self {
        Self {
            head,
            signer: signer_sk.public().to_bytes(),
            sig: signer_sk.sign(&head.signing_bytes()),
        }
    }

    /// Verify the signature.
    pub fn verify(&self) -> Result<(), CryptoError> {
        SignPublic::from_bytes(&self.signer)?.verify(&self.head.signing_bytes(), &self.sig)
    }

    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(8 + 32 + 32 + SIG_LEN);
        w.u64(self.head.size)
            .fixed(&self.head.root)
            .fixed(&self.signer)
            .fixed(&self.sig);
        w.into_vec()
    }

    /// Decode; does not verify the signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let size = r.u64()?;
        let root = r.fixed::<32>()?;
        let signer = r.fixed::<32>()?;
        let sig = r.fixed::<SIG_LEN>()?;
        r.finish()?;
        Ok(Self {
            head: TreeHead { size, root },
            signer,
            sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use dante_crypto::sign::SignSecret;

    use super::*;

    #[test]
    fn seal_verify_encode_roundtrip() {
        let sk = SignSecret::generate();
        let head = TreeHead {
            size: 12345,
            root: [7u8; 32],
        };
        let sth = SignedTreeHead::seal(head, &sk);
        sth.verify().unwrap();
        let back = SignedTreeHead::decode(&sth.encode()).unwrap();
        assert_eq!(sth, back);
        back.verify().unwrap();
    }

    #[test]
    fn tamper_is_detected() {
        let sk = SignSecret::generate();
        let sth = SignedTreeHead::seal(
            TreeHead {
                size: 1,
                root: [0u8; 32],
            },
            &sk,
        );

        let mut bad_size = sth;
        bad_size.head.size = 2;
        assert!(bad_size.verify().is_err());

        let mut bad_root = sth;
        bad_root.head.root[0] ^= 1;
        assert!(bad_root.verify().is_err());
    }
}
