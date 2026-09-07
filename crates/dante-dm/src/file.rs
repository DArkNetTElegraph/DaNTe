//! Chunked encrypted file transfer (`docs/PROTOCOL.md` §4.3).
//!
//! A file is split into [`CHUNK_SIZE`] pieces, each sealed with a single random
//! per-file XChaCha20-Poly1305 key under a deterministic per-chunk nonce. A
//! [`FileManifest`] — carried as a normal ratchet message ([`crate::Packet`]) —
//! holds the file key, the SHA-256 of every *ciphertext* chunk, and the
//! sender's signature over all of it. The ciphertext chunks themselves are put
//! in the relay's TTL'd blob store, addressed by their hash.

use dante_crypto::{
    aead,
    hash::{sha256, sha256_parts},
    random_array,
    sign::{SignPublic, SIG_LEN},
};
use dante_identity::Identity;
use dante_proto::enc::{Reader, WireError, Writer};

use crate::error::DmError;

/// Plaintext bytes per chunk.
pub const CHUNK_SIZE: usize = 64 * 1024;

const MANIFEST_SIG_DOMAIN: &[u8] = b"dante/file-manifest/v1";
const CHUNK_NONCE_DOMAIN: &[u8] = b"dante-file-chunk";

/// Describes an encrypted file. Sent over the ratchet; the ciphertext chunks
/// travel separately through the relay blob store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileManifest {
    /// Per-file XChaCha20-Poly1305 key. Secret — only the recipient learns it.
    pub file_key: [u8; 32],
    /// Original filename (display only; never used as a path).
    pub filename: String,
    /// Total plaintext size.
    pub total_size: u64,
    /// Plaintext chunk size (== [`CHUNK_SIZE`] except the design may evolve).
    pub chunk_size: u32,
    /// `SHA-256` of each ciphertext chunk, in order.
    pub chunk_hashes: Vec<[u8; 32]>,
    /// Sender's Ed25519 identity key.
    pub sender_idk: [u8; 32],
    /// `sender_idk` over [`FileManifest::sig_challenge`].
    pub sig: [u8; SIG_LEN],
}

impl FileManifest {
    /// The bytes the manifest signature covers.
    pub fn sig_challenge(
        file_key: &[u8; 32],
        filename: &str,
        total_size: u64,
        chunk_size: u32,
        chunk_hashes: &[[u8; 32]],
    ) -> [u8; 32] {
        let mut w = Writer::new();
        w.fixed(MANIFEST_SIG_DOMAIN)
            .fixed(file_key)
            .string(filename)
            .u64(total_size)
            .u32(chunk_size)
            .u32(chunk_hashes.len() as u32);
        for h in chunk_hashes {
            w.fixed(h);
        }
        sha256(&w.into_vec())
    }

    /// Deterministic 24-byte nonce for chunk `index` (unique because `file_key`
    /// is random per file).
    pub fn chunk_nonce(index: u32) -> [u8; 24] {
        let mut n = [0u8; 24];
        n[..CHUNK_NONCE_DOMAIN.len()].copy_from_slice(CHUNK_NONCE_DOMAIN);
        n[20..].copy_from_slice(&index.to_be_bytes());
        n
    }

    /// Encrypt `plaintext` for transfer. Returns the manifest and the ordered
    /// ciphertext chunks (each `chunk || tag`).
    pub fn build(sender: &Identity, filename: &str, plaintext: &[u8]) -> (Self, Vec<Vec<u8>>) {
        let file_key = random_array::<32>();
        let mut chunk_hashes = Vec::new();
        let mut chunks = Vec::new();
        for (i, part) in plaintext.chunks(CHUNK_SIZE).enumerate() {
            let ct = aead::xchacha_seal(&file_key, &Self::chunk_nonce(i as u32), part, &[]);
            chunk_hashes.push(sha256(&ct));
            chunks.push(ct);
        }
        let total_size = plaintext.len() as u64;
        let chunk_size = CHUNK_SIZE as u32;
        let sender_idk = sender.sign_public().to_bytes();
        let sig = sender.sign(&Self::sig_challenge(
            &file_key,
            filename,
            total_size,
            chunk_size,
            &chunk_hashes,
        ));
        (
            Self {
                file_key,
                filename: filename.to_owned(),
                total_size,
                chunk_size,
                chunk_hashes,
                sender_idk,
                sig,
            },
            chunks,
        )
    }

    /// Verify the manifest signature.
    pub fn verify(&self) -> Result<(), DmError> {
        SignPublic::from_bytes(&self.sender_idk)
            .map_err(|_| DmError::FileIntegrity)?
            .verify(
                &Self::sig_challenge(
                    &self.file_key,
                    &self.filename,
                    self.total_size,
                    self.chunk_size,
                    &self.chunk_hashes,
                ),
                &self.sig,
            )
            .map_err(|_| DmError::FileIntegrity)
    }

    /// The hashes the recipient must fetch from the blob store.
    pub fn blob_hashes(&self) -> &[[u8; 32]] {
        &self.chunk_hashes
    }

    /// Verify + decrypt + concatenate `ciphertext_chunks` (in manifest order)
    /// into the original file. Also re-checks the signature.
    pub fn reassemble(&self, ciphertext_chunks: &[Vec<u8>]) -> Result<Vec<u8>, DmError> {
        self.verify()?;
        if ciphertext_chunks.len() != self.chunk_hashes.len() {
            return Err(DmError::FileIntegrity);
        }
        let mut out = Vec::with_capacity(self.total_size as usize);
        for (i, ct) in ciphertext_chunks.iter().enumerate() {
            if sha256(ct) != self.chunk_hashes[i] {
                return Err(DmError::FileIntegrity);
            }
            let pt = aead::xchacha_open(&self.file_key, &Self::chunk_nonce(i as u32), ct, &[])
                .map_err(|_| DmError::FileIntegrity)?;
            out.extend_from_slice(&pt);
        }
        if out.len() as u64 != self.total_size {
            return Err(DmError::FileIntegrity);
        }
        Ok(out)
    }

    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.file_key)
            .string(&self.filename)
            .u64(self.total_size)
            .u32(self.chunk_size)
            .u32(self.chunk_hashes.len() as u32);
        for h in &self.chunk_hashes {
            w.fixed(h);
        }
        w.fixed(&self.sender_idk).fixed(&self.sig);
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let file_key = r.fixed::<32>()?;
        let filename = r.string()?;
        let total_size = r.u64()?;
        let chunk_size = r.u32()?;
        let n = r.u32()? as usize;
        if n > r.remaining() {
            return Err(WireError::LengthTooLarge(n as u64));
        }
        let mut chunk_hashes = Vec::with_capacity(n);
        for _ in 0..n {
            chunk_hashes.push(r.fixed::<32>()?);
        }
        let sender_idk = r.fixed::<32>()?;
        let sig = r.fixed::<SIG_LEN>()?;
        r.finish()?;
        Ok(Self {
            file_key,
            filename,
            total_size,
            chunk_size,
            chunk_hashes,
            sender_idk,
            sig,
        })
    }
}

/// The hash a chunk is stored under in the relay blob store.
pub fn blob_id(ciphertext_chunk: &[u8]) -> [u8; 32] {
    sha256_parts(&[ciphertext_chunk])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_then_reassemble_roundtrips() {
        let sender = Identity::generate(0);
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let (manifest, chunks) = FileManifest::build(&sender, "photo.jpg", &data);

        assert_eq!(chunks.len(), data.len().div_ceil(CHUNK_SIZE));
        manifest.verify().unwrap();
        assert_eq!(manifest.reassemble(&chunks).unwrap(), data);

        let back = FileManifest::decode(&manifest.encode()).unwrap();
        assert_eq!(back, manifest);
    }

    #[test]
    fn empty_and_tiny_files() {
        let s = Identity::generate(0);
        for data in [
            vec![],
            vec![7u8],
            vec![9u8; CHUNK_SIZE],
            vec![3u8; CHUNK_SIZE + 1],
        ] {
            let (m, c) = FileManifest::build(&s, "f", &data);
            assert_eq!(m.reassemble(&c).unwrap(), data);
        }
    }

    #[test]
    fn a_tampered_chunk_is_rejected() {
        let s = Identity::generate(0);
        let (m, mut c) = FileManifest::build(&s, "f", &[5u8; CHUNK_SIZE * 2 + 10]);
        c[1][0] ^= 1;
        assert!(matches!(m.reassemble(&c), Err(DmError::FileIntegrity)));
    }

    #[test]
    fn a_tampered_manifest_is_rejected() {
        let s = Identity::generate(0);
        let (mut m, c) = FileManifest::build(&s, "f", &[1u8; 100]);
        m.total_size += 1;
        assert!(m.verify().is_err());
        assert!(m.reassemble(&c).is_err());
    }

    #[test]
    fn wrong_number_of_chunks_is_rejected() {
        let s = Identity::generate(0);
        let (m, mut c) = FileManifest::build(&s, "f", &[1u8; CHUNK_SIZE * 2]);
        c.pop();
        assert!(matches!(m.reassemble(&c), Err(DmError::FileIntegrity)));
    }
}
