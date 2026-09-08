//! The encrypted on-disk keystore (`docs/PROTOCOL.md` §1.2).
//!
//! Layout: a CBOR [`KeystoreFile`] whose `ciphertext` is
//! `XChaCha20-Poly1305(key, nonce, CBOR(KeystoreInner), aad)` where `key =
//! Argon2id(passphrase, salt, params)` and `aad` binds the version, the KDF
//! parameters, and a container-context label so a keystore file cannot be
//! opened as a key backup or vice versa.

use dante_crypto::{
    aead::{self, XNONCE_LEN},
    pwhash::{self, Argon2idParams},
    random_array,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{error::IdentityError, identity::Identity};

/// Current keystore container version.
pub const VERSION: u16 = 1;

/// Container-context label for the primary keystore.
pub(crate) const CONTEXT_KEYSTORE: &[u8] = b"dante-keystore-v1";
/// Container-context label for the recovery key backup.
pub(crate) const CONTEXT_BACKUP: &[u8] = b"dante-key-backup-v1";

const SALT_LEN: usize = 16;

/// Ceiling on the Argon2 memory cost accepted from a keystore/backup file's
/// header (2 GiB). Well above the honest [`pwhash::KEYSTORE`] 256 MiB, but
/// bounds the allocation a hostile file can force on the importer.
const MAX_KEYSTORE_M_COST_KIB: u32 = 2 * 1024 * 1024;
/// Ceiling on the Argon2 time cost accepted from a file header.
const MAX_KEYSTORE_T_COST: u32 = 16;

/// Serialized KDF description stored in the clear.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfDesc {
    /// Always `"argon2id"` for version 1.
    pub alg: String,
    /// Argon2 memory cost, KiB.
    pub m_cost_kib: u32,
    /// Argon2 time cost (passes).
    pub t_cost: u32,
    /// Argon2 parallelism (lanes).
    pub p: u32,
    /// Random salt.
    pub salt: [u8; SALT_LEN],
}

/// The on-disk keystore, as serialized to CBOR.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeystoreFile {
    /// Container version.
    pub version: u16,
    /// KDF used to derive the wrapping key.
    pub kdf: KdfDesc,
    /// XChaCha20-Poly1305 nonce.
    pub nonce: [u8; XNONCE_LEN],
    /// `ciphertext || tag` of the CBOR-encoded [`KeystoreInner`].
    pub ciphertext: Vec<u8>,
}

/// The secret payload. Never leaves this module unencrypted.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct KeystoreInner {
    idk_secret: [u8; 32],
    ik_secret: [u8; 32],
    ratchet_db_key: [u8; 32],
    created_ms: u64,
}

fn aad(context: &[u8], version: u16, kdf: &KdfDesc) -> Vec<u8> {
    let mut a = Vec::with_capacity(context.len() + 2 + kdf.alg.len() + 12 + SALT_LEN);
    a.extend_from_slice(context);
    a.extend_from_slice(&version.to_be_bytes());
    a.extend_from_slice(kdf.alg.as_bytes());
    a.extend_from_slice(&kdf.m_cost_kib.to_be_bytes());
    a.extend_from_slice(&kdf.t_cost.to_be_bytes());
    a.extend_from_slice(&kdf.p.to_be_bytes());
    a.extend_from_slice(&kdf.salt);
    a
}

fn cbor_to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, IdentityError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|_| IdentityError::Encoding)?;
    Ok(buf)
}

fn cbor_from_slice<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, IdentityError> {
    ciborium::from_reader(bytes).map_err(|_| IdentityError::Encoding)
}

pub(crate) fn seal_with_context(
    identity: &Identity,
    passphrase: &[u8],
    params: Argon2idParams,
    context: &[u8],
) -> Result<Vec<u8>, IdentityError> {
    let kdf = KdfDesc {
        alg: "argon2id".to_string(),
        m_cost_kib: params.m_cost_kib,
        t_cost: params.t_cost,
        p: params.p_cost,
        salt: random_array::<SALT_LEN>(),
    };

    let mut wrapping_key = [0u8; 32];
    pwhash::argon2id(passphrase, &kdf.salt, params, &mut wrapping_key)?;

    let mut inner = KeystoreInner {
        idk_secret: identity.idk_secret(),
        ik_secret: identity.ik_secret(),
        ratchet_db_key: *identity.ratchet_db_key(),
        created_ms: identity.created_ms(),
    };
    // The serialized secrets must be wiped too, not just the struct — a bare
    // Vec would otherwise linger in freed heap (core dumps, swap).
    let plaintext = Zeroizing::new(cbor_to_vec(&inner)?);
    inner.zeroize();

    let nonce = random_array::<XNONCE_LEN>();
    let ciphertext = aead::xchacha_seal(
        &wrapping_key,
        &nonce,
        &plaintext,
        &aad(context, VERSION, &kdf),
    );
    wrapping_key.zeroize();

    let file = KeystoreFile {
        version: VERSION,
        kdf,
        nonce,
        ciphertext,
    };
    cbor_to_vec(&file)
}

pub(crate) fn open_with_context(
    bytes: &[u8],
    passphrase: &[u8],
    context: &[u8],
) -> Result<Identity, IdentityError> {
    let file: KeystoreFile = cbor_from_slice(bytes)?;
    if file.version != VERSION {
        return Err(IdentityError::KeystoreVersion(file.version));
    }
    if file.kdf.alg != "argon2id" {
        return Err(IdentityError::KeystoreOpen);
    }

    // These cost parameters come from the file, which may be hostile (a pasted
    // "recovery blob"). Reject absurd values before handing them to Argon2, or a
    // crafted header could OOM or wedge the importer. The ceilings sit well
    // above the honest KEYSTORE params (256 MiB / 3 passes).
    if file.kdf.m_cost_kib > MAX_KEYSTORE_M_COST_KIB || file.kdf.t_cost > MAX_KEYSTORE_T_COST {
        return Err(IdentityError::KeystoreOpen);
    }
    let params = Argon2idParams {
        m_cost_kib: file.kdf.m_cost_kib,
        t_cost: file.kdf.t_cost,
        p_cost: file.kdf.p,
    };
    let mut wrapping_key = [0u8; 32];
    pwhash::argon2id(passphrase, &file.kdf.salt, params, &mut wrapping_key)?;

    let plaintext = aead::xchacha_open(
        &wrapping_key,
        &file.nonce,
        &file.ciphertext,
        &aad(context, file.version, &file.kdf),
    )
    .map_err(|_| IdentityError::KeystoreOpen);
    wrapping_key.zeroize();
    // Decrypted secrets: wipe the buffer once we've parsed it out.
    let plaintext = Zeroizing::new(plaintext?);

    let inner: KeystoreInner = cbor_from_slice(&plaintext)?;
    Ok(Identity::from_parts(
        &inner.idk_secret,
        &inner.ik_secret,
        inner.ratchet_db_key,
        inner.created_ms,
    ))
}

/// Encrypt `identity` under `passphrase` into a keystore file, using
/// [`pwhash::KEYSTORE`] cost parameters. Returns the CBOR bytes to write to
/// disk.
pub fn seal(identity: &Identity, passphrase: &[u8]) -> Result<Vec<u8>, IdentityError> {
    seal_with_context(identity, passphrase, pwhash::KEYSTORE, CONTEXT_KEYSTORE)
}

/// As [`seal`] but with caller-chosen Argon2id cost (e.g. lower in tests).
pub fn seal_with_params(
    identity: &Identity,
    passphrase: &[u8],
    params: Argon2idParams,
) -> Result<Vec<u8>, IdentityError> {
    seal_with_context(identity, passphrase, params, CONTEXT_KEYSTORE)
}

/// Decrypt a keystore file produced by [`seal`].
pub fn open(bytes: &[u8], passphrase: &[u8]) -> Result<Identity, IdentityError> {
    open_with_context(bytes, passphrase, CONTEXT_KEYSTORE)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: Argon2idParams = Argon2idParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn seal_then_open_roundtrips() {
        let id = Identity::generate(1_700_000_000_123);
        let file = seal_with_params(&id, b"correct horse battery staple", FAST).unwrap();
        let back = open(&file, b"correct horse battery staple").unwrap();
        assert_eq!(id.id(), back.id());
        assert_eq!(id.agree_public(), back.agree_public());
        assert_eq!(id.ratchet_db_key(), back.ratchet_db_key());
        assert_eq!(id.created_ms(), back.created_ms());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let id = Identity::generate(0);
        let file = seal_with_params(&id, b"open sesame", FAST).unwrap();
        assert!(matches!(
            open(&file, b"open sasame"),
            Err(IdentityError::KeystoreOpen)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let id = Identity::generate(0);
        let mut file: KeystoreFile =
            cbor_from_slice(&seal_with_params(&id, b"pw", FAST).unwrap()).unwrap();
        let n = file.ciphertext.len() / 2;
        file.ciphertext[n] ^= 0x40;
        let bytes = cbor_to_vec(&file).unwrap();
        assert!(open(&bytes, b"pw").is_err());
    }

    #[test]
    fn keystore_cannot_be_opened_as_backup_context() {
        let id = Identity::generate(0);
        let file = seal_with_params(&id, b"pw", FAST).unwrap();
        // Same bytes, wrong container context -> AAD mismatch -> failure.
        assert!(open_with_context(&file, b"pw", CONTEXT_BACKUP).is_err());
    }

    #[test]
    fn a_hostile_kdf_header_is_refused_before_hashing() {
        // A crafted file demanding an enormous Argon2 cost must be rejected up
        // front rather than driving the importer into an OOM or a multi-year
        // hash. This returns fast because argon2id is never called.
        let id = Identity::generate(0);
        let mut file: KeystoreFile =
            cbor_from_slice(&seal_with_params(&id, b"pw", FAST).unwrap()).unwrap();
        file.kdf.m_cost_kib = u32::MAX;
        let bytes = cbor_to_vec(&file).unwrap();
        assert!(matches!(
            open(&bytes, b"pw"),
            Err(IdentityError::KeystoreOpen)
        ));
    }

    #[test]
    fn each_seal_uses_fresh_salt_and_nonce() {
        let id = Identity::generate(0);
        let a: KeystoreFile =
            cbor_from_slice(&seal_with_params(&id, b"pw", FAST).unwrap()).unwrap();
        let b: KeystoreFile =
            cbor_from_slice(&seal_with_params(&id, b"pw", FAST).unwrap()).unwrap();
        assert_ne!(a.kdf.salt, b.kdf.salt);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }
}
