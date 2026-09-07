//! Encrypted key backup for recovery (`docs/PROTOCOL.md` §1.3).
//!
//! Same container as [`crate::keystore`] but sealed under a user-supplied
//! **recovery passphrase** with an independent salt and a distinct container
//! context, so the exported blob can be stored separately and cannot be
//! confused with the primary keystore. Losing both the keystore and this backup
//! (with its passphrase) means the identity is unrecoverable — by design, there
//! is no operator to reset it.

use dante_crypto::pwhash::{self, Argon2idParams};

use crate::{
    error::IdentityError,
    identity::Identity,
    keystore::{open_with_context, seal_with_context, CONTEXT_BACKUP},
};

/// Export `identity` as a recovery blob encrypted under `recovery_passphrase`,
/// using [`pwhash::KEYSTORE`] cost parameters.
pub fn export(identity: &Identity, recovery_passphrase: &[u8]) -> Result<Vec<u8>, IdentityError> {
    seal_with_context(
        identity,
        recovery_passphrase,
        pwhash::KEYSTORE,
        CONTEXT_BACKUP,
    )
}

/// As [`export`] but with caller-chosen Argon2id cost.
pub fn export_with_params(
    identity: &Identity,
    recovery_passphrase: &[u8],
    params: Argon2idParams,
) -> Result<Vec<u8>, IdentityError> {
    seal_with_context(identity, recovery_passphrase, params, CONTEXT_BACKUP)
}

/// Restore an identity from a blob produced by [`export`].
pub fn import(bytes: &[u8], recovery_passphrase: &[u8]) -> Result<Identity, IdentityError> {
    open_with_context(bytes, recovery_passphrase, CONTEXT_BACKUP)
}

#[cfg(test)]
mod tests {
    use dante_crypto::pwhash::Argon2idParams;

    use super::*;
    use crate::keystore;

    const FAST: Argon2idParams = Argon2idParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn export_then_import_roundtrips() {
        let id = Identity::generate(1_700_000_000_999);
        let blob = export_with_params(&id, b"twelve random words here", FAST).unwrap();
        let back = import(&blob, b"twelve random words here").unwrap();
        assert_eq!(id.id(), back.id());
        assert_eq!(id.ratchet_db_key(), back.ratchet_db_key());
        assert_eq!(id.created_ms(), back.created_ms());
    }

    #[test]
    fn wrong_recovery_passphrase_fails() {
        let id = Identity::generate(0);
        let blob = export_with_params(&id, b"passphrase A", FAST).unwrap();
        assert!(import(&blob, b"passphrase B").is_err());
    }

    #[test]
    fn a_backup_blob_is_not_a_valid_keystore() {
        let id = Identity::generate(0);
        let blob = export_with_params(&id, b"pw", FAST).unwrap();
        // Correct passphrase, wrong container -> AAD mismatch.
        assert!(keystore::open(&blob, b"pw").is_err());
    }
}
