//! The in-memory [`Identity`]: everything secret that belongs to one DaNTe user.

use dante_crypto::{
    agree::{AgreePublic, AgreeSecret},
    random_array,
    sign::{SignPublic, SignSecret, SIG_LEN},
};
use zeroize::Zeroizing;

use crate::id::IdentityId;

/// A user's long-term secrets, held in memory while the app runs.
///
/// - `idk` — Ed25519 identity/signing key (defines the [`IdentityId`])
/// - `ik` — X25519 long-term agreement key (the X3DH "identity key")
/// - `ratchet_db_key` — symmetric key for the local encrypted message store
///
/// All three are zeroized on drop. Persist an `Identity` with
/// [`crate::keystore`]; never write the raw secrets to disk yourself.
pub struct Identity {
    idk: SignSecret,
    ik: AgreeSecret,
    ratchet_db_key: Zeroizing<[u8; 32]>,
    created_ms: u64,
}

impl Identity {
    /// Generate a brand-new identity. `created_ms` is the wall-clock time of
    /// creation (Unix milliseconds), recorded in the keystore.
    pub fn generate(created_ms: u64) -> Self {
        Self {
            idk: SignSecret::generate(),
            ik: AgreeSecret::generate(),
            ratchet_db_key: Zeroizing::new(random_array::<32>()),
            created_ms,
        }
    }

    /// Reconstruct an identity from its stored secret material (used by
    /// [`crate::keystore`] and [`crate::backup`]).
    pub fn from_parts(
        idk_secret: &[u8; 32],
        ik_secret: &[u8; 32],
        ratchet_db_key: [u8; 32],
        created_ms: u64,
    ) -> Self {
        Self {
            idk: SignSecret::from_bytes(idk_secret),
            ik: AgreeSecret::from_bytes(ik_secret),
            ratchet_db_key: Zeroizing::new(ratchet_db_key),
            created_ms,
        }
    }

    /// This identity's id (`SHA-256(idk_pub)`).
    pub fn id(&self) -> IdentityId {
        IdentityId::of(&self.idk.public())
    }

    /// The public Ed25519 identity key.
    pub fn sign_public(&self) -> SignPublic {
        self.idk.public()
    }

    /// The public X25519 long-term agreement key.
    pub fn agree_public(&self) -> AgreePublic {
        self.ik.public()
    }

    /// Creation time (Unix milliseconds).
    pub fn created_ms(&self) -> u64 {
        self.created_ms
    }

    /// Sign `msg` with the identity key.
    pub fn sign(&self, msg: &[u8]) -> [u8; SIG_LEN] {
        self.idk.sign(msg)
    }

    /// Diffie-Hellman between our long-term agreement key and `their_ik`.
    pub fn agree(&self, their_ik: &AgreePublic) -> Result<[u8; 32], dante_crypto::CryptoError> {
        self.ik.agree(their_ik)
    }

    /// The local message-store key.
    pub fn ratchet_db_key(&self) -> &[u8; 32] {
        &self.ratchet_db_key
    }

    // --- accessors used only within this crate to persist the identity ---

    pub(crate) fn idk_secret(&self) -> [u8; 32] {
        self.idk.to_bytes()
    }

    pub(crate) fn ik_secret(&self) -> [u8; 32] {
        self.ik.to_bytes()
    }
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Identity")
            .field("id", &self.id())
            .field("created_ms", &self.created_ms)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_unique_and_self_consistent() {
        let a = Identity::generate(1_700_000_000_000);
        let b = Identity::generate(1_700_000_000_000);
        assert_ne!(a.id(), b.id());
        assert_eq!(IdentityId::of(&a.sign_public()), a.id());
    }

    #[test]
    fn sign_verify_through_identity() {
        let id = Identity::generate(0);
        let sig = id.sign(b"hello");
        id.sign_public().verify(b"hello", &sig).unwrap();
    }

    #[test]
    fn from_parts_reconstructs_same_identity() {
        let orig = Identity::generate(42);
        let rebuilt = Identity::from_parts(
            &orig.idk_secret(),
            &orig.ik_secret(),
            *orig.ratchet_db_key(),
            orig.created_ms(),
        );
        assert_eq!(orig.id(), rebuilt.id());
        assert_eq!(orig.agree_public(), rebuilt.agree_public());
        assert_eq!(orig.ratchet_db_key(), rebuilt.ratchet_db_key());
    }

    #[test]
    fn two_identities_agree_on_a_shared_secret() {
        let a = Identity::generate(0);
        let b = Identity::generate(0);
        assert_eq!(
            a.agree(&b.agree_public()).unwrap(),
            b.agree(&a.agree_public()).unwrap()
        );
    }
}
