//! The sealed-sender [`Envelope`] (`docs/PROTOCOL.md` §4.2).
//!
//! Every message a relay stores or forwards is an `Envelope`. A relay sees
//! only:
//! - `recipient_hint` — a coarse, day-rotating tag so a recipient can poll
//!   "is there mail for me" without presenting a stable identifier,
//! - `size_class` — a padded length bucket, not the true length,
//! - timing.
//!
//! It never sees the sender: `payload` decrypts (only with the recipient's
//! long-term X25519 key) to a [`SealedContent`] that carries the sender's
//! identity key and a signature binding them to this exact message and
//! recipient.

use dante_crypto::{
    aead,
    agree::{self, AgreeSecret},
    hash::sha256_parts,
    kdf,
    sign::{SignPublic, SignSecret, SIG_LEN},
    CryptoError,
};

use crate::enc::{Reader, WireError, Writer};

/// Envelope schema version.
pub const ENVELOPE_VERSION: u16 = 1;

/// Milliseconds per day, for `recipient_hint` epoch bucketing.
pub const EPOCH_MS: u64 = 86_400_000;

const SEAL_KDF_INFO: &[u8] = b"dante/sealed-sender/v1";
const HINT_DOMAIN: &[u8] = b"dante/recipient-hint/v1";
const CONTENT_SIG_DOMAIN: &[u8] = b"dante/sealed-sender-content/v1";

/// Padded plaintext size buckets (bytes). `size_class` indexes this table.
pub const SIZE_BUCKETS: [usize; 7] = [256, 1024, 4096, 16_384, 65_536, 262_144, 1_048_576];

/// What `Envelope::payload` decrypts to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedContent {
    /// The sender's Ed25519 identity key.
    pub sender_idk: [u8; 32],
    /// `sender_idk` over `SHA-256(domain || recipient_hint || inner)` — binds
    /// the sender to this message and this recipient window.
    pub sender_sig: [u8; SIG_LEN],
    /// The opaque inner payload (a DM ciphertext, a key exchange, …).
    pub inner: Vec<u8>,
}

impl SealedContent {
    fn sig_challenge(recipient_hint: &[u8; 8], inner: &[u8]) -> [u8; 32] {
        sha256_parts(&[CONTENT_SIG_DOMAIN, recipient_hint, inner])
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(32 + SIG_LEN + 4 + self.inner.len());
        w.fixed(&self.sender_idk)
            .fixed(&self.sender_sig)
            .bytes(&self.inner);
        w.into_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let sender_idk = r.fixed::<32>()?;
        let sender_sig = r.fixed::<SIG_LEN>()?;
        let inner = r.bytes()?.to_vec();
        r.finish()?;
        Ok(Self {
            sender_idk,
            sender_sig,
            inner,
        })
    }
}

/// A stored-and-forwarded message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Schema version.
    pub v: u16,
    /// `SHA-256(domain || recipient_identity_id || be(deposited_ms / EPOCH_MS))[..8]`.
    pub recipient_hint: [u8; 8],
    /// `ephemeral_x25519_pub (32) || XChaCha20-Poly1305(padded SealedContent)`.
    pub payload: Vec<u8>,
    /// Index into [`SIZE_BUCKETS`] the plaintext was padded to.
    pub size_class: u16,
    /// When the sender created it (Unix ms).
    pub deposited_ms: u64,
    /// Relay drops it after this many ms past `deposited_ms`.
    pub ttl_ms: u32,
}

/// The day-rotating polling tag for `recipient_id` at `at_ms`.
pub fn recipient_hint(recipient_id: &[u8; 32], at_ms: u64) -> [u8; 8] {
    let epoch = at_ms / EPOCH_MS;
    let full = sha256_parts(&[HINT_DOMAIN, recipient_id, &epoch.to_be_bytes()]);
    full[..8].try_into().unwrap()
}

fn bucket_for(len: usize) -> Option<(u16, usize)> {
    SIZE_BUCKETS
        .iter()
        .position(|&b| len + 4 <= b)
        .map(|i| (i as u16, SIZE_BUCKETS[i]))
}

fn derive_seal(
    shared: &[u8; 32],
    eph_pub: &[u8; 32],
    recipient_ik_pub: &[u8; 32],
) -> ([u8; 32], [u8; 24]) {
    let prk = kdf::extract(&[eph_pub.as_slice(), recipient_ik_pub].concat(), shared);
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    kdf::expand(&prk, &[SEAL_KDF_INFO, b"/key"].concat(), &mut key).expect("32");
    kdf::expand(&prk, &[SEAL_KDF_INFO, b"/nonce"].concat(), &mut nonce).expect("24");
    (key, nonce)
}

fn header_aad(v: u16, hint: &[u8; 8], size_class: u16, deposited_ms: u64, ttl_ms: u32) -> Vec<u8> {
    let mut w = Writer::with_capacity(24);
    w.u16(v)
        .fixed(hint)
        .u16(size_class)
        .u64(deposited_ms)
        .u32(ttl_ms);
    w.into_vec()
}

impl Envelope {
    /// Seal `inner` for a recipient identified by `recipient_id` (their
    /// `IdentityId` bytes) with long-term agreement key `recipient_ik_pub`.
    /// `sender_idk` signs the content. Fails only if `inner` is larger than the
    /// biggest [`SIZE_BUCKETS`] entry.
    pub fn seal(
        recipient_id: &[u8; 32],
        recipient_ik_pub: &[u8; 32],
        sender_idk: &SignSecret,
        inner: &[u8],
        deposited_ms: u64,
        ttl_ms: u32,
    ) -> Result<Self, CryptoError> {
        let hint = recipient_hint(recipient_id, deposited_ms);

        let content = SealedContent {
            sender_idk: sender_idk.public().to_bytes(),
            sender_sig: sender_idk.sign(&SealedContent::sig_challenge(&hint, inner)),
            inner: inner.to_vec(),
        };
        let plain = content.encode();

        let (size_class, bucket) = bucket_for(plain.len()).ok_or(CryptoError::InvalidKey)?;
        let mut padded = Vec::with_capacity(bucket);
        padded.extend_from_slice(&(plain.len() as u32).to_be_bytes());
        padded.extend_from_slice(&plain);
        padded.resize(bucket, 0);

        let eph = AgreeSecret::generate();
        let eph_pub = eph.public().to_bytes();
        let shared = eph.agree(&agree::AgreePublic::from_bytes(recipient_ik_pub))?;
        let (key, nonce) = derive_seal(&shared, &eph_pub, recipient_ik_pub);

        let aad = header_aad(ENVELOPE_VERSION, &hint, size_class, deposited_ms, ttl_ms);
        let ct = aead::xchacha_seal(&key, &nonce, &padded, &aad);

        let mut payload = Vec::with_capacity(32 + ct.len());
        payload.extend_from_slice(&eph_pub);
        payload.extend_from_slice(&ct);

        Ok(Self {
            v: ENVELOPE_VERSION,
            recipient_hint: hint,
            payload,
            size_class,
            deposited_ms,
            ttl_ms,
        })
    }

    /// Open with the recipient's long-term X25519 secret. Verifies the sender
    /// signature and returns the [`SealedContent`].
    pub fn open(&self, recipient_ik: &AgreeSecret) -> Result<SealedContent, CryptoError> {
        if self.v != ENVELOPE_VERSION || self.payload.len() < 32 {
            return Err(CryptoError::AeadFailure);
        }
        let eph_pub: [u8; 32] = self.payload[..32].try_into().unwrap();
        let recipient_ik_pub = recipient_ik.public().to_bytes();
        let shared = recipient_ik.agree(&agree::AgreePublic::from_bytes(&eph_pub))?;
        let (key, nonce) = derive_seal(&shared, &eph_pub, &recipient_ik_pub);

        let aad = header_aad(
            self.v,
            &self.recipient_hint,
            self.size_class,
            self.deposited_ms,
            self.ttl_ms,
        );
        let padded = aead::xchacha_open(&key, &nonce, &self.payload[32..], &aad)?;
        if padded.len() < 4 {
            return Err(CryptoError::AeadFailure);
        }
        let real_len = u32::from_be_bytes(padded[..4].try_into().unwrap()) as usize;
        if 4 + real_len > padded.len() {
            return Err(CryptoError::AeadFailure);
        }
        let content = SealedContent::decode(&padded[4..4 + real_len])
            .map_err(|_| CryptoError::AeadFailure)?;

        let signer = SignPublic::from_bytes(&content.sender_idk)?;
        signer.verify(
            &SealedContent::sig_challenge(&self.recipient_hint, &content.inner),
            &content.sender_sig,
        )?;
        Ok(content)
    }

    /// True if the envelope has outlived its TTL at `now_ms`.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.deposited_ms) > u64::from(self.ttl_ms)
    }

    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(28 + self.payload.len());
        w.u16(self.v)
            .fixed(&self.recipient_hint)
            .bytes(&self.payload)
            .u16(self.size_class)
            .u64(self.deposited_ms)
            .u32(self.ttl_ms);
        w.into_vec()
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let v = r.u16()?;
        let recipient_hint = r.fixed::<8>()?;
        let payload = r.bytes()?.to_vec();
        let size_class = r.u16()?;
        let deposited_ms = r.u64()?;
        let ttl_ms = r.u32()?;
        r.finish()?;
        Ok(Self {
            v,
            recipient_hint,
            payload,
            size_class,
            deposited_ms,
            ttl_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use dante_crypto::{agree::AgreeSecret, sign::SignSecret};

    use super::*;

    struct Peer {
        id: [u8; 32],
        idk: SignSecret,
        ik: AgreeSecret,
    }

    fn peer() -> Peer {
        let idk = SignSecret::generate();
        Peer {
            id: dante_crypto::hash::sha256(&idk.public().to_bytes()),
            idk,
            ik: AgreeSecret::generate(),
        }
    }

    #[test]
    fn seal_open_roundtrip_hides_sender_from_the_wire() {
        let alice = peer();
        let bob = peer();
        let now = 1_770_000_000_000;

        let env = Envelope::seal(
            &bob.id,
            &bob.ik.public().to_bytes(),
            &alice.idk,
            b"hi bob",
            now,
            3_600_000,
        )
        .unwrap();

        // The encoded envelope must not contain Alice's identity key anywhere.
        let wire = env.encode();
        assert!(!wire.windows(32).any(|w| w == alice.idk.public().to_bytes()));

        let content = env.open(&bob.ik).unwrap();
        assert_eq!(content.inner, b"hi bob");
        assert_eq!(content.sender_idk, alice.idk.public().to_bytes());
    }

    #[test]
    fn only_the_intended_recipient_can_open() {
        let alice = peer();
        let bob = peer();
        let mallory = peer();
        let env = Envelope::seal(
            &bob.id,
            &bob.ik.public().to_bytes(),
            &alice.idk,
            b"secret",
            1,
            1000,
        )
        .unwrap();
        assert!(env.open(&mallory.ik).is_err());
    }

    #[test]
    fn tampering_with_header_or_payload_fails_open() {
        let alice = peer();
        let bob = peer();
        let mut env = Envelope::seal(
            &bob.id,
            &bob.ik.public().to_bytes(),
            &alice.idk,
            b"x",
            10,
            10,
        )
        .unwrap();

        let mut t1 = env.clone();
        t1.deposited_ms ^= 1;
        assert!(t1.open(&bob.ik).is_err()); // deposited_ms is in the AAD

        env.payload[40] ^= 1;
        assert!(env.open(&bob.ik).is_err());
    }

    #[test]
    fn recipient_hint_rotates_daily_and_is_stable_within_a_day() {
        let id = [5u8; 32];
        let day1 = 3 * EPOCH_MS + 10;
        let day1_late = 3 * EPOCH_MS + EPOCH_MS - 1;
        let day2 = 4 * EPOCH_MS + 5;
        assert_eq!(recipient_hint(&id, day1), recipient_hint(&id, day1_late));
        assert_ne!(recipient_hint(&id, day1), recipient_hint(&id, day2));
    }

    #[test]
    fn size_class_padding_hides_true_length() {
        let alice = peer();
        let bob = peer();
        let short =
            Envelope::seal(&bob.id, &bob.ik.public().to_bytes(), &alice.idk, b"a", 1, 1).unwrap();
        let longer = Envelope::seal(
            &bob.id,
            &bob.ik.public().to_bytes(),
            &alice.idk,
            &[7u8; 100],
            1,
            1,
        )
        .unwrap();
        assert_eq!(short.size_class, longer.size_class);
        assert_eq!(short.payload.len(), longer.payload.len());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let alice = peer();
        let bob = peer();
        let env = Envelope::seal(
            &bob.id,
            &bob.ik.public().to_bytes(),
            &alice.idk,
            b"wire",
            99,
            5,
        )
        .unwrap();
        assert_eq!(Envelope::decode(&env.encode()).unwrap(), env);
    }

    #[test]
    fn expiry() {
        let alice = peer();
        let bob = peer();
        let env = Envelope::seal(
            &bob.id,
            &bob.ik.public().to_bytes(),
            &alice.idk,
            b"x",
            1_000,
            500,
        )
        .unwrap();
        assert!(!env.is_expired(1_400));
        assert!(env.is_expired(1_600));
    }
}
