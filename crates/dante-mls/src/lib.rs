//! `dante-mls` — MLS (RFC 9420) groups for DaNTe, via [OpenMLS].
//!
//! This is the building block for migrating channels off the sender-keys
//! ratchet in `dante-group` and for **group calls**: MLS gives post-compromise
//! security, O(log n) rekey, and — the part group calls need — a shared
//! per-epoch secret every member can derive independently
//! ([`Member::call_key`]). Delivery of the handshake messages this produces
//! (Commits, Welcomes, KeyPackages) still rides DaNTe's authenticated pairwise
//! DMs / channel log; this crate is transport-agnostic and hands back opaque
//! byte blobs.
//!
//! Scope: create a group, publish a [`KeyPkg`] to be added, add / remove
//! members, process inbound handshake + application messages, export the
//! group-call key for the current epoch, and [`export`](Member::export) /
//! [`import`](Member::import) the whole member so a call / channel survives a
//! restart. Not yet driven by `dante-core` — the group-call orchestration
//! (fetching members' KeyPackages, carrying Welcome / Commit over the channel
//! log, opening the media mesh) is the next step.
//!
//! This crate declares `rust-version = 1.91` (OpenMLS 0.9's floor); the rest of
//! the workspace still builds on 1.85.
//!
//! [OpenMLS]: https://openmls.tech

use openmls::prelude::{
    tls_codec::{Deserialize as _, Serialize as _},
    *,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

mod error;
pub use error::MlsError;

/// The one ciphersuite DaNTe uses: X25519 + AES-128-GCM + SHA-256 + Ed25519.
/// Mandatory-to-implement in RFC 9420 and all-Rust in the backend we ship.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Label for the exported group-call key. Bump the version suffix to force a
/// domain change if the media-key derivation ever changes.
const CALL_KEY_LABEL: &str = "dante/group-call/v1";
/// Group-call keys are 32 bytes (fed into the media layer's own KDF/AEAD).
pub const CALL_KEY_LEN: usize = 32;

/// A serialized MLS message (Commit, Welcome, or application message) as it
/// travels over DaNTe transport. Opaque; hand it to [`Member::process`] (or
/// [`Pending::join`] for a Welcome).
pub type Wire = Vec<u8>;

/// A serialized KeyPackage — a member publishes one so others can add it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPkg(pub Vec<u8>);

/// What a member must broadcast after a local add / remove: the Commit goes to
/// existing members, the Welcome (if any) goes to the newly added members.
#[derive(Clone, Debug)]
pub struct Handshake {
    /// Commit message — every current member must [`Member::process`] it.
    pub commit: Wire,
    /// Welcome message — present only when members were added; send it to them.
    pub welcome: Option<Wire>,
}

/// The outcome of [`Member::process`]ing an inbound message.
#[derive(Debug)]
pub enum Processed {
    /// An application message's plaintext.
    Application(Vec<u8>),
    /// A staged commit was merged; the epoch advanced. Re-derive
    /// [`Member::call_key`].
    EpochChanged,
    /// A protocol message that changed nothing observable (e.g. a bare
    /// proposal awaiting its commit).
    Ignored,
}

/// An identity that has published a [`KeyPkg`] and is waiting to be added
/// to a group. Keep it until the matching Welcome arrives — the KeyPackage's
/// private half lives in this value's OpenMLS store.
pub struct Pending {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    identity: Vec<u8>,
}

impl Pending {
    /// Consume the Welcome produced by [`Member::add`] and become a full
    /// [`Member`].
    pub fn join(self, welcome: &[u8]) -> Result<Member, MlsError> {
        let msg = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(|e| MlsError::Codec(e.to_string()))?;
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(MlsError::Unexpected("expected a Welcome message")),
        };

        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
            .map_err(|e| MlsError::Group(e.to_string()))?;
        let group = staged
            .into_group(&self.provider)
            .map_err(|e| MlsError::Group(e.to_string()))?;

        Ok(Member {
            provider: self.provider,
            signer: self.signer,
            credential: self.credential,
            identity: self.identity,
            group,
        })
    }
}

/// One member's live view of one MLS group.
pub struct Member {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    #[allow(dead_code)] // held so the signer's public half stays paired with it
    credential: CredentialWithKey,
    identity: Vec<u8>,
    group: MlsGroup,
}

impl Member {
    /// Create a brand-new group containing only this member. `identity` is the
    /// member's stable name inside the group (DaNTe passes the identity-key
    /// fingerprint); `group_id` is the channel id.
    pub fn create(identity: &[u8], group_id: &[u8]) -> Result<Self, MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let (signer, credential) = new_credential(identity, &provider)?;

        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &provider,
            &signer,
            &config,
            GroupId::from_slice(group_id),
            credential.clone(),
        )
        .map_err(|e| MlsError::Group(e.to_string()))?;

        Ok(Self {
            provider,
            signer,
            credential,
            identity: identity.to_vec(),
            group,
        })
    }

    /// Publish a [`KeyPkg`] so an existing member can add this identity.
    /// Returns the [`Pending`] half to keep until the Welcome arrives.
    pub fn publish_key_package(identity: &[u8]) -> Result<(Pending, KeyPkg), MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let (signer, credential) = new_credential(identity, &provider)?;

        let bundle = KeyPackage::builder()
            .build(CIPHERSUITE, &provider, &signer, credential.clone())
            .map_err(|e| MlsError::Group(e.to_string()))?;
        let bytes = bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|e| MlsError::Codec(e.to_string()))?;

        Ok((
            Pending {
                provider,
                signer,
                credential,
                identity: identity.to_vec(),
            },
            KeyPkg(bytes),
        ))
    }

    /// Add members from their published KeyPackages. Returns the handshake to
    /// broadcast; the local epoch has already advanced.
    pub fn add(&mut self, key_packages: &[KeyPkg]) -> Result<Handshake, MlsError> {
        let mut kps = Vec::with_capacity(key_packages.len());
        for kp in key_packages {
            let parsed = KeyPackageIn::tls_deserialize_exact(&kp.0)
                .map_err(|e| MlsError::Codec(e.to_string()))?;
            let validated = parsed
                .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|e| MlsError::Group(format!("invalid key package: {e:?}")))?;
            kps.push(validated);
        }

        let (commit, welcome, _group_info) = self
            .group
            .add_members(&self.provider, &self.signer, &kps)
            .map_err(|e| MlsError::Group(e.to_string()))?;
        self.group
            .merge_pending_commit(&self.provider)
            .map_err(|e| MlsError::Group(e.to_string()))?;

        Ok(Handshake {
            commit: commit.to_bytes().map_err(codec)?,
            welcome: Some(welcome.to_bytes().map_err(codec)?),
        })
    }

    /// Remove members by their in-group leaf index (see
    /// [`member_indices`](Self::member_indices)). Returns the handshake to
    /// broadcast; the local epoch has already advanced.
    pub fn remove(&mut self, members: &[u32]) -> Result<Handshake, MlsError> {
        let leaves: Vec<LeafNodeIndex> = members.iter().copied().map(LeafNodeIndex::new).collect();
        let (commit, welcome, _group_info) = self
            .group
            .remove_members(&self.provider, &self.signer, &leaves)
            .map_err(|e| MlsError::Group(e.to_string()))?;
        self.group
            .merge_pending_commit(&self.provider)
            .map_err(|e| MlsError::Group(e.to_string()))?;

        Ok(Handshake {
            commit: commit.to_bytes().map_err(codec)?,
            welcome: welcome.map(|w| w.to_bytes()).transpose().map_err(codec)?,
        })
    }

    /// Encrypt an application message for the group.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Wire, MlsError> {
        self.group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(|e| MlsError::Group(e.to_string()))?
            .to_bytes()
            .map_err(codec)
    }

    /// Process an inbound protocol message: an application message, or a Commit
    /// that advances the epoch.
    pub fn process(&mut self, wire: &[u8]) -> Result<Processed, MlsError> {
        let msg = MlsMessageIn::tls_deserialize_exact(wire)
            .map_err(|e| MlsError::Codec(e.to_string()))?;
        let protocol: ProtocolMessage = msg
            .try_into_protocol_message()
            .map_err(|_| MlsError::Unexpected("not an application/handshake message"))?;

        let processed = self
            .group
            .process_message(&self.provider, protocol)
            .map_err(|e| MlsError::Group(e.to_string()))?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                Ok(Processed::Application(app.into_bytes()))
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                self.group
                    .merge_staged_commit(&self.provider, *staged)
                    .map_err(|e| MlsError::Group(e.to_string()))?;
                Ok(Processed::EpochChanged)
            }
            ProcessedMessageContent::ProposalMessage(_)
            | ProcessedMessageContent::ExternalJoinProposalMessage(_)
            | ProcessedMessageContent::OwnPendingCommit
            | ProcessedMessageContent::OwnPrivateMessage => Ok(Processed::Ignored),
        }
    }

    /// The current epoch number. Every member in the same epoch derives the
    /// same [`call_key`](Self::call_key).
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// This member's own leaf index — its handle for another member's
    /// [`remove`](Self::remove).
    pub fn own_index(&self) -> u32 {
        self.group.own_leaf_index().u32()
    }

    /// The in-group leaf indices of every current member.
    pub fn member_indices(&self) -> Vec<u32> {
        self.group.members().map(|m| m.index.u32()).collect()
    }

    /// `(leaf index, identity bytes)` for every current member. The identity is
    /// what each was created / added with (DaNTe passes the identity-key
    /// fingerprint), so callers can map a peer to the leaf they pass to
    /// [`remove`](Self::remove).
    pub fn members(&self) -> Vec<(u32, Vec<u8>)> {
        self.group
            .members()
            .map(|m| (m.index.u32(), m.credential.serialized_content().to_vec()))
            .collect()
    }

    /// The identity bytes this member was created with.
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    /// Derive the group-call media key for the current epoch. All members in
    /// the epoch get identical bytes; it changes on every add / remove — the
    /// post-compromise-security property group calls rely on.
    pub fn call_key(&self) -> Result<[u8; CALL_KEY_LEN], MlsError> {
        let secret = self
            .group
            .export_secret(self.provider.crypto(), CALL_KEY_LABEL, &[], CALL_KEY_LEN)
            .map_err(|e| MlsError::Group(e.to_string()))?;
        let mut out = [0u8; CALL_KEY_LEN];
        out.copy_from_slice(&secret);
        Ok(out)
    }

    /// Serialize the whole member — the OpenMLS store (group state + this
    /// member's signature key) plus the handles needed to reload it. DaNTe
    /// keeps this blob in its own encrypted local store so a call / channel
    /// survives a restart. It carries private keys: treat it like the keystore.
    pub fn export(&self) -> Result<Vec<u8>, MlsError> {
        let values = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| MlsError::Group("storage lock poisoned".into()))?;

        let mut store = Vec::new();
        store.extend_from_slice(&(values.len() as u32).to_be_bytes());
        for (k, v) in values.iter() {
            put(&mut store, k);
            put(&mut store, v);
        }

        let mut out = Vec::new();
        put(&mut out, self.group.group_id().as_slice());
        put(&mut out, &self.identity);
        put(&mut out, &self.signer.to_public_vec());
        put(&mut out, &store);
        Ok(out)
    }

    /// Rebuild a member from [`export`](Self::export) bytes.
    pub fn import(bytes: &[u8]) -> Result<Self, MlsError> {
        let mut cur = bytes;
        let group_id = get(&mut cur)?;
        let identity = get(&mut cur)?;
        let signer_public = get(&mut cur)?;
        let store_bytes = get(&mut cur)?;

        let provider = OpenMlsRustCrypto::default();
        {
            let mut sb = &store_bytes[..];
            if sb.len() < 4 {
                return Err(MlsError::Codec("truncated store".into()));
            }
            let (count_bytes, rest) = sb.split_at(4);
            let count = u32::from_be_bytes(count_bytes.try_into().unwrap());
            sb = rest;

            let mut values = provider
                .storage()
                .values
                .write()
                .map_err(|_| MlsError::Group("storage lock poisoned".into()))?;
            for _ in 0..count {
                let k = get(&mut sb)?;
                let v = get(&mut sb)?;
                values.insert(k, v);
            }
        }

        let signer = SignatureKeyPair::read(
            provider.storage(),
            &signer_public,
            CIPHERSUITE.signature_algorithm(),
        )
        .ok_or(MlsError::Group("no signature key in the store".into()))?;

        let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&group_id))
            .map_err(|e| MlsError::Group(format!("{e:?}")))?
            .ok_or(MlsError::Group("no group in the store".into()))?;

        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity.clone()).into(),
            signature_key: signer.to_public_vec().into(),
        };

        Ok(Self {
            provider,
            signer,
            credential,
            identity,
            group,
        })
    }
}

/// Length-prefix (`u32` big-endian) a field into `buf`.
fn put(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
    buf.extend_from_slice(field);
}

/// Read one length-prefixed field, advancing `cur`.
fn get(cur: &mut &[u8]) -> Result<Vec<u8>, MlsError> {
    if cur.len() < 4 {
        return Err(MlsError::Codec("truncated export".into()));
    }
    let (len_bytes, rest) = cur.split_at(4);
    let len = u32::from_be_bytes(len_bytes.try_into().unwrap()) as usize;
    if rest.len() < len {
        return Err(MlsError::Codec("truncated export".into()));
    }
    let (field, rest) = rest.split_at(len);
    *cur = rest;
    Ok(field.to_vec())
}

fn new_credential(
    identity: &[u8],
    provider: &OpenMlsRustCrypto,
) -> Result<(SignatureKeyPair, CredentialWithKey), MlsError> {
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
        .map_err(|e| MlsError::Crypto(format!("{e:?}")))?;
    signer
        .store(provider.storage())
        .map_err(|e| MlsError::Group(format!("storing signer: {e:?}")))?;
    let credential = CredentialWithKey {
        credential: BasicCredential::new(identity.to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    };
    Ok((signer, credential))
}

fn codec<E: std::fmt::Display>(e: E) -> MlsError {
    MlsError::Codec(e.to_string())
}

#[cfg(test)]
mod tests;
