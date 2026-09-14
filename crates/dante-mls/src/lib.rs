//! `dante-mls` — MLS (RFC 9420) groups for DaNTe, via [OpenMLS].
//!
//! Used by `dante-core` for **channels** (message confidentiality with
//! post-compromise security and O(log n) rekey) and for **group calls** (a
//! shared per-epoch media key every member derives independently,
//! [`Member::call_key`]). Delivery of the handshake messages this produces
//! (Commits, Welcomes, KeyPackages) rides DaNTe's authenticated pairwise DMs /
//! channel log; this crate is transport-agnostic and hands back opaque byte
//! blobs.
//!
//! Surface: create a group, publish [`KeyPkg`]s to be added, add / remove
//! members, [`process`](Member::process) / [`process_from`](Member::process_from)
//! inbound handshake + application messages, [`export_key`](Member::export_key)
//! per-epoch secrets, and [`export`](Member::export) / [`import`](Member::import)
//! the whole member so a channel / call survives a restart.
//!
//! [OpenMLS]: https://openmls.tech

use dante_crypto::sign::{SignPublic, SignSecret};
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

/// MLS's own `BasicCredential` only carries caller-chosen identity bytes —
/// nothing in RFC 9420 or OpenMLS ties them to anything, so a client is free
/// to publish a KeyPackage (or found a group) claiming to be any identity at
/// all. DaNTe closes that with its own credential type: caller-chosen
/// identity bytes, plus a binding proof — the identity's own long-term
/// Ed25519 ("`idk`") signature over a domain-separated challenge covering
/// this specific KeyPackage's fresh, per-package MLS signature key, minted
/// once at [`Member::create`] / [`Member::publish_key_package`] time and
/// self-checked by every consumer of the credential (`members()`,
/// [`Member::process`]'s sender extraction, [`Member::key_package_identity`]).
///
/// This only proves internal self-consistency — "whoever holds this idk
/// vouches for this leaf key" — not that the embedded `idk_pub` is really
/// the current key for the claimed identity on DaNTe's ledger. That
/// cross-check needs the ledger, which this crate has no access to; callers
/// (`dante-core`) do it on top, the same way the relay's own signature
/// checks and the engine's credential-on-use check already do for the
/// wire-level publish path.
///
/// This is registered as a private-use `CredentialType::Other` — OpenMLS
/// treats every credential type as opaque bytes it merely stores and passes
/// along ("OpenMLS does not look into credentials"), so this is exactly the
/// extension point RFC 9420 leaves for exactly this purpose, not a hack.
const DANTE_CREDENTIAL_TYPE: u16 = 0xDA47; // "DAnTe", picked to avoid the
                                           // GREASE range OpenMLS reserves.

/// Domain-separated so a signature minted for this can't be replayed as a
/// signature over anything else this identity signs elsewhere in DaNTe.
const CREDENTIAL_BINDING_DOMAIN: &[u8] = b"dante/mls/credential-binding/v1";

fn credential_binding_challenge(identity: &[u8], mls_signature_pub: &[u8]) -> [u8; 32] {
    dante_crypto::hash::sha256_parts(&[CREDENTIAL_BINDING_DOMAIN, identity, mls_signature_pub])
}

/// The identity + binding proof carried in every DaNTe MLS credential. See
/// the [`DANTE_CREDENTIAL_TYPE`] doc comment for why this exists.
struct DanteCredential {
    identity: Vec<u8>,
    idk_pub: [u8; 32],
    sig: [u8; 64],
}

impl DanteCredential {
    /// Mint a new credential for `identity`, binding it to `mls_signature_pub`
    /// (the fresh per-package/per-group MLS signature key this credential
    /// will be paired with) via `idk`'s own signature.
    fn new(identity: &[u8], idk: &SignSecret, mls_signature_pub: &[u8]) -> Self {
        let idk_pub = idk.public().to_bytes();
        let sig = idk.sign(&credential_binding_challenge(identity, mls_signature_pub));
        Self {
            identity: identity.to_vec(),
            idk_pub,
            sig,
        }
    }

    /// `identity(4-byte-LE-length-prefixed) || idk_pub(32) || sig(64)`.
    /// Hand-rolled rather than pulling in a wire-encoding crate for one
    /// struct — this never leaves `dante-mls`'s own encode/decode pair.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.identity.len() + 32 + 64);
        out.extend_from_slice(&(self.identity.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.identity);
        out.extend_from_slice(&self.idk_pub);
        out.extend_from_slice(&self.sig);
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }
        let len = u32::from_le_bytes(bytes[..4].try_into().ok()?) as usize;
        let rest = &bytes[4..];
        if rest.len() != len + 32 + 64 {
            return None;
        }
        let identity = rest[..len].to_vec();
        let idk_pub: [u8; 32] = rest[len..len + 32].try_into().ok()?;
        let sig: [u8; 64] = rest[len + 32..].try_into().ok()?;
        Some(Self {
            identity,
            idk_pub,
            sig,
        })
    }

    /// Decode `bytes` and verify the embedded signature is self-consistent
    /// with `mls_signature_pub` — i.e. `idk_pub` really did sign for this
    /// exact `(identity, mls_signature_pub)` pair. Does **not** check that
    /// `idk_pub` is the real current key for `identity` on the ledger; that
    /// needs a caller with ledger access.
    fn decode_and_verify(bytes: &[u8], mls_signature_pub: &[u8]) -> Option<Self> {
        let cred = Self::decode(bytes)?;
        let challenge = credential_binding_challenge(&cred.identity, mls_signature_pub);
        SignPublic::from_bytes(&cred.idk_pub)
            .ok()?
            .verify(&challenge, &cred.sig)
            .ok()?;
        Some(cred)
    }
}

/// Extract just the identity bytes from a credential's serialized content,
/// without re-verifying the binding signature. Safe to use for an
/// already-established group member: MLS itself only ever accepted this
/// credential paired with that leaf's signature key once, at whichever
/// add/join time [`Member::key_package_identity`]'s `decode_and_verify`
/// (or, for the group's founder, [`Member::create`] minting its own valid
/// credential by construction) already checked it — the ratchet tree keeps
/// that pairing immutable for the life of the leaf. Returns an empty `Vec`
/// (matches nothing real) if the bytes aren't a decodable DanteCredential at
/// all, rather than panicking.
fn credential_identity(serialized_content: &[u8]) -> Vec<u8> {
    DanteCredential::decode(serialized_content)
        .map(|c| c.identity)
        .unwrap_or_default()
}

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
    /// An application message: the sender's identity bytes and the plaintext.
    Application {
        /// The sender's credential identity (what they joined with).
        sender: Vec<u8>,
        /// The decrypted payload.
        plaintext: Vec<u8>,
    },
    /// A staged commit was merged; the epoch advanced. Re-derive
    /// [`Member::call_key`].
    EpochChanged,
    /// A protocol message that changed nothing observable (a bare proposal, an
    /// own message echoed back, or — for [`Member::process_from`] — a commit
    /// from an unauthorized committer that was dropped).
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
    /// [`Member`]. On failure (e.g. this Welcome was built for a *different*
    /// KeyPackage) the `Pending` is handed back (boxed) in the error so the
    /// caller can try it against another Welcome.
    #[allow(clippy::result_large_err)] // the Ok side (Member) is large too
    pub fn join(self, welcome: &[u8]) -> Result<Member, (Box<Self>, MlsError)> {
        let msg = match MlsMessageIn::tls_deserialize_exact(welcome) {
            Ok(m) => m,
            Err(e) => return Err((Box::new(self), MlsError::Codec(e.to_string()))),
        };
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => {
                return Err((
                    Box::new(self),
                    MlsError::Unexpected("expected a Welcome message"),
                ))
            }
        };

        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged = match StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None) {
            Ok(s) => s,
            Err(e) => return Err((Box::new(self), MlsError::Group(e.to_string()))),
        };
        let group = match staged.into_group(&self.provider) {
            Ok(g) => g,
            Err(e) => return Err((Box::new(self), MlsError::Group(e.to_string()))),
        };

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
    /// fingerprint); `group_id` is the channel id. `idk` signs the credential
    /// binding (see [`DANTE_CREDENTIAL_TYPE`]) — the caller's own long-term
    /// Ed25519 identity key, not anything generated here.
    pub fn create(identity: &[u8], idk: &SignSecret, group_id: &[u8]) -> Result<Self, MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let (signer, credential) = new_credential(identity, idk, &provider)?;

        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .capabilities(dante_capabilities())
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
    /// Returns the [`Pending`] half to keep until the Welcome arrives. `idk`
    /// signs the credential binding — see [`Member::create`].
    pub fn publish_key_package(
        identity: &[u8],
        idk: &SignSecret,
    ) -> Result<(Pending, KeyPkg), MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let (signer, credential) = new_credential(identity, idk, &provider)?;

        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(dante_capabilities())
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

    /// The identity bytes embedded in `kp`'s credential, plus the `idk`
    /// public key that vouched for it, without adding it to the group. The
    /// embedded signature is checked for self-consistency (does `idk_pub`
    /// really sign for this exact identity + this exact KeyPackage's MLS
    /// signature key) before either is returned — a KeyPackage whose
    /// credential doesn't carry a valid DaNTe binding at all is refused
    /// outright. This does **not** check that `idk_pub` is the real current
    /// key for that identity on DaNTe's ledger — callers that fetched `kp`
    /// for a specific peer should check both that the returned identity
    /// equals that peer's id AND that the returned `idk_pub` matches the
    /// ledger's key for it, before trusting the package enough to
    /// [`add`](Self::add).
    pub fn key_package_identity(&self, kp: &KeyPkg) -> Result<(Vec<u8>, [u8; 32]), MlsError> {
        let parsed = KeyPackageIn::tls_deserialize_exact(&kp.0)
            .map_err(|e| MlsError::Codec(e.to_string()))?;
        let validated = parsed
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| MlsError::Group(format!("invalid key package: {e:?}")))?;
        let leaf = validated.leaf_node();
        let cred = DanteCredential::decode_and_verify(
            leaf.credential().serialized_content(),
            leaf.signature_key().as_slice(),
        )
        .ok_or(MlsError::Unexpected(
            "key package credential missing or invalid DaNTe binding",
        ))?;
        Ok((cred.identity, cred.idk_pub))
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
    /// that advances the epoch. Any member's commit is accepted.
    pub fn process(&mut self, wire: &[u8]) -> Result<Processed, MlsError> {
        self.process_from(wire, None)
    }

    /// Like [`process`](Self::process), but if `allowed_committer` is `Some(id)`
    /// a Commit is applied only when its committer's identity equals `id` —
    /// otherwise it is dropped (`Processed::Ignored`) and the epoch does not
    /// advance. Application messages are unaffected. DaNTe uses this so a
    /// channel only honours membership commits from its host.
    pub fn process_from(
        &mut self,
        wire: &[u8],
        allowed_committer: Option<&[u8]>,
    ) -> Result<Processed, MlsError> {
        let msg = MlsMessageIn::tls_deserialize_exact(wire)
            .map_err(|e| MlsError::Codec(e.to_string()))?;
        let protocol: ProtocolMessage = msg
            .try_into_protocol_message()
            .map_err(|_| MlsError::Unexpected("not an application/handshake message"))?;

        let processed = self
            .group
            .process_message(&self.provider, protocol)
            .map_err(|e| MlsError::Group(e.to_string()))?;

        let sender = credential_identity(processed.credential().serialized_content());

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(Processed::Application {
                sender,
                plaintext: app.into_bytes(),
            }),
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                if let Some(allowed) = allowed_committer {
                    if sender != allowed {
                        return Ok(Processed::Ignored);
                    }
                }
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
            .map(|m| {
                (
                    m.index.u32(),
                    credential_identity(m.credential.serialized_content()),
                )
            })
            .collect()
    }

    /// The identity bytes this member was created with.
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    /// Derive an application secret for the current epoch under `label`. Every
    /// member in the same epoch gets identical bytes; it changes on every
    /// add / remove (post-compromise security). Use distinct labels for
    /// distinct purposes.
    pub fn export_key(&self, label: &str, len: usize) -> Result<Vec<u8>, MlsError> {
        self.group
            .export_secret(self.provider.crypto(), label, &[], len)
            .map_err(|e| MlsError::Group(e.to_string()))
    }

    /// The group-call media key for the current epoch (a fixed-label
    /// [`export_key`](Self::export_key)).
    pub fn call_key(&self) -> Result<[u8; CALL_KEY_LEN], MlsError> {
        let secret = self.export_key(CALL_KEY_LABEL, CALL_KEY_LEN)?;
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

/// The [`Capabilities`] every DaNTe leaf node and group advertises. OpenMLS
/// only accepts `CredentialType::Basic` by default — a group or KeyPackage
/// that doesn't explicitly list [`DANTE_CREDENTIAL_TYPE`] here refuses every
/// `DanteCredential` with "Credentials are not acceptable", so this must be
/// applied everywhere a group is created or a KeyPackage is built.
fn dante_capabilities() -> Capabilities {
    Capabilities::new(
        None,
        None,
        None,
        None,
        Some(&[CredentialType::Other(DANTE_CREDENTIAL_TYPE)]),
    )
}

fn new_credential(
    identity: &[u8],
    idk: &SignSecret,
    provider: &OpenMlsRustCrypto,
) -> Result<(SignatureKeyPair, CredentialWithKey), MlsError> {
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
        .map_err(|e| MlsError::Crypto(format!("{e:?}")))?;
    signer
        .store(provider.storage())
        .map_err(|e| MlsError::Group(format!("storing signer: {e:?}")))?;
    let mls_pub = signer.to_public_vec();
    let dante_cred = DanteCredential::new(identity, idk, &mls_pub);
    let credential = CredentialWithKey {
        credential: Credential::new(
            CredentialType::Other(DANTE_CREDENTIAL_TYPE),
            dante_cred.encode(),
        ),
        signature_key: mls_pub.into(),
    };
    Ok((signer, credential))
}

fn codec<E: std::fmt::Display>(e: E) -> MlsError {
    MlsError::Codec(e.to_string())
}

#[cfg(test)]
mod tests;
