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

use dante_crypto::sign::SignPublic;
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
/// once at [`Member::create`] / [`Member::publish_key_package`] time.
///
/// **This binding is verified when adding a member, and when joining via a
/// Welcome — but not for a member added by a *later* commit.**
/// [`Member::key_package_identity`] verifies it (self-consistency; see
/// below) before a KeyPackage is trusted enough to add its holder to a
/// group — every `add()` call site in `dante-core` gates on this plus a
/// ledger cross-check. [`Pending::join`] inspects every leaf in a Welcome's
/// ratchet tree the same way *before* ever building a live group from it,
/// refusing the whole Welcome if any leaf's binding doesn't verify;
/// `dante-core` does the matching ledger cross-check via
/// [`Member::member_bindings`] right after a successful join. What's still
/// open: once a member has joined, a commit that adds someone new isn't
/// re-checked the same way — `members()` / [`Member::process`]'s sender
/// extraction (`credential_identity`) only decode the identity from
/// whatever's already in the tree, they do not re-verify the signature. So
/// a *host* who controls their own already-established group can still add
/// a leaf whose credential is self-consistent but names a ledger-invalid
/// identity via an ordinary commit, and every *existing* member processing
/// that commit will trust `members()`/`process()`'s attribution of it —
/// this is not a regression (pre-this-type, credentials were equally
/// unverified), but it is a real, currently-open gap. Closing it needs
/// verifying newly-added leaves on every processed commit, which has not
/// been built yet.
///
/// The self-consistency property this type DOES give the adding side: proof
/// that *some* real `idk` vouches for `(identity, this leaf's signature
/// key)` — not that the embedded `idk_pub` is really the current key for
/// that identity on DaNTe's ledger. That cross-check needs the ledger,
/// which this crate has no access to; `dante-core` does it on top, the same
/// way the relay's own signature checks and the engine's credential-on-use
/// check already do for the wire-level publish path.
///
/// This is registered in RFC 9420's private-use `CredentialType` range
/// (0xF000–0xFFFF) as `CredentialType::Other` — OpenMLS treats every
/// credential type as opaque bytes it merely stores and passes along
/// ("OpenMLS does not look into credentials"), so this is exactly the
/// extension point the RFC leaves for exactly this purpose, not a hack.
const DANTE_CREDENTIAL_TYPE: u16 = 0xF0DA; // "DAnTe", inside the private-use block.

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
    /// will be paired with) via `idk_sign` — the caller's own long-term
    /// signing capability, taken as `idk_pub` + a signing closure rather
    /// than a raw secret-key reference, matching this codebase's existing
    /// idiom for handing signing capability across a crate boundary without
    /// handing out the secret itself.
    fn new(
        identity: &[u8],
        idk_pub: [u8; 32],
        idk_sign: impl Fn(&[u8]) -> [u8; 64],
        mls_signature_pub: &[u8],
    ) -> Self {
        let sig = idk_sign(&credential_binding_challenge(identity, mls_signature_pub));
        Self {
            identity: identity.to_vec(),
            idk_pub,
            sig,
        }
    }

    /// Uses `dante-proto`'s canonical `Writer`/`Reader` — the same
    /// length-prefixed-bytes-plus-fixed-fields encoding used throughout the
    /// rest of this codebase, rather than a bespoke one-off format.
    fn encode(&self) -> Vec<u8> {
        let mut w = dante_proto::enc::Writer::with_capacity(4 + self.identity.len() + 32 + 64);
        w.bytes(&self.identity)
            .fixed(&self.idk_pub)
            .fixed(&self.sig);
        w.into_vec()
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = dante_proto::enc::Reader::new(bytes);
        let identity = r.bytes().ok()?.to_vec();
        let idk_pub = r.fixed::<32>().ok()?;
        let sig = r.fixed::<64>().ok()?;
        r.finish().ok()?;
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
/// without re-verifying the binding signature.
///
/// This trusts that whoever put this leaf in the tree already had its
/// binding verified — true for a leaf this client itself added (every
/// `add()` call site in `dante-core` gates on it) and for every leaf
/// present when the group was joined (`Pending::join` refuses the whole
/// Welcome otherwise), but **not** for a leaf added by a commit processed
/// *after* joining (see [`DANTE_CREDENTIAL_TYPE`]'s doc comment for the
/// open gap this leaves). The ratchet tree does keep a credential/leaf-key
/// pairing immutable for the life of the leaf once *accepted*, so
/// re-verifying the signature on every message would be redundant *if* it
/// was checked at acceptance — today that's guaranteed for every leaf
/// except one added by a later commit. Returns an empty `Vec` (matches
/// nothing real) if the bytes aren't a decodable DanteCredential at all,
/// rather than panicking.
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

        // Inspect the Welcome's ratchet tree *before* ever creating a live
        // group from it: every leaf's credential must be a self-consistent
        // DanteCredential binding, checked against that exact leaf's own MLS
        // signature key. `StagedWelcome::members()` exposes this without
        // needing `into_group()` first, so a Welcome carrying even one
        // leaf with no valid binding (or a legacy `BasicCredential`) is
        // refused outright — no live `MlsGroup` is ever built from it, let
        // alone joined. This only proves self-consistency, not that each
        // `idk_pub` is the ledger's real current key for its identity;
        // `dante-core` does that check on top via `member_bindings` once
        // joined, the same layering used for adding members ourselves.
        for m in staged.members() {
            if DanteCredential::decode_and_verify(
                m.credential.serialized_content(),
                &m.signature_key,
            )
            .is_none()
            {
                return Err((
                    Box::new(self),
                    MlsError::Unexpected(
                        "a member in this Welcome's ratchet tree has no valid DaNTe credential binding",
                    ),
                ));
            }
        }

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
    /// fingerprint); `group_id` is the channel id. `idk_pub` + `idk_sign` sign
    /// the credential binding (see [`DANTE_CREDENTIAL_TYPE`]) — the caller's
    /// own long-term Ed25519 identity key, not anything generated here, taken
    /// as a public key plus a signing closure rather than a raw secret-key
    /// reference.
    pub fn create(
        identity: &[u8],
        idk_pub: [u8; 32],
        idk_sign: impl Fn(&[u8]) -> [u8; 64],
        group_id: &[u8],
    ) -> Result<Self, MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let (signer, credential) = new_credential(identity, idk_pub, idk_sign, &provider)?;

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
    /// Returns the [`Pending`] half to keep until the Welcome arrives.
    /// `idk_pub` + `idk_sign` sign the credential binding — see
    /// [`Member::create`].
    pub fn publish_key_package(
        identity: &[u8],
        idk_pub: [u8; 32],
        idk_sign: impl Fn(&[u8]) -> [u8; 64],
    ) -> Result<(Pending, KeyPkg), MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let (signer, credential) = new_credential(identity, idk_pub, idk_sign, &provider)?;

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

    /// `(leaf index, identity, idk_pub)` for every current member whose
    /// credential is a self-consistent DanteCredential — checked (again;
    /// see the doc comment on [`Pending::join`]) against that exact leaf's
    /// own MLS signature key. A member with no valid binding is silently
    /// omitted rather than erroring, since after a fresh join every leaf is
    /// already known-valid (`Pending::join` refuses the whole Welcome
    /// otherwise) and the only way to reach one here is a leaf added by a
    /// *later* commit — not yet gated the same way (see
    /// [`DANTE_CREDENTIAL_TYPE`]'s doc comment).
    ///
    /// Callers with ledger access (`dante-core`) should check every
    /// returned `idk_pub` against the ledger's current key for that
    /// identity before trusting a freshly-joined group's roster —
    /// self-consistency alone doesn't prove that; it's the same second
    /// layer `key_package_binds_to` already applies when *we* add someone.
    pub fn member_bindings(&self) -> Vec<(u32, Vec<u8>, [u8; 32])> {
        self.group
            .members()
            .filter_map(|m| {
                DanteCredential::decode_and_verify(
                    m.credential.serialized_content(),
                    &m.signature_key,
                )
                .map(|c| (m.index.u32(), c.identity, c.idk_pub))
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

        // A group persisted before this credential type existed has leaves
        // whose credential is a plain `BasicCredential` — `credential_identity`
        // can't decode those as a `DanteCredential`, and silently defaulting
        // every one to an empty (matches-nothing) identity would quietly
        // empty out the roster and drop incoming messages instead of failing
        // where the problem actually is. Fail loudly here instead: this is
        // the wire-incompatible break `THREAT_MODEL.md` already documents as
        // accepted pre-1.0, so a persisted group from before it should be
        // refused outright, not imported into a half-broken state.
        for m in group.members() {
            if DanteCredential::decode(m.credential.serialized_content()).is_none() {
                return Err(MlsError::Group(
                    "this group was persisted before DaNTe's credential binding existed \
                     and can no longer be imported — its leaves don't carry a decodable \
                     DanteCredential"
                        .into(),
                ));
            }
        }

        // `credential` is never read back out of a live `Member` (every group
        // operation goes through `self.group`, `self.signer`, `self.provider`
        // — see the `#[allow(dead_code)]` on the field) — the real DaNTe
        // credential this member published is durable inside `self.group`'s
        // own persisted ratchet-tree state, not reconstructed here. This
        // `BasicCredential` placeholder only needs to type-check the field;
        // it is deliberately not a `DanteCredential`.
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
    idk_pub: [u8; 32],
    idk_sign: impl Fn(&[u8]) -> [u8; 64],
    provider: &OpenMlsRustCrypto,
) -> Result<(SignatureKeyPair, CredentialWithKey), MlsError> {
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
        .map_err(|e| MlsError::Crypto(format!("{e:?}")))?;
    signer
        .store(provider.storage())
        .map_err(|e| MlsError::Group(format!("storing signer: {e:?}")))?;
    let mls_pub = signer.to_public_vec();
    let dante_cred = DanteCredential::new(identity, idk_pub, idk_sign, &mls_pub);
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
