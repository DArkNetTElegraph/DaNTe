//! [`Engine`] — one client's whole world: an identity, a local ledger replica,
//! a relay connection, prekeys, and live DM sessions.

use std::collections::{HashMap, HashSet};

use dante_crypto::{hash::sha256, pow::Difficulty};
use dante_dm::{Content, FileManifest, Packet, PreKeyBundle, PreKeySecrets, Session};
use dante_identity::{
    records::{IdentityAnnounce, LivenessProof},
    Identity,
};
use dante_ledger::{Ledger, LedgerParams, MemoryStore};
use dante_net::{sync, transport::Client};
use dante_proto::{envelope::recipient_hint, Envelope, Record};

use crate::error::CoreError;

/// Default envelope TTL for DMs: 7 days.
pub const DM_TTL_MS: u32 = 7 * 24 * 60 * 60 * 1000;

/// A decrypted inbound direct message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedDm {
    /// The sender's Ed25519 identity key.
    pub from_idk: [u8; 32],
    /// The plaintext.
    pub text: String,
}

/// Something decrypted from the relay: a text message or a fully reassembled
/// file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inbound {
    /// A text message.
    Message(ReceivedDm),
    /// A received file.
    File {
        /// Sender's Ed25519 identity key.
        from_idk: [u8; 32],
        /// The sender-declared filename (display only — never used as a path).
        filename: String,
        /// The decrypted file bytes.
        data: Vec<u8>,
    },
}

/// The client engine.
pub struct Engine {
    identity: Identity,
    prekeys: PreKeySecrets,
    ledger: Ledger<MemoryStore>,
    client: Client,
    sessions: HashMap<[u8; 32], Session>,
    seen_envelopes: HashSet<[u8; 32]>,
    pow: Difficulty,
    last_fetch_since_ms: u64,
}

impl Engine {
    /// Connect to a relay and build an engine around `identity`.
    ///
    /// `pow` is the difficulty used for this client's own announce/liveness
    /// records; it must meet the network's floor (tests pass a low value).
    pub async fn connect(
        identity: Identity,
        prekeys: PreKeySecrets,
        relay_addr: &str,
        params: LedgerParams,
        pow: Difficulty,
    ) -> Result<Self, CoreError> {
        let client = Client::connect(relay_addr).await?;
        Ok(Self {
            identity,
            prekeys,
            ledger: Ledger::new(MemoryStore::default(), params),
            client,
            sessions: HashMap::new(),
            seen_envelopes: HashSet::new(),
            pow,
            last_fetch_since_ms: 0,
        })
    }

    /// This identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Pull new ledger records from the relay into the local replica. Returns
    /// how many were accepted.
    pub async fn sync(&mut self, now_ms: u64) -> Result<u64, CoreError> {
        let local = self.ledger.len() as u64;
        let ledger = &mut self.ledger;
        let (_fetched, accepted) =
            sync::pull_records(&mut self.client, local, now_ms, 256, |rec: Record, now| {
                ledger.append(rec, now).is_ok()
            })
            .await?;
        Ok(accepted)
    }

    /// Announce this identity to the ledger (builds the PoW). The record lands
    /// in the local replica on the next [`Engine::sync`], keeping the replica a
    /// strict prefix of the relay's log.
    pub async fn announce(&mut self, display_hint: &str, now_ms: u64) -> Result<(), CoreError> {
        let rec = IdentityAnnounce::build(&self.identity, display_hint, self.pow)
            .to_record(&self.identity, now_ms);
        sync::submit_record(&mut self.client, &rec).await?;
        Ok(())
    }

    /// Publish a fresh liveness proof.
    pub async fn prove_liveness(&mut self, now_ms: u64) -> Result<(), CoreError> {
        let rec = LivenessProof::build(&self.identity, now_ms, self.pow)
            .to_record(&self.identity, now_ms);
        sync::submit_record(&mut self.client, &rec).await?;
        Ok(())
    }

    /// Publish this identity's prekey bundle to the relay.
    pub async fn publish_prekeys(&mut self) -> Result<(), CoreError> {
        let bundle = self.prekeys.bundle(&self.identity).encode();
        sync::publish_prekeys(&mut self.client, &bundle).await?;
        Ok(())
    }

    /// Send a text DM to the identity whose fingerprint (`IdentityId` bytes) is
    /// `peer_id`. Establishes a session on first contact, fetching the peer's
    /// prekeys from the relay; thereafter ratchets forward.
    ///
    /// The peer must be present in the local ledger replica ([`Engine::sync`]).
    pub async fn send_dm(
        &mut self,
        peer_id: &[u8; 32],
        text: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        self.send_content(peer_id, Content::Text(text.to_owned()), now_ms)
            .await
    }

    /// Send a file DM: the ciphertext chunks go to the relay blob store, the
    /// [`FileManifest`] goes through the ratchet like any other message.
    pub async fn send_file(
        &mut self,
        peer_id: &[u8; 32],
        filename: &str,
        data: &[u8],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let (manifest, chunks) = FileManifest::build(&self.identity, filename, data);
        for chunk in &chunks {
            sync::put_blob(&mut self.client, chunk).await?;
        }
        self.send_content(peer_id, Content::File(manifest), now_ms)
            .await
    }

    async fn send_content(
        &mut self,
        peer_id: &[u8; 32],
        content: Content,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let peer_idk = self
            .ledger
            .idk_for_id(peer_id)
            .ok_or(CoreError::UnknownPeer)?;
        let peer_id = *peer_id;
        let peer_ik = self
            .ledger
            .agreement_key(&peer_idk)
            .ok_or(CoreError::UnknownPeer)?;
        let plaintext = content.encode();

        let packet = if let Some(session) = self.sessions.get_mut(&peer_idk) {
            Packet::Message(session.encrypt(&plaintext)?)
        } else {
            let blob = sync::get_prekeys(&mut self.client, &peer_id)
                .await?
                .ok_or(CoreError::NoPrekeys)?;
            let bundle = PreKeyBundle::decode(&blob)?;
            if bundle.idk_pub != peer_idk || bundle.identity_id != peer_id {
                return Err(CoreError::BadPeerPrekeys);
            }
            bundle.verify().map_err(|_| CoreError::BadPeerPrekeys)?;
            let (session, init) = Session::initiate(&self.identity, &bundle, &plaintext)?;
            self.sessions.insert(peer_idk, session);
            Packet::Init(init)
        };

        let inner = packet.encode();
        let env = Envelope::seal_with(
            &peer_id,
            &peer_ik,
            self.identity.sign_public().to_bytes(),
            &inner,
            now_ms,
            DM_TTL_MS,
            |m| self.identity.sign(m),
        )?;
        sync::deposit(&mut self.client, &env).await?;
        Ok(())
    }

    /// Poll the relay and return any newly decrypted messages / files.
    /// Convenience wrapper returning only text messages.
    pub async fn receive(&mut self, now_ms: u64) -> Result<Vec<ReceivedDm>, CoreError> {
        Ok(self
            .receive_all(now_ms)
            .await?
            .into_iter()
            .filter_map(|i| match i {
                Inbound::Message(m) => Some(m),
                Inbound::File { .. } => None,
            })
            .collect())
    }

    /// Poll the relay for inbound envelopes; decrypt messages and reassemble
    /// files (fetching their chunks from the blob store).
    pub async fn receive_all(&mut self, now_ms: u64) -> Result<Vec<Inbound>, CoreError> {
        let my_id = *self.identity.id().as_bytes();
        let hints = [
            recipient_hint(&my_id, now_ms),
            recipient_hint(
                &my_id,
                now_ms.saturating_sub(dante_proto::envelope::EPOCH_MS),
            ),
            recipient_hint(
                &my_id,
                now_ms.saturating_add(dante_proto::envelope::EPOCH_MS),
            ),
        ];
        let envelopes = sync::fetch(&mut self.client, &hints, self.last_fetch_since_ms).await?;

        let ik = self.identity.agreement_secret();
        let mut out = Vec::new();
        for env in envelopes {
            let tag = sha256(&env.encode());
            if !self.seen_envelopes.insert(tag) {
                continue;
            }
            let Ok(sealed) = env.open(&ik) else { continue };
            let Ok(packet) = Packet::decode(&sealed.inner) else {
                continue;
            };
            let from = sealed.sender_idk;

            let plaintext = match self.decrypt_packet(&from, packet) {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(error = %e, "dropping undecryptable inbound packet");
                    continue;
                }
            };
            match Content::decode(&plaintext) {
                Ok(Content::Text(text)) => out.push(Inbound::Message(ReceivedDm {
                    from_idk: from,
                    text,
                })),
                Ok(Content::File(manifest)) => match self.fetch_file(manifest).await {
                    Ok((filename, data)) => out.push(Inbound::File {
                        from_idk: from,
                        filename,
                        data,
                    }),
                    Err(e) => tracing::debug!(error = %e, "dropping file with a failed transfer"),
                },
                Err(e) => tracing::debug!(error = %e, "dropping malformed content"),
            }
        }
        self.last_fetch_since_ms = now_ms.saturating_sub(2 * dante_proto::envelope::EPOCH_MS);
        Ok(out)
    }

    fn decrypt_packet(
        &mut self,
        from_idk: &[u8; 32],
        packet: Packet,
    ) -> Result<Vec<u8>, CoreError> {
        match packet {
            Packet::Init(init) => {
                let (session, plaintext) =
                    Session::accept(&self.identity, &mut self.prekeys, &init)?;
                self.sessions.insert(*from_idk, session);
                Ok(plaintext)
            }
            Packet::Message(msg) => {
                let session = self
                    .sessions
                    .get_mut(from_idk)
                    .ok_or(CoreError::NoSession)?;
                Ok(session.decrypt(&msg)?)
            }
        }
    }

    async fn fetch_file(&mut self, manifest: FileManifest) -> Result<(String, Vec<u8>), CoreError> {
        manifest.verify()?;
        let mut chunks = Vec::with_capacity(manifest.blob_hashes().len());
        for hash in manifest.blob_hashes() {
            let blob = sync::get_blob(&mut self.client, hash)
                .await?
                .ok_or(CoreError::MissingBlob)?;
            chunks.push(blob);
        }
        let data = manifest.reassemble(&chunks)?;
        Ok((manifest.filename.clone(), data))
    }

    /// Records currently in the local replica (for inspection / tests).
    pub fn ledger_len(&self) -> usize {
        self.ledger.len()
    }

    /// Whether `peer_idk` is a live identity in the local replica.
    pub fn knows(&self, peer_idk: &[u8; 32]) -> bool {
        self.ledger.is_live(peer_idk)
    }
}
