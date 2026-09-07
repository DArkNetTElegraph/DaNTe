//! [`Engine`] — one client's whole world: an identity, a local ledger replica,
//! a relay connection, prekeys, live DM sessions, and (optionally) an encrypted
//! on-disk store so all of that survives a restart.

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use dante_crypto::{hash::sha256, pow::Difficulty, random_array, sign::SignSecret};
use dante_dm::{Content, FileManifest, Packet, PreKeyBundle, PreKeySecrets, Session};
use dante_group::{Group, GroupMessage, SenderKeyBundle};
use dante_identity::{
    records::{IdentityAnnounce, LivenessProof},
    Identity,
};
use dante_ledger::{server::ServerRegister, Ledger, LedgerParams, MemoryStore};
use dante_net::{sync, transport::Client};
use dante_proto::{envelope::recipient_hint, Envelope, Record};

use crate::{
    channel::{ChannelControl, ChannelInfo, ChannelMessage},
    error::CoreError,
    store::{self, ChannelHistoryEntry, HistoryEntry, HistoryKind, PersistedState},
};

/// Default envelope TTL for DMs: 7 days.
pub const DM_TTL_MS: u32 = 7 * 24 * 60 * 60 * 1000;

/// Re-announce / re-prove liveness only if the last one is older than this.
pub const REANNOUNCE_AFTER_MS: u64 = 24 * 60 * 60 * 1000;

/// Cap on persisted seen-envelope tags.
const SEEN_CAP: usize = 5000;

/// Cap on persisted channel-history lines (oldest dropped first).
const CHANNEL_HISTORY_CAP: usize = 2000;

/// TTL on a typing signal's carrier envelope. Deliberately short: a stale
/// "is typing" is worse than a missing one.
const TYPING_TTL_MS: u32 = 10_000;

/// Domain tag for the shared per-conversation typing-signal topic.
const DM_TYPING_TOPIC_DOMAIN: &[u8] = b"dante/typing/dm/v1";

/// A decrypted inbound direct message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedDm {
    /// The sender's Ed25519 identity key.
    pub from_idk: [u8; 32],
    /// The plaintext.
    pub text: String,
}

/// Where a typing signal belongs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypingScope {
    /// A 1:1 conversation with the peer whose Ed25519 identity key this is.
    Dm([u8; 32]),
    /// A channel, by `channel_id`.
    Channel([u8; 32]),
}

/// An ephemeral "someone is typing" event. Not persisted; the caller shows it
/// for a few seconds and then forgets it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypingEvent {
    /// The conversation the signal is for.
    pub scope: TypingScope,
    /// The typer: an Ed25519 identity key for `Dm`, a member id for `Channel`.
    pub who: [u8; 32],
    /// When the signal was created (its carrier's `deposited_ms`, AEAD-bound).
    /// Freshness is judged from this, not from when it was fetched, so a signal
    /// stops showing a few seconds after the last keystroke even though the
    /// relay keeps serving it until its TTL.
    pub at_ms: u64,
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

/// One channel this client belongs to.
pub(crate) struct ChannelSession {
    pub info: ChannelInfo,
    pub group: Group,
    pub roster: HashSet<[u8; 32]>,
    pub last_seq: u64,
}

/// A server this client hosts (holds the root key).
pub(crate) struct HostedServer {
    pub name: String,
    pub root: SignSecret,
    pub channels: Vec<[u8; 32]>,
}

/// The client engine.
pub struct Engine {
    identity: Identity,
    prekeys: PreKeySecrets,
    ledger: Ledger<MemoryStore>,
    client: Client,
    sessions: HashMap<[u8; 32], Session>,
    channels: HashMap<[u8; 32], ChannelSession>,
    hosted: HashMap<[u8; 32], HostedServer>,
    seen_envelopes: HashSet<[u8; 32]>,
    history: Vec<HistoryEntry>,
    channel_history: Vec<ChannelHistoryEntry>,
    pow: Difficulty,
    last_fetch_since_ms: u64,
    last_announce_ms: u64,
    store_path: Option<PathBuf>,
    dirty: bool,
}

impl Engine {
    /// Connect to a relay and build an engine around `identity`, restoring
    /// prior state from `store_path` if that file exists (otherwise a fresh
    /// prekey set is generated). `pow` is the difficulty for this client's own
    /// announce/liveness records; it must meet the network's floor.
    pub async fn connect(
        identity: Identity,
        relay_addr: &str,
        params: LedgerParams,
        pow: Difficulty,
        store_path: Option<PathBuf>,
    ) -> Result<Self, CoreError> {
        let client = Client::connect(relay_addr).await?;

        let restored = match &store_path {
            Some(p) => store::load(p, &identity)?,
            None => None,
        };

        let mut engine = Self {
            prekeys: PreKeySecrets::generate(50),
            identity,
            ledger: Ledger::new(MemoryStore::default(), params),
            client,
            sessions: HashMap::new(),
            channels: HashMap::new(),
            hosted: HashMap::new(),
            seen_envelopes: HashSet::new(),
            history: Vec::new(),
            channel_history: Vec::new(),
            pow,
            last_fetch_since_ms: 0,
            last_announce_ms: 0,
            store_path,
            dirty: false,
        };

        if let Some(s) = restored {
            engine.prekeys = PreKeySecrets::import(s.prekeys);
            engine.sessions = s
                .sessions
                .into_iter()
                .map(|(idk, st)| (idk, Session::import(st)))
                .collect();
            engine.seen_envelopes = s.seen_envelopes.into_iter().collect();
            engine.history = s.history;
            engine.channel_history = s.channel_history;
            engine.last_fetch_since_ms = s.last_fetch_since_ms;
            engine.last_announce_ms = s.last_announce_ms;
            for c in s.channels {
                engine.channels.insert(
                    c.info.channel_id,
                    ChannelSession {
                        info: c.info,
                        group: Group::import(&c.group)?,
                        roster: c.roster.into_iter().collect(),
                        last_seq: c.last_seq,
                    },
                );
            }
            for h in s.hosted {
                engine.hosted.insert(
                    h.root_pub,
                    HostedServer {
                        name: h.name,
                        root: SignSecret::from_bytes(&h.root_secret),
                        channels: h.channels,
                    },
                );
            }
        }
        Ok(engine)
    }

    fn my_member_id(&self) -> [u8; 32] {
        *self.identity.id().as_bytes()
    }

    /// This identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Conversation history restored from and appended to the local store.
    pub fn history(&self) -> &[HistoryEntry] {
        &self.history
    }

    /// Channel history restored from and appended to the local store, oldest
    /// first.
    pub fn channel_history(&self) -> &[ChannelHistoryEntry] {
        &self.channel_history
    }

    /// Flush state to the store file if anything changed since the last flush.
    /// A no-op when no store path was configured.
    pub fn persist(&mut self) -> Result<(), CoreError> {
        let Some(path) = self.store_path.clone() else {
            return Ok(());
        };
        if !self.dirty {
            return Ok(());
        }
        let mut seen: Vec<[u8; 32]> = self.seen_envelopes.iter().copied().collect();
        if seen.len() > SEEN_CAP {
            seen.drain(..seen.len() - SEEN_CAP);
        }
        let state = PersistedState {
            prekeys: self.prekeys.export(),
            sessions: self
                .sessions
                .iter()
                .map(|(k, s)| (*k, s.export()))
                .collect(),
            channels: self
                .channels
                .values()
                .map(|c| store::StoredChannel {
                    info: c.info.clone(),
                    group: c.group.export(),
                    roster: c.roster.iter().copied().collect(),
                    last_seq: c.last_seq,
                })
                .collect(),
            hosted: self
                .hosted
                .iter()
                .map(|(root_pub, h)| store::StoredHostedServer {
                    root_pub: *root_pub,
                    name: h.name.clone(),
                    root_secret: h.root.to_bytes(),
                    channels: h.channels.clone(),
                })
                .collect(),
            history: self.history.clone(),
            channel_history: self.channel_history.clone(),
            seen_envelopes: seen,
            last_announce_ms: self.last_announce_ms,
            last_fetch_since_ms: self.last_fetch_since_ms,
        };
        store::save(&path, &self.identity, &state)?;
        self.dirty = false;
        Ok(())
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
        self.last_announce_ms = now_ms;
        self.dirty = true;
        Ok(())
    }

    /// Publish a fresh liveness proof.
    pub async fn prove_liveness(&mut self, now_ms: u64) -> Result<(), CoreError> {
        let rec = LivenessProof::build(&self.identity, now_ms, self.pow)
            .to_record(&self.identity, now_ms);
        sync::submit_record(&mut self.client, &rec).await?;
        self.last_announce_ms = now_ms;
        self.dirty = true;
        Ok(())
    }

    /// Announce on first run, then only re-prove liveness once a day — a
    /// restored client that announced recently skips the PoW entirely.
    pub async fn announce_if_stale(
        &mut self,
        display_hint: &str,
        now_ms: u64,
    ) -> Result<bool, CoreError> {
        if now_ms.saturating_sub(self.last_announce_ms) <= REANNOUNCE_AFTER_MS {
            return Ok(false);
        }
        if self.last_announce_ms == 0 {
            self.announce(display_hint, now_ms).await?;
        } else {
            self.prove_liveness(now_ms).await?;
        }
        Ok(true)
    }

    /// Publish this identity's prekey bundle to the relay.
    pub async fn publish_prekeys(&mut self) -> Result<(), CoreError> {
        let bundle = self.prekeys.bundle(&self.identity).encode();
        sync::publish_prekeys(&mut self.client, &bundle).await?;
        Ok(())
    }

    // ---- channels / servers -------------------------------------------------

    /// Channels this client currently belongs to.
    pub fn channels(&self) -> Vec<ChannelInfo> {
        self.channels.values().map(|c| c.info.clone()).collect()
    }

    /// Create a server: mint a root key, register it on the ledger. Returns the
    /// `server_root` public key (also its display handle).
    pub async fn create_server(&mut self, name: &str, now_ms: u64) -> Result<[u8; 32], CoreError> {
        let root = SignSecret::generate();
        let server_root = root.public().to_bytes();
        let reg = ServerRegister {
            server_root,
            name: name.chars().take(64).collect(),
            summary: String::new(),
            tags: vec![],
            entry_relays: vec![],
            discoverable: false,
        };
        let rec = reg.to_record(now_ms, |m| root.sign(m));
        sync::submit_record(&mut self.client, &rec).await?;
        self.hosted.insert(
            server_root,
            HostedServer {
                name: name.to_owned(),
                root,
                channels: vec![],
            },
        );
        self.dirty = true;
        Ok(server_root)
    }

    /// Create a channel in a server this client hosts. Returns the channel id.
    pub fn create_channel(
        &mut self,
        server_root: &[u8; 32],
        name: &str,
        private: bool,
    ) -> Result<[u8; 32], CoreError> {
        let server_name = self
            .hosted
            .get(server_root)
            .ok_or(CoreError::NotServerHost)?
            .name
            .clone();
        let channel_id = random_array::<32>();
        let (group, _my_bundle) = Group::create(channel_id, self.my_member_id());
        let info = ChannelInfo {
            server_root: *server_root,
            server_name,
            channel_id,
            channel_name: name.to_owned(),
            private,
        };
        let mut roster = HashSet::new();
        roster.insert(self.my_member_id());
        self.channels.insert(
            channel_id,
            ChannelSession {
                info,
                group,
                roster,
                last_seq: 0,
            },
        );
        self.hosted
            .get_mut(server_root)
            .unwrap()
            .channels
            .push(channel_id);
        self.dirty = true;
        Ok(channel_id)
    }

    /// Add `peer_id` to a channel (host only): DM them an invite carrying every
    /// current member's sender-key bundle, and add them to the local roster.
    pub async fn invite_to_channel(
        &mut self,
        channel_id: &[u8; 32],
        peer_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let ch = self
            .channels
            .get(channel_id)
            .ok_or(CoreError::UnknownChannel)?;
        if !self.hosted.contains_key(&ch.info.server_root) {
            return Err(CoreError::NotServerHost);
        }
        let info = ch.info.clone();
        let roster: Vec<[u8; 32]> = ch.roster.iter().copied().collect();
        // Hand the joiner our bundle plus a reconstructed bundle for every other
        // member we already know, so they can decrypt everyone from the start.
        // Those members learn the joiner's key from the `KeyBundle` it sends
        // back (and reply in kind — see `handle_channel_control`).
        let mut bundles = vec![ch.group.my_bundle().encode()];
        bundles.extend(ch.group.peer_bundles().iter().map(|b| b.encode()));

        let invite = ChannelControl::Invite {
            info,
            roster: roster.clone(),
            bundles,
        };
        self.send_content(peer_id, Content::Channel(invite.encode()), now_ms)
            .await?;

        if let Some(ch) = self.channels.get_mut(channel_id) {
            ch.roster.insert(*peer_id);
        }
        self.dirty = true;
        Ok(())
    }

    /// Send a text message to a channel.
    pub async fn send_channel(
        &mut self,
        channel_id: &[u8; 32],
        text: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let ch = self
            .channels
            .get_mut(channel_id)
            .ok_or(CoreError::UnknownChannel)?;
        let gm = ch.group.encrypt(&Content::Text(text.to_owned()).encode());
        sync::post_to_channel(&mut self.client, channel_id, &gm.encode()).await?;
        self.push_channel_history(ChannelHistoryEntry {
            channel_id: *channel_id,
            sender: self.my_member_id(),
            outgoing: true,
            ts_ms: now_ms,
            text: text.to_owned(),
        });
        self.dirty = true;
        Ok(())
    }

    fn push_channel_history(&mut self, e: ChannelHistoryEntry) {
        self.channel_history.push(e);
        if self.channel_history.len() > CHANNEL_HISTORY_CAP {
            let overflow = self.channel_history.len() - CHANNEL_HISTORY_CAP;
            self.channel_history.drain(..overflow);
        }
    }

    /// Poll every channel's relay log and return newly decrypted messages
    /// (excluding our own).
    pub async fn poll_channels(&mut self, now_ms: u64) -> Result<Vec<ChannelMessage>, CoreError> {
        let me = self.my_member_id();
        let ids: Vec<[u8; 32]> = self.channels.keys().copied().collect();
        let mut out = Vec::new();
        let mut new_history = Vec::new();
        for id in ids {
            let since = self.channels[&id].last_seq;
            let entries = sync::fetch_channel(&mut self.client, &id, since).await?;
            for (seq, blob) in entries {
                if let Some(ch) = self.channels.get_mut(&id) {
                    ch.last_seq = ch.last_seq.max(seq);
                    let Ok(gm) = GroupMessage::decode(&blob) else {
                        continue;
                    };
                    if gm.sender == me {
                        continue;
                    }
                    match ch.group.decrypt(&gm) {
                        Ok(pt) => {
                            if let Ok(Content::Text(text)) = Content::decode(&pt) {
                                new_history.push(ChannelHistoryEntry {
                                    channel_id: id,
                                    sender: gm.sender,
                                    outgoing: false,
                                    ts_ms: now_ms,
                                    text: text.clone(),
                                });
                                out.push(ChannelMessage {
                                    channel_id: id,
                                    channel_name: ch.info.channel_name.clone(),
                                    sender: gm.sender,
                                    text,
                                });
                            }
                        }
                        Err(e) => tracing::debug!(error = %e, "undecryptable channel message"),
                    }
                }
            }
        }
        if !out.is_empty() {
            for e in new_history {
                self.push_channel_history(e);
            }
            self.dirty = true;
        }
        Ok(out)
    }

    async fn handle_channel_control(&mut self, blob: &[u8], now_ms: u64) -> Result<(), CoreError> {
        match ChannelControl::decode(blob)? {
            ChannelControl::Invite {
                info,
                roster,
                bundles,
            } => {
                let channel_id = info.channel_id;
                if !self.channels.contains_key(&channel_id) {
                    let (mut group, _) = Group::create(channel_id, self.my_member_id());
                    for b in &bundles {
                        if let Ok(bundle) = SenderKeyBundle::decode(b) {
                            let _ = group.upsert_member(&bundle);
                        }
                    }
                    let mut roster_set: HashSet<[u8; 32]> = roster.iter().copied().collect();
                    roster_set.insert(self.my_member_id());
                    self.channels.insert(
                        channel_id,
                        ChannelSession {
                            info,
                            group,
                            roster: roster_set,
                            last_seq: 0,
                        },
                    );
                }
                // Send our bundle to every other roster member.
                let my_bundle = self.channels[&channel_id].group.my_bundle().encode();
                let kb = ChannelControl::KeyBundle {
                    channel_id,
                    bundle: my_bundle,
                };
                let targets: Vec<[u8; 32]> = roster
                    .into_iter()
                    .filter(|m| *m != self.my_member_id())
                    .collect();
                for m in targets {
                    let _ = self
                        .send_content(&m, Content::Channel(kb.encode()), now_ms)
                        .await;
                }
                self.dirty = true;
            }
            ChannelControl::KeyBundle { channel_id, bundle } => {
                let Ok(b) = SenderKeyBundle::decode(&bundle) else {
                    return Ok(());
                };
                let member = b.member;
                let me = self.my_member_id();
                let mut reply_to = None;
                if let Some(ch) = self.channels.get_mut(&channel_id) {
                    let is_new = !ch.group.known_members().any(|m| *m == member);
                    ch.roster.insert(member);
                    ch.group.upsert_member(&b)?;
                    self.dirty = true;
                    // First time we hear from this member: hand them our bundle
                    // back so every pair of members ends up mutually keyed, not
                    // just each member and the host.
                    if is_new && member != me {
                        reply_to = Some(ch.group.my_bundle().encode());
                    }
                }
                if let Some(my_bundle) = reply_to {
                    let kb = ChannelControl::KeyBundle {
                        channel_id,
                        bundle: my_bundle,
                    };
                    let _ = self
                        .send_content(&member, Content::Channel(kb.encode()), now_ms)
                        .await;
                }
            }
        }
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

    /// The shared relay topic both ends of a DM derive for typing signals:
    /// `SHA-256(domain || min(idk) || max(idk))`. Order-independent so either
    /// party computes the same value; opaque to the relay.
    fn dm_typing_topic(&self, peer_idk: &[u8; 32]) -> [u8; 32] {
        let mine = self.identity.sign_public().to_bytes();
        let (lo, hi) = if mine <= *peer_idk {
            (mine, *peer_idk)
        } else {
            (*peer_idk, mine)
        };
        let mut buf = Vec::with_capacity(DM_TYPING_TOPIC_DOMAIN.len() + 64);
        buf.extend_from_slice(DM_TYPING_TOPIC_DOMAIN);
        buf.extend_from_slice(&lo);
        buf.extend_from_slice(&hi);
        sha256(&buf)
    }

    /// Broadcast a short-lived "I am typing" signal to a DM peer. Stateless:
    /// it seals a fresh sealed-sender envelope (no ratchet step, nothing
    /// persisted) and posts it to the pair's ephemeral relay topic. Callers
    /// gate this on a user setting and rate-limit it.
    pub async fn send_typing_dm(
        &mut self,
        peer_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let peer_idk = self
            .ledger
            .idk_for_id(peer_id)
            .ok_or(CoreError::UnknownPeer)?;
        let peer_ik = self
            .ledger
            .agreement_key(&peer_idk)
            .ok_or(CoreError::UnknownPeer)?;
        let topic = self.dm_typing_topic(&peer_idk);
        let env = Envelope::seal_with(
            peer_id,
            &peer_ik,
            self.identity.sign_public().to_bytes(),
            &Content::Typing.encode(),
            now_ms,
            TYPING_TTL_MS,
            |m| self.identity.sign(m),
        )?;
        sync::post_signal(&mut self.client, &topic, &env.encode()).await?;
        Ok(())
    }

    /// Broadcast a short-lived "I am typing" signal to a channel. Stateless:
    /// [`Group::seal_signal`] AEADs the marker under the member's static signal
    /// key without advancing the message chain, so nothing is persisted.
    pub async fn send_typing_channel(
        &mut self,
        channel_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let blob = {
            let ch = self
                .channels
                .get(channel_id)
                .ok_or(CoreError::UnknownChannel)?;
            let mut pt = now_ms.to_be_bytes().to_vec();
            pt.extend_from_slice(&Content::Typing.encode());
            ch.group.seal_signal(&pt)
        };
        sync::post_signal(&mut self.client, channel_id, &blob).await?;
        Ok(())
    }

    /// Poll for inbound typing signals across every open DM and channel.
    /// Ephemeral: the result is a snapshot, nothing is stored, and re-polling
    /// re-reports a signal that is still within its TTL on the relay.
    pub async fn poll_typing(&mut self, _now_ms: u64) -> Result<Vec<TypingEvent>, CoreError> {
        let ik = self.identity.agreement_secret();
        let peer_idks: Vec<[u8; 32]> = self.sessions.keys().copied().collect();
        let mut out = Vec::new();
        for peer_idk in peer_idks {
            let topic = self.dm_typing_topic(&peer_idk);
            let blobs = sync::fetch_signals(&mut self.client, &topic).await?;
            for blob in blobs {
                let Ok(env) = Envelope::decode(&blob) else {
                    continue;
                };
                // Our own signal is sealed to the peer, so `open` fails for us.
                let Ok(sealed) = env.open(&ik) else { continue };
                if sealed.sender_idk != peer_idk {
                    continue;
                }
                if let Ok(Content::Typing) = Content::decode(&sealed.inner) {
                    out.push(TypingEvent {
                        scope: TypingScope::Dm(peer_idk),
                        who: sealed.sender_idk,
                        at_ms: env.deposited_ms,
                    });
                }
            }
        }

        let me = self.my_member_id();
        let channel_ids: Vec<[u8; 32]> = self.channels.keys().copied().collect();
        for channel_id in channel_ids {
            let blobs = sync::fetch_signals(&mut self.client, &channel_id).await?;
            let Some(ch) = self.channels.get(&channel_id) else {
                continue;
            };
            for blob in blobs {
                let Some((member, pt)) = ch.group.open_signal(&blob) else {
                    continue;
                };
                if member == me || pt.len() < 8 {
                    continue;
                }
                let at_ms = u64::from_be_bytes(pt[..8].try_into().unwrap());
                if let Ok(Content::Typing) = Content::decode(&pt[8..]) {
                    out.push(TypingEvent {
                        scope: TypingScope::Channel(channel_id),
                        who: member,
                        at_ms,
                    });
                }
            }
        }
        Ok(out)
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
        let history_kind = match &content {
            Content::Text(t) => Some(HistoryKind::Text(t.clone())),
            Content::File(m) => Some(HistoryKind::File {
                filename: m.filename.clone(),
                size: m.total_size,
            }),
            Content::Channel(_) => None, // control traffic, not conversation
            Content::Typing => None,     // ephemeral; never sent via this path
        };
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
        if let Some(kind) = history_kind {
            self.history.push(HistoryEntry {
                peer_idk,
                outgoing: true,
                ts_ms: now_ms,
                kind,
            });
        }
        self.dirty = true;
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
        let mut consumed_prekey = false;
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
            consumed_prekey |= matches!(packet, Packet::Init(_));

            let plaintext = match self.decrypt_packet(&from, packet) {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(error = %e, "dropping undecryptable inbound packet");
                    continue;
                }
            };
            match Content::decode(&plaintext) {
                Ok(Content::Text(text)) => {
                    self.history.push(HistoryEntry {
                        peer_idk: from,
                        outgoing: false,
                        ts_ms: now_ms,
                        kind: HistoryKind::Text(text.clone()),
                    });
                    out.push(Inbound::Message(ReceivedDm {
                        from_idk: from,
                        text,
                    }));
                }
                Ok(Content::File(manifest)) => match self.fetch_file(manifest).await {
                    Ok((filename, data)) => {
                        self.history.push(HistoryEntry {
                            peer_idk: from,
                            outgoing: false,
                            ts_ms: now_ms,
                            kind: HistoryKind::File {
                                filename: filename.clone(),
                                size: data.len() as u64,
                            },
                        });
                        out.push(Inbound::File {
                            from_idk: from,
                            filename,
                            data,
                        });
                    }
                    Err(e) => tracing::debug!(error = %e, "dropping file with a failed transfer"),
                },
                Ok(Content::Channel(blob)) => {
                    if let Err(e) = self.handle_channel_control(&blob, now_ms).await {
                        tracing::debug!(error = %e, "dropping channel-control message");
                    }
                }
                // Typing signals travel the ephemeral signal path, not the
                // mailbox; ignore one that somehow arrives here.
                Ok(Content::Typing) => {}
                Err(e) => tracing::debug!(error = %e, "dropping malformed content"),
            }
            self.dirty = true;
        }
        self.last_fetch_since_ms = now_ms.saturating_sub(2 * dante_proto::envelope::EPOCH_MS);
        // A first-contact packet consumed one of our one-time prekeys (locally,
        // and on the relay). Re-publish so the relay's copy tracks our remaining
        // set and later initiators still get a fresh OTP.
        if consumed_prekey {
            let _ = self.publish_prekeys().await;
        }
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
