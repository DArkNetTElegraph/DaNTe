//! [`Engine`] — one client's whole world: an identity, a local ledger replica,
//! a relay connection, prekeys, live DM sessions, and (optionally) an encrypted
//! on-disk store so all of that survives a restart.

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use dante_crypto::{
    hash::sha256,
    pow::Difficulty,
    random_array,
    sign::{SignPublic, SignSecret},
};
use dante_dm::{Content, FileManifest, Packet, PreKeyBundle, PreKeySecrets, Session};
use dante_group::{Group, GroupMessage, SenderKeyBundle};
use dante_identity::{
    id::IdentityId,
    records::{IdentityAnnounce, LivenessProof},
    Identity,
};
use dante_ledger::{server::ServerRegister, Ledger, LedgerParams, MemoryStore};
use dante_net::{sync, transport::Client};
use dante_proto::{envelope::recipient_hint, Envelope, Record};

use crate::{
    channel::{ChannelControl, ChannelInfo, ChannelMessage},
    error::CoreError,
    roles::{self, ServerPolicy},
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

/// One-time-prekey pool is refilled to this before each publish.
const PREKEY_POOL_TARGET: usize = 50;

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
    /// Members ejected from this channel: `member -> removal `issued_ms``. We
    /// refuse to re-key them and drop their messages. Re-admitting a removed
    /// member is not supported by the sender-keys scheme (MLS migration will
    /// fix this) — recreate the channel instead.
    pub removed: HashMap<[u8; 32], u64>,
}

/// A server this client hosts (holds the root key).
pub(crate) struct HostedServer {
    pub name: String,
    pub root: SignSecret,
    pub channels: Vec<[u8; 32]>,
    /// If set, [`Engine::sweep_inactive_members`] removes any channel member
    /// whose identity has had no ledger activity for this many ms. Off by
    /// default.
    pub auto_kick_ms: Option<u64>,
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
    /// Redemption counts for invite tokens we minted, keyed by token nonce.
    invite_uses: HashMap<[u8; 8], u32>,
    /// Role configuration per server_root: the one we sign for servers we host,
    /// the latest verified broadcast for servers we have joined.
    server_policies: HashMap<[u8; 32], ServerPolicy>,
    /// The relay address this engine connected to (embedded in invite links).
    relay_addr: String,
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
            invite_uses: HashMap::new(),
            server_policies: HashMap::new(),
            relay_addr: relay_addr.to_owned(),
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
            engine.invite_uses = s.invite_uses.into_iter().collect();
            engine.last_fetch_since_ms = s.last_fetch_since_ms;
            engine.last_announce_ms = s.last_announce_ms;
            let mut removed_by_chan: HashMap<[u8; 32], HashMap<[u8; 32], u64>> = HashMap::new();
            for (chan, member, at) in s.channel_removed {
                removed_by_chan.entry(chan).or_default().insert(member, at);
            }
            for c in s.channels {
                let removed = removed_by_chan
                    .remove(&c.info.channel_id)
                    .unwrap_or_default();
                engine.channels.insert(
                    c.info.channel_id,
                    ChannelSession {
                        info: c.info,
                        group: Group::import(&c.group)?,
                        roster: c.roster.into_iter().collect(),
                        last_seq: c.last_seq,
                        removed,
                    },
                );
            }
            for blob in s.server_policies {
                if let Ok(p) = ServerPolicy::decode(&blob) {
                    if p.verify().is_ok() {
                        engine.server_policies.insert(p.server_root, p);
                    }
                }
            }
            let autokick: HashMap<[u8; 32], u64> = s.server_autokick.into_iter().collect();
            for h in s.hosted {
                engine.hosted.insert(
                    h.root_pub,
                    HostedServer {
                        auto_kick_ms: autokick.get(&h.root_pub).copied(),
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
            invite_uses: self.invite_uses.iter().map(|(k, v)| (*k, *v)).collect(),
            channel_removed: self
                .channels
                .iter()
                .flat_map(|(cid, c)| c.removed.iter().map(move |(m, at)| (*cid, *m, *at)))
                .collect(),
            server_autokick: self
                .hosted
                .iter()
                .filter_map(|(root, h)| h.auto_kick_ms.map(|ms| (*root, ms)))
                .collect(),
            server_policies: self.server_policies.values().map(|p| p.encode()).collect(),
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
        // Refill the one-time-prekey pool before every publish. The relay hands
        // out one OTP per fetch, so without this a client that accepted a few
        // first-contacts would eventually publish an OTP-less bundle.
        if self.prekeys.replenish(PREKEY_POOL_TARGET) > 0 {
            self.dirty = true;
        }
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
        self.server_policies.insert(
            server_root,
            ServerPolicy::genesis(&root, self.my_member_id(), now_ms),
        );
        self.hosted.insert(
            server_root,
            HostedServer {
                name: name.to_owned(),
                root,
                channels: vec![],
                auto_kick_ms: None,
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
                removed: HashMap::new(),
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
        let server_root = ch.info.server_root;
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

        // Hand the joiner the current role configuration too.
        if let Some(policy) = self.server_policies.get(&server_root).cloned() {
            let pol = ChannelControl::Policy {
                policy: policy.encode(),
            };
            let _ = self
                .send_content(peer_id, Content::Channel(pol.encode()), now_ms)
                .await;
        }

        if let Some(ch) = self.channels.get_mut(channel_id) {
            ch.roster.insert(*peer_id);
        }
        self.dirty = true;
        Ok(())
    }

    /// Mint a shareable invite link for a channel this client hosts. `ttl_ms`
    /// is how long the link stays valid; `max_uses` of `0` means unlimited.
    pub fn create_invite_link(
        &self,
        channel_id: &[u8; 32],
        ttl_ms: u64,
        max_uses: u32,
        now_ms: u64,
    ) -> Result<String, CoreError> {
        let ch = self
            .channels
            .get(channel_id)
            .ok_or(CoreError::UnknownChannel)?;
        let host = self
            .hosted
            .get(&ch.info.server_root)
            .ok_or(CoreError::NotServerHost)?;
        let token = crate::invite::InviteToken::mint(
            &host.root,
            self.my_member_id(),
            *channel_id,
            &self.relay_addr,
            now_ms.saturating_add(ttl_ms),
            max_uses,
            random_array::<8>(),
        );
        Ok(token.to_link())
    }

    /// Redeem an invite link: verify it locally, then DM the host a request to
    /// be added. Joining completes when the host's `Invite` arrives on a later
    /// [`Engine::receive_all`].
    pub async fn redeem_invite(&mut self, link: &str, now_ms: u64) -> Result<(), CoreError> {
        let token = crate::invite::InviteToken::from_link(link)?;
        token.verify()?;
        if token.is_expired(now_ms) {
            return Err(CoreError::Invite("expired"));
        }
        if self.channels.contains_key(&token.channel_id) {
            return Ok(()); // already a member
        }
        let host_id = token.host_id;
        let redeem = ChannelControl::Redeem {
            token: token.encode(),
        };
        self.send_content(&host_id, Content::Channel(redeem.encode()), now_ms)
            .await
    }

    /// Eject a member from a channel this client hosts. Issues a server-root-
    /// signed [`crate::channel::RemoveOrder`] to every remaining member, drops
    /// the member locally, and rotates our own sender chain. Each remaining
    /// member does the same on receipt, so the removed member's cached keys go
    /// stale — an O(n) rekey.
    pub async fn remove_from_channel(
        &mut self,
        channel_id: &[u8; 32],
        member_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        if *member_id == self.my_member_id() {
            return Err(CoreError::Channel("cannot remove yourself"));
        }
        let (server_root, targets) = {
            let ch = self
                .channels
                .get(channel_id)
                .ok_or(CoreError::UnknownChannel)?;
            if !self.hosted.contains_key(&ch.info.server_root) {
                return Err(CoreError::NotServerHost);
            }
            let me = self.my_member_id();
            let targets: Vec<[u8; 32]> = ch
                .roster
                .iter()
                .copied()
                .filter(|m| *m != *member_id && *m != me)
                .collect();
            (ch.info.server_root, targets)
        };

        let order = crate::channel::RemoveOrder::mint(
            &self.hosted[&server_root].root,
            *channel_id,
            *member_id,
            now_ms,
        )
        .encode();

        let new_bundle = {
            let ch = self.channels.get_mut(channel_id).unwrap();
            ch.removed.insert(*member_id, now_ms);
            ch.roster.remove(member_id);
            ch.group.remove_member(member_id).encode()
        };
        self.dirty = true;

        for t in targets {
            let rm = ChannelControl::Remove {
                order: order.clone(),
            };
            let _ = self
                .send_content(&t, Content::Channel(rm.encode()), now_ms)
                .await;
            let kb = ChannelControl::KeyBundle {
                channel_id: *channel_id,
                bundle: new_bundle.clone(),
            };
            let _ = self
                .send_content(&t, Content::Channel(kb.encode()), now_ms)
                .await;
        }
        Ok(())
    }

    /// Set (or clear, with `None`) the inactivity auto-kick window for a server
    /// this client hosts. When set, [`Engine::sweep_inactive_members`] removes
    /// channel members whose identity has had no ledger activity for `window_ms`.
    pub fn set_auto_kick(
        &mut self,
        server_root: &[u8; 32],
        window_ms: Option<u64>,
    ) -> Result<(), CoreError> {
        let h = self
            .hosted
            .get_mut(server_root)
            .ok_or(CoreError::NotServerHost)?;
        h.auto_kick_ms = window_ms;
        self.dirty = true;
        Ok(())
    }

    /// The configured auto-kick window for a hosted server, if any.
    pub fn auto_kick_window(&self, server_root: &[u8; 32]) -> Option<u64> {
        self.hosted.get(server_root).and_then(|h| h.auto_kick_ms)
    }

    /// For every hosted server with an auto-kick window, remove channel members
    /// whose identity has had no ledger activity within the window (or has
    /// evaporated / is unknown). Returns the ids removed. Call periodically;
    /// keep the local ledger replica fresh with [`Engine::sync`] first.
    pub async fn sweep_inactive_members(
        &mut self,
        now_ms: u64,
    ) -> Result<Vec<[u8; 32]>, CoreError> {
        let me = self.my_member_id();
        let mut victims: Vec<([u8; 32], [u8; 32])> = Vec::new();
        for (root, h) in &self.hosted {
            let Some(window) = h.auto_kick_ms else {
                continue;
            };
            for chan_id in &h.channels {
                let Some(ch) = self.channels.get(chan_id) else {
                    continue;
                };
                if ch.info.server_root != *root {
                    continue;
                }
                for m in &ch.roster {
                    if *m == me || ch.removed.contains_key(m) {
                        continue;
                    }
                    let inactive = match self.ledger.idk_for_id(m) {
                        None => true, // unknown / evaporated
                        Some(idk) => self
                            .ledger
                            .last_activity(&idk)
                            .is_none_or(|t| now_ms.saturating_sub(t) > window),
                    };
                    if inactive {
                        victims.push((*chan_id, *m));
                    }
                }
            }
        }
        let mut removed = Vec::with_capacity(victims.len());
        for (chan_id, member) in victims {
            if self
                .remove_from_channel(&chan_id, &member, now_ms)
                .await
                .is_ok()
            {
                removed.push(member);
            }
        }
        Ok(removed)
    }

    // ---- roles / permissions ---------------------------------------------

    /// The role configuration for a server we host or have joined.
    pub fn server_policy(&self, server_root: &[u8; 32]) -> Option<&ServerPolicy> {
        self.server_policies.get(server_root)
    }

    /// Effective permission mask for `member` on a server (0 if unknown).
    pub fn member_perms(&self, server_root: &[u8; 32], member: &[u8; 32]) -> u32 {
        self.server_policies
            .get(server_root)
            .map_or(roles::PERM_DEFAULT, |p| p.effective_perms(member))
    }

    /// Create (id `None`) or update a role on a server we host, then broadcast
    /// the new policy. Returns the role id.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_role(
        &mut self,
        server_root: &[u8; 32],
        id: Option<u16>,
        name: &str,
        allow: u32,
        deny: u32,
        rank: u16,
        now_ms: u64,
    ) -> Result<u16, CoreError> {
        let (mut roles_vec, assignments, owner, version, root) = self.policy_draft(server_root)?;
        let id = id.unwrap_or_else(|| roles_vec.iter().map(|r| r.id).max().unwrap_or(0) + 1);
        match roles_vec.iter_mut().find(|r| r.id == id) {
            Some(r) => {
                r.name = name.to_owned();
                r.allow = allow;
                r.deny = deny;
                r.rank = rank;
            }
            None => roles_vec.push(crate::roles::Role {
                id,
                name: name.to_owned(),
                allow,
                deny,
                rank,
            }),
        }
        self.commit_policy(
            *server_root,
            &root,
            owner,
            version,
            roles_vec,
            assignments,
            now_ms,
        )
        .await?;
        Ok(id)
    }

    /// Delete a role (and strip it from every assignment) on a hosted server.
    pub async fn delete_role(
        &mut self,
        server_root: &[u8; 32],
        role_id: u16,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let (mut roles_vec, mut assignments, owner, version, root) =
            self.policy_draft(server_root)?;
        roles_vec.retain(|r| r.id != role_id);
        for (_, ids) in &mut assignments {
            ids.retain(|i| *i != role_id);
        }
        assignments.retain(|(_, ids)| !ids.is_empty());
        self.commit_policy(
            *server_root,
            &root,
            owner,
            version,
            roles_vec,
            assignments,
            now_ms,
        )
        .await
    }

    /// Give (`add`) or take (`!add`) a role from a member on a hosted server.
    pub async fn assign_role(
        &mut self,
        server_root: &[u8; 32],
        member: &[u8; 32],
        role_id: u16,
        add: bool,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let (roles_vec, mut assignments, owner, version, root) = self.policy_draft(server_root)?;
        if add && !roles_vec.iter().any(|r| r.id == role_id) {
            return Err(CoreError::Channel("no such role"));
        }
        match assignments.iter_mut().find(|(m, _)| m == member) {
            Some((_, ids)) => {
                if add {
                    if !ids.contains(&role_id) {
                        ids.push(role_id);
                    }
                } else {
                    ids.retain(|i| *i != role_id);
                }
            }
            None if add => assignments.push((*member, vec![role_id])),
            None => {}
        }
        assignments.retain(|(_, ids)| !ids.is_empty());
        self.commit_policy(
            *server_root,
            &root,
            owner,
            version,
            roles_vec,
            assignments,
            now_ms,
        )
        .await
    }

    /// Ask for a member to be removed. If we host the server, do it directly;
    /// otherwise (with `PERM_KICK`) DM the host a `KickRequest`.
    pub async fn request_kick(
        &mut self,
        channel_id: &[u8; 32],
        member: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let server_root = self
            .channels
            .get(channel_id)
            .ok_or(CoreError::UnknownChannel)?
            .info
            .server_root;
        if self.hosted.contains_key(&server_root) {
            return self.remove_from_channel(channel_id, member, now_ms).await;
        }
        let owner = self
            .server_policies
            .get(&server_root)
            .map(|p| p.owner_id)
            .ok_or(CoreError::Channel(
                "no server policy — cannot reach the host",
            ))?;
        if self.member_perms(&server_root, &self.my_member_id()) & roles::PERM_KICK == 0 {
            return Err(CoreError::Channel("you lack the kick permission"));
        }
        let req = ChannelControl::KickRequest {
            channel_id: *channel_id,
            member: *member,
        };
        self.send_content(&owner, Content::Channel(req.encode()), now_ms)
            .await
    }

    /// Pull the mutable parts of a hosted server's policy plus a fresh copy of
    /// its signing key.
    #[allow(clippy::type_complexity)]
    fn policy_draft(
        &self,
        server_root: &[u8; 32],
    ) -> Result<
        (
            Vec<crate::roles::Role>,
            Vec<([u8; 32], Vec<u16>)>,
            [u8; 32],
            u64,
            SignSecret,
        ),
        CoreError,
    > {
        let root_bytes = self
            .hosted
            .get(server_root)
            .ok_or(CoreError::NotServerHost)?
            .root
            .to_bytes();
        let p = self
            .server_policies
            .get(server_root)
            .ok_or(CoreError::NotServerHost)?;
        Ok((
            p.roles.clone(),
            p.assignments.clone(),
            p.owner_id,
            p.version,
            SignSecret::from_bytes(&root_bytes),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn commit_policy(
        &mut self,
        server_root: [u8; 32],
        root: &SignSecret,
        owner: [u8; 32],
        prev_version: u64,
        roles_vec: Vec<crate::roles::Role>,
        assignments: Vec<([u8; 32], Vec<u16>)>,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let np = ServerPolicy::signed(
            root,
            owner,
            prev_version + 1,
            roles_vec,
            assignments,
            now_ms,
        );
        self.server_policies.insert(server_root, np);
        self.dirty = true;
        self.broadcast_policy(&server_root, now_ms).await
    }

    /// DM the current policy to every member of every channel of `server_root`.
    async fn broadcast_policy(
        &mut self,
        server_root: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let Some(policy) = self.server_policies.get(server_root).cloned() else {
            return Ok(());
        };
        let blob = ChannelControl::Policy {
            policy: policy.encode(),
        }
        .encode();
        let me = self.my_member_id();
        let mut targets: HashSet<[u8; 32]> = HashSet::new();
        for ch in self.channels.values() {
            if ch.info.server_root == *server_root {
                targets.extend(ch.roster.iter().copied().filter(|m| *m != me));
            }
        }
        for t in targets {
            let _ = self
                .send_content(&t, Content::Channel(blob.clone()), now_ms)
                .await;
        }
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
                    if gm.sender == me || ch.removed.contains_key(&gm.sender) {
                        continue;
                    }
                    // Roles: drop messages from a member without PERM_SEND
                    // (muted role, announcement channel, …).
                    if self
                        .server_policies
                        .get(&ch.info.server_root)
                        .is_some_and(|p| p.effective_perms(&gm.sender) & roles::PERM_SEND == 0)
                    {
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

    async fn handle_channel_control(
        &mut self,
        from: &[u8; 32],
        blob: &[u8],
        now_ms: u64,
    ) -> Result<(), CoreError> {
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
                            removed: HashMap::new(),
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
                // Never re-key a member we've ejected (guards against a stale
                // bundle that was already in flight when they were removed).
                if self
                    .channels
                    .get(&channel_id)
                    .is_some_and(|ch| ch.removed.contains_key(&member))
                {
                    return Ok(());
                }
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
            ChannelControl::Redeem { token } => {
                let token = crate::invite::InviteToken::decode(&token)?;
                token.verify()?;
                if token.is_expired(now_ms) || token.host_id != self.my_member_id() {
                    return Ok(());
                }
                // We must actually host this channel's server.
                let Some(ch) = self.channels.get(&token.channel_id) else {
                    return Ok(());
                };
                if ch.info.server_root != token.server_root
                    || !self.hosted.contains_key(&token.server_root)
                {
                    return Ok(());
                }
                let used = *self.invite_uses.get(&token.nonce).unwrap_or(&0);
                if token.max_uses != 0 && used >= token.max_uses {
                    return Ok(()); // link is used up — silently ignore
                }
                // `from` is the redeemer's Ed25519 key; channel membership is
                // keyed by IdentityId.
                let Ok(pk) = SignPublic::from_bytes(from) else {
                    return Ok(());
                };
                let redeemer_id = *IdentityId::of(&pk).as_bytes();
                self.invite_uses.insert(token.nonce, used + 1);
                self.dirty = true;
                self.invite_to_channel(&token.channel_id, &redeemer_id, now_ms)
                    .await?;
            }
            ChannelControl::Remove { order } => {
                let order = crate::channel::RemoveOrder::decode(&order)?;
                order.verify()?;
                let me = self.my_member_id();
                if order.member == me {
                    return Ok(()); // a removal of us — nothing to rotate
                }
                let targets = {
                    let Some(ch) = self.channels.get(&order.channel_id) else {
                        return Ok(());
                    };
                    if ch.info.server_root != order.server_root {
                        return Ok(());
                    }
                    // Already applied this removal (or a newer one) for member.
                    if ch
                        .removed
                        .get(&order.member)
                        .is_some_and(|&t| t >= order.issued_ms)
                    {
                        return Ok(());
                    }
                    ch.roster
                        .iter()
                        .copied()
                        .filter(|m| *m != order.member && *m != me)
                        .collect::<Vec<_>>()
                };

                let new_bundle = {
                    let ch = self.channels.get_mut(&order.channel_id).unwrap();
                    ch.removed.insert(order.member, order.issued_ms);
                    ch.roster.remove(&order.member);
                    ch.group.remove_member(&order.member).encode()
                };
                self.dirty = true;

                for t in targets {
                    let kb = ChannelControl::KeyBundle {
                        channel_id: order.channel_id,
                        bundle: new_bundle.clone(),
                    };
                    let _ = self
                        .send_content(&t, Content::Channel(kb.encode()), now_ms)
                        .await;
                }
            }
            ChannelControl::Policy { policy } => {
                let Ok(p) = ServerPolicy::decode(&policy) else {
                    return Ok(());
                };
                if p.verify().is_err() {
                    return Ok(());
                }
                let newer = self
                    .server_policies
                    .get(&p.server_root)
                    .is_none_or(|cur| p.version > cur.version);
                if newer {
                    self.server_policies.insert(p.server_root, p);
                    self.dirty = true;
                }
            }
            ChannelControl::KickRequest { channel_id, member } => {
                let Some(server_root) = self.channels.get(&channel_id).map(|c| c.info.server_root)
                else {
                    return Ok(());
                };
                if !self.hosted.contains_key(&server_root) {
                    return Ok(());
                }
                let Ok(pk) = SignPublic::from_bytes(from) else {
                    return Ok(());
                };
                let requester = *IdentityId::of(&pk).as_bytes();
                if self.member_perms(&server_root, &requester) & roles::PERM_KICK != 0 {
                    self.remove_from_channel(&channel_id, &member, now_ms)
                        .await?;
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
                    if let Err(e) = self.handle_channel_control(&from, &blob, now_ms).await {
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
