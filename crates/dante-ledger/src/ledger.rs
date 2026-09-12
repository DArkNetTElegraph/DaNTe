//! The verifiable append-only log itself.

use std::collections::HashMap;

use dante_crypto::sign::SignPublic;
use dante_identity::{records::IdentityRecord, IdentityId};
use dante_proto::{
    merkle::{self, Hash},
    record::{Record, RecordId, RecordKind, CLOCK_SKEW_MS, RECORD_VERSION},
    TreeHead,
};

use crate::{
    error::LedgerError,
    server::{ServerDelist, ServerRegister},
    tombstone::Tombstone,
};

/// 90 days, in milliseconds (`docs/PROTOCOL.md` §2.3).
pub const IDENTITY_TTL_MS: u64 = 90 * 24 * 60 * 60 * 1000;

/// Network-tunable acceptance parameters.
#[derive(Clone, Copy, Debug)]
pub struct LedgerParams {
    /// Evaporate an identity whose newest activity is older than this.
    pub identity_ttl_ms: u64,
    /// Minimum PoW difficulty (leading zero bits) for an `IdentityAnnounce`.
    pub min_announce_pow_bits: u8,
    /// Minimum PoW difficulty for a `LivenessProof`.
    pub min_liveness_pow_bits: u8,
    /// Minimum Argon2 memory cost (KiB) a PoW proof may claim. Without a floor
    /// a spammer meets the bit target with a trivially cheap Argon2 pass — far
    /// less total work than an honest solver. `0` disables it (dev / tests).
    pub min_pow_m_cost_kib: u32,
    /// Minimum Argon2 time cost a PoW proof may claim. `0` disables it.
    pub min_pow_t_cost: u32,
}

impl Default for LedgerParams {
    fn default() -> Self {
        Self {
            identity_ttl_ms: IDENTITY_TTL_MS,
            min_announce_pow_bits: dante_crypto::pow::REGISTRATION.bits,
            min_liveness_pow_bits: dante_crypto::pow::LIVENESS.bits,
            // The deployed floor tracks the registration puzzle, like the bit
            // floor above. A dev network overrides all of these.
            min_pow_m_cost_kib: dante_crypto::pow::REGISTRATION.m_cost_kib,
            min_pow_t_cost: dante_crypto::pow::REGISTRATION.t_cost,
        }
    }
}

/// Where accepted records are kept, in append order.
pub trait RecordStore {
    /// Number of records stored.
    fn len(&self) -> usize;
    /// Whether the store holds no records.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Borrow the record at `index`.
    fn get(&self, index: usize) -> Option<&Record>;
    /// Append a record (already fully validated by the caller).
    fn push(&mut self, record: Record);
}

/// A `Vec`-backed [`RecordStore`].
#[derive(Default)]
pub struct MemoryStore {
    records: Vec<Record>,
}

impl RecordStore for MemoryStore {
    fn len(&self) -> usize {
        self.records.len()
    }
    fn get(&self, index: usize) -> Option<&Record> {
        self.records.get(index)
    }
    fn push(&mut self, record: Record) {
        self.records.push(record);
    }
}

/// One identity's key-rotation chain.
#[derive(Clone, Debug)]
struct Chain {
    /// First `idk` in the chain — defines the stable [`IdentityId`].
    root_idk: [u8; 32],
    /// Current signing key.
    tip_idk: [u8; 32],
    /// Current X25519 agreement key.
    tip_ik: [u8; 32],
    /// Newest `created_ms` of any announce / liveness / rotation for the chain.
    last_activity_ms: u64,
    /// Set once the chain has been evaporated.
    tombstoned: bool,
    /// Set once the chain's own key has published an `IdentityRevoke`.
    revoked: bool,
    /// The self-asserted display name from the chain's `IdentityAnnounce`
    /// (`display_hint`). Non-unique, untrusted, empty if none was given.
    display_hint: String,
    /// Current global avatar blob hash, or `None`. Set by the newest accepted
    /// `IdentityProfile` record.
    avatar_hash: Option<[u8; 32]>,
    /// Current profile status/bio, or `None`. Set by the newest accepted
    /// `IdentityProfile` record.
    status: Option<String>,
    /// Newest accepted profile-record timestamp. Ordering guard: a profile
    /// record must be strictly newer than the last one, so a replay cannot
    /// roll an avatar back. Deliberately separate from `last_activity_ms` — a
    /// profile update is cheap and must not keep an identity alive.
    profile_ms: u64,
}

impl Chain {
    /// A chain resolves to a usable key only while it is neither evaporated nor
    /// revoked.
    fn usable(&self) -> bool {
        !self.tombstoned && !self.revoked
    }
}

#[derive(Clone, Copy, Debug)]
struct ServerState {
    /// Index into the store of the newest accepted `ServerRegister`.
    record_index: usize,
    /// Newest `ServerRegister` / `ServerDelist` timestamp for this server.
    last_ms: u64,
    /// Withdrawn (by `ServerDelist` or an owner evaporation).
    delisted: bool,
    /// The chain id of `server_root`, if it is also a registered identity.
    owner_chain: Option<usize>,
}

/// The append-only verifiable log.
pub struct Ledger<S: RecordStore = MemoryStore> {
    store: S,
    params: LedgerParams,
    /// `leaf_hash(record.encode())` for every stored record, in order.
    leaves: Vec<Hash>,
    /// `record.id()` -> store index.
    by_id: HashMap<RecordId, usize>,
    /// Every `idk` ever seen (root or rotated-to) -> chain index.
    idk_to_chain: HashMap<[u8; 32], usize>,
    /// `IdentityId` bytes (`SHA-256(root idk)`) -> chain index.
    id_to_chain: HashMap<[u8; 32], usize>,
    chains: Vec<Chain>,
    /// `server_root` -> state.
    servers: HashMap<[u8; 32], ServerState>,
}

impl Default for Ledger<MemoryStore> {
    fn default() -> Self {
        Self::new(MemoryStore::default(), LedgerParams::default())
    }
}

impl<S: RecordStore> Ledger<S> {
    /// A ledger over `store` (which must be empty) with `params`.
    pub fn new(store: S, params: LedgerParams) -> Self {
        assert!(store.is_empty(), "Ledger::new requires an empty store");
        Self {
            store,
            params,
            leaves: Vec::new(),
            by_id: HashMap::new(),
            idk_to_chain: HashMap::new(),
            id_to_chain: HashMap::new(),
            chains: Vec::new(),
            servers: HashMap::new(),
        }
    }

    /// Number of records in the log.
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// The current signed-nothing tree head (size + Merkle root).
    pub fn head(&self) -> TreeHead {
        TreeHead {
            size: self.leaves.len() as u64,
            root: merkle::root(&self.leaves),
        }
    }

    /// Borrow a record by store index.
    pub fn record(&self, index: usize) -> Option<&Record> {
        self.store.get(index)
    }

    /// Inclusion proof for a record id: `(leaf_index, audit_path)`.
    pub fn inclusion_proof(&self, id: &RecordId) -> Option<(usize, Vec<Hash>)> {
        let &index = self.by_id.get(id)?;
        let path = merkle::inclusion_proof(index, &self.leaves)?;
        Some((index, path))
    }

    /// Consistency proof from an earlier size to the current head.
    pub fn consistency_proof(&self, old_size: usize) -> Option<Vec<Hash>> {
        merkle::consistency_proof(old_size, &self.leaves)
    }

    /// Is `idk` part of a chain that is currently usable (neither evaporated
    /// nor revoked)?
    pub fn is_live(&self, idk: &[u8; 32]) -> bool {
        self.chain_of(idk).is_some_and(Chain::usable)
    }

    /// Has `idk`'s chain been permanently revoked by its own key?
    pub fn is_revoked(&self, idk: &[u8; 32]) -> bool {
        self.chain_of(idk).is_some_and(|c| c.revoked)
    }

    /// Newest announce / liveness-proof / key-rotation time for the chain that
    /// contains `idk`. `None` if `idk` is not in any known chain. Drives
    /// inactivity policies (e.g. a server's auto-kick window).
    pub fn last_activity(&self, idk: &[u8; 32]) -> Option<u64> {
        self.chain_of(idk).map(|c| c.last_activity_ms)
    }

    /// The stable [`IdentityId`] for any `idk` in a known chain.
    pub fn identity_id(&self, idk: &[u8; 32]) -> Option<IdentityId> {
        let root = self.chain_of(idk)?.root_idk;
        SignPublic::from_bytes(&root)
            .ok()
            .map(|pk| IdentityId::of(&pk))
    }

    /// The self-asserted display name (`IdentityAnnounce::display_hint`) for the
    /// chain containing `idk`. Non-unique and unverified — a display convenience
    /// only. `None` if unknown or the identity gave no name.
    pub fn display_name(&self, idk: &[u8; 32]) -> Option<&str> {
        self.chain_of(idk)
            .map(|c| c.display_hint.as_str())
            .filter(|s| !s.is_empty())
    }

    /// [`display_name`](Self::display_name) resolved from stable `IdentityId`
    /// bytes (a fingerprint) instead of an `idk`.
    pub fn display_name_by_id(&self, identity_id: &[u8; 32]) -> Option<&str> {
        let &chain_id = self.id_to_chain.get(identity_id)?;
        let s = self.chains[chain_id].display_hint.as_str();
        (!s.is_empty()).then_some(s)
    }

    /// Every known identity that announced a non-empty display name, as
    /// `(IdentityId bytes, name)`. For populating a client's name cache.
    pub fn usernames(&self) -> Vec<([u8; 32], String)> {
        self.id_to_chain
            .iter()
            .filter_map(|(id, &ci)| {
                let s = &self.chains[ci].display_hint;
                (!s.is_empty()).then(|| (*id, s.clone()))
            })
            .collect()
    }

    /// The current global avatar blob hash (SHA-256) for the chain containing
    /// `idk`. `None` if unknown, never set, or cleared.
    pub fn avatar_hash(&self, idk: &[u8; 32]) -> Option<[u8; 32]> {
        self.chain_of(idk).and_then(|c| c.avatar_hash)
    }

    /// [`avatar_hash`](Self::avatar_hash) resolved from stable `IdentityId`
    /// bytes (a fingerprint) instead of an `idk`.
    pub fn avatar_hash_by_id(&self, identity_id: &[u8; 32]) -> Option<[u8; 32]> {
        let &chain_id = self.id_to_chain.get(identity_id)?;
        self.chains[chain_id].avatar_hash
    }

    /// Every known identity that currently has an avatar, as
    /// `(IdentityId bytes, hash)`. For populating a client's avatar cache.
    pub fn avatars(&self) -> Vec<([u8; 32], [u8; 32])> {
        self.id_to_chain
            .iter()
            .filter_map(|(id, &ci)| self.chains[ci].avatar_hash.map(|h| (*id, h)))
            .collect()
    }

    /// The current profile status/bio for the chain containing `idk`.
    pub fn status(&self, idk: &[u8; 32]) -> Option<&str> {
        self.chain_of(idk).and_then(|c| c.status.as_deref())
    }

    /// [`status`](Self::status) resolved from stable `IdentityId` bytes (a
    /// fingerprint) instead of an `idk`.
    pub fn status_by_id(&self, identity_id: &[u8; 32]) -> Option<&str> {
        let &chain_id = self.id_to_chain.get(identity_id)?;
        self.chains[chain_id].status.as_deref()
    }

    /// Every known identity that currently has a status, as
    /// `(IdentityId bytes, text)`. For populating a client's status cache.
    pub fn statuses(&self) -> Vec<([u8; 32], String)> {
        self.id_to_chain
            .iter()
            .filter_map(|(id, &ci)| self.chains[ci].status.as_ref().map(|s| (*id, s.clone())))
            .collect()
    }

    /// The current X25519 agreement key for a live identity named by any `idk`
    /// in its chain.
    pub fn agreement_key(&self, idk: &[u8; 32]) -> Option<[u8; 32]> {
        let c = self.chain_of(idk)?;
        c.usable().then_some(c.tip_ik)
    }

    /// The current signing key (chain tip) for the identity whose stable
    /// [`IdentityId`] bytes are `identity_id` — i.e. resolve a fingerprint to a
    /// usable key. `None` if unknown or evaporated.
    pub fn idk_for_id(&self, identity_id: &[u8; 32]) -> Option<[u8; 32]> {
        let &chain_id = self.id_to_chain.get(identity_id)?;
        let c = &self.chains[chain_id];
        c.usable().then_some(c.tip_idk)
    }

    /// The current signing key (chain tip) for a live identity.
    pub fn tip_key(&self, idk: &[u8; 32]) -> Option<[u8; 32]> {
        let c = self.chain_of(idk)?;
        c.usable().then_some(c.tip_idk)
    }

    /// Discoverable servers, newest registration each.
    pub fn discoverable_servers(&self) -> Vec<ServerRegister> {
        let mut out = Vec::new();
        for state in self.servers.values() {
            if state.delisted {
                continue;
            }
            if let Some(rec) = self.store.get(state.record_index) {
                if let Ok(reg) = ServerRegister::decode(&rec.body) {
                    if reg.discoverable {
                        out.push(reg);
                    }
                }
            }
        }
        out
    }

    fn chain_of(&self, idk: &[u8; 32]) -> Option<&Chain> {
        self.idk_to_chain.get(idk).map(|&i| &self.chains[i])
    }

    fn author_key(record: &Record) -> Result<SignPublic, LedgerError> {
        SignPublic::from_bytes(&record.author).map_err(|_| LedgerError::BadSignature)
    }

    fn push_record(&mut self, record: Record) -> RecordId {
        let id = record.id();
        self.leaves.push(merkle::leaf_hash(&record.encode()));
        self.by_id.insert(id, self.store.len());
        self.store.push(record);
        id
    }

    /// Validate `record` against the current state and, if it is accepted,
    /// append it. `now_ms` is the verifier's wall clock (for the skew check).
    pub fn append(&mut self, record: Record, now_ms: u64) -> Result<RecordId, LedgerError> {
        if record.v != RECORD_VERSION {
            return Err(LedgerError::UnsupportedVersion(record.v));
        }
        if record.created_ms > now_ms.saturating_add(CLOCK_SKEW_MS) {
            return Err(LedgerError::TimestampInFuture {
                created_ms: record.created_ms,
                now_ms,
            });
        }
        if record.kind == RecordKind::Tombstone {
            return Err(LedgerError::TombstoneNotAllowed);
        }
        record
            .verify_signature()
            .map_err(|_| LedgerError::BadSignature)?;

        match record.kind {
            RecordKind::IdentityAnnounce => self.apply_announce(record),
            RecordKind::LivenessProof => self.apply_liveness(record),
            RecordKind::KeyRotation => self.apply_rotation(record),
            RecordKind::ServerRegister => self.apply_server_register(record),
            RecordKind::ServerDelist => self.apply_server_delist(record),
            RecordKind::IdentityRevoke => self.apply_revoke(record),
            RecordKind::IdentityProfile => self.apply_profile(record),
            RecordKind::Tombstone => unreachable!("handled above"),
        }
    }

    fn apply_announce(&mut self, record: Record) -> Result<RecordId, LedgerError> {
        let IdentityRecord::Announce(body) = IdentityRecord::from_record(&record)? else {
            return Err(LedgerError::AuthorMismatch);
        };
        if self.idk_to_chain.contains_key(&record.author) {
            return Err(LedgerError::AlreadyAnnounced);
        }
        body.verify(
            &Self::author_key(&record)?,
            self.params.min_announce_pow_bits,
            self.params.min_pow_m_cost_kib,
            self.params.min_pow_t_cost,
        )?;

        let chain_id = self.chains.len();
        self.chains.push(Chain {
            root_idk: record.author,
            tip_idk: record.author,
            tip_ik: body.ik_pub,
            last_activity_ms: record.created_ms,
            tombstoned: false,
            revoked: false,
            display_hint: body.display_hint.clone(),
            avatar_hash: None,
            status: None,
            profile_ms: 0,
        });
        self.idk_to_chain.insert(record.author, chain_id);
        self.id_to_chain
            .insert(dante_crypto::hash::sha256(&record.author), chain_id);
        Ok(self.push_record(record))
    }

    fn apply_liveness(&mut self, record: Record) -> Result<RecordId, LedgerError> {
        let IdentityRecord::Liveness(body) = IdentityRecord::from_record(&record)? else {
            return Err(LedgerError::AuthorMismatch);
        };
        let &chain_id = self
            .idk_to_chain
            .get(&record.author)
            .ok_or(LedgerError::UnknownIdentity)?;
        let chain = &self.chains[chain_id];
        if chain.tombstoned {
            return Err(LedgerError::IdentityEvaporated);
        }
        if chain.revoked {
            return Err(LedgerError::IdentityRevoked);
        }
        if record.author != chain.tip_idk {
            return Err(LedgerError::NotChainTip);
        }
        if record.created_ms <= chain.last_activity_ms {
            return Err(LedgerError::NonMonotonic);
        }
        body.verify(
            &Self::author_key(&record)?,
            record.created_ms,
            self.params.min_liveness_pow_bits,
            self.params.min_pow_m_cost_kib,
            self.params.min_pow_t_cost,
        )?;

        self.chains[chain_id].last_activity_ms = record.created_ms;
        Ok(self.push_record(record))
    }

    fn apply_rotation(&mut self, record: Record) -> Result<RecordId, LedgerError> {
        let IdentityRecord::KeyRotation(body) = IdentityRecord::from_record(&record)? else {
            return Err(LedgerError::AuthorMismatch);
        };
        if record.author != body.new_idk {
            return Err(LedgerError::AuthorMismatch);
        }
        body.verify()?;

        let &chain_id = self
            .idk_to_chain
            .get(&body.prev_idk)
            .ok_or(LedgerError::UnknownIdentity)?;
        let chain = &self.chains[chain_id];
        if chain.tombstoned {
            return Err(LedgerError::IdentityEvaporated);
        }
        if chain.revoked {
            return Err(LedgerError::IdentityRevoked);
        }
        if body.prev_idk != chain.tip_idk {
            return Err(LedgerError::NotChainTip);
        }
        if record.created_ms <= chain.last_activity_ms {
            return Err(LedgerError::NonMonotonic);
        }
        if self.idk_to_chain.contains_key(&body.new_idk) {
            return Err(LedgerError::KeyAlreadyInUse);
        }

        let chain = &mut self.chains[chain_id];
        chain.tip_idk = body.new_idk;
        chain.tip_ik = body.new_ik;
        chain.last_activity_ms = record.created_ms;
        self.idk_to_chain.insert(body.new_idk, chain_id);
        Ok(self.push_record(record))
    }

    fn apply_revoke(&mut self, record: Record) -> Result<RecordId, LedgerError> {
        let IdentityRecord::Revoke(body) = IdentityRecord::from_record(&record)? else {
            return Err(LedgerError::AuthorMismatch);
        };
        if record.author != body.revoked_idk {
            return Err(LedgerError::AuthorMismatch);
        }
        body.verify()?;

        let &chain_id = self
            .idk_to_chain
            .get(&record.author)
            .ok_or(LedgerError::UnknownIdentity)?;
        let chain = &self.chains[chain_id];
        if chain.tombstoned {
            return Err(LedgerError::IdentityEvaporated);
        }
        if chain.revoked {
            return Err(LedgerError::IdentityRevoked);
        }
        // Only the live chain tip may revoke the chain.
        if record.author != chain.tip_idk {
            return Err(LedgerError::NotChainTip);
        }
        if record.created_ms <= chain.last_activity_ms {
            return Err(LedgerError::NonMonotonic);
        }

        let chain = &mut self.chains[chain_id];
        chain.revoked = true;
        chain.last_activity_ms = record.created_ms;
        for state in self.servers.values_mut() {
            if state.owner_chain == Some(chain_id) {
                state.delisted = true;
            }
        }
        Ok(self.push_record(record))
    }

    fn apply_profile(&mut self, record: Record) -> Result<RecordId, LedgerError> {
        let IdentityRecord::Profile(body) = IdentityRecord::from_record(&record)? else {
            return Err(LedgerError::AuthorMismatch);
        };

        let &chain_id = self
            .idk_to_chain
            .get(&record.author)
            .ok_or(LedgerError::UnknownIdentity)?;
        let chain = &self.chains[chain_id];
        if chain.tombstoned {
            return Err(LedgerError::IdentityEvaporated);
        }
        if chain.revoked {
            return Err(LedgerError::IdentityRevoked);
        }
        // Only the live chain tip may change its chain's public state.
        if record.author != chain.tip_idk {
            return Err(LedgerError::NotChainTip);
        }
        // Strictly newer than the last profile record: an old avatar can never
        // be replayed over a newer one, whatever order records arrive in.
        if record.created_ms <= chain.profile_ms {
            return Err(LedgerError::NonMonotonic);
        }

        let chain = &mut self.chains[chain_id];
        chain.avatar_hash = body.avatar_hash;
        chain.status = body.status;
        chain.profile_ms = record.created_ms;
        Ok(self.push_record(record))
    }

    fn apply_server_register(&mut self, record: Record) -> Result<RecordId, LedgerError> {
        let body = ServerRegister::decode(&record.body)?;
        if record.author != body.server_root {
            return Err(LedgerError::AuthorMismatch);
        }
        body.validate()?;
        // Server roots are throwaway keys, not PoW'd identities, so the record
        // carries its own proof of work — bound to `server_root` alone, so one
        // solve covers every later re-registration.
        dante_crypto::pow::verify(
            &ServerRegister::challenge(&body.server_root),
            &body.pow,
            self.params.min_announce_pow_bits,
            self.params.min_pow_m_cost_kib,
            self.params.min_pow_t_cost,
        )
        .map_err(|_| LedgerError::BadPow)?;

        if let Some(state) = self.servers.get(&body.server_root) {
            if record.created_ms <= state.last_ms {
                return Err(LedgerError::NonMonotonic);
            }
        }
        let owner_chain = self.idk_to_chain.get(&body.server_root).copied();
        let index = self.store.len();
        self.servers.insert(
            body.server_root,
            ServerState {
                record_index: index,
                last_ms: record.created_ms,
                delisted: false,
                owner_chain,
            },
        );
        Ok(self.push_record(record))
    }

    fn apply_server_delist(&mut self, record: Record) -> Result<RecordId, LedgerError> {
        let body = ServerDelist::decode(&record.body)?;
        if record.author != body.server_root {
            return Err(LedgerError::AuthorMismatch);
        }
        let state = self
            .servers
            .get_mut(&body.server_root)
            .ok_or(LedgerError::UnknownServer)?;
        if record.created_ms <= state.last_ms {
            return Err(LedgerError::NonMonotonic);
        }
        state.last_ms = record.created_ms;
        state.delisted = true;
        Ok(self.push_record(record))
    }

    /// Run deterministic evaporation GC at `now_ms`: append a [`Tombstone`] for
    /// every non-evaporated chain whose newest activity is older than
    /// `identity_ttl_ms`, and delist any servers those chains own. Returns the
    /// ids of the tombstone records, in the order appended.
    ///
    /// Deterministic given `(current log, now_ms, params)`: eligible chains are
    /// processed in ascending `root_idk` order, so every honest replica produces
    /// the same suffix.
    pub fn evaporate(&mut self, now_ms: u64) -> Vec<RecordId> {
        let mut eligible: Vec<[u8; 32]> = self
            .chains
            .iter()
            .filter(|c| !c.tombstoned)
            .filter(|c| now_ms.saturating_sub(c.last_activity_ms) > self.params.identity_ttl_ms)
            .map(|c| c.root_idk)
            .collect();
        eligible.sort_unstable();

        let mut ids = Vec::with_capacity(eligible.len());
        for root_idk in eligible {
            let chain_id = self.idk_to_chain[&root_idk];
            self.chains[chain_id].tombstoned = true;
            for state in self.servers.values_mut() {
                if state.owner_chain == Some(chain_id) {
                    state.delisted = true;
                }
            }
            let record = Tombstone {
                subject: root_idk,
                evaporated_ms: now_ms,
            }
            .to_record();
            ids.push(self.push_record(record));
        }
        ids
    }
}

#[cfg(test)]
mod tests {
    use dante_crypto::pow::Difficulty;
    use dante_identity::{
        records::{
            IdentityAnnounce, IdentityProfile, IdentityRevoke, KeyRotation, LivenessProof,
            RevokeReason,
        },
        Identity,
    };
    use dante_proto::merkle;

    use super::*;
    use crate::server::{ServerDelist, ServerRegister, NAME_MAX};

    const D: Difficulty = Difficulty {
        m_cost_kib: 32,
        t_cost: 1,
        bits: 8,
    };

    fn params() -> LedgerParams {
        LedgerParams {
            identity_ttl_ms: 10_000,
            min_announce_pow_bits: 8,
            min_liveness_pow_bits: 8,
            // Tests solve at the tiny `D` cost — no Argon2 floor.
            min_pow_m_cost_kib: 0,
            min_pow_t_cost: 0,
        }
    }

    fn ledger() -> Ledger<MemoryStore> {
        Ledger::new(MemoryStore::default(), params())
    }

    fn announce(id: &Identity, t: u64) -> Record {
        IdentityAnnounce::build(id, "", D).to_record(id, t)
    }

    fn liveness(id: &Identity, t: u64) -> Record {
        LivenessProof::build(id, t, D).to_record(id, t)
    }

    fn profile(id: &Identity, avatar: Option<[u8; 32]>, t: u64) -> Record {
        IdentityProfile::new(avatar, None).to_record(id, t)
    }

    fn profile_with(id: &Identity, avatar: Option<[u8; 32]>, status: &str, t: u64) -> Record {
        let status = (!status.is_empty()).then(|| status.to_owned());
        IdentityProfile::new(avatar, status).to_record(id, t)
    }

    fn server_reg(root: &Identity, discoverable: bool, t: u64) -> Record {
        let server_root = root.sign_public().to_bytes();
        ServerRegister {
            server_root,
            name: "S".into(),
            summary: String::new(),
            tags: vec![],
            entry_relays: vec![],
            discoverable,
            invite: String::new(),
            pow: dante_crypto::pow::solve(&ServerRegister::challenge(&server_root), D),
        }
        .to_record(t, |m| root.sign(m))
    }

    #[test]
    fn announce_then_query() {
        let mut l = ledger();
        let id = Identity::generate(0);
        l.append(announce(&id, 1_000), 1_000).unwrap();

        let idk = id.sign_public().to_bytes();
        assert!(l.is_live(&idk));
        assert_eq!(l.agreement_key(&idk), Some(id.agree_public().to_bytes()));
        assert_eq!(l.identity_id(&idk), Some(id.id()));
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn announce_carries_a_display_name() {
        let mut l = ledger();
        let id = Identity::generate(0);
        l.append(
            IdentityAnnounce::build(&id, "captain", D).to_record(&id, 1_000),
            1_000,
        )
        .unwrap();
        let idk = id.sign_public().to_bytes();
        assert_eq!(l.display_name(&idk), Some("captain"));
        assert_eq!(l.display_name_by_id(id.id().as_bytes()), Some("captain"));
        assert_eq!(l.usernames(), vec![(*id.id().as_bytes(), "captain".into())]);

        // An identity that announced without a name has none.
        let plain = Identity::generate(1);
        l.append(announce(&plain, 2_000), 2_000).unwrap();
        assert_eq!(l.display_name(&plain.sign_public().to_bytes()), None);
        assert_eq!(l.usernames().len(), 1);
    }

    #[test]
    fn profile_sets_updates_and_clears_the_avatar() {
        let mut l = ledger();
        let id = Identity::generate(0);
        l.append(announce(&id, 1_000), 1_000).unwrap();

        l.append(profile(&id, Some([1u8; 32]), 2_000), 2_000)
            .unwrap();
        let idk = id.sign_public().to_bytes();
        assert_eq!(l.avatar_hash(&idk), Some([1u8; 32]));
        assert_eq!(l.avatar_hash_by_id(id.id().as_bytes()), Some([1u8; 32]));
        assert_eq!(l.avatars(), vec![(*id.id().as_bytes(), [1u8; 32])]);

        // A newer profile replaces the avatar.
        l.append(profile(&id, Some([2u8; 32]), 3_000), 3_000)
            .unwrap();
        assert_eq!(l.avatar_hash_by_id(id.id().as_bytes()), Some([2u8; 32]));

        // Clearing removes it.
        l.append(profile(&id, None, 4_000), 4_000).unwrap();
        assert_eq!(l.avatar_hash(&idk), None);
        assert!(l.avatars().is_empty());
    }

    #[test]
    fn profile_status_and_avatar_are_independent_state() {
        let mut l = ledger();
        let id = Identity::generate(0);
        l.append(announce(&id, 1_000), 1_000).unwrap();
        let idk = id.sign_public().to_bytes();
        let idb = *id.id().as_bytes();

        // Status only: no avatar.
        l.append(profile_with(&id, None, "on a walk", 2_000), 2_000)
            .unwrap();
        assert_eq!(l.status(&idk), Some("on a walk"));
        assert_eq!(l.status_by_id(&idb), Some("on a walk"));
        assert_eq!(l.statuses(), vec![(idb, "on a walk".into())]);
        assert_eq!(l.avatar_hash(&idk), None);

        // Avatar and status together.
        l.append(
            profile_with(&id, Some([4u8; 32]), "on a walk", 3_000),
            3_000,
        )
        .unwrap();
        assert_eq!(l.avatar_hash(&idk), Some([4u8; 32]));
        assert_eq!(l.status(&idk), Some("on a walk"));

        // A record is the full profile: the caller patches one field by
        // carrying the other through (dante-core does this). Clearing the
        // avatar leaves the status, and vice versa.
        l.append(profile_with(&id, None, "still here", 4_000), 4_000)
            .unwrap();
        assert_eq!(l.avatar_hash(&idk), None);
        assert_eq!(l.status(&idk), Some("still here"));

        l.append(profile(&id, Some([5u8; 32]), 5_000), 5_000)
            .unwrap();
        assert_eq!(l.avatar_hash(&idk), Some([5u8; 32]));
        assert_eq!(l.status(&idk), None);
        assert!(l.statuses().is_empty());
    }

    #[test]
    fn profile_replay_and_a_rotated_away_key_are_rejected() {
        let mut l = ledger();
        let id = Identity::generate(0);
        l.append(announce(&id, 1_000), 1_000).unwrap();
        l.append(profile(&id, Some([2u8; 32]), 3_000), 3_000)
            .unwrap();

        // Same timestamp is not strictly newer.
        assert!(matches!(
            l.append(profile(&id, Some([1u8; 32]), 3_000), 3_000),
            Err(LedgerError::NonMonotonic)
        ));
        // A replay of an older record is refused, and the newer avatar stands.
        assert!(matches!(
            l.append(profile(&id, Some([1u8; 32]), 2_500), 2_500),
            Err(LedgerError::NonMonotonic)
        ));
        assert_eq!(l.avatar_hash_by_id(id.id().as_bytes()), Some([2u8; 32]));

        // After a rotation only the new tip may update the profile.
        let new = Identity::generate(1);
        l.append(KeyRotation::build(&id, &new).to_record(&new, 4_000), 4_000)
            .unwrap();
        assert!(matches!(
            l.append(profile(&id, Some([3u8; 32]), 5_000), 5_000),
            Err(LedgerError::NotChainTip)
        ));
        assert_eq!(l.avatar_hash_by_id(id.id().as_bytes()), Some([2u8; 32]));
    }

    #[test]
    fn profile_does_not_refresh_activity() {
        // A cheap, PoW-free profile update must not keep an identity from
        // evaporating, or the TTL GC would be trivial to dodge.
        let mut l = ledger();
        let id = Identity::generate(0);
        l.append(announce(&id, 1_000), 1_000).unwrap();
        l.append(profile(&id, Some([1u8; 32]), 20_000), 20_000)
            .unwrap();
        assert_eq!(l.evaporate(20_000).len(), 1);
        assert!(!l.is_live(&id.sign_public().to_bytes()));
    }

    #[test]
    fn profile_after_revoke_or_evaporation_is_rejected() {
        let mut l = ledger();
        let a = Identity::generate(0);
        let b = Identity::generate(1);
        l.append(announce(&a, 1_000), 1_000).unwrap();
        l.append(announce(&b, 1_000), 1_000).unwrap();

        l.append(
            IdentityRevoke::build(&a, RevokeReason::Retired).to_record(&a, 2_000),
            2_000,
        )
        .unwrap();
        assert!(matches!(
            l.append(profile(&a, Some([1u8; 32]), 3_000), 3_000),
            Err(LedgerError::IdentityRevoked)
        ));

        // Params TTL is 10_000 (strictly greater to evaporate).
        l.evaporate(12_000);
        assert!(matches!(
            l.append(profile(&b, Some([1u8; 32]), 13_000), 13_000),
            Err(LedgerError::IdentityEvaporated)
        ));
    }

    #[test]
    fn duplicate_announce_is_rejected() {
        let mut l = ledger();
        let id = Identity::generate(0);
        l.append(announce(&id, 1_000), 1_000).unwrap();
        assert!(matches!(
            l.append(announce(&id, 2_000), 2_000),
            Err(LedgerError::AlreadyAnnounced)
        ));
    }

    #[test]
    fn announce_below_pow_floor_is_rejected() {
        let mut l = Ledger::new(
            MemoryStore::default(),
            LedgerParams {
                min_announce_pow_bits: 24,
                ..params()
            },
        );
        let id = Identity::generate(0);
        assert!(l.append(announce(&id, 1_000), 1_000).is_err());
    }

    #[test]
    fn announce_below_argon2_cost_floor_is_rejected() {
        // Bits met, but the proof was solved with a weaker Argon2 cost than the
        // network's floor — a spammer's cheap grind must not be accepted.
        let mut l = Ledger::new(
            MemoryStore::default(),
            LedgerParams {
                min_pow_m_cost_kib: D.m_cost_kib + 1,
                ..params()
            },
        );
        let id = Identity::generate(0);
        assert!(l.append(announce(&id, 1_000), 1_000).is_err());
        // At/above the floor it is accepted.
        let mut ok = Ledger::new(
            MemoryStore::default(),
            LedgerParams {
                min_pow_m_cost_kib: D.m_cost_kib,
                min_pow_t_cost: D.t_cost,
                ..params()
            },
        );
        ok.append(announce(&Identity::generate(1), 1_000), 1_000)
            .unwrap();
    }

    #[test]
    fn future_timestamp_is_rejected() {
        let mut l = ledger();
        let id = Identity::generate(0);
        let far_future = 10_000_000 + CLOCK_SKEW_MS + 1;
        let rec = announce(&id, far_future);
        assert!(matches!(
            l.append(rec, 10_000_000),
            Err(LedgerError::TimestampInFuture { .. })
        ));
    }

    #[test]
    fn tombstone_cannot_be_appended() {
        let mut l = ledger();
        let rec = Tombstone {
            subject: [1u8; 32],
            evaporated_ms: 5,
        }
        .to_record();
        assert!(matches!(
            l.append(rec, 10),
            Err(LedgerError::TombstoneNotAllowed)
        ));
    }

    #[test]
    fn liveness_flow_and_monotonicity() {
        let mut l = ledger();
        let id = Identity::generate(0);
        l.append(announce(&id, 1_000), 1_000).unwrap();

        l.append(liveness(&id, 2_000), 2_000).unwrap();
        // not strictly newer than last activity
        assert!(matches!(
            l.append(liveness(&id, 2_000), 3_000),
            Err(LedgerError::NonMonotonic)
        ));
        // unknown identity
        let stranger = Identity::generate(0);
        assert!(matches!(
            l.append(liveness(&stranger, 3_000), 3_000),
            Err(LedgerError::UnknownIdentity)
        ));
    }

    #[test]
    fn key_rotation_moves_the_chain_tip() {
        let mut l = ledger();
        let old = Identity::generate(0);
        let new = Identity::generate(0);
        l.append(announce(&old, 1_000), 1_000).unwrap();

        let rot = KeyRotation::build(&old, &new).to_record(&new, 2_000);
        l.append(rot, 2_000).unwrap();

        let old_idk = old.sign_public().to_bytes();
        let new_idk = new.sign_public().to_bytes();
        // both keys resolve to the same identity; tip is the new key
        assert_eq!(l.identity_id(&old_idk), l.identity_id(&new_idk));
        assert_eq!(l.tip_key(&old_idk), Some(new_idk));
        assert_eq!(
            l.agreement_key(&old_idk),
            Some(new.agree_public().to_bytes())
        );

        // liveness must now be signed by the new key
        assert!(matches!(
            l.append(liveness(&old, 3_000), 3_000),
            Err(LedgerError::NotChainTip)
        ));
        l.append(liveness(&new, 3_000), 3_000).unwrap();
    }

    #[test]
    fn key_rotation_rejects_used_key_and_wrong_prev() {
        let mut l = ledger();
        let a = Identity::generate(0);
        let b = Identity::generate(0);
        l.append(announce(&a, 1_000), 1_000).unwrap();
        l.append(announce(&b, 1_000), 1_000).unwrap();

        // rotate a -> b, but b's key is already an identity
        let rot = KeyRotation::build(&a, &b).to_record(&b, 2_000);
        assert!(matches!(
            l.append(rot, 2_000),
            Err(LedgerError::KeyAlreadyInUse)
        ));

        // rotate from an unknown prev
        let ghost = Identity::generate(0);
        let fresh = Identity::generate(0);
        let rot = KeyRotation::build(&ghost, &fresh).to_record(&fresh, 2_000);
        assert!(matches!(
            l.append(rot, 2_000),
            Err(LedgerError::UnknownIdentity)
        ));
    }

    fn revoke(id: &Identity, t: u64) -> Record {
        dante_identity::records::IdentityRevoke::build(
            id,
            dante_identity::RevokeReason::Compromised,
        )
        .to_record(id, t)
    }

    #[test]
    fn revocation_kills_the_chain() {
        let mut l = ledger();
        let id = Identity::generate(0);
        let idk = id.sign_public().to_bytes();
        l.append(announce(&id, 1_000), 1_000).unwrap();
        l.append(server_reg(&id, true, 1_500), 1_500).unwrap();
        assert!(l.is_live(&idk));

        l.append(revoke(&id, 2_000), 2_000).unwrap();

        assert!(l.is_revoked(&idk));
        assert!(!l.is_live(&idk));
        assert_eq!(l.agreement_key(&idk), None);
        assert_eq!(l.idk_for_id(id.id().as_bytes()), None);
        assert_eq!(l.tip_key(&idk), None);
        // the server it hosted is gone from discovery
        assert!(l.discoverable_servers().is_empty());

        // no further records for the chain
        assert!(matches!(
            l.append(liveness(&id, 3_000), 3_000),
            Err(LedgerError::IdentityRevoked)
        ));
        let new = Identity::generate(0);
        assert!(matches!(
            l.append(KeyRotation::build(&id, &new).to_record(&new, 3_000), 3_000),
            Err(LedgerError::IdentityRevoked)
        ));
        assert!(matches!(
            l.append(revoke(&id, 4_000), 4_000),
            Err(LedgerError::IdentityRevoked)
        ));
    }

    #[test]
    fn revoke_requires_a_known_live_chain_tip() {
        let mut l = ledger();
        let stranger = Identity::generate(0);
        assert!(matches!(
            l.append(revoke(&stranger, 1_000), 1_000),
            Err(LedgerError::UnknownIdentity)
        ));

        // after a rotation, only the new tip may revoke
        let old = Identity::generate(0);
        let new = Identity::generate(0);
        l.append(announce(&old, 1_000), 1_000).unwrap();
        l.append(KeyRotation::build(&old, &new).to_record(&new, 2_000), 2_000)
            .unwrap();
        assert!(matches!(
            l.append(revoke(&old, 3_000), 3_000),
            Err(LedgerError::NotChainTip)
        ));
        l.append(revoke(&new, 3_000), 3_000).unwrap();
        assert!(l.is_revoked(&old.sign_public().to_bytes()));
    }

    #[test]
    fn evaporation_is_deterministic_and_ttl_bounded() {
        let mut a = ledger();
        let mut b = ledger();
        let id1 = Identity::generate(0);
        let id2 = Identity::generate(0);
        // Build each record once (PoW nonces are random) and feed both replicas
        // the identical log.
        let a1 = announce(&id1, 1_000);
        let a2 = announce(&id2, 1_000);
        let live = liveness(&id2, 8_000);
        for l in [&mut a, &mut b] {
            l.append(a1.clone(), 1_000).unwrap();
            l.append(a2.clone(), 1_000).unwrap();
            l.append(live.clone(), 8_000).unwrap();
        }

        // now = 1_000 + ttl(10_000) + 5_000 -> id1 evaporates, id2 does not
        let now = 16_000;
        let ids_a = a.evaporate(now);
        let ids_b = b.evaporate(now);
        assert_eq!(ids_a, ids_b, "replicas must produce the same tombstones");
        assert_eq!(ids_a.len(), 1);

        assert!(!a.is_live(&id1.sign_public().to_bytes()));
        assert!(a.is_live(&id2.sign_public().to_bytes()));
        // second sweep is a no-op
        assert!(a.evaporate(now).is_empty());
        // a liveness proof for an evaporated identity is rejected
        assert!(matches!(
            a.append(liveness(&id1, 17_000), 17_000),
            Err(LedgerError::IdentityEvaporated)
        ));
        assert_eq!(a.head().root, b.head().root);
    }

    #[test]
    fn server_registry_and_discovery() {
        let mut l = ledger();
        let root = Identity::generate(0);
        let hidden = Identity::generate(0);

        l.append(server_reg(&root, true, 1_000), 1_000).unwrap();
        l.append(server_reg(&hidden, false, 1_000), 1_000).unwrap();
        assert_eq!(l.discoverable_servers().len(), 1);

        // monotonic
        assert!(matches!(
            l.append(server_reg(&root, true, 1_000), 2_000),
            Err(LedgerError::NonMonotonic)
        ));

        // author mismatch
        let mut bad = server_reg(&root, true, 3_000);
        bad.author = Identity::generate(0).sign_public().to_bytes();
        // re-sign so the envelope check passes but author != body.server_root
        assert!(l.append(bad, 3_000).is_err());

        // delist
        let del = ServerDelist {
            server_root: root.sign_public().to_bytes(),
        }
        .to_record(4_000, |m| root.sign(m));
        l.append(del, 4_000).unwrap();
        assert!(l.discoverable_servers().is_empty());
    }

    #[test]
    fn server_register_rejects_overlong_name() {
        let mut l = ledger();
        let root = Identity::generate(0);
        let server_root = root.sign_public().to_bytes();
        let rec = ServerRegister {
            server_root,
            name: "x".repeat(NAME_MAX + 1),
            summary: String::new(),
            tags: vec![],
            entry_relays: vec![],
            discoverable: true,
            invite: String::new(),
            pow: dante_crypto::pow::solve(&ServerRegister::challenge(&server_root), D),
        }
        .to_record(1_000, |m| root.sign(m));
        assert!(matches!(
            l.append(rec, 1_000),
            Err(LedgerError::FieldTooLong)
        ));
    }

    #[test]
    fn server_register_needs_a_matching_proof_of_work() {
        // Below the bit floor.
        let mut strict = Ledger::new(
            MemoryStore::default(),
            LedgerParams {
                min_announce_pow_bits: 20,
                ..params()
            },
        );
        let root = Identity::generate(0);
        assert!(matches!(
            strict.append(server_reg(&root, true, 1_000), 1_000),
            Err(LedgerError::BadPow)
        ));

        // Right difficulty, but the proof was solved for a different server
        // root — the digest check fails.
        let mut l = ledger();
        let root = Identity::generate(0);
        let server_root = root.sign_public().to_bytes();
        let rec = ServerRegister {
            server_root,
            name: "S".into(),
            summary: String::new(),
            tags: vec![],
            entry_relays: vec![],
            discoverable: true,
            invite: String::new(),
            pow: dante_crypto::pow::solve(
                &ServerRegister::challenge(&[9u8; 32]),
                Difficulty { bits: 16, ..D },
            ),
        }
        .to_record(1_000, |m| root.sign(m));
        assert!(matches!(l.append(rec, 1_000), Err(LedgerError::BadPow)));

        // A correct proof is accepted.
        l.append(server_reg(&Identity::generate(1), true, 2_000), 2_000)
            .unwrap();
    }

    #[test]
    fn evaporation_delists_owned_servers() {
        let mut l = ledger();
        let root = Identity::generate(0);
        l.append(announce(&root, 1_000), 1_000).unwrap();
        l.append(server_reg(&root, true, 1_000), 1_000).unwrap();
        assert_eq!(l.discoverable_servers().len(), 1);

        l.evaporate(1_000 + params().identity_ttl_ms + 1);
        assert!(l.discoverable_servers().is_empty());
    }

    #[test]
    fn merkle_head_inclusion_and_consistency() {
        let mut l = ledger();
        let a = Identity::generate(0);
        let b = Identity::generate(0);

        let r1 = announce(&a, 1_000);
        let id1 = r1.id();
        l.append(r1.clone(), 1_000).unwrap();
        let head1 = l.head();
        assert_eq!(head1.size, 1);

        let r2 = announce(&b, 1_000);
        l.append(r2.clone(), 1_000).unwrap();
        l.append(liveness(&a, 2_000), 2_000).unwrap();
        let head2 = l.head();
        assert_eq!(head2.size, 3);
        assert_ne!(head1.root, head2.root);

        // inclusion of r1 against the current head
        let (idx, path) = l.inclusion_proof(&id1).unwrap();
        assert_eq!(idx, 0);
        assert!(merkle::verify_inclusion(
            idx,
            head2.size as usize,
            &merkle::leaf_hash(&r1.encode()),
            &path,
            &head2.root,
        ));

        // consistency head1 -> head2
        let proof = l.consistency_proof(head1.size as usize).unwrap();
        assert!(merkle::verify_consistency(
            head1.size as usize,
            head2.size as usize,
            &head1.root,
            &head2.root,
            &proof,
        ));
    }
}
