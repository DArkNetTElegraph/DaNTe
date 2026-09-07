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
}

impl Default for LedgerParams {
    fn default() -> Self {
        Self {
            identity_ttl_ms: IDENTITY_TTL_MS,
            min_announce_pow_bits: dante_crypto::pow::REGISTRATION.bits,
            min_liveness_pow_bits: dante_crypto::pow::LIVENESS.bits,
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

    /// Is `idk` part of a currently non-evaporated chain?
    pub fn is_live(&self, idk: &[u8; 32]) -> bool {
        self.chain_of(idk).is_some_and(|c| !c.tombstoned)
    }

    /// The stable [`IdentityId`] for any `idk` in a known chain.
    pub fn identity_id(&self, idk: &[u8; 32]) -> Option<IdentityId> {
        let root = self.chain_of(idk)?.root_idk;
        SignPublic::from_bytes(&root)
            .ok()
            .map(|pk| IdentityId::of(&pk))
    }

    /// The current X25519 agreement key for a live identity named by any `idk`
    /// in its chain.
    pub fn agreement_key(&self, idk: &[u8; 32]) -> Option<[u8; 32]> {
        let c = self.chain_of(idk)?;
        (!c.tombstoned).then_some(c.tip_ik)
    }

    /// The current signing key (chain tip) for the identity whose stable
    /// [`IdentityId`] bytes are `identity_id` — i.e. resolve a fingerprint to a
    /// usable key. `None` if unknown or evaporated.
    pub fn idk_for_id(&self, identity_id: &[u8; 32]) -> Option<[u8; 32]> {
        let &chain_id = self.id_to_chain.get(identity_id)?;
        let c = &self.chains[chain_id];
        (!c.tombstoned).then_some(c.tip_idk)
    }

    /// The current signing key (chain tip) for a live identity.
    pub fn tip_key(&self, idk: &[u8; 32]) -> Option<[u8; 32]> {
        let c = self.chain_of(idk)?;
        (!c.tombstoned).then_some(c.tip_idk)
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
        )?;

        let chain_id = self.chains.len();
        self.chains.push(Chain {
            root_idk: record.author,
            tip_idk: record.author,
            tip_ik: body.ik_pub,
            last_activity_ms: record.created_ms,
            tombstoned: false,
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

    fn apply_server_register(&mut self, record: Record) -> Result<RecordId, LedgerError> {
        let body = ServerRegister::decode(&record.body)?;
        if record.author != body.server_root {
            return Err(LedgerError::AuthorMismatch);
        }
        body.validate()?;

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
        records::{IdentityAnnounce, KeyRotation, LivenessProof},
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

    fn server_reg(root: &Identity, discoverable: bool, t: u64) -> Record {
        ServerRegister {
            server_root: root.sign_public().to_bytes(),
            name: "S".into(),
            summary: String::new(),
            tags: vec![],
            entry_relays: vec![],
            discoverable,
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
        let rec = ServerRegister {
            server_root: root.sign_public().to_bytes(),
            name: "x".repeat(NAME_MAX + 1),
            summary: String::new(),
            tags: vec![],
            entry_relays: vec![],
            discoverable: true,
        }
        .to_record(1_000, |m| root.sign(m));
        assert!(matches!(
            l.append(rec, 1_000),
            Err(LedgerError::FieldTooLong)
        ));
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
