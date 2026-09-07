# DaNTe Protocol Specification

> Status: draft v0 (Phase 0). Wire-breaking changes are allowed freely until the
> first tagged release. Every struct here is versioned; unknown fields are
> rejected, not ignored, unless marked otherwise.

## 0. Conventions

- **Encoding:** all wire structures use an **explicit length-prefixed binary
  codec** owned by `dante-proto` (`enc::Writer` / `enc::Reader`). Integers are
  big-endian and fixed-width; `[u8; N]` is written raw; variable byte strings and
  UTF-8 strings carry a `u32` byte-length prefix; lists carry a `u32` count.
  There is exactly one encoding of a given value — canonical by construction,
  with no dependency on a serializer's canonicalisation behaviour. (Phase 0
  proposed canonical CBOR; replaced in Phase 2 because CBOR canonicalisation is
  an implementation-defined footgun for a signed format.) The local keystore
  file (§1.2) is the one exception and stays CBOR — it is AEAD-sealed, never
  signed, and never compared byte-for-byte across implementations.
- **Hashes:** SHA-256 unless stated. `H(x)` = SHA-256(x). Merkle tree uses
  RFC 6962 domain separation (`0x00` leaf prefix, `0x01` node prefix).
- **Signatures:** Ed25519 over the canonical encoding of the struct with its
  `sig` field omitted entirely (`Record::signing_bytes` = the record encoding up
  to but not including `sig`).
- **Time:** unsigned milliseconds since Unix epoch (`u64`). Clients MUST reject
  timestamps more than `CLOCK_SKEW_MS` (default 300_000) in the future.
- **IDs:**
  - `IdentityId` = `H(ed25519_pubkey_bytes)`, 32 bytes.
  - Fingerprint (display) = Crockford base32 of `IdentityId` in 4-char groups,
    **and** a BIP39 word phrase encoding the same 32 bytes. Both render the same
    value; either can be typed to look a contact up.
  - `ServerId` = `H(server_root_pubkey)`, 32 bytes.
  - `RecordId` = `H(canonical_encoding_of_record)`.

## 1. Identity

### 1.1 Keys

Each identity holds two keypairs, generated together:

| Key | Algorithm | Purpose |
|---|---|---|
| `idk` | Ed25519 | Long-term signing / identity. Signs all ledger records and prekey bundles. |
| `ik`  | X25519  | Long-term key-agreement key (the "identity key" input to X3DH). |

`ik`'s public value is itself signed by `idk` inside `IdentityAnnounce`.

### 1.2 Keystore (on disk, `dante-identity`)

```
KeystoreFile {
  version: u16,               // = 1
  kdf: { alg: "argon2id", m_cost_kib: u32, t_cost: u32, p: u32, salt: [u8;16] },
  nonce: [u8;24],             // XChaCha20-Poly1305
  ciphertext: bytes,          // AEAD-sealed CBOR of KeystoreInner, AAD = version||kdf params
}
KeystoreInner {
  idk_secret: [u8;32],        // zeroized on drop
  ik_secret:  [u8;32],
  created_ms: u64,
  ratchet_db_key: [u8;32],    // key for the local encrypted message store
}
```

Default Argon2id parameters: `m_cost = 262144` KiB (256 MiB), `t_cost = 3`,
`p = 1`. Tunable; parameters travel in the file.

### 1.3 Encrypted key backup (recovery)

Same structure as `KeystoreFile` but sealed with a key derived from a
user-supplied **recovery passphrase** (Argon2id, independent salt). The exported
blob is portable; storing it is the user's responsibility (§5 of the threat
model). Social recovery is a later phase.

## 2. Verifiable log ("the ledger")

The ledger is an append-only multiset of **records**, each self-signed by the
identity (or server root key) it concerns. There is **no global consensus and no
mining**: correctness of a single record is verified by its signature; global
integrity is provided by a Merkle tree over all accepted records and by
consistency proofs between tree states.

### 2.1 Record envelope

```
Record {
  v: u16,                     // schema version, = 1
  kind: u8,                   // see 2.2
  body: bytes,                // enc-encoded kind-specific struct (u32-len-prefixed)
  author: [u8;32],            // ed25519 pubkey of signer
  created_ms: u64,
  sig: [u8;64],               // Ed25519 by `author` over Record{sig: 0}
}
```

Acceptance rules (all MUST pass):
1. `sig` verifies under `author`.
2. `created_ms` within skew bounds.
3. kind-specific validation (2.2) passes.
4. For kinds that supersede a prior record (liveness, key rotation), `created_ms`
   is strictly greater than the newest accepted record of that kind for the same
   subject.

### 2.2 Record kinds

| kind | name | body |
|---|---|---|
| 1 | `IdentityAnnounce` | `{ ik_pub: [u8;32], ik_sig: [u8;64], pow: PowProof, display_hint: string(<=64) }` — `ik_sig` is `idk` over `ik_pub`. `author` = `idk` pubkey. `pow` binds to `H(author || ik_pub)`. |
| 2 | `LivenessProof` | `{ pow: PowProof }` — `pow` binds to `H(author || created_ms_bucket)` where the bucket is `created_ms / LIVENESS_BUCKET_MS`. Re-announces the identity is active. |
| 3 | `KeyRotation` | `{ prev_idk: [u8;32], new_idk: [u8;32], new_ik: [u8;32], new_ik_sig: [u8;64], link_sig: [u8;64] }` — `prev_idk` is the current chain tip being rotated away from (so a verifier can locate the old key in O(1)); `new_ik_sig` is `new_idk` over `new_ik`; `link_sig` is `prev_idk` over `H("dante/key-rotation/link/v1" ‖ prev_idk ‖ new_idk ‖ new_ik)`; `sig`/`author` are the new key. Establishes a verifiable chain across rotation. `IdentityId` is pinned to the *first* `idk` in the chain. |
| 4 | `ServerRegister` | `{ server_root: [u8;32], name: string(<=64), summary: string(<=280), tags: [string](<=8), entry_relays: [Multiaddr](<=8), discoverable: bool }` — signed by `server_root`. Only listed on the discovery page when `discoverable = true`. |
| 5 | `ServerDelist` | `{ server_root: [u8;32] }` — signed by `server_root`; removes a prior `ServerRegister` from discovery. |
| 6 | `Tombstone` | `{ subject: [u8;32], evaporated_ms: u64 }` — node-generated, never accepted through `append`; see §2.3. |
| 7 | `IdentityRevoke` | `{ revoked_idk: [u8;32], reason: u8 }` — `revoked_idk` **must** equal `author`, which **must** be the current chain tip. `reason` is informational (`0` unspecified, `1` compromised, `2` superseded, `3` retired; unknown ⇒ `0`). Accepted only for a known, non-evaporated, non-revoked chain with a strictly-monotonic `created_ms`. Terminal: the chain then takes no further `LivenessProof` / `KeyRotation` / `IdentityRevoke`, resolves to no usable key (`idk_for_id` / `agreement_key` / `tip_key` → `None`, `is_live` → `false`), and any server it hosts is delisted. Irreversible — a revoked chain cannot re-announce (its `idk` is permanently bound). |

`display_hint` / `name` / `summary` are **untrusted, non-unique** strings. They
are never used for lookup or uniqueness — only `IdentityId` / `ServerId` are.

### 2.3 Evaporation (garbage collection)

Deterministic so every honest replica converges:

- An identity is **live** at time `now` iff it has an accepted `IdentityAnnounce`
  and its newest `LivenessProof` (or the `IdentityAnnounce` itself) has
  `created_ms >= now - IDENTITY_TTL_MS`.
- A non-live identity's records are **tombstoned**: replaced in the tree by a
  `Tombstone{ subject, evaporated_ms }` leaf and dropped from active indexes.
  The tree is append-only, so tombstoning is itself an append.
- `ServerRegister` evaporates with its `server_root` identity, or on
  `ServerDelist`, whichever is first.
- A tombstoned identity may re-announce later (new `IdentityAnnounce`, fresh
  PoW). It regains the same `IdentityId` only if it still controls the original
  `idk` chain; otherwise it is a new identity.

Default constants (network parameters, may be tuned by a future governance
record):

| Constant | Default | Meaning |
|---|---|---|
| `IDENTITY_TTL_MS` | 90 days | Max age of newest liveness proof before evaporation. |
| `LIVENESS_BUCKET_MS` | 7 days | PoW-binding bucket; also the minimum useful re-proof cadence. |
| `CLOCK_SKEW_MS` | 5 min | Future-timestamp tolerance. |

### 2.4 Replication & split-view detection

- New records are flooded over a gossipsub topic (`dante/ledger/v0`).
- A joining or re-syncing node fetches ranges via request-response and verifies
  every record.
- Nodes periodically gossip their current `TreeHead { size: u64, root: [u8;32],
  sig_by_self }`. On seeing a peer head, a node requests an **RFC 6962
  consistency proof** between its head and the peer's. Failure to produce a
  consistent proof = that peer is equivocating or faulty → logged, surfaced to
  the user, peer distrusted.

## 3. Proof of Work

```
PowProof { alg: "argon2id-pow", m_cost_kib: u32, t_cost: u32, difficulty: u8, nonce: [u8;16] }
```

Valid iff `Argon2id(pwd = challenge || nonce, salt = challenge[0..16],
m_cost, t_cost, p = 1, out_len = 32)` has at least `difficulty` leading zero
bits, where `challenge` is the kind-specific 32-byte value from 2.2.

- **Registration** (`IdentityAnnounce`): default `difficulty = 20`,
  `m_cost = 65536` KiB.
- **Liveness** (`LivenessProof`): default `difficulty = 16`, `m_cost = 16384`
  KiB — cheap for a human on login, costly across a large fake population every
  `LIVENESS_BUCKET_MS`.
- Relays additionally rate-limit accepted `IdentityAnnounce` per source IP and
  per `/24` to `RELAY_ANNOUNCE_RATE` (default 10 / hour, token-bucket).
- Difficulty values are advisory network parameters; a relay MAY require higher.

## 4. Transport & messaging

### 4.1 libp2p stack

- Transports: QUIC (preferred) and TCP.
- Security: Noise (`XX`).
- Muxing: Yamux (TCP path); QUIC is natively muxed.
- Discovery: Kademlia DHT. DHT keys used:
  - `identity/<IdentityId>` → latest known `Record`s + provider peer IDs.
  - `prekeys/<IdentityId>` → current `PreKeyBundle` (§4.3).
  - `server/<ServerId>` → `ServerRegister` + entry relay addresses.
- Pubsub: gossipsub for `dante/ledger/v0` and per-server topics (later phase).

### 4.2 Sealed-sender envelope

Every stored/forwarded message crosses relays as:

```
Envelope {
  v: u16,                       // = 1
  recipient_hint: [u8;8],       // H(IdentityId || epoch_day)[0..8] — coarse, rotating
  payload: bytes,               // AEAD ciphertext; only the recipient can open
  size_class: u16,              // padded length bucket, not exact length
  deposited_ms: u64,
  ttl_ms: u32,                  // relay drops after this
}
```

`payload` decrypts to `SealedContent { sender: IdentityId, sender_sig: [u8;64],
inner: bytes }` where `inner` is the DM or group ciphertext. The relay never sees
`sender`. `recipient_hint` lets a recipient poll "is there mail for me" without
revealing a stable identifier to the relay across epochs.

### 4.3 1:1 DM (X3DH + Double Ratchet)

`PreKeyBundle` published to the DHT and refreshed by the client:

```
PreKeyBundle {
  identity_id: [u8;32],
  idk_pub: [u8;32],
  ik_pub: [u8;32],
  signed_prekey: { pub: [u8;32], sig: [u8;64], created_ms: u64 },  // sig by idk
  one_time_prekeys: [[u8;32]](<=100),                              // consumed on use
}
```

- **Initiation:** sender runs X3DH against a fetched bundle → initial root key;
  first message carries the used one-time prekey id + sender's ephemeral pub.
- **Ratcheting:** standard Double Ratchet; per-message keys; skipped-message keys
  retained up to `MAX_SKIP` (default 1000) then dropped.
- **File transfer:** file is chunked (`CHUNK = 64 KiB`), each chunk sealed with a
  per-file random XChaCha20-Poly1305 key; the file key + SHA-256 manifest +
  sender Ed25519 signature travel as a normal ratchet message; chunks are stored
  as TTL'd blobs on a relay / DHT provider and referenced by hash.

### 4.4 Groups (servers, channels, group voice)

MLS (RFC 9420) via `OpenMLS`. One MLS group per channel (a private channel is its
own group). Covered in detail in a Phase 6 addendum to this document; Phase 0
fixes only:

- Ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (baseline;
  revisit before Phase 6).
- Membership changes (join/leave/kick) MUST trigger an MLS commit → new epoch.
- Password-gated server: `Argon2id(password, salt = ServerId[0..16], m=262144,
  t=3, p=1)` → 32-byte PSK injected via an MLS `PreSharedKey` proposal; the
  relay also checks a `H(psk)` token before admitting the joiner to the topic.
- Group voice: SRTP keys are exported from the MLS exporter secret
  (`exporter("dante-srtp", channel_id, 32)`); a new epoch = an SRTP rekey.

## 5. Versioning & compatibility

- Every wire struct carries an explicit `v`/`version`. A peer receiving a
  version it does not implement rejects the message and reports an incompatible-
  peer event.
- Pre-1.0: no compatibility guarantees between commits.
- Post-1.0: additive fields require a minor bump and MUST be optional; any change
  to signed-bytes layout requires a major bump and a migration note here.
