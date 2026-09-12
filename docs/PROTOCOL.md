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
4. For kinds that supersede a prior record (liveness, key rotation, identity
   profile), `created_ms` is strictly greater than the newest accepted record
   of that kind for the same subject.

### 2.2 Record kinds

| kind | name | body |
|---|---|---|
| 1 | `IdentityAnnounce` | `{ ik_pub: [u8;32], ik_sig: [u8;64], pow: PowProof, display_hint: string(<=64) }` — `ik_sig` is `idk` over `ik_pub`. `author` = `idk` pubkey. `pow` binds to `H(author || ik_pub)`. |
| 2 | `LivenessProof` | `{ pow: PowProof }` — `pow` binds to `H(author || created_ms_bucket)` where the bucket is `created_ms / LIVENESS_BUCKET_MS`. Re-announces the identity is active. |
| 3 | `KeyRotation` | `{ prev_idk: [u8;32], new_idk: [u8;32], new_ik: [u8;32], new_ik_sig: [u8;64], link_sig: [u8;64] }` — `prev_idk` is the current chain tip being rotated away from (so a verifier can locate the old key in O(1)); `new_ik_sig` is `new_idk` over `new_ik`; `link_sig` is `prev_idk` over `H("dante/key-rotation/link/v1" ‖ prev_idk ‖ new_idk ‖ new_ik)`; `sig`/`author` are the new key. Establishes a verifiable chain across rotation. `IdentityId` is pinned to the *first* `idk` in the chain. |
| 4 | `ServerRegister` | `{ server_root: [u8;32], name: string(<=64), summary: string(<=280), tags: [string](<=8), entry_relays: [Multiaddr](<=8), discoverable: bool, invite: string(<=2048), pow: PowProof }` — signed by `server_root`. Only listed on the discovery page when `discoverable = true`. `pow` binds to `H("dante/pow/server-register/v1" ‖ server_root)` — a server root is a throwaway key, not a PoW'd identity, so mass server creation is priced by this proof; it is solved once and replayed on every later re-registration of the same server. |
| 5 | `ServerDelist` | `{ server_root: [u8;32] }` — signed by `server_root`; removes a prior `ServerRegister` from discovery. |
| 6 | `Tombstone` | `{ subject: [u8;32], evaporated_ms: u64 }` — node-generated, never accepted through `append`; see §2.3. |
| 7 | `IdentityRevoke` | `{ revoked_idk: [u8;32], reason: u8 }` — `revoked_idk` **must** equal `author`, which **must** be the current chain tip. `reason` is informational (`0` unspecified, `1` compromised, `2` superseded, `3` retired; unknown ⇒ `0`). Accepted only for a known, non-evaporated, non-revoked chain with a strictly-monotonic `created_ms`. Terminal: the chain then takes no further `LivenessProof` / `KeyRotation` / `IdentityRevoke`, resolves to no usable key (`idk_for_id` / `agreement_key` / `tip_key` → `None`, `is_live` → `false`), and any server it hosts is delisted. Irreversible — a revoked chain cannot re-announce (its `idk` is permanently bound). |
| 8 | `IdentityProfile` | `{ avatar_hash: opt<[u8;32]> }` — mutable public identity state. `author` **must** be the current chain tip; `avatar_hash` is the SHA-256 of the global avatar image in the relay blob store, or absent to clear it. Accepted only for a known, non-evaporated, non-revoked chain whose newest accepted `IdentityProfile` has a strictly smaller `created_ms` (so an old avatar cannot be replayed over a newer one). Does **not** count as liveness activity — a PoW-free profile update cannot extend an identity's evaporation TTL. |

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

- New records are flooded over a gossipsub topic (`dante/ledger/v1`).
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
- A verifier enforces a **three-axis floor** on every proof: `difficulty`,
  `m_cost_kib` and `t_cost` must each be at least the network's minimum (the
  registration puzzle's parameters by default). Meeting only the bit target
  with a trivially cheap Argon2 pass is a downgrade and is rejected. The
  verifier also caps `m_cost_kib`/`t_cost` at `MAX_VERIFY_M_COST_KIB` /
  `MAX_VERIFY_T_COST` (128 MiB / 8) so a single unauthenticated proof cannot
  drive a multi-GiB allocation or a multi-year hash. A dev network lowers all
  three floors together (`dante-relay --min-pow-bits …`).
- Difficulty values are advisory network parameters; a relay MAY require higher.

## 4. Transport & messaging

### 4.1 libp2p stack

The libp2p layer lives in `dante-p2p` and is compiled in by the `p2p` feature
(**on by default** for `dante-cli` and `dante-relay`; a `--no-default-features`
build is TCP-only with no libp2p tree).

- Transport: **TCP** only. QUIC is not enabled in this phase; bootstrap is by
  `/ip4/.../tcp/N/p2p/<peer-id>` multiaddr (no `/dnsaddr` — the `dns` feature is
  off to avoid a resolver-side DoS advisory).
- Security: **Noise** (`XX`). Muxing: **Yamux**.
- Node identity: an Ed25519 key derived per-device as
  `H("dante/p2p-node-seed/v1" ‖ idk_secret)` — stable across restarts,
  **unlinkable** to the `IdentityId` (the raw idk secret never leaves
  `dante-identity`). A relay's node key is a 32-byte seed from `--p2p-seed`.
- Sub-protocols:
  - `/dante/kad/1.0.0` — Kademlia DHT (`MemoryStore`, `Server` mode).
  - `/dante/p2p/1.0.0` — identify (feeds observed addrs into the Kad table).
  - `/dante/relay/1` — the relay request/response wire (§4.5), length-prefixed
    opaque bytes, 16 MiB frame cap.
  - libp2p ping.
- DHT usage:
  - **Record** `dante/prekey/v1:<IdentityId>` → the current `PreKeyBundle`
    (§4.3). Written by the publisher, used as a fallback when the relay prekey
    directory has no bundle.
  - **Provider** key `dante/relay/v1` (`RELAY_CAPABILITY`) → every relay run
    with `--p2p-listen` advertises itself here; a client with only a bootstrap
    multiaddr discovers the relay set from these provider records.
  - The **ledger is not in the DHT** — it is relay-replicated and gossiped
    (§2.4). There are no `identity/` or `server/` DHT keys.
- Pubsub (gossipsub, signed, strict): see §4.5 for the full topic list.

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

`PreKeyBundle` published to the relay prekey directory (and the DHT as a
fallback, §4.1) and refreshed by the client:

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

MLS (RFC 9420) via `OpenMLS` 0.9. One MLS group per channel and one per group
voice call; a private channel is its own group.

- Ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
- Channels are **host-centric**: only the channel host's Commits are honoured
  (`process_from(_, Some(host_id))`), so members converge on one epoch without
  a consensus round. The relay log frame is tagged `FRAME_APP` (MLS
  application message) or `FRAME_COMMIT` (MLS Commit); a member replays the log
  in `seq` order to catch up to the latest epoch before it may send.
- Each client keeps a small pool of single-use `KeyPackage`s published to the
  relay (`PublishKeyPackages{identity, [kp]}` — one rate-limit charge for the
  batch); the relay hands out the oldest and keeps the last as a reusable
  last-resort. A `KeyPackage` joins exactly one group.
- Membership changes (join/leave/kick) MUST trigger an MLS commit → new epoch.
- Password-gated server: `Argon2id(password, salt = ServerId[0..16], m=262144,
  t=3, p=1)` → 32-byte PSK injected via an MLS `PreSharedKey` proposal; the
  relay also checks a `H(psk)` token before admitting the joiner to the topic.
- Group voice: SRTP keys are exported from the MLS exporter secret
  (`exporter("dante-srtp", channel_id, 32)`); a new epoch = an SRTP rekey.
  An optional **SFrame** layer (Chromium `RTCRtpScriptTransform`) additionally
  AES-GCM-encrypts each Opus frame under a key derived from the per-epoch
  `group_call_key` (`HKDF … info = "dante/sframe/v1"`), so media stays
  end-to-end encrypted through an SFU that only ever sees ciphertext; it
  falls back to pass-through where the browser lacks the API. The mesh path is
  DTLS-SRTP regardless.

### 4.5 Relay wire over libp2p + relay federation (`p2p` feature)

The relay request/response protocol (`dante-net::wire::{Request, Response}`,
the same enum used over plain TCP) also rides a libp2p `/dante/relay/1`
request-response stream, so a client reaches a relay peer-to-peer with no
`host:port`. Per-IP rate limiting still applies: an inbound libp2p request is
bucketed by a synthetic `fd00::/8` address hashed from the peer id.

**Client relay selection** (`--relay dht`, discovering relays from the
`dante/relay/v1` provider records):

- **Idempotent / content-addressed writes** (`Deposit`, `PutBlob`,
  `PublishPrekeys`, `SubmitRecord`) → sent to **every** discovered relay.
- **Mailbox `Fetch`** → queried from every relay, envelopes concatenated
  (the engine de-dups by tag).
- **Channel log** (`PostToChannel`, `FetchChannel`) → **rendezvous-hashed**:
  the relay with the lowest `H(relay_peer_id ‖ channel_id)` gets *all* of that
  channel's reads and writes. Every client computes the same winner, so a
  channel has exactly **one `seq` writer** regardless of how many clients or
  relays are online. A health-maxed relay drops to the back of the hash order,
  so a genuinely dead one fails over to the next relay (which already holds the
  replicated log and continues the `seq`).
- Everything else (single-use key packages, ephemeral signals, ledger reads)
  → one relay, healthiest first, rotate on transport failure.

**Relay ↔ relay federation** (a relay run with `--p2p-listen` +
`--p2p-bootstrap`). Relays in a set replicate to each other so a client on any
one of them sees the whole network. Each accepted item is re-broadcast on its
gossipsub topic and folded on receipt (idempotently — the ledger's own rules,
a SHA-256 envelope-dedup set, latest-wins prekeys, seq-keyed channel frames):

| Topic | Payload | Fold rule |
|---|---|---|
| `dante/ledger/v1` | encoded `Record` | `Ledger::append` (dedups/rejects) |
| `dante/prekey/v1` | encoded `PreKeyBundle` | latest-wins, keyed by leading `IdentityId` |
| `dante/mbox/v1` | encoded `Envelope` | `Mailbox::deposit`, SHA-256 dedup |
| `dante/keypkg/v1` | `IdentityId ‖ last-resort KeyPackage` | adopt only if the follower holds none |
| `dante/chan/<hex channel_id>` | `seq` (LE `u64`) ‖ frame | insert at `seq`; a writer that sees a sibling frame at/past its next slot steps down rather than fork |

On startup a federated relay also pulls the ledger and any already-known
channel logs from each `--p2p-bootstrap` sibling over `/dante/relay/1`
(gossip carries no history). A relay with **no** `--p2p-listen` federates
nothing — its clients' metadata stays with that one operator (THREAT_MODEL
§5.4).

**Relay-assisted bootstrap** (no manual multiaddr exchange):
`Request::AnnounceP2p([multiaddr])` self-reports a client's dial addresses to a
relay (1 h TTL, capped); `Request::GetP2pPeers` returns the operator seed set
first, then fresh self-reports. `--bootstrap` on the CLI merges with the
`DANTE_BOOTSTRAP` env var and a compiled-in `DEFAULT_BOOTSTRAP` (empty until a
network is deployed).

## 5. Versioning & compatibility

- Every wire struct carries an explicit `v`/`version`. A peer receiving a
  version it does not implement rejects the message and reports an incompatible-
  peer event.
- Pre-1.0: no compatibility guarantees between commits.
- Post-1.0: additive fields require a minor bump and MUST be optional; any change
  to signed-bytes layout requires a major bump and a migration note here.
