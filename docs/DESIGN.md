# DaNTe (DArkNetTElegraph) — Implementation Plan

## Context

Greenfield (`E:\DaNTe` is empty). Building an open-source, privacy-first,
end-to-end-encrypted, peer-to-peer chat app with Discord-equivalent feature scope.
Core motivations from the user: **no central authority that can spy**,
**anonymity**, and **zero infrastructure budget** — the project itself must run no
permanent servers.

All four architectural forks are now decided (see Decisions). This plan turns
those into a phased build, with a concrete MVP slice: an anonymous identity on a
verifiable log, peer discovery over a DHT, and fully E2E 1:1 direct messages —
achievable with no project-run infrastructure.

## Decisions (locked)

| Area | Decision |
|---|---|
| Topology | **P2P-first.** Project runs nothing. Bootstrap = a few well-known libp2p addrs seeded via DNS/GitHub, swappable. Relay nodes are run by whoever creates a server, for their own community (store-and-forward + later TURN/SFU). Clients join the DHT + gossip mesh. |
| Ledger | **Verifiable append-only log, not a mined blockchain.** Holds identity→pubkey records, liveness proofs, key rotations, and the public server registry (for discovery). Each identity signs its own records (single-writer-per-record — no global consensus). A gossiped Merkle root makes tampering evident. Replicated across relay nodes. |
| Crypto | Primitives: **X25519 + Ed25519** (libsodium). **1:1 DMs:** X3DH + Double Ratchet (forward secrecy + post-compromise security). **Groups (channels + group voice):** **MLS / RFC 9420** via `OpenMLS`. All payload/file encryption is hybrid (random XChaCha20-Poly1305 data key, wrapped). |
| Foundation | **From scratch in Rust.** Reuse crates aggressively (`OpenMLS`, `rust-libp2p`, `webrtc-rs`, `rnnoise`). Element is a UX reference only. Not a Matrix fork — homeservers conflict with "no infra" and server-bound identity. |
| Stack | **Rust core (Cargo workspace) + Tauri client.** Frontend: SvelteKit (recommended for bundle size/simplicity; reversible). |
| Identity | Unique ID = public-key fingerprint, rendered as Crockford base32 **and** a BIP39-style word phrase. Display names = free text, **non-unique**. Petnames for locally-verified contacts (safety-number / QR). Global human-readable aliases deferred to an optional PoW-gated layer. |
| Anti-flood | **PoW to mint an identity + PoW on each liveness proof.** Difficulty tunable by network parameter. Relay per-IP/per-identity rate-limiting on announces as an extra layer. No invite graph (preserves anonymity). |
| Identity liveness (global) | Identity carries a signed + PoW'd **liveness proof** republished ≤ every 90 days (automatic on login). Nodes tombstone + GC the stale **ledger record** — NOT the account; the local keypair survives and re-announces (re-runs PoW) on next login. Bounds ledger growth; core to anti-flood. |
| Per-server auto-kick (separate, optional) | Server-admin setting: remove members inactive *in that server* for X days. **Default off.** Local to the server's membership list; unrelated to the identity ledger. Typical for large public servers, off for private. |
| Per-server password (optional) | Two layers: (1) server relay checks it before admitting a joiner — defeats brute-forced invite links; (2) Argon2id(password) injected into the server's **MLS key schedule as a PSK** — relay operator cannot read group history without it. |
| Invite links | Server-signed capability tokens (optional expiry + max-uses) pointing at entry relays + group ID. Password, if set, is a second factor on top. |
| Recovery (revisit before Phase 1, non-blocking) | Recommended default: exportable **encrypted key-backup file** (passphrase → Argon2id → wrap), Element-SSSS-style. Social recovery deferred. |
| License (user's call) | Recommended **AGPL-3.0** — keeps forks open for a privacy tool. No telemetry, ever. |

## Repository structure to create

```
DaNTe/
  Cargo.toml                 # workspace
  crates/
    dante-crypto/            # X25519/Ed25519, hybrid AEAD, X3DH, Double Ratchet, MLS wrapper (OpenMLS), PoW puzzle
    dante-identity/          # identity keys, fingerprint (base32 + BIP39), safety numbers, encrypted keystore, liveness proof
    dante-ledger/            # Merkle log, record schema, inclusion/consistency proofs, evaporation GC, replication sync
    dante-proto/             # wire types (prost/serde), sealed-sender envelope
    dante-net/               # libp2p: QUIC/TCP + Noise + Yamux, Kademlia DHT, gossipsub, request-response, relay mailbox client
    dante-relay/             # BINARY: relay node — mailbox store-and-forward, ledger replication, rate-limiting
    dante-dm/                # 1:1 sessions: prekey bundles, X3DH, Double Ratchet, chunked file transfer, encrypted SQLite store
    dante-core/              # orchestration engine consumed by the UI (identity + net + ledger + dm)
    dante-cli/               # BINARY: headless client for tests/dev
  client/                    # Tauri app (src-tauri/ Rust commands, src/ SvelteKit frontend)
  docs/
    ARCHITECTURE.md
    THREAT_MODEL.md          # first-class deliverable
    PROTOCOL.md              # wire formats + ledger record schema
  DESIGN.md                  # this plan, promoted into the repo
  .github/workflows/ci.yml   # fmt, clippy, test, cargo-deny
```

## Phased roadmap

### Phase 0 — Foundations & specs
- Cargo workspace skeleton; CI (fmt/clippy/test/`cargo-deny`); AGPL-3.0 license file.
- `docs/THREAT_MODEL.md`: adversaries (passive network observer, malicious relay, malicious server admin, Sybil/flood attacker, compromised endpoint). Protected: DM content, DM metadata (sealed sender), forward secrecy, tamper-evidence of the key directory. **Explicitly not protected:** server-channel content from a member-host, large-scale traffic analysis, endpoint compromise.
- `docs/PROTOCOL.md`: envelope structure, ledger record schema, PoW parameters.

### Phase 1 — Identity & keystore  (`dante-crypto`, `dante-identity`)
- Ed25519 identity key + X25519 agreement key generation.
- Fingerprint: Crockford base32 + BIP39 word phrase; safety-number rendering.
- Encrypted local keystore (Argon2id over private material; OS keychain optional later).
- Registration PoW: memory-hard puzzle (Argon2-based), tunable difficulty parameter.
- Liveness proof: `sign(identity, {ts, nonce, pow})`.
- Encrypted key-backup export/import (recovery default).
- Test vectors: Ed25519/X25519 against RFC vectors.

### Phase 2 — Verifiable ledger  (`dante-ledger`)
- CT-style append-only Merkle log; inclusion + consistency proofs.
- Records: `IdentityAnnounce`, `LivenessProof`, `KeyRotation`, `ServerRegister`, `ServerDelist` — each self-signed by the owning identity.
- Evaporation GC: tombstone + compact identities with newest liveness proof > 90d; deterministic ordering so replicas converge.
- Replication: gossipsub for new records + request-response range sync; Merkle-root gossip for tamper detection.

### Phase 3 — Networking  (`dante-net`, `dante-relay`)
- **Implemented (MVP):** framed-TCP client↔relay request/response protocol
  (`Ping` / `SubmitRecord` / `GetTreeHead` / `GetRecords` / `Deposit` / `Fetch`);
  sealed-sender `Envelope` with day-rotating recipient hint + size-class padding;
  relay `Mailbox` store-and-forward with TTL; per-IP token-bucket rate limiting
  (announce 10/h per §3); relay-side ledger replica + periodic evaporation GC;
  `dante-relay` binary (`--listen`, background maintenance, ctrl-c shutdown).
- **Deferred:** libp2p (QUIC + Noise + Yamux), Kademlia DHT for peer/prekey
  lookup, gossipsub for multi-relay ledger fan-out. The request/response
  protocol is designed to run unchanged over that overlay; until then a client
  syncs the key directory by pulling records from the relay(s) it connects to.

### Phase 4 — E2E 1:1 DMs  (`dante-dm`, `dante-core`, `dante-cli`)  — **MVP**
- **Done:** signed prekey bundles published to the relay; X3DH session init;
  Double Ratchet (per-message keys, skipped-key handling, root/chain management).
- **Done:** `dante-core::Engine` — announce / publish-prekeys / sync / send_dm /
  receive, over the relay; local ledger replica; sealed-sender envelopes;
  inbound dedup. Integration-tested (two engines + in-process relay) and
  demoed live between two `dante` CLI processes over TCP through a relay.
- **Done:** `dante-cli` (`dante gen` / `fp` / `chat`) — a scriptable headless
  client.
- **Deferred:** chunked encrypted file transfer; encrypted local message store
  (`rusqlite`); petname assignment UI. Safety-number verification exists in
  `dante-identity`; wiring it into a client flow is Phase 5.

### Phase 5 — Client shell  (`client/`, Tauri + SvelteKit)  — **MVP**
- Tauri commands bridging `dante-core`.
- MVP screens: onboarding (generate identity → run PoW → back up key), add contact (paste/scan fingerprint → verify safety number), DM conversation, file send/receive, settings.

**--- MVP boundary: anonymous identity on a verifiable log, DHT discovery, fully E2E DMs with FS/PCS + file transfer, zero project infrastructure. ---**

### Phase 6 — Servers & channels  (post-MVP)
- Server = one or more **MLS groups**; creator's client runs the server's relay role.
- Roles/permissions: bitflag capabilities + role hierarchy. Private channel = its own MLS group scoped to a role/user set.
- Public text channels: still MLS-encrypted to *members* (passive non-member relays never see plaintext; the member-host does — matches the trust model). History replication via the server relay + hybrid logical clock ordering.
- Discovery: `ServerRegister` record; private servers simply omit it.
- **Invite links:** server-signed capability tokens (expiry + max-uses), resolve to entry relays + group ID.
- **Optional join password:** relay-side check on join + `Argon2id(password)` as an MLS PSK in the group key schedule (content protection, not just gatekeeping).
- **Optional per-server auto-kick:** admin-set inactivity window (default off); prunes the local membership list only.

### Phase 7 — Voice & media  (post-MVP)
- WebRTC (`webrtc-rs`), DTLS-SRTP. Group voice keys exported from the channel's MLS group; **rekey on every join/leave** (the correct form of the user's "regenerate keys on connect/disconnect").
- SFU role in the server relay above ~5 participants; full mesh below.
- Screen share with audio: VP9 first, then AV1; FHD60 target, HD30 floor, 4K144 a native-only stretch.
  Sources: full display, single window, and "follow the active screen" (see `IDEAS.md`).
- Noise suppression: RNNoise, client-side.

### Phase 8 — Rich features  (post-MVP)
- Reactions incl. custom emoji; per-server emoji/sticker/soundboard blob stores (content-hash referenced); cross-server via a local favorites cache.
- Tenor/Giphy search — opt-in, off by default, warns it contacts a third party.
- URL embeds — opt-in (leaks IP); optionally via a relay-side unfurler.
- Bots: a bot is a normal identity with a per-server capability grant, driven via `dante-core` as a library or a local RPC socket; WASM sandboxing later.
- Custom profiles, per-server nicknames/avatars — stored in the relevant MLS group state.

## Cross-cutting
- Reproducible builds + signed releases (users must be able to trust binaries).
- Run the `security-review` skill each phase; external audit before any `stable` tag.
- Crypto code changes always paired with test vectors.

## Verification (MVP)
- Per-crate unit tests; crypto vectors vs Signal / MLS RFC references.
- Integration harness: 2–3 `dante-cli` nodes + 1 `dante-relay` locally. Assert the
  full path: identity announce → DHT lookup → X3DH → ratchet exchange →
  offline delivery via relay mailbox → file transfer → key rotation →
  liveness proof → evaporation GC on a simulated +90d clock.
- Manual: two Tauri clients on one machine — add by fingerprint, verify safety
  number, exchange messages + a file, take one offline, send, restart, confirm
  delivery.
