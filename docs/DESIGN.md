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

## Current status

**MVP reached.** Working today (all tested; `cargo test` ~158, CI green):

- **Identity** (`dante-crypto`, `dante-identity`): Ed25519 + X25519, Argon2id
  keystore + recovery backup, Crockford-base32 / BIP39 fingerprints, safety
  numbers, `argon2id` PoW, `IdentityAnnounce` / `LivenessProof` / `KeyRotation`.
- **Ledger** (`dante-proto`, `dante-ledger`): explicit binary codec, signed
  `Record` envelope, RFC 6962 Merkle (inclusion + consistency proofs),
  acceptance rules, identity/key-rotation chains, server registry, deterministic
  90-day evaporation GC.
- **Network** (`dante-net`, `dante-relay`): framed-TCP client↔relay protocol,
  sealed-sender `Envelope`, mailbox store-and-forward, prekey directory, file
  blob store, per-IP rate limiting; `dante-relay` binary.
- **E2E DMs** (`dante-dm`): X3DH + Double Ratchet (FS + PCS), chunked encrypted
  file transfer.
- **Groups** (`dante-group`): sender-keys channel ratchet (FS within a chain,
  removed-member lockout, insider-forgery resistance; **no PCS** — MLS migration
  planned).
- **Client**: `dante-core::Engine` + `dante` CLI (`gen` / `fp` / `chat` /
  `serve`). `dante serve` is a localhost browser UI.

- **Persistence** (`dante-core`): encrypted local store — sessions, prekey
  secrets, channel groups, hosted-server root keys, DM history, channel history
  (last 2000 lines), cursors survive a restart; `chat` / `serve` skip the
  announce PoW when recently done. The channel-history section is appended at
  the tail of the store so stores written before it existed still load.
- **Channels** wired end-to-end: `Engine::create_server` / `create_channel` /
  `invite_to_channel` / `send_channel` / `poll_channels`. Invites + sender-key
  exchange ride authenticated DMs (`Content::Channel`); channel messages go to a
  per-`channel_id` relay log (`PostToChannel` / `FetchChannel`, opaque to the
  relay). Every member ends up keyed to every other member, not just the host:
  an invite carries reconstructed bundles for all members the host knows, and a
  member replies with its own bundle the first time it hears a `KeyBundle` from
  a member it did not have. `dante chat`: `/server`, `/channel`, `/invite`,
  `/channels`, `/to #<id>`. The `serve` web UI lists channels as clickable chips, has
  create-server / create-channel / invite controls, and routes the composer to
  a channel or a DM peer (`GET /api/channels`, `POST /api/server` / `/channel` /
  `/invite`, `POST /api/send {to:"#<id>"|fingerprint}`). Verified across a relay
  + host + member, both `chat` and `serve`. Both clients replay stored channel
  history on start.
- **Typing indicators (DM + channel).** `Engine::send_typing_dm` /
  `send_typing_channel` / `poll_typing`; ephemeral, never persisted. They ride a
  new relay *signal* channel — a topic-keyed buffer held ~12 s and never logged
  (`PostSignal` / `FetchSignals`). DM: a fresh sealed-sender envelope (no ratchet
  step) posted to a per-pair topic `SHA-256(domain ‖ sorted idks)`; freshness is
  judged from its AEAD-bound `deposited_ms`. Channel: `Group::seal_signal` AEADs
  the marker under a **static per-member `signal_key`** carried in the
  `SenderKeyBundle` (rotated on member removal), so a typing signal never
  advances the sender-keys message chain; the marker's plaintext prefixes an
  8-byte timestamp for the same freshness rule. `dante serve`: a "broadcast
  when I'm typing" toggle, `GET`/`POST /api/typing`, and the coalescing rule
  (>3 concurrent → "several people are typing…"). `GroupState` gained a
  tail-appended signal-key block so pre-existing stores still load (minting
  fresh keys).

**Not built yet:** roles/permissions, per-server passwords (MLS PSK), invite
links, member removal in the client, private-channel access control beyond the
secret `channel_id`. libp2p/DHT + multi-relay gossip (Phase 3 deferred);
voice/video/screenshare (Phase 7); rich features — reactions, emoji/stickers/
soundboards, bots, discovery UI, embeds (Phase 8); the Tauri desktop client;
MLS migration for channels.

One-time prekeys: the relay hands out one OTP per `GetPrekeys` and shrinks its
stored copy; `Engine::publish_prekeys` refills the client pool to 50 before
each publish and `receive_all` re-publishes after accepting a first-contact,
so the relay stays stocked. If a client is offline while its published pool
drains, first contact falls back to OTP-less X3DH until it next publishes.

**`dante serve` is a throwaway.** It is a hand-rolled HTTP server + a
single-file vanilla-JS page, built only so the engine has a clickable client
that is verifiable headlessly. It polls `/api/messages` every 2 s, so inbound
messages land with up to ~2 s of latency — a real client (Tauri, or a rewrite
with a push transport / SSE / WebSocket) replaces both the transport and the
visual design. Do not invest in its look.

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
- **Done:** chunked encrypted file transfer — `dante_dm::FileManifest`
  (per-file XChaCha20-Poly1305 key, per-chunk nonce, signed manifest of
  ciphertext-chunk hashes), relay `PutBlob`/`GetBlob` TTL'd blob store,
  `Engine::send_file` / `receive_all`, `dante chat /file <path>`.
- **Done:** encrypted local store (`dante_core::store`) — one atomically-rewritten
  file, XChaCha20-Poly1305 under an HKDF of the identity's `ratchet_db_key`,
  holding prekey secrets + every Double Ratchet session + message history +
  the seen-envelope set + announce/fetch cursors. `dante chat` / `dante serve`
  persist on a 15 s timer and on exit, restore on start, replay history, and
  skip the announce PoW when it was done within the day. Not `rusqlite` — a
  single sealed blob; SQLite is a later scale optimisation.
- **Deferred:** petname assignment UI. Safety-number verification exists in
  `dante-identity`; wiring it into a client flow is Phase 5.

### Phase 5 — Client shell  — **MVP**
- **Done (interim):** `dante serve` — the engine behind a tiny localhost
  HTTP UI (embedded single-file SPA + a JSON API: `/api/me`,
  `/api/messages`, `/api/send`). Cross-platform, no system deps, verified
  between two processes. Open `http://127.0.0.1:8080` after
  `dante serve --keystore K --relay ADDR`.
- **Deferred:** the Tauri + SvelteKit desktop client from the plan — its Linux
  build needs `webkit2gtk4.1-devel` / `libsoup3-devel` (not installable in the
  build environment used so far). Onboarding, contact add + safety-number
  verification, and a settings screen are still to build in whichever shell.

**--- MVP boundary: anonymous identity on a verifiable log, key directory via
relay, fully E2E DMs with FS/PCS + file transfer, a usable client, zero project
infrastructure. Reached. ---**

### Phase 6 — Servers & channels  (post-MVP)
- Server = one or more **MLS groups**; creator's client runs the server's relay role.
- Roles/permissions: bitflag capabilities + role hierarchy. Private channel = its own MLS group scoped to a role/user set.
- Public text channels: still MLS-encrypted to *members* (passive non-member relays never see plaintext; the member-host does — matches the trust model). History replication via the server relay + hybrid logical clock ordering.
- Discovery: `ServerRegister` record; private servers simply omit it.
- **Invite links** *(done)*: `InviteToken { server_root, host_id, channel_id, relay_hint, expires_ms, max_uses, nonce, sig }`, signed by the server root key, rendered `dante-invite:<hex>`. `Engine::create_invite_link` mints one; `redeem_invite` verifies it locally then DMs the host a `ChannelControl::Redeem`; the host checks the signature/expiry/use-count (`invite_uses` map, persisted) and runs the normal channel-invite. The relay is never involved. `serve`: `POST /api/invite-link` / `POST /api/redeem`; CLI: `/invitelink` / `/redeem`.
- **Member removal** *(done, manual)*: `Engine::remove_from_channel` (host only) mints a server-root-signed `RemoveOrder { server_root, channel_id, member, issued_ms, sig }`, DMs it to every remaining member, drops the member locally, and rotates its own sender chain + signal key (`Group::remove_member`). Each remaining member verifies the order, does the same, and re-keys the others — O(n). The removed member's cached keys go stale; their messages are dropped (`ChannelSession.removed`, persisted; also guards against a stale in-flight `KeyBundle`). **Re-admitting a removed member is not supported** by the sender-keys scheme — recreate the channel (MLS migration fixes this). `serve`: `POST /api/remove`; CLI: `/kick`.
- **Optional join password:** relay-side check on join + `Argon2id(password)` as an MLS PSK in the group key schedule (content protection, not just gatekeeping).
- **Optional per-server auto-kick** *(done)*: `HostedServer.auto_kick_ms` (opt-in, off by default; `Engine::set_auto_kick`). `Engine::sweep_inactive_members` — run periodically by the client — removes any channel member whose ledger identity has had no announce / liveness-proof / rotation within the window (`Ledger::last_activity`), driving the same `remove_from_channel` rekey. Inactivity is measured against **ledger activity**, not chattiness, so a member active elsewhere in DaNTe is safe. `serve` sweeps every 120 s; `POST /api/autokick {server,days}`; CLI `/autokick <root> <days|off>`.

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
- **Typing indicators.** Ephemeral "is typing" signals, never persisted and
  never written to the channel log. They ride a dedicated relay *signal* channel
  (`PostSignal` / `FetchSignals`): a topic-keyed buffer the relay holds for
  ~12 s, sweeps aggressively, and never logs. **DM typing** —
  `Engine::send_typing_dm` seals a standalone sealed-sender envelope (no ratchet
  step, nothing persisted) and posts it to the per-pair topic
  `SHA-256("dante/typing/dm/v1" ‖ min(idk) ‖ max(idk))`; the receiver judges
  freshness from the envelope's AEAD-bound `deposited_ms`, so the indicator
  clears a few seconds after the last keystroke even while the relay still
  serves the signal. **Channel typing** — `Group::seal_signal` AEADs the marker
  (8-byte timestamp ‖ `Content::Typing`) under a static per-member `signal_key`
  distributed in the `SenderKeyBundle` and rotated on member removal, so it
  never advances the forward-secret message chain; `Engine::send_typing_channel`
  posts the blob to the `channel_id` topic. **Off by default is the intent**;
  the `serve` client ships a
  "broadcast when I'm typing" toggle (currently defaulted on for the demo) that
  gates *sending* — a user who does not broadcast still *sees* others.
  Client-side send rate limit: one signal per 3 s while composing. Receiver
  display / coalescing: one name → "Alice is typing…", two → "A and B…", three →
  "A, B and C…", **more than three concurrent → "several people are typing…"**
  with no names. Best-effort: a dropped or late signal just means the dots do
  not show. Metadata note: a typing signal reveals activity timing to exactly
  the parties that already see message timing (and, for channels, the relay
  sees another entry on the `channel_id` side channel) — hence opt-in.
  Tracked in `THREAT_MODEL.md` §5.

## Cross-cutting
- Reproducible builds + signed releases (users must be able to trust binaries).
- Run the `security-review` skill each phase; external audit before any `stable` tag.
- Crypto code changes always paired with test vectors.

## Verification (MVP)
- Per-crate unit tests; crypto vectors vs Signal / MLS RFC references.
- Property tests (`proptest`) over the wire boundary: every public decoder
  (`dante-proto` `Record`/`Envelope`/codec, `dante-dm` `Content`/`Packet`/
  state snapshots, `dante-group` `GroupMessage`/`SenderKeyBundle`/`GroupState`,
  `dante-net` `Request`/`Response`) is total on arbitrary bytes and canonical
  (decode∘encode is identity); the Double Ratchet and the sender-keys ratchet
  each decrypt an arbitrarily reordered batch exactly once and reject replays.
  `cargo-fuzz` targets on the same decoders are a later add (needs nightly).
- Integration harness: 2–3 `dante-cli` nodes + 1 `dante-relay` locally. Assert the
  full path: identity announce → DHT lookup → X3DH → ratchet exchange →
  offline delivery via relay mailbox → file transfer → key rotation →
  liveness proof → evaporation GC on a simulated +90d clock.
- Manual: two Tauri clients on one machine — add by fingerprint, verify safety
  number, exchange messages + a file, take one offline, send, restart, confirm
  delivery.
