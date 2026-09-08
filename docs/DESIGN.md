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
| Stack | **Rust core (Cargo workspace) + Tauri desktop shell.** Frontend: the vanilla-JS single-file SPA from `crates/dante-cli/web` (no build step), served by `dante_cli::serve` and loaded by the shell over localhost. |
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
  crates/dante-cli/          # [lib] serve (engine + HTTP/JSON API + embedded SPA) + [bin] dante (gen/fp/chat/serve/revoke)
  apps/dante-desktop/        # Tauri 2 shell — spawns dante_cli::serve, opens a WebviewWindow at it (detached from the workspace)
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
- Records: `IdentityAnnounce`, `LivenessProof`, `KeyRotation`, `ServerRegister`, `ServerDelist`, `IdentityRevoke` — each self-signed by the owning identity.
- **Key revocation** *(done)*: `IdentityRevoke` (kind 7, `{ revoked_idk, reason }`) is a terminal record signed by the chain tip. Once accepted the chain resolves to no usable key everywhere (`is_live` → false, `agreement_key`/`idk_for_id`/`tip_key` → `None`), rejects all later liveness/rotation/revoke records, and delists any server it hosts. `Engine::revoke_identity` / `is_revoked`; `dante revoke --keystore … --relay … [--reason compromised|superseded|retired] --yes`. Irreversible; does not recall already-sent messages; a relay hiding the record from a victim is the split-view problem (see THREAT_MODEL §6).
- Evaporation GC: tombstone + compact identities with newest liveness proof > 90d; deterministic ordering so replicas converge.
- Replication: gossipsub for new records + request-response range sync; Merkle-root gossip for tamper detection.

### Phase 3 — Networking  (`dante-net`, `dante-relay`)
- **Implemented (MVP):** framed-TCP client↔relay request/response protocol
  (`Ping` / `SubmitRecord` / `GetTreeHead` / `GetRecords` / `Deposit` / `Fetch`);
  sealed-sender `Envelope` with day-rotating recipient hint + size-class padding;
  relay `Mailbox` store-and-forward with TTL; per-IP token-bucket rate limiting
  (announce 10/h per §3); relay-side ledger replica + periodic evaporation GC;
  `dante-relay` binary (`--listen`, `--min-pow-bits`, background maintenance,
  ctrl-c shutdown).
- **Client relay resiliency:** `net::Client` holds an ordered list of relay
  endpoints; `request()` transparently reconnects and fails over to the next
  endpoint across a dropped connection (application-level `Peer` errors are
  never retried). `Engine::connect` takes a comma/whitespace-separated
  `--relay` list; the first entry is what invite links and `ServerRegister.
  entry_relays` advertise. Not yet: health-based reordering, or learning new
  endpoints from `entry_relays`.
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
- **Safety-number verification** *(done)*: `Engine::safety_number` derives a
  60-digit pair fingerprint from
  `SHA-512("dante/safety-number/v1" ‖ min(idk) ‖ max(idk))` (order-independent,
  both ends match). `set_verified` / `is_verified` persist the confirmation,
  pinned to the peer `idk` so a key rotation drops it back to unverified.
  `dante chat`: `/safety <fp>`, `/verify <fp> [off]`. `dante serve`:
  `GET /api/safety?peer=` / `POST /api/verify`, with a per-DM shield (🛡️/⚠️)
  and a compare dialog in the SPA.
- **Delete channel / server** *(done, host)*: `Engine::delete_channel` DMs every
  member a server-root-signed `RemoveOrder` with the **all-zeros sentinel
  member** — the `Remove` handler reads that as "the host closed this channel"
  and drops it locally — then removes it from `hosted`. `Engine::delete_server`
  closes every channel that way and publishes a `ServerDelist` (ledger kind 5)
  so the server leaves discovery, then drops the `hosted` entry and its policy.
  `dante chat`: `/delchannel #<chan>`, `/delserver <root>`. `dante serve`:
  `POST /api/channel/delete`, `POST /api/server/delete`; SPA 🗑 buttons for the
  owner (channel header + server pane actions).
- **Leave channel** *(done)*: `ChannelControl::Leave { channel_id }` (tag 7).
  `Engine::leave_channel` DMs it to every other member and drops all local
  state for the channel (and the server policy if no channels remain); the
  host turns it into a self-`Remove` (mint a `RemoveOrder`, O(n) rekey) so
  post-leave messages stay private. A host can't leave its own server this way
  (`delete_channel` is the path). `dante chat`: `/leave #<chan>`.
  `dante serve`: `POST /api/leave {channel}`; SPA 🚪 header button (hidden for
  the owner).
- **Block list** *(done)*: `Engine.blocked` (set of `IdentityId` bytes,
  persisted, local-only). `block` / `unblock` / `is_blocked` / `blocked`.
  Receive-side enforcement: `receive_all` drops the whole envelope from a
  blocked sender, `poll_channels` drops a blocked member's messages,
  `poll_typing` drops their DM + channel typing, and `send_dm` to a blocked
  peer returns `CoreError::Blocked`. `dante chat`: `/block` / `/unblock` /
  `/blocked`. `dante serve`: `GET /api/blocked`, `POST /api/block|unblock`;
  the SPA has a 🚫 header toggle, strikes through blocked DM rows, and hides
  the conversation while blocked.
- **Contacts / petnames** *(done)*: `Engine` keeps a private
  `contacts: {IdentityId -> {petname, added_ms}}` map (persisted, never leaves
  the device). `add_contact` / `remove_contact` / `contacts` (sorted by
  petname) / `petname` / `is_contact`. `dante chat`: `/contact <fp> [petname]`,
  `/contact <fp> remove`, `/contacts`. `dante serve`: `GET /api/contacts`,
  `POST /api/contact {peer,petname}`, `POST /api/contact/remove`; the SPA DM
  list is the union of contacts and message partners, shows petnames and a ✓
  for verified, with a ☆/★ header button to save/edit.

### Phase 5 — Client shell  — **MVP**
- **Done (interim):** `dante serve` — the engine behind a tiny localhost
  HTTP UI (embedded single-file SPA + a JSON API: `/api/me`,
  `/api/messages`, `/api/send`). Cross-platform, no system deps, verified
  between two processes. Open `http://127.0.0.1:8080` after
  `dante serve --keystore K --relay ADDR`.
- **Onboarding *(done)*:** `dante serve` no longer needs a keystore up front.
  With none present, the page shows a create / unlock / import flow —
  `GET /api/state`, `POST /api/onboard {mode,passphrase,blob}`. *create* mints
  an `Identity`, seals a keystore to `--keystore` (default `dante.keystore`),
  returns the recovery-backup blob (hex of `backup::export`) for the user to
  save, and connects the engine; *unlock* opens the existing keystore file
  with a passphrase; *import* accepts a pasted keystore **or** recovery blob.
  `DANTE_PASSPHRASE` still short-circuits to a direct load when set.
- **Desktop shell *(scaffolded)*:** `apps/dante-desktop` — a Tauri 2 crate that
  is a **thin wrapper**, not a rewrite. `crates/dante-cli` now has a `[lib]`
  target exposing `serve::run` / `serve::run_on(existing, listener, boot)` plus
  `now_ms` / `parse_fingerprint`; the desktop `main.rs` binds an ephemeral
  `127.0.0.1` port, spawns `serve::run_on`, and points a native `WebviewWindow`
  at it. So the whole existing web UI + JSON API + onboarding is reused
  verbatim; the desktop build only adds the native layer (window/menus, OS
  notifications, tray, auto-update — TODO). Config via env (`DANTE_HOME`,
  `DANTE_RELAY`, `DANTE_PASSPHRASE`, `DANTE_POW_BITS`), matching `dante serve`.
  The crate is **detached from the workspace** (own `[workspace]`, not a
  member) because Tauri needs `webkit2gtk-4.1` / `libsoup-3` (Linux) /
  WebView2 / WKWebView that the CI container lacks — `cargo build --workspace`
  skips it; build it with `cd apps/dante-desktop && cargo tauri dev` (see its
  README). SvelteKit is no longer planned — the vanilla-JS SPA is the frontend.
- **Still to build in whichever shell:** a settings screen (typing-broadcast
  toggle, relay list editing, identity backup re-download).

**--- MVP boundary: anonymous identity on a verifiable log, key directory via
relay, fully E2E DMs with FS/PCS + file transfer, a usable client, zero project
infrastructure. Reached. ---**

### Phase 6 — Servers & channels  (post-MVP)
- Server = one or more **MLS groups**; creator's client runs the server's relay role.
- **Roles/permissions** *(v1 done)*: `roles::ServerPolicy` — server-root-signed
  `{ owner_id, version, roles: [{id, name, allow, deny, rank}], assignments }`,
  broadcast to members as `ChannelControl::Policy` and verified against the root
  key; members keep the highest `version`. Permissions are allow/deny masks over
  the `@everyone` default (`PERM_SEND` default-on; deny wins, so a full-deny
  role is a mute). Enforcement in this host-centric model: `PERM_SEND` is
  checked by *receivers* in `poll_channels` (a member without it has their
  channel messages dropped); `PERM_KICK` lets a member send
  `ChannelControl::KickRequest`, which the host validates against the policy
  before running the removal. Other bits are advisory (the host performs every
  privileged mutation because only it holds the root key). Host API:
  `set_role` / `delete_role` / `assign_role`; `serve` `POST /api/role` /
  `/api/roleassign` / `GET /api/policy`; CLI `/roles` `/role` `/assignrole`.
  Full role hierarchy and private-channel-per-role-set come with the MLS
  migration.
- Public text channels: still MLS-encrypted to *members* (passive non-member relays never see plaintext; the member-host does — matches the trust model). History replication via the server relay + hybrid logical clock ordering.
- **Discovery** *(done)*: `ServerRegister` (kind 4) gained an `invite` field —
  an unlimited-use `dante-invite:` link the host embeds when it lists a server.
  `Engine::set_discoverable(root, on, summary, tags)` re-submits the signed
  record; `discoverable_servers()` reads the ledger replica; `join_discovered`
  redeems the embedded link (with a join password if the server has one).
  `serve` `GET`/`POST /api/discover`, `POST /api/discover/join`; CLI
  `/discover` `/publish` `/joindisc`. Private servers omit the record entirely.
- **`dante serve` sends a strict CSP** (`default-src 'none'`, same-origin
  `connect-src`, inline script/style only) plus `X-Frame-Options: DENY`,
  `nosniff`, `no-referrer` on every response — an injected string cannot pull
  an external script or exfiltrate cross-origin.
- **Invite links** *(done)*: `InviteToken { server_root, host_id, channel_id, relay_hint, expires_ms, max_uses, nonce, sig }`, signed by the server root key, rendered `dante-invite:<hex>`. `Engine::create_invite_link` mints one; `redeem_invite` verifies it locally then DMs the host a `ChannelControl::Redeem`; the host checks the signature/expiry/use-count (`invite_uses` map, persisted) and runs the normal channel-invite. The relay is never involved. `serve`: `POST /api/invite-link` / `POST /api/redeem`; CLI: `/invitelink` / `/redeem`.
- **Member removal** *(done, manual)*: `Engine::remove_from_channel` (host only) mints a server-root-signed `RemoveOrder { server_root, channel_id, member, issued_ms, sig }`, DMs it to every remaining member, drops the member locally, and rotates its own sender chain + signal key (`Group::remove_member`). Each remaining member verifies the order, does the same, and re-keys the others — O(n). The removed member's cached keys go stale; their messages are dropped (`ChannelSession.removed`, persisted; also guards against a stale in-flight `KeyBundle`). **Re-admitting a removed member is not supported** by the sender-keys scheme — recreate the channel (MLS migration fixes this). `serve`: `POST /api/remove`; CLI: `/kick`.
- **Optional join password** *(gatekeeping done)*: the host stores
  `SHA-256("dante/join-pw/v1" || server_root || password)` (`Engine::
  set_join_password`); an invite-link redemption (`ChannelControl::Redeem`)
  carries the password and the host checks it before admitting the joiner.
  Direct invites bypass it. `POST /api/joinpw`, `/joinpw`. The
  content-protection form (an `Argon2id` PSK woven into the channel key
  schedule so the password is needed to *decrypt*, not just to join) waits for
  the MLS migration — sender-keys has no key schedule to mix it into.
- **Optional per-server auto-kick** *(done)*: `HostedServer.auto_kick_ms` (opt-in, off by default; `Engine::set_auto_kick`). `Engine::sweep_inactive_members` — run periodically by the client — removes any channel member whose ledger identity has had no announce / liveness-proof / rotation within the window (`Ledger::last_activity`), driving the same `remove_from_channel` rekey. Inactivity is measured against **ledger activity**, not chattiness, so a member active elsewhere in DaNTe is safe. `serve` sweeps every 120 s; `POST /api/autokick {server,days}`; CLI `/autokick <root> <days|off>`.

### Phase 7 — Voice & media  (post-MVP)
- **1:1 calls *(done — transport & signalling)*:** `crate/dante-voice` wraps
  `webrtc` 0.21 (`PeerConnection` + a reliable `"dante"` control `DataChannel`,
  DTLS-SRTP). `Call::offer()` / `answer(sdp)` / `set_answer` / `add_ice` /
  `send_ctl` / `next_event` — signalling-agnostic (opaque strings). `dante-core`
  carries the offer/answer/ICE as **sealed-sender ratchet DMs**
  (`Content::CallOffer/CallAnswer/CallIce/CallEnd`, tags 6–9): the SDP holds the
  DTLS fingerprint, so riding a sender-authenticated message is what makes the
  media path E2E — a relay that cannot forge a ratchet DM cannot substitute its
  own DTLS identity. `Engine::start_call` / `accept_call` / `hangup` /
  `poll_calls` (relays locally-gathered ICE) / `call_state`; `Inbound::
  IncomingCall` / `CallEnded`. `dante chat`: `/call` `/answer` `/hangup
  <fp>`. e2e-tested: a call connects to `CallState::Connected` purely over the
  DM path (loopback ICE, no STUN) and the hang-up propagates.
- **NAT traversal *(done — plumbing)*:** `dante-voice::IceServer` +
  `Call::offer_with` / `answer_with(ice)`; `Engine::set_ice_servers` /
  `ice_servers`. The relay advertises them: `Request::GetIceConfig` →
  `Response::IceConfig(Vec<IceCfg>)`, configured with
  `dante-relay --stun URL … --turn URL … --turn-secret STR [--turn-ttl SECS]`.
  TURN credentials are **short-lived** and use the standard coturn
  `use-auth-secret` scheme: `username = "{expiry}"`,
  `credential = base64(HMAC-SHA1(turn-secret, username))` (minted via
  `turn::auth::generate_long_term_credentials`) — so a stock coturn verifies
  them unchanged. `Engine::connect` fetches the config from its relay
  automatically; `dante serve` exposes it at `GET /api/ice`.
- **In-process TURN *(done)*:** `dante-relay --turn-listen HOST:PORT
  [--turn-public-ip IP] --turn-secret STR` runs a TURN server inside the relay
  process (`dante_relay::turn_server::TurnServer` over the `turn` crate,
  `LongTermAuthHandler` + `RelayAddressGeneratorStatic`), and auto-appends
  `turn:<public-ip>:<port>` to the advertised ICE list — one binary, zero-config
  NAT traversal. Operators who already run coturn just skip `--turn-listen` and
  point `--turn` / `--turn-secret` at it. Integration-tested in
  `crates/dante-relay/tests/turn.rs` (auth + datagram relay; forged credential
  refused).
- **Call UI *(done)*:** `dante serve` `GET /api/calls`,
  `POST /api/call|call/accept|call/hangup {peer}`; SPA has a 📞 button, a call
  bar (ringing/calling/connecting/connected + Accept/Hang up) and a corner
  ring toast. No browser media path — the engine owns the peer connection.
- **Audio track *(done — transport)*:** `dante-voice` registers the default
  codecs (Opus, PT 111, 48 kHz) and adds a `TrackLocalStaticSample` to every
  call. `Call::push_audio(opus, ms)` writes one frame; `on_track` →
  `CallEvent::RemoteAudio(payload)`. `Engine::send_call_audio` /
  `take_call_audio` (frames folded by `poll_calls`). e2e-tested: Opus-shaped
  payloads round-trip through SRTP on the negotiated `m=audio` line, in the
  `dante-voice` loopback test and the `dante-core` call test.
- **Mic/speaker *(done — `crates/dante-audio`, detached)*:** `OpusCodec`
  (`opus` → libopus), `Capture` / `Playback` (`cpal`), and a documented bridge
  loop (`Capture::try_frame` → `encode` → `send_call_audio`; `take_call_audio`
  → `decode` → `Playback::play`). Its own `[workspace]` — `opus`/`cpal` link
  system libs the CI container lacks; the Opus round-trip test runs on a real
  host. The desktop client wires this in; `dante serve` has no browser media
  path so its call UI stays state-only.
- **Still to build:** wiring `dante-audio` into a client (Tauri); screen
  share; group calls (MLS-derived media keys).
- Group voice keys exported from the channel's MLS group; **rekey on every join/leave** (the correct form of the user's "regenerate keys on connect/disconnect").
- SFU role in the server relay above ~5 participants; full mesh below.
- Screen share with audio: VP9 first, then AV1; FHD60 target, HD30 floor, 4K144 a native-only stretch.
  Sources: full display, single window, and "follow the active screen" (see `IDEAS.md`).
- Noise suppression: RNNoise, client-side.

### Phase 8 — Rich features  (post-MVP)
- **Emoji reactions** *(done, unicode)*: `Content::Reaction { target_seq,
  emoji, remove }` rides the channel log like a normal message (advances the
  sender chain, same encryption). `poll_channels` folds reactions out of the
  message stream into `Engine::take_reactions()`; `ChannelMessage` gained a
  `seq` so clients can key reactions to a message. `Engine` also folds every
  reaction into a standing `channel_id -> seq -> emoji -> members` map that is
  written to the encrypted local store (the channel log is only re-polled from
  `last_seq`, so a replay would not rebuild it) and re-exposed on restart via
  `Engine::reaction_snapshot()`; `serve` seeds its in-memory view from that at
  boot (`GET /api/reactions`, `POST /api/react`), the SPA renders toggle chips
  under each message. You still cannot react to your own optimistic echo (no
  `seq` until it round-trips).
- **Custom per-server emoji** *(done)*: `ServerPolicy` gained an `emojis:
  Vec<(shortcode, [u8;32])>` tail field (back-compat: only written when
  non-empty, so pre-emoji signatures still verify). `Engine::set_server_emoji`
  `PutBlob`s the image (**unencrypted**, keyed by SHA-256, subject to the
  relay's 7-day blob TTL) and bumps + re-signs + broadcasts the policy;
  `remove_server_emoji`, `server_emojis`, `fetch_blob`. Names are
  `[a-z0-9_]{1..32}`, images ≤ 256 KiB, ≤ 200 per server. `serve`:
  `POST /api/emoji {server,name,image_hex}`, `POST /api/emoji/remove`,
  `GET /api/emoji?hash=` (MIME-sniffed). SPA renders `:shortcode:` in channel
  messages and reaction chips as `<img>`, and a 😀 button uploads/removes.
  `chat`: `/emoji <root> <name> <path|remove>`. Stickers / soundboards still to
  do.
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
