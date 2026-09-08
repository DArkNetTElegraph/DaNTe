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
- **Groups** (`crates/dante-mls`): channels and group calls each run **one MLS
  group** (RFC 9420, via OpenMLS 0.9) — forward secrecy, post-compromise
  security, O(log n) rekey, working re-admission of removed members.
  `Member::{create, publish_key_package, add, remove, encrypt, process,
  process_from}`, `Member::export_key` (per-epoch application secrets:
  group-call media key, channel typing-signal key), `Member::{export, import}`
  (whole-member byte blob for DaNTe's encrypted local state). Workspace MSRV is
  1.91 (OpenMLS's floor); one build-time advisory (`RUSTSEC-2026-0173`,
  unmaintained proc-macro) is allow-listed in `deny.toml`. `dante-group` (the
  old sender-keys ratchet) is retired — kept only for its fuzz target.
- **Channels *(done — MLS)*:** each channel is an MLS group; the server host is
  the sole committer. Membership commits (add / remove) travel in the channel's
  relay log, tagged and interleaved with the encrypted messages, so every
  member applies them in order and converges on one epoch. A joiner gets an MLS
  **Welcome** over an authenticated DM (`ChannelControl::MlsWelcome`) then
  catches up from the log; `process_from(_, Some(host_id))` makes members honour
  commits only from the host. Each client keeps a pool of 12 single-use
  KeyPackages published to the relay (`PublishKeyPackages` / `GetKeyPackage`).
  Persisted as `Member::export()`; a channel whose MLS state can't be restored
  is dropped with a warning.
- **Group calls *(done — 1:1-mesh + MLS key)*:** a channel group call is an
  MLS group for a shared media key (`Engine::group_call_key`, rotates on every
  join/leave) plus a full mesh of the existing 1:1 `Call`s for the media. The
  relay keeps an **MLS KeyPackage directory** (`PublishKeyPackage` /
  `GetKeyPackage`, mirrors the prekey dir). `Engine::start_group_call` creates
  the group, adds every roster member with a published KeyPackage, DMs the
  Welcome (`Content::GroupCallWelcome`), and opens a leg to each (glare-free:
  the lower identity id offers, the higher auto-accepts). `join_group_call` /
  `leave_group_call` (a leaver's `GroupCallLeave` → the lowest-id remaining
  member commits the removal → `GroupCallCommit` fan-out). `dante serve`
  `GET /api/groupcalls`, `POST /api/groupcall/{start,join,leave}`; SPA has a
  📞👥 header button, a group-call bar, and an invite toast. CLI:
  `/groupcall start|join|leave #<channel>`. e2e-tested (three members share one
  key off one Welcome; it rotates when one leaves) and smoke-tested across two
  `dante serve` instances (mesh legs reach `connected`). Media key is not yet
  applied as an SFrame layer — the mesh legs' own DTLS-SRTP protects the audio.
- **Voice channels *(done — persistent, Discord-style)*:** a channel created
  with `voice = true` (`ChannelInfo.voice`, back-compat: a blob without the byte
  decodes as text) has no message log; members join a persistent call in it.
  `Engine::join_voice_channel` starts a solo MLS call directly when the room is
  empty, otherwise sends `Content::GroupCallJoinRequest` (dm tag 21) and sets a
  join-intent flag so the incoming `GroupCallWelcome` auto-joins; the lowest-id
  current participant issues the add Commit. Presence is beaconed through the
  relay signal buffer under `sha256("dante/voice-presence/v1" ‖ channel_id)`,
  sealed per the channel MLS epoch, fresh for 15 s (`send_voice_presence` /
  `voice_participants` / `poll_voice`). `create_voice_channel`,
  `leave_voice_channel`. `dante serve`: `GET /api/voice`,
  `POST /api/voice/{join,leave}`, `voice:` on `POST /api/channel`; the SPA lists
  voice channels under their own header with a nested participant list and shows
  a room view with a Join / Disconnect button. CLI: `/vchannel <root> <name>`,
  `/vc join|leave #<chan>`. e2e-tested (two members connect off one Welcome and
  see each other in presence).
- **Voice-channel audio *(done — browser WebRTC)*:** unlike 1:1 calls, the SPA
  itself owns the media. Joining captures the mic with `getUserMedia` and builds
  a full mesh of browser `RTCPeerConnection`s (one per other participant; the
  lower fingerprint offers). `dante serve` only relays signalling —
  `Content::VoiceSignal` (dm tag 22: offer / answer / ICE / bye),
  `Engine::send_voice_signal`, `Inbound::VoiceSignal`, `POST /api/voice/signal`,
  and a `voicesignal` stream item. Presence still rides the engine beacon so the
  mesh knows who to dial. Room view has a mic-mute toggle and a per-peer live
  dot. STUN comes from `/api/ice`; TURN isn't wired (creds aren't exposed), so
  it's localhost / same-LAN until a browser TURN path lands.
- **Voice bitrate *(done — ≥64 kbps)*:** all voice comms (1:1 calls + group /
  voice channels) target ≥64 kbps Opus. `dante-voice` munges the outbound SDP
  fmtp for the Opus payload (`maxaveragebitrate=64000`, `useinbandfec=1`,
  `stereo=1`) on the copy handed to the peer only — webrtc-rs rejects a SDP that
  does not match the one given to `set_local_description`. `dante-audio`'s
  `OpusCodec` sets the encoder to 64 kbps with inband FEC and a 10% loss hint.
- **Channel rename + #general *(done)*:** `ChannelControl::Renamed` (tag 9),
  host-signed, updates every member's display name (`Engine::rename_channel`,
  `POST /api/channel/rename`, `/renamechannel`). Every server is created with a
  `#general` text channel that can't be renamed or deleted; the create-server
  flow asks for a join password instead of a first channel name, and changing
  a join password requires the current one.
- **SPA context menus *(done)*:** the browser's right-click menu is suppressed
  inside `#app` and replaced with CSS menus — channel rows (rename / delete /
  leave / mute / copy id) and messages (reply / edit / delete / pin / forward /
  copy). The chat header's icon row collapses under a `⋯` button.
- **Usernames *(done)*:** registration asks for a username; it rides the
  `IdentityAnnounce.display_hint` (already in the record, now surfaced) so it
  propagates over the ledger. `Ledger::{display_name, display_name_by_id,
  usernames}`, `Engine::{my_username, username_of, known_usernames}`,
  `POST /api/onboard {username}`, `GET /api/usernames`, `GET /api/me.username`.
  Non-unique, unverified — a display convenience. The SPA resolves a name as
  petname → username → block-id prefix, and the bottom-left chip shows the
  username big with the block-id small beneath it.
- **Emoji *(done)*:** channels no longer take a password (only a whole server
  has a join password — dropped from `POST /api/channel`, `Cmd::CreateChannel`,
  the `/channel` CLI arg, and the SPA modal). Reactions and the composer use a
  categorised emoji picker (`openEmojiPicker`, phone-keyboard style) instead of
  a text field; the composer's emoji button sits opposite the file-attach
  button. Custom server emoji: PNG/JPEG only, ≤1 MiB (magic-byte checked in
  `Engine::set_server_emoji`), rendered inline at `--emoji-size` (20px). UI
  chrome uses inline monochrome stroke icons (`ICONS`/`svgIcon`/`paintIcons`,
  `data-icon` attrs); emoji now appear only in message content, reactions, and
  the picker.
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
  judged from its AEAD-bound `deposited_ms`. Channel: the marker is XChaCha20-
  Poly1305-sealed under a key derived from the channel MLS group's current
  epoch (`Member::export_key("dante/channel-signal/v1", …)`), framed
  `member(32) ‖ nonce(24) ‖ ct`, so it never touches the message log; its
  plaintext prefixes an 8-byte timestamp for the same freshness rule.
  `dante serve`: a "broadcast when I'm typing" toggle, `GET`/`POST /api/typing`,
  and the coalescing rule (>3 concurrent → "several people are typing…").

**Not built yet:** private-channel access control beyond the secret
`channel_id` + password wrapper. Gossipsub fan-out of the ledger + channel
logs (the libp2p DHT is wired in as an opt-in key-directory fallback — feature
`p2p`; see Phase 3); screen share + an SFrame layer over the group-call key
(Phase 7); rich features — stickers/soundboards, bots, embeds (Phase 8);
the Tauri desktop native layer.

One-time prekeys: the relay hands out one OTP per `GetPrekeys` and shrinks its
stored copy; `Engine::publish_prekeys` refills the client pool to 50 before
each publish and `receive_all` re-publishes after accepting a first-contact,
so the relay stays stocked. If a client is offline while its published pool
drains, first contact falls back to OTP-less X3DH until it next publishes.

**`dante serve` is the interim client.** A hand-rolled HTTP server + a
single-file vanilla-JS page (no build step), so the engine has a real client
that is also verifiable headlessly; the Tauri shell loads the same page. Inbound
items arrive over a Server-Sent-Events stream (`GET /api/stream?since=N` — a
server-side tail of the inbox, ~150 ms latency); a slow `GET /api/messages` poll
is the fallback when the stream drops. The stylesheet is token-driven
(`:root` custom properties, an elevation/`--radius`/`--shadow` scale, a modern
system font stack, `color-mix()` tints) and theme-aware — dark by default, with
a light palette under `prefers-color-scheme` and `[data-theme]`, and a
`prefers-reduced-motion` opt-out.

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
- **`crates/dante-p2p`** — a `Node` over a libp2p Swarm: TCP + Noise + Yamux,
  Kademlia (memory store, DaNTe-private `/dante/kad/1.0.0` protocol, server
  mode) for `put_record`/`get_record`, gossipsub for `publish`/`subscribe`,
  identify feeding addresses into the kad routing table, ping for liveness.
  Driven by a background Tokio task behind a command channel + `Event` stream.
  It is a **workspace member but not a default one** (`default-members` omits
  it), so a bare `cargo build` / `cargo test` never pulls the libp2p tree;
  `--workspace` and `-p dante-p2p` do. `deny.toml` carries an
  `advisories.ignore` for `paste` (RUSTSEC-2024-0436, unmaintained, build-time
  proc-macro from the `netlink`/`if-watch` stack `libp2p-tcp` needs on Linux);
  `licenses`/`bans` are clean. The `dns` feature is left off to avoid
  `hickory-proto` 0.25's DoS advisory (bootstrap peers are IP multiaddrs).
- **DHT key-directory fallback** *(done, opt-in — `dante-core` feature `p2p`)*:
  `Identity::p2p_node_seed()` derives a stable libp2p node key from the signing
  secret through a hash (the `PeerId` doesn't leak the identity key).
  `Engine::enable_p2p(listen, bootstrap)` spawns the node, dials the bootstrap
  multiaddrs and runs a Kademlia bootstrap round; `publish_prekeys` then
  mirrors the bundle onto the DHT under `"dante/prekey/v1:" ‖ IdentityId`, and
  `send_content`'s first-contact path (`fetch_prekey_bundle`) falls back to a
  DHT `get_record` when the relay has no bundle. The relay stays primary and
  remains the only sealed-sender mailbox. `dante chat` / `dante serve` (built
  `--features p2p`) take `--p2p` / `--p2p-listen <multiaddr>` /
  `--bootstrap <a,b>`. e2e: `the_dht_serves_as_a_prekey_directory_fallback`
  (two engines, one resolves the other's bundle purely over the DHT).
- **Relay-assisted bootstrap** *(done, opt-in — feature `p2p`)*: no manual
  multiaddr exchange needed. `Request::AnnounceP2p(Vec<String>)` /
  `Request::GetP2pPeers` → `Response::P2pPeers`: `enable_p2p` asks its relay for
  known libp2p bootstrap addresses (operator-seeded via
  `dante-relay --p2p-bootstrap`, plus recently self-reported by other clients —
  bounded to 64, 1-hour TTL) and dials them, then reports its own dialable
  addresses back; `poll_p2p` refreshes that every ~10 min. So a `--p2p` client
  finds the mesh through the relay it already talks to. e2e: the DHT-fallback
  test now has the second engine discover the first purely via `GetP2pPeers`.
- **Ledger gossip** *(done, opt-in — feature `p2p`)*: `announce` /
  `prove_liveness` / `revoke_identity` also publish the encoded record to the
  `dante/ledger/v1` gossipsub topic; `Engine::poll_p2p(now)` (driven each tick
  by `serve` / `chat`) folds records heard from peers into the local replica
  via `ledger.append` (rejections — dups, out-of-order liveness — are dropped).
  So a client can learn a brand-new peer's identity, and revocations, from the
  mesh before its next relay `sync`. To make this safe, the relay-sync cursor
  is now an explicit `Engine::relay_ledger_cursor` (was `ledger.len()`) and
  `sync::pull_records` returns the relay-log position to resume from — gossip
  appends no longer make `sync` skip relay records. e2e
  `a_peer_learns_an_identity_from_ledger_gossip`.
- **Still deferred:** gossipsub fan-out of channel MLS logs (channel delivery
  leans on the relay's ordered per-channel log); learning relay endpoints from
  `entry_relays`; health-based relay reordering.

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
  `Engine::send_file` / `receive_all`, `dante chat /file <path>`. `dante serve`:
  `POST /api/file?to=<fp>&name=<file>` (raw body = bytes, ≤ 9 MiB, DMs only);
  the SPA has a 📎 button plus drag-and-drop and image-paste on the composer.
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
  member a `ChannelControl::Closed { channel_id }` — recipients verify it came
  from the recorded `host_id` and drop the channel — then removes it from
  `hosted`. `Engine::delete_server`
  closes every channel that way and publishes a `ServerDelist` (ledger kind 5)
  so the server leaves discovery, then drops the `hosted` entry and its policy.
  `dante chat`: `/delchannel #<chan>`, `/delserver <root>`. `dante serve`:
  `POST /api/channel/delete`, `POST /api/server/delete`; SPA 🗑 buttons for the
  owner (channel header + server pane actions).
- **Leave channel** *(done)*: `ChannelControl::Leave { channel_id }`.
  `Engine::leave_channel` DMs it to the host and drops all local state for the
  channel (and the server policy if no channels remain); the host commits an
  MLS remove of the leaver so post-leave messages stay private. A host can't
  leave its own server this way
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
- **Settings screen** *(done)*: a ⚙ overlay in the SPA — Identity (recovery
  phrase), Appearance (light/dark/auto theme), Behaviour (typing-broadcast
  toggle, desktop-notification permission), Network (relay list, read-only),
  Danger zone (revoke identity). `GET /api/state` returns the relay list;
  `POST /api/revoke {reason,confirm}` + CLI `dante revoke`.

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
- **Invite links** *(done)*: `InviteToken { server_root, host_id, channel_id, relay_hint, expires_ms, max_uses, nonce, sig }`, signed by the server root key, rendered `dante-invite:<hex>`. `Engine::create_invite_link` mints one; `redeem_invite` verifies it locally then DMs the host a `ChannelControl::Redeem`; the host checks the signature/expiry/use-count (`invite_uses` map, persisted), fetches the redeemer's MLS KeyPackage, and runs the normal channel add. The relay only stores KeyPackages. `serve`: `POST /api/invite-link` / `POST /api/redeem`; CLI: `/invitelink` / `/redeem`.
- **Member removal** *(done — MLS)*: `Engine::remove_from_channel` (host only) commits an MLS remove of the member's leaf and posts the Commit to the channel log. Every remaining member applies it (O(log n) rekey); the removed member sees the Commit, learns it is evicted, and drops the channel. `ChannelSession.removed` still tombstones the ex-member so their already-cached backlog is hidden. **Re-admitting** a removed member now works — the host just adds them again with a fresh KeyPackage. `serve`: `POST /api/remove`; CLI: `/kick`.
- **Optional join password** *(gatekeeping done)*: the host stores
  `SHA-256("dante/join-pw/v1" || server_root || password)` (`Engine::
  set_join_password`); an invite-link redemption (`ChannelControl::Redeem`)
  carries the password and the host checks it before admitting the joiner.
  Direct invites bypass it. `POST /api/joinpw`, `/joinpw`.
- **Password-protected channels** *(content protection done)*:
  `create_channel(…, password)` derives `log_key = Argon2id(password; salt =
  "dante/channel-content/v1" || server_root || channel_id)` and wraps **every**
  relay-log frame (MLS app messages *and* Commits) in an outer
  XChaCha20-Poly1305 layer (`channel::{derive_log_key, wrap, unwrap}`). So a
  holder of just the 32-byte `channel_id` — the shared capability, visible to
  the relay — cannot read the log without the password. The host ships
  `log_key` to each joiner inside `ChannelControl::MlsWelcome` (E2E, and only
  after the `Redeem` password check). `ChannelSession.log_key` /
  `StoredChannel.log_key` persisted. `POST /api/channel {…, password}`; SPA
  create-channel modal has a password field; CLI `/channel <root>
  <name>[ | <password>]`. Not the same as weaving the PSK into the MLS key
  schedule (a possible future hardening) — this is an outer wrapper, so the
  key is static per `(channel, password)` and rotating the password means
  re-distributing it.
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
  host. `dante serve` has no browser media path so its call UI stays
  state-only.
- **Desktop mic/speaker *(done)*:** `apps/dante-desktop/src/audio.rs` — a
  dedicated thread (`cpal::Stream` is `!Send`) that, whenever a call is
  `connected`, captures + Opus-encodes with `dante-audio` and exchanges frames
  with the co-hosted `dante-cli` service over `POST` / `GET /api/call/audio`
  (the `POST` grew a `frames_hex: [..]` batch form so a burst flushes in one
  round-trip). It drives **every** `connected` leg — one for a 1:1 call, the
  whole mesh for a group call — encoding the mic once and playing a summed mix
  of the per-leg decoders. `dante-audio` is a dependency of the (detached)
  desktop crate, never of `dante-cli`, so the CI gate never links libopus/cpal.
- **Still to build:** screen share; an SFrame layer that applies
  `group_call_key` to the media so an SFU can forward without decrypting; the
  channel-messaging MLS migration (group calls already use MLS).
- Group voice keys exported from the channel's MLS group; **rekey on every join/leave** (done — `Engine::group_call_key`).
- SFU role in the server relay above ~5 participants; full mesh below (mesh done).
- Screen share with audio: VP9 first, then AV1; FHD60 target, HD30 floor, 4K144 a native-only stretch.
  Sources: full display, single window, and "follow the active screen" (see `IDEAS.md`).
- Noise suppression: RNNoise, client-side.

### Phase 8 — Rich features  (post-MVP)
- **Emoji reactions** *(done, unicode)*: `Content::Reaction { target_seq,
  emoji, remove }` rides the channel log like a normal message (an MLS
  application message, same as text). `poll_channels` folds reactions out of the
  message stream into `Engine::take_reactions()`; `ChannelMessage` gained a
  `seq` so clients can key reactions to a message. `Engine` also folds every
  reaction into a standing `channel_id -> seq -> emoji -> members` map that is
  written to the encrypted local store (the channel log is only re-polled from
  `last_seq`, so a replay would not rebuild it) and re-exposed on restart via
  `Engine::reaction_snapshot()`; `serve` seeds its in-memory view from that at
  boot (`GET /api/reactions`, `POST /api/react`), the SPA renders toggle chips
  under each message.
- **Edit / delete channel messages** *(done)*: `Content::Edit { target_seq,
  text }` / `Content::Delete { target_seq }` ride the channel log like
  reactions. Only the recorded author's change is applied (`channel_edits`
  map, persisted; `take_edits` / `edit_snapshot` mirror the reaction path).
  `PostToChannel` now answers `Response::Posted(seq)` so `send_channel`
  returns the relay-log seq — the sender's handle to its own message, which
  never comes back through `poll_channels`. `serve` `POST /api/edit
  {channel,seq,text}` (empty text deletes); own sent messages now carry a
  real `ref_seq`; the SPA folds the edit in, shows `(edited)` / `(message
  deleted)`, and hover ✎/🗑 on your own lines. CLI `/edit` `/delete`. Same
  restart caveat as reactions (authorship of a pre-restart message isn't
  re-derivable).
- **Replies** *(done)*: `Content::Reply { target_seq, text }` rides the channel
  log — an ordinary editable/deletable message that also carries the `seq` it
  answers. `ChannelMessage.reply_to: Option<u64>`;
  `Engine::send_channel_reply`. `serve` `POST /api/send` takes an optional
  `reply_to`; the SPA has a ↩ hover action → a reply bar over the composer and
  a quoted line above the reply; CLI `/reply #<chan> <seq> <text>`.
- **Edit / delete direct messages** *(done)*: a text DM now travels as
  `Content::TextId { text, id }` (tag 17) with a random 16-byte `id` the sender
  mints; `send_dm` returns it. `Content::DmEdit { target, text }` (18) /
  `Content::DmDelete { target }` (19) ride the same ratchet. The id is stored
  on `store::HistoryEntry::msg_id` (persisted as a positional `dm_msg_ids`
  section) and echoed on `ReceivedDm`. Authorisation is structural — an inbound
  `DmEdit` is applied only against a `history` entry in the same conversation
  and direction as the original, so only the sender's change lands. Standing
  state `peer_idk -> msg_id -> {text, deleted}` (persisted as
  `store::StoredDmEdit`); `take_dm_edits` / `dm_edit_snapshot` mirror the
  channel path. `serve` `POST /api/dm/edit {peer,msg_id,text}` (empty text
  deletes); `Item::Message` gained `peer` + `msg_id`, new `Item::DmEdit`. SPA
  folds it in with `(edited)` / `(message deleted)` and hover ✎/🗑 on your own
  DM lines. CLI `/editdm` `/deldm`. Legacy `Content::Text` (tag 1, no id) still
  decodes and stays the channel path; those messages just aren't editable.
- **Pinned messages** *(done)*: `Content::Pin { target_seq, unpin }` rides the
  channel log. A pin is honoured only from the channel host or the pinned
  message's recorded author (`Engine::may_pin`). Folded into a standing
  `channel_id -> seq -> {by, at_ms}` map, persisted as `store::StoredPin`;
  `take_pins` / `pin_snapshot` / `pinned_messages` mirror the reaction/edit
  path. `serve` `GET /api/pins?channel=`, `POST /api/pin {channel,seq,pinned}`,
  `Item::ChannelPin`. SPA: 📌 hover action, a `📌 pinned` tag on the message,
  and a 📌 header button opening a pinned-messages panel that jumps to the
  message. CLI `/pin` `/unpin` `/pins`. Same pre-restart-authorship caveat as
  edits (a message whose author was never seen this run can't be pinned).
- **@mentions** *(done, client-side)*: no protocol change — the SPA's
  `richText` renders `@<fingerprint>` (full, or an unambiguous prefix resolved
  against channel members + contacts) as a pill; a mention of your own
  fingerprint highlights and, when the channel is closed, raises a desktop
  notification + an `@` badge on the channel row. The composer has an
  `@`-autocomplete over channel members that inserts the full fingerprint.
- **Message search** *(done)*: `Engine::search(query, limit)` — case-insensitive
  substring over stored DM + channel text, newest first. `serve`
  `GET /api/search?q=`; the SPA's 🔍 button / Ctrl+K opens an overlay with
  debounced live results that jump to the DM or channel.
- **Message forwarding** *(done)*: `Content::Forward { origin, text }` (tag 20)
  rides the channel MLS log like an ordinary message — editable / deletable /
  pinnable — but carries an unauthenticated display label of the original
  author. `ChannelMessage` / serve `Item::Channel` gained `forwarded_from`;
  `Engine::forward_to_channel`. A DM forward has no protocol change: it is a
  normal text DM whose body is prefixed `↪ Forwarded from <label>\n…`, which
  the SPA/CLI strip and render as a chip. `serve` `POST /api/forward
  {to,origin,text}` routes to either. SPA: an ↪ hover action on any message
  opens a destination picker (channels + DMs). CLI `/forward <#chan|fp>
  <origin> <text>`. The channel `forwarded_from` isn't persisted, so the chip
  is lost after a restart (same class of caveat as reactions/edits).
- **Unread counts + per-conversation mute** *(done, client-side)*: the SPA
  tracks an unread *count* per DM / channel (was a binary dot), shows it as a
  badge on the sidebar row, and reflects the total in the browser tab title.
  A 🔔/🔕 header toggle mutes a conversation (persisted in `localStorage`):
  muted rows dim, their badge greys out and drops from the tab total, and they
  raise no desktop notification. Background-tab DMs now notify (not only
  mentions), gated on mute.
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
  serves the signal. **Channel typing** — the marker (8-byte timestamp ‖
  `Content::Typing`) is XChaCha20-Poly1305-sealed under a key exported from the
  channel MLS group's current epoch, so it never touches the message log;
  `Engine::send_typing_channel` posts the blob to the `channel_id` topic. **Off by default is the intent**;
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
  state snapshots, `dante-net` `Request`/`Response`) is total on arbitrary
  bytes and canonical (decode∘encode is identity); the Double Ratchet decrypts
  an arbitrarily reordered batch exactly once and rejects replays.
  `cargo-fuzz` targets on the same decoders are a later add (needs nightly).
- Integration harness: 2–3 `dante-cli` nodes + 1 `dante-relay` locally. Assert the
  full path: identity announce → DHT lookup → X3DH → ratchet exchange →
  offline delivery via relay mailbox → file transfer → key rotation →
  liveness proof → evaporation GC on a simulated +90d clock.
- Manual: two Tauri clients on one machine — add by fingerprint, verify safety
  number, exchange messages + a file, take one offline, send, restart, confirm
  delivery.
