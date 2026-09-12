# DaNTe — DArkNetTElegraph

A privacy-first, end-to-end-encrypted, peer-to-peer chat application with
Discord-equivalent feature scope (servers, channels, roles, voice, custom emoji,
discovery). No central server, no project-run infrastructure, anonymous
identities.

> **Status: pre-1.0, actively built.** The MVP and the Discord-scope feature set
> work today: identities, servers & channels over MLS, roles, 1:1 + group +
> persistent-channel voice, screen share, reactions / custom emoji / stickers /
> soundboards, opt-in link previews, a headless bot bridge, and a single-file
> browser client (`dante serve`). The libp2p transport (DHT relay discovery,
> redundant relay set, relay federation) is **on by default**, and the Tauri
> desktop shell has its native layer — live startup progress, tray, OS
> notifications — built for Linux, Windows and macOS in CI. Voice-channel,
> 1:1 call, and now ad-hoc group-call audio all have real, verified browser
> audio (three independent browser peers exchanging live RTP audio in a full
> mesh — see [Partial / caveats](#partial--caveats)). Main gaps:
> **the desktop shell has never been opened** and **cross-NAT voice is
> unverified**, and there is no group-call SFU (mesh only, fine to ~8). Wire
> formats still change without notice. See the
> [roadmap](#roadmap) and [`docs/DESIGN.md`](docs/DESIGN.md) for detail.

## What it is

- **End-to-end encrypted.** 1:1 messages use X3DH + Double Ratchet (forward
  secrecy + post-compromise security). Servers, channels and group voice use
  MLS (RFC 9420, via OpenMLS).
- **Peer-to-peer.** A libp2p layer (on by default) carries relay discovery over
  a Kademlia DHT, gossips the ledger and channel logs, and lets relays federate.
  Offline delivery is still handled by community-run relay nodes — which see
  only ciphertext and coarse routing metadata.
- **Anonymous.** An identity is a keypair. No phone number, email, payment, or
  invite required. Your unique ID is your public-key fingerprint ("block-ID");
  you also pick a non-unique display username at registration.
  An anonymous identity is only as anonymous as the network under it, so a
  relay reached at an `.onion` address is dialled through Tor automatically
  (or set `DANTE_SOCKS5` to send everything through a proxy). Run that way the
  relay never learns a client IP — which is the difference between anonymous
  and merely pseudonymous. Note Tor carries TCP only, so voice does not work
  over it.
- **No infrastructure.** The project operates nothing. Relays are run by whoever
  creates a server, for their own community — as a Tor onion service needing no
  public IP, or on a public host. See
  [`docs/RUNNING_A_RELAY.md`](docs/RUNNING_A_RELAY.md). Looking for one to
  connect to rather than running your own? See
  [Relay status](#relay-status) below — an opt-in directory, checked from a
  real external vantage point so it reflects who is actually reachable, not
  just who claims to be.

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before relying on any of the
above — it states precisely what is and is not protected.

## Roadmap

### Working now

| Area | Status |
|---|---|
| **Identity** | Ed25519 + X25519 keypairs, Argon2id keystore + recovery backup, Crockford-base32 / BIP39 fingerprints, safety-number verification, memory-hard registration PoW, liveness proofs, key rotation, **key revocation**, self-chosen **usernames** (non-unique, carried on the ledger) |
| **Verifiable ledger** | Append-only RFC 6962 Merkle log, inclusion + consistency proofs, identity / rotation chains, server registry, deterministic 90-day evaporation GC |
| **Relay + transport** | Client↔relay `Request`/`Response` wire over framed TCP **or** a libp2p `/dante/relay/1` stream; sealed-sender envelopes (day-rotating hint + size padding), mailbox store-and-forward, prekey + key-package directories, blob store, per-IP rate limiting, multi-relay failover, `dante-relay` binary with in-process zero-config TURN |
| **1:1 DMs** | X3DH + Double Ratchet (FS + PCS), chunked encrypted file transfer, edit / delete, typing indicators, forwarding, block list, contacts / petnames, full-text search over local history |
| **Servers & channels** | MLS group per channel (host is sole committer); create server / channel, direct invites + invite links, **server-level join password**, roles & permissions v1, member kick + inactivity auto-kick, channel history, delete server / channel, leave channel, rename channel, always-present `#general`, public **discovery** & join, **host-set per-server nicknames** |
| **In-channel** | Emoji reactions (unicode + custom), **categorised emoji picker**, edit / delete, replies, pinned messages, @mentions, message forwarding, per-conversation unread counts + mute, **custom per-server emoji / stickers / soundboards** |
| **Voice** | **1:1 calls with real browser audio**, **ad-hoc group calls (in any channel) with real browser audio**, **persistent Discord-style voice channels with real browser audio**, **screen share (verified)**, optional **SFrame** media encryption under the group-call key (verified active), ≥ 64 kbps Opus floor, STUN / TURN plumbing |
| **Clients** | `dante` CLI (`gen` / `fp` / `chat` / `serve` / `bot` / `revoke`); `dante serve` — a single-file browser app: onboarding, four-pane Discord-shaped shell, light / dark themes, right-click context menus, monochrome UI icons, SSE live updates, opt-in link previews; `dante bot` — a JSON-lines headless bridge; `apps/dante-desktop` — a Tauri 2 native window around the same service, with a live startup screen, system tray and OS notifications |
| **P2P (on by default; `--no-default-features` for a lean TCP build)** | `dante-p2p` libp2p node (Kademlia + gossipsub + identify + ping); the relay wire over `/dante/relay/1`; **DHT relay discovery**, a redundant relay set with health scoring, **relay↔relay federation** (ledger, prekeys, mailbox, key packages, channel logs), rendezvous-hashed single-writer channel logs, relay-assisted bootstrap + `DANTE_BOOTSTRAP` |

### Partial / caveats

- **Voice-channel audio: runtime-verified (2026-09-12).** Two independent
  headless-Chromium peers (fake mic devices, real `getUserMedia` +
  `RTCPeerConnection`), driven through the actual `dante serve` UI against a
  local relay, joined the same voice channel and reached `connectionState:
  "connected"` — and `RTCPeerConnection.getStats()` showed real inbound RTP
  audio flowing both directions (~220 packets / ~18 KB each way in a few
  seconds). This is the first time this code path has been exercised by
  anything.
- **Screen share and SFrame: runtime-verified (2026-09-12).** Same two-peer
  setup: `voiceToggleScreen()` grabbed a fake `getDisplayMedia` capture
  (Chromium's `--auto-select-desktop-capture-source` in headless mode) and
  the remote peer's `RTCPeerConnection.getStats()` showed real inbound video
  RTP (15 decoded frames within a second). Separately, `sframeActive()` came
  back `true` on both peers with a shared epoch — Chromium's
  `createEncodedStreams` is supported headless, so the AES-GCM transform
  over each Opus frame is genuinely running, not silently no-op'd.
- **Browser TURN.** The page gets the relay's TURN credentials from
  `/api/ice`, so cross-NAT calls can allocate a relay candidate — the above
  test ran same-host (host candidates only), so this still hasn't been
  exercised across two real NATs.
- **1:1 call audio: runtime-verified (2026-09-12).** `dante serve` already had
  a full browser WebRTC path for 1:1 calls (`callRtc`/`CallSignal`, mirroring
  the voice-channel mesh) — it just hadn't been exercised or documented as
  such. The same two-headless-Chromium test used for voice channels drove the
  real DM call UI (start → accept) and confirmed `RTCPeerConnection` reached
  `connected` with real inbound RTP audio both directions (~240 packets each
  way). The engine's own `dante-voice::Call` (webrtc-rs) still separately
  drives the `chat` CLI's `/call` and the desktop mic/speaker bridge.
- **Group call audio: added and runtime-verified (2026-09-12).** Ad-hoc group
  calls (`start_group_call`/`join_group_call` in any channel, not just a
  dedicated voice channel) now get the same real browser audio as voice
  channels — the mesh code is the same (`voiceRtc`, `VoiceSignal`, which
  was already generic over channel id and never actually gated on
  `channel.voice`), pointed at the group call's participant list
  (`/api/groupcalls`, extended to carry fingerprints, not just a count)
  instead of a voice channel's presence beacon. A "Start/Join a group call"
  button and bar (`#gcallbar`/`#gcall-toast`, CSS already scaffolded from an
  earlier session, wired up here) sit in any ordinary channel's header —
  they were tucked behind the header's overflow "More" menu until now
  because nothing set them up. Verified with three independent
  headless-Chromium peers in a full mesh: every one of the six directional
  legs reached `connected` with real inbound RTP audio.
- **Per-server nicknames (2026-09-12): host-set only, no self-service yet.**
  `ServerPolicy` gained a fourth signed tail list (`nicknames`, after roles,
  emoji, stickers and sounds — same "count written whenever it or a later
  list is non-empty" pattern that keeps old policies decoding). The host can
  set or clear any member's nickname (a "Set nickname" action in the member
  list); it overrides their username in that server's message authorship and
  member list, never in DMs or other servers. There is no path yet for a
  member to set their own — that needs a signed request-to-host flow (like
  `KickRequest`), which this round didn't add. Verified live: two real
  `dante serve` browser sessions, host sets a nickname, both the host's and
  the member's own client render it in the channel message author label and
  the member list.
- **Restart gaps**: *(closed)* channel history persists each message's
  relay-log `seq` (plus `reply_to` / `forwarded_from`), and the plaintext
  backlog a host hands a new member carries the `seq` too, so both restored and
  backfilled messages can be reacted to, pinned, replied to and edited.
- **Desktop shell not runtime-verified.** The native layer (startup progress,
  tray, notifications, the mic/speaker bridge) builds green in CI on Linux,
  Windows and macOS, but no one has yet opened the window: how it looks,
  whether the tray behaves per-platform, and whether notifications fire at
  sensible moments are all unconfirmed. A passing build says the code is
  well-formed, nothing more. The dev environment has no GTK/webview stack, so
  this needs a real desktop — see
  [`apps/dante-desktop/README.md`](apps/dante-desktop/README.md).
- **Multi-relay channel writes** converge via rendezvous hashing while every
  relay is up; a relay that flaps then recovers can briefly double-sequence one
  channel (the step-down rule converges it within a few frames). A true network
  partition needs consensus — out of scope for community relays.

### Not done yet

- **Desktop app: packaging and updates.** The shell itself is in place —
  it reuses `dante serve` verbatim, opens the window *before* the engine starts
  and narrates each startup step into it, hides to the tray instead of quitting,
  raises OS notifications, and bridges the mic/speaker for calls via
  `dante-audio`. CI now compiles it on Linux, Windows and macOS. What is
  outstanding is the release side: native application menus, auto-update, and
  signed/notarized installers — CI proves the code builds on all three
  platforms, but produces no distributable bundle for any of them yet.
- A **group-call SFU** for large voice rooms (full mesh only now, fine to ~8).
- Tenor / Giphy GIF search.
- Custom profiles / avatars; emoji in roles. Self-service nickname changes —
  a member can only ask their server's host to change it for them today (see
  [Partial / caveats](#partial--caveats)).
- Seeding a real `DEFAULT_BOOTSTRAP` (needs a deployed network).
- Reproducible builds + signed releases; external security audit; a
  `cargo-fuzz` corpus in CI.

## Try it

```bash
cargo build --release -p dante-relay -p dante-cli

# a local relay (low PoW so identity creation is instant — the real floor is 20)
./target/release/dante-relay --listen 127.0.0.1:9944 --min-pow-bits 8 &

# the browser client
./target/release/dante serve --keystore ~/dante.keystore \
    --relay 127.0.0.1:9944 --http 127.0.0.1:8080 --pow-bits 8
```

Open <http://127.0.0.1:8080>, pick a username + passphrase, and you're in. Run a
second `dante serve` on another `--http` port with a different `--keystore` to
talk to yourself. `dante chat --keystore … --relay …` is the terminal client.

### As a desktop app

The same thing in a native window, with a startup screen that reports what the
engine is doing, a system tray, and OS notifications. It needs a webview and
audio stack the plain CLI does not, so it is built separately — see
[`apps/dante-desktop/README.md`](apps/dante-desktop/README.md) for the
per-platform packages:

```bash
cargo install tauri-cli --version '^2'
cd apps/dante-desktop
DANTE_RELAY=127.0.0.1:9944 DANTE_POW_BITS=8 cargo tauri dev
```

Nobody has run this yet — it is built on Linux, Windows and macOS in CI, and
that is the whole of what is known about it. Expect rough edges and please
report them.

## Relay status

An opt-in directory of public relays, checked on a schedule from a real
external vantage point (GitHub's own infrastructure) using a genuine
protocol round trip — not a ping, and not merely "is a socket open," which a
relay behind an ISP with no public IPv4 (common on residential CGNAT) could
never pass anyway. That is the actual "is this eligible to be a public
node" test.

**[View the status page →](https://darknettelegraph.github.io/DaNTe/)**

Nothing here scans or discovers relays on its own — that would mean
fingerprinting operators (Tor relay operators especially) who never agreed
to be public. A relay is listed only because its operator added it via a
PR to [`relays/registry.toml`](relays/registry.toml). See
[`relays/README.md`](relays/README.md) to list yours, including what the
check actually verifies before your relay counts as online.

## Repository layout

| Path | What |
|---|---|
| [`crates/dante-crypto`](crates/dante-crypto/README.md) | Primitives: X25519, Ed25519, AEAD, HKDF, Argon2id PoW |
| [`crates/dante-identity`](crates/dante-identity/README.md) | Identity keys, fingerprints, encrypted keystore, liveness proofs, backup |
| [`crates/dante-ledger`](crates/dante-ledger/README.md) | Verifiable Merkle log: records, proofs, evaporation GC |
| [`crates/dante-proto`](crates/dante-proto/README.md) | Canonical wire types + explicit binary codec |
| [`crates/dante-net`](crates/dante-net/README.md) | Relay client/server wire (framed TCP or libp2p), sealed-sender envelopes, mailbox, rate limiting, sync |
| [`crates/dante-p2p`](crates/dante-p2p/README.md) | libp2p node: Kademlia, gossipsub, identify, ping, the `/dante/relay/1` protocol (default-on via the `p2p` feature; `--no-default-features` skips it) |
| [`crates/dante-relay`](crates/dante-relay/README.md) | Relay node binary (mailbox, ledger replica, prekey/key-package dirs, blob store, per-channel log, TURN, federation) |
| [`crates/dante-relay-check`](crates/dante-relay-check/README.md) | Checks the opt-in relay directory (`relays/registry.toml`) and publishes the status page |
| [`crates/dante-mls`](crates/dante-mls/README.md) | OpenMLS 0.9 wrapper — one MLS group per channel / group call |
| [`crates/dante-dm`](crates/dante-dm/README.md) | 1:1 DM sessions (X3DH + Double Ratchet), file transfer, `Content` payloads |
| [`crates/dante-core`](crates/dante-core/README.md) | Orchestration engine consumed by every client |
| [`crates/dante-voice`](crates/dante-voice/README.md) | WebRTC (webrtc-rs) call transport + Opus track tuning |
| [`crates/dante-audio`](crates/dante-audio/README.md) | Opus codec + cpal capture/playback for the desktop shell (detached) |
| [`crates/dante-group`](crates/dante-group/README.md) | Retired sender-keys ratchet — kept only for its fuzz target |
| [`crates/dante-cli`](crates/dante-cli/README.md) | `dante` binary: `gen` / `fp` / `chat` / `serve` / `bot` / `revoke` + the browser SPA |
| [`apps/dante-desktop`](apps/dante-desktop/README.md) | Tauri 2 desktop shell (detached workspace) |
| [`relays/`](relays/README.md) | The opt-in public relay directory + status page — see below |
| `docs/` | `DESIGN.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `PROTOCOL.md` |

## Building

Requires a recent **stable** Rust toolchain (≥ 1.91 — the OpenMLS floor);
[`rust-toolchain.toml`](rust-toolchain.toml) pins the channel and `rustup`
installs it on first `cargo` invocation.

### Install Rust

- **Fedora:** `sudo dnf install rustup && rustup-init`. Build essentials:
  `sudo dnf install @development-tools pkgconf-pkg-config`.
- **Any platform:** `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Windows:** install from <https://rustup.rs>.

### Commands

```bash
cargo build --workspace
cargo test  --workspace --all-features
cargo fmt   --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

A bare `cargo build` / `cargo test` does not select `dante-p2p` directly
(`default-members` omits it), but `dante-core`, `dante-cli` and `dante-relay`
enable their `p2p` feature by default, so the libp2p tree is still built
transitively. Use `--no-default-features` for a lean TCP-only build;
`--workspace` and `-p dante-p2p` build it explicitly. `dante-audio` and
`apps/dante-desktop` are detached (they need libopus / webkit2gtk) and are not
part of the workspace build — which also means `cargo fmt --all` and
`clippy --workspace` do not see them. CI builds the desktop crate in its own
job (Linux, Windows and macOS, with its own fmt and clippy) so the
detachment cannot hide a break; to build it by hand, follow
[`apps/dante-desktop/README.md`](apps/dante-desktop/README.md).

`cargo-deny` (license / advisory / source checks) runs in CI; install locally
with `cargo install cargo-deny` and run `cargo deny check`.

## Purpose and disclaimer

DaNTe exists to protect ordinary private communication from mass surveillance and
bulk data collection. The project operates no infrastructure and cannot read,
decrypt, or moderate anything; servers are run by independent third parties. The
contributors do not support or condone any unlawful use. Full statement:
[`DISCLAIMER.md`](DISCLAIMER.md).

## Support

DaNTe is free and takes no money to run. Donations in Monero are welcome and keep
the project independent — they are optional and grant nothing.

[![Donate — Monero](https://img.shields.io/badge/Donate-Monero-FF6600?logo=monero&logoColor=white)](monero:88oT41WmnzQEakPZBD5ucLJuc4F3Q59uX9zvJE8hn5Qm68ELKFDKPHiaqNX8VnDA6u1tmoBpFFGYhU2HrLXh5EoEQiMXyBr)

**XMR:**

```
88oT41WmnzQEakPZBD5ucLJuc4F3Q59uX9zvJE8hn5Qm68ELKFDKPHiaqNX8VnDA6u1tmoBpFFGYhU2HrLXh5EoEQiMXyBr
```

<sub>The canonical donation address is the one in this file on the `main` branch.
Verify it against a second source before sending — never trust an address from a
fork, an issue, or a screenshot.</sub>

## License

[AGPL-3.0-or-later](LICENSE). This is deliberate: a privacy tool's source, and
that of its forks and network-deployed variants, must stay open. No telemetry is
collected, ever.

## Contributing

The project is pre-1.0 and wire formats change without notice. Crypto-affecting
changes must ship with RFC / reference test vectors and go through a security
review. See [`docs/DESIGN.md`](docs/DESIGN.md) for the current phase.

Start with [`CONTRIBUTING.md`](CONTRIBUTING.md). Report vulnerabilities privately
per [`SECURITY.md`](SECURITY.md) — never in a public issue. Participation is
governed by the [`Code of Conduct`](CODE_OF_CONDUCT.md).
