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
> notifications — built for Linux, Windows and macOS in CI. Main gaps:
> **nothing in the voice/media path or the desktop shell has been run by a
> human yet**, and there is no group-call SFU. Wire formats still change
> without notice. See the
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
  [`docs/RUNNING_A_RELAY.md`](docs/RUNNING_A_RELAY.md).

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
| **Servers & channels** | MLS group per channel (host is sole committer); create server / channel, direct invites + invite links, **server-level join password**, roles & permissions v1, member kick + inactivity auto-kick, channel history, delete server / channel, leave channel, rename channel, always-present `#general`, public **discovery** & join |
| **In-channel** | Emoji reactions (unicode + custom), **categorised emoji picker**, edit / delete, replies, pinned messages, @mentions, message forwarding, per-conversation unread counts + mute, **custom per-server emoji / stickers / soundboards** |
| **Voice** | 1:1 calls, group calls (shared MLS media key + 1:1 mesh), **persistent Discord-style voice channels with real browser audio**, **screen share**, optional **SFrame** media encryption under the group-call key, ≥ 64 kbps Opus floor, STUN / TURN plumbing |
| **Clients** | `dante` CLI (`gen` / `fp` / `chat` / `serve` / `bot` / `revoke`); `dante serve` — a single-file browser app: onboarding, four-pane Discord-shaped shell, light / dark themes, right-click context menus, monochrome UI icons, SSE live updates, opt-in link previews; `dante bot` — a JSON-lines headless bridge; `apps/dante-desktop` — a Tauri 2 native window around the same service, with a live startup screen, system tray and OS notifications |
| **P2P (on by default; `--no-default-features` for a lean TCP build)** | `dante-p2p` libp2p node (Kademlia + gossipsub + identify + ping); the relay wire over `/dante/relay/1`; **DHT relay discovery**, a redundant relay set with health scoring, **relay↔relay federation** (ledger, prekeys, mailbox, key packages, channel logs), rendezvous-hashed single-writer channel logs, relay-assisted bootstrap + `DANTE_BOOTSTRAP` |

### Partial / caveats

- **Media paths not runtime-verified.** Voice-channel audio, screen share and
  the SFrame transform are written to the standard browser WebRTC patterns but
  have never been exercised in a real browser (none in the dev env / CI). The
  Rust relay/signalling halves have e2e tests; the browser halves do not.
- **Browser TURN.** The page now gets the relay's TURN credentials from
  `/api/ice`, so cross-NAT calls can allocate a relay candidate — but this has
  only been exercised against a local relay, never between two real NATs.
- **1:1 and group call audio**: the engine has the full WebRTC + Opus transport,
  but `dante serve` has no browser microphone path for these — only voice
  channels do. Real mic / speaker for 1:1 needs the desktop shell.
- **Restart gaps**: *(closed)* channel history persists each message's
  relay-log `seq` (plus `reply_to` / `forwarded_from`), and the plaintext
  backlog a host hands a new member carries the `seq` too, so both restored and
  backfilled messages can be reacted to, pinned, replied to and edited.
- **Desktop shell not runtime-verified.** The native layer (startup progress,
  tray, notifications, the mic/speaker bridge) builds green in CI on both Linux
  and Windows, but no one has yet opened the window: how it looks, whether the
  tray behaves per-platform, and whether notifications fire at sensible moments
  are all unconfirmed. A passing build says the code is well-formed, nothing
  more. The dev environment has no GTK/webview stack, so this needs
  a real desktop — see
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
  `dante-audio`. What is outstanding is the release side: native application
  menus, auto-update, signed bundles, and a macOS build (CI covers Linux and
  Windows).
- A **group-call SFU** for large voice rooms (full mesh only now, fine to ~8).
- Tenor / Giphy GIF search.
- Custom profiles, per-server nicknames / avatars; emoji in roles.
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

## Repository layout

| Path | What |
|---|---|
| `crates/dante-crypto` | Primitives: X25519, Ed25519, AEAD, HKDF, Argon2id PoW |
| `crates/dante-identity` | Identity keys, fingerprints, encrypted keystore, liveness proofs, backup |
| `crates/dante-ledger` | Verifiable Merkle log: records, proofs, evaporation GC |
| `crates/dante-proto` | Canonical wire types + explicit binary codec |
| `crates/dante-net` | Relay client/server wire (framed TCP or libp2p), sealed-sender envelopes, mailbox, rate limiting, sync |
| `crates/dante-p2p` | libp2p node: Kademlia, gossipsub, identify, ping, the `/dante/relay/1` protocol (default-on, kept out of the bare `cargo build` set) |
| `crates/dante-relay` | Relay node binary (mailbox, ledger replica, prekey/key-package dirs, blob store, per-channel log, TURN, federation) |
| `crates/dante-mls` | OpenMLS 0.9 wrapper — one MLS group per channel / group call |
| `crates/dante-dm` | 1:1 DM sessions (X3DH + Double Ratchet), file transfer, `Content` payloads |
| `crates/dante-core` | Orchestration engine consumed by every client |
| `crates/dante-voice` | WebRTC (webrtc-rs) call transport + Opus track tuning |
| `crates/dante-audio` | Opus codec + cpal capture/playback for the desktop shell (detached) |
| `crates/dante-group` | Retired sender-keys ratchet — kept only for its fuzz target |
| `crates/dante-cli` | `dante` binary: `gen` / `fp` / `chat` / `serve` / `bot` / `revoke` + the browser SPA |
| `apps/dante-desktop` | Tauri 2 desktop shell (detached workspace) |
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

A bare `cargo build` / `cargo test` excludes `dante-p2p` (the libp2p tree) by
design; `--workspace` and `-p dante-p2p` include it. `dante-audio` and
`apps/dante-desktop` are detached (they need libopus / webkit2gtk) and are not
part of the workspace build — which also means `cargo fmt --all` and
`clippy --workspace` do not see them. CI builds the desktop crate in its own
job (Linux + Windows, with its own fmt and clippy) so the detachment cannot
hide a break; to build it by hand, follow
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
