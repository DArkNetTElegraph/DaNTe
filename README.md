# DaNTe — DArkNetTElegraph

A privacy-first, end-to-end-encrypted, peer-to-peer chat application with
Discord-equivalent feature scope (servers, channels, roles, voice, custom emoji,
discovery). No central server, no project-run infrastructure, anonymous
identities.

> **Status: pre-1.0, actively built.** The MVP and most of the Discord-scope
> feature set work today against a local relay: identities, servers & channels
> over MLS, roles, 1:1 + group voice, persistent voice channels, reactions &
> custom emoji, and a single-file browser client (`dante serve`). The native
> desktop app and libp2p-as-default transport are the main gaps. Wire formats
> still change without notice. See the [roadmap](#roadmap) below and
> [`docs/DESIGN.md`](docs/DESIGN.md) for detail.

## What it is

- **End-to-end encrypted.** 1:1 messages use X3DH + Double Ratchet (forward
  secrecy + post-compromise security). Servers, channels and group voice use
  MLS (RFC 9420, via OpenMLS).
- **Peer-to-peer.** Peers can find each other over a libp2p DHT (opt-in today).
  Offline delivery is handled by community-run relay nodes that see only
  ciphertext.
- **Anonymous.** An identity is a keypair. No phone number, email, payment, or
  invite required. Your unique ID is your public-key fingerprint ("block-ID");
  you also pick a non-unique display username at registration.
- **No infrastructure.** The project operates nothing. Relays are run by whoever
  creates a server, for their own community.

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before relying on any of the
above — it states precisely what is and is not protected.

## Roadmap

### Working now

| Area | Status |
|---|---|
| **Identity** | Ed25519 + X25519 keypairs, Argon2id keystore + recovery backup, Crockford-base32 / BIP39 fingerprints, safety-number verification, memory-hard registration PoW, liveness proofs, key rotation, **key revocation**, self-chosen **usernames** (non-unique, carried on the ledger) |
| **Verifiable ledger** | Append-only RFC 6962 Merkle log, inclusion + consistency proofs, identity / rotation chains, server registry, deterministic 90-day evaporation GC |
| **Relay + transport** | Framed-TCP client↔relay protocol, sealed-sender envelopes (day-rotating hint + size padding), mailbox store-and-forward, prekey directory, blob store, per-IP rate limiting, multi-relay failover, `dante-relay` binary with in-process zero-config TURN |
| **1:1 DMs** | X3DH + Double Ratchet (FS + PCS), chunked encrypted file transfer, edit / delete, typing indicators, forwarding, block list, contacts / petnames, full-text search over local history |
| **Servers & channels** | MLS group per channel (host is sole committer); create server / channel, direct invites + invite links, **server-level join password**, roles & permissions v1, member kick + inactivity auto-kick, channel history, delete server / channel, leave channel, rename channel, always-present `#general`, public **discovery** & join |
| **In-channel** | Emoji reactions (unicode + custom), **categorised emoji picker**, edit / delete, replies, pinned messages, @mentions, message forwarding, per-conversation unread counts + mute, **custom per-server emoji** (PNG / JPEG ≤ 1 MiB, fixed inline size) |
| **Voice** | 1:1 calls, group calls (shared MLS media key + 1:1 mesh), **persistent Discord-style voice channels with real browser audio**, ≥ 64 kbps Opus floor, STUN / TURN plumbing |
| **Clients** | `dante` CLI (`gen` / `fp` / `chat` / `serve` / `revoke`); `dante serve` — a single-file browser app: onboarding, four-pane Discord-shaped shell, light / dark themes, right-click context menus, monochrome UI icons, SSE live updates |
| **P2P (opt-in, `--features p2p`)** | `dante-p2p` libp2p node (Kademlia + gossipsub + identify + ping); DHT prekey-directory fallback, relay-assisted bootstrap, ledger-record gossip |

### Partial / caveats

- **Voice-channel audio** is written to the standard WebRTC perfect-negotiation
  pattern but has not been runtime-verified in CI (no browser / mic there). Only
  STUN is wired to the browser (TURN credentials aren't exposed yet), so it
  connects on localhost / same-LAN today.
- **1:1 and group call audio**: the engine has the full WebRTC + Opus transport,
  but `dante serve` has no browser microphone path — only voice channels do.
  Real mic / speaker for 1:1 needs the desktop shell.
- **P2P is off by default.** The relay is still the sealed-sender mailbox and the
  primary directory; the DHT is a fallback. Channel-log fan-out uses the relay's
  ordered per-channel log, not gossipsub.
- **Restart gaps**: MLS state for calls isn't persisted across a restart
  (channels' is); a few client-side derivations (reaction / pin / edit
  authorship, the "forwarded from" chip) don't fully survive a client restart.

### Not done yet

- **Native desktop app** — `apps/dante-desktop` (Tauri 2) is a thin shell that
  reuses `dante serve`; native menus / tray / notifications / auto-update and a
  buildable CI target are outstanding. A mic / speaker bridge (`dante-audio`)
  exists for it.
- Screen share.
- An SFrame layer applying the group-call key to media (so an untrusted SFU
  could forward it) and an SFU path for large voice rooms (mesh only now).
- Stickers, soundboards, bots, URL embeds / unfurler, Tenor / Giphy.
- Custom profiles, per-server nicknames / avatars; emoji in roles.
- libp2p / DHT as the **default** transport.
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

## Repository layout

| Path | What |
|---|---|
| `crates/dante-crypto` | Primitives: X25519, Ed25519, AEAD, HKDF, Argon2id PoW |
| `crates/dante-identity` | Identity keys, fingerprints, encrypted keystore, liveness proofs, backup |
| `crates/dante-ledger` | Verifiable Merkle log: records, proofs, evaporation GC |
| `crates/dante-proto` | Canonical wire types + explicit binary codec |
| `crates/dante-net` | Framed-TCP relay client/server, sealed-sender envelopes, sync |
| `crates/dante-relay` | Relay node binary (mailbox, ledger replica, blob store, TURN) |
| `crates/dante-mls` | OpenMLS 0.9 wrapper — one MLS group per channel / group call |
| `crates/dante-dm` | 1:1 DM sessions (X3DH + Double Ratchet), file transfer, `Content` payloads |
| `crates/dante-core` | Orchestration engine consumed by every client |
| `crates/dante-voice` | WebRTC (webrtc-rs) call transport + Opus track tuning |
| `crates/dante-audio` | Opus codec + cpal capture/playback for the desktop shell (detached) |
| `crates/dante-p2p` | libp2p node: Kademlia, gossipsub, identify, ping (opt-in) |
| `crates/dante-group` | Retired sender-keys ratchet — kept only for its fuzz target |
| `crates/dante-cli` | `dante` binary: `gen` / `fp` / `chat` / `serve` / `revoke` + the browser SPA |
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
part of the workspace build.

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
