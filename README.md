# DaNTe — DArkNetTElegraph

A privacy-first, end-to-end-encrypted, peer-to-peer chat application with
Discord-equivalent feature scope (servers, channels, roles, voice, screen share,
soundboards, custom emoji/stickers, bots, discovery). No central server, no
project-run infrastructure, anonymous identities.

> **Status: Phase 0 (scaffold).** No functional code yet. This repository
> currently contains the workspace layout, CI, license, and the design +
> protocol + threat-model specifications. See [`docs/DESIGN.md`](docs/DESIGN.md)
> for the roadmap.

## What it is

- **End-to-end encrypted.** 1:1 messages use X3DH + Double Ratchet (forward
  secrecy + post-compromise security). Servers, channels and group voice use
  MLS (RFC 9420).
- **Peer-to-peer.** Peers find each other over a libp2p DHT. Offline delivery is
  handled by community-run relay nodes that see only ciphertext.
- **Anonymous.** An identity is a keypair. No phone number, email, payment, or
  invite required. Your unique ID is your public-key fingerprint.
- **No infrastructure.** The project operates nothing. Relays are run by whoever
  creates a server, for their own community.

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before relying on any of the
above — it states precisely what is and is not protected.

## Repository layout

| Path | What |
|---|---|
| `crates/dante-crypto` | Primitives: X25519, Ed25519, AEAD, HKDF, Argon2id PoW, ratchet + MLS wrappers |
| `crates/dante-identity` | Identity keys, fingerprints, encrypted keystore, liveness proofs, backup |
| `crates/dante-ledger` | Verifiable Merkle log: records, proofs, evaporation GC, replication |
| `crates/dante-proto` | Canonical wire types (CBOR) |
| `crates/dante-net` | libp2p transport, DHT, gossipsub, relay client |
| `crates/dante-relay` | Relay node binary |
| `crates/dante-dm` | 1:1 DM sessions, file transfer, local store |
| `crates/dante-core` | Orchestration engine consumed by clients |
| `crates/dante-cli` | Headless client for dev + integration tests |
| `client/` | Tauri desktop app (added in Phase 5) |
| `docs/` | `DESIGN.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `PROTOCOL.md` |

## Building

Requires a Rust toolchain — the version is pinned in
[`rust-toolchain.toml`](rust-toolchain.toml) (currently 1.82) and `rustup` will
install it automatically on first `cargo` invocation.

### Install Rust

- **Fedora:** `sudo dnf install rustup && rustup-init` (or use the upstream
  installer below). Build essentials: `sudo dnf install @development-tools pkgconf-pkg-config`.
- **Any platform:** `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Windows:** install from <https://rustup.rs>.

### Commands

```bash
cargo build --workspace
cargo test --workspace --all-features
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

`cargo-deny` (license / advisory / source checks) runs in CI; install locally
with `cargo install cargo-deny` and run `cargo deny check`.

## Purpose and disclaimer

DaNTe exists to protect ordinary private communication from mass surveillance and
bulk data collection. The project operates no infrastructure and cannot read,
decrypt, or moderate anything; servers are run by independent third parties. The
contributors do not support or condone any unlawful use. Full statement:
[`DISCLAIMER.md`](DISCLAIMER.md).

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
