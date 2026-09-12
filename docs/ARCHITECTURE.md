# DaNTe Architecture

> Status: draft, evolves per phase. Authoritative decisions live in [`DESIGN.md`](DESIGN.md).

## One-paragraph summary

DaNTe is a peer-to-peer, end-to-end-encrypted chat application. There is no
central server and no project-run infrastructure. Identities are anonymous
keypairs published to a replicated, tamper-evident append-only log. Peers find
each other over a libp2p DHT and exchange messages directly or via
community-run relay nodes that provide store-and-forward for offline delivery.
1:1 messages use the Signal protocol (X3DH + Double Ratchet); group contexts
(servers, channels, group voice) use MLS (RFC 9420).

## Trust model in one picture

```
        anonymous identity keypair (Ed25519 + X25519), stored locally
                              |
                announces / re-proves liveness (+ PoW)
                              v
     +-------------------- verifiable log (Merkle) --------------------+
     |  identity records | liveness proofs | key rotations | servers  |
     +---------------------------------------------------------------- +
        replicated across relay nodes; gossiped Merkle root
                              |
        DHT lookup of peers + prekey bundles + relay addresses
                              |
        +---------------------+----------------------+
        |                                            |
   direct P2P (online)                     relay mailbox (offline)
   Noise-encrypted libp2p                  sealed-sender envelopes
        |                                            |
        +------------------ E2E payload -------------+
              DM: X3DH + Double Ratchet
              Group: MLS (RFC 9420)
```

## Crate map (Cargo workspace)

| Crate | Kind | Responsibility |
|---|---|---|
| `dante-crypto` | lib | Primitives only: X25519, Ed25519, AEAD (XChaCha20-Poly1305 / AES-256-GCM), HKDF, Argon2id, the memory-hard PoW puzzle, thin wrappers over the Double Ratchet and over `OpenMLS`. No I/O, no policy. |
| `dante-identity` | lib | Identity keypair lifecycle; fingerprint encoding (Crockford base32 + BIP39 word phrase); safety numbers; the on-disk encrypted keystore; liveness-proof construction; encrypted key-backup export/import; the libp2p node-key derivation. |
| `dante-ledger` | lib | The verifiable log: record schema, append, Merkle tree, inclusion + consistency proofs, deterministic evaporation GC, key revocation, server registry, replication/sync state machine. Storage-backend agnostic. |
| `dante-proto` | lib | Canonical wire types shared across the network boundary: the length-prefixed binary codec (`enc::Writer`/`Reader`), the `Record` envelope, sealed-sender `Envelope`, RFC 6962 Merkle proofs. No logic beyond encode/verify. |
| `dante-net` | lib | The **framed-TCP** relay transport (`u32` length prefix), the `Request`/`Response` relay wire + `RequestHandler`, the relay **client** (with multi-endpoint failover and, with `p2p`, a libp2p backend), the sealed-sender mailbox, per-key rate limiting, ledger sync. |
| `dante-p2p` | lib | The libp2p stack (feature-gated, on by default): TCP+Noise+Yamux `Swarm`, Kademlia DHT, gossipsub, identify, ping, and the `/dante/relay/1` request-response protocol that carries the `dante-net` relay wire peer-to-peer. |
| `dante-relay` | bin | A relay node: sealed-sender mailbox store-and-forward with TTL, ledger replica, prekey + key-package directories, per-channel log, ephemeral signal buffer, per-IP rate limiting; optional in-process TURN; with `--p2p-listen`, relay↔relay federation over gossipsub. |
| `dante-dm` | lib | 1:1 sessions: prekey bundle publication, X3DH, Double Ratchet, chunked encrypted file transfer. |
| `dante-mls` | lib | Thin wrapper over `OpenMLS` 0.9 — one MLS group per channel and per group call; member export/import for persistence. |
| `dante-group` | lib | **Legacy** sender-keys ratchet, superseded by `dante-mls`; retained only for its fuzz target, not a `dante-core` dependency. |
| `dante-voice` | lib | 1:1 voice/media calls (`webrtc` sans-IO core) over DM signalling; DTLS-SRTP; Opus track; ≥64 kbps floor; ICE/TURN plumbing. |
| `dante-audio` | lib | Opus codec + `cpal` mic/speaker glue. Detached (`[workspace]`, links libopus/ALSA); not in CI. |
| `dante-core` | lib | Orchestration engine the UI consumes: wires identity + ledger + net (+ `dante-p2p`) + dm + mls + voice together; task-oriented async API + event stream. No UI concerns. |
| `dante-cli` | bin | `dante` — headless client (`serve` embeds the web UI + JSON API, `chat` a TTY client, `bot` a JSON-lines bridge) and the integration-test harness. |
| `apps/dante-desktop` | Tauri app | Thin shell: binds `127.0.0.1:0`, runs `dante_cli::serve::run_on`, opens a `WebviewWindow` on it — reuses the whole SPA + API. Detached; needs webkit2gtk, not in CI. |

Dependency direction is strictly downward:
`cli`/`desktop` → `core` → {`dm`, `mls`, `voice`, `net`, `p2p`, `ledger`, `identity`} → `proto` → `crypto`.
`crypto` depends on nothing internal; `proto` depends only on `crypto` (a wire
record hashes and verifies itself). `dante-p2p` is reached through the `p2p`
feature, which is on by default in `dante-core` / `dante-cli` / `dante-relay`;
`default-members` omits the crate, but a bare root `cargo build` still pulls it
in transitively — `--no-default-features` is the lean path.

## Runtime roles

- **Client** — every user. Participates in the DHT and gossip mesh, holds the
  identity keystore, runs all E2E crypto locally.
- **Relay** — opt-in, run by whoever creates a server (or by volunteers).
  Sees only ciphertext and coarse routing metadata (recipient hint, size,
  timing). Provides offline delivery and, later, media relay (TURN/SFU).
- **Bootstrap** — a handful of `/ip4/.../tcp/N/p2p/<id>` multiaddrs used only for
  first contact with the DHT (`--bootstrap`, the `DANTE_BOOTSTRAP` env var, or a
  compiled-in `DEFAULT_BOOTSTRAP`, currently empty). Swappable; not trusted for
  anything beyond peer discovery. A relay can also hand a client fresh peer
  addresses (`GetP2pPeers`).

## Phase status

See [`DESIGN.md`](DESIGN.md) for the phased roadmap and current state. In
short: Phases 1–8 are implemented (identity/ledger/relay, E2E DMs, files,
servers & channels on MLS, 1:1 + group + channel voice, screen share,
stickers/soundboards/embeds/bots), and the libp2p transport is the default
(DHT relay discovery, redundant relay set, relay federation, rendezvous-hashed
channel logs). `THREAT_MODEL.md` and `PROTOCOL.md` are the authoritative specs.
Known deferrals: a serverless mailbox, a group-call SFU, seeding
`DEFAULT_BOOTSTRAP`, and browser runtime-verification of the media paths.
