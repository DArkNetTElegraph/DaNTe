# DaNTe Architecture

> Status: draft, evolves per phase. Authoritative decisions live in [`../DESIGN.md`](../DESIGN.md).

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
| `dante-identity` | lib | Identity keypair lifecycle; fingerprint encoding (Crockford base32 + BIP39 word phrase); safety numbers; the on-disk encrypted keystore; liveness-proof construction; encrypted key-backup export/import. |
| `dante-ledger` | lib | The verifiable log: record schema, append, Merkle tree, inclusion + consistency proofs, deterministic evaporation GC, replication/sync state machine. Storage-backend agnostic. |
| `dante-proto` | lib | Wire types shared across the network boundary (framing, envelopes, record encodings). Generated/serde types only — no logic. |
| `dante-net` | lib | libp2p stack (QUIC + TCP, Noise, Yamux), Kademlia DHT, gossipsub, request-response; the relay **client** (publish/fetch mailbox, sync ledger). |
| `dante-relay` | bin | A relay node: encrypted mailbox store-and-forward with TTL, ledger replication, per-IP / per-identity rate limiting, bootstrap addressing. Later: TURN + SFU roles. |
| `dante-dm` | lib | 1:1 sessions: prekey bundle publication, X3DH, Double Ratchet session store, chunked encrypted file transfer, encrypted local message store (`rusqlite`). |
| `dante-core` | lib | Orchestration engine the UI consumes: wires identity + net + ledger + dm together, exposes a task-oriented async API and an event stream. Holds no UI concerns. |
| `dante-cli` | bin | Headless client for development and the integration test harness. |
| `client/` | Tauri app | `src-tauri/` Rust commands bridging `dante-core`; `src/` SvelteKit frontend. |

Dependency direction is strictly downward:
`cli`/`client` → `core` → {`dm`, `net`, `ledger`, `identity`} → {`proto`, `crypto`}.
`crypto` and `proto` depend on nothing internal.

## Runtime roles

- **Client** — every user. Participates in the DHT and gossip mesh, holds the
  identity keystore, runs all E2E crypto locally.
- **Relay** — opt-in, run by whoever creates a server (or by volunteers).
  Sees only ciphertext and coarse routing metadata (recipient hint, size,
  timing). Provides offline delivery and, later, media relay (TURN/SFU).
- **Bootstrap** — a handful of well-known libp2p multiaddrs used only for first
  contact with the DHT. Published via DNS + the repo; swappable; not trusted for
  anything beyond peer discovery.

## Phase status

See [`../DESIGN.md`](../DESIGN.md) for the phased roadmap. Phase 0 (this
scaffold) establishes the workspace, CI, license, and the `THREAT_MODEL.md` /
`PROTOCOL.md` specifications that later phases implement against.
