# dante-p2p

libp2p transport prototype for DaNTe's Phase-3 decentralised control plane.

**Status: prototype, detached crate.** This is not a member of the root Cargo
workspace and is not wired into `dante-core` yet. It has its own `[workspace]`
table so the root `cargo deny` / `cargo test` gates are unaffected while the
libp2p dependency tree is still being vetted.

## What it does

`Node::spawn(&ed25519_secret)` builds a libp2p `Swarm` and drives it from a
background Tokio task. Callers use async methods that post a command and await a
reply; noteworthy swarm events arrive on the `Event` receiver.

| libp2p behaviour | DaNTe role |
| --- | --- |
| Kademlia (`MemoryStore`, `/dante/kad/1.0.0`, server mode) | key directory: `put_record` / `get_record` keyed by the 32-byte identity hash |
| gossipsub (signed, strict validation) | append-only log fan-out: transparency ledger, channel relay logs |
| identify | connection bring-up; feeds peer addresses into the kad routing table |
| ping | liveness |

The sealed-sender mailbox stays on `dante-relay` — offline delivery needs a
storage supernode and does not belong on the DHT.

## Build / test

```sh
cd crates/dante-p2p
cargo test
```

Tests use in-process swarms on `127.0.0.1`: two nodes forming a gossipsub mesh
and exchanging a message, and a DHT record written on one node being resolved by
a peer.

## Why it is detached

Running `cargo deny check` (against the repo-root `deny.toml`):

- **licenses / bans / sources — clean.** No `openssl`; `ring` / `rcgen` are
  license-clear.
- **advisories — one finding:** `paste` (RUSTSEC-2024-0436, unmaintained, no
  safe upgrade) via `netlink-packet-core` ← `if-watch` ← `libp2p-tcp`, which is
  unavoidable for TCP interface-watching on Linux. Same class as the already
  accepted `proc-macro-error2` finding.
- The `dns` libp2p feature is deliberately **off**: it pulls `hickory-proto`
  0.25, which has an unfixed DoS advisory (GHSA-q2qq-hmj6-3wpp). Bootstrap peers
  are given by IP multiaddr for now.

Folding this into the workspace waits on that advisory clearing (or an explicit
`advisories.ignore` entry with rationale) and on the `Engine` integration.
