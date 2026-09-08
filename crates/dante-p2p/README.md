# dante-p2p

libp2p transport for DaNTe's decentralised control plane.

**Status: workspace member, but not a default one.** `default-members` in the
root `Cargo.toml` omits this crate, so a bare `cargo build` / `cargo test` never
pulls the libp2p dependency tree. Build it explicitly with `-p dante-p2p`, or
with `--workspace`. It is reached from the rest of the project only through the
opt-in `p2p` feature of `dante-core` / `dante-cli`.

## What it does

`Node::spawn(&ed25519_seed)` builds a libp2p `Swarm` and drives it from a
background Tokio task. Callers use async methods that post a command and await a
reply; noteworthy swarm events arrive on the `Event` receiver.

| libp2p behaviour | DaNTe role |
| --- | --- |
| Kademlia (`MemoryStore`, `/dante/kad/1.0.0`, server mode) | key directory: `put_record` / `get_record` keyed by the 32-byte identity hash |
| gossipsub (signed, strict validation) | append-only log fan-out (future: ledger, channel logs) |
| identify | connection bring-up; feeds peer addresses into the kad routing table |
| ping | liveness |

The sealed-sender mailbox stays on `dante-relay` — offline delivery needs a
storage supernode and does not belong on the DHT.

## Where it is used

`dante-core` (feature `p2p`) wires the DHT in as a **key-directory fallback**:
`Engine::enable_p2p` starts a node, `publish_prekeys` mirrors the prekey bundle
onto the DHT, and first-contact resolution falls back to a DHT `get_record` when
the relay has no bundle. `dante chat` / `dante serve` built `--features p2p`
expose `--p2p` / `--p2p-listen` / `--bootstrap`.

## Build / test

```sh
cargo test -p dante-p2p
cargo test -p dante-core --features p2p   # includes the DHT-fallback e2e
```

In-process-swarm tests cover two nodes forming a gossipsub mesh and a DHT record
written on one node being resolved by a peer.

## Dependency notes

`cargo deny` against the repo-root `deny.toml`:

- **licenses / bans / sources — clean.** No `openssl`; `ring` / `rcgen` are
  license-clear.
- **advisories — one ignore:** `paste` (RUSTSEC-2024-0436, unmaintained, no CVE,
  no safe upgrade) reaches us via `netlink-packet-core` ← `if-watch` ←
  `libp2p-tcp`, which libp2p needs for TCP interface-watching on Linux. It is a
  build-time proc-macro helper with no runtime code. Documented in `deny.toml`.
- The `dns` libp2p feature is deliberately **off**: it pulls `hickory-proto`
  0.25, which has an unfixed DoS advisory (GHSA-q2qq-hmj6-3wpp). Bootstrap peers
  are given by IP multiaddr.
