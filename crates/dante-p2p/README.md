# dante-p2p

libp2p transport for DaNTe's decentralised control plane.

**Status: workspace member, but not a default one.** `default-members` in the
root `Cargo.toml` omits this crate. It is used through the `p2p` feature of
`dante-core`, `dante-net` and `dante-relay`, which is **on by default in all
three** — so a bare root `cargo build` still pulls the libp2p dependency tree.
Build with `--no-default-features` for the lean TCP-only path, or this crate
directly with `-p dante-p2p` / `--workspace`.

## What it does

`Node::spawn(&ed25519_seed)` builds a libp2p `Swarm` and drives it from a
background Tokio task. Callers use async methods that post a command and await a
reply; noteworthy swarm events arrive on the `Event` receiver.

| libp2p behaviour | DaNTe role |
| --- | --- |
| Kademlia (`MemoryStore`, `/dante/kad/1.0.0`, server mode) | key directory: prekey bundles and identity records keyed by the 32-byte identity hash, plus relay provider records for DHT discovery |
| gossipsub (signed, strict validation) | fan-out for ledger records, prekeys, mailbox envelopes, MLS KeyPackages, and per-channel logs (`dante/chan/<hex>`) |
| identify | connection bring-up; feeds peer addresses into the kad routing table |
| ping | liveness |
| request-response (`/dante/relay/1`) | carries the opaque `dante-net` relay wire peer-to-peer: relay clients and relay↔relay backfill |

The sealed-sender mailbox stays on `dante-relay` — offline delivery needs a
storage supernode and does not belong on the DHT.

## Where it is used

- `dante-core` (feature `p2p`, default-on): DHT key-directory fallback for
  prekeys, ledger gossip, channel-log gossip.
- `dante-net` (feature `p2p`): the relay wire over `/dante/relay/1`, plus DHT
  relay discovery (`Client::connect_p2p_discover`).
- `dante-relay` (feature `p2p`, default-on): `--p2p-listen` accepts clients on
  `/dante/relay/1` and federates ledger / prekeys / mailbox / KeyPackages /
  channel logs with sibling relays over gossipsub.

`dante chat` / `dante serve` built with `p2p` expose `--p2p` / `--p2p-listen` /
`--bootstrap`.

## Build / test

```sh
cargo test -p dante-p2p
cargo test -p dante-core --features p2p   # includes the DHT-fallback e2e
```

In-process-swarm tests cover two nodes forming a gossipsub mesh, a DHT record
written on one node being resolved by a peer, relay discovery through provider
records, and a `/dante/relay/1` request round trip.

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
