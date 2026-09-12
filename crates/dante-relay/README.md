# dante-relay

A community-run relay node: the store-and-forward and sync anchor of a DaNTe
community.

`RelayState` holds a ledger replica, the sealed-sender mailbox, prekey and MLS
key-package directories, a content-addressed blob store, per-channel ordered
logs and ephemeral signals. It speaks the `dante-net` request / response wire
over framed TCP — and, with the default `p2p` feature, over libp2p
`/dante/relay/1` — federating ledger / prekeys / mailbox / KeyPackages / channel
logs with sibling relays over gossipsub. It can run an in-process TURN server
and hands clients signed ICE config. It sees only ciphertext, routing hints,
sizes and timing.

## The binary

`dante-relay` flags:

- `--listen 127.0.0.1:9944` (repeatable) — framed TCP
- `--p2p-listen <multiaddr>` + `--p2p-bootstrap` — libp2p clients + federation
  (`--p2p-seed` pins a stable node key)
- `--stun` / `--turn` / `--turn-secret` / `--turn-ttl` / `--turn-listen` /
  `--turn-public-ip` — ICE
- `--min-pow-bits` / `--min-pow-m-cost-kib` / `--min-pow-t-cost` — ledger
  acceptance floors

All state is in memory (`MemoryStore`): a restart starts a fresh replica, then
resyncs from peers. Prefer `DANTE_TURN_SECRET` over `--turn-secret` so the
secret stays out of `argv` / process listings.

Operator guide: [`docs/RUNNING_A_RELAY.md`](../../docs/RUNNING_A_RELAY.md).
systemd unit: [`deploy/dante-relay.service`](../../deploy/dante-relay.service).

## Used by

Deployed as a process; `dante-core` uses it as a dev-dependency to run an
in-process relay for its e2e suite. It links `dante-net`, `dante-ledger`,
`dante-dm` and (feature `p2p`) `dante-p2p`.

## Test

```sh
cargo test -p dante-relay
```

Covers store-and-fetch for every directory, rate limiting, one-time prekeys and
last-resort KeyPackages, TURN credential minting, federation ingest / outbox
dedup, writer step-down on channel-log overtake, and the in-process TURN server
(credential accept / reject).
