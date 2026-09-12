# dante-ledger

The verifiable append-only log — DaNTe's identity and server registry.

Not a blockchain: no mining and no global consensus. A record is accepted iff
its signature verifies and it satisfies the per-kind rules; global integrity
comes from an RFC 6962 Merkle tree over record encodings and consistency proofs
between signed tree heads.

## What's in it

- `Ledger` — append (`&mut self`), identity / key-rotation chains, the server
  directory index, `head`, `inclusion_proof`, `consistency_proof`, and
  deterministic TTL `evaporate` GC
- `LedgerParams` — TTL and PoW floors (`Default`: 90 days, registration /
  liveness floors from `dante-crypto`)
- `RecordStore` / `MemoryStore` — pluggable storage; only the in-memory store
  ships, callers persist records themselves
- `server` — `ServerRegister` / `ServerDelist` bodies and field limits
- `tombstone` — the node-generated evaporation record (`NULL_AUTHOR`)

Acceptance rules in one place: announce once per identity, liveness strictly
forward on a weekly bucket, rotations move the chain tip and never reuse a key,
revocation kills the chain and delists owned servers, profile updates are
tip-only and strictly ordered, and over-TTL records evaporate deterministically
to identical tombstones on every replica.

## Used by

`dante-relay` (replica behind `GetTreeHead` / `GetRecords`), `dante-core`
(announce / liveness / revoke / server registration / evaporation), `dante-cli`
and the desktop shell (`LedgerParams`). Record gossip, range sync and tree-head
comparison live in `dante-core` / `dante-net` / `dante-relay`, not here.

## Test

```sh
cargo test -p dante-ledger
```

23 unit tests cover every acceptance rule, Merkle inclusion / consistency proofs
for all leaf counts up to 40, and replica-convergent evaporation.
