# dante-proto

Canonical wire types and the binary codec shared across the DaNTe network
boundary.

A hand-rolled length-prefixed codec rather than serde + CBOR, so encoding is
canonical by construction: decoders reject trailing bytes, and fuzz / property
tests assert that decode → re-encode is byte-identical. Body semantics belong to
the owning crates (`dante-identity`, `dante-ledger`).

## What's in it

| Module | Surface |
| --- | --- |
| `enc` | `Writer` / `Reader` / `WireError` — the deterministic codec |
| `record` | body-agnostic `Record` envelope (`v`, `kind`, `body`, `author`, `created_ms`, signature) with `seal` / `verify_signature` / `id` / `encode` |
| `merkle` | RFC 6962 tree hashing, inclusion and consistency proofs |
| `head` | `TreeHead` + `SignedTreeHead` (sign / verify / encode) |
| `envelope` | sealed-sender `Envelope`: day-rotating 8-byte `recipient_hint`, padding to fixed size buckets, TTL; `SealedContent`, `recipient_hint` |
| `pow` | wire codec for `dante_crypto::pow::PowProof` |

## Used by

Every crate that touches the wire: `dante-identity`, `dante-ledger`,
`dante-dm`, `dante-group`, `dante-net`, `dante-relay`, `dante-core`, and the
`fuzz` targets. Depends only on `dante-crypto`.

## Test

```sh
cargo test -p dante-proto
```

30 unit tests + 7 property tests: codec round-trips, decoder totality on
arbitrary / truncated input, canonical re-encoding for `Record`, `Envelope` and
`SignedTreeHead`, Merkle vectors and proofs, and sealed-sender header privacy
(hint rotation, length padding, expiry).
