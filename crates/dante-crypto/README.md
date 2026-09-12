# dante-crypto

Cryptographic primitives for DaNTe — the bottom of the dependency graph.

Thin, policy-free wrappers only: no I/O, no application logic, no `unsafe`
(`unsafe_code = "forbid"`). Wrappers are checked against RFC / reference test
vectors where published vectors exist, and against round-trip + tamper tests
otherwise.

## What's in it

| Module | Surface |
| --- | --- |
| `sign` | Ed25519 (RFC 8032), strict and lenient verify |
| `agree` | X25519 (RFC 7748), low-order rejection |
| `aead` | XChaCha20-Poly1305 and AES-256-GCM |
| `kdf` | HKDF-SHA-256 (RFC 5869) extract / expand / derive |
| `mac` | HMAC-SHA-256 (RFC 4231) |
| `hash` | SHA-256 / SHA-512, plus `sha256_parts` |
| `pwhash` | Argon2id KDF for low-entropy secrets (keystore, backup) |
| `pow` | The `argon2id-pow` memory-hard registration / liveness puzzle |
| — | `random_array` / `fill_random` (OS CSPRNG) |

`CryptoError` is the single error type; secrets zeroize on drop.

The Double Ratchet lives in `dante-dm` and the MLS (RFC 9420) wrapper in
`dante-mls`; both build on these primitives.

## Used by

Every crate in the workspace, directly or transitively. This is a leaf node —
it has no DaNTe dependencies.

## Test

```sh
cargo test -p dante-crypto
```

Covers RFC 8032 / 7748 / 5869 / 4231 vectors, SHA-2 known answers, AEAD
round-trips and tamper rejection, Argon2id determinism, and PoW difficulty
binding / downgrade rejection / cost-bomb ceilings.
