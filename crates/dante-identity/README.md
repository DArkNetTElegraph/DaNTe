# dante-identity

Identity lifecycle for DaNTe: keys, fingerprints, the on-disk keystore, and the
identity ledger records.

An identity is a keypair, nothing more:

- `idk` — Ed25519 signing key, the root of the identity
- `ik` — X25519 agreement key, published for X3DH / sealed sender
- a local message-store key

No phone number, email, payment or invite is involved.

## What's in it

| Module | Surface |
| --- | --- |
| `identity` | `Identity` — `(idk, ik)` plus the store key; zeroizes on drop |
| `id` | `IdentityId = SHA-256(idk_pub)`, Crockford-base32 and 24-word BIP39 renderings, pairwise `safety_number` |
| `keystore` | Argon2id + XChaCha20-Poly1305 sealed keystore ([`docs/PROTOCOL.md`](../../docs/PROTOCOL.md) §1.2) |
| `backup` | passphrase-encrypted recovery blob (§1.3) |
| `records` | `IdentityAnnounce`, `LivenessProof`, `KeyRotation`, `IdentityRevoke`, `IdentityProfile` bodies, their PoW / link challenges, and `Record` wrapping (§2.2) |

`Identity::p2p_node_seed()` derives the stable libp2p node key without leaking
the identity key.

## Used by

`dante-ledger` (rotation / revocation chain state), `dante-dm` (X3DH, file
manifests), `dante-core` (identity lifecycle, announcements, revocation),
`dante-cli` / `dante-desktop` (keystore create / unlock / import).

## Notes

- `KeyRotation::to_record` / `IdentityRevoke::to_record` sanity-check the new
  key / subject with `debug_assert_eq!` only; `dante-ledger` enforces the rules
  on append.
- The keystore accepts a hostile KDF header but clamps cost (≤ 2 GiB memory,
  ≤ 16 passes).
- There is deliberately no operator recovery path.

## Test

```sh
cargo test -p dante-identity
```

Covers base32 / word-phrase round-trips and normalisation, safety-number shape
and order-independence, keystore wrong-passphrase / tamper / cross-context
rejection, and announce / liveness / rotation / revoke verification.
