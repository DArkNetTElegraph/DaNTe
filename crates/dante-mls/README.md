# dante-mls

MLS (RFC 9420) groups for DaNTe, a thin wrapper over [OpenMLS].

This is the building block for two things:

1. **Migrating channels** off the sender-keys ratchet in `dante-group` — MLS
   adds post-compromise security and O(log n) rekey.
2. **Group calls** — every member can independently derive the same per-epoch
   media key (`Member::call_key`), and it rotates on every join/leave.

The crate is transport-agnostic: `add` / `remove` hand back opaque
`Handshake` byte blobs (Commit + optional Welcome) that DaNTe delivers over its
authenticated pairwise DMs / channel log, and `process` takes the bytes back.

## Status

Not yet driven by `dante-core`. Covered:

- `Member::create` — start a group
- `Member::publish_key_package` → `Pending::join` — be added to one
- `Member::add` / `remove` — membership changes, epoch advances
- `Member::encrypt` / `process` — application messages + inbound commits
- `Member::call_key` — the group-call media key for the current epoch
- `Member::export` / `import` — serialize the whole member (OpenMLS store +
  signature key + reload handles) to a byte blob DaNTe keeps in its own
  encrypted local state, so a call / channel survives a restart

Remaining before group calls work end to end: a `dante-core` group-call state
machine (fetch members' KeyPackages, carry Welcome / Commit over the channel
log, open the media mesh) and the N-party audio path.

## Notes

- Requires Rust 1.91 (OpenMLS 0.9's floor); declared per-crate, the rest of the
  workspace still builds on 1.85.
- One transitive advisory is allow-listed in the repo `deny.toml`:
  RUSTSEC-2026-0173 (`proc-macro-error2` unmaintained) — a build-time
  proc-macro from the libcrux stack with no runtime exposure and no fix
  available upstream.
- Our newtype is `KeyPkg`, not `KeyPackage` (which collides with the OpenMLS
  prelude glob). `MlsMessageIn::into_welcome()` is test-only in OpenMLS — use
  `.extract()` + match `MlsMessageBodyIn::Welcome`.

## Test

```sh
cargo test -p dante-mls
```

[OpenMLS]: https://openmls.tech
