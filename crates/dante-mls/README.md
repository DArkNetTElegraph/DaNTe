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

Groundwork, not yet wired into `dante-core`. Covered:

- `Member::create` — start a group
- `Member::publish_key_package` → `Pending::join` — be added to one
- `Member::add` / `remove` — membership changes, epoch advances
- `Member::encrypt` / `process` — application messages + inbound commits
- `Member::call_key` — the group-call media key for the current epoch

Group state currently lives in an in-memory OpenMLS store; serializing it for
restart-persistence is a prerequisite for the `dante-core` integration.

## Why it's detached from the workspace

Like `crates/dante-audio` and `apps/dante-desktop`, this crate has its own
`[workspace]` and is **not** a member of the root workspace. OpenMLS's current
release pulls a crypto stack (`hpke-rs` → `libcrux-sha3` 0.0.8, plus the
`hax-lib` proc-macros) that trips four RUSTSEC advisories the root `cargo deny`
gate rejects (RUSTSEC-2026-0207/0208/0212 in the SHA-3/SHAKE code, which our
`…_SHA256_…` ciphersuite does not exercise, and RUSTSEC-2026-0173 for an
unmaintained build-time proc-macro). Since nothing ships against it yet,
keeping it out of the gate is the same call already made for the audio stack.

When MLS is integrated for real, revisit with a fixed OpenMLS release or a
documented `[advisories] ignore` list and fold this back into the workspace.

## Test

```sh
cd crates/dante-mls && cargo test
```

[OpenMLS]: https://openmls.tech
