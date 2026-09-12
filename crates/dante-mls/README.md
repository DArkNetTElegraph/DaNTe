# dante-mls

MLS (RFC 9420) groups for DaNTe, a thin wrapper over [OpenMLS].

This is the building block for two things:

1. **Channels** — every server channel is one MLS group, replacing the retired
   sender-keys ratchet in `dante-group`; the host is the sole committer.
2. **Group calls** — every member can independently derive the same per-epoch
   media key (`Member::call_key`), and it rotates on every join/leave.

The crate is transport-agnostic: `add` / `remove` hand back opaque
`Handshake` byte blobs (Commit + optional Welcome) that DaNTe delivers over its
authenticated pairwise DMs / channel log, and `process` takes the bytes back.

## Status

Driven by `dante-core` for every channel and every group call. Covered:

- `Member::create` — start a group
- `Member::publish_key_package` → `Pending::join` — be added to one
- `Member::add` / `remove` — membership changes, epoch advances
- `Member::encrypt` / `process` / `process_from` — application messages + inbound
  commits (host-only gating via `process_from`)
- `Member::call_key` — the group-call media key for the current epoch
- `Member::export` / `import` — serialize the whole member (OpenMLS store +
  signature key + reload handles) to a byte blob DaNTe keeps in its own
  encrypted local state, so a call / channel survives a restart

The `dante-core` group-call state machine (KeyPackage fetch, Welcome / Commit
over the channel log, media mesh) and the N-party audio path are in place. The
browser SPA carries real mic audio for 1:1 calls, ad-hoc group calls and voice
channels (runtime-verified 2026-09-12), and the desktop shell bridges
`dante-audio` for native capture / playback.

## Notes

- Requires Rust 1.91 (OpenMLS 0.9's floor), which is now the workspace floor.
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
