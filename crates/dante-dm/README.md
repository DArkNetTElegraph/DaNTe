# dante-dm

End-to-end-encrypted 1:1 messaging: X3DH + Double Ratchet, the DM wire, typed
payloads, and chunked file transfer ([`docs/PROTOCOL.md`](../../docs/PROTOCOL.md)
§4.3).

## What's in it

- `x3dh` — first contact: `PreKeyBundle` / `PreKeySecrets`, one-time prekeys
- `ratchet` — the Signal Double Ratchet with unencrypted headers; forward
  secrecy + post-compromise security, skipped message keys up to `MAX_SKIP`
- `session` — `Session` ties them together; `InitMessage` is first contact,
  `DmMessage` every message after
- `content` — the typed `Content` payloads carried over a session: text, file,
  channel control, typing, reactions, edits, calls, voice signals
- `file` — `FileManifest`, `CHUNK_SIZE`, `blob_id`: chunked AEAD file transfer
  over the relay blob store

## Used by

`dante-core` (all DM send / receive, file reassembly, the encrypted store),
`dante-relay` (`PreKeyBundle::decode` validates the prekey directory), and the
`fuzz` target `dm_packet`. The local encrypted message store itself lives in
`dante-core`.

## Notes

- Ratchet headers are unencrypted, as in Signal.
- `Content::Forward.origin` is display-only and unauthenticated.
- File chunks are individually AEAD-sealed; `FileManifest` verifies count,
  order and per-chunk hashes.

## Test

```sh
cargo test -p dante-dm
```

Unit tests cover X3DH agreement with and without a one-time prekey, ratchet
reordering / dropped messages / tamper / skip cap, one-time-prekey single-use,
and session export / import. Property tests assert decoders are total and that
any reordering of a message batch decrypts exactly once.
