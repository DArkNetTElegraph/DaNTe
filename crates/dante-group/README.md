# dante-group

**Retired.** The sender-keys ratchet that encrypted channels before the MLS
migration.

Each member kept a per-channel sender chain and shared the chain key over
authenticated pairwise DMs. It gave forward secrecy within a chain and removed
a departed member on an O(n) rekey — but not MLS's post-compromise security or
O(log n) rekey. Channels now use [`dante-mls`](../dante-mls/README.md).

No workspace crate depends on it. It is compiled only because the detached
`fuzz` crate exercises its decoders (`fuzz/fuzz_targets/group_state.rs`); it
stays in `default-members` so plain `cargo test` keeps the unit tests alive.

## Test

```sh
cargo test -p dante-group
```
