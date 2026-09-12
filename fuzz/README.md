# Fuzzing the wire decoders

Coverage-guided fuzz targets for the parsers that sit on the untrusted network
boundary. This crate is **detached from the main workspace** — `cargo
build/test/clippy --workspace` never builds it. The `Fuzzing` workflow
(`.github/workflows/fuzz.yml`) runs every target for a fixed 60 s on a weekly
schedule, on PRs that touch `fuzz/`, and on demand, caching the corpus between
runs; a crash fails that job and uploads the reproducer.

Each target decodes an arbitrary byte string and, for the length-prefixed
types, asserts `encode(decode(bytes)) == bytes` (canonical form). A panic, an
over-read, or a non-canonical decode is a finding.

## Running

Needs a nightly toolchain, a C/C++ toolchain (libFuzzer is compiled from
source), and `cargo-fuzz`:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run proto_record        # or any target below
```

Targets: `proto_record`, `proto_envelope`, `dm_packet`, `net_wire`.

The targets call the same decoder API as the `proptest` suites in each crate
(`src/proptests.rs`); those run on stable in CI and cover the same surface with
random-but-not-coverage-guided input.
