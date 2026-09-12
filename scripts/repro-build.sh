#!/usr/bin/env sh
# Reproducible release build of the `dante` CLI and `dante-relay`.
#
# Usage: scripts/repro-build.sh [OUT_DIR]      (default: dist)
#
# Produces OUT_DIR/dante, OUT_DIR/dante-relay and OUT_DIR/SHA256SUMS. Two runs
# from different checkout paths, or on different machines with the same OS,
# architecture and pinned toolchain, produce identical hashes. The release
# workflow uses the same script, so a locally rebuilt binary can be compared
# against the published SHA256SUMS byte for byte.
#
# See docs/REPRODUCIBLE_BUILDS.md for the full why and the verification steps.
set -eu

out="${1:-dist}"
root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
: "${CARGO_HOME:=$HOME/.cargo}"
: "${CARGO_TARGET_DIR:=$root/target}"
export CARGO_HOME CARGO_TARGET_DIR

# Build directories vary by machine and user and are embedded in panic
# locations and debug info unless rewritten. Map them onto fixed virtual
# paths (the choice of path is arbitrary; only its consistency matters).
# `$root` also covers the default target dir, which lives under it.
remap="--remap-path-prefix=$root=/dante"
remap="$remap --remap-path-prefix=$CARGO_HOME=/cargo"
remap="$remap --remap-path-prefix=$CARGO_TARGET_DIR=/dante-target"
export RUSTFLAGS="$remap"

# Nothing in the CLI/relay build reads a clock, but pin it anyway so a future
# build script cannot quietly introduce a timestamp. Overrides an inherited
# value so every builder uses the same one.
export SOURCE_DATE_EPOCH=0

# `--locked`: the committed Cargo.lock is the dependency set, never a silent
# update. `--release`: the profile in the root Cargo.toml is part of the
# reproduction recipe (opt-level 3, thin LTO, codegen-units 1, strip).
cargo build --locked --release -p dante-cli -p dante-relay

mkdir -p "$out"
cp "$CARGO_TARGET_DIR/release/dante" "$out/dante"
cp "$CARGO_TARGET_DIR/release/dante-relay" "$out/dante-relay"
cargo --version
rustc --version
( cd "$out" && sha256sum dante dante-relay > SHA256SUMS )
cat "$out/SHA256SUMS"
