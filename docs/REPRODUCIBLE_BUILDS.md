# Reproducible builds & release verification

This document is for a skeptical user who downloaded a release and wants to
confirm it was built from the published source by the project's release
workflow — without trusting the download.

> **Status: Linux x86_64 only, verified locally by building twice from
> different checkout paths and diffing hashes.** Windows, macOS and the
> detached Tauri desktop shell are **not** claimed reproducible (see
> [Limitations](#limitations)). An external security audit is still pending
> and is not something this document replaces.

## What you get

Each `v*` tag produces a GitHub Release with:

| Asset | What it is |
|---|---|
| `dante` | the CLI binary (contains `gen` / `fp` / `chat` / `serve` / `bot` / `revoke`) |
| `dante-relay` | the relay binary |
| `SHA256SUMS` | `sha256sum` lines for the two binaries above |
| `SHA256SUMS.bundle` | cosign signature + certificate + transparency-log bundle for `SHA256SUMS` |

The release workflow (`.github/workflows/release.yml`) runs only on tag pushes.
It builds with `scripts/repro-build.sh`, which is the same command documented
below, and signs the checksum file keyless via Sigstore — the signature is
bound to the workflow identity, and the signing key exists only for the
duration of the job.

## Reproduce the build

You need the same OS and architecture (Linux x86_64) and nothing else: no
Docker, no project keys.

1. **Get the source at the release tag** (replace `v0.0.1` with the release
   you are verifying):

   ```sh
   git clone https://github.com/DArkNetTElegraph/DaNTe
   cd DaNTe
   git checkout v0.0.1
   ```

2. **Install Rust.** [`rust-toolchain.toml`](../rust-toolchain.toml) pins the
   exact compiler (currently `1.98.1`); `rustup` installs it automatically on
   the first `cargo` invocation. If you do not have rustup:
   <https://rustup.rs>.

   ```sh
   rustc --version   # must print 1.98.1
   ```

3. **Build and hash:**

   ```sh
   scripts/repro-build.sh dist
   ```

   This runs (so you can also type it yourself):

   ```sh
   RUSTFLAGS="--remap-path-prefix=$PWD=/dante \
              --remap-path-prefix=$HOME/.cargo=/cargo \
              --remap-path-prefix=$PWD/target=/dante-target" \
   SOURCE_DATE_EPOCH=0 \
   cargo build --locked --release -p dante-cli -p dante-relay
   ```

4. **Compare against the published checksums.** Download `SHA256SUMS` next to
   the binaries the script wrote, then check it:

   ```sh
   curl -L -o dist/SHA256SUMS \
     https://github.com/DArkNetTElegraph/DaNTe/releases/download/v0.0.1/SHA256SUMS
   ( cd dist && sha256sum -c SHA256SUMS )
   ```

   Or diff by eye:

   ```sh
   sha256sum dist/dante dist/dante-relay
   ```

If the hashes match, the binary you are about to run is the one built from
this exact source, by anyone following the recipe — including you.

### Why the build is deterministic

- **Exact toolchain.** `rust-toolchain.toml` pins `1.98.1`; a floating
  `stable` would resolve differently over time (and has already changed a
  clippy lint out from under the desktop shell). Same compiler, same output.
- **`--locked`.** The committed `Cargo.lock` is the dependency set; a build
  can never silently pick up a different crate version.
- **`--remap-path-prefix`.** Absolute paths (`/home/you/...`, the cargo
  registry cache, the target directory) are rewritten to fixed virtual paths
  (`/dante`, `/cargo`, `/dante-target`). Without this, panic locations and
  debug info carry machine-specific paths.
- **`SOURCE_DATE_EPOCH=0`.** Nothing in the CLI/relay build reads a clock —
  only `apps/dante-desktop`, which is detached and out of scope — but pinning
  the variable means a future build script cannot introduce a timestamp
  unnoticed.
- **Release profile.** `opt-level = 3`, `lto = "thin"`, `codegen-units = 1`,
  `strip = true` (root `Cargo.toml`). Serialized codegen plus stripping removes
  the ordering and symbol-name variance that parallelism and unstripped
  symbols can introduce.

## Verify the signature

The checksum file is signed with [cosign] in keyless mode. The signature is
tied to the `Release` workflow in this repository at the tag, not to a private
key that could be stolen or lost.

```sh
# one-time
go install github.com/sigstore/cosign/v2/cmd/cosign@latest   # or your package manager

curl -LO https://github.com/DArkNetTElegraph/DaNTe/releases/download/v0.0.1/SHA256SUMS
curl -LO https://github.com/DArkNetTElegraph/DaNTe/releases/download/v0.0.1/SHA256SUMS.bundle

cosign verify-blob \
  --bundle SHA256SUMS.bundle \
  --certificate-identity-regexp \
    '^https://github\.com/DArkNetTElegraph/DaNTe/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS
```

A successful verification means: this checksum file was signed by a GitHub
Actions run of *this repository's* release workflow for a `v*` tag
(`--certificate-identity-regexp`), via GitHub's OIDC issuer
(`--certificate-oidc-issuer`), and the signature is recorded in the Sigstore
transparency log. Then `sha256sum -c SHA256SUMS` ties the binaries to the
signed file.

### What signing does and does not prove

- **Proves:** the artifacts were produced by the `release.yml` workflow from a
  commit in this repository tagged with that version, and have not been
  altered since.
- **Does not prove:** the source is free of bugs or backdoors. A compromised
  maintainer account, the workflow file itself, or the build toolchain could
  still produce a signed artifact the user would not want. That is what an
  external audit and continued review are for; signing raises the cost of a
  silent substitution, it does not eliminate trust.

## Limitations

- **Linux x86_64 only.** The release job builds on `ubuntu-latest`; the hash
  is valid for that target. Cross-OS reproducibility is not claimed.
- **The build host matters.** Native builds link against the host's linker
  and C library; a different distribution (or even a much newer glibc) can
  change the bytes even with identical source and toolchain. The path-remap
  technique removes machine-*path* variance, which the local two-path proof
  below covers; it cannot normalize the linker. Reproduce on a matching Linux
  image if you need the hash to match exactly.
- **The desktop shell is out of scope.** `apps/dante-desktop` is a detached
  workspace with a Tauri `build.rs`, native webview/audio dependencies and its
  own toolchain; nothing there is claimed reproducible.
- **The toolchain version is part of the recipe.** Rebuilding with a different
  `rustc` will almost certainly change the bytes — that is expected, and why
  the toolchain is pinned.
- **This was verified by building twice at two different absolute paths with
  two different target directories and comparing hashes** (byte-identical;
  see the PR that added this document), not by an independent third party. If
  you find a mismatch, please open an issue with the output — a
  reproducibility bug is a real bug.

[cosign]: https://docs.sigstore.dev/cosign/overview/
