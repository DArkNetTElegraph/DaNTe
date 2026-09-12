# Contributing to DaNTe

Thanks for your interest. DaNTe is a peer-to-peer, end-to-end-encrypted chat
application; correctness of the cryptography and the protocol matters more than
velocity. Please read this before opening a pull request.

## Ground rules

- **Pre-1.0.** Wire formats, APIs, and on-disk formats change without notice and
  without migration. Don't build anything external against `main` yet.
- **Discuss big changes first.** Anything that touches
  [`docs/PROTOCOL.md`](docs/PROTOCOL.md), the threat model, a crate boundary, or
  a roadmap phase should start as a GitHub **Discussion** or issue, not a
  surprise PR.
- **Stay on-phase.** [`docs/DESIGN.md`](docs/DESIGN.md) defines an ordered
  roadmap. Work that jumps ahead of the current phase will usually be asked to
  wait.
- **No telemetry, ever.** No analytics, phone-home, crash reporting to a project
  server, or bundled third-party SDKs that do any of these.
- **Licensing.** Contributions are licensed under **AGPL-3.0-or-later**, the same
  as the project. By submitting a PR you certify the DCO (below).

## Cryptography changes — extra requirements

Any change under `crates/dante-crypto`, or that alters how keys, nonces,
ciphertexts, signatures, or KDF inputs are produced or consumed, must:

1. Cite the RFC or reference implementation it follows, and include **test
   vectors from that source** in the PR.
2. Use vetted crates and constructions — **no home-rolled primitives or novel
   protocol combinations.** See the cryptographic-posture section of
   [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
3. Keep secret-dependent code paths constant-time; use `zeroize` for key
   material; never log secrets or plaintext.
4. Update [`docs/PROTOCOL.md`](docs/PROTOCOL.md) in the same PR if the wire
   format or parameters change, and note the version bump.
5. Expect a slower, more thorough review. Security-relevant PRs need a second
   reviewer.

## Development setup

Install Rust via [rustup](https://rustup.rs); the toolchain version is pinned in
[`rust-toolchain.toml`](rust-toolchain.toml) and installed automatically on first
`cargo` run.

- Fedora: `sudo dnf install rustup @development-tools pkgconf-pkg-config && rustup-init -y`
- Other: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

## Before you push

All four must pass — CI enforces them:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check      # cargo install cargo-deny
```

Also:

- Update docs in `docs/` when behaviour or structure changes.
- Add tests for new behaviour and for every bug you fix.
- Keep PRs focused; unrelated changes belong in separate PRs.

## Commit and PR conventions

- Write imperative, present-tense subject lines ≤ 72 chars
  (`Add X3DH session initiation`, not `added` / `adds`). Explain *why* in the
  body when it isn't obvious.
- Reference the relevant phase or issue (`Refs #12`, `Phase 2`).
- Rebase on `main` rather than merging it into your branch.
- **Open every PR with base `main`**, even one that builds on another
  still-open PR — merge or rebase that PR's branch into yours locally first,
  then open against `main` regardless. Opening against the other PR's branch
  instead means a squash-merge later lands on that branch, not `main`, and the
  change silently never reaches production even though the PR shows as merged.
  Confirm with `gh pr view <N> --json baseRefName` before calling a PR done.
- Fill in the pull-request template. Draft PRs are welcome for early feedback.

### Developer Certificate of Origin (DCO)

Every commit must be signed off:

```bash
git commit -s -m "Your message"
```

This adds a `Signed-off-by: Name <email>` trailer certifying you wrote the patch
or otherwise have the right to submit it under the project license
(see <https://developercertificate.org>). There is no separate CLA.

## Reporting bugs and vulnerabilities

- **Security vulnerabilities:** follow [`SECURITY.md`](SECURITY.md) — never a
  public issue.
- **Ordinary bugs and features:** use the issue templates.
- **Questions and design debate:** GitHub Discussions.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating you are expected to uphold it.
