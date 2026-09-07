<!-- Keep PRs focused. Unrelated changes belong in a separate PR. -->

## Summary

<!-- What does this change and why? -->

## Related

<!-- Refs #issue, roadmap phase (see docs/DESIGN.md), or Discussion link. -->

## Checklist

- [ ] `cargo fmt --all` clean
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean
- [ ] `cargo test --workspace --all-features` passes
- [ ] `cargo deny check` passes
- [ ] Tests added/updated for the change (and for any bug it fixes)
- [ ] Docs in `docs/` updated if behaviour or structure changed
- [ ] All commits `Signed-off-by` (DCO — `git commit -s`)

## Security / protocol impact

- [ ] This PR does **not** touch cryptography, wire formats, or the threat model.

<!-- If it does, delete the line above and complete this section: -->
<!--
- [ ] `docs/PROTOCOL.md` updated and version bumped where needed
- [ ] `docs/THREAT_MODEL.md` reviewed; guarantees still hold or are amended here
- [ ] RFC / reference-implementation test vectors included
- [ ] Secrets zeroized; no secret-dependent branching on non-constant-time paths
- [ ] Requested a second reviewer for the security-relevant parts
-->
