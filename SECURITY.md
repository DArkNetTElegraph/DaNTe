# Security Policy

DaNTe is pre-1.0 software implementing cryptographic protocols. **Do not use it
to protect anything you cannot afford to have exposed.** It has not been audited.

## Supported versions

Until the first tagged release, only the `main` branch is supported. There are no
backports.

## Reporting a vulnerability

**Do not open a public issue, pull request, or Discussion for a security
problem.**

**GitHub Private Vulnerability Reporting** is the channel — on this repository,
go to the **Security** tab → **Report a vulnerability**. This opens a private
advisory visible only to you and the maintainers, and needs no email address.

<!-- Maintainers: before the first tagged release, set up a dedicated role
address (e.g. security@your-domain) with a published PGP/age key and list it
here as a fallback. Do not use a personal email address. -->

Please include:

- affected component(s) and commit hash,
- a description of the issue and its impact,
- reproduction steps or a proof of concept,
- any suggested remediation.

## What is in scope

- Anything that breaks a guarantee stated in
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §4 against an adversary that
  document says it defends against.
- Cryptographic mistakes: protocol misuse, weak parameters, nonce reuse, missing
  authentication, downgrade paths, key-material leakage, non-constant-time
  handling of secrets.
- Deviations from [`docs/PROTOCOL.md`](docs/PROTOCOL.md) that weaken security.
- Memory-safety issues, panics reachable from untrusted network input, and
  denial-of-service via malformed messages.

## What is **not** in scope

The items listed as non-goals in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
§5 are known limitations, not vulnerabilities. In particular: endpoint
compromise, a server member reading a private channel they belong to,
large-scale traffic analysis, and IP-address exposure to peers/relays. Reports
about these will be closed with a pointer to the threat model — but a
*well-argued case that the threat model itself is wrong* is welcome through the
private channels above.

## Disclosure process

1. Acknowledge receipt within **7 days**.
2. Confirm the issue and agree on a severity and target fix window with you
   through the advisory thread.
3. Develop and review a fix privately; add regression tests.
4. Publish a GitHub Security Advisory crediting you (unless you ask to remain
   anonymous), release the fix, and only then discuss details publicly.

We aim to keep the private window under 90 days. Coordinated disclosure is
expected; please do not disclose publicly before the advisory is published.

## Safe harbor

Good-faith security research that respects users' privacy, avoids data
destruction and service disruption, and uses only accounts/servers you control
or have permission to test will not be pursued by the project. This is not a paid
bug-bounty program.
