# Relay directory

An opt-in list of public relays, checked periodically and shown on
[the status page](https://darknettelegraph.github.io/DaNTe/) so people
looking for one to connect to can see which are actually reachable right
now.

This is not how DaNTe discovers relays to talk to at runtime — that is
`--relay`/`--bootstrap`/`DANTE_BOOTSTRAP`, unrelated to this file. This is
purely a public-facing directory for humans.

## Listing yours

Add a block to [`registry.toml`](registry.toml) and open a PR:

```toml
[[relay]]
name = "example-community"
addr = "relay.example.org:9944"
contact = "you@example.org"   # optional; see below
```

- `name` — whatever you want shown on the status page.
- `addr` — `host:port`, the exact address you'd hand someone for
  `dante serve --relay ...` or `dante-relay --listen ...`'s advertised port.
  This has to be reachable from the public internet — see
  [What gets checked](#what-gets-checked).
- `contact` (optional) — never published or shown on the page. Only read by
  a maintainer, only if your relay has been down long enough to be worth a
  heads-up.

Keep entries alphabetical by `name`; it keeps diffs to one relay per PR.

**Onion (`.onion`) addresses can be listed too**, but the automated check
does not verify them yet — checking those needs a Tor client wherever the
check runs, which isn't wired up yet (see [`registry.toml`](registry.toml)'s
comments and `crates/dante-relay-check`'s module docs). They will show as
unchecked, not as offline, until that lands.

## What gets checked

A scheduled job connects to `addr` and sends the same `Ping` request a real
client would, over the real wire protocol — not a plain TCP connect, not an
ICMP ping. That is a genuine test of whether *your* relay is reachable from
outside your network, run from a real external vantage point (GitHub's own
infrastructure), which is exactly the thing a non-public IPv4 (common behind
CGNAT, which plenty of residential ISPs still use) will fail. If your relay
doesn't show as online, that check failing is almost always the reason —
confirm your `--listen` port is actually forwarded/open to the internet
before opening a PR.

Two attempts, a few seconds apart, before a relay is marked offline for that
run — a single transient blip doesn't flip your listing, but a relay that's
actually down or unreachable will show that way until it's fixed.

## Removing a listing

Open a PR removing your `[[relay]]` block. There's no other way to take a
relay off the page — it isn't derived from anything else, so nothing else
needs to change.
