# dante-relay-check

Checks the opt-in relay registry
([`relays/registry.toml`](../../relays/registry.toml)) and writes the status
document behind the published status page.

The registry is a plain list relay operators add themselves to via a PR —
nothing here *scans* for relays on its own, which would mean fingerprinting
operators (onion relay operators especially) who never agreed to be public. But
once at least one relay in a federated cluster is listed, this follows the graph
outward: a listed relay is asked (`Request::GetP2pPeers`) for the addresses it
knows about, and each new one is verified and published too, up to a bounded
depth (3 hops) and total (100 relays). An `[[exclude]]` entry opts a
discovered peer out of checking and publishing entirely.

"Online" means a real protocol round trip succeeded: `Request::Ping` →
`Response::Pong` over the same wire a client uses — plain framed TCP for a
registry entry, or the actual libp2p connection for a discovered multiaddr.
What a relay *reports* about its peers is never published unverified; it is only
ever a lead to go check. Each relay gets two attempts, 8 s each, so a transient
blip on the runner's network does not flap the page.

Not covered yet: relays reachable only over Tor. They can still be listed; they
just show as unchecked.

## Usage

```sh
cargo run -p dante-relay-check -- [registry.toml] [status.json]
```

Both paths are positional and default to `relays/registry.toml` and
`status.json`. [`relay-status.yml`](../../.github/workflows/relay-status.yml)
runs it on a schedule and publishes the result.

## Test

No unit tests yet; it is exercised end to end by the scheduled workflow against
the live registry.
