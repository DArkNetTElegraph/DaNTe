# dante-net

The transport and relay protocol: the client↔relay wire, the relay-side mailbox
and rate limiter, and the client sync helpers.

Clients open a framed TCP connection to one or more community relays; with the
`p2p` feature the same wire also rides a libp2p `/dante/relay/1` stream. This
crate is transport-only — no identity or ledger acceptance logic lives here.

## What's in it

| Module | Surface |
| --- | --- |
| `wire` | `Request` / `Response`: ledger sync, mailbox, prekeys, key packages, blobs, channel logs, signals, ICE, p2p peers; canonical encode / decode |
| `transport` | `Client` (multi-endpoint failover, SOCKS5 for `.onion`, p2p backend with health scoring and rendezvous-hash channel routing), `serve`, the `RequestHandler` trait; `MAX_FRAME` = 8 MiB |
| `mailbox` | sealed-sender store-and-forward keyed by the 8-byte recipient hint, with TTL / clock-skew / depth / byte caps |
| `ratelimit` | token-bucket `KeyedRateLimiter` with an explicit clock |
| `socks5` | minimal no-auth SOCKS5 client for Tor |
| `sync` | the high-level helpers `dante-core` actually calls |

## Used by

`dante-core` (every request, the p2p transport, the e2e suite), `dante-relay`
(`serve`, `Mailbox`, `KeyedRateLimiter`, `IceCfg`), and the `fuzz` target
`net_wire`. Feature `p2p` adds the `dante-p2p` backend.

## Notes

- Mailbox `fetch` does not remove entries; delivery is idempotent and TTL GC is
  the only deletion path.
- `pull_records` skips undecodable records silently; the caller persists the
  cursor.
- SOCKS5 supports the domain address type and no-auth only.
- `dante-identity` / `dante-ledger` are declared dependencies but unused in
  `src/`.

## Test

```sh
cargo test -p dante-net
cargo test -p dante-net --features p2p
```

Covers wire round-trips and rejections, mailbox TTL / depth / byte caps, rate
limiting, reconnect and multi-endpoint failover, SOCKS5 against a stub proxy,
and p2p channel-routing agreement across clients and shards.
