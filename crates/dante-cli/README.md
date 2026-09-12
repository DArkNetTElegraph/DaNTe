# dante-cli

The `dante` binary and the shared `dante_cli` library behind `dante serve`.

## Subcommands

| Command | What it does |
| --- | --- |
| `dante gen --out KEYSTORE` | generate an identity, seal the keystore, print base32 + word fingerprints |
| `dante fp --keystore KEYSTORE` | print both fingerprint renderings |
| `dante chat --keystore … --relay …` | interactive terminal client: DMs, servers / channels, calls, roles, reactions, … |
| `dante serve --keystore … --relay … [--http 127.0.0.1:8080]` | local web UI: JSON API + embedded single-file SPA |
| `dante bot --keystore … --relay …` | headless JSON-lines bridge on stdio |
| `dante revoke --keystore … --relay … --yes` | publish an identity revocation |

The keystore passphrase comes from `DANTE_PASSPHRASE`. `--relay` accepts a
comma-separated list of `host:port` endpoints; with `p2p` (default) it also
accepts a libp2p multiaddr or the literal `dht` with `--bootstrap`. `chat` /
`serve` take `--p2p` / `--p2p-listen` / `--bootstrap` for the DHT key-directory
and ledger-gossip fallback.

## Library surface

`dante_cli` exposes `serve` (`run` / `run_on`, `Bootstrap`) and `unfurl`, plus
`now_ms` and `parse_fingerprint`. The desktop shell reuses `serve::run_on`
verbatim on its own ephemeral port.

- `serve.rs` — hand-rolled HTTP/1.1 server for the localhost JSON API + SSE,
  CSRF / DNS-rebinding guards, a single `engine_task`, and file uploads ≤ 9 MiB
- `unfurl.rs` — opt-in link previews: SSRF-guarded (public unicast only),
  redirect / size / time capped
- `web/index.html` — the whole SPA: one ~4.9k-line file with inline CSS / JS,
  embedded via `include_str!` and served under a strict nonce CSP

A complete endpoint list is in the `serve` module docs.

## Test

```sh
cargo test -p dante-cli
```

Unit tests cover the ICE refresh window, the CSRF guard, typing coalescing, and
unfurl's SSRF checks / OpenGraph scraping. There is no HTTP-level or SPA test
suite; the binary's chat / bot loops are exercised only by hand.
