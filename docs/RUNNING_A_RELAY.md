# Running a DaNTe relay

Everything in DaNTe works on `127.0.0.1`, and none of it is *proven* there. A
relay other people can reach is what turns a local demo into something two
people on different networks can use — and it is the only way to find out
whether the parts that have never been exercised (NAT traversal, voice across
real networks, relay federation) work at all.

The project runs no infrastructure. A relay is run by whoever wants one.

This doc covers the dedicated `dante-relay` binary — the right choice for a
homelab box or VPS that should keep relaying whether or not your own client
happens to be open. If you just want a relay online whenever you're chatting,
`dante serve --also-relay` runs the exact same code in-process instead — see
the README's [Every client can opt in as a
relay](../README.md#every-client-can-opt-in-as-a-relay). Everything below
(TURN, Tor, the port table, what an operator can see) applies identically
either way.

**The default way to run one is as a Tor onion service.** It needs no public
IP, no port forwarding and no VPS — a laptop or a spare box at home is enough —
and it is the only configuration in which the relay does not learn its users'
IP addresses. If you want a plain public host instead, see
[Without Tor](#without-tor-a-public-host) at the end.

## What a relay is, and is not

It is a **meeting point**, not a server that owns anything:

- a store-and-forward **mailbox** for sealed-sender envelopes,
- a replica of the append-only **ledger** (identities, servers, revocations),
- a **prekey / key-package directory** so people can start conversations,
- a **blob store** for file chunks,
- a per-channel **log** that members read and the host writes,
- optionally a **TURN server**, so calls traverse symmetric NAT.

It is not a blockchain and holds no balances. It cannot read message content —
that is end-to-end encrypted between clients. It has no long-lived secret of
its own: everything it holds is public, rebuilt from peers, or deposited by
clients. Ledger entries evaporate after 90 days.

## What an operator can see

Anyone you hand a relay address to should know what running it lets you
observe. From [`THREAT_MODEL.md`](THREAT_MODEL.md):

| | Over Tor | On a public host |
|---|---|---|
| Message contents | No — E2E encrypted | No — E2E encrypted |
| Who is talking to whom | No — sealed sender | No — sealed sender |
| **Client IP addresses** | **No** — connections arrive from the Tor network | **Yes** |
| Timing and volume of traffic | Yes | Yes |
| Both peers' IPs on a TURN-relayed call | n/a (see below) | Yes |

That third row is the whole argument for the onion service. An anonymous
identity is only as anonymous as the network path underneath it, and on a
public host the relay sees every client's real address.

## Running it as an onion service

Install Tor and the relay:

```sh
sudo dnf install tor          # or: sudo apt install tor
cargo build --release -p dante-relay
sudo install -m0755 target/release/dante-relay /usr/local/bin/
sudo install -m0644 deploy/dante-relay.service /etc/systemd/system/
```

Declare the hidden service in `/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/dante/
HiddenServicePort 9944 127.0.0.1:9944
```

```sh
sudo systemctl restart tor
sudo cat /var/lib/tor/dante/hostname     # -> <56 chars>.onion
```

That hostname **is** your relay's address. Keep the `HiddenServiceDir` backed
up: it holds the service's private key, and losing it means a new address and
every client having to be told.

The relay itself binds only to localhost — Tor is the only thing that should
reach it:

```sh
sudo systemctl enable --now dante-relay
journalctl -u dante-relay -f
```

The shipped unit binds `127.0.0.1:9944`, which is exactly right here. Nothing
is exposed to the internet directly, so there is no firewall rule to add.

## Connecting to it

Clients need Tor running locally too — the daemon's SOCKS port, nothing else:

```sh
dante serve --keystore ~/dante.keystore \
    --relay <56chars>.onion:9944 \
    --http 127.0.0.1:8080
```

An address ending in `.onion` is routed through Tor's SOCKS port
(`127.0.0.1:9050`) automatically; there is no flag to remember. To send
*everything* through a proxy — a different Tor port, or a VPN's SOCKS — set:

```sh
DANTE_SOCKS5=127.0.0.1:9150 dante serve ...     # e.g. Tor Browser's port
```

Several relays can be given comma-separated for failover, and `.onion` and
plain addresses can be mixed: each is dialled the way its address implies.

## Voice over Tor

Tor carries TCP only, so **WebRTC media does not flow through it**. A call
between two people on an onion-only relay will exchange signalling fine and
then fail to find a media path, or fall back to a TURN server that sees both
real IPs — which gives away exactly what the onion service was protecting.

So: **do not enable TURN on an onion relay** and treat voice as unavailable
there for now. Text, files, servers, channels and reactions all work.
Anonymous voice needs a different transport than this, and that is not built.

## Without Tor: a public host

For a community that wants voice and accepts the IP exposure, or for someone
self-hosting for people who already know them.

Needs a machine with a public IP. A €4/month VPS is ample — the relay is a
single static binary that idles near zero CPU with bounded memory.

| Port | Proto | Flag | For |
|---|---|---|---|
| 9944 | TCP | `--listen` | The client↔relay wire. **Required.** |
| 3478 | UDP | `--turn-listen` | TURN, so calls survive symmetric NAT |
| 9945 | TCP | `--p2p-listen` | libp2p: DHT, gossip, relay↔relay federation |

TURN is **UDP**. Forgetting that is the usual reason calls connect on a LAN and
nowhere else.

Generate a TURN secret — 32+ random bytes, shared with nothing else:

```sh
head -c 32 /dev/urandom | base64
```

Put the real arguments in a drop-in, so an update cannot clobber them:

```sh
sudo systemctl edit dante-relay
```

```ini
[Service]
Environment=DANTE_TURN_SECRET=<the secret>
ExecStart=
ExecStart=/usr/local/bin/dante-relay --listen 0.0.0.0:9944 \
    --turn-listen 0.0.0.0:3478 --turn-public-ip 203.0.113.10 \
    --p2p-listen /ip4/0.0.0.0/tcp/9945
```

`--turn-public-ip` must be the address clients can actually reach, not the one
the interface is bound to — on a VPS behind a NAT gateway those differ, and
TURN will otherwise hand out an unroutable candidate.

The secret goes in the environment on purpose: `--turn-secret` puts it in
`argv`, where any local user can read it from `/proc`.

On start the relay logs what it will advertise:

```
INFO dante_relay: in-process TURN server running listen=0.0.0.0:3478 url=turn:203.0.113.10:3478
INFO dante_relay: advertising ICE servers for calls stun=0 turn=1 turn_creds=true
INFO dante_relay: dante-relay listening listen=0.0.0.0:9944
```

`turn_creds=true` is the line that matters — without it clients get a `turn:`
URL they cannot authenticate against.

## Hosting an SFU for large voice rooms (optional)

Group calls are a full mesh by default — every participant connects to every
other, comfortable to roughly 8. A relay built with the non-default `sfu`
feature can instead terminate one DTLS-SRTP connection per participant and
forward the media, so a room scales past the mesh limit:

```sh
cargo build --release -p dante-relay --features sfu
```

Clients opt in with `dante serve --sfu` (optionally
`--sfu-mesh-limit N`, default 8), and **every member of a call must do
so** — a mixed-mode call has no shared media path. The browser client only
enters SFU mode when it can encrypt its own call frames (SFrame, Chromium
`createEncodedStreams`) and the room's MLS roster is above the limit;
otherwise it stays on the mesh at or below the limit, and above the limit it
refuses the join with a visible explanation rather than send plaintext. The
desktop shell does not offer SFU mode (its native audio path has no SFrame
layer). The relay sees only RTP headers, sizes and timing; call audio stays
AES-GCM-encrypted under the channel's MLS key in SFrame-capable browsers (see
[`SFU.md`](SFU.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md) §5.10 for the
exact boundary, including the non-Chromium refusal).

Two honest limitations of the current SFU build:

- The SFU advertises **host candidates only** (no STUN configured), so run it
  on a host with a publicly reachable IP or full-cone port mapping.
- It is off by default because it pulls the WebRTC dependency tree into the
  relay binary. The media plane and signalling are proven with real multi-peer
  tests, but the browser and desktop client paths are not wired yet.

## Proof-of-work

The default floor makes registering an identity cost real memory and time,
which is what stops a stranger minting thousands of identities against your
relay. **Leave it alone in public.** `--min-pow-bits` exists for local testing,
where waiting out 20 bits per throwaway identity is intolerable; lowering it in
public removes the only cost of spamming you.

## Keeping it up

- There is no state to back up **except**, for an onion service, the
  `HiddenServiceDir`. Losing the rest costs undelivered mailbox items;
  identities, servers and channels live on the clients and in the ledger
  replica, which rebuilds from peers.
- `systemctl restart` is safe at any time; clients reconnect and retry.

## What is still unproven

Written down so nobody mistakes deployment for validation. As of this writing
**no DaNTe network has been deployed**, which means:

- No relay has been run as an onion service in anger. The client side of that
  is unit-tested against a stub proxy, not against Tor.
- Cross-NAT voice has only been exercised against a relay on `127.0.0.1`.
- Relay↔relay federation has e2e tests but no deployed instance.
- `DEFAULT_BOOTSTRAP` is empty; there is no network to seed it with yet.

If you are the first to run one of these in public, those are what to watch —
please report what breaks.
