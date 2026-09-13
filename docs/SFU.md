# Group-call SFU (selective forwarding unit)

> **Status: media plane, relay signalling, engine mode and browser mode are
> proven; desktop is deliberately excluded.** [`crates/dante-sfu`](../crates/dante-sfu/README.md)
> terminates real DTLS-SRTP PeerConnections and forwards RTP payloads opaquely;
> `dante-relay`'s `sfu` feature (off by default) hosts rooms and carries
> SDP/ICE over the existing relay wire, offering each room's `Sfu` the same
> operator-configured STUN/TURN policy `Request::GetIceConfig` hands ordinary
> calls; `Engine::enable_sfu()` gives an engine
> one SFU leg instead of a mesh; and the SPA now negotiates the SFU through
> `dante serve`'s `/api/sfu/*`, gated on SFrame support and chosen by a roster
> threshold. The desktop shell is not offered SFU mode (no SFrame in its
> native audio path), and the SPA refuses rather than send plaintext. See
> [What the component proves today](#what-the-component-proves-today).

## Why

A channel group call is a full mesh of 1:1 WebRTC legs. Each participant holds
one DTLS-SRTP connection per other participant, so uplink grows O(N) and the
browser does O(N) encryptions; it is workable to roughly 8 participants and
falls over after that. An SFU gives each participant **one** connection,
receives each participant's stream once, and forwards it to the others.

What makes that tractable without the SFU becoming a trusted party for call
content is the SFrame layer the SPA already applies to every Opus frame
(Chromium `createEncodedStreams`): the payload the SFU forwards is
`DSF1 ‖ IV ‖ AES-GCM(Opus)` keyed by the channel's MLS `group_call_key`, and
the SFU never receives that key. It routes ciphertext it cannot read.

## Where it runs

A new crate, `dante-sfu`, intended to be hosted by `dante-relay` (the same
process that already terminates TURN): a future `--sfu-listen` alongside
`--turn-listen`, with the same operator/trust model. Rationale:

- The relay already accepts media-plane connections (TURN) and already has the
  per-connection identity context a future SFU needs to authorize a slot.
- Content confidentiality does not depend on the SFU operator, so co-locating
  with the relay's existing duties adds no new trust assumption.
- A separate crate keeps the media component testable in isolation and
  unreachable from the default build until the signalling work lands.

## Topology

```
browser A ──DTLS-SRTP──┐
browser B ──DTLS-SRTP──┤  SFU (webrtc-rs)  ── forwards RTP payloads, rewrites SSRC only
browser C ──DTLS-SRTP──┘
```

Each participant negotiates **one** PeerConnection with the SFU. The SFU
terminates DTLS-SRTP per leg and re-writes each received RTP packet onto the
subscriber tracks for that source, changing only the SSRC (so each source has
a stable, collision-free stream id); sequence numbers, timestamps, payload
type and payload bytes pass through untouched. No decode, no re-encode, no
SFrame key.

The component implemented today pre-allocates `room_size - 1` outgoing tracks
per participant at join time (one per possible source slot), so no
renegotiation is ever required. That is a deliberate v0 simplification: a
production SFU would advertise a fixed room size or renegotiate as speakers
join, rather than carrying silent m-lines.

## Signalling

A relay built with the **non-default `sfu` feature** hosts rooms and carries
the negotiation over its existing framed-TCP / libp2p wire:

| request | meaning |
|---|---|
| `SfuJoin { room, offer }` → `SfuAnswer { slot, answer }` | join (or create) the room for a channel, get a slot and the SFU's SDP answer |
| `SfuIce { room, slot, candidate }` | trickle one local candidate to the SFU |
| `SfuPull { room, slot }` → `SfuIce(candidates)` | drain the SFU's candidates for this slot |
| `SfuLeave { room, slot }` | close the leg and free the slot |

`room` is the 32-byte channel id — the same capability the channel log already
uses — so possession of the channel id is the authorization, and the relay
needs no new identity check. Media never travels this path: each participant
holds a DTLS-SRTP connection to the SFU's own UDP endpoint.

Still to do on the client side: the desktop audio bridge fans out per mesh
leg (`/api/call/audio`) with no SFU equivalent — see [Browser
mode](#browser-mode-dante-serve--spa) below for the SPA's negotiation,
threshold and mixed-mode handling, all implemented. The relay feature is off
in release builds.

## Engine mode (`dante-core`)

`Engine::enable_sfu()` (opt-in, not persisted) switches group calls to the
relay-hosted SFU:

- `reconcile_group_legs` opens **one** `Call::offer_for_sfu` leg per channel
  and negotiates it over the relay wire instead of starting mesh legs;
- `poll_group_calls` drives `SfuIce`/`SfuPull` and queues inbound frames;
- `send_group_audio` / `take_group_audio` are the SFU equivalents of the
  per-peer `send_call_audio` / `take_call_audio`;
- `group_call_state` reports the single leg's connection state;
- `leave_group_call` sends `SfuLeave` and closes the leg.

`crates/dante-core/src/e2e_tests.rs::an_sfu_group_call_forwards_audio_between_three_engines`
runs three real engines against the in-process relay (whose test build enables
`sfu`), starts a group call, and asserts each engine hears the other two's
distinct markers and never its own. The CLI reaches this mode with
`dante chat --sfu`. This path has **no SFrame layer** (it is the engine's own
Rust media stack), so it is for API/CLI clients whose audio is not
content-sensitive to the relay operator; the browser path below is the one
with the SFrame guarantee.

## Browser mode (`dante serve` + SPA)

`dante serve --sfu [--sfu-mesh-limit N]` offers the browser client the
relay-hosted SFU. The engine is **not** put in SFU mode in this case: the page
owns the media, so the engine must not open a competing leg. The SPA
negotiates the relay wire through the local API:

| endpoint | relays to |
|---|---|
| `POST /api/sfu/join {channel, offer}` | `Engine::sfu_offer` → `SfuJoin`, returns `{slot, answer}` |
| `POST /api/sfu/ice {channel, slot, candidate}` | `Engine::sfu_ice` → `SfuIce` |
| `GET /api/sfu/ice?channel=&slot=` | `Engine::sfu_pull` → `SfuPull`, returns `{candidates}` |
| `POST /api/sfu/leave {channel, slot}` | `Engine::sfu_leave` → `SfuLeave` |

All four reject with `403` if `dante serve` was not started with `--sfu` —
enforced server-side, not left to the SPA's own gating alone. Without this, a
caller that skips the SPA's JS entirely (a raw HTTP client, or a compromised
page) could reach a relay's SFU whenever the relay happened to support it,
regardless of whether the operator opted the *client* into SFU mode at all.

`GET /api/state` reports `sfu` and `sfu_mesh_limit` to the page. The SPA:

- chooses the mode from the channel's **MLS roster** (all members compute the
  same size, so the room cannot split into mixed modes): mesh at or below the
  limit, SFU above it;
- only enters SFU mode when `sframeAvailable()` is true, and waits for the
  MLS media key (`sframeEnsureKey`) before opening the peer connection —
  `sframeEncrypt` drops frames rather than pass plaintext if the key ever
  vanishes while an SFU leg is up;
- on a room above the limit where SFrame is unavailable (or the key cannot be
  derived, or the join fails), **refuses the call and says why** rather than
  fall back to a mesh that no longer interconnects with the SFU peers;
- shows a hint in a mesh room that has grown past the limit: leave and rejoin
  to switch — shown once per room (`voiceRtc.sfuHinted`, reset on leaving),
  not once per session;
- blocks the mesh-sync poll (`refreshVoice`/`refreshGroupCalls`, every 1.5s)
  for the whole SFU negotiation window, not just once negotiation finishes:
  `voiceRtc.sfu` is only set at the very end of a multi-second wait (SFrame
  key + SDP/ICE), so a poll tick mid-negotiation would otherwise see neither
  it nor a useful `pendingMode` (already cleared) and open real mesh legs,
  splitting the room the mode switch exists to keep exclusive. A dedicated
  `voiceRtc.sfuPending` flag covers the gap, set before the wait begins and
  cleared on every exit path (success, refusal, or leaving).

The desktop shell deliberately does **not** offer SFU mode: its native audio
path (`dante-audio` → engine media) has no SFrame equivalent, so the relay
would receive plaintext Opus. It stays on the mesh until a Rust SFrame layer
exists.

## Mesh vs SFU

Implemented as a **roster threshold** (default 8, `--sfu-mesh-limit`, clamped
server-side to `SFU_MAX_MESH_LIMIT` = 15 — the SPA's `SFU_RECV_SLOTS`, one
receive-only m-line per possible other participant, matching the relay's
16-slot room capacity. A configured limit above that would tell an
over-capacity room to switch to an SFU that cannot actually admit it, which is
worse than staying in mesh, so it is enforced, not just documented, in
`crates/dante-cli/src/main.rs`'s flag parsing):

- **At or below the limit:** mesh. Per-leg DTLS-SRTP means the relay never
  sees media content, and SFrame is a bonus.
- **Above the limit, SFrame available:** SFU, with SFrame keeping content
  confidential from the operator.
- **Above the limit, SFrame unavailable or the SFU cannot be established:**
  refuse the join with an explanation. This is deliberate: mesh fallback would
  leave the participant isolated from the SFU peers, and entering the SFU
  without SFrame would expose plaintext.
- **Mixed-capability rooms over the limit do not interconnect** — a
  non-Chromium browser is refused while Chromium peers use the SFU. This is a
  known limitation until capability is communicated room-wide.

The decision uses the MLS roster, not live presence, so early and late joiners
agree. If the room later grows past the limit, existing mesh participants get
the rejoin hint; mid-call switching would drop everyone's audio.

## Trust boundary: what the operator can and cannot observe

The SFU is a media endpoint, not a passive relay. DTLS-SRTP terminates **at**
the SFU, so the SFU's connection to each participant is hop-by-hop, not
end-to-end. Concretely, a relay/SFU operator can see:

- Participant IP addresses, join/leave times and participant count.
- RTP headers: SSRC, sequence numbers, timestamps, payload type.
- Packet sizes and timing — including talk-spurt markers and Opus VBR cadence,
  which leaks approximate speech activity (who is talking, roughly when, how
  much).

And cannot see, **when SFrame is active**:

- Audio content: the payload is `DSF1 ‖ AES-GCM` ciphertext under the MLS
  group-call key, which the SFU never receives. It cannot forge a frame
  either.

**Honest caveat:** SFrame is Chromium-only. Where
`RTCRtpSender.createEncodedStreams` is unavailable the SPA silently passes
plaintext Opus through, and an SFU would forward — and could decode — that
plaintext. In the mesh, DTLS-SRTP still protects it end to end between
browsers; through an SFU it would not be protected from the operator. So the
SFU's content-confidentiality guarantee is **conditional on client-side SFrame
support**, and a client that cannot do SFrame should prefer the mesh (or the
call should state the weaker guarantee). This is recorded in
[`THREAT_MODEL.md`](THREAT_MODEL.md) §5.

Traffic analysis (who talks when) is *not* hidden even with SFrame, by either
an SFU or a TURN relay.

## What the component proves today

- `crates/dante-sfu/tests/forwarding.rs`: three `dante_voice::Call`
  participants each negotiate DTLS-SRTP with one `Sfu`, push a distinct audio
  payload, and each receives exactly the other two participants' payloads
  through the SFU — real RTP, opaque payloads, no direct peer connection.
- `crates/dante-relay/tests/sfu.rs` (feature `sfu`): the same three-peer
  exchange, but every bit of signalling — `SfuJoin` / `SfuIce` / `SfuPull` —
  goes over the relay's real wire to the relay-hosted room, proving the
  protocol path end to end.
- `dante-core` e2e: three full engines with `enable_sfu()` start a group call
  through the in-process relay and hear each other's markers via
  `send_group_audio` / `take_group_audio`.
- **Browser (headless Chromium, manual rig — not in CI):** two `dante serve
  --sfu --sfu-mesh-limit 1` instances against a `--features sfu` relay, with a
  two-member voice channel.
  - Both pages with real `createEncodedStreams`: each negotiates its own SFU
    slot, `sframeActive()` is true, and `RTCPeerConnection.getStats()` shows
    inbound RTP packets both ways (31/32 packets in the recorded run) — real
    audio through the relay SFU.
  - One page with `createEncodedStreams` deleted before load: `voiceRtc.sfu`
    stays `null`, `voiceRtc.sfuNotice === "no-sframe"`, the refusal modal is
    shown, the join is torn down, and **zero** `/api/sfu/join` requests are
    made — no plaintext path exists.
  - Decision checks: `voiceModeFor` returns `"sfu"` above the limit with
    SFrame, `"mesh"` at/below it, `"refuse"` above it without SFrame, and
    `"mesh"` when `--sfu` is off.

See the crate README for the exact status list.

## Open questions / next steps

- **Renegotiation** for real rooms instead of a fixed `room_size`.
- **RTCP NACK**: every leg (the SFU's own, and `dante-voice`'s, so this
  covers CLI/engine calls end to end) registers the NACK generator/responder
  interceptors *and* declares `nack` feedback capability for Opus — the
  upstream default only advertises it for video, so leaving that step out
  would have installed the interceptors without ever letting them engage. A
  dropped packet on a real leg is now retransmitted from the sender's buffer
  rather than relying on Opus FEC alone. Not proven for the browser path: it
  depends on the browser's own SDP offer declaring audio NACK support, which
  the SPA does not control and this repo cannot verify without a real
  browser. PLI is video-only feedback and does not apply to this audio-only
  component; it will need adding if screen share/video forwarding lands.
- **Resource limits**: per-IP rate limiting, a room cap, offer/candidate size
  limits, empty-room teardown and a per-source bitrate cap (drop, not queue,
  past budget — see `dante-sfu`'s `SOURCE_BITRATE_CAP_BYTES_PER_SEC`) are in.
- **Fallback behaviour** when an SFU dies mid-call (demote to mesh? drop the
  call?).
- **Mixed-capability rooms over the limit** do not interconnect: a
  non-Chromium browser is refused while Chromium peers use the SFU. Needs a
  room-wide capability signal to converge on one mode.
- **Desktop SFrame**: the native audio path needs its own SFrame (or another
  E2E media layer) before the desktop shell can safely offer SFU mode.
- **Screen share over SFU** is currently refused in the SPA (the pre-allocated
  audio slots do not carry video; it needs renegotiation).
- **SFU discovery** beyond "the connected relay hosts it", and a per-network
  default rather than a `--sfu` flag.
