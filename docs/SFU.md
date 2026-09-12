# Group-call SFU (selective forwarding unit)

> **Status: media plane, relay signalling and the `dante-core` client mode are
> proven; browser/desktop wiring is not done.** [`crates/dante-sfu`](../crates/dante-sfu/README.md)
> terminates real DTLS-SRTP PeerConnections and forwards RTP payloads opaquely;
> `dante-relay`'s `sfu` feature (off by default) hosts rooms and carries
> SDP/ICE over the existing relay wire; and `Engine::enable_sfu()` gives an
> engine one SFU leg instead of a mesh, verified by a three-engine e2e. The
> shipped browser client and the desktop audio bridge still use the mesh. This
> document is the design the rest of that work should follow.

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

Still to do on the client side: the SPA does no SFU negotiation, the desktop
audio bridge still fans out per mesh leg (`/api/call/audio`), no SFU endpoint
is advertised to clients, there is no participant-count threshold, and the
mode must currently be chosen consistently by every member (mixed mode leaves
the two sides with no shared media path). The relay feature is off in release
builds.

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
`dante serve --sfu` / `dante chat --sfu`, the desktop shell with
`DANTE_SFU=1`.

## Mesh vs SFU

Threshold-based: keep the mesh at or below **8** participants (the point where
mesh stops being comfortable); above it the host/relay advertises an SFU
endpoint for the channel and clients switch. If no SFU is reachable, fall back
to mesh and surface the degraded mode. The threshold and the fallback belong
in `dante-core`, not in the SFU component.

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

See the crate README for the exact status list.

## Open questions / next steps

- **Renegotiation** for real rooms instead of a fixed `room_size`.
- **SFU-side ICE**: the SFU gathers host candidates only (no STUN/TURN
  configured), so a relay behind NAT cannot offer a reachable candidate yet.
- **RTCP**: the component relies on webrtc-rs' internal sender/receiver
  interceptors; it does not propagate NACK/PLI between legs. Audio at 64 kbps
  is tolerant, but this needs review before video/screen-share forwarding.
- **Resource limits**: per-IP rate limiting, a room cap, offer/candidate size
  limits and empty-room teardown are in; per-participant bitrate and fairness
  are not.
- **Fallback behaviour** when an SFU dies mid-call (demote to mesh? drop the
  call?).
- **SFrame-capability gating** (above): decide the policy for non-Chromium
  clients before advertising SFU mode.
- **Desktop/browser wiring**: the SPA does no SFU negotiation, the desktop
  audio bridge still drives mesh legs, and there is no participant-count
  threshold or SFU discovery yet. The CLI (`--sfu`) and library
  (`Engine::enable_sfu`) paths exist.
