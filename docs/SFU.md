# Group-call SFU (selective forwarding unit)

> **Status: media-plane component proven, integration not started.** The crate
> [`crates/dante-sfu`](../crates/dante-sfu/README.md) terminates real
> DTLS-SRTP PeerConnections and forwards RTP payloads opaquely; a Rust-only
> three-peer test proves real RTP reaches the other participants and never
> loops back to the sender. Nothing is wired into `dante-relay`, `dante-core`
> or the SPA yet — the default client path is still the full mesh. This
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

## Signalling (designed, not implemented)

Today's mesh signalling is pairwise: `Content::VoiceSignal` carries SDP and
trickled ICE between browsers over authenticated DMs. For SFU mode each
participant instead negotiates with the SFU endpoint:

1. The client decides mesh vs SFU (see below) and, in SFU mode, asks the relay
   to allocate a slot on the channel's call (a new `Request` on the existing
   relay wire, authorized by the caller's identity and channel membership).
2. Offer/answer + trickled ICE travel through that same authenticated path —
   the SFU's DTLS fingerprint is bound to the slot allocation, not to a
   `VoiceSignal` DM, so a client can verify it is talking to the allocated
   SFU rather than a substituted peer.
3. The MLS `group_call_key` still comes from the channel's MLS group and is
   never sent to the relay; SFrame keys rotate on join/leave as today.

Until this exists, `dante-sfu` is a library with no network signalling of its
own — exactly like `dante-voice`, the SDP strings are opaque.

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

`crates/dante-sfu/tests/forwarding.rs`: three `dante_voice::Call` participants
each negotiate DTLS-SRTP with one `Sfu`, push a distinct audio payload, and
each receives exactly the other two participants' payloads through the SFU —
real RTP, opaque payloads, no direct peer connection between them. See the
crate README for the exact status list.

## Open questions / next steps

- **Signalling + authorization** (above): the largest missing piece.
- **Renegotiation** for real rooms instead of a fixed `room_size`.
- **RTCP**: the component relies on webrtc-rs' internal sender/receiver
  interceptors; it does not propagate NACK/PLI between legs. Audio at 64 kbps
  is tolerant, but this needs review before video/screen-share forwarding.
- **Resource limits**: rooms, slots, per-participant bitrate, and fairness.
- **Fallback behaviour** when an SFU dies mid-call (demote to mesh? drop the
  call?).
- **SFrame-capability gating** (above): decide the policy for non-Chromium
  clients before advertising SFU mode.
