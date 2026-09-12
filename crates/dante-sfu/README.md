# dante-sfu

SFU (selective forwarding unit) media component for large DaNTe voice rooms.

> **Status: media plane, relay signalling and the `dante-core` client mode are
> proven; browser/desktop wiring is not done.** A real three-participant test
> terminates DTLS-SRTP and forwards RTP opaquely, `dante-relay`'s `sfu` feature
> hosts rooms and carries SDP/ICE over the relay wire, and `Engine::enable_sfu()`
> gives an engine one SFU leg instead of a mesh (verified by a three-engine
> e2e). The shipped browser client and the desktop audio bridge still use the
> mesh. See [`docs/SFU.md`](../../docs/SFU.md) for the design.

## What it does

Each participant negotiates **one** PeerConnection with `Sfu` instead of one
per other participant. Incoming RTP from slot `s` is rewritten to
`slot_ssrc(s)` and written unmodified to every other slot's outgoing track for
`s` — same sequence numbers, timestamps, payload type and payload bytes. No
decode, no re-encode, and no access to the SFrame (`DSF1 ‖ AES-GCM`) key, so
the SFU never sees call audio.

The room size is fixed at construction; every answer pre-allocates one
outgoing track per other slot, so participants can join in any order without
renegotiation. Slots with no participant stay silent.

```rust,no_run
use dante_sfu::Sfu;

# async fn example(offer_sdp: &str) -> Result<(), dante_sfu::SfuError> {
let (mut sfu, mut events) = Sfu::new(8);
let (slot, answer_sdp) = sfu.add_peer(offer_sdp).await?;
// hand `answer_sdp` back; feed the participant's ICE in:
sfu.add_ice(slot, "candidate:...").await?;
// events carry the SFU's own ICE candidates and per-slot states
while let Some(ev) = events.recv().await {
    let _ = ev;
}
# Ok(())
# }
```

## Proven

`tests/forwarding.rs` — three `dante_voice::Call` participants, each with a
distinct audio payload, all connected only to one `Sfu`:

- all three reach `Connected` over real DTLS-SRTP;
- each participant receives the other two participants' exact payloads
  (proving forwarding, not just connection setup);
- no participant ever receives its own payload (proving no loopback / no
  direct peer-to-peer path between participants).

## Not done

- **Signalling**: no relay wire request, no authorization binding a slot to a
  participant identity, no client-side negotiation flow.
- **Mesh/SFU switch**: no threshold logic in `dante-core`; nothing advertises
  an SFU to clients.
- **Renegotiation**: fixed room size at construction rather than dynamic
  membership.
- **RTCP**: relies on webrtc-rs' internal sender/receiver interceptors; no
  NACK/PLI propagation between legs (audio-only for now).
- **Video / screen share**: forwards audio; video would take the same opaque
  path but is untested.
- **Resource limits**: no cap on rooms, bandwidth or CPU.
- **SFrame-capability gating**: clients that cannot do SFrame would send
  plaintext Opus through an SFU — see the trust-boundary caveat in
  [`docs/SFU.md`](../../docs/SFU.md).

## Test

```sh
cargo test -p dante-sfu
```
