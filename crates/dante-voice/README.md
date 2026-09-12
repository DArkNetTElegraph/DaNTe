# dante-voice

1:1 WebRTC media transport for DaNTe calls: DTLS-SRTP plus a reliable control
DataChannel and an Opus audio track.

The crate owns only the media pipe and is signalling-agnostic: SDP and ICE
candidates are opaque strings. `dante-core` ships them inside authenticated
ratchet DMs (`Content::Call*`), which binds the DTLS certificate in the SDP to
the chat identity — a relay that cannot forge a ratchet message cannot
man-in-the-middle the call. Group calls and voice channels are assembled in
`dante-core` from one `Call` per mesh leg, keyed by the channel's MLS group;
capture / playback lives in the detached `dante-audio` crate.

## API

- `Call::offer()` / `answer(sdp)` / `offer_with(ice)` / `answer_with(sdp, ice)`
  → `(Call, sdp_string)`
- `set_answer`, `add_ice`, `next_event() -> Option<CallEvent>`, `try_event`
- `push_audio(opus, ms)`, `send_ctl(&[u8])`, `close`
- `CallEvent::{LocalIce, State, CtlOpen, Ctl, RemoteAudio}`, `CallState`,
  `IceServer`, `VoiceError`
- `MIN_VOICE_BITRATE = 64_000` — the SDP fmtp is rewritten to guarantee it

## Used by

`dante-core` only (it re-exports the types and drives calls, group calls and
voice channels). The browser SPA has its own WebRTC path and does not use this
crate.

## Test

```sh
cargo test -p dante-voice
```

Unit tests cover SDP Opus tuning; `tests/loopback.rs` connects two calls over
loopback and passes control-channel probes and an Opus-shaped RTP payload both
ways through SRTP.
