# dante-audio

Opus codec + microphone/speaker glue for DaNTe 1:1 calls.

`dante-voice` already carries **Opus frames** end to end over the call's SRTP
audio track — `Engine::send_call_audio(peer, &opus, 20)` sends one 20 ms frame,
`Engine::take_call_audio(peer)` drains the frames received from the peer. This
crate is the last mile on the local machine:

```
mic  --cpal-->  i16 PCM  --OpusCodec::encode-->  Opus  -->  Engine::send_call_audio
speaker <--cpal-- i16 PCM <--OpusCodec::decode-- Opus  <--  Engine::take_call_audio
```

See the module docs for a runnable bridge loop.

## Detached from the workspace

`opus` links **libopus** (needs `pkg-config` + `libopus-dev` / `opus`), and
`cpal` links the **platform audio stack** (ALSA on Linux, CoreAudio, WASAPI).
A bare workspace build should not assume these, so this crate has its own
`[workspace]` and `cargo build --workspace` at the repo root skips it. CI
installs the libraries and builds this crate (via the desktop shell) on Linux,
Windows and macOS in a dedicated job.

## Build / test (on a real host)

```sh
# Debian/Ubuntu
sudo apt install pkg-config libopus-dev libasound2-dev
cd crates/dante-audio
cargo test          # runs the Opus round-trip tests (no device needed)
```

The device paths (`Capture`, `Playback`) need an actual input/output device;
they are exercised by the desktop client, not by unit tests.
