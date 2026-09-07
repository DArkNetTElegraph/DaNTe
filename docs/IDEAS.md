# DaNTe Ideas / Backlog

Features and refinements that are **not** in the phased roadmap
([`DESIGN.md`](DESIGN.md)) yet. No commitment implied — this is a holding place
so ideas aren't lost. Promote an entry into a phase when it's scheduled.

---

## Screen share: "follow the active screen" mode

**What:** a screen-share source option that shares *whichever physical monitor
the mouse cursor is currently on*, switching the shared surface automatically as
the cursor moves between monitors — instead of the usual "pick one fixed
display" or "pick one application window".

**Why:** multi-monitor users routinely present from one screen while pulling up
references, notes, or chat on another. Today they either share everything (all
displays, wasteful and leaky) or keep manually swapping the shared display.
Following the active screen matches how people actually work across monitors.

**Sketch:**
- Sits in the capture layer (Phase 7 media pipeline), *before* the encoder —
  no crypto/transport impact; the MLS-exported SRTP keying is unaffected.
- Per-platform active-display + capture-source APIs:
  - Linux/Wayland: `xdg-desktop-portal` ScreenCast (PipeWire); note the portal
    picker is per-source, so seamless switching may need re-negotiation or
    capturing all outputs and cropping to the active one.
  - Linux/X11: query the pointer's `RRCrtc` via XRandR; capture that CRTC.
  - Windows: `MonitorFromPoint(GetCursorPos())` + a per-monitor DXGI duplication.
  - macOS: `ScreenCaptureKit` `SCDisplay` for the display under
    `NSEvent.mouseLocation`.
- **Debounce** display switches (~300–500 ms dwell) so a cursor grazing a
  monitor edge doesn't strobe the stream.
- On switch, keep output resolution/framerate stable for the viewer (letterbox
  or scale rather than renegotiating the video track mid-call).

**Privacy note:** a notification, preview, or private window that pops up on a
monitor the moment the cursor crosses to it would briefly appear in the share.
Mitigations: the switch debounce above; a always-visible on-screen indicator of
which display is currently live; optionally a "hold current screen" hotkey to
freeze the source while glancing elsewhere.

**Open questions:** behaviour when the cursor is on a display that isn't being
captured (e.g. permissions denied for one output); interaction with per-window
"exclude from capture" flags; whether to also offer "follow focused window".
