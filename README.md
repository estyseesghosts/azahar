# CITnLO 
### CITra n LOtus 

a fork of the azahar (citra) emulator, intended for writing and debugging 3DS homebrew. CITnLO is the emulator backend powering Lotus. 

CITnLO is the `experimental` branch of this fork. `integration` (AZAHAR in Lotus) carries only the native worker hooks and frame, audio and input adapters; CITnLO adds the debugger on top. Lotus pins both branches in [`config/pins.toml`](https://github.com/estyseesghosts/lotus/blob/main/config/pins.toml). Branch rules: [03](https://github.com/estyseesghosts/lotus/blob/main/docs/03-azahar-branches.md).

## What CITnLO adds to Azahar

Everything lives in `src/ctr_worker` plus small hooks in core and video_core. `ctr-worker` is a headless process that Lotus drives over a private pipe, one process per emulated console ([21](https://github.com/estyseesghosts/lotus/blob/main/docs/21-native-control.md)). Qt, SDL, Libretro, OpenGL and Azahar's GDB stub are off in Lotus builds; Lotus serves GDB from Rust.

- Safe-point CPU, kernel and memory inspection, execute breakpoints kept in the JIT, and watchpoints ([07](https://github.com/estyseesghosts/lotus/blob/main/docs/07-debugger-core.md)).
- Rewind: frame checkpoints at a configurable interval, reverse step and reverse continue to the previous breakpoint or watchpoint hit.
- PICA draw capture with frozen buffer lineage, plus bounded CiTrace recording and replay ([08](https://github.com/estyseesghosts/lotus/blob/main/docs/08-gpu-and-trace.md)).
- Settings bindings classified by the code that consumes them, movies tied to a recorded console identity, private camera images, and scripted peripherals.
- Live previews from a shared-memory ring, with asynchronous Vulkan readback.

No hardware accuracy changes are claimed.

## Changes since Lotus v0.0.1

v0.0.1 shipped CITnLO and AZAHAR from the same commit, `05773bbb`; v0.0.3 pins the commit that adds this section. Details and measurements: [Lotus release notes](https://github.com/estyseesghosts/lotus/blob/main/docs/35-release-notes.md), [34](https://github.com/estyseesghosts/lotus/blob/main/docs/34-performance-and-issue-triage.md).

- Wave 3 debugger: safe-point CPU, kernel, GPU and replay debugger, CiTrace, rewind replay for continuous reverse continue, settings classification, camera and microphone handling, and console identity in movie playback.
- Execute breakpoints no longer force single-stepping (`PreCodeReadHook` block split).
- The PICA debug context is installed only while GPU tools are enabled, so the batched command path runs otherwise.
- Input snapshots are built only when a rewind checkpoint is due.
- Rewind:
  - The checkpoint interval is 1–60 frames, and a breakpoint change starts a new hit window.
  - The zstd level is selectable (`compression_level`, -7..19, default 3), and `rewind_status` reports checkpoint costs.
  - Page tables are saved as runs, class version 1. Version 0 states still load.
  - Measured on a busy host, 5–8x less serialize time and roughly half the restore time per checkpoint.
- The `preview` control method serves frames from the shared-memory ring.

## Building

Use Lotus's `scripts/build-azahar.ps1 -Branch experimental`. It refuses a dirty tree or a commit other than the pin, and writes a build manifest ([27](https://github.com/estyseesghosts/lotus/blob/main/docs/27-build-and-run.md)).
