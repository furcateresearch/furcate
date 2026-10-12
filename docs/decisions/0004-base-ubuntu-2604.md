# 0004 — The one Furcate OS is built on Ubuntu 26.04 LTS

Date: 2026-10-11. Status: decided by the owner. Supersedes the base release in [0001](0001-one-os.md); everything else in 0001 stands (one OS, one userspace, one image format, one update mechanism, per-board kernel, firmware and boot only, headless).

## Decision

- **Base: Ubuntu 26.04 LTS** for every board: single-board computers (Raspberry Pi 5 / CM5, officially supported by 26.04), any x86_64 or arm64 server (the production servers already run 26.04), and embedded AI modules.
- **Embedded AI modules (Jetson, the Furcate Hub tier) wait** until NVIDIA supports Ubuntu 26.04 for its board software. There is no 24.04 line and no second release: one OS, one release, and the Hub tier joins when its vendor support does.
- The image toolchain is in the 26.04 archive: `systemd-sysupdate` (in `systemd-container`, systemd 259), `mkosi`, `systemd-ukify`; CUDA is in the archive for servers.

## Consequences

- Board layers: `server` and `sbc` now; `embedded-ai` is defined but not built until NVIDIA's 26.04 support exists.
- Furcate Hub hardware design proceeds; its software bring-up is gated on the vendor.
- Hosts on other releases keep running; `furcate convert` still installs onto existing Ubuntu and Debian machines.
