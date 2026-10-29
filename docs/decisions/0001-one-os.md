# 0001 — One Furcate OS for every machine

Date: 2026-10-11. Status: decided by the owner. **Base release superseded by [0004](0004-base-ubuntu-2604.md): Ubuntu 26.04 LTS, Jetson waits.**

## Decision

One Furcate OS, built on **Ubuntu 24.04 LTS**, for single-board computers, embedded AI modules and any x86_64 or arm64 server. One userspace, one image format, one update mechanism, one release line. Per-board differences are confined to kernel, firmware and boot method ([boards/](../../os/boards/README.md)). Furcate OS is headless everywhere; it is operated from a web or tablet interface.

## Why 24.04

It is the newest release every target supports. NVIDIA supports only Ubuntu 24.04 for JetPack 7.2 (Jetson Linux 39.2, Orin and Thor). Ubuntu 24.04 supports Raspberry Pi 5 and CM5. Every server runs it. Standard support runs to 2029 and ESM to 2034.

The image-based toolchain is in the 24.04 archive (checked on packages.ubuntu.com, arm64): systemd 255 ships the `systemd-sysupdate` units; `mkosi` and `systemd-ukify` are packaged.

## Consequences

- The whole OS moves to the next LTS together, once NVIDIA supports it for Jetson. No board is ever on a different release.
- CUDA and NVIDIA userspace come from NVIDIA's 24.04 repositories and are built into a system extension on the operator's own build machine rather than redistributed.
- Hosts already running other releases keep running; `furcate convert` still installs Furcate onto existing Ubuntu and Debian machines.

## Superseded

The private research note `os-base-distribution` recommended Ubuntu 26.04 with a separate 24.04 line for Jetson. This decision replaces the two lines with one.
