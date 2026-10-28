# Furcate

Furcate is an operating system for running your own AI on your own machines. One headless Linux system runs on every machine a site contains, from a rack server to a single-board computer, and microcontroller-class leaves attach to it for sensing and actuation. It is operated from a browser or a tablet on the local network, with no cloud in the path and nothing that phones home to run.

This repository is the open Furcate: Apache-2.0, complete for anyone running their own machines. A home lab, a maker with a few boards on a desk, a lab with a handful of machines and some sensors: all of it runs on what is here, with nothing to buy and nothing to register.

## Local AI, end to end

A private local-AI setup in Furcate has two kinds of machine.

- **A gateway.** A small Linux machine running Furcate OS. It pulls model weights, verifies them against the source digest before they run, and serves them on an OpenAI-compatible endpoint at an address the machine tells you. One gateway serves every local model and loads each on demand.
- **Leaves.** Microcontroller firmware for sensors and actuators. A leaf attaches to its gateway rather than joining a cluster. It signs its readings on the device that took them, so a measurement is attributable to the sensor and not to whatever was on the bus, and it can run small models of its own and hand harder cases to the gateway.

```
$ furcatectl model pull <model>      fetch weights, verified against the source
$ furcatectl model serve <model>     serve it here, OpenAI-compatible
$ furcatectl model endpoint          where to reach it
```

Nothing in this path depends on an outside service once the weights are on the machine.

## Status

What runs today on real hardware:

- **The gateway OS on a Raspberry Pi 5.** Furcate OS boots from an SD card or USB drive, with a read-only verified base. Furcate updates live as signed system extensions, with no reinstall. A tampered or unsigned update is refused, and a failed one rolls back.
- **Hardware identity.** The node key is generated inside the Pi's one-time-programmable memory and never leaves it.
- **Cells.** A gateway heads a cell under an operator's controller, joins the encrypted overlay with a key that lives only in memory, and is reachable by name.
- **The leaf.** On an ESP32 development board:
  - identity from the chip's own silicon fingerprint;
  - a signed, replay-protected link that refuses unknown keys;
  - models loaded at runtime from signed bundles;
  - signed updates that need two release keys, with automatic rollback.
- **Three node roles.** A sensing node measures, a micro processing node (a leaf) signs for the
  sensing node behind it, and a small processing node (a Raspberry Pi running Furcate) verifies
  everything the rung below it says; medium and large nodes sit above. Each rung checks the one
  below, and the roles are in [docs/leaf-tier.md](docs/leaf-tier.md). Worked pages: the
  [sensing node](crates/furcate-sense/docs/nicla-sense-me.md), the
  [XIAO ESP32-S3 leaf](docs/leaf-devices/xiao-esp32s3.md) and the
  [small processing node](crates/furcate-sense/docs/small-processing-node.md). These are tested in
  software; running the whole cascade on boards is in progress.

In progress:

- **Local models served on the gateway.** The commands above exist; the guided path is being verified on the Pi.
- The leaf's Wi-Fi link to its gateway.
- The in-place A/B update of the base system on real boards.
- Accelerator (NPU) serving.

Status is updated as each piece is proven on hardware.

## What makes it different

- **Hardware-rooted identity.** A node's name is a public key produced by the machine's own root of trust and sealed to it. No registry issued it and none can revoke it.
- **Authority you hold.** Policy is a file you keep. Deny by default, and deny beats allow. Halting, powering down, isolating and erasing a machine are the operator's alone, over their own signing key.
- **Claims you can read.** Everything that makes a trust claim (identity, attestation, policy, the ledger, the kill switch) is in this repository, and the default build compiles it alone.
- **Updates that cannot break a machine.** An update replaces a signed image; it never edits a machine. Identity, sealed keys and configuration sit outside anything an update carries, and a failed component rolls back on its own.

## What is here

| path | what it is |
|---|---|
| `crates/` | the system: node agent (`furcated`), operator CLI (`furcatectl`), console, identity, attestation, policy, ledger, kill switch, membership, transport, model serving |
| `os/` | the OS image recipe: base, board layers, system extensions, signed A/B releases, boot tests |
| `leaf/` | leaf firmware and its host side: identity, the signed link, on-device models, OTA, and the gateway that leaves attach to |
| `docs/` | decisions, interfaces and architecture; start at [docs/README.md](docs/README.md) |

## Build

Furcate is Linux only. You need a recent stable Rust toolchain.

```
cargo build --release -p furcated -p furcatectl
cargo test --workspace
```

The OS image is built with mkosi; see `os/` for the board layers and `os/build.sh`. Leaf firmware builds with its vendor toolchain; see `leaf/README.md`.

## Furcate and Praecise

Praecise develops and stewards Furcate in the open. Production fleets, edge and cloud deployments, and support come from Praecise; see [FURCATE-AND-PRAECISE.md](FURCATE-AND-PRAECISE.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE). How decisions are made: [GOVERNANCE.md](GOVERNANCE.md). How to contribute: [CONTRIBUTING.md](CONTRIBUTING.md). Reporting a vulnerability: [SECURITY.md](SECURITY.md).
