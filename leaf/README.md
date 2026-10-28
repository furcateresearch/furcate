# Furcate leaf node firmware

This repository holds the firmware for the **Furcate leaf node**: a microcontroller-class member of a Furcate cluster (ESP32 family). Its design, build, security plan and pending work are documented, built and managed here.

A leaf node does five things:

- **Identity.** It holds an identity derived from its own silicon.
- **Outbound only.** It talks only to Furcate nodes the operator has authorised, and only over connections it opened itself.
- **Model server.** It runs models that arrive at runtime as signed artifacts. Firmware never has to be rebuilt for a new model.
- **Results stay local.** It sends results to the cluster and keeps raw data on the device by default.
- **Signed updates.** It updates its own firmware from signed images, with automatic rollback.

## Hardware

| Role | Chip | Status |
|---|---|---|
| Development board | Classic ESP32 (ESP32-D0WD-V3 rev 3.1, 4 MB flash, no PSRAM) | Phase 1 runs here |
| Development and gateway, micro processing node | ESP32-S3 (XIAO ESP32S3: 8 MB flash, 8 MB PSRAM, USB-Serial/JTAG): identity from eFuse silicon values, HMAC-key path when a key is burned, own sensors, BLE link to a Nicla Sense ME sensing module, no camera or microphone input. See the device page docs/leaf-devices/xiao-esp32s3.md in the Furcate repository | Builds and runs; no eFuse burned |
| **Production, sensors** | ESP32-C5 (rev 1.2 or later): Key Manager with a PUF-derived hardware key, ECDSA peripheral, TEE, glitch detector | Decided; backend pending |
| **Production, vision** | ESP32-P4 (rev 3.0 or later) with a C5/C6 radio: Key Manager/PUF, ECDSA, glitch detector, AI vector unit, PSRAM | Decided; backend pending |

The classic ESP32 is a development board only:

- It has no hardware engine that uses a key without software seeing it.
- There are published, unfixed physical attacks on its secure boot and flash encryption.

Its lock-down checklist in [docs/SECURITY.md](docs/SECURITY.md) hardens development units. It does not make them production units. On production hardware the device key never leaves the chip.

The firmware is portable across targets:

- Identity and crypto sit behind one interface (`fl_identity.h`, `fl_crypto.h`), with one backend per chip family.
- Model capability checks use the build target.

## Layout

```
main/                     boot sequence and command dispatch
components/fl_core/       identity, silicon fingerprint, trust anchors, channel, OTA, wire format
components/fl_nicla/      BLE central for a sensing module (Nicla Sense ME) on the ESP32-S3, frame decoding
components/fl_sense/      the leaf's own sensors and the signed reading path
components/fl_models/     model server: slots, signed manifests, capability check, TFLM runtime
components/micro-ecc/     P-256 (vendored, BSD-2-Clause)
partitions.csv            firmware A/B + models partition (two slots)
provision/                generated pinned public keys (not committed)
host/                     node-side tools: Secure Enclave helper, protocol, release signing, tests
docs/                     DESIGN, SECURITY, MODELS
```

## Where it fits in Furcate

The cluster side lives in the Furcate monorepo, which already has these pieces:

- the model catalogue with a `Leaf` tier;
- leaf attachment and signed readings;
- the `no_std` leaf core.

This repository is the device side. The monorepo changes this firmware needs are listed in `docs/PENDING.md` of the development repository:

- microcontroller manifest fields in the catalogue;
- a leaf connector on Pi and Jetson parents;
- leaf enrollment in the roster.

## Start here

- [docs/DESIGN.md](docs/DESIGN.md): architecture, protocol, model server
- [docs/SECURITY.md](docs/SECURITY.md): hardware dossier, threat model, production lock-down
- [docs/MODELS.md](docs/MODELS.md): what runs on which chip, with measured and published numbers
- The ESP32-S3 leaf (XIAO ESP32S3) is described on the device page `docs/leaf-devices/xiao-esp32s3.md` in the Furcate repository; the three node roles and the cascade are in its `docs/leaf-tier.md`.

## Building and flashing the ESP32-S3 target

Build with ESP-IDF for the `esp32s3` target and flash over the USB-Serial/JTAG port. A unit
takes its identity from silicon values it reads from its own eFuses; no device identifier
is stored in this repository. Pass the serial port of your own unit to the flash step.
Firmware images are signed and the update path rolls back automatically.

## eFuse state

Nothing in this repository burns an eFuse by itself. Burning is irreversible, so every burn
on a real unit needs an explicit yes from the unit's owner, and the lock-down steps are
rehearsed first on a virtual eFuse model. Until an owner has said yes for a given unit, its
eFuses are as they left the factory.

Licence: Apache-2.0, except vendored components under their own licences.
