# Supported hardware

Which parts Furcate covers, at which position in the cascade, and how far each is verified. The positions are in `docs/leaf-tier.md`; one page per board is in this folder. This page states only what is verified in the repositories or on the vendor's own page.

Attestation levels, weakest to strongest: `soft`, `device`, `se`, `tee`, `dice`, `tpm`. A chain is graded by its weakest link. A unit's class is earned from how its key is held; a device never states one.

Status words used below. Verified on hardware: run on the real part and recorded in a repository. Built: code and host tests exist; not run on the part. Planned: decided, not built.

## Supported now

| Part | Position | Class it earns now | Highest class reachable | Status |
|---|---|---|---|---|
| Arduino Nicla Sense ME (ANNA-B112 module with nRF52832; Bosch BHI260AP, BMM150, BMP390, BME688) | Sensing node | `soft` | `soft` | Verified on hardware: USB text lines, and BLE to an ESP32-S3 with signed readings (2026-10-28). Built: I2C link to the S3, not run against a module. |
| ESP32-S3 (Seeed Studio XIAO ESP32S3: dual-core Xtensa LX7, 8 MB flash, 8 MB octal PSRAM, Wi-Fi, BLE 5) | Micro processing node | `soft` (key derived from the unique ID and MAC, which any code on the part can read) | `device` (eFuse HMAC key) | Verified on hardware: identity from silicon values, signed readings, Wi-Fi, BLE central for the Nicla. Built: the eFuse HMAC path; no eFuse has been burned. |
| ESP32, classic (ESP32-D0WD-V3 rev 3.1) | Rehearsal board | `soft`; also `soft` with every lockdown fuse burned, because a fingerprint key is never graded above `soft` (`LeafKeyCustody::class`) | not a production part | Verified on hardware. Published, unfixed attacks on secure boot and flash encryption on this revision make it a development board only. |
| Raspberry Pi 5 and Compute Module 5 (BCM2712) | Small processing node | `device` (device-unique ECDSA P-256 key in OTP, used through the firmware) | `tpm` with a discrete TPM 2.0 on SPI | Verified on hardware: the leaf head signs with the OTP key through the signing broker (2026-10-14). The discrete-TPM path is built, not run on a Pi. |
| NVIDIA Jetson Orin (AGX Orin, Orin NX, Orin Nano) and AGX Thor | Medium processing node | `tee`; `tpm` only when secure boot is fused (lock and key hash burned), the firmware TPM is provisioned, its endorsement certificate chains to a CA the operator named and is for this TPM's key, and a fresh signed quote agrees with the replayed boot log and a PCR 0 the operator pinned | `tpm` | Built from NVIDIA documentation and checked against fixtures only. Not run on a real device; the owner owns none. See `docs/leaf-devices/jetson.md`. |

### Nicla Sense ME sensors

| Measurement | Sensor on the board | Reaches Furcate as |
|---|---|---|
| Acceleration, angular rate, orientation | Bosch BHI260AP (6-axis IMU with sensor hub) | `acc.x/y/z` and `gyr.x/y/z` signed through the leaf; `rot.x/y/z/w` is decoded in `furcate-sense` but not in the leaf's BLE path |
| Magnetic field | Bosch BMM150 | `mag.x/y/z` decoded in `furcate-sense`; not in the leaf's BLE path |
| Pressure | Bosch BMP390 | `prs`, signed through the leaf |
| Temperature, humidity, gas resistance | Bosch BME688 | `tmp`, `hum`, `gas`, signed through the leaf; the gas unit is the vendor's, not checked |

The module holds no secret and has no secure element, so it is identified and not authenticated. Operating range of the BME688 on the board: -40 to +85 C (Arduino ABX00050 datasheet).

### ESP32-S3 security features (Espressif ESP-IDF documentation)

Secure Boot v2 (RSA-3072, up to three key digests with revocation), flash encryption, a digital-signature peripheral that signs without exposing the RSA key to software, HMAC, secure download mode and eFuse anti-rollback. Espressif advisory AR2026-005 (2026-06-11) reports AES-128 key recovery on the ESP32-S3 by voltage fault injection and differential fault analysis; plan flash encryption with that in mind.

## Planned

| Part | Position | Why | Status |
|---|---|---|---|
| ESP32-C5 (revision 1.2 or later) | Sensing and micro processing node, production | Key Manager with a PUF-derived hardware key, ECDSA peripheral, ESP-TEE | Decided; backend not built. Espressif advisory AR2026-006 (2026-07-28) affects the ECDSA secure-boot check on this chip, so the lock-down plan uses RSA secure boot. |
| ESP32-P4 (revision 3.0 or later) with a C5 or C6 radio | Vision node | Key Manager, ECDSA, AI vector instructions, PSRAM | Decided; backend not built. Also listed in AR2026-006. |

## Researched, not built

Vendor pages read for these parts state the following (nxp.com product pages for MCX N94x, i.MX RT1180, i.MX 95 and EdgeLock SE050; ti.com F29H850TU; the Infineon OPTIGA Trust M datasheet, revision 3.70; all read 2026-10-29):

| Part | Position | What the vendor page states |
|---|---|---|
| NXP MCX N94x and N54x | Drive and joint controller | EdgeLock Secure Enclave, DICE and UID support, an SRAM PUF root key, FlexCAN FD, -40 to 125 C |
| NXP i.MX RT1180 | Drive controller with fieldbus | EdgeLock Secure Enclave, EtherCAT subdevice controller, gigabit TSN switch, IEC 61508 support, -40 to 125 C |
| NXP i.MX 95 | Application processor | EdgeLock Secure Enclave, Cortex-M7 and M33 beside 6 Cortex-A55, IEC 61508 SIL 2 and ISO 26262 ASIL B stated, industrial grade -40 C ambient to 105 C junction |
| Texas Instruments F29H85x | Real-time controller | EVITA-Full HSM, three C29 cores in lockstep, 6 CAN FD, -40 to 125 C |
| Infineon OPTIGA Trust M | Secure element | ECC P-256/384/521 and Brainpool, no Ed25519, factory X.509 certificate, CC EAL6+-based hardware, -40 to 105 C |
| NXP EdgeLock SE050 | Secure element | NIST, Brainpool, Twisted Edwards and Montgomery curve families, CC EAL6+, -40 to 105 C |

A discrete TPM 2.0 with a manufacturer endorsement certificate earns `tpm`. A secure element (OPTIGA Trust M, SE050, ATECC608B, STSAFE-A120) earns `se`. No microcontroller surveyed is a TPM; the realistic ceiling at a joint is `tee`, or `dice` on a part whose vendor lists it.

## What Furcate does not do

It does not provide a safety function. The Furcate kill switch is not an emergency stop and is not a safety function: it sends an authenticated stop request to equipment you have chosen, and the machine's own emergency stop and safety functions must work without Furcate and without the network. A missing order is not a safe state. Furcate never resets, clears or overrides an emergency stop and never sends a restart, and it does not carry or modify safety-protocol traffic (FSoE, PROFIsafe, CIP Safety). Stop category requested: 0, 1, 2 or unspecified; the safety controller decides. Regulation (EU) 2023/1230 applies from 14 January 2027; conformity of a machine is the manufacturer's. See `docs/physical-command.md`: only shadow mode exists, and a request to actuate is refused.
