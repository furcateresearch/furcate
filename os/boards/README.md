# Board layers

Everything above the kernel is identical on every board. A board layer supplies only:

| Layer | Kernel | Firmware | Boot | Updates |
|---|---|---|---|---|
| `server` (x86_64, arm64 UEFI) | Ubuntu generic | distro firmware | UKI via systemd-boot, Secure Boot | A/B verity `/usr` via systemd-sysupdate; TPM2 PCR policy for encrypted state |
| `sbc` (Raspberry Pi 5 / CM5) | Raspberry Pi kernel | Pi firmware and EEPROM | tryboot A/B with a signed boot image | A/B `/usr` via systemd-sysupdate, boot image as its own transfer |
| `embedded-ai` (NVIDIA Jetson Orin / Thor), waits for NVIDIA 26.04 support | NVIDIA L4T kernel for 26.04 | L4T firmware, OP-TEE | L4T boot chain | A/B `/usr` via systemd-sysupdate where L4T's slot scheme allows; to be proven on hardware |

Board layers are the only per-board difference. A new board is a new layer, never a new distribution.
