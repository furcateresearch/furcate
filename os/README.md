# Furcate OS images

Furcate OS is two layers on a device.

1. **A base that does not change while it runs:**
   - the kernel, board firmware files, systemd and Ubuntu 26.04 LTS packages;
   - `/usr` is a read-only erofs image, checked block by block by dm-verity against a root hash on the kernel command line;
   - the base holds no Furcate code;
   - there are two base slots, A and B, so a new base is written beside the running one.
2. **Furcate as signed system extensions:**
   - the node agent (`furcated`), `furcatectl` and the console ship as `furcate.raw`, merged over `/usr` at boot by `systemd-sysext`;
   - each extension's dm-verity root hash is signed by the Furcate release key;
   - updating Furcate means adding a new extension version: no reinstall, and the base is not touched.

What stays across every update: `/etc` (configuration) and `/var` (data, the extension store, the node's enrolment) on the state partition.

## Layout

| Path | What it is |
|---|---|
| `boards/rpi5/` | the Raspberry Pi 5 board layer: kernel and firmware files, the boot configuration, A/B boot via the bootloader's `autoboot.txt` and tryboot |
| `extensions/furcate/` | the Furcate extension (node agent, CLI, console) |
| `extensions/hw-rpi5/` | the Pi 5 hardware tools: Wi-Fi (`iwd`), Bluetooth, audio, I2C/GPIO tools, the signing broker for the board's one-time-programmable key |
| `extensions/modelserver/` | the local model server |
| `extensions/leafhead/` | the head service for a leaf's Wi-Fi link, with Python's `cryptography` from the Ubuntu archive |
| `extensions/sysext-image/` | shared tooling to build and seal an extension image |
| `rootfs/` | files placed in the base, including the `furcate-os` command |
| `release/` | release tooling: checksums, signatures, the public release certificate |
| `tests/` | boot and behaviour tests under qemu, plus unit tests |
| `build.sh`, `mkosi.conf*` | the image build (mkosi) |

## Build

```
os/build.sh rpi5 preflight                   # check every tool, before starting
os/build.sh rpi5 extension <bin-dir>         # stage the furcate extension (unsigned)
os/build.sh rpi5 seal <signature.b64>        # seal it with the release signature
os/build.sh rpi5 hw-extension <base-usr-list>   # the board's hardware extension
os/build.sh rpi5 model-extension <base-usr-list> # the model server
os/build.sh rpi5 image                       # assemble the disk image
os/build.sh rpi5 finish <signature.b64>      # attach and check the image signature
```

A release is `<name>.img.zst` with its `.sha256`, the signature `.sha256.p7s` and `furcate-release.crt`. Verify both before writing a drive. [docs/local-ai.md](../docs/local-ai.md) walks through it from a blank drive.

## On the device: `furcate-os`

| Command | What it does |
|---|---|
| `furcate-os status` | base and slot, `/usr` verification, extensions, network, Wi-Fi, power, watchdog, journal, identity |
| `furcate-os extension install DIR` | add a new extension version live; refused unless signed; rolls back if its health check fails |
| `furcate-os wifi add SSID` / `list` / `remove SSID` | Wi-Fi networks; the passphrase is read from stdin only, never from the command line |
| `furcate-os base-update BUNDLE [--extension DIR]` | write a signed base into the idle slot and arm one trial boot; the trial is kept only if it passes its checks, otherwise the board returns to the previous slot |
| `furcate-os base-tryboot` / `base-status` | boot the armed slot once; show both slots and the last update |
| `furcate-os eeprom-update` | stage the pinned Pi 5 bootloader for the next reboot (`--check` afterwards) |
| `furcate-os identity` | re-run the identity check |
| `furcate-os otp-provision` | write the board's one-time device key. **Permanent and irreversible.** |

## Node health

- The hardware watchdog resets a hung board.
- The journal is persistent and synced every few seconds, and can be streamed to the controller over the overlay.
- A power monitor reads the board's supply and undervoltage flags and sheds load when the supply sags. The real fix for undervoltage is a supply that delivers 5 V at 5 A.

## Tests

`tests/qemu-boot`, `tests/qemu-checks` and `tests/qemu-base-update` boot images under qemu and check verification, extensions, identity, updates and rollback. qemu cannot reproduce the real board's bootloader, so A/B trial boots are also proven on hardware before a release claims them.
