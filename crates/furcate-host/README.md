# furcate-host

Host facts: the layer underneath workloads where most real outages start. Filesystems and when they will fill, the clock and its time source, pending reboots, disk wear, firmware age, OS image drift, fans and temperatures, BMC readings, accelerators and the board the node is running on. Most modules are parsers over the output of standard tools and sysfs, with a judgement function on top that says whether the reading is a concern.

## Role in Furcate

Used by `furcated` (which serves `/host`, `/hardware`, `/cooling`, `/thermal` and related routes), `furcatectl`, `furcate-identity`, `furcate-power`, `furcate-sched` and `furcate-build`.

## Public API

- `filesystem` (`Mount`, `Trend`, `Concern`, `assess`), `platform` (`Clock`, `TimeSource`, `Reboot`, `parse_timedatectl`).
- `storage` (SMART: `parse_smartctl`, `assess`), `firmware` (`parse_fwupd`, `Age`), `image` (`parse_os_release`, `parse_bootc`, `parse_ostree`, `drift`).
- `cooling` and `wall` (IPMI SDR parsing), `redfish` (BMC manager, firmware inventory and thermal), `thermal` (`Lever`, `Envelope`, `probe`, `plan`).
- `board`: board identification (Raspberry Pi, Jetson modules, Tegra SoCs), secure-boot state and TPM kind.
- `accelerator`, `inventory`, `mig`, `xid`: accelerator discovery, partitioning layouts and error classification.
- `hardware`: the machine and component registry under `deploy/hardware/` (`recognise`, `Profile`, `may_attempt`).
- `custody` (backup and certificate expectations), `acoustics` (quiet hours for builds), `journal`, `reading`.

## Build and test

From the repository root:

```
cargo build -p furcate-host
cargo test -p furcate-host
```

## Notes

- Linux. Parsers are tested against captured tool output in `src/testdata`; live readers return an absent value when the tool or sysfs node is missing.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
