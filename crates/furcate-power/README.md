# furcate-power

Power as a first-class subsystem. The ladder descends through reversible rungs as a supply drains and stays interruptible until the last one. The bring-up graph treats startup as dependency resolution rather than a fixed sequence. Measurement comes first and differs per machine: RAPL counters on x86, PMIC and hwmon rails on boards, and power modes on Jetson.

## Role in Furcate

Used by `furcated` (`/power`, `/bringup`, `/thermal`). The kill switch that was once here is now `furcate-killswitch`.

## Public API

- `ladder`: `Ladder`, `Rung`, `PowerState`.
- `bringup`: `BringUp`, `Gate`, `GateState`, `Unit`, `Started`.
- `rapl`: `discover`, `Power`, `Sample`, `Scope`, `Domain`, `power_between`.
- `rails`: `Rail`, `discover_hwmon`, `read_pi_pmic`, `PowerMode`, `parse_nvpmodel`.
- `actuator`: `Governor`, `Lever`, `Applied`, `Capabilities`, `resolve`, `sysfs_write`.
- `thermal`: `rung_for`, `rung_from`, `Thresholds`, `Reading`, `Origin`.
- `wake`: Wake-on-LAN (`magic_packet`, `send`, `armed_from_ethtool`, `WakePath`).

## Build and test

From the repository root:

```
cargo build -p furcate-power
cargo test -p furcate-power
```

## Notes

- Linux sysfs (`/sys/class/powercap`, `/sys/class/hwmon`). Fixtures for tests live in `src/testdata`.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
