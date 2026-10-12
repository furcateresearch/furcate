# furcate-killswitch

Signed orders to stop a machine, a failure domain or the whole cluster. A kill switch asserts that an order was authorised by the operator key and nobody else, and that claim is only worth as much as a reader's ability to check it, so this is a small, separate, Apache-2.0 crate rather than part of the power subsystem.

## Role in Furcate

Used by `furcated` (which verifies and carries out orders) and `furcatectl operator kill`. Depends only on `furcate-topology` for the domain tree, `furcate-authn` for passkey approvals, and signature crates.

## Public API

- `KillOrder`, `KillScope` (`Cluster`, `Node`, `Domain`), `KillMode` (`Drain`, `Halt`, `PowerOff`, `Isolate`, `CryptoErase`), `KillSwitch`, `KillError`, `ExecutionStep`.
- `actuate`: `Actuator`, `OutOfBand`, `Report`, `carry_out`.
- `warden`: an out-of-band serial path for powering a machine off when its OS is unreachable (`Warden`, `SerialLine`, `power_off_frame`, `parse_reply`).

## Build and test

From the repository root:

```
cargo build -p furcate-killswitch
cargo test -p furcate-killswitch
```

## Notes

- Actuation on a real host goes through a privileged helper; the crate itself performs no privileged operation in tests.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
