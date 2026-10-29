# furcate-killswitch

Signed orders to request a stop of a machine, a failure domain or the whole cluster. For a machine the order is an advisory stop request, never an emergency stop. A kill switch asserts that an order was authorised by the operator key and nobody else, and that claim is only worth as much as a reader's ability to check it, so this is a small, separate, Apache-2.0 crate rather than part of the power subsystem.

## Role in Furcate

Used by `furcated` (which verifies and carries out orders) and `furcatectl operator kill`. Depends only on `furcate-topology` for the domain tree, `furcate-authn` for passkey approvals, and signature crates.

## What the kill switch is, for a machine

Wording fixed by the project's stop-request decision:

- The Furcate kill switch is not an emergency stop and is not a safety function. It sends an authenticated stop request to equipment you have chosen. The machine's own emergency stop and safety functions must work without Furcate and without the network.
- A missing order is not a safe state. Failure of the link, a key or a Furcate component must leave your safety function unchanged.
- Furcate never resets, clears or overrides an emergency stop and never sends a restart.
- Furcate does not carry or modify safety-protocol traffic (FSoE, PROFIsafe, CIP Safety).
- Stop category requested: 0, 1, 2 or unspecified. The safety controller decides.
- Regulation (EU) 2023/1230 applies from 14 January 2027. Conformity of a machine is the manufacturer's.

On hosts, failure domains and compute, an order still stops what Furcate itself runs: that is the operator's sovereignty guarantee, and it is a supervisory control, not a stop in the sense of IEC 60204-1. A soft pause or a stopped container is a pause or a stopped container, not a stop category.

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
