# furcate-resource

Pressure, control-group accounting, and limits. It measures pressure rather than utilisation (Pressure Stall Information), reads the kernel's cgroup v2 accounting rather than a container runtime's view so that containers, systemd units and pods are all covered, and sets limits from observed use rather than guesses.

## Role in Furcate

Used by `furcated` (`/resources`, `/bindings`) and `furcate-build`.

## Public API

- `psi`: `Psi`, `Pressure`, `Kind`, `Level`, `Share`, `Thresholds`.
- `cgroup`: `Group`, `Cpu`, `Memory`, `Owner`, `find`, `unified_hierarchy`, `CGROUP_ROOT`.
- `limits`: `Bounds`, `IoMax`, `Step`, `create`, `bound`, `attach`, `remove`.
- `toolchain`: build machine shapes and bounds (`Toolchain`, `BuildMachine`, `Observed`, `Shape`).
- `binding`: service bindings a workload is given (`Binding`, `Need`, `Var`, `redacted_url`).
- `tenancy`: tenant shapes and grants (`Shape`, `Grant`, `Isolation`, `admits`).

## Build and test

From the repository root:

```
cargo build -p furcate-resource
cargo test -p furcate-resource
```

## Notes

- Linux with cgroup v2 mounted at `/sys/fs/cgroup`. Writing limits needs the corresponding delegation or privilege.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
