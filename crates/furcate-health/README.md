# furcate-health

Node lifecycle, health signals and bounded remediation. The lifecycle is explicit so that every transition can be recorded, and remediation is bounded: a node that flaps between repair attempts is worse than one that stays cordoned and waits for a person.

## Role in Furcate

Used by `furcated`, which feeds it signals and serves the workload inventory on `/workloads` and `/healthz`.

## Public API

- `Lifecycle`, `State`, `Transition`, `LifecycleError`.
- `Signal`, `SignalKind`, `Severity`.
- `Remediator`, `Playbook`, `Step`, `Outcome`.
- `workload`: `Workload`, `WorkloadKind`, `RunState`, `Health`, `Inventory`, `Owner`, `ProjectRollup`, `Endpoint`.
- `slo`: `Objective`, `Observed`, `Status`, `assess`.

## Build and test

From the repository root:

```
cargo build -p furcate-health
cargo test -p furcate-health
```

## Notes

- Pure library with no platform requirements.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
