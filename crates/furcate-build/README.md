# furcate-build

The build arm: attested, content-addressed builds placed on machines the operator owns. A build is an action on a site. It is submitted to the policy engine, placed on a node elected from attested capability rather than self-reported capability, its inputs and outputs are named by content, its result is cached against the digest of the action, and the artifact carries an in-toto provenance statement signed by the node's own key and naming the assurance grade of the machine that produced it.

## Role in Furcate

A library. Builds on `furcate-policy`, `furcate-attest`, `furcate-identity`, `furcate-ledger`, `furcate-host` and `furcate-resource`. No open binary depends on it yet.

## Public API

- Entry point: `execute` with a `BuildContext`, returning an `Outcome` or `BuildError`.
- `BuildAction`, `Network`, `Manifest` (declared build description) and `ManifestAction`.
- `Cas` (content-addressed store), `Digest`, `Hasher`.
- `ActionCache`, `ActionResult`.
- `Isolation`, `ProcessSandbox`, `MicroVm`, `RunReport`.
- `placement::decide`, `NodeCapability`, `PlacementPolicy`, `Placement`.
- `provenance`: in-toto `Statement`, `Predicate`, `Subject`, `Builder`, `SignedProvenance`.
- `Refusal`: the reasons a build is refused.

## Build and test

From the repository root:

```
cargo build -p furcate-build
cargo test -p furcate-build
```

## Notes

- `ProcessSandbox` is the isolation used today; `MicroVm` implements the same `Isolation` trait and refuses to run until it is wired, rather than offering a weaker boundary under its name.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
