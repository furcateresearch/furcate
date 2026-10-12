# furcate-mesh

The local intelligence mesh. A real edge cluster is uneven: one machine has a GPU, some have decent CPUs, a Jetson sits in a corner and microcontrollers read sensors. Each tier hosts what it can hold, and the whole cluster addresses all of it as one surface. Capability comes from the attested hardware inventory, never from self-declaration, so placement inherits the trust properties of attestation.

## Role in Furcate

Used by `furcated` (model routing and `/infer`) and `furcatectl` (`model`, `roles`, `owner`, `fleet` and `name` commands).

## Public API

- `Capability`, `Tier`.
- `catalog`: `Catalog`, `ModelManifest`, `Route`, `RouteError`.
- `router`: `route`, `route_request`, `score`, `score_with`, `Candidate`, `Weights`, `RouteFailure`.
- `cascade`: `CascadePlan`, `CascadeStage`, `Granularity`.
- `receipt`: `InferenceReceipt`, `VerificationLevel`, `digest`.
- `agreement`, `corruption`: cross-replica comparison and detection of a replica that disagrees.
- `administration`, `roles`, `ownership`, `handles`: which node administers a site, assigned roles, which account owns which machine, and machine names.

## Build and test

From the repository root:

```
cargo build -p furcate-mesh
cargo test -p furcate-mesh
```

## Notes

- Pure library; inference engines are run by the node, not by this crate.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
