# furcate-topology

The failure-domain tree and placement rules. Furcate records the physical hierarchy (site, feed, UPS, rack, chassis, node) and evaluates placement as a rule over it: name the domain to spread across, and the structure makes unsafe placements inexpressible. Two replicas on two machines fed by one UPS is not two failure domains. The crate also holds cells (the trust tree of sites and leaves), capacity and headroom, cabling audits and LLDP discovery.

## Role in Furcate

Used by `furcated`, `furcatectl`, `furcate-health`, `furcate-killswitch`, `furcate-mesh`, `furcate-power` and `furcate-siteview`.

## Public API

- `tree`: `DomainTree`, `Node`, `DomainKind`, `Provenance`.
- `placement`: `place`, `PlacementRequest`, `PlacementResult`, `PlacementError`.
- `capacity`: `Capacity`, `Headroom`, `PowerModel`.
- `cell`: `Cell`, `CellTree`, `RollUp`, enrolment and revocation (`enrol_head`, `enrol_leaf`, `apply_revocations`).
- `leaf_request`, `read_token`: signed requests from leaves and short-lived read tokens (`ReadToken`, `ReadTokenVerifier`, `issue`).
- `lldp`: `discover`, `Neighbour`. `cabling`: `audit` of planned against observed links. `path`: `LinkPath`, `PathPreference`.

## Build and test

From the repository root:

```
cargo build -p furcate-topology
cargo test -p furcate-topology
```

## Notes

- LLDP discovery reads neighbour data from the host; the rest is pure.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
