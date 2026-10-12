# furcate-breakglass

Emergency access that works when the control plane does not, and the accountability that makes it safe. Ordinary grants in `furcate-policy` assume the machinery that issues them is reachable; emergency access is needed exactly when it is not. A break-glass grant is therefore a signed order verified locally against the operator key, in the same way as a kill-switch order, with its use recorded so it can be reviewed afterwards.

## Role in Furcate

Used by `furcatectl operator breakglass`. Depends on `furcate-policy` for the action vocabulary and invariants an emergency grant still cannot reach.

## Public API

- `BreakGlass`: an emergency grant (holder, actions, resources, lifetime, reason) signed by the operator key.
- `Requirement`: what must hold for a grant to be honoured.
- `Use`, `Register`: the record of each use of a grant.
- `BreakGlassError`.

## Build and test

From the repository root:

```
cargo build -p furcate-breakglass
cargo test -p furcate-breakglass
```

## Notes

- Single-module crate with no platform requirements.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
