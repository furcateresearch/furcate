# furcate-policy

Who may do what, as data, and the small set of things that must never be. Ordinary authority is a policy evaluated by an engine, so a rule can change without rebuilding every agent. Delegation replaces impersonation: an agent receives a narrowed grant, keeps its own identity, and every hop is traceable. A fixed set of invariants sits outside the policy data and cannot be granted by anyone.

## Role in Furcate

Used by `furcated`, `furcatectl` (`policy`, `act`, `custody`), `furcate-build`, `furcate-breakglass`, `furcate-net`, `furcate-sense` and `furcate-topology`.

## Public API

- `engine`: `PolicySet`, `Policy`, `Request`, `Decision`, `Effect`.
- `delegation`: `Grant`, `GrantError`, `Role`, `Scope`, `Scale`, `CellDelegation`, `evaluate`.
- `invariant`: `Invariant`, `forbidden_to_all`, `forbidden_to_automation`.
- `action`: `Action`, `Refusal`, power cap bounds.
- `proposal`: `Proposal`, `Reversal`, `Status`, `ProposalError` (changes a person approves before an operator signs them).
- `change`: change windows and near-miss classification. `custody`: signed key-custody changes. `file`: loading policy files (`load_from`, `default_candidates`).

## Build and test

From the repository root:

```
cargo build -p furcate-policy
cargo test -p furcate-policy
```

## Notes

- Deny by default; deny wins over allow. Pure library.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
