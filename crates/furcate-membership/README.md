# furcate-membership

Cluster membership and failure detection. Membership is gossip, not consensus: SWIM gives scalable, weakly consistent membership without a quorum, which matters because a two-node site cannot form one. The Lifeguard refinement is implemented so that a node starved of CPU or losing packets raises its own local health score and becomes more patient before accusing others; false failure detection triggers drains and, at worst, fencing a healthy machine.

## Role in Furcate

Used by `furcated` (`/members`).

## Public API

- `swim`: `Membership`, `Member`, `MemberState`, `Incarnation`, `Transition`, `LocalHealth`.
- `rumour`: `Rumour`, `Rumours`, `Taken` (piggybacked dissemination).

## Build and test

From the repository root:

```
cargo build -p furcate-membership
cargo test -p furcate-membership
```

## Notes

- Pure library; transport is supplied by the caller.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
