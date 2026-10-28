# furcate-leaf-core

The core of the leaf firmware: the logic a microcontroller runs to attach to a parent node and publish readings. It is `no_std` and allocation-free so it compiles into ESP32-class firmware with no operating system, no dependable heap and no trustworthy clock. Freshness comes from a monotonic counter, not a timestamp, and the leaf describes how its key is held rather than grading itself.

## Role in Furcate

Supported leaf boards are listed in `docs/leaf-devices/`. Used by `furcate-leaf` (the host-side simulator) and by the leaf firmware, which is built from a separate tree. The parent side of the protocol is in `furcate-sense`.

## Public API

- `LeafState`: sequence counter and payload construction (`next_seq`, `payload`).
- `LeafState::bound_payload`: the signed payload that also binds the hash of the model active when a reading was taken.
- `Sample`, `Batch` and `MAX_BATCH`: bounded batching that drops the oldest sample when full.

## Build and test

From the repository root:

```
cargo build -p furcate-leaf-core
cargo test -p furcate-leaf-core
```

## Notes

- `no_std`, no allocator. Keep dependencies `no_std` compatible.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
