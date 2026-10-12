# furcate-ledger

Hash-chained proofs of chip-level operations. Every operation that touches the root of trust appends to a per-node chain in which each entry commits to its predecessor. Periodically the chain head is extended into a platform register and quoted, producing a checkpoint the operator cannot forge or roll back. Site controllers aggregate node heads into a Merkle root, so one anchor covers every node and any single operation can be proven against it with a short inclusion path.

## Role in Furcate

Used by `furcated` (`/ledger`), `furcatectl ledger`, `furcate-attest`, `furcate-build`, `furcate-machine`, `furcate-mesh`, `furcate-policy` and `furcate-session`.

## Public API

- `Chain`, `Op`, `OpKind`, `ChainError`, `Digest32`.
- `Checkpoint`, `CheckpointError`, `predict_extend`, `DEFAULT_CHECKPOINT_PCR`.
- `MerkleTree`, `InclusionProof`.
- `store`: `load`, `save`, `StoreError`.

## Build and test

From the repository root:

```
cargo build -p furcate-ledger
cargo test -p furcate-ledger
```

## Notes

- Pure library; checkpoint quotes are produced through `furcate-identity`.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
