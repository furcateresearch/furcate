# furcate-sched

One scheduler for everything that runs on a timer. It replaces hand-rolled sleep loops with tasks that have jitter (so nodes restarted together do not poll in lockstep), backoff on failure, drift-free cadence, and a registry that shows which tasks have stalled.

## Role in Furcate

Used by `furcated` (every periodic task), `furcatectl scheduler` and `furcate-siteview`.

## Public API

- `spawn`, `registry`, `Registry`, `TaskState`, `Ran`, `snapshot`, `stalled`.
- `policy`: `Cadence`, `Backoff`, `Outcome`, `Plan`, `next_wait`, `JITTER_PERCENT`.
- `placement`: `place`, `Candidate`, `Demand`, `Share`, `Placement`, `Refusal`.

## Build and test

From the repository root:

```
cargo build -p furcate-sched
cargo test -p furcate-sched
```

## Notes

- Uses standard library threads; no async runtime.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
