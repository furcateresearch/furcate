# furcate-leaf

A host-side simulator for the leaf firmware. The firmware core is `no_std` and cannot run on a workstation as-is, so this binary drives the same logic from `furcate-leaf-core` against a real parent port from `furcate-sense`. It is how the attachment and replay rules are checked without flashing a device.

## Role in Furcate

A development tool. Nothing in the shipped tree depends on it.

## Public API

- Binary `furcate-leaf`, no arguments. It attaches a simulated device to a parent, publishes a series of readings, and prints which were accepted or refused.

- Binary `furcate-small`, the small processing node: `serve`, `replay` and `identity`. See `crates/open/furcate-sense/docs/small-processing-node.md` and `deploy/small-node/README.md`.

## Build and test

From the repository root:

```
cargo build -p furcate-leaf
cargo test -p furcate-leaf
```

Run the binary with `cargo run -p furcate-leaf --bin furcate-leaf`.

## Notes

- Runs on any host that builds the workspace.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
