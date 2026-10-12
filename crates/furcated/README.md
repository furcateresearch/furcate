# furcated

The node agent. It runs on every machine, holds the root of trust, keeps the operation chain, watches health and power, tracks membership, publishes sensors and capability, and serves the local API. The agent survives the control plane: if a site controller fails, the node keeps its last known good intent and degrades to safe autonomy rather than waiting for instructions, so a controller crash never becomes a power event.

## Role in Furcate

Ships as `/usr/sbin/furcated` in the node package and the board extension, run by `deploy/systemd/furcated.service`. Brings together nearly every other open crate.

## Public API

- Binaries: `furcated` (full node agent) and `furcated-lite` (for constrained hardware: attests, reports capability, carries sensors and takes work, but never hosts the site controller or the proving ground).
- Library: `main`, `run`, `extension::{Extension, register, Node, NodeFacts}`, `policyfile`, `workloads`.
- HTTP routes include `/healthz`, `/identity`, `/ledger`, `/members`, `/power`, `/thermal`, `/host`, `/hardware`, `/resources`, `/sensors`, `/workloads`, `/models`, `/network`, `/overlay`, `/orders`, `/attest` and `/infer`.
- Configuration is by environment, for example `FURCATE_LISTEN` (default `127.0.0.1:7616`), `FURCATE_SITE`, `FURCATE_NODE_NAME`, `FURCATE_PEERS`, `FURCATE_OVERLAY_ADDR`, `FURCATE_WG_IFACE`, `FURCATE_UPS`, `FURCATE_DEPLOY_ROOT`.

## Build and test

From the repository root:

```
cargo build -p furcated
cargo test -p furcated
```

Run the binary with `cargo run -p furcated --bin furcated`.

## Notes

- Feature `tss` enables the native TSS 2.0 backend. Feature `lite` builds the constrained profile.
- Linux is the primary target; macOS is supported with the Secure Enclave as root of trust.
- Runs unprivileged; interface and power changes go through separate privileged helpers.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
