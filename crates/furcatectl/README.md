# furcatectl

The operator command-line tool. It inspects the machine's hardware identity, seals and unseals secrets, issues signed operator orders (kill switch, break-glass, accelerator reset), manages people, roles, trust and policy, deploys sites and domains, runs local models, and reads every subsystem the node agent exposes. All logic is in the library; the binary calls `furcatectl::main`.

## Role in Furcate

Ships as `/usr/bin/furcatectl` in the CLI package. Editions add commands by implementing `extension::Commands` and calling `extension::register` before `main`.

## Public API

- Library: `main`, `signed_post`, `extension::{Commands, register}`.
- Identity and secrets: `identity show|quote|enroll|coverage|bench|recovery|soft-enroll|re-enrol`, `seal`, `unseal`, `custody`.
- Authority: `operator init|seal|kill|breakglass`, `session`, `act`, `policy grant|revoke`, `trust`, `people`, `roster`, `roles`.
- Fleet and site: `fleet`, `site`, `members`, `name`, `owner`, `node decommission`, `gateway`.
- Network: `network show|links|lan`, `tunnels`, `domain`, `edge render|zone`.
- Workloads and models: `deploy`, `workloads`, `workload restart`, `model`, `orchestrator`, `chat`, `ask`.
- Machine state: `host`, `hardware`, `power`, `thermal`, `cooling`, `sensors`, `ledger`, `scheduler`, `routing`, `keys`, `wake`, `selftest pcr|tpm|uki|units`.
- Run `furcatectl` with no arguments for the full usage text.

## Build and test

From the repository root:

```
cargo build -p furcatectl
cargo test -p furcatectl
```

Run the binary with `cargo run -p furcatectl --bin furcatectl`.

## Notes

- Feature `tss` passes through to `furcate-identity/tss` (native TSS 2.0 backend, needs `libtss2-dev`).
- The default build has no feature flags; everything Apache-2.0 compiles without any.
- Commands that touch the TPM or install files need root.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
