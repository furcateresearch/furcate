# furcate-command

The site-side gate for commands that a simulation platform proposes. One command in, one signed and chained receipt out. The wire format, the gate order and every error code are in `docs/physical-command.md`; the decision behind actuation is `docs/decisions/0012-actuation-approval-and-release.md`.

## Not a safety function

The Furcate kill switch is not an emergency stop and is not a safety function. It sends an authenticated stop request to equipment you have chosen. The machine's own emergency stop and safety functions must work without Furcate and without the network. A missing order is not a safe state. Furcate never resets, clears or overrides an emergency stop and never sends a restart.

Nothing in this crate is a safety function either: not the stages, not the approval, not the executor interface, not a receipt. A refusal is not a safe state. A stop request is advisory, is emitted only for a vetoed or truncated chunk and for a trajectory command under a kill order, and nothing here transmits it. An execution failure does not emit one. Conformity of a machine is the manufacturer's.

## Stages

Per system class the site sets a stage (`Stage`): `Observe` refuses every command (`observe_only`), `Shadow` (the default) decides and records and writes nothing, `Actuate` may release an accepted command. Releasing needs both the site-local stage and an installed actuation approval signed by an approver the site enrolled, covering tenant, site, class, actuator and command kind. Anything missing or doubtful is `actuation_not_approved`.

`Gate::new` with no `with_actuation` never releases. `Gate::decide` has no executor and never releases. Only `Gate::decide_exec` can.

## Use

```rust
let mut gate = Gate::new(policy, kill, site_key, chain).with_actuation(ActuationConfig {
    classes: vec![("arm-1".into(), "robot_arm".into())],
    stages: vec![("robot_arm".into(), Stage::Actuate)],
    approvers: vec!["ed25519:...".into()],
});
gate.install_approval(approval_bytes, now_ms)?;      // ledgered
let receipt = gate.decide_exec(command_bytes, now_ms, &mut executor);
gate.revoke_approval("approval-id", now_ms)?;        // ledgered, takes effect at once
let state = gate.export_state();                     // persist atomically after every decision
let gate = Gate::restore(policy, kill, signer, Some(cfg), state)?; // refuses a state whose chain does not verify
```

An `Executor` receives a `Release`, which only the gate can make. For a trajectory it holds only the accepted prefix. The gate writes a ledger entry (`released:ok:<sha256 of the command>`) before the executor runs, advances the sequence number whether or not the write succeeds, and re-reads the kill state and takes a probe signature immediately before release; a site signer that cannot sign releases nothing. The receipt of a command whose mode is `actuate` carries an `execution` member.

`Gate` is generic over `SiteSigner`, so the site key can stay in a key service or hardware module; an in-memory `SigningKey` implements it and is what tests use.

## Tests

`cargo test -p furcate-command`. The fault suites (`tests/faults.rs`, `tests/chunk_faults.rs`) run 20,000 mutated commands in a debug build and 1,000,000 in a release build, `FAULT_CASES` overrides; they assert zero false accepts and, against an approved actuate-stage gate, that an executor is called only for the pristine approved command (or, under a truncating policy, with the exact predicted prefix). Test keys are public seeds (`0x4c` platform, `0x53` site, `0x41` approver) and sign nothing real.
