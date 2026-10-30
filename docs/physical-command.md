# Physical command and receipt: the wire format

The down path. A simulation platform (Living Worlds core) proposes a setpoint or a trajectory chunk; a site gate (Furcate) decides and answers with a signed receipt. Per system class the site sets one of three stages: `observe` (readings flow up, every command is refused with `observe_only`), `shadow` (the default: the gate decides and records what it would do, nothing is written anywhere) and `actuate`. A command is written to equipment only when BOTH the site-local stage of the actuator's system class is `actuate` AND a verified, unexpired, unrevoked actuation approval covers the tenant, site, class, actuator and command kind. Anything missing or doubtful is `actuation_not_approved`. A gate built without an actuation configuration, or asked to decide without an executor, refuses every command that asks to actuate, exactly as before. Version lives in the payload (`v`), never in a URL: the route is `/physical/commands`.

Nothing in this document describes a safety function. The gate is a security and supervisory check in front of a write path; it is not an emergency stop, it does not replace the machine's own safety system, and a refusal, a receipt or a stop request is never evidence that a machine is in a safe state (see "What the kill switch is" and "What is and is not a safety function" below).

Both records are JSON in RFC 8785 canonical form. A gate accepts a document only if the bytes it received ARE the canonical form of what they parse to (no whitespace, keys in UTF-16 code unit order, integers as integers, other numbers in ECMAScript shortest form, strings escaped only where required). That one rule rules out duplicate keys, reordered keys, escapes where a literal would do, `1.0` for `1`, a byte order mark and trailing data. Integer-valued numbers of magnitude 2^53 or more are refused. Unknown members are refused.

## Signatures

Every signature is Ed25519 over `SHA-256( len(domain) || domain || len(msg) || msg )`, lengths as 8 bytes big-endian, `msg` the canonical bytes of the record without its `signature` member. Keys are written `ed25519:<64 lowercase hex>`, signatures as 128 lowercase hex. Verification is strict (small-order keys and non-reduced signatures refused).

| Record | Signer | Domain |
|---|---|---|
| physical-command | enrolled simulation-platform key | `lw-physical/command/v1` |
| twin-band-certificate | enrolled simulation-platform key | `lw-physical/twin-cert/v1` |
| physical-receipt | the site key | `furcate/physical-receipt/v1` |
| actuation-approval | an approver key the site owner enrolled | `lw-physical/actuation-approval/v1` |

The platform signer is a hardware-backed key held by the platform's operators and enrolled at the site by the site owner. No private key is ever stored in a repository; golden vectors use public test seeds (32 bytes of `0x4c` for the platform, `0x53` for the site, `0x41` for the approver). The site key may live in a key service or hardware module: the gate holds only the `SiteSigner` interface (a public key id and a call that signs the 32-byte domain digest), and a signer that cannot sign stops every release.

## physical-command (v1)

```
{ "format": "physical-command", "v": 1,
  "command_id": id, "tenant": id, "site_id": id,
  "target": { "actuator_id": id, "scope": id },
  "kind": "setpoint",
  "body": { "quantity": name, "unit": name, "value": number },
  "issued_at_ms": int, "not_before_ms": int, "expires_at_ms": int,
  "nonce": 32 hex, "command_seq": int >= 1,
  "mode": "shadow" | "actuate",
  "policy_sha256": 64 hex, "model_sha256": 64 hex, "birth_record_sha256": 64 hex (optional),
  "envelope": { "min": number, "max": number, "max_rate_per_s": number >= 0 },
  "twin_cert": { twin-band-certificate },
  "signer": key, "signature": 128 hex }
```
`id` is 1 to 64 characters of `[A-Za-z0-9._:-]`; `name` is 1 to 32 characters of `[a-z_]`. Two kinds are accepted in v1: `setpoint` and `trajectory` (below). The other kinds (`model_update`, `calibration_update`, `mode`) are reserved and refused as `unsupported_kind`; a model update has its own record, `model-update`, in docs/model-update.md. Times are milliseconds since the Unix epoch. `command_seq` is strictly increasing per site over accepted commands. `policy_sha256` is the hash of the signed operator policy the sender believes is in force; `model_sha256` is the model that produced the setpoint; `birth_record_sha256`, when present, binds the model to its signed birth record (world, twin, run, solved-band certificate at release). `envelope` is the sender's clipped envelope; the site enforces its own, independent and stricter-wins.

## twin-band-certificate (v1)

The twin's solved-band certificate, issued by the platform from the twin state and signed by it.
```
{ "format": "twin-band-certificate", "v": 1, "tenant": id, "twin_id": id, "version": int,
  "ranges": [ { "quantity": name, "unit": name, "min": number, "max": number } ],
  "valid_from_ms": int, "valid_until_ms": int, "fidelity_score": number in [0,1],
  "signer": key, "signature": 128 hex }
```

## Gate order (first failure is the answer)

1. canonical and well formed (`malformed`, `not_canonical`, `unsupported_format`, `unsupported_kind`)
2. `wrong_site`, `wrong_tenant`
3. kill switch for the site or actuator in force: `kill_switch_active` (decision `killed`)
4. signer enrolled (`signer_not_enrolled`) and signature valid (`bad_signature`)
5. stage and approval (`observe_only`, `actuation_not_approved`; see "Stages and actuation"). Nothing the command says can raise a stage or stand in for an approval.
6. freshness: `issued_at_ms` not beyond now plus the site skew and now at or after `not_before_ms` (`not_yet_valid`); now before `expires_at_ms` and no older than the site's maximum age (`expired`, decision `expired`); lifetime within the site maximum (`ttl_too_long`)
7. `command_seq` greater than the last accepted (`replayed_sequence`)
8. `policy_sha256` equals the site policy (`policy_hash_mismatch`); `model_sha256` in the approved set (`model_not_approved`); where the site requires a birth record, present (`birth_record_required`) and approved (`birth_record_not_approved`)
9. certificate: signer enrolled (`twin_cert_signer_not_enrolled`), signature (`twin_cert_bad_signature`), same tenant (`twin_cert_wrong_tenant`), `valid_from_ms` reached (`twin_cert_not_yet_valid`), unexpired and valid through the command's expiry (`twin_cert_expired`), fidelity at or above the site minimum (`twin_fidelity_low`), value inside a certified range for its quantity and unit (`outside_certified_range`)
10. for a `setpoint`: envelopes: inside the sender's envelope (`outside_lw_envelope`); the site has a limit for the actuator and quantity (`no_site_limit`, default deny); inside the site limit (`outside_site_envelope`); change per second since the last accepted setpoint within both rates (`rate_exceeded`)

11. for a `trajectory`, in place of 9's range check and 10: the band reference (`band_reference_mismatch`), a site limit for the actuator (`no_site_limit`), then the chunk checks below (`chunk_vetoed`, or `chunk_truncated` where the site allows truncation)

Only an accepted command advances the sequence. Decision values: `executed` (the whole command was written and acknowledged; produced only when an executor is attached and the command was released), `shadowed`, `truncated` (a trajectory accepted in part; with an executor only the accepted prefix is written), `failed` (released, and the executor reported an error; writes may be partial), `denied`, `expired`, `killed`.

## Stages and actuation

Each actuator belongs to one system class, a name (`[a-z_]`, 1 to 32 characters, for example `robot_arm` or `hvac_valve`) that the site assigns locally. Per class the site sets a stage. The site configuration holds the actuator-to-class table, the stage per class and the enrolled approver keys; none of it comes from a command.

| Stage | A command for the class |
|---|---|
| `observe` | refused with `observe_only`, whatever its mode |
| `shadow` (default when nothing is configured) | decided and recorded; a command with mode `actuate` is `actuation_not_approved` |
| `actuate` | may be released, if an approval covers it and the gate has an executor |

An actuator with no class is in no class and is never released. A class with no stage entry is at `shadow`.

### actuation-approval (v1)

A person or organisation, holding a hardware-backed approver key that the site owner enrolled at the site, approves actuation for one system class, a list of actuators and the command kinds.
```
{ "format": "actuation-approval", "v": 1, "approval_id": id, "tenant": id, "site_id": id,
  "system_class": name, "actuator_ids": [id, ...]  (1 to 64, sorted, unique),
  "kinds": ["setpoint", "trajectory"]  (non-empty subset, sorted, unique),
  "valid_from_ms": int, "valid_until_ms": int  (at most 31 days apart; both ends enforced),
  "approver": key, "signature": 128 hex }
```
Canonical bytes, exact member set, unknown members refused. The gate installs it only if the tenant and site are its own, the approver is enrolled, the signature verifies (strict), the window is positive, at most 31 days and not over, and the id is neither installed nor ever revoked. A future `valid_from_ms` is accepted and enforced at use. Installing and revoking each append a ledger entry (kind `command`, actor `gate:<site_id>`, subject the approval id, result `approval_installed:ok:<sha256 of the record bytes>` or `approval_revoked:ok:<id>`). Revocation removes the approval at once; the id can never be installed again. An approval whose approver is later removed from the enrolled set stays in the state and stays inert.

### Release

An accepted command with mode `actuate`, for a class at `actuate`, with a covering approval, decided by `decide_exec` with an executor, goes through this fixed sequence after every check above has passed:

1. the kill state is read again immediately before release (unknown is killed): `kill_switch_active`, nothing released;
2. the approval is checked again at the decision time;
3. a probe signature is taken with the site signer and verified; if the signer cannot sign, nothing is released, nothing is consumed and the service answers "unavailable";
4. a write-ahead ledger entry (kind `command`, actor `gate:<site_id>`, subject the command id, result `released:ok:<sha256 of the command bytes>`) is appended;
5. the sequence number and the rate and chunk state advance; a failed write still consumes the sequence number, so a command is never replayed;
6. the optional release hook persists the state; if it fails, the executor is not called;
7. the executor runs and the final receipt is made: `executed`, `truncated` (only the accepted prefix was released) or `failed` with `execution_failed`.

The executor is never called for a refusal. It receives a `Release`, which only the gate can construct (private fields, crate-private constructor, a `compile_fail` doctest proves it); a setpoint release carries quantity, unit and value, a trajectory release carries only the accepted prefix of steps. A crash after step 4 and before the receipt leaves a `released` entry with no receipt: the command may or may not have been written, and the site's operator reconciles it; that is why the entry is written first.

`decide` (no executor) never releases: a command asking to actuate is `actuation_not_approved`.

### State kept across a restart

`GateState` holds the last accepted sequence number, the last accepted setpoint per actuator and quantity, the end of the last accepted chunk per actuator, the receipt counter, the installed approvals (raw bytes), the ids of revoked approvals and the ledger chain. `export_state` produces it; `restore` rebuilds a gate and refuses (fail closed) a state for another site or tenant, whose chain does not verify, whose approvals do not verify or are not in the chain as installed and not revoked, or that lists a revocation the chain does not contain. The service writes the state atomically (temporary file, fsync, rename) after every decision before it answers.

## trajectory (action chunk), kind `trajectory`

Modern robot policies (vision-language-action, diffusion, flow-matching) emit a chunk of N future steps per inference, not one command. A `trajectory` command is one chunk, decided as a whole. It has no top-level `envelope` member (a command with both is `malformed`); the sender's limits are inside the body and the site's own limits are independent, with the stricter winning. Everything else in the command is as for a setpoint, so the chunk is signed, fresh, sequenced, tied to the policy hash, the approved `model_sha256` and the birth record, and carries the twin certificate.

```
"kind": "trajectory",
"body": {
  "chunk_index": int, "dof": 1..32, "step_ms": 1..1000,
  "steps": [ { "q": [dof numbers], "tau": [dof numbers] (optional), "xyz": [3 numbers] (optional) } ],   1 to 1024 steps
  "start": { "q": [dof], "dq": [dof], "ddq": [dof] },
  "limits": { "q_min", "q_max", "dq_max", "ddq_max", "dddq_max": [dof], "tau_max": [dof] (optional),
              "xyz_min": [3], "xyz_max": [3] (optional, together) },
  "twin_cert_sha256": 64 hex }
```
Units are fixed: joint position in radian, effort in newton metre, workspace in metre. Every number is at most 1e9 in magnitude. `tau` and `xyz` are present in every step or in none.

Per chunk, bound by the signature: `model_sha256` and `birth_record_sha256` are the command's own members, so the model that produced a chunk is signed with the chunk and checked against the approved set every time. The solved-band reference is `twin_cert_sha256`, the SHA-256 of the canonical twin certificate including its signature; it must equal the hash of the certificate carried in the command, or the chunk is refused as `band_reference_mismatch`. The band check itself is per step: every `q` must lie inside a certified range for quantity `joint_position`, unit `radian`, and every `tau` inside one for `joint_effort`, `newton_metre`. No certified range for a quantity the chunk uses means every step is outside it.

Derived quantities are finite differences at `dt = step_ms / 1000`: `v[i] = (q[i] - q[i-1]) / dt`, `a[i] = (v[i] - v[i-1]) / dt`, `jerk[i] = (a[i] - a[i-1]) / dt`. A limit is violated when the magnitude is strictly greater than it. Before step 0, the previous values come from the gate's own record of the end of the last accepted chunk for the actuator; where there is none, from the chunk's `start`.

### Site limits (per actuator, default deny)

`dof`; `q_min`, `q_max`, `dq_max`, `ddq_max`, `dddq_max` per joint; optional `tau_max` per joint and workspace box `xyz` (when set, the chunk must carry `tau` or `xyz` in every step); `min_step_ms`, `max_step_ms` (the update rate), `max_steps`, `min_chunk_interval_ms`, `join_tolerance` (largest joint position gap between the end of the last accepted chunk and `start.q`); the overrun policy, `veto` or `truncate` with a minimum prefix; and the safety controller a stop request is addressed to, with the stop category asked for. An actuator with no trajectory limit is `no_site_limit`.

### Verdict

The gate always returns a structured verdict. `outcome` is `accepted`, `truncated` or `vetoed`; `steps_total`; `steps_accepted` (all, the steps before the first violation, or 0); and `first_violation`: `step` (index from 0, null when the whole chunk or the start state is at fault), `joint` (the joint index; the axis for `workspace`), `limit`, `source` (`site`, `sender` or `band`), `value` and `bound`. Checks run in a fixed order and the first violation is the one reported: chunk level first (`dof`, `step_rate`, `chunk_length`, `chunk_interval`, `missing_field`, `continuity`, then the start state's velocity and acceleration), then step by step, and inside a step `position`, `certified_band`, `workspace`, `effort`, `velocity`, `acceleration`, `jerk`; lowest joint first; the site's bound before the sender's.

A violation of the chunk as a whole always vetoes the whole chunk. A violation at a step vetoes the whole chunk under the `veto` policy; under `truncate` the longest prefix before the first violating step is kept if it has at least the site's minimum number of steps (at least 1), and otherwise the chunk is vetoed. A veto is decision `denied` with error code `chunk_vetoed`; a truncation is decision `truncated` with `chunk_truncated`. Neither executes anything. A truncated chunk ends wherever its prefix ends, and that end is what the next chunk must join.

The gate's own record is advanced only by an accepted or truncated chunk: its sequence number, its end state (position, velocity, acceleration at the last accepted step) and its issue time for the interval check. A vetoed chunk changes nothing.

The receipt of a trajectory command adds two members that setpoint receipts do not have: `chunk` (the verdict above, or null when the command was refused before it could be judged) and `stop_request_sha256` (null or the SHA-256 of the stop request's canonical bytes). Setpoint receipts and the golden vector for them are unchanged.

### Stop request (advisory, never an emergency stop)

When a chunk is vetoed or truncated, and when any trajectory command arrives while a kill order is in force, the gate emits a signed output record, `physical-stop-request`, addressed to the safety controller the site named for that actuator. It is an output record only: nothing in this crate transmits it, and nothing acts on it.

It is advisory to a safety-rated controller and never replaces one. Under Regulation (EU) 2023/1230 Annex III 1.2.4.3 an emergency stop device must stop the hazardous process as quickly as possible, latch, not restart on release and be available at all times; a network message is not that device, and the loss of this channel must leave the machine safe by its own means. The record therefore carries `"advisory": true` and `"emergency_stop": false`, and a verifier refuses a record that says otherwise. It names a stop category (`sto` for IEC 60204-1 category 0, `ss1` for category 1, `ss2` for category 2) as a request: the safety controller decides and executes. No record in this crate clears or resets a stop, and a remote resume does not exist.

```
{ "format": "physical-stop-request", "v": 1, "request_id": "stop-<command_id>", "tenant", "site_id", "actuator_id",
  "command_id", "command_sha256": sha256 of the bytes received,
  "reason": "chunk_vetoed" | "chunk_truncated" | "kill_switch_active", "first_violation": object | null,
  "safety_controller_id": id, "requested_stop": "sto" | "ss1" | "ss2", "advisory": true, "emergency_stop": false,
  "receipt_seq": int, "issued_at_ms": int, "site_key": key, "signature": 128 hex }
```
Signed by the site key, Ed25519 over the same domain-separated digest, domain `furcate/physical-stop-request/v1`. A request is not appended to the ledger on its own; the receipt of the same decision commits to it by hash, and the receipt's ledger entry commits to the receipt.

### Time budget

A chunk period on a 50 Hz policy with a 50-step chunk is about 1 s of motion, and about 0.5 s on a pi0-class policy; the gate's decision time for a 50-step, 7-joint chunk is measured by `decision_time_for_one_chunk` in tests/chunk.rs, which prints the figure and asserts it is below one chunk period. The figure for a release build is in docs/research/robotics-hardware-and-architectures-2026-10.md section 14.

## physical-receipt (v1)

One per decision, refusals included, appended to the site ledger chain before it is returned.
```
{ "format": "physical-receipt", "v": 1, "command_id": id | "unparsed", "tenant", "site_id",
  "decision": "executed|shadowed|truncated|failed|denied|expired|killed", "error_code": code | null,
  "mode": string | null, "command_sha256": sha256 of the bytes received,
  "policy_sha256": the site's, "model_sha256": string | null, "birth_record_sha256": string | null,
  "envelope_applied": { "min", "max" } | null  (intersection of both envelopes, accepted only),
  "decided_at_ms": int, "receipt_seq": int, "site_key": key,
  "ledger": { "seq": int, "entry_hash": 64 hex }, "signature": 128 hex }
```
A receipt for a command whose `mode` is `actuate`, whatever the decision, has one more member, `execution`: null when the command never reached release, else `{ "approval_id": id, "system_class": name, "release_ledger_seq": int, "release_entry_hash": 64 hex, "writes": int, "acked": bool }`. `release_ledger_seq` and `release_entry_hash` name the write-ahead entry. `writes` is the number of writes done and acknowledged; `acked` is true only when the executor reported the whole release done. For `failed`, the writes may be partial and `acked` is false, and the receipt says so. Shadow receipts and the golden vectors do not have the member.

If the site signer cannot sign, the receipt cannot be signed: the gate returns an unsigned result with `signer_error` set and no bytes, and the service answers 503. When that happens before release nothing was released and nothing was consumed.

The ledger entry (kind `command`) has the actor `gate:<site_id>`, the subject the command id, and the result `decision:code:digest`, where digest is SHA-256 of the canonical receipt without its `ledger` and `signature` members. The receipt carries the entry's sequence and hash, and the site signs the whole.

## What the kill switch is

Wording fixed by the project's stop-request decision:

- The Furcate kill switch is not an emergency stop and is not a safety function. It sends an authenticated stop request to equipment you have chosen. The machine's own emergency stop and safety functions must work without Furcate and without the network.
- A missing order is not a safe state. Failure of the link, a key or a Furcate component must leave your safety function unchanged.
- Furcate never resets, clears or overrides an emergency stop and never sends a restart.
- Furcate does not carry or modify safety-protocol traffic (FSoE, PROFIsafe, CIP Safety).
- Stop category requested: 0, 1, 2 or unspecified. The safety controller decides.
- Regulation (EU) 2023/1230 applies from 14 January 2027. Conformity of a machine is the manufacturer's.

The gate `kill_switch_active` records that an operator stop request is in force and answers `killed`; it is a refusal of Furcate's own output, not a stop of the machine. `resume`, `mode` and any restart stay refused at `unsupported_kind` permanently where they would touch emergency-stop or protective-stop state; that is not a temporary limitation.

## Error codes

`malformed not_canonical unsupported_format unsupported_kind wrong_site wrong_tenant kill_switch_active signer_not_enrolled bad_signature actuation_not_approved expired not_yet_valid ttl_too_long replayed_sequence policy_hash_mismatch model_not_approved birth_record_required birth_record_not_approved twin_cert_signer_not_enrolled twin_cert_bad_signature twin_cert_wrong_tenant twin_cert_expired twin_cert_not_yet_valid twin_fidelity_low outside_certified_range outside_lw_envelope no_site_limit outside_site_envelope rate_exceeded chunk_vetoed chunk_truncated band_reference_mismatch observe_only execution_failed`

`chunk_vetoed`, `chunk_truncated` and `band_reference_mismatch` are for trajectory commands. The first twenty-nine are unchanged. `observe_only` (the class is at stage `observe`) and `execution_failed` (a released command whose write failed; decision `failed`) are the two newest. `actuation_not_approved` now means any of: no actuation configuration, no executor, the class not at `actuate`, the actuator in no class, or no installed, unexpired approval from an enrolled approver covering the actuator, class and kind.

## What is and is not a safety function

Nothing in the gate, the approval record, the executor interface or a receipt is a safety function, a safety-rated channel or an emergency stop, and none carries a performance level, SIL or stop category of its own. The stages, the approval, the second range check in an executor and the kill switch are layers of authorisation and supervision in front of a write path. The machine's own emergency stop, protective stops and safety-rated controller stay the safety function, must work without Furcate and without the network, and are the manufacturer's to validate (Regulation (EU) 2023/1230 applies from 14 January 2027).

Two limits are stated plainly. The stop request is advisory and nothing here transmits it: it is emitted for a vetoed or truncated chunk and for a trajectory command that arrives under a kill order, exactly as before, and it is not emitted for an execution failure. A `failed` receipt with partial writes tells an operator what was written; it does not stop or undo anything. Revoking an approval or setting a class back to `observe` stops further releases from this gate; it does not stop a write already in progress and is not a stop of the machine.

Enabling actuation for a real machine is a physical, owner-gated act: wiring an executor to equipment, enrolling an approver, and a customer's approval are not done by software here (docs/decisions/0012).

## Golden vector

`tests/fixtures/physical-command.golden.json` (crates/open/furcate-command in Furcate, tests/fixtures in core): the unsigned inputs, the canonical signed command, the receipt for it and the receipt for its replay. Both sides rebuild the command from the inputs with the public test seed and require the same bytes; the Furcate side also regenerates the receipts. The file is identical in both repositories; a test on each side fails on drift.

## Numbers

Non-integer numbers are written in the ECMAScript shortest form, the nearest digits of the shortest length and the even one on a tie. A reader must parse exactly (round to nearest) and write that form back; `tests/fixtures/canonical-numbers.json` holds 4,000 numbers generated by Node that both sides must render to exactly the text given. (Parsing that is off by one unit in the last place changes the canonical bytes and so the signature; the Furcate gate enables the exact parser for that reason.)

## Offline verification of the action history

`furcate-history-verify <chain.json> <checkpoint.json> [--site-key <key> <receipt.json>...]` checks a site's ledger chain against a quoted checkpoint `{size, head, merkle_root}` (the Merkle root is over the entry hashes). It finds a deleted, reordered or altered entry (the chain no longer verifies), a history shorter than the quote, a different history behind the same quote (head or root differ), and two histories that fork. For a receipt it checks the site's signature, that its `ledger.seq` and `entry_hash` are the entry in the chain, and that the entry's result carries the digest of that receipt. With an inclusion proof instead of the chain it checks the receipt's entry hash is the leaf at its position under the quoted root. It cannot check that the physical effect matched the command.

## Golden vector for trajectories

`tests/fixtures/physical-trajectory.golden.json`: one accepted chunk, one vetoed chunk with its stop request, and one truncated chunk, each as the unsigned inputs, canonical signed command, receipt and stop request, with the public test seeds. It is generated and checked on the Furcate side by `tests/chunk_golden.rs`. The Living Worlds core has not built the matching side, so the file is not yet shared; the byte-identity discipline of the setpoint vector applies once it does.

## Fault-injection test

`crates/open/furcate-command/tests/faults.rs` mutates valid commands with a fixed seed and asserts that the gate accepts none of them. A second test in the same file runs the same mutations against a gate at stage `actuate` with an installed approval and an executor, and asserts that the executor is called only for the pristine approved command, exactly once. A debug-profile `cargo test` runs 20,000 cases; `cargo test --release` runs 1,000,000. The environment variable `FAULT_CASES` overrides the count in either profile, for example `FAULT_CASES=1000000 cargo test -p furcate-command --test faults --release -- --nocapture`. The seed does not change with the count, and the assertion of zero false accepts holds for every count.

### Chunk fault-injection test

`crates/open/furcate-command/tests/chunk_faults.rs` does the same for trajectories, with the same counts (20,000 in a debug build, 1,000,000 in a release build, `FAULT_CASES` to override) and the same invariant, zero false accepts. Its 38 categories are byte-level damage to the signed chunk, re-signed chunks with one thing wrong (a position, a jump in position, effort or workspace out of range, a step period outside the site's, a chunk longer than the site's, missing effort or workspace members, a start state over the limits, a sender limit tighter than the motion, a narrowed band, a wrong band reference, a gap in continuity, chunks too close together, the wrong number of joints, malformed bodies, actuate, a wrong model, policy or birth record, wrong site or tenant, time, fidelity, an unenrolled signer, a kill order, sequence numbers, wrong kind or an envelope member, oversize and deep nesting). For designed violations the test knows the step, the joint and the limit, and compares the verdict: the limit and step named must match, and under a truncating policy the accepted prefix must be exactly the steps before the violation. Every vetoed or truncated mutant must carry a stop request that verifies. A further test runs the same mutations against an approved gate at stage `actuate` with an executor: the executor must never be called for a mutant except for a designed step-level violation under a truncating policy, where it receives exactly the predicted prefix; the pristine approved chunk is released whole, once. A second test checks the gate against an independent re-implementation of the limits on random perturbations of a valid chunk: the gate accepts the whole chunk exactly when the independent check finds no violation, and names the same step and limit otherwise.
