# The birth record and the experience ledger

A policy, controller, model or plan that leaves a digital world for a physical machine carries a signed birth record. The record binds the artefact hash to its digital lineage and to a hash-chained experience ledger of everything the run lived through. The producer is the Living Worlds service signer; the consumer is a node, which refuses to accept a model or policy without a valid record.

Two implementations share this contract and one golden vector:

- Living Worlds core: `src/experience-ledger.ts`, `src/birth-record.ts`, `src/release-gate.ts`, vector `tests/fixtures/birth-record.golden.json`.
- Furcate: `crates/open/furcate-sense/src/cascade/birth.rs`, vector `crates/open/furcate-sense/tests/fixtures/birth-record.golden.json`. This file is byte-identical to the core copy.

Status: built in both, no route, no table, no deploy. Nothing here actuates anything.

## What simulated time is worth

Simulated time counts for physical purposes only inside the band the twin has been validated against real measurements. Experience gathered outside that band is recorded, counted separately as unvalidated, and never unlocks actuation. A simulated year is not a physical year of evidence. The record therefore carries `simulated_seconds_validated` and `simulated_seconds_unvalidated` as separate numbers, and any surface that quotes the record must quote the validated figure as the physical one. A verifier recomputes the split from the ledger; a record that moves seconds from unvalidated to validated is refused.

## Canonical form and signature

- Records and ledger bodies are JSON canonicalised per RFC 8785. Integers must be below 2^53; a larger integer is refused. Fractions appear only in band limits, ranges and the release point.
- Record signature: Ed25519 (`ed25519:<64 hex>` key ids) over the SHA-256 of `len(domain) || domain || len(message) || message`, lengths as 8 bytes big-endian, domain `lw-physical/birth-record/v1`, message the canonical record without its `signature` member. This is the same construction as the physical batch.
- Record hash: SHA-256 of the canonical record including its signature, lower-case hex. This is what a reading or a receipt may carry to point at its birth record.
- Ledger entry hash: SHA-256 of `lp(domain) || lp(prev) || be64(seq) || be64(ts_ms) || lp(kind) || lp(sha256hex(canonical(body)))`, with `lp(x) = be64(len(x)) || x`, domain `lw-experience/entry/v1`. The head of an empty ledger is SHA-256 of `lp("lw-experience/genesis/v1") || lp(run_id)`.

## The record

```
format "birth-record", version 1
signer              "ed25519:<hex>", must be enrolled by the verifier
issued_ms, valid_from_ms, valid_until_ms   integers; the window is at most 366 days
artefact            { kind: model | policy | plan, hashes: [sha256 hex, sorted, unique, 1 to 16],
                      knowledge_set_hash: sha256 hex }
lineage             { world_id, world_version, twin_id, twin_version }   strings
run                 { run_id, seed, started_ms, finished_ms,
                      data_sources: [ { kind: "physical_batch", batch_id, batch_hash, min_attestation } ] sorted by batch_id }
results             { benchmarks: [ { name, score_ppm, threshold_ppm? } ] sorted by name,
                      fidelity_ppm, fidelity_minimum_ppm }
band_certificate    { calibration_id, band: { param: [lo, hi] }, release_point: { param: value } }
experience          { ledger_head, ledger_entries,
                      simulated_seconds_total, simulated_seconds_validated, simulated_seconds_unvalidated,
                      wall_clock_seconds, cpu_core_seconds, gpu_seconds,
                      episodes_total, episodes_validated, scenarios_total, scenarios_validated,
                      coverage: { param: [lo, hi] }, coverage_validated: { param: [lo, hi] },
                      validated_scope: "inside_band_only" }
signature           hex, 128 characters
```

`min_attestation` is one of soft, device, se, tee, dice, tpm, the lowest level any reading of that physical batch carried. Scores are integers in parts per million. `knowledge_set_hash` commits to what the artefact knows at birth: for an agent built on the harness, the hash over its memory folder and the document hashes it was grounded in.

## The experience ledger

Append-only and hash-chained, one per run. An entry is `{ seq, ts_ms, kind, body, prev, hash }`, `seq` from 0 without gaps, `ts_ms` never decreasing. Kinds:

| kind | body |
|---|---|
| `run_started` | run_id, seed, world_id, world_version, twin_id, twin_version, artefact_kind |
| `episode_batch` | episodes, scenarios, simulated_seconds, wall_clock_seconds, cpu_core_seconds, gpu_seconds, ranges `{param: [lo, hi]}`, in_band |
| `calibration_update` | calibration_id, band `{param: [lo, hi]}` |
| `physical_batch_ingested` | batch_id, batch_hash, min_attestation |
| `benchmark_result` | name, score_ppm, threshold_ppm? (the name `twin_fidelity` carries the fidelity score) |
| `run_finished` | artefact_hashes, knowledge_set_hash |

The first entry is `run_started`, the last is `run_finished`, and nothing follows it. An `episode_batch` is inside the band when a calibration has arrived and every parameter it varied lies inside that calibration's band; its `in_band` claim must equal that recomputation or the ledger is refused.

## Release gate

The gate refuses to produce a record unless the ledger verifies end to end, the twin's release point is inside its solved band (every band parameter present and within its limits), the fidelity score meets the configured minimum, every ingested physical batch meets the configured attestation floor, and the artefact hashes and knowledge hash are those the run finished with. The record is built from the ledger alone, then signed through a signer interface; no key material lives in the repository.

## Verification and error codes

Order of checks, first failure wins: structure, format, version, enrolled signer, signature, window, model hash, ledger head, internal consistency, fidelity.

| code | meaning |
|---|---|
| `malformed` | not the shape above, a number beyond 2^53, a bad hash or key id |
| `wrong_format` / `unsupported_version` | not `birth-record` / not version 1 |
| `unknown_signer` | signer not enrolled with the verifier |
| `bad_signature` | signature does not verify over the canonical record |
| `window_invalid` | until not after from, or window over 366 days |
| `not_yet_valid` / `expired` | the verifier's clock is before the window / at or after its end |
| `model_hash_mismatch` | the hash being installed is not in `artefact.hashes` |
| `ledger_head_missing` | no ledger head, or the head of an empty ledger |
| `knowledge_hash_missing` | no knowledge set hash |
| `experience_inconsistent` | seconds do not add up, validated above total, counts above totals |
| `band_missing` | no band, or an empty band |
| `release_point_outside_band` | the release point is not inside the band |
| `coverage_outside_band` | validated coverage extends outside the band |
| `fidelity_below_minimum` | fidelity below the record's own stated minimum |
| `birth_record_absent` | node side: a model or policy offered with no record |
| `ledger_malformed` | an entry is not the shape above |
| `ledger_reordered` | sequence not contiguous from 0, or time going backwards |
| `ledger_chain_broken` | an entry's `prev` or `hash` is wrong (a deletion, an edit, a swap) |
| `ledger_head_mismatch` | the ledger's head is not the record's head |
| `ledger_kind_unknown` / `ledger_not_started` / `ledger_not_finished` / `ledger_after_finish` | kind or run boundaries wrong |
| `out_of_band_claimed_validated` | an episode batch claims inside the band what the band does not cover |
| `ledger_summary_mismatch` | the record's experience summary is not what the ledger adds up to |
| `twin_outside_band` | gate: the release point is outside the solved band |
| `data_source_attestation_low` | gate: a physical batch is below the attestation floor |
| `artefact_not_in_ledger` | gate: artefact or knowledge hash differs from the ledger's `run_finished` |

The node holds the record and the head, not the ledger: it checks signature, enrolment, window, model hash, head present and the internal consistency rows. The ledger itself is checked by whoever holds it (the core's gate, an auditor) with `ledger_*` and `ledger_summary_mismatch`.

## Open decision

The production signing key for the service signer is not chosen. Tests sign with a test key whose seed is public (32 bytes of 0x42). A node's enrolled-signer list is what grants authority, so the production key must live in hardware-held custody and be enrolled per node; that choice is the owner's.

## Golden vector

`birth-record.golden.json` holds `{ record, ledger, expected }` from one fixed run, signed by the test key. Both repositories verify it, check the head and summary recomputed from the ledger, and pin the file's SHA-256 so one copy cannot change without the other.
