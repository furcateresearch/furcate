# Small processing node

The first rung that checks everything the one below it says. It is a
Raspberry Pi 5 running Furcate. This page covers the rung; the sensing node
below the cascade is described in [`nicla-sense-me.md`](nicla-sense-me.md), and
how to put the program on a board is in
`deploy/small-node/README.md`.

## Role names and the existing vocabulary

| Role | Existing term | Example hardware |
|---|---|---|
| sensing node | a leaf with no key it can prove | Arduino Nicla Sense ME |
| micro processing node | a leaf that signs, the **gateway** of the sensing nodes behind it | XIAO ESP32-S3 |
| **small processing node** | a `furcated-lite` worker; the **parent** of the micro processing nodes attached to it | Raspberry Pi 5 |
| medium processing node | a node with a hardware root of trust and an accelerator | Jetson class |
| large processing node | a `furcated` voting member | servers, cloud |

"Hub" is not used for a rung. A micro processing node attaches to a small one
through the same `Attachment` and `ParentPort` that any leaf uses.

## What it does

1. **Verifies** every frame from a micro processing node and refuses and records what fails.
2. **Witnesses** a hash-chained log of everything each micro node emitted, and cosigns its checkpoints.
3. **Runs a model** on embedding windows, and records the model id and hash in the chain.
4. **Escalates** what its policy will not stand behind to the next rung, with the chain extended by this rung.

The library is `furcate_sense::cascade`; the program is `furcate-small`
(binary of the `furcate-leaf` crate); the unit is
`deploy/small-node/furcate-small-node.service`.

## Frames

One JSON object per line, tagged by `frame`:

| `frame` | carries |
|---|---|
| `reading` | a `BridgedReading` and its log entry |
| `embedding` | a `BridgedEmbedding` (an int8 vector, the id and hash of the model that produced it, the provenance) and its log entry |
| `checkpoint` | the micro node's signed log size and head |

Every item is signed by the micro processing node, which holds a key. The
sensing node behind it holds none and is graded `soft`.

## Verification, in order

1. The envelope signature, against the key of the processing node enrolled for that sensing node.
2. The chain. The verifier computes the class an item may be treated as: the lowest class of any rung. A rung may claim a class at or below what its enrolment earns and never above it; the sensing node is capped at `soft`; an aggregate class stated in the provenance may not exceed the computed one; the rungs run in order from the sensing node outward, each once; only the sensing node may say it measured; a value a model produced may not be stated as direct. There is no function that returns a level while a lower rung exists.
3. The signatures of rungs added after the signing node.
4. The log entry commits to this item and continues the witnessed chain.
5. Replay: the reading's own signature and sequence, or the window sequence.
6. The model binding, when `--bindings FILE` is given: see [Model bindings](#model-bindings).
7. Policy: the lowest class accepted (`--min-level`) and a bound on extra delay (`--max-delay-ms`).

Steps 1 to 5 change nothing until all pass, so a forged frame cannot use up a
sequence number. A frame that passes them is entered in the log even if step 6
or 7 refuses it, because the log records what the micro node emitted and a policy
refusal must not leave a gap that blocks every frame behind it.

Refusal codes (`refusals.jsonl`): `unknown_source`, `bad_envelope_signature`,
`bad_reading_signature`, `replayed_reading`, `replayed_window`, `chain`,
`bad_countersignature`, `log_digest_mismatch`, `log_gap`, `log_duplicate`,
`log`, `below_floor`, `late`, and the binding codes below. A line that is not a frame is written to
`results.jsonl` as `malformed`. Nothing is accepted by default and nothing is
dropped without a record.

## The witnessed log

The micro node appends an entry per item: `hash = H(prev, seq, node time,
item digest)`. Every so often it signs a checkpoint of the log's size and head.
The small node builds the same chain from what reached it and cosigns a
checkpoint only if it has seen every entry up to it and its head at that size
is the same. A consumer that requires a recent cosigned checkpoint
(`verify_cosigned`) learns that nothing before that point was dropped and that
the log was alive no longer ago than the cosignature.

| Fault | Seen as |
|---|---|
| an entry dropped | `log_gap` on the next one; the checkpoint over the hole is not cosigned (`MissingEntries`) |
| an entry repeated or replayed | `log_duplicate` |
| a different entry for a position already witnessed | equivocation (`log`) |
| entries reordered | `log_gap` for the early one, then accepted once the missing ones arrive in order |
| an entry altered, or from another chain | `log` (hash or link) |
| delivered late | `late`, measured against the fastest delivery seen from that node |

The witness never advances over a gap; the micro node heals it by sending the
missing entries in order. The witnessed log survives a restart: accepted
entries are journalled in `witness.jsonl` and replayed, chain-checked, at start.

Limits: the micro node is the trusted signer, so an item it never produced and
never logged cannot be detected; delay is bounded against the fastest delivery
seen, which is not synchronised time.

## The model hook and the reference model

`WindowModel` takes an int8 embedding and returns an `Inference` (label,
margin, and the `ModelRef` id and SHA-256 of its parameters). The hop this node
adds to the chain carries that `ModelRef` as `Derivation::Model`, and the node
signs its answer together with the item and the chain, so the next rung can
check which model produced it and that the answer is the one that was signed.

`NearestCentroid` is the reference model: one mean vector per label, the nearest
wins, hash computed from the parameters held. Its margin is a distance ratio and
is not a calibrated probability. It exists to exercise the path. No accuracy is
claimed for it on any data.

## Escalation

`EscalationPolicy` decides per processed item. The default, `MarginPolicy`:

- escalate when the margin is below a threshold (`--margin`, default 0.2);
- escalate every Nth item whatever the margin (`--audit-every`, default 50), so
  the next rung keeps seeing a sample of what this node was sure about;
- escalate when there is no model or it cannot answer.

The threshold is a constant the operator sets and the audit is a fixed interval,
not a draw. A gate that learns its threshold from the next rung's answers, with
a stated bound on disagreement, is a later step; the trait is where it plugs in.

An escalated item is a `Forwarded`: the item as it arrived, this rung's hop
appended to its chain (role, node id, its own class from its root of trust, and
the model), the answer, and this rung's signature over all of it. The next rung
calls `verify_forwarded` with its own directory. A forward that fails is
reported (`forward_failed`), never swallowed. Readings are kept unless
`--forward-readings` is set.

## Model bindings

Every reading and embedding can state, inside the provenance the micro node
signs, which model, epoch and calibration produced it and whether the node's own
check of both passed: 17 bytes in the compact form
(`furcate_sense::cascade::binding::BINDING_WIRE_LEN`: 8 model hash prefix, 4
epoch, 4 calibration hash prefix, 1 self-test). With `--bindings FILE` the rung
refuses an item whose binding is missing, names an unregistered or revoked
model, is below the minimum epoch, is lower than an epoch already seen from that
node, names a calibration not registered for that node, reports a failed self
test, or (for an embedding) disagrees with the model named in the window. Codes:
`binding_missing`, `binding_malformed`, `binding_unknown_model`,
`binding_revoked_model`, `binding_epoch_too_old`, `binding_epoch_regressed`,
`binding_unknown_calibration`, `binding_self_test_failed`,
`binding_model_disagrees`. A refused item stays in the witnessed log, which is
the quarantine: nothing acts on it, and the log has no gap.

```
{"min_epoch": 2,
 "models": [{"id": "window-features", "sha256": "<64 hex>", "min_epoch": 0, "revoked": false}],
 "calibrations": [{"sensing_node": "<node id>", "prefix": "<8 hex>"}]}
```

Without `--bindings` nothing is checked and `furcate-small` says so at start.
The highest epoch seen is held in memory, so after a restart only
`min_epoch` protects against a replayed older reading until a newer one arrives.
The binding is what the node states it ran: a node that hashes its own weights
shows a changed weight as an unregistered model, and a node whose software is
replaced can state a registered hash while running something else. That needs a
challenge that exercises the running model, which this page does not provide.

## Committed embedding batches

`furcate_sense::cascade::commit`. Per window the wire carries the embedding; per
batch of K windows it carries one signed commitment (114 bytes: batch 4, first
window 4, count 2, model prefix 8, Merkle root 32, signature 64). The leaves
commit to each window's sequence, embedding and the digest of its raw samples.
The rung may then ask for any window: the node reveals the raw samples and the
path, and the rung rebuilds the leaf from the embedding it received, checks the
path to the signed root at the position the window must occupy, and recomputes
the embedding from the raw samples. Failures are named: `batch_bad_signature`,
`batch_incomplete`, `batch_wrong_batch`, `batch_not_in_batch`,
`batch_wrong_position`, `batch_not_committed`, `batch_proof_invalid`,
`batch_embedding_mismatch`. The node keeps raw windows in a byte-bounded ring; an
older window cannot be challenged and is reported expired, not passed. This does
not show the raw samples are what the sensor produced.

## Further checks

Escalation gate, embedding drift, inference attestation and cross-sensor
coherence are library modules of `furcate_sense::cascade`; their behaviour and
measured results, with what remains unverified, are in
[`cascade-trust-measurements.md`](cascade-trust-measurements.md). Drift is
enabled with `SmallNode::with_drift`; `furcate-small replay` prints coherence
flags for a capture.

## Identity and signing

`furcate-small serve` signs with the machine's hardware root of trust, through
`furcate-identity` (`--backend rpi-fw-crypto` on a Pi: the firmware-held key,
through the signing broker). It refuses to start without one. There is no key
file and no fallback signer. `furcate-small replay` uses fixed in-memory keys,
says so, and attests nothing.

## What this does not establish

It does not make a sensing node authentic: the class of anything that passes
through stays `soft` because the first rung is `soft`. It does not detect a
micro node that lies, since that node is the signer. It says nothing about
whether a sensor's values are right. A swapped sensing unit is caught only
when its identifiers differ; one that repeats them passes, as on the page for
the sensing node.

## Commands

```
furcate-small serve  --directory FILE --state-dir DIR [--backend NAME] [--config-dir DIR]
                     [--listen stdin|unix:PATH] [--forward -|FILE|unix:PATH] [--model FILE]
                     [--margin F] [--audit-every N] [--min-level CLASS]
                     [--max-delay-ms N] [--forward-readings] [--bindings FILE]
furcate-small replay CAPTURE [USB-SERIAL]
furcate-small identity [--backend NAME] [--config-dir DIR]
```

`--model` reads `{"id": "...", "centroids": [["label", [f32, ...]], ...]}`.
