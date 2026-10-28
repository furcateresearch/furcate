# Cascade trust checks and what was measured

Six checks added to `furcate_sense::cascade`. Each entry says what it does, how
it was tested and the number the test produced. Statements are marked
**VERIFIED** (the test ran and produced it) or **UNVERIFIED** (not run, or run
only on a stand-in). Everything here runs on a host with no board attached; no
claim below was measured on an ESP32-S3, a Pi or a Nicla.

| module | check | where it is wired |
|---|---|---|
| `binding` | model, epoch, calibration and self test carried in every signed item | `Ingest` (policy `bindings`), `furcate-small serve --bindings` |
| `commit` | Merkle commitment to K embeddings and their raw windows, audited by challenge | library; end-to-end test over the recorded capture |
| `gate` | escalation gate that holds the agreement of kept items to a target | library, usable as the small node's `EscalationPolicy`; evaluation example |
| `drift` | per-node embedding drift and its cause across nodes | `SmallNode::with_drift` |
| `attest` | nonce challenge that has the running model compute | library with a software prover |
| `coherence` | accelerometer, gyroscope and rotation vector must agree | `furcate-small replay`; end-to-end test over the capture |

## Model bindings (`binding`)

Compact form 17 bytes: 8 model hash prefix, 4 epoch, 4 calibration prefix, 1
self test. **VERIFIED**: `BINDING_WIRE_LEN == 17`, round trip tested. In the JSON
frames this implementation exchanges the field is **80 bytes**, so the
"under 20 bytes" holds for the compact form only; no node sends the compact form
yet (**UNVERIFIED** on firmware).

Fault injection through the full ingest path (`tests/small_node_e2e.rs`,
`fault_injection_without_a_registry_is_accepted_and_with_one_is_detected_in_full`):
554 faults: every single-bit flip of a 68-byte weight array (544), every epoch
below the minimum (7), a failed self test, an unregistered calibration, and an
exact replay.

| | accepted | refused |
|---|---|---|
| no registry (before) | 553 | 1 (the replay, by the log) |
| registry | 0 | 554 |

Time to detect is the same call as the arrival of the item. A reading signed at
an older epoch and shown to a verifier that has lost its state is refused by the
registry floor (`binding_epoch_too_old`); the highest epoch seen from a node is
held in memory, so after a restart only the registry floor protects until a
newer item arrives. Limit: the binding is what the node states it ran. A node
that hashes its own weights shows a flipped weight as an unregistered model; a
node whose software is replaced can state a registered hash, which is what
`attest` is for. CPU on the S3: **UNVERIFIED**.

## Committed embedding batches (`commit`)

One signed commitment per batch of K windows: 114 bytes (batch 4, first window
4, count 2, model prefix 8, root 32, signature 64). With 32-dimension int8
embeddings and K = 10: 32 + 11.4 = 43.4 bytes per window against 1200 for six
int16 axes at 100 Hz, 27.6 times less (computed by `wire_cost`, **VERIFIED** as
arithmetic on the constants, not measured on a link). On the recorded capture
(14 lines, 155 bytes of text per window, 4-value embedding) it is 12.1 bytes
per window, 12.8 times less. A challenge of any window is recomputed from the
raw samples and checked against the signed root: **VERIFIED** for every window
of the capture; a hidden window (embedding replaced by zeros) is found by
challenging it and only it. A simulated audit of K = 20 with 1, 3 and 5 altered
windows and 1 to 4 challenges matches the closed form `detection_probability` to
within 0.03. Time to answer a challenge, signing energy and hardware versus
software signing on the S3: **UNVERIFIED**.

## Conformal escalation gate (`gate`)

Evaluation: `cargo run --release -p furcate-sense --example gate_eval -- "<UCI HAR Dataset>" 0.05`.
Data: UCI "Human Activity Recognition Using Smartphones" (CC BY 4.0, Anguita et
al. 2013), 10299 windows, 30 subjects, downloaded without credentials and not
stored in the repository. Leave one subject out: models fitted on 25 other
subjects, 4 more calibrate. The leaf is a softmax classifier on a 64-dimension
random projection of the 561 features (accuracy against the labels 0.875); the
teacher is a softmax classifier on all 561 (0.941); agreement is leaf label equal
to teacher label (0.901). Both are software stand-ins for the S3 student and the
Pi teacher.

Target agreement among windows not escalated 0.95 (delta 0.05). File order,
95% bootstrap intervals over subjects:

| method | escalation rate | agreement kept | subjects within delta | subjects significantly over |
|---|---|---|---|---|
| static max-softmax threshold (calibrated on the 4 subjects) | 0.144 [0.121, 0.166] | 0.950 [0.939, 0.961] | 0.53 | 6 / 30 |
| static entropy score | 0.165 | 0.948 | 0.47 | 8 / 30 |
| static temperature-scaled | 0.144 | 0.950 | 0.57 | 7 / 30 |
| oracle fixed threshold (hindsight, per subject) | 0.166 [0.117, 0.225] | 0.952 | 1.00 | 0 / 30 |
| gate, adaptive step 0.05, audit 0.05 | 0.191 [0.168, 0.214] | 0.951 | 0.60 | 7 / 30 |
| gate, adaptive step 0.05, audit 0.10 | 0.221 | 0.948 | 0.57 | 6 / 30 |
| gate, adaptive step 0.20, audit 0.10 | 0.260 | 0.948 | 0.53 | 4 / 30 |
| gate, buffer 3000 / 25, audit 0.10 | 0.220 | 0.949 | 0.53 | 5 / 30 |
| random escalation at the same rate (0.221) | 0.229 | 0.901 | 0.07 | 22 / 30 |

The shuffled order gives the same picture (within-delta fractions 0.47 to 0.70
for the calibrated methods).

Reading. Every calibrated method reaches the pooled target of 0.95; random
escalation at the same cost does not (0.90). The pass rule in the research note,
"violation rate within delta in at least 95 percent of held-out subjects",
**FAILS for every method**: the best is 0.63. With about 290 kept windows per
subject the sampling noise of the kept error alone puts a share of subjects over
delta, and 4 to 8 of 30 are significantly over (one-sided exact binomial, 5%).
The adaptive gates cost 5 to 12 points of extra escalation (the audit share)
and showed **no measured advantage over the static threshold on this
leave-one-subject-out test**: the change between subjects is modest and each
stream is short. The adaptive behaviour is shown on a synthetic drift, where
the lower model's error rate rises after 20000 items (delta 0.05, mean of 5
seeds): kept error before/after drift, frozen threshold 0.053 / 0.186,
adaptive step 0.051 / 0.045, buffer 0.049 / 0.056, at 0.85 and 0.81 escalation
afterwards against 0.25. Real drift in real wearers is **UNVERIFIED**.

Not run: PAMAP2, WISDM, Opportunity, the wrist-versus-waist placement shift,
energy per decision on the S3, a real Pi teacher.

## Embedding drift (`drift`)

Mean-shift score plus Page-Hinkley per node, cause read across nodes. All
synthetic: 6 nodes, 8-dimension embeddings, Gaussian noise (**VERIFIED** in the
unit tests; **UNVERIFIED** on real embeddings, which are autocorrelated and not
Gaussian). Over 20 fleets, 6 nodes and 3000 windows without change: 0 alarms.
Common shift on all nodes: read as site-wide in 20/20, worst alarm delay 37
windows. One node shifted: sensor drift for that node and stable for the rest
in 20/20, worst delay 26. A slow ramp on one node (0.04 spreads per window):
found in 20/20, worst delay 40 windows. Every node changing model and shifting:
model change in 20/20, never site-wide. A staged rollout to one node: model
change there, the rest stable. A model change with no shift: no alarm. Two nodes
drifting in opposite directions: two sensor drifts, not site-wide. Limits are in
the module header (small fleets, two alarmed nodes cannot be told from aligned
drift). An end-to-end test with three simulated nodes behind one small node
reads the three causes correctly.

## Inference attestation (`attest`)

Nonce, derived input, signed output digest, reference recompute; nonce spent on
first use; software stand-in prover (a two-layer int8 network, 64-32-16).
Single-bit flips of every weight bit (20480): detected by 1 challenge 0.241, by
4 0.749, by 16 0.988 (by bit position at 16: bit 0 0.926 rising to 1.0 for bit
4 upward). A load-time hash check detects none of these runtime changes by
construction. A node that states the registered hash while computing with
altered weights is caught by the output (16/16 challenges refused in the test).
Rounding: a second implementation that rounds differently (floor against half
away from zero) differs from the reference on 9998 of 10000 nonces by up to 4
steps, so exact comparison refuses an honest chip and a tolerance is required;
with the tolerance set to the observed maximum plus one, 0 of 10000 honest
answers are refused. Real ESP-DL rounding, flips in PSRAM or the tensor arena,
and challenge latency on the S3 are **UNVERIFIED**. The challenge shows the
stated model computes correctly on the node now, not that every production
window used it.

## Cross-sensor coherence (`coherence`)

Flags, not identity. **VERIFIED** on the recorded capture
(`tests/fixtures/nicla-standalone-usb.txt`): the accelerometer vector is 4.12 g
at the printed 8 g range with the gyroscope at rest, and the rotation vector
predicts the same direction of gravity to within the tolerance, so the monitor
raises one magnitude flag and no direction flag, with the hint that a scale of
0.243 would make it 1 g. Decoded at a 2 g range the capture raises nothing. This
is the open point `nicla-sense-me.md` already records, now caught by a check
that runs on every decoded stream; whether the range really in effect is 2 g
needs a capture with the later range lines and is **UNVERIFIED**. Synthetic
trajectories (random attitudes and rates, noise): 60 consistent trajectories of
1000 windows raise no flag; an accelerometer scaled by 4, x and y swapped
(counted where the swap moves the vector by more than twice the tolerance, 55
trials), a gyroscope scaled by 3, and a rotation vector off the unit sphere are
each flagged in every counted trial (80 each, 55 for the swap). Acoustic or
other injection attacks on a physical board: **UNVERIFIED**.
