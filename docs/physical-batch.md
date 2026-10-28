# Sending verified readings to Living Worlds: the physical batch

This page is the producer side. A large processing node holds readings that reached it through the cascade
described in [`leaf-tier.md`](leaf-tier.md). When a consumer outside Furcate (Living Worlds is the first) wants to use
them, the large node assembles a **physical batch**: the verified readings, the chain of rungs each one passed, the
witnessed log that shows nothing was dropped, one signature by the site key. The consumer checks the arithmetic itself
with no Furcate code. Its side of the contract, with the full wire format, canonical JSON rules and refusal codes, is
the consumer's `docs/physical.md`; this page does not repeat it.

## Scope

Furcate is the physical layer of a two-way loop that also covers machines and robots: real-world data calibrates and
trains a simulation, plans and policies trained in simulation are validated and then control the real machine, and the
residual is measured again. The stages are (1) sense, (2) ingest and calibrate the twin, (3) simulate and train or plan,
(4) validate inside the twin's solved band, (5) shadow command, (6) approved actuation with signed policy and the kill
switch, (7) measure the outcome and return to (2). Furcate owns stage 1 and the site side of stages 5 to 7. Built today:
the cascade logic, the signed batch described here, and (in other crates) policy, kill switch and ledger. Planned: the
uplink that sends batches, receiving and verifying commands, and any actuator beyond a null one. Nothing in this
repository drives a real machine from a remote proposal yet.

## The cascade and the loop

The cascade has no fixed number of rungs; a deployment uses the ones it has, and a larger machine or a robot is another
sensing node (joint states, currents) plus an actuator set on the same rungs.

```
   physical world
        |  measures                                          ^  actuates (stage 6, planned)
        v                                                    |
  [ sensing node ]  transduces, holds no secret, level soft  |
        |  signed for by the rung above                      |
        v                                                    |
  [ micro processing node ]  signs each reading, keeps the   |
        |  per-leaf hash-chained log, level from key custody |
        v                                                    |
  [ small processing node ]  verifies envelope, chain,       |
        |  log; runs a model; escalates; cosigns checkpoints |
        v                                                    |
  [ medium processing node ]  (optional) hardware-attested   |
        |  inference                                         |
        v                                                    |
  [ large processing node = the site ]  re-verifies, adds    |
        |  its rung, signs the batch with the site key       |
        |                                                    |
        |  physical-batch (push, outbound only)              |  physical-command, shadow first,
        v                                                    |  polled by the site (planned)
  [ Living Worlds core ]  verifies signature, log, level;    |
        |  stores; feeds the twin loop and calibration       |
        v                                                    |
  [ Lisgen ]  simulate, train, plan; validate in the band ---+
        |
        +--> residual from the measured response goes back up the same path (stage 7)
             and a signed model or calibration update goes down the cascade, refused unsigned.
```

The site is the only party that talks to Living Worlds, and only outward: it pushes batches and polls for commands, so
no inbound connection to a site is needed. Living Worlds proposes; the site's signed policy decides; a kill order at the
site dominates anything proposed.

## What the large node does

1. **Verify.** Each reading is checked again with `verify_forwarded` against the large node's own directory of enrolled
   rungs: envelope signature, the reading's own signature, the chain, the countersignatures, the last rung's output
   signature. The exporter takes only readings that pass; it has no entry point for one that did not.
2. **Add its rung.** The large node appends itself to the chain as `large_processing` with the class its own key
   custody earns. A site key held in a file is `soft`, which then bounds the level of everything it signs.
3. **Take the log.** For each sensing node, the witnessed log from its first entry to a checkpoint the micro node signed
   and the small node cosigned. The exporter refuses a log that is not an unbroken chain from the leaf's genesis, whose
   checkpoint does not cover exactly its entries, or whose signatures do not verify; and a reading with no entry for it.
4. **Sign.** The batch minus its `signature` is written in canonical JSON (RFC 8785) and signed under the domain
   `lw-physical/batch/v1` with the node's signer. The signer is the same `CascadeSigner` every rung uses, so a hardware
   key signs without the exporter ever holding key bytes.

The level of a reading is the lowest class of any rung, computed here by the same rule the verifier uses
(`cascade/chain.rs`) and again by the consumer. A batch is `soft` when its sensing node is, whatever the rungs above are.

## Where it is in the code

| What | Where |
|---|---|
| Exporter, canonical JSON, batch signing | `crates/open/furcate-sense/src/cascade/physical.rs` |
| Test that runs the recorded sensing-node capture through the cascade and writes the batch | `crates/open/furcate-sense/tests/physical_batch.rs` |
| Golden vector (batch plus expected hash, level and key) | `crates/open/furcate-sense/tests/fixtures/physical-batch.golden.json` |

The golden vector is generated from the byte-exact recorded capture, with a sensing-node identifier synthesised from a
made-up serial, and a test key whose seed is public (32 bytes of `0x5a`). It carries no real device identifier and the key
protects nothing. The consumer keeps a copy and verifies it with its own code. The producer test regenerates the vector
and fails if it differs from the committed file, so the two sides cannot drift: change the producer, regenerate with
`UPDATE_GOLDEN=1 cargo test -p furcate-sense --test physical_batch`, and copy the file to the consumer's fixtures.

The recorded capture prints no full-scale ranges, so the test states them (2 g, 2000 dps) as the capture's own tests do.
The captured sketch emits no timestamps, so `sensor_ts_ms` is null and `at_ms` is the site's clock; the test declares an
`ntp` clock with 50 ms uncertainty for the synthetic site.

## Attestation classes in the batch

Read from `furcate-identity` (`AssuranceClass`, lowest first): `soft`, `device`, `se`, `tee`, `dice`, `tpm`. The wire
tag is `AssuranceClass::as_str`, not the serde name (`se`, not `secureelement`). A sensing node is capped at `soft`
(`SENSING_CEILING` in `cascade/chain.rs`). A micro node with fuse-backed keys earns `device`; a node with a TPM, a secure
element, a TEE or DICE earns the class of that root of trust.

## Not done yet

- Deep per-rung checking by the consumer: it relies on the large node having verified the countersignatures and checks the
  log and the batch signature itself. A signed key directory for every rung is the next step.
- The uplink: queueing batches while the consumer is unreachable, back-off, `batch_seq` bookkeeping.
- Receiving commands, evaluating them against `furcate-policy`, honouring kill orders, and sending receipts.
- Windowing for high-rate streams (a decimated stream plus a Merkle root over the full-rate window held at the site).
