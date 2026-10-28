# furcate-sense

Sensors, actuators and leaf devices. A microcontroller cannot run gossip, consensus or a TPM stack, so a leaf attaches to a parent node, attests with whatever root of trust its silicon offers, and publishes signed readings through it. The parent represents its leaves in the cluster, which keeps membership small while making every sensor addressable from every machine.

## Role in Furcate

Used by `furcated` (`/sensors`), `furcatectl sensors`, `furcate-topology` and `furcate-leaf`.

## Public API

- `leaf`: `Leaf`, `Attachment`, `Reading`, `LeafError`, `ParentPort`.
- `registry`: `SensorRegistry`, `Sensor`, `SensorKind`, `Actuator`, `Modality`, `Unit`.
- `nicla`, `identity`, `text`, `frame`, `bhy2`, `serial`: the adapter that attaches a sensing node with no key of its own (the Arduino Nicla Sense ME) behind a processing node. See [`docs/nicla-sense-me.md`](docs/nicla-sense-me.md) for the supported sensors, the attestation wording, the cascade role names and how to attach one.

- `cascade`: the processing rungs above a sensing node: `chain` (the class an item may be treated as is the lowest rung's, computed by the verifier), `witness` (per-leaf hash-chained log, cosigned by the rung above), `ingest`, `model`, `escalate`, `small` and a host-side `micro` stand-in; `gate`, `drift`, `attest` and `coherence` (see [`docs/cascade-trust-measurements.md`](docs/cascade-trust-measurements.md) for what each does and what was measured), `binding` (the model, epoch and calibration a reading states it ran, and the registry that checks it) and `commit` (a signed Merkle commitment to a batch of embeddings, audited by challenge). See [`docs/small-processing-node.md`](docs/small-processing-node.md).

## Build and test

From the repository root:

```
cargo build -p furcate-sense
cargo test -p furcate-sense
```

## Notes

- The device side of the protocol is `furcate-leaf-core`.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
