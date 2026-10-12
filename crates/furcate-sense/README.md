# furcate-sense

Sensors, actuators and leaf devices. A microcontroller cannot run gossip, consensus or a TPM stack, so a leaf attaches to a parent node, attests with whatever root of trust its silicon offers, and publishes signed readings through it. The parent represents its leaves in the cluster, which keeps membership small while making every sensor addressable from every machine.

## Role in Furcate

Used by `furcated` (`/sensors`), `furcatectl sensors`, `furcate-topology` and `furcate-leaf`.

## Public API

- `leaf`: `Leaf`, `Attachment`, `Reading`, `LeafError`, `ParentPort`.
- `registry`: `SensorRegistry`, `Sensor`, `SensorKind`, `Actuator`, `Modality`, `Unit`.

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
