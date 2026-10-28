# Furcate documentation

| Document | What it covers |
|---|---|
| [local-ai.md](local-ai.md) | A private local-AI setup end to end: a Raspberry Pi 5 gateway serving models, and a leaf that asks it questions |
| [leaf-tier.md](leaf-tier.md) | The three node roles (sensing, micro processing, small processing), the medium and large rungs above them, and how each rung verifies the one below |
| [leaf-devices/xiao-esp32s3.md](leaf-devices/xiao-esp32s3.md) | The XIAO ESP32-S3 leaf: what it supports, what its identity proves, how to attach it |
| [../crates/furcate-sense/docs/nicla-sense-me.md](../crates/furcate-sense/docs/nicla-sense-me.md) | The sensing node adapter for the Arduino Nicla Sense ME |
| [../crates/furcate-sense/docs/small-processing-node.md](../crates/furcate-sense/docs/small-processing-node.md) | The small processing node, the first rung that verifies the one below it |
| [physical-batch.md](physical-batch.md) | Signed batches of verified readings for a consumer outside Furcate |
| [physical-command.md](physical-command.md) | Physical command and receipt: the shadow-mode wire format for the down path |
| [birth-record.md](birth-record.md) | The signed birth record an artefact carries when it leaves a digital world for a physical machine, and the experience ledger |
| [architecture/os-image.md](architecture/os-image.md) | How a Furcate OS image is built and updated: the read-only base, signed system extensions, A/B slots |

## Decisions

| | |
|---|---|
| [0001](decisions/0001-one-os.md) | One OS for every machine a site contains |
| [0002](decisions/0002-interface-and-authority.md) | The interface and who holds authority |
| [0003](decisions/0003-cluster-key-custody.md) | Where a cluster's keys are held |
| [0004](decisions/0004-base-ubuntu-2604.md) | The base: Ubuntu 26.04 LTS on every board |
| [0005](decisions/0005-edge-cells.md) | Edge cells: clusters of their own, owned by an operator, scoped by signed delegation |

## Interfaces

These are contracts between parts that are built separately.

| | |
|---|---|
| [leaf-attachment.md](interfaces/leaf-attachment.md) | The record a leaf presents to join a gateway's cell |
| [leaf-gateway-request.md](interfaces/leaf-gateway-request.md) | How a leaf signs its requests to its gateway (no shared tokens) |
| [pi-gateway-contracts.md](interfaces/pi-gateway-contracts.md) | The gateway's signing service, power status file and log shipping |

[clients/](clients/) holds a reference leaf client with its tests.
