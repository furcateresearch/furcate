# The leaf tier and the processing cascade

A leaf is a microcontroller-class device that attaches to a parent node. It does not join the
cluster, vote, or run gossip. This page names the positions in the cascade between a sensor and the
cluster, says how the names relate to the vocabulary already in the code, and says how identity and
signed readings work at every position. Boards are described only in `docs/leaf-devices/`.

## The positions

The cascade has no fixed number of rungs. Each position attaches to whichever node is above it.

| Position | What it does | Examples of what fills it |
|---|---|---|
| Sensing node | Measures. Has little or no processing of its own to sign with; identified by values burned into its silicon | a sensor module with a low-power microcontroller |
| Micro processing node | Processes and signs for the sensing node behind it, and for its own sensors. A leaf | an ESP32-class board |
| Small processing node | Single-board computer running Furcate | a Raspberry Pi |
| Medium processing node | Edge AI board, hardware-attested where it has a TPM | a Jetson |
| Large processing node | Server, spark or cloud | the cluster |

## How these map onto the existing words

* **Leaf**: the tier. Sensing nodes and micro processing nodes are both leaves; the difference is
  whether the device processes and signs for others. A leaf never votes.
* **Node**: small, medium and large processing nodes are nodes. They are parents of whatever is
  below them.
* **Parent**: the node a leaf attaches to, whichever rung that is.
* **Gateway** is the mesh role `Edge` (public ingress, `furcate-mesh` `Role`), not a position in
  this cascade. A processing node may also have that role. The positions here describe where in the
  chain a device sits; `Role` describes what a machine is for. They are independent.
* **Hub** is not a term in the code and is not added.

## Identity at every rung

One mechanism, the one `furcate-identity` already has, applies at every position:

* A node or leaf describes how its key is held (`LeafKeyCustody`); the parent grades it, and the
  device never states a class. A key derived from values anyone can read is `Soft`. A key in a
  read-protected eFuse block, used through a peripheral and never read back, is `Device`.
* The silicon values a device presents (factory IDs, part numbers, MAC) are enrolled once by the
  operator as a `Fingerprint` and compared on every session (`Continuity`).
* `UnitRoster` (`furcate-identity`) is the roster of units behind a leaf. `verify` returns one of:
  not enrolled (left to the operator), verified with the class the evidence earns, a replaceable
  part changed (continues), replaced (a value that never changes did: escalate), key mismatch
  (same silicon values, different key), or duplicate session (one identity already live).
* A unit identified only by silicon values is identified, not authenticated. It stays `Soft` however
  well it matches. No attestation level is added for it; the existing two cover it.

## Readings carry the chain

A reading is signed by its origin over `LeafState::bound_payload`: the device id, attachment
generation, sensor index, value, sequence number and the hash of the signed model active when it was
taken (all zero if none). The model hash is bound into every reading, so a reading says which model,
if any, stood between the sensor and the number. A node that forwards a reading appends its own entry
(id and role) and signs over what is below it; nothing assumes how many entries there are.

## The small processing node

The small processing node is the first rung that checks everything the one below it says. It
verifies each signed item against its own enrolment records, validates the chain (the class an item
may be treated as is the lowest rung, and no rung can raise it), keeps and cosigns a hash-chained log
of what each micro processing node emitted so drops, repeats, reordering and delay are detected, runs
a model on received embeddings with the model id and hash recorded in the chain, and escalates what
its policy will not stand behind with its own rung appended. Anything unverified is refused and
recorded. It is a `furcated-lite` worker; the library is `furcate_sense::cascade` and the program is
`furcate-small`. See `crates/open/furcate-sense/docs/small-processing-node.md`; the sensing node
below it is described in `crates/open/furcate-sense/docs/nicla-sense-me.md`.

Built and tested: the checks above, the reference model (a nearest-centroid model, no accuracy
claimed), the escalation policy and the next-rung check, end to end on a recorded capture. Seams, not
built: the link from the micro processing node's firmware to this node, transport of escalations to
a medium or large node, a calibrated escalation gate, and shipping the program in the base release.
The small processing node has not been run on a board.

### The first wire-free chain

Nicla Sense ME (sensing node) over Bluetooth LE to a XIAO ESP32-S3 (micro processing node), over Wi-Fi
to the head of the Raspberry Pi (small processing node), then to the next rung and the batch exporter.

* Built and tested on the real devices: Nicla to S3 over BLE, decoding, the S3 signing the module's
  values with the module as a `sensing` signer, and a parent session reading them. Over the S3's USB
  link, an independent verifier checked all nine signed readings and the unit-binding record against the
  leaf key. Frame decoding is host-tested with constructed frames and a simulated BLE peer.
* Built, not yet run end to end: the head's `sense` control op (the gateway program in the leaf firmware
  repository), the Wi-Fi leg to the Pi.
* Limits: the BLE link is unencrypted and unbonded and the module is `soft`; values carry the leaf's
  arrival time, not the sensor's own timestamp; the gyroscope scale is the library default and not
  checked with a known rotation; the module sent no humidity frames. The ESP32-S3 joins 2.4 GHz only.

## Where a device is described

`docs/leaf-devices/` has one page per supported board: what it supports, what its identity does and
does not prove, and how to attach it.
