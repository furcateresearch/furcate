# furcate-leaf-link

The host end of a micro processing node's link, and the bridge from it into the small processing node.

A micro processing node (a leaf: an ESP32-class board) dials out, says HELLO, and is answered by a node that holds the
operator's grant for its key. This crate is that node's side. `furcate-small` reads frames from the micro node's link; before
this crate nothing produced them from a real leaf's session, because a HELLO is unsigned and carries no readings.

```
leaf  --FL1 lines-->  wire  -->  session  -->  report  -->  bridge  -->  relay (furcate-sense)  -->  JSON frames  -->  furcate-small
        (Wi-Fi TCP, serial)   keys, AEAD   leaf signatures   enrolment,     hardware-signed
                                                            class, module
```

## What it does

* **`wire`**: the frame format, `FL1:` + base64 + newline, and the message fields (type byte, then tag/length/value). Strict:
  a field that runs past the end of a message is an error, not a short read. Lines that are not frames are the leaf's log and
  pass through as text.
* **`session`**: the node's half of the handshake. The leaf sends HELLO (its key, an ephemeral key, a nonce, its evidence). The node
  answers AUTH: its key, an ephemeral key, the operator's grant for that key, and its signature over the transcript. The leaf
  answers FINISH with its own signature over the same transcript. From there every message is AES-256-GCM, one key per
  direction from HKDF over the ECDH secret with the transcript hash as salt, and a counter nonce. A record out of order ends the
  session. The node signs through `NodeSigner`; the command wires that to the machine's hardware root of trust, so the key is
  never in this process.
* **`report`**: the leaf's SENSE reply. Each reading is `sensor | f32 | seq | signature`, signed over
  `furcate_leaf_core::LeafState::bound_payload`. Every signature is checked against the leaf's key before its sequence number is
  recorded, so a forged reading cannot use one up. Sequences rise within an attachment generation, and an older generation never
  returns. The module behind the leaf is named by a unit record the leaf signs.
* **`bridge`**: the state machine that ties these to the enrolment. A leaf that is not in the operator's file is not answered. A
  leaf whose key or silicon values changed is refused by `UnitRoster`. A frame is signed with the host's key through
  `furcate_sense::relay::Relay`, and claims the lower of that key's class and what the leaf's enrolment earns.
  Module readings are accepted only if the unit record verifies, its fingerprint is the enrolled one, the chain lists it as a
  `sensing` signer, and the reading's sequence number is inside the range the leaf signed.
* **`serve`**: the three links (serial device, `listen://` where the leaf dials in, `tcp://` to a relay) and the loop that
  drives the bridge.
* **`config`**: the operator's file, `furcate-leaf-link directory` and `enrol`.

The command is in `src/main.rs`: `serve`, `enrol` (listens for one HELLO and prints the entry for the operator to review; it
sends nothing), `directory` and `unit-fingerprint`. How to put it on a Raspberry Pi is in `deploy/small-node/README.md`.

## What has been checked

* The handshake's transcript hash, both keys, the leaf-auth digest and sealed records are byte-identical to the values
  `host/fl_proto.py` in the leaf firmware repository produces on the same inputs (reference vectors in `src/session.rs`).
* The reading digest is the one `furcate-leaf-core` pins against the firmware's host test. The unit-record digest and the I2C
  unit fingerprint are pinned to values computed independently with Python's hashlib, and the fingerprint also to the firmware's
  host test.
* Against a simulated leaf (`sim`) that follows the firmware's message layouts and signs with a test key: the whole path from
  HELLO to a frame the small node's `Ingest` accepts, including over a TCP socket the leaf dials in on; an unenrolled leaf, a
  clone with the same silicon values and another key, a swapped chip, a changed value (and that it uses up no sequence number),
  a replayed sealed record, a restarted leaf (new generation) and a rolled-back one, a crossed HELLO, a grant for another key,
  frames altered after signing, the claimed class never above the leaf's or the host's, and module readings with a wrong
  fingerprint, a missing chain entry, a missing or out-of-range unit record.

## What has not

* A session with a real board. The node's AUTH is a protocol write to the board, so it waits for the owner's go-ahead.
* The host key on a board: the tests use in-memory keys behind the same traits. `HardwareNodeSigner` over the firmware-crypto
  broker has not been run on the Pi.
* A restart of the bridge starts each leaf's log over at entry 1, which the small node's witness reads as a repeat.
  `furcate_sense::cascade::witness::LeafLog` cannot resume from a saved head.
* A leaf that has gone quiet is dropped after the reply wait and answered again on its next HELLO; there is no back-off for a
  leaf that dials in a loop.
