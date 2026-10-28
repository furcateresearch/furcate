# Sensing node: Arduino Nicla Sense ME

This page covers one device adapter. The generic rules it relies on are in the
leaf tier description in the README and in `furcate-sense`.

## Role names and the existing vocabulary

The cascade is described by role. The older vocabulary stays; this is how the
two line up.

| Role | Existing term | What it does | Example hardware |
|---|---|---|---|
| sensing node | a leaf with no key it can prove | transduces; never signs | this board |
| micro processing node | a leaf that signs, acting as the **gateway** (parent) of the sensing nodes behind it | processes, signs for them | ESP32-class |
| small processing node | `furcated-lite` worker | verifies, aggregates, runs small models | Raspberry Pi |
| medium processing node | a node with a hardware root of trust and an accelerator | edge inference, hardware-attested | Jetson class |
| large processing node | `furcated` voting member | compute | servers, cloud |

"Leaf" remains the name of the API (`Leaf`, `ParentPort`, `Attachment`): a
sensing node is attached through it with a delegated signer. "Hub" in this page
always means the sensor hub chip on the board (the BHI260AP), never a cascade
role. The cascade is open-ended: nothing in the reading format fixes the number
of rungs.

## What is supported

| Channel | Kind | Unit | Origin |
|---|---|---|---|
| `acc.x/y/z` | acceleration | m/s2, gravity included | transducer |
| `gyr.x/y/z` | angular rate | rad/s | transducer |
| `mag.x/y/z` | magnetic field | microtesla | transducer |
| `tmp` | temperature | degrees C | transducer |
| `hum` | humidity | percent | transducer |
| `prs` | pressure | pascals | transducer |
| `gas` | gas resistance | ohms (see below) | transducer |
| `rot.x/y/z/w` | orientation | unit quaternion | on-sensor fusion |
| `iaq`, `co2eq`, `bvoceq` | air-quality index and equivalents | index, ppm | on-sensor estimate |
| `steps` | step count | count | on-sensor algorithm |
| `act` | activity class | code | on-sensor classifier |

Transducer channels are `Direct`. Everything computed on the sensor is
`Inferred`, which in the registry means "derived, not transduced": it may
inform and corroborate but cannot justify a physical action alone. The
provenance chain records which algorithm made it. The "CO2 equivalent" is an
estimate from gas resistance, not a CO2 measurement, and has its own kind
(`GasEquivalent`) so it cannot be confused with `AirQuality`. Air-quality values
are withheld while the sensor reports accuracy 0 (stabilising).

Vectors are one registry sensor per axis, because a reading carries one number.

## Transports

| Path | Needs | Status |
|---|---|---|
| Text lines from the stock `Standalone` example, 115200 baud | nothing new | **Verified on a real board.** Works today. |
| Framed lines (`$FNS1,...*HH`, specified in `frame.rs`) | firmware that emits them | Decoder tested against constructed frames only. No firmware ships here. |
| Binary protocol (`bhy2.rs`) over serial, ESLOV or BLE | the stock host-controlled `App` sketch, a host board | Written from the documented protocol, **not checked against hardware**. |
| BLE | an implementation of `SensorLink` | Seam only. |

The stock `App` sketch answers only over ESLOV (I2C) or BLE; its USB serial is
silent unless its debug flag is on, so a bare board running it gives a serial
reader nothing. A 6 second read of a board in that state returned 0 bytes.

The text path is a debugging print, not a protocol. The parser accepts only the
exact line shapes, requires the three decimals the library always prints (so a
truncated number is rejected rather than read short), rejects interleaved lines,
and skips the `temperature: 0.000` placeholder that precedes the first sample.
Counts for acceleration and rotation rate are scaled by the range line printed
at start; until one is seen they are refused and counted by reason, and the commands
exit with an error naming the skipped sensor classes. The real Standalone
sketch prints no range line, so state it: `--accel-g N --gyro-dps N` on
`furcate-leaf nicla` and `furcate-small replay`, or `TextSession::with_configured`.
The range is never inferred from the data.

Open points on the verified path:

* The fixture's acceleration vector has a magnitude of about 4.1 g at the
  printed +/-8 g range and about 1.03 g at +/-2 g. A board at rest should read
  1 g, so the range that is really in effect is probably not the one printed
  first. The example sets the range after printing it; the parser takes the
  latest range line. Confirm against a capture that includes the later lines.
* The `gas` value is whatever the library prints; its unit and scale have not
  been checked against the sensor, and it is labelled ohms on the vendor's word.
* The fixture (`tests/fixtures/nicla-standalone-usb.txt`) is transcribed from
  the lines reported from the owner's capture of the board running `Standalone`.
  It is not a byte-for-byte file.

## Attestation

Recorded with every attachment and every reading, word for word:

> Fingerprint-identified, not hardware-keyed: the Arduino Nicla Sense ME holds
> no secret and has no secure element, so it cannot authenticate itself. Its
> identity is derived from identifiers the board reports (chip and USB serial
> numbers), which any code on it or anyone holding it can repeat; a fingerprint
> shows continuity with the unit that was enrolled, not that this unit is the
> one answering. Readings are signed by the processing node that reads the
> board, on its behalf.

Class: `soft`. No class was added; `soft` already means an identity not bound
to a secret the hardware keeps, and the finer fact travels as data
(`IdentityBasis::Fingerprint { anchors }`). A parent that requires `device`
refuses the board, as the default leaf floor does.

The board goes through the ordinary identity machinery (`furcate-identity`
fingerprint backend): the USB serial is a `board_serial` characteristic, the
nRF52832 device id and address are `soc_serial` and `mac` when the firmware
reports them (the stock examples do not), and the node id derives from the
fingerprint digest. The operator enrols it once (`identity::enrol`), the
enrolment record commits to the evidence, and the node id is the leaf id, so it
is inside every signed reading. Per-unit analogue offsets and noise are not
used: they drift with temperature and age and there is no extraction method to
rely on.

What it proves: that the signing processing node read these values from a
board presenting the enrolled characteristics, and that nothing altered them
after that node signed. What it does not prove: that the board is the enrolled
one (a unit repeating the readable identifiers passes the continuity check; a
test records exactly this), that its firmware is unmodified, that the USB path
was not interposed, or that the values are right. A swapped unit is caught
(`Standing::HardwareChanged`) and escalated to an operator.

## The next hop

A reading is a `BridgedReading`: the signed `Reading`, a `Provenance`, the
signing node's signature over both, and a list of countersignatures. The
provenance carries the sensing node's class and attestation record, the
transport, the modality, and `chain`, the rungs passed so far, each with role,
node id, class, and what it did to the value (`Measured`, `OnSensor`, `Model`
with id and SHA-256, or `Relayed`). A later rung calls `countersign` to append
itself; the receiving tier calls `verify_bridged` and
`verify_countersignatures`, supplying its own record of each node's public key.
The small processing node is described in [`small-processing-node.md`](small-processing-node.md): it verifies this format, validates the chain, keeps a witnessed log and escalates. What a medium or large processing node does with an `Inferred` or below-floor reading remains that node's own policy.

## Attaching one

```console
$ furcate-leaf nicla <capture-or-tty> <usb-serial>
```

reads a recorded capture or a serial device read-only, enrols the unit,
attaches it behind the simulated processing node, verifies each reading and
reports. In code: `identity::enrol(fingerprint_of(serial, chip_ids)?, name, nonce)`,
then `NiclaAdapter::new(...)` with a `Leaf` whose id is the enrolled node id and
whose key the processing node derives from its own identity (the adapter makes
no keys), then `attach`, `register_sensors`, `ingest`.

## Provenance of this code

An independent implementation from the documented protocol (frame layouts,
sensor ids, fixed-point scalings). The vendor's Arduino libraries and firmware
are AGPL-3.0 and nothing from them is copied here. The Bosch sensor API is
BSD-3-Clause and is not used. BSEC2 is closed and is neither required nor
redistributed: the air-quality channels carry what the board reports, and the
raw gas resistance is available without it. No firmware is shipped in this
repository, because a sketch linking the vendor libraries is AGPL-3.0; the
framed format is specified so the owner can choose how to produce it.

## Known problems in the vendor libraries

Relevant when using the binary path with the stock sketch: timestamps are
discarded, BLE batch mode overwrites payload byte 9 (corrupting the quaternion
accuracy), a partial BLE batch is never flushed, and the host library's long
frame loop is bounded by the wrong count. Long-frame width differs between
library versions (20 bytes in older ones, 23 in the current), which the decoder
handles as `ReadKind::Long` and `ReadKind::LongLegacy`.
