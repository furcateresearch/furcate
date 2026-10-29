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

`chip.tmp` is a separate channel: the die temperature of the micro processing
node that hosts the module (`Origin::HostChip`). It is not the module's `tmp`
and is not registered under the module's identity.

## Channel catalogue

One table per quantity. "Verified" means read from a real board and checked;
"built" means decoded and tested against constructed bytes only. Datasheet
figures are the part maker's typical values, not transcribed or measured here,
and are marked as such; figures from the recorded Standalone capture
(`tests/fixtures/nicla-standalone-real-capture.bin`, 60 lines of each class at
about 1 per second) are marked as measured.

Applies to every channel: the module's own timestamps are discarded by the vendor
library, so a reading is stamped when the processing node reads the frame
(`taken_at`, whole seconds) and the transport latency is its timing
uncertainty (not characterised). Every reading carries the `binding` the
signing node states (model, epoch, `calibration`, `self_test`). `calibration`
is the first 4 bytes of the SHA-256 of a calibration artefact and is all zero
when there is none; no calibration artefact exists for any module channel
today, so every module reading carries zeros. The attestation floor of every
module channel is `soft` (fingerprint-identified, see Attestation). Every
channel except the derived ones (`Inferred`) is `Direct` and may justify an
action together with other evidence; none of them does so alone while the
module is `soft` in a chain that requires more.

### Acceleration: `acc.x`, `acc.y`, `acc.z`

| | |
|---|---|
| Kind, unit | `acceleration`, m/s2, gravity included |
| Wire | signed 16-bit counts, full scale 2, 4, 8 or 16 g set on the hub; value = counts / 32768 * range * 9.80665 |
| Resolution | one count = 0.061 mg at 2 g, 0.244 mg (2.39 mm/s2) at 8 g |
| Noise | measured: rms scatter of the three axes 3.5 to 5.0 mg and of the magnitude 4.0 mg over the capture, taken at +/-2 g; an upper bound, the board was not clamped. Datasheet noise density: not transcribed |
| Bias, cross-axis, drift | not characterised. Zero-g offset needs a six-position test per unit |
| Range in effect | must be stated (`--accel-g`); never inferred. Over BLE the stock firmware runs 8 g (gravity reads 1.00 g, verified). The Standalone capture prints +/-8 g but gravity reads 1.0015 g only at +/-2 g, see the open points |
| Rate | requested 10 Hz |
| Calibration binding | zeros (none) |
| Twin variable | `specific_force`: validates and recalibrates a body or structure model of load and motion; the magnitude near 1 g is the check that the stated range is right |
| Status | text path verified on a board; BLE path verified (leaf firmware); binary path built |

### Angular rate: `gyr.x`, `gyr.y`, `gyr.z`

| | |
|---|---|
| Kind, unit | `angular_rate`, rad/s |
| Wire | signed 16-bit counts, full scale 125 to 2000 dps; value = counts / 32768 * range * pi / 180 |
| Resolution | one count = 0.061 dps (1.07 mrad/s) at 2000 dps |
| Bias, noise | measured by the leaf tool on a still board: bias 0.010, -0.010, 0.002 dps; noise 0.04 to 0.08 dps. The Standalone capture scatters 0.44 to 1.9 dps rms, which does not agree with that figure; the board may have been moving, and the two setups ran different ranges |
| Scale | the 2000 dps default is the library's; the scale itself is not checked (the check needs a rotation of about 90 degrees, `tools/nicla_gyro_check.py`) |
| Cross-axis, drift | not characterised |
| Rate | requested 10 Hz |
| Calibration binding | zeros |
| Twin variable | `angular_velocity`: validates and recalibrates a rotating-body model; integrated, it is checked against the fused orientation (`cascade::coherence`) |
| Status | text and BLE paths verified for the signal, scale unchecked; binary path built |

### Magnetic field: `mag.x`, `mag.y`, `mag.z`

| | |
|---|---|
| Kind, unit | `magnetic_field`, microtesla |
| Wire | signed 16-bit counts at a full scale that is a setting and has no default (`--mag-ut`, `Ranges::set_mag`, `CONFIG_FL_NICLA_I2C_MAG_UT`, NVS `fl-nicla/mag_ut`); a frame arriving with none set is refused and counted, and the sensor is not asked for |
| Resolution | one count = 0.040 uT at 1300 uT full scale; the sensor's own step is coarser (datasheet, about 0.3 uT, not transcribed) |
| Range | the sensor measures +/-1300 uT in x and y and +/-2500 uT in z (datasheet) |
| Bias, hard and soft iron, noise | not characterised; the raw field includes the board's own and nearby iron and current |
| Rate | requested 10 Hz |
| Calibration binding | zeros |
| Twin variable | `magnetic_flux_density`: a change from the site's baseline marks nearby motors, steel or current (the derived `field_strength`); heading needs tilt compensation and a calibrated hub |
| Status | built; never read from a real board |

### Orientation: `rot.x`, `rot.y`, `rot.z`, `rot.w`

| | |
|---|---|
| Kind, unit | `orientation`, unitless: a unit quaternion from the hub's sensor fusion, `Inferred` |
| Wire | four signed 16-bit components at 1/16384 and an accuracy field |
| Resolution | 6.1e-5 per component |
| Measured | the capture holds the board still: components stable to 0.001 over 60 s, norm 1.00015 |
| Accuracy | the field reads a constant 3.142 (pi rad) in the capture, i.e. no estimate; it is not exported. Over BLE batching the vendor library overwrites that byte |
| Drift | yaw drift of a gyro-and-accelerometer fusion without a calibrated magnetometer: not characterised |
| Rate | requested 10 Hz |
| Calibration binding | zeros; the derivation is recorded as `on_sensor: bhi260ap-sensor-fusion` |
| Twin variable | `attitude`: validates a pose forecast; being inferred it never recalibrates a twin and never stands alone behind an action |
| Status | text path verified; BLE path decoded on constructed frames; binary path built |

### Temperature: `tmp`

| | |
|---|---|
| Kind, unit | `temperature`, celsius |
| Wire | signed 16-bit at 0.01 degC |
| Range | the sensor covers -40 to 85 degC (datasheet) |
| Measured | 29.53 to 29.73 degC over the capture (rms 0.06). It rises 0.2 degC in a minute, which points to self-heating from the board and the gas heater (not isolated here), so it reads above the air. An offset against a reference thermometer is not calibrated; until then it is a board-side temperature, not air temperature |
| Accuracy | datasheet about +/-0.5 degC at 25 degC before self-heating; not verified |
| Rate | requested 1 Hz; the module sends on change |
| Calibration binding | zeros |
| Twin variable | `temperature`: validates a thermal model of the board's surroundings only after an offset calibration; recalibrates a housing or surface temperature of the machine it is mounted on |
| Status | text path verified; BLE path verified |

### Pressure: `prs`

| | |
|---|---|
| Kind, unit | `pressure`, pascal |
| Wire | unsigned 24-bit in 1/128 hPa (one count = 0.78 Pa); 1013.25 hPa is 129696. Verified on the module over BLE. The binary decoder read it as 1/128 Pa until this change, which put a 101325 Pa reading at 1013 Pa, inside the interface's range check |
| Range | the sensor covers 300 to 1250 hPa (datasheet) |
| Accuracy | datasheet about +/-0.5 hPa absolute and +/-0.03 hPa relative; not verified here |
| Rate | requested 1 Hz; sent on change |
| Calibration binding | zeros |
| Twin variable | `pressure`: validates and recalibrates an ambient or process-line pressure model; the derived `pressure_height_change` follows relative pressure at about 8 m per hPa near sea level |
| Status | BLE path verified; binary path built |

### Humidity: `hum`

| | |
|---|---|
| Kind, unit | `humidity`, percent relative |
| Wire | one byte, 1 %RH steps, under the wake-up id 134 only (id 130 stays silent on the stock firmware); both are accepted |
| Accuracy | datasheet about +/-3 %RH; not verified. First frames read 30 to 33 %RH indoors (verified) |
| Rate | requested 1 Hz; sent on change |
| Calibration binding | zeros |
| Twin variable | `relative_humidity`; with `tmp` it gives the derived `dew_point` |
| Status | BLE path verified |

### Gas resistance: `gas`

| | |
|---|---|
| Kind, unit | `gas_resistance`, ohm, unsigned 32-bit, `Direct` |
| Measured | 10053 to 10434 ohm over the capture (rms 75 ohm, 0.7 %) |
| Meaning | the resistance of the heated sensing layer. It depends on the heater profile, temperature and humidity and drifts over weeks; it is a trend, not a concentration. The unit is the vendor's word and has not been checked against a reference |
| Rate | requested 1 Hz |
| Calibration binding | zeros |
| Twin variable | `gas_sensor_resistance`: validates a change in the air of a space against a baseline; recalibrates nothing by itself |
| Status | text path verified; BLE path verified |

### Air quality: `iaq`, `co2eq`, `bvoceq`

| | |
|---|---|
| Kind, unit | `air_quality_index` (unitless, static index 0 to 500), `gas_equivalent` (ppm) twice: CO2 equivalent and breath-VOC equivalent. `Inferred`: the vendor's closed algorithm computes them from gas resistance, so they are estimates, not a measurement of CO2 |
| Wire | the long frame (20 bytes): index u16, static index u16, VOC u16 at 0.01 ppm, CO2 u24 ppm, accuracy u8 |
| Accuracy field | 0 stabilising (withheld and counted), 1 to 3 rising confidence |
| Rate | requested 0.33 Hz (one estimate per 3 s) |
| Calibration binding | zeros; the derivation is recorded as `on_sensor: bsec-air-quality` |
| Twin variable | `air_quality_index` and `gas_concentration_estimate`: validate an occupancy or ventilation model; never recalibrate, never stand alone behind an action |
| Status | built; the module has not been run with the air-quality firmware here |

### Steps and activity: `steps`, `act`

| | |
|---|---|
| Kind, unit | `step_count` (count), `activity_state` (code); both `Inferred` |
| Wire | steps: unsigned 32-bit; activity: a 16-bit word, bit n (0 to 6) an activity ended, bit n + 8 started; the published code is the bit index (still 0, walking 1, running 2, on bicycle 3, in vehicle 4, tilting 5, in vehicle still 6) |
| Behaviour | the step count restarts when the hub restarts. A word with several changes publishes one value on the leaf (the last) and counts the collapse; the host decoder publishes every change |
| Rate | requested 1 Hz; sent on change |
| Calibration binding | zeros |
| Twin variable | `step_count`, `activity_state`: validate a people-flow or machine-state model; never recalibrate |
| Status | built |

### Chip temperature: `chip.tmp`

| | |
|---|---|
| Kind, unit | `temperature`, celsius; the processing node's own die, `Direct` |
| Range | -10 to 80 degC as configured in the driver |
| Meaning | die temperature, which sits above ambient under load; not air temperature |
| Twin variable | `temperature` of the controller; a thermal-load check on the node itself |
| Status | verified over the USB link on the real pair |

Drift tests: `tests/measurement_kinds.rs` holds the kind, unit and modality of
every channel against `tests/fixtures/measurement-kinds.json`, which the
consumer keeps byte for byte; `tests/nicla_vectors.rs` decodes the 27 frame
vectors the firmware's host test decodes with its own C decoder
(`nicla-frame-vectors.txt`); `tests/physical_batch.rs` signs every channel into
a batch (`physical-batch-all-channels.golden.json`) that the consumer verifies.
The frame vectors are constructed from the documented layouts, not recorded.

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
