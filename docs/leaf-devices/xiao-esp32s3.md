# Seeed Studio XIAO ESP32S3

Position: micro processing node (see `docs/leaf-tier.md`). Licence class: open (`LICENSING.md`).

## Supports

* ESP32-S3, 8 MB flash, 8 MB octal PSRAM, Wi-Fi, Bluetooth LE 5 (central role only, for a sensing module), USB-Serial/JTAG.
* Identity from the chip's own eFuse values: the 128-bit unique ID and the factory MAC. Never a random
  software key.
* The chip's own temperature sensor, read on request and signed (`temperature`). GPIO, ADC and I2C
  inputs become sensors once an operator declares what is wired to them.
* A signed-model slot: the hash of the active model is bound into every reading.
* A sensing node behind it over BLE: the Arduino Nicla Sense ME running the unmodified host-controlled
  example firmware. The leaf is its central, signs its latest values when the parent asks for readings
  (sensor indices 16 to 25: acceleration, angular rate, temperature, pressure, humidity, gas resistance; the module's magnetometer, orientation and on-sensor estimates are decoded by `furcate-sense` but are not configured in the leaf's BLE path), adds the
  module as a `sensing` signer in the chain and a signed record binding the module's address fingerprint
  to the sequence numbers it issued. The module holds no key: identified, graded `soft`. The link is
  neither encrypted nor bonded. The I2C driver (`components/fl_nicla_i2c`) is built and tested against a simulated module only; it has not run against a real module. The UART driver is not built.
* **No camera and no microphone.** The Sense variant's camera and microphone are not enabled by the
  leaf firmware and no driver for them is built; a build check enforces it.

## What its identity proves

On an unfused board the key is derived from values anyone with the part can read, so it grades
`Soft`: it proves the same silicon answered before, not that the answerer holds a secret. Burning an
eFuse HMAC key (an owner decision, per device) moves it to a key the chip uses and never reveals
(`Device`). Secure boot and flash encryption are what stop other firmware on the part from asking the
peripheral for the same output. None of these is burned by default.

## How to attach

Plug it into the parent over USB. The leaf starts the session and waits for a node that holds an
operator grant. Wi-Fi is configured afterwards by a signed message. The full steps, flash and
rollback, and the eFuse list are in the `furcate-leaf-firmware` tree, `docs/XIAO-ESP32S3.md`.
