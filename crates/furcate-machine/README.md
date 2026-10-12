# furcate-machine

Machine-class guests and the boot-cycle proving ground. Measured boot cannot be tested by running it once: it needs a machine booted hundreds of times, broken deliberately, and the verifier watched as it catches each break. This crate does that on a hypervisor with a virtual TPM, and also models guests as sub-attesters underneath their host.

## Role in Furcate

Used by `furcatectl selftest`. Provides the `furcate-prove` binary used during attestation development.

## Public API

- `guest`: `Guest`, `GuestState`, `GuestError`, `Vmm`.
- `proving`: `boot`, `qemu_args`, `BootRequest`, `Firmware`, `Sandbox`, `Swtpm`.
- `reference`: `UkiSections`, `expected_pcr11`, `expected_pcr11_hex` (predicting the PCR 11 value of a unified kernel image).
- `vtpm`: `VtpmCustody`, `VtpmError`.
- Binary `furcate-prove [SANDBOX_DIR]` (default `/tmp/furcate-proving`): boots a guest with a virtual TPM and reports whether the chip was exercised.

## Build and test

From the repository root:

```
cargo build -p furcate-machine
cargo test -p furcate-machine
```

Run the binary with `cargo run -p furcate-machine --bin furcate-prove`.

## Notes

- `furcate-prove` needs `qemu-system-x86_64`, `swtpm` and UEFI firmware on the host. Unit tests do not.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
