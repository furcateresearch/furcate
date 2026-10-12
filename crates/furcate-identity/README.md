# furcate-identity

Hardware-rooted node identity. A node's identity is derived from its root of trust, never distributed to it as a secret; the private half never leaves the hardware. `RootOfTrust` abstracts over TPM 2.0, TEEs and device keys, and `AssuranceClass` records how strong the binding actually is. Enrollment, quotes, sealing, the node ID and key custody all live here.

## Role in Furcate

The most widely used crate in the tree: `furcated`, `furcatectl`, `furcate-attest`, `furcate-build`, `furcate-ledger`, `furcate-machine`, `furcate-mesh`, `furcate-net`, `furcate-policy`, `furcate-sense`, `furcate-siteview`, `furcate-topology`, `furcate-vault` and `furcate-leaf` depend on it.

## Public API

- `rot`: `RootOfTrust`, `AssuranceClass`, `Quote`, `Evidence`, `PcrSet`.
- `NodeId`, `Enrollment`, `EnrolledIdentity` and the `pin` module (`open_node`, `resolve`, `key_state`, `NodePaths`).
- `backends::select`: tries a TPM, then a TEE, then a device key. Backends: `tpm2_tools`, `tss_native`, `firmware_tpm`, `optee`, `rpi_fw_crypto`, `secure_enclave`, `fingerprint`, `host`.
- `seal::Sealer`, `signer` (`MessageSigner`, `Ed25519Signer`, `RootOfTrustSigner`).
- `custody`: who holds sealed material (`Custody`, `CustodyMode`, `CustodyGrant`, `CustodyRecord`, `CustodySettings`, `elect`).
- `leaf`: how a leaf device's key is held (`LeafKeyCustody`, `Lockdown`, `admits_leaf`).
- `expected`, `recovery`: expected-binding checks and recovery from a faulted root of trust.

## Build and test

From the repository root:

```
cargo build -p furcate-identity
cargo test -p furcate-identity
```

## Notes

- Feature `tss` enables the native TSS 2.0 backend and needs `libtss2-dev` at build time. Without it, the TPM backend drives the `tpm2-tools` binaries.
- The Secure Enclave backend is compiled on macOS only. An emulated TPM is refused unless explicitly allowed (`ALLOW_EMULATED_TPM`).

## Licence

Apache-2.0. See `LICENSE` at the repository root.
