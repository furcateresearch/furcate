# furcate-vault

Sealed custody of keys, proofs and data. Everything is encrypted at rest under a key sealed to the local root of trust, so a disk removed from a machine is inert and a machine that booted the wrong way cannot unseal its own data. Sharing does not hand over the vault key: the holder re-wraps one object's key to the requesting node's attested public key, so access is granted per object, to one node, in one attested state.

## Role in Furcate

Used by `furcated` and `furcatectl` (`seal`, `unseal`, `operator seal`).

## Public API

- `seal`: `Vault`, `Sealed`, `VaultError`.
- `envelope`: `Envelope`, `EnvelopeError`, `seal`, `open`, `DATA_KEY_LEN`, `NONCE_LEN`.
- `share`: `PeerKey`, `WrappedKey`, `wrap_for`, `unwrap_with`.

## Build and test

From the repository root:

```
cargo build -p furcate-vault
cargo test -p furcate-vault
```

## Notes

- Sealing to hardware goes through `furcate-identity`; envelope encryption is tested without a TPM.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
