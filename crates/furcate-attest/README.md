# furcate-attest

The remote attestation verifier, following the RATS architecture (RFC 9334). Nodes are Attesters producing Evidence, the TPM vendor is the Endorser, and the site controller appraises Evidence against reference values and an appraisal policy to produce an Attestation Result. Both the passport topology (the node carries a signed Result) and the background-check topology (raw Evidence is passed through to a verifier the consumer chooses) are supported.

## Role in Furcate

Used by `furcatectl` and `furcate-build`. Builds on `furcate-identity` for quotes and evidence and on `furcate-ledger` for chain heads.

## Public API

- `Verifier`, `AttestationResult`, `Verdict`, `Topology`.
- `AppraisalPolicy`, `ReferenceValues`, `Coverage`, `PolicyViolation`, `classify_coverage`.
- `freshness`: `NonceChallenge`, `FreshnessProof`, `EpochId`, `EpochClock`, `FreshnessError`.

## Build and test

From the repository root:

```
cargo build -p furcate-attest
cargo test -p furcate-attest
```

## Notes

- Pure library; it does not talk to a TPM itself. Quotes come from `furcate-identity`.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
