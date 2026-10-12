# furcate-authn

Authentication: who is asking. A request arrives carrying evidence, and what comes out is either a `Principal` that was proved or a `Refusal` saying why; there is no way to construct a principal by naming one. Authorization (what that principal may do) is the job of `furcate-policy`; this crate answers the question that comes before it.

## Role in Furcate

Used by `furcate-api` (every guarded route), `furcated`, `furcatectl`, `furcate-policy`, `furcate-killswitch`, `furcate-siteview` and `furcate-topology`.

## Public API

- Core: `Principal`, `Class`, `Evidence`, `Presented`, `Refusal`, the `Verifier` trait, `AnyOf`, `signing_input`.
- `local`: `LocalVerifier`, `Person`, `People`, `Signer`, `MachineSigner`, `sign` (signed requests from local operators and machines).
- `token`: `TokenVerifier`, `Claims`, `Delegation` (bounded-depth delegated tokens).
- `trust`: `TrustStore`, `Issuer`, `Level`, `Kind`.
- `order`: the canonical signed order format (`Order`, `Action`, `Target`, `Bounds`).
- `vouch`: quorum endorsement (`Vouch`, `Endorser`, `QUORUM`, `admits`).
- `webauthn`: passkey enrolment and assertion verification (`Challenge`, `Credential`, `Assertion`, `verify_assertion`, `verify_enrolment`, `Roster`, `Thresholds`, `Tally`).
- Re-exports `SigningKey` and `VerifyingKey` from `ed25519-dalek`.

## Build and test

From the repository root:

```
cargo build -p furcate-authn
cargo test -p furcate-authn
```

## Notes

- Feature `test-authenticator` enables a software authenticator that holds a private key. It exists for other crates' tests only and must never be enabled in a shipped build.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
