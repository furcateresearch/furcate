# furcate-session

A record of what somebody did while they held authority, kept so it can be checked afterwards. `furcate-policy` decides who may act and `furcate-breakglass` covers acting when that machinery is unreachable; this crate records the commands run under such a grant, with secrets redacted, in a form that can be verified later. It records commands and their outcomes, not keystrokes.

## Role in Furcate

Used by `furcatectl session open|record|close|verify`.

## Public API

- `Session`, `Action`, `Recording`.
- `redact`, `REDACTED`.
- `save`, `save_recording`, `resume`.
- `Broken`, `Untrusted`: what verification reports when a recording does not check out.

## Build and test

From the repository root:

```
cargo build -p furcate-session
cargo test -p furcate-session
```

## Notes

- Pure library. Recordings can be anchored to the ledger chain.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
