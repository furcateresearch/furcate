# Contributing

Thank you for helping build Furcate.

## Sign-off, not a CLA

Furcate uses the Developer Certificate of Origin (https://developercertificate.org). Each commit carries a sign-off line stating that you have the right to submit it under the project's licence:

```
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds it. There is no contributor licence agreement: contributions are made under Apache-2.0, the same licence you received the code under.

## Making a change

1. Open an issue first for anything larger than a small fix, so the approach can be agreed before the work is done.
2. Keep a pull request to one change. Describe what it does and why, and how you checked it.
3. `cargo test --workspace` and `cargo clippy --workspace` pass. Changes to the OS recipe pass the boot tests in `os/tests/`.
4. A change that alters a decision or an interface comes with a decision record or an interface update; see [GOVERNANCE.md](GOVERNANCE.md).

## Style

Code comments explain why the code is the way it is. Errors say what was refused and what to do next. A value that was not measured is reported as not measured, never as zero.

## Conduct

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
