# furcate-console

One terminal screen for the machine and the site it belongs to: power draw, temperatures, disks, workloads, identity and who may change what, all at once. Everything shown is read from the node and the site over HTTP, parsed for a small set of known fields, range-checked and displayed with its provenance. A service that is not answering shows a line saying so rather than stopping the screen. It draws with plain ANSI escapes and has no TUI library dependency.

## Role in Furcate

Ships as the `furcate-console` binary in the CLI package. Editions extend it through `extension::register` and call the same entry point from their own binary.

## Public API

- Binary `furcate-console`. Flags: `--once` (print one screen and exit), `--session` (run inside a terminal multiplexer session it owns), `--panes` (list pane names), `--pane NAME` (open on one pane).
- Reads `FURCATE_NODE_ADDR` (falling back to `FURCATE_LISTEN`, default `127.0.0.1:7616`) and `FURCATE_SITE_ADDR` for the endpoints it queries.
- Library: `main`, `extension::{Console, register}`, and `style` (the shared colour and layout helpers).

## Build and test

From the repository root:

```
cargo build -p furcate-console
cargo test -p furcate-console
```

Run the binary with `cargo run -p furcate-console --bin furcate-console`.

## Notes

- Needs a terminal that understands ANSI escapes. The pane list is read from `deploy/os/arms.toml` at build time.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
