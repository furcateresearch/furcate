# furcate-paths

Where Furcate's state, configuration and runtime files live. Every crate that needs a path asks this one rather than reaching for `$HOME`, so a system service and an operator's tool agree, and nothing compiles a user's home directory in as a default.

## Role in Furcate

Used by `furcated`, `furcatectl` and `furcate-siteview`.

## Public API

- `state_dir`, `config_dir`, `runtime_dir`: defaults `/var/lib/furcate`, `/etc/furcate`, `/run/furcate`.
- `state`, `config`, `runtime`: a path under the respective directory.
- `ensure_state`, `describe`.

## Build and test

From the repository root:

```
cargo build -p furcate-paths
cargo test -p furcate-paths
```

## Notes

- Each directory is overridden by `FURCATE_STATE_DIR`, `FURCATE_CONFIG_DIR` or `FURCATE_RUNTIME_DIR`, then by systemd's `STATE_DIRECTORY`, `CONFIGURATION_DIRECTORY` or `RUNTIME_DIRECTORY`.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
