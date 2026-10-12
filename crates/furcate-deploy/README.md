# furcate-deploy

Building a site from source and placing it on machines the operator owns. It detects the framework a project uses, plans its build, consumes a filesystem build-output layout (static assets, functions and a routing configuration), and records each deploy as a release that can be verified and rolled back. Domain ownership, certificates and the edge configuration that routes traffic to a release are handled here as well.

## Role in Furcate

Used by `furcated` (which builds and serves releases) and `furcatectl deploy`, `furcatectl domain` and `furcatectl edge`.

## Public API

- `detect`: `plan`, `Plan`, `Framework`, `Tier`, `Evidence`, `Manager`.
- `release`: `Release`, `Site`, `Route`, `Redirect`, `Header`, `Device`, `MemoryBound`, `prune`, `KEEP_RELEASES`, plus path helpers (`site_dir`, `release_dir`, `current_link`).
- `verify`: `check`, `Verdict`, `Fetched`, `body_digest`.
- `domain`: verification state machine (`Domain`, `Step`, `Record`, `records`, `verdict`, `advance`).
- `edge`: renders the edge proxy configuration (`Edge`, `Vhost`, `Upstream`, `Wildcard`, `render`).
- `placed`: which zones and domains a node serves (`Placed`, `placed`, `zone_for`, `domains`).
- `certs::not_after`; `request` and `ACTION` for submitting a deploy as a policy action.

## Build and test

From the repository root:

```
cargo build -p furcate-deploy
cargo test -p furcate-deploy
```

## Notes

- Test fixtures live in `src/testdata`. Building a site invokes that site's own toolchain, which must be installed on the node.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
