# furcate-siteview

One read-only view of a site, assembled from its nodes. Every node answers `/healthz` and `/workloads` about itself only; this crate lists the site's nodes, polls each on a timer, keeps the last reading with its age, and serves the result as JSON and as a read-only page. It holds no authority: nothing here signs, admits, places or orders anything, so any node can serve it.

## Role in Furcate

Used by `furcated` (which mounts its routes) and `furcatectl fleet`.

## Public API

- `SiteView`, `Reading`, `Readings`, `spawn_poller`, `routes`, `poll`, `absorb`, `freshness`, `STALE_SECS`, `POLL_SECS`.
- `site_name`, `hosted_sites`, `overlay_lock_state`.
- `cells`: the cell tree view (`tree_json`, `answer`, `routes`, `page`).
- `web`: the HTML overview and dashboard (`homepage`, `dashboard`, `Overview`, `NodeRow`).

## Build and test

From the repository root:

```
cargo build -p furcate-siteview
cargo test -p furcate-siteview
```

## Notes

- Serves through `furcate-api`; no separate listener.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
