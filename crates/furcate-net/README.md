# furcate-net

Authenticated transport between Furcate nodes. A node proves what it is by attestation, receives a short-lived credential, authenticates every call with it, and the credential expires rather than being revoked. The identity is already a public key sealed to hardware, so there is nothing to distribute: a node signs with a key it cannot export, and the roster of acceptable keys comes from enrollment. The crate also carries the overlay network: peer announcements, WireGuard peer planning, NAT traversal, overlay names and link diagnosis.

## Role in Furcate

Used by `furcated` (overlay, roster and leases) and `furcatectl` (`network`, `roster`, `tunnels`). Provides the `furcate-overlay` binary.

## Public API

- `roster`: `Roster`, `RosterError`.
- `lease`: short-lived credentials (`Binding`, `Terms`, `bind`, `check`, `valid_until`).
- `announce`: signed peer announcements with replay defence (`Announcement`, `seal`, `open`, `Replay`).
- `overlay`: peer resolution and exposure (`resolve`, `merge`, `Peer`, `Hint`, `Resolution`).
- `wg`: WireGuard planning (`plan`, `render_setconf`, `parse_showconf`, `WgPeer`, `Interface`).
- `punch`: address reflection and hole punching (`reflect_once`, `observe`, `decide`, `choose_relay`).
- `names`: overlay DNS (`Zone`, `Record`, `answer`, `query`, `TLD`).
- `lock`: authorization anchors (`Anchors`, `authorize`, `verify`). `link`, `quality`, `reach`: link counters, diagnosis and reachability probes.
- Binary `furcate-overlay` with subcommands `names`, `reflect`, `observe` and `verify`.

## Build and test

From the repository root:

```
cargo build -p furcate-net
cargo test -p furcate-net
```

Run the binary with `cargo run -p furcate-net --bin furcate-overlay`.

## Notes

- No subcommand of `furcate-overlay` configures an interface, route or resolver. Interface changes are applied by `deploy/furcate-wg.sh` running as a separate privileged unit.
- Linux for the WireGuard path.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
