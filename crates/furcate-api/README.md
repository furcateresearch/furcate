# furcate-api

The local HTTP/JSON API every Furcate node serves. It is a small blocking server built on the standard library rather than an async runtime: a daemon that also controls power keeps as little machinery underneath it as possible, and the request rate is tens per second. Subsystems are reached only through handlers registered on a `Router`, so a caller cannot bypass policy by touching a subsystem directly.

## Role in Furcate

Used by `furcated` (which mounts every node route on it), `furcatectl` (as a client), and `furcate-siteview`. Request authentication is delegated to `furcate-authn`.

## Public API

- `Router`: `route`, `route_with`, `guarded`, `admitted`, `carrying_proof`, `carrying_order`, `originating`, `verified_by`, and `dispatch`/`dispatch_at`/`dispatch_from`.
- `Request`, `Response` (`ok`, `text`, `html`, `error`, `refused`), `Handler`, `Access`, `Admission`, `OriginCheck`, `MAX_BODY`, `MAX_HEADERS`.
- Server: `serve`, `serve_also`, `listen_also`, `parse_request`.
- Client helpers: `get_json`, `get_signed`, `post_json`, `post_bearer`, `post_signed`, `Credentialler`.
- `orders`: the signed-order desk (`Desk`, `Executor`, `Execution`, `OrdersConfig`, `mount`, `mount_at`).
- `custody`: the key-custody status route (`CustodyStatus`, `HolderStatus`, `CustodySource`, `mount`).

## Build and test

From the repository root:

```
cargo build -p furcate-api
cargo test -p furcate-api
```

## Notes

- No async runtime. The node listens on loopback (`127.0.0.1:7616` by default in `furcated`) and on the overlay address it is told to.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
