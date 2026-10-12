# furcate-sql

A small synchronous PostgreSQL client implementing the simple query protocol and SCRAM-SHA-256 authentication. Every published PostgreSQL client for Rust is built on an async runtime; a synchronous program that only needs to write a few rows uses this instead of adding one.

## Role in Furcate

Used by the site controller in other editions. Nothing in the open tree depends on it.

## Public API

- `Config::from_url`, `Client::connect`, `Client::connect_url`.
- `Client::query` returning `Rows`, `Client::execute`.
- `literal`: quotes a string as an SQL literal.

## Build and test

From the repository root:

```
cargo build -p furcate-sql
cargo test -p furcate-sql
```

## Notes

- Simple query protocol only: no prepared statements. Plain TCP only: a URL asking for `sslmode=require` is refused rather than downgraded, so connect over loopback or the overlay. Values are passed as quoted literals.

## Licence

Apache-2.0. See `LICENSE` at the repository root.
