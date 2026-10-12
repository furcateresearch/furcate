# Leaf-signed gateway request

How a leaf asks the model gateway on its cell's head. The leaf signs each HTTP request with the key its attachment names; the gateway checks the signature against the cell's chain. No token, password or shared secret is given to the leaf, and nothing the leaf stores would let another device ask in its name.

The gateway side is `furcate_topology::leaf_request` (the check) and `furcatectl model front` (the door the gateway unit runs). A reference client is [`docs/clients/furcate_leaf_request.py`](../clients/furcate_leaf_request.py).

## The request

An ordinary HTTP/1.1 request to the gateway (`http://<head address>:8750`), with one added header:

```
POST /v1/chat/completions HTTP/1.1
Host: <head address>:8750
Content-Type: application/json
Content-Length: 81
X-Furcate-Credential: leaf:<holder>:<nonce>.<expires_at>.<signature>

{"model":"qwen3-0.6b","messages":[{"role":"user","content":"ok"}],"max_tokens":8}
```

- Methods: `GET` and `POST`. Targets: `/v1/...` and `/health`. Anything else is refused before the signature is read.
- The body is sent with `Content-Length`. Chunked request bodies are refused (411). Bodies are limited to 1 MiB.
- `Authorization` is not a credential here. The gateway never forwards it.

## The credential

`leaf:<holder>:<nonce>.<expires_at>.<signature>`

- `holder`: the leaf's key exactly as its link names it: `p256:` and the hex of the 33-byte compressed SEC1 point (`02` or `03` by the parity of y, then x). Lower-case hex. An Ed25519 leaf uses `ed25519:<hex>`.
- `nonce`: 8 to 64 characters of `A-Z a-z 0-9 - _`, never reused by this leaf while a request with it could still be valid. A random 64-bit value in hex, or a per-boot random prefix and a counter, both work.
- `expires_at`: seconds since the epoch, after which the request is void. At most 300 seconds ahead of the gateway's clock; 60 is a good value.
- `signature`: lower-case hex of the 64-byte ECDSA P-256 signature `r || s` (each 32 bytes, big-endian) over the canonical request below, with SHA-256. DER is also accepted. Low-S is not required.

## The canonical request

The bytes signed are the UTF-8 string:

```
furcate-request/1\n
<METHOD>\n
<target>\n
<sha256(body) as 64 lower-case hex>\n
<nonce>\n
<expires_at as decimal>\n
```

six lines, each ended by `\n` (0x0A), no other whitespace. `<METHOD>` is upper case. `<target>` is the request target exactly as sent on the request line, query string included. An empty body hashes to `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

This is the canonical form every signed Furcate request uses (`furcate_authn::signing_input`); an operator request differs only in its prefix and key.

On the leaf: `hash = SHA-256(canonical)`, then sign `hash` with the identity key (`fl_identity_sign(hash, sig)` returns `r || s`).

### Test vector

Body `{"model":"qwen3-0.6b","messages":[{"role":"user","content":"ok"}],"max_tokens":8}`, method `POST`, target `/v1/chat/completions`, nonce `n-00000001`, `expires_at` 1791800060:

```
furcate-request/1
POST
/v1/chat/completions
7c8a1c1aca564a14f4af1c3b9b3761486bfae7f819c920489c632e929c36b0d5
n-00000001
1791800060
```

(each line ended by `\n`, including the last). The gateway's tests and the reference client's tests hold this vector.

## What the gateway checks

In this order, refusing at the first that fails:

1. `expires_at` is after the gateway's clock and no more than 300 seconds ahead of it.
2. `holder` is a well-formed key in the compressed spelling, and the signature verifies under it.
3. `holder` is a leaf of the cell this gateway heads, read from the cell's chain on disk at the time of the request: the head's anchor, the links it signed, and the operator's revocations. A revoked leaf, a leaf whose link has ended, and a leaf of another cell are not leaves of this cell. The refusal says which, with the operator's reason for a revocation.
4. The class the leaf's link records meets the cell's leaf floor (`leaf_min_class`) as it stands now. Raising the floor shuts out leaves below it at once.
5. The nonce has not been used by this leaf within its validity. It is recorded only once 1 to 4 hold, so a forged request cannot spend a real one's nonce.

Then the request goes to the model router on the head's loopback and the answer comes back as it is produced (a `"stream": true` completion streams).

## Answers

| status | meaning |
| --- | --- |
| 200 and the router's answer | admitted |
| 400, 404, 405, 411, 413, 431, 505 | the request itself is not one the gateway takes |
| 401 | no credential, a malformed one, a bad signature, an expired or far-future `expires_at`, a replay, a leaf not attached here, revoked, ended, or below the floor |
| 403 | this node heads no cell, so it admits no leaf |
| 502 | the model router did not answer |
| 503 | too many requests at once |

A refusal body is `{"error":{"message":"...","type":"authentication_error","code":401}}`. The message says what to fix; a bad signature always reads the same, whichever part did not match.

## What the leaf needs

- Time: a clock within a minute or so of the head's (SNTP from the head or the network) before the first request. With no time the leaf cannot make a valid request and should not try.
- Its attachment: the leaf is attached to the cell (`furcatectl cell leaf`, see [leaf attachment](leaf-attachment.md)) with a class at or above the cell's floor.
- The gateway's address: the head's address on the leaf network, port 8750.

## The operator

The operator asks the same door with the operator signature every Furcate service takes, `X-Furcate-Credential: op:<nonce>.<expires_at>.<signature>`, an Ed25519 signature by the operator key over the same canonical request (`furcate_authn::local::sign`). A teammate admitted in `people.json` signs with their own key the same way.

Applications on the head itself use the router on `127.0.0.1:8751` with its loopback credential (`furcatectl model credential gateway`). That credential is for the head's own processes; it is never given to a leaf or put on a network.
