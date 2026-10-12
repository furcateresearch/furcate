#!/usr/bin/env python3
"""Reference client for leaf-signed gateway requests.

The wire format is docs/interfaces/leaf-gateway-request.md. This module builds
the canonical request and the X-Furcate-Credential header, and sends a
request. It never holds a private key: signing is done by whatever holds the
leaf's key, passed in as a function from message bytes to signature. The
command line uses a P-256 key held in a TPM (tpm2-tools), which is how a
Linux machine acting as a leaf keeps its key; an ESP32 leaf implements the
same steps in firmware with its identity key.

    python3 furcate_leaf_request.py key --tpm-handle 0x81000010
    python3 furcate_leaf_request.py ask --tpm-handle 0x81000010 \\
        --url http://<head>:8750/v1/chat/completions \\
        --data '{"model":"qwen3-0.6b","messages":[{"role":"user","content":"ok"}],"max_tokens":16}'

Standard library only.
"""

import argparse
import hashlib
import http.client
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.parse

SCHEME = "leaf:"
HEADER = "X-Furcate-Credential"
MAX_VALIDITY_SECS = 300
NONCE_MIN, NONCE_MAX = 8, 64
_NONCE_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

# The order of the P-256 group, for writing a signature in its low-S form.
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
# The DER SubjectPublicKeyInfo prefix of an uncompressed P-256 point.
_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


def canonical(method, target, body, nonce, expires_at):
    """The bytes a leaf signs (furcate_authn::signing_input)."""
    digest = hashlib.sha256(body).hexdigest()
    return f"furcate-request/1\n{method.upper()}\n{target}\n{digest}\n{nonce}\n{expires_at}\n".encode()


def holder_from_point(point):
    """`p256:<compressed point hex>` from a 33- or 65-byte SEC1 point or a
    91-byte SubjectPublicKeyInfo, the spelling cell links use."""
    if len(point) == 91 and point[:26] == _SPKI_PREFIX:
        point = point[26:]
    if len(point) == 33 and point[0] in (2, 3):
        return "p256:" + point.hex()
    if len(point) != 65 or point[0] != 4:
        raise ValueError(f"not a P-256 point ({len(point)} bytes)")
    x, y = point[1:33], point[33:]
    return "p256:" + (bytes([2 + (y[-1] & 1)]) + x).hex()


def raw_signature(sig):
    """64-byte `r || s`, low-S, from `r || s` or DER."""
    if len(sig) == 64:
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    else:
        r, s = _der_ints(sig)
    if not (0 < r < _N and 0 < s < _N):
        raise ValueError("signature out of range")
    if s > _N // 2:
        s = _N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _der_ints(der):
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2:
        raise ValueError("not a DER ECDSA signature")
    out, i = [], 2
    for _ in range(2):
        if der[i] != 0x02:
            raise ValueError("not a DER ECDSA signature")
        n = der[i + 1]
        out.append(int.from_bytes(der[i + 2:i + 2 + n], "big"))
        i += 2 + n
    if i != len(der):
        raise ValueError("trailing bytes after the DER signature")
    return out[0], out[1]


def new_nonce():
    return secrets.token_hex(8)


def credential(holder, method, target, body, sign, nonce=None, expires_at=None, now=None):
    """The X-Furcate-Credential value for one request.

    `sign(message) -> signature` signs `message` with ECDSA P-256 and SHA-256
    and returns `r || s` or DER."""
    nonce = nonce or new_nonce()
    if not (NONCE_MIN <= len(nonce) <= NONCE_MAX and set(nonce) <= _NONCE_CHARS):
        raise ValueError(f"a nonce is {NONCE_MIN} to {NONCE_MAX} characters of A-Z a-z 0-9 - _")
    if expires_at is None:
        expires_at = int(now if now is not None else time.time()) + 60
    sig = raw_signature(sign(canonical(method, target, body, nonce, expires_at)))
    return f"{SCHEME}{holder}:{nonce}.{expires_at}.{sig.hex()}"


class Tpm2Key:
    """A P-256 signing key held in a TPM at a persistent handle, used through
    tpm2-tools. The private half never leaves the TPM."""

    def __init__(self, handle):
        self.handle = handle

    def _run(self, *args):
        r = subprocess.run(args, capture_output=True)
        if r.returncode != 0:
            raise RuntimeError(f"{args[0]} failed: {r.stderr.decode(errors='replace').strip()}")

    def holder(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "pub.der")
            self._run("tpm2_readpublic", "-c", self.handle, "-f", "der", "-o", out)
            with open(out, "rb") as f:
                return holder_from_point(f.read())

    def sign(self, message):
        with tempfile.TemporaryDirectory() as d:
            msg, sig = os.path.join(d, "msg"), os.path.join(d, "sig")
            with open(msg, "wb") as f:
                f.write(message)
            self._run("tpm2_sign", "-c", self.handle, "-g", "sha256", "-s", "ecdsa", "-f", "plain", "-o", sig, msg)
            with open(sig, "rb") as f:
                return f.read()


def ask(url, body, holder, sign, method="POST", out=sys.stdout.buffer):
    """Send one signed request and copy the answer to `out` as it arrives.
    Returns the HTTP status."""
    u = urllib.parse.urlsplit(url)
    if u.scheme != "http":
        raise ValueError("the gateway is http://<head>:8750 on the cell's network")
    target = u.path + (f"?{u.query}" if u.query else "")
    cred = credential(holder, method, target, body, sign)
    c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=600)
    headers = {HEADER: cred, "Content-Length": str(len(body))}
    if body:
        headers["Content-Type"] = "application/json"
    # http.client adds Host; the signature does not cover it.
    c.putrequest(method, target)
    for k, v in headers.items():
        c.putheader(k, v)
    c.endheaders(body)
    r = c.getresponse()
    while True:
        chunk = r.read1(8192) if hasattr(r, "read1") else r.read(8192)
        if not chunk:
            break
        out.write(chunk)
        out.flush()
    return r.status


def main(argv=None):
    p = argparse.ArgumentParser(description="Leaf-signed requests to a Furcate model gateway")
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("key", help="print the key as a cell link names it")
    k.add_argument("--tpm-handle", required=True)
    a = sub.add_parser("ask", help="send one signed request")
    a.add_argument("--tpm-handle", required=True)
    a.add_argument("--url", required=True)
    a.add_argument("--data", help="request body (JSON); omitted means GET")
    args = p.parse_args(argv)
    key = Tpm2Key(args.tpm_handle)
    if args.cmd == "key":
        print(key.holder())
        return 0
    body = args.data.encode() if args.data is not None else b""
    status = ask(args.url, body, key.holder(), key.sign, method="POST" if args.data is not None else "GET")
    sys.stdout.write("\n")
    return 0 if status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
