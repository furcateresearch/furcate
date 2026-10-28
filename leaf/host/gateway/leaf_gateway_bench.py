#!/usr/bin/env python3
"""Bench for leaf-signed gateway requests (furcate docs/interfaces/leaf-gateway-request.md).

The gateway under test is `furcatectl model front`, the door the gateway unit
runs, started by hand on the gateway node with its directories pointed at a
bench cell (FURCATE_CONFIG_DIR, FURCATE_STATE_DIR, FURCATE_MODELS_DIR). The
node's own /etc/furcate and /var/lib/furcate are not read or written.

  leaf_gateway_bench.py fixture DIR LEAF_HOLDER   (on the signer host)
      Writes a bench cell: a head link issued by the operator key and the
      leaf's link issued by the head key, both signed by hardware-held keys
      through FL_SE (fl-tpm). The leaf's class is `soft` (SRAM fingerprint on
      an open part) and the head's link lowers the cell's leaf floor to it.
  leaf_gateway_bench.py echo PORT                  (on the gateway node)
      A router stand-in on 127.0.0.1:PORT that answers with what crossed the
      loopback: method, target, headers, body length.
  leaf_gateway_bench.py check URL LEAF_RUN.json    (anywhere that reaches URL)
      Verifies every leaf credential in LEAF_RUN.json (fl_bench.py gateway
      output) against the reference client's canonical request, then sends
      the refusal cases: a replay, a tampered body, a credential moved to a
      wrong key, a valid signature by a key not attached to the cell, and an
      expired credential. Prints JSON.

Holds no private key: signatures come from FL_SE.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import subprocess
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

CLIENTS = os.environ.get("FURCATE_CLIENTS")
if CLIENTS:
    sys.path.insert(0, CLIENTS)

FL_SE = os.environ.get("FL_SE", "fl-tpm")
SITE = "bench"
CELL = "leaf-bench"


def se_pub(name: str) -> bytes:
    return bytes.fromhex(subprocess.check_output([FL_SE, "pub", name], text=True).strip())


def se_sign(name: str, data: bytes) -> bytes:
    return bytes.fromhex(subprocess.check_output([FL_SE, "sign", name], input=data).decode().strip().split()[-1])


def holder(pub: bytes) -> str:
    import furcate_leaf_request as flr
    return flr.holder_from_point(pub)


def signed_bytes(link: dict) -> bytes:
    """furcate_policy::delegation::CellDelegation::signed_bytes."""
    debug = {"soft": "Soft", "device": "Device", "secureelement": "SecureElement", "tee": "Tee", "dice": "Dice",
             "tpm": "Tpm"}
    fields = [link["site"], link["issuer"], link["holder"], link["role"], link["scope"], link.get("scale") or "",
              debug[link["assurance"]] if link.get("assurance") else "", link.get("endpoint", ""),
              link.get("name", ""), link.get("parent") or "", str(link["not_before"]), str(link["not_after"])]
    m = b"furcate:cell-delegation:v1\0"
    for f in fields:
        b = f.encode()
        m += len(b).to_bytes(8, "big") + b
    if link.get("leaf_min_class"):
        b = f"leaf_min_class={debug[link['leaf_min_class']]}".encode()
        m += len(b).to_bytes(8, "big") + b
    return m


def digest(link: dict) -> str:
    return hashlib.sha256(signed_bytes(link) + link["signature"].encode()).hexdigest()


def sign_link(link: dict, key: str) -> dict:
    import furcate_leaf_request as flr
    link["signature"] = flr.raw_signature(se_sign(key, signed_bytes(link))).hex()
    return link


def cmd_fixture(out: str, leaf_holder: str, operator_key="fl-operator", head_key="fl-node"):
    now = int(time.time())
    op, head = holder(se_pub(operator_key)), holder(se_pub(head_key))
    until = now + 7 * 86400
    head_link = sign_link({"site": SITE, "issuer": op, "holder": head, "role": "head", "scope": f"cell:{CELL}",
                           "scale": "other", "assurance": "tpm", "leaf_min_class": "soft", "endpoint": "",
                           "name": "bench-head", "parent": None, "not_before": now - 60, "not_after": until},
                          operator_key)
    leaf_link = sign_link({"site": SITE, "issuer": head, "holder": leaf_holder, "role": "leaf",
                           "scope": f"cell:{CELL}", "scale": None, "assurance": "soft", "endpoint": "",
                           "name": "esp32-leaf", "parent": digest(head_link), "not_before": now - 60,
                           "not_after": until}, head_key)
    d = Path(out)
    for sub in ("config", "state", "models"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    (d / "config/cell-anchor.json").write_text(json.dumps({"own": head_link, "parent_endpoint": "bench:0"}, indent=1))
    (d / "state/cells-issued.json").write_text(json.dumps({"site": SITE, "links": [leaf_link], "revoked": []},
                                                          indent=1))
    # The router stand-in checks nothing; this marks what the gateway forwards.
    (d / "models/gateway.token").write_text("bench-router-stand-in\n")
    print(json.dumps({"dir": str(d), "operator": op, "head": head, "leaf": leaf_holder, "cell": CELL,
                      "not_after": until}, indent=1))


class Echo(BaseHTTPRequestHandler):
    def _answer(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        seen = {"method": self.command, "target": self.path, "body_sha256": hashlib.sha256(body).hexdigest(),
                "body_len": len(body), "authorization": self.headers.get("Authorization"),
                "x_furcate_credential_forwarded": self.headers.get("X-Furcate-Credential") is not None}
        b = json.dumps({"router_stand_in": seen}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b)

    do_GET = do_POST = _answer

    def log_message(self, fmt, *args):
        sys.stderr.write("echo: " + fmt % args + "\n")


def cmd_echo(port: str):
    HTTPServer(("127.0.0.1", int(port)), Echo).serve_forever()


def send(url: str, method: str, target: str, body: bytes, cred: str | None) -> tuple[int, str]:
    u = urllib.parse.urlsplit(url)
    c = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
    c.putrequest(method, target)
    c.putheader("Content-Length", str(len(body)))
    if body:
        c.putheader("Content-Type", "application/json")
    if cred:
        c.putheader("X-Furcate-Credential", cred)
    c.endheaders()
    if body:
        c.send(body)
    r = c.getresponse()
    return r.status, r.read().decode(errors="replace")


def parse_cred(cred: str) -> tuple[str, str, int, str]:
    assert cred.startswith("leaf:p256:")
    rest = cred[len("leaf:"):]
    h, tail = rest.rsplit(":", 1)
    nonce, exp, sig = tail.split(".")
    return h, nonce, int(exp), sig


def verify_independently(ask: dict) -> dict:
    """The leaf's signature checked with `cryptography` over the reference
    client's canonical request: no firmware code involved."""
    import furcate_leaf_request as flr
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    h, nonce, exp, sig = parse_cred(ask["credential"])
    canon = flr.canonical(ask["method"], ask["target"], ask["body"].encode(), nonce, exp)
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(h[5:]))
    raw = bytes.fromhex(sig)
    r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    try:
        key.verify(encode_dss_signature(r, s), canon, ec.ECDSA(hashes.SHA256()))
        ok = True
    except InvalidSignature:
        ok = False
    return {"signature_verifies": ok, "low_s": s <= flr._N // 2, "reference_low_s_unchanged": flr.raw_signature(raw) == raw,
            "nonce": nonce, "expires_at": exp, "canonical_sha256": hashlib.sha256(canon).hexdigest()}


def cmd_check(url: str, run_file: str, wrong_key="fl-operator"):
    import furcate_leaf_request as flr
    run = json.load(open(run_file))
    asks = [a for a in run["asks"] if a.get("credential")]
    res = {"leaf_holder": run["holder"], "independent_verification": [verify_independently(a) for a in asks],
           "refusals": {}}
    post = next(a for a in asks if a["method"] == "POST")
    get = next(a for a in asks if a["method"] == "GET")
    R = res["refusals"]
    # 1. The same request again: spent nonce.
    R["replay"] = send(url, post["method"], post["target"], post["body"].encode(), post["credential"])
    # 2. The POST's credential on a changed body.
    tampered = post["body"].replace('"max_tokens":8', '"max_tokens":9').encode()
    assert tampered != post["body"].encode()
    R["tampered_body"] = send(url, post["method"], post["target"], tampered, post["credential"])
    # 3a. The leaf's signature presented under another key.
    h, nonce, exp, sig = parse_cred(get["credential"])
    other = holder(se_pub(wrong_key))
    R["moved_to_wrong_key"] = send(url, get["method"], get["target"], b"", f"leaf:{other}:{nonce}.{exp}.{sig}")
    # 3b. A valid signature by a hardware key that is not attached to the cell.
    cred = flr.credential(other, "GET", get["target"], b"", lambda m: se_sign(wrong_key, m))
    R["unattached_key_valid_signature"] = send(url, "GET", get["target"], b"", cred)
    # 4. No credential at all.
    R["no_credential"] = send(url, "GET", get["target"], b"", None)
    # 5. Expired: wait out the GET's validity, then send it as it was.
    wait = exp - time.time() + 2
    if wait > 0:
        time.sleep(wait)
    R["expired"] = send(url, get["method"], get["target"], b"", get["credential"])
    res["expired_sent_at"] = int(time.time())
    print(json.dumps(res, indent=1))


def main():
    cmd, args = sys.argv[1], sys.argv[2:]
    {"fixture": cmd_fixture, "echo": cmd_echo, "check": cmd_check}[cmd](*args)


if __name__ == "__main__":
    main()
