#!/usr/bin/env python3
"""fl-gateway: the controller end of a Furcate leaf link, for a gateway node.

Runs on the node that owns the leaf (the gateway, or a controller until a gateway owns it).
It holds no private key: every node signature comes from the configured
hardware signer. The leaf always initiates; this program only answers.

  fl-gateway [options] info
  fl-gateway [options] serve [--every S]          keep the link, one INFO JSON line per S seconds
  fl-gateway [options] config -                   deliver an operator-signed CONFIG envelope read from stdin
  fl-gateway [options] ota MANIFEST BIN           offer release-signed firmware
  fl-gateway [options] model MANIFEST TFLITE      offer a release-signed model
  fl-gateway [options] infer INPUT.bin            run one inference

Options (or environment):
  --link L      /dev/ttyUSB0 (serial), listen://0.0.0.0:7781 (the leaf dials out over Wi-Fi),
                or tcp://HOST:PORT (a byte relay)                         FL_LINK
  --signer S    tpm:NAME   this host's TPM key through fl-tpm
                cmd:CMD    any command that reads the message on stdin and prints a DER
                           ECDSA P-256 signature (hex) over SHA-256 of it; CMD with
                           "pub" in place of "sign" must print the public key (hex)  FL_SIGNER
  --grant F     the operator-signed grant for this node's key (JSON: grant, sig)  FL_GRANT
  --leaf HEX    the enrolled leaf id; any other leaf is refused             FL_LEAF

Requires Python 3.9+ and the `cryptography` package; `pyserial` only for a
serial link. Output is JSON on stdout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import fl_proto as P  # noqa: E402

CHUNK = 4096


def make_signer(spec: str):
    """Returns (pub(), sign(data)) for the node's hardware key."""
    kind, _, arg = spec.partition(":")
    if kind == "tpm":
        tool = os.environ.get("FL_TPM", "fl-tpm")
        pub_cmd, sign_cmd = [tool, "pub", arg], [tool, "sign", arg]
    elif kind == "cmd":
        sign_cmd = shlex.split(arg)
        if "sign" not in sign_cmd:
            raise SystemExit("--signer cmd: the command must contain the word 'sign'")
        pub_cmd = [("pub" if w == "sign" else w) for w in sign_cmd]
    else:
        raise SystemExit(f"unknown signer {spec!r}")

    def pub(_name=None) -> bytes:
        return bytes.fromhex(subprocess.check_output(pub_cmd, text=True).strip().split()[-1])

    def sign(_name, data: bytes) -> bytes:
        return bytes.fromhex(subprocess.check_output(sign_cmd, input=data).decode().strip().split()[-1])

    return pub, sign


def info_dict(f) -> dict:
    u = lambda t: P.u(P.one(f, t))
    t = lambda tag: (lambda b: b.decode(errors="replace") if b is not None else None)(P.one(f, tag))
    rssi = u(72)
    return {"leaf_id": t(P.T_DETAIL), "assurance": t(60), "min_generation": u(61), "release_threshold": u(62),
            "arena_used": u(41), "free_heap": u(45), "running": t(50), "fw_seq": u(51), "min_fw_seq": u(52),
            "boot_event": t(53), "transport": t(70), "ssid": t(71),
            "rssi_dbm": rssi - 256 if rssi is not None and rssi > 127 else rssi, "channel": u(73), "ip": t(74),
            "controller": t(78), "config_seq": u(76), "auth_window_ms": u(77)}


def result(f) -> dict:
    r = P.one(f, P.T_REASON)
    return {"ok": P.u(P.one(f, P.T_OK)), "reason": r.decode() if r else None,
            "latency_us": P.u(P.one(f, P.T_LATENCY_US))}


class Gateway:
    def __init__(self, a):
        self.link = P.Serial(a.link)
        self.node = "node"
        g = json.loads(Path(a.grant).read_text())
        self.grant, self.grant_sig = bytes.fromhex(g["grant"]), bytes.fromhex(g["sig"])
        self.leaf = bytes.fromhex(a.leaf) if a.leaf else None
        self.refusals: list[str] = []

    def session(self, wait: float = 60.0, tries: int = 3) -> P.Session:
        for i in range(tries):
            try:
                return P.Session.open(self.link, self.node, self.grant, self.grant_sig, expect_leaf=self.leaf,
                                      wait=wait)
            except P.Refused as e:
                self.refusals.append(str(e))
                if i == tries - 1:
                    raise

    def stream(self, ses, offer_t, chunk_t, commit_t, manifest: bytes, blob: bytes) -> dict:
        _, f = ses.call(offer_t, P.tlv(P.T_SIGNED, manifest), timeout=60)
        r = {"offer": result(f)}
        if not r["offer"]["ok"]:
            return r
        t0 = time.time()
        for off in range(0, len(blob), CHUNK):
            _, f = ses.call(chunk_t, P.tlv(P.T_OFFSET, off), P.tlv(P.T_DATA, blob[off:off + CHUNK]), timeout=60)
            if not P.u(P.one(f, P.T_OK)):
                r["chunk"] = result(f)
                return r
        r["transfer_s"] = round(time.time() - t0, 1)
        _, f = ses.call(commit_t, timeout=120)
        r["commit"] = result(f)
        return r


def main():
    ap = argparse.ArgumentParser(prog="fl-gateway", description=__doc__.split("\n")[0])
    ap.add_argument("--link", default=os.environ.get("FL_LINK"))
    ap.add_argument("--signer", default=os.environ.get("FL_SIGNER"))
    ap.add_argument("--grant", default=os.environ.get("FL_GRANT"))
    ap.add_argument("--leaf", default=os.environ.get("FL_LEAF"))
    sp = ap.add_subparsers(dest="cmd", required=True)
    sp.add_parser("info")
    p = sp.add_parser("serve")
    p.add_argument("--every", type=float, default=30.0)
    p = sp.add_parser("config")
    p.add_argument("envelope", choices=["-"])
    p = sp.add_parser("ota")
    p.add_argument("manifest")
    p.add_argument("bin")
    p = sp.add_parser("model")
    p.add_argument("manifest")
    p.add_argument("tflite")
    p = sp.add_parser("infer")
    p.add_argument("input")
    a = ap.parse_args()
    for k in ("link", "signer", "grant"):
        if not getattr(a, k):
            ap.error(f"--{k} is required")
    P.se_pub, P.se_sign = make_signer(a.signer)
    gw = Gateway(a)
    out: dict = {"cmd": a.cmd}

    if a.cmd == "config":
        envelope = sys.stdin.buffer.read()  # operator-signed; never written to disk here
    ses = gw.session()
    out["leaf_id"] = ses.leaf_id.hex()[:32]
    out["handshake_s"] = round(ses.timings["handshake_s"], 3)
    if a.cmd == "info":
        _, f = ses.call(P.INFO_REQ)
        out["info"] = info_dict(f)
    elif a.cmd == "serve":
        while True:
            try:
                _, f = ses.call(P.INFO_REQ)
                print(json.dumps({"t": round(time.time(), 1), "info": info_dict(f)}), flush=True)
                time.sleep(a.every)
            except (TimeoutError, ConnectionError) as e:
                print(json.dumps({"t": round(time.time(), 1), "link": repr(e)}), flush=True)
                ses = gw.session()
    elif a.cmd == "config":
        _, f = ses.call(P.CONFIG, P.tlv(P.T_SIGNED, envelope))
        del envelope
        out["result"] = result(f)
    elif a.cmd == "ota":
        out.update(gw.stream(ses, P.OTA_OFFER, P.OTA_CHUNK, P.OTA_COMMIT, Path(a.manifest).read_bytes(),
                             Path(a.bin).read_bytes()))
    elif a.cmd == "model":
        out.update(gw.stream(ses, P.MODEL_OFFER, P.MODEL_CHUNK, P.MODEL_COMMIT, Path(a.manifest).read_bytes(),
                             Path(a.tflite).read_bytes()))
    elif a.cmd == "infer":
        data = Path(a.input).read_bytes()
        for off in range(0, len(data), CHUNK):  # inputs larger than one record go in parts
            t, f = ses.call(P.INFER, P.tlv(P.T_OFFSET, off), P.tlv(P.T_INPUT, data[off:off + CHUNK]), timeout=60)
        if t == P.INFER_RESULT:
            lab = P.one(f, P.T_LABEL)
            out["result"] = {"label": lab.decode() if lab else None, "latency_us": P.u(P.one(f, P.T_LATENCY_US)),
                             "scores_int8": [x - 256 if x > 127 else x for x in P.one(f, P.T_SCORES) or b""]}
        else:
            out["result"] = result(f)
    if not (a.cmd == "ota" and out.get("commit", {}).get("ok")):
        ses.call(P.BYE)
    if gw.refusals:
        out["refused_attempts"] = gw.refusals
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
