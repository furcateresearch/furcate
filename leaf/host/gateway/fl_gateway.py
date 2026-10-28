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
  fl-gateway [options] head --control SOCK [--every S] [--sense-every S] [--buffer N] [--config F]
                keep the leaves' links, keep the readings that verify, and answer requests on a
                local control socket (one JSON line in, one JSON line out; see Head.control)
  fl-gateway shim --control SOCK [--out -|FILE|unix:PATH] [--state F] [--poll S] [--once]
                read verified readings from the head and emit one JSON line per reading

Options (or environment):
  --link L      /dev/ttyUSB0 (serial), listen://0.0.0.0:7781 (the leaf dials out over Wi-Fi),
                or tcp://HOST:PORT (a byte relay)                         FL_LINK
  --signer S    tpm:NAME   this host's TPM key through fl-tpm
                broker[:PATH[#KEY_ID]]  the node's OTP device key through the Furcate OS
                           signing broker (default /run/furcate-os/fwcrypto.sock, key 1)
                cmd:CMD    any command that reads the message on stdin and prints a DER
                           ECDSA P-256 signature (hex) over SHA-256 of it; CMD with
                           "pub" in place of "sign" must print the public key (hex)  FL_SIGNER
  --grant F     the operator-signed grant for this node's key (JSON: grant, sig)  FL_GRANT
  --leaf HEX    the enrolled leaf id (comma-separated for several); any other
                leaf is refused                                          FL_LEAF
  --config F    JSON: link, signer, grant, sense_every, buffer and "leaves":
                [{"id": HEX, "grant": FILE}]; options and environment win   FL_CONFIG

Requires Python 3.9+ and the `cryptography` package; `pyserial` only for a
serial link (imported only when one is used). Output is JSON on stdout.
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
import fl_sense as S  # noqa: E402

CHUNK = 4096


BROKER_SOCK = "/run/furcate-os/fwcrypto.sock"


class SignerError(RuntimeError):
    pass


def broker_signer(arg: str):
    """The node key held by the Furcate OS signing broker: JSON lines on a
    unix socket. The broker hashes the message (ECDSA P-256 over SHA-256) and
    the key never leaves it. There is no fallback: if the broker cannot be
    reached or refuses, SignerError is raised."""
    import base64
    import socket
    path, _, kid = (arg or "").partition("#")
    path = path or BROKER_SOCK
    key_id = int(kid) if kid else 1

    def call(req: dict, field: str) -> bytes:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as k:
                k.settimeout(15)
                k.connect(path)
                k.sendall(json.dumps(req).encode() + b"\n")
                buf = b""
                while not buf.endswith(b"\n"):
                    d = k.recv(65536)
                    if not d:
                        break
                    buf += d
        except OSError as e:
            raise SignerError(f"signing broker {path} unavailable: {e}") from None
        try:
            r = json.loads(buf)
        except ValueError:
            raise SignerError(f"signing broker {path}: unreadable answer to {req['op']}") from None
        if not r.get("ok") or field not in r:
            raise SignerError(f"signing broker {path} refused {req['op']} (key {key_id}): {r.get('error', r)}")
        return base64.b64decode(r[field], validate=True)

    def pub(_name=None) -> bytes:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
        k = load_der_public_key(call({"op": "pubkey", "key_id": key_id}, "spki_der_b64"))
        if not isinstance(k, ec.EllipticCurvePublicKey) or k.curve.name != "secp256r1":
            raise SignerError(f"signing broker key {key_id} is not a P-256 key")
        return k.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def sign(_name, data: bytes) -> bytes:
        return call({"op": "sign", "key_id": key_id, "alg": "ecdsa-p256-sha256",
                     "msg_b64": base64.b64encode(data).decode()}, "sig_der_b64")

    return pub, sign


def make_signer(spec: str):
    """Returns (pub(), sign(data)) for the node's hardware key."""
    kind, _, arg = spec.partition(":")
    if kind == "broker":
        return broker_signer(arg)
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
    def __init__(self, a, config: dict | None = None):
        config = config or {}
        link = a.link
        self.hub = P._Hub(link) if a.cmd == "head" and link.startswith("listen://") else None
        self.link = None if self.hub else P.Serial(link)
        self.node = "node"
        self.enrol = S.Enrolment.build(config, a.leaf, a.grant)
        self.grant_override = None
        self.last_grant = None
        self.refusals: list[str] = []

    def resolve(self, leaf_pub: bytes):
        g = self.grant_override or self.enrol.resolve(leaf_pub)
        self.last_grant = g
        return g

    def session(self, wait: float = 60.0, tries: int = 3, link=None) -> P.Session:
        for i in range(tries):
            try:
                ses = P.Session.open(link or self.link, self.node, self.resolve, wait=wait)
                ses.grant_used = self.last_grant
                return ses
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


def sense_dict(f, leaf_pub: bytes) -> dict:
    """A SENSE reply as JSON: every field in hex, for a verifier above the head.

    The head does not judge the signatures; the session is authenticated, and the
    signatures are checked by whoever consumes the answer against `leaf_pub`
    (the reading payload is in fl_sample.h)."""
    rd = []
    for b in f.get(P.T_READING, []):
        if len(b) == 1 + 4 + 4 + 64:
            rd.append({"sensor": b[0], "value_f32_be": b[1:5].hex(), "seq": int.from_bytes(b[5:9], "big"),
                       "sig": b[9:].hex()})
    unit = None
    u = P.one(f, P.T_UNIT)
    if u is not None and len(u) == 16 + 8 + 64:
        unit = {"fingerprint": u[:16].hex(), "first_seq": int.from_bytes(u[16:20], "big"),
                "last_seq": int.from_bytes(u[20:24], "big"), "sig": u[24:].hex()}
    chain = [{"id": c[:16].hex(), "role": c[16:].decode(errors="replace")} for c in f.get(P.T_CHAIN, [])]
    return {"leaf_pub": leaf_pub.hex(), "generation": P.u(P.one(f, P.T_GENERATION)),
            "model_sha256": (P.one(f, P.T_MODEL_SHA) or b"").hex(),
            "signer_id": (P.one(f, P.T_SIGNER_ID) or b"").hex(), "chain": chain, "unit": unit, "readings": rd}


class Slot:
    """One link to one leaf: its connection, its session when open, and what
    was learned about it when the session opened."""

    def __init__(self, link, conn=None):
        self.link, self.conn, self.ses = link, conn, None
        self.key = None
        self.tries = 0
        self.last_sense = -1e9
        self.last_info = 0.0
        self.grant_used = None
        self.sensors: dict = {}
        self.assurance = None

    def close(self):
        if self.conn is not None:
            self.conn.close()


class Head:
    """The long-running head: keeps every enrolled leaf's session, asks each for
    its readings every `sense_every` seconds and keeps the ones that verify,
    sends INFO every `every` seconds (one JSON line on stdout), and answers
    control requests (see `control`)."""

    def __init__(self, gw, every=30.0, sense_every=10.0, capacity=512, log=None, mono=time.monotonic,
                 wall=time.time):
        self.gw, self.every, self.sense_every, self.capacity = gw, every, sense_every, capacity
        self.mono, self.wall = mono, wall
        self.log = log or (lambda d: print(json.dumps(dict(t=round(wall(), 1), **d)), flush=True))
        self.epoch = os.urandom(4).hex()
        self.slots: list[Slot] = [] if gw.hub else [Slot(gw.link)]
        self.bufs: dict[str, S.LeafBuffer] = {}
        self.refused: dict[str, int] = {}

    # -- sessions

    def _drop(self, s: Slot):
        s.ses = None
        if s.conn is not None:
            s.close()
            if s in self.slots:
                self.slots.remove(s)

    def accept(self):
        if self.gw.hub:
            for c in self.gw.hub.poll(0):
                self.slots.append(Slot(P.Serial.over(c), c))

    def open_slot(self, s: Slot, wait: float = 5.0) -> bool:
        if s.conn is not None and s.conn.closed:
            self._drop(s)
            return False
        try:
            ses = self.gw.session(link=s.link, wait=wait if s.conn is None else min(wait, 3.0), tries=1)
        except TimeoutError:
            s.tries += 1
            if s.conn is not None and s.tries >= 3:
                self._drop(s)
            return False
        except P.Refused as e:
            self.refused[str(e)] = self.refused.get(str(e), 0) + 1
            self.log({"session": "refused", "reason": str(e)})
            if s.conn is not None:
                self._drop(s)
            return False
        except ConnectionError:
            self._drop(s)
            return False
        s.ses, s.tries, s.last_sense, s.grant_used = ses, 0, -1e9, ses.grant_used
        s.key = ses.leaf_id.hex()[:32]
        for o in [o for o in self.slots if o is not s and o.key == s.key]:
            o.ses = None  # the leaf redialled: the older connection is stale
            if o.conn is not None:
                o.close()
                self.slots.remove(o)
        b = self.bufs.setdefault(s.key, S.LeafBuffer(self.capacity))
        ev = P.one(ses.evidence, 4)
        s.assurance = ev.decode(errors="replace") if ev else None
        try:
            t, f = ses.call(P.INFO_REQ, timeout=15)
            if t == P.INFO:
                s.sensors = S.parse_sensors(f)
                a = P.one(f, 60)
                if a:
                    s.assurance = a.decode(errors="replace")
        except (TimeoutError, ConnectionError):
            self._drop(s)
            return False
        b.meta.update(leaf_pub=ses.leaf_pub.hex(), assurance=s.assurance,
                      sensors={str(k): v for k, v in s.sensors.items()}, grant_roles=s.grant_used[0][4 + 65])
        self.log({"session": "open", "leaf_id": s.key, "handshake_s": round(ses.timings["handshake_s"], 3)})
        s.last_info = self.mono()
        return True

    # -- readings

    def ingest(self, s: Slot, t: int, f) -> dict | None:
        """Verifies a SENSE reply and keeps what passes. Returns the reply facts or None."""
        b = self.bufs[s.key]
        b.polls += 1
        if t != P.SENSE:
            r = result(f)
            need = P.one(f, P.T_ROLE_NEEDED)
            if need is not None:
                b.role_refused += 1
            else:
                b.count_reject("leaf_refused")
            b.last_refusal = dict(r, role_needed=P.u(need))
            return None
        entries, rej, facts = S.verify_reply(s.ses.leaf_pub, f)
        for reason, _, _ in rej:
            b.count_reject(reason)
        if rej:
            self.log({"sense": "refused", "leaf_id": s.key, "count": len(rej), "reasons": sorted({r[0] for r in rej})})
        b.add(entries, self.wall(), self.mono())
        b.last_ok_mono = self.mono()
        return facts

    def poll_sense(self, s: Slot):
        try:
            t, f = s.ses.call(P.SENSE_REQ, timeout=20)
        except (TimeoutError, ConnectionError) as e:
            self.log({"link": repr(e), "leaf_id": s.key})
            self._drop(s)
            return
        self.ingest(s, t, f)
        s.last_sense = self.mono()

    # -- control

    def _pick(self, req: dict):
        if req.get("leaf"):
            p = str(req["leaf"]).lower()
            m = [s for s in self.slots if s.key and s.key.startswith(p)]
            return (m[0], None) if m else (None, f"no leaf {p!r} is connected")
        live = [s for s in self.slots if s.ses is not None]
        if len(live) == 1:
            return live[0], None
        if not live and not self.gw.hub:
            return self.slots[0], None
        if not live:
            return None, "no leaf is connected"
        return None, "several leaves are connected: name one with \"leaf\": " + ", ".join(s.key for s in live)

    def _leaf_view(self, key: str, since: int, limit: int, max_age) -> dict:
        b = self.bufs[key]
        now = self.mono()
        slot = next((s for s in self.slots if s.key == key and s.ses is not None), None)
        age = None if b.last_ok_mono is None else round(now - b.last_ok_mono, 1)
        v = b.since(since, limit, now, max_age)
        v.update(b.meta)
        v.update(leaf_id=key, connected=slot is not None, oldest=b.items[0]["cursor"] if b.items else None,
                 stale=slot is None or age is None or age > 3 * self.sense_every + 5, last_ok_age_s=age,
                 counters={"polls": b.polls, "accepted": b.accepted, "rejected": dict(b.rejected),
                           "role_refused": b.role_refused, "last_refusal": b.last_refusal,
                           "buffered": len(b.items), "capacity": b.cap})
        return v

    def _buffered(self, req: dict) -> dict:
        keys = sorted(self.bufs)
        if req.get("leaf"):
            p = str(req["leaf"]).lower()
            keys = [k for k in keys if k.startswith(p)]
            if not keys:
                return {"ok": False, "op": "sense", "error": f"no leaf {p!r} is known"}
        try:
            limit = max(1, min(int(req.get("limit", 200)), 1000))
            since = req.get("since", 0)
            ma = req.get("max_age_s")
            ma = None if ma is None else float(ma)
            if not isinstance(since, dict):
                since = {k: int(since) for k in keys}
            since = {k: int(v) for k, v in since.items()}
        except (TypeError, ValueError):
            return {"ok": False, "op": "sense", "error": "bad since, limit or max_age_s"}
        changed = req.get("epoch") not in (None, self.epoch)
        leaves = {k: self._leaf_view(k, 0 if changed else since.get(k, 0), limit, ma) for k in keys}
        return {"ok": True, "op": "sense", "epoch": self.epoch, "epoch_changed": changed,
                "now_wall": round(self.wall(), 3), "leaves": leaves}

    def control(self, req: dict) -> dict:
        op = req.get("op")
        if op not in ("info", "sense", "infer", "ask", "bye", "leaves"):
            return {"ok": False, "error": f"unknown op {op!r}"}
        if op == "leaves":
            return {"ok": True, "op": op, "epoch": self.epoch, "refused": dict(self.refused),
                    "leaves": {k: {kk: vv for kk, vv in self._leaf_view(k, 0, 1, None).items()
                                   if kk not in ("readings",)} for k in sorted(self.bufs)}}
        if op == "sense" and not req.get("live"):
            return self._buffered(req)
        s, err = self._pick(req)
        if s is None:
            return {"ok": False, "op": op, "error": err}
        gw = self.gw
        override = bool(req.get("grant"))
        if override:
            g = req["grant"]
            if s.ses is not None:
                try:
                    s.ses.call(P.BYE)
                except (TimeoutError, ConnectionError):
                    pass
                s.ses = None
            gw.grant_override = (bytes.fromhex(g["grant"]), bytes.fromhex(g["sig"]))
        f = None
        try:
            opened = s.ses is None
            if opened:
                s.ses = gw.session(link=s.link, wait=float(req.get("wait", 60)), tries=1)
                s.key = s.ses.leaf_id.hex()[:32]
                s.grant_used = s.ses.grant_used
                self.bufs.setdefault(s.key, S.LeafBuffer(self.capacity))
            ses = s.ses
            out = {"ok": True, "op": op, "leaf_id": ses.leaf_id.hex()[:32], "grant_roles": s.grant_used[0][4 + 65],
                   "grant_generation": int.from_bytes(s.grant_used[0][70:74], "big")}
            if opened:
                out["handshake_s"] = round(ses.timings["handshake_s"], 3)
            if op == "info":
                t, f = ses.call(P.INFO_REQ)
                out["info"] = info_dict(f) if t == P.INFO else result(f)
            elif op == "sense":
                t, f = ses.call(P.SENSE_REQ)
                out["sense"] = sense_dict(f, ses.leaf_pub) if t == P.SENSE else result(f)
                if not override:
                    self.ingest(s, t, f)
            elif op == "infer":
                import base64
                data = base64.b64decode(req["input_b64"], validate=True)
                t0 = time.time()
                for off in range(0, len(data), CHUNK):
                    t, f = ses.call(P.INFER, P.tlv(P.T_OFFSET, off), P.tlv(P.T_INPUT, data[off:off + CHUNK]),
                                    timeout=60)
                out["round_trip_s"] = round(time.time() - t0, 3)
                if t == P.INFER_RESULT:
                    lab = P.one(f, P.T_LABEL)
                    out["result"] = {"label": lab.decode() if lab else None,
                                     "latency_us": P.u(P.one(f, P.T_LATENCY_US)),
                                     "scores_int8": [x - 256 if x > 127 else x for x in P.one(f, P.T_SCORES) or b""]}
                else:
                    out["result"] = result(f)
            elif op == "ask":
                fields = [P.tlv(P.T_METHOD, req["method"]), P.tlv(P.T_TARGET, req["target"])]
                if req.get("body"):
                    fields.append(P.tlv(P.T_DATA, req["body"].encode()))
                t0 = time.time()
                t, f = ses.call(P.GATEWAY_ASK, *fields, timeout=60)
                out["round_trip_s"] = round(time.time() - t0, 3)
                d = P.one(f, P.T_DATA)
                out["result"] = dict(result(f), status=P.u(P.one(f, P.T_STATUS)),
                                     answer=d.decode(errors="replace") if d is not None else None)
            elif op == "bye":
                ses.call(P.BYE)
                s.ses = None
            need = P.one(f, P.T_ROLE_NEEDED) if f is not None else None
            if need is not None:
                out["role_needed"] = P.u(need)
        except (TimeoutError, ConnectionError, P.Refused) as e:
            out = {"ok": False, "op": op, "error": f"{type(e).__name__}: {e}"}
            s.ses = None
        if override:
            if s.ses is not None:
                try:
                    s.ses.call(P.BYE)
                except (TimeoutError, ConnectionError):
                    pass
            s.ses = None
            gw.grant_override = None
        return out

    # -- the loop

    def serve_control(self, srv):
        k, _ = srv.accept()
        with k:
            k.settimeout(10)
            buf = b""
            try:
                while not buf.endswith(b"\n"):
                    d = k.recv(65536)
                    if not d:
                        break
                    buf += d
                ans = self.control(json.loads(buf))
            except (ValueError, KeyError, OSError) as e:
                ans = {"ok": False, "error": f"bad request: {e}"}
            self.log({"control": ans.get("op"), "ok": ans.get("ok")})
            try:
                k.sendall(json.dumps(ans).encode() + b"\n")
            except OSError:
                pass

    def step(self, srv=None, wait: float = 0.2):
        import select
        self.accept()
        for s in list(self.slots):
            if s.ses is None:
                self.open_slot(s)
        if srv is not None:
            r, _, _ = select.select([srv], [], [], wait)
            if r:
                self.serve_control(srv)
        now = self.mono()
        for s in list(self.slots):
            if s.ses is None:
                continue
            if now - s.last_sense >= self.sense_every:
                self.poll_sense(s)
                if s.ses is None:
                    continue
            if now - s.last_info >= self.every:
                try:
                    _, f = s.ses.call(P.INFO_REQ)
                    self.log({"info": info_dict(f)})
                except (TimeoutError, ConnectionError) as e:
                    self.log({"link": repr(e)})
                    self._drop(s)
                s.last_info = now


def head(gw, a):
    import socket
    ctl = Path(a.control)
    if ctl.exists():
        ctl.unlink()
    old = os.umask(0o117)  # 0660: the head's user and group only
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(ctl))
    os.umask(old)
    srv.listen(4)
    h = Head(gw, a.every, a.sense_every, a.buffer)
    h.log({"head": "up", "node_pub": P.se_pub("node").hex(), "control": str(ctl), "epoch": h.epoch,
           "sense_every": a.sense_every, "buffer": a.buffer})
    while True:
        h.step(srv)


def main():
    ap = argparse.ArgumentParser(prog="fl-gateway", description=__doc__.split("\n")[0])
    ap.add_argument("--link", default=os.environ.get("FL_LINK"))
    ap.add_argument("--signer", default=os.environ.get("FL_SIGNER"))
    ap.add_argument("--grant", default=os.environ.get("FL_GRANT"))
    ap.add_argument("--leaf", default=os.environ.get("FL_LEAF"))
    ap.add_argument("--config", default=os.environ.get("FL_CONFIG"))
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
    p = sp.add_parser("head")
    p.add_argument("--control", required=True, help="unix socket path for control requests")
    p.add_argument("--every", type=float, default=30.0)
    p.add_argument("--sense-every", type=float, default=float(os.environ.get("FL_SENSE_EVERY", 10)),
                   help="seconds between readings requests to each leaf")
    p.add_argument("--buffer", type=int, default=int(os.environ.get("FL_BUFFER", 512)),
                   help="readings kept per leaf")
    p = sp.add_parser("shim")
    p.add_argument("--control", required=True)
    p.add_argument("--out", default="-", help="- (stdout), a file to append to, or unix:PATH")
    p.add_argument("--state", help="file holding the cursors, so a restart resumes")
    p.add_argument("--poll", type=float, default=10.0)
    p.add_argument("--once", action="store_true")
    p.add_argument("--leaf", dest="shim_leaf")
    a = ap.parse_args()
    if a.cmd == "shim":
        S.shim(a.control, a.out, a.state, a.poll, a.once, a.shim_leaf)
        return
    config = json.loads(Path(a.config).read_text()) if a.config else {}
    a.link = a.link or config.get("link")
    a.signer = a.signer or config.get("signer")
    if a.cmd == "head":
        if "--sense-every" not in sys.argv and "FL_SENSE_EVERY" not in os.environ:
            a.sense_every = float(config.get("sense_every", a.sense_every))
        if "--buffer" not in sys.argv and "FL_BUFFER" not in os.environ:
            a.buffer = int(config.get("buffer", a.buffer))
    for k in ("link", "signer"):
        if not getattr(a, k):
            ap.error(f"--{k} is required")
    P.se_pub, P.se_sign = make_signer(a.signer)
    gw = Gateway(a, config)
    # A grant names the node key; a signer holding another key is refused by
    # every leaf, so stop here instead.
    for g, _ in gw.enrol.all_grants():
        if g[4:4 + 65] != P.se_pub("node"):
            sys.exit("fl-gateway: a grant is for another node key than the signer's")
    if a.cmd == "head":
        try:
            head(gw, a)
        except SignerError as e:
            sys.exit(f"fl-gateway: {e}")
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
    try:
        main()
    except SignerError as e:
        sys.exit(f"fl-gateway: {e}")
