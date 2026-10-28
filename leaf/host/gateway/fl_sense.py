"""Verified readings at the head: checks a SENSE reply, keeps what verified in a
bounded per-leaf buffer behind a cursor, and carries the consumer side.

A reading is kept only when:
  * the leaf's signature over the sample payload verifies against the leaf key of
    the session (payload as in components/fl_sense/include/fl_sample.h);
  * the reply names the signer the key hashes to;
  * a reading from a sensing module (sensor index 16 and up) is covered by a
    unit-binding record whose signature verifies, whose sequence range holds the
    reading, and whose fingerprint appears in the chain as a `sensing` entry;
  * its (generation, sequence) is newer than any kept before it.
Everything else is refused and counted by reason; nothing is dropped silently.

Times: the cursor and every age are computed on the monotonic clock, so a step
of the wall clock (a Pi that has just synced) neither reorders nor expires
readings. The wall time is carried for display only.
"""

from __future__ import annotations

import collections
import hashlib
import json
import math
import os
import socket
import struct
import sys
import time

import fl_proto as P

SAMPLE_DOMAIN = b"furcate/leaf/sample/v2"
UNIT_DOMAIN = b"furcate/leaf/unit/v1"
MODULE_FIRST_INDEX = 16
SCHEMA = "furcate-fl1-reading/1"


def sample_payload(leaf_pub: bytes, generation: int, sensor: int, value_be: bytes, seq: int,
                   model_sha: bytes) -> bytes:
    dev8 = hashlib.sha256(leaf_pub).digest()[:8]
    return (SAMPLE_DOMAIN + dev8 + generation.to_bytes(2, "big") + bytes([sensor]) + value_be
            + seq.to_bytes(4, "big") + model_sha)


def unit_payload(leaf_pub: bytes, generation: int, fp: bytes, first: int, last: int) -> bytes:
    dev8 = hashlib.sha256(leaf_pub).digest()[:8]
    return (UNIT_DOMAIN + dev8 + generation.to_bytes(2, "big") + fp + first.to_bytes(4, "big")
            + last.to_bytes(4, "big"))


def parse_sensors(f) -> dict:
    """The INFO sensor table: "<index>:<kind>:<unit>:<source>" entries."""
    out = {}
    for b in f.get(P.T_SENSOR, []):
        p = b.decode(errors="replace").split(":", 3)
        if len(p) == 4 and p[0].isdigit():
            out[int(p[0])] = {"kind": p[1], "unit": p[2], "source": p[3]}
    return out


def verify_reply(leaf_pub: bytes, f) -> tuple[list, list, dict]:
    """Returns (accepted entries, [(reason, sensor, seq)], reply facts)."""
    gen = P.u(P.one(f, P.T_GENERATION))
    model = P.one(f, P.T_MODEL_SHA)
    signer = P.one(f, P.T_SIGNER_ID)
    chain = [{"id": c[:16].hex(), "role": c[16:].decode(errors="replace")}
             for c in f.get(P.T_CHAIN, []) if len(c) > 16]
    unit = None
    ub = P.one(f, P.T_UNIT)
    if ub is not None and len(ub) == 16 + 8 + 64 and gen is not None:
        fp, first, last = ub[:16], int.from_bytes(ub[16:20], "big"), int.from_bytes(ub[20:24], "big")
        ok = P.verify_raw(leaf_pub, unit_payload(leaf_pub, gen, fp, first, last), ub[24:])
        unit = {"fingerprint": fp.hex(), "first_seq": first, "last_seq": last, "sig": ub[24:].hex(),
                "verified": ok}
    facts = {"generation": gen, "chain": chain, "unit": unit,
             "model_sha256": (model or b"").hex(), "signer_id": (signer or b"").hex()}
    raw = f.get(P.T_READING, [])
    rej: list = []
    if gen is None or model is None or len(model) != 32 or signer is None:
        return [], [("malformed", None, None)] * max(1, len(raw)), facts
    if signer != hashlib.sha256(leaf_pub).digest()[:16]:
        return [], [("signer_mismatch", b[0] if b else None, None) for b in raw] or [("signer_mismatch", None, None)], facts
    sensing = {c["id"] for c in chain if c["role"] == "sensing"}
    ok_entries = []
    for b in raw:
        if len(b) != 1 + 4 + 4 + 64:
            rej.append(("malformed", None, None))
            continue
        sensor, vbe, seq, sig = b[0], b[1:5], int.from_bytes(b[5:9], "big"), b[9:]
        value = struct.unpack(">f", vbe)[0]
        if not math.isfinite(value):
            rej.append(("value", sensor, seq))
            continue
        if not P.verify_raw(leaf_pub, sample_payload(leaf_pub, gen, sensor, vbe, seq, model), sig):
            rej.append(("bad_signature", sensor, seq))
            continue
        bound = None
        if sensor >= MODULE_FIRST_INDEX:
            if (unit is None or not unit["verified"] or unit["fingerprint"] not in sensing
                    or not unit["first_seq"] <= seq <= unit["last_seq"]):
                rej.append(("unit_binding", sensor, seq))
                continue
            bound = unit
        ok_entries.append({"sensor": sensor, "value": value, "value_f32_be": vbe.hex(), "seq": seq,
                           "generation": gen, "model_sha256": model.hex(), "sig": sig.hex(),
                           "signer_id": signer.hex(), "unit": bound,
                           "chain": [c for c in chain if bound or c["role"] != "sensing"]})
    ok_entries.sort(key=lambda e: e["seq"])
    return ok_entries, rej, facts


def verify_entry(leaf_pub: bytes, e: dict) -> bool:
    """Independent re-check of one buffered entry, for a consumer above the head."""
    try:
        vbe, model = bytes.fromhex(e["value_f32_be"]), bytes.fromhex(e["model_sha256"])
        if hashlib.sha256(leaf_pub).digest()[:16].hex() != e["signer_id"]:
            return False
        if not P.verify_raw(leaf_pub, sample_payload(leaf_pub, e["generation"], e["sensor"], vbe, e["seq"], model),
                            bytes.fromhex(e["sig"])):
            return False
        if e["sensor"] >= MODULE_FIRST_INDEX:
            u = e.get("unit")
            if not u or not u["first_seq"] <= e["seq"] <= u["last_seq"]:
                return False
            fp = bytes.fromhex(u["fingerprint"])
            if not any(c["id"] == u["fingerprint"] and c["role"] == "sensing" for c in e["chain"]):
                return False
            return P.verify_raw(leaf_pub, unit_payload(leaf_pub, e["generation"], fp, u["first_seq"], u["last_seq"]),
                                bytes.fromhex(u["sig"]))
        return True
    except (KeyError, ValueError, TypeError):
        return False


class LeafBuffer:
    """Per-leaf readings that verified, newest last, bounded. Cursors count
    accepted readings from 1 and are never reused within one head run."""

    def __init__(self, capacity: int = 512):
        self.cap = max(1, capacity)
        self.items: collections.deque = collections.deque(maxlen=self.cap)
        self.counter = 0
        self.last_key = (-1, -1)
        self.accepted = 0
        self.rejected: dict = {}
        self.role_refused = 0
        self.polls = 0
        self.last_refusal = None
        self.last_ok_mono = None
        self.meta: dict = {}

    def count_reject(self, reason: str, n: int = 1):
        self.rejected[reason] = self.rejected.get(reason, 0) + n

    def add(self, entries: list, rx_wall: float, rx_mono: float) -> int:
        n = 0
        for e in entries:
            key = (e["generation"], e["seq"])
            if key <= self.last_key:
                self.count_reject("replay")
                continue
            self.last_key = key
            self.counter += 1
            self.items.append(dict(e, cursor=self.counter, rx_wall=round(rx_wall, 3), rx_mono=rx_mono))
            self.accepted += 1
            n += 1
        return n

    def since(self, cursor: int, limit: int, now_mono: float, max_age_s: float | None = None) -> dict:
        reset = cursor > self.counter
        if reset:
            cursor = 0
        oldest = self.items[0]["cursor"] if self.items else self.counter + 1
        dropped = max(0, oldest - cursor - 1)
        out = []
        for it in self.items:
            if it["cursor"] <= cursor:
                continue
            age = now_mono - it["rx_mono"]
            if max_age_s is not None and age > max_age_s:
                continue
            e = {k: v for k, v in it.items() if k != "rx_mono"}
            e["age_s"] = round(max(0.0, age), 3)
            out.append(e)
            if len(out) >= limit:
                break
        nxt = out[-1]["cursor"] if out else self.counter
        return {"cursor": nxt, "dropped": dropped, "reset": reset, "readings": out}


# ---- configuration ----------------------------------------------------------

def load_grant_file(path: str) -> tuple[bytes, bytes]:
    with open(path) as fh:
        g = json.load(fh)
    return bytes.fromhex(g["grant"]), bytes.fromhex(g["sig"])


class Enrolment:
    """Which leaves this head serves and the grant for each.

    From a JSON file (--config / FL_CONFIG) or the single-leaf options:
      {"leaves": [{"id": "<hex, 16 bytes or more>", "grant": "/path/grant.json"}, ...],
       "grant": "/path/default-grant.json"}
    A leaf entry without its own grant uses the default one. With no leaf listed,
    any leaf is served under the default grant (the earlier behaviour without FL_LEAF).
    FL_LEAF may hold several ids separated by commas."""

    def __init__(self, leaves: list[tuple[bytes | None, tuple[bytes, bytes] | None]],
                 default: tuple[bytes, bytes] | None):
        self.leaves, self.default = leaves, default

    @classmethod
    def build(cls, config: dict | None, leaf_opt: str | None, grant_opt: str | None) -> "Enrolment":
        config = config or {}
        gpath = grant_opt or config.get("grant")
        default = load_grant_file(gpath) if gpath else None
        leaves = []
        for ent in config.get("leaves", []):
            lid = bytes.fromhex(ent["id"])
            if len(lid) < 16:
                raise SystemExit("fl-gateway: a leaf id must be at least 16 bytes (32 hex digits)")
            leaves.append((lid, load_grant_file(ent["grant"]) if ent.get("grant") else None))
        for part in (leaf_opt or "").split(","):
            if part.strip():
                lid = bytes.fromhex(part.strip())
                if len(lid) < 16:
                    raise SystemExit("fl-gateway: a leaf id must be at least 16 bytes (32 hex digits)")
                leaves.append((lid, None))
        e = cls(leaves, default)
        if not default and any(g is None for _, g in leaves):
            raise SystemExit("fl-gateway: a leaf has no grant and there is no default grant")
        if not leaves and not default:
            raise SystemExit("fl-gateway: a grant is required")
        return e

    def resolve(self, leaf_pub: bytes) -> tuple[bytes, bytes]:
        h = hashlib.sha256(leaf_pub).digest()
        if not self.leaves:
            return self.default
        for lid, g in self.leaves:
            if h[:len(lid)] == lid:
                return g or self.default
        raise P.Refused("leaf identity does not match the enrolled one")

    def all_grants(self):
        if self.default:
            yield self.default
        for _, g in self.leaves:
            if g:
                yield g


# ---- consumer side ----------------------------------------------------------

def control_call(path: str, req: dict, timeout: float = 15.0) -> dict:
    k = socket.socket(socket.AF_UNIX)
    k.settimeout(timeout)
    k.connect(path)
    k.sendall(json.dumps(req).encode() + b"\n")
    b = b""
    while not b.endswith(b"\n"):
        d = k.recv(65536)
        if not d:
            break
        b += d
    k.close()
    return json.loads(b)


def shim_lines(answer: dict, state: dict) -> list[str]:
    """Turns one buffered `sense` answer into output lines and advances `state`
    (cursor per leaf). Each reading is re-verified here against the leaf key the
    head reported; one that does not verify is not emitted and is counted."""
    lines = []
    for lid, L in answer.get("leaves", {}).items():
        pub = bytes.fromhex(L["leaf_pub"])
        for e in L["readings"]:
            if not verify_entry(pub, e):
                state["refused"] = state.get("refused", 0) + 1
                continue
            s = L.get("sensors", {}).get(str(e["sensor"]), {})
            lines.append(json.dumps({
                "schema": SCHEMA, "leaf_id": lid, "leaf_pub": L["leaf_pub"], "assurance": L.get("assurance"),
                "sensor": {"index": e["sensor"], "kind": s.get("kind"), "unit": s.get("unit"),
                           "source": s.get("source")},
                "value": e["value"], "value_f32_be": e["value_f32_be"], "seq": e["seq"],
                "generation": e["generation"], "model_sha256": e["model_sha256"], "signature": e["sig"],
                "unit_binding": e["unit"], "chain": e["chain"], "cursor": e["cursor"], "rx_wall": e["rx_wall"],
            }, sort_keys=True))
        state.setdefault("cursors", {})[lid] = L["cursor"]
    state["epoch"] = answer.get("epoch")
    return lines


def shim(control: str, out: str, state_path: str | None, poll: float, once: bool, leaf: str | None):
    state: dict = {}
    if state_path and os.path.exists(state_path):
        try:
            with open(state_path) as fh:
                state = json.load(fh)
        except ValueError:
            state = {}
    sink = None
    while True:
        req = {"op": "sense", "since": state.get("cursors", {}), "epoch": state.get("epoch"), "limit": 500}
        if leaf:
            req["leaf"] = leaf
        ans = control_call(control, req)
        if not ans.get("ok"):
            print(json.dumps({"shim": "refused", "answer": ans}), file=sys.stderr, flush=True)
        else:
            lines = shim_lines(ans, state)
            if lines:
                text = "\n".join(lines) + "\n"
                if out == "-":
                    sys.stdout.write(text)
                    sys.stdout.flush()
                elif out.startswith("unix:"):
                    sink = socket.socket(socket.AF_UNIX)
                    sink.connect(out[5:])
                    sink.sendall(text.encode())
                    sink.close()
                else:
                    with open(out, "a") as fh:
                        fh.write(text)
            if state_path:  # saved after the lines are written: a crash repeats, never skips
                tmp = state_path + ".tmp"
                with open(tmp, "w") as fh:
                    json.dump(state, fh)
                os.replace(tmp, state_path)
        if once:
            return state
        time.sleep(poll)
