"""Node side of the Furcate leaf protocol (mirror of components/fl_core).

Wire: one type byte, then TLV fields (tag u8, length u16 BE, value).
Frames: "FL1:" + base64(message) + "\\n" on the serial console, or on the
TCP connection the leaf dials out to its controller (listen://HOST:PORT).

The node's long-term key never touches this process: every signature is
made by the Secure Enclave (macOS) or TPM through the `fl-se` helper.
Only the per-session ephemeral ECDH key exists in memory here.
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
import subprocess
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# message types
HELLO, AUTH, FINISH, REFUSE, SEALED = 0x01, 0x02, 0x03, 0x04, 0x10
INFO_REQ, INFO, RESULT = 0x20, 0x21, 0x22
MODEL_OFFER, MODEL_CHUNK, MODEL_COMMIT, MODEL_ROLLBACK = 0x30, 0x31, 0x32, 0x33
INFER, INFER_RESULT = 0x40, 0x41
OTA_OFFER, OTA_CHUNK, OTA_COMMIT = 0x50, 0x51, 0x52
REVOKE, CONFIG, SINK, BYE = 0x60, 0x61, 0x70, 0x7F
ROLLOVER_REQ, ROLLOVER = 0x62, 0x63
GATEWAY_ASK = 0x71
SENSE_REQ, SENSE = 0x72, 0x73

# tags
T_VERSION, T_DEV_PUB, T_EPH, T_NONCE, T_EVIDENCE = 1, 2, 3, 4, 5
T_NODE_PUB, T_GRANT, T_GRANT_SIG, T_NODE_SIG, T_DEV_SIG = 6, 7, 8, 9, 10
T_REASON, T_OK, T_COUNTER, T_BOX = 11, 12, 13, 14
T_SIGNED, T_OFFSET, T_DATA, T_INPUT, T_SCORES, T_LATENCY_US, T_LABEL, T_DETAIL = 20, 21, 22, 23, 24, 25, 26, 27
T_ROLE_NEEDED, T_QPARAMS, T_BODY, T_SIG = 28, 29, 30, 31
T_METHOD, T_TARGET, T_STATUS, T_CREDENTIAL = 32, 33, 34, 35
T_ROLL_SEQ, T_NOT_BEFORE, T_NOT_AFTER, T_RECORD = 36, 37, 38, 39
# sensor replies (fl_sensors.c)
T_READING, T_GENERATION, T_MODEL_SHA, T_SIGNER_ID, T_CHAIN, T_UNIT, T_SENSOR = 80, 81, 82, 83, 85, 86, 90

# manifest tags
M = dict(KIND=1, ID=2, VERSION=3, SIZE=4, SHA256=5, RUNTIME=6, RUNTIME_MIN=7, TARGET=8, ARENA_KB=9,
         NEEDS_PSRAM=10, INPUT=11, LABELS=12, PRE=13, POST=14, ST_SEED=15, ST_EXPECT=16, POLICY=17,
         LICENCE=18, OPS=19, ST_TOL=20)

ROLES = dict(read=1, command=2, model=4, config=8, ota=16)


def tlv(tag: int, value: bytes | str | int, size: int | None = None) -> bytes:
    if isinstance(value, str):
        value = value.encode()
    elif isinstance(value, int):
        value = value.to_bytes(size or 4, "big")
    return bytes([tag]) + len(value).to_bytes(2, "big") + value


def msg(mtype: int, *fields: bytes) -> bytes:
    return bytes([mtype]) + b"".join(fields)


def parse(body: bytes) -> dict[int, list[bytes]]:
    out: dict[int, list[bytes]] = {}
    i = 0
    while i + 3 <= len(body):
        tag = body[i]
        n = int.from_bytes(body[i + 1:i + 3], "big")
        out.setdefault(tag, []).append(body[i + 3:i + 3 + n])
        i += 3 + n
    return out


def one(f: dict[int, list[bytes]], tag: int, default: bytes | None = None) -> bytes | None:
    v = f.get(tag)
    return v[0] if v else default


def u(b: bytes | None) -> int | None:
    return None if b is None else int.from_bytes(b, "big")


# ---- hardware-held keys -------------------------------------------------

FL_SE = os.environ.get("FL_SE", "fl-se")


def se_pub(name: str) -> bytes:
    return bytes.fromhex(subprocess.check_output([FL_SE, "pub", name], text=True).strip())


def se_sign(name: str, data: bytes) -> bytes:
    """DER ECDSA P-256 over SHA-256(data), made inside the Secure Enclave."""
    return bytes.fromhex(subprocess.check_output([FL_SE, "sign", name], input=data).decode().strip())


def verify_raw(pub: bytes, digest_input: bytes, sig: bytes) -> bool:
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    try:
        # The leaf signs a SHA-256 digest it computed itself.
        key.verify(der, hashlib.sha256(digest_input).digest(), ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except Exception:
        return False


# ---- grants, manifests ---------------------------------------------------

def make_grant(node_pub: bytes, roles: int, generation: int, leaf_id: bytes = bytes(32)) -> bytes:
    return b"FLG1" + node_pub + bytes([roles]) + generation.to_bytes(4, "big") + leaf_id


def envelope(body: bytes, signatures: list[tuple[int, bytes]]) -> bytes:
    return tlv(T_BODY, body) + b"".join(tlv(T_SIG, bytes([i]) + s) for i, s in signatures)


# ---- serial link --------------------------------------------------------

class _Tcp:
    """A byte stream to a relay (host/fl_relay.py) that carries the leaf's serial
    console. The relay only moves bytes; every signature is made here."""

    def __init__(self, url: str):
        import socket
        host, port = url[len("tcp://"):].rsplit(":", 1)
        self.k = socket.create_connection((host, int(port)))
        self.k.settimeout(0.05)

    def read(self, n: int) -> bytes:
        import socket
        try:
            d = self.k.recv(n)
        except socket.timeout:
            return b""
        if d == b"":
            raise ConnectionError("relay closed")
        return d

    def write(self, b: bytes):
        self.k.sendall(b)


class _Listen:
    """The controller end of the leaf's Wi-Fi link. The leaf dials out to this
    address; the controller never connects to the leaf. A redial replaces the
    previous connection."""

    def __init__(self, url: str):
        import socket
        host, port = url[len("listen://"):].rsplit(":", 1)
        self.srv = socket.create_server((host, int(port)))
        self.srv.setblocking(False)
        self.k = None
        self.peer = None
        self.accepts = 0

    def _poll_accept(self, wait: float):
        import select
        import socket
        r, _, _ = select.select([self.srv], [], [], wait)
        if not r:
            return
        k, peer = self.srv.accept()
        if self.k is not None:
            self.k.close()
        k.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        k.settimeout(0.05)
        self.k, self.peer = k, peer
        self.accepts += 1

    def read(self, n: int) -> bytes:
        import socket
        self._poll_accept(0 if self.k is not None else 0.05)
        if self.k is None:
            return b""
        try:
            d = self.k.recv(n)
        except socket.timeout:
            return b""
        except OSError:
            d = b""
        if d == b"":
            self.k.close()
            self.k = None
        return d

    def write(self, b: bytes):
        if self.k is None:
            raise ConnectionError("the leaf is not connected")
        self.k.sendall(b)


class _Conn:
    """One accepted leaf connection, read and written like the other streams."""

    def __init__(self, k, peer):
        import socket
        k.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        k.settimeout(0.05)
        self.k, self.peer, self.closed = k, peer, False

    def read(self, n: int) -> bytes:
        import socket
        if self.closed:
            return b""
        try:
            d = self.k.recv(n)
        except socket.timeout:
            return b""
        except OSError:
            d = b""
        if d == b"":
            self.close()
        return d

    def write(self, b: bytes):
        if self.closed:
            raise ConnectionError("the leaf is not connected")
        try:
            self.k.sendall(b)
        except OSError as e:
            self.close()
            raise ConnectionError(str(e)) from None

    def close(self):
        self.closed = True
        try:
            self.k.close()
        except OSError:
            pass


class _Hub:
    """A listening address that keeps every leaf that dials in, one connection
    each. Which leaf a connection is only becomes known from its HELLO."""

    def __init__(self, url: str):
        import socket
        host, port = url[len("listen://"):].rsplit(":", 1)
        self.srv = socket.create_server((host, int(port)))
        self.srv.setblocking(False)
        self.accepts = 0

    def poll(self, wait: float = 0.0) -> list:
        import select
        out = []
        while True:
            r, _, _ = select.select([self.srv], [], [], wait if not out else 0)
            if not r:
                return out
            k, peer = self.srv.accept()
            self.accepts += 1
            out.append(_Conn(k, peer))


class Serial:
    def __init__(self, port: str, baud: int = 115200, log=None):
        if port.startswith("tcp://"):
            self.s = _Tcp(port)
        elif port.startswith("listen://"):
            self.s = _Listen(port)
        else:
            import serial  # pyserial
            self.s = serial.Serial(port, baud, timeout=0.05)
        self.buf = b""
        self.log = log or (lambda line: None)
        self.lines: list[str] = []
        self.sent: list[bytes] = []  # raw frames as sent, for replay tests

    @classmethod
    def over(cls, stream, log=None) -> "Serial":
        """A framed link over an already open stream (a _Conn)."""
        o = cls.__new__(cls)
        o.s, o.buf, o.log, o.lines, o.sent = stream, b"", log or (lambda line: None), [], []
        return o

    def reset(self, hold_s: float = 0.2):
        """Pulse EN (RTS) with GPIO0 high (DTR), as the dev board's auto-reset wires them."""
        self.s.dtr = False
        self.s.rts = True
        time.sleep(hold_s)
        self.s.rts = False

    def send(self, m: bytes):
        self.sent.append(m)
        self.s.write(b"FL1:" + base64.b64encode(m) + b"\n")

    def recv(self, timeout: float) -> bytes | None:
        end = time.time() + timeout
        while time.time() < end:
            nl = self.buf.find(b"\n")
            if nl < 0:
                self.buf += self.s.read(4096)
                continue
            line, self.buf = self.buf[:nl].rstrip(b"\r"), self.buf[nl + 1:]
            if line.startswith(b"FL1:"):
                try:
                    return base64.b64decode(line[4:], validate=True)
                except Exception:
                    continue
            text = line.decode(errors="replace")
            self.lines.append(text)
            self.log(text)
        return None


class Refused(Exception):
    pass


@dataclass
class Session:
    link: Serial
    k_tx: bytes = b""
    k_rx: bytes = b""
    c_tx: int = 0
    c_rx: int = 0
    leaf_pub: bytes = b""
    evidence: dict = field(default_factory=dict)
    timings: dict = field(default_factory=dict)

    @property
    def leaf_id(self) -> bytes:
        return hashlib.sha256(self.leaf_pub).digest()

    @classmethod
    def open(cls, link: Serial, node_key: str, grant, grant_sig: bytes | None = None,
             expect_leaf: bytes | None = None, wait: float = 30.0) -> "Session":
        """Waits for the leaf's HELLO (the leaf always initiates), then authenticates.

        `grant` is the grant bytes with `grant_sig`, or a function taking the leaf's public
        key and returning (grant, grant_sig), or raising Refused for a leaf it does not
        enrol; it runs before anything is sent to the leaf."""
        # The leaf accepts an AUTH only within a few seconds of the HELLO it
        # answers, and every HELLO carries a fresh ephemeral key and nonce.
        # So: everything that does not depend on the HELLO is done first, any
        # HELLO already queued is discarded, and the next fresh one is answered.
        node_pub = se_pub(node_key)
        eph = ec.generate_private_key(ec.SECP256R1())
        eph_pub = eph.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        while link.recv(0.3) is not None:
            pass
        link.buf = b""
        end = time.time() + wait
        hello = None
        while time.time() < end:
            m = link.recv(1.0)
            if m and m[0] == HELLO:
                hello = m
                break
        if hello is None:
            raise TimeoutError("no HELLO from the leaf")
        f = parse(hello[1:])
        leaf_pub, leaf_eph, ev = one(f, T_DEV_PUB), one(f, T_EPH), one(f, T_EVIDENCE)
        # The enrolled id may be the full SHA-256 of the leaf key or the
        # 16-byte prefix the leaf reports in INFO.
        if expect_leaf is not None and (len(expect_leaf) < 16 or
                                        hashlib.sha256(leaf_pub).digest()[:len(expect_leaf)] != expect_leaf):
            raise Refused("leaf identity does not match the enrolled one")
        if callable(grant):
            grant, grant_sig = grant(leaf_pub)
        t0 = time.time()
        th = hashlib.sha256(b"FL1 transcript" + hello + node_pub + eph_pub + grant).digest()
        node_sig = se_sign(node_key, b"FL1 node auth " + th)  # enclave hashes, then signs
        auth = msg(AUTH, tlv(T_NODE_PUB, node_pub), tlv(T_EPH, eph_pub), tlv(T_GRANT, grant),
                   tlv(T_GRANT_SIG, grant_sig), tlv(T_NODE_SIG, node_sig))
        link.send(auth)
        t_sent = time.time()
        while True:
            r = link.recv(max(0.1, t_sent + 20 - time.time()))
            if r is None:
                raise TimeoutError("leaf did not finish the handshake")
            if r[0] == REFUSE:
                raise Refused(one(parse(r[1:]), T_REASON, b"").decode())
            if r[0] == FINISH:
                break
            if r[0] == HELLO:  # a HELLO that crossed our AUTH; keep waiting for the answer
                continue
        dev_sig = one(parse(r[1:]), T_DEV_SIG)
        if not verify_raw(leaf_pub, b"FL1 leaf auth " + th + node_sig[:72], dev_sig):
            raise Refused("leaf signature does not verify")
        shared = eph.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), leaf_eph))
        k = lambda info: HKDF(algorithm=hashes.SHA256(), length=32, salt=th, info=info).derive(shared)
        s = cls(link, k_tx=k(b"FL1 node to leaf"), k_rx=k(b"FL1 leaf to node"), leaf_pub=leaf_pub)
        s.evidence = parse(ev)
        s.timings["handshake_s"] = time.time() - t0
        s.timings["leaf_side_s"] = time.time() - t_sent
        return s

    @staticmethod
    def _nonce(c: int, d: bytes) -> bytes:
        return d + b"\0\0\0" + c.to_bytes(8, "big")

    def send(self, mtype: int, *fields: bytes):
        plain = msg(mtype, *fields)
        box = AESGCM(self.k_tx).encrypt(self._nonce(self.c_tx, b"N"), plain, None)
        self.link.send(msg(SEALED, tlv(T_COUNTER, self.c_tx), tlv(T_BOX, box)))
        self.c_tx += 1

    def call(self, mtype: int, *fields: bytes, timeout: float = 30.0) -> tuple[int, dict]:
        self.send(mtype, *fields)
        if mtype == BYE:
            return 0, {}
        return self.reply(mtype, timeout)

    def reply(self, mtype: int = 0, timeout: float = 30.0) -> tuple[int, dict]:
        end = time.time() + timeout
        while time.time() < end:
            r = self.link.recv(max(0.05, end - time.time()))
            if r is None:
                break
            if r[0] != SEALED:
                continue
            f = parse(r[1:])
            ctr = u(one(f, T_COUNTER))
            if ctr != self.c_rx:
                continue
            pt = AESGCM(self.k_rx).decrypt(self._nonce(self.c_rx, b"L"), one(f, T_BOX), None)
            self.c_rx += 1
            return pt[0], parse(pt[1:])
        raise TimeoutError(f"no reply to command 0x{mtype:02x}")
