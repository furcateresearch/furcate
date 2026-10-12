#!/usr/bin/env python3
"""Tests for the reference client: the canonical request, the key and
signature spellings, and the credential's shape. Run from anywhere:
python3 -I docs/clients/test_furcate_leaf_request.py"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import furcate_leaf_request as flr  # noqa: E402

BODY = b'{"model":"qwen3-0.6b","messages":[{"role":"user","content":"ok"}],"max_tokens":8}'

# The P-256 base point: a curve constant, used here only as a point to spell.
GX = bytes.fromhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
GY = bytes.fromhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")


def der(r, s):
    def i(v):
        b = v.to_bytes((v.bit_length() + 8) // 8, "big")
        return b"\x02" + bytes([len(b)]) + b
    body = i(r) + i(s)
    return b"\x30" + bytes([len(body)]) + body


class Canonical(unittest.TestCase):
    def test_matches_the_gateways_vector(self):
        # The same vector as furcate_topology::leaf_request's test.
        self.assertEqual(
            flr.canonical("post", "/v1/chat/completions", BODY, "n-00000001", 1791800060),
            b"furcate-request/1\nPOST\n/v1/chat/completions\n"
            b"7c8a1c1aca564a14f4af1c3b9b3761486bfae7f819c920489c632e929c36b0d5\n"
            b"n-00000001\n1791800060\n",
        )

    def test_empty_body(self):
        self.assertIn(b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", flr.canonical("GET", "/v1/models", b"", "abcdefgh", 1))


class Spellings(unittest.TestCase):
    def test_holder_is_the_compressed_point(self):
        want = "p256:03" + GX.hex()
        self.assertEqual(flr.holder_from_point(b"\x04" + GX + GY), want)
        self.assertEqual(flr.holder_from_point(flr._SPKI_PREFIX + b"\x04" + GX + GY), want)
        self.assertEqual(flr.holder_from_point(bytes.fromhex(want[5:])), want)
        with self.assertRaises(ValueError):
            flr.holder_from_point(b"\x04" + GX)

    def test_signature_is_raw_low_s_whatever_the_signer_gave(self):
        r, s = 12345, flr._N - 7
        raw = flr.raw_signature(der(r, s))
        self.assertEqual(len(raw), 64)
        self.assertEqual(int.from_bytes(raw[:32], "big"), r)
        self.assertEqual(int.from_bytes(raw[32:], "big"), 7)
        self.assertEqual(flr.raw_signature(raw), raw)
        with self.assertRaises(ValueError):
            flr.raw_signature(der(r, s)[:-1])


class Credential(unittest.TestCase):
    def test_shape_and_what_is_signed(self):
        seen = []

        def sign(m):
            seen.append(m)
            return (1).to_bytes(32, "big") + (2).to_bytes(32, "big")

        holder = "p256:03" + GX.hex()
        c = flr.credential(holder, "POST", "/v1/chat/completions", BODY, sign, nonce="n-00000001", expires_at=1791800060)
        self.assertEqual(seen, [flr.canonical("POST", "/v1/chat/completions", BODY, "n-00000001", 1791800060)])
        self.assertEqual(c, f"leaf:{holder}:n-00000001.1791800060." + "00" * 31 + "01" + "00" * 31 + "02")

    def test_default_expiry_and_nonce(self):
        c = flr.credential("p256:03" + GX.hex(), "GET", "/v1/models", b"", lambda m: b"\x01" * 64, now=1000)
        nonce, exp, _ = c.rsplit(":", 1)[1].split(".")
        self.assertEqual(int(exp), 1060)
        self.assertTrue(flr.NONCE_MIN <= len(nonce) <= flr.NONCE_MAX)

    def test_bad_nonce_is_refused(self):
        for n in ["short", "has.dot", "x" * 65, "has:colon"]:
            with self.assertRaises(ValueError):
                flr.credential("p256:03" + GX.hex(), "GET", "/v1/models", b"", lambda m: b"\x01" * 64, nonce=n)


if __name__ == "__main__":
    unittest.main()
