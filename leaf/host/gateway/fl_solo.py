"""Solo manifests: which models a leaf may run, signed by the operator.

A manifest says, for one leaf, the model hashes its readings may come from and whether a reading with no model is
allowed. The head enforces it (fl_sense.model_permitted); this module is the format and the signature check.

The manifest is signed by an operator key the head has pinned, the same kind of key a leaf pins for grants (ECDSA
P-256). The signature is DER ECDSA over SHA-256 of `signing_bytes(manifest)`. A manifest is bound to one leaf id, so it
cannot be moved to another leaf, carries a generation, and may carry an expiry (`not_after`, Unix seconds): an expired
manifest allows nothing. Everything except `verify` is standard library, so the signing side (a machine with the
operator key and no `cryptography` package) can import this file.

Limit: the head keeps no memory of the highest generation it has seen, so an older, still validly signed manifest
that has not expired is accepted if it is put back. Use `not_after` to bound that.
"""

from __future__ import annotations

import json

DOMAIN = b"furcate/solo/manifest/v1"
HEX64 = set("0123456789abcdef")


def make(leaf_id: str, models, generation: int, allow_no_model: bool = False, not_after=None) -> dict:
    """-> a manifest dict. Raises ValueError for anything malformed; never repairs input."""
    leaf = leaf_id.lower()
    bytes.fromhex(leaf)
    if len(leaf) < 32:
        raise ValueError("a leaf id is at least 16 bytes (32 hex digits)")
    ms = sorted({m.lower() for m in models})
    for m in ms:
        if len(m) != 64 or not set(m) <= HEX64:
            raise ValueError("a model hash is 64 hex digits: %r" % m)
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
        raise ValueError("generation is a non-negative integer")
    if not_after is not None and (isinstance(not_after, bool) or not isinstance(not_after, int)):
        raise ValueError("not_after is Unix seconds or null")
    return {"v": 1, "leaf_id": leaf, "models": ms, "allow_no_model": bool(allow_no_model),
            "generation": generation, "not_after": not_after}


def signing_bytes(m: dict) -> bytes:
    """The exact bytes the operator signs: the domain, then the canonical JSON of the manifest."""
    return DOMAIN + json.dumps(m, sort_keys=True, separators=(",", ":")).encode()


def verify(doc: dict, operator_keys) -> dict:
    """doc = {"manifest": {...}, "sig": "<DER hex>"}; operator_keys = list of 65-byte uncompressed P-256 points (bytes).
    -> the manifest when the signature verifies under one of the keys. Raises ValueError otherwise."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        m = make(doc["manifest"]["leaf_id"], doc["manifest"]["models"], doc["manifest"]["generation"],
                 doc["manifest"].get("allow_no_model", False), doc["manifest"].get("not_after"))
        if doc["manifest"] != m:  # canonical form only: no extra fields, no reordering of meaning
            raise ValueError("manifest is not in canonical form")
        sig = bytes.fromhex(doc["sig"])
    except (KeyError, TypeError, AttributeError) as e:
        raise ValueError("malformed manifest document: %r" % e)
    data = signing_bytes(m)
    for k in operator_keys:
        try:
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), k)
            key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
            return m
        except Exception:
            continue
    raise ValueError("signature does not verify under any pinned operator key")
