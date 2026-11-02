"""Deterministic secp256k1 fixture signatures in the CORE §B.7 encoding.

A fixture that labels a signature ``ecdsa-secp256k1`` must carry a value that
encoding, not relabelled Ed25519 bytes: §B.7 rejects a 64-byte ``r || s``
before any key is consulted, so a relabelled value turns an ``unavailable``
case into an encoding ``fail`` for a verifier that implements the algorithm.
"""
from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import ec, utils

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def fixture_private_value(label: bytes) -> int:
    return (int.from_bytes(hashlib.sha256(label).digest(), "big") % (SECP256K1_ORDER - 1)) + 1


def deterministic_ecdsa_signature(private_value: int, payload: bytes) -> bytes:
    """RFC 6979 secp256k1/SHA-256 with canonical DER and low-S output."""

    digest_bytes = hashlib.sha256(payload).digest()
    private_bytes = private_value.to_bytes(32, "big")
    reduced_hash = (int.from_bytes(digest_bytes, "big") % SECP256K1_ORDER).to_bytes(32, "big")
    value = b"\x01" * 32
    key = b"\x00" * 32
    key = hmac.new(key, value + b"\x00" + private_bytes + reduced_hash, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    key = hmac.new(key, value + b"\x01" + private_bytes + reduced_hash, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    while True:
        value = hmac.new(key, value, hashlib.sha256).digest()
        nonce = int.from_bytes(value, "big")
        if 1 <= nonce < SECP256K1_ORDER:
            break
        key = hmac.new(key, value + b"\x00", hashlib.sha256).digest()
        value = hmac.new(key, value, hashlib.sha256).digest()
    point = ec.derive_private_key(nonce, ec.SECP256K1()).public_key().public_numbers()
    r = point.x % SECP256K1_ORDER
    z = int.from_bytes(digest_bytes, "big")
    s = (pow(nonce, -1, SECP256K1_ORDER) * (z + r * private_value)) % SECP256K1_ORDER
    s = min(s, SECP256K1_ORDER - s)
    return utils.encode_dss_signature(r, s)
