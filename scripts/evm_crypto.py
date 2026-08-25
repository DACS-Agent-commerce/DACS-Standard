"""Small deterministic EVM helpers used by committed conformance vectors.

The module deliberately has no Web3 dependency: CI needs only ``cryptography``.
It implements legacy Keccak-256 (not FIPS SHA3-256), EVM address derivation,
and RFC 6979 ECDSA so generated vector bytes remain reproducible.
"""
from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_MASK64 = (1 << 64) - 1
_ROTATION = (
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
)
_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
)


def _rotl64(value: int, count: int) -> int:
    if count == 0:
        return value & _MASK64
    return ((value << count) | (value >> (64 - count))) & _MASK64


def _keccak_f1600(state: list[int]) -> None:
    for constant in _ROUND_CONSTANTS:
        columns = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        for x in range(5):
            delta = columns[(x - 1) % 5] ^ _rotl64(columns[(x + 1) % 5], 1)
            for y in range(5):
                state[x + 5 * y] ^= delta

        rotated = [0] * 25
        for x in range(5):
            for y in range(5):
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(
                    state[x + 5 * y], _ROTATION[x + 5 * y]
                )

        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = rotated[x + 5 * y] ^ (
                    (~rotated[(x + 1) % 5 + 5 * y])
                    & rotated[(x + 2) % 5 + 5 * y]
                )
                state[x + 5 * y] &= _MASK64
        state[0] ^= constant


def keccak256(data: bytes) -> bytes:
    """Return the pre-FIPS Keccak-256 digest used by EVM addresses."""

    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(b"\x00" * ((rate - len(padded) % rate - 1) % rate))
    padded.append(0x80)
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for lane in range(rate // 8):
            state[lane] ^= int.from_bytes(block[lane * 8:(lane + 1) * 8], "little")
        _keccak_f1600(state)
    return b"".join(value.to_bytes(8, "little") for value in state)[:32]


def uncompressed_public_key(private_scalar: int) -> bytes:
    if not 1 <= private_scalar < SECP256K1_ORDER:
        raise ValueError("invalid secp256k1 private scalar")
    numbers = ec.derive_private_key(private_scalar, ec.SECP256K1()).public_key().public_numbers()
    return b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")


def evm_address(public_key: bytes) -> str:
    if len(public_key) != 65 or public_key[0] != 4:
        raise ValueError("expected uncompressed secp256k1 public key")
    return "0x" + keccak256(public_key[1:])[-20:].hex()


def _rfc6979_nonce(private_scalar: int, message_hash: bytes) -> int:
    scalar = private_scalar.to_bytes(32, "big")
    reduced_hash = (int.from_bytes(message_hash, "big") % SECP256K1_ORDER).to_bytes(32, "big")
    k = b"\x00" * 32
    v = b"\x01" * 32
    k = hmac.new(k, v + b"\x00" + scalar + reduced_hash, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + scalar + reduced_hash, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < SECP256K1_ORDER:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def deterministic_ecdsa_sha256(private_scalar: int, payload: bytes) -> bytes:
    """Create a low-S, DER-encoded secp256k1 signature deterministically."""

    message_hash = hashlib.sha256(payload).digest()
    nonce = _rfc6979_nonce(private_scalar, message_hash)
    r = ec.derive_private_key(nonce, ec.SECP256K1()).public_key().public_numbers().x
    r %= SECP256K1_ORDER
    if r == 0:
        raise ValueError("invalid deterministic ECDSA nonce")
    z = int.from_bytes(message_hash, "big")
    s = (pow(nonce, -1, SECP256K1_ORDER) * (z + r * private_scalar)) % SECP256K1_ORDER
    if s == 0:
        raise ValueError("invalid deterministic ECDSA signature")
    if s > SECP256K1_ORDER // 2:
        s = SECP256K1_ORDER - s
    return encode_dss_signature(r, s)
