"""Shared CORE §B.7 signature-value encoding checks for the test oracles.

One implementation of the SIG-6 wire spelling and of the algorithm-specific
value formats this repository pins, used by the canonical channel-message
oracle (``test_channel_message_vectors.verify_algorithm``) and by the
cross-corpus consistency test (``test_signature_vector_consistency``).

* SIG-6 (every algorithm): unpadded RFC 4648 §5 Base64URL whose decoded bytes
  re-encode to exactly the same string.
* ``ed25519``: 64 raw bytes (RFC 8032), as pinned by the
  ``signature-value-encoding-v0.1`` corpus.
* ``ecdsa-secp256k1``: canonical DER ``SEQUENCE {r, s}`` with
  ``1 <= r < n`` and low-S ``1 <= s <= n/2``, as pinned by the channel corpus
  (``signatureEncoding: canonical-DER-low-S``).  A 64-byte fixed-width
  ``r || s`` value is not DER and is rejected.
* ``sr1-aggregate``: the SR-1 aggregate format is substrate-defined, so only
  the SIG-6 wire spelling is checked here.
"""
from __future__ import annotations

import base64
import re
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import utils


ROOT = Path(__file__).resolve().parents[1]
BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ED25519_SIGNATURE_BYTES = 64
CHECKED_ALGORITHMS = frozenset({"ed25519", "ecdsa-secp256k1", "sr1-aggregate"})
# Signature-envelope type lines such as
#   algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"
ALGORITHM_UNION = re.compile(r'^\s*algorithm:\s*("[^"]+"(?:\s*\|\s*"[^"]+")*)', re.M)


def decode_b64url(value):
    """Decode a SIG-6 value, raising ``ValueError`` for any other spelling."""
    if not isinstance(value, str) or not value or not BASE64URL.fullmatch(value):
        raise ValueError("not unpadded Base64URL")
    if len(value) % 4 == 1:
        raise ValueError("impossible Base64URL length")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ValueError("non-canonical Base64URL")
    return raw


def ecdsa_secp256k1_format_violation(signature):
    """Return why raw ECDSA bytes are not canonical DER low-S, else ``None``."""
    try:
        r, s = utils.decode_dss_signature(signature)
    except ValueError:
        return "%d raw bytes are not a DER signature" % len(signature)
    if utils.encode_dss_signature(r, s) != signature:
        return "DER encoding is not canonical"
    if not 1 <= r < SECP256K1_ORDER:
        return "r is outside [1, n)"
    if not 1 <= s <= SECP256K1_ORDER // 2:
        return "s is not low-S"
    return None


def signature_value_violation(algorithm, value):
    """Return why ``value`` breaks CORE §B.7 for ``algorithm``, else ``None``."""
    if algorithm not in CHECKED_ALGORITHMS:
        raise ValueError("no CORE §B.7 value checker for %r" % (algorithm,))
    try:
        raw = decode_b64url(value)
    except ValueError as exc:
        return "SIG-6: %s" % exc
    if algorithm == "ed25519" and len(raw) != ED25519_SIGNATURE_BYTES:
        return "ed25519 value decodes to %d bytes, not 64" % len(raw)
    if algorithm == "ecdsa-secp256k1":
        violation = ecdsa_secp256k1_format_violation(raw)
        if violation is not None:
            return "ecdsa-secp256k1 value: %s" % violation
    return None


def registered_signature_algorithms(root=ROOT):
    """Union of every ``algorithm:`` envelope enum in the published spec."""
    found = set()
    for path in sorted((root / "spec").glob("*.md")):
        for union in ALGORITHM_UNION.findall(path.read_text(encoding="utf-8")):
            found.update(re.findall(r'"([^"]+)"', union))
    return frozenset(found)
