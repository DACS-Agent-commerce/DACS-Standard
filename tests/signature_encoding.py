"""Shared signature-value encoding checks for the test oracles.

The canonical channel-message oracle (``test_channel_message_vectors``) and the
cross-corpus consistency test (``test_signature_vector_consistency``) share the
SIG-6 decoder and the ECDSA format check below.  A defect has one of two
stages, which decide the verdicts a case may expect:

* ``wire`` — CORE §B.7 SIG-6, every algorithm: the value is not unpadded
  RFC 4648 §5 Base64URL whose decoded bytes re-encode to exactly the same
  string.  Every verifier finds this before any algorithm or key question.
* ``format`` — the decoded bytes are not the algorithm's signature format.
  CORE §B.7 leaves "decoded length and internal signature format"
  algorithm-specific and requires a verifier to validate them; it does not
  name the formats.  The formats checked here are the ones this repository
  pins:

  * ``ed25519``: 64 raw bytes (RFC 8032 §5.1.6), as the
    ``signature-value-encoding-v0.1`` corpus pins;
  * ``ecdsa-secp256k1``: canonical DER ``SEQUENCE {r, s}`` with
    ``1 <= r < n`` and low-S ``1 <= s <= n/2`` (n from SEC 2 §2.4.1), the
    profile the channel corpus pins in its authenticated key fixture
    (``signatureEncoding: canonical-DER-low-S``).  No spec text states it for
    every envelope yet; open PR #426 proposes that §B.7 text.  A 64-byte
    fixed-width ``r || s`` value is not DER and is a format defect;
  * ``sr1-aggregate``: the SR-1 aggregate format is substrate-defined, so only
    the wire stage is checked.  (The channel oracle verifies its own
    ``sr1-aggregate`` fixture as a 64-byte Ed25519 signature; that is the
    channel corpus's fixture model, not an SR-1 format rule.)
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
WIRE = "wire"
FORMAT = "format"
# Signature-envelope type members such as
#   algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"
# including `algorithm?:` and unions continued on following `|` lines.
ALGORITHM_MEMBER = re.compile(r"^\s*algorithm\??\s*:(.*)$")
UNION_CONTINUATION = re.compile(r"^\s*\|")
STRING_LITERAL = re.compile(r'"([^"]+)"')


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


def signature_value_defect(algorithm, value):
    """Return ``(stage, reason)`` for a defective ``value``, else ``None``.

    ``stage`` is ``WIRE`` (SIG-6 spelling) or ``FORMAT`` (decoded bytes are
    not ``algorithm``'s pinned signature format).
    """
    if algorithm not in CHECKED_ALGORITHMS:
        raise ValueError("no signature value checker for %r" % (algorithm,))
    try:
        raw = decode_b64url(value)
    except ValueError as exc:
        return WIRE, "SIG-6: %s" % exc
    if algorithm == "ed25519" and len(raw) != ED25519_SIGNATURE_BYTES:
        return FORMAT, "ed25519 value decodes to %d bytes, not 64" % len(raw)
    if algorithm == "ecdsa-secp256k1":
        violation = ecdsa_secp256k1_format_violation(raw)
        if violation is not None:
            return FORMAT, "ecdsa-secp256k1 value: %s" % violation
    return None


def algorithm_unions(text):
    """Yield the literal set of every ``algorithm`` type member in ``text``.

    Raises ``ValueError`` for an ``algorithm`` member whose type is not a union
    of string literals, so a registration this parser cannot read fails
    instead of silently registering nothing.
    """
    lines = text.splitlines()
    for number, line in enumerate(lines):
        match = ALGORITHM_MEMBER.match(line)
        if match is None:
            continue
        union = [match.group(1)]
        for following in lines[number + 1:]:
            if not UNION_CONTINUATION.match(following):
                break
            union.append(following)
        joined = " ".join(union).strip().rstrip(";,").strip()
        literals = STRING_LITERAL.findall(joined)
        if not literals or re.sub(r'"[^"]+"|\|', "", joined).strip():
            raise ValueError(
                "line %d: cannot read the algorithm member %r" % (number + 1, line.strip())
            )
        yield frozenset(literals)


def registered_signature_algorithms(root=ROOT):
    """Union of every ``algorithm`` envelope enum in the published spec."""
    found = set()
    for path in sorted((root / "spec").glob("*.md")):
        try:
            for union in algorithm_unions(path.read_text(encoding="utf-8")):
                found.update(union)
        except ValueError as exc:
            raise ValueError("%s: %s" % (path.name, exc)) from None
    return frozenset(found)
