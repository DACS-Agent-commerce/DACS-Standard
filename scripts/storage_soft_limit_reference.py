"""DACS storage soft limit: producer packaging for Demos Storage Programs.

DACS-4 §9.6.1 and DACS-5 §10.4.2 apply a 128 KB soft limit, stricter than
the 1,048,576-byte substrate cap (DEMOS-MAPPING §A.2).  The limit is
131,072 bytes, measured over the exact payload bytes: raw bytes as given, or
the UTF-8 bytes of the RFC 8785 canonical form of a JSON value.  A payload of
exactly 131,072 bytes is stored directly; one byte more needs the
extended-pointer pattern.
"""

from __future__ import annotations

import hashlib
from typing import Any

try:
    from scripts.jcs import canonicalize
except ImportError:  # pragma: no cover - direct script execution
    from jcs import canonicalize

SOFT_LIMIT_BYTES = 128 * 1024


def payload_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return canonicalize(value).encode("utf-8")


def fits_soft_limit(value: Any) -> bool:
    return len(payload_bytes(value)) <= SOFT_LIMIT_BYTES


def package_deliverable(payload: Any, external_url: str) -> dict:
    """DACS-4 §9.6.1: store directly, or anchor an extended-pointer record."""
    data = payload_bytes(payload)
    if len(data) <= SOFT_LIMIT_BYTES:
        return {"kind": "direct", "payload": data}
    return {
        "kind": "extended-pointer",
        "record": {
            "externalUrl": external_url,
            "externalContentHash": hashlib.sha256(data).hexdigest(),
        },
    }


def package_bundle(bundle: dict, full_bundle_url: str) -> dict:
    """DACS-5 §10.4.2: anchor the bundle, or its unsigned BundleExtendedPointer scope."""
    data = payload_bytes(bundle)
    if len(data) <= SOFT_LIMIT_BYTES:
        return {"kind": "direct", "payload": data}
    return {
        "kind": "extended-pointer",
        "record": {
            "bundleVersion": "1",
            "pointerKind": "extended",
            "fullBundleUrl": full_bundle_url,
            "fullBundleContentHash": hashlib.sha256(data).hexdigest(),
        },
    }
