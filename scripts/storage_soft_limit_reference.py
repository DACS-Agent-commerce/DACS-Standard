"""DACS storage soft limit: producer packaging for Demos Storage Programs.

DACS-4 §9.6.1 and DACS-5 §10.4.2 apply a 128 KB soft limit, stricter than
the 1,048,576-byte substrate cap (DEMOS-MAPPING §A.2).  The limit is
131,072 bytes, measured over the exact payload bytes: raw bytes as given, or
the UTF-8 bytes of the RFC 8785 canonical form of a JSON value.  A payload of
exactly 131,072 bytes is stored directly; one byte more needs the
extended-pointer pattern.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any
from urllib.parse import urlsplit

try:
    from scripts.jcs import canonicalize
except ImportError:  # pragma: no cover - direct script execution
    from jcs import canonicalize

SOFT_LIMIT_BYTES = 128 * 1024

# DACS-5 §10.4.1/§10.4.2: each bundle type's discriminator, and the pointer
# signature domain its typed extended pointer uses.  CORE §B.7 registers no
# domain for the generic AttestationBundle pointer (`bundleVersion`), so this
# producer cannot sign one and refuses rather than emit unverifiable content.
BUNDLE_DISCRIMINATORS = (
    "bundleVersion",
    "faultBundleVersion",
    "evidenceBoundFaultBundleVersion",
    "finalityBoundEvidenceFaultBundleVersion",
)
POINTER_DOMAINS = {
    "faultBundleVersion": "dacs-fault-bundle-pointer:v1:",
    "evidenceBoundFaultBundleVersion": "dacs-evidence-bound-fault-bundle-pointer:v1:",
    "finalityBoundEvidenceFaultBundleVersion":
        "dacs-finality-bound-evidence-fault-bundle-pointer:v1:",
}
HTTPS_POINTER_TYPES = {
    "evidenceBoundFaultBundleVersion", "finalityBoundEvidenceFaultBundleVersion",
}


def payload_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return canonicalize(value).encode("utf-8")


def fits_soft_limit(value: Any) -> bool:
    return len(payload_bytes(value)) <= SOFT_LIMIT_BYTES


def package_deliverable(payload: Any, external_url: str) -> dict:
    """DACS-4 §9.6.1: store directly, or anchor an extended-pointer record."""
    data = payload_bytes(payload)
    if fits_soft_limit(data):
        return {"kind": "direct", "payload": data}
    record = {
        "externalUrl": external_url,
        "externalContentHash": hashlib.sha256(data).hexdigest(),
    }
    if not fits_soft_limit(record):
        raise ValueError("extended pointer exceeds the DACS storage soft limit")
    return {"kind": "extended-pointer", "record": record}


def attestation_bundle_hash(bundle: dict) -> str:
    """DACS-5 §10.4.1: sha256 of the canonical form without the two signing members."""
    unsigned = {
        key: value for key, value in bundle.items()
        if key not in {"signatures", "anchoredByRole"}
    }
    return hashlib.sha256(payload_bytes(unsigned)).hexdigest()


def extended_bundle_pointer(bundle: dict, full_bundle_url: str, signing_key: Any) -> dict:
    """DACS-5 §10.4.2: the typed pointer a consumer accepts for ``bundle``.

    The discriminator and signature domain follow the bundle's own type,
    ``fullBundleContentHash`` is its §10.4.1 hash, and the signer is the
    unique party holding ``anchoredByRole``; ``signing_key`` is that party's
    Ed25519 key.
    """
    discriminators = [name for name in BUNDLE_DISCRIMINATORS if name in bundle]
    if len(discriminators) != 1:
        raise ValueError("bundle must carry exactly one type discriminator")
    discriminator = discriminators[0]
    if discriminator not in POINTER_DOMAINS:
        raise ValueError("no registered pointer signature domain for an AttestationBundle")
    if discriminator in HTTPS_POINTER_TYPES:
        url = urlsplit(full_bundle_url)
        if url.scheme != "https" or not url.hostname or url.username or url.password:
            raise ValueError("pointer URL must be absolute HTTPS without userinfo")
    signers = [
        party.get("primaryClaim") for party in bundle.get("parties", [])
        if isinstance(party, dict) and party.get("role") == bundle.get("anchoredByRole")
    ]
    if len(signers) != 1 or not isinstance(signers[0], str):
        raise ValueError("anchoredByRole must name exactly one party")
    pointer = {
        discriminator: "1",
        "pointerKind": "extended",
        "fullBundleUrl": full_bundle_url,
        "fullBundleContentHash": attestation_bundle_hash(bundle),
    }
    digest = hashlib.sha256(payload_bytes(pointer)).hexdigest()
    value = signing_key.sign((POINTER_DOMAINS[discriminator] + digest).encode("utf-8"))
    pointer["signature"] = {
        "signer": signers[0],
        "algorithm": "ed25519",
        "value": base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii"),
    }
    if not fits_soft_limit(pointer):
        raise ValueError("extended pointer exceeds the DACS storage soft limit")
    return pointer


def package_bundle(bundle: dict, full_bundle_url: str, signing_key: Any) -> dict:
    """DACS-5 §10.4.2: anchor the bundle, or its signed typed extended pointer."""
    data = payload_bytes(bundle)
    if fits_soft_limit(data):
        return {"kind": "direct", "payload": data}
    return {
        "kind": "extended-pointer",
        "record": extended_bundle_pointer(bundle, full_bundle_url, signing_key),
    }
