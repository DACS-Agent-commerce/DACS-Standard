#!/usr/bin/env python3
"""Run the dependency-free DACS v0.1 minimum-conformant walkthrough.

The walkthrough builds a deterministic Identify -> Vet -> Negotiate -> Settle
-> Verify artifact chain from public test keys.  It performs no live SDK calls,
publishes through a fake logical-to-native SR-2 adapter, and byte-pins its trace
for CI.  The tool is non-normative; ``spec/`` remains authoritative.
"""

from __future__ import annotations

import argparse
import base64
import copy
import functools
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "spec" / "PROFILE.md"
MANIFEST = ROOT / "conformance" / "MANIFEST.json"
SB2_VECTORS = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "sb2-settlement-uniqueness-v0.1.json"
)
PINS = ROOT / "conformance" / "walkthrough" / "PINS.json"

STAGES = ["DACS-1", "DACS-2", "DACS-3", "DACS-4", "DACS-5"]
STAGE_LINKS = {
    "DACS-1": {
        "operation": "Identify",
        "rules": ["CF-1", "CF-4", "BP-1", "BP-2", "BP-3", "BP-4", "SIG-6"],
        "vectorIds": ["sig-roundtrip", "dacs1-siwd-resource-binding"],
    },
    "DACS-2": {
        "operation": "Vet",
        "rules": ["CF-1", "CF-4", "CM-1", "CM-2", "CM-3", "CM-4", "CM-5", "SIG-6"],
        "vectorIds": ["vet-ma3-verified-accept", "cf4-dacs2-composite-address"],
    },
    "DACS-3": {
        "operation": "Negotiate",
        "rules": ["PS-1", "PS-2", "PS-3", "CA-1", "CA-4", "CA-6", "CA-7", "SIG-6"],
        "vectorIds": ["neg-band-inclusive", "neg-priceanchor-absent-ok"],
    },
    "DACS-4": {
        "operation": "Settle",
        "rules": ["PC-1", "PC-2", "PC-3", "PC-6", "FP-1", "FP-2", "FP-3", "FP-4", "PIPE-1", "PIPE-3", "SIG-6"],
        "vectorIds": ["settlement-payment-pass", "settlement-delivery-pass"],
    },
    "DACS-5": {
        "operation": "Verify",
        "rules": ["ST-1", "ST-2", "ST-4", "ST-6", "SIG-6", "§10.4.2"],
        "vectorIds": ["bundle-0004-pass", "verify-consume-unified"],
    },
}

DOMAINS = {
    "Listing": "dacs-listing:v1:",
    "VerifyResult": "dacs-verifyresult:v1:",
    "CompositeVerificationRecord": "dacs-composite:v1:",
    "PayeeBoundAgreementDocument": "dacs-payee-bound-agreement:v1:",
    "SettlementEvidence": "dacs-evidence:v1:",
    "AttestationBundle": "dacs-bundle:v1:",
}

NOW = 1781280000000
JOB_ID = "01KTY8ZJ00CW7KSECW3FS6PQPK"
LISTING_ID = "minimum-lifecycle-0001"
RAIL_ID = "evm-erc20:8453:USDC"
JOB_ID_RE = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}\Z")
PHASE_INDEX_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")


def nfc_deep(value: Any) -> Any:
    """Apply CORE CF-1 recursively and reject key collisions after NFC."""

    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [nfc_deep(item) for item in value]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normal_key = unicodedata.normalize("NFC", key)
            if normal_key in result:
                raise ValueError("object keys collide after NFC normalisation")
            result[normal_key] = nfc_deep(item)
        return result
    return value


def canonical_json(value: Any) -> bytes:
    """Produce the repository's integer/string-only RFC 8785 byte form."""

    return json.dumps(
        nfc_deep(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def payment_anchor_tuple(logical_address: str) -> tuple[str, str, int, bool]:
    """Recover the PC-2 tuple from a canonical payment-evidence address."""

    if not isinstance(logical_address, str):
        raise ValueError("payment evidence logical address must be a string")
    parts = logical_address.split(":")
    if len(parts) not in {5, 6} or parts[:2] != ["dacs4", "payment"]:
        raise ValueError("payment evidence logical address has the wrong shape")
    if len(parts) == 6 and parts[5] != "resolved":
        raise ValueError("payment evidence logical address has an unknown suffix")
    job_id, encoded_rail, phase_text = parts[2:5]
    if JOB_ID_RE.fullmatch(job_id) is None:
        raise ValueError("payment evidence logical address carries a non-ULID jobId")
    rail_id = unquote(encoded_rail)
    if quote(rail_id, safe="") != encoded_rail:
        raise ValueError("payment evidence railId is not canonically CF-4 encoded")
    if PHASE_INDEX_RE.fullmatch(phase_text) is None:
        raise ValueError("payment evidence phaseIndex is not a bare integer")
    return job_id, rail_id, int(phase_text), len(parts) == 6


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256_hex(path.read_bytes())


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_base64url(value: str) -> bytes:
    """Decode only CORE SIG-6's canonical unpadded Base64URL form."""

    if not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("signature is not unpadded Base64URL")
    if len(value) % 4 == 1:
        raise ValueError("invalid unpadded Base64URL length")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if encode_base64url(decoded) != value:
        raise ValueError("non-canonical Base64URL encoding")
    return decoded


# Dependency-free RFC 8032 Ed25519.  The fixed seeds below are public test data,
# not operational credentials.
Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, Q - 2, Q)) % Q
I = pow(2, (Q - 1) // 4, Q)


def x_recover(y: int) -> int:
    xx = ((y * y - 1) * pow(D * y * y + 1, Q - 2, Q)) % Q
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q != 0:
        x = (x * I) % Q
    if (x * x - xx) % Q != 0:
        raise ValueError("point is not on the Ed25519 curve")
    return Q - x if x & 1 else x


BASE_Y = (4 * pow(5, Q - 2, Q)) % Q
BASE = (x_recover(BASE_Y), BASE_Y)


def point_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = (D * x1 * x2 * y1 * y2) % Q
    x3 = ((x1 * y2 + x2 * y1) * pow(1 + product, Q - 2, Q)) % Q
    y3 = ((y1 * y2 + x1 * x2) * pow(1 - product, Q - 2, Q)) % Q
    return x3, y3


def scalar_mult(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = (0, 1)
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def decode_point(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ValueError("Ed25519 point must be 32 bytes")
    raw = int.from_bytes(encoded, "little")
    y = raw & ((1 << 255) - 1)
    if y >= Q:
        raise ValueError("non-canonical Ed25519 point")
    x = x_recover(y)
    if (x & 1) != (raw >> 255):
        x = Q - x
    if (-x * x + y * y - 1 - D * x * x * y * y) % Q != 0:
        raise ValueError("point is not on the Ed25519 curve")
    return x, y


@functools.lru_cache(maxsize=None)
def private_scalar(seed: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(seed).digest()
    clamped = bytearray(digest[:32])
    clamped[0] &= 248
    clamped[31] &= 63
    clamped[31] |= 64
    return int.from_bytes(clamped, "little"), digest[32:]


@functools.lru_cache(maxsize=None)
def public_key(seed: bytes) -> bytes:
    scalar, _ = private_scalar(seed)
    return encode_point(scalar_mult(BASE, scalar))


def sign_ed25519(seed: bytes, message: bytes) -> bytes:
    scalar, prefix = private_scalar(seed)
    key = public_key(seed)
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    encoded_r = encode_point(scalar_mult(BASE, nonce))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + key + message).digest(), "little"
    ) % L
    encoded_s = ((nonce + challenge * scalar) % L).to_bytes(32, "little")
    return encoded_r + encoded_s


@functools.lru_cache(maxsize=None)
def verify_ed25519(public: bytes, signature: bytes, message: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= L:
        return False
    try:
        encoded_r = signature[:32]
        point_r = decode_point(encoded_r)
        point_a = decode_point(public)
    except ValueError:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public + message).digest(), "little"
    ) % L
    return scalar_mult(BASE, scalar) == point_add(
        point_r, scalar_mult(point_a, challenge)
    )


SEEDS = {
    role: hashlib.sha256(f"DACS issue 261 public test seed:{role}".encode()).digest()
    for role in ("buyer", "seller", "orchestrator")
}
CLAIMS = {role: "cci:" + public_key(seed).hex() for role, seed in SEEDS.items()}


class FakeSubstrate:
    """Deterministic SR-2 adapter with explicit logical/native bindings."""

    def __init__(self) -> None:
        self.native_anchors: dict[str, bytes] = {}
        self.bindings: dict[str, dict[str, str]] = {}
        self.settlement_claims: dict[str, tuple[str, int]] = {}

    def publish(self, logical: str, value: bytes, publisher: str) -> dict[str, str]:
        prior = self.bindings.get(logical)
        if prior is not None:
            native = prior["nativeAddress"]
            if self.native_anchors[native] != value:
                raise ValueError(f"immutable logical binding collision at {logical}")
            return prior
        material = f"fake-sr2:v1:{publisher}:{logical}:{len(self.bindings)}"
        native = "stor-" + sha256_hex(material.encode())[:40]
        if native == logical:
            raise ValueError("fake native address unexpectedly equals logical address")
        binding = {
            "logicalAddress": logical,
            "nativeAddress": native,
            "contentSha256": sha256_hex(value),
        }
        self.bindings[logical] = binding
        self.native_anchors[native] = value
        return binding

    def read_logical(self, logical: str) -> bytes | None:
        binding = self.bindings.get(logical)
        return None if binding is None else self.native_anchors.get(binding["nativeAddress"])

    def claim_settlement(self, tx_id: str, job_id: str, phase_index: int) -> str:
        binding = (job_id, phase_index)
        prior = self.settlement_claims.get(tx_id)
        if prior is None:
            self.settlement_claims[tx_id] = binding
            return "count"
        if prior == binding:
            return "already-counted"
        return "reject"


def signing_scope(kind: str, artifact: dict[str, Any]) -> dict[str, Any]:
    omitted = {"signatures"} if "signatures" in artifact else {"signature"}
    if kind == "AttestationBundle":
        omitted.add("anchoredByRole")
    return {key: value for key, value in artifact.items() if key not in omitted}


def artifact_hash(kind: str, artifact: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(signing_scope(kind, artifact)))


def sign_value(kind: str, unsigned: dict[str, Any], role: str) -> str:
    digest = artifact_hash(kind, unsigned)
    payload = (DOMAINS[kind] + digest).encode("ascii")
    return encode_base64url(sign_ed25519(SEEDS[role], payload))


def signature_entries(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    if "signature" in artifact:
        return [artifact["signature"]]
    return artifact.get("signatures", [])


def key_from_claim(claim: str) -> bytes:
    scheme, identifier = claim.split(":", 1)
    if scheme != "cci" or not re.fullmatch(r"[0-9a-f]{64}", identifier):
        raise ValueError(f"cannot resolve walkthrough signer {claim!r}")
    return bytes.fromhex(identifier)


def verify_signatures(kind: str, artifact: dict[str, Any]) -> list[dict[str, Any]]:
    digest = artifact_hash(kind, artifact)
    payload = (DOMAINS[kind] + digest).encode("ascii")
    results = []
    for envelope in signature_entries(artifact):
        signer = envelope.get("signer") or envelope.get("party")
        canonical = False
        try:
            signature = decode_base64url(envelope["value"])
            canonical = True
            verified = verify_ed25519(key_from_claim(signer), signature, payload)
        except (KeyError, TypeError, ValueError):
            verified = False
        results.append(
            {
                "signer": signer,
                "algorithm": envelope.get("algorithm"),
                "canonicalBase64Url": canonical,
                "verified": verified,
            }
        )
    return results


def identity_scope(bundle: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in bundle.items() if key != "presentation"}


def sign_identity_presentation(bundle: dict[str, Any], role: str) -> dict[str, Any]:
    """Sign an IdentityBundle scope, including deliberately malformed test scopes."""

    signed = copy.deepcopy(bundle)
    unsigned = identity_scope(signed)
    digest = sha256_hex(canonical_json(unsigned))
    payload = ("dacs-bundle-presentation:v1:" + digest).encode("ascii")
    signed["presentation"] = {
        "kind": "per-claim",
        "signatures": [
            {
                "ref": CLAIMS[role],
                "signature": encode_base64url(sign_ed25519(SEEDS[role], payload)),
            }
        ],
    }
    return signed


def build_identity(role: str) -> dict[str, Any]:
    unsigned = {
        "bundleVersion": "1",
        "presentedBy": CLAIMS[role],
        "presentedAt": NOW,
        "sessionNonce": sha256_hex(f"{JOB_ID}:{role}:nonce".encode())[:32],
        "claims": [{"ref": CLAIMS[role], "metadata": {"testRole": role}}],
    }
    return sign_identity_presentation(unsigned, role)


def verify_identity(bundle: dict[str, Any]) -> dict[str, Any]:
    digest = sha256_hex(canonical_json(identity_scope(bundle)))
    payload = ("dacs-bundle-presentation:v1:" + digest).encode("ascii")
    results = []
    for envelope in bundle["presentation"]["signatures"]:
        try:
            raw = decode_base64url(envelope["signature"])
            verified = verify_ed25519(key_from_claim(envelope["ref"]), raw, payload)
        except (KeyError, TypeError, ValueError):
            verified = False
        results.append({"signer": envelope.get("ref"), "verified": verified})
    return {
        "bundleHash": digest,
        "canonicalBytes": canonical_json(identity_scope(bundle)).decode("utf-8"),
        "domainSeparator": "dacs-bundle-presentation:v1:",
        "signaturePayload": payload.decode("ascii"),
        "signatureResults": results,
    }


def validate_identity(bundle: dict[str, Any]) -> dict[str, Any]:
    """Execute the minimum IdentityBundle structure and presentation checks."""

    errors: list[str] = []
    if not isinstance(bundle, dict):
        return {
            "accepted": False,
            "observed": "reject-counterparty",
            "errors": ["IdentityBundle must be an object"],
            "verification": None,
        }
    claims = bundle.get("claims")
    if not isinstance(claims, list) or not claims:
        errors.append("IdentityBundle.claims must be a non-empty array")
    elif any(not isinstance(claim, dict) or not isinstance(claim.get("ref"), str) for claim in claims):
        errors.append("every IdentityBundle claim must be an object with a string ref")
    verification = None
    try:
        verification = verify_identity(bundle)
    except (KeyError, TypeError, ValueError):
        errors.append("IdentityBundle presentation is malformed")
    if verification is not None:
        results = verification["signatureResults"]
        if not results or not all(item["verified"] for item in results):
            errors.append("IdentityBundle presentation signature does not verify")
    return {
        "accepted": not errors,
        "observed": "accepted" if not errors else "reject-counterparty",
        "errors": errors,
        "verification": verification,
    }


def attestation_ref(binding: dict[str, str], content_hash: str) -> dict[str, Any]:
    return {
        "anchor": {"kind": "storage-program", "locator": binding["nativeAddress"]},
        "contentHash": content_hash,
    }


def trace_artifact(
    *,
    stage: str,
    artifact_id: str,
    kind: str,
    artifact: dict[str, Any],
    logical_address: str,
    publisher: str,
    substrate: FakeSubstrate,
) -> tuple[dict[str, Any], dict[str, Any]]:
    canonical = canonical_json(artifact)
    signing_bytes = canonical_json(signing_scope(kind, artifact))
    digest = sha256_hex(signing_bytes)
    results = verify_signatures(kind, artifact)
    if not results or not all(result["verified"] for result in results):
        raise ValueError(f"{artifact_id}: signature verification failed")
    binding = substrate.publish(logical_address, canonical, publisher)
    if substrate.read_logical(logical_address) != canonical:
        raise ValueError(f"{artifact_id}: fake substrate round-trip failed")
    trace = {
        "artifactId": artifact_id,
        "kind": kind,
        "artifact": artifact,
        "canonicalBytes": canonical.decode("utf-8"),
        "anchoredBytesSha256": sha256_hex(canonical),
        "signingCanonicalBytes": signing_bytes.decode("utf-8"),
        "artifactHash": digest,
        "domainSeparator": DOMAINS[kind],
        "signaturePayload": DOMAINS[kind] + digest,
        "signatureResults": results,
        "logicalAddress": logical_address,
        "publishedBinding": binding,
        "attestationRef": attestation_ref(binding, digest),
        "anchorRoundTrip": True,
    }
    return trace, trace["attestationRef"]


def signed_single(kind: str, unsigned: dict[str, Any], role: str) -> dict[str, Any]:
    artifact = copy.deepcopy(unsigned)
    artifact["signature"] = {
        "algorithm": "ed25519",
        "signer": CLAIMS[role],
        "value": sign_value(kind, unsigned, role),
    }
    return artifact


def signed_multi(kind: str, unsigned: dict[str, Any], roles: list[str]) -> dict[str, Any]:
    artifact = copy.deepcopy(unsigned)
    artifact["signatures"] = [
        {
            "party": CLAIMS[role],
            "algorithm": "ed25519",
            "value": sign_value(kind, unsigned, role),
        }
        for role in roles
    ]
    return artifact


def stage_entry(stage: str, artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "stage": stage,
        "operation": STAGE_LINKS[stage]["operation"],
        "rules": STAGE_LINKS[stage]["rules"],
        "vectorIds": STAGE_LINKS[stage]["vectorIds"],
        "artifacts": artifacts,
    }


def validate_agreement_against_listing(
    listing: dict[str, Any], agreement: dict[str, Any]
) -> dict[str, Any]:
    """Verify agreement signatures and enforce the listing's rail policy."""

    signature_results = verify_signatures("PayeeBoundAgreementDocument", agreement)
    required_signers = {
        party["primaryClaim"]
        for party in agreement.get("parties", [])
        if party.get("role") in {"buyer", "seller"}
    }
    verified_signers = {
        result["signer"] for result in signature_results if result["verified"]
    }
    selected_rail = agreement.get("terms", {}).get("rail", {}).get("railId")
    accepted_rails = {
        rail.get("railId") for rail in listing.get("acceptedRails", [])
    }
    reason = None
    if not signature_results or not all(
        result["verified"] for result in signature_results
    ):
        reason = "agreement signatures do not verify"
    elif not required_signers or not required_signers <= verified_signers:
        reason = "agreement is missing a required buyer or seller signature"
    elif selected_rail not in accepted_rails:
        reason = "agreement selected a rail outside listing policy"
    return {
        "accepted": reason is None,
        "observed": "accept" if reason is None else "reject-before-settle",
        "reason": reason,
        "selectedRail": selected_rail,
        "acceptedRails": sorted(rail for rail in accepted_rails if rail is not None),
        "signatureResults": signature_results,
    }


def evaluate_delivery_after_payment(
    payment: dict[str, Any], delivery_result: dict[str, Any]
) -> dict[str, Any]:
    """Apply the delivery transition while retaining already-recorded payment."""

    if payment.get("outcome") != "success":
        raise ValueError("delivery transition requires successful payment evidence")
    evidence = {
        "evidenceVersion": "1",
        "jobId": payment["jobId"],
        "phase": "deliver-storage-program",
        "observedAt": NOW + 6000,
    }
    phase_entry: dict[str, Any] = {
        "index": 4,
        "kind": "deliver-storage-program",
    }
    if delivery_result.get("ok") is True:
        content_hash = delivery_result.get("deliverableContentHash")
        anchor = delivery_result.get("deliverableAnchor")
        if not isinstance(content_hash, str) or not isinstance(anchor, dict):
            raise ValueError("successful delivery result lacks content hash or anchor")
        evidence.update(
            {
                "outcome": "success",
                "deliverableContentHash": content_hash,
                "deliverableAnchor": anchor,
            }
        )
        phase_entry["outcome"] = "ok"
        session_outcome = "completed"
    else:
        error_class = delivery_result.get("errorClass")
        outcomes = {
            "counterparty": "failed-counterparty",
            "substrate": "failed-substrate",
            "permanent": "failed-permanent",
        }
        if error_class not in outcomes:
            raise ValueError("failed delivery result has an unsupported errorClass")
        evidence.update(
            {
                "outcome": "failure",
                "reason": f"delivery adapter reported {error_class} failure",
            }
        )
        phase_entry.update({"outcome": "fail", "errorClass": error_class})
        session_outcome = outcomes[error_class]
    return {
        "sessionOutcome": session_outcome,
        "phaseEntry": phase_entry,
        "evidenceUnsigned": evidence,
        "paymentRemainsRecorded": True,
    }


def consume_bundle_pair(
    left: dict[str, Any], right: dict[str, Any]
) -> dict[str, Any]:
    """Consume two role copies and classify whether reputation may use them."""

    signature_results = {
        "leftCopy": verify_signatures("AttestationBundle", left),
        "rightCopy": verify_signatures("AttestationBundle", right),
    }
    for label, bundle in (("leftCopy", left), ("rightCopy", right)):
        results = signature_results[label]
        required_signers = {
            party["primaryClaim"] for party in bundle.get("parties", [])
        }
        verified_signers = {
            result["signer"] for result in results if result["verified"]
        }
        if (
            not results
            or not all(result["verified"] for result in results)
            or not required_signers
            or not required_signers <= verified_signers
        ):
            return {
                "disposition": "invalid",
                "reputationDisposition": "exclude",
                "reason": f"{label} lacks valid signatures from every party",
                "signatureResults": signature_results,
            }
    if left.get("jobId") != right.get("jobId"):
        return {
            "disposition": "invalid",
            "reputationDisposition": "exclude",
            "reason": "bundle copies identify different jobs",
            "signatureResults": signature_results,
        }
    left_phases = {entry["index"]: entry for entry in left.get("phaseSummary", [])}
    right_phases = {entry["index"]: entry for entry in right.get("phaseSummary", [])}
    phase_keys = ("kind", "outcome", "errorClass")
    divergent = left.get("outcome") != right.get("outcome") or set(
        left_phases
    ) != set(right_phases)
    if not divergent:
        divergent = any(
            any(
                left_phases[index].get(key) != right_phases[index].get(key)
                for key in phase_keys
            )
            for index in left_phases
        )
    return {
        "disposition": "divergent" if divergent else "unified",
        "reputationDisposition": "exclude" if divergent else "include",
        "reason": (
            "signed bundle outcomes or phase summaries conflict"
            if divergent
            else "signed bundle outcomes and phase summaries agree"
        ),
        "signatureResults": signature_results,
    }


def build_happy_path(substrate: FakeSubstrate) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    identities = {role: build_identity(role) for role in SEEDS}
    identity_validations = {
        role: validate_identity(bundle) for role, bundle in identities.items()
    }
    if not all(result["accepted"] for result in identity_validations.values()):
        raise ValueError("identity presentation verification failed")
    identity_results = {
        role: result["verification"]
        for role, result in identity_validations.items()
    }

    deliverable = {
        "kind": "storage-program",
        "schemaUrl": "https://example.invalid/dacs/walkthrough-result.schema.json",
        "expectedSizeBytes": 80,
        "accessModel": "public",
    }
    requirement = {
        "requirementVersion": "1",
        "required": [{"scheme": "cci", "verificationRequired": True}],
    }
    listing_unsigned = {
        "dacsVersion": "1",
        "listingVersion": 1,
        "listingId": LISTING_ID,
        "seller": {
            "identity": identities["seller"],
            "displayName": "DACS walkthrough seller",
        },
        "offering": {
            "title": "Deterministic lifecycle result",
            "description": "Produce and anchor a deterministic walkthrough result.",
            "category": "reference.conformance.walkthrough",
            "tags": ["conformance", "lifecycle"],
            "deliverable": deliverable,
        },
        "buyerRequirement": requirement,
        "pipeline": [
            {"kind": "vet-credentials"},
            {"kind": "negotiate-fixed-price"},
            {"kind": "commit-payee-bound-agreement"},
            {"kind": "pay-evm-erc20", "parameters": {"rail": RAIL_ID}},
            {"kind": "deliver-storage-program"},
        ],
        "pricing": {"kind": "fixed", "price": {"amount": "5", "currency": "USDC"}},
        "acceptedRails": [{"railId": RAIL_ID, "railVersion": 1}],
        "terms": {"deadlineSecAfterCommit": 3600, "cancellationPolicy": "pre-commit"},
        "validity": {"notBefore": NOW - 60000, "notAfter": NOW + 86400000},
    }
    listing = signed_single("Listing", listing_unsigned, "seller")
    listing_logical = (
        f"dacs1:{quote(CLAIMS['seller'], safe='')}:{LISTING_ID}:v1"
    )
    listing_trace, listing_ref = trace_artifact(
        stage="DACS-1",
        artifact_id="listing-minimum-lifecycle",
        kind="Listing",
        artifact=listing,
        logical_address=listing_logical,
        publisher="seller",
        substrate=substrate,
    )
    dacs1 = stage_entry("DACS-1", [listing_trace])
    dacs1["identityPresentations"] = identity_results

    vet_traces = []
    vet_refs: dict[str, dict[str, Any]] = {}
    requirement_hash = sha256_hex(canonical_json(requirement))
    for role in ("buyer", "seller"):
        authority_response = {
            "claim": CLAIMS[role],
            "selfSignedKeyMatch": True,
        }
        authority_logical = f"sr3:walkthrough:{JOB_ID}:{quote(CLAIMS[role], safe='')}"
        authority_bytes = canonical_json(authority_response)
        authority_binding = substrate.publish(
            authority_logical, authority_bytes, "orchestrator"
        )
        verify_result_unsigned = {
            "resultVersion": "1",
            "scheme": "cci",
            "identifier": CLAIMS[role].split(":", 1)[1],
            "recipeVersion": 1,
            "method": "self-signed",
            "decision": "pass",
            "reason": "public test key verified its deterministic challenge",
            "attestation": attestation_ref(
                authority_binding, sha256_hex(authority_bytes)
            ),
            "data": {"selfSignedKeyMatch": True},
            "fetchedAt": NOW + 500,
            "verifiedAt": NOW + 1000,
            "validUntil": NOW + 86400000,
        }
        verify_result = signed_single("VerifyResult", verify_result_unsigned, "orchestrator")
        verify_logical = f"dacs2:verify:{JOB_ID}:{quote(CLAIMS[role], safe='')}"
        verify_trace, verify_attestation_ref = trace_artifact(
            stage="DACS-2",
            artifact_id=f"verify-result-{role}",
            kind="VerifyResult",
            artifact=verify_result,
            logical_address=verify_logical,
            publisher="orchestrator",
            substrate=substrate,
        )
        verify_ref = {**verify_attestation_ref, "recipeVersion": 1}
        vet_unsigned = {
            "recordVersion": "1",
            "jobId": JOB_ID,
            "evaluatedParty": CLAIMS[role],
            "bundleHash": identity_results[role]["bundleHash"],
            "requirementHash": requirement_hash,
            "freshness": [],
            "supplementary": [],
            "dealSpecific": [verify_ref],
            "overallDecision": "pass",
            "generatedAt": NOW + 2000,
        }
        vet = signed_single("CompositeVerificationRecord", vet_unsigned, "orchestrator")
        vet_logical = f"dacs2:composite:{JOB_ID}:{quote(CLAIMS[role], safe='')}"
        vet_trace, vet_refs[role] = trace_artifact(
            stage="DACS-2",
            artifact_id=f"composite-vet-{role}",
            kind="CompositeVerificationRecord",
            artifact=vet,
            logical_address=vet_logical,
            publisher="orchestrator",
            substrate=substrate,
        )
        vet_traces.extend([verify_trace, vet_trace])
    dacs2 = stage_entry("DACS-2", vet_traces)

    agreement_unsigned = {
        "payeeBoundAgreementVersion": "1",
        "jobId": JOB_ID,
        "listingRef": {
            "listingId": LISTING_ID,
            "version": 1,
            "contentHash": listing_ref["contentHash"],
        },
        "parties": [
            {
                "role": role,
                "bundleHash": identity_results[role]["bundleHash"],
                "primaryClaim": CLAIMS[role],
                "vetRecordRef": vet_refs[role],
            }
            for role in ("buyer", "seller")
        ],
        "terms": {
            "deliverable": {
                "deliverableType": deliverable["kind"],
                "hash": sha256_hex(canonical_json(deliverable)),
                "schemaUrl": deliverable["schemaUrl"],
            },
            "price": {"amount": "5", "currency": "USDC"},
            "rail": {"railId": RAIL_ID, "railVersion": 1},
            "deadline": NOW + 3600000,
            "payoutBindings": [
                {
                    "railId": RAIL_ID,
                    "phaseIndex": 3,
                    "payeeAddress": "0x0000000000000000000000000000000000000261",
                }
            ],
        },
        "derivedFromPattern": "fixed-price",
        "generatedAt": NOW + 3000,
    }
    agreement = signed_multi(
        "PayeeBoundAgreementDocument", agreement_unsigned, ["buyer", "seller"]
    )
    agreement_trace, agreement_ref = trace_artifact(
        stage="DACS-3",
        artifact_id="agreement-payee-bound-fixed-price",
        kind="PayeeBoundAgreementDocument",
        artifact=agreement,
        logical_address=f"dacs3:commit:{JOB_ID}",
        publisher="orchestrator",
        substrate=substrate,
    )
    dacs3 = stage_entry("DACS-3", [agreement_trace])

    payment_unsigned = {
        "evidenceVersion": "1",
        "jobId": JOB_ID,
        "phase": "pay-evm-erc20",
        "outcome": "success",
        "paymentTxRefs": [
            {"kind": "evm", "chainId": 8453, "txHash": "0x" + "26" * 32}
        ],
        "paymentAmount": {"amount": "5", "currency": "USDC"},
        "settlementFinality": {
            "model": "block-depth",
            "finalityBlocks": 12,
            "finalityObservedAt": NOW + 5000,
        },
        "observedAt": NOW + 4000,
    }
    payment = signed_single("SettlementEvidence", payment_unsigned, "orchestrator")
    payment_trace, payment_ref = trace_artifact(
        stage="DACS-4",
        artifact_id="settlement-payment-success",
        kind="SettlementEvidence",
        artifact=payment,
        logical_address=f"dacs4:payment:{JOB_ID}:{quote(RAIL_ID, safe='')}:3",
        publisher="orchestrator",
        substrate=substrate,
    )

    deliverable_bytes = canonical_json(
        {"jobId": JOB_ID, "result": "minimum lifecycle completed", "rows": 1}
    )
    deliverable_logical = f"dacs4:deliverable:{JOB_ID}"
    deliverable_binding = substrate.publish(
        deliverable_logical, deliverable_bytes, "seller"
    )
    delivery_transition = evaluate_delivery_after_payment(
        payment,
        {
            "ok": True,
            "deliverableContentHash": sha256_hex(deliverable_bytes),
            "deliverableAnchor": {
                "kind": "storage-program",
                "locator": deliverable_binding["nativeAddress"],
            },
        },
    )
    delivery = signed_single(
        "SettlementEvidence", delivery_transition["evidenceUnsigned"], "orchestrator"
    )
    delivery_trace, delivery_ref = trace_artifact(
        stage="DACS-4",
        artifact_id="settlement-delivery-success",
        kind="SettlementEvidence",
        artifact=delivery,
        logical_address=f"dacs4:evidence:deliverable:{JOB_ID}",
        publisher="orchestrator",
        substrate=substrate,
    )
    dacs4 = stage_entry("DACS-4", [payment_trace, delivery_trace])
    dacs4["deliveredObject"] = {
        "canonicalBytes": deliverable_bytes.decode("utf-8"),
        "contentHash": sha256_hex(deliverable_bytes),
        "logicalAddress": deliverable_logical,
        "publishedBinding": deliverable_binding,
    }

    phase_summary = [
        {"index": 0, "kind": "vet-credentials", "outcome": "ok"},
        {"index": 1, "kind": "negotiate-fixed-price", "outcome": "ok"},
        {"index": 2, "kind": "commit-payee-bound-agreement", "outcome": "ok"},
        {
            "index": 3,
            "kind": "pay-evm-erc20",
            "outcome": "ok",
            "txRefs": payment["paymentTxRefs"],
            "attestationRef": payment_ref,
        },
        {**delivery_transition["phaseEntry"], "attestationRef": delivery_ref},
    ]
    bundle_unsigned = {
        "bundleVersion": "1",
        "jobId": JOB_ID,
        "outcome": delivery_transition["sessionOutcome"],
        "listingRef": agreement_unsigned["listingRef"],
        "agreementRef": agreement_ref,
        "parties": [
            {
                "role": role,
                "bundleHash": identity_results[role]["bundleHash"],
                "primaryClaim": CLAIMS[role],
            }
            for role in ("buyer", "seller", "orchestrator")
        ],
        "phaseSummary": phase_summary,
        "vetRecords": [vet_refs["buyer"], vet_refs["seller"]],
        "settlementEvidence": [payment_ref, delivery_ref],
        "recipeRegistryVersion": 1,
        "railRegistryVersion": 1,
        "finalisedAt": NOW + 7000,
    }
    bundle_base = signed_multi(
        "AttestationBundle", bundle_unsigned, ["buyer", "seller", "orchestrator"]
    )
    bundle_traces = []
    bundle_copies = {}
    for role in ("buyer", "seller", "orchestrator"):
        bundle = copy.deepcopy(bundle_base)
        bundle["anchoredByRole"] = role
        # anchoredByRole is excluded from the signing scope, so the shared
        # signatures verify on every independently anchored role copy.
        logical = "stor-" + sha256_hex(f"{JOB_ID}-bundle-{role}".encode())
        bundle_trace, _ = trace_artifact(
            stage="DACS-5",
            artifact_id=f"attestation-bundle-{role}",
            kind="AttestationBundle",
            artifact=bundle,
            logical_address=logical,
            publisher=role,
            substrate=substrate,
        )
        bundle_traces.append(bundle_trace)
        bundle_copies[role] = bundle
    dacs5 = stage_entry("DACS-5", bundle_traces)

    context = {
        "identities": identities,
        "listing": listing,
        "listingAttestationRef": listing_ref,
        "listingDocumentRef": agreement_unsigned["listingRef"],
        "vetRefs": vet_refs,
        "agreement": agreement,
        "agreementRef": agreement_ref,
        "payment": payment,
        "paymentTrace": payment_trace,
        "paymentRef": payment_ref,
        "delivery": delivery,
        "deliveryRef": delivery_ref,
        "bundleBase": bundle_base,
        "bundleCopies": bundle_copies,
    }
    return [dacs1, dacs2, dacs3, dacs4, dacs5], context


def validate_happy_path(stages: list[dict[str, Any]], context: dict[str, Any]) -> None:
    listing = context["listing"]
    agreement = context["agreement"]
    payment = context["payment"]
    delivery = context["delivery"]
    bundle = context["bundleBase"]
    pipeline = listing["pipeline"]
    kinds = [step["kind"] for step in pipeline]

    if [stage["stage"] for stage in stages] != STAGES:
        raise ValueError("walkthrough does not cover the five stages in order")
    if not any(kind.startswith("deliver-") for kind in kinds):
        raise ValueError("PIPE-1: happy path has no delivery phase")
    if agreement["listingRef"] != context["listingDocumentRef"]:
        raise ValueError("agreement does not pin the anchored listing")
    if agreement["terms"]["deliverable"]["hash"] != sha256_hex(
        canonical_json(listing["offering"]["deliverable"])
    ):
        raise ValueError("agreement deliverable does not bind the listing")
    agreement_validation = validate_agreement_against_listing(listing, agreement)
    if not agreement_validation["accepted"]:
        raise ValueError(agreement_validation["reason"])
    expected_vet = {json.dumps(ref, sort_keys=True) for ref in context["vetRefs"].values()}
    actual_party_vet = {
        json.dumps(party["vetRecordRef"], sort_keys=True) for party in agreement["parties"]
    }
    if expected_vet != actual_party_vet:
        raise ValueError("agreement parties do not bind the DACS-2 records")
    if JOB_ID_RE.fullmatch(JOB_ID) is None:
        raise ValueError("walkthrough jobId is not a canonical ULID")
    payment_entries = [
        entry
        for entry in bundle["phaseSummary"]
        if entry.get("attestationRef") == context["paymentRef"]
    ]
    delivery_entries = [
        entry
        for entry in bundle["phaseSummary"]
        if entry.get("attestationRef") == context["deliveryRef"]
    ]
    if len(payment_entries) != 1 or len(delivery_entries) != 1:
        raise ValueError("settlement evidence is not bound to exactly one pipeline phase")
    payment_entry, delivery_entry = payment_entries[0], delivery_entries[0]
    payment_trace = context["paymentTrace"]
    payment_binding = payment_trace["publishedBinding"]
    if payment_binding["logicalAddress"] != payment_trace["logicalAddress"]:
        raise ValueError("payment trace logical address diverges from its published binding")
    if payment_binding["nativeAddress"] != context["paymentRef"]["anchor"]["locator"]:
        raise ValueError("payment reference locator diverges from its published binding")
    if payment_binding["contentSha256"] != payment_trace["anchoredBytesSha256"]:
        raise ValueError("payment binding content hash diverges from the anchored bytes")
    if payment_trace["artifactHash"] != context["paymentRef"]["contentHash"]:
        raise ValueError("payment reference content hash diverges from the signed artifact")
    payment_address = payment_anchor_tuple(payment_binding["logicalAddress"])
    expected_payment_address = (
        JOB_ID,
        agreement["terms"]["rail"]["railId"],
        payment_entry["index"],
        False,
    )
    if payment_address != expected_payment_address:
        raise ValueError("payment evidence anchor does not match the authenticated phase tuple")
    if payment["jobId"] != JOB_ID or payment["phase"] != payment_entry["kind"]:
        raise ValueError("payment evidence does not match its bundle phase")
    if delivery["jobId"] != JOB_ID or delivery["phase"] != delivery_entry["kind"]:
        raise ValueError("delivery evidence does not match its bundle phase")
    if bundle["agreementRef"] != context["agreementRef"]:
        raise ValueError("bundle does not reference the committed agreement")
    if bundle["vetRecords"] != list(context["vetRefs"].values()):
        raise ValueError("bundle vetRecords do not match DACS-2 outputs")
    if bundle["settlementEvidence"] != [context["paymentRef"], context["deliveryRef"]]:
        raise ValueError("bundle settlementEvidence does not match DACS-4 outputs")
    if [entry["kind"] for entry in bundle["phaseSummary"]] != kinds:
        raise ValueError("bundle phaseSummary diverges from the listing pipeline")
    for entry, index in zip(bundle["phaseSummary"], range(len(pipeline))):
        if entry["index"] != index:
            raise ValueError("bundle phaseSummary index is not the bare pipeline index")
    if {item["party"] for item in bundle["signatures"]} != set(CLAIMS.values()):
        raise ValueError("completed bundle is missing a required signer")
    bundle_consumption = consume_bundle_pair(
        context["bundleCopies"]["buyer"], context["bundleCopies"]["seller"]
    )
    if (
        bundle_consumption["disposition"] != "unified"
        or bundle_consumption["reputationDisposition"] != "include"
    ):
        raise ValueError("matching happy-path bundles were not consumed as unified")
    for stage in stages:
        for item in stage["artifacts"]:
            if item["logicalAddress"] == item["publishedBinding"]["nativeAddress"]:
                raise ValueError("logical and native addresses were conflated")


def settlement_tx_id(record: dict[str, Any]) -> str:
    ref = record["settlementRef"]
    if ref["rail"] != "evm":
        raise ValueError("minimum walkthrough expects the EVM SB-2 vector")
    tx_hash = ref["txHash"].removeprefix("0x").lower()
    return f"evm:{ref['chainId']}:{tx_hash}:{ref['logIndex']}"


def malformed_identity_case(identity: dict[str, Any]) -> dict[str, Any]:
    candidate = copy.deepcopy(identity)
    candidate["claims"] = "not-an-array"
    candidate = sign_identity_presentation(candidate, "buyer")
    validation = validate_identity(candidate)
    signature_results = (
        validation["verification"]["signatureResults"]
        if validation["verification"] is not None
        else []
    )
    presentation_valid = bool(signature_results) and all(
        result["verified"] for result in signature_results
    )
    rejected_for_shape = (
        "IdentityBundle.claims must be a non-empty array" in validation["errors"]
    )
    return {
        "id": "malformed-identity",
        "mutation": "IdentityBundle.claims is a string instead of an array",
        "rules": ["BR-1", "VPC-4"],
        "vectorIds": ["vet-counterparty-malformed-attribution"],
        "enforcementPath": "validate_identity",
        "validation": validation,
        "expected": "reject-counterparty",
        "observed": validation["observed"],
        "passed": presentation_valid and not validation["accepted"] and rejected_for_shape,
    }


def outside_policy_case(listing: dict[str, Any], agreement: dict[str, Any]) -> dict[str, Any]:
    candidate_unsigned = copy.deepcopy(
        signing_scope("PayeeBoundAgreementDocument", agreement)
    )
    unlisted_rail = "evm-erc20:1:UNLISTED"
    candidate_unsigned["terms"]["rail"]["railId"] = unlisted_rail
    for payout in candidate_unsigned["terms"]["payoutBindings"]:
        payout["railId"] = unlisted_rail
    candidate = signed_multi(
        "PayeeBoundAgreementDocument", candidate_unsigned, ["buyer", "seller"]
    )
    validation = validate_agreement_against_listing(listing, candidate)
    signatures_valid = bool(validation["signatureResults"]) and all(
        result["verified"] for result in validation["signatureResults"]
    )
    return {
        "id": "agreement-outside-listing-policy",
        "mutation": "Agreement selects a rail absent from Listing.acceptedRails",
        "rules": ["RFQ-3", "CA-1", "§8.5.2 check 3"],
        "vectorIds": ["neg-rail-reject"],
        "enforcementPath": "validate_agreement_against_listing",
        "validation": validation,
        "expected": "reject-before-settle",
        "observed": validation["observed"],
        "passed": (
            signatures_valid
            and not validation["accepted"]
            and validation["reason"]
            == "agreement selected a rail outside listing policy"
        ),
    }


def duplicate_settlement_case(substrate: FakeSubstrate) -> dict[str, Any]:
    vectors = load_json(SB2_VECTORS)["vectors"]
    first = next(item for item in vectors if item["name"] == "first-claim-evm")["record"]
    duplicate = next(
        item for item in vectors if item["name"] == "cross-session-double-count"
    )["record"]
    tx_id = settlement_tx_id(first)
    first_result = substrate.claim_settlement(tx_id, first["jobId"], first["phaseIndex"])
    duplicate_result = substrate.claim_settlement(
        settlement_tx_id(duplicate), duplicate["jobId"], duplicate["phaseIndex"]
    )
    passed = first_result == "count" and duplicate_result == "reject"
    return {
        "id": "duplicate-settlement-transaction-id",
        "mutation": "one canonical settlement-tx-id is rebound to a second jobId",
        "rules": ["SB-1", "SB-2"],
        "vectorIds": ["sb2-settlement-uniqueness-v0.1#cross-session-double-count"],
        "settlementTxId": tx_id,
        "expected": "reject-later-binding",
        "observed": "reject-later-binding" if passed else duplicate_result,
        "passed": passed,
    }


def delivery_failure_case(context: dict[str, Any]) -> dict[str, Any]:
    transition = evaluate_delivery_after_payment(
        context["payment"], {"ok": False, "errorClass": "counterparty"}
    )
    substrate = FakeSubstrate()
    failure_evidence = signed_single(
        "SettlementEvidence", transition["evidenceUnsigned"], "orchestrator"
    )
    evidence_trace, evidence_ref = trace_artifact(
        stage="DACS-4",
        artifact_id="settlement-delivery-counterparty-failure",
        kind="SettlementEvidence",
        artifact=failure_evidence,
        logical_address=f"dacs4:evidence:delivery-failure:{JOB_ID}",
        publisher="orchestrator",
        substrate=substrate,
    )
    failure_unsigned = copy.deepcopy(
        signing_scope("AttestationBundle", context["bundleBase"])
    )
    failure_unsigned["outcome"] = transition["sessionOutcome"]
    failure_unsigned["phaseSummary"][-1] = {
        **transition["phaseEntry"],
        "attestationRef": evidence_ref,
    }
    failure_unsigned["settlementEvidence"] = [context["paymentRef"], evidence_ref]
    failure_bundle = signed_multi(
        "AttestationBundle", failure_unsigned, ["buyer", "seller", "orchestrator"]
    )
    failure_bundle["anchoredByRole"] = "orchestrator"
    bundle_trace, _ = trace_artifact(
        stage="DACS-5",
        artifact_id="attestation-bundle-delivery-counterparty-failure",
        kind="AttestationBundle",
        artifact=failure_bundle,
        logical_address="stor-"
        + sha256_hex(f"{JOB_ID}-bundle-delivery-failure".encode()),
        publisher="orchestrator",
        substrate=substrate,
    )
    evidence_signatures_valid = all(
        result["verified"] for result in evidence_trace["signatureResults"]
    )
    bundle_signatures_valid = all(
        result["verified"] for result in bundle_trace["signatureResults"]
    )
    return {
        "id": "delivery-failure-after-payment",
        "mutation": "delivery adapter returns counterparty failure after final payment",
        "rules": ["PIPE-3", "ST-2"],
        "vectorIds": ["settlement-delivery-missing-deliverable-fail"],
        "enforcementPath": "evaluate_delivery_after_payment",
        "paymentRemainsRecorded": transition["paymentRemainsRecorded"],
        "failureEvidence": {
            "artifact": failure_evidence,
            "artifactHash": evidence_trace["artifactHash"],
            "attestationRef": evidence_ref,
            "signatureResults": evidence_trace["signatureResults"],
        },
        "resultingBundle": {
            "artifact": failure_bundle,
            "artifactHash": bundle_trace["artifactHash"],
            "signatureResults": bundle_trace["signatureResults"],
        },
        "expected": "failed-counterparty",
        "observed": transition["sessionOutcome"],
        "passed": (
            transition["sessionOutcome"] == "failed-counterparty"
            and transition["paymentRemainsRecorded"]
            and failure_unsigned["settlementEvidence"][0] == context["paymentRef"]
            and evidence_signatures_valid
            and bundle_signatures_valid
        ),
    }


def divergent_bundle_case(context: dict[str, Any]) -> dict[str, Any]:
    buyer = copy.deepcopy(context["bundleCopies"]["buyer"])
    seller_unsigned = copy.deepcopy(
        signing_scope("AttestationBundle", context["bundleBase"])
    )
    seller_unsigned["outcome"] = "failed-counterparty"
    seller_unsigned["phaseSummary"][-1] = {
        "index": 4,
        "kind": "deliver-storage-program",
        "outcome": "fail",
        "errorClass": "counterparty",
    }
    seller_unsigned["settlementEvidence"] = [context["paymentRef"]]
    seller = signed_multi(
        "AttestationBundle", seller_unsigned, ["buyer", "seller", "orchestrator"]
    )
    seller["anchoredByRole"] = "seller"
    consumption = consume_bundle_pair(buyer, seller)
    buyer_hash = artifact_hash("AttestationBundle", buyer)
    seller_hash = artifact_hash("AttestationBundle", seller)
    return {
        "id": "divergent-buyer-seller-bundles",
        "mutation": "separately signed role copies contradict on outcome and phase summary",
        "rules": ["§10.4.3(d)", "§10.5.1 guard (ii)"],
        "vectorIds": ["verify-consume-divergent"],
        "enforcementPath": "consume_bundle_pair",
        "buyerBundleHash": buyer_hash,
        "sellerBundleHash": seller_hash,
        "consumption": consumption,
        "expected": "divergent-exclude-from-reputation",
        "observed": (
            "divergent-exclude-from-reputation"
            if consumption["disposition"] == "divergent"
            and consumption["reputationDisposition"] == "exclude"
            else consumption["disposition"]
        ),
        "passed": (
            consumption["disposition"] == "divergent"
            and consumption["reputationDisposition"] == "exclude"
        ),
    }


def parse_profile_versions(profile_text: str) -> dict[str, str]:
    rows = re.findall(r"\| \[([^]]+)\]\([^)]+\) \| ([0-9.]+) \|", profile_text)
    return dict(rows)


def validate_links(manifest: dict[str, Any]) -> None:
    manifest_ids = {case["id"] for case in manifest["cases"]}
    required = {
        vector_id
        for links in STAGE_LINKS.values()
        for vector_id in links["vectorIds"]
    }
    required.update(
        {
            "vet-counterparty-malformed-attribution",
            "neg-rail-reject",
            "settlement-delivery-missing-deliverable-fail",
            "verify-consume-divergent",
        }
    )
    missing = sorted(required - manifest_ids)
    if missing:
        raise ValueError("walkthrough links missing manifest vector IDs: " + ", ".join(missing))
    sb2 = load_json(SB2_VECTORS)
    if not any(item["name"] == "cross-session-double-count" for item in sb2["vectors"]):
        raise ValueError("SB-2 cross-session-double-count vector is missing")


def build_trace() -> dict[str, Any]:
    profile_versions = parse_profile_versions(PROFILE.read_text(encoding="utf-8"))
    manifest = load_json(MANIFEST)
    expected_documents = [
        "CORE",
        "DACS-1-IDENTIFY",
        "DACS-2-VET",
        "DACS-3-NEGOTIATE",
        "DACS-4-SETTLE",
        "DACS-5-VERIFY",
    ]
    if list(profile_versions) != expected_documents:
        raise ValueError("spec/PROFILE.md no longer pins the expected v0.1 document set")
    # The unqualified DACS-v0.1 profile identity remains the shared baseline,
    # while stage modules advance independently. The current composition table
    # therefore need not contain one common document version; the conformance
    # manifest still declares the baseline profile it exercises.
    if manifest["dacsVersion"] != "0.1":
        raise ValueError("conformance manifest no longer targets the DACS-v0.1 baseline")
    validate_links(manifest)

    substrate = FakeSubstrate()
    stages, context = build_happy_path(substrate)
    validate_happy_path(stages, context)
    negatives = [
        malformed_identity_case(context["identities"]["buyer"]),
        outside_policy_case(context["listing"], context["agreement"]),
        duplicate_settlement_case(substrate),
        delivery_failure_case(context),
        divergent_bundle_case(context),
    ]
    if not all(case["passed"] for case in negatives):
        raise ValueError("one or more deterministic negative examples did not reject/classify")

    artifact_count = sum(len(stage["artifacts"]) for stage in stages)
    return {
        "walkthroughVersion": "2",
        "status": "non-normative-reference-tooling",
        "profile": {
            "path": "spec/PROFILE.md",
            "dacsVersion": "0.1",
            "documents": profile_versions,
            "sha256": file_sha256(PROFILE),
        },
        "manifest": {
            "path": "conformance/MANIFEST.json",
            "dacsVersion": manifest["dacsVersion"],
            "caseCount": len(manifest["cases"]),
            "sha256": file_sha256(MANIFEST),
        },
        "source": {
            "kind": "deterministic-generated-chain",
            "publicTestKeyRoles": list(SEEDS),
            "settlementUniquenessVector": "conformance/vectors/security/sb2-settlement-uniqueness-v0.1.json",
            "settlementUniquenessVectorStatus": "historical-superseded",
            "currentCollisionAuthorityVector": "conformance/vectors/security/sb2-collision-authority-v0.8.json",
            "settlementUniquenessVectorSha256": file_sha256(SB2_VECTORS),
        },
        "substrate": {
            "adapter": "FakeSubstrate",
            "logicalNativeSeparated": True,
            "bindingCount": len(substrate.bindings),
            "liveSdkCalls": False,
            "operationalFollowUps": [
                "https://github.com/DACS-Agent-commerce/DACS-Standard/issues/212",
                "https://github.com/DACS-Agent-commerce/DACS-Standard/issues/242",
            ],
        },
        "stages": stages,
        "negativeExamples": negatives,
        "result": {
            "verifies": True,
            "stageCount": len(stages),
            "artifactCount": artifact_count,
            "negativeCount": len(negatives),
            "anchoredObjectCount": len(substrate.native_anchors),
        },
    }


def computed_pins(trace: dict[str, Any]) -> dict[str, str]:
    return {
        "profileSha256": file_sha256(PROFILE),
        "manifestSha256": file_sha256(MANIFEST),
        "settlementUniquenessVectorSha256": file_sha256(SB2_VECTORS),
        "traceSha256": sha256_hex(canonical_json(trace)),
    }


def check_pins(trace: dict[str, Any]) -> None:
    expected = load_json(PINS)
    actual = computed_pins(trace)
    if expected != actual:
        lines = ["lifecycle walkthrough pin drift:"]
        for key in actual:
            if expected.get(key) != actual[key]:
                lines.append(f"- {key}: expected {expected.get(key)!r}, got {actual[key]!r}")
        for key in expected.keys() - actual.keys():
            lines.append(f"- obsolete pin: {key}")
        raise ValueError("\n".join(lines))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate pins (the default)")
    parser.add_argument("--json", action="store_true", help="emit the complete trace")
    parser.add_argument(
        "--print-pins",
        action="store_true",
        help="print pins after an intentional profile/vector update",
    )
    args = parser.parse_args(argv)
    try:
        trace = build_trace()
        if args.print_pins:
            print(json.dumps(computed_pins(trace), indent=2, sort_keys=True))
            return 0
        if args.check or not args.json:
            check_pins(trace)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"lifecycle walkthrough failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(trace, indent=2, ensure_ascii=False))
    else:
        print(
            "lifecycle walkthrough: PASS "
            f"({trace['result']['stageCount']} stages, "
            f"{trace['result']['artifactCount']} artifacts, "
            f"{trace['result']['negativeCount']} negative examples, "
            f"trace {computed_pins(trace)['traceSha256']})"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
