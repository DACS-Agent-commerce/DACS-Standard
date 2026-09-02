#!/usr/bin/env python3
"""Reference predicates for CORE SR2-10..SR2-13 and registry bootstrap v1.

The receipt-evidence booleans in these candidate fixtures are results supplied
by a substrate-specific proof verifier. They are never treated as proof bytes.
Registry-bootstrap signatures are genuine Ed25519 signatures over the exact
registered DACS domain.
"""
from __future__ import annotations

import base64
import hashlib
import math
import re
from copy import deepcopy
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jcs import canonicalize as jcs_canonicalize


BOOTSTRAP_DOMAIN = b"dacs-registry-bootstrap:v1:"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
KEY_ID = re.compile(r"^key:([0-9a-f]{64})$")
STATE_RANK = {"submitted": 0, "accepted": 1, "included": 2, "finalized": 3}
PAIRING = {
    "recipe": "dacs2:registry:v0.1",
    "rail": "dacs4:registry:v0.1",
}
SIGNATURE_FIELDS = {"authorizationSignature", "authorityAcceptanceSignature"}


def canonical_bytes(value: Any) -> bytes:
    return jcs_canonicalize(value).encode("utf-8")


def hash_hex(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def descriptor_hash(descriptor: dict[str, Any]) -> str:
    return hash_hex({k: v for k, v in descriptor.items() if k not in SIGNATURE_FIELDS})


def _try_descriptor_hash(descriptor: Any) -> str | None:
    if not isinstance(descriptor, dict):
        return None
    try:
        return descriptor_hash(descriptor)
    except (TypeError, ValueError, UnicodeError):
        return None


def _decode_b64url(value: Any) -> bytes | None:
    if not isinstance(value, str) or not value or "=" in value:
        return None
    if re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        return None
    try:
        raw = base64.urlsafe_b64decode(value + "=" * ((-len(value)) % 4))
    except Exception:
        return None
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        return None
    return raw


def _verify_signature(signature: Any, digest: str, expected_key: str) -> bool:
    if not isinstance(signature, dict) or set(signature) != {"keyId", "algorithm", "value"}:
        return False
    if signature.get("algorithm") != "ed25519" or signature.get("keyId") != expected_key:
        return False
    match = KEY_ID.fullmatch(expected_key)
    raw_signature = _decode_b64url(signature.get("value"))
    if match is None or raw_signature is None or len(raw_signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(match.group(1))).verify(
            raw_signature, BOOTSTRAP_DOMAIN + digest.encode("ascii")
        )
    except (ValueError, InvalidSignature):
        return False
    return True


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _finite_number(value: Any) -> bool:
    return type(value) in {int, float} and math.isfinite(value)


def _valid_reference(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and _nonempty_string(value.get("kind"))
        and _nonempty_string(value.get("value"))
    )


def _valid_receipt_shape(receipt: Any) -> bool:
    if not isinstance(receipt, dict) or receipt.get("receiptVersion") != "1":
        return False
    if any(
        not _nonempty_string(receipt.get(field))
        for field in (
            "substrate",
            "finalityProfile",
            "logicalAddress",
            "nativeAddress",
            "contentHash",
            "writer",
        )
    ):
        return False
    if HEX64.fullmatch(receipt["contentHash"]) is None:
        return False
    if not _valid_reference(receipt.get("transactionRef")):
        return False
    if "nonce" in receipt and not _nonempty_string(receipt["nonce"]):
        return False
    if receipt.get("state") not in STATE_RANK:
        return False
    if receipt.get("observationDisposition") != "established":
        return False
    if not _finite_number(receipt.get("observedAt")):
        return False
    if not _valid_reference(receipt.get("evidence")):
        return False
    block_ref = receipt.get("blockRef")
    if receipt["state"] in {"included", "finalized"}:
        if not isinstance(block_ref, dict) or not _nonempty_string(block_ref.get("id")):
            return False
    if isinstance(block_ref, dict):
        if "height" in block_ref and (
            not isinstance(block_ref["height"], str)
            or re.fullmatch(r"0|[1-9][0-9]*", block_ref["height"]) is None
        ):
            return False
        if "timestamp" in block_ref and not _finite_number(block_ref["timestamp"]):
            return False
    try:
        canonical_bytes(receipt)
    except (TypeError, ValueError, UnicodeError):
        return False
    return True


def _receipt_tuple(receipt: dict[str, Any]) -> tuple[Any, ...]:
    if not _valid_receipt_shape(receipt):
        raise TypeError("receipt does not match the AnchorReceipt shape")
    transaction_ref = receipt["transactionRef"]
    return (
        receipt.get("substrate"),
        receipt.get("logicalAddress"),
        receipt.get("nativeAddress"),
        receipt.get("contentHash"),
        canonical_bytes(transaction_ref).decode("utf-8"),
        receipt.get("writer"),
        receipt.get("nonce"),
    )


def evaluate_resolution(case: dict[str, Any]) -> str:
    """Return pass/fail/indeterminate for one portable-resolution fixture."""
    policy = case.get("absencePolicy", {})
    authenticated_absence = (
        case.get("claimsAbsent") is True
        and isinstance(policy, dict)
        and policy.get("declared") is True
        and policy.get("satisfied") is True
    )

    carriers = case.get("carriers")
    if not isinstance(carriers, list) or not carriers:
        return "pass" if authenticated_absence else "indeterminate"

    qualified_receipts: list[tuple[tuple[Any, ...], tuple[Any, ...], dict[str, Any]]] = []
    qualified_references: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    storage = case.get("storage")
    if not isinstance(storage, dict):
        storage = {}
    for carrier in carriers:
        if not isinstance(carrier, dict):
            continue
        kind = carrier.get("kind")
        if kind in {"bare-native-locator", "catalog-assertion", "index-assertion"}:
            continue
        if kind == "authenticated-reference":
            if carrier.get("referenceAuthenticated") is not True:
                continue
            if carrier.get("surface") not in {
                "finalized-dacs5-bundle",
                "registry-bootstrap-index",
            }:
                continue
            native = carrier.get("nativeAddress")
            content_hash = carrier.get("contentHash")
            if (
                not _nonempty_string(native)
                or not _nonempty_string(content_hash)
                or HEX64.fullmatch(content_hash) is None
            ):
                continue
            content = storage.get(native)
            try:
                content_matches = content is not None and hash_hex(content) == carrier.get("contentHash")
            except (TypeError, ValueError, UnicodeError):
                content_matches = False
            if not content_matches:
                continue
            expected_hash = case.get("expectedContentHash")
            if expected_hash is not None and carrier.get("contentHash") != expected_hash:
                continue
            if carrier.get("artifactChecksVerified") is not True:
                continue
            qualified_references.append(((native, carrier.get("contentHash")), carrier))
            continue
        if kind != "anchor-receipt":
            continue
        receipt = carrier.get("receipt")
        if (
            not _valid_receipt_shape(receipt)
            or carrier.get("receiptEvidenceVerified") is not True
        ):
            continue
        state = receipt.get("state")
        minimum = case.get("minimumState")
        if state not in STATE_RANK or minimum not in STATE_RANK or STATE_RANK[state] < STATE_RANK[minimum]:
            continue
        if receipt.get("logicalAddress") != case.get("expectedLogicalAddress"):
            continue
        expected_hash = case.get("expectedContentHash")
        if expected_hash is not None and receipt.get("contentHash") != expected_hash:
            continue
        if carrier.get("authorityVerified") is not True:
            continue
        native = receipt["nativeAddress"]
        content = storage.get(native)
        try:
            content_matches = content is not None and hash_hex(content) == receipt.get("contentHash")
        except (TypeError, ValueError, UnicodeError):
            content_matches = False
        if not content_matches:
            continue
        delivered_at = carrier.get("deliveredAt")
        required_by = case.get("requiredBy")
        if delivered_at is not None or required_by is not None:
            if not _finite_number(delivered_at) or not _finite_number(required_by):
                continue
            if delivered_at > required_by:
                return "fail"
        try:
            receipt_tuple = _receipt_tuple(receipt)
        except (TypeError, ValueError, UnicodeError):
            # An unsupported transactionRef cannot participate in an SR2-5
            # identity comparison. Discard this carrier just like any other
            # malformed or unverifiable receipt candidate.
            continue
        qualified_receipts.append((
            receipt_tuple,
            (receipt.get("nativeAddress"), receipt.get("contentHash")),
            carrier,
        ))

    if not qualified_receipts and not qualified_references:
        return "pass" if authenticated_absence else "indeterminate"
    if authenticated_absence:
        return "indeterminate"
    if qualified_receipts:
        receipt_tuples = {item[0] for item in qualified_receipts}
        if len(receipt_tuples) != 1:
            return "indeterminate"
        receipt_artifact = qualified_receipts[0][1]
        if any(reference[0] != receipt_artifact for reference in qualified_references):
            return "indeterminate"
        return "pass"
    reference_artifacts = {item[0] for item in qualified_references}
    return "pass" if len(reference_artifacts) == 1 else "indeterminate"


def _basic_descriptor(descriptor: Any) -> bool:
    if not isinstance(descriptor, dict):
        return False
    discriminators = [
        key for key in descriptor if isinstance(key, str) and key.endswith("BootstrapVersion")
    ]
    if discriminators != ["registryBootstrapVersion"] or descriptor.get("registryBootstrapVersion") != "1":
        return False
    required = {
        "registryBootstrapVersion", "registryKind", "registryLogicalAddress",
        "substrate", "sequence", "nativeIndexAddress", "indexContentHash",
        "indexAnchorReceipt", "authorityKeyId", "authorizationSignature",
    }
    if not required.issubset(descriptor):
        return False
    kind = descriptor.get("registryKind")
    if kind not in PAIRING or descriptor.get("registryLogicalAddress") != PAIRING[kind]:
        return False
    sequence = descriptor.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1 or sequence > 9007199254740991:
        return False
    if not isinstance(descriptor.get("substrate"), str) or not descriptor["substrate"]:
        return False
    if not isinstance(descriptor.get("nativeIndexAddress"), str) or not descriptor["nativeIndexAddress"]:
        return False
    if HEX64.fullmatch(str(descriptor.get("indexContentHash"))) is None:
        return False
    if KEY_ID.fullmatch(str(descriptor.get("authorityKeyId"))) is None:
        return False
    revoked = descriptor.get("revokedAuthorityKeyIds", [])
    if not isinstance(revoked, list) or revoked != sorted(set(revoked)):
        return False
    if any(KEY_ID.fullmatch(str(key)) is None for key in revoked):
        return False
    if descriptor["authorityKeyId"] in revoked:
        return False
    if sequence == 1:
        if "supersedesDescriptorHash" in descriptor or "authorityAcceptanceSignature" in descriptor:
            return False
    elif HEX64.fullmatch(str(descriptor.get("supersedesDescriptorHash"))) is None:
        return False
    receipt = descriptor.get("indexAnchorReceipt")
    if not isinstance(receipt, dict):
        return False
    return True


def _verify_snapshot(descriptor: dict[str, Any], case: dict[str, Any]) -> str:
    receipt = descriptor["indexAnchorReceipt"]
    if receipt.get("receiptVersion") != "1" or receipt.get("state") != "finalized":
        return "fail"
    if receipt.get("observationDisposition") != "established" or not isinstance(receipt.get("blockRef"), dict):
        return "fail"
    if (
        receipt.get("substrate") != descriptor.get("substrate")
        or receipt.get("logicalAddress") != descriptor.get("registryLogicalAddress")
        or receipt.get("nativeAddress") != descriptor.get("nativeIndexAddress")
        or receipt.get("contentHash") != descriptor.get("indexContentHash")
    ):
        return "fail"
    evidence = receipt.get("evidence", {}).get("value") if isinstance(receipt.get("evidence"), dict) else None
    if receipt.get("evidence", {}).get("kind") == "registry-dependent":
        return "fail"
    if evidence not in case.get("verifiedEvidenceValues", []):
        return "indeterminate"
    snapshot = case.get("indexStorage", {}).get(descriptor.get("nativeIndexAddress"))
    if snapshot is None or hash_hex(snapshot) != descriptor.get("indexContentHash"):
        return "indeterminate"
    return "pass"


def _validate_root(descriptor: dict[str, Any], case: dict[str, Any]) -> str:
    if not _basic_descriptor(descriptor) or descriptor.get("sequence") != 1:
        return "fail"
    digest = descriptor_hash(descriptor)
    if not _verify_signature(descriptor.get("authorizationSignature"), digest, descriptor["authorityKeyId"]):
        return "fail"
    pin = case.get("trustPin", {})
    if not isinstance(pin, dict) or not ({"descriptorHash", "authorityKeyId"} & set(pin)):
        return "fail"
    if "descriptorHash" in pin and pin["descriptorHash"] != digest:
        return "fail"
    if "authorityKeyId" in pin and pin["authorityKeyId"] != descriptor["authorityKeyId"]:
        return "fail"
    return _verify_snapshot(descriptor, case)


def _validate_successor(
    predecessor: dict[str, Any], descriptor: dict[str, Any], case: dict[str, Any]
) -> str:
    if not _basic_descriptor(descriptor):
        return "fail"
    if descriptor.get("sequence") != predecessor.get("sequence") + 1:
        return "fail"
    if descriptor.get("supersedesDescriptorHash") != descriptor_hash(predecessor):
        return "fail"
    for field in ("registryKind", "registryLogicalAddress", "substrate", "registryBootstrapVersion"):
        if descriptor.get(field) != predecessor.get(field):
            return "fail"
    previous_revoked = predecessor.get("revokedAuthorityKeyIds", [])
    current_revoked = descriptor.get("revokedAuthorityKeyIds", [])
    if not set(previous_revoked).issubset(current_revoked):
        return "fail"
    digest = descriptor_hash(descriptor)
    previous_key = predecessor["authorityKeyId"]
    if previous_key in previous_revoked:
        return "fail"
    if not _verify_signature(descriptor.get("authorizationSignature"), digest, previous_key):
        return "fail"
    changed = descriptor["authorityKeyId"] != previous_key
    acceptance = descriptor.get("authorityAcceptanceSignature")
    if changed:
        if not _verify_signature(acceptance, digest, descriptor["authorityKeyId"]):
            return "fail"
    elif acceptance is not None:
        return "fail"
    if descriptor.get("indexContentHash") != predecessor.get("indexContentHash"):
        if descriptor.get("nativeIndexAddress") == predecessor.get("nativeIndexAddress"):
            return "fail"
    elif descriptor.get("nativeIndexAddress") != predecessor.get("nativeIndexAddress"):
        return "fail"
    return _verify_snapshot(descriptor, case)


def _definition_result(head: dict[str, Any], case: dict[str, Any]) -> str:
    query = case.get("definitionQuery")
    if not isinstance(query, dict):
        return "pass"
    index = case.get("indexStorage", {}).get(head["nativeIndexAddress"])
    entries = index.get("entries", []) if isinstance(index, dict) else []
    matches = [
        entry for entry in entries
        if entry.get("id") == query.get("id") and entry.get("version") == query.get("version")
    ]
    if len(matches) != 1:
        return "fail"
    entry = matches[0]
    locator = entry.get("anchor", {}).get("locator") if isinstance(entry.get("anchor"), dict) else None
    definition = case.get("definitionStorage", {}).get(locator)
    if definition is None:
        return "indeterminate"
    try:
        definition_hash = hash_hex(definition)
    except (TypeError, ValueError, UnicodeError):
        return "fail"
    if definition_hash != entry.get("contentHash"):
        return "fail"
    checks = case.get("definitionChecks", {})
    if checks.get("signatureVerified") is not True or checks.get("semanticRulesVerified") is not True:
        return "fail"
    return "pass"


def evaluate_bootstrap(case: dict[str, Any]) -> str:
    descriptors = case.get("descriptors")
    if not isinstance(descriptors, list) or not descriptors:
        return "indeterminate"
    root_candidates = [
        d for d in descriptors if isinstance(d, dict) and d.get("sequence") == 1
    ]
    valid_roots: dict[str, dict[str, Any]] = {}
    indeterminate_root_seen = False
    for candidate in root_candidates:
        try:
            status = _validate_root(candidate, case)
        except (TypeError, ValueError, UnicodeError):
            status = "fail"
        if status == "pass":
            digest = _try_descriptor_hash(candidate)
            if digest is not None:
                valid_roots.setdefault(digest, candidate)
        elif status == "indeterminate":
            indeterminate_root_seen = True
    if len(valid_roots) > 1 or indeterminate_root_seen:
        return "indeterminate"
    if not valid_roots:
        return "fail"
    root = next(iter(valid_roots.values()))
    head = root
    accepted_chain = [root]
    while True:
        head_hash = _try_descriptor_hash(head)
        if head_hash is None:
            return "fail"
        candidates = [
            d for d in descriptors
            if isinstance(d, dict)
            and d.get("supersedesDescriptorHash") == head_hash
        ]
        valid: list[dict[str, Any]] = []
        indeterminate_seen = False
        for candidate in candidates:
            try:
                result = _validate_successor(head, candidate, case)
            except (TypeError, ValueError, UnicodeError):
                result = "fail"
            if result == "pass":
                valid.append(candidate)
            elif result == "indeterminate":
                indeterminate_seen = True
        if len(valid) > 1:
            return "indeterminate"
        if indeterminate_seen and valid:
            return "indeterminate"
        if len(valid) == 1:
            head = valid[0]
            accepted_chain.append(head)
            continue
        if indeterminate_seen:
            return "indeterminate"
        break

    stored = case.get("storedLatest")
    if isinstance(stored, dict) and case.get("mode", "latest") == "latest":
        if head.get("sequence") < stored.get("sequence", 0):
            return "fail"
        if head.get("sequence") == stored.get("sequence") and _try_descriptor_hash(head) != stored.get("descriptorHash"):
            return "indeterminate"
    if case.get("mode") == "historical":
        target_sequence = case.get("targetSequence")
        target_hash = case.get("targetDescriptorHash")
        if (
            isinstance(target_sequence, bool)
            or not isinstance(target_sequence, int)
            or HEX64.fullmatch(str(target_hash)) is None
        ):
            return "fail"
        matches = [
            d for d in accepted_chain
            if d.get("sequence") == target_sequence
            and _try_descriptor_hash(d) == target_hash
        ]
        if len(matches) != 1:
            return "indeterminate"
        head = matches[0]
    return _definition_result(head, case)


def evaluate_vector(vector: dict[str, Any]) -> str:
    family = vector.get("family")
    if family == "resolution":
        return evaluate_resolution(deepcopy(vector["input"]))
    if family == "bootstrap":
        return evaluate_bootstrap(deepcopy(vector["input"]))
    return "error"
