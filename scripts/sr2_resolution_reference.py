#!/usr/bin/env python3
"""Reference predicates for CORE SR2-10..SR2-13 and registry bootstrap v1.

The receipt-evidence and named class-specific check booleans in these candidate
fixtures are results supplied by the corresponding proof verifier. They are
never treated as proof bytes or accepted for an unregistered carrier class.
Likewise, ``verifiedReceiptEvidence`` contains fixture evidence-verifier outputs,
not proof material. ``expectedRegistryTuple`` and ``trustPin`` are independent
release configuration and are never derived from presented registry material.
Registry-bootstrap signatures are genuine Ed25519 signatures over the exact
registered DACS domain.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
import unicodedata
from copy import deepcopy
from typing import Any, Callable

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
RECIPE_FAMILIES = {
    "verifiable-credential",
    "tlsnotary",
    "zktls",
    "consensus-backed-proxy",
    "oauth-attested",
    "evm-rpc",
    "domain-tls-control",
    "self-signed",
    "demos-gcr-domain",
}
REGISTRY_TUPLE_FIELDS = (
    "registryKind",
    "registryLogicalAddress",
    "substrate",
    "registryBootstrapVersion",
)
SIGNATURE_FIELDS = {"authorizationSignature", "authorityAcceptanceSignature"}
REFERENCE_CLASS_CHECKS = {
    "finalized-dacs5-bundle": "finalizedBundleChecksVerified",
    "registry-bootstrap-index": "registrySnapshotChecksVerified",
}


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
    except (ValueError, binascii.Error):
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
    if type(value) is int:
        return -9007199254740991 <= value <= 9007199254740991
    if type(value) is float:
        return math.isfinite(value) and abs(value) <= 9007199254740991
    return False


def _positive_safe_integer(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, int)
        and 1 <= value <= 9007199254740991
    )


def _nfc_key(value: Any) -> str | None:
    """Return a derived comparison key without changing authenticated input."""
    if not isinstance(value, str):
        return None
    try:
        return unicodedata.normalize("NFC", value)
    except UnicodeError:
        return None


def _valid_hash(value: Any) -> bool:
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def _valid_key_id(value: Any) -> bool:
    return isinstance(value, str) and KEY_ID.fullmatch(value) is not None


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
    state = receipt.get("state")
    if not isinstance(state, str) or state not in STATE_RANK:
        return False
    if receipt.get("observationDisposition") != "established":
        return False
    if not _finite_number(receipt.get("observedAt")):
        return False
    if not _valid_reference(receipt.get("evidence")):
        return False
    block_ref = receipt.get("blockRef")
    if block_ref is not None and not isinstance(block_ref, dict):
        return False
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
    if not isinstance(case, dict):
        return "indeterminate"
    expected_logical = case.get("expectedLogicalAddress")
    minimum = case.get("minimumState")
    expected_hash = case.get("expectedContentHash")
    if not _nonempty_string(expected_logical):
        return "indeterminate"
    if not isinstance(minimum, str) or minimum not in STATE_RANK:
        return "indeterminate"
    if expected_hash is not None and not _valid_hash(expected_hash):
        return "indeterminate"
    storage = case.get("storage")
    if not isinstance(storage, dict):
        return "indeterminate"
    required_by = case.get("requiredBy")
    if required_by is not None and not _finite_number(required_by):
        return "indeterminate"

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

    receipt_candidates: list[
        tuple[tuple[Any, ...], bytes, tuple[str, str], int | float | None, str]
    ] = []
    qualified_references: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    for carrier in carriers:
        if not isinstance(carrier, dict):
            continue
        kind = carrier.get("kind")
        if not isinstance(kind, str):
            continue
        if kind in {"bare-native-locator", "catalog-assertion", "index-assertion"}:
            continue
        if kind == "authenticated-reference":
            if carrier.get("referenceAuthenticated") is not True:
                continue
            surface = carrier.get("surface")
            if not isinstance(surface, str):
                continue
            class_check = REFERENCE_CLASS_CHECKS.get(surface)
            if class_check is None or carrier.get(class_check) is not True:
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
        state = receipt["state"]
        if receipt.get("logicalAddress") != expected_logical:
            continue
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
        try:
            receipt_tuple = _receipt_tuple(receipt)
            receipt_identity = canonical_bytes(receipt)
        except (TypeError, ValueError, UnicodeError):
            # An unsupported transactionRef cannot participate in an SR2-5
            # identity comparison. Discard this carrier just like any other
            # malformed or unverifiable receipt candidate.
            continue
        delivered_at = carrier.get("deliveredAt")
        verified_delivery = delivered_at if _finite_number(delivered_at) else None
        receipt_candidates.append((
            receipt_tuple,
            receipt_identity,
            (receipt.get("nativeAddress"), receipt.get("contentHash")),
            verified_delivery,
            state,
        ))

    qualified_receipts = receipt_candidates
    if receipt_candidates:
        receipt_tuples = {item[0] for item in receipt_candidates}
        if len(receipt_tuples) != 1:
            return "indeterminate"
        receipt_snapshots = {item[1] for item in receipt_candidates}
        if len(receipt_snapshots) != 1:
            return "indeterminate"
        if STATE_RANK[receipt_candidates[0][4]] < STATE_RANK[minimum]:
            qualified_receipts = []
    if not qualified_receipts and not qualified_references:
        return "pass" if authenticated_absence else "indeterminate"
    if authenticated_absence:
        return "indeterminate"
    if qualified_receipts:
        receipt_artifact = qualified_receipts[0][2]
        if any(reference[0] != receipt_artifact for reference in qualified_references):
            return "indeterminate"
        if required_by is not None:
            deliveries = [
                item[3] for item in qualified_receipts if item[3] is not None
            ]
            if not deliveries:
                return "indeterminate"
            if min(deliveries) > required_by:
                return "fail"
        return "pass"
    reference_artifacts = {item[0] for item in qualified_references}
    return "pass" if len(reference_artifacts) == 1 else "indeterminate"


def _valid_expected_registry_tuple(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != set(REGISTRY_TUPLE_FIELDS):
        return False
    kind = value.get("registryKind")
    return (
        isinstance(kind, str)
        and kind in PAIRING
        and value.get("registryLogicalAddress") == PAIRING[kind]
        and _nonempty_string(value.get("substrate"))
        and value.get("registryBootstrapVersion") == "1"
    )


def _matches_expected_registry_tuple(
    descriptor: Any, expected: dict[str, Any]
) -> bool:
    return isinstance(descriptor, dict) and all(
        descriptor.get(field) == expected[field]
        for field in REGISTRY_TUPLE_FIELDS
    )


def _valid_trust_pin(pin: Any) -> bool:
    if not isinstance(pin, dict):
        return False
    has_hash = "descriptorHash" in pin
    has_key = "authorityKeyId" in pin
    if not (has_hash or has_key):
        return False
    if has_hash and not _valid_hash(pin["descriptorHash"]):
        return False
    if has_key and not _valid_key_id(pin["authorityKeyId"]):
        return False
    return True


def _valid_stored_latest(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"sequence", "descriptorHash"}
        and _positive_safe_integer(value.get("sequence"))
        and _valid_hash(value.get("descriptorHash"))
    )


def _valid_verified_receipt_evidence(value: Any) -> bool:
    """Validate independent successful verifier outputs, not presented proof bytes."""
    return isinstance(value, list) and all(
        isinstance(item, dict)
        and set(item) == {"evidence", "receiptHash"}
        and _valid_reference(item.get("evidence"))
        and set(item["evidence"]) == {"kind", "value"}
        and _valid_hash(item.get("receiptHash"))
        for item in value
    )


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
    if (
        not isinstance(kind, str)
        or kind not in PAIRING
        or descriptor.get("registryLogicalAddress") != PAIRING[kind]
    ):
        return False
    sequence = descriptor.get("sequence")
    if not _positive_safe_integer(sequence):
        return False
    if not _nonempty_string(descriptor.get("substrate")):
        return False
    if not _nonempty_string(descriptor.get("nativeIndexAddress")):
        return False
    if not _valid_hash(descriptor.get("indexContentHash")):
        return False
    if not _valid_key_id(descriptor.get("authorityKeyId")):
        return False
    revoked = descriptor.get("revokedAuthorityKeyIds", [])
    if not isinstance(revoked, list) or any(
        not _valid_key_id(key) for key in revoked
    ):
        return False
    if revoked != sorted(set(revoked)):
        return False
    if descriptor["authorityKeyId"] in revoked:
        return False
    if sequence == 1:
        if "supersedesDescriptorHash" in descriptor or "authorityAcceptanceSignature" in descriptor:
            return False
    elif not _valid_hash(descriptor.get("supersedesDescriptorHash")):
        return False
    receipt = descriptor.get("indexAnchorReceipt")
    if not isinstance(receipt, dict):
        return False
    return True


def _verify_snapshot(descriptor: dict[str, Any], case: dict[str, Any]) -> str:
    receipt = descriptor["indexAnchorReceipt"]
    if not _valid_receipt_shape(receipt):
        return "fail"
    if receipt.get("state") != "finalized":
        return "fail"
    if (
        receipt.get("observationDisposition") != "established"
        or not isinstance(receipt.get("blockRef"), dict)
    ):
        return "fail"
    if (
        receipt.get("substrate") != descriptor.get("substrate")
        or receipt.get("logicalAddress") != descriptor.get("registryLogicalAddress")
        or receipt.get("nativeAddress") != descriptor.get("nativeIndexAddress")
        or receipt.get("contentHash") != descriptor.get("indexContentHash")
    ):
        return "fail"
    evidence_record = receipt["evidence"]
    if evidence_record["kind"] == "registry-dependent":
        return "fail"
    verified_evidence = case.get("verifiedReceiptEvidence")
    if not _valid_verified_receipt_evidence(verified_evidence):
        return "fail"
    try:
        receipt_digest = hash_hex(receipt)
        evidence_bytes = canonical_bytes(evidence_record)
    except (TypeError, ValueError, UnicodeError):
        return "fail"
    try:
        verified = any(
            result["receiptHash"] == receipt_digest
            and canonical_bytes(result["evidence"]) == evidence_bytes
            for result in verified_evidence
        )
    except (TypeError, ValueError, UnicodeError):
        return "fail"
    if not verified:
        return "indeterminate"
    index_storage = case.get("indexStorage")
    if not isinstance(index_storage, dict):
        return "fail"
    snapshot = index_storage.get(descriptor.get("nativeIndexAddress"))
    if snapshot is None:
        return "indeterminate"
    try:
        if hash_hex(snapshot) != descriptor.get("indexContentHash"):
            return "indeterminate"
    except (TypeError, ValueError, UnicodeError):
        return "fail"
    if not _valid_index_snapshot(snapshot, descriptor):
        return "fail"
    return "pass"


def _valid_index_snapshot(snapshot: Any, descriptor: dict[str, Any]) -> bool:
    """Validate the closed v1 registry-index envelope and entry references."""
    if not isinstance(snapshot, dict):
        return False
    required = {"registryIndexVersion", "registryKind", "revision", "entries"}
    if set(snapshot) != required:
        return False
    if snapshot.get("registryIndexVersion") != "1":
        return False
    if snapshot.get("registryKind") != descriptor.get("registryKind"):
        return False
    revision = snapshot.get("revision")
    if (
        isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision < 1
        or revision > 9007199254740991
        or revision != descriptor.get("sequence")
    ):
        return False
    entries = snapshot.get("entries")
    if not isinstance(entries, list):
        return False
    seen: set[tuple[str, int]] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            return False
        if set(entry) != {"id", "version", "anchor", "contentHash"}:
            return False
        identifier = entry.get("id")
        version = entry.get("version")
        identifier_key = _nfc_key(identifier)
        if identifier_key is None or not identifier:
            return False
        if not _positive_safe_integer(version):
            return False
        identity = (identifier_key, version)
        if identity in seen:
            return False
        seen.add(identity)
        anchor = entry.get("anchor")
        if not isinstance(anchor, dict) or set(anchor) != {"kind", "locator"}:
            return False
        anchor_kind = anchor.get("kind")
        if (
            not isinstance(anchor_kind, str)
            or anchor_kind not in {"storage-program", "ipfs", "https"}
        ):
            return False
        if not isinstance(anchor.get("locator"), str) or not anchor["locator"]:
            return False
        if not _valid_hash(entry.get("contentHash")):
            return False
    return True


def _validate_root(descriptor: dict[str, Any], case: dict[str, Any]) -> str:
    expected = case["expectedRegistryTuple"]
    if not _matches_expected_registry_tuple(descriptor, expected):
        return "fail"
    if not _basic_descriptor(descriptor) or descriptor.get("sequence") != 1:
        return "fail"
    digest = descriptor_hash(descriptor)
    if not _verify_signature(descriptor.get("authorizationSignature"), digest, descriptor["authorityKeyId"]):
        return "fail"
    pin = case.get("trustPin")
    if not _valid_trust_pin(pin):
        return "fail"
    if "descriptorHash" in pin and pin["descriptorHash"] != digest:
        return "fail"
    if "authorityKeyId" in pin and pin["authorityKeyId"] != descriptor["authorityKeyId"]:
        return "fail"
    return _verify_snapshot(descriptor, case)


def _validate_successor(
    predecessor: dict[str, Any], descriptor: dict[str, Any], case: dict[str, Any]
) -> str:
    expected = case["expectedRegistryTuple"]
    if not _matches_expected_registry_tuple(descriptor, expected):
        return "fail"
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


def _valid_definition_query(query: Any, kind: str) -> bool:
    if not isinstance(query, dict):
        return False
    required = {"id", "family"} if kind == "recipe" else {"id"}
    fields = set(query)
    if fields != required and fields != required | {"version"}:
        return False
    if not _nonempty_string(query.get("id")) or _nfc_key(query.get("id")) is None:
        return False
    if kind == "recipe" and query.get("family") not in RECIPE_FAMILIES:
        return False
    return "version" not in query or _positive_safe_integer(query.get("version"))


def _load_indexed_definition(
    entry: dict[str, Any], kind: str, definition_storage: dict[str, Any]
) -> tuple[str, dict[str, Any] | None, str | None]:
    anchor = entry.get("anchor")
    locator = anchor.get("locator") if isinstance(anchor, dict) else None
    definition = definition_storage.get(locator)
    if definition is None:
        return "indeterminate", None, None
    try:
        definition_hash = hash_hex(definition)
    except (TypeError, ValueError, UnicodeError):
        return "fail", None, None
    if definition_hash != entry.get("contentHash"):
        return "fail", None, None
    if not isinstance(definition, dict):
        return "fail", None, None

    id_field = "scheme" if kind == "recipe" else "railId"
    version_field = "recipeVersion" if kind == "recipe" else "railVersion"
    definition_id = definition.get(id_field)
    definition_version = definition.get(version_field)
    if (
        not _nonempty_string(definition_id)
        or _nfc_key(definition_id) != _nfc_key(entry.get("id"))
        or not _positive_safe_integer(definition_version)
        or definition_version != entry.get("version")
    ):
        return "fail", None, None

    family = None
    if kind == "recipe":
        default_method = definition.get("defaultMethod")
        family = default_method.get("kind") if isinstance(default_method, dict) else None
        if family not in RECIPE_FAMILIES:
            return "fail", None, None
    return "pass", definition, family


def _select_definition(
    head: dict[str, Any], case: dict[str, Any]
) -> tuple[str, dict[str, Any] | None]:
    query = case.get("definitionQuery")
    kind = head.get("registryKind")
    if kind not in PAIRING or not _valid_definition_query(query, kind):
        return "fail", None
    index_storage = case.get("indexStorage")
    if not isinstance(index_storage, dict):
        return "fail", None
    index = index_storage.get(head["nativeIndexAddress"])
    entries = index.get("entries", []) if isinstance(index, dict) else []
    query_id = _nfc_key(query.get("id"))
    matches = [
        entry for entry in entries
        if isinstance(entry, dict) and _nfc_key(entry.get("id")) == query_id
    ]
    definition_storage = case.get("definitionStorage", {})
    if not isinstance(definition_storage, dict):
        return "fail", None

    if "version" in query:
        matches = [entry for entry in matches if entry.get("version") == query["version"]]
        if len(matches) != 1:
            return "fail", None
        status, definition, family = _load_indexed_definition(
            matches[0], kind, definition_storage
        )
        if status != "pass":
            return status, None
        if kind == "recipe" and family != query["family"]:
            return "fail", None
        return "pass", definition

    # Resolve latest by descending numeric version before any selected-definition
    # eligibility checks. An unavailable or unclassifiable higher recipe entry
    # cannot be bypassed because it might belong to the requested family.
    matches.sort(key=lambda entry: entry["version"], reverse=True)
    for entry in matches:
        status, definition, family = _load_indexed_definition(
            entry, kind, definition_storage
        )
        if status != "pass":
            return status, None
        if kind == "rail" or family == query["family"]:
            return "pass", definition
    return "fail", None


def _definition_result(head: dict[str, Any], case: dict[str, Any]) -> str:
    if "definitionQuery" not in case:
        return "pass"
    status, definition = _select_definition(head, case)
    if status != "pass" or definition is None:
        return status
    checks = case.get("definitionChecks", {})
    if not isinstance(checks, dict):
        return "fail"
    if checks.get("signatureVerified") is not True or checks.get("semanticRulesVerified") is not True:
        return "fail"
    return "pass"


def _classify_descriptor_identities(
    candidates: list[dict[str, Any]],
    classify: Callable[[dict[str, Any]], str],
) -> tuple[list[dict[str, Any]], bool]:
    """Classify every transport copy, then collapse its descriptor identity."""
    identities: dict[str, tuple[str, dict[str, Any]]] = {}
    for candidate in candidates:
        candidate_hash = _try_descriptor_hash(candidate)
        try:
            status = classify(candidate)
        except (TypeError, ValueError, UnicodeError):
            status = "fail"
        if candidate_hash is None or status not in {"pass", "indeterminate"}:
            continue
        previous = identities.get(candidate_hash)
        if previous is None or status == "pass":
            identities[candidate_hash] = (status, candidate)
    return (
        [candidate for status, candidate in identities.values() if status == "pass"],
        any(status == "indeterminate" for status, _ in identities.values()),
    )


def evaluate_bootstrap(case: dict[str, Any]) -> str:
    if not isinstance(case, dict):
        return "fail"
    expected = case.get("expectedRegistryTuple")
    if not _valid_expected_registry_tuple(expected):
        return "fail"
    mode = case["mode"] if "mode" in case else "latest"
    if not isinstance(mode, str) or mode not in {"latest", "historical"}:
        return "fail"
    pin = case.get("trustPin")
    if not _valid_trust_pin(pin):
        return "fail"
    if "storedLatest" in case and not _valid_stored_latest(case["storedLatest"]):
        return "fail"
    if not _valid_verified_receipt_evidence(case.get("verifiedReceiptEvidence")):
        return "fail"
    if not isinstance(case.get("indexStorage"), dict):
        return "fail"
    if mode == "historical" and (
        not _positive_safe_integer(case.get("targetSequence"))
        or not _valid_hash(case.get("targetDescriptorHash"))
    ):
        return "fail"

    descriptors = case.get("descriptors")
    if not isinstance(descriptors, list) or not descriptors:
        return "indeterminate"
    roots = [d for d in descriptors if isinstance(d, dict) and d.get("sequence") == 1]
    if "descriptorHash" in pin:
        roots = [d for d in roots if _try_descriptor_hash(d) == pin["descriptorHash"]]
    if "authorityKeyId" in pin:
        roots = [d for d in roots if d.get("authorityKeyId") == pin["authorityKeyId"]]
    valid_roots, indeterminate_root_seen = _classify_descriptor_identities(
        roots, lambda candidate: _validate_root(candidate, case)
    )
    if len(valid_roots) > 1:
        return "indeterminate"
    if valid_roots and indeterminate_root_seen:
        return "indeterminate"
    if not valid_roots:
        return "indeterminate" if indeterminate_root_seen else "fail"
    root = valid_roots[0]
    head = root
    accepted_chain = [root]
    while True:
        head_hash = _try_descriptor_hash(head)
        if head_hash is None:
            return "fail"
        if mode == "historical":
            target_sequence = case["targetSequence"]
            if head.get("sequence") == target_sequence:
                if head_hash != case["targetDescriptorHash"]:
                    return "indeterminate"
                return _definition_result(head, case)
            if head.get("sequence") > target_sequence:
                return "indeterminate"
        candidates = [
            d for d in descriptors
            if isinstance(d, dict)
            and d.get("supersedesDescriptorHash") == head_hash
        ]
        valid, indeterminate_seen = _classify_descriptor_identities(
            candidates,
            lambda candidate: _validate_successor(head, candidate, case),
        )
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
    if stored is not None and mode == "latest":
        stored_sequence = stored.get("sequence")
        stored_hash = stored.get("descriptorHash")
        if head.get("sequence") < stored_sequence:
            return "fail"
        persisted = [
            descriptor for descriptor in accepted_chain
            if descriptor.get("sequence") == stored_sequence
            and _try_descriptor_hash(descriptor) == stored_hash
        ]
        if len(persisted) != 1:
            return "indeterminate"
    if mode == "historical":
        return "indeterminate"
    return _definition_result(head, case)


def evaluate_vector(vector: dict[str, Any]) -> str:
    if not isinstance(vector, dict):
        return "error"
    family = vector.get("family")
    if family == "resolution":
        return evaluate_resolution(deepcopy(vector.get("input")))
    if family == "bootstrap":
        return evaluate_bootstrap(deepcopy(vector.get("input")))
    return "error"
