import base64
import hashlib
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from scripts import generate_revocation_state_completeness_vectors as g

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from scripts.jcs import canonicalize as jcs_canonicalize


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "revocation-state-completeness-v0.8.json"
)
GENERATOR = ROOT / "scripts" / "generate_revocation_state_completeness_vectors.py"
SPEC = ROOT / "spec" / "DACS-1-IDENTIFY.md"
CORE = ROOT / "spec" / "CORE.md"
MAPPING = ROOT / "spec" / "DEMOS-MAPPING.md"
HEAD_DOMAIN = "dacs-revocation-state-head:v1:"
MARKER_DOMAIN = "dacs-revocation:v1:"
LISTING_DOMAIN = "dacs-listing:v1:"
CURRENT_STATE_DOMAIN = "dacs-rsc-conformance-current-state:v1:"
KEY_LIFECYCLE_DOMAIN = "dacs-key-lifecycle:v1:"
KEY_LIFECYCLE_KIND = "dacs1-key-lifecycle-attestation"
CURRENT_STATE_POLICY = "rsc-conformance-test-current-value-v1"
RECEIPT_SUBSTRATE = "conformance:test"
RECEIPT_FINALITY_PROFILE = "rsc-conformance-test-finality-v1"
RECEIPT_WRITER = "demos1seller"
LISTING_LOGICAL_ADDRESS = "dacs1-listings:did%3Aexample%3Aseller:compute-hour:v3"
LISTING_NATIVE_ADDRESS = "storage-program:listing-compute-hour"
AUTHORITATIVE_RELEASE_PIN = "0000000000000000000000000000000000000001"
AUTHORITATIVE_MODULE_VERSIONS = {
    "core": "0.3",
    "dacs1": "0.8",
    "dacs2": "0.6",
    "dacs3": "0.6",
    "dacs4": "0.8",
    "dacs5": "0.7",
}
ZERO_HASH = "00" * 32


def canonical_bytes(value):
    return jcs_canonicalize(value).encode("utf-8")


def hash_hex(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def artifact_hash(value):
    return hash_hex({key: item for key, item in value.items() if key != "signature"})


def decode_b64url(value):
    if not isinstance(value, str):
        raise ValueError("non-string base64url value")
    raw = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ValueError("non-canonical base64url")
    return raw


def verify_artifact(value, public_key, domain):
    if not isinstance(value, dict):
        return False
    if not isinstance(public_key, str):
        return False
    signature = value.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519":
        return False
    if not isinstance(signature.get("value"), str):
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
        key.verify(
            decode_b64url(signature.get("value", "")),
            (domain + artifact_hash(value)).encode("ascii"),
        )
    except (TypeError, ValueError, InvalidSignature):
        return False
    return True


def key_attestation_message(claim, key, valid_at):
    return {"claim": claim, "key": key, "validAt": valid_at}


def verify_authority_evidence(authority, authority_public_key, claim, key_hex, valid_at):
    """Authenticate the key-lifecycle authority evidence (RSC-2).

    The evidence MUST be a closed-shape `{kind, value}` attestation whose Ed25519
    signature binds the exact `(claim, key, validAt)` tuple, where `validAt` is
    the artifact's finalized inclusion state. Every field is type-checked so a
    missing, wrongly-containerized, attacker-substituted, or nested-malformed
    evidence value fails closed without raising.
    """
    if not isinstance(authority, dict) or set(authority) != {"claim", "key", "disposition", "evidence"}:
        return False
    if authority.get("disposition") != "verified":
        return False
    if authority.get("claim") != claim:
        return False
    if not isinstance(authority.get("key"), str) or re.fullmatch(r"[0-9a-f]{64}", authority.get("key", "")) is None:
        return False
    if authority.get("key") != key_hex:
        return False
    evidence = authority.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != {"kind", "value"}:
        return False
    if evidence.get("kind") != KEY_LIFECYCLE_KIND or not isinstance(evidence.get("value"), str):
        return False
    if not isinstance(valid_at, str) or not isinstance(authority_public_key, str):
        return False
    payload = (KEY_LIFECYCLE_DOMAIN + hash_hex(key_attestation_message(claim, key_hex, valid_at))).encode("ascii")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(authority_public_key)).verify(
            decode_b64url(evidence["value"]), payload
        )
    except (TypeError, ValueError, InvalidSignature):
        return False
    return True


def cf4(value):
    encoded = value
    for raw, escaped in (("%", "%25"), (":", "%3A"), ("?", "%3F"), ("&", "%26"), ("=", "%3D")):
        encoded = encoded.replace(raw, escaped)
    return encoded


def empty_hashes():
    result = [hashlib.sha256(b"\x00").digest()]
    for _ in range(256):
        result.append(hashlib.sha256(b"\x01" + result[-1] + result[-1]).digest())
    return result


EMPTY = empty_hashes()


def revoked_leaf(key, revocation_ref):
    ref_hash = hashlib.sha256(canonical_bytes(revocation_ref)).digest()
    return hashlib.sha256(b"\x02" + bytes.fromhex(key) + ref_hash).digest()


def proof_root(key, proof, start):
    if not isinstance(proof, dict) or set(proof) != {"siblings"}:
        return None
    siblings = proof["siblings"]
    if not isinstance(siblings, list):
        return None
    by_height = {}
    prior_height = -1
    for sibling in siblings:
        if not isinstance(sibling, dict) or set(sibling) != {"height", "hash"}:
            return None
        height = sibling["height"]
        value = sibling["hash"]
        if not isinstance(height, int) or isinstance(height, bool) or not prior_height < height < 256:
            return None
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            return None
        raw = bytes.fromhex(value)
        if raw == EMPTY[height]:
            return None
        by_height[height] = raw
        prior_height = height
    index = int(key, 16)
    running = start
    for height in range(256):
        sibling = by_height.get(height, EMPTY[height])
        if (index >> height) & 1:
            running = hashlib.sha256(b"\x01" + sibling + running).digest()
        else:
            running = hashlib.sha256(b"\x01" + running + sibling).digest()
    return running.hex()


def canonical_decimal(value):
    return isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value) is not None


GENESIS_HEAD_FIELDS = {
    "revocationStateHeadVersion", "sellerPrimaryClaim", "logicalAddress",
    "sequence", "previousHeadHash", "rootHash", "entryCount", "issuedAt",
    "signature",
}
TRANSITION_HEAD_FIELDS = GENESIS_HEAD_FIELDS | {"transition"}


def validate_head_shape(head):
    """Enforce RSC-2's sequence-dependent closed RevocationStateHead shape."""
    if not isinstance(head, dict) or head.get("revocationStateHeadVersion") != "1":
        return False
    sequence = head.get("sequence")
    if not canonical_decimal(sequence):
        return False
    expected_fields = GENESIS_HEAD_FIELDS if sequence == "0" else TRANSITION_HEAD_FIELDS
    if set(head) != expected_fields:
        return False
    if not isinstance(head.get("sellerPrimaryClaim"), str):
        return False
    if not isinstance(head.get("logicalAddress"), str):
        return False
    if re.fullmatch(r"[0-9a-f]{64}", head.get("previousHeadHash", "")) is None:
        return False
    if re.fullmatch(r"[0-9a-f]{64}", head.get("rootHash", "")) is None:
        return False
    if not canonical_decimal(head.get("entryCount")):
        return False
    issued_at = head.get("issuedAt")
    if not isinstance(issued_at, int) or isinstance(issued_at, bool):
        return False
    signature = head.get("signature")
    if (
        not isinstance(signature, dict)
        or set(signature) != {"algorithm", "signer", "value"}
        or not isinstance(signature.get("algorithm"), str)
        or not isinstance(signature.get("signer"), str)
        or not isinstance(signature.get("value"), str)
    ):
        return False
    if sequence != "0":
        transition = head.get("transition")
        if not isinstance(transition, dict) or set(transition) != {
            "leafKey", "revocationRef", "priorProof"
        }:
            return False
        if re.fullmatch(r"[0-9a-f]{64}", transition.get("leafKey", "")) is None:
            return False
        ref = transition.get("revocationRef")
        if not isinstance(ref, dict) or set(ref) not in (
            {"anchor", "contentHash"}, {"anchor", "contentHash", "signer"}
        ):
            return False
        anchor = ref.get("anchor")
        if (
            not isinstance(anchor, dict)
            or set(anchor) != {"kind", "locator"}
            or not isinstance(anchor.get("kind"), str)
            or not isinstance(anchor.get("locator"), str)
            or re.fullmatch(r"[0-9a-f]{64}", ref.get("contentHash", "")) is None
            or ("signer" in ref and not isinstance(ref["signer"], str))
        ):
            return False
        prior_proof = transition.get("priorProof")
        if not isinstance(prior_proof, dict) or set(prior_proof) != {"siblings"}:
            return False
        siblings = prior_proof.get("siblings")
        if not isinstance(siblings, list):
            return False
        prior_height = -1
        for sibling in siblings:
            if not isinstance(sibling, dict) or set(sibling) != {"height", "hash"}:
                return False
            height = sibling.get("height")
            if (
                not isinstance(height, int) or isinstance(height, bool)
                or not prior_height < height < 256
                or re.fullmatch(r"[0-9a-f]{64}", sibling.get("hash", "")) is None
            ):
                return False
            prior_height = height
    return True


def marker_tuple(marker, seller):
    return {
        "sellerPrimaryClaim": seller,
        "listingId": marker.get("listingId"),
        "listingVersion": marker.get("listingVersion"),
        "listingContentHash": marker.get("listingContentHash"),
    }


def resolve_marker(context, ref, expected_tuple=None, public_keys=None):
    if not isinstance(ref, dict):
        return None
    markers = context.get("resolvedMarkers")
    if not isinstance(markers, list):
        return None
    candidates = [
        item for item in markers
        if isinstance(item, dict) and item.get("revocationRef") == ref
    ]
    if len(candidates) != 1:
        return None
    candidate = candidates[0]
    marker = candidate.get("marker")
    authority = candidate.get("authority")
    receipt = candidate.get("receipt")
    if not isinstance(authority, dict) or authority.get("disposition") != "verified":
        return None
    if authority.get("claim") != ref.get("signer"):
        return None
    if not verify_artifact(marker, authority.get("key", ""), MARKER_DOMAIN):
        return None
    if artifact_hash(marker) != ref.get("contentHash"):
        return None
    if marker.get("signature", {}).get("signer") != ref.get("signer"):
        return None
    anchor = ref.get("anchor")
    if not isinstance(receipt, dict) or not isinstance(anchor, dict):
        return None
    if (
        receipt.get("state") != "finalized"
        or receipt.get("observationDisposition") != "established"
        or receipt.get("nativeAddress") != anchor.get("locator")
        or receipt.get("contentHash") != ref.get("contentHash")
    ):
        return None
    block_ref = receipt.get("blockRef")
    valid_at = block_ref.get("id") if isinstance(block_ref, dict) else None
    if public_keys is None:
        return None
    if not verify_authority_evidence(
        authority,
        public_keys.get("keyLifecycleAuthority", ""),
        ref.get("signer"),
        authority.get("key", ""),
        valid_at,
    ):
        return None
    resolved_tuple = marker_tuple(marker, ref.get("signer"))
    if expected_tuple is not None and resolved_tuple != expected_tuple:
        return None
    return resolved_tuple


def validate_receipt(receipt, digest, sequence, state_ref):
    if not isinstance(receipt, dict) or receipt.get("receiptVersion") != "1":
        return False
    if not isinstance(state_ref, dict):
        return False
    anchor = state_ref.get("anchor")
    if not isinstance(anchor, dict) or not isinstance(anchor.get("locator"), str):
        return False
    if receipt.get("substrate") != RECEIPT_SUBSTRATE:
        return False
    if receipt.get("finalityProfile") != RECEIPT_FINALITY_PROFILE:
        return False
    if receipt.get("logicalAddress") != state_ref["logicalAddress"]:
        return False
    if receipt.get("nativeAddress") != anchor["locator"]:
        return False
    if receipt.get("contentHash") != digest:
        return False
    if receipt.get("writer") != RECEIPT_WRITER:
        return False
    if receipt.get("nonce") != str(40 + sequence):
        return False
    if receipt.get("state") != "finalized" or receipt.get("observationDisposition") != "established":
        return False
    if receipt.get("observedAt") != 1_780_000_100_000 + sequence:
        return False
    binding = {
        "logicalAddress": state_ref["logicalAddress"],
        "nativeAddress": anchor["locator"],
        "contentHash": digest,
        "writer": RECEIPT_WRITER,
        "nonce": str(40 + sequence),
    }
    transaction_ref = {"kind": "demos-tx", "value": hash_hex(binding)}
    if receipt.get("transactionRef") != transaction_ref:
        return False
    block_ref = receipt.get("blockRef")
    if not isinstance(block_ref, dict):
        return False
    if block_ref.get("height") != str(100 + sequence):
        return False
    if block_ref.get("timestamp") != 1_780_000_000_000 + sequence:
        return False
    block_material = {
        "height": block_ref.get("height"),
        "timestamp": block_ref.get("timestamp"),
        "orderedTransactions": [transaction_ref],
    }
    if block_ref.get("id") != hash_hex(block_material):
        return False
    if receipt.get("evidence") != {"kind": "rsc-conformance-test-finality", "value": f"proof-{sequence}"}:
        return False
    return True


def validate_head_item(item, listing, state_ref, public_keys=None):
    if not isinstance(item, dict) or set(item) != {"head", "receipt", "authority"}:
        return None
    head = item["head"]
    receipt = item["receipt"]
    authority = item["authority"]
    if not validate_head_shape(head):
        return None
    if not isinstance(authority, dict):
        return None
    if authority.get("disposition") != "verified" or authority.get("claim") != listing["sellerPrimaryClaim"]:
        return None
    if not verify_artifact(head, authority.get("key", ""), HEAD_DOMAIN):
        return None
    if head.get("signature", {}).get("signer") != listing["sellerPrimaryClaim"]:
        return None
    if head.get("sellerPrimaryClaim") != listing["sellerPrimaryClaim"] or head.get("logicalAddress") != state_ref["logicalAddress"]:
        return None
    if not canonical_decimal(head.get("sequence")) or not canonical_decimal(head.get("entryCount")):
        return None
    digest = artifact_hash(head)
    if not validate_receipt(receipt, digest, int(head["sequence"]), state_ref):
        return None
    if public_keys is None:
        return None
    block_ref = receipt.get("blockRef") if isinstance(receipt, dict) else None
    valid_at = block_ref.get("id") if isinstance(block_ref, dict) else None
    if not verify_authority_evidence(
        authority,
        public_keys.get("keyLifecycleAuthority", ""),
        listing["sellerPrimaryClaim"],
        authority.get("key", ""),
        valid_at,
    ):
        return None
    return head, digest


def validate_transition(head, previous, previous_digest, context, public_keys=None):
    sequence = int(head["sequence"])
    if sequence != int(previous["sequence"]) + 1 or head.get("previousHeadHash") != previous_digest:
        return False
    transition = head.get("transition")
    if not isinstance(transition, dict) or set(transition) != {"leafKey", "revocationRef", "priorProof"}:
        return False
    key = transition["leafKey"]
    if not isinstance(key, str) or re.fullmatch(r"[0-9a-f]{64}", key) is None:
        return False
    if proof_root(key, transition["priorProof"], EMPTY[0]) != previous.get("rootHash"):
        return False
    resolved_tuple = resolve_marker(context, transition["revocationRef"], public_keys=public_keys)
    if resolved_tuple is None or hash_hex(resolved_tuple) != key:
        return False
    return proof_root(
        key,
        transition["priorProof"],
        revoked_leaf(key, transition["revocationRef"]),
    ) == head.get("rootHash")


def current_state_message(state_ref, context, evidence, listing_digest):
    anchor = state_ref.get("anchor")
    head_ref = context.get("headRef")
    payload = {
        "policy": evidence.get("policy"),
        "finalizedStateId": evidence.get("finalizedStateId"),
        "logicalAddress": state_ref.get("logicalAddress"),
        "nativeAddress": anchor.get("locator") if isinstance(anchor, dict) else None,
        "headContentHash": head_ref.get("contentHash") if isinstance(head_ref, dict) else None,
        "headReceiptHash": hash_hex(context.get("headReceipt")),
        "listingContentHash": listing_digest,
        "listingReceiptHash": hash_hex(context.get("listingReceipt")),
        "conflictingHeadsHash": hash_hex(context.get("knownConflictingHeads")),
    }
    return (CURRENT_STATE_DOMAIN + hash_hex(payload)).encode("ascii")


def validate_listing_receipt(receipt, digest):
    if not isinstance(receipt, dict) or receipt.get("receiptVersion") != "1":
        return False
    if (
        receipt.get("substrate") != RECEIPT_SUBSTRATE
        or receipt.get("finalityProfile") != RECEIPT_FINALITY_PROFILE
        or receipt.get("logicalAddress") != LISTING_LOGICAL_ADDRESS
        or receipt.get("nativeAddress") != LISTING_NATIVE_ADDRESS
        or receipt.get("contentHash") != digest
        or receipt.get("writer") != RECEIPT_WRITER
        or receipt.get("nonce") != "10"
        or receipt.get("state") != "finalized"
        or receipt.get("observationDisposition") != "established"
    ):
        return False
    binding = {
        "logicalAddress": LISTING_LOGICAL_ADDRESS,
        "nativeAddress": LISTING_NATIVE_ADDRESS,
        "contentHash": digest,
        "writer": RECEIPT_WRITER,
        "nonce": "10",
    }
    if receipt.get("transactionRef") != {"kind": "demos-tx", "value": hash_hex(binding)}:
        return False
    if receipt.get("evidence") != {"kind": "rsc-conformance-test-finality", "value": "listing-proof"}:
        return False
    return True


def listing_receipt_joins_head(listing_block_ref, head_block_ref):
    return (
        isinstance(listing_block_ref, dict)
        and listing_block_ref.get("id") == head_block_ref.get("id")
    )


def exact_corrective_profile(profile):
    return (
        isinstance(profile, dict)
        and set(profile) == {"releasePin", "moduleVersions"}
        and isinstance(profile.get("releasePin"), str)
        and profile["releasePin"] == AUTHORITATIVE_RELEASE_PIN
        and isinstance(profile.get("moduleVersions"), dict)
        and set(profile["moduleVersions"]) == set(AUTHORITATIVE_MODULE_VERSIONS)
        and profile["moduleVersions"] == AUTHORITATIVE_MODULE_VERSIONS
    )


def profile_admission_valid(admission, listing, session_id):
    if not isinstance(listing, dict):
        return False
    if not isinstance(admission, dict) or set(admission) != {
        "sessionId", "role", "participantIdentity", "authenticated", "profile"
    }:
        return False
    if admission.get("authenticated") is not True:
        return False
    if admission.get("role") != "seller":
        return False
    if not isinstance(admission.get("sessionId"), str) or not admission["sessionId"]:
        return False
    if admission.get("sessionId") != session_id:
        return False
    if admission.get("participantIdentity") != listing.get("sellerPrimaryClaim"):
        return False
    return exact_corrective_profile(admission.get("profile"))


def verify_current_state(state_ref, context, public_key, listing):
    evidence = context.get("currentStateEvidence")
    receipt = context.get("headReceipt")
    head_ref = context.get("headRef")
    if (
        not isinstance(evidence, dict)
        or set(evidence) != {
            "policy", "finalizedStateId", "valueContentHash", "listingContentHash",
            "listingReceiptHash", "conflictingHeadsHash", "evidence",
        }
        or evidence.get("policy") != CURRENT_STATE_POLICY
        or not isinstance(receipt, dict)
        or not isinstance(head_ref, dict)
        or evidence.get("valueContentHash") != head_ref.get("contentHash")
    ):
        return False
    head_block_ref = receipt.get("blockRef")
    if not isinstance(head_block_ref, dict):
        return False
    if (
        evidence.get("finalizedStateId") != head_block_ref.get("id")
        or receipt.get("substrate") != "conformance:test"
        or receipt.get("finalityProfile") != "rsc-conformance-test-finality-v1"
    ):
        return False
    listing_digest = artifact_hash(listing)
    listing_receipt = context.get("listingReceipt")
    if not validate_listing_receipt(listing_receipt, listing_digest):
        return False
    listing_block_ref = listing_receipt.get("blockRef")
    if not listing_receipt_joins_head(listing_block_ref, head_block_ref):
        return False
    if evidence.get("listingContentHash") != listing_digest:
        return False
    if evidence.get("listingReceiptHash") != hash_hex(listing_receipt):
        return False
    conflicting = context.get("knownConflictingHeads")
    if not isinstance(conflicting, list):
        return False
    if evidence.get("conflictingHeadsHash") != hash_hex(conflicting):
        return False
    signature = evidence.get("evidence")
    if not isinstance(signature, dict) or signature.get("kind") != "ed25519-signature":
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(
            decode_b64url(signature.get("value", "")),
            current_state_message(state_ref, context, evidence, listing_digest),
        )
    except (TypeError, ValueError, InvalidSignature):
        return False
    return True


def discovery_disposition(discovery, context, target, public_keys=None):
    if not isinstance(discovery, dict) or discovery.get("integrityConsistent") is not True:
        return "indeterminate"
    status = discovery.get("status")
    if status == "active" and "revocationRef" not in discovery:
        return "absent"
    if status == "revoked":
        ref = discovery.get("revocationRef")
        if isinstance(ref, dict) and resolve_marker(context, ref, target, public_keys=public_keys) is not None:
            return "revoked"
        return "indeterminate"
    return "indeterminate"


def verified_discovered_marker(discovery, context, target, public_keys):
    """RB-4 checks the selected exact binding, not unrelated RSC context."""
    if not isinstance(discovery, dict) or not isinstance(context, dict):
        return False
    if discovery.get("status") != "revoked" or not isinstance(discovery.get("revocationRef"), dict):
        return False
    markers = context.get("resolvedMarkers")
    if not isinstance(markers, list):
        return False
    matching = [
        item for item in markers
        if isinstance(item, dict) and item.get("revocationRef") == discovery["revocationRef"]
    ]
    return (
        len(matching) == 1
        and validate_resolved_marker_entry(matching[0])
        and discovery_disposition(discovery, context, target, public_keys) == "revoked"
    )


def validate_state_proof_shape(proof, expected_leaf_key, expected_head_hash):
    """Fail-closed disposition-dependent closed-shape gate for RevocationStateProof.

    The wire type (DACS-1 v0.8, RSC-6/RSC-9) is disposition-dependent: an
    ``absent`` proof carries exactly the base member set and no ``revocationRef``,
    while a ``revoked`` proof carries exactly one closed-shape ``revocationRef``.
    Every authorizing branch therefore runs only after the exact key set, scalar
    types, version literal, and both binding hashes pass here. A downgraded,
    extra-key, non-string, list-proof, or malformed-ref proof returns False so the
    authorizing absent branch can never run on a mutated proof shape.
    """
    if not isinstance(proof, dict):
        return False
    disposition = proof.get("disposition")
    base = {"revocationStateProofVersion", "headContentHash", "leafKey", "disposition", "proof"}
    if disposition == "absent":
        if set(proof) != base:
            return False
    elif disposition == "revoked":
        if set(proof) != base | {"revocationRef"}:
            return False
    else:
        return False
    if proof.get("revocationStateProofVersion") != "1":
        return False
    if not isinstance(proof.get("headContentHash"), str) or proof.get("headContentHash") != expected_head_hash:
        return False
    if not isinstance(proof.get("leafKey"), str) or proof.get("leafKey") != expected_leaf_key:
        return False
    if not isinstance(proof.get("proof"), dict):
        return False
    if disposition == "revoked":
        ref = proof.get("revocationRef")
        anchor = ref.get("anchor") if isinstance(ref, dict) else None
        if (
            not isinstance(ref, dict)
            or set(ref) != {"anchor", "contentHash", "signer"}
            or not isinstance(anchor, dict)
            or set(anchor) != {"kind", "locator"}
            or anchor.get("kind") not in {"storage-program", "ipfs", "https"}
            or not isinstance(anchor.get("locator"), str)
            or not isinstance(ref.get("contentHash"), str)
            or not isinstance(ref.get("signer"), str)
        ):
            return False
    return True


def validate_resolved_marker_entry(entry):
    """Fail-closed closed-shape gate for one ``ResolvedRevocationMarker``.

    The resolved-context wrapper is closed, but the signed marker permits
    future optional members under CORE SIG-5 and ordinary-minor compatibility.
    Required fields and nested containers are checked before authentication,
    so an empty dict or shell entry cannot be skipped as inert context while
    an ``absent`` result is reproduced.
    """
    if not isinstance(entry, dict) or set(entry) != {"revocationRef", "marker", "receipt", "authority"}:
        return False
    ref = entry.get("revocationRef")
    if not isinstance(ref, dict) or set(ref) != {"anchor", "contentHash", "signer"}:
        return False
    anchor = ref.get("anchor")
    if (
        not isinstance(anchor, dict)
        or set(anchor) != {"kind", "locator"}
        or anchor.get("kind") not in {"storage-program", "ipfs", "https"}
        or not isinstance(anchor.get("locator"), str)
    ):
        return False
    if not isinstance(ref.get("contentHash"), str) or not isinstance(ref.get("signer"), str):
        return False
    marker = entry.get("marker")
    if not isinstance(marker, dict):
        return False
    if not {"listingId", "listingVersion", "listingContentHash", "revokedAt", "signature"} <= set(marker):
        return False
    if (
        not isinstance(marker.get("listingId"), str)
        or not isinstance(marker.get("listingContentHash"), str)
        or not isinstance(marker.get("listingVersion"), int)
        or isinstance(marker.get("listingVersion"), bool)
        or not isinstance(marker.get("revokedAt"), int)
        or isinstance(marker.get("revokedAt"), bool)
    ):
        return False
    if "reason" in marker and not isinstance(marker["reason"], str):
        return False
    signature = marker.get("signature")
    if (
        not isinstance(signature, dict)
        or set(signature) != {"algorithm", "signer", "value"}
        or not isinstance(signature.get("algorithm"), str)
        or not isinstance(signature.get("signer"), str)
        or not isinstance(signature.get("value"), str)
    ):
        return False
    if not isinstance(entry.get("receipt"), dict):
        return False
    authority = entry.get("authority")
    if (
        not isinstance(authority, dict)
        or set(authority) != {"claim", "key", "disposition", "evidence"}
        or not isinstance(authority.get("claim"), str)
        or not isinstance(authority.get("key"), str)
        or authority.get("disposition") not in ("verified", "indeterminate")
    ):
        return False
    evidence = authority.get("evidence")
    if (
        not isinstance(evidence, dict)
        or set(evidence) != {"kind", "value"}
        or not isinstance(evidence.get("kind"), str)
        or not isinstance(evidence.get("value"), str)
    ):
        return False
    return True


def marker_context_forbids_absent(context, target, public_keys, consumed_refs):
    """Fail-closed marker-context gate for the authorizing absent branch.

    ``resolvedMarkers`` is verifier-supplied resolution context (RSC-9). A
    producer retaining an ``absent`` result must reproduce the exact context it
    used: a marker entry that does not independently authenticate (RB-1/RB-4
    shape plus key-lifecycle authority) is malformed or unused context and is
    non-conforming, so it can never be skipped while reproducing ``absent``.
    An authenticated marker not used by a validated transition is also unused
    context, even when it refers to another Listing tuple.
    A marker that does authenticate a revocation of the exact Listing tuple is
    verified revocation evidence that cannot be ignored while a non-membership
    proof returns ``absent``: RSC-7 gives the conflict between authenticated
    views precedence over RSC-proven absence. Returns True — so the absent
    branch refuses with non-authorizing indeterminate, never ``absent`` — when
    the retained marker context is non-conforming or when any marker
    authenticates the exact Listing tuple.
    """
    markers = context.get("resolvedMarkers")
    if not isinstance(markers, list):
        return True
    for item in markers:
        ref = item.get("revocationRef") if isinstance(item, dict) else None
        if not isinstance(ref, dict):
            return True
        resolved = resolve_marker(context, ref, public_keys=public_keys)
        if resolved is None:
            return True
        if resolved == target:
            return True
        if ref not in consumed_refs:
            return True
    return False


def evaluate(data, public_keys, trusted_admission=None):
    # RSC totality: every untrusted root/container/scalar is evaluated through a
    # fail-closed boundary. A non-object root, a malformed revocationState anchor,
    # a list/None authority key, or a list-valued signature value must return
    # non-authorizing indeterminate, never leak an AttributeError/TypeError/KeyError.
    try:
        return _evaluate(data, public_keys, trusted_admission)
    except Exception:
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}


def evaluate_recorded_policy(data, public_keys, trusted_admission=None, effects=None):
    """Replay the frozen v1 fixture policy; this is not fresh admission authority.

    The retained ``revocation-state-completeness-v0.8.json`` corpus records the
    earlier v1 reference policy and is replayed here byte-for-byte. Current
    ``rsc-current-admission-v2`` acceptance is a separate, registered policy
    (see ``scripts/rsc_current_admission.py`` and
    ``tests/test_rsc_current_admission_v2.py``); a historical v1 pass is never
    promoted to current admission.
    """
    del effects  # the frozen v1 evaluator has no consumer-effect dispatch
    try:
        return _evaluate(data, public_keys, trusted_admission)
    except Exception:
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}


def _evaluate(data, public_keys, trusted_admission=None):
    listing = data.get("listing")
    if not isinstance(listing, dict):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    # CORE §11.1.2 / RSC-10: corrective-profile admission is verifier-owned and
    # precedes all listing interpretation. A caller-supplied `currentProfile` or
    # profile copy has no authority; missing/mismatched/tampered admission fails
    # closed before any listing signature or state work.
    if not profile_admission_valid(trusted_admission, listing, data.get("sessionId")):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    # The Listing must be a cryptographically authenticated artifact whose
    # signature binds the exact tuple this revocation check queries; a missing,
    # forged, or substituted signature cannot establish the evaluation state.
    if not verify_artifact(listing, public_keys.get("initial", ""), LISTING_DOMAIN):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    if listing.get("signature", {}).get("signer") != listing.get("sellerPrimaryClaim"):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    context = data.get("resolutionContext")
    target = {
        "sellerPrimaryClaim": listing.get("sellerPrimaryClaim"),
        "listingId": listing.get("listingId"),
        "listingVersion": listing.get("listingVersion"),
        "listingContentHash": listing.get("listingContentHash"),
    }
    key = hash_hex(target)
    # RB-4 authenticates the exact marker independently of the RSC head view.
    # Missing RSC join fields cannot demote a proven revocation to unknown.
    if verified_discovered_marker(data.get("discovery"), context, target, public_keys):
        return "fail", {"revocationCheck": "revoked", "session": "refuse"}
    state_ref = listing.get("revocationState")
    if not isinstance(state_ref, dict):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    if set(state_ref) != {"revocationStateRefVersion", "logicalAddress", "anchor", "checkpointSequence", "checkpointHeadHash"}:
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    if state_ref.get("revocationStateRefVersion") != "1" or not canonical_decimal(state_ref.get("checkpointSequence")):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    expected_logical = f"dacs1-revocations:{cf4(listing.get('sellerPrimaryClaim', ''))}"
    if state_ref.get("logicalAddress") != expected_logical:
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    if not validate_resolution_context_shape(context):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    rb_disposition = discovery_disposition(data.get("discovery"), context, target, public_keys)
    if not verify_current_state(state_ref, context, public_keys.get("currentStateAuthority", ""), listing):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    evidence = context["currentStateEvidence"]

    history = context.get("headHistory")
    if not isinstance(history, list) or not history:
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    validated = []
    for item in history:
        value = validate_head_item(item, listing, state_ref, public_keys)
        if value is None:
            return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
        validated.append(value)
    first, _ = validated[0]
    if first.get("sequence") != "0":
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}

    checkpoints = [
        head for head, digest in validated
        if head.get("sequence") == state_ref.get("checkpointSequence")
        and digest == state_ref.get("checkpointHeadHash")
    ]
    if len(checkpoints) != 1 or int(validated[-1][0]["sequence"]) < int(state_ref["checkpointSequence"]):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}

    for index, (head, digest) in enumerate(validated):
        sequence = int(head["sequence"])
        if int(head["entryCount"]) != sequence:
            return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
        if index == 0 and sequence == 0:
            if head.get("previousHeadHash") != ZERO_HASH or "transition" in head or head.get("rootHash") != EMPTY[256].hex():
                return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
            continue
        if index == 0:
            continue
        previous, previous_digest = validated[index - 1]
        if not validate_transition(head, previous, previous_digest, context, public_keys):
            return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}

    current, current_hash = validated[-1]
    head_ref = context.get("headRef")
    head_receipt = context.get("headReceipt")
    if not isinstance(head_ref, dict) or not isinstance(head_receipt, dict):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    if (
        head_ref.get("contentHash") != current_hash
        or head_ref.get("anchor") != state_ref.get("anchor")
        or head_ref.get("signer") != listing.get("sellerPrimaryClaim")
    ):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    if evidence.get("valueContentHash") != current_hash or head_receipt != history[-1]["receipt"]:
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    if context.get("headReceiptHistory") != [item["receipt"] for item in history]:
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}

    current_seq = int(current["sequence"])
    conflict_revokes_target = False
    conflict_indeterminate = False
    for conflict in context.get("knownConflictingHeads", []):
        checked = validate_head_item(conflict, listing, state_ref, public_keys)
        if checked is None:
            conflict_indeterminate = True
            continue
        conflicting, conflicting_hash = checked
        conflict_seq = int(conflicting["sequence"])
        transition = conflicting.get("transition")
        if isinstance(transition, dict) and transition.get("leafKey") == key:
            # Append-only revocation: an otherwise-authenticated head whose exact
            # transition revokes this target cannot be ignored. A higher head
            # supersedes the stale read, while an authenticated same-sequence
            # sibling from the same predecessor is itself exact revocation proof.
            predecessor = next(
                ((head, digest) for head, digest in validated if digest == conflicting.get("previousHeadHash")),
                None,
            )
            if predecessor is None or not validate_transition(
                conflicting, predecessor[0], predecessor[1], context, public_keys
            ):
                conflict_indeterminate = True
                continue
            if conflict_seq >= current_seq:
                conflict_revokes_target = True
            else:
                conflict_indeterminate = True
            continue
        if conflict_seq == current_seq and (
            conflicting.get("previousHeadHash") == current.get("previousHeadHash")
            and conflicting_hash != current_hash
        ):
            # A same-sequence sibling omitting this target must not turn an
            # established revocation into absent: it is an equivocation.
            conflict_indeterminate = True
        if conflict_seq > current_seq:
            # A later authenticated head that does not revoke the target still
            # proves the accepted current head is stale.
            conflict_indeterminate = True

    # Classify the complete signed observation set before applying RSC-7:
    # a verified target revocation wins regardless of producer-chosen ordering.
    if conflict_revokes_target:
        return "fail", {"revocationCheck": "revoked", "session": "refuse"}
    if conflict_indeterminate:
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}

    proof = context.get("stateProof")
    if not validate_state_proof_shape(proof, key, current_hash):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    disposition = proof.get("disposition")
    if disposition == "absent":
        if proof_root(key, proof.get("proof"), EMPTY[0]) != current.get("rootHash"):
            return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
        if rb_disposition == "indeterminate":
            return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
        # A known authenticated conflicting view cannot establish complete
        # absence. Target-revoking higher heads have already returned revoked;
        # all remaining nonempty conflict sets are non-authorizing under RSC-7.
        # In particular, a conflict's unverified transition cannot be used to
        # launder an otherwise-unused resolved marker into accepted context.
        if context["knownConflictingHeads"]:
            return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
        consumed_refs = [
            transition["revocationRef"]
            for head, _ in validated
            if isinstance((transition := head.get("transition")), dict)
            and isinstance(transition.get("revocationRef"), dict)
        ]
        if marker_context_forbids_absent(context, target, public_keys, consumed_refs):
            # RSC-7 precedence over RSC-proven absence: an independently
            # authenticated exact-target revocation marker is verified revocation
            # evidence that the non-membership proof cannot out-rank; RSC-9
            # marks a malformed, shadowed, duplicated, or otherwise unused marker
            # context non-conforming. Either way the authorizing absent branch
            # refuses — never `absent`.
            return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
        return "pass", {"revocationCheck": "absent", "session": "continue"}
    if disposition == "revoked":
        ref = proof.get("revocationRef")
        if proof_root(key, proof.get("proof"), revoked_leaf(key, ref)) != current.get("rootHash"):
            return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
        if resolve_marker(context, ref, target, public_keys) is None:
            return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
        return "fail", {"revocationCheck": "revoked", "session": "refuse"}
    return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}


EXPECTED_CONTEXT_FIELDS = [
    "headRef",
    "headReceipt",
    "headReceiptHistory",
    "listingReceipt",
    "currentStateEvidence",
    "headHistory",
    "stateProof",
    "resolvedMarkers",
    "knownConflictingHeads",
]
EXPECTED_CURRENT_STATE_FIELDS = [
    "policy",
    "finalizedStateId",
    "valueContentHash",
    "listingContentHash",
    "listingReceiptHash",
    "conflictingHeadsHash",
    "evidence",
]

EXPECTED_CONTEXT_TYPES = {
    "headRef": "AttestationRef",
    "headReceipt": "AnchorReceipt",
    "headReceiptHistory": ("list", "AnchorReceipt"),
    "listingReceipt": "AnchorReceipt",
    "currentStateEvidence": ("object", (
        ("policy", "string"),
        ("finalizedStateId", "string"),
        ("valueContentHash", "string"),
        ("listingContentHash", "string"),
        ("listingReceiptHash", "string"),
        ("conflictingHeadsHash", "string"),
        ("evidence", ("object", (("kind", "string"), ("value", "string")))),
    )),
    "headHistory": ("list", "ResolvedRevocationHead"),
    "stateProof": "RevocationStateProof",
    "resolvedMarkers": ("list", "ResolvedRevocationMarker"),
    "knownConflictingHeads": ("list", "ResolvedRevocationHead"),
}

EXPECTED_CURRENT_STATE_TYPES = EXPECTED_CONTEXT_TYPES["currentStateEvidence"][1]


def validate_resolution_context_shape(context):
    """Fail-closed closed-shape gate for the mandatory resolution context.

    All nine normative ``RevocationHeadResolutionContext`` members are mandatory
    (RSC-9) and must carry their exact container/value types before the RSC
    inclusion or non-membership branches may run. Independently authenticated
    RB-4 revocation is handled earlier. A missing member (notably an omitted
    ``resolvedMarkers``), a null/object/malformed entry, or an extra key fails
    closed here, so a transition-free genesis ``absent`` cannot bypass marker
    resolution. Each ``resolvedMarkers`` entry must itself be a closed
    ``ResolvedRevocationMarker`` shape and each ``revocationRef`` must appear
    exactly once: an empty dict, a shell entry, or a shadow/duplicate marker
    cannot be carried into the marker-resolution boundary and then ignored
    while ``absent`` is reproduced.
    """
    if not isinstance(context, dict) or set(context) != set(EXPECTED_CONTEXT_FIELDS):
        return False
    if not validate_marker_resolution_context_shape(context):
        return False
    head_ref = context.get("headRef")
    if not isinstance(head_ref, dict):
        return False
    anchor = head_ref.get("anchor")
    if (
        not isinstance(anchor, dict)
        or not isinstance(anchor.get("kind"), str)
        or not isinstance(anchor.get("locator"), str)
        or not isinstance(head_ref.get("contentHash"), str)
    ):
        return False
    signer = head_ref.get("signer")
    if signer is not None and not isinstance(signer, str):
        return False
    if not isinstance(context.get("headReceipt"), dict):
        return False
    head_receipt_history = context.get("headReceiptHistory")
    if not isinstance(head_receipt_history, list) or not all(
        isinstance(item, dict) for item in head_receipt_history
    ):
        return False
    if not isinstance(context.get("listingReceipt"), dict):
        return False
    evidence = context.get("currentStateEvidence")
    if not isinstance(evidence, dict) or set(evidence) != set(EXPECTED_CURRENT_STATE_FIELDS):
        return False
    for field in (
        "policy", "finalizedStateId", "valueContentHash", "listingContentHash",
        "listingReceiptHash", "conflictingHeadsHash",
    ):
        if not isinstance(evidence.get(field), str):
            return False
    signature = evidence.get("evidence")
    if (
        not isinstance(signature, dict)
        or not isinstance(signature.get("kind"), str)
        or not isinstance(signature.get("value"), str)
    ):
        return False
    head_history = context.get("headHistory")
    if not isinstance(head_history, list) or not all(
        isinstance(item, dict) for item in head_history
    ):
        return False
    if not isinstance(context.get("stateProof"), dict):
        return False
    conflicting = context.get("knownConflictingHeads")
    if not isinstance(conflicting, list) or not all(
        isinstance(item, dict) for item in conflicting
    ):
        return False
    return True


def validate_marker_resolution_context_shape(context):
    """Validate the RB-4 subset without requiring unrelated RSC join evidence."""
    if not isinstance(context, dict):
        return False
    resolved_markers = context.get("resolvedMarkers")
    if not isinstance(resolved_markers, list):
        return False
    seen_refs = set()
    for item in resolved_markers:
        if not validate_resolved_marker_entry(item):
            return False
        ref = item.get("revocationRef")
        if isinstance(ref, dict):
            marker_ref = (ref.get("anchor", {}).get("locator"), ref.get("contentHash"), ref.get("signer"))
            if marker_ref in seen_refs:
                return False
            seen_refs.add(marker_ref)
    return True


def _strip_spec_comment(line):
    index = line.find("//")
    if index != -1:
        line = line[:index]
    return line.rstrip()


def _split_inline_fields(text):
    parts = []
    depth = 0
    current = []
    for char in text:
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        if char == ";" and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _split_field(line):
    line = _strip_spec_comment(line).strip()
    depth = 0
    separator = None
    for index, char in enumerate(line):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        elif char == ":" and depth == 0:
            separator = index
            break
    if separator is None:
        raise AssertionError("malformed spec field line: %r" % line)
    return line[:separator].strip(), line[separator + 1:].strip()


def _consume_inline_object(declared):
    """Locate the exact closing brace of an inline ``{ ... }`` object.

    Returns ``(inner_text, closing_index)`` for the balanced object whose opening
    brace is at index 0. Depth is tracked so a nested ``{ ... }`` cannot hide or
    truncate the boundary; the caller then rejects any trailing material and any
    unmatched content. This is the strict boundary check that previously allowed
    ``{ kind: string; value: string`` (missing ``}``) to parse identically to the
    valid schema.
    """
    depth = 0
    for index, char in enumerate(declared):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return declared[1:index], index
            if depth < 0:
                raise AssertionError("stray closing brace in type declaration: %r" % declared)
    raise AssertionError("premature EOF: unclosed inline object: %r" % declared)


def _parse_type_decl(declared):
    """Normalize a declared type into a comparable shape.

    ``string``/``number``/``AttestationRef``/... stay as their name; ``X[]``
    becomes ``("list", <inner>)``; an inline ``{ ... }`` object becomes
    ``("object", ((name, <type>), ...))``. Nested braces are respected so inner
    objects and comments cannot hide a field.

    The inline-object branch is strict and total: braces must be balanced with
    exact consumption (no missing/extra closing brace, no premature EOF, no
    trailing/unconsumed material), and a nested ``name?`` optionality marker is
    preserved in the normalized field name so a mutated ``kind?``/``value?`` is
    detectable rather than silently collapsed to ``kind``/``value``.
    """
    declared = declared.strip()
    if not declared:
        raise AssertionError("empty type declaration")
    if declared.endswith("[]"):
        inner = declared[:-2].strip()
        if not inner:
            raise AssertionError("empty list element type: %r" % declared)
        return ("list", _parse_type_decl(inner))
    if declared.startswith("{"):
        inner, closing = _consume_inline_object(declared)
        rest = declared[closing + 1:].strip()
        if rest:
            raise AssertionError("trailing material after inline object: %r" % rest)
        fields = []
        for part in _split_inline_fields(inner.strip()):
            part = part.strip()
            if not part:
                raise AssertionError("empty field in inline object: %r" % declared)
            name, sub = _split_field(part)
            if not name:
                raise AssertionError("empty field name in inline object: %r" % declared)
            fields.append((name, _parse_type_decl(sub)))
        return ("object", tuple(fields))
    if "{" in declared or "}" in declared:
        raise AssertionError("unbalanced braces in type declaration: %r" % declared)
    return declared


def _parse_fields(lines, start, indent):
    """Parse one indentation-delimited object body, returning (fields, optional,
    types, object_optionals, next_index).

    Strict and total: field lines must sit at exactly ``indent`` spaces, the
    object's closing ``}`` at exactly ``indent - 2``, and the body must be
    terminated by that closing brace. Blank lines are skipped. A missing or
    misplaced closing brace, an invalid (partial) dedent, or an unexpected
    indentation raise ``AssertionError`` instead of silently truncating the
    object, so an in-memory spec mutation cannot hide a field or boundary.
    """
    fields = []
    optional = set()
    types = {}
    object_optionals = {}
    index = start
    closed = False
    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()
        if not stripped:
            index += 1
            continue
        line_indent = len(raw) - len(raw.lstrip(" "))
        if stripped == "}":
            if line_indent != indent - 2:
                raise AssertionError(
                    "misplaced closing brace at indentation %d (expected %d): %r"
                    % (line_indent, indent - 2, raw)
                )
            index += 1
            closed = True
            break
        if line_indent < indent:
            raise AssertionError(
                "invalid dedent at indentation %d (expected %d): %r"
                % (line_indent, indent, raw)
            )
        if line_indent > indent:
            raise AssertionError(
                "invalid indentation at %d (expected %d): %r"
                % (line_indent, indent, raw)
            )
        name, declared = _split_field(raw)
        if name.endswith("?"):
            name = name[:-1]
            optional.add(name)
        fields.append(name)
        if declared == "{":
            sub_fields, sub_optional, sub_types, sub_object_optionals, index = _parse_fields(
                lines, index + 1, indent + 2
            )
            types[name] = ("object", tuple((n, sub_types[n]) for n in sub_fields))
            object_optionals[name] = set(sub_optional)
            object_optionals.update(sub_object_optionals)
        else:
            types[name] = _parse_type_decl(declared)
            index += 1
    if not closed:
        raise AssertionError(
            "premature EOF: unclosed object body (expected '}' at indentation %d)"
            % (indent - 2)
        )
    return fields, optional, types, object_optionals, index


def _extract_context_type_block(spec_text):
    lines = spec_text.splitlines()
    start = end = None
    for index, line in enumerate(lines):
        if line.strip() == "type RevocationHeadResolutionContext = {":
            start = index
        elif start is not None and line == "}":
            end = index
            break
    if start is None or end is None:
        raise AssertionError("RevocationHeadResolutionContext type block not found in spec")
    return "\n".join(lines[start:end + 1])


def _parse_context_type_block(block_text):
    lines = block_text.splitlines()
    fields, optional, types, object_optionals, final_index = _parse_fields(lines, 1, 2)
    if final_index != len(lines):
        raise AssertionError(
            "trailing/unconsumed material after RevocationHeadResolutionContext block"
        )
    current_state_fields = []
    current_state_types = {}
    evidence_type = types.get("currentStateEvidence")
    if isinstance(evidence_type, tuple) and evidence_type and evidence_type[0] == "object":
        for name, field_type in evidence_type[1]:
            current_state_fields.append(name)
            current_state_types[name] = field_type
    return {
        "context_fields": fields,
        "context_optional": optional,
        "context_types": types,
        "current_state_fields": current_state_fields,
        "current_state_optional": object_optionals.get("currentStateEvidence", set()),
        "current_state_types": current_state_types,
    }


def _parse_context_shape(spec_text):
    return _parse_context_type_block(_extract_context_type_block(spec_text))


def _normative_context_shape():
    """Extract the normative RevocationHeadResolutionContext members and their
    normalized declared types from the spec.

    Returns a mapping with ``context_fields``, ``context_optional``,
    ``context_types``, ``current_state_fields``, ``current_state_optional`` and
    ``current_state_types``. Declared types are normalized (arrays and inline
    objects included) so the suite pins types against the generator/evaluator,
    not just key sets.
    """
    return _parse_context_shape(SPEC.read_text(encoding="utf-8"))


class RevocationStateCompletenessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_metadata_and_hash(self):
        vectors = self.document["vectors"]
        encoded = json.dumps(vectors, separators=(",", ":"), ensure_ascii=False).encode()
        self.assertEqual(self.document["count"], len(vectors))
        self.assertEqual(self.document["hash"], hashlib.sha256(encoded).hexdigest())
        self.assertEqual(len({item["name"] for item in vectors}), len(vectors))

    def test_jcs_canonical_bytes_parity_and_numeric_bounds(self):
        cases = (
            ({"n": 1.0}, b'{"n":1}'),
            ({"n": -0.0}, b'{"n":0}'),
            ({"s": "e\u0301"}, '{"s":"\u00e9"}'.encode("utf-8")),
            ({"\ue000": 1, "\U00010000": 2}, '{"\U00010000":2,"\ue000":1}'.encode("utf-8")),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(g.canonical_bytes(value), expected)
                self.assertEqual(canonical_bytes(value), expected)

        safe = {"issuedAt": 2 ** 53 - 1}
        self.assertEqual(g.canonical_bytes(safe), b'{"issuedAt":9007199254740991}')
        self.assertEqual(canonical_bytes(safe), b'{"issuedAt":9007199254740991}')
        for unsupported in ({"issuedAt": 2 ** 53}, {"issuedAt": float("inf")}):
            with self.subTest(unsupported=unsupported):
                with self.assertRaises(ValueError):
                    g.canonical_bytes(unsupported)
                with self.assertRaises(ValueError):
                    canonical_bytes(unsupported)

    def test_sign_artifact_enforces_jcs_safe_integer_range(self):
        safe = {"issuedAt": 2 ** 53 - 1}
        signed = g.sign_artifact(safe, g.SELLER_KEY, g.SELLER, g.HEAD_DOMAIN)
        self.assertTrue(verify_artifact(signed, g.public_hex(g.SELLER_KEY), g.HEAD_DOMAIN))
        with self.assertRaises(ValueError):
            g.sign_artifact(
                {"issuedAt": 2 ** 53}, g.SELLER_KEY, g.SELLER, g.HEAD_DOMAIN
            )

    def test_legacy_sorted_json_unsupported_integer_is_rejected_end_to_end(self):
        def legacy_sign(unsigned, domain):
            encoded = json.dumps(
                unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            digest = hashlib.sha256(encoded).hexdigest()
            return ({
                **unsigned,
                "signature": {
                    "algorithm": "ed25519",
                    "signer": g.SELLER,
                    "value": g.b64url(g.SELLER_KEY.sign((domain + digest).encode("ascii"))),
                },
            }, digest)

        unsigned_head = {key: value for key, value in g.GENESIS.items() if key != "signature"}
        unsigned_head["issuedAt"] = 2 ** 53
        legacy_head, legacy_head_hash = legacy_sign(unsigned_head, g.HEAD_DOMAIN)
        self.assertFalse(
            verify_artifact(legacy_head, g.public_hex(g.SELLER_KEY), g.HEAD_DOMAIN)
        )

        # Rebind every surrounding receipt, listing checkpoint, authority
        # attestation, and current-state signature to the legacy head digest.
        # The exact unsupported head signature is therefore the only invalid
        # primitive inside an otherwise authenticated admission envelope.
        head_receipt = g.receipt(g.GENESIS, 0)
        head_receipt["contentHash"] = legacy_head_hash
        binding = {
            "logicalAddress": g.LOGICAL_ADDRESS,
            "nativeAddress": g.NATIVE_ADDRESS,
            "contentHash": legacy_head_hash,
            "writer": g.RECEIPT_WRITER,
            "nonce": "40",
        }
        transaction_ref = {"kind": "demos-tx", "value": g.hash_hex(binding)}
        head_receipt["transactionRef"] = transaction_ref
        block_material = {
            "height": head_receipt["blockRef"]["height"],
            "timestamp": head_receipt["blockRef"]["timestamp"],
            "orderedTransactions": [transaction_ref],
        }
        head_receipt["blockRef"]["id"] = g.hash_hex(block_material)
        valid_at = head_receipt["blockRef"]["id"]
        history = [{
            "head": legacy_head,
            "receipt": head_receipt,
            "authority": {
                "claim": g.SELLER,
                "key": g.public_hex(g.SELLER_KEY),
                "disposition": "verified",
                "evidence": g.key_attestation(
                    g.SELLER, g.public_hex(g.SELLER_KEY), valid_at
                ),
            },
        }]
        listing_unsigned = g.listing_unsigned()
        listing_unsigned["revocationState"]["checkpointHeadHash"] = legacy_head_hash
        listing = g.sign_artifact(
            listing_unsigned, g.SELLER_KEY, g.SELLER, g.LISTING_DOMAIN
        )
        data = g.input_for(
            g.GENESIS, {}, checkpoint=g.GENESIS, history=[g.history_item(g.GENESIS)]
        )
        data["listing"] = listing
        context = data["resolutionContext"]
        context["headRef"]["contentHash"] = legacy_head_hash
        context["headReceipt"] = head_receipt
        context["headReceiptHistory"] = [head_receipt]
        context["headHistory"] = history
        context["stateProof"]["headContentHash"] = legacy_head_hash
        context["listingReceipt"] = g.listing_receipt(
            listing,
            valid_at,
            head_receipt["blockRef"]["height"],
            head_receipt["blockRef"]["timestamp"],
        )
        evidence = context["currentStateEvidence"]
        evidence["finalizedStateId"] = valid_at
        evidence["valueContentHash"] = legacy_head_hash
        evidence["listingContentHash"] = g.artifact_hash(listing)
        evidence["listingReceiptHash"] = g.hash_hex(context["listingReceipt"])
        evidence["evidence"]["value"] = g.b64url(g.CURRENT_STATE_KEY.sign(
            g.current_state_message(
                context["headRef"], context["headReceipt"], valid_at,
                evidence["listingContentHash"], context["listingReceipt"],
                context["knownConflictingHeads"],
            )
        ))
        outcome = evaluate(
            data, self.document["publicKeys"], g.profile_admission()
        )
        self.assertEqual(
            outcome,
            ("indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}),
        )
        self.assertNotEqual(outcome, ("pass", {"revocationCheck": "absent", "session": "continue"}))

    def test_independent_evaluator(self):
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                expected, want = evaluate(
                    vector["input"], self.document["publicKeys"],
                    vector.get("trustedProfileAdmission"),
                )
                self.assertEqual((expected, want), (vector["expected"], vector["want"]))

    def test_rb4_verified_marker_precedes_unrelated_rsc_context(self):
        vectors = {item["name"]: item for item in self.document["vectors"]}
        rb4 = vectors["rsc-rb4-discovered-marker-precedes-nonmembership"]
        revoked = ("fail", {"revocationCheck": "revoked", "session": "refuse"})
        self.assertEqual(evaluate(rb4["input"], self.document["publicKeys"], rb4["trustedProfileAdmission"]), revoked)
        for field in ("headReceipt", "currentStateEvidence", "headHistory", "stateProof", "knownConflictingHeads"):
            with self.subTest(field=field):
                data = json.loads(json.dumps(rb4["input"]))
                data["resolutionContext"].pop(field)
                self.assertEqual(evaluate(data, self.document["publicKeys"], rb4["trustedProfileAdmission"]), revoked)

        unrelated_malformed = json.loads(json.dumps(rb4["input"]))
        unrelated_malformed["resolutionContext"]["resolvedMarkers"].append({})
        self.assertEqual(
            evaluate(unrelated_malformed, self.document["publicKeys"], rb4["trustedProfileAdmission"]),
            revoked,
        )

        for mutation in ("missing", "malformed", "duplicate", "unauthenticated"):
            with self.subTest(marker=mutation):
                data = json.loads(json.dumps(rb4["input"]))
                if mutation == "missing":
                    data["resolutionContext"].pop("resolvedMarkers")
                elif mutation == "malformed":
                    data["resolutionContext"]["resolvedMarkers"] = [{}]
                elif mutation == "duplicate":
                    data["resolutionContext"]["resolvedMarkers"].append(
                        json.loads(json.dumps(data["resolutionContext"]["resolvedMarkers"][-1]))
                    )
                else:
                    data["resolutionContext"]["resolvedMarkers"][-1]["marker"]["signature"]["value"] = "not-a-signature"
                self.assertEqual(evaluate(data, self.document["publicKeys"], rb4["trustedProfileAdmission"])[1]["revocationCheck"], "indeterminate")

        active = vectors["rsc-valid-active-nonmembership"]
        for field in ("headReceipt", "currentStateEvidence", "headHistory", "stateProof", "knownConflictingHeads"):
            with self.subTest(active_missing=field):
                data = json.loads(json.dumps(active["input"]))
                data["resolutionContext"].pop(field)
                self.assertNotEqual(evaluate(data, self.document["publicKeys"], active["trustedProfileAdmission"])[1]["revocationCheck"], "absent")

    def test_rb4_signed_historical_listing_without_state_ref(self):
        vectors = {item["name"]: item for item in self.document["vectors"]}
        historical = vectors["rsc-rb4-historical-listing-without-state-ref"]
        revoked = ("fail", {"revocationCheck": "revoked", "session": "refuse"})
        self.assertNotIn("revocationState", historical["input"]["listing"])
        self.assertEqual(
            evaluate(historical["input"], self.document["publicKeys"],
                     historical["trustedProfileAdmission"]), revoked,
        )
        for mutation in ("missing", "malformed", "duplicate", "unauthenticated"):
            with self.subTest(mutation=mutation):
                data = json.loads(json.dumps(historical["input"]))
                markers = data["resolutionContext"]["resolvedMarkers"]
                if mutation == "missing":
                    markers.clear()
                elif mutation == "malformed":
                    markers[-1] = {}
                elif mutation == "duplicate":
                    markers.append(json.loads(json.dumps(markers[-1])))
                else:
                    markers[-1]["marker"]["signature"]["value"] = "not-a-signature"
                self.assertEqual(
                    evaluate(data, self.document["publicKeys"],
                             historical["trustedProfileAdmission"])[1]["revocationCheck"],
                    "indeterminate",
                )
        active = vectors["rsc-historical-listing-without-state-ref"]
        self.assertEqual(
            evaluate(active["input"], self.document["publicKeys"],
                     active["trustedProfileAdmission"])[1]["revocationCheck"],
            "indeterminate",
        )

    def test_named_negative_current_state_envelopes_are_authentic_and_sensitive(self):
        vectors = {item["name"]: item for item in self.document["vectors"]}
        cases = (
            ("rsc-producer-time-cannot-prove-latest", "policy"),
            ("rsc-listing-receipt-stale", "join"),
            ("rsc-listing-receipt-tampered", "receipt"),
            ("rsc-listing-receipt-blockref-list", "join"),
            ("rsc-listing-receipt-blockref-string", "join"),
        )
        for name, gate in cases:
            with self.subTest(name=name):
                vector = vectors[name]
                data = vector["input"]
                context = data["resolutionContext"]
                evidence = context["currentStateEvidence"]
                self.assertEqual(evidence["listingReceiptHash"], hash_hex(context["listingReceipt"]))
                message = current_state_message(
                    data["listing"]["revocationState"], context, evidence,
                    artifact_hash(data["listing"]),
                )
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(
                    self.document["publicKeys"]["currentStateAuthority"]
                )).verify(decode_b64url(evidence["evidence"]["value"]), message)
                self.assertEqual(
                    evaluate(data, self.document["publicKeys"], vector["trustedProfileAdmission"]),
                    (vector["expected"], vector["want"]),
                )
                if gate == "policy":
                    patch = mock.patch.object(sys.modules[__name__], "CURRENT_STATE_POLICY", "producer-time-only")
                elif gate == "receipt":
                    patch = mock.patch.object(sys.modules[__name__], "validate_listing_receipt", return_value=True)
                else:
                    patch = mock.patch.object(sys.modules[__name__], "listing_receipt_joins_head", return_value=True)
                with patch:
                    self.assertEqual(
                        evaluate(data, self.document["publicKeys"], vector["trustedProfileAdmission"])[1]["revocationCheck"],
                        "absent", "omitting the named gate must invalidate this negative oracle",
                    )

    def test_acceptance_cases_are_explicit(self):
        names = {item["name"] for item in self.document["vectors"]}
        self.assertTrue({
            "rsc-censored-tombstone",
            "rsc-stale-signed-head",
            "rsc-two-equivocated-heads",
            "rsc-invalid-nonmembership",
            "rsc-valid-active-nonmembership",
            "rsc-valid-revocation-inclusion",
            "rsc-authorized-rotation-key",
            "rsc-rotated-key-corrupted-signature",
            "rsc-wrong-signer-key",
            "rsc-wrong-signature-algorithm",
            "rsc-higher-known-head-revokes",
            "rsc-rb4-discovered-marker-precedes-nonmembership",
            "rsc-rb5-indeterminate-precedes-nonmembership",
        } <= names)

    def test_receipt_provenance_mutations_do_not_pass(self):
        positive = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-valid-active-nonmembership"
        )
        mutations = [
            ("receiptVersion", lambda r: r.__setitem__("receiptVersion", "2")),
            ("logicalAddress", lambda r: r.__setitem__("logicalAddress", "other-address")),
            ("nativeAddress", lambda r: r.__setitem__("nativeAddress", "other-native-address")),
            ("contentHash", lambda r: r.__setitem__("contentHash", "00" * 32)),
            ("state", lambda r: r.__setitem__("state", "included")),
            ("observationDisposition", lambda r: r.__setitem__("observationDisposition", "pending")),
            ("transactionRef.kind", lambda r: r["transactionRef"].__setitem__("kind", "other-tx")),
            ("writer", lambda r: r.__setitem__("writer", "other-writer")),
            ("transactionRef.value", lambda r: r.__setitem__(
                "transactionRef", {"kind": "demos-tx", "value": "00" * 32})),
            ("nonce", lambda r: r.__setitem__("nonce", "999")),
            ("blockRef.id", lambda r: r["blockRef"].__setitem__("id", "ff" * 32)),
            ("blockRef.height", lambda r: r["blockRef"].__setitem__("height", "999")),
            ("blockRef.timestamp", lambda r: r["blockRef"].__setitem__("timestamp", 1)),
            ("evidence", lambda r: r.__setitem__("evidence", {"kind": "x", "value": "y"})),
            ("finalityProfile", lambda r: r.__setitem__("finalityProfile", "other")),
            ("substrate", lambda r: r.__setitem__("substrate", "other")),
            ("observedAt", lambda r: r.__setitem__("observedAt", 1)),
        ]
        history = positive["input"]["resolutionContext"]["headHistory"]
        for position in range(len(history)):
            for name, mutate in mutations:
                with self.subTest(position=position, field=name):
                    tampered = json.loads(json.dumps(positive["input"]))
                    mutate(tampered["resolutionContext"]["headHistory"][position]["receipt"])
                    self.assertEqual(
                        evaluate(tampered, self.document["publicKeys"],
                                 positive.get("trustedProfileAdmission"))[0],
                        "indeterminate",
                    )

    def test_listing_is_authenticated_not_a_bare_boolean(self):
        positive = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-valid-active-nonmembership"
        )
        listing = positive["input"]["listing"]
        self.assertNotIn("authenticated", listing)
        self.assertIn("signature", listing)
        for name, mutate in (
            ("signature-value", lambda l: l["signature"].__setitem__(
                "value", "A" + l["signature"]["value"][1:])),
            ("signature-missing", lambda l: l.pop("signature")),
            ("signer-forged", lambda l: l["signature"].__setitem__(
                "signer", "did:example:outsider")),
            ("tuple-substituted", lambda l: l.__setitem__("listingId", "other-hour")),
        ):
            with self.subTest(mutation=name):
                tampered = json.loads(json.dumps(positive["input"]))
                mutate(tampered["listing"])
                self.assertEqual(
                    evaluate(tampered, self.document["publicKeys"],
                             positive.get("trustedProfileAdmission"))[0],
                    "indeterminate",
                )

    def test_rotation_vector_executes_rsc_inclusion_not_discovery(self):
        rotated = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-authorized-rotation-key"
        )
        self.assertEqual(rotated["input"]["discovery"]["status"], "active")
        self.assertEqual(
            evaluate(rotated["input"], self.document["publicKeys"],
                     rotated.get("trustedProfileAdmission"))[0], "fail"
        )
        corrupted = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-rotated-key-corrupted-signature"
        )
        self.assertEqual(
            evaluate(corrupted["input"], self.document["publicKeys"],
                     corrupted.get("trustedProfileAdmission"))[0], "indeterminate"
        )

    def test_higher_known_head_revokes_supersedes_absent(self):
        higher = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-higher-known-head-revokes"
        )
        self.assertEqual(
            evaluate(higher["input"], self.document["publicKeys"],
                     higher.get("trustedProfileAdmission"))[1]["revocationCheck"],
            "revoked",
        )

    def test_pr396_same_sequence_sibling_matrix_is_authenticated_and_decision_bearing(self):
        vectors = {item["name"]: item for item in self.document["vectors"]}
        expected = {
            "rsc-same-sequence-target-present-authentic": ("fail", "revoked", True),
            "rsc-same-sequence-target-absent-authentic": ("indeterminate", "indeterminate", True),
            "rsc-same-sequence-target-present-inauthentic": ("indeterminate", "indeterminate", False),
            "rsc-same-sequence-target-absent-inauthentic": ("indeterminate", "indeterminate", False),
        }
        for name, (verdict, disposition, authentic) in expected.items():
            with self.subTest(case=name):
                vector = vectors[name]
                data = vector["input"]
                context = data["resolutionContext"]
                conflict = context["knownConflictingHeads"][0]
                checked = validate_head_item(
                    conflict, data["listing"], data["listing"]["revocationState"],
                    self.document["publicKeys"],
                )
                self.assertEqual(checked is not None, authentic)
                self.assertEqual(
                    evaluate(data, self.document["publicKeys"], vector["trustedProfileAdmission"]),
                    (verdict, {"revocationCheck": disposition, "session": "refuse"}),
                )

    def test_pr396_closed_head_schema_matrix_is_signed_but_never_authenticates(self):
        vectors = {item["name"]: item for item in self.document["vectors"]}
        names = {
            f"rsc-head-schema-{head_kind}-{mutation}"
            for head_kind in ("genesis", "transition")
            for mutation in ("extra", "missing", "wrong-type")
        }
        for name in sorted(names):
            with self.subTest(case=name):
                vector = vectors[name]
                data = vector["input"]
                malformed = data["resolutionContext"]["headHistory"][-1]
                head = malformed["head"]
                self.assertTrue(
                    verify_artifact(head, self.document["publicKeys"]["initial"], HEAD_DOMAIN),
                    "the negative must remain freshly signed so the schema gate is load-bearing",
                )
                self.assertIsNone(validate_head_item(
                    malformed, data["listing"], data["listing"]["revocationState"],
                    self.document["publicKeys"],
                ))
                self.assertEqual(
                    evaluate(data, self.document["publicKeys"], vector["trustedProfileAdmission"]),
                    ("indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}),
                )

        controls = ("rsc-valid-genesis-absent", "rsc-valid-active-nonmembership")
        for name in controls:
            vector = vectors[name]
            item = vector["input"]["resolutionContext"]["headHistory"][-1]
            self.assertIsNotNone(validate_head_item(
                item, vector["input"]["listing"],
                vector["input"]["listing"]["revocationState"],
                self.document["publicKeys"],
            ))

    def test_pre_review_selector_and_reference_negatives_isolate_the_intended_property(self):
        vectors = {item["name"]: item for item in self.document["vectors"]}

        for name in (
            "rsc-selector-genesis-with-transition",
            "rsc-selector-transition-without-transition",
        ):
            with self.subTest(case=name):
                vector = vectors[name]
                item = vector["input"]["resolutionContext"]["headHistory"][-1]
                head = item["head"]
                self.assertTrue(
                    verify_artifact(head, self.document["publicKeys"]["initial"], HEAD_DOMAIN),
                    "selector negatives must remain signed",
                )
                self.assertEqual(item["receipt"]["contentHash"], artifact_hash(head))
                self.assertFalse(validate_head_shape(head))

        for name in (
            "rsc-reference-duplicate-consumed",
            "rsc-reference-shadowed-consumed",
            "rsc-reference-wrong-target",
            "rsc-reference-unused-authentic",
        ):
            with self.subTest(case=name):
                vector = vectors[name]
                markers = vector["input"]["resolutionContext"]["resolvedMarkers"]
                self.assertTrue(markers)
                for entry in markers:
                    marker = entry["marker"]
                    self.assertTrue(
                        verify_artifact(
                            marker, self.document["publicKeys"]["initial"], MARKER_DOMAIN
                        ),
                        "reference-boundary negatives must not rely on a bad marker signature",
                    )
                self.assertEqual(
                    evaluate(
                        vector["input"], self.document["publicKeys"],
                        vector["trustedProfileAdmission"],
                    ),
                    ("indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}),
                )

        shadow = vectors["rsc-reference-shadowed-consumed"]["input"][
            "resolutionContext"
        ]["resolvedMarkers"][-1]
        self.assertEqual(
            len(vectors["rsc-reference-shadowed-consumed"]["input"][
                "resolutionContext"
            ]["resolvedMarkers"]),
            1,
            "shadow coverage must not collapse into duplicate-reference coverage",
        )
        self.assertEqual(
            shadow["receipt"]["contentHash"], shadow["revocationRef"]["contentHash"],
            "the shadow must not fail because its finalized receipt is stale",
        )
        self.assertNotEqual(
            artifact_hash(shadow["marker"]), shadow["revocationRef"]["contentHash"],
            "the exact marker-to-reference binding is the isolated shadow defect",
        )
        self.assertTrue(verify_authority_evidence(
            shadow["authority"], self.document["publicKeys"]["keyLifecycleAuthority"],
            shadow["revocationRef"]["signer"], shadow["authority"]["key"],
            shadow["receipt"]["blockRef"]["id"],
        ))
        repaired = json.loads(json.dumps(
            vectors["rsc-reference-shadowed-consumed"]["input"]
        ))
        repaired["resolutionContext"]["resolvedMarkers"][0]["marker"] = json.loads(
            json.dumps(vectors["rsc-valid-active-nonmembership"]["input"][
                "resolutionContext"
            ]["resolvedMarkers"][0]["marker"])
        )
        self.assertEqual(
            evaluate(
                repaired, self.document["publicKeys"],
                vectors["rsc-reference-shadowed-consumed"]["trustedProfileAdmission"],
            ),
            ("pass", {"revocationCheck": "absent", "session": "continue"}),
            "repairing only the marker-to-reference binding must restore the control",
        )

    def test_conflict_set_revocation_precedence_is_order_independent(self):
        third = g.listing_tuple("third-service", "66" * 32)
        third_marker = g.marker(third)
        third_ref = g.marker_ref(third_marker, "third-service")
        non_target, _ = g.append_head(g.OTHER_HEAD, g.OTHER_LEAVES,
                                      third, third_ref)
        target, _ = g.append_head(g.OTHER_HEAD, g.OTHER_LEAVES,
                                  g.TARGET, g.TARGET_REF)
        pubs = self.document["publicKeys"]
        for heads in ((non_target, target), (target, non_target)):
            with self.subTest(target_last=heads[-1] is target):
                data = g.input_for(
                    g.OTHER_HEAD, g.OTHER_LEAVES,
                    conflicting_heads=[g.history_item(head) for head in heads],
                )
                context = data["resolutionContext"]
                context["resolvedMarkers"].extend([
                    g.resolved_marker(g.TARGET_REF, g.TARGET_MARKER,
                                      g.SELLER_KEY, g.LISTING_ID),
                    g.resolved_marker(third_ref, third_marker,
                                      g.SELLER_KEY, "third-service"),
                ])
                for item in context["knownConflictingHeads"]:
                    self.assertIsNotNone(validate_head_item(
                        item, data["listing"], data["listing"]["revocationState"], pubs,
                    ))
                    self.assertTrue(validate_transition(
                        item["head"], g.OTHER_HEAD, g.artifact_hash(g.OTHER_HEAD),
                        context, pubs,
                    ))
                for caller in (evaluate, evaluate_recorded_policy):
                    self.assertEqual(
                        caller(data, pubs, g.profile_admission()),
                        ("fail", {"revocationCheck": "revoked", "session": "refuse"}),
                    )

        non_target_only = g.input_for(
            g.OTHER_HEAD, g.OTHER_LEAVES,
            conflicting_heads=[g.history_item(non_target)],
        )
        non_target_only["resolutionContext"]["resolvedMarkers"].append(
            g.resolved_marker(third_ref, third_marker, g.SELLER_KEY, "third-service")
        )
        self.assertEqual(
            evaluate(non_target_only, pubs, g.profile_admission()),
            ("indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}),
        )

    def test_invalid_conflict_does_not_mask_independent_revocation(self):
        target_higher, _ = g.append_head(g.OTHER_HEAD, g.OTHER_LEAVES,
                                         g.TARGET, g.TARGET_REF)
        invalid = g.history_item(target_higher)
        invalid["head"]["signature"]["value"] = "not-a-signature"
        valid = g.history_item(target_higher)
        for heads in ((invalid, valid), (valid, invalid)):
            with self.subTest(valid_last=heads[-1] is valid):
                data = g.input_for(g.OTHER_HEAD, g.OTHER_LEAVES,
                                   conflicting_heads=list(heads))
                data["resolutionContext"]["resolvedMarkers"].append(
                    g.resolved_marker(g.TARGET_REF, g.TARGET_MARKER,
                                      g.SELLER_KEY, g.LISTING_ID)
                )
                for caller in (evaluate, evaluate_recorded_policy):
                    self.assertEqual(
                        caller(data, g.document()["publicKeys"], g.profile_admission()),
                        ("fail", {"revocationCheck": "revoked", "session": "refuse"}),
                    )
        invalid_only = g.input_for(g.OTHER_HEAD, g.OTHER_LEAVES,
                                   conflicting_heads=[invalid])
        self.assertEqual(
            evaluate(invalid_only, g.document()["publicKeys"], g.profile_admission()),
            ("indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}),
        )

    def test_wrong_key_and_wrong_algorithm_vectors_fail_closed(self):
        for name in ("rsc-wrong-signer-key", "rsc-wrong-signature-algorithm"):
            with self.subTest(vector=name):
                vector = next(
                    item for item in self.document["vectors"]
                    if item["name"] == name
                )
                self.assertEqual(
                    evaluate(vector["input"], self.document["publicKeys"],
                             vector.get("trustedProfileAdmission"))[0],
                    "indeterminate",
                )

    def test_positive_current_state_proof_is_cryptographic_and_test_only(self):
        self.assertEqual(self.document["testBinding"]["scope"], "conformance-harness-only")
        self.assertFalse(self.document["testBinding"]["productionEligible"])
        positive = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-valid-active-nonmembership"
        )
        tampered = json.loads(json.dumps(positive["input"]))
        tampered["resolutionContext"]["currentStateEvidence"]["finalizedStateId"] = "block-other"
        self.assertEqual(
            evaluate(tampered, self.document["publicKeys"],
                     positive.get("trustedProfileAdmission"))[0],
            "indeterminate",
        )

    def test_generator_is_deterministic(self):
        completed = subprocess.run(
            ["python3", str(GENERATOR), "--check"], cwd=ROOT,
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_spec_and_mapping_pin_fail_closed_boundary(self):
        spec = SPEC.read_text(encoding="utf-8")
        core = CORE.read_text(encoding="utf-8")
        mapping = MAPPING.read_text(encoding="utf-8")
        self.assertIn("**DACS-1 v0.8**", spec)
        self.assertIn("(RSC-1)", spec)
        self.assertIn("(RSC-9)", spec)
        self.assertIn("(RSC-10)", spec)
        self.assertIn("Downgrade-safe boundary", spec)
        self.assertIn('"dacs-revocation-state-head:v1:"', core)
        self.assertIn("cannot produce current RSC `absent`", spec)
        self.assertIn("cannot satisfy DACS-1 RSC-3", mapping)

    def test_downgrade_without_profile_admission_refuses(self):
        vector = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-downgrade-without-profile-admission"
        )
        self.assertNotIn("currentProfile", vector["input"])
        self.assertNotIn("trustedProfileAdmission", vector)
        self.assertEqual(
            evaluate(vector["input"], self.document["publicKeys"],
                     vector.get("trustedProfileAdmission"))[0], "indeterminate"
        )

    def test_profile_admission_negatives_fail_closed_before_effects(self):
        names = {
            "rsc-profile-admission-release-mismatch",
            "rsc-profile-admission-module-mismatch",
            "rsc-profile-admission-module-incomplete",
            "rsc-profile-admission-session-mismatch",
            "rsc-profile-admission-identity-mismatch",
            "rsc-profile-admission-unauthenticated",
            "rsc-profile-admission-caller-copy",
        }
        for name in names:
            with self.subTest(vector=name):
                vector = next(
                    item for item in self.document["vectors"]
                    if item["name"] == name
                )
                self.assertEqual(
                    evaluate(vector["input"], self.document["publicKeys"],
                             vector.get("trustedProfileAdmission"))[0],
                    "indeterminate",
                )

    def test_authoritative_profile_is_exact_and_closed(self):
        profile = self.document["authoritativeProfile"]
        self.assertEqual(profile["releasePin"], AUTHORITATIVE_RELEASE_PIN)
        self.assertEqual(profile["moduleVersions"], AUTHORITATIVE_MODULE_VERSIONS)
        self.assertTrue(exact_corrective_profile(profile))
        current_table = dict(re.findall(
            r"^\| \[([^]]+)\]\([^)]+\) \| ([0-9.]+) \|",
            (ROOT / "spec" / "PROFILE.md").read_text(encoding="utf-8"),
            re.MULTILINE,
        ))
        for key, document in (
            ("core", "CORE"), ("dacs1", "DACS-1-IDENTIFY"),
            ("dacs2", "DACS-2-VET"), ("dacs3", "DACS-3-NEGOTIATE"),
            ("dacs4", "DACS-4-SETTLE"), ("dacs5", "DACS-5-VERIFY"),
        ):
            self.assertEqual(profile["moduleVersions"][key], current_table[document])
        positive = next(
            vector for vector in self.document["vectors"]
            if vector["name"] == "rsc-valid-active-nonmembership"
        )
        self.assertEqual(positive["trustedProfileAdmission"]["profile"], profile)

    def test_conflict_evidence_omission_is_indeterminate_not_absent(self):
        # A1: the higher revoking-head case is `revoked`; removing the signed
        # complete conflict-observation set must be indeterminate, never absent.
        higher = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-higher-known-head-revokes"
        )
        self.assertEqual(
            evaluate(higher["input"], self.document["publicKeys"],
                     higher.get("trustedProfileAdmission"))[1]["revocationCheck"],
            "revoked",
        )
        for name in ("rsc-conflict-evidence-omitted", "rsc-conflict-evidence-tampered"):
            with self.subTest(vector=name):
                vector = next(
                    item for item in self.document["vectors"]
                    if item["name"] == name
                )
                verdict, want = evaluate(
                    vector["input"], self.document["publicKeys"],
                    vector.get("trustedProfileAdmission"),
                )
                self.assertEqual(verdict, "indeterminate")
                self.assertEqual(want["revocationCheck"], "indeterminate")
                self.assertNotEqual(want["revocationCheck"], "absent")

    def test_listing_receipt_negatives_are_indeterminate(self):
        for name in (
            "rsc-listing-receipt-missing",
            "rsc-listing-receipt-stale",
            "rsc-listing-receipt-tampered",
        ):
            with self.subTest(vector=name):
                vector = next(
                    item for item in self.document["vectors"]
                    if item["name"] == name
                )
                self.assertEqual(
                    evaluate(vector["input"], self.document["publicKeys"],
                             vector.get("trustedProfileAdmission"))[0],
                    "indeterminate",
                )

    def test_conflict_evolution_rewrite_and_removal_are_indeterminate(self):
        # A1 completion: authenticated conflict-set evolution stays fail-closed.
        # A later authenticated head that rewrites the target via a cross-tuple
        # transition substitution, or that removes the appended leaf via a root
        # mutation, is indeterminate — never `revoked` and never `absent`.
        for name in ("rsc-conflict-later-rewrite", "rsc-conflict-removal-transition"):
            with self.subTest(vector=name):
                vector = next(
                    item for item in self.document["vectors"]
                    if item["name"] == name
                )
                verdict, want = evaluate(
                    vector["input"], self.document["publicKeys"],
                    vector.get("trustedProfileAdmission"),
                )
                self.assertEqual(verdict, "indeterminate")
                self.assertEqual(want["revocationCheck"], "indeterminate")
                self.assertNotIn(want["revocationCheck"], ("revoked", "absent"))

    def test_malformed_nested_proof_containers_are_indeterminate(self):
        # The RSC reference evaluator is total on malformed nested proof
        # containers: a list-valued or otherwise non-object blockRef on the head
        # or listing receipt, or a non-object head authority, must return
        # non-authorizing indeterminate and never raise AttributeError.
        for name in (
            "rsc-head-receipt-blockref-list",
            "rsc-head-receipt-blockref-string",
            "rsc-listing-receipt-blockref-list",
            "rsc-listing-receipt-blockref-string",
            "rsc-head-authority-list",
            "rsc-head-authority-string",
        ):
            with self.subTest(vector=name):
                vector = next(
                    item for item in self.document["vectors"]
                    if item["name"] == name
                )
                self.assertEqual(
                    evaluate(vector["input"], self.document["publicKeys"],
                             vector.get("trustedProfileAdmission"))[0],
                    "indeterminate",
                )

    def test_malformed_scalars_roots_and_signatures_are_indeterminate(self):
        # RSC totality completion: an independently re-signed Listing whose
        # revocationState anchor is a list/string/locator-less object, a list/None
        # authority key, a list-valued Listing/head/marker signature value, and a
        # non-object root input must all return non-authorizing indeterminate and
        # never raise TypeError/KeyError/AttributeError.
        for name in (
            "rsc-listing-anchor-list",
            "rsc-listing-anchor-string",
            "rsc-listing-anchor-missing-locator",
            "rsc-head-authority-key-list",
            "rsc-head-authority-key-none",
            "rsc-listing-signature-value-list",
            "rsc-head-signature-value-list",
            "rsc-marker-signature-value-list",
            "rsc-non-object-root-list",
            "rsc-non-object-root-string",
        ):
            with self.subTest(vector=name):
                vector = next(
                    item for item in self.document["vectors"]
                    if item["name"] == name
                )
                self.assertEqual(
                    evaluate(vector["input"], self.document["publicKeys"],
                             vector.get("trustedProfileAdmission"))[0],
                    "indeterminate",
                )

    def test_authority_evidence_is_load_bearing(self):
        # RSC-2: the key-lifecycle authority evidence binding (claim, key,
        # validAt) is authenticated at every head and marker path. Omission,
        # wrong containers, attacker substitution, and nested malformation must
        # fail closed as indeterminate, never authorizing absent/revoked.
        names = {
            item["name"] for item in self.document["vectors"]
        }
        self.assertTrue(any(
            name.startswith("rsc-head-authority-evidence-") for name in names
        ))
        self.assertTrue(any(
            name.startswith("rsc-marker-authority-evidence-") for name in names
        ))
        for name in names:
            if not (
                name.startswith("rsc-head-authority-evidence-")
                or name.startswith("rsc-marker-authority-evidence-")
            ):
                continue
            with self.subTest(vector=name):
                vector = next(
                    item for item in self.document["vectors"]
                    if item["name"] == name
                )
                verdict, want = evaluate(
                    vector["input"], self.document["publicKeys"],
                    vector.get("trustedProfileAdmission"),
                )
                self.assertEqual(verdict, "indeterminate")
                self.assertNotIn(want["revocationCheck"], ("absent", "revoked"))

    def test_authority_evidence_probe_tamper_cannot_authorize(self):
        # Independent reproduction of the reviewer probe: mutating or removing
        # authority.evidence at either headHistory position or on the marker must
        # stop authorizing the active non-membership (never `absent`).
        positive = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-valid-active-nonmembership"
        )
        history = positive["input"]["resolutionContext"]["headHistory"]
        for position in range(len(history)):
            for mutate in (
                lambda a: a.pop("evidence", None),
                lambda a: a.__setitem__("evidence", ["bad"]),
                lambda a: a.__setitem__("evidence", {"kind": "x", "value": "y"}),
            ):
                with self.subTest(position=position):
                    tampered = json.loads(json.dumps(positive["input"]))
                    mutate(tampered["resolutionContext"]["headHistory"][position]["authority"])
                    verdict, want = evaluate(
                        tampered, self.document["publicKeys"],
                        positive.get("trustedProfileAdmission"),
                    )
                    self.assertEqual(verdict, "indeterminate")
                    self.assertNotEqual(want["revocationCheck"], "absent")
        markers = positive["input"]["resolutionContext"].get("resolvedMarkers", [])
        for position in range(len(markers)):
            for mutate in (
                lambda a: a.pop("evidence", None),
                lambda a: a.__setitem__("evidence", ["bad"]),
                lambda a: a.__setitem__("evidence", {"kind": "x", "value": "y"}),
            ):
                with self.subTest(marker=position):
                    tampered = json.loads(json.dumps(positive["input"]))
                    mutate(tampered["resolutionContext"]["resolvedMarkers"][position]["authority"])
                    verdict, want = evaluate(
                        tampered, self.document["publicKeys"],
                        positive.get("trustedProfileAdmission"),
                    )
                    self.assertEqual(verdict, "indeterminate")
                    self.assertNotEqual(want["revocationCheck"], "absent")

    def test_normative_type_parity_with_vector_and_evaluator(self):
        # The normative RevocationHeadResolutionContext wire type must carry every
        # mandatory runtime field the generator emits and the reference evaluator
        # requires, with `knownConflictingHeads` mandatory (never optional) and a
        # `currentStateEvidence` shape that includes the listing/head/conflict
        # binding hashes. The declared types (not just key sets) must also match:
        # arrays stay arrays, `listingReceipt` stays `AnchorReceipt`, and the
        # nested `currentStateEvidence.evidence` object stays `{kind, value}`.
        shape = _normative_context_shape()
        self.assertEqual(set(shape["context_fields"]), set(EXPECTED_CONTEXT_FIELDS))
        self.assertEqual(shape["context_optional"], set(), "RevocationHeadResolutionContext fields must all be mandatory")
        self.assertEqual(set(shape["current_state_fields"]), set(EXPECTED_CURRENT_STATE_FIELDS))
        self.assertEqual(shape["current_state_optional"], set(), "currentStateEvidence fields must all be mandatory")
        self.assertNotIn("knownConflictingHeads", shape["context_optional"])
        self.assertEqual(shape["context_types"], EXPECTED_CONTEXT_TYPES)
        self.assertEqual(shape["current_state_types"], dict(EXPECTED_CURRENT_STATE_TYPES))
        self.assertEqual(
            shape["current_state_types"]["evidence"],
            ("object", (("kind", "string"), ("value", "string"))),
        )

        positive = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-valid-active-nonmembership"
        )
        resolution = positive["input"]["resolutionContext"]
        self.assertEqual(set(resolution.keys()), set(EXPECTED_CONTEXT_FIELDS))
        self.assertEqual(
            set(resolution["currentStateEvidence"].keys()),
            set(EXPECTED_CURRENT_STATE_FIELDS),
        )

    def test_normative_type_parity_detects_type_mutations(self):
        # The spec-parity parser must pin declared types, not just field names.
        # Independently mutating a declared type (listingReceipt -> string,
        # knownConflictingHeads -> string, listingContentHash -> number) must
        # change the normalized type; a name-only parser would return an
        # equivalent shape and falsely pass.
        block = _extract_context_type_block(SPEC.read_text(encoding="utf-8"))
        baseline = _parse_context_type_block(block)
        mutations = [
            ("listingReceipt: AnchorReceipt", "listingReceipt: string",
             "context_types", "listingReceipt", "string"),
            ("knownConflictingHeads: ResolvedRevocationHead[]", "knownConflictingHeads: string",
             "context_types", "knownConflictingHeads", "string"),
            ("listingContentHash: string", "listingContentHash: number",
             "current_state_types", "listingContentHash", "number"),
        ]
        for needle, replacement, bucket, field, expected_mutant in mutations:
            with self.subTest(mutation=needle):
                self.assertEqual(block.count(needle), 1, "spec field must be unique within the type block")
                mutated = _parse_context_type_block(block.replace(needle, replacement, 1))
                self.assertEqual(mutated[bucket][field], expected_mutant)
                self.assertNotEqual(mutated[bucket][field], baseline[bucket][field])

    def test_type_parser_preserves_nested_evidence_optionality(self):
        # The reviewer probe: ``currentStateEvidence.evidence`` is a closed inline
        # ``{ kind: string; value: string }`` object whose ``kind``/``value`` are
        # normative and mandatory. A nested ``?`` optionality marker on either
        # field must survive normalization (never be stripped to ``kind``/``value``)
        # and must therefore change the parsed nested type, not reuse the baseline.
        block = _extract_context_type_block(SPEC.read_text(encoding="utf-8"))
        baseline = _parse_context_type_block(block)
        evidence = baseline["current_state_types"]["evidence"]
        self.assertEqual(
            evidence,
            ("object", (("kind", "string"), ("value", "string"))),
        )
        for name, _ in evidence[1]:
            self.assertFalse(name.endswith("?"), "nested evidence field %r must not be optional" % name)

        needle = "evidence: { kind: string; value: string }"
        self.assertEqual(block.count(needle), 1, "evidence inline object must be unique in the context type block")
        mutations = (
            ("kind?", "evidence: { kind?: string; value: string }",
             ("object", (("kind?", "string"), ("value", "string")))),
            ("value?", "evidence: { kind: string; value?: string }",
             ("object", (("kind", "string"), ("value?", "string")))),
            ("both?", "evidence: { kind?: string; value?: string }",
             ("object", (("kind?", "string"), ("value?", "string")))),
        )
        for label, replacement, expected in mutations:
            with self.subTest(mutation=label):
                mutated = _parse_context_type_block(block.replace(needle, replacement, 1))
                self.assertEqual(mutated["current_state_types"]["evidence"], expected)
                self.assertNotEqual(mutated["current_state_types"]["evidence"], evidence)
                self.assertEqual(mutated["current_state_fields"], baseline["current_state_fields"])

    def test_type_parser_requires_balanced_braces_and_exact_consumption(self):
        # The inline-object boundary must be strict and total: a missing nested
        # closing brace, an extra closing brace, a premature EOF, an invalid
        # (partial) dedent, or trailing/unconsumed type material must raise
        # AssertionError instead of silently truncating to the valid schema.
        block = _extract_context_type_block(SPEC.read_text(encoding="utf-8"))
        needle = "evidence: { kind: string; value: string }"
        self.assertEqual(block.count(needle), 1, "evidence inline object must be unique in the context type block")
        missing = block.replace(needle, "evidence: { kind: string; value: string", 1)
        extra = block.replace(needle, "evidence: { kind: string; value: string } }", 1)
        eof = block[:-1]
        trailing = block + "\nextraField: string"
        dedented = block.replace("  headRef: AttestationRef", " headRef: AttestationRef")
        for label, mutated_text in (
            ("missing-nested-closing-brace", missing),
            ("extra-closing-brace", extra),
            ("premature-eof", eof),
            ("trailing-unconsumed-material", trailing),
            ("invalid-dedent", dedented),
        ):
            with self.subTest(mutation=label):
                with self.assertRaises(AssertionError):
                    _parse_context_type_block(mutated_text)

    def test_evaluator_rejects_omission_of_every_mandatory_runtime_field(self):
        # Pin the reference evaluator's closed shape: dropping any mandatory
        # currentStateEvidence member or any runtime-read context field from the
        # generated positive vector must be indeterminate, never absent. This now
        # includes `resolvedMarkers`, whose omission is otherwise fail-open on a
        # transition-free genesis absent read.
        positive = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-valid-active-nonmembership"
        )
        for field in EXPECTED_CURRENT_STATE_FIELDS:
            with self.subTest(component="currentStateEvidence", field=field):
                tampered = json.loads(json.dumps(positive["input"]))
                tampered["resolutionContext"]["currentStateEvidence"].pop(field)
                verdict, want = evaluate(
                    tampered, self.document["publicKeys"],
                    positive.get("trustedProfileAdmission"),
                )
                self.assertEqual(verdict, "indeterminate")
                self.assertNotEqual(want["revocationCheck"], "absent")
        for field in EXPECTED_CONTEXT_FIELDS:
            with self.subTest(component="resolutionContext", field=field):
                tampered = json.loads(json.dumps(positive["input"]))
                tampered["resolutionContext"].pop(field)
                verdict, want = evaluate(
                    tampered, self.document["publicKeys"],
                    positive.get("trustedProfileAdmission"),
                )
                self.assertEqual(verdict, "indeterminate")
                self.assertNotEqual(want["revocationCheck"], "absent")

    def test_resolved_markers_empty_is_valid_and_malformed_is_rejected(self):
        # The mandatory ``resolvedMarkers`` is a closed-shape container: an
        # explicit empty array on a transition-free genesis absent read is valid
        # (pass/absent), while omission, null, an object, a malformed entry, or
        # an extra context member all fail closed as indeterminate, never absent.
        genesis = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-valid-genesis-absent"
        )
        self.assertEqual(genesis["input"]["resolutionContext"]["resolvedMarkers"], [])
        self.assertEqual(genesis["input"]["resolutionContext"]["headHistory"][0]["head"]["sequence"], "0")
        verdict, want = evaluate(
            genesis["input"], self.document["publicKeys"],
            genesis.get("trustedProfileAdmission"),
        )
        self.assertEqual((verdict, want), (genesis["expected"], genesis["want"]))
        self.assertEqual(want["revocationCheck"], "absent")

        mutations = [
            ("omitted", lambda c: c.pop("resolvedMarkers")),
            ("null", lambda c: c.__setitem__("resolvedMarkers", None)),
            ("object", lambda c: c.__setitem__("resolvedMarkers", {})),
            ("string-entry", lambda c: c.__setitem__("resolvedMarkers", ["marker"])),
            ("null-entry", lambda c: c.__setitem__("resolvedMarkers", [None])),
            ("extra-member", lambda c: c.__setitem__("resolvedMarkersExtra", [])),
        ]
        for name, mutate in mutations:
            with self.subTest(mutation=name):
                tampered = json.loads(json.dumps(genesis["input"]))
                mutate(tampered["resolutionContext"])
                verdict, want = evaluate(
                    tampered, self.document["publicKeys"],
                    genesis.get("trustedProfileAdmission"),
                )
                self.assertEqual(verdict, "indeterminate")
                self.assertNotEqual(want["revocationCheck"], "absent")

    def test_explicit_empty_conflict_set_is_mandatory_and_valid(self):
        # The complete conflict-observation set is mandatory even when empty: the
        # generated positive vector carries an explicit ``knownConflictingHeads: []``
        # and still admits a new session. Omitting the field is indeterminate.
        positive = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-valid-active-nonmembership"
        )
        self.assertIn("knownConflictingHeads", positive["input"]["resolutionContext"])
        self.assertEqual(positive["input"]["resolutionContext"]["knownConflictingHeads"], [])
        verdict, want = evaluate(
            positive["input"], self.document["publicKeys"],
            positive.get("trustedProfileAdmission"),
        )
        self.assertEqual((verdict, want), (positive["expected"], positive["want"]))
        self.assertEqual(want["revocationCheck"], "absent")

        omitted = json.loads(json.dumps(positive["input"]))
        omitted["resolutionContext"].pop("knownConflictingHeads")
        verdict, want = evaluate(
            omitted, self.document["publicKeys"],
            positive.get("trustedProfileAdmission"),
        )
        self.assertEqual(verdict, "indeterminate")
        self.assertNotEqual(want["revocationCheck"], "absent")

    def test_absent_branch_refuses_independently_authenticated_target_marker(self):
        # RSC-7/RSC-9: the authorizing absent branch cannot ignore a resolved
        # marker that independently authenticates a revocation of the exact
        # Listing tuple. A producer caching such a context (unused marker) must
        # not reproduce `absent`: the authenticated marker view conflicts with
        # the current-head non-membership view, so the verdict is non-authorizing
        # indeterminate, never absent and never revoked.
        active = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-valid-active-nonmembership"
        )
        discovered = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-rb4-discovered-marker-precedes-nonmembership"
        )
        listing = active["input"]["listing"]
        target_entry = next(
            item for item in discovered["input"]["resolutionContext"]["resolvedMarkers"]
            if item.get("marker", {}).get("listingId") == listing.get("listingId")
            and item.get("marker", {}).get("listingContentHash") == listing.get("listingContentHash")
        )
        self.assertEqual(active["expected"], "pass")
        self.assertEqual(active["want"]["revocationCheck"], "absent")

        injected = json.loads(json.dumps(active["input"]))
        injected["resolutionContext"]["resolvedMarkers"].append(
            json.loads(json.dumps(target_entry))
        )
        verdict, want = evaluate(
            injected, self.document["publicKeys"],
            active.get("trustedProfileAdmission"),
        )
        self.assertEqual(verdict, "indeterminate")
        self.assertNotIn(want["revocationCheck"], ("absent", "revoked"))
        self.assertEqual(want["session"], "refuse")

    def test_absent_branch_refuses_malformed_or_unusable_marker_context(self):
        # RSC-9: retained marker context must be exact. An empty dict entry, a
        # shell entry with a non-object revocationRef, or a well-shaped but
        # unauthenticated marker entry is malformed or unused context and is
        # non-conforming; reproducing `absent` from it must refuse. The
        # legitimate active/genesis absence — including the consumed other-target
        # transition marker on the active vector — stays `absent`.
        active = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-valid-active-nonmembership"
        )
        genesis = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-valid-genesis-absent"
        )
        discovered = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-rb4-discovered-marker-precedes-nonmembership"
        )
        listing = active["input"]["listing"]
        target_entry = next(
            item for item in discovered["input"]["resolutionContext"]["resolvedMarkers"]
            if item.get("marker", {}).get("listingId") == listing.get("listingId")
            and item.get("marker", {}).get("listingContentHash") == listing.get("listingContentHash")
        )
        unusable = json.loads(json.dumps(target_entry))
        unusable["marker"]["signature"]["value"] = (
            "A" + unusable["marker"]["signature"]["value"][1:]
        )
        mutations = [
            ("empty-dict", {}),
            ("shell-revocationRef-string", {"revocationRef": "not-a-ref"}),
            ("shell-missing-authority", {
                "revocationRef": json.loads(json.dumps(target_entry["revocationRef"])),
                "marker": json.loads(json.dumps(target_entry["marker"])),
                "receipt": json.loads(json.dumps(target_entry["receipt"])),
            }),
            ("unauthenticated-marker", unusable),
        ]
        for name, entry in mutations:
            with self.subTest(mutation=name):
                injected = json.loads(json.dumps(active["input"]))
                injected["resolutionContext"]["resolvedMarkers"].append(entry)
                verdict, want = evaluate(
                    injected, self.document["publicKeys"],
                    active.get("trustedProfileAdmission"),
                )
                self.assertEqual(verdict, "indeterminate")
                self.assertNotEqual(want["revocationCheck"], "absent")
                self.assertEqual(want["session"], "refuse")

        baseline, want = evaluate(
            active["input"], self.document["publicKeys"],
            active.get("trustedProfileAdmission"),
        )
        self.assertEqual((baseline, want), (active["expected"], active["want"]))
        self.assertEqual(want["revocationCheck"], "absent")
        genesis_result, genesis_want = evaluate(
            genesis["input"], self.document["publicKeys"],
            genesis.get("trustedProfileAdmission"),
        )
        self.assertEqual((genesis_result, genesis_want), (genesis["expected"], genesis["want"]))
        self.assertEqual(genesis_want["revocationCheck"], "absent")

    def test_absent_branch_refuses_valid_but_unused_other_marker(self):
        # RSC-9 does not permit a well-authenticated marker to become inert
        # merely because it names another tuple. The active control consumes
        # this marker in a validated head transition; genesis has no transition
        # and therefore cannot retain it while claiming complete absence.
        active = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-valid-active-nonmembership"
        )
        genesis = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-valid-genesis-absent"
        )
        marker = active["input"]["resolutionContext"]["resolvedMarkers"][0]
        self.assertEqual(
            evaluate(active["input"], self.document["publicKeys"],
                     active.get("trustedProfileAdmission")),
            ("pass", {"revocationCheck": "absent", "session": "continue"}),
        )
        replay = json.loads(json.dumps(genesis["input"]))
        replay["resolutionContext"]["resolvedMarkers"].append(json.loads(json.dumps(marker)))
        self.assertEqual(
            evaluate(replay, self.document["publicKeys"],
                     genesis.get("trustedProfileAdmission")),
            ("indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}),
        )

    def test_conflicting_head_cannot_launder_unused_marker(self):
        # A signed conflict head can have the right outer shape while its
        # transition is invalid. Its ref must not make an otherwise-unused
        # marker appear consumed in an authorizing absence proof.
        third = g.listing_tuple("third-service", "66" * 32)
        third_marker = g.marker(third)
        ref = g.marker_ref(third_marker, "third-service")
        key = g.leaf_key(third)
        unsigned = {name: json.loads(json.dumps(value)) for name, value in g.GENESIS.items()
                    if name != "signature"}
        unsigned["transition"] = {
            "leafKey": key,
            "revocationRef": ref,
            "priorProof": g.compact_proof({}, key),
        }
        conflict = g.sign_artifact(unsigned, g.SELLER_KEY, g.SELLER, g.HEAD_DOMAIN)
        data = g.input_for(g.OTHER_HEAD, g.OTHER_LEAVES,
                           conflicting_heads=[g.history_item(conflict)])
        context = data["resolutionContext"]
        context["resolvedMarkers"].append(
            g.resolved_marker(ref, third_marker, g.SELLER_KEY, "third-service")
        )
        pubs = g.document()["publicKeys"]
        # RSC-2 now rejects this sequence-0-plus-transition shape before it can
        # be treated as an authenticated head; the unused marker remains
        # non-authorizing either way.
        self.assertIsNone(validate_head_item(
            context["knownConflictingHeads"][0], data["listing"],
            data["listing"]["revocationState"], pubs,
        ))
        self.assertEqual(
            evaluate(data, pubs, g.profile_admission()),
            ("indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}),
        )

    def test_consumed_signed_marker_accepts_future_optional_member(self):
        # CORE SIG-5: preserve and authenticate unknown signed artifact members;
        # a valid non-target transition remains a legitimate absence control.
        base = g.marker(g.OTHER)
        unsigned = {name: json.loads(json.dumps(value)) for name, value in base.items()
                    if name != "signature"}
        unsigned["futureOptionalNote"] = "inert-signed-extension"
        extended = g.sign_artifact(unsigned, g.SELLER_KEY, g.SELLER, g.MARKER_DOMAIN)
        ref = g.marker_ref(extended, "other-extended")
        head, leaves = g.append_head(g.GENESIS, {}, g.OTHER, ref)
        data = g.input_for(head, leaves)
        context = data["resolutionContext"]
        context["resolvedMarkers"] = [
            g.resolved_marker(ref, extended, g.SELLER_KEY, g.OTHER_LISTING_ID)
        ]
        pubs = g.document()["publicKeys"]
        self.assertTrue(verify_artifact(extended, pubs["initial"], MARKER_DOMAIN))
        self.assertTrue(validate_transition(
            head, g.GENESIS, g.artifact_hash(g.GENESIS), context, pubs,
        ))
        self.assertEqual(
            evaluate(data, pubs, g.profile_admission()),
            ("pass", {"revocationCheck": "absent", "session": "continue"}),
        )

    def test_absent_branch_refuses_shadowed_and_duplicate_target_marker(self):
        # RSC-9/RSC-7: a shadow or duplicate marker entry with the same
        # `revocationRef` must not hide a verified exact-target revocation.
        # `resolve_marker`'s multiplicity guard alone would treat the duplicated
        # ref as unresolved; the closed marker-context boundary must refuse
        # (indeterminate), never reproduce `absent`, whether the second entry is
        # a full duplicate of the authenticated target marker, a shadow entry
        # carrying the same revocationRef, or the authenticated marker followed
        # by an identical copy.
        active = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-valid-active-nonmembership"
        )
        discovered = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-rb4-discovered-marker-precedes-nonmembership"
        )
        listing = active["input"]["listing"]
        target_entry = next(
            item for item in discovered["input"]["resolutionContext"]["resolvedMarkers"]
            if item.get("marker", {}).get("listingId") == listing.get("listingId")
            and item.get("marker", {}).get("listingContentHash") == listing.get("listingContentHash")
        )
        shadow = {"revocationRef": json.loads(json.dumps(target_entry["revocationRef"]))}
        mutations = [
            ("authenticated-plus-same-ref-shadow", [target_entry, shadow]),
            ("duplicated-valid-entry", [target_entry, target_entry]),
            ("shadow-then-authenticated", [shadow, target_entry]),
        ]
        for name, entries in mutations:
            with self.subTest(mutation=name):
                injected = json.loads(json.dumps(active["input"]))
                injected["resolutionContext"]["resolvedMarkers"].extend(
                    json.loads(json.dumps(entries))
                )
                verdict, want = evaluate(
                    injected, self.document["publicKeys"],
                    active.get("trustedProfileAdmission"),
                )
                self.assertEqual(verdict, "indeterminate")
                self.assertNotEqual(want["revocationCheck"], "absent")
                self.assertEqual(want["session"], "refuse")

    def test_absent_state_proof_is_closed_disposition_dependent_shape(self):
        # RSC-6/RSC-9: an `absent` RevocationStateProof carries exactly the base
        # member set and no `revocationRef`. The authorizing absent branch fails
        # closed on any extra key, injected/downgraded member, non-string scalar,
        # or list-valued proof — never `absent`.
        positive = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-valid-active-nonmembership"
        )
        proof = positive["input"]["resolutionContext"]["stateProof"]
        self.assertEqual(
            set(proof),
            {"revocationStateProofVersion", "headContentHash", "leafKey", "disposition", "proof"},
        )
        ref = {"anchor": {"kind": "storage-program", "locator": "storage-program:marker-x"},
               "contentHash": "00" * 32, "signer": "did:example:seller"}
        mutations = [
            ("extra-key", lambda p: p.__setitem__("extraMember", "x")),
            ("revocationRef-injected", lambda p: p.__setitem__("revocationRef", dict(ref))),
            ("revocationRef-null", lambda p: p.__setitem__("revocationRef", None)),
            ("disposition-mutated", lambda p: p.__setitem__("disposition", "unclear")),
            ("disposition-list", lambda p: p.__setitem__("disposition", ["absent"])),
            ("proof-list", lambda p: p.__setitem__("proof", [])),
            ("proof-omitted", lambda p: p.pop("proof")),
            ("proof-empty-object", lambda p: p.__setitem__("proof", {})),
            ("leafKey-list", lambda p: p.__setitem__("leafKey", [])),
            ("headContentHash-list", lambda p: p.__setitem__("headContentHash", [])),
            ("version-omitted", lambda p: p.pop("revocationStateProofVersion")),
            ("version-mutated", lambda p: p.__setitem__("revocationStateProofVersion", "2")),
            ("headContentHash-omitted", lambda p: p.pop("headContentHash")),
            ("leafKey-omitted", lambda p: p.pop("leafKey")),
        ]
        for name, mutate in mutations:
            with self.subTest(mutation=name):
                tampered = json.loads(json.dumps(positive["input"]))
                mutate(tampered["resolutionContext"]["stateProof"])
                verdict, want = evaluate(
                    tampered, self.document["publicKeys"],
                    positive.get("trustedProfileAdmission"),
                )
                self.assertEqual(verdict, "indeterminate")
                self.assertNotEqual(want["revocationCheck"], "absent")
                self.assertEqual(want["session"], "refuse")

    def test_revoked_state_proof_is_closed_disposition_dependent_shape(self):
        # RSC-6/RSC-9: a `revoked` RevocationStateProof carries exactly one
        # closed-shape `revocationRef`. Mutating or removing it — including a
        # downgrade to `absent` — must be indeterminate, never `revoked` and
        # never `absent`. The censored-tombstone vector exercises the RSC
        # inclusion path (discovery active), not the discovery-revoked early
        # return.
        censored = next(
            item for item in self.document["vectors"]
            if item["name"] == "rsc-censored-tombstone"
        )
        self.assertEqual(censored["input"]["discovery"]["status"], "active")
        proof = censored["input"]["resolutionContext"]["stateProof"]
        self.assertEqual(
            set(proof),
            {"revocationStateProofVersion", "headContentHash", "leafKey",
             "disposition", "revocationRef", "proof"},
        )
        invalid_kind = json.loads(json.dumps(proof))
        invalid_kind["revocationRef"]["anchor"]["kind"] = "not-a-registered-anchor-kind"
        self.assertFalse(validate_state_proof_shape(
            invalid_kind, proof["leafKey"], proof["headContentHash"]
        ))
        mutations = [
            ("extra-key", lambda p: p.__setitem__("extraMember", "x")),
            ("revocationRef-omitted", lambda p: p.pop("revocationRef")),
            ("revocationRef-null", lambda p: p.__setitem__("revocationRef", None)),
            ("revocationRef-string", lambda p: p.__setitem__("revocationRef", "ref")),
            ("revocationRef-extra-key", lambda p: p["revocationRef"].__setitem__("extra", True)),
            ("revocationRef-anchor-list", lambda p: p["revocationRef"].__setitem__("anchor", ["a"])),
            ("revocationRef-anchor-no-locator",
             lambda p: p["revocationRef"].__setitem__("anchor", {"kind": "storage-program"})),
            ("revocationRef-contentHash-list",
             lambda p: p["revocationRef"].__setitem__("contentHash", [])),
            ("revocationRef-signer-list",
             lambda p: p["revocationRef"].__setitem__("signer", [])),
            ("disposition-downgraded-to-absent",
             lambda p: (p.pop("revocationRef"), p.__setitem__("disposition", "absent"))),
            ("disposition-mutated", lambda p: p.__setitem__("disposition", "unclear")),
            ("proof-list", lambda p: p.__setitem__("proof", [])),
        ]
        for name, mutate in mutations:
            with self.subTest(mutation=name):
                tampered = json.loads(json.dumps(censored["input"]))
                mutate(tampered["resolutionContext"]["stateProof"])
                verdict, want = evaluate(
                    tampered, self.document["publicKeys"],
                    censored.get("trustedProfileAdmission"),
                )
                self.assertEqual(verdict, "indeterminate")
                self.assertNotIn(want["revocationCheck"], ("revoked", "absent"))
                self.assertEqual(want["session"], "refuse")

    def test_rsc7_precedence_survives_absent_branch_hardening(self):
        # RSC-7 precedence is unchanged by the closed-context hardening: a
        # discovered marker still outranks a non-membership proof, an RB-5
        # indeterminate discovery still blocks absence, a strictly-higher
        # authenticated revoking head still supersedes a stale absent read, and
        # legitimate active/genesis absence — including the consumed other-target
        # transition marker on the active vector — still admits a session.
        cases = {
            "rsc-valid-active-nonmembership": ("pass", "absent"),
            "rsc-valid-genesis-absent": ("pass", "absent"),
            "rsc-rb4-discovered-marker-precedes-nonmembership": ("fail", "revoked"),
            "rsc-rb5-indeterminate-precedes-nonmembership": ("indeterminate", "indeterminate"),
            "rsc-higher-known-head-revokes": ("fail", "revoked"),
            "rsc-censored-tombstone": ("fail", "revoked"),
            "rsc-two-equivocated-heads": ("indeterminate", "indeterminate"),
        }
        for name, (verdict, check) in cases.items():
            with self.subTest(vector=name):
                vector = next(
                    item for item in self.document["vectors"]
                    if item["name"] == name
                )
                result = evaluate(
                    vector["input"], self.document["publicKeys"],
                    vector.get("trustedProfileAdmission"),
                )
                self.assertEqual(result[0], verdict)
                self.assertEqual(result[1]["revocationCheck"], check)

    def test_recorded_policy_replay_remains_byte_faithful_after_hardening(self):
        # RSC-9 replay: the frozen v0.8 corpus is replayed byte-for-byte through
        # the explicitly recorded v1 policy oracle, which shares the hardened
        # evaluator. Every recorded verdict must reproduce exactly; a historical
        # v1 pass is never promoted to current admission.
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                expected, want = evaluate_recorded_policy(
                    vector["input"], self.document["publicKeys"],
                    vector.get("trustedProfileAdmission"),
                )
                self.assertEqual((expected, want), (vector["expected"], vector["want"]))


if __name__ == "__main__":
    unittest.main()
