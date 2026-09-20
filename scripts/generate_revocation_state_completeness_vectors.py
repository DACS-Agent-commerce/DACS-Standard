#!/usr/bin/env python3
"""Generate DACS-1 v0.8 revocation-state completeness vectors."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "vectors" / "security"
    / "revocation-state-completeness-v0.8.json"
)
SET_NAME = "revocation-state-completeness-v0.8"
SPEC = "DACS-1 v0.8 §6.3.4 RSC-1..RSC-10 authoritative revocation completeness"
HEAD_DOMAIN = "dacs-revocation-state-head:v1:"
MARKER_DOMAIN = "dacs-revocation:v1:"
LISTING_DOMAIN = "dacs-listing:v1:"
CURRENT_STATE_DOMAIN = "dacs-rsc-conformance-current-state:v1:"
CURRENT_STATE_POLICY = "rsc-conformance-test-current-value-v1"
RECEIPT_SUBSTRATE = "conformance:test"
RECEIPT_FINALITY_PROFILE = "rsc-conformance-test-finality-v1"
RECEIPT_WRITER = "demos1seller"
ZERO_HASH = "00" * 32


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def hash_hex(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def artifact_hash(value: dict) -> str:
    unsigned = {key: item for key, item in value.items() if key != "signature"}
    return hash_hex(unsigned)


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def private_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes_raw().hex()


def sign_artifact(unsigned: dict, key: Ed25519PrivateKey, signer: str, domain: str) -> dict:
    digest = hash_hex(unsigned)
    return {
        **copy.deepcopy(unsigned),
        "signature": {
            "algorithm": "ed25519",
            "signer": signer,
            "value": b64url(key.sign((domain + digest).encode("ascii"))),
        },
    }


def key_attestation_message(claim: str, key_hex: str, valid_at: str) -> dict:
    return {"claim": claim, "key": key_hex, "validAt": valid_at}


def key_attestation(claim: str, key_hex: str, valid_at: str) -> dict:
    message = key_attestation_message(claim, key_hex, valid_at)
    return {
        "kind": KEY_LIFECYCLE_KIND,
        "value": b64url(KEY_LIFECYCLE_AUTHORITY_KEY.sign(
            (KEY_LIFECYCLE_DOMAIN + hash_hex(message)).encode("ascii")
        )),
    }


def cf4(value: str) -> str:
    encoded = value
    for raw, escaped in (("%", "%25"), (":", "%3A"), ("?", "%3F"), ("&", "%26"), ("=", "%3D")):
        encoded = encoded.replace(raw, escaped)
    return encoded


SELLER_KEY = private_key("rsc-seller-initial")
ROTATED_KEY = private_key("rsc-seller-rotated")
OUTSIDER_KEY = private_key("rsc-outsider")
CURRENT_STATE_KEY = private_key("rsc-test-current-state-authority")
KEY_LIFECYCLE_AUTHORITY_KEY = private_key("rsc-test-key-lifecycle-authority")
KEY_LIFECYCLE_DOMAIN = "dacs-key-lifecycle:v1:"
KEY_LIFECYCLE_KIND = "dacs1-key-lifecycle-attestation"
SELLER = "did:example:seller"
LISTING_ID = "compute-hour"
LISTING_VERSION = 3
LISTING_HASH = "44" * 32
OTHER_LISTING_ID = "storage-hour"
OTHER_LISTING_HASH = "55" * 32
LOGICAL_ADDRESS = f"dacs1-revocations:{cf4(SELLER)}"
NATIVE_ADDRESS = "storage-program:revocation-line-a"
LISTING_LOGICAL_ADDRESS = f"dacs1-listings:{cf4(SELLER)}:{LISTING_ID}:v{LISTING_VERSION}"
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
SESSION_ID = "session-rsc-0001"


def profile_admission(
    *,
    participant_identity: str = SELLER,
    release_pin: str = AUTHORITATIVE_RELEASE_PIN,
    module_versions: dict | None = None,
    authenticated: bool = True,
    session_id: str = SESSION_ID,
) -> dict:
    return {
        "sessionId": session_id,
        "role": "seller",
        "participantIdentity": participant_identity,
        "authenticated": authenticated,
        "profile": {
            "releasePin": release_pin,
            "moduleVersions": (
                copy.deepcopy(AUTHORITATIVE_MODULE_VERSIONS)
                if module_versions is None else copy.deepcopy(module_versions)
            ),
        },
    }


def listing_tuple(listing_id: str = LISTING_ID, content_hash: str = LISTING_HASH) -> dict:
    return {
        "sellerPrimaryClaim": SELLER,
        "listingId": listing_id,
        "listingVersion": LISTING_VERSION,
        "listingContentHash": content_hash,
    }


def leaf_key(value: dict) -> str:
    return hash_hex(value)


def empty_hashes() -> list[bytes]:
    values = [hashlib.sha256(b"\x00").digest()]
    for _ in range(256):
        values.append(hashlib.sha256(b"\x01" + values[-1] + values[-1]).digest())
    return values


EMPTY = empty_hashes()


def revoked_leaf(key: str, revocation_ref: dict) -> bytes:
    ref_hash = hashlib.sha256(canonical_bytes(revocation_ref)).digest()
    return hashlib.sha256(b"\x02" + bytes.fromhex(key) + ref_hash).digest()


def tree_levels(leaves: dict[str, dict]) -> list[dict[int, bytes]]:
    levels: list[dict[int, bytes]] = [
        {int(key, 16): revoked_leaf(key, ref) for key, ref in leaves.items()}
    ]
    for height in range(256):
        current = levels[-1]
        parents: dict[int, bytes] = {}
        for parent in {index >> 1 for index in current}:
            left = current.get(parent << 1, EMPTY[height])
            right = current.get((parent << 1) | 1, EMPTY[height])
            combined = hashlib.sha256(b"\x01" + left + right).digest()
            if combined != EMPTY[height + 1]:
                parents[parent] = combined
        levels.append(parents)
    return levels


def root_hash(leaves: dict[str, dict]) -> str:
    return tree_levels(leaves)[256].get(0, EMPTY[256]).hex()


def compact_proof(leaves: dict[str, dict], key: str) -> dict:
    levels = tree_levels(leaves)
    index = int(key, 16)
    siblings = []
    for height in range(256):
        sibling = levels[height].get((index >> height) ^ 1, EMPTY[height])
        if sibling != EMPTY[height]:
            siblings.append({"height": height, "hash": sibling.hex()})
    return {"siblings": siblings}


def state_proof(head: dict, leaves: dict[str, dict], target: dict) -> dict:
    key = leaf_key(target)
    revocation_ref = leaves.get(key)
    result = {
        "revocationStateProofVersion": "1",
        "headContentHash": artifact_hash(head),
        "leafKey": key,
        "disposition": "revoked" if revocation_ref else "absent",
        "proof": compact_proof(leaves, key),
    }
    if revocation_ref:
        result["revocationRef"] = copy.deepcopy(revocation_ref)
    return result


def marker(target: dict, key: Ed25519PrivateKey = SELLER_KEY) -> dict:
    unsigned = {
        "listingId": target["listingId"],
        "listingVersion": target["listingVersion"],
        "listingContentHash": target["listingContentHash"],
        "revokedAt": 1_780_000_000_000,
        "reason": "withdrawn",
    }
    return sign_artifact(unsigned, key, SELLER, MARKER_DOMAIN)


def marker_ref(value: dict, suffix: str) -> dict:
    return {
        "anchor": {"kind": "storage-program", "locator": f"storage-program:marker-{suffix}"},
        "contentHash": artifact_hash(value),
        "signer": SELLER,
    }


def head_ref(value: dict) -> dict:
    return {
        "anchor": {"kind": "storage-program", "locator": NATIVE_ADDRESS},
        "contentHash": artifact_hash(value),
        "signer": SELLER,
    }


def make_genesis() -> dict:
    unsigned = {
        "revocationStateHeadVersion": "1",
        "sellerPrimaryClaim": SELLER,
        "logicalAddress": LOGICAL_ADDRESS,
        "sequence": "0",
        "previousHeadHash": ZERO_HASH,
        "rootHash": EMPTY[256].hex(),
        "entryCount": "0",
        "issuedAt": 1_779_000_000_000,
    }
    return sign_artifact(unsigned, SELLER_KEY, SELLER, HEAD_DOMAIN)


def append_head(previous: dict, prior_leaves: dict[str, dict], target: dict, ref: dict,
                key: Ed25519PrivateKey = SELLER_KEY) -> tuple[dict, dict[str, dict]]:
    item_key = leaf_key(target)
    leaves = copy.deepcopy(prior_leaves)
    leaves[item_key] = copy.deepcopy(ref)
    sequence = int(previous["sequence"]) + 1
    unsigned = {
        "revocationStateHeadVersion": "1",
        "sellerPrimaryClaim": SELLER,
        "logicalAddress": LOGICAL_ADDRESS,
        "sequence": str(sequence),
        "previousHeadHash": artifact_hash(previous),
        "rootHash": root_hash(leaves),
        "entryCount": str(sequence),
        "transition": {
            "leafKey": item_key,
            "revocationRef": copy.deepcopy(ref),
            "priorProof": compact_proof(prior_leaves, item_key),
        },
        "issuedAt": 1_780_000_000_000 + sequence,
    }
    return sign_artifact(unsigned, key, SELLER, HEAD_DOMAIN), leaves


def receipt_binding(value: dict, sequence: int) -> dict:
    return {
        "logicalAddress": LOGICAL_ADDRESS,
        "nativeAddress": NATIVE_ADDRESS,
        "contentHash": artifact_hash(value),
        "writer": RECEIPT_WRITER,
        "nonce": str(40 + sequence),
    }


def receipt(value: dict, sequence: int) -> dict:
    binding = receipt_binding(value, sequence)
    transaction_ref = {"kind": "demos-tx", "value": hash_hex(binding)}
    block_ref = {
        "height": str(100 + sequence),
        "timestamp": 1_780_000_000_000 + sequence,
        "orderedTransactions": [transaction_ref],
    }
    return {
        "receiptVersion": "1",
        "substrate": RECEIPT_SUBSTRATE,
        "finalityProfile": RECEIPT_FINALITY_PROFILE,
        "logicalAddress": LOGICAL_ADDRESS,
        "nativeAddress": NATIVE_ADDRESS,
        "contentHash": artifact_hash(value),
        "transactionRef": transaction_ref,
        "writer": RECEIPT_WRITER,
        "nonce": str(40 + sequence),
        "state": "finalized",
        "observationDisposition": "established",
        "observedAt": 1_780_000_100_000 + sequence,
        "blockRef": {
            "id": hash_hex(block_ref),
            "height": block_ref["height"],
            "timestamp": block_ref["timestamp"],
        },
        "evidence": {"kind": "rsc-conformance-test-finality", "value": f"proof-{sequence}"},
    }


def listing_receipt(listing_value: dict, finalized_state_id: str,
                    block_height: str, block_timestamp: int) -> dict:
    digest = artifact_hash(listing_value)
    binding = {
        "logicalAddress": LISTING_LOGICAL_ADDRESS,
        "nativeAddress": LISTING_NATIVE_ADDRESS,
        "contentHash": digest,
        "writer": RECEIPT_WRITER,
        "nonce": "10",
    }
    transaction_ref = {"kind": "demos-tx", "value": hash_hex(binding)}
    return {
        "receiptVersion": "1",
        "substrate": RECEIPT_SUBSTRATE,
        "finalityProfile": RECEIPT_FINALITY_PROFILE,
        "logicalAddress": LISTING_LOGICAL_ADDRESS,
        "nativeAddress": LISTING_NATIVE_ADDRESS,
        "contentHash": digest,
        "transactionRef": transaction_ref,
        "writer": RECEIPT_WRITER,
        "nonce": "10",
        "state": "finalized",
        "observationDisposition": "established",
        "observedAt": 1_780_000_100_000,
        "blockRef": {
            "id": finalized_state_id,
            "height": block_height,
            "timestamp": block_timestamp,
        },
        "evidence": {"kind": "rsc-conformance-test-finality", "value": "listing-proof"},
    }


def current_state_message(
    head_ref_value: dict,
    head_receipt: dict,
    finalized_state_id: str,
    listing_content_hash: str,
    listing_receipt_value: dict,
    conflicting_heads: list[dict],
) -> bytes:
    payload = {
        "policy": CURRENT_STATE_POLICY,
        "finalizedStateId": finalized_state_id,
        "logicalAddress": LOGICAL_ADDRESS,
        "nativeAddress": NATIVE_ADDRESS,
        "headContentHash": head_ref_value["contentHash"],
        "headReceiptHash": hash_hex(head_receipt),
        "listingContentHash": listing_content_hash,
        "listingReceiptHash": hash_hex(listing_receipt_value),
        "conflictingHeadsHash": hash_hex(conflicting_heads),
    }
    return (CURRENT_STATE_DOMAIN + hash_hex(payload)).encode("ascii")


def marker_receipt(ref: dict, suffix: str) -> dict:
    return {
        "receiptVersion": "1",
        "substrate": "demos:testnet",
        "finalityProfile": "demos-bft-final",
        "logicalAddress": f"dacs1-revoked:{cf4(SELLER)}:{suffix}:v{LISTING_VERSION}",
        "nativeAddress": ref["anchor"]["locator"],
        "contentHash": ref["contentHash"],
        "transactionRef": {"kind": "demos-tx", "value": f"tx-marker-{suffix}"},
        "writer": "demos1seller",
        "nonce": "30",
        "state": "finalized",
        "observationDisposition": "established",
        "observedAt": 1_780_000_050_000,
        "blockRef": {"id": "block-90", "height": "90", "timestamp": 1_780_000_000_000},
        "evidence": {"kind": "demos-finality-proof", "value": f"marker-proof-{suffix}"},
    }


GENESIS = make_genesis()
TARGET = listing_tuple()
OTHER = listing_tuple(OTHER_LISTING_ID, OTHER_LISTING_HASH)
TARGET_MARKER = marker(TARGET)
OTHER_MARKER = marker(OTHER)
TARGET_REF = marker_ref(TARGET_MARKER, "target")
OTHER_REF = marker_ref(OTHER_MARKER, "other")
TARGET_HEAD, TARGET_LEAVES = append_head(GENESIS, {}, TARGET, TARGET_REF)
OTHER_HEAD, OTHER_LEAVES = append_head(GENESIS, {}, OTHER, OTHER_REF)


def listing_unsigned(checkpoint: dict = GENESIS) -> dict:
    return {
        "dacsVersion": "1",
        **listing_tuple(),
        "revocationState": {
            "revocationStateRefVersion": "1",
            "logicalAddress": LOGICAL_ADDRESS,
            "anchor": {"kind": "storage-program", "locator": NATIVE_ADDRESS},
            "checkpointSequence": checkpoint["sequence"],
            "checkpointHeadHash": artifact_hash(checkpoint),
        },
    }


def listing(checkpoint: dict = GENESIS) -> dict:
    return sign_artifact(listing_unsigned(checkpoint), SELLER_KEY, SELLER, LISTING_DOMAIN)


def history_item(value: dict, key: Ed25519PrivateKey = SELLER_KEY,
                 authority_valid: bool = True) -> dict:
    receipt_value = receipt(value, int(value["sequence"]))
    valid_at = receipt_value["blockRef"]["id"]
    evidence = (
        key_attestation(SELLER, public_hex(key), valid_at)
        if authority_valid
        else {"kind": KEY_LIFECYCLE_KIND, "value": "invalid"}
    )
    return {
        "head": copy.deepcopy(value),
        "receipt": receipt_value,
        "authority": {
            "claim": SELLER,
            "key": public_hex(key),
            "disposition": "verified" if authority_valid else "indeterminate",
            "evidence": evidence,
        },
    }


def resign_head(value: dict, key: Ed25519PrivateKey = SELLER_KEY) -> dict:
    unsigned = {k: v for k, v in value.items() if k != "signature"}
    return sign_artifact(unsigned, key, SELLER, HEAD_DOMAIN)


def resign_listing(value: dict, key: Ed25519PrivateKey = SELLER_KEY) -> dict:
    unsigned = {k: v for k, v in value.items() if k != "signature"}
    return sign_artifact(unsigned, key, SELLER, LISTING_DOMAIN)


def malformed_anchor_listing(anchor: object) -> dict:
    value = listing_unsigned()
    value["revocationState"]["anchor"] = anchor
    return sign_artifact(value, SELLER_KEY, SELLER, LISTING_DOMAIN)


def resolved_marker(ref: dict, value: dict, key: Ed25519PrivateKey, listing_id: str) -> dict:
    marker_receipt_value = marker_receipt(ref, listing_id)
    valid_at = marker_receipt_value["blockRef"]["id"]
    return {
        "revocationRef": copy.deepcopy(ref),
        "marker": copy.deepcopy(value),
        "receipt": marker_receipt_value,
        "authority": {
            "claim": SELLER,
            "key": public_hex(key),
            "disposition": "verified",
            "evidence": key_attestation(SELLER, public_hex(key), valid_at),
        },
    }


def context(current: dict, leaves: dict[str, dict], *, target: dict = TARGET,
            history: list[dict] | None = None, listing_value: dict,
            conflicting_heads: list[dict] | None = None) -> dict:
    current_ref = head_ref(current)
    current_receipt = receipt(current, int(current["sequence"]))
    finalized_state_id = current_receipt["blockRef"]["id"]
    if history is None:
        history = [history_item(GENESIS)]
        if current["sequence"] != "0":
            history.append(history_item(current))
    required_hashes = {
        item["head"].get("transition", {}).get("revocationRef", {}).get("contentHash")
        for item in history
    }
    proof = state_proof(current, leaves, target)
    required_hashes.add(proof.get("revocationRef", {}).get("contentHash"))
    resolved = []
    if TARGET_REF["contentHash"] in required_hashes:
        resolved.append(resolved_marker(TARGET_REF, TARGET_MARKER, SELLER_KEY, LISTING_ID))
    if OTHER_REF["contentHash"] in required_hashes:
        resolved.append(resolved_marker(OTHER_REF, OTHER_MARKER, SELLER_KEY, OTHER_LISTING_ID))
    listing_content_hash = artifact_hash(listing_value)
    listing_receipt_value = listing_receipt(
        listing_value,
        finalized_state_id,
        current_receipt["blockRef"]["height"],
        current_receipt["blockRef"]["timestamp"],
    )
    conflicting = [] if conflicting_heads is None else copy.deepcopy(conflicting_heads)
    return {
        "headRef": current_ref,
        "headReceipt": current_receipt,
        "headReceiptHistory": [item["receipt"] for item in history],
        "listingReceipt": listing_receipt_value,
        "currentStateEvidence": {
            "policy": CURRENT_STATE_POLICY,
            "finalizedStateId": finalized_state_id,
            "valueContentHash": current_ref["contentHash"],
            "listingContentHash": listing_content_hash,
            "listingReceiptHash": hash_hex(listing_receipt_value),
            "conflictingHeadsHash": hash_hex(conflicting),
            "evidence": {
                "kind": "ed25519-signature",
                "value": b64url(CURRENT_STATE_KEY.sign(
                    current_state_message(
                        current_ref, current_receipt, finalized_state_id,
                        listing_content_hash, listing_receipt_value, conflicting,
                    )
                )),
            },
        },
        "headHistory": copy.deepcopy(history),
        "stateProof": proof,
        "resolvedMarkers": resolved,
        "knownConflictingHeads": copy.deepcopy(conflicting),
    }


def changed(value: dict, mutation) -> dict:
    result = copy.deepcopy(value)
    mutation(result)
    return result


def input_for(current: dict, leaves: dict[str, dict], *, target: dict = TARGET,
              checkpoint: dict = GENESIS, discovery_status: str = "active",
              history: list[dict] | None = None, listing_value: dict | None = None,
              conflicting_heads: list[dict] | None = None) -> dict:
    discovery = {"status": discovery_status, "integrityConsistent": True}
    if discovery_status == "revoked":
        discovery["revocationRef"] = copy.deepcopy(TARGET_REF)
    resolved_listing = listing(checkpoint) if listing_value is None else listing_value
    return {
        "sessionId": SESSION_ID,
        "listing": resolved_listing,
        "discovery": discovery,
        "resolutionContext": context(
            current, leaves, target=target, history=history,
            listing_value=resolved_listing, conflicting_heads=conflicting_heads,
        ),
    }


def want(disposition: str) -> dict:
    return {
        "revocationCheck": disposition,
        "session": "continue" if disposition == "absent" else "refuse",
    }


_DEFAULT_ADMISSION = object()


def vector(name: str, expected: str, note: str, data: dict, disposition: str,
           trusted_admission: object = _DEFAULT_ADMISSION) -> dict:
    result = {"name": name, "expected": expected, "note": note, "input": data, "want": want(disposition)}
    if trusted_admission is _DEFAULT_ADMISSION:
        result["trustedProfileAdmission"] = profile_admission()
    elif trusted_admission is not None:
        result["trustedProfileAdmission"] = trusted_admission
    return result


def build_vectors() -> list[dict]:
    active = input_for(OTHER_HEAD, OTHER_LEAVES)
    revoked = input_for(TARGET_HEAD, TARGET_LEAVES, discovery_status="revoked")
    censored = input_for(TARGET_HEAD, TARGET_LEAVES, discovery_status="active")

    genesis_absent = input_for(GENESIS, {})

    stale = input_for(GENESIS, {})
    stale["resolutionContext"]["currentStateEvidence"]["valueContentHash"] = artifact_hash(TARGET_HEAD)

    fork = input_for(TARGET_HEAD, TARGET_LEAVES, conflicting_heads=[history_item(OTHER_HEAD)])
    fork["resolutionContext"]["resolvedMarkers"].append(
        resolved_marker(OTHER_REF, OTHER_MARKER, SELLER_KEY, OTHER_LISTING_ID)
    )

    bad_nonmembership = changed(active, lambda x: x["resolutionContext"]["stateProof"]["proof"]["siblings"].append({"height": 0, "hash": "aa" * 32}))
    missing_latest = changed(active, lambda x: x["resolutionContext"]["currentStateEvidence"].update({"evidence": {"kind": "ed25519-signature", "value": "invalid"}}))
    wrong_tuple = changed(active, lambda x: x["resolutionContext"].update({"stateProof": state_proof(OTHER_HEAD, OTHER_LEAVES, OTHER)}))

    unresolved_marker = changed(revoked, lambda x: x["resolutionContext"].update({"resolvedMarkers": [item for item in x["resolutionContext"]["resolvedMarkers"] if item["revocationRef"]["contentHash"] != TARGET_REF["contentHash"]]}))

    rollback = input_for(GENESIS, {}, checkpoint=TARGET_HEAD)

    unauthorized_head, unauthorized_leaves = append_head(GENESIS, {}, TARGET, TARGET_REF, OUTSIDER_KEY)
    unauthorized_history = [history_item(GENESIS), history_item(unauthorized_head, OUTSIDER_KEY, False)]
    unauthorized = input_for(unauthorized_head, unauthorized_leaves, history=unauthorized_history)

    rotated_marker = marker(TARGET, ROTATED_KEY)
    rotated_ref = marker_ref(rotated_marker, "rotated")
    rotated_head, rotated_leaves = append_head(GENESIS, {}, TARGET, rotated_ref, ROTATED_KEY)
    rotated_history = [history_item(GENESIS), history_item(rotated_head, ROTATED_KEY, True)]
    rotated = input_for(rotated_head, rotated_leaves, discovery_status="active", history=rotated_history)
    rotated["resolutionContext"]["resolvedMarkers"].append(
        resolved_marker(rotated_ref, rotated_marker, ROTATED_KEY, LISTING_ID)
    )

    rotated_corrupted = copy.deepcopy(rotated)
    for item in rotated_corrupted["resolutionContext"]["resolvedMarkers"]:
        if item["revocationRef"]["contentHash"] == rotated_ref["contentHash"]:
            item["marker"]["signature"]["value"] = "A" + item["marker"]["signature"]["value"][1:]

    wrong_key = input_for(TARGET_HEAD, TARGET_LEAVES, discovery_status="revoked")
    wrong_key_marker = marker(TARGET, OUTSIDER_KEY)
    for item in wrong_key["resolutionContext"]["resolvedMarkers"]:
        if item["revocationRef"]["contentHash"] == TARGET_REF["contentHash"]:
            item["marker"] = wrong_key_marker

    wrong_algorithm = input_for(TARGET_HEAD, TARGET_LEAVES, discovery_status="revoked")
    for item in wrong_algorithm["resolutionContext"]["resolvedMarkers"]:
        if item["revocationRef"]["contentHash"] == TARGET_REF["contentHash"]:
            item["marker"]["signature"]["algorithm"] = "ecdsa-secp256k1"

    higher_head, higher_leaves = append_head(OTHER_HEAD, OTHER_LEAVES, TARGET, TARGET_REF)
    higher = input_for(OTHER_HEAD, OTHER_LEAVES, conflicting_heads=[history_item(higher_head)])
    higher["resolutionContext"]["resolvedMarkers"].append(
        resolved_marker(TARGET_REF, TARGET_MARKER, SELLER_KEY, LISTING_ID)
    )

    historical_listing = sign_artifact(
        {key: value for key, value in listing_unsigned().items() if key != "revocationState"},
        SELLER_KEY, SELLER, LISTING_DOMAIN,
    )
    no_state_ref = input_for(OTHER_HEAD, OTHER_LEAVES, listing_value=historical_listing)
    history_gap = changed(active, lambda x: x["resolutionContext"].update({"headHistory": [x["resolutionContext"]["headHistory"][-1]]}))
    producer_time_only = copy.deepcopy(active)
    producer_time_only["producerSaysLatestAt"] = 9_999_999_999_999
    producer_time_only["resolutionContext"]["currentStateEvidence"]["policy"] = "producer-time-only"

    discovered_marker = copy.deepcopy(active)
    discovered_marker["discovery"] = {
        "status": "revoked",
        "integrityConsistent": True,
        "revocationRef": copy.deepcopy(TARGET_REF),
    }
    discovered_marker["resolutionContext"]["resolvedMarkers"].append(
        resolved_marker(TARGET_REF, TARGET_MARKER, SELLER_KEY, LISTING_ID)
    )

    rb5_indeterminate = copy.deepcopy(active)
    rb5_indeterminate["discovery"] = {
        "status": "revoked",
        "integrityConsistent": True,
        "revocationRef": changed(TARGET_REF, lambda x: x["anchor"].update({"locator": "storage-program:unreachable"})),
    }

    # A2: a caller-supplied profile object or opaque label has no authority, even
    # when it copies locally meaningful bytes.
    caller_copy = copy.deepcopy(active)
    caller_copy["currentProfile"] = True
    caller_copy["profile"] = {
        "releasePin": AUTHORITATIVE_RELEASE_PIN,
        "moduleVersions": copy.deepcopy(AUTHORITATIVE_MODULE_VERSIONS),
    }

    # A2 negatives: verifier-owned profile admission must be exact and identity-bound.
    release_mismatch = profile_admission(release_pin="f" * 40)
    module_mismatch = profile_admission(
        module_versions={**AUTHORITATIVE_MODULE_VERSIONS, "dacs5": "0.4"}
    )
    partial_module = profile_admission(
        module_versions={k: v for k, v in AUTHORITATIVE_MODULE_VERSIONS.items() if k != "dacs5"}
    )
    session_mismatch = profile_admission(session_id="session-other")
    identity_mismatch = profile_admission(participant_identity="did:example:outsider")
    unauthenticated = profile_admission(authenticated=False)

    # A1: the complete conflict-observation set is signed into the current-state
    # evidence; omitting or substituting it is indeterminate, never absent.
    conflict_omitted = copy.deepcopy(higher)
    conflict_omitted["resolutionContext"].pop("knownConflictingHeads")
    conflict_tampered = copy.deepcopy(higher)
    conflict_tampered["resolutionContext"]["knownConflictingHeads"] = []

    # C10: the listing and the revocation head must be evaluated in one
    # authenticated finalized state via a finalized listing receipt.
    listing_receipt_missing = changed(active, lambda x: x["resolutionContext"].pop("listingReceipt"))
    listing_receipt_stale = changed(active, lambda x: x["resolutionContext"]["listingReceipt"]["blockRef"].update({"id": "block-stale", "height": "1"}))
    listing_receipt_tampered = changed(active, lambda x: x["resolutionContext"]["listingReceipt"].update({"contentHash": "00" * 32}))

    # A1 completion: authenticated conflict-set evolution stays fail-closed. A
    # later authenticated head that rewrites the target via a cross-tuple
    # transition substitution, or that removes the appended leaf via a root
    # mutation, is indeterminate, never revoked and never absent.
    rewrite_head = copy.deepcopy(higher_head)
    rewrite_head["transition"]["revocationRef"] = copy.deepcopy(OTHER_REF)
    rewrite_head = resign_head(rewrite_head)
    conflict_later_rewrite = input_for(
        OTHER_HEAD, OTHER_LEAVES, conflicting_heads=[history_item(rewrite_head)]
    )
    removal_head = copy.deepcopy(higher_head)
    removal_head["rootHash"] = OTHER_HEAD["rootHash"]
    removal_head = resign_head(removal_head)
    conflict_removal_transition = input_for(
        OTHER_HEAD, OTHER_LEAVES, conflicting_heads=[history_item(removal_head)]
    )
    conflict_removal_transition["resolutionContext"]["resolvedMarkers"].append(
        resolved_marker(TARGET_REF, TARGET_MARKER, SELLER_KEY, LISTING_ID)
    )

    # RSC totality: malformed nested proof containers must be non-authorizing
    # indeterminate, never an AttributeError from dereferencing a non-object.
    head_blockref_list = changed(active, lambda x: x["resolutionContext"]["headReceipt"].__setitem__("blockRef", ["block-0"]))
    head_blockref_string = changed(active, lambda x: x["resolutionContext"]["headReceipt"].__setitem__("blockRef", "block-0"))
    listing_blockref_list = changed(active, lambda x: x["resolutionContext"]["listingReceipt"].__setitem__("blockRef", ["block-0"]))
    listing_blockref_string = changed(active, lambda x: x["resolutionContext"]["listingReceipt"].__setitem__("blockRef", "block-0"))
    head_authority_list = changed(active, lambda x: x["resolutionContext"]["headHistory"][0].__setitem__("authority", []))
    head_authority_string = changed(active, lambda x: x["resolutionContext"]["headHistory"][0].__setitem__("authority", "seller"))

    # RSC totality completion: independently re-signed Listings whose
    # revocationState.anchor is a list, a string, or an object missing its locator;
    # a list/None authority key; list-valued Listing/head/marker signature values;
    # and a non-object root must all fail closed as non-authorizing indeterminate,
    # never raise a dereference, fromhex, or concat TypeError/KeyError.
    anchor_list = input_for(OTHER_HEAD, OTHER_LEAVES,
                            listing_value=malformed_anchor_listing(["storage-program:revocation-line-a"]))
    anchor_string = input_for(OTHER_HEAD, OTHER_LEAVES,
                              listing_value=malformed_anchor_listing("storage-program:revocation-line-a"))
    anchor_missing_locator = input_for(OTHER_HEAD, OTHER_LEAVES,
                                       listing_value=malformed_anchor_listing({"kind": "storage-program"}))

    head_authority_key_list = changed(active, lambda x: x["resolutionContext"]["headHistory"][0]["authority"].__setitem__("key", ["aa"] * 32))
    head_authority_key_none = changed(active, lambda x: x["resolutionContext"]["headHistory"][0]["authority"].__setitem__("key", None))

    listing_sig_value_list = changed(active, lambda x: x["listing"]["signature"].__setitem__("value", ["bad"]))
    head_sig_value_list = changed(active, lambda x: x["resolutionContext"]["headHistory"][0]["head"]["signature"].__setitem__("value", ["bad"]))
    marker_sig_value_list = changed(revoked, lambda x: x["resolutionContext"]["resolvedMarkers"][0]["marker"]["signature"].__setitem__("value", ["bad"]))

    non_object_root_list = []
    non_object_root_string = "not-an-object"

    # RSC-2 authority evidence must be load-bearing: the key-lifecycle authority
    # attestation binding (claim, key, validAt) is verified against the head's
    # (or marker's) finalized inclusion state. Omission, wrong containers,
    # attacker substitution, and nested malformation all fail closed.
    authority_evidence_variants = (
        ("missing", None),
        ("list", ["bad"]),
        ("string", "bad"),
        ("null", None),
        ("wrong-kind", {"kind": "test-key-history", "value": "valid"}),
        ("missing-value", {"kind": KEY_LIFECYCLE_KIND}),
        ("extra-key", {"kind": KEY_LIFECYCLE_KIND, "value": "AAAA", "extra": True}),
        ("value-list", {"kind": KEY_LIFECYCLE_KIND, "value": ["bad"]}),
        ("value-invalid", {"kind": KEY_LIFECYCLE_KIND, "value": "AAAA"}),
        ("wrong-claim", "claim"),
        ("wrong-key", "key"),
        ("wrong-validAt", "validAt"),
    )

    def authority_evidence_mutated(base: dict, path: list, variant: str, value: object) -> dict:
        data = copy.deepcopy(base)
        authority = data
        for segment in path:
            authority = authority[segment]
        if variant == "missing":
            authority.pop("evidence", None)
        elif variant == "null" and value is None:
            authority["evidence"] = None
        elif variant in {"wrong-claim", "wrong-key", "wrong-validAt"}:
            claim = "did:example:outsider" if variant == "wrong-claim" else SELLER
            key = OUTSIDER_KEY if variant == "wrong-key" else SELLER_KEY
            valid_at = (
                "block-other" if variant == "wrong-validAt"
                else (
                    data["resolutionContext"]["headHistory"][path[2]]["receipt"]["blockRef"]["id"]
                    if "headHistory" in path
                    else data["resolutionContext"]["resolvedMarkers"][path[2]]["receipt"]["blockRef"]["id"]
                )
            )
            authority["evidence"] = key_attestation(claim, public_hex(key), valid_at)
        else:
            authority["evidence"] = copy.deepcopy(value)
        return data

    authority_evidence_vectors = []
    for position in range(len(active["resolutionContext"]["headHistory"])):
        for variant, value in authority_evidence_variants:
            data = authority_evidence_mutated(
                active,
                ["resolutionContext", "headHistory", position, "authority"],
                variant, value,
            )
            authority_evidence_vectors.append(vector(
                f"rsc-head-authority-evidence-{variant}-pos{position}",
                "indeterminate",
                "head authority evidence that is missing, wrongly containerized, "
                "attacker-substituted, or nested-malformed cannot authorize the head",
                data, "indeterminate",
            ))
    for marker_base, marker_label in ((active, "active"), (revoked, "revoked")):
        markers = marker_base["resolutionContext"].get("resolvedMarkers", [])
        for position in range(len(markers)):
            for variant, value in authority_evidence_variants:
                data = authority_evidence_mutated(
                    marker_base,
                    ["resolutionContext", "resolvedMarkers", position, "authority"],
                    variant, value,
                )
                authority_evidence_vectors.append(vector(
                    f"rsc-marker-authority-evidence-{variant}-{marker_label}-pos{position}",
                    "indeterminate",
                    "marker authority evidence that is missing, wrongly containerized, "
                    "attacker-substituted, or nested-malformed cannot authenticate the marker",
                    data, "indeterminate",
                ))

    return [
        vector("rsc-valid-active-nonmembership", "pass", "an exact empty-leaf proof against the authenticated current head admits a new session", active, "absent"),
        vector("rsc-valid-genesis-absent", "pass", "a transition-free genesis head with an explicit empty marker set and an exact empty-leaf proof admits a new session", genesis_absent, "absent"),
        vector("rsc-valid-revocation-inclusion", "fail", "an exact inclusion proof and marker refuse the revoked listing", revoked, "revoked"),
        vector("rsc-censored-tombstone", "fail", "an active discovery row cannot hide a revocation committed by the current head", censored, "revoked"),
        vector("rsc-stale-signed-head", "indeterminate", "a valid old signed head is not the current finalized native value", stale, "indeterminate"),
        vector("rsc-two-equivocated-heads", "indeterminate", "two valid children of one head at one sequence block selection", fork, "indeterminate"),
        vector("rsc-invalid-nonmembership", "indeterminate", "a sibling mutation cannot establish the signed root", bad_nonmembership, "indeterminate"),
        vector("rsc-latest-proof-unavailable", "indeterminate", "a finalized head without authenticated latest-state evidence is incomplete", missing_latest, "indeterminate"),
        vector("rsc-cross-tuple-proof-replay", "indeterminate", "another listing tuple's proof cannot establish this listing", wrong_tuple, "indeterminate"),
        vector("rsc-revocation-marker-unresolved", "indeterminate", "a committed leaf without an independently resolvable marker fails closed", unresolved_marker, "indeterminate"),
        vector("rsc-rollback-below-listing-checkpoint", "indeterminate", "the current view cannot move behind the checkpoint signed into the listing", rollback, "indeterminate"),
        vector("rsc-unauthorized-rotation-key", "indeterminate", "a cryptographically valid head from an unauthorized key has no seller authority", unauthorized, "indeterminate"),
        vector("rsc-authorized-rotation-key", "fail", "an authenticated rotated seller key may append an exact revocation through the RSC inclusion path", rotated, "revoked"),
        vector("rsc-rotated-key-corrupted-signature", "indeterminate", "a rotated marker whose signature does not verify fails closed", rotated_corrupted, "indeterminate"),
        vector("rsc-wrong-signer-key", "indeterminate", "a marker signed by a key other than the authenticated authority key fails closed", wrong_key, "indeterminate"),
        vector("rsc-wrong-signature-algorithm", "indeterminate", "a marker declaring an unsupported algorithm is unverifiable", wrong_algorithm, "indeterminate"),
        vector("rsc-higher-known-head-revokes", "fail", "an authenticated later head that revokes the target supersedes a stale absent read", higher, "revoked"),
        vector("rsc-downgrade-without-profile-admission", "indeterminate", "a current-profile Listing without the authenticated corrective-profile admission cannot start a new session", active, "indeterminate", trusted_admission=None),
        vector("rsc-profile-admission-release-mismatch", "indeterminate", "a different release pin refuses the session before listing validation", active, "indeterminate", trusted_admission=release_mismatch),
        vector("rsc-profile-admission-module-mismatch", "indeterminate", "a different module tuple refuses the session before listing validation", active, "indeterminate", trusted_admission=module_mismatch),
        vector("rsc-profile-admission-module-incomplete", "indeterminate", "a partial module tuple refuses the session before listing validation", active, "indeterminate", trusted_admission=partial_module),
        vector("rsc-profile-admission-session-mismatch", "indeterminate", "a session mismatch refuses the session before listing validation", active, "indeterminate", trusted_admission=session_mismatch),
        vector("rsc-profile-admission-identity-mismatch", "indeterminate", "an identity mismatch refuses the session before listing validation", active, "indeterminate", trusted_admission=identity_mismatch),
        vector("rsc-profile-admission-unauthenticated", "indeterminate", "unauthenticated admission evidence refuses the session before listing validation", active, "indeterminate", trusted_admission=unauthenticated),
        vector("rsc-profile-admission-caller-copy", "indeterminate", "a caller-supplied profile copy has no admission authority", caller_copy, "indeterminate", trusted_admission=None),
        vector("rsc-conflict-evidence-omitted", "indeterminate", "omitting the signed conflict-observation set is indeterminate, never absent", conflict_omitted, "indeterminate"),
        vector("rsc-conflict-evidence-tampered", "indeterminate", "a substituted conflict-observation set is indeterminate, never absent", conflict_tampered, "indeterminate"),
        vector("rsc-listing-receipt-missing", "indeterminate", "a current check without a finalized listing receipt is not one authenticated state", listing_receipt_missing, "indeterminate"),
        vector("rsc-listing-receipt-stale", "indeterminate", "a listing receipt outside the shared finalized state is indeterminate", listing_receipt_stale, "indeterminate"),
        vector("rsc-listing-receipt-tampered", "indeterminate", "a listing receipt whose tuple hash does not match the listing is indeterminate", listing_receipt_tampered, "indeterminate"),
        vector("rsc-historical-listing-without-state-ref", "indeterminate", "an old listing remains audit-readable but cannot enter the current new-session profile", no_state_ref, "indeterminate"),
        vector("rsc-checkpoint-history-gap", "indeterminate", "a later head cannot substitute for the complete checkpoint chain", history_gap, "indeterminate"),
        vector("rsc-producer-time-cannot-prove-latest", "indeterminate", "producer time cannot replace an authenticated current-state policy", producer_time_only, "indeterminate"),
        vector("rsc-rb4-discovered-marker-precedes-nonmembership", "fail", "a verified discovered marker cannot be ignored even when the state proof says absent", discovered_marker, "revoked"),
        vector("rsc-rb5-indeterminate-precedes-nonmembership", "indeterminate", "an unresolved discovered revocation record prevents state non-membership from returning absent", rb5_indeterminate, "indeterminate"),
        vector("rsc-conflict-later-rewrite", "indeterminate", "a later authenticated head that rewrites the target via a cross-tuple transition substitution is indeterminate, never revoked", conflict_later_rewrite, "indeterminate"),
        vector("rsc-conflict-removal-transition", "indeterminate", "a later authenticated head whose root removes the appended revocation leaf is indeterminate, never absent", conflict_removal_transition, "indeterminate"),
        vector("rsc-head-receipt-blockref-list", "indeterminate", "a list-valued head receipt blockRef fails closed without raising", head_blockref_list, "indeterminate"),
        vector("rsc-head-receipt-blockref-string", "indeterminate", "a non-object head receipt blockRef fails closed without raising", head_blockref_string, "indeterminate"),
        vector("rsc-listing-receipt-blockref-list", "indeterminate", "a list-valued listing receipt blockRef fails closed without raising", listing_blockref_list, "indeterminate"),
        vector("rsc-listing-receipt-blockref-string", "indeterminate", "a non-object listing receipt blockRef fails closed without raising", listing_blockref_string, "indeterminate"),
        vector("rsc-head-authority-list", "indeterminate", "a list-valued head authority fails closed without raising", head_authority_list, "indeterminate"),
        vector("rsc-head-authority-string", "indeterminate", "a non-object head authority fails closed without raising", head_authority_string, "indeterminate"),
        vector("rsc-listing-anchor-list", "indeterminate", "a re-signed listing whose revocationState anchor is a list fails closed without raising", anchor_list, "indeterminate"),
        vector("rsc-listing-anchor-string", "indeterminate", "a re-signed listing whose revocationState anchor is a string fails closed without raising", anchor_string, "indeterminate"),
        vector("rsc-listing-anchor-missing-locator", "indeterminate", "a re-signed listing whose revocationState anchor object lacks a locator fails closed without raising", anchor_missing_locator, "indeterminate"),
        vector("rsc-head-authority-key-list", "indeterminate", "a list-valued head authority key fails closed without raising", head_authority_key_list, "indeterminate"),
        vector("rsc-head-authority-key-none", "indeterminate", "a null head authority key fails closed without raising", head_authority_key_none, "indeterminate"),
        vector("rsc-listing-signature-value-list", "indeterminate", "a list-valued listing signature value fails closed without raising", listing_sig_value_list, "indeterminate"),
        vector("rsc-head-signature-value-list", "indeterminate", "a list-valued head signature value fails closed without raising", head_sig_value_list, "indeterminate"),
        vector("rsc-marker-signature-value-list", "indeterminate", "a list-valued marker signature value fails closed without raising", marker_sig_value_list, "indeterminate"),
        vector("rsc-non-object-root-list", "indeterminate", "a non-object (list) root input fails closed without raising", non_object_root_list, "indeterminate"),
        vector("rsc-non-object-root-string", "indeterminate", "a non-object (string) root input fails closed without raising", non_object_root_string, "indeterminate"),
        *authority_evidence_vectors,
    ]


def document() -> dict:
    vectors = build_vectors()
    encoded = json.dumps(vectors, separators=(",", ":"), ensure_ascii=False).encode()
    return {
        "set": SET_NAME,
        "spec": SPEC,
        "decisionModel": "verifier-owned corrective-profile admission (exact release pin + complete module tuple, session- and identity-bound) precedes all listing interpretation; only a signed Listing whose finalized receipt and authenticated current-head non-membership share one authenticated finalized state admits a new session; verified inclusion or a superseding authenticated revocation fails as revoked; every incomplete/conflicting/provenance-mutated proof is indeterminate",
        "inputModel": "a signed Listing carrying its revocationState reference, a finalized listing receipt, exact signed heads/markers, sparse proofs, binding-self-authenticated finalized receipts, key-authority results, and binding-authenticated current-state context whose signature binds the listing, the head, and the complete conflict-observation set",
        "authoritativeProfile": {
            "releasePin": AUTHORITATIVE_RELEASE_PIN,
            "moduleVersions": AUTHORITATIVE_MODULE_VERSIONS,
        },
        "publicKeys": {
            "initial": public_hex(SELLER_KEY),
            "rotated": public_hex(ROTATED_KEY),
            "outsider": public_hex(OUTSIDER_KEY),
            "currentStateAuthority": public_hex(CURRENT_STATE_KEY),
            "keyLifecycleAuthority": public_hex(KEY_LIFECYCLE_AUTHORITY_KEY),
        },
        "testBinding": {
            "policy": CURRENT_STATE_POLICY,
            "scope": "conformance-harness-only",
            "productionEligible": False,
            "note": "This deterministic signed-current-value adapter does not claim a deployed Demos capability.",
        },
        "hash": hashlib.sha256(encoded).hexdigest(),
        "count": len(vectors),
        "vectors": vectors,
    }


def render(data: dict) -> str:
    lines = ["{"]
    for key, value in ((key, value) for key, value in data.items() if key != "vectors"):
        lines.append(f"  {json.dumps(key)}: {json.dumps(value, ensure_ascii=False, separators=(',', ':'))},")
    lines.append('  "vectors": [')
    for index, item in enumerate(data["vectors"]):
        comma = "," if index + 1 < len(data["vectors"]) else ""
        lines.append("    " + json.dumps(item, ensure_ascii=False, separators=(",", ":")) + comma)
    lines.extend(["  ]", "}"])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render(document())
    if args.write:
        OUTPUT.write_text(expected, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != expected:
            print(f"{OUTPUT.relative_to(ROOT)} is not deterministic/current")
            return 1
        print(f"revocation-state completeness vectors OK ({document()['count']} vectors)")
        return 0
    print(expected, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
