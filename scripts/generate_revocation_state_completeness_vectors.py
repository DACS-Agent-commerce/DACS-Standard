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
SPEC = "DACS-1 v0.8 §6.3.4 RSC-1..RSC-9 authoritative revocation completeness"
HEAD_DOMAIN = "dacs-revocation-state-head:v1:"
MARKER_DOMAIN = "dacs-revocation:v1:"
CURRENT_STATE_DOMAIN = "dacs-rsc-conformance-current-state:v1:"
CURRENT_STATE_POLICY = "rsc-conformance-test-current-value-v1"
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


def cf4(value: str) -> str:
    encoded = value
    for raw, escaped in (("%", "%25"), (":", "%3A"), ("?", "%3F"), ("&", "%26"), ("=", "%3D")):
        encoded = encoded.replace(raw, escaped)
    return encoded


SELLER_KEY = private_key("rsc-seller-initial")
ROTATED_KEY = private_key("rsc-seller-rotated")
OUTSIDER_KEY = private_key("rsc-outsider")
CURRENT_STATE_KEY = private_key("rsc-test-current-state-authority")
SELLER = "did:example:seller"
LISTING_ID = "compute-hour"
LISTING_VERSION = 3
LISTING_HASH = "44" * 32
OTHER_LISTING_ID = "storage-hour"
OTHER_LISTING_HASH = "55" * 32
LOGICAL_ADDRESS = f"dacs1-revocations:{cf4(SELLER)}"
NATIVE_ADDRESS = "storage-program:revocation-line-a"


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


def receipt(value: dict, sequence: int) -> dict:
    return {
        "receiptVersion": "1",
        "substrate": "conformance:test",
        "finalityProfile": "rsc-conformance-test-finality-v1",
        "logicalAddress": LOGICAL_ADDRESS,
        "nativeAddress": NATIVE_ADDRESS,
        "contentHash": artifact_hash(value),
        "transactionRef": {"kind": "demos-tx", "value": f"tx-head-{sequence}"},
        "writer": "demos1seller",
        "nonce": str(40 + sequence),
        "state": "finalized",
        "observationDisposition": "established",
        "observedAt": 1_780_000_100_000 + sequence,
        "blockRef": {
            "id": f"block-{100 + sequence}",
            "height": str(100 + sequence),
            "timestamp": 1_780_000_000_000 + sequence,
        },
        "evidence": {"kind": "rsc-conformance-test-finality", "value": f"proof-{sequence}"},
    }


def current_state_message(head_ref_value: dict, head_receipt: dict,
                          finalized_state_id: str) -> bytes:
    payload = {
        "policy": CURRENT_STATE_POLICY,
        "finalizedStateId": finalized_state_id,
        "logicalAddress": LOGICAL_ADDRESS,
        "nativeAddress": NATIVE_ADDRESS,
        "headContentHash": head_ref_value["contentHash"],
        "headReceiptHash": hash_hex(head_receipt),
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


def listing(checkpoint: dict = GENESIS) -> dict:
    return {
        "authenticated": True,
        **listing_tuple(),
        "revocationState": {
            "revocationStateRefVersion": "1",
            "logicalAddress": LOGICAL_ADDRESS,
            "anchor": {"kind": "storage-program", "locator": NATIVE_ADDRESS},
            "checkpointSequence": checkpoint["sequence"],
            "checkpointHeadHash": artifact_hash(checkpoint),
        },
    }


def history_item(value: dict, key: Ed25519PrivateKey = SELLER_KEY,
                 authority_valid: bool = True) -> dict:
    return {
        "head": copy.deepcopy(value),
        "receipt": receipt(value, int(value["sequence"])),
        "authority": {
            "claim": SELLER,
            "key": public_hex(key),
            "disposition": "verified" if authority_valid else "indeterminate",
            "evidence": {"kind": "test-key-history", "value": "valid" if authority_valid else "invalid"},
        },
    }


def resolved_marker(ref: dict, value: dict, key: Ed25519PrivateKey, listing_id: str) -> dict:
    return {
        "revocationRef": copy.deepcopy(ref),
        "marker": copy.deepcopy(value),
        "receipt": marker_receipt(ref, listing_id),
        "authority": {
            "claim": SELLER,
            "key": public_hex(key),
            "disposition": "verified",
            "evidence": {"kind": "test-key-history", "value": "valid"},
        },
    }


def context(current: dict, leaves: dict[str, dict], *, target: dict = TARGET,
            history: list[dict] | None = None) -> dict:
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
    return {
        "headRef": current_ref,
        "headReceipt": current_receipt,
        "headReceiptHistory": [item["receipt"] for item in history],
        "currentStateEvidence": {
            "policy": CURRENT_STATE_POLICY,
            "finalizedStateId": finalized_state_id,
            "valueContentHash": current_ref["contentHash"],
            "evidence": {
                "kind": "ed25519-signature",
                "value": b64url(CURRENT_STATE_KEY.sign(
                    current_state_message(current_ref, current_receipt, finalized_state_id)
                )),
            },
        },
        "headHistory": copy.deepcopy(history),
        "stateProof": proof,
        "resolvedMarkers": resolved,
        "knownConflictingHeads": [],
    }


def changed(value: dict, mutation) -> dict:
    result = copy.deepcopy(value)
    mutation(result)
    return result


def input_for(current: dict, leaves: dict[str, dict], *, target: dict = TARGET,
              checkpoint: dict = GENESIS, discovery_status: str = "active",
              history: list[dict] | None = None) -> dict:
    discovery = {"status": discovery_status, "integrityConsistent": True}
    if discovery_status == "revoked":
        discovery["revocationRef"] = copy.deepcopy(TARGET_REF)
    return {
        "currentProfile": True,
        "listing": listing(checkpoint),
        "discovery": discovery,
        "resolutionContext": context(current, leaves, target=target, history=history),
    }


def want(disposition: str) -> dict:
    return {
        "revocationCheck": disposition,
        "session": "continue" if disposition == "absent" else "refuse",
    }


def vector(name: str, expected: str, note: str, data: dict, disposition: str) -> dict:
    return {"name": name, "expected": expected, "note": note, "input": data, "want": want(disposition)}


def build_vectors() -> list[dict]:
    active = input_for(OTHER_HEAD, OTHER_LEAVES)
    revoked = input_for(TARGET_HEAD, TARGET_LEAVES, discovery_status="revoked")
    censored = input_for(TARGET_HEAD, TARGET_LEAVES, discovery_status="active")

    stale = input_for(GENESIS, {})
    stale["resolutionContext"]["currentStateEvidence"]["valueContentHash"] = artifact_hash(TARGET_HEAD)

    fork = input_for(TARGET_HEAD, TARGET_LEAVES)
    fork["resolutionContext"]["knownConflictingHeads"] = [history_item(OTHER_HEAD)]
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
    rotated = input_for(rotated_head, rotated_leaves, discovery_status="revoked", history=rotated_history)
    rotated["resolutionContext"]["resolvedMarkers"].append(
        resolved_marker(rotated_ref, rotated_marker, ROTATED_KEY, LISTING_ID)
    )

    no_state_ref = changed(active, lambda x: x["listing"].pop("revocationState"))
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

    return [
        vector("rsc-valid-active-nonmembership", "pass", "an exact empty-leaf proof against the authenticated current head admits a new session", active, "absent"),
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
        vector("rsc-authorized-rotation-key", "fail", "an authenticated rotated seller key may append an exact revocation", rotated, "revoked"),
        vector("rsc-historical-listing-without-state-ref", "indeterminate", "an old listing remains audit-readable but cannot enter the current new-session profile", no_state_ref, "indeterminate"),
        vector("rsc-checkpoint-history-gap", "indeterminate", "a later head cannot substitute for the complete checkpoint chain", history_gap, "indeterminate"),
        vector("rsc-producer-time-cannot-prove-latest", "indeterminate", "producer time cannot replace an authenticated current-state policy", producer_time_only, "indeterminate"),
        vector("rsc-rb4-discovered-marker-precedes-nonmembership", "fail", "a verified discovered marker cannot be ignored even when the state proof says absent", discovered_marker, "revoked"),
        vector("rsc-rb5-indeterminate-precedes-nonmembership", "indeterminate", "an unresolved discovered revocation record prevents state non-membership from returning absent", rb5_indeterminate, "indeterminate"),
    ]


def document() -> dict:
    vectors = build_vectors()
    encoded = json.dumps(vectors, separators=(",", ":"), ensure_ascii=False).encode()
    return {
        "set": SET_NAME,
        "spec": SPEC,
        "decisionModel": "only authenticated current-head non-membership passes; verified inclusion fails as revoked; every incomplete/conflicting proof is indeterminate",
        "inputModel": "authenticated Listing projection plus exact signed heads/markers, sparse proofs, finalized receipts, key-authority results, and binding-authenticated current-state context",
        "publicKeys": {
            "initial": public_hex(SELLER_KEY),
            "rotated": public_hex(ROTATED_KEY),
            "outsider": public_hex(OUTSIDER_KEY),
            "currentStateAuthority": public_hex(CURRENT_STATE_KEY),
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
