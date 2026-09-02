#!/usr/bin/env python3
"""Generate deterministic SR2-10..SR2-13 and registry-bootstrap vectors."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sr2_resolution_reference import BOOTSTRAP_DOMAIN, descriptor_hash, hash_hex


ROOT = Path(__file__).resolve().parents[1]
SECURITY = ROOT / "conformance" / "vectors" / "security"
RESOLUTION_OUTPUT = SECURITY / "sr2-logical-native-resolution-v0.1.json"
BOOTSTRAP_OUTPUT = SECURITY / "registry-bootstrap-v0.1.json"

OLD_SEED = bytes.fromhex("41" * 32)
NEW_SEED = bytes.fromhex("42" * 32)
THIRD_SEED = bytes.fromhex("43" * 32)
ARTIFACT = {"recordVersion": "1", "jobId": "01K2SR20000000000000000000", "result": "pass"}
LOGICAL = "dacs2:vet:01K2SR20000000000000000000:buyer"
NATIVE = "demos:storage:sr2-artifact-1"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def key_id(seed: bytes) -> str:
    raw = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "key:" + raw.hex()


OLD_KEY = key_id(OLD_SEED)
NEW_KEY = key_id(NEW_SEED)
THIRD_KEY = key_id(THIRD_SEED)
SEEDS = {OLD_KEY: OLD_SEED, NEW_KEY: NEW_SEED, THIRD_KEY: THIRD_SEED}


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def signature(seed: bytes, digest: str, domain: bytes = BOOTSTRAP_DOMAIN) -> dict[str, str]:
    return {
        "keyId": key_id(seed),
        "algorithm": "ed25519",
        "value": b64url(
            Ed25519PrivateKey.from_private_bytes(seed).sign(
                domain + digest.encode("ascii")
            )
        ),
    }


def sign_descriptor(
    descriptor: dict[str, Any],
    authorization_seed: bytes,
    acceptance_seed: bytes | None = None,
    domain: bytes = BOOTSTRAP_DOMAIN,
) -> None:
    digest = descriptor_hash(descriptor)
    descriptor["authorizationSignature"] = signature(authorization_seed, digest, domain)
    if acceptance_seed is not None:
        descriptor["authorityAcceptanceSignature"] = signature(
            acceptance_seed, digest, domain
        )
    else:
        descriptor.pop("authorityAcceptanceSignature", None)


def anchor_receipt(
    *, logical: str, native: str, content_hash: str, evidence: str, state: str = "finalized"
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "receiptVersion": "1",
        "substrate": "demos:testnet",
        "finalityProfile": "demos-bft-final:v1",
        "logicalAddress": logical,
        "nativeAddress": native,
        "contentHash": content_hash,
        "transactionRef": {"kind": "demos-transaction", "value": "tx:" + evidence},
        "writer": "demos:account:registry-writer",
        "nonce": evidence.removeprefix("evidence-"),
        "state": state,
        "observationDisposition": "established",
        "observedAt": 1787036400000,
        "evidence": {"kind": "demos-finality-proof", "value": evidence},
    }
    if state in {"included", "finalized"}:
        receipt["blockRef"] = {
            "id": "block:" + evidence,
            "height": "42000",
            "timestamp": 1787036399000,
        }
    return receipt


def base_resolution() -> dict[str, Any]:
    content_hash = hash_hex(ARTIFACT)
    receipt = anchor_receipt(
        logical=LOGICAL,
        native=NATIVE,
        content_hash=content_hash,
        evidence="evidence-artifact-1",
    )
    return {
        "expectedLogicalAddress": LOGICAL,
        "expectedContentHash": content_hash,
        "minimumState": "finalized",
        "requiredBy": 1787036405000,
        "storage": {NATIVE: copy.deepcopy(ARTIFACT)},
        "carriers": [
            {
                "kind": "anchor-receipt",
                "receipt": receipt,
                "receiptEvidenceVerified": True,
                "authorityVerified": True,
                "deliveredAt": 1787036401000,
            }
        ],
    }


def resolution_vector(
    name: str,
    expected: str,
    reason: str,
    mutate: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    case = base_resolution()
    if mutate:
        mutate(case)
    return {
        "name": name,
        "family": "resolution",
        "input": case,
        "expected": expected,
        "reason": reason,
    }


def receipt_carrier(case: dict[str, Any]) -> dict[str, Any]:
    return case["carriers"][0]


def unverify_after(field: str, value: Any) -> Callable[[dict[str, Any]], None]:
    def mutate(case: dict[str, Any]) -> None:
        carrier = receipt_carrier(case)
        carrier["receipt"][field] = value
        carrier["receiptEvidenceVerified"] = False

    return mutate


def build_resolution_vectors() -> list[dict[str, Any]]:
    vectors = [
        resolution_vector(
            "direct-finalized-receipt-resolves",
            "pass",
            "a verified finalized direct receipt authorizes the exact fetch-and-hash path",
        ),
        resolution_vector(
            "vet-accepted-permits-reversible-progress",
            "pass",
            "the DACS-2 calling rule may select verified durable accepted for a reversible gate",
            lambda c: (
                c.update({"minimumState": "accepted"}),
                receipt_carrier(c)["receipt"].update({"state": "accepted"}),
                receipt_carrier(c)["receipt"].pop("blockRef", None),
            ),
        ),
        resolution_vector(
            "accepted-cannot-satisfy-finalized-gate",
            "indeterminate",
            "a lower lifecycle observation cannot promote itself to the caller's finalized gate",
            lambda c: receipt_carrier(c)["receipt"].update({"state": "accepted"}),
        ),
        resolution_vector(
            "bare-native-locator-is-not-resolution",
            "indeterminate",
            "a locator without an authenticated carrier does not establish the mapping",
            lambda c: c.update({"carriers": [{"kind": "bare-native-locator", "nativeAddress": NATIVE}]}),
        ),
        resolution_vector(
            "unverified-receipt-is-discarded",
            "indeterminate",
            "receipt fields are assertions until substrate evidence verifies",
            lambda c: receipt_carrier(c).update({"receiptEvidenceVerified": False}),
        ),
        resolution_vector(
            "malformed-number-transaction-ref-is-discarded",
            "indeterminate",
            "a numeric transactionRef is malformed and the receipt is discarded",
            lambda c: receipt_carrier(c)["receipt"].update({"transactionRef": 1.5}),
        ),
        resolution_vector(
            "unauthenticated-catalog-assertion-is-discarded",
            "indeterminate",
            "an ordinary catalog assertion is not a portable mapping carrier",
            lambda c: c.update({"carriers": [{"kind": "catalog-assertion", "nativeAddress": NATIVE}]}),
        ),
        resolution_vector(
            "unauthenticated-index-assertion-is-discarded",
            "indeterminate",
            "an ordinary index assertion is not a portable mapping carrier",
            lambda c: c.update({"carriers": [{"kind": "index-assertion", "nativeAddress": NATIVE}]}),
        ),
        resolution_vector(
            "missing-receipt-remains-indeterminate",
            "indeterminate",
            "non-delivery is not authoritative absence",
            lambda c: c.update({"carriers": []}),
        ),
    ]

    substitutions = [
        ("logical-address", "logicalAddress", "dacs2:vet:other:buyer"),
        ("native-address", "nativeAddress", "demos:storage:substituted"),
        ("content-hash", "contentHash", "aa" * 32),
        ("transaction-ref", "transactionRef", {"kind": "demos-transaction", "value": "tx:other"}),
        ("writer", "writer", "demos:account:attacker"),
        ("nonce", "nonce", "999"),
    ]
    for label, field, value in substitutions:
        vectors.append(resolution_vector(
            f"receipt-{label}-substitution",
            "indeterminate",
            f"a {label.replace('-', ' ')} mutation invalidates the authenticated SR2-5 tuple",
            unverify_after(field, value),
        ))

    vectors.extend([
        resolution_vector(
            "artifact-authority-is-a-separate-gate",
            "indeterminate",
            "valid storage proof does not authorize the writer for this logical artifact",
            lambda c: receipt_carrier(c).update({"authorityVerified": False}),
        ),
        resolution_vector(
            "fetched-content-hash-mismatch",
            "indeterminate",
            "returned bytes that do not match the verified receipt are not accepted",
            lambda c: c["storage"].update({NATIVE: {"recordVersion": "1", "result": "tampered"}}),
        ),
        resolution_vector(
            "receipt-delivered-after-first-gate",
            "fail",
            "late delivery is a producer conformance failure and cannot validate prior progress retroactively",
            lambda c: receipt_carrier(c).update({"deliveredAt": c["requiredBy"] + 1}),
        ),
        resolution_vector(
            "aborted-session-still-requires-retained-receipt",
            "indeterminate",
            "an aborted session without a bundle does not waive direct receipt retention",
            lambda c: c.update({"carriers": [], "sessionOutcome": "aborted"}),
        ),
    ])

    def authenticated_reference(case: dict[str, Any], surface: str) -> None:
        case["carriers"] = [{
            "kind": "authenticated-reference",
            "surface": surface,
            "referenceAuthenticated": True,
            "nativeAddress": NATIVE,
            "contentHash": hash_hex(ARTIFACT),
            "artifactChecksVerified": True,
        }]

    vectors.extend([
        resolution_vector(
            "finalized-bundle-reference-dereferences",
            "pass",
            "an authenticated finalized-bundle reference may carry an exact locator and hash",
            lambda c: authenticated_reference(c, "finalized-dacs5-bundle"),
        ),
        resolution_vector(
            "authenticated-registry-index-reference-dereferences",
            "pass",
            "a verified immutable registry snapshot may carry an exact definition reference",
            lambda c: authenticated_reference(c, "registry-bootstrap-index"),
        ),
        resolution_vector(
            "unauthenticated-reference-does-not-dereference",
            "indeterminate",
            "content hash and locator alone do not authenticate a transitive reference",
            lambda c: (
                authenticated_reference(c, "unsigned-cache"),
                c["carriers"][0].update({"referenceAuthenticated": False}),
            ),
        ),
    ])

    def equivocation(case: dict[str, Any]) -> None:
        second_artifact = copy.deepcopy(ARTIFACT)
        second_artifact["publisherRevision"] = 2
        second_native = "demos:storage:sr2-artifact-2"
        second_receipt = anchor_receipt(
            logical=LOGICAL,
            native=second_native,
            content_hash=hash_hex(second_artifact),
            evidence="evidence-artifact-2",
        )
        case.pop("expectedContentHash")
        case["storage"][second_native] = second_artifact
        case["carriers"].append({
            "kind": "anchor-receipt",
            "receipt": second_receipt,
            "receiptEvidenceVerified": True,
            "authorityVerified": True,
            "deliveredAt": 1787036401001,
        })

    vectors.extend([
        resolution_vector(
            "two-unequal-authorized-carriers-are-a-fork",
            "indeterminate",
            "arrival order cannot select between unequal qualifying immutable mappings",
            equivocation,
        ),
        resolution_vector(
            "ordinary-not-found-is-not-absence",
            "indeterminate",
            "an unqualified no-content response remains indeterminate",
            lambda c: c.update({"carriers": [], "claimsAbsent": True, "absencePolicy": {"declared": False}}),
        ),
        resolution_vector(
            "declared-authenticated-absence-policy-can-establish-absence",
            "pass",
            "a binding-defined finalized authenticated absence policy may establish absence",
            lambda c: c.update({"carriers": [], "claimsAbsent": True, "absencePolicy": {"declared": True, "satisfied": True}}),
        ),
        resolution_vector(
            "authenticated-presence-and-absence-conflict",
            "indeterminate",
            "conflicting authenticated positive and negative state views cannot select a winner",
            lambda c: c.update({"claimsAbsent": True, "absencePolicy": {"declared": True, "satisfied": True}}),
        ),
        resolution_vector(
            "ordinary-absence-claim-cannot-override-presence",
            "pass",
            "an unauthenticated absence claim is ignored when a qualifying receipt resolves",
            lambda c: c.update({"claimsAbsent": True, "absencePolicy": {"declared": False, "satisfied": False}}),
        ),
    ])

    def equivalent_reference_and_receipt(case: dict[str, Any]) -> None:
        case["carriers"].append({
            "kind": "authenticated-reference",
            "surface": "finalized-dacs5-bundle",
            "referenceAuthenticated": True,
            "nativeAddress": NATIVE,
            "contentHash": hash_hex(ARTIFACT),
            "artifactChecksVerified": True,
        })

    vectors.append(resolution_vector(
        "equivalent-reference-and-receipt-collapse",
        "pass",
        "two carrier classes resolving the same artifact are retained but are not a fork",
        equivalent_reference_and_receipt,
    ))

    def observed_at_does_not_choose(case: dict[str, Any]) -> None:
        equivocation(case)
        case["carriers"][0]["receipt"]["observedAt"] = 1
        case["carriers"][1]["receipt"]["observedAt"] = 9999999999999
        case["carriers"][0]["indexed"] = False
        case["carriers"][1]["indexed"] = True

    vectors.append(resolution_vector(
        "observer-time-and-index-visibility-do-not-choose-a-fork",
        "indeterminate",
        "observedAt and index visibility are not authenticated ordering inputs",
        observed_at_does_not_choose,
    ))
    return vectors


def index_snapshot(kind: str, revision: int = 1, include_definition: bool = False) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    if include_definition:
        definition = {"definitionVersion": "1", "kind": kind, "id": "sample", "version": "1"}
        entries.append({
            "id": "sample",
            "version": "1",
            "anchor": {"kind": "storage-program", "locator": f"demos:storage:{kind}-definition-1"},
            "contentHash": hash_hex(definition),
        })
    return {"registryIndexVersion": "1", "registryKind": kind, "revision": revision, "entries": entries}


def make_descriptor(
    *,
    kind: str,
    sequence: int,
    snapshot: dict[str, Any],
    native: str,
    authority_seed: bytes,
    evidence: str,
    predecessor: dict[str, Any] | None = None,
    acceptance_seed: bytes | None = None,
    revoked: list[str] | None = None,
) -> dict[str, Any]:
    logical = "dacs2:registry:v0.1" if kind == "recipe" else "dacs4:registry:v0.1"
    descriptor: dict[str, Any] = {
        "registryBootstrapVersion": "1",
        "registryKind": kind,
        "registryLogicalAddress": logical,
        "substrate": "demos:testnet",
        "sequence": sequence,
        "nativeIndexAddress": native,
        "indexContentHash": hash_hex(snapshot),
        "indexAnchorReceipt": anchor_receipt(
            logical=logical,
            native=native,
            content_hash=hash_hex(snapshot),
            evidence=evidence,
        ),
        "authorityKeyId": key_id(acceptance_seed or authority_seed),
    }
    if predecessor is not None:
        descriptor["supersedesDescriptorHash"] = descriptor_hash(predecessor)
    if revoked is not None:
        descriptor["revokedAuthorityKeyIds"] = copy.deepcopy(revoked)
    sign_descriptor(descriptor, authority_seed, acceptance_seed)
    return descriptor


def base_bootstrap(kind: str = "recipe", include_definition: bool = False) -> dict[str, Any]:
    snapshot = index_snapshot(kind, include_definition=include_definition)
    native = f"demos:storage:{kind}-index-1"
    root = make_descriptor(
        kind=kind,
        sequence=1,
        snapshot=snapshot,
        native=native,
        authority_seed=OLD_SEED,
        evidence=f"evidence-{kind}-index-1",
    )
    case: dict[str, Any] = {
        "trustPin": {"descriptorHash": descriptor_hash(root), "authorityKeyId": OLD_KEY},
        "descriptors": [root],
        "verifiedEvidenceValues": [f"evidence-{kind}-index-1"],
        "indexStorage": {native: snapshot},
        "mode": "latest",
    }
    if include_definition:
        definition = {"definitionVersion": "1", "kind": kind, "id": "sample", "version": "1"}
        case["definitionQuery"] = {"id": "sample", "version": "1"}
        case["definitionStorage"] = {f"demos:storage:{kind}-definition-1": definition}
        case["definitionChecks"] = {"signatureVerified": True, "semanticRulesVerified": True}
    return case


def bootstrap_vector(
    name: str,
    expected: str,
    reason: str,
    mutate: Callable[[dict[str, Any]], None] | None = None,
    *,
    kind: str = "recipe",
    definition: bool = False,
) -> dict[str, Any]:
    case = base_bootstrap(kind, definition)
    if mutate:
        mutate(case)
    return {
        "name": name,
        "family": "bootstrap",
        "input": case,
        "expected": expected,
        "reason": reason,
    }


def resign_root(case: dict[str, Any], seed: bytes = OLD_SEED, domain: bytes = BOOTSTRAP_DOMAIN) -> None:
    root = case["descriptors"][0]
    sign_descriptor(root, seed, domain=domain)
    case["trustPin"]["descriptorHash"] = descriptor_hash(root)


def add_successor(
    case: dict[str, Any], *, rotate: bool = False, revision: int = 2
) -> dict[str, Any]:
    predecessor = case["descriptors"][-1]
    kind = predecessor["registryKind"]
    snapshot = index_snapshot(kind, revision=revision)
    native = f"demos:storage:{kind}-index-{revision}"
    authorization_seed = SEEDS[predecessor["authorityKeyId"]]
    acceptance_seed = NEW_SEED if rotate else None
    revoked = list(predecessor.get("revokedAuthorityKeyIds", []))
    if rotate:
        revoked = sorted(set(revoked + [predecessor["authorityKeyId"]]))
    descriptor = make_descriptor(
        kind=kind,
        sequence=predecessor["sequence"] + 1,
        snapshot=snapshot,
        native=native,
        authority_seed=authorization_seed,
        acceptance_seed=acceptance_seed,
        evidence=f"evidence-{kind}-index-{revision}",
        predecessor=predecessor,
        revoked=revoked or None,
    )
    case["descriptors"].append(descriptor)
    case["verifiedEvidenceValues"].append(f"evidence-{kind}-index-{revision}")
    case["indexStorage"][native] = snapshot
    return descriptor


def build_bootstrap_vectors() -> list[dict[str, Any]]:
    vectors = [
        bootstrap_vector(
            "valid-recipe-registry-root",
            "pass",
            "the pinned recipe root verifies without consulting the recipe registry",
        ),
        bootstrap_vector(
            "valid-rail-registry-root",
            "pass",
            "the pinned rail root verifies without consulting the rail registry",
            kind="rail",
        ),
        bootstrap_vector(
            "hash-only-first-contact-pin",
            "pass",
            "a canonical sequence-1 descriptor hash is a sufficient release pin",
            lambda c: c.update({"trustPin": {"descriptorHash": descriptor_hash(c["descriptors"][0])}}),
        ),
        bootstrap_vector(
            "key-only-first-contact-pin",
            "pass",
            "a canonical sequence-1 authority key is a sufficient release pin",
            lambda c: c.update({"trustPin": {"authorityKeyId": OLD_KEY}}),
        ),
        bootstrap_vector(
            "transport-without-release-pin-is-rejected",
            "fail",
            "HTTPS and repository retrieval are transport, not bootstrap authority",
            lambda c: c.update({"trustPin": {}, "retrievalTransport": "https"}),
        ),
    ]

    def root_field_mismatch(field: str, value: Any, receipt_field: str | None = None):
        def mutate(case: dict[str, Any]) -> None:
            root = case["descriptors"][0]
            root[field] = value
            if receipt_field:
                root["indexAnchorReceipt"][receipt_field] = value
            resign_root(case)
        return mutate

    vectors.extend([
        bootstrap_vector(
            "registry-kind-logical-address-pairing-mismatch", "fail",
            "the self-describing logical address must match the exact kind pairing",
            root_field_mismatch("registryLogicalAddress", "dacs4:registry:v0.1"),
        ),
        bootstrap_vector(
            "descriptor-receipt-substrate-mismatch", "fail",
            "the embedded receipt substrate must equal the descriptor substrate",
            lambda c: (c["descriptors"][0]["indexAnchorReceipt"].update({"substrate": "other:testnet"}), resign_root(c)),
        ),
        bootstrap_vector(
            "descriptor-receipt-logical-address-mismatch", "fail",
            "the embedded receipt logical address must equal the registry logical address",
            lambda c: (c["descriptors"][0]["indexAnchorReceipt"].update({"logicalAddress": "dacs2:registry:v9"}), resign_root(c)),
        ),
        bootstrap_vector(
            "descriptor-receipt-native-address-mismatch", "fail",
            "the embedded receipt native address must equal the immutable snapshot address",
            lambda c: (c["descriptors"][0]["indexAnchorReceipt"].update({"nativeAddress": "demos:storage:other"}), resign_root(c)),
        ),
        bootstrap_vector(
            "descriptor-receipt-content-hash-mismatch", "fail",
            "the embedded receipt content hash must equal the descriptor snapshot hash",
            lambda c: (c["descriptors"][0]["indexAnchorReceipt"].update({"contentHash": "ab" * 32}), resign_root(c)),
        ),
        bootstrap_vector(
            "non-final-bootstrap-receipt", "fail",
            "registry bootstrap requires established finalized evidence",
            lambda c: (c["descriptors"][0]["indexAnchorReceipt"].update({"state": "included"}), resign_root(c)),
        ),
        bootstrap_vector(
            "unavailable-bootstrap-receipt-evidence", "indeterminate",
            "unavailable otherwise-valid finality evidence cannot become pass or fail",
            lambda c: c.update({"verifiedEvidenceValues": []}),
        ),
        bootstrap_vector(
            "recursive-bootstrap-evidence", "fail",
            "bootstrap finality proof cannot depend on the registry being bootstrapped",
            lambda c: (c["descriptors"][0]["indexAnchorReceipt"]["evidence"].update({"kind": "registry-dependent"}), resign_root(c)),
        ),
        bootstrap_vector(
            "same-key-content-successor", "pass",
            "each immutable index-byte update advances sequence and is authorized by the predecessor key",
            lambda c: add_successor(c),
        ),
        bootstrap_vector(
            "two-signature-key-rotation", "pass",
            "rotation requires predecessor delegation and exact new-key acceptance",
            lambda c: add_successor(c, rotate=True),
        ),
    ])

    def changed_successor(case: dict[str, Any], mutate: Callable[[dict[str, Any]], None]) -> None:
        successor = add_successor(case, rotate=True)
        mutate(successor)
        old_seed = OLD_SEED
        acceptance_seed = NEW_SEED if successor.get("authorityKeyId") == NEW_KEY else None
        sign_descriptor(successor, old_seed, acceptance_seed)

    vectors.extend([
        bootstrap_vector(
            "rotation-missing-predecessor-authorization", "pass",
            "an invalid rotation is discarded and cannot replace the accepted root",
            lambda c: (add_successor(c, rotate=True)["authorizationSignature"].update({"value": "AA"}),),
        ),
        bootstrap_vector(
            "rotation-missing-new-key-acceptance", "pass",
            "a rotation without new-key acceptance is discarded and the accepted root remains",
            lambda c: add_successor(c, rotate=True).pop("authorityAcceptanceSignature"),
        ),
        bootstrap_vector(
            "sequence-skipping-candidate-is-discarded", "pass",
            "a sequence-skipping candidate is discarded and cannot advance the accepted chain",
            lambda c: changed_successor(c, lambda d: d.update({"sequence": 3})),
        ),
        bootstrap_vector(
            "successor-registry-tuple-change", "pass",
            "a tuple-changing candidate is discarded and cannot advance the accepted chain",
            lambda c: changed_successor(c, lambda d: d.update({"substrate": "other:testnet"})),
        ),
        bootstrap_vector(
            "authority-key-alias-is-rejected", "fail",
            "key identifiers are exactly key plus raw lower-case Ed25519 public bytes",
            lambda c: (c["descriptors"][0].update({"authorityKeyId": "did:key:" + OLD_KEY[4:]}), resign_root(c)),
        ),
        bootstrap_vector(
            "active-key-cannot-be-revoked", "fail",
            "the descriptor's active authority cannot appear in its revocation set",
            lambda c: (c["descriptors"][0].update({"revokedAuthorityKeyIds": [OLD_KEY]}), resign_root(c)),
        ),
    ])

    def revoked_chain_case(case: dict[str, Any], mode: str) -> None:
        rotated = add_successor(case, rotate=True)
        successor = add_successor(case, revision=3)
        if mode == "shrink":
            successor["revokedAuthorityKeyIds"] = []
        elif mode == "duplicate":
            successor["revokedAuthorityKeyIds"] = [OLD_KEY, OLD_KEY]
        elif mode == "reorder":
            successor["revokedAuthorityKeyIds"] = sorted([THIRD_KEY, OLD_KEY], reverse=True)
        elif mode == "revoked-predecessor":
            rotated["revokedAuthorityKeyIds"] = sorted([OLD_KEY, NEW_KEY])
        sign_descriptor(successor, NEW_SEED)

    vectors.extend([
        bootstrap_vector("non-cumulative-revocation-candidate-is-discarded", "pass", "a successor with non-cumulative revocations is discarded", lambda c: revoked_chain_case(c, "shrink")),
        bootstrap_vector("duplicate-revocation-candidate-is-discarded", "pass", "a successor with duplicate revocations is discarded", lambda c: revoked_chain_case(c, "duplicate")),
        bootstrap_vector("revocation-set-order-is-canonical", "pass", "a successor with non-canonical revocation order is discarded", lambda c: revoked_chain_case(c, "reorder")),
        bootstrap_vector("active-authority-revocation-candidate-is-discarded", "pass", "an invalid candidate that revokes its active authority is discarded", lambda c: revoked_chain_case(c, "revoked-predecessor")),
    ])

    def successor_fork(case: dict[str, Any]) -> None:
        root = case["descriptors"][0]
        first = add_successor(case, revision=2)
        other_snapshot = index_snapshot("recipe", revision=22)
        other = make_descriptor(
            kind="recipe", sequence=2, snapshot=other_snapshot,
            native="demos:storage:recipe-index-22", authority_seed=OLD_SEED,
            evidence="evidence-recipe-index-22", predecessor=root,
        )
        case["descriptors"].append(other)
        case["verifiedEvidenceValues"].append("evidence-recipe-index-22")
        case["indexStorage"]["demos:storage:recipe-index-22"] = other_snapshot
        assert first != other

    def root_fork(case: dict[str, Any]) -> None:
        case["trustPin"] = {"authorityKeyId": OLD_KEY}
        snapshot = index_snapshot("recipe", revision=99)
        other = make_descriptor(
            kind="recipe", sequence=1, snapshot=snapshot,
            native="demos:storage:recipe-index-99", authority_seed=OLD_SEED,
            evidence="evidence-recipe-index-99",
        )
        case["descriptors"].append(other)
        case["verifiedEvidenceValues"].append("evidence-recipe-index-99")
        case["indexStorage"]["demos:storage:recipe-index-99"] = snapshot

    def valid_and_unavailable_successor(case: dict[str, Any]) -> None:
        successor_fork(case)
        unavailable = case["descriptors"][-1]
        evidence = unavailable["indexAnchorReceipt"]["evidence"]["value"]
        case["verifiedEvidenceValues"].remove(evidence)

    def valid_and_invalid_successor(case: dict[str, Any]) -> None:
        successor_fork(case)
        case["descriptors"][-1]["authorizationSignature"]["value"] = "AA"

    def historical_root(case: dict[str, Any]) -> None:
        add_successor(case)
        root = case["descriptors"][0]
        case.update({
            "mode": "historical",
            "targetSequence": 1,
            "targetDescriptorHash": descriptor_hash(root),
        })

    def historical_unrelated_descriptor(case: dict[str, Any]) -> None:
        add_successor(case)
        snapshot = index_snapshot("recipe", revision=33)
        unrelated = make_descriptor(
            kind="recipe",
            sequence=3,
            snapshot=snapshot,
            native="demos:storage:recipe-index-33",
            authority_seed=OLD_SEED,
            evidence="evidence-recipe-index-33",
        )
        unrelated["supersedesDescriptorHash"] = "ef" * 32
        sign_descriptor(unrelated, OLD_SEED)
        case["descriptors"].append(unrelated)
        case["verifiedEvidenceValues"].append("evidence-recipe-index-33")
        case["indexStorage"]["demos:storage:recipe-index-33"] = snapshot
        case.update({
            "mode": "historical",
            "targetSequence": 3,
            "targetDescriptorHash": descriptor_hash(unrelated),
        })

    vectors.extend([
        bootstrap_vector("two-valid-successors-are-a-fork", "indeterminate", "transport order cannot choose a valid successor fork", successor_fork),
        bootstrap_vector(
            "valid-and-unavailable-successors-remain-unresolved", "indeterminate",
            "proof availability cannot select one of two predecessor-authorized signed candidates",
            valid_and_unavailable_successor,
        ),
        bootstrap_vector(
            "invalid-successor-is-discarded", "pass",
            "an invalid sibling candidate is discarded before the one valid successor advances",
            valid_and_invalid_successor,
        ),
        bootstrap_vector("key-only-sequence-one-fork", "indeterminate", "a key-only first-contact pin cannot choose between two valid roots", root_fork),
        bootstrap_vector(
            "latest-mode-rollback-is-rejected", "fail",
            "a lower sequence than persisted latest state is rollback",
            lambda c: c.update({"storedLatest": {"sequence": 2, "descriptorHash": "cd" * 32}}),
        ),
        bootstrap_vector(
            "historical-replay-uses-recorded-sequence", "pass",
            "historical replay selects the exact retained sequence-and-descriptor-hash pair",
            historical_root,
        ),
        bootstrap_vector(
            "historical-replay-requires-descriptor-hash", "fail",
            "a numeric registry sequence alone is not authenticated replay authority",
            lambda c: (add_successor(c), c.update({"mode": "historical", "targetSequence": 1})),
        ),
        bootstrap_vector(
            "historical-replay-refuses-unrelated-descriptor", "indeterminate",
            "an exact target hash outside the validated predecessor chain cannot be selected",
            historical_unrelated_descriptor,
        ),
    ])

    def same_native_changed_bytes(case: dict[str, Any]) -> None:
        successor = add_successor(case)
        successor["nativeIndexAddress"] = case["descriptors"][0]["nativeIndexAddress"]
        successor["indexAnchorReceipt"]["nativeAddress"] = successor["nativeIndexAddress"]
        sign_descriptor(successor, OLD_SEED)

    vectors.extend([
        bootstrap_vector(
            "content-change-at-same-native-address", "pass",
            "a same-address content replacement is discarded and cannot advance the chain",
            same_native_changed_bytes,
        ),
        bootstrap_vector(
            "missing-index-snapshot-bytes", "indeterminate",
            "an otherwise valid descriptor cannot be used until exact snapshot bytes are available",
            lambda c: c.update({"indexStorage": {}}),
        ),
        bootstrap_vector(
            "stale-index-snapshot-bytes", "indeterminate",
            "stale bytes that miss the pinned hash cannot become an unpinned latest index",
            lambda c: c["indexStorage"].update({c["descriptors"][0]["nativeIndexAddress"]: index_snapshot("recipe", 999)}),
        ),
        bootstrap_vector(
            "authenticated-index-definition-reference", "pass",
            "an entry in a verified immutable index is an authenticated content reference",
            definition=True,
        ),
        bootstrap_vector(
            "definition-content-hash-mismatch", "fail",
            "definition bytes must match the authenticated entry hash",
            lambda c: c["definitionStorage"].update({"demos:storage:recipe-definition-1": {"tampered": True}}),
            definition=True,
        ),
        bootstrap_vector(
            "unsafe-integer-in-definition-is-rejected", "fail",
            "definition bytes outside the JCS safe-magnitude subset fail explicitly",
            lambda c: c["definitionStorage"]["demos:storage:recipe-definition-1"].update({"futureUnsafe": 9007199254740992}),
            definition=True,
        ),
        bootstrap_vector(
            "definition-bytes-unavailable", "indeterminate",
            "unavailable referenced definition bytes remain indeterminate",
            lambda c: c.update({"definitionStorage": {}}),
            definition=True,
        ),
        bootstrap_vector(
            "definition-signature-or-semantics-fail", "fail",
            "the authenticated locator does not waive the definition's own checks",
            lambda c: c["definitionChecks"].update({"signatureVerified": False}),
            definition=True,
        ),
    ])

    def signed_unknown(case: dict[str, Any]) -> None:
        case["descriptors"][0]["futurePolicyHint"] = {"mode": "audit"}
        resign_root(case)

    def mutate_unknown_without_resign(case: dict[str, Any]) -> None:
        signed_unknown(case)
        case["descriptors"][0]["futurePolicyHint"]["mode"] = "replace"
        case["trustPin"]["descriptorHash"] = descriptor_hash(case["descriptors"][0])

    def signed_unknown_nfc(case: dict[str, Any]) -> None:
        case["descriptors"][0]["futurePolicyHint"] = {"label": "e\u0301"}
        resign_root(case)

    vectors.extend([
        bootstrap_vector(
            "signed-unknown-member-is-preserved", "pass",
            "SIG-5 includes unknown members in the descriptor hash and signature",
            signed_unknown,
        ),
        bootstrap_vector(
            "signed-unknown-member-is-nfc-canonical", "pass",
            "descriptor hashing applies CF-1 NFC to signed unknown string values",
            signed_unknown_nfc,
        ),
        bootstrap_vector(
            "unsafe-integer-in-unknown-member-is-rejected", "fail",
            "descriptor hashing rejects integers outside the JCS safe subset",
            lambda c: c["descriptors"][0].update({"futureUnsafe": 9007199254740992}),
        ),
        bootstrap_vector(
            "float-in-unknown-member-is-rejected", "fail",
            "descriptor hashing rejects unsupported floating-point values fail closed",
            lambda c: c["descriptors"][0].update({"futureUnsafe": 1.5}),
        ),
        bootstrap_vector(
            "unknown-member-mutation-without-resigning", "fail",
            "a verifier cannot strip or mutate an unknown member before hashing",
            mutate_unknown_without_resign,
        ),
        bootstrap_vector(
            "cross-domain-signature-replay", "fail",
            "a valid Ed25519 signature under another domain is not bootstrap authorization",
            lambda c: resign_root(c, domain=b"dacs-anchor-receipt:v1:"),
        ),
        bootstrap_vector(
            "extra-bootstrap-discriminator-is-rejected", "fail",
            "multiple structural bootstrap discriminators are refused before interpretation",
            lambda c: (c["descriptors"][0].update({"recipeBootstrapVersion": "1"}), resign_root(c)),
        ),
    ])
    return vectors


def document(set_name: str, spec: str, model: str, vectors: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "set": set_name,
        "spec": spec,
        "decisionModel": model,
        "hashRecipe": "sha256(compact sorted-key UTF-8 JSON of vectors)",
        "hash": hashlib.sha256(canonical_bytes(vectors)).hexdigest(),
        "count": len(vectors),
        "publicTestSeeds": {
            "oldAuthorityEd25519": OLD_SEED.hex(),
            "newAuthorityEd25519": NEW_SEED.hex(),
            "thirdAuthorityEd25519": THIRD_SEED.hex(),
        },
        "vectors": vectors,
    }


def rendered_documents() -> dict[Path, str]:
    resolution = build_resolution_vectors()
    bootstrap = build_bootstrap_vectors()
    documents = {
        RESOLUTION_OUTPUT: document(
            "sr2-logical-native-resolution-v0.1",
            "CORE §5 SR2-10..SR2-13; DACS-1 §6.3.4; DACS-5 §10.4.2",
            "Only verified direct receipts or class-authenticated references establish fetch inputs; lifecycle, exact bytes, authority, timeliness, absence, and equivocation remain separate fail-closed gates.",
            resolution,
        ),
        BOOTSTRAP_OUTPUT: document(
            "registry-bootstrap-v0.1",
            "CORE §5 RegistryBootstrapDescriptor; DACS-1 §6.3.4 LRR-2; DACS-2 §7.4.3; DACS-4 §9.4.3",
            "A release-pinned sequence-one descriptor starts a non-recursive immutable registry-index chain; exact predecessor authorization, optional new-key acceptance, finality evidence, snapshot hashes, rollback, forks, and definition checks are independently enforced.",
            bootstrap,
        ),
    }
    return {path: json.dumps(data, indent=2, ensure_ascii=False) + "\n" for path, data in documents.items()}


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    stale: list[Path] = []
    for path, rendered in rendered_documents().items():
        if args.write:
            path.write_text(rendered, encoding="utf-8")
            print(f"wrote {path.relative_to(ROOT)}")
        elif not path.exists() or path.read_text(encoding="utf-8") != rendered:
            stale.append(path)
    if stale:
        print("SR-2 resolution vectors are stale; run "
              "python3 scripts/generate_sr2_resolution_vectors.py --write")
        return 1
    if args.check:
        print("SR-2 resolution and registry-bootstrap vectors deterministic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
