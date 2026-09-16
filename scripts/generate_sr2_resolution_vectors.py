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


def expected_registry_tuple(kind: str) -> dict[str, str]:
    return {
        "registryKind": kind,
        "registryLogicalAddress": (
            "dacs2:registry:v0.1" if kind == "recipe" else "dacs4:registry:v0.1"
        ),
        "substrate": "demos:testnet",
        "registryBootstrapVersion": "1",
    }


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
            "unhashable-native-address-is-discarded",
            "indeterminate",
            "a non-string nativeAddress is malformed and cannot reach storage lookup",
            lambda c: receipt_carrier(c)["receipt"].update(
                {"nativeAddress": ["demos:storage:sr2-artifact-1"]}
            ),
        ),
        resolution_vector(
            "non-numeric-delivery-time-is-discarded",
            "indeterminate",
            "a non-numeric carrier delivery time cannot satisfy the receipt-delivery gate",
            lambda c: receipt_carrier(c).update({"deliveredAt": "1787036401000"}),
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
        carrier = {
            "kind": "authenticated-reference",
            "surface": surface,
            "referenceAuthenticated": True,
            "nativeAddress": NATIVE,
            "contentHash": hash_hex(ARTIFACT),
            "artifactChecksVerified": True,
        }
        if surface == "finalized-dacs5-bundle":
            carrier["finalizedBundleChecksVerified"] = True
        elif surface == "registry-bootstrap-index":
            carrier["registrySnapshotChecksVerified"] = True
        case["carriers"] = [carrier]

    def remove_class_check(case: dict[str, Any], surface: str) -> None:
        authenticated_reference(case, surface)
        for field in (
            "finalizedBundleChecksVerified", "registrySnapshotChecksVerified"
        ):
            case["carriers"][0].pop(field, None)

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
        resolution_vector(
            "unrecognized-authenticated-reference-surface-is-discarded",
            "indeterminate",
            "an authenticated-reference tag cannot invent a third SR2-10 discovery surface",
            lambda c: authenticated_reference(c, "attacker-cache"),
        ),
        resolution_vector(
            "finalized-bundle-reference-requires-class-checks",
            "indeterminate",
            "a bundle-labelled reference requires the finalized DACS-5 bundle predicate",
            lambda c: remove_class_check(c, "finalized-dacs5-bundle"),
        ),
        resolution_vector(
            "registry-reference-requires-class-checks",
            "indeterminate",
            "a registry-labelled reference requires the verified bootstrap snapshot predicate",
            lambda c: remove_class_check(c, "registry-bootstrap-index"),
        ),
        resolution_vector(
            "fractional-unknown-in-transaction-ref-is-canonical",
            "pass",
            "a bounded fractional unknown member uses CORE canonical bytes in the SR2-5 tuple",
            lambda c: receipt_carrier(c)["receipt"]["transactionRef"].update(
                {"futureMetric": 1.5}
            ),
        ),
        resolution_vector(
            "unsafe-number-in-transaction-ref-is-discarded",
            "indeterminate",
            "an uncanonicalizable receipt tuple is discarded without escaping the evaluator",
            lambda c: receipt_carrier(c)["receipt"]["transactionRef"].update(
                {"futureUnsafe": 9007199254740992}
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
            "finalizedBundleChecksVerified": True,
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

    def redeliver_identical_receipt(
        case: dict[str, Any], first_delivery: int, second_delivery: int
    ) -> None:
        first = receipt_carrier(case)
        first["deliveredAt"] = first_delivery
        second = copy.deepcopy(first)
        second["deliveredAt"] = second_delivery
        case["carriers"].append(second)

    def unresolved_lifecycle_copies(case: dict[str, Any]) -> None:
        case["minimumState"] = "accepted"
        first = receipt_carrier(case)
        first["deliveredAt"] = case["requiredBy"] + 1
        second = copy.deepcopy(first)
        second["receipt"]["state"] = "included"
        second["receipt"]["observedAt"] += 1
        second["deliveredAt"] += 1
        case["carriers"].append(second)

    vectors.extend([
        resolution_vector(
            "timely-identical-receipt-survives-late-redelivery",
            "pass",
            "delivery is assessed after exact receipt copies collapse and retains the earliest finite verified delivery",
            lambda c: redeliver_identical_receipt(
                c, c["requiredBy"] + 1, c["requiredBy"] - 1
            ),
        ),
        resolution_vector(
            "all-identical-receipt-copies-arrive-late",
            "fail",
            "all finite verified deliveries of one exact receipt snapshot miss the first required gate",
            lambda c: redeliver_identical_receipt(
                c, c["requiredBy"] + 1, c["requiredBy"] + 2
            ),
        ),
        resolution_vector(
            "unequal-lifecycle-snapshots-remain-unordered",
            "indeterminate",
            "equal SR2-5 tuples with unequal receipt snapshots remain unresolved without binding-authenticated pairwise ordering",
            unresolved_lifecycle_copies,
        ),
    ])
    return vectors


def sign_recipe_definition(definition: dict[str, Any]) -> dict[str, Any]:
    """Sign an ordinary Recipe fixture using the pinned test steward codec."""
    unsigned = {key: value for key, value in definition.items() if key != "signature"}
    return {
        **unsigned,
        "signature": signature(OLD_SEED, hash_hex(unsigned), b"dacs-recipe:v1:"),
    }


def sample_definition(kind: str, version: int = 1) -> dict[str, Any]:
    if kind == "recipe":
        return sign_recipe_definition({
            "recipeVersion": version,
            "scheme": "key",
            "defaultMethod": {"kind": "self-signed"},
            "defaultMaxAgeSec": 3600,
            "retryClass": "permanent",
            "availability": "live",
            "governance": {
                "proposedBy": OLD_KEY,
                "acceptedAt": 1787036400000,
                "anchoring": "single-signer",
                **({"supersedes": version - 1} if version > 1 else {}),
            },
        })
    return {"railVersion": version, "railId": "sample", "availability": "live"}


def index_snapshot(kind: str, revision: int = 1, include_definition: bool = False) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    if include_definition:
        definition = sample_definition(kind)
        entries.append({
            "id": definition["scheme"] if kind == "recipe" else definition["railId"],
            "version": 1,
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
        "expectedRegistryTuple": expected_registry_tuple(kind),
        "trustPin": {"descriptorHash": descriptor_hash(root), "authorityKeyId": OLD_KEY},
        "descriptors": [root],
        "verifiedEvidenceValues": [f"evidence-{kind}-index-1"],
        "indexStorage": {native: snapshot},
        "mode": "latest",
    }
    if include_definition:
        definition = sample_definition(kind)
        case["definitionQuery"] = {
            "id": definition["scheme"] if kind == "recipe" else definition["railId"],
            "version": 1,
        }
        if kind == "recipe":
            case["definitionQuery"]["family"] = "self-signed"
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


def bind_fixture_receipt_evidence(case: dict[str, Any]) -> None:
    """Compile reviewed fixture proof outcomes into exact observation bindings.

    This generator-only setup is not an evidence verifier. The evaluator receives
    the serialized independent results; it never derives them from a descriptor.
    Legacy labels select the existing fixture outcomes only during generation.
    """
    labels = case.pop("verifiedEvidenceValues", None)
    if labels is None:
        # The mutation already supplied exact independent verifier results
        # (for example, the forward-readable extended-evidence vectors).
        return
    if not isinstance(labels, list):
        case["verifiedReceiptEvidence"] = labels
        return
    results = []
    for descriptor in case["descriptors"]:
        receipt = descriptor["indexAnchorReceipt"]
        evidence = receipt["evidence"]
        if evidence["value"] not in labels:
            continue
        result = {"evidence": copy.deepcopy(evidence), "receiptHash": hash_hex(receipt)}
        if result not in results:
            results.append(result)
    case["verifiedReceiptEvidence"] = results


def build_bootstrap_vectors() -> list[dict[str, Any]]:
    def invalid_key_pinned_root_sibling(case: dict[str, Any]) -> None:
        case["trustPin"] = {"authorityKeyId": OLD_KEY}
        sibling = copy.deepcopy(case["descriptors"][0])
        sibling["authorizationSignature"]["value"] = "AA"
        case["descriptors"].append(sibling)

    def invalid_first_root_copy(case: dict[str, Any], *, unavailable: bool = False) -> None:
        case["trustPin"] = {"authorityKeyId": OLD_KEY}
        valid = case["descriptors"][0]
        invalid = copy.deepcopy(valid)
        invalid["authorizationSignature"]["value"] = "AA"
        case["descriptors"] = [invalid, valid]
        if unavailable:
            case["verifiedEvidenceValues"] = []

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
            "invalid-key-pinned-root-sibling-is-discarded",
            "pass",
            "a pin-matching root with an invalid signature is discarded before fork classification",
            invalid_key_pinned_root_sibling,
        ),
        bootstrap_vector(
            "invalid-first-root-copy-cannot-suppress-valid-identity",
            "pass",
            "transport copies are classified before same-hash root identities collapse",
            invalid_first_root_copy,
        ),
        bootstrap_vector(
            "invalid-first-root-copy-cannot-suppress-unresolved-identity",
            "indeterminate",
            "an invalid transport copy cannot erase an unavailable same-hash root identity",
            lambda c: invalid_first_root_copy(c, unavailable=True),
        ),
        bootstrap_vector(
            "transport-without-release-pin-is-rejected",
            "fail",
            "HTTPS and repository retrieval are transport, not bootstrap authority",
            lambda c: c.update({"trustPin": {}, "retrievalTransport": "https"}),
        ),
        bootstrap_vector(
            "omitted-mode-defaults-to-latest",
            "pass",
            "omitting the selection mode preserves latest-mode evaluation",
            lambda c: c.pop("mode"),
        ),
        bootstrap_vector(
            "missing-expected-registry-tuple-is-rejected",
            "fail",
            "the verifier cannot derive registry identity from presented descriptor or index fields",
            lambda c: c.pop("expectedRegistryTuple"),
        ),
        bootstrap_vector(
            "expected-registry-tuple-is-closed",
            "fail",
            "release configuration rejects unknown expected-registry-tuple fields",
            lambda c: c["expectedRegistryTuple"].update({"sequence": 1}),
        ),
        bootstrap_vector(
            "expected-registry-tuple-substrate-is-nonempty",
            "fail",
            "release configuration requires a nonempty independently supplied substrate",
            lambda c: c["expectedRegistryTuple"].update({"substrate": ""}),
        ),
        bootstrap_vector(
            "expected-registry-tuple-must-match-root",
            "fail",
            "a complete valid rail expectation cannot authorize a presented recipe root",
            lambda c: c.update({"expectedRegistryTuple": expected_registry_tuple("rail")}),
        ),
        bootstrap_vector(
            "explicit-null-mode-is-rejected",
            "fail",
            "an explicit null cannot disable latest-mode rollback policy",
            lambda c: c.update({"mode": None}),
        ),
        bootstrap_vector(
            "unsupported-mode-is-rejected",
            "fail",
            "only latest and historical selection modes are defined",
            lambda c: c.update({"mode": "transport-order"}),
        ),
        bootstrap_vector(
            "malformed-verified-evidence-context-is-rejected",
            "fail",
            "fixture evidence-verifier outputs must be structured exact receipt bindings",
            lambda c: c.update({"verifiedEvidenceValues": {}}),
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

    def replace_root_snapshot(case: dict[str, Any], snapshot: Any) -> None:
        root = case["descriptors"][0]
        snapshot_hash = hash_hex(snapshot)
        root["indexContentHash"] = snapshot_hash
        root["indexAnchorReceipt"]["contentHash"] = snapshot_hash
        case["indexStorage"][root["nativeIndexAddress"]] = snapshot
        resign_root(case)

    def add_unknown_snapshot_member(case: dict[str, Any], level: str) -> None:
        snapshot = index_snapshot(
            "recipe", include_definition=level in {"entry", "anchor"}
        )
        if level == "snapshot":
            snapshot["unexpectedAuthority"] = True
        elif level == "entry":
            snapshot["entries"][0]["unexpectedAuthority"] = True
        elif level == "anchor":
            snapshot["entries"][0]["anchor"]["unexpectedAuthority"] = True
        else:  # pragma: no cover - generator-internal misuse
            raise ValueError(level)
        replace_root_snapshot(case, snapshot)

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
            "snapshot-version-is-bound", "fail",
            "matching bytes with an unsupported registry index version are not a v1 snapshot",
            lambda c: replace_root_snapshot(
                c, {**index_snapshot("recipe"), "registryIndexVersion": "2"}
            ),
        ),
        bootstrap_vector(
            "snapshot-kind-is-bound", "fail",
            "a recipe descriptor cannot authenticate a rail-shaped registry index",
            lambda c: replace_root_snapshot(c, index_snapshot("rail")),
        ),
        bootstrap_vector(
            "snapshot-revision-is-bound-to-sequence", "fail",
            "the authenticated snapshot revision must equal its descriptor sequence",
            lambda c: replace_root_snapshot(c, index_snapshot("recipe", revision=2)),
        ),
        bootstrap_vector(
            "snapshot-entry-schema-is-validated", "fail",
            "matching bytes with a malformed entries collection are not registry authority",
            lambda c: replace_root_snapshot(
                c, {**index_snapshot("recipe"), "entries": {}}
            ),
        ),
        bootstrap_vector(
            "snapshot-envelope-is-closed", "fail",
            "an unknown top-level snapshot member is outside the closed v1 shape",
            lambda c: add_unknown_snapshot_member(c, "snapshot"),
        ),
        bootstrap_vector(
            "snapshot-entry-is-closed", "fail",
            "an unknown registry-entry member is outside the closed v1 shape",
            lambda c: add_unknown_snapshot_member(c, "entry"),
        ),
        bootstrap_vector(
            "snapshot-entry-anchor-is-closed", "fail",
            "an unknown registry-entry anchor member is outside the closed v1 shape",
            lambda c: add_unknown_snapshot_member(c, "anchor"),
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
        bootstrap_vector("active-key-revoking-candidate-is-discarded", "pass", "an invalid candidate that revokes its active authority is discarded", lambda c: revoked_chain_case(c, "revoked-predecessor")),
    ])

    def successor_fork(case: dict[str, Any]) -> None:
        root = case["descriptors"][0]
        first = add_successor(case, revision=2)
        other_snapshot = index_snapshot(
            "recipe", revision=2, include_definition=True
        )
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
        snapshot = index_snapshot(
            "recipe", revision=1, include_definition=True
        )
        other = make_descriptor(
            kind="recipe", sequence=1, snapshot=snapshot,
            native="demos:storage:recipe-index-99", authority_seed=OLD_SEED,
            evidence="evidence-recipe-index-99",
        )
        case["descriptors"].append(other)
        case["verifiedEvidenceValues"].append("evidence-recipe-index-99")
        case["indexStorage"]["demos:storage:recipe-index-99"] = snapshot

    def valid_and_invalid_same_key_roots(case: dict[str, Any]) -> None:
        case["trustPin"] = {"authorityKeyId": OLD_KEY}
        snapshot = index_snapshot("recipe")
        invalid = make_descriptor(
            kind="recipe", sequence=1, snapshot=snapshot,
            native="demos:storage:recipe-index-invalid", authority_seed=OLD_SEED,
            evidence="evidence-recipe-index-invalid",
        )
        invalid["authorizationSignature"]["value"] = "AA"
        case["descriptors"].append(invalid)
        case["verifiedEvidenceValues"].append("evidence-recipe-index-invalid")
        case["indexStorage"]["demos:storage:recipe-index-invalid"] = snapshot

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

    def historical_with_stored_latest(
        case: dict[str, Any], *, malformed: bool
    ) -> None:
        historical_root(case)
        case["storedLatest"] = {
            "sequence": 999,
            "descriptorHash": "cd" * 32,
        }
        if malformed:
            case["storedLatest"]["transportHint"] = "ignored"

    def persisted_sibling_branch(case: dict[str, Any]) -> None:
        root = case["descriptors"][0]
        persisted = add_successor(case, revision=2)
        case["storedLatest"] = {
            "sequence": 2,
            "descriptorHash": descriptor_hash(persisted),
        }
        case["descriptors"] = [root]

        sibling_snapshot = index_snapshot(
            "recipe", revision=2, include_definition=True
        )
        sibling = make_descriptor(
            kind="recipe", sequence=2, snapshot=sibling_snapshot,
            native="demos:storage:recipe-index-sibling-2",
            authority_seed=OLD_SEED, evidence="evidence-recipe-index-sibling-2",
            predecessor=root,
        )
        head_snapshot = index_snapshot(
            "recipe", revision=3, include_definition=True
        )
        head = make_descriptor(
            kind="recipe", sequence=3, snapshot=head_snapshot,
            native="demos:storage:recipe-index-sibling-3",
            authority_seed=OLD_SEED, evidence="evidence-recipe-index-sibling-3",
            predecessor=sibling,
        )
        case["descriptors"].extend([sibling, head])
        case["verifiedEvidenceValues"].extend([
            "evidence-recipe-index-sibling-2",
            "evidence-recipe-index-sibling-3",
        ])
        case["indexStorage"].update({
            sibling["nativeIndexAddress"]: sibling_snapshot,
            head["nativeIndexAddress"]: head_snapshot,
        })

    def duplicate_successor(case: dict[str, Any]) -> None:
        successor = add_successor(case)
        case["descriptors"].append(copy.deepcopy(successor))

    def invalid_first_successor_copy(
        case: dict[str, Any], *, unavailable: bool = False
    ) -> None:
        valid = add_successor(case)
        invalid = copy.deepcopy(valid)
        invalid["authorizationSignature"]["value"] = "AA"
        case["descriptors"] = [case["descriptors"][0], invalid, valid]
        if unavailable:
            evidence = valid["indexAnchorReceipt"]["evidence"]["value"]
            case["verifiedEvidenceValues"].remove(evidence)

    def duplicate_root(case: dict[str, Any]) -> None:
        case["trustPin"] = {"authorityKeyId": OLD_KEY}
        case["descriptors"].append(copy.deepcopy(case["descriptors"][0]))

    vectors.extend([
        bootstrap_vector("two-valid-successors-are-a-fork", "indeterminate", "transport order cannot choose a valid successor fork", successor_fork),
        bootstrap_vector(
            "duplicate-successor-transport-copy-collapses", "pass",
            "byte-identical transport copies name one descriptor rather than a fork",
            duplicate_successor,
        ),
        bootstrap_vector(
            "invalid-first-successor-copy-cannot-suppress-valid-identity",
            "pass",
            "transport copies are classified before same-hash successor identities collapse",
            invalid_first_successor_copy,
        ),
        bootstrap_vector(
            "invalid-first-successor-copy-cannot-suppress-unresolved-identity",
            "indeterminate",
            "an invalid transport copy cannot erase an unavailable same-hash successor identity",
            lambda c: invalid_first_successor_copy(c, unavailable=True),
        ),
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
            "duplicate-root-transport-copy-collapses", "pass",
            "byte-identical root transport copies name one descriptor rather than a fork",
            duplicate_root,
        ),
        bootstrap_vector(
            "invalid-same-key-root-cannot-suppress-valid-root", "pass",
            "invalid roots are discarded before key-pinned first-contact fork counting",
            valid_and_invalid_same_key_roots,
        ),
        bootstrap_vector(
            "latest-mode-rollback-is-rejected", "fail",
            "a lower sequence than persisted latest state is rollback",
            lambda c: c.update({"storedLatest": {"sequence": 2, "descriptorHash": "cd" * 32}}),
        ),
        bootstrap_vector(
            "persisted-branch-must-be-ancestor-of-latest", "indeterminate",
            "a longer sibling branch cannot replace the consumer's persisted branch",
            persisted_sibling_branch,
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
        bootstrap_vector(
            "historical-mode-validates-but-does-not-apply-stored-latest",
            "pass",
            "a closed stored-latest pair is validated in historical mode without imposing latest ancestry",
            lambda c: historical_with_stored_latest(c, malformed=False),
        ),
        bootstrap_vector(
            "historical-mode-rejects-malformed-stored-latest",
            "fail",
            "historical selection cannot use its mode to bypass stored-latest shape validation",
            lambda c: historical_with_stored_latest(c, malformed=True),
        ),
    ])

    def same_native_changed_bytes(case: dict[str, Any]) -> None:
        successor = add_successor(case)
        successor["nativeIndexAddress"] = case["descriptors"][0]["nativeIndexAddress"]
        successor["indexAnchorReceipt"]["nativeAddress"] = successor["nativeIndexAddress"]
        sign_descriptor(successor, OLD_SEED)

    def replace_definition(case: dict[str, Any], definition: dict[str, Any]) -> None:
        """Migrate signed dependencies from definition bytes toward outer bindings.

        The required order is definition identity/version and bytes, entry hash,
        snapshot hash, receipt binding, descriptor signature/release pin, then the
        fixture receipt-verifier sidecar compiled after all vector mutations.
        """
        root = case["descriptors"][0]
        snapshot = case["indexStorage"][root["nativeIndexAddress"]]
        entry = snapshot["entries"][0]
        locator = entry["anchor"]["locator"]
        if "recipeVersion" in definition:
            definition = sign_recipe_definition(definition)
        case["definitionStorage"][locator] = definition
        entry["contentHash"] = hash_hex(definition)
        root["indexContentHash"] = hash_hex(snapshot)
        root["indexAnchorReceipt"]["contentHash"] = root["indexContentHash"]
        resign_root(case)

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
            "fractional-unknown-in-definition-is-canonical", "pass",
            "bounded fractional unknown members participate in definition content hashing",
            lambda c: replace_definition(c, {
                **sample_definition("recipe"), "futureMetric": 1.5,
            }),
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

    def signed_unknown_fraction(case: dict[str, Any]) -> None:
        case["descriptors"][0]["futurePolicyHint"] = {"weight": 1.5}
        resign_root(case)

    def extended_receipt_evidence(case: dict[str, Any]) -> None:
        """SIG-5 forward-readable optional evidence member, re-signed and pinned.

        The receipt evidence gains an additive ``futureHint`` member, the
        complete extended evidence record is copied into the independent
        verifier sidecar, the receipt hash is recomputed over the extended
        receipt, and the descriptor is re-signed and re-pinned.
        """
        root = case["descriptors"][0]
        root["indexAnchorReceipt"]["evidence"]["futureHint"] = "forward-compatible"
        case.pop("verifiedEvidenceValues", None)
        case["verifiedReceiptEvidence"] = [{
            "evidence": copy.deepcopy(root["indexAnchorReceipt"]["evidence"]),
            "receiptHash": hash_hex(root["indexAnchorReceipt"]),
        }]
        resign_root(case)

    def extended_evidence_mismatch(case: dict[str, Any]) -> None:
        """The sidecar result must equal the complete extended evidence record."""
        extended_receipt_evidence(case)
        case["verifiedReceiptEvidence"][0]["evidence"]["futureHint"] = "attacker-different"

    def extended_evidence_missing_required(case: dict[str, Any]) -> None:
        """An optional member cannot replace the required kind/value members."""
        extended_receipt_evidence(case)
        root = case["descriptors"][0]
        del root["indexAnchorReceipt"]["evidence"]["kind"]
        case["verifiedReceiptEvidence"] = [{
            "evidence": copy.deepcopy(root["indexAnchorReceipt"]["evidence"]),
            "receiptHash": hash_hex(root["indexAnchorReceipt"]),
        }]
        resign_root(case)

    vectors.extend([
        bootstrap_vector(
            "extended-evidence-optional-member-is-forward-readable", "pass",
            "a signed optional evidence member is admitted when the independent verifier result repeats the complete extended record",
            extended_receipt_evidence,
        ),
        bootstrap_vector(
            "extended-evidence-sidecar-must-equal-complete-record", "indeterminate",
            "an optional member with a different value in the verifier sidecar does not authorize the receipt",
            extended_evidence_mismatch,
        ),
        bootstrap_vector(
            "extended-evidence-required-members-stay-required", "fail",
            "an optional member cannot replace the required evidence kind and value members",
            extended_evidence_missing_required,
        ),
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
            "unsigned-fraction-member-invalidates-root", "fail",
            "adding an unsigned finite fraction invalidates the descriptor pin and signature",
            lambda c: c["descriptors"][0].update({"futureUnsafe": 1.5}),
        ),
        bootstrap_vector(
            "signed-fraction-in-unknown-member-is-canonical", "pass",
            "an in-range finite fraction is valid JCS data when covered by the pin and signature",
            signed_unknown_fraction,
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
    for vector in vectors:
        bind_fixture_receipt_evidence(vector["input"])
    return vectors


def document(set_name: str, spec: str, model: str, vectors: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "set": set_name,
        "spec": spec,
        "decisionModel": model,
        "syntheticProfileAdmissionFixture": {
            "scope": "candidate conformance fixture only; not a published release or live deployment profile",
            "implementationOwnedReleasePin": "0000000000000000000000000000000000000001",
            "moduleVersions": {
                "core": "0.3",
                "dacs1": "0.8",
                "dacs2": "0.6",
                "dacs3": "0.6",
                "dacs4": "0.8",
                "dacs5": "0.6",
            },
            "peerEvidence": "verifier-owned context, separate from vector input, binds the exact session and expected peer identity",
        },
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
            "Only verified direct receipts or class-authenticated references establish fetch inputs; canonical receipt-snapshot identity precedes lifecycle and earliest-delivery evaluation, while exact bytes, authority, absence, and equivocation remain separate fail-closed gates.",
            resolution,
        ),
        BOOTSTRAP_OUTPUT: document(
            "registry-bootstrap-v0.1",
            "CORE §5 RegistryBootstrapDescriptor; DACS-1 §6.3.4 LRR-2; DACS-2 §7.4.3; DACS-4 §9.4.3",
            "An independently configured exact registry tuple and release-pinned sequence-one descriptor start a non-recursive immutable registry-index chain; receipt shape and evidence, exact predecessor authorization, optional new-key acceptance, snapshot hashes, rollback, forks, and definition checks are independently enforced.",
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
