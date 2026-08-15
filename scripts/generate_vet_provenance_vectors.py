#!/usr/bin/env python3
"""Generate deterministic candidate vectors for authenticated Vet provenance.

The fixture contains genuine Ed25519 signatures and CORE-canonical hashes for
Listings, IdentityBundles, VerifyResults, VetRequirementAuthorizations, and
ProvenancedCompositeVerificationRecords.  It exercises the VPA/PVC/PVPC chain,
the sealed admission hand-off, and the DACS-5 ``vetRecords`` projection.  It
does not claim to be a complete outer AttestationBundle fixture or a second
full DACS-1 schema suite: baseline Listing/PhaseStep shape validation is an
explicit precondition, with the provenance-relevant Listing gates rechecked.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from jcs import canonicalize


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance" / "vectors" / "security" / "vet-provenance-v0.6.json"

BASE_VECTOR_NAMES = (
    "ordinary-bilateral-third-party-verifiers",
    "procurement-two-bidder-completed",
)

LISTING_DOMAIN = "dacs-listing:v1:"
BUNDLE_DOMAIN = "dacs-bundle-presentation:v1:"
VERIFY_DOMAIN = "dacs-verifyresult:v1:"
LEGACY_COMPOSITE_DOMAIN = "dacs-composite:v1:"
AUTH_DOMAIN = "dacs-vet-authorization:v1:"
COMPOSITE_DOMAIN = "dacs-provenanced-composite:v1:"
RECEIPT_DOMAIN = "fixture-anchor-receipt:v1:"

NOW = 1786723200000
SESSION_NONCE = "90" * 16
RECIPE_REGISTRY_VERSION = 7
RAIL_REGISTRY_VERSION = 3

SEEDS = {
    "publisher": bytes.fromhex("11" * 32),
    "bidder-a": bytes.fromhex("22" * 32),
    "bidder-b": bytes.fromhex("33" * 32),
    "evidence-verifier": bytes.fromhex("44" * 32),
    "verifier-a-counterparty": bytes.fromhex("55" * 32),
    "verifier-a-publisher": bytes.fromhex("66" * 32),
    "verifier-b-counterparty": bytes.fromhex("77" * 32),
    "verifier-b-publisher": bytes.fromhex("88" * 32),
    "attacker": bytes.fromhex("99" * 32),
    "substrate-validator": bytes.fromhex("aa" * 32),
}


def canonical_bytes(value: Any) -> bytes:
    return canonicalize(value).encode("utf-8")


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def hash_value(value: Any) -> str:
    return sha256_hex(canonical_bytes(value))


def compact_json_bytes(value: Any) -> bytes:
    """Encode collection-level fixture hashes exactly as the set validator does."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def json_pointer_escape(token: str) -> str:
    """Encode one RFC 6901 token for use in an RFC 6902 patch path."""
    return token.replace("~", "~0").replace("/", "~1")


def json_patch(source: Any, target: Any, path: str = "") -> list[dict]:
    """Return a deterministic, non-overlapping RFC 6902 subset patch.

    Objects recurse by member and equal-length arrays recurse by index. Arrays
    whose cardinality changes are replaced as a unit, which avoids the
    order-sensitive index shifts of add/remove array operations. Scalar or
    type changes are also represented by one replacement.
    """
    if type(source) is not type(target):
        return [{"op": "replace", "path": path, "value": copy.deepcopy(target)}]
    if isinstance(source, dict):
        operations: list[dict] = []
        source_keys = set(source)
        target_keys = set(target)
        for key in sorted(source_keys - target_keys):
            member_path = path + "/" + json_pointer_escape(key)
            operations.append({"op": "remove", "path": member_path})
        for key in sorted(target_keys - source_keys):
            member_path = path + "/" + json_pointer_escape(key)
            operations.append(
                {"op": "add", "path": member_path, "value": copy.deepcopy(target[key])}
            )
        for key in sorted(source_keys & target_keys):
            member_path = path + "/" + json_pointer_escape(key)
            operations.extend(json_patch(source[key], target[key], member_path))
        return operations
    if isinstance(source, list):
        if len(source) != len(target):
            return [{"op": "replace", "path": path, "value": copy.deepcopy(target)}]
        operations = []
        for index, (source_item, target_item) in enumerate(zip(source, target)):
            operations.extend(json_patch(source_item, target_item, f"{path}/{index}"))
        return operations
    if source != target:
        return [{"op": "replace", "path": path, "value": copy.deepcopy(target)}]
    return []


def assert_non_overlapping_patch(patch: list[dict]) -> None:
    """Fail generation if two operations address the same or nested paths."""
    paths = [operation["path"] for operation in patch]
    if len(paths) != len(set(paths)):
        raise ValueError("generated JSON Patch contains duplicate paths")
    tokenized = [tuple(path.split("/")[1:]) if path else () for path in paths]
    for index, left in enumerate(tokenized):
        for right in tokenized[index + 1 :]:
            common = min(len(left), len(right))
            if left[:common] == right[:common]:
                raise ValueError("generated JSON Patch contains overlapping paths")


def compact_vectors(vectors: list[dict]) -> list[dict]:
    """Represent the semantic vectors with two literal, one-level bases."""
    by_name = {item["name"]: item for item in vectors}
    if len(by_name) != len(vectors):
        raise ValueError("vector names must be unique before compaction")
    if any(name not in by_name for name in BASE_VECTOR_NAMES):
        raise ValueError("required compact representation base is missing")

    base_inputs = {
        name: copy.deepcopy(by_name[name]["input"]) for name in BASE_VECTOR_NAMES
    }
    represented: list[dict] = []
    for item in vectors:
        compact = {
            "name": item["name"],
            "rule": item["rule"],
            "operation": item["operation"],
        }
        if item["name"] in BASE_VECTOR_NAMES:
            compact["input"] = copy.deepcopy(item["input"])
        else:
            candidates = []
            for base_name in BASE_VECTOR_NAMES:
                patch = json_patch(base_inputs[base_name], item["input"])
                assert_non_overlapping_patch(patch)
                candidates.append(
                    (
                        len(
                            compact_json_bytes(
                                {"base": base_name, "patch": patch}
                            )
                        ),
                        base_name,
                        patch,
                    )
                )
            _, base_name, patch = min(candidates, key=lambda candidate: candidate[0])
            compact["base"] = base_name
            compact["patch"] = patch
        compact["expandedInputHash"] = hash_value(item["input"])
        compact["expected"] = item["expected"]
        compact["note"] = item["note"]
        represented.append(compact)
    return represented


def full_content_hash(artifact: dict) -> str:
    """Hash the complete anchored artifact, including its signature."""
    return hash_value(artifact)


def signing_hash(artifact: dict, omitted: str) -> str:
    """Hash the purpose-specific signature preimage, omitting one field."""
    return hash_value({key: value for key, value in artifact.items() if key != omitted})


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def public_hex(seed_name: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(SEEDS[seed_name]).public_key()
    return key.public_bytes_raw().hex()


def claim_for(seed_name: str) -> str:
    return "key:" + public_hex(seed_name)


def sign_digest(seed_name: str, domain: str, digest: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(SEEDS[seed_name])
    return b64url(key.sign(domain.encode("utf-8") + digest.encode("ascii")))


def sign_bytes(seed_name: str, payload: bytes) -> str:
    key = Ed25519PrivateKey.from_private_bytes(SEEDS[seed_name])
    return b64url(key.sign(payload))


def sign_artifact(artifact: dict, seed_name: str, domain: str) -> None:
    artifact["signature"]["value"] = sign_digest(
        seed_name, domain, signing_hash(artifact, "signature")
    )


def cf4(value: str) -> str:
    return quote(value, safe="-._~")


def bundle_hash(bundle: dict) -> str:
    return signing_hash(bundle, "presentation")


def native_locator(logical: str) -> str:
    return "stor-" + sha256_hex(("native:" + logical).encode("utf-8"))[:40]


def receipt(logical: str, native: str, content_hash: str, writer: str, state: str) -> dict:
    tx = sha256_hex(("tx:" + logical + ":" + content_hash).encode("utf-8"))
    value = {
        "receiptVersion": "1",
        "substrate": "fixture-sr2",
        "finalityProfile": "fixture-immediate-finality",
        "logicalAddress": logical,
        "nativeAddress": native,
        "contentHash": content_hash,
        "transactionRef": {"kind": "fixture-tx", "value": tx},
        "writer": writer,
        "nonce": "0",
        "state": state,
        "observationDisposition": "established",
        "observedAt": NOW + 500,
    }
    if state in {"included", "finalized"}:
        value["blockRef"] = {
            "id": "fixture-block-100",
            "height": "100",
            "timestamp": NOW + 400,
        }
    refresh_receipt_evidence(value)
    return value


def refresh_receipt_evidence(value: dict) -> None:
    scope = {key: member for key, member in value.items() if key != "evidence"}
    value["evidence"] = {
        "kind": "fixture-ed25519-receipt/" + claim_for("substrate-validator"),
        "value": sign_digest("substrate-validator", RECEIPT_DOMAIN, hash_value(scope)),
    }


def envelope(
    artifact: dict,
    logical: str,
    *,
    state: str = "finalized",
    full_signed_content: bool = False,
) -> dict:
    content_hash = (
        full_content_hash(artifact)
        if full_signed_content
        else signing_hash(artifact, "signature")
    )
    native = native_locator(logical)
    signer = artifact.get("signature", {}).get("signer")
    ref = {
        "anchor": {"kind": "storage-program", "locator": native},
        "contentHash": content_hash,
    }
    if signer is not None:
        ref["signer"] = signer
    return {
        "artifact": artifact,
        "ref": ref,
        "receipt": receipt(logical, native, content_hash, signer or "fixture-writer", state),
    }


def raw_envelope(artifact: dict, logical: str, writer: str) -> dict:
    """Envelope method-native evidence whose integrity hash covers all bytes."""
    content_hash = full_content_hash(artifact)
    native = native_locator(logical)
    return {
        "artifact": artifact,
        "ref": {
            "anchor": {"kind": "storage-program", "locator": native},
            "contentHash": content_hash,
            "signer": writer,
        },
        "receipt": receipt(logical, native, content_hash, writer, "finalized"),
    }


def result_ref(result_envelope: dict) -> dict:
    return {
        "anchor": copy.deepcopy(result_envelope["ref"]["anchor"]),
        "contentHash": result_envelope["ref"]["contentHash"],
        "recipeVersion": 1,
    }


def make_verify_result(job_id: str, party_seed: str, decision: str) -> tuple[dict, dict]:
    identifier = public_hex(party_seed)
    assertion = f"dacs-self-signed-claim:v1:{job_id}:key:{identifier}"
    assertion_signature = sign_bytes(
        "attacker" if decision == "fail" else party_seed,
        assertion.encode("utf-8"),
    )
    if decision == "error":
        evidence_artifact = {
            "kind": "self-signed-invocation-error",
            "identifier": identifier,
            "error": "declared assertion bytes unavailable to parser",
        }
    else:
        evidence_artifact = {
            "kind": "self-signed-assertion",
            "identifier": identifier,
            "assertion": assertion,
            "signature": assertion_signature,
        }
    evidence_logical = f"fixture:self-signed-evidence:{job_id}:{cf4(identifier)}"
    evidence = raw_envelope(evidence_artifact, evidence_logical, claim_for(party_seed))
    artifact = {
        "resultVersion": "1",
        "scheme": "key",
        "identifier": identifier,
        "recipeVersion": 1,
        "method": "self-signed",
        "decision": decision,
        "reason": "deterministic fixture " + decision,
        "attestation": copy.deepcopy(evidence["ref"]),
        "fetchedAt": NOW,
        "verifiedAt": NOW + 1,
        "validUntil": NOW + 3_600_000,
        "signature": {
            "algorithm": "ed25519",
            "signer": claim_for("evidence-verifier"),
            "value": "",
        },
    }
    sign_artifact(artifact, "evidence-verifier", VERIFY_DOMAIN)
    logical = f"dacs2:{job_id}:key:{cf4(identifier)}:v1"
    return envelope(artifact, logical), evidence


def make_identity(seed_name: str, *, session: bool, verified_by: dict | None = None) -> dict:
    claim = claim_for(seed_name)
    bundle_claim: dict[str, Any] = {"ref": claim}
    if verified_by is not None:
        bundle_claim["verifiedBy"] = copy.deepcopy(verified_by)
    artifact = {
        "bundleVersion": "1",
        "presentedBy": claim,
        "presentedAt": NOW,
        "claims": [bundle_claim],
        "presentation": {
            "kind": "per-claim",
            "signatures": [{"ref": claim, "signature": ""}],
        },
    }
    if session:
        artifact["sessionNonce"] = SESSION_NONCE
    artifact["presentation"]["signatures"][0]["signature"] = sign_digest(
        seed_name, BUNDLE_DOMAIN, bundle_hash(artifact)
    )
    return artifact


def requirement(preferred: str | None = None) -> dict:
    value: dict[str, Any] = {
        "requirementVersion": "1",
        "required": [{"scheme": "key", "verificationRequired": True}],
    }
    if preferred is not None:
        value["preferredPresentation"] = preferred
    return value


def make_listing(mode: str, publisher_listing_identity: dict, job_id: str) -> dict:
    if mode == "procurement":
        negotiation = {
            "kind": "negotiate-sealed-envelope-procurement",
            "parameters": {
                "commitDeadline": NOW + 60_000,
                "revealWindow": 60,
                "selectionRule": "lowest-price",
                "auctionMode": "procurement",
            },
        }
        pricing = {
            "kind": "auction",
            "reservePrice": {"amount": "10", "currency": "USDC", "unit": "job"},
            "selectionRule": "lowest-price",
        }
    else:
        negotiation = {"kind": "negotiate-fixed-price"}
        pricing = {
            "kind": "fixed",
            "price": {"amount": "1", "currency": "USDC", "unit": "job"},
        }
    artifact = {
        "dacsVersion": "1",
        "listingVersion": 1,
        "listingId": "vet-provenance-" + mode + "-" + job_id[-4:],
        "seller": {
            "identity": copy.deepcopy(publisher_listing_identity),
            "displayName": "Fixture publisher",
        },
        "offering": {
            "title": "Provenanced Vet fixture",
            "description": "Deterministic authenticated Vet provenance fixture.",
            "category": "conformance.vet",
            "tags": ["vet", "provenance"],
            "deliverable": {
                "kind": "storage-program",
                "schemaUrl": "https://example.test/vet-result.schema.json",
            },
        },
        "buyerRequirement": requirement(),
        "pipeline": [
            {"kind": "vet-credentials-provenanced"},
            negotiation,
            {"kind": "commit-agreement"},
            {"kind": "deliver-storage-program"},
        ],
        "pricing": pricing,
        "terms": {"deadlineSecAfterCommit": 3600},
        "validity": {"notBefore": NOW - 60_000, "notAfter": NOW + 3_600_000},
        "signature": {
            "algorithm": "ed25519",
            "signer": claim_for("publisher"),
            "value": "",
        },
    }
    sign_artifact(artifact, "publisher", LISTING_DOMAIN)
    logical = (
        f"dacs1:{cf4(artifact['seller']['identity']['presentedBy'])}:"
        f"{artifact['listingId']}:v{artifact['listingVersion']}"
    )
    return envelope(artifact, logical)


def listing_ref(listing_envelope: dict) -> dict:
    artifact = listing_envelope["artifact"]
    return {
        "listingId": artifact["listingId"],
        "version": artifact["listingVersion"],
        "contentHash": listing_envelope["ref"]["contentHash"],
    }


def make_session_context(
    mode: str,
    job_id: str,
    listing_envelope: dict,
    publisher: dict,
    candidates: list[dict],
    prior_phase_outputs: dict,
) -> dict:
    publisher_role = "buyer" if mode == "procurement" else "seller"
    counterparty_role = "seller" if mode == "procurement" else "buyer"
    parties = [
        {
            "role": publisher_role,
            "bundleHash": bundle_hash(publisher),
            "primaryClaim": publisher["presentedBy"],
        }
    ]
    if mode != "procurement":
        parties.extend(
            {
                "role": counterparty_role,
                "bundleHash": bundle_hash(candidate),
                "primaryClaim": candidate["presentedBy"],
            }
            for candidate in candidates
        )
    return {
        "jobId": job_id,
        "listingRef": listing_ref(listing_envelope),
        "recipeRegistryVersion": RECIPE_REGISTRY_VERSION,
        "railRegistryVersion": RAIL_REGISTRY_VERSION,
        "parties": parties,
        "priorPhaseOutputs": copy.deepcopy(prior_phase_outputs),
        "signer": {
            "kind": "fixture-substrate-signer",
            "keyRef": publisher["presentedBy"],
        },
        "startedAt": NOW - 1_000,
    }


def roster_entries(candidates: list[dict]) -> list[dict]:
    unique: dict[str, dict] = {}
    for candidate in candidates:
        claim = candidate["presentedBy"]
        candidate_hash = bundle_hash(candidate)
        entry = {"primaryClaim": claim, "bundleHash": candidate_hash}
        previous = unique.get(claim)
        if previous is not None and previous != entry:
            raise ValueError("same primary claim with different candidate bundle")
        unique[claim] = entry
    return [unique[key] for key in sorted(unique, key=lambda value: value.encode("utf-8"))]


def auth_logical(artifact: dict) -> str:
    return (
        "dacs2:vet-authorization:"
        f"{artifact['jobId']}:{artifact['evaluatedRole']}:"
        f"{cf4(artifact['counterpartyContext'])}:{cf4(artifact['evaluatedParty'])}"
    )


def composite_logical(artifact: dict) -> str:
    return (
        "dacs2:provenanced-composite:"
        f"{artifact['jobId']}:{artifact['evaluatedRole']}:"
        f"{cf4(artifact['counterpartyContext'])}:{cf4(artifact['evaluatedParty'])}"
    )


def verifier_seed(candidate_seed: str, evaluated_role: str) -> str:
    letter = "a" if candidate_seed == "bidder-a" else "b"
    return f"verifier-{letter}-{evaluated_role}"


def make_authorization(
    *,
    job_id: str,
    listing_envelope: dict,
    publisher: dict,
    candidate: dict,
    candidate_seed: str,
    evaluated_role: str,
    roster_hash: str,
    roster_count: int,
) -> dict:
    if evaluated_role == "counterparty":
        evaluated = candidate
        authorizer = publisher
        authorizer_seed = "publisher"
        origin = {"kind": "listing", "field": "buyerRequirement"}
        required = copy.deepcopy(listing_envelope["artifact"]["buyerRequirement"])
    else:
        evaluated = publisher
        authorizer = candidate
        authorizer_seed = candidate_seed
        origin = {"kind": "party-declared"}
        preferred = "per-claim" if candidate_seed == "bidder-a" else "siwd"
        required = requirement(preferred)
    selected_verifier = verifier_seed(candidate_seed, evaluated_role)
    artifact = {
        "vetAuthorizationVersion": "1",
        "jobId": job_id,
        "listingRef": listing_ref(listing_envelope),
        "recipeRegistryVersion": RECIPE_REGISTRY_VERSION,
        "counterpartySetHash": roster_hash,
        "counterpartyCount": roster_count,
        "evaluatedRole": evaluated_role,
        "counterpartyContext": candidate["presentedBy"],
        "evaluatedIdentity": copy.deepcopy(evaluated),
        "evaluatedParty": evaluated["presentedBy"],
        "evaluatedBundleHash": bundle_hash(evaluated),
        "authorizerRole": "publisher" if evaluated_role == "counterparty" else "counterparty",
        "authorizerIdentity": copy.deepcopy(authorizer),
        "requirementOrigin": origin,
        "requirement": required,
        "requirementHash": hash_value(required),
        "verifierIdentity": make_identity(selected_verifier, session=True),
        "authorizedAt": NOW + (1 if evaluated_role == "counterparty" else 2),
        "signature": {
            "algorithm": "ed25519",
            "signer": claim_for(authorizer_seed),
            "value": "",
        },
    }
    sign_artifact(artifact, authorizer_seed, AUTH_DOMAIN)
    return envelope(artifact, auth_logical(artifact))


def make_composite(auth_envelope: dict, verify_ref: dict, candidate_seed: str) -> dict:
    authorization = auth_envelope["artifact"]
    selected_verifier = verifier_seed(candidate_seed, authorization["evaluatedRole"])
    # One required claim and one result make §7.7.1 recomputation executable.
    decision = verify_ref["_decision"]
    ref = {key: copy.deepcopy(value) for key, value in verify_ref.items() if key != "_decision"}
    artifact = {
        "provenancedRecordVersion": "1",
        "jobId": authorization["jobId"],
        "evaluatedRole": authorization["evaluatedRole"],
        "counterpartyContext": authorization["counterpartyContext"],
        "evaluatedParty": authorization["evaluatedParty"],
        "bundleHash": authorization["evaluatedBundleHash"],
        "requirementHash": authorization["requirementHash"],
        "authorizationRef": copy.deepcopy(auth_envelope["ref"]),
        "freshness": [ref],
        "supplementary": [],
        "dealSpecific": [],
        "overallDecision": decision,
        "generatedAt": NOW + 100,
        "signature": {
            "algorithm": "ed25519",
            "signer": claim_for(selected_verifier),
            "value": "",
        },
    }
    sign_artifact(artifact, selected_verifier, COMPOSITE_DOMAIN)
    return envelope(artifact, composite_logical(artifact))


def make_legacy_composite(provenanced: dict, verifier_seed_name: str) -> dict:
    """Project shared evidence into the frozen legacy record shape."""
    source = provenanced["artifact"]
    artifact = {
        "recordVersion": "1",
        "jobId": source["jobId"],
        "evaluatedParty": source["evaluatedParty"],
        "bundleHash": source["bundleHash"],
        "requirementHash": source["requirementHash"],
        "freshness": copy.deepcopy(source["freshness"]),
        "supplementary": copy.deepcopy(source["supplementary"]),
        "dealSpecific": copy.deepcopy(source["dealSpecific"]),
        "overallDecision": source["overallDecision"],
        "generatedAt": source["generatedAt"],
        "signature": {
            "algorithm": "ed25519",
            "signer": claim_for(verifier_seed_name),
            "value": "",
        },
    }
    sign_artifact(artifact, verifier_seed_name, LEGACY_COMPOSITE_DOMAIN)
    logical = f"dacs2:composite:{artifact['jobId']}:{cf4(artifact['evaluatedParty'])}"
    return envelope(artifact, logical)


def ref_key(ref: dict) -> tuple[str, str]:
    return ref["anchor"]["locator"], ref["contentHash"]


def sorted_vet_refs(case: dict) -> list[dict]:
    items: list[tuple[bytes, int, int, dict]] = []
    role_order = {"counterparty": 0, "publisher": 1}
    for kind_order, collection in enumerate((case["authorizations"], case["composites"])):
        for item in collection:
            artifact = item["artifact"]
            items.append(
                (
                    artifact["counterpartyContext"].encode("utf-8"),
                    role_order[artifact["evaluatedRole"]],
                    kind_order,
                    copy.deepcopy(item["ref"]),
                )
            )
    return [item[3] for item in sorted(items, key=lambda value: value[:3])]


def composite_for(case: dict, context: str, role: str) -> dict:
    for item in case["composites"]:
        artifact = item["artifact"]
        if artifact["counterpartyContext"] == context and artifact["evaluatedRole"] == role:
            return item
    raise KeyError((context, role))


def make_case(
    mode: str = "ordinary",
    *,
    candidate_decisions: tuple[str, ...] | None = None,
    publisher_decision: str = "pass",
    outcome: str = "completed",
    prewinner_terminal: bool = False,
) -> dict:
    candidate_seeds = ["bidder-a"] if mode == "ordinary" else ["bidder-a", "bidder-b"]
    if candidate_decisions is None:
        candidate_decisions = tuple("pass" for _ in candidate_seeds)
    job_id = "01K2VPA0000000000000000" + ("101" if mode == "ordinary" else "202")

    results: list[dict] = []
    method_evidence: list[dict] = []
    publisher_result, publisher_evidence = make_verify_result(job_id, "publisher", publisher_decision)
    results.append(publisher_result)
    method_evidence.append(publisher_evidence)
    publisher_ref = result_ref(publisher_result)
    publisher_ref["_decision"] = publisher_decision
    publisher = make_identity("publisher", session=True, verified_by=result_ref(publisher_result))

    candidates: list[dict] = []
    candidate_refs: dict[str, dict] = {}
    for seed_name, decision in zip(candidate_seeds, candidate_decisions):
        result, evidence = make_verify_result(job_id, seed_name, decision)
        results.append(result)
        method_evidence.append(evidence)
        candidate = make_identity(seed_name, session=True, verified_by=result_ref(result))
        candidates.append(candidate)
        ref = result_ref(result)
        ref["_decision"] = decision
        candidate_refs[seed_name] = ref

    listing_identity = make_identity("publisher", session=False)
    listing_envelope = make_listing(mode, listing_identity, job_id)
    entries = roster_entries(candidates)
    roster_hash = hash_value(entries)

    authorizations: list[dict] = []
    composites: list[dict] = []
    for seed_name, candidate in zip(candidate_seeds, candidates):
        for role in ("counterparty", "publisher"):
            auth = make_authorization(
                job_id=job_id,
                listing_envelope=listing_envelope,
                publisher=publisher,
                candidate=candidate,
                candidate_seed=seed_name,
                evaluated_role=role,
                roster_hash=roster_hash,
                roster_count=len(entries),
            )
            authorizations.append(auth)
            evidence_ref = candidate_refs[seed_name] if role == "counterparty" else publisher_ref
            composites.append(make_composite(auth, evidence_ref, seed_name))

    eligible = []
    for seed_name, candidate, decision in zip(candidate_seeds, candidates, candidate_decisions):
        if decision == "pass" and publisher_decision == "pass":
            eligible.append(candidate["presentedBy"])
    eligible.sort(key=lambda value: value.encode("utf-8"))

    case: dict[str, Any] = {
        "gate": "finalized-audit-projection" if outcome == "completed" else "bundle-consumption-projection",
        "mode": mode,
        "phaseKind": "vet-credentials-provenanced",
        "jobId": job_id,
        "sessionNonce": SESSION_NONCE,
        "recipeRegistryVersion": RECIPE_REGISTRY_VERSION,
        "listing": listing_envelope,
        "publisher": publisher,
        "candidates": candidates,
        "verificationResults": results,
        "methodEvidence": method_evidence,
        "authorizations": authorizations,
        "composites": composites,
        "phaseInput": {
            "jobId": job_id,
            "invocations": [],
            "sessionContext": make_session_context(
                mode, job_id, listing_envelope, publisher, candidates, {}
            ),
            "recipeRegistryVersion": RECIPE_REGISTRY_VERSION,
            "attempt": 1,
        },
        "vetContextDelta": {
            "records": [],
            "eligibleCounterparties": eligible,
        },
        "negotiateInput": None,
        "agreementProjection": None,
        "auditProjection": {
            "projectionKind": "vet-provenance-audit-projection",
            "outcome": outcome,
            "phaseSummary": {
                "index": 0,
                "kind": "vet-credentials-provenanced",
                "outcome": "ok" if outcome == "completed" else "fail",
                "errorClass": None if outcome == "completed" else "counterparty",
            },
            "winnerMappingPresent": False,
            "faultedParty": None,
            "representationDisposition": "projected-representable",
            "reputationDisposition": "include",
            "vetRecords": [],
        },
    }
    for item in sorted(
        composites,
        key=lambda env: (
            env["artifact"]["counterpartyContext"].encode("utf-8"),
            0 if env["artifact"]["evaluatedRole"] == "counterparty" else 1,
        ),
    ):
        artifact = item["artifact"]
        auth = next(
            auth_item
            for auth_item in authorizations
            if ref_key(auth_item["ref"]) == ref_key(artifact["authorizationRef"])
        )
        case["vetContextDelta"]["records"].append(
            {
                "counterpartyContext": artifact["counterpartyContext"],
                "evaluatedRole": artifact["evaluatedRole"],
                "compositeRecord": copy.deepcopy(item["ref"]),
                "authorizationRecord": copy.deepcopy(auth["ref"]),
                "overallDecision": artifact["overallDecision"],
            }
        )

    auth_by_tuple = {
        (item["artifact"]["counterpartyContext"], item["artifact"]["evaluatedRole"]): item
        for item in authorizations
    }
    for context in sorted((candidate["presentedBy"] for candidate in candidates), key=lambda value: value.encode("utf-8")):
        for role in ("counterparty", "publisher"):
            auth = auth_by_tuple[(context, role)]
            case["phaseInput"]["invocations"].append(
                {
                    "counterpartyContext": context,
                    "evaluatedRole": role,
                    "bundleToVet": copy.deepcopy(auth["artifact"]["evaluatedIdentity"]),
                    "authorizationRef": copy.deepcopy(auth["ref"]),
                }
            )

    case["auditProjection"]["vetRecords"] = sorted_vet_refs(case)

    if mode == "procurement":
        pairs = []
        by_claim = {candidate["presentedBy"]: candidate for candidate in candidates}
        for context in eligible:
            pairs.append(
                {
                    "counterpartyContext": context,
                    "counterpartyBundle": copy.deepcopy(by_claim[context]),
                    "counterpartyVetRef": copy.deepcopy(composite_for(case, context, "counterparty")["ref"]),
                    "publisherVetRef": copy.deepcopy(composite_for(case, context, "publisher")["ref"]),
                }
            )
        case["negotiateInput"] = {
            "vetProvenanceInputVersion": "1",
            "jobId": job_id,
            "listingHash": listing_envelope["ref"]["contentHash"],
            "listingRef": {
                "listingId": listing_envelope["artifact"]["listingId"],
                "version": 1,
            },
            "publisherBundle": copy.deepcopy(publisher),
            "vetPairs": pairs,
            "parameters": copy.deepcopy(listing_envelope["artifact"]["pipeline"][1]["parameters"]),
            "sessionContext": make_session_context(
                mode,
                job_id,
                listing_envelope,
                publisher,
                candidates,
                {"vet-credentials-provenanced": case["vetContextDelta"]},
            ),
        }

    if outcome == "completed" and eligible and not prewinner_terminal:
        winner = eligible[0]
        role_publisher = "buyer" if mode == "procurement" else "seller"
        role_winner = "seller" if mode == "procurement" else "buyer"
        by_claim = {candidate["presentedBy"]: candidate for candidate in candidates}
        parties = [
            {
                "role": role_publisher,
                "primaryClaim": publisher["presentedBy"],
                "bundleHash": bundle_hash(publisher),
                "vetRecordRef": copy.deepcopy(composite_for(case, winner, "publisher")["ref"]),
            },
            {
                "role": role_winner,
                "primaryClaim": winner,
                "bundleHash": bundle_hash(by_claim[winner]),
                "vetRecordRef": copy.deepcopy(composite_for(case, winner, "counterparty")["ref"]),
            },
        ]
        for context in eligible[1:]:
            parties.append(
                {
                    "role": "bidder-non-winning",
                    "primaryClaim": context,
                    "bundleHash": bundle_hash(by_claim[context]),
                    "vetRecordRef": copy.deepcopy(composite_for(case, context, "counterparty")["ref"]),
                }
            )
        case["agreementProjection"] = {"winnerContext": winner, "parties": parties}
        case["auditProjection"]["winnerMappingPresent"] = True
    elif outcome != "completed" and len(candidates) == 1:
        failing_roles = [
            item["artifact"]["evaluatedRole"]
            for item in composites
            if item["artifact"]["overallDecision"] == "fail"
        ]
        if len(set(failing_roles)) == 1:
            mapped = role_publisher = (
                "seller" if failing_roles[0] == "publisher" else "buyer"
            )
            case["auditProjection"]["faultedParty"] = mapped

    return case


def resign_envelope(item: dict, seed_name: str, domain: str, logical: str | None = None) -> None:
    sign_artifact(item["artifact"], seed_name, domain)
    if logical is None:
        if "vetAuthorizationVersion" in item["artifact"]:
            logical = auth_logical(item["artifact"])
        elif "provenancedRecordVersion" in item["artifact"] or "recordVersion" in item["artifact"]:
            logical = composite_logical(item["artifact"])
        else:
            raise ValueError("logical address required")
    state = item["receipt"]["state"]
    refreshed = envelope(
        item["artifact"],
        logical,
        state=state,
    )
    item.clear()
    item.update(refreshed)


def sync_surface_refs(case: dict) -> None:
    """Rebuild all valid downstream references after intentional resigning."""
    # Relink each Composite by its signed tuple.
    auth_by_tuple = {
        (
            item["artifact"]["counterpartyContext"],
            item["artifact"]["evaluatedRole"],
        ): item
        for item in case["authorizations"]
    }
    for invocation in case["phaseInput"]["invocations"]:
        key = (invocation["counterpartyContext"], invocation["evaluatedRole"])
        if key in auth_by_tuple:
            invocation["authorizationRef"] = copy.deepcopy(auth_by_tuple[key]["ref"])
    for item in case["composites"]:
        artifact = item["artifact"]
        auth = auth_by_tuple[(artifact["counterpartyContext"], artifact["evaluatedRole"])]
        artifact["authorizationRef"] = copy.deepcopy(auth["ref"])
        seed = next(
            name
            for name in SEEDS
            if claim_for(name) == artifact["signature"]["signer"]
        )
        resign_envelope(item, seed, COMPOSITE_DOMAIN)

    case["vetContextDelta"]["records"] = []
    for item in sorted(
        case["composites"],
        key=lambda env: (
            env["artifact"]["counterpartyContext"].encode("utf-8"),
            0 if env["artifact"]["evaluatedRole"] == "counterparty" else 1,
        ),
    ):
        artifact = item["artifact"]
        auth = auth_by_tuple[(artifact["counterpartyContext"], artifact["evaluatedRole"])]
        case["vetContextDelta"]["records"].append(
            {
                "counterpartyContext": artifact["counterpartyContext"],
                "evaluatedRole": artifact["evaluatedRole"],
                "compositeRecord": copy.deepcopy(item["ref"]),
                "authorizationRecord": copy.deepcopy(auth["ref"]),
                "overallDecision": artifact["overallDecision"],
            }
        )
    case["auditProjection"]["vetRecords"] = sorted_vet_refs(case)

    if case["negotiateInput"] is not None:
        eligible = case["vetContextDelta"]["eligibleCounterparties"]
        by_claim = {candidate["presentedBy"]: candidate for candidate in case["candidates"]}
        case["negotiateInput"]["vetPairs"] = [
            {
                "counterpartyContext": context,
                "counterpartyBundle": copy.deepcopy(by_claim[context]),
                "counterpartyVetRef": copy.deepcopy(composite_for(case, context, "counterparty")["ref"]),
                "publisherVetRef": copy.deepcopy(composite_for(case, context, "publisher")["ref"]),
            }
            for context in eligible
        ]
    if case["agreementProjection"] is not None:
        winner = case["agreementProjection"]["winnerContext"]
        for party in case["agreementProjection"]["parties"]:
            if party["primaryClaim"] == case["publisher"]["presentedBy"]:
                party["vetRecordRef"] = copy.deepcopy(composite_for(case, winner, "publisher")["ref"])
            else:
                party["vetRecordRef"] = copy.deepcopy(
                    composite_for(case, party["primaryClaim"], "counterparty")["ref"]
                )
    sync_vet_prior_output(case)


def sync_composite_surface_refs(case: dict) -> None:
    """Relink projections to current PCR refs without repairing PCR contents."""
    auth_by_tuple = {
        (item["artifact"]["counterpartyContext"], item["artifact"]["evaluatedRole"]): item
        for item in case["authorizations"]
    }
    composite_by_tuple = {
        (item["artifact"]["counterpartyContext"], item["artifact"]["evaluatedRole"]): item
        for item in case["composites"]
    }
    records = []
    for key in sorted(
        composite_by_tuple,
        key=lambda value: (value[0].encode("utf-8"), 0 if value[1] == "counterparty" else 1),
    ):
        if key not in auth_by_tuple:
            continue
        composite = composite_by_tuple[key]
        authorization = auth_by_tuple[key]
        records.append(
            {
                "counterpartyContext": key[0],
                "evaluatedRole": key[1],
                "compositeRecord": copy.deepcopy(composite["ref"]),
                "authorizationRecord": copy.deepcopy(authorization["ref"]),
                "overallDecision": composite["artifact"]["overallDecision"],
            }
        )
    case["vetContextDelta"]["records"] = records

    if case.get("negotiateInput") is not None:
        by_claim = {candidate["presentedBy"]: candidate for candidate in case["candidates"]}
        pairs = []
        for context in case["vetContextDelta"]["eligibleCounterparties"]:
            counterparty = composite_by_tuple.get((context, "counterparty"))
            publisher = composite_by_tuple.get((context, "publisher"))
            if counterparty is None or publisher is None:
                continue
            pairs.append(
                {
                    "counterpartyContext": context,
                    "counterpartyBundle": copy.deepcopy(by_claim[context]),
                    "counterpartyVetRef": copy.deepcopy(counterparty["ref"]),
                    "publisherVetRef": copy.deepcopy(publisher["ref"]),
                }
            )
        case["negotiateInput"]["vetPairs"] = pairs

    agreement = case.get("agreementProjection")
    if agreement is not None:
        winner = agreement["winnerContext"]
        publisher_claim = case["publisher"]["presentedBy"]
        for party in agreement["parties"]:
            key = (
                (winner, "publisher")
                if party["primaryClaim"] == publisher_claim
                else (party["primaryClaim"], "counterparty")
            )
            composite = composite_by_tuple.get(key)
            if composite is not None:
                party["vetRecordRef"] = copy.deepcopy(composite["ref"])
    case["auditProjection"]["vetRecords"] = sorted_vet_refs(case)
    sync_vet_prior_output(case)


def sync_vet_prior_output(case: dict) -> None:
    negotiate = case.get("negotiateInput")
    if negotiate is not None:
        negotiate["sessionContext"]["priorPhaseOutputs"] = {
            "vet-credentials-provenanced": copy.deepcopy(case["vetContextDelta"])
        }


def replace_projected_ref(case: dict, old_ref: dict, new_ref: dict) -> None:
    """Replace one artifact reference on every projection surface."""
    old_key = ref_key(old_ref)
    for record in case["vetContextDelta"]["records"]:
        if ref_key(record["compositeRecord"]) == old_key:
            record["compositeRecord"] = copy.deepcopy(new_ref)
    negotiate = case.get("negotiateInput")
    if negotiate is not None:
        for pair in negotiate["vetPairs"]:
            for field in ("counterpartyVetRef", "publisherVetRef"):
                if ref_key(pair[field]) == old_key:
                    pair[field] = copy.deepcopy(new_ref)
    agreement = case.get("agreementProjection")
    if agreement is not None:
        for party in agreement["parties"]:
            if ref_key(party["vetRecordRef"]) == old_key:
                party["vetRecordRef"] = copy.deepcopy(new_ref)
    case["auditProjection"]["vetRecords"] = [
        copy.deepcopy(new_ref) if ref_key(item) == old_key else item
        for item in case["auditProjection"]["vetRecords"]
    ]
    sync_vet_prior_output(case)


def resign_listing_and_relink(case: dict) -> None:
    """Re-sign a deliberately mutated Listing and rebuild its valid descendants."""
    listing = case["listing"]["artifact"]
    logical = (
        f"dacs1:{cf4(listing['seller']['identity']['presentedBy'])}:"
        f"{listing['listingId']}:v{listing['listingVersion']}"
    )
    listing_signer = listing["signature"]["signer"]
    listing_seed = next(name for name in SEEDS if claim_for(name) == listing_signer)
    resign_envelope(case["listing"], listing_seed, LISTING_DOMAIN, logical)
    new_listing_ref = listing_ref(case["listing"])
    case["phaseInput"]["sessionContext"]["listingRef"] = copy.deepcopy(
        new_listing_ref
    )
    for item in case["authorizations"]:
        artifact = item["artifact"]
        artifact["listingRef"] = copy.deepcopy(new_listing_ref)
        signer = artifact["signature"]["signer"]
        seed = next(name for name in SEEDS if claim_for(name) == signer)
        resign_envelope(item, seed, AUTH_DOMAIN)
    if case["negotiateInput"] is not None:
        case["negotiateInput"]["listingHash"] = new_listing_ref["contentHash"]
        case["negotiateInput"]["listingRef"] = {
            "listingId": new_listing_ref["listingId"],
            "version": new_listing_ref["version"],
        }
        case["negotiateInput"]["parameters"] = copy.deepcopy(
            listing["pipeline"][1].get("parameters", {})
        )
        case["negotiateInput"]["sessionContext"]["listingRef"] = copy.deepcopy(
            new_listing_ref
        )
    sync_surface_refs(case)


def vector(name: str, rule: str, note: str, case: dict, expected: str) -> dict:
    return {
        "name": name,
        "rule": rule,
        "operation": "validate-provenanced-vet-chain-and-admission",
        "input": case,
        "expected": expected,
        "note": note,
    }


def build_vectors() -> list[dict]:
    vectors: list[dict] = []

    def add(name: str, rule: str, note: str, case: dict, expected: str) -> None:
        vectors.append(vector(name, rule, note, case, expected))

    add(
        "ordinary-bilateral-third-party-verifiers",
        "VPA-1..VPA-10; PVC-1..PVC-6; PVPC-1..PVPC-11",
        "One bilateral pair uses distinct signed requirements and independently selected third-party verifiers.",
        make_case(),
        "pass",
    )
    add(
        "procurement-two-bidder-completed",
        "PVPC-1; PVPC-6..PVPC-8; DACS-3 §8.5.2 check 10; ST-11",
        "Two all-pass supplier contexts produce four distinct records, an exact eligible set, winner/loser mappings, and retained publisher-for-loser provenance.",
        make_case("procurement"),
        "pass",
    )
    case = make_case("procurement")
    case["phaseInput"]["invocations"].reverse()
    case["negotiateInput"]["vetPairs"].reverse()
    add(
        "input-array-order-is-nonauthoritative",
        "PVPC-1; PVPC-4; DACS-3 provenanced ingress",
        "Invocation and context-keyed vetPairs input order may vary while canonical outputs and audit ordering remain unchanged.",
        case,
        "pass",
    )
    add(
        "procurement-conclusive-fail-excluded-and-retained",
        "PVPC-6; PVPC-8; ST-11",
        "A conclusively failing second supplier is excluded before negotiation but all four of its authorization/record refs remain auditable.",
        make_case("procurement", candidate_decisions=("pass", "fail")),
        "pass",
    )
    add(
        "bilateral-single-direction-fail-attributable",
        "PVPC-10; DACS-5 §10.4.3",
        "A sole counterparty-evaluation fail maps uniquely to the bilateral buyer fault.",
        make_case(candidate_decisions=("fail",), outcome="failed-counterparty"),
        "pass",
    )

    case = make_case()
    case["preauthorizationBarrier"] = "not-reached"
    case["authorizations"] = case["authorizations"][:1]
    case["composites"] = []
    case["verificationResults"] = []
    case["methodEvidence"] = []
    case["phaseInput"] = None
    case["vetContextDelta"] = None
    case["preauthorizationProjection"] = {
        "projectionKind": "vet-preauthorization-collection",
        "authorizationRefs": [
            copy.deepcopy(item["ref"]) for item in case["authorizations"]
        ],
        "claimLookupCount": 0,
        "invocationCount": 0,
        "verifyResultCount": 0,
        "methodEvidenceCount": 0,
        "compositeCount": 0,
    }
    case["agreementProjection"] = None
    case["auditProjection"] = {
        "projectionKind": "vet-provenance-audit-projection",
        "outcome": "aborted-by-self",
        "phaseDisposition": {
            "index": 0,
            "kind": "vet-credentials-provenanced",
            "state": "not-invoked",
            "cause": "party-withdrawal",
        },
        "abortEvent": "fixture-party-withdrawal-before-invocation",
        "winnerMappingPresent": False,
        "faultedParty": None,
        "representationDisposition": "projected-prebarrier-nonattributable",
        "reputationDisposition": "exclude",
        "vetRecords": sorted_vet_refs(case),
    }
    add(
        "partial-authorization-barrier-has-zero-verifier-effects",
        "PVPC-2; PVPC-10",
        "A partial authorization set aborts before method invocation, VerifyResult or Composite emission, eligibility, fault attribution, or reputation use.",
        case,
        "pass",
    )

    case = make_case(candidate_decisions=("fail",), outcome="failed-counterparty")
    case["preauthorizationBarrier"] = "not-reached"
    case["authorizations"] = case["authorizations"][:1]
    case["composites"] = case["composites"][:1]
    case["phaseInput"] = None
    case["vetContextDelta"] = None
    case["preauthorizationProjection"] = {
        "projectionKind": "vet-preauthorization-collection",
        "authorizationRefs": [
            copy.deepcopy(item["ref"]) for item in case["authorizations"]
        ],
        "claimLookupCount": 1,
        "invocationCount": 1,
        "verifyResultCount": len(case["verificationResults"]),
        "methodEvidenceCount": len(case["methodEvidence"]),
        "compositeCount": len(case["composites"]),
    }
    case["agreementProjection"] = None
    case["auditProjection"]["vetRecords"] = sorted_vet_refs(case)
    add(
        "partial-authorization-cannot-carry-composite-or-fault",
        "PVPC-2; PVPC-10; DACS-5 §10.4.3",
        "A partial authorization set with verifier side effects, a Composite, and counterparty fault/reputation projection is not the permitted pre-barrier abort shape.",
        case,
        "fail",
    )

    case = make_case(candidate_decisions=("fail",), publisher_decision="fail", outcome="failed-counterparty")
    case["auditProjection"]["faultedParty"] = None
    case["auditProjection"]["representationDisposition"] = "exclude-current-single-fault-type"
    case["auditProjection"]["reputationDisposition"] = "exclude"
    add(
        "bilateral-both-directions-fail-not-single-fault",
        "PVPC-10; DACS-5 single-fault gate",
        "Different commerce parties fail the two directions; current faultedParty cannot choose one.",
        case,
        "indeterminate",
    )

    case = make_case("procurement", prewinner_terminal=True)
    case["auditProjection"]["outcome"] = "failed-counterparty"
    case["auditProjection"]["phaseSummary"] = {
        "index": 0,
        "kind": "vet-credentials-provenanced",
        "outcome": "fail",
        "errorClass": "counterparty",
    }
    case["auditProjection"]["representationDisposition"] = "exclude-prewinner-multicandidate"
    case["auditProjection"]["reputationDisposition"] = "exclude"
    add(
        "multi-candidate-prewinner-terminal-unrepresentable",
        "PVPC-8; DACS-5 pre-winner gate",
        "The current outer bundle roles cannot represent a pre-agreement multi-candidate terminal.",
        case,
        "indeterminate",
    )

    case = make_case()
    case["listing"]["receipt"]["state"] = "accepted"
    case["listing"]["receipt"].pop("blockRef", None)
    refresh_receipt_evidence(case["listing"]["receipt"])
    add(
        "accepted-listing-cannot-cross-preverification-gate",
        "VPA-2",
        "Unlike reversible authorization progression, the pinned Listing must already have a verified finalized anchor before any verification side effect.",
        case,
        "fail",
    )

    case = make_case()
    case["authorizations"][0]["receipt"]["state"] = "accepted"
    case["authorizations"][0]["receipt"].pop("blockRef", None)
    refresh_receipt_evidence(case["authorizations"][0]["receipt"])
    case["auditProjection"].pop("outcome")
    case["auditProjection"].pop("phaseSummary")
    case["auditProjection"]["sessionState"] = "audit-pending"
    case["auditProjection"]["phaseDisposition"] = {
        "index": 0,
        "kind": "vet-credentials-provenanced",
        "outcome": "ok",
    }
    case["auditProjection"]["representationDisposition"] = "exclude-pending-finality"
    case["auditProjection"]["reputationDisposition"] = "exclude"
    add(
        "accepted-authorization-not-final-at-st11",
        "VPA-10; ST-11",
        "Accepted permits reversible verification, but ST-11 remains pending until finalized.",
        case,
        "indeterminate",
    )

    case = make_case()
    first = copy.deepcopy(case["composites"][0]["artifact"]["authorizationRef"])
    second = copy.deepcopy(case["composites"][1]["artifact"]["authorizationRef"])
    case["composites"][0]["artifact"]["authorizationRef"] = second
    case["composites"][1]["artifact"]["authorizationRef"] = first
    resign_envelope(case["composites"][0], "verifier-a-counterparty", COMPOSITE_DOMAIN)
    resign_envelope(case["composites"][1], "verifier-a-publisher", COMPOSITE_DOMAIN)
    sync_composite_surface_refs(case)
    add("swapped-authorization-refs", "PVC-2; PVC-3", "Valid outer signatures cannot repair swapped role references.", case, "fail")

    case = make_case()
    first_hash = case["authorizations"][0]["artifact"]["requirementHash"]
    second_hash = case["authorizations"][1]["artifact"]["requirementHash"]
    case["authorizations"][0]["artifact"]["requirementHash"] = second_hash
    case["authorizations"][1]["artifact"]["requirementHash"] = first_hash
    resign_envelope(case["authorizations"][0], "publisher", AUTH_DOMAIN)
    resign_envelope(case["authorizations"][1], "bidder-a", AUTH_DOMAIN)
    sync_surface_refs(case)
    add(
        "swapped-authorization-requirement-hashes",
        "VPA-7; PVC-3",
        "Genuinely re-signed opposite-direction authorizations cannot swap their distinct requirement hashes.",
        case,
        "fail",
    )

    case = make_case()
    auth = case["authorizations"][0]["artifact"]
    auth["requirement"]["preferredPresentation"] = "siwd"
    resign_envelope(case["authorizations"][0], "publisher", AUTH_DOMAIN)
    sync_surface_refs(case)
    add("authorization-requirement-body-hash-mismatch", "VPA-7", "The signed body changes while requirementHash stays pinned.", case, "fail")

    case = make_case()
    auth = case["authorizations"][0]["artifact"]
    auth["requirement"] = requirement("siwd")
    auth["requirementHash"] = hash_value(auth["requirement"])
    resign_envelope(case["authorizations"][0], "publisher", AUTH_DOMAIN)
    sync_surface_refs(case)
    add("listing-requirement-substitution-validly-signed", "VPA-4", "Publisher signature does not permit replacing the exact signed Listing body.", case, "fail")

    case = make_case()
    auth = case["authorizations"][0]["artifact"]
    auth["signature"]["signer"] = claim_for("bidder-a")
    resign_envelope(case["authorizations"][0], "bidder-a", AUTH_DOMAIN)
    sync_surface_refs(case)
    add("wrong-party-authorizer", "VPA-3; VPA-4", "The evaluated bidder cannot self-authorize the Listing requirement.", case, "fail")

    case = make_case()
    composite = case["composites"][0]["artifact"]
    composite["signature"]["signer"] = claim_for("attacker")
    resign_envelope(case["composites"][0], "attacker", COMPOSITE_DOMAIN)
    sync_composite_surface_refs(case)
    add("unauthorized-verifier-substitution", "VPA-8; PVC-4", "A valid signature by an unselected verifier is unauthorized.", case, "fail")

    case = make_case()
    del case["authorizations"][0]["artifact"]["verifierIdentity"]
    resign_envelope(case["authorizations"][0], "publisher", AUTH_DOMAIN)
    sync_surface_refs(case)
    add("missing-verifier-identity", "VPA-8", "A signer ClaimReference alone does not preserve the selected verifier bundle.", case, "fail")

    case = make_case()
    verifier = case["authorizations"][0]["artifact"]["verifierIdentity"]
    verifier["presentation"]["signatures"][0]["signature"] = "AAAA"
    resign_envelope(case["authorizations"][0], "publisher", AUTH_DOMAIN)
    sync_surface_refs(case)
    add("invalid-verifier-presentation", "VPA-8", "The authorizer cannot validate a verifier IdentityBundle with an invalid control proof.", case, "fail")

    case = make_case()
    verifier = case["authorizations"][0]["artifact"]["verifierIdentity"]
    verifier["sessionNonce"] = "00" * 16
    verifier["presentation"]["signatures"][0]["signature"] = sign_digest(
        "verifier-a-counterparty", BUNDLE_DOMAIN, bundle_hash(verifier)
    )
    resign_envelope(case["authorizations"][0], "publisher", AUTH_DOMAIN)
    sync_surface_refs(case)
    add(
        "verifier-presentation-wrong-session-nonce",
        "VPA-8; CORE SN-1..SN-4",
        "A valid verifier control proof from a different job-issued challenge is not the selected session verifier presentation.",
        case,
        "fail",
    )

    case = make_case()
    auth = case["authorizations"][0]["artifact"]
    auth["evaluatedIdentity"]["presentedAt"] += 1
    auth["evaluatedIdentity"]["presentation"]["signatures"][0]["signature"] = sign_digest(
        "bidder-a", BUNDLE_DOMAIN, bundle_hash(auth["evaluatedIdentity"])
    )
    auth["evaluatedBundleHash"] = bundle_hash(auth["evaluatedIdentity"])
    resign_envelope(case["authorizations"][0], "publisher", AUTH_DOMAIN)
    sync_surface_refs(case)
    add("evaluated-identity-body-substitution-replay", "VPA-6; PVC-5", "A valid, re-signed changed body no longer equals the admitted session bundle and cannot reuse its result.", case, "fail")

    case = make_case()
    case["authorizations"][0]["artifact"]["evaluatedBundleHash"] = "00" * 32
    resign_envelope(case["authorizations"][0], "publisher", AUTH_DOMAIN)
    sync_surface_refs(case)
    add("evaluated-bundle-hash-mismatch", "VPA-6", "The signed evaluated body hash must recompute exactly.", case, "fail")

    case = make_case("procurement", candidate_decisions=("pass", "fail"))
    omitted_context = case["candidates"][1]["presentedBy"]
    case["authorizations"] = [item for item in case["authorizations"] if item["artifact"]["counterpartyContext"] != omitted_context]
    case["composites"] = [item for item in case["composites"] if item["artifact"]["counterpartyContext"] != omitted_context]
    sync_composite_surface_refs(case)
    add("missing-whole-bidder-pair", "VPA-2; VPA-9; PVPC-8", "Shared roster count/hash detects omission of both directions for a bidder.", case, "fail")

    case = make_case("procurement")
    case["authorizations"][0]["artifact"]["counterpartyCount"] = 1
    resign_envelope(case["authorizations"][0], "publisher", AUTH_DOMAIN)
    sync_surface_refs(case)
    add("roster-count-disagreement", "VPA-2; VPA-9", "Every authorization must carry the same positive roster count and commitment.", case, "fail")

    case = make_case("procurement")
    auth = case["authorizations"][2]["artifact"]
    auth["counterpartyContext"] = case["candidates"][0]["presentedBy"]
    resign_envelope(case["authorizations"][2], "publisher", AUTH_DOMAIN)
    # Preserve both artifacts at their now-colliding native tuple to expose duplication.
    case["auditProjection"]["vetRecords"] = sorted_vet_refs(case)
    add("cross-bidder-context-substitution", "VPA-3; VPA-9", "A candidate body cannot be moved under another candidate context.", case, "fail")

    case = make_case()
    case["authorizations"][0]["receipt"]["logicalAddress"] = "dacs2:vet-authorization:wrong"
    case["authorizations"][0]["receipt"]["transactionRef"]["value"] = sha256_hex(
        (
            "tx:dacs2:vet-authorization:wrong:"
            + case["authorizations"][0]["receipt"]["contentHash"]
        ).encode("utf-8")
    )
    refresh_receipt_evidence(case["authorizations"][0]["receipt"])
    add("authorization-wrong-logical-receipt", "VPA-10", "Native resolution does not excuse a receipt bound to the wrong logical tuple.", case, "fail")

    case = make_case()
    case["authorizations"][0]["ref"]["anchor"]["locator"] = native_locator("wrong-native")
    sync_surface_refs(case)
    add("authorization-wrong-native-ref", "VPA-10", "AttestationRef locator must equal the authenticated receipt native address.", case, "fail")

    case = make_case()
    case["composites"][0]["receipt"]["logicalAddress"] = "dacs2:provenanced-composite:wrong"
    case["composites"][0]["receipt"]["transactionRef"]["value"] = sha256_hex(
        (
            "tx:dacs2:provenanced-composite:wrong:"
            + case["composites"][0]["receipt"]["contentHash"]
        ).encode("utf-8")
    )
    refresh_receipt_evidence(case["composites"][0]["receipt"])
    add("composite-wrong-logical-receipt", "PVC-6", "Composite receipt logical address must derive from its signed tuple.", case, "fail")

    case = make_case()
    old_ref = copy.deepcopy(case["composites"][0]["ref"])
    case["composites"][0]["ref"]["anchor"]["locator"] = native_locator("wrong-native")
    replace_projected_ref(case, old_ref, case["composites"][0]["ref"])
    add("composite-wrong-native-ref", "PVC-6", "Composite ref must resolve the receipt-authenticated native address.", case, "fail")

    case = make_case()
    case["composites"][0]["artifact"]["authorizationRef"]["contentHash"] = "00" * 32
    resign_envelope(case["composites"][0], "verifier-a-counterparty", COMPOSITE_DOMAIN)
    sync_composite_surface_refs(case)
    add("authorization-ref-content-hash-mismatch", "PVC-2", "A Composite authorizationRef with a generic wrong content hash cannot resolve the signed authorization.", case, "fail")

    case = make_case()
    auth_item = case["authorizations"][0]
    wrong_envelope = envelope(
        auth_item["artifact"],
        auth_logical(auth_item["artifact"]),
        state=auth_item["receipt"]["state"],
        full_signed_content=True,
    )
    auth_item.clear()
    auth_item.update(wrong_envelope)
    sync_surface_refs(case)
    add("authorization-full-signed-hash-is-not-content-hash", "VPA-10; PVC-2", "The VRA content hash follows CORE §B.2 and omits the signature; a full-signed hash cannot replace it.", case, "fail")

    case = make_case()
    composite_item = case["composites"][0]
    wrong_envelope = envelope(
        composite_item["artifact"],
        composite_logical(composite_item["artifact"]),
        state=composite_item["receipt"]["state"],
        full_signed_content=True,
    )
    composite_item.clear()
    composite_item.update(wrong_envelope)
    sync_composite_surface_refs(case)
    add("composite-full-signed-hash-is-not-content-hash", "PVC-6", "The PCR content hash follows CORE §B.2 and omits the signature; a full-signed hash cannot replace it.", case, "fail")

    case = make_case()
    case["authorizations"][0]["artifact"]["recordVersion"] = "1"
    resign_envelope(case["authorizations"][0], "publisher", AUTH_DOMAIN)
    sync_surface_refs(case)
    add("authorization-both-discriminators", "VPA-1; CORE §11.1.2", "Both legacy and authorization discriminators are invalid.", case, "fail")

    case = make_case()
    case["composites"][0]["artifact"]["recordVersion"] = "1"
    resign_envelope(case["composites"][0], "verifier-a-counterparty", COMPOSITE_DOMAIN)
    sync_composite_surface_refs(case)
    add("composite-both-discriminators", "PVC-1; CORE §11.1.2", "Both provenanced and legacy Composite discriminators are invalid.", case, "fail")

    case = make_case()
    old_ref = copy.deepcopy(case["composites"][0]["ref"])
    case["composites"][0] = make_legacy_composite(
        case["composites"][0], "verifier-a-counterparty"
    )
    replace_projected_ref(case, old_ref, case["composites"][0]["ref"])
    add("new-phase-cannot-use-legacy-composite", "PVC-1; PVPC-1", "The signed new phase cannot downgrade to a legacy Composite.", case, "fail")

    case = make_case()
    case["listing"]["artifact"]["pipeline"][0] = {"kind": "vet-credentials"}
    resign_listing_and_relink(case)
    case["phaseKind"] = "vet-credentials"
    case["auditProjection"]["phaseSummary"]["kind"] = "vet-credentials"
    add("legacy-phase-cannot-use-provenanced-record", "CORE §11.1.2; DACS-5 §10.4.3", "A genuinely signed legacy-phase Listing cannot consume the new authorization or provenanced Composite types.", case, "fail")

    case = make_case()
    duplicate = copy.deepcopy(case["authorizations"][0])
    duplicate["artifact"]["authorizedAt"] += 1
    resign_envelope(duplicate, "publisher", AUTH_DOMAIN, logical=case["authorizations"][0]["receipt"]["logicalAddress"])
    case["authorizations"].append(duplicate)
    case["auditProjection"]["vetRecords"] = sorted_vet_refs(case)
    add("same-logical-address-different-content", "VPA-9", "Timestamp does not choose between different immutable bytes at one tuple address.", case, "fail")

    case = make_case("procurement")
    winner = case["agreementProjection"]["winnerContext"]
    case["agreementProjection"]["parties"] = [
        party for party in case["agreementProjection"]["parties"] if party["primaryClaim"] != winner
    ]
    add("unvetted-winning-bidder", "PVPC-7; DACS-3 check 10", "The agreement cannot omit its winner's exact counterparty record.", case, "fail")

    case = make_case("procurement")
    loser = case["vetContextDelta"]["eligibleCounterparties"][1]
    for party in case["agreementProjection"]["parties"]:
        if party["primaryClaim"] == loser:
            party["vetRecordRef"]["contentHash"] = "00" * 32
    add("unvetted-losing-bidder", "PVPC-7; DACS-3 check 10", "Every all-pass losing candidate needs its own exact record.", case, "fail")

    case = make_case("procurement")
    loser = case["vetContextDelta"]["eligibleCounterparties"][1]
    case["agreementProjection"]["parties"] = [
        party for party in case["agreementProjection"]["parties"] if party["primaryClaim"] != loser
    ]
    add("all-pass-loser-omitted-from-agreement", "DACS-3 check 10; ST-11", "Agreement candidate contexts must equal the eligible set in both directions.", case, "fail")

    case = make_case("procurement")
    winner = case["agreementProjection"]["winnerContext"]
    loser = case["vetContextDelta"]["eligibleCounterparties"][1]
    for party in case["agreementProjection"]["parties"]:
        if party["primaryClaim"] == case["publisher"]["presentedBy"]:
            party["vetRecordRef"] = copy.deepcopy(composite_for(case, loser, "publisher")["ref"])
    add("publisher-ref-bound-to-loser-context", "PVPC-7; DACS-3 check 10", "The publisher's singular AgreementParty ref must use the winner context.", case, "fail")

    case = make_case("procurement")
    for party in case["agreementProjection"]["parties"]:
        if party["role"] == "buyer":
            party["role"] = "seller"
        elif party["role"] == "seller":
            party["role"] = "buyer"
    add("procurement-agreement-role-inversion", "DACS-3 §8.5.2 check 10", "Publisher and winning supplier cannot use demand-mode seller/buyer roles.", case, "fail")

    case = make_case("procurement", candidate_decisions=("pass", "fail"))
    failed_context = case["candidates"][1]["presentedBy"]
    case["vetContextDelta"]["eligibleCounterparties"].append(failed_context)
    case["vetContextDelta"]["eligibleCounterparties"].sort(key=lambda value: value.encode("utf-8"))
    sync_vet_prior_output(case)
    add("signed-fail-cannot-be-admitted", "PVPC-6; PVPC-10", "A validly signed fail record remains audit evidence and cannot enter the eligible set.", case, "fail")

    case = make_case("procurement", candidate_decisions=("pass", "error"))
    pending_context = case["candidates"][1]["presentedBy"]
    retry_policy = {
        "retryClass": "transient",
        "retryBudget": 2,
        "retryOnIndeterminate": False,
    }
    case["composites"] = []
    case["vetContextDelta"] = None
    case["negotiateInput"] = None
    case["agreementProjection"] = None
    case["vetRetryProjection"] = {
        "projectionKind": "vet-retry-pending",
        "counterpartyContext": pending_context,
        "evaluatedRole": "counterparty",
        "decision": "error",
        "retryState": "pending",
        "attempt": 1,
        "emittedCompositeCount": 0,
        "phaseOutputEmitted": False,
        "admissionEmitted": False,
        "agreementEmitted": False,
        "bundleEmitted": False,
        "pinnedRetryPolicyProjection": {
            "projectionKind": "pinned-recipe-retry-policy",
            "recipeRegistryVersion": RECIPE_REGISTRY_VERSION,
            "scheme": "key",
            "recipeVersion": 1,
            "policy": retry_policy,
            "policyHash": hash_value(retry_policy),
        },
    }
    case["auditProjection"].pop("outcome")
    case["auditProjection"].pop("phaseSummary")
    case["auditProjection"]["sessionState"] = "vet-pending"
    case["auditProjection"]["phaseDisposition"] = {
        "index": 0,
        "kind": "vet-credentials-provenanced",
        "decision": "error",
        "retryState": "pending",
    }
    case["auditProjection"]["winnerMappingPresent"] = False
    case["auditProjection"]["faultedParty"] = None
    case["auditProjection"]["representationDisposition"] = "exclude-retryable-or-indeterminate"
    case["auditProjection"]["reputationDisposition"] = "exclude"
    case["auditProjection"]["vetRecords"] = sorted_vet_refs(case)
    add("retryable-error-bidder-cannot-be-silently-excluded", "PVPC-6", "A verifier/parser error follows its retry path and blocks phase admission rather than becoming bidder censorship.", case, "indeterminate")

    case = make_case()
    case["auditProjection"]["vetRecords"] = list(reversed(case["auditProjection"]["vetRecords"]))
    add("vet-record-order-is-canonical", "DACS-5 §10.4.3", "Scheduler or array order cannot alter the signed mixed-artifact list.", case, "fail")

    case = make_case()
    case["authorizations"][0]["artifact"]["recipeRegistryVersion"] += 1
    resign_envelope(case["authorizations"][0], "publisher", AUTH_DOMAIN)
    sync_surface_refs(case)
    add("authorization-registry-pin-mismatch", "VPA-2; PVPC-11", "Replay must use the exact signed session-start recipe registry pin.", case, "fail")

    case = make_case("procurement")
    publisher_auth = next(
        item for item in case["authorizations"]
        if item["artifact"]["evaluatedRole"] == "publisher"
        and item["artifact"]["counterpartyContext"] == case["candidates"][1]["presentedBy"]
    )
    changed = copy.deepcopy(case["publisher"])
    changed["presentedAt"] += 1
    changed["presentation"]["signatures"][0]["signature"] = sign_digest(
        "publisher", BUNDLE_DOMAIN, bundle_hash(changed)
    )
    publisher_auth["artifact"]["evaluatedIdentity"] = changed
    publisher_auth["artifact"]["evaluatedBundleHash"] = bundle_hash(changed)
    resign_envelope(publisher_auth, "bidder-b", AUTH_DOMAIN)
    sync_surface_refs(case)
    add("publisher-body-differs-across-contexts", "VPA-9; DACS-3 ingress", "One publisher primary claim cannot hide different signed bodies across bidder contexts.", case, "fail")

    case = make_case(candidate_decisions=("fail",), outcome="failed-counterparty")
    case["auditProjection"]["phaseSummary"]["errorClass"] = "permanent"
    add("decision-errorclass-mismatch", "PVPC-10; DACS-5 outcome mapping", "A conclusive attributable fail cannot be relabelled as permanent self failure.", case, "fail")

    case = make_case()
    case["authorizations"][0]["receipt"]["writer"] = claim_for("attacker")
    add(
        "authorization-receipt-writer-proof-tamper",
        "VPA-10; CORE SR2-5",
        "Changing the receipt-authenticated writer tuple without a new valid substrate proof fails; no equality with the artifact signer is implied.",
        case,
        "fail",
    )

    case = make_case()
    case["composites"][0]["receipt"]["transactionRef"]["value"] = "00" * 32
    refresh_receipt_evidence(case["composites"][0]["receipt"])
    add("composite-receipt-transaction-mismatch", "PVC-6; CORE SR2-5", "The fixture proof and deterministic transaction tuple must bind the Composite.", case, "fail")

    case = make_case()
    case["authorizations"][0]["receipt"]["nonce"] = "1"
    refresh_receipt_evidence(case["authorizations"][0]["receipt"])
    add("authorization-receipt-nonce-mismatch", "VPA-10; CORE SR2-5", "The applicable writer nonce is part of the immutable receipt tuple.", case, "fail")

    case = make_case()
    resign_envelope(case["authorizations"][0], "publisher", COMPOSITE_DOMAIN)
    sync_surface_refs(case)
    add("authorization-cross-domain-signature", "VPA-3; CORE SIG-1/SIG-2", "Correct-key bytes over the PCR domain do not authenticate a VRA.", case, "fail")

    case = make_case()
    resign_envelope(case["composites"][0], "verifier-a-counterparty", AUTH_DOMAIN)
    sync_composite_surface_refs(case)
    add("composite-cross-domain-signature", "PVC-4; CORE SIG-1/SIG-2", "Correct-key bytes over the VRA domain do not authenticate a PCR.", case, "fail")

    case = make_case()
    case["authorizations"][0]["artifact"]["jobId"] = "01K2VPA9999999999999999999"
    resign_envelope(case["authorizations"][0], "publisher", AUTH_DOMAIN)
    sync_surface_refs(case)
    add("cross-session-authorization-substitution", "VPA-2; PVC-3", "A genuine authorization for another job cannot enter this pinned session.", case, "fail")

    case = make_case()
    publisher_result = case["verificationResults"][0]
    candidate = make_identity("publisher", session=True, verified_by=result_ref(publisher_result))
    candidate["presentedAt"] += 1
    candidate["presentation"]["signatures"][0]["signature"] = sign_digest(
        "publisher", BUNDLE_DOMAIN, bundle_hash(candidate)
    )
    case["candidates"] = [candidate]
    context = candidate["presentedBy"]
    committed = hash_value(roster_entries([candidate]))
    for item in case["authorizations"]:
        auth = item["artifact"]
        auth["counterpartyContext"] = context
        auth["counterpartySetHash"] = committed
        if auth["evaluatedRole"] == "counterparty":
            auth["evaluatedIdentity"] = copy.deepcopy(candidate)
            auth["evaluatedParty"] = context
            auth["evaluatedBundleHash"] = bundle_hash(candidate)
            auth["authorizerIdentity"] = copy.deepcopy(case["publisher"])
        else:
            auth["evaluatedIdentity"] = copy.deepcopy(case["publisher"])
            auth["evaluatedParty"] = case["publisher"]["presentedBy"]
            auth["evaluatedBundleHash"] = bundle_hash(case["publisher"])
            auth["authorizerIdentity"] = copy.deepcopy(candidate)
        auth["signature"]["signer"] = claim_for("publisher")
        resign_envelope(item, "publisher", AUTH_DOMAIN)
    for item in case["composites"]:
        record = item["artifact"]
        auth = next(auth_item for auth_item in case["authorizations"] if auth_item["artifact"]["evaluatedRole"] == record["evaluatedRole"])
        source = auth["artifact"]
        record["counterpartyContext"] = context
        record["evaluatedParty"] = source["evaluatedParty"]
        record["bundleHash"] = source["evaluatedBundleHash"]
        record["authorizationRef"] = copy.deepcopy(auth["ref"])
        seed = "verifier-a-" + record["evaluatedRole"]
        resign_envelope(item, seed, COMPOSITE_DOMAIN)
    case["phaseInput"]["invocations"] = [
        {
            "counterpartyContext": context,
            "evaluatedRole": role,
            "bundleToVet": copy.deepcopy(next(item for item in case["authorizations"] if item["artifact"]["evaluatedRole"] == role)["artifact"]["evaluatedIdentity"]),
            "authorizationRef": copy.deepcopy(next(item for item in case["authorizations"] if item["artifact"]["evaluatedRole"] == role)["ref"]),
        }
        for role in ("counterparty", "publisher")
    ]
    case["phaseInput"]["sessionContext"] = make_session_context(
        case["mode"],
        case["jobId"],
        case["listing"],
        case["publisher"],
        case["candidates"],
        {},
    )
    case["vetContextDelta"]["eligibleCounterparties"] = [context]
    case["agreementProjection"] = None
    case["auditProjection"]["winnerMappingPresent"] = False
    sync_composite_surface_refs(case)
    add("same-primary-different-session-bodies", "VPA-3; VPA-9", "Role-bearing addresses remain distinct, but opposite commerce parties must have distinct primary claims and cannot hide body equivocation.", case, "fail")

    case = make_case()
    case["listing"]["artifact"]["validity"]["notAfter"] = NOW - 1
    resign_listing_and_relink(case)
    add(
        "expired-signed-listing-rejected",
        "VPA-2; DACS-1 listing validation",
        "A genuine, fully relinked chain cannot use a Listing that is expired at the fixture session time.",
        case,
        "fail",
    )

    case = make_case()
    case["listing"]["artifact"]["dacsVersion"] = "2"
    resign_listing_and_relink(case)
    add(
        "unsupported-listing-major-version",
        "VPA-2; DACS-1 listing validation",
        "A genuine, fully relinked Listing from an unsupported major version is rejected before provenance use.",
        case,
        "fail",
    )

    case = make_case()
    case["authorizations"][0]["artifact"]["counterpartyCount"] = True
    resign_envelope(case["authorizations"][0], "publisher", AUTH_DOMAIN)
    sync_surface_refs(case)
    add(
        "authorization-boolean-count-is-not-an-integer",
        "VPA-2; VPA-9",
        "JSON true cannot satisfy the positive safe-integer counterpartyCount even in runtimes where booleans compare equal to one.",
        case,
        "fail",
    )

    case = make_case()
    case["listing"]["artifact"]["seller"]["identity"] = make_identity(
        "attacker", session=False
    )
    case["listing"]["artifact"]["signature"]["signer"] = claim_for("attacker")
    resign_listing_and_relink(case)
    add(
        "listing-publisher-session-party-mismatch",
        "VPA-2; VPA-4",
        "A genuine attacker-published Listing cannot be relinked to authorizations whose authenticated session publisher has a different presentedBy claim.",
        case,
        "fail",
    )

    case = make_case()
    case["listing"]["artifact"]["pipeline"][0] = {"kind": "vet-credentials"}
    resign_listing_and_relink(case)
    add(
        "listing-missing-provenanced-vet-phase",
        "PVPC-1; DACS-3 PS-1",
        "A relinked Listing selecting only the legacy Vet phase cannot authorize the provenanced handler.",
        case,
        "fail",
    )

    case = make_case()
    case["listing"]["artifact"]["pricing"]["price"]["amount"] = "-1"
    resign_listing_and_relink(case)
    add(
        "fixed-price-must-be-positive",
        "DACS-3 PS-3; DACS-4 PriceTerm",
        "A valid Listing signature and provenance chain do not make a non-positive fixed price conformant.",
        case,
        "fail",
    )

    case = make_case("procurement")
    case["negotiateInput"]["sessionContext"]["jobId"] = "01K2VPA9999999999999999999"
    add(
        "sealed-negotiate-session-context-job-mismatch",
        "DACS-3 provenanced ingress",
        "The sealed handoff's complete SessionContext must preserve the exact job, Listing tuple, registry pins, parties, prior Vet output, signer, and start time.",
        case,
        "fail",
    )

    case = make_case()
    case["auditProjection"]["phaseSummary"]["kind"] = "vet-credentials"
    add(
        "audit-phase-kind-mismatch",
        "ST-11",
        "The audit projection must identify the provenanced phase whose records it retains.",
        case,
        "fail",
    )

    case = make_case()
    case["agreementProjection"]["parties"][0]["bundleHash"] = "00" * 32
    add(
        "agreement-party-bundle-hash-mismatch",
        "DACS-3 §8.5.2 check 10",
        "Every projected AgreementParty hash must bind the exact authenticated publisher or counterparty bundle.",
        case,
        "fail",
    )

    return vectors


def build_document() -> dict:
    expanded_vectors = build_vectors()
    vectors = compact_vectors(expanded_vectors)
    return {
        "set": "vet-provenance-v0.6",
        "spec": "DACS-2 VPA-1..VPA-10, PVC-1..PVC-6, PVPC-1..PVPC-11; DACS-3 provenanced ingress/check 10; DACS-5 ST-11/vetRecords projection",
        "scope": "Signed Vet provenance, fanout admission, agreement binding, and audit projection; assumes baseline DACS-1 Listing/PhaseStep schema validation and is not a complete outer AttestationBundle fixture",
        "provenance": "Deterministic in-repo generator; public Ed25519 test seeds; RFC 8785 JCS hashes; fixture strings are ASCII",
        "representation": {
            "kind": "two-literal-bases-with-rfc6902-subset-patches",
            "baseVectors": list(BASE_VECTOR_NAMES),
            "baseDepth": 1,
            "patchOperations": ["add", "remove", "replace"],
            "hashScope": "represented compact vectors array",
            "expandedHashScope": "semantic vectors array with every patch expanded to its full input and representation-only members removed",
            "expandedInputHashScope": "RFC 8785 JCS hash of each vector's fully expanded input",
        },
        "domains": {
            "listing": LISTING_DOMAIN,
            "identityBundle": BUNDLE_DOMAIN,
            "verifyResult": VERIFY_DOMAIN,
            "legacyComposite": LEGACY_COMPOSITE_DOMAIN,
            "authorization": AUTH_DOMAIN,
            "provenancedComposite": COMPOSITE_DOMAIN,
        },
        "publicTestSeeds": {name: seed.hex() for name, seed in SEEDS.items()},
        "publicKeys": {claim_for(name): public_hex(name) for name in SEEDS},
        "count": len(vectors),
        "hash": hashlib.sha256(compact_json_bytes(vectors)).hexdigest(),
        "expandedHash": hashlib.sha256(
            compact_json_bytes(expanded_vectors)
        ).hexdigest(),
        "vectors": vectors,
    }


def rendered() -> str:
    return json.dumps(build_document(), indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    wanted = rendered()
    if args.write:
        OUTPUT.write_text(wanted, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    try:
        current = OUTPUT.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"ERROR: missing {OUTPUT.relative_to(ROOT)}; run with --write")
        return 1
    if current != wanted:
        print(f"ERROR: stale {OUTPUT.relative_to(ROOT)}; run with --write")
        return 1
    print(f"vet provenance vectors OK ({build_document()['count']} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
