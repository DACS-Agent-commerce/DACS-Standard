#!/usr/bin/env python3
"""Generate deterministic #390 identity-bound agreement conformance vectors."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import jcs
from run_lifecycle_walkthrough import public_key, sign_ed25519, verify_ed25519


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance/vectors/security/identity-bundle-hash-binding-v0.1.json"
BASE_SHA = "3426faaebc09948d57a3a6d30fd6795df579b68f"
NOW = 1_900_000_000_000
WRONG_HASH = "11" * 32

BUNDLE_DOMAIN = "dacs-bundle-presentation:v1:"
LISTING_DOMAIN = "dacs-listing:v1:"
COMPOSITE_DOMAIN = "dacs-composite:v1:"
COMMITMENT_DOMAIN = "dacs-commitment:v1:"
FINALITY_COMMITMENT_DOMAIN = "dacs-finality-commitment:v1:"
RAIL_DOMAIN = "dacs-rail:v1:"
TERMINAL_DOMAIN = "dacs-bundle:v1:"
DISPOSITION_DOMAIN = "dacs-prior-payment-disposition:v1:"
RECEIPT_EVIDENCE_DOMAIN = "dacs-390-anchor-receipt:v1:"

ARTIFACTS = (
    "agreement",
    "payeeBoundAgreement",
    "identityBoundAgreement",
    "identityBoundPayeeAgreement",
)
DISCRIMINATORS = {
    "agreement": "agreementVersion",
    "payeeBoundAgreement": "payeeBoundAgreementVersion",
    "identityBoundAgreement": "identityBoundAgreementVersion",
    "identityBoundPayeeAgreement": "identityBoundPayeeAgreementVersion",
}
PHASES = {
    "agreement": "commit-agreement",
    "payeeBoundAgreement": "commit-payee-bound-agreement",
    "identityBoundAgreement": "commit-identity-bound-agreement",
    "identityBoundPayeeAgreement": "commit-identity-bound-payee-agreement",
}
AGREEMENT_DOMAINS = {
    "agreement": "dacs-agreement:v1:",
    "payeeBoundAgreement": "dacs-payee-bound-agreement:v1:",
    "identityBoundAgreement": "dacs-identity-bound-agreement:v1:",
    "identityBoundPayeeAgreement": "dacs-identity-bound-payee-agreement:v1:",
}
STRONG_ARTIFACTS = {"identityBoundAgreement", "identityBoundPayeeAgreement"}
PAYEE_ARTIFACTS = {"payeeBoundAgreement", "identityBoundPayeeAgreement"}
RAIL_REF = {"railId": "demos-native:DEM", "railVersion": 1}
JOB_IDS = {
    "agreement": "01KTY8ZJ00CW7KSECW3FS6PQ0A",
    "payeeBoundAgreement": "01KTY8ZJ00CW7KSECW3FS6PQ0B",
    "identityBoundAgreement": "01KTY8ZJ00CW7KSECW3FS6PQ0C",
    "identityBoundPayeeAgreement": "01KTY8ZJ00CW7KSECW3FS6PQ0D",
    "prior": "01KTY8ZJ00CW7KSECW3FS6PQ0E",
    "replacement": "01KTY8ZJ00CW7KSECW3FS6PQ0F",
}


def canonical_bytes(value: object) -> bytes:
    return jcs.canonicalize(value).encode("utf-8")


def hash_hex(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def private_key(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def public_hex(key: bytes) -> str:
    return public_key(key).hex()


KEYS = {
    role: private_key(f"dacs-390-{role}")
    for role in ("buyer", "seller", "orchestrator")
}
CLAIMS = {role: f"key:{public_hex(key)}" for role, key in KEYS.items()}


def unsigned(value: dict[str, Any], field: str) -> dict[str, Any]:
    return {key: copy.deepcopy(item) for key, item in value.items() if key != field}


def component_signature(
    value: dict[str, Any], domain: str, role: str, *, signature_field: str = "signature"
) -> dict[str, str]:
    payload = (domain + hash_hex(unsigned(value, signature_field))).encode("ascii")
    return {
        "algorithm": "ed25519",
        "signer": CLAIMS[role],
        "value": b64url(sign_ed25519(KEYS[role], payload)),
    }


def identity_bundle(role: str, nonce: str) -> dict[str, Any]:
    bundle: dict[str, Any] = {
        "bundleVersion": "1",
        "presentedBy": CLAIMS[role],
        "presentedAt": NOW - 10_000,
        "sessionNonce": nonce,
        "claims": [{"ref": CLAIMS[role], "metadata": {"fixture": "dacs-390"}}],
    }
    digest = hash_hex(bundle)
    bundle["presentation"] = {
        "kind": "per-claim",
        "signatures": [{
            "ref": CLAIMS[role],
            "signature": b64url(
                sign_ed25519(KEYS[role], (BUNDLE_DOMAIN + digest).encode("ascii"))
            ),
        }],
    }
    return bundle


def resign_bundle(bundle: dict[str, Any], role: str) -> None:
    digest = hash_hex(unsigned(bundle, "presentation"))
    bundle["presentation"] = {
        "kind": "per-claim",
        "signatures": [{
            "ref": CLAIMS[role],
            "signature": b64url(
                sign_ed25519(KEYS[role], (BUNDLE_DOMAIN + digest).encode("ascii"))
            ),
        }],
    }


def artifact_ref(value: dict[str, Any], label: str) -> dict[str, Any]:
    return {
        "anchor": {
            "kind": "storage-program",
            "locator": f"demos:dacs-390:{label}",
        },
        "contentHash": hash_hex(value),
    }


def composite_record(role: str, bundle: dict[str, Any], job_id: str) -> dict[str, Any]:
    record: dict[str, Any] = {
        "recordVersion": "1",
        "jobId": job_id,
        "evaluatedParty": CLAIMS[role],
        "bundleHash": hash_hex(unsigned(bundle, "presentation")),
        "requirementHash": hashlib.sha256(b"dacs-390-requirement").hexdigest(),
        "freshness": [],
        "supplementary": [],
        "dealSpecific": [],
        "overallDecision": "pass",
        "generatedAt": NOW - 8_000,
    }
    record["signature"] = component_signature(record, COMPOSITE_DOMAIN, "orchestrator")
    return record


def listing(phase: str, seller_bundle: dict[str, Any], job_id: str) -> dict[str, Any]:
    deliverable = {"kind": "storage-program", "accessModel": "public"}
    value: dict[str, Any] = {
        "dacsVersion": "1",
        "listingVersion": 1,
        "listingId": f"dacs-390-{job_id}",
        "seller": {
            "identity": copy.deepcopy(seller_bundle),
            "displayName": "DACS #390 seller",
        },
        "offering": {
            "title": "Identity-bound fixture",
            "description": "Deterministic offline conformance fixture",
            "category": "conformance.identity",
            "tags": ["dacs-390"],
            "deliverable": deliverable,
        },
        "buyerRequirement": {"requirementVersion": "1", "required": []},
        "pipeline": [
            {"kind": "vet-credentials"},
            {"kind": phase},
            {"kind": "pay-dem", "parameters": {"rail": RAIL_REF["railId"]}},
            {"kind": "deliver-storage-program"},
        ],
        "pricing": {
            "kind": "fixed",
            "price": {"amount": "1", "currency": "DEM"},
        },
        "acceptedRails": [copy.deepcopy(RAIL_REF)],
        "terms": {"deadlineSecAfterCommit": 3600},
        "validity": {"notBefore": NOW - 100_000, "notAfter": NOW + 100_000},
    }
    value["signature"] = component_signature(value, LISTING_DOMAIN, "seller")
    return value


def listing_ref(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "listingId": value["listingId"],
        "version": value["listingVersion"],
        "contentHash": hash_hex(unsigned(value, "signature")),
    }


def agreement(
    artifact: str,
    job_id: str,
    signed_listing: dict[str, Any],
    bundles: dict[str, dict[str, Any]],
    records: dict[str, dict[str, Any]],
    *,
    prior_disposition_ref: dict[str, Any] | None = None,
) -> dict[str, Any]:
    strong = artifact in STRONG_ARTIFACTS
    parties = []
    for role in ("buyer", "seller"):
        digest = hash_hex(unsigned(bundles[role], "presentation"))
        parties.append({
            "role": role,
            "bundleHash": digest if strong else f"sha256:{digest}",
            "primaryClaim": CLAIMS[role],
            "vetRecordRef": artifact_ref(records[role], f"{job_id}-{role}-cvr"),
        })
    terms: dict[str, Any] = {
        "deliverable": {
            "deliverableType": "storage-program",
            "hash": hash_hex(signed_listing["offering"]["deliverable"]),
        },
        "price": {"amount": "1", "currency": "DEM"},
        "rail": copy.deepcopy(RAIL_REF),
        "deadline": NOW + 50_000,
    }
    if artifact in PAYEE_ARTIFACTS:
        terms["payoutBindings"] = [{
            "railId": RAIL_REF["railId"],
            "phaseIndex": 2,
            "payeeAddress": CLAIMS["seller"],
        }]
    if prior_disposition_ref is not None:
        terms["priorPaymentDispositionRef"] = copy.deepcopy(prior_disposition_ref)
    value: dict[str, Any] = {
        DISCRIMINATORS[artifact]: "1",
        "jobId": job_id,
        "listingRef": listing_ref(signed_listing),
        "parties": parties,
        "terms": terms,
        "derivedFromPattern": "fixed-price",
        "generatedAt": NOW - 5_000,
        "signatures": [],
    }
    resign_agreement(value, artifact)
    return value


def resign_agreement(
    value: dict[str, Any], artifact: str, *, signing_as: str | None = None
) -> None:
    domain = AGREEMENT_DOMAINS[signing_as or artifact]
    digest = hash_hex(unsigned(value, "signatures"))
    value["signatures"] = [
        {
            "party": CLAIMS[role],
            "algorithm": "ed25519",
            "value": b64url(
                sign_ed25519(KEYS[role], (domain + digest).encode("ascii"))
            ),
        }
        for role in ("buyer", "seller")
    ]


def commitments(value: dict[str, Any], job_id: str) -> dict[str, Any]:
    signing_parties = [
        party["primaryClaim"]
        for party in value["parties"]
        if party.get("role") in {"buyer", "seller"}
    ]
    common = {
        "jobId": job_id,
        "agreementHash": hash_hex(unsigned(value, "signatures")),
        "listingRef": copy.deepcopy(value["listingRef"]),
        "parties": signing_parties,
        "pattern": "fixed-price",
    }
    legacy_record = {"dacsVersion": "1", **common, "committedAt": NOW}
    legacy_signature = component_signature(
        {**legacy_record, "signature": {}}, COMMITMENT_DOMAIN, "orchestrator"
    )
    finality_record: dict[str, Any] = {
        "finalityCommitmentVersion": "1",
        **common,
        "createdAt": NOW - 1_000,
    }
    finality_record["signature"] = component_signature(
        finality_record, FINALITY_COMMITMENT_DOMAIN, "orchestrator"
    )
    return {
        "legacy": {
            "record": legacy_record,
            "externalSignature": legacy_signature,
            "anchorReceipt": finalized_receipt(legacy_record, job_id),
        },
        "finality": {
            "record": finality_record,
            "anchorReceipt": finalized_receipt(finality_record, job_id),
        },
    }


def finalized_receipt(record: dict[str, Any], job_id: str) -> dict[str, Any]:
    content_hash = hash_hex(record)
    receipt: dict[str, Any] = {
        "receiptVersion": "1",
        "substrate": "dacs-390-fixture",
        "finalityProfile": "deterministic-test-finality",
        "logicalAddress": f"dacs3:commit:{job_id}",
        "nativeAddress": f"fixture:{content_hash}",
        "contentHash": content_hash,
        "transactionRef": {
            "kind": "fixture",
            "value": hashlib.sha256(f"tx:{content_hash}".encode()).hexdigest(),
        },
        "writer": CLAIMS["orchestrator"],
        "state": "finalized",
        "observationDisposition": "established",
        "observedAt": NOW + 1_000,
        "blockRef": {
            "id": hashlib.sha256(f"block:{job_id}".encode()).hexdigest(),
            "height": "390",
            "timestamp": NOW,
        },
        "evidence": {},
    }
    payload = (RECEIPT_EVIDENCE_DOMAIN + hash_hex(unsigned(receipt, "evidence"))).encode(
        "ascii"
    )
    receipt["evidence"] = {
        "kind": "ed25519",
        "value": b64url(sign_ed25519(KEYS["orchestrator"], payload)),
    }
    return receipt


def party_carrier(role: str, bundle: dict[str, Any]) -> dict[str, Any]:
    return {
        "role": role,
        "bundleHash": hash_hex(unsigned(bundle, "presentation")),
        "primaryClaim": CLAIMS[role],
    }


def rail_definition() -> dict[str, Any]:
    value: dict[str, Any] = {
        "railVersion": 1,
        "railId": RAIL_REF["railId"],
        "railType": "demos-native",
        "asset": {"kind": "native-dem", "symbol": "DEM", "decimals": 9},
        "network": {"kind": "demos"},
        "phaseHandler": "pay-dem",
        "parameters": {},
        "availability": "live",
        "governance": {
            "proposedBy": CLAIMS["orchestrator"],
            "acceptedAt": NOW - 100_000,
            "anchoring": "in-code",
        },
    }
    value["signature"] = component_signature(value, RAIL_DOMAIN, "orchestrator")
    return value


def terminal_bundle(
    job_id: str,
    signed_listing: dict[str, Any],
    signed_agreement: dict[str, Any],
    phase: str,
    bundles: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "bundleVersion": "1",
        "jobId": job_id,
        "outcome": "completed",
        "anchoredByRole": "buyer",
        "listingRef": listing_ref(signed_listing),
        "agreementRef": artifact_ref(signed_agreement, f"{job_id}-agreement"),
        "parties": [party_carrier(role, bundles[role]) for role in (
            "buyer", "seller", "orchestrator"
        )],
        "phaseSummary": [
            {"index": 0, "kind": "vet-credentials", "outcome": "ok"},
            {"index": 1, "kind": phase, "outcome": "ok"},
            {"index": 2, "kind": "pay-dem", "outcome": "ok"},
            {"index": 3, "kind": "deliver-storage-program", "outcome": "ok"},
        ],
        "vetRecords": [],
        "settlementEvidence": [],
        "recipeRegistryVersion": 1,
        "railRegistryVersion": 1,
        "finalisedAt": NOW + 10_000,
        "signatures": [],
    }
    resign_terminal(value)
    return value


def resign_terminal(value: dict[str, Any]) -> None:
    digest = hash_hex({
        key: copy.deepcopy(item)
        for key, item in value.items()
        if key not in {"signatures", "anchoredByRole"}
    })
    value["signatures"] = [
        {
            "party": CLAIMS[role],
            "algorithm": "ed25519",
            "value": b64url(
                sign_ed25519(KEYS[role], (TERMINAL_DOMAIN + digest).encode("ascii"))
            ),
        }
        for role in ("buyer", "seller", "orchestrator")
    ]


def prior_disposition(
    prior_job: str, replacement_job: str, prior_agreement: dict[str, Any]
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "priorPaymentDispositionVersion": "1",
        "dispositionId": hashlib.sha256(b"dacs-390-disposition").hexdigest(),
        "priorJobId": prior_job,
        "replacementJobId": replacement_job,
        "priorAgreementRef": artifact_ref(prior_agreement, "prior-agreement"),
        "priorSelection": copy.deepcopy(RAIL_REF),
        "priorPhaseIndex": 2,
        "disposition": "closed-before-authorization",
        "observedAt": NOW - 2_000,
    }
    value["signature"] = component_signature(value, DISPOSITION_DOMAIN, "orchestrator")
    return value


def scenario(
    artifact: str,
    job_id: str,
    *,
    prior_agreement: dict[str, Any] | None = None,
    disposition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    nonce = hashlib.sha256(f"nonce:{job_id}".encode()).hexdigest()
    bundles = {role: identity_bundle(role, nonce) for role in KEYS}
    records = {
        role: composite_record(role, bundles[role], job_id)
        for role in ("buyer", "seller")
    }
    signed_listing = listing(PHASES[artifact], bundles["seller"], job_id)
    disposition_ref = (
        artifact_ref(disposition, f"{job_id}-prior-disposition")
        if disposition is not None else None
    )
    signed_agreement = agreement(
        artifact, job_id, signed_listing, bundles, records,
        prior_disposition_ref=disposition_ref,
    )
    companions = [
        {
            "identityBundle": copy.deepcopy(bundles[role]),
            "compositeRecord": copy.deepcopy(records[role]),
        }
        for role in ("buyer", "seller")
    ]
    terminal_companions = copy.deepcopy(companions) + [{
        "identityBundle": copy.deepcopy(bundles["orchestrator"])
    }]
    session_parties = [
        party_carrier(role, bundles[role]) for role in (
            "buyer", "seller", "orchestrator"
        )
    ]
    session_context = {
        "jobId": job_id,
        "listingRef": listing_ref(signed_listing),
        "recipeRegistryVersion": 1,
        "railRegistryVersion": 1,
        "parties": copy.deepcopy(session_parties),
        "priorPhaseOutputs": {},
        "signer": {
            "kind": "deterministic-test-capability",
            "claim": CLAIMS["orchestrator"],
        },
        "startedAt": NOW - 20_000,
    }
    payment_input = {
        "jobId": job_id,
        "agreement": copy.deepcopy(signed_agreement),
        "rail": rail_definition(),
        "amount": {"amount": "1", "currency": "DEM"},
        "payer": {
            "bundleHash": hash_hex(unsigned(bundles["buyer"], "presentation")),
            "primaryClaim": CLAIMS["buyer"],
            "payingKey": CLAIMS["buyer"],
        },
        "payee": {
            "bundleHash": hash_hex(unsigned(bundles["seller"], "presentation")),
            "primaryClaim": CLAIMS["seller"],
            "payeeAddress": CLAIMS["seller"],
        },
        "sessionContext": copy.deepcopy(session_context),
        "identityBindingCompanions": copy.deepcopy(companions),
    }
    terminal = terminal_bundle(
        job_id, signed_listing, signed_agreement, PHASES[artifact], bundles
    )
    commitment_set = commitments(signed_agreement, job_id)
    commit_input = {
        "jobId": job_id,
        "agreement": copy.deepcopy(signed_agreement),
        "listingRef": listing_ref(signed_listing),
        "sessionContext": copy.deepcopy(session_context),
    }
    if artifact in STRONG_ARTIFACTS:
        commit_input["identityBindingCompanions"] = copy.deepcopy(companions)
    result = {
        "artifact": artifact,
        "verifierContext": {
            "sessionNonce": nonce,
            "authenticatedOrchestrator": CLAIMS["orchestrator"],
            "authenticatedRailSteward": CLAIMS["orchestrator"],
            "paymentPhaseIndex": 2,
        },
        "listing": signed_listing,
        "agreement": signed_agreement,
        "commitments": commitment_set,
        "commitInput": commit_input,
        "paymentInput": payment_input,
        "terminalInput": {
            "bundle": terminal,
            "listing": copy.deepcopy(signed_listing),
            "agreement": copy.deepcopy(signed_agreement),
            "commitment": copy.deepcopy(commitment_set["finality"]),
            "identityBindingCompanions": terminal_companions,
            "sessionContext": copy.deepcopy(session_context),
        },
    }
    if prior_agreement is not None and disposition is not None:
        result["priorAgreement"] = copy.deepcopy(prior_agreement)
        result["priorPaymentDisposition"] = {
            "artifact": copy.deepcopy(disposition),
            "receipt": {
                "state": "finalized",
                "contentHash": hash_hex(disposition),
                "writer": CLAIMS["orchestrator"],
            },
        }
    return result


def refresh_commitments(context: dict[str, Any]) -> None:
    value = context["agreement"]
    for kind, wrapped in context["commitments"].items():
        record = wrapped["record"]
        record["agreementHash"] = hash_hex(unsigned(value, "signatures"))
        record["listingRef"] = copy.deepcopy(value["listingRef"])
        if kind == "legacy":
            wrapped["externalSignature"] = component_signature(
                {**record, "signature": {}}, COMMITMENT_DOMAIN, "orchestrator"
            )
        else:
            record["signature"] = component_signature(
                record, FINALITY_COMMITMENT_DOMAIN, "orchestrator"
            )
        wrapped["anchorReceipt"] = finalized_receipt(
            record, str(record.get("jobId", "bad"))
        )


def refresh_agreement_chain(
    context: dict[str, Any], *, signing_as: str | None = None
) -> None:
    resign_agreement(
        context["agreement"], context["artifact"], signing_as=signing_as
    )
    refresh_commitments(context)
    reference = artifact_ref(
        context["agreement"], f"{context['agreement'].get('jobId', 'bad')}-agreement"
    )
    context["terminalInput"]["bundle"]["agreementRef"] = copy.deepcopy(reference)
    resign_terminal(context["terminalInput"]["bundle"])
    synchronize_phase_inputs(context)


def synchronize_phase_inputs(context: dict[str, Any]) -> None:
    agreement = copy.deepcopy(context["agreement"])
    listing = copy.deepcopy(context["listing"])
    listing_reference = listing_ref(context["listing"])
    context["commitInput"]["agreement"] = copy.deepcopy(agreement)
    context["commitInput"]["listingRef"] = copy.deepcopy(listing_reference)
    context["paymentInput"]["agreement"] = copy.deepcopy(agreement)
    context["terminalInput"]["listing"] = listing
    context["terminalInput"]["agreement"] = agreement
    for carrier in (
        context["commitInput"], context["paymentInput"], context["terminalInput"]
    ):
        session = carrier.get("sessionContext")
        if isinstance(session, dict):
            session["listingRef"] = copy.deepcopy(listing_reference)


def resign_context(context: dict[str, Any], action: str) -> None:
    """Authenticate a vector mutation as a producer-created artifact."""
    if action == "agreement-chain":
        refresh_agreement_chain(context)
    elif action.startswith("agreement-domain:"):
        refresh_agreement_chain(context, signing_as=action.split(":", 1)[1])
    elif action == "listing-chain":
        context["listing"]["signature"] = component_signature(
            context["listing"], LISTING_DOMAIN, "seller"
        )
        ref = listing_ref(context["listing"])
        context["agreement"]["listingRef"] = copy.deepcopy(ref)
        context["terminalInput"]["bundle"]["listingRef"] = copy.deepcopy(ref)
        pipeline = context["listing"].get("pipeline")
        if isinstance(pipeline, list) and len(pipeline) > 1 and isinstance(pipeline[1], dict):
            context["terminalInput"]["bundle"]["phaseSummary"][1]["kind"] = pipeline[1].get("kind")
        refresh_agreement_chain(context)
    elif action.startswith("bundle:"):
        index = int(action.split(":", 1)[1])
        companion = context["commitInput"]["identityBindingCompanions"][index]
        resign_bundle(companion["identityBundle"], ("buyer", "seller")[index])
        context["paymentInput"]["identityBindingCompanions"][index]["identityBundle"] = copy.deepcopy(companion["identityBundle"])
        context["terminalInput"]["identityBindingCompanions"][index]["identityBundle"] = copy.deepcopy(companion["identityBundle"])
    elif action.startswith("cvr-ref-chain:"):
        index = int(action.split(":", 1)[1])
        role = ("buyer", "seller")[index]
        companion = context["commitInput"]["identityBindingCompanions"][index]
        record = companion["compositeRecord"]
        record["signature"] = component_signature(record, COMPOSITE_DOMAIN, "orchestrator")
        for carrier in (context["paymentInput"], context["terminalInput"]):
            carrier["identityBindingCompanions"][index]["compositeRecord"] = copy.deepcopy(record)
        context["agreement"]["parties"][index]["vetRecordRef"] = artifact_ref(
            record, f"{context['agreement'].get('jobId', 'bad')}-{role}-cvr"
        )
        refresh_agreement_chain(context)
    elif action == "terminal":
        resign_terminal(context["terminalInput"]["bundle"])
    elif action == "payment-rail":
        rail = context["paymentInput"]["rail"]
        rail["signature"] = component_signature(
            rail, RAIL_DOMAIN, "orchestrator"
        )
    elif action == "disposition":
        value = context["priorPaymentDisposition"]["artifact"]
        value["signature"] = component_signature(value, DISPOSITION_DOMAIN, "orchestrator")
        context["priorPaymentDisposition"]["receipt"]["contentHash"] = hash_hex(value)
        context["agreement"]["terms"]["priorPaymentDispositionRef"] = artifact_ref(
            value, f"{context['agreement'].get('jobId', 'bad')}-prior-disposition"
        )
        refresh_agreement_chain(context)
    elif action == "disposition-reference-chain":
        value = context["priorPaymentDisposition"]["artifact"]
        context["priorPaymentDisposition"]["receipt"]["contentHash"] = hash_hex(value)
        context["agreement"]["terms"]["priorPaymentDispositionRef"] = artifact_ref(
            value, f"{context['agreement'].get('jobId', 'bad')}-prior-disposition"
        )
        refresh_agreement_chain(context)
    elif action == "prior-agreement-reference-chain":
        value = context["priorPaymentDisposition"]["artifact"]
        value["priorAgreementRef"] = artifact_ref(
            context["priorAgreement"], "prior-agreement"
        )
        value["signature"] = component_signature(
            value, DISPOSITION_DOMAIN, "orchestrator"
        )
        context["priorPaymentDisposition"]["receipt"]["contentHash"] = hash_hex(value)
        context["agreement"]["terms"]["priorPaymentDispositionRef"] = artifact_ref(
            value, f"{context['agreement'].get('jobId', 'bad')}-prior-disposition"
        )
        refresh_agreement_chain(context)
    else:
        raise ValueError(f"unknown resign action: {action}")


def vector(
    name: str,
    expected: str,
    *,
    scenario_name: str,
    stage: str = "commit",
    commitment: str = "finality",
    mutations: list[dict[str, Any]] | None = None,
    resign: list[str] | None = None,
    unavailable: list[str] | None = None,
    reason: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "operation": "validate-identity-bound-agreement-path",
        "scenario": scenario_name,
        "stage": stage,
        "commitment": commitment,
        "mutations": mutations or [],
        "resign": resign or [],
        "unavailable": unavailable or [],
        "expected": expected,
        "want": {
            "verdict": expected,
            "authorizedAction": expected == "pass",
            "reason": reason,
        },
    }


def set_mutation(path: list[Any], value: Any) -> dict[str, Any]:
    return {"op": "set", "path": path, "value": value}


def delete_mutation(path: list[Any]) -> dict[str, Any]:
    return {"op": "delete", "path": path}


def build_vectors() -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []
    for artifact in ARTIFACTS:
        for phase_artifact in ARTIFACTS:
            phase = PHASES[phase_artifact]
            ok = artifact == phase_artifact
            vectors.append(vector(
                f"dispatch-{artifact}-under-{phase}", "pass" if ok else "fail",
                scenario_name=artifact,
                mutations=[set_mutation(["listing", "pipeline", 1, "kind"], phase)],
                resign=["listing-chain"],
                reason="verified" if ok else "phase-artifact-mismatch",
            ))
    for artifact in ARTIFACTS:
        for signing_as in ARTIFACTS:
            ok = artifact == signing_as
            vectors.append(vector(
                f"domain-{artifact}-signature-under-{signing_as}",
                "pass" if ok else "fail", scenario_name=artifact,
                resign=[f"agreement-domain:{signing_as}"],
                reason="verified" if ok else "agreement-signature-invalid",
            ))
    discriminator_cases = [
        ("missing", delete_mutation(["agreement", "identityBoundAgreementVersion"])),
        ("unknown", set_mutation(["agreement", "identityBoundAgreementVersion"], "2")),
        ("dual", set_mutation(["agreement", "agreementVersion"], "1")),
        ("renamed", set_mutation(["agreement", "strongAgreementVersion"], "1")),
        ("null", set_mutation(["agreement", "identityBoundAgreementVersion"], None)),
        ("numeric", set_mutation(["agreement", "identityBoundAgreementVersion"], 1)),
    ]
    for label, mutation in discriminator_cases:
        mutations = [mutation]
        if label == "renamed":
            mutations.insert(0, delete_mutation(["agreement", "identityBoundAgreementVersion"]))
        vectors.append(vector(
            f"discriminator-{label}-rejected", "fail",
            scenario_name="identityBoundAgreement", mutations=mutations,
            reason="agreement-discriminator-invalid",
        ))
    for artifact in ("agreement", "payeeBoundAgreement"):
        for commitment in ("legacy", "finality"):
            vectors.append(vector(
                f"historical-{artifact}-prefixed-bytes-{commitment}", "pass",
                scenario_name=artifact, commitment=commitment, reason="verified",
            ))
    for artifact in ("identityBoundAgreement", "identityBoundPayeeAgreement"):
        for stage in ("commit", "payment", "terminal"):
            vectors.append(vector(
                f"{artifact}-{stage}-verified", "pass",
                scenario_name=artifact, stage=stage, reason="verified",
            ))
    vectors.extend([
        vector(
            "strong-policy-old-artifact-downgrade-rejected", "fail",
            scenario_name="agreement",
            mutations=[set_mutation(["listing", "pipeline", 1, "kind"], PHASES["identityBoundAgreement"])],
            resign=["listing-chain"], reason="phase-artifact-mismatch",
        ),
        vector(
            "buyer-presentation-signer-contradiction", "fail",
            scenario_name="identityBoundAgreement",
            mutations=[set_mutation([
                "commitInput", "identityBindingCompanions", 0, "identityBundle",
                "presentation", "signatures", 0, "ref"
            ], CLAIMS["orchestrator"])], reason="identity-bundle-invalid",
        ),
        vector(
            "buyer-presentation-signature-invalid", "fail",
            scenario_name="identityBoundAgreement",
            mutations=[set_mutation([
                "commitInput", "identityBindingCompanions", 0, "identityBundle",
                "presentation", "signatures", 0, "signature"
            ], "AAAA")], reason="identity-bundle-invalid",
        ),
        vector(
            "buyer-session-nonce-contradiction", "fail",
            scenario_name="identityBoundAgreement",
            mutations=[set_mutation([
                "commitInput", "identityBindingCompanions", 0,
                "identityBundle", "sessionNonce"
            ], "ff" * 32)], resign=["bundle:0"], reason="session-nonce-mismatch",
        ),
        vector(
            "buyer-cvr-role-contradiction", "fail",
            scenario_name="identityBoundAgreement",
            mutations=[set_mutation([
                "commitInput", "identityBindingCompanions", 0,
                "compositeRecord", "evaluatedParty"
            ], CLAIMS["seller"])], resign=["cvr-ref-chain:0"],
            reason="companion-join-contradiction",
        ),
        vector(
            "buyer-cvr-job-contradiction", "fail",
            scenario_name="identityBoundAgreement",
            mutations=[set_mutation([
                "commitInput", "identityBindingCompanions", 0,
                "compositeRecord", "jobId"
            ], "different-job")], resign=["cvr-ref-chain:0"], reason="cvr-job-mismatch",
        ),
        vector(
            "buyer-cvr-reference-hash-contradiction", "fail",
            scenario_name="identityBoundAgreement",
            mutations=[set_mutation([
                "agreement", "parties", 0, "vetRecordRef", "contentHash"
            ], WRONG_HASH)], resign=["agreement-chain"], reason="cvr-reference-mismatch",
        ),
        vector(
            "duplicate-buyer-companion-rejected", "fail",
            scenario_name="identityBoundAgreement",
            mutations=[{"op": "append-copy", "path": ["commitInput", "identityBindingCompanions"], "index": 0}],
            reason="companion-cardinality-invalid",
        ),
        vector(
            "missing-buyer-companion-indeterminate", "indeterminate",
            scenario_name="identityBoundAgreement",
            mutations=[delete_mutation(["commitInput", "identityBindingCompanions", 0])],
            reason="required-companion-missing",
        ),
        vector(
            "buyer-identity-authority-unavailable", "indeterminate",
            scenario_name="identityBoundAgreement",
            unavailable=[f"identity:{CLAIMS['buyer']}"], reason="identity-bundle-unavailable",
        ),
        vector(
            "seller-cvr-authority-unavailable", "indeterminate",
            scenario_name="identityBoundAgreement",
            unavailable=[f"cvr:{CLAIMS['seller']}"], reason="cvr-unavailable",
        ),
        vector(
            "producer-verified-boolean-cannot-replace-bundle", "indeterminate",
            scenario_name="identityBoundAgreement",
            mutations=[
                delete_mutation([
                    "commitInput", "identityBindingCompanions", 0,
                    "identityBundle"
                ]),
                set_mutation(["commitInput", "identityBindingDecision"], True),
            ],
            reason="required-companion-missing",
        ),
        vector(
            "producer-asserted-digest-cannot-replace-bundle", "indeterminate",
            scenario_name="identityBoundAgreement",
            mutations=[
                delete_mutation([
                    "commitInput", "identityBindingCompanions", 0,
                    "identityBundle"
                ]),
                set_mutation([
                    "commitInput", "identityBindingCompanions", 0,
                    "assertedBundleHash"
                ], hash_hex(unsigned(
                    identity_bundle("buyer", "asserted-value-is-not-authority"),
                    "presentation",
                ))),
            ],
            reason="required-companion-missing",
        ),
        vector(
            "agreement-role-contradiction", "fail",
            scenario_name="identityBoundAgreement",
            mutations=[set_mutation(["agreement", "parties", 0, "role"], "seller")],
            resign=["agreement-chain"], reason="agreement-role-invalid",
        ),
        vector(
            "agreement-primary-claim-contradiction", "fail",
            scenario_name="identityBoundAgreement",
            mutations=[set_mutation([
                "agreement", "parties", 0, "primaryClaim"
            ], CLAIMS["orchestrator"])], resign=["agreement-chain"],
            reason="agreement-signers-invalid",
        ),
    ])
    for index, role in enumerate(("buyer", "seller")):
        vectors.extend([
            vector(
                f"agreement-{role}-hash-position-rejected", "fail",
                scenario_name="identityBoundAgreement",
                mutations=[set_mutation(["agreement", "parties", index, "bundleHash"], WRONG_HASH)],
                resign=["agreement-chain"], reason="agreement-bundle-hash-mismatch",
            ),
            vector(
                f"cvr-{role}-hash-position-rejected", "fail",
                scenario_name="identityBoundAgreement",
                mutations=[set_mutation([
                    "commitInput", "identityBindingCompanions", index,
                    "compositeRecord", "bundleHash"
                ], WRONG_HASH)], resign=[f"cvr-ref-chain:{index}"], reason="cvr-bundle-hash-mismatch",
            ),
            vector(
                f"payment-{role}-hash-position-rejected", "fail",
                scenario_name="identityBoundAgreement", stage="payment",
                mutations=[set_mutation([
                    "paymentInput", "payer" if role == "buyer" else "payee", "bundleHash"
                ], WRONG_HASH)], reason="payment-party-mismatch",
            ),
            vector(
                f"payment-{role}-primary-claim-rejected", "fail",
                scenario_name="identityBoundAgreement", stage="payment",
                mutations=[set_mutation([
                    "paymentInput", "payer" if role == "buyer" else "payee",
                    "primaryClaim"
                ], CLAIMS["orchestrator"])], reason="payment-party-mismatch",
            ),
            vector(
                f"payment-session-{role}-primary-claim-rejected", "fail",
                scenario_name="identityBoundAgreement", stage="payment",
                mutations=[set_mutation([
                    "paymentInput", "sessionContext", "parties", index,
                    "primaryClaim"
                ], CLAIMS["orchestrator"])], reason="session-party-mismatch",
            ),
            vector(
                f"session-{role}-hash-position-rejected", "fail",
                scenario_name="identityBoundAgreement", stage="terminal",
                mutations=[set_mutation([
                    "terminalInput", "sessionContext", "parties", index,
                    "bundleHash"
                ], WRONG_HASH)], reason="session-party-mismatch",
            ),
            vector(
                f"session-{role}-primary-claim-rejected", "fail",
                scenario_name="identityBoundAgreement", stage="terminal",
                mutations=[set_mutation([
                    "terminalInput", "sessionContext", "parties", index,
                    "primaryClaim"
                ], CLAIMS["orchestrator"])], reason="session-party-mismatch",
            ),
            vector(
                f"terminal-{role}-hash-position-rejected", "fail",
                scenario_name="identityBoundAgreement", stage="terminal",
                mutations=[set_mutation([
                    "terminalInput", "bundle", "parties", index, "bundleHash"
                ], WRONG_HASH)], resign=["terminal"], reason="terminal-party-mismatch",
            ),
            vector(
                f"terminal-{role}-primary-claim-rejected", "fail",
                scenario_name="identityBoundAgreement", stage="terminal",
                mutations=[set_mutation([
                    "terminalInput", "bundle", "parties", index, "primaryClaim"
                ], CLAIMS["orchestrator"])], resign=["terminal"],
                reason="terminal-party-mismatch",
            ),
        ])
    for carrier, path in (
        ("session", [
            "terminalInput", "sessionContext", "parties", 2, "bundleHash"
        ]),
        ("terminal", ["terminalInput", "bundle", "parties", 2, "bundleHash"]),
    ):
        vectors.append(vector(
            f"{carrier}-orchestrator-hash-position-rejected", "fail",
            scenario_name="identityBoundAgreement", stage="terminal",
            mutations=[set_mutation(path, WRONG_HASH)],
            resign=["terminal"] if carrier == "terminal" else [],
            reason=f"{carrier}-party-mismatch",
        ))
    for carrier, path in (
        ("session", [
            "terminalInput", "sessionContext", "parties", 2, "primaryClaim"
        ]),
        ("terminal", ["terminalInput", "bundle", "parties", 2, "primaryClaim"]),
    ):
        vectors.append(vector(
            f"{carrier}-orchestrator-primary-claim-rejected", "fail",
            scenario_name="identityBoundAgreement", stage="terminal",
            mutations=[set_mutation(path, CLAIMS["buyer"])],
            resign=["terminal"] if carrier == "terminal" else [],
            reason=f"{carrier}-party-mismatch",
        ))
    vectors.extend([
        vector(
            "terminal-orchestrator-companion-missing", "indeterminate",
            scenario_name="identityBoundAgreement", stage="terminal",
            mutations=[delete_mutation(["terminalInput", "identityBindingCompanions", 2])],
            reason="orchestrator-companion-missing",
        ),
        vector(
            "terminal-phase-relabelled-rejected-before-count", "fail",
            scenario_name="identityBoundAgreement", stage="terminal",
            mutations=[set_mutation([
                "terminalInput", "bundle", "phaseSummary", 1, "kind"
            ], "commit-agreement")], resign=["terminal"], reason="terminal-phase-mismatch",
        ),
        vector(
            "terminal-agreement-reference-mismatch", "fail",
            scenario_name="identityBoundAgreement", stage="terminal",
            mutations=[set_mutation([
                "terminalInput", "bundle", "agreementRef", "contentHash"
            ], WRONG_HASH)], resign=["terminal"], reason="terminal-agreement-reference-mismatch",
        ),
        vector(
            "identity-bound-payee-payout-missing", "fail",
            scenario_name="identityBoundPayeeAgreement", stage="payment",
            mutations=[set_mutation(["agreement", "terms", "payoutBindings"], [])],
            resign=["agreement-chain"], reason="payout-binding-invalid",
        ),
        vector(
            "identity-bound-payee-payout-duplicate", "fail",
            scenario_name="identityBoundPayeeAgreement", stage="payment",
            mutations=[{"op": "append-copy", "path": ["agreement", "terms", "payoutBindings"], "index": 0}],
            resign=["agreement-chain"], reason="payout-binding-invalid",
        ),
        vector(
            "identity-bound-payee-payout-address-mismatch", "fail",
            scenario_name="identityBoundPayeeAgreement", stage="payment",
            mutations=[set_mutation([
                "agreement", "terms", "payoutBindings", 0, "payeeAddress"
            ], CLAIMS["buyer"])], resign=["agreement-chain"], reason="payout-destination-mismatch",
        ),
        vector(
            "identity-bound-payee-payout-rail-mismatch", "fail",
            scenario_name="identityBoundPayeeAgreement", stage="payment",
            mutations=[set_mutation([
                "agreement", "terms", "payoutBindings", 0, "railId"
            ], "demos-native:OTHER")], resign=["agreement-chain"],
            reason="payout-binding-invalid",
        ),
        vector(
            "identity-bound-payee-payout-index-mismatch", "fail",
            scenario_name="identityBoundPayeeAgreement", stage="payment",
            mutations=[set_mutation([
                "agreement", "terms", "payoutBindings", 0, "phaseIndex"
            ], 3)], resign=["agreement-chain"], reason="payout-binding-invalid",
        ),
        vector(
            "identity-bound-payee-signed-rail-handler-mismatch", "fail",
            scenario_name="identityBoundPayeeAgreement", stage="payment",
            mutations=[set_mutation([
                "paymentInput", "rail", "phaseHandler"
            ], "pay-evm-erc20")], resign=["payment-rail"],
            reason="rail-definition-invalid",
        ),
        vector(
            "identity-bound-payee-agreement-rail-mismatch", "fail",
            scenario_name="identityBoundPayeeAgreement", stage="payment",
            mutations=[set_mutation([
                "agreement", "terms", "rail", "railVersion"
            ], 2)], resign=["agreement-chain"], reason="rail-binding-mismatch",
        ),
        vector(
            "identity-bound-payee-replacement-verified", "pass",
            scenario_name="identityBoundPayeeReplacement", stage="payment", reason="verified",
        ),
        vector(
            "identity-bound-payee-replacement-proof-unavailable", "indeterminate",
            scenario_name="identityBoundPayeeReplacement", stage="payment",
            unavailable=["prior-disposition"], reason="prior-disposition-unavailable",
        ),
        vector(
            "identity-bound-payee-replacement-wrong-job", "fail",
            scenario_name="identityBoundPayeeReplacement", stage="payment",
            mutations=[set_mutation([
                "priorPaymentDisposition", "artifact", "replacementJobId"
            ], "wrong-replacement-job")], resign=["disposition"], reason="replacement-job-mismatch",
        ),
        vector(
            "identity-bound-payee-replacement-pending-refused", "fail",
            scenario_name="identityBoundPayeeReplacement", stage="payment",
            mutations=[set_mutation([
                "priorPaymentDisposition", "artifact", "disposition"
            ], "authorization-pending")], resign=["disposition"], reason="replacement-not-safe",
        ),
        vector(
            "identity-bound-payee-replacement-reference-hash-mismatch", "fail",
            scenario_name="identityBoundPayeeReplacement", stage="payment",
            mutations=[set_mutation([
                "agreement", "terms", "priorPaymentDispositionRef", "contentHash"
            ], WRONG_HASH)], resign=["agreement-chain"],
            reason="prior-disposition-reference-mismatch",
        ),
        vector(
            "identity-bound-payee-replacement-signature-invalid", "fail",
            scenario_name="identityBoundPayeeReplacement", stage="payment",
            mutations=[set_mutation([
                "priorPaymentDisposition", "artifact", "signature", "value"
            ], "AAAA")], resign=["disposition-reference-chain"],
            reason="prior-disposition-signature-invalid",
        ),
        vector(
            "identity-bound-payee-replacement-receipt-writer-mismatch", "fail",
            scenario_name="identityBoundPayeeReplacement", stage="payment",
            mutations=[set_mutation([
                "priorPaymentDisposition", "receipt", "writer"
            ], CLAIMS["buyer"])], reason="prior-disposition-receipt-invalid",
        ),
        vector(
            "identity-bound-payee-replacement-prior-agreement-ref-mismatch", "fail",
            scenario_name="identityBoundPayeeReplacement", stage="payment",
            mutations=[set_mutation([
                "priorPaymentDisposition", "artifact", "priorAgreementRef",
                "contentHash"
            ], WRONG_HASH)], resign=["disposition"],
            reason="prior-agreement-reference-mismatch",
        ),
        vector(
            "identity-bound-payee-replacement-selection-mismatch", "fail",
            scenario_name="identityBoundPayeeReplacement", stage="payment",
            mutations=[set_mutation([
                "priorPaymentDisposition", "artifact", "priorSelection",
                "railVersion"
            ], 2)], resign=["disposition"], reason="prior-selection-mismatch",
        ),
        vector(
            "identity-bound-payee-replacement-index-mismatch", "fail",
            scenario_name="identityBoundPayeeReplacement", stage="payment",
            mutations=[set_mutation([
                "priorPaymentDisposition", "artifact", "priorPhaseIndex"
            ], 3)], resign=["disposition"], reason="prior-selection-mismatch",
        ),
        vector(
            "identity-bound-payee-replacement-prior-agreement-invalid", "fail",
            scenario_name="identityBoundPayeeReplacement", stage="payment",
            mutations=[set_mutation([
                "priorAgreement", "signatures", 0, "value"
            ], "AAAA")], resign=["prior-agreement-reference-chain"],
            reason="prior-agreement-invalid",
        ),
    ])
    for artifact in ARTIFACTS:
        vectors.append(vector(
            f"modeled-old-reader-{artifact}",
            "pass" if artifact in {"agreement", "payeeBoundAgreement"} else "fail",
            scenario_name=artifact, stage="old-reader",
            reason="verified" if artifact in {"agreement", "payeeBoundAgreement"} else "unsupported-new-type",
        ))
    malformed_paths = [
        ["listing", "pipeline"], ["listing", "pipeline", 1],
        ["listing", "pipeline", 1, "kind"], ["agreement", "parties"],
        ["agreement", "parties", 0], ["agreement", "parties", 0, "role"],
        ["agreement", "parties", 0, "primaryClaim"],
        ["agreement", "parties", 0, "bundleHash"],
        ["agreement", "parties", 0, "vetRecordRef"],
        ["commitInput", "identityBindingCompanions"],
        ["commitInput", "identityBindingCompanions", 0],
        ["commitInput", "identityBindingCompanions", 0, "identityBundle"],
        ["commitInput", "identityBindingCompanions", 0, "identityBundle", "claims"],
        ["commitInput", "identityBindingCompanions", 0, "identityBundle", "sessionNonce"],
        ["commitInput", "identityBindingCompanions", 0, "identityBundle", "presentation"],
        ["commitInput", "identityBindingCompanions", 0, "identityBundle", "presentation", "signatures"],
        ["commitInput", "identityBindingCompanions", 0, "identityBundle", "presentation", "signatures", 0],
        ["commitInput", "identityBindingCompanions", 0, "compositeRecord"],
        ["commitInput", "identityBindingCompanions", 0, "compositeRecord", "bundleHash"],
        ["commitInput", "identityBindingCompanions", 0, "compositeRecord", "signature"],
    ]
    malformed_values = [("null", None), ("numeric", 7), ("list", []), ("dict", {})]
    for path_index, path in enumerate(malformed_paths):
        for label, value in malformed_values:
            vectors.append(vector(
                f"malformed-commit-{path_index:02d}-{label}", "error",
                scenario_name="identityBoundAgreement",
                mutations=[set_mutation(path, value)], reason="malformed-input",
            ))
        missing_is_authority = path_index in {10, 11, 17}
        vectors.append(vector(
            f"malformed-commit-{path_index:02d}-missing",
            "indeterminate" if missing_is_authority else "error",
            scenario_name="identityBoundAgreement",
            mutations=[delete_mutation(path)],
            reason="required-companion-missing" if missing_is_authority else "malformed-input",
        ))
    for stage, paths in {
        "payment": [
            ["paymentInput", "payer"], ["paymentInput", "payer", "bundleHash"],
            ["paymentInput", "payee"], ["paymentInput", "payee", "bundleHash"],
            ["paymentInput", "payee", "payeeAddress"],
            ["paymentInput", "sessionContext"],
            ["paymentInput", "sessionContext", "parties"],
            ["paymentInput", "identityBindingCompanions"],
        ],
        "terminal": [
            ["terminalInput", "bundle"], ["terminalInput", "bundle", "parties"],
            ["terminalInput", "bundle", "parties", 0],
            ["terminalInput", "bundle", "parties", 0, "bundleHash"],
            ["terminalInput", "bundle", "phaseSummary"],
            ["terminalInput", "bundle", "phaseSummary", 1],
            ["terminalInput", "bundle", "phaseSummary", 1, "kind"],
            ["terminalInput", "bundle", "signatures"],
            ["terminalInput", "sessionContext"],
            ["terminalInput", "sessionContext", "parties"],
            ["terminalInput", "identityBindingCompanions"],
        ],
    }.items():
        for path_index, path in enumerate(paths):
            for label, value in malformed_values:
                vectors.append(vector(
                    f"malformed-{stage}-{path_index:02d}-{label}", "error",
                    scenario_name="identityBoundAgreement", stage=stage,
                    mutations=[set_mutation(path, value)], reason="malformed-input",
                ))
            vectors.append(vector(
                f"malformed-{stage}-{path_index:02d}-missing", "error",
                scenario_name="identityBoundAgreement", stage=stage,
                mutations=[delete_mutation(path)], reason="malformed-input",
            ))
    return vectors


def build() -> dict[str, Any]:
    scenarios = {
        artifact: scenario(artifact, JOB_IDS[artifact]) for artifact in ARTIFACTS
    }
    prior = scenario("identityBoundPayeeAgreement", JOB_IDS["prior"])
    disposition = prior_disposition(
        JOB_IDS["prior"], JOB_IDS["replacement"], prior["agreement"]
    )
    scenarios["identityBoundPayeeReplacement"] = scenario(
        "identityBoundPayeeAgreement", JOB_IDS["replacement"],
        prior_agreement=prior["agreement"], disposition=disposition,
    )
    vectors = build_vectors()
    return {
        "set": "identity-bundle-hash-binding-v0.1",
        "spec": "CORE §B.2 IBH-1..IBH-6; DACS-1 §6.3.4; DACS-2 §7.7; DACS-3 §8.5/§8.6; DACS-4 §9.5/§9.9.1; DACS-5 §10.4/§10.5.1",
        "provenance": {
            "generator": "scripts/generate_identity_bundle_hash_binding_vectors.py",
            "cryptography": (
                "repository-native dependency-free Ed25519 sign/verify helpers; "
                "JCS + SHA-256"
            ),
            "oldReaderEvidence": {
                "kind": "modeled-agreement-plus-executable-terminal", "baseSha": BASE_SHA,
                "agreementDispatcher": {
                    "kind": "modeled-base-dispatcher",
                    "sourcePaths": ["spec/DACS-1-IDENTIFY.md", "spec/DACS-3-NEGOTIATE.md"],
                    "note": "No pinned prior agreement-reader executable is present in this repository."
                },
                "terminalReader": {
                    "kind": "executable-base-reference",
                    "path": "tests/dacs5_reference.py",
                    "test": "tests.test_bundle_settlement_evidence_bijection_vectors.BundleSettlementEvidenceBijectionVectorTests.test_signed_listing_rejects_unknown_phase_before_deriving_empty_evidence"
                },
                "deployedReaderProof": False,
                "note": "The terminal refusal is executable modeled reference evidence; neither arm is deployed-reader proof."
            },
        },
        "otherApprovedReservationsNotImplemented": [
            "RevocationBoundListing/revocationBoundListingVersion",
            "FinalityBoundSettlementEvidence/finalityBoundEvidenceVersion",
            "FinalityBoundEvidenceFaultAttestationBundle/finalityBoundEvidenceFaultBundleVersion",
            "FinalityBoundEvidenceFaultBundleExtendedPointer",
            "LegacyBundleActivationCheckpoint/legacyBundleCheckpointVersion",
            "LegacyBundleCheckpointBinding/legacyBundleCheckpointBindingVersion",
            "CurrentUseReplayableReputationDerivation/currentUseReplayableDerivationVersion"
        ],
        "publicClaims": copy.deepcopy(CLAIMS),
        "scenarios": scenarios,
        "count": len(vectors),
        "hash": hash_hex(vectors),
        "vectors": vectors,
    }


def rendered() -> str:
    return json.dumps(build(), indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true")
    group.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = rendered()
    if args.write:
        OUTPUT.write_text(expected, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != expected:
        print(f"stale: {OUTPUT.relative_to(ROOT)}")
        return 1
    print(f"ok: {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
