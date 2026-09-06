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
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


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
VERIFY_RESULT_DOMAIN = "dacs-verifyresult:v1:"

# This prefix authenticates only the deterministic native-observation adapter in
# this conformance fixture. It is not a DACS protocol domain and is deliberately
# absent from CORE's domain registry.
FIXTURE_OBSERVATION_PREFIX = b"fixture-only:dacs-390-native-observation:v1:"

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
BASE_SUPPORTED_PHASES = frozenset({
    "vet-credentials",
    "negotiate-fixed-price",
    "negotiate-rfq",
    "negotiate-sealed-envelope",
    "negotiate-sealed-envelope-procurement",
    "commit-agreement",
    "commit-payee-bound-agreement",
    "pay-evm-erc20",
    "pay-solana-spl",
    "pay-cross-chain-htlc",
    "pay-cross-chain-liquidity-tank",
    "pay-ap2",
    "pay-x402",
    "pay-dem",
    "pay-alternative",
    "deliver-storage-program",
    "deliver-entitlement",
    "deliver-attested-payload",
    "rate",
})
CURRENT_SUPPORTED_PHASES = BASE_SUPPORTED_PHASES | {
    PHASES["identityBoundAgreement"],
    PHASES["identityBoundPayeeAgreement"],
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
    "historicalSealed": "01KTY8ZJ00CW7KSECW3FS6PQ0G",
    "identityBoundSealed": "01KTY8ZJ00CW7KSECW3FS6PQ0H",
}

FIXTURE_REQUIREMENT = {
    "requirementVersion": "1",
    "required": [{
        "scheme": "key",
        "verificationRequired": True,
        "recipeVersion": 1,
        "parameters": {
            "verificationMethod": "self-signed",
            "possessionVerified": True,
        },
    }],
}
FIXTURE_RECIPE_REGISTRY = {
    "recipeRegistryVersion": 1,
    "latestByFamily": {"key": {"self-signed": 1}},
    "versionsByFamily": {"key": {"self-signed": {"1": "live"}}},
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


def public_key(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def sign_ed25519(seed: bytes, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def verify_ed25519(public: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


KEYS = {
    role: private_key(f"dacs-390-{role}")
    for role in ("buyer", "seller", "orchestrator", "bidder")
}
CLAIMS = {role: f"key:{public_hex(key)}" for role, key in KEYS.items()}
RECEIPT_AUTHORITY_KEY = private_key("dacs-390-independent-receipt-observer")
RECEIPT_AUTHORITY_CLAIM = f"key:{public_hex(RECEIPT_AUTHORITY_KEY)}"


def unsigned(value: dict[str, Any], field: str) -> dict[str, Any]:
    return {key: copy.deepcopy(item) for key, item in value.items() if key != field}


def artifact_hash(value: dict[str, Any], signature_field: str | None) -> str:
    """Hash one artifact's §B.2 scope, omitting only its declared envelope."""
    scope = value if signature_field is None else unsigned(value, signature_field)
    return hash_hex(scope)


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


def artifact_ref(
    value: dict[str, Any], label: str, signature_field: str | None
) -> dict[str, Any]:
    return {
        "anchor": {
            "kind": "storage-program",
            "locator": f"demos:dacs-390:{label}",
        },
        "contentHash": artifact_hash(value, signature_field),
    }


def verify_result(role: str, job_id: str) -> dict[str, Any]:
    identifier = CLAIMS[role].removeprefix("key:")
    attestation_content = {
        "claim": CLAIMS[role],
        "method": "self-signed",
        "possessionVerified": True,
    }
    value: dict[str, Any] = {
        "resultVersion": "1",
        "scheme": "key",
        "identifier": identifier,
        "method": "self-signed",
        "recipeVersion": 1,
        "decision": "pass",
        "reason": "fixture self-signature verified",
        "attestation": {
            "anchor": {
                "kind": "storage-program",
                "locator": f"demos:dacs-390:{job_id}-{role}-attestation",
            },
            "contentHash": hash_hex(attestation_content),
        },
        "data": {"possessionVerified": True},
        "fetchedAt": NOW - 9_500,
        "verifiedAt": NOW - 9_000,
    }
    value["signature"] = component_signature(
        value, VERIFY_RESULT_DOMAIN, "orchestrator"
    )
    return value


def verify_result_ref(value: dict[str, Any], role: str, job_id: str) -> dict[str, Any]:
    return {
        "anchor": {
            "kind": "storage-program",
            "locator": f"demos:dacs-390:{job_id}-{role}-verify-result",
        },
        "contentHash": artifact_hash(value, "signature"),
        "recipeVersion": value["recipeVersion"],
    }


def composite_record(
    role: str,
    bundle: dict[str, Any],
    job_id: str,
    requirement: dict[str, Any],
    result_ref: dict[str, Any],
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "recordVersion": "1",
        "jobId": job_id,
        "evaluatedParty": CLAIMS[role],
        "bundleHash": hash_hex(unsigned(bundle, "presentation")),
        "requirementHash": hash_hex(requirement),
        "freshness": [copy.deepcopy(result_ref)],
        "supplementary": [],
        "dealSpecific": [],
        "overallDecision": "pass",
        "generatedAt": NOW - 8_000,
    }
    record["signature"] = component_signature(record, COMPOSITE_DOMAIN, "orchestrator")
    return record


def listing(
    phase: str,
    seller_bundle: dict[str, Any],
    job_id: str,
    *,
    sealed: bool = False,
) -> dict[str, Any]:
    deliverable = {"kind": "storage-program", "accessModel": "public"}
    pipeline: list[dict[str, Any]] = [{"kind": "vet-credentials"}]
    if sealed:
        pipeline.append({
            "kind": "negotiate-sealed-envelope",
            "parameters": {
                "commitDeadline": NOW - 7_000,
                "revealWindow": 1_000,
                "selectionRule": "highest-price",
            },
        })
    pipeline.extend([
        {"kind": phase},
        {"kind": "pay-dem", "parameters": {"rail": RAIL_REF["railId"]}},
        {"kind": "deliver-storage-program"},
    ])
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
        "buyerRequirement": copy.deepcopy(FIXTURE_REQUIREMENT),
        "pipeline": pipeline,
        "pricing": (
            {
                "kind": "auction",
                "reservePrice": {"amount": "1", "currency": "DEM"},
                "selectionRule": "highest-price",
            }
            if sealed else {
                "kind": "fixed",
                "price": {"amount": "1", "currency": "DEM"},
            }
        ),
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
    bidder_roles: tuple[str, ...] = (),
    derived_from_pattern: str = "fixed-price",
    payment_phase_index: int = 2,
) -> dict[str, Any]:
    strong = artifact in STRONG_ARTIFACTS
    parties = []
    for role in ("buyer", "seller", *bidder_roles):
        digest = hash_hex(unsigned(bundles[role], "presentation"))
        parties.append({
            "role": "bidder-non-winning" if role == "bidder" else role,
            "bundleHash": digest if strong else f"sha256:{digest}",
            "primaryClaim": CLAIMS[role],
            "vetRecordRef": artifact_ref(
                records[role], f"{job_id}-{role}-cvr", "signature"
            ),
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
            "phaseIndex": payment_phase_index,
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
        "derivedFromPattern": derived_from_pattern,
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
        "pattern": value["derivedFromPattern"],
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


def commitment_record_hash(record: dict[str, Any]) -> str:
    if record.get("finalityCommitmentVersion") == "1":
        return artifact_hash(record, "signature")
    return artifact_hash(record, None)


def fixture_observation_envelope(
    native_receipt: dict[str, Any],
    *,
    signer_claim: str = RECEIPT_AUTHORITY_CLAIM,
    signer_key: bytes = RECEIPT_AUTHORITY_KEY,
) -> dict[str, Any]:
    payload = FIXTURE_OBSERVATION_PREFIX + hash_hex(native_receipt).encode("ascii")
    return {
        "fixtureEvidenceVersion": "1",
        "scope": "offline-conformance-fixture-only",
        "observer": signer_claim,
        "nativeReceipt": copy.deepcopy(native_receipt),
        "signature": b64url(sign_ed25519(signer_key, payload)),
    }


def set_fixture_evidence(
    receipt: dict[str, Any],
    native_receipt: dict[str, Any],
    *,
    signer_claim: str = RECEIPT_AUTHORITY_CLAIM,
    signer_key: bytes = RECEIPT_AUTHORITY_KEY,
) -> None:
    envelope = fixture_observation_envelope(
        native_receipt, signer_claim=signer_claim, signer_key=signer_key
    )
    receipt["evidence"] = {
        "kind": "fixture-native-finality-observation",
        "value": canonical_bytes(envelope).decode("utf-8"),
    }


def mutate_fixture_evidence(receipt: dict[str, Any], variant: str) -> None:
    envelope = json.loads(receipt["evidence"]["value"])
    native = envelope["nativeReceipt"]
    signer_claim = RECEIPT_AUTHORITY_CLAIM
    signer_key = RECEIPT_AUTHORITY_KEY
    if variant == "producer-authority":
        signer_claim = CLAIMS["orchestrator"]
        signer_key = KEYS["orchestrator"]
    elif variant == "content":
        native["binding"]["contentHash"] = WRONG_HASH
    elif variant == "transaction":
        native["binding"]["transactionRef"]["value"] = WRONG_HASH
    elif variant == "location":
        native["binding"]["nativeAddress"] = "fixture:wrong-native-address"
    elif variant == "ordering":
        native["inclusion"]["transactionIndex"] = 1
    elif variant == "block":
        native["inclusion"]["blockRef"]["id"] = WRONG_HASH
    elif variant == "finality":
        native["consensus"]["inclusionIsFinal"] = False
    else:
        raise ValueError(f"unknown fixture evidence mutation: {variant}")
    set_fixture_evidence(
        receipt, native, signer_claim=signer_claim, signer_key=signer_key
    )


def finalized_receipt(record: dict[str, Any], job_id: str) -> dict[str, Any]:
    content_hash = commitment_record_hash(record)
    logical_address = f"dacs3:commit:{job_id}"
    native_address = f"fixture:{hashlib.sha256(logical_address.encode()).hexdigest()}"
    nonce = hashlib.sha256(f"nonce:{job_id}".encode()).hexdigest()
    transaction_binding = {
        "logicalAddress": logical_address,
        "nativeAddress": native_address,
        "contentHash": content_hash,
        "writer": CLAIMS["orchestrator"],
        "nonce": nonce,
    }
    transaction_ref = {"kind": "fixture", "value": hash_hex(transaction_binding)}
    ordered_transactions = [copy.deepcopy(transaction_ref)]
    block_material = {
        "height": "390",
        "timestamp": NOW,
        "orderedTransactions": ordered_transactions,
    }
    block_ref = {
        "id": hash_hex(block_material),
        "height": block_material["height"],
        "timestamp": block_material["timestamp"],
    }
    native_receipt = {
        "fixtureNativeReceiptVersion": "1",
        "substrate": "dacs-390-fixture",
        "finalityProfile": "deterministic-fixture-bft-final",
        "binding": {
            **transaction_binding,
            "transactionRef": copy.deepcopy(transaction_ref),
        },
        "inclusion": {
            "blockRef": copy.deepcopy(block_ref),
            "transactionIndex": 0,
            "orderedTransactions": ordered_transactions,
        },
        "consensus": {"state": "finalized", "inclusionIsFinal": True},
    }
    receipt: dict[str, Any] = {
        "receiptVersion": "1",
        "substrate": "dacs-390-fixture",
        "finalityProfile": "deterministic-fixture-bft-final",
        "logicalAddress": logical_address,
        "nativeAddress": native_address,
        "contentHash": content_hash,
        "transactionRef": transaction_ref,
        "writer": CLAIMS["orchestrator"],
        "nonce": nonce,
        "state": "finalized",
        "observationDisposition": "established",
        "observedAt": NOW + 1_000,
        "blockRef": block_ref,
        "evidence": {},
    }
    set_fixture_evidence(receipt, native_receipt)
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
        "agreementRef": artifact_ref(
            signed_agreement, f"{job_id}-agreement", "signatures"
        ),
        "parties": [party_carrier(role, bundles[role]) for role in (
            "buyer", "seller", "orchestrator"
        )],
        "phaseSummary": [
            {"index": index, "kind": step["kind"], "outcome": "ok"}
            for index, step in enumerate(signed_listing["pipeline"])
        ],
        "vetRecords": [
            copy.deepcopy(party["vetRecordRef"])
            for party in signed_agreement["parties"]
        ],
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
        "priorAgreementRef": artifact_ref(
            prior_agreement, "prior-agreement", "signatures"
        ),
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
    sealed: bool = False,
) -> dict[str, Any]:
    nonce = hashlib.sha256(f"nonce:{job_id}".encode()).hexdigest()
    agreement_roles = ("buyer", "seller", "bidder") if sealed else ("buyer", "seller")
    bundles = {
        role: identity_bundle(role, nonce)
        for role in ("buyer", "seller", "orchestrator", *agreement_roles[2:])
    }
    signed_listing = listing(
        PHASES[artifact], bundles["seller"], job_id, sealed=sealed
    )
    results = {role: verify_result(role, job_id) for role in agreement_roles}
    result_refs = {
        role: verify_result_ref(results[role], role, job_id)
        for role in agreement_roles
    }
    records = {
        role: composite_record(
            role,
            bundles[role],
            job_id,
            signed_listing["buyerRequirement"],
            result_refs[role],
        )
        for role in agreement_roles
    }
    payment_phase_index = next(
        index
        for index, step in enumerate(signed_listing["pipeline"])
        if step["kind"] == "pay-dem"
    )
    disposition_ref = (
        artifact_ref(disposition, f"{job_id}-prior-disposition", "signature")
        if disposition is not None else None
    )
    signed_agreement = agreement(
        artifact, job_id, signed_listing, bundles, records,
        prior_disposition_ref=disposition_ref,
        bidder_roles=agreement_roles[2:],
        derived_from_pattern="sealed-envelope" if sealed else "fixed-price",
        payment_phase_index=payment_phase_index,
    )
    companions = [
        {
            "identityBundle": copy.deepcopy(bundles[role]),
            "compositeRecord": copy.deepcopy(records[role]),
        }
        for role in agreement_roles
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
            "authenticatedReceiptAuthority": RECEIPT_AUTHORITY_CLAIM,
            "paymentPhaseIndex": payment_phase_index,
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
    result["verifierContext"]["qualificationPublicKeys"] = {
        claim: b64url(public_key(KEYS[role]))
        for role, claim in CLAIMS.items()
    }
    result["verifierContext"]["recipeRegistries"] = [
        copy.deepcopy(FIXTURE_RECIPE_REGISTRY)
    ]
    result["verifierContext"]["authenticatedQualification"] = {
        CLAIMS[role]: {
            "sessionStartId": f"{job_id}-{role}-session-start",
            "authenticatedSessionStart": copy.deepcopy(session_context),
            "vetInput": {
                "jobId": job_id,
                "actor": CLAIMS[role],
                "bundleToVet": copy.deepcopy(bundles[role]),
                "requirement": copy.deepcopy(signed_listing["buyerRequirement"]),
                "recipeRegistryVersion": 1,
                "sessionContext": copy.deepcopy(session_context),
            },
            "results": [{
                "ref": copy.deepcopy(result_refs[role]),
                "result": copy.deepcopy(results[role]),
            }],
        }
        for role in agreement_roles
    }
    if prior_agreement is not None and disposition is not None:
        result["priorAgreement"] = copy.deepcopy(prior_agreement)
        result["priorPaymentDisposition"] = {
            "artifact": copy.deepcopy(disposition),
            "receipt": {
                "state": "finalized",
                "contentHash": artifact_hash(disposition, "signature"),
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
        context["agreement"],
        f"{context['agreement'].get('jobId', 'bad')}-agreement",
        "signatures",
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
        if isinstance(pipeline, list) and all(isinstance(step, dict) for step in pipeline):
            context["terminalInput"]["bundle"]["phaseSummary"] = [
                {"index": index, "kind": step.get("kind"), "outcome": "ok"}
                for index, step in enumerate(pipeline)
            ]
        refresh_agreement_chain(context)
    elif action.startswith("bundle:"):
        index = int(action.split(":", 1)[1])
        companion = context["commitInput"]["identityBindingCompanions"][index]
        resign_bundle(companion["identityBundle"], ("buyer", "seller")[index])
        context["paymentInput"]["identityBindingCompanions"][index]["identityBundle"] = copy.deepcopy(companion["identityBundle"])
        context["terminalInput"]["identityBindingCompanions"][index]["identityBundle"] = copy.deepcopy(companion["identityBundle"])
    elif action.startswith("cvr-ref-chain:"):
        index = int(action.split(":", 1)[1])
        claim = context["agreement"]["parties"][index]["primaryClaim"]
        role = next(role for role, value in CLAIMS.items() if value == claim)
        companion = context["commitInput"]["identityBindingCompanions"][index]
        record = companion["compositeRecord"]
        record["signature"] = component_signature(record, COMPOSITE_DOMAIN, "orchestrator")
        for carrier in (context["paymentInput"], context["terminalInput"]):
            carrier["identityBindingCompanions"][index]["compositeRecord"] = copy.deepcopy(record)
        context["agreement"]["parties"][index]["vetRecordRef"] = artifact_ref(
            record,
            f"{context['agreement'].get('jobId', 'bad')}-{role}-cvr",
            "signature",
        )
        context["terminalInput"]["bundle"]["vetRecords"][index] = copy.deepcopy(
            context["agreement"]["parties"][index]["vetRecordRef"]
        )
        refresh_agreement_chain(context)
    elif action.startswith("commitment-receipt-evidence:"):
        variant = action.split(":", 1)[1]
        for wrapped in context["commitments"].values():
            mutate_fixture_evidence(wrapped["anchorReceipt"], variant)
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
        context["priorPaymentDisposition"]["receipt"]["contentHash"] = artifact_hash(
            value, "signature"
        )
        context["agreement"]["terms"]["priorPaymentDispositionRef"] = artifact_ref(
            value,
            f"{context['agreement'].get('jobId', 'bad')}-prior-disposition",
            "signature",
        )
        refresh_agreement_chain(context)
    elif action == "disposition-reference-chain":
        value = context["priorPaymentDisposition"]["artifact"]
        context["priorPaymentDisposition"]["receipt"]["contentHash"] = artifact_hash(
            value, "signature"
        )
        context["agreement"]["terms"]["priorPaymentDispositionRef"] = artifact_ref(
            value,
            f"{context['agreement'].get('jobId', 'bad')}-prior-disposition",
            "signature",
        )
        refresh_agreement_chain(context)
    elif action == "prior-agreement-reference-chain":
        value = context["priorPaymentDisposition"]["artifact"]
        value["priorAgreementRef"] = artifact_ref(
            context["priorAgreement"], "prior-agreement", "signatures"
        )
        value["signature"] = component_signature(
            value, DISPOSITION_DOMAIN, "orchestrator"
        )
        context["priorPaymentDisposition"]["receipt"]["contentHash"] = artifact_hash(
            value, "signature"
        )
        context["agreement"]["terms"]["priorPaymentDispositionRef"] = artifact_ref(
            value,
            f"{context['agreement'].get('jobId', 'bad')}-prior-disposition",
            "signature",
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


def append_mutation(path: list[Any], value: Any) -> dict[str, Any]:
    return {"op": "append-value", "path": path, "value": value}


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
    for stage in ("commit", "payment", "terminal"):
        vectors.append(vector(
            f"signed-listing-unknown-phase-refused-at-{stage}",
            "fail",
            scenario_name="identityBoundAgreement",
            stage=stage,
            mutations=[append_mutation(
                ["listing", "pipeline"], {"kind": "release-unknown-value"}
            )],
            resign=["listing-chain"],
            reason="unsupported-phase",
        ))
    vectors.append(vector(
        "signed-listing-duplicate-commitment-phase-refused",
        "fail",
        scenario_name="identityBoundAgreement",
        mutations=[append_mutation(
            ["listing", "pipeline"],
            {"kind": PHASES["identityBoundAgreement"]},
        )],
        resign=["listing-chain"],
        reason="commitment-phase-cardinality-invalid",
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
            "signed-listing-requirement-does-not-match-cvr", "fail",
            scenario_name="identityBoundAgreement",
            mutations=[set_mutation([
                "listing", "buyerRequirement", "required", 0, "parameters",
                "possessionVerified",
            ], False)],
            resign=["listing-chain"], reason="cvr-requirement-mismatch",
        ),
        vector(
            "signed-cvr-overall-decision-disagrees-with-replay", "fail",
            scenario_name="identityBoundAgreement",
            mutations=[set_mutation([
                "commitInput", "identityBindingCompanions", 0,
                "compositeRecord", "overallDecision",
            ], "fail")],
            resign=["cvr-ref-chain:0"], reason="cvr-aggregation-mismatch",
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
            "commitment-receipt-producer-cannot-self-attest-finality", "fail",
            scenario_name="identityBoundAgreement",
            resign=["commitment-receipt-evidence:producer-authority"],
            reason="commitment-receipt-invalid",
        ),
        vector(
            "commitment-receipt-native-content-tamper", "fail",
            scenario_name="identityBoundAgreement",
            resign=["commitment-receipt-evidence:content"],
            reason="commitment-receipt-invalid",
        ),
        vector(
            "commitment-receipt-native-transaction-tamper", "fail",
            scenario_name="identityBoundAgreement",
            resign=["commitment-receipt-evidence:transaction"],
            reason="commitment-receipt-invalid",
        ),
        vector(
            "commitment-receipt-native-location-tamper", "fail",
            scenario_name="identityBoundAgreement",
            resign=["commitment-receipt-evidence:location"],
            reason="commitment-receipt-invalid",
        ),
        vector(
            "commitment-receipt-native-ordering-tamper", "fail",
            scenario_name="identityBoundAgreement",
            resign=["commitment-receipt-evidence:ordering"],
            reason="commitment-receipt-invalid",
        ),
        vector(
            "commitment-receipt-native-block-tamper", "fail",
            scenario_name="identityBoundAgreement",
            resign=["commitment-receipt-evidence:block"],
            reason="commitment-receipt-invalid",
        ),
        vector(
            "commitment-receipt-native-finality-tamper", "fail",
            scenario_name="identityBoundAgreement",
            resign=["commitment-receipt-evidence:finality"],
            reason="commitment-receipt-invalid",
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
    for commitment in ("legacy", "finality"):
        vectors.append(vector(
            f"historical-sealed-envelope-losing-bidder-{commitment}",
            "pass",
            scenario_name="historicalSealed",
            commitment=commitment,
            reason="verified",
        ))
    vectors.append(vector(
        "modeled-old-reader-historical-sealed-envelope-losing-bidder",
        "pass",
        scenario_name="historicalSealed",
        stage="old-reader",
        reason="verified",
    ))
    for stage in ("commit", "payment", "terminal"):
        vectors.append(vector(
            f"identity-bound-sealed-envelope-losing-bidder-{stage}",
            "pass",
            scenario_name="identityBoundSealed",
            stage=stage,
            reason="verified",
        ))
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
    scenarios["historicalSealed"] = scenario(
        "agreement", JOB_IDS["historicalSealed"], sealed=True
    )
    scenarios["identityBoundSealed"] = scenario(
        "identityBoundAgreement", JOB_IDS["identityBoundSealed"], sealed=True
    )
    vectors = build_vectors()
    return {
        "set": "identity-bundle-hash-binding-v0.1",
        "spec": "CORE §B.2 IBH-1..IBH-6; DACS-1 §6.3.4; DACS-2 §7.7; DACS-3 §8.5/§8.6; DACS-4 §9.5/§9.9.1; DACS-5 §10.4/§10.5.1",
        "provenance": {
            "generator": "scripts/generate_identity_bundle_hash_binding_vectors.py",
            "cryptography": (
                "native cryptography Ed25519 sign/verify; JCS + SHA-256"
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
            "receiptAuthorityEvidence": {
                "kind": "independently-pinned-fixture-native-observer",
                "scope": "deterministic offline conformance fixture only",
                "observer": RECEIPT_AUTHORITY_CLAIM,
                "commitmentProducer": CLAIMS["orchestrator"],
                "liveSubstrateProof": False,
                "note": (
                    "The signed native observation exercises SR2-4/SR2-5 "
                    "binding and ordering checks but does not claim Demos or any "
                    "other live substrate consensus verification."
                ),
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
