#!/usr/bin/env python3
"""Generate DACS-5 v0.7 participation and rating admission vectors."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from reputation_evidence import (
    artifact_hash,
    decode_canonical_object,
    encode_canonical_object,
    jcs_hash,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "vectors" / "security"
    / "reputation-participation-admission-v0.7.json"
)
SET_NAME = "reputation-participation-admission-v0.7"
SPEC = "DACS-5 v0.7 §10.3.2/§10.5 SPA-1..SPA-8 exact participation and rating admission"

PARTICIPATION_DOMAIN = "dacs-participation-admission:v1:"
RATING_DOMAIN = "dacs-rating:v1:"
CHANNEL_DOMAIN = "dacs-channelmsg:v1:"
AGREEMENT_DOMAIN = "dacs-agreement:v1:"
PAYEE_BOUND_AGREEMENT_DOMAIN = "dacs-payee-bound-agreement:v1:"
ANCHOR_ADAPTER_DOMAIN = "dacs-test-participation-anchor-adapter:v1:"
CHALLENGE_ADAPTER_DOMAIN = "dacs-test-participation-challenge-adapter:v1:"
OUTCOME_ADAPTER_DOMAIN = "dacs-test-reputation-outcome-adapter:v1:"
ANCHOR_POLICY = "dacs-test-participation-anchor-v1"
CHALLENGE_POLICY = "dacs-test-session-challenge-v1"
OUTCOME_POLICY = {
    "policyId": "dacs-test-exact-session-outcome-v1",
    "adapter": "fixture-only-exact-session-outcome-adapter-v1",
    "trustSource": "conformance-harness-fixture-only",
    "proofProfile": "exact-job-bundle-listing-roster-phase-and-obligation",
    "historyOrder": "native-order-then-sha256-jcs-ascending",
}

JOB = "01J00000000000000000000000"
OTHER_JOB = "01J00000000000000000000001"
SESSION_NONCE = "aa" * 32
DEADLINE = 2_000
FIXTURE_CHALLENGE_ISSUED_AT = 1_000
FIXTURE_CHALLENGE_DURATION = 1_000
FIXTURE_VERIFIER_NOW = 1_500

# Verifier-owned corrective-profile authority.  It is never recovered from the
# caller input (the inert `currentProfile` boolean or any copied profile object);
# the independent reference evaluator reads it from the vector's verifier-owned
# `trustedContext` field and refuses before any one-sided blame or rating can
# become current/countable when it is absent, unauthenticated, duplicated, or
# pin/tuple/session/identity-mismatched.
AUTHORITATIVE_RELEASE_PIN = "0000000000000000000000000000000000000001"
AUTHORITATIVE_MODULE_VERSIONS = {
    "core": "0.3",
    "dacs1": "0.8",
    "dacs2": "0.6",
    "dacs3": "0.6",
    "dacs4": "0.8",
    "dacs5": "0.7",
}
AUTHORITATIVE_PROFILE = {
    "releasePin": AUTHORITATIVE_RELEASE_PIN,
    "moduleVersions": AUTHORITATIVE_MODULE_VERSIONS,
}


def private_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def claim_for(key: Ed25519PrivateKey) -> str:
    return "key:" + key.public_key().public_bytes_raw().hex()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def sign_artifact(
    unsigned: dict,
    key: Ed25519PrivateKey,
    signer: str,
    domain: str,
) -> dict:
    digest = artifact_hash(unsigned)
    return {
        **copy.deepcopy(unsigned),
        "signature": {
            "algorithm": "ed25519",
            "signer": signer,
            "value": b64url(key.sign((domain + digest).encode("ascii"))),
        },
    }


BUYER_KEY = private_key("dacs-395-buyer")
SELLER_KEY = private_key("dacs-395-seller")
OUTSIDER_KEY = private_key("dacs-395-outsider")
ORCHESTRATOR_KEY = private_key("dacs-395-orchestrator")
ADAPTER_KEY = private_key("dacs-395-fixture-adapter")
BUYER = claim_for(BUYER_KEY)
SELLER = claim_for(SELLER_KEY)
OUTSIDER = claim_for(OUTSIDER_KEY)
ORCHESTRATOR = claim_for(ORCHESTRATOR_KEY)
ADAPTER = claim_for(ADAPTER_KEY)

LISTING_REF = {"listingId": "listing-a", "version": 1, "contentHash": "44" * 32}
AGREEMENT_REF = {
    "anchor": {"kind": "storage-program", "locator": "storage-program:agreement-a"},
    "contentHash": "55" * 32,
    "signer": SELLER,
}
PARTIES = [
    {"role": "buyer", "primaryClaim": BUYER, "bundleHash": "66" * 32},
    {"role": "seller", "primaryClaim": SELLER, "bundleHash": "77" * 32},
]
AGREEMENT_PARTIES = [
    {
        **copy.deepcopy(PARTIES[0]),
        "vetRecordRef": {
            "anchor": {"kind": "storage-program", "locator": "storage-program:vet-buyer"},
            "contentHash": "86" * 32,
        },
    },
    {
        **copy.deepcopy(PARTIES[1]),
        "vetRecordRef": {
            "anchor": {"kind": "storage-program", "locator": "storage-program:vet-seller"},
            "contentHash": "87" * 32,
        },
    },
]


def agreement_domain(agreement: dict) -> str:
    if "agreementVersion" in agreement and "payeeBoundAgreementVersion" not in agreement:
        return AGREEMENT_DOMAIN
    if "payeeBoundAgreementVersion" in agreement and "agreementVersion" not in agreement:
        return PAYEE_BOUND_AGREEMENT_DOMAIN
    raise ValueError("agreement must have exactly one supported discriminator")


def set_agreement_signatures(
    agreement: dict,
    signers: list[tuple[Ed25519PrivateKey, str, str]],
) -> None:
    agreement["signatures"] = []
    digest = artifact_hash(agreement, signature_field="signatures")
    domain = agreement_domain(agreement)
    agreement["signatures"] = [
        {
            "party": party,
            "algorithm": algorithm,
            "value": b64url(key.sign((domain + digest).encode("ascii"))),
        }
        for key, party, algorithm in signers
    ]


PROPOSED_AGREEMENT = {
    "agreementVersion": "1",
    "jobId": JOB,
    "listingRef": copy.deepcopy(LISTING_REF),
    "parties": copy.deepcopy(AGREEMENT_PARTIES),
    "derivedFromPattern": "rfq",
    "terms": {
        "deliverable": {"deliverableType": "storage-program", "hash": "88" * 32},
        "price": {"amount": "10", "currency": "USDC"},
        "deadline": 3_000,
    },
    "generatedAt": 1_300,
    "signatures": [],
}
set_agreement_signatures(PROPOSED_AGREEMENT, [(BUYER_KEY, BUYER, "ed25519")])


def phase(index: int, kind: str) -> dict:
    return {"index": index, "kind": kind, "outcome": "ok"}


CHANNEL_MESSAGE = sign_artifact(
    {
        "channelId": "channel-job-a",
        "sequence": 4,
        "sender": BUYER,
        "sentAt": 1_200,
        "type": "counter",
        "body": {"proposedTermsHash": "12" * 32},
        "refs": {"repliesTo": 3},
    },
    BUYER_KEY,
    BUYER,
    CHANNEL_DOMAIN,
)


def mapped_obligation(kind: str) -> tuple[str, str]:
    if kind == "vet-credentials":
        return "vet-pending", "present-credentials"
    if kind.startswith("negotiate-"):
        return "negotiate-pending", "respond-to-negotiation"
    if kind.startswith("commit-"):
        return "commit-pending", "co-sign-agreement"
    if kind.startswith("pay-") and kind != "pay-alternative":
        return "settle-pending", "authorize-payment"
    if kind.startswith("deliver-"):
        return "settle-pending", "deliver"
    raise ValueError(kind)


def obligation(kind: str, index: int) -> dict:
    pending_state, owed_action = mapped_obligation(kind)
    item = {
        "obligationVersion": "1",
        "obligationType": "listing-phase-action",
        "phaseIndex": index,
        "phaseKind": kind,
        "pendingState": pending_state,
        "obligorRole": "seller",
        "owedAction": owed_action,
        "source": {
            "sourceType": "listing-phase",
            "listingRef": copy.deepcopy(LISTING_REF),
            "phaseIndex": index,
            "phaseKind": kind,
        },
    }
    if kind == "negotiate-rfq":
        item["obligationType"] = "rfq-turn-response"
        item["source"] = {
            "sourceType": "channel-message",
            "messageHash": artifact_hash(CHANNEL_MESSAGE),
            "channelId": CHANNEL_MESSAGE["channelId"],
            "sequence": CHANNEL_MESSAGE["sequence"],
            "sender": CHANNEL_MESSAGE["sender"],
            "expectedResponder": SELLER,
        }
    elif kind.startswith("commit-"):
        item["obligationType"] = "agreement-co-signature"
        item["source"] = {
            "sourceType": "agreement-proposal",
            "proposedAgreementHash": artifact_hash(
                PROPOSED_AGREEMENT, signature_field="signatures"
            ),
            "proposer": BUYER,
        }
    elif kind.startswith("pay-") or kind.startswith("deliver-"):
        item["obligationType"] = "agreement-performance"
        item["source"] = {
            "sourceType": "agreement-reference",
            "agreementRef": copy.deepcopy(AGREEMENT_REF),
        }
    return item


def timeout_marker(bound_obligation: dict) -> dict:
    return {
        "timeoutMarkerVersion": "1",
        "obligation": copy.deepcopy(bound_obligation),
        "deadline": DEADLINE,
        "deadlinePolicy": "obligor-admitted-absolute-consensus-deadline",
        "deadlineClock": "sr2-finalized-inclusion-timestamp",
    }


def challenge_evidence(
    obligor: str = SELLER,
    nonce: str = SESSION_NONCE,
    issued_by: str = BUYER,
    acting_for: str | None = None,
) -> dict:
    unsigned = {
        "challengeEvidenceVersion": "1",
        "policyId": CHALLENGE_POLICY,
        "jobId": JOB,
        "issuedBy": issued_by,
        "presentedTo": obligor,
        "nonce": nonce,
    }
    if acting_for is not None:
        unsigned["actingFor"] = acting_for
    return sign_artifact(
        unsigned,
        ADAPTER_KEY,
        ADAPTER,
        CHALLENGE_ADAPTER_DOMAIN,
    )


def receipt_adapter_evidence(receipt: dict) -> dict | None:
    evidence = receipt.get("evidence")
    if not isinstance(evidence, dict):
        return None
    return decode_canonical_object(evidence.get("value"))


def seal_receipt(
    receipt: dict,
    authorized_signer: str = SELLER,
    *,
    native_order: int | None = None,
    lineage_root_transaction: dict | None = None,
    replacement_relation: dict | None = None,
) -> dict:
    prior = receipt_adapter_evidence(receipt) or {}
    if native_order is None:
        native_order = prior.get("nativeOrder")
    if native_order is None:
        raise ValueError("fixture-native order is required")
    if lineage_root_transaction is None:
        lineage_root_transaction = prior.get("lineageRootTransactionRef")
    if lineage_root_transaction is None:
        lineage_root_transaction = copy.deepcopy(receipt.get("transactionRef"))
    if replacement_relation is None:
        replacement_relation = prior.get("replacementRelation")

    # These belong to the signed fixture adapter result, never to CORE AnchorReceipt.
    receipt.pop("adapterEvidence", None)
    receipt.pop("nativeOrder", None)
    receipt.pop("replacementRelation", None)
    receipt.pop("evidence", None)
    unsigned_evidence = {
        "anchorEvidenceVersion": "1",
        "policyId": ANCHOR_POLICY,
        "receiptHash": jcs_hash(receipt),
        "authorizedSigner": authorized_signer,
        "nativeOrder": native_order,
        "lineageRootTransactionRef": copy.deepcopy(lineage_root_transaction),
    }
    if receipt.get("state") == "replaced":
        if replacement_relation is None:
            replacement_relation = {
                "kind": "authenticated-replacement",
                "predecessor": copy.deepcopy(receipt.get("transactionRef")),
                "replacement": copy.deepcopy(receipt.get("replacementTransactionRef")),
            }
        unsigned_evidence["replacementRelation"] = copy.deepcopy(replacement_relation)
    adapter_result = sign_artifact(
        unsigned_evidence,
        ADAPTER_KEY,
        ADAPTER,
        ANCHOR_ADAPTER_DOMAIN,
    )
    receipt["evidence"] = {
        "kind": ANCHOR_POLICY,
        "value": encode_canonical_object(adapter_result),
    }
    return receipt


def tamper_receipt_adapter_field(receipt: dict, field: str, value: object) -> None:
    """Change signed adapter bytes without re-signing, for negative vectors."""
    adapter_result = receipt_adapter_evidence(receipt)
    if adapter_result is None:
        raise ValueError("missing fixture adapter evidence")
    adapter_result[field] = copy.deepcopy(value)
    receipt["evidence"]["value"] = encode_canonical_object(adapter_result)


def admission_receipt(
    admission: dict,
    *,
    transaction: str = "tx-participation-a",
    native_order: int = 15,
    timestamp: int = 1_500,
    state: str = "finalized",
    replacement_transaction: str | None = None,
    lineage_root_transaction: str | None = None,
) -> dict:
    bound_obligation = admission["obligation"]
    address_suffix = jcs_hash(bound_obligation)
    item = {
        "receiptVersion": "1",
        "substrate": "demos:testnet",
        "logicalAddress": (
            f"dacs5:participation:{admission['jobId']}:"
            f"{bound_obligation['obligorRole']}:{address_suffix}"
        ),
        "nativeAddress": f"storage-program:participation-{address_suffix[:16]}",
        "contentHash": artifact_hash(admission),
        "writer": "demos1seller",
        "nonce": "9",
        "finalityProfile": "demos-bft-final",
        "transactionRef": {"kind": "demos-tx", "value": transaction},
        "state": state,
        "observationDisposition": "established",
        "observedAt": 9_999_999,
    }
    if state in {"included", "finalized"}:
        item["blockRef"] = {
            "id": f"block-{native_order}",
            "height": str(native_order),
            "timestamp": timestamp,
        }
    if state == "replaced":
        if replacement_transaction is None:
            raise ValueError("a replaced receipt requires its replacement transaction")
        item["replacementTransactionRef"] = {
            "kind": "demos-tx", "value": replacement_transaction,
        }
    root = {
        "kind": "demos-tx",
        "value": lineage_root_transaction or transaction,
    }
    return seal_receipt(item, native_order=native_order, lineage_root_transaction=root)


def outcome_binding_objects(data: dict) -> dict:
    bundle = data["bundle"]
    objects = {
        "sessionOutcome": {
            "jobId": bundle["jobId"],
            "bundleContentHash": bundle["contentHash"],
            "outcome": bundle["outcome"],
        },
        "listingPipeline": {
            "listingRef": copy.deepcopy(data["listing"]["listingRef"]),
            "effectivePipeline": copy.deepcopy(data["listing"]["effectivePipeline"]),
        },
        "partyRoster": copy.deepcopy(bundle["parties"]),
        "phaseSummary": copy.deepcopy(bundle["phaseSummary"]),
    }
    if "timeout" in bundle:
        objects["timeoutMarker"] = copy.deepcopy(bundle["timeout"])
    return objects


def outcome_evidence(
    data: dict,
    *,
    timestamp: int = 2_100,
    native_order: int = 21,
    transaction: str = "tx-session-outcome-a",
    event_index: str = "0",
) -> dict:
    objects = outcome_binding_objects(data)
    bundle = data["bundle"]
    proof_kind = "obligation-nonresponse" if "timeout" in bundle else "completed-session"
    event = {
        "kind": "fixture-only-session-outcome-event",
        "substrate": "demos:testnet",
        "transactionRef": {"kind": "demos-tx", "value": transaction},
        "eventIndex": event_index,
        "nativeOrder": native_order,
        "timestamp": timestamp,
        "jobId": bundle["jobId"],
        "bundleContentHash": bundle["contentHash"],
        "outcome": bundle["outcome"],
    }
    if "timeoutMarker" in objects:
        event["obligationHash"] = jcs_hash(objects["timeoutMarker"]["obligation"])
    return sign_artifact(
        {
            "outcomeEvidenceVersion": "1",
            "policyId": OUTCOME_POLICY["policyId"],
            "proofKind": proof_kind,
            "objectHashes": {key: jcs_hash(value) for key, value in objects.items()},
            "nativeEvent": event,
        },
        ADAPTER_KEY,
        ADAPTER,
        OUTCOME_ADAPTER_DOMAIN,
    )


def one_sided_input(
    *,
    pipeline: list[str] | None = None,
    phase_index: int = 1,
) -> dict:
    effective = pipeline or ["vet-credentials", "negotiate-rfq"]
    kind = effective[phase_index]
    bound_obligation = obligation(kind, phase_index)
    prefix = [phase(i, item) for i, item in enumerate(effective[:phase_index])]
    admission = sign_artifact(
        {
            "participationAdmissionVersion": "1",
            "jobId": JOB,
            "listingRef": copy.deepcopy(LISTING_REF),
            "parties": copy.deepcopy(PARTIES),
            "completedPrefix": copy.deepcopy(prefix),
            "obligation": copy.deepcopy(bound_obligation),
            "deadline": DEADLINE,
            "deadlinePolicy": "obligor-admitted-absolute-consensus-deadline",
            "deadlineClock": "sr2-finalized-inclusion-timestamp",
            "sessionNonce": SESSION_NONCE,
            "admittedAt": 99_999_999,
        },
        SELLER_KEY,
        SELLER,
        PARTICIPATION_DOMAIN,
    )
    receipt = admission_receipt(admission)
    bundle = {
        "bundleType": "FaultAttestationBundle",
        "contentHash": "ab" * 32,
        "jobId": JOB,
        "listingRef": copy.deepcopy(LISTING_REF),
        "parties": copy.deepcopy(PARTIES),
        "phaseSummary": copy.deepcopy(prefix),
        "outcome": "aborted-by-other",
        "anchoredByRole": "buyer",
        "verifiedSignerRoles": ["buyer"],
        "faultedParty": "seller",
        "timeout": timeout_marker(bound_obligation),
    }
    if kind.startswith("pay-") or kind.startswith("deliver-"):
        bundle["agreementRef"] = copy.deepcopy(AGREEMENT_REF)
    data = {
        "mode": "one-sided-blame",
        "currentProfile": True,
        "windowStart": 1_000,
        "windowEnd": 3_000,
        "absenceDisposition": "absent",
        "listing": {
            "verificationDisposition": "verified",
            "listingRef": copy.deepcopy(LISTING_REF),
            "effectivePipeline": copy.deepcopy(effective),
        },
        "bundle": bundle,
        "sessionChallengeEvidence": challenge_evidence(),
        "authenticatedChannelMessages": (
            [copy.deepcopy(CHANNEL_MESSAGE)] if kind == "negotiate-rfq" else []
        ),
        "proposedAgreement": (
            copy.deepcopy(PROPOSED_AGREEMENT) if kind.startswith("commit-") else None
        ),
        "participationEvidence": {
            "admissionRef": {
                "anchor": {
                    "kind": "storage-program",
                    "locator": receipt["nativeAddress"],
                },
                "contentHash": artifact_hash(admission),
                "signer": SELLER,
            },
            "admission": admission,
            "admissionReceipt": copy.deepcopy(receipt),
            "admissionReceiptHistory": [copy.deepcopy(receipt)],
        },
        "outcomeTimePolicy": copy.deepcopy(OUTCOME_POLICY),
        "knownOutcomeEvidence": [],
    }
    data["knownOutcomeEvidence"] = [outcome_evidence(data)]
    return data


def rating_input() -> dict:
    pipeline = ["vet-credentials", "negotiate-fixed-price", "commit-agreement", "rate"]
    rating = sign_artifact(
        {
            "ratingVersion": "1",
            "jobId": JOB,
            "rater": BUYER,
            "target": SELLER,
            "targetRole": "seller",
            "value": 1,
            "ratedAt": 2_200,
        },
        BUYER_KEY,
        BUYER,
        RATING_DOMAIN,
    )
    rating_ref = {
        "anchor": {"kind": "storage-program", "locator": "storage-program:rating-a"},
        "contentHash": artifact_hash(rating),
        "signer": BUYER,
    }
    data = {
        "mode": "rating",
        "currentProfile": True,
        "windowStart": 1_000,
        "windowEnd": 3_000,
        "listing": {
            "verificationDisposition": "verified",
            "listingRef": copy.deepcopy(LISTING_REF),
            "effectivePipeline": pipeline,
        },
        "bundle": {
            "bundleType": "FaultAttestationBundle",
            "contentHash": "cd" * 32,
            "jobId": JOB,
            "listingRef": copy.deepcopy(LISTING_REF),
            "parties": copy.deepcopy(PARTIES),
            "outcome": "completed",
            "verifiedSignerRoles": ["buyer", "seller"],
            "phaseSummary": [phase(i, kind) for i, kind in enumerate(pipeline)],
            "ratingRefs": [copy.deepcopy(rating_ref)],
        },
        "ratingRef": copy.deepcopy(rating_ref),
        "rating": rating,
        "outcomeTimePolicy": copy.deepcopy(OUTCOME_POLICY),
        "knownOutcomeEvidence": [],
    }
    data["knownOutcomeEvidence"] = [outcome_evidence(data, timestamp=2_200)]
    return data


def reseal_all_receipts(data: dict) -> None:
    evidence = data["participationEvidence"]
    for receipt in [evidence["admissionReceipt"], *evidence["admissionReceiptHistory"]]:
        seal_receipt(receipt)


def resealed_receipts_changed(
    base: dict,
    mutate,
    *,
    sync_native_locator: bool = False,
) -> dict:
    item = copy.deepcopy(base)
    evidence = item["participationEvidence"]
    for receipt in [evidence["admissionReceipt"], *evidence["admissionReceiptHistory"]]:
        mutate(receipt)
        seal_receipt(receipt)
    if sync_native_locator:
        evidence["admissionRef"]["anchor"]["locator"] = copy.deepcopy(
            evidence["admissionReceipt"].get("nativeAddress")
        )
    return item


def resign_admission(data: dict) -> None:
    evidence = data["participationEvidence"]
    unsigned = copy.deepcopy(evidence["admission"])
    unsigned.pop("signature", None)
    role = unsigned["obligation"]["obligorRole"]
    key, signer = {
        "buyer": (BUYER_KEY, BUYER),
        "seller": (SELLER_KEY, SELLER),
    }[role]
    admission = sign_artifact(unsigned, key, signer, PARTICIPATION_DOMAIN)
    evidence["admission"] = admission
    digest = artifact_hash(admission)
    evidence["admissionRef"]["contentHash"] = digest
    evidence["admissionRef"]["signer"] = signer
    obligation_digest = jcs_hash(admission["obligation"])
    expected_address = (
        f"dacs5:participation:{admission['jobId']}:"
        f"{admission['obligation']['obligorRole']}:{obligation_digest}"
    )
    native_address = f"storage-program:participation-{obligation_digest[:16]}"
    evidence["admissionRef"]["anchor"]["locator"] = native_address
    for receipt in [evidence["admissionReceipt"], *evidence["admissionReceiptHistory"]]:
        receipt["logicalAddress"] = expected_address
        receipt["nativeAddress"] = native_address
        receipt["contentHash"] = digest
        seal_receipt(receipt, authorized_signer=signer)


def resign_rating(
    data: dict,
    *,
    key: Ed25519PrivateKey = BUYER_KEY,
    signer: str = BUYER,
) -> None:
    unsigned = copy.deepcopy(data["rating"])
    unsigned.pop("signature", None)
    old_ref = copy.deepcopy(data["ratingRef"])
    rating = sign_artifact(unsigned, key, signer, RATING_DOMAIN)
    data["rating"] = rating
    data["ratingRef"]["contentHash"] = artifact_hash(rating)
    data["ratingRef"]["signer"] = signer
    data["bundle"]["ratingRefs"] = [
        copy.deepcopy(data["ratingRef"]) if ref == old_ref else ref
        for ref in data["bundle"].get("ratingRefs", [])
    ]


def refresh_outcome(data: dict) -> None:
    prior = data.get("knownOutcomeEvidence") or []
    timestamp = 2_100
    if prior and isinstance(prior[0], dict):
        event = prior[0].get("nativeEvent")
        if isinstance(event, dict) and isinstance(event.get("timestamp"), int):
            timestamp = event["timestamp"]
    data["knownOutcomeEvidence"] = [outcome_evidence(data, timestamp=timestamp)]


def proposal_changed(
    base: dict,
    mutate,
    *,
    signers: list[tuple[Ed25519PrivateKey, str, str]] | None = None,
) -> dict:
    item = copy.deepcopy(base)
    proposal = item["proposedAgreement"]
    mutate(proposal)
    set_agreement_signatures(
        proposal,
        signers if signers is not None else [(BUYER_KEY, BUYER, "ed25519")],
    )
    source = item["participationEvidence"]["admission"]["obligation"]["source"]
    source["proposedAgreementHash"] = artifact_hash(
        proposal, signature_field="signatures"
    )
    item["bundle"]["timeout"]["obligation"] = copy.deepcopy(
        item["participationEvidence"]["admission"]["obligation"]
    )
    resign_admission(item)
    refresh_outcome(item)
    return item


def changed(base: dict, mutate) -> dict:
    item = copy.deepcopy(base)
    mutate(item)
    return item


def changed_and_refresh_outcome(base: dict, mutate) -> dict:
    item = changed(base, mutate)
    refresh_outcome(item)
    return item


def admission_changed(
    base: dict,
    mutate,
    *,
    sync_timeout: bool = False,
    refresh_outcome_evidence: bool = False,
) -> dict:
    item = copy.deepcopy(base)
    mutate(item["participationEvidence"]["admission"])
    if sync_timeout:
        item["bundle"]["timeout"]["obligation"] = copy.deepcopy(
            item["participationEvidence"]["admission"]["obligation"]
        )
    resign_admission(item)
    if refresh_outcome_evidence:
        refresh_outcome(item)
    return item


def rating_changed(
    base: dict,
    mutate,
    *,
    key: Ed25519PrivateKey = BUYER_KEY,
    signer: str = BUYER,
    resign: bool = False,
    refresh_outcome_evidence: bool = False,
) -> dict:
    item = copy.deepcopy(base)
    mutate(item)
    if resign:
        resign_rating(item, key=key, signer=signer)
    if refresh_outcome_evidence:
        refresh_outcome(item)
    return item


def channel_changed(base: dict, mutate, *, algorithm: str = "ed25519") -> dict:
    item = copy.deepcopy(base)
    unsigned = copy.deepcopy(item["authenticatedChannelMessages"][0])
    unsigned.pop("signature", None)
    mutate(unsigned)
    message = sign_artifact(unsigned, BUYER_KEY, BUYER, CHANNEL_DOMAIN)
    message["signature"]["algorithm"] = algorithm
    item["authenticatedChannelMessages"] = [message]
    admission = item["participationEvidence"]["admission"]
    admission["obligation"]["source"]["messageHash"] = artifact_hash(message)
    item["bundle"]["timeout"]["obligation"] = copy.deepcopy(admission["obligation"])
    resign_admission(item)
    refresh_outcome(item)
    return item


def with_replacement_predecessor(
    base: dict,
    *,
    predecessor: str = "tx-participation-predecessor",
    predecessor_order: int = 10,
) -> dict:
    item = copy.deepcopy(base)
    evidence = item["participationEvidence"]
    selected_transaction = evidence["admissionReceipt"]["transactionRef"]["value"]
    root = {"kind": "demos-tx", "value": predecessor}
    for receipt in [evidence["admissionReceipt"], *evidence["admissionReceiptHistory"]]:
        seal_receipt(receipt, lineage_root_transaction=root)
    evidence["admissionReceiptHistory"].append(admission_receipt(
        evidence["admission"],
        transaction=predecessor,
        native_order=predecessor_order,
        state="replaced",
        replacement_transaction=selected_transaction,
        lineage_root_transaction=predecessor,
    ))
    return item


def buyer_obligor_with_seller_fault(base: dict) -> dict:
    """Build one internally coherent buyer admission with only fault attribution mismatched."""
    item = copy.deepcopy(base)
    unsigned_message = copy.deepcopy(CHANNEL_MESSAGE)
    unsigned_message.pop("signature")
    unsigned_message["sender"] = SELLER
    message = sign_artifact(
        unsigned_message, SELLER_KEY, SELLER, CHANNEL_DOMAIN
    )
    item["authenticatedChannelMessages"] = [message]
    admission = item["participationEvidence"]["admission"]
    obligation_item = admission["obligation"]
    obligation_item["obligorRole"] = "buyer"
    obligation_item["source"].update({
        "messageHash": artifact_hash(message),
        "sender": SELLER,
        "expectedResponder": BUYER,
    })
    item["bundle"]["timeout"]["obligation"] = copy.deepcopy(obligation_item)
    item["sessionChallengeEvidence"] = challenge_evidence(
        obligor=BUYER, issued_by=SELLER
    )
    receipts = item["participationEvidence"]
    for receipt_item in [
        receipts["admissionReceipt"], *receipts["admissionReceiptHistory"]
    ]:
        receipt_item["writer"] = "demos1buyer"
    resign_admission(item)
    refresh_outcome(item)
    return item


def want(*, admitted: bool, blame: bool = False, rating: bool = False) -> dict:
    return {
        "reputationDisposition": "admitted" if admitted else "excluded",
        "oneSidedBlame": blame,
        "ratingCounted": rating,
        "currentWindowCountable": admitted,
    }


def verifier_fixture(*, anchor_nonce: str | None = "9", now: int = FIXTURE_VERIFIER_NOW) -> dict:
    anchor_binding = {} if anchor_nonce is None else {"nonce": anchor_nonce}
    return {
        "clock": {"now": now},
        "challengePolicy": {"duration": FIXTURE_CHALLENGE_DURATION},
        "challengeState": [
            {
                "jobId": JOB,
                "nonce": SESSION_NONCE,
                "issuedAt": FIXTURE_CHALLENGE_ISSUED_AT,
                "expiresAt": FIXTURE_CHALLENGE_ISSUED_AT + FIXTURE_CHALLENGE_DURATION,
                "status": "issued",
            }
        ],
        "anchorBinding": anchor_binding,
    }


def profile_role_record(
    session: str,
    role: str,
    claim: str,
    *,
    authenticated: bool = True,
    profile: dict | None = None,
) -> dict:
    return {
        "sessionId": session,
        "role": role,
        "participantIdentity": claim,
        "authenticated": authenticated,
        "profile": copy.deepcopy(AUTHORITATIVE_PROFILE if profile is None else profile),
    }


def profile_context(
    parties: list[dict],
    *,
    session: str | None = None,
    authenticated: bool = True,
    profile: dict | None = None,
    roles: list[tuple[str, str]] | None = None,
) -> dict:
    """Build the verifier-owned current-operation authority for one roster."""
    session = JOB if session is None else session
    rows = (
        [(role, claim) for role, claim in roles]
        if roles is not None
        else [(party["role"], party["primaryClaim"]) for party in parties]
    )
    return {
        "roleMap": [
            profile_role_record(
                session,
                role,
                claim,
                authenticated=authenticated,
                profile=profile,
            )
            for role, claim in rows
        ],
        "query": None,
        "entryAuthorities": [],
    }


_AUTO_CONTEXT = object()
_OMIT_CONTEXT = object()


def vector(
    name: str,
    expected: str,
    note: str,
    data: dict,
    result: dict,
    *,
    fixture: dict | None = None,
    trusted_context: object = _AUTO_CONTEXT,
) -> dict:
    item = {"name": name, "expected": expected, "note": note, "input": data, "want": result}
    if data.get("mode") == "one-sided-blame":
        item["verifierFixture"] = copy.deepcopy(
            verifier_fixture() if fixture is None else fixture
        )
    if trusted_context is _AUTO_CONTEXT:
        trusted_context = profile_context(data["bundle"]["parties"])
    if trusted_context is not _OMIT_CONTEXT:
        item["trustedContext"] = trusted_context
    return item


def build_vectors() -> list[dict]:
    base = one_sided_input()
    admitted_blame = want(admitted=True, blame=True)
    excluded = want(admitted=False)
    vectors = [
        vector("spa-valid-rfq-turn-obligation", "pass", "the signed admission binds the exact authenticated channel turn and derived responder", base, admitted_blame),
        vector("spa-valid-vet-obligation", "pass", "a source-backed index-zero vet obligation has an empty completed prefix", one_sided_input(pipeline=["vet-credentials"], phase_index=0), admitted_blame),
        vector("spa-valid-fixed-negotiation-obligation", "pass", "a fixed-price phase is bound to the exact signed Listing phase", one_sided_input(pipeline=["vet-credentials", "negotiate-fixed-price"], phase_index=1), admitted_blame),
        vector("spa-valid-commit-obligation", "pass", "commit binds the exact authenticated pre-cosign Agreement artifact hash and proposer signature", one_sided_input(pipeline=["vet-credentials", "negotiate-rfq", "commit-agreement"], phase_index=2), admitted_blame),
        vector("spa-valid-payment-obligation", "pass", "payment authorization binds the exact committed agreement reference", one_sided_input(pipeline=["vet-credentials", "negotiate-fixed-price", "commit-agreement", "pay-dem"], phase_index=3), admitted_blame),
        vector("spa-valid-delivery-obligation", "pass", "delivery binds the exact committed agreement reference", one_sided_input(pipeline=["vet-credentials", "negotiate-fixed-price", "commit-agreement", "pay-dem", "deliver-storage-program"], phase_index=4), admitted_blame),
    ]

    orchestrated = copy.deepcopy(base)
    orchestrator_party = {
        "role": "orchestrator", "primaryClaim": ORCHESTRATOR, "bundleHash": "76" * 32,
    }
    orchestrated["bundle"]["parties"].append(copy.deepcopy(orchestrator_party))
    orchestrated["bundle"]["parties"].sort(
        key=lambda party: (party["role"], party["primaryClaim"], party["bundleHash"])
    )
    orchestrated["participationEvidence"]["admission"]["parties"] = copy.deepcopy(
        orchestrated["bundle"]["parties"]
    )
    orchestrated["sessionChallengeEvidence"] = challenge_evidence(
        issued_by=ORCHESTRATOR, acting_for=BUYER
    )
    resign_admission(orchestrated)
    refresh_outcome(orchestrated)
    vectors.append(vector(
        "spa-valid-roster-orchestrator-challenge", "pass",
        "the trusted challenge adapter authenticates the in-roster session orchestrator acting for the counterparty",
        orchestrated, admitted_blame,
    ))

    direct_with_orchestrator = copy.deepcopy(orchestrated)
    direct_with_orchestrator["sessionChallengeEvidence"] = challenge_evidence()
    vectors.append(vector(
        "spa-valid-direct-challenge-with-orchestrator-roster", "pass",
        "the actual counterparty remains direct challenge authority when the unique roster also has an orchestrator",
        direct_with_orchestrator, admitted_blame,
    ))

    alternate_writer = resealed_receipts_changed(
        base, lambda receipt: receipt.__setitem__("writer", "demos1delegated-writer")
    )
    vectors.append(vector(
        "spa-valid-adapter-authorized-alternate-writer", "pass",
        "the trusted adapter binds a nonempty delegated native writer to the exact obligor-authorized receipt hash",
        alternate_writer, admitted_blame,
    ))

    nonce_less = resealed_receipts_changed(base, lambda receipt: receipt.pop("nonce", None))
    vectors.append(vector(
        "spa-valid-nonce-less-portable-receipt", "pass",
        "CORE nonce remains optional when the independent fixture binding context selects a nonce-less receipt",
        nonce_less, admitted_blame, fixture=verifier_fixture(anchor_nonce=None),
    ))

    empty_nonce = resealed_receipts_changed(base, lambda receipt: receipt.__setitem__("nonce", ""))
    vectors.append(vector(
        "spa-valid-empty-string-nonce", "pass",
        "CORE constrains an applicable nonce to string shape without globally prohibiting the empty string",
        empty_nonce, admitted_blame, fixture=verifier_fixture(anchor_nonce=""),
    ))
    vectors.append(vector(
        "spa-receipt-nonce-binding-context-mismatch", "indeterminate",
        "a present receipt nonce must exactly equal the independently selected binding context",
        copy.deepcopy(base), excluded, fixture=verifier_fixture(anchor_nonce="10"),
    ))

    optional_block_members = copy.deepcopy(base)
    optional_block_evidence = optional_block_members["participationEvidence"]
    included_receipt = admission_receipt(
        optional_block_evidence["admission"],
        transaction="tx-participation-a",
        native_order=14,
        timestamp=1_400,
        state="included",
    )
    included_receipt["blockRef"].pop("height")
    included_receipt["blockRef"].pop("timestamp")
    seal_receipt(included_receipt)
    optional_block_evidence["admissionReceiptHistory"].append(included_receipt)
    vectors.append(vector(
        "spa-valid-optional-block-members-in-history", "pass",
        "a non-selected included CORE receipt needs blockRef.id but does not globally require optional height or timestamp",
        optional_block_members, admitted_blame,
    ))

    finalized_no_height = resealed_receipts_changed(
        base, lambda receipt: receipt["blockRef"].pop("height", None)
    )
    vectors.append(vector(
        "spa-valid-finalized-block-without-height", "pass",
        "the selected finalized CORE blockRef requires id while height remains optional",
        finalized_no_height, admitted_blame,
    ))

    commit = one_sided_input(
        pipeline=["vet-credentials", "negotiate-rfq", "commit-agreement"], phase_index=2
    )
    forward_agreement = proposal_changed(
        commit, lambda agreement: agreement.__setitem__(
            "futureSignedMetadata", {"source": "preserved"}
        )
    )
    vectors.append(vector(
        "spa-valid-forward-agreement-member", "pass",
        "an unknown signed Agreement member remains in the signature-omitted source hash and proposer signature payload",
        forward_agreement, admitted_blame,
    ))

    forward_channel = channel_changed(
        base, lambda message: message.__setitem__("futureEnvelopeMetadata", {"trace": "signed"})
    )
    vectors.append(vector(
        "spa-valid-forward-channel-envelope-member", "pass",
        "an unknown forward-compatible DACS-3 envelope member remains in the exact signed bytes and source hash",
        forward_channel, admitted_blame,
    ))

    unrelated_sources = copy.deepcopy(base)
    unrelated_sources["authenticatedChannelMessages"].insert(0, [])
    unrelated_unsigned = copy.deepcopy(CHANNEL_MESSAGE)
    unrelated_unsigned.pop("signature")
    unrelated_unsigned["body"]["proposedTermsHash"] = "13" * 32
    unrelated_unavailable = sign_artifact(
        unrelated_unsigned, BUYER_KEY, BUYER, CHANNEL_DOMAIN
    )
    unrelated_unavailable["signature"]["algorithm"] = "ecdsa-secp256k1"
    unrelated_sources["authenticatedChannelMessages"].append(unrelated_unavailable)
    vectors.append(vector(
        "spa-rfq-unrelated-malformed-and-unavailable-sources-ignored", "pass",
        "unrelated malformed or locally unavailable envelopes do not poison the one exact unsigned-body hash match",
        unrelated_sources, admitted_blame,
    ))

    valid_replacement = with_replacement_predecessor(base)
    vectors.append(vector(
        "spa-valid-incoming-replacement-lineage", "pass",
        "a complete unique adapter-authenticated predecessor lineage reaches the selected finalized transaction",
        valid_replacement, admitted_blame,
    ))

    prefix_evidence = changed(base, lambda x: x["bundle"]["phaseSummary"][0].update({
        "txRefs": [{"kind": "demos-tx", "value": "tx-vet-a"}],
        "attestationRef": {"anchor": {"kind": "storage-program", "locator": "vet-a"}, "contentHash": "ef" * 32},
    }))
    refresh_outcome(prefix_evidence)
    vectors.append(vector(
        "spa-prefix-projection-allows-authenticated-bundle-evidence", "pass",
        "optional authenticated phase evidence stays outside the three-field prefix projection",
        prefix_evidence, admitted_blame,
    ))

    producer_reuse = changed(base, lambda x: x.__setitem__("producerNonceClaim", "previously-used-for-other-job"))
    vectors.append(vector(
        "spa-producer-nonce-reuse-claim-is-inert", "pass",
        "an unsupported producer freshness/reuse claim cannot veto trusted job challenge matching",
        producer_reuse, admitted_blame,
    ))

    unissued_challenge = admission_changed(
        base, lambda admission: admission.__setitem__("sessionNonce", "bb" * 32)
    )
    unissued_challenge["sessionChallengeEvidence"] = challenge_evidence(
        nonce="bb" * 32
    )
    vectors.append(vector(
        "spa-unissued-verifier-challenge-fails", "fail",
        "an authoritative verifier-state miss rejects a nonce that was never issued",
        unissued_challenge, excluded,
    ))
    vectors.append(vector(
        "spa-expired-verifier-challenge-fails", "fail",
        "the verifier clock rejects an issued challenge after the fixture-local duration",
        copy.deepcopy(base), excluded,
        fixture=verifier_fixture(now=FIXTURE_CHALLENGE_ISSUED_AT + FIXTURE_CHALLENGE_DURATION + 1),
    ))

    duplicate_history = changed(base, lambda x: x["participationEvidence"]["admissionReceiptHistory"].append(
        copy.deepcopy(x["participationEvidence"]["admissionReceiptHistory"][0])
    ))
    vectors.append(vector(
        "spa-byte-identical-receipt-history-collapses", "pass",
        "byte-identical authenticated snapshots collapse before exact selected-member comparison",
        duplicate_history, admitted_blame,
    ))

    advisory = admission_changed(base, lambda a: a.__setitem__("admittedAt", 1))
    vectors.append(vector(
        "spa-admitted-at-is-advisory", "pass",
        "producer time cannot replace challenge, receipt, or outcome authority",
        advisory, admitted_blame,
    ))

    cases: list[tuple[str, str, str, dict]] = []
    cases.extend([
        ("spa-never-participant-missing-admission", "indeterminate", "absence proves non-publication, not participation", changed(base, lambda x: x.__setitem__("participationEvidence", None))),
        ("spa-unqualified-bundle-absence", "indeterminate", "participation does not replace authoritative bundle absence", changed(base, lambda x: x.__setitem__("absenceDisposition", "indeterminate"))),
        ("spa-invalid-admission-signature", "fail", "a forged admission cannot establish participation", changed(base, lambda x: x["participationEvidence"]["admission"]["signature"].__setitem__("value", "A" * 86))),
        ("spa-signed-unknown-admission-field", "fail", "a valid signature over an unknown SPA-v1 member cannot bypass the closed schema", admission_changed(base, lambda a: a.__setitem__("futureAuthority", True))),
        ("spa-wrong-job-replay", "fail", "a re-signed admission from another job cannot cross sessions", admission_changed(base, lambda a: a.__setitem__("jobId", OTHER_JOB))),
        ("spa-wrong-listing", "fail", "a re-signed admission cannot substitute another Listing", admission_changed(base, lambda a: a["listingRef"].__setitem__("contentHash", "cc" * 32))),
        ("spa-roster-primary-claim-mismatch", "fail", "the internally coherent admitted roster must equal the distinct authenticated terminal roster", copy.deepcopy(base)),
        ("spa-duplicate-buyer-role-resigned", "fail", "roles are globally unique even when admission and bundle carry the same duplicate", copy.deepcopy(base)),
        ("spa-duplicate-primary-claim-resigned", "fail", "primary claims are globally unique across the complete roster", copy.deepcopy(base)),
        ("spa-roster-order-noncanonical", "fail", "the complete roster has one canonical order", admission_changed(base, lambda a: a.__setitem__("parties", list(reversed(a["parties"]))))),
        ("spa-obligor-not-faulted-party", "fail", "an internally coherent buyer admission cannot be used to blame the seller", buyer_obligor_with_seller_fault(base)),
        ("spa-timeout-obligation-mismatch", "fail", "the timeout marker must carry the exact signed typed obligation", changed_and_refresh_outcome(base, lambda x: x["bundle"]["timeout"]["obligation"]["source"].__setitem__("messageHash", "33" * 32))),
        ("spa-rfq-turn-hash-mismatch", "fail", "an authenticated channel turn cannot be replaced by another body hash", admission_changed(base, lambda a: a["obligation"]["source"].__setitem__("messageHash", "34" * 32), sync_timeout=True, refresh_outcome_evidence=True)),
        ("spa-rfq-turn-sequence-mismatch", "fail", "the exact DACS-3 sequence is part of the obligation", admission_changed(base, lambda a: a["obligation"]["source"].__setitem__("sequence", 5), sync_timeout=True, refresh_outcome_evidence=True)),
        ("spa-rfq-expected-responder-mismatch", "fail", "the source turn derives the opposite unique roster party as responder", admission_changed(base, lambda a: a["obligation"]["source"].__setitem__("expectedResponder", BUYER), sync_timeout=True, refresh_outcome_evidence=True)),
        ("spa-rfq-source-message-unavailable", "indeterminate", "an unavailable signed source turn cannot establish the RFQ obligation", changed(base, lambda x: x.__setitem__("authenticatedChannelMessages", []))),
        ("spa-rfq-duplicate-exact-source", "fail", "two exact unsigned-body hash matches are ambiguous even when byte-identical", changed(base, lambda x: x["authenticatedChannelMessages"].append(copy.deepcopy(x["authenticatedChannelMessages"][0])))),
        ("spa-changed-channel-body-with-stale-signature", "fail", "source lookup verifies the complete received DACS-3 envelope", changed(base, lambda x: x["authenticatedChannelMessages"][0]["body"].__setitem__("proposedTermsHash", "35" * 32))),
        ("spa-commit-proposal-hash-mismatch", "fail", "commit cannot borrow an admission for a different proposed agreement", one_sided_input(pipeline=["vet-credentials", "negotiate-rfq", "commit-agreement"], phase_index=2)),
        ("spa-timeout-commit-proposal-mismatch", "fail", "the timeout marker cannot substitute another commit proposal", one_sided_input(pipeline=["vet-credentials", "negotiate-rfq", "commit-agreement"], phase_index=2)),
        ("spa-commit-arbitrary-hash-matching-object", "fail", "a hash-matching arbitrary object is not authenticated DACS-3 Agreement source authority", copy.deepcopy(commit)),
        ("spa-commit-proposal-wrong-job", "fail", "a valid proposer signature cannot move an Agreement proposal across jobs", proposal_changed(commit, lambda agreement: agreement.__setitem__("jobId", OTHER_JOB))),
        ("spa-commit-proposal-wrong-listing", "fail", "the authenticated Agreement proposal must pin the exact admission Listing", proposal_changed(commit, lambda agreement: agreement["listingRef"].__setitem__("contentHash", "91" * 32))),
        ("spa-commit-proposal-wrong-pattern", "fail", "the authenticated Agreement pattern must match the Listing negotiation phase", proposal_changed(commit, lambda agreement: agreement.__setitem__("derivedFromPattern", "fixed-price"))),
        ("spa-commit-proposal-invalid-signature", "fail", "a malformed proposer signature cannot authenticate pre-cosign Agreement authority", changed(commit, lambda x: x["proposedAgreement"]["signatures"][0].__setitem__("value", "A" * 86))),
        ("spa-commit-proposal-algorithm-unavailable", "indeterminate", "a registered Agreement signature algorithm unavailable to the fixture resolver does not become invalid", changed(commit, lambda x: x["proposedAgreement"]["signatures"][0].__setitem__("algorithm", "sr1-aggregate"))),
        ("spa-commit-proposal-source-unavailable", "indeterminate", "missing proposed Agreement source authority cannot establish a co-signature obligation", changed(commit, lambda x: x.__setitem__("proposedAgreement", None))),
        ("spa-commit-proposal-signature-missing", "indeterminate", "an Agreement-shaped proposal without a proposer signature has unavailable source authority", proposal_changed(commit, lambda agreement: None, signers=[])),
        ("spa-commit-proposer-substitution", "fail", "even a valid obligor signature cannot substitute the exact opposite proposer", copy.deepcopy(commit)),
        ("spa-commit-obligor-already-cosigned", "fail", "a valid obligor co-signature proves the admitted co-sign action is no longer owed", proposal_changed(commit, lambda agreement: None, signers=[(BUYER_KEY, BUYER, "ed25519"), (SELLER_KEY, SELLER, "ed25519")])),
        ("spa-commit-artifact-phase-mismatch", "fail", "a payee-bound Agreement artifact cannot satisfy a legacy commit-agreement phase", proposal_changed(commit, lambda agreement: (agreement.__setitem__("payeeBoundAgreementVersion", agreement.pop("agreementVersion")), agreement["terms"].__setitem__("payoutBindings", [])))),
        ("spa-wrong-action", "fail", "the typed action must follow the active phase mapping", admission_changed(base, lambda a: a["obligation"].__setitem__("owedAction", "co-sign-agreement"), sync_timeout=True, refresh_outcome_evidence=True)),
        ("spa-phase-never-active", "fail", "a phase outside the effective pipeline was never due", admission_changed(base, lambda a: a["obligation"].__setitem__("phaseIndex", 2), sync_timeout=True, refresh_outcome_evidence=True)),
        ("spa-incomplete-completed-prefix", "fail", "the active-phase acknowledgement cannot omit a prior phase", admission_changed(base, lambda a: a.__setitem__("completedPrefix", []))),
        ("spa-prefix-contradicts-bundle", "fail", "the admitted prefix must match authenticated terminal phase facts", changed_and_refresh_outcome(base, lambda x: x["bundle"].__setitem__("phaseSummary", []))),
        ("spa-pay-alternative-is-not-handler", "fail", "listing-only pay-alternative is not an executable obligation", admission_changed(base, lambda a: (a["obligation"].__setitem__("phaseKind", "pay-alternative"), a["obligation"].__setitem__("pendingState", "settle-pending"), a["obligation"].__setitem__("owedAction", "authorize-payment")), sync_timeout=True, refresh_outcome_evidence=True)),
        ("spa-session-challenge-mismatch", "fail", "producer freshness cannot replace the verifier-issued job challenge", admission_changed(base, lambda a: a.__setitem__("sessionNonce", "bb" * 32))),
        ("spa-outsider-issued-challenge", "fail", "a trusted adapter signature does not make a non-counterparty nonce issuer authorized", changed(base, lambda x: x.__setitem__("sessionChallengeEvidence", challenge_evidence(issued_by=OUTSIDER)))),
        ("spa-orchestrator-challenge-missing-delegation", "indeterminate", "an in-roster orchestrator without authenticated exact-counterparty delegation has no challenge authority", changed(orchestrated, lambda x: x.__setitem__("sessionChallengeEvidence", challenge_evidence(issued_by=ORCHESTRATOR)))),
        ("spa-orchestrator-challenge-wrong-party-delegation", "fail", "signed orchestrator delegation for the obligor contradicts the required exact counterparty relation", changed(orchestrated, lambda x: x.__setitem__("sessionChallengeEvidence", challenge_evidence(issued_by=ORCHESTRATOR, acting_for=SELLER)))),
        ("spa-unsigned-orchestrator-delegation-is-inert", "indeterminate", "an unsigned producer acting-for assertion cannot repair missing signed adapter delegation", changed(orchestrated, lambda x: (x.__setitem__("sessionChallengeEvidence", challenge_evidence(issued_by=ORCHESTRATOR)), x.__setitem__("orchestratorActingFor", BUYER)))),
        ("spa-producer-fresh-flag-cannot-authorize", "fail", "a fresh producer flag is inert when trusted challenge matching fails", admission_changed(base, lambda a: a.__setitem__("sessionNonce", "bb" * 32))),
        ("spa-signed-nonce-fresh-flag-is-unknown", "fail", "SPA-v1 does not acquire global nonce-index authority from a signed boolean", admission_changed(base, lambda a: a.__setitem__("nonceFresh", True))),
        ("spa-missing-challenge-authority", "indeterminate", "missing verifier-issued challenge evidence cannot authorize", changed(base, lambda x: x.__setitem__("sessionChallengeEvidence", None))),
        ("spa-wrong-deadline", "fail", "the timeout deadline must equal the signed admission", changed_and_refresh_outcome(base, lambda x: x["bundle"]["timeout"].__setitem__("deadline", 2_001))),
        ("spa-admission-at-deadline-too-late", "fail", "the exact admission must finalize before its accepted deadline", copy.deepcopy(base)),
        ("spa-missing-admission-receipt", "indeterminate", "a signature without exact finalized anchor authority is non-countable", changed(base, lambda x: x["participationEvidence"].__setitem__("admissionReceipt", None))),
        ("spa-marker-only-receipt-history", "indeterminate", "a producer disposition marker is not an authenticated receipt", changed(base, lambda x: x["participationEvidence"].__setitem__("admissionReceiptHistory", [{"historyDisposition": "canonical"}]))),
        ("spa-selected-receipt-not-in-history", "indeterminate", "selection must be an exact canonical-history member", changed(base, lambda x: x["participationEvidence"].__setitem__("admissionReceiptHistory", []))),
        ("spa-signed-receipt-transaction-substitution", "indeterminate", "adapter evidence authenticates the complete transaction field", copy.deepcopy(base)),
        ("spa-signed-receipt-writer-substitution", "indeterminate", "adapter evidence authenticates the native writer", copy.deepcopy(base)),
        ("spa-signed-receipt-nonce-substitution", "indeterminate", "adapter evidence authenticates the native nonce", copy.deepcopy(base)),
        ("spa-signed-receipt-native-order-substitution", "indeterminate", "adapter evidence authenticates native ordering", copy.deepcopy(base)),
        ("spa-resealed-receipt-writer-array", "indeterminate", "an adapter-resealed array writer is not a portable CORE receipt", resealed_receipts_changed(base, lambda receipt: receipt.__setitem__("writer", ["demos1seller"]))),
        ("spa-resealed-receipt-writer-object", "indeterminate", "an adapter-resealed object writer is not a portable CORE receipt", resealed_receipts_changed(base, lambda receipt: receipt.__setitem__("writer", {"account": "demos1seller"}))),
        ("spa-resealed-receipt-writer-empty", "indeterminate", "an adapter-resealed empty writer cannot identify native authority", resealed_receipts_changed(base, lambda receipt: receipt.__setitem__("writer", ""))),
        ("spa-resealed-receipt-nonce-object", "indeterminate", "an adapter-resealed object nonce violates the optional string wire shape", resealed_receipts_changed(base, lambda receipt: receipt.__setitem__("nonce", {"value": "9"}))),
        ("spa-required-receipt-nonce-missing", "indeterminate", "an independently nonce-bound lookup does not accept an omitted receipt nonce", resealed_receipts_changed(base, lambda receipt: receipt.pop("nonce", None))),
        ("spa-resealed-receipt-native-address-array", "fail", "a matching array locator and adapter-resealed native address remain malformed", resealed_receipts_changed(base, lambda receipt: receipt.__setitem__("nativeAddress", ["storage-program:participation"]), sync_native_locator=True)),
        ("spa-resealed-receipt-native-address-empty", "fail", "a matching empty locator and adapter-resealed native address remain malformed", resealed_receipts_changed(base, lambda receipt: receipt.__setitem__("nativeAddress", ""), sync_native_locator=True)),
        ("spa-resealed-receipt-content-not-hash", "indeterminate", "adapter authentication cannot turn a malformed content hash into this admission digest", resealed_receipts_changed(base, lambda receipt: receipt.__setitem__("contentHash", "not-a-sha256"))),
        ("spa-finalized-receipt-missing-deadline-timestamp", "indeterminate", "the selected finalized participation receipt separately needs blockRef.timestamp for its deadline comparison", resealed_receipts_changed(base, lambda receipt: receipt["blockRef"].pop("timestamp", None))),
        ("spa-finalized-receipt-missing-block-id", "indeterminate", "CORE blockRef.id remains required even when height and timestamp are independently optional", resealed_receipts_changed(base, lambda receipt: receipt["blockRef"].pop("id", None))),
        ("spa-finalized-receipt-malformed-height", "indeterminate", "a present CORE block height must retain its string shape", resealed_receipts_changed(base, lambda receipt: receipt["blockRef"].__setitem__("height", []))),
        ("spa-producer-receipt-booleans-rejected", "indeterminate", "producer evidenceValid/writerAuthorized booleans are not adapter evidence", copy.deepcopy(base)),
        ("spa-conflicting-finalized-receipt-history", "indeterminate", "a second authenticated but unauthorized finalization cannot be cherry-picked", copy.deepcopy(base)),
        ("spa-illegal-post-finality-history", "indeterminate", "all known authenticated lifecycle observations are reconciled", copy.deepcopy(base)),
        ("spa-admission-receipt-hash-mismatch", "indeterminate", "an adapter-authenticated receipt for other bytes cannot bind this admission", copy.deepcopy(base)),
        ("spa-missing-replacement-predecessor", "indeterminate", "a signed lineage-root declaration cannot replace the missing predecessor receipt and relation", copy.deepcopy(base)),
        ("spa-disconnected-receipt-history", "indeterminate", "an authenticated but disconnected transaction cannot enter the selected lineage", copy.deepcopy(base)),
        ("spa-branched-replacement-history", "indeterminate", "one authenticated predecessor cannot select two replacement transactions", copy.deepcopy(base)),
        ("spa-cyclic-replacement-history", "indeterminate", "authenticated replacement relations cannot form a cycle", copy.deepcopy(base)),
        ("spa-late-replacement-edge", "indeterminate", "a predecessor relation ordered after successor finality cannot authorize selection", with_replacement_predecessor(base, predecessor_order=16)),
        ("spa-finalized-predecessor-replaced", "indeterminate", "a finalized predecessor cannot later transition to replaced", with_replacement_predecessor(base)),
        ("spa-receipt-state-list", "indeterminate", "a trusted adapter-signed list-valued lifecycle state is malformed without escaping an exception", copy.deepcopy(base)),
        ("spa-receipt-state-object", "indeterminate", "a trusted adapter-signed object-valued lifecycle state is malformed without escaping an exception", copy.deepcopy(base)),
        ("spa-supported-receipt-algorithm-unavailable", "indeterminate", "a registered signature algorithm unavailable to the fixture adapter is not mislabeled invalid", copy.deepcopy(base)),
        ("spa-missing-outcome-authority", "indeterminate", "deadline passage and publication cannot prove nonresponse", changed(base, lambda x: x.__setitem__("knownOutcomeEvidence", []))),
        ("spa-unsupported-outcome-policy", "indeterminate", "a policy identifier does not grant outcome authority", changed(base, lambda x: x["outcomeTimePolicy"].__setitem__("policyId", "producer-policy"))),
        ("spa-forged-outcome-evidence", "indeterminate", "producer-created outcome evidence cannot establish abort causality", changed(base, lambda x: x["knownOutcomeEvidence"][0]["signature"].__setitem__("value", "A" * 86))),
        ("spa-conflicting-outcome-evidence", "indeterminate", "conflicting trusted exact outcome events are non-countable", copy.deepcopy(base)),
        ("spa-publication-after-deadline-without-outcome", "indeterminate", "late publication still supplies no nonresponse authority", changed(base, lambda x: x.__setitem__("knownOutcomeEvidence", []))),
        ("spa-supported-channel-algorithm-unavailable", "indeterminate", "a registered ChannelMessage algorithm unavailable to the fixture resolver is not invalid", channel_changed(base, lambda message: None, algorithm="ecdsa-secp256k1")),
        ("spa-unknown-channel-algorithm", "fail", "an unregistered ChannelMessage algorithm is rejected", channel_changed(base, lambda message: None, algorithm="future-signature")),
        ("spa-roster-role-list-resigned", "fail", "a signed list-valued roster role is malformed without escaping an exception", copy.deepcopy(base)),
        ("spa-roster-role-object-resigned", "fail", "a signed object-valued roster role is malformed without escaping an exception", copy.deepcopy(base)),
    ])

    # Complete mutations that need multi-object synchronization or trusted fixture signatures.
    roster_mismatch = next(
        item for item in cases if item[0] == "spa-roster-primary-claim-mismatch"
    )[3]
    roster_mismatch["bundle"]["parties"].append({
        "role": "orchestrator",
        "primaryClaim": ORCHESTRATOR,
        "bundleHash": "76" * 32,
    })
    roster_mismatch["bundle"]["parties"].sort(
        key=lambda party: (party["role"], party["primaryClaim"], party["bundleHash"])
    )
    refresh_outcome(roster_mismatch)

    duplicate_role = next(item for item in cases if item[0] == "spa-duplicate-buyer-role-resigned")[3]
    duplicate_role_party = {
        "role": "buyer", "primaryClaim": ORCHESTRATOR, "bundleHash": "76" * 32,
    }
    duplicate_role["bundle"]["parties"].append(copy.deepcopy(duplicate_role_party))
    duplicate_role["bundle"]["parties"].sort(
        key=lambda party: (party["role"], party["primaryClaim"], party["bundleHash"])
    )
    duplicate_role["participationEvidence"]["admission"]["parties"] = copy.deepcopy(
        duplicate_role["bundle"]["parties"]
    )
    resign_admission(duplicate_role)
    refresh_outcome(duplicate_role)

    duplicate_claim = next(item for item in cases if item[0] == "spa-duplicate-primary-claim-resigned")[3]
    duplicate_claim_party = {
        "role": "orchestrator", "primaryClaim": BUYER, "bundleHash": "76" * 32,
    }
    duplicate_claim["bundle"]["parties"].append(copy.deepcopy(duplicate_claim_party))
    duplicate_claim["bundle"]["parties"].sort(
        key=lambda party: (party["role"], party["primaryClaim"], party["bundleHash"])
    )
    duplicate_claim["participationEvidence"]["admission"]["parties"] = copy.deepcopy(
        duplicate_claim["bundle"]["parties"]
    )
    resign_admission(duplicate_claim)
    refresh_outcome(duplicate_claim)

    for case_name, malformed_role in (
        ("spa-roster-role-list-resigned", ["buyer"]),
        ("spa-roster-role-object-resigned", {"role": "buyer"}),
    ):
        malformed_roster = next(item for item in cases if item[0] == case_name)[3]
        malformed_roster["bundle"]["parties"][0]["role"] = copy.deepcopy(malformed_role)
        malformed_roster["participationEvidence"]["admission"]["parties"][0]["role"] = copy.deepcopy(malformed_role)
        resign_admission(malformed_roster)
        refresh_outcome(malformed_roster)

    commit_mismatch = next(item for item in cases if item[0] == "spa-commit-proposal-hash-mismatch")[3]
    commit_mismatch["participationEvidence"]["admission"]["obligation"]["source"]["proposedAgreementHash"] = "99" * 32
    commit_mismatch["bundle"]["timeout"]["obligation"] = copy.deepcopy(commit_mismatch["participationEvidence"]["admission"]["obligation"])
    resign_admission(commit_mismatch)
    refresh_outcome(commit_mismatch)

    timeout_commit = next(item for item in cases if item[0] == "spa-timeout-commit-proposal-mismatch")[3]
    timeout_commit["bundle"]["timeout"]["obligation"]["source"]["proposedAgreementHash"] = "98" * 32
    refresh_outcome(timeout_commit)

    arbitrary_proposal = next(
        item for item in cases if item[0] == "spa-commit-arbitrary-hash-matching-object"
    )[3]
    arbitrary_proposal["proposedAgreement"] = {"attacker": "supplied"}
    arbitrary_source = arbitrary_proposal["participationEvidence"]["admission"][
        "obligation"
    ]["source"]
    arbitrary_source["proposedAgreementHash"] = artifact_hash(
        arbitrary_proposal["proposedAgreement"], signature_field="signatures"
    )
    arbitrary_proposal["bundle"]["timeout"]["obligation"] = copy.deepcopy(
        arbitrary_proposal["participationEvidence"]["admission"]["obligation"]
    )
    resign_admission(arbitrary_proposal)
    refresh_outcome(arbitrary_proposal)

    proposer_substitution = next(
        item for item in cases if item[0] == "spa-commit-proposer-substitution"
    )[3]
    set_agreement_signatures(
        proposer_substitution["proposedAgreement"],
        [(SELLER_KEY, SELLER, "ed25519")],
    )
    substituted_source = proposer_substitution["participationEvidence"]["admission"][
        "obligation"
    ]["source"]
    substituted_source["proposer"] = SELLER
    substituted_source["proposedAgreementHash"] = artifact_hash(
        proposer_substitution["proposedAgreement"], signature_field="signatures"
    )
    proposer_substitution["bundle"]["timeout"]["obligation"] = copy.deepcopy(
        proposer_substitution["participationEvidence"]["admission"]["obligation"]
    )
    resign_admission(proposer_substitution)
    refresh_outcome(proposer_substitution)

    late = next(item for item in cases if item[0] == "spa-admission-at-deadline-too-late")[3]
    for receipt in [late["participationEvidence"]["admissionReceipt"], *late["participationEvidence"]["admissionReceiptHistory"]]:
        receipt["blockRef"]["timestamp"] = DEADLINE
        seal_receipt(receipt)

    for case_name, field, value in (
        ("spa-signed-receipt-transaction-substitution", "transactionRef", {"kind": "demos-tx", "value": "tx-other"}),
        ("spa-signed-receipt-writer-substitution", "writer", "demos1attacker"),
        ("spa-signed-receipt-nonce-substitution", "nonce", "999"),
        ("spa-signed-receipt-native-order-substitution", "nativeOrder", 99),
    ):
        item = next(entry for entry in cases if entry[0] == case_name)[3]
        receipts = [
            item["participationEvidence"]["admissionReceipt"],
            item["participationEvidence"]["admissionReceiptHistory"][0],
        ]
        for receipt in receipts:
            if field == "nativeOrder":
                tamper_receipt_adapter_field(receipt, field, value)
            else:
                receipt[field] = copy.deepcopy(value)

    booleans = next(item for item in cases if item[0] == "spa-producer-receipt-booleans-rejected")[3]
    for receipt in [booleans["participationEvidence"]["admissionReceipt"], *booleans["participationEvidence"]["admissionReceiptHistory"]]:
        receipt["evidenceValid"] = True
        receipt["writerAuthorized"] = True

    conflicting = next(item for item in cases if item[0] == "spa-conflicting-finalized-receipt-history")[3]
    other_final = admission_receipt(
        conflicting["participationEvidence"]["admission"],
        transaction="tx-participation-conflict", native_order=16, timestamp=1_600,
    )
    conflicting["participationEvidence"]["admissionReceiptHistory"].append(other_final)

    illegal = next(item for item in cases if item[0] == "spa-illegal-post-finality-history")[3]
    post_final = admission_receipt(
        illegal["participationEvidence"]["admission"],
        transaction="tx-participation-a", native_order=16, state="accepted",
    )
    illegal["participationEvidence"]["admissionReceiptHistory"].append(post_final)

    wrong_hash = next(item for item in cases if item[0] == "spa-admission-receipt-hash-mismatch")[3]
    for receipt in [wrong_hash["participationEvidence"]["admissionReceipt"], *wrong_hash["participationEvidence"]["admissionReceiptHistory"]]:
        receipt["contentHash"] = "ff" * 32
        seal_receipt(receipt)

    missing_predecessor = next(item for item in cases if item[0] == "spa-missing-replacement-predecessor")[3]
    missing_root = {"kind": "demos-tx", "value": "tx-participation-missing-root"}
    for receipt in [
        missing_predecessor["participationEvidence"]["admissionReceipt"],
        *missing_predecessor["participationEvidence"]["admissionReceiptHistory"],
    ]:
        seal_receipt(receipt, lineage_root_transaction=missing_root)

    disconnected = next(item for item in cases if item[0] == "spa-disconnected-receipt-history")[3]
    disconnected["participationEvidence"]["admissionReceiptHistory"].append(admission_receipt(
        disconnected["participationEvidence"]["admission"],
        transaction="tx-participation-disconnected",
        native_order=14,
        lineage_root_transaction="tx-participation-a",
    ))

    branched = next(item for item in cases if item[0] == "spa-branched-replacement-history")[3]
    branched_lineage = with_replacement_predecessor(branched)
    branched.clear()
    branched.update(branched_lineage)
    branched["participationEvidence"]["admissionReceiptHistory"].append(admission_receipt(
        branched["participationEvidence"]["admission"],
        transaction="tx-participation-predecessor",
        native_order=10,
        state="replaced",
        replacement_transaction="tx-participation-branch",
        lineage_root_transaction="tx-participation-predecessor",
    ))

    cyclic = next(item for item in cases if item[0] == "spa-cyclic-replacement-history")[3]
    cycle_root = {"kind": "demos-tx", "value": "tx-participation-cycle-a"}
    for receipt in [
        cyclic["participationEvidence"]["admissionReceipt"],
        *cyclic["participationEvidence"]["admissionReceiptHistory"],
    ]:
        seal_receipt(receipt, lineage_root_transaction=cycle_root)
    cyclic["participationEvidence"]["admissionReceiptHistory"].extend([
        admission_receipt(
            cyclic["participationEvidence"]["admission"],
            transaction="tx-participation-cycle-a",
            native_order=10,
            state="replaced",
            replacement_transaction="tx-participation-cycle-b",
            lineage_root_transaction="tx-participation-cycle-a",
        ),
        admission_receipt(
            cyclic["participationEvidence"]["admission"],
            transaction="tx-participation-cycle-b",
            native_order=11,
            state="replaced",
            replacement_transaction="tx-participation-cycle-a",
            lineage_root_transaction="tx-participation-cycle-a",
        ),
    ])

    finalized_predecessor = next(item for item in cases if item[0] == "spa-finalized-predecessor-replaced")[3]
    finalized_predecessor["participationEvidence"]["admissionReceiptHistory"].append(
        admission_receipt(
            finalized_predecessor["participationEvidence"]["admission"],
            transaction="tx-participation-predecessor",
            native_order=9,
            timestamp=1_400,
            lineage_root_transaction="tx-participation-predecessor",
        )
    )

    for case_name, malformed_state in (
        ("spa-receipt-state-list", ["finalized"]),
        ("spa-receipt-state-object", {"state": "finalized"}),
    ):
        malformed_receipt = next(item for item in cases if item[0] == case_name)[3]
        receipt = malformed_receipt["participationEvidence"]["admissionReceiptHistory"][0]
        receipt["state"] = copy.deepcopy(malformed_state)
        seal_receipt(receipt)

    unavailable_receipt = next(
        item for item in cases if item[0] == "spa-supported-receipt-algorithm-unavailable"
    )[3]
    unavailable_adapter = receipt_adapter_evidence(
        unavailable_receipt["participationEvidence"]["admissionReceiptHistory"][0]
    )
    unavailable_adapter["signature"]["algorithm"] = "sr1-aggregate"
    unavailable_receipt["participationEvidence"]["admissionReceiptHistory"][0]["evidence"]["value"] = (
        encode_canonical_object(unavailable_adapter)
    )

    outcome_conflict = next(item for item in cases if item[0] == "spa-conflicting-outcome-evidence")[3]
    outcome_conflict["knownOutcomeEvidence"].append(
        outcome_evidence(
            outcome_conflict,
            timestamp=2_200,
            native_order=22,
            transaction="tx-session-outcome-conflict",
            event_index="1",
        )
    )

    for name, expected, note, data in cases:
        vectors.append(vector(name, expected, note, data, excluded))

    # Verifier-owned corrective-profile admission negatives for one-sided blame.
    # The caller `currentProfile` boolean is inert; only the independently owned
    # `trustedContext` can admit the current consumer, and every missing,
    # unauthenticated, duplicated, or pin/tuple/session/identity-mismatched
    # authority fails closed before any blame becomes current/countable.
    pin_mismatch_profile = {
        "releasePin": "f" * 40,
        "moduleVersions": copy.deepcopy(AUTHORITATIVE_MODULE_VERSIONS),
    }
    tuple_mismatch_profile = {
        "releasePin": AUTHORITATIVE_RELEASE_PIN,
        "moduleVersions": {**AUTHORITATIVE_MODULE_VERSIONS, "dacs5": "0.4"},
    }
    blame_profile_negatives = [
        (
            "spa-blame-profile-authority-absent",
            "absent verifier-owned corrective-profile authority fails closed before one-sided blame",
            None,
        ),
        (
            "spa-blame-profile-authority-unauthenticated",
            "an unauthenticated profile record cannot admit current one-sided blame",
            profile_context(PARTIES, authenticated=False),
        ),
        (
            "spa-blame-profile-authority-duplicate",
            "duplicate role records in the verifier-owned context fail closed as ambiguous",
            profile_context(PARTIES + [copy.deepcopy(PARTIES[0])]),
        ),
        (
            "spa-blame-profile-pin-mismatch",
            "a wrong corrective-profile release pin refuses current one-sided blame",
            profile_context(PARTIES, profile=pin_mismatch_profile),
        ),
        (
            "spa-blame-profile-tuple-mismatch",
            "a wrong complete module tuple refuses current one-sided blame",
            profile_context(PARTIES, profile=tuple_mismatch_profile),
        ),
        (
            "spa-blame-profile-session-mismatch",
            "profile authority bound to another session cannot authorize this one",
            profile_context(PARTIES, session=OTHER_JOB),
        ),
        (
            "spa-blame-profile-identity-mismatch",
            "a participant authenticated under a different identity cannot authorize this party",
            profile_context(
                PARTIES, roles=[("buyer", OUTSIDER), ("seller", SELLER)]
            ),
        ),
        (
            "spa-blame-caller-currentprofile-only",
            "the caller currentProfile boolean is inert without verifier-owned authority",
            None,
        ),
        (
            "spa-blame-caller-copied-profile-object-inert",
            "a caller-copied full profile object is not verifier-owned authority",
            None,
        ),
        (
            "spa-blame-trusted-context-omitted",
            "an omitted trustedContext field fails closed exactly like explicit null before one-sided blame",
            _OMIT_CONTEXT,
        ),
    ]
    caller_copied_blame = copy.deepcopy(base)
    caller_copied_blame["localProfile"] = copy.deepcopy(AUTHORITATIVE_PROFILE)
    for name, note, context in blame_profile_negatives:
        data = (
            copy.deepcopy(base)
            if name != "spa-blame-caller-copied-profile-object-inert"
            else caller_copied_blame
        )
        vectors.append(vector(name, "fail", note, data, excluded, trusted_context=context))

    rate = rating_input()
    counted = want(admitted=True, rating=True)
    rating_vectors = [
        vector("spa-rating-valid-buyer-to-seller", "pass", "a completed exact-outcome rate phase admits the exact unsigned-hash rating reference", rate, counted),
        vector("spa-rating-valid-seller-to-buyer", "pass", "the inverse direction uses the same closed artifact and global roster gate", rating_changed(rate, lambda x: x["rating"].update({"rater": SELLER, "target": BUYER, "targetRole": "buyer"}), resign=True, key=SELLER_KEY, signer=SELLER), counted),
        vector("spa-rating-valid-free-text", "pass", "the normative optional freeText member is preserved in the signed bytes and exact reference hash", rating_changed(rate, lambda x: x["rating"].__setitem__("freeText", "Clear and timely delivery."), resign=True), counted),
        vector("spa-rating-valid-dimensions", "pass", "the normative opaque dimensions object is preserved without assigning conformance semantics to its scores", rating_changed(rate, lambda x: x["rating"].__setitem__("dimensions", {"communication": 4.5, "timeliness": 5}), resign=True), counted),
        vector("spa-rating-valid-fractional-rated-at", "pass", "ratedAt follows the CORE finite safe-magnitude number profile rather than an integer-only timestamp policy", rating_changed(rate, lambda x: x["rating"].__setitem__("ratedAt", 2_200.5), resign=True), counted),
        vector("spa-rating-valid-negative-rated-at", "pass", "the current RatingRecord contract does not impose a nonnegative ratedAt policy", rating_changed(rate, lambda x: x["rating"].__setitem__("ratedAt", -1), resign=True), counted),
        vector("spa-rating-signed-unknown-field", "fail", "a re-signed unknown RatingRecord-v1 member fails the shared closed schema", rating_changed(rate, lambda x: x["rating"].__setitem__("futureWeight", 2), resign=True), excluded),
        vector("spa-rating-rated-at-string", "fail", "a re-signed string ratedAt is not a JSON number", rating_changed(rate, lambda x: x["rating"].__setitem__("ratedAt", "2200"), resign=True), excluded),
        vector("spa-rating-rated-at-array", "fail", "a re-signed array ratedAt is not a JSON number", rating_changed(rate, lambda x: x["rating"].__setitem__("ratedAt", [2_200]), resign=True), excluded),
        vector("spa-rating-rated-at-object", "fail", "a re-signed object ratedAt is not a JSON number", rating_changed(rate, lambda x: x["rating"].__setitem__("ratedAt", {"timestamp": 2_200}), resign=True), excluded),
        vector("spa-rating-rated-at-boolean", "fail", "a re-signed boolean ratedAt is not a JSON number", rating_changed(rate, lambda x: x["rating"].__setitem__("ratedAt", True), resign=True), excluded),
        vector("spa-rating-free-text-not-string", "fail", "freeText has its normative string shape", rating_changed(rate, lambda x: x["rating"].__setitem__("freeText", ["text"]), resign=True), excluded),
        vector("spa-rating-free-text-too-long", "fail", "freeText over 1000 characters is excluded rather than truncated", rating_changed(rate, lambda x: x["rating"].__setitem__("freeText", "x" * 1001), resign=True), excluded),
        vector("spa-rating-dimensions-not-object", "fail", "dimensions has its normative record shape", rating_changed(rate, lambda x: x["rating"].__setitem__("dimensions", [5]), resign=True), excluded),
        vector("spa-rating-dimension-not-number", "fail", "each opaque dimension value is still a JSON number", rating_changed(rate, lambda x: x["rating"].__setitem__("dimensions", {"timeliness": "5"}), resign=True), excluded),
        vector("spa-rating-reference-uses-signed-object-hash", "fail", "a hash including the signature cannot replace the exact unsigned JCS artifact hash", changed(rate, lambda x: x["ratingRef"].__setitem__("contentHash", jcs_hash(x["rating"]))), excluded),
        vector("spa-rating-on-abort", "fail", "ordinary ratings cannot attach to an aborted session", changed_and_refresh_outcome(rate, lambda x: x["bundle"].update({"outcome": "aborted-by-other", "verifiedSignerRoles": ["buyer"]})), excluded),
        vector("spa-rating-completed-bundle-not-fully-signed", "fail", "completed outcome alone does not prove target participation", changed(rate, lambda x: x["bundle"].__setitem__("verifiedSignerRoles", ["buyer"])), excluded),
        vector("spa-rating-phase-not-in-listing", "fail", "a producer cannot invent a rate phase", changed_and_refresh_outcome(rate, lambda x: x["listing"].__setitem__("effectivePipeline", x["listing"]["effectivePipeline"][:-1])), excluded),
        vector("spa-rating-phase-failed", "fail", "a failed rate phase is ineligible", changed_and_refresh_outcome(rate, lambda x: x["bundle"]["phaseSummary"][-1].__setitem__("outcome", "fail")), excluded),
        vector("spa-rating-reference-not-in-bundle", "fail", "a loose rating reference is not admitted", changed(rate, lambda x: x["bundle"].__setitem__("ratingRefs", [])), excluded),
        vector("spa-rating-invalid-signature", "fail", "a forged rating is excluded", changed(rate, lambda x: x["rating"]["signature"].__setitem__("value", "A" * 86)), excluded),
        vector("spa-rating-wrong-job-resigned", "fail", "a valid rating signature cannot cross sessions", rating_changed(rate, lambda x: x["rating"].__setitem__("jobId", OTHER_JOB), resign=True), excluded),
        vector("spa-rating-non-roster-target", "fail", "an invented target is excluded", rating_changed(rate, lambda x: x["rating"].__setitem__("target", OUTSIDER), resign=True), excluded),
        vector("spa-rating-wrong-target-role", "fail", "targetRole equals the target's one exact authenticated role", rating_changed(rate, lambda x: x["rating"].__setitem__("targetRole", "buyer"), resign=True), excluded),
        vector("spa-rating-non-roster-rater", "fail", "only an authenticated session party may rate", rating_changed(rate, lambda x: x["rating"].__setitem__("rater", OUTSIDER), resign=True, key=OUTSIDER_KEY, signer=OUTSIDER), excluded),
        vector("spa-rating-self-rating", "fail", "a party cannot rate itself", rating_changed(rate, lambda x: x["rating"].update({"target": BUYER, "targetRole": "buyer"}), resign=True), excluded),
        vector("spa-rating-target-list", "fail", "a list-valued target is malformed without escaping an exception", rating_changed(rate, lambda x: x["rating"].__setitem__("target", [SELLER]), resign=True), excluded),
        vector("spa-rating-target-object", "fail", "an object-valued target is malformed without escaping an exception", rating_changed(rate, lambda x: x["rating"].__setitem__("target", {"claim": SELLER}), resign=True), excluded),
        vector("spa-rating-duplicate-buyer-role", "fail", "the shared global roster gate rejects duplicate roles", copy.deepcopy(rate), excluded),
        vector("spa-rating-listing-unavailable", "indeterminate", "unavailable Listing authority cannot establish the rate phase", changed(rate, lambda x: x["listing"].__setitem__("verificationDisposition", "indeterminate")), excluded),
        vector("spa-rating-supported-algorithm-unavailable", "indeterminate", "a registered RatingRecord algorithm unavailable to the fixture resolver is not mislabeled invalid", changed(rate, lambda x: x["rating"]["signature"].__setitem__("algorithm", "sr1-aggregate")), excluded),
        vector("spa-rating-ed25519-claim-resolution-unavailable", "indeterminate", "an Ed25519 signature whose claim-key resolution is unavailable to the fixture resolver is not mislabeled invalid", changed(rate, lambda x: x["rating"]["signature"].__setitem__("signer", "did:example:unresolved-rater")), excluded),
        vector("spa-rating-unknown-algorithm", "fail", "an unregistered RatingRecord signature algorithm is rejected", changed(rate, lambda x: x["rating"]["signature"].__setitem__("algorithm", "future-signature")), excluded),
        vector("spa-rating-algorithm-list", "fail", "a list-valued signature algorithm is malformed without escaping an exception", changed(rate, lambda x: x["rating"]["signature"].__setitem__("algorithm", ["ed25519"])), excluded),
        vector("spa-rating-algorithm-object", "fail", "an object-valued signature algorithm is malformed without escaping an exception", changed(rate, lambda x: x["rating"]["signature"].__setitem__("algorithm", {"name": "ed25519"})), excluded),
        vector("spa-rating-outcome-authority-unavailable", "indeterminate", "a rating is not current-window countable without exact completed-outcome occurrence", changed(rate, lambda x: x.__setitem__("knownOutcomeEvidence", [])), excluded),
        vector("spa-rating-conflicting-outcome-history", "indeterminate", "conflicting trusted completion events are non-countable", copy.deepcopy(rate), excluded),
    ]
    duplicate_rating_role = next(
        item["input"] for item in rating_vectors if item["name"] == "spa-rating-duplicate-buyer-role"
    )
    duplicate_rating_role["bundle"]["parties"].append({
        "role": "buyer", "primaryClaim": ORCHESTRATOR, "bundleHash": "76" * 32,
    })
    duplicate_rating_role["bundle"]["parties"].sort(
        key=lambda party: (party["role"], party["primaryClaim"], party["bundleHash"])
    )
    refresh_outcome(duplicate_rating_role)
    rating_outcome_conflict = next(
        item["input"] for item in rating_vectors
        if item["name"] == "spa-rating-conflicting-outcome-history"
    )
    rating_outcome_conflict["knownOutcomeEvidence"].append(
        outcome_evidence(
            rating_outcome_conflict,
            timestamp=2_300,
            native_order=23,
            transaction="tx-rating-outcome-conflict",
            event_index="1",
        )
    )
    vectors.extend(rating_vectors)

    # Verifier-owned corrective-profile admission negatives for ordinary ratings.
    # The same shared gate runs before the SPA-7 rating path, so an absent,
    # unauthenticated, duplicated, or pin/tuple/session/identity-mismatched
    # authority keeps the rating non-countable with no caller boolean escape.
    rating_profile_negatives = [
        (
            "spa-rating-profile-authority-absent",
            "absent verifier-owned corrective-profile authority fails closed before rating countability",
            None,
        ),
        (
            "spa-rating-profile-authority-unauthenticated",
            "an unauthenticated profile record cannot admit a current rating",
            profile_context(PARTIES, authenticated=False),
        ),
        (
            "spa-rating-profile-authority-duplicate",
            "duplicate role records in the verifier-owned context fail closed as ambiguous",
            profile_context(PARTIES + [copy.deepcopy(PARTIES[0])]),
        ),
        (
            "spa-rating-profile-pin-mismatch",
            "a wrong corrective-profile release pin refuses a current rating",
            profile_context(PARTIES, profile=pin_mismatch_profile),
        ),
        (
            "spa-rating-profile-tuple-mismatch",
            "a wrong complete module tuple refuses a current rating",
            profile_context(PARTIES, profile=tuple_mismatch_profile),
        ),
        (
            "spa-rating-profile-session-mismatch",
            "profile authority bound to another session cannot authorize this rating",
            profile_context(PARTIES, session=OTHER_JOB),
        ),
        (
            "spa-rating-profile-identity-mismatch",
            "a participant authenticated under a different identity cannot authorize this rating",
            profile_context(
                PARTIES, roles=[("buyer", OUTSIDER), ("seller", SELLER)]
            ),
        ),
        (
            "spa-rating-caller-currentprofile-only",
            "the caller currentProfile boolean is inert without verifier-owned authority",
            None,
        ),
        (
            "spa-rating-caller-copied-profile-object-inert",
            "a caller-copied full profile object is not verifier-owned authority",
            None,
        ),
        (
            "spa-rating-trusted-context-omitted",
            "an omitted trustedContext field fails closed exactly like explicit null before rating countability",
            _OMIT_CONTEXT,
        ),
    ]
    caller_copied_rating = copy.deepcopy(rate)
    caller_copied_rating["localProfile"] = copy.deepcopy(AUTHORITATIVE_PROFILE)
    for name, note, context in rating_profile_negatives:
        data = (
            copy.deepcopy(rate)
            if name != "spa-rating-caller-copied-profile-object-inert"
            else caller_copied_rating
        )
        vectors.append(vector(name, "fail", note, data, excluded, trusted_context=context))
    return vectors


def document() -> dict:
    vectors = build_vectors()
    encoded = json.dumps(vectors, separators=(",", ":"), ensure_ascii=False).encode()
    return {
        "set": SET_NAME,
        "spec": SPEC,
        "decisionModel": "only exact authenticated current-profile participation, rating, and outcome evidence is countable; fail/indeterminate has no alternative blame",
        "inputModel": "post-reconciliation bundle/Listing projections plus exact signed artifacts, all known portable CORE receipts with canonically encoded fixture-adapter evidence, authenticated DACS-3 pre-cosign Agreement source fixtures, and fixture-only trusted exact-outcome evidence; the caller currentProfile boolean is inert; Ed25519 is modeled locally while other registered algorithms are indeterminate; no production nonresponse authority is modeled",
        "profileAuthorityModel": "the current SPA consumer admits only through verifier-owned trustedContext outside caller input, binding the exact session and authenticated participant identities to the immutable corrective-profile pin and complete module tuple CORE 0.3/DACS-1 0.7/DACS-2 0.6/DACS-3 0.5/DACS-4 0.8/DACS-5 0.7; an omitted trustedContext field and an explicit-null trustedContext fail closed identically, as do unauthenticated, duplicated, or pin/tuple/session/identity-mismatched authority and caller-copied profile objects, all before blame or rating countability",
        "challengeAuthorityModel": "fixture-local verifier state independently issues exact job+nonce challenges with issuance, expiry, consumed status, and an authoritative clock; recognized challenges are consumed before later checks; the signed adapter binds issuedBy and orchestrator actingFor authority, while producer freshness flags are inert",
        "agreementSourceAuthorityModel": "the source-pinned synthetic Agreement fixture has the actual DACS-3 required shape and a raw-key proposer AgreementSignature over the signatures-omitted artifact hash; it models pre-cosign source authentication only, while missing key/source or registered-algorithm support remains indeterminate",
        "anchorHistoryModel": "portable receipts carry evidence:{kind,value}; the canonical value contains the trusted adapter signature over the complete receipt hash, including the nonempty obligor-authorized writer, plus native order, replacement relation, and lineage root; nonce applicability comes only from an independent fixture binding context and present/required values compare exactly; byte-identical duplicates collapse; one complete unique authenticated lineage must reach the exact selected finalized member",
        "outcomeAuthorityModel": "positive timeout/rating cases use dacs-test-exact-session-outcome-v1, a fixture-only trusted adapter over exact job/bundle/Listing/roster/phase/obligation objects; deadlines and publication never prove nonresponse, and unavailable/conflicting production proof is non-countable",
        "hash": hashlib.sha256(encoded).hexdigest(),
        "count": len(vectors),
        "vectors": vectors,
    }


def render_document(data: dict) -> str:
    lines = ["{"]
    for key, value in ((key, value) for key, value in data.items() if key != "vectors"):
        lines.append(f"  {json.dumps(key)}: {json.dumps(value, ensure_ascii=False)},")
    lines.append('  "vectors": [')
    for index, item in enumerate(data["vectors"]):
        comma = "," if index + 1 < len(data["vectors"]) else ""
        lines.append("    " + json.dumps(item, separators=(", ", ": "), ensure_ascii=False) + comma)
    lines.extend(["  ]", "}"])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = render_document(document())
    if args.write:
        OUTPUT.write_text(rendered, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != rendered:
        print(f"ERROR: {OUTPUT.relative_to(ROOT)} is stale; run this script with --write")
        return 1
    print(f"participation-admission vectors OK ({len(build_vectors())} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
