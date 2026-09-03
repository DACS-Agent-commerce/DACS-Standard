#!/usr/bin/env python3
"""Generate deterministic non-normative delivery-or-remedy candidate packs."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from jcs import canonicalize as jcs_canonicalize
except ModuleNotFoundError:  # imported as scripts.generate_* by another tool
    from scripts.jcs import canonicalize as jcs_canonicalize


ROOT = Path(__file__).resolve().parents[1]
VECTOR_OUTPUT = ROOT / "conformance/fixtures/delivery-remedy/candidate-vectors-v0.1.json"
DEPLOYMENT_OUTPUT = ROOT / "conformance/fixtures/delivery-remedy/deployment-capabilities-v0.1.json"

JOB_A = "01J8ME0SXKQ4T9V2RC5HJ6WX7D"
JOB_B = "01J8ME0SXKQ4T9V2RC5HJ6WX7E"
CASE_A = "01J8ME0SXKQ4T9V2RC5HJ6WX7F"
BUYER = "did:demos:agent:" + "11" * 32
SELLER = "did:demos:agent:" + "22" * 32
EVALUATOR = "did:demos:agent:" + "33" * 32
ORCHESTRATOR = "did:demos:agent:" + "44" * 32
CLAIMS = {
    "buyer": BUYER,
    "seller": SELLER,
    "evaluator": EVALUATOR,
    "orchestrator": ORCHESTRATOR,
}
SEEDS = {
    role: hashlib.sha256(f"DACS #356 candidate {role} key v1".encode("ascii")).digest()
    for role in CLAIMS
}
CHAIN_ID = 8453
CONTRACT = "0x" + "81" * 20
TOKEN = "0x" + "55" * 20
BUYER_ACCOUNT = "0x" + "11" * 20
SELLER_ACCOUNT = "0x" + "22" * 20
EVALUATOR_ACCOUNT = "0x" + "33" * 20
RELAYER_ACCOUNT = "0x" + "77" * 20
RUNTIME_HASH = hashlib.sha256(b"synthetic DACS delivery gate runtime v1").hexdigest()

DOMAINS = {
    "agreement": "dacs-x-delivery-remedy-agreement:v1:",
    "job": "dacs-x-escrow-job-ref:v1:",
    "funding": "dacs-x-escrow-funding-evidence:v1:",
    "delivery": "dacs-evidence:v1:",
    "evaluation": "dacs-x-execution-evaluation:v1:",
    "dispute": "dacs-x-dispute-outcome:v1:",
    "decision": "dacs-x-escrow-decision:v1:",
    "terminal": "dacs-x-escrow-terminal-evidence:v1:",
}


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def content_hash(value: Any) -> str:
    return hashlib.sha256(jcs_canonicalize(value).encode("utf-8")).hexdigest()


def unsigned_artifact(value: dict[str, Any]) -> dict[str, Any]:
    omitted = "signatures" if "signatures" in value else "signature"
    return {key: item for key, item in value.items() if key != omitted}


def artifact_hash(value: dict[str, Any]) -> str:
    return content_hash(unsigned_artifact(value))


def key(role: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(SEEDS[role])


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def public_key(role: str) -> str:
    return b64u(key(role).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ))


def component_signature(artifact: dict[str, Any], role: str, domain: str) -> dict[str, str]:
    return {
        "algorithm": "ed25519",
        "signer": CLAIMS[role],
        "value": b64u(key(role).sign((domain + artifact_hash(artifact)).encode("ascii"))),
    }


def sign_component(artifact: dict[str, Any], role: str, domain: str) -> dict[str, Any]:
    artifact["signature"] = component_signature(artifact, role, domain)
    return artifact


def sign_overlay(agreement: dict[str, Any]) -> dict[str, Any]:
    agreement["signatures"] = []
    for role in ("buyer", "seller", "evaluator"):
        signature = component_signature(agreement, role, DOMAINS["agreement"])
        agreement["signatures"].append({
            "role": role,
            "party": signature.pop("signer"),
            **signature,
        })
    return agreement


def ref(artifact: dict[str, Any], locator: str) -> dict[str, str]:
    return {
        "kind": "storage-program",
        "locator": locator,
        "contentHash": artifact_hash(artifact),
    }


def event(job_id: str, tag: str, log_index: int) -> dict[str, Any]:
    return {
        "kind": "evm-event",
        "chainId": CHAIN_ID,
        "txHash": "0x" + hashlib.sha256(f"{job_id}:{tag}".encode("ascii")).hexdigest(),
        "logIndex": log_index,
    }


def event_input(
    ref_value: dict[str, Any],
    job_id: str,
    native_job_id: str,
    tag: str,
    block_number: int,
    block_timestamp_sec: int,
    event_name: str,
    arguments: dict[str, Any],
    confirmations: int = 64,
) -> dict[str, Any]:
    block_preimage = f"{job_id}:{tag}:block:{block_number}:{block_timestamp_sec}"
    return {
        "eventRef": copy.deepcopy(ref_value),
        "txHashPreimageUtf8": f"{job_id}:{tag}",
        "blockNumber": block_number,
        "blockHash": "0x" + hashlib.sha256(block_preimage.encode("ascii")).hexdigest(),
        "blockHashPreimageUtf8": block_preimage,
        "blockTimestampSec": block_timestamp_sec,
        "confirmations": confirmations,
        "contractAddress": CONTRACT,
        "nativeJobId": native_job_id,
        "eventName": event_name,
        "arguments": arguments,
    }


def finality(event_timestamp_sec: int) -> dict[str, Any]:
    return {
        "model": "block-depth",
        "finalityBlocks": 64,
        "finalityObservedAt": (event_timestamp_sec + 128) * 1000,
    }


def logical(job_id: str, suffix: str) -> str:
    return f"dacsx:delivery-remedy:{job_id}:{suffix}"


def make_base(lifecycle: str, job_id: str = JOB_A) -> dict[str, Any]:
    if lifecycle not in {
        "release", "rejected-refund", "pre-submission-rejected-refund",
        "expired-pre", "expired-post",
    }:
        raise ValueError(lifecycle)
    created_at_sec = 1799989000
    funded_at_sec = 1799990000
    submitted_at_sec = 1799995000
    terminal_at_sec = (
        1799997000
        if lifecycle == "pre-submission-rejected-refund"
        else 1800007200
        if lifecycle in {"expired-pre", "expired-post"}
        else 1800001000
    )
    pipeline = [
        {"kind": "commit-delivery-or-remedy-agreement"},
        {"kind": "job-escrow", "parameters": {"action": "fund", "rail": "pay-evm-erc8183:fixture-v1"}},
        {"kind": "deliver-storage-program"},
        {"kind": "job-escrow", "parameters": {"action": "terminal", "rail": "pay-evm-erc8183:fixture-v1"}},
        {"kind": "rate"},
    ]
    profile = {
        "minimumEvaluationWindowSec": 3600,
        "deadlineProfile": "separate-submission-cutoff-v1",
        "finalityBlocks": 64,
        "decisionOrderingProfile": "synthetic-single-chain-finalized-before-terminal-v1",
        "platformFeeBP": 0,
        "evaluatorFeeBP": 0,
        "capabilityProfile": "dacs-delivery-gate-v1",
    }
    bilateral = {
        "agreementVersion": "1",
        "jobId": job_id,
        "buyer": BUYER,
        "seller": SELLER,
        "price": {"amount": "1000000", "currency": "USDC"},
    }
    rail = {
        "railVersion": 1,
        "railId": "pay-evm-erc8183:fixture-v1",
        "railType": "evm-erc8183",
        "availability": "mocked",
        "fixtureOnly": True,
        "chainId": CHAIN_ID,
        "contractAddress": CONTRACT,
        "runtimeBytecodeHash": RUNTIME_HASH,
        "paymentToken": TOKEN,
        "tokenDecimals": 6,
        "profileParameters": copy.deepcopy(profile),
    }
    requirement = {
        "op": "all",
        "of": [
            {"claimType": "demos-agent", "verificationRequired": True},
            {"claimType": "cci-xm", "verificationRequired": True},
        ],
    }
    role_accounts = {
        "buyer": BUYER_ACCOUNT,
        "seller": SELLER_ACCOUNT,
        "evaluator": EVALUATOR_ACCOUNT,
    }
    role_bundles = {
        role: {
            "fixtureRecordVersion": "1",
            "kind": "role-bundle-input",
            "primaryClaim": CLAIMS[role],
            "claims": [f"cci-xm:evm:{CHAIN_ID}:{role_accounts[role]}"],
        }
        for role in ("buyer", "seller", "evaluator")
    }
    vet_records = {
        role: {
            "fixtureRecordVersion": "1",
            "kind": "vet-record-input",
            "subject": CLAIMS[role],
            "bundleHash": artifact_hash(role_bundles[role]),
            "result": "pass",
            "validFromSec": 1799900000,
            "validUntilSec": 1800010000,
            **(
                {"requirementHash": content_hash(requirement)}
                if role == "evaluator"
                else {}
            ),
        }
        for role in ("buyer", "seller", "evaluator")
    }
    evaluation_rule = {
        "fixtureRecordVersion": "1",
        "kind": "evaluation-rule-input",
        "rule": "exact-output-v1",
    }
    delivered_artifact = {
        "fixtureRecordVersion": "1",
        "kind": "delivered-artifact-input",
        "jobId": job_id,
        "payloadUtf8": f"deliverable:{job_id}",
    }
    dispute_case = {
        "fixtureRecordVersion": "1",
        "kind": "dispute-case-input",
        "jobId": job_id,
        "caseId": CASE_A,
        "reason": "agreement-authorized-pre-submission-rejection",
    }
    agreement = sign_overlay({
        "deliveryOrRemedyAgreementVersion": "1",
        "jobId": job_id,
        "agreementRef": ref(bilateral, f"fixture:agreement:{job_id}"),
        "agreementHash": artifact_hash(bilateral),
        "railDefinitionRef": ref(rail, "fixture:rail:pay-evm-erc8183:fixture-v1"),
        "fundPhaseIndex": 1,
        "deliveryPhaseIndex": 2,
        "terminalPhaseIndex": 3,
        "buyer": {
            "primaryClaim": BUYER,
            "bundleHash": artifact_hash(role_bundles["buyer"]),
            "vetRecordRef": ref(vet_records["buyer"], "fixture:vet:buyer"),
            "evmAccountClaim": f"cci-xm:evm:{CHAIN_ID}:{BUYER_ACCOUNT}",
        },
        "seller": {
            "primaryClaim": SELLER,
            "bundleHash": artifact_hash(role_bundles["seller"]),
            "vetRecordRef": ref(vet_records["seller"], "fixture:vet:seller"),
            "evmAccountClaim": f"cci-xm:evm:{CHAIN_ID}:{SELLER_ACCOUNT}",
        },
        "evaluator": {
            "primaryClaim": EVALUATOR,
            "bundleHash": artifact_hash(role_bundles["evaluator"]),
            "vetRecordRef": ref(vet_records["evaluator"], "fixture:vet:evaluator"),
            "evmAccountClaim": f"cci-xm:evm:{CHAIN_ID}:{EVALUATOR_ACCOUNT}",
            "requirement": requirement,
            "requirementHash": content_hash(requirement),
        },
        "budgetBaseUnits": "1000000",
        "submissionCutoffSec": 1800000000,
        "evaluationDeadlineSec": 1800007200,
        "preSubmissionRefundPolicy": "evaluator-rejection",
        "disclosurePolicy": "public-evidence-only",
        "evaluationRuleRef": {
            "kind": "storage-program",
            "locator": "fixture:evaluation-rule:exact-output-v1",
            "contentHash": artifact_hash(evaluation_rule),
        },
    })
    agreement_hash = artifact_hash(agreement)
    job = sign_component({
        "escrowJobRefVersion": "1",
        "jobId": job_id,
        "deliveryOrRemedyAgreementHash": agreement_hash,
        "railDefinitionRef": agreement["railDefinitionRef"],
        "chainId": CHAIN_ID,
        "contractAddress": CONTRACT,
        "runtimeBytecodeHash": RUNTIME_HASH,
        "nativeJobId": "1" if job_id == JOB_A else "2",
        "creationEvent": event(job_id, "create", 0),
    }, "orchestrator", DOMAINS["job"])
    job_ref = ref(job, logical(job_id, "job"))
    funding = sign_component({
        "escrowFundingEvidenceVersion": "1",
        "jobId": job_id,
        "deliveryOrRemedyAgreementHash": agreement_hash,
        "escrowJobRef": job_ref,
        "fundPhaseIndex": 1,
        "token": TOKEN,
        "amountBaseUnits": "1000000",
        "fundingEventRefs": [event(job_id, "fund", 1)],
        "finality": finality(funded_at_sec),
        "observedAt": (funded_at_sec + 128) * 1000,
    }, "orchestrator", DOMAINS["funding"])
    funding_ref = ref(funding, logical(job_id, "funding"))

    artifacts: dict[str, Any] = {
        "bilateralAgreement": bilateral,
        "railDefinition": rail,
        "agreement": agreement,
        "job": job,
        "funding": funding,
    }
    delivery = None
    delivery_ref = None
    if lifecycle not in {"expired-pre", "pre-submission-rejected-refund"}:
        delivery = sign_component({
            "evidenceVersion": "1",
            "jobId": job_id,
            "phase": "deliver-storage-program",
            "phaseIndex": 2,
            "outcome": "success",
            "artifactRef": {
                "kind": "storage-program",
                "locator": f"fixture:deliverable:{job_id}",
                "contentHash": artifact_hash(delivered_artifact),
            },
            "observedAt": 1799995000000,
        }, "orchestrator", DOMAINS["delivery"])
        delivery_ref = ref(delivery, f"fixture:evidence:{job_id}:delivery")
        artifacts.update({"delivery": delivery, "deliveryRef": delivery_ref})

    evaluation = None
    decision = None
    decision_ref = None
    if lifecycle in {"release", "rejected-refund"}:
        evaluation_result = "accept" if lifecycle == "release" else "reject"
        disposition = "release-to-provider" if lifecycle == "release" else "refund-to-client"
        classification = "seller-fulfilled" if lifecycle == "release" else "seller-fault"
        evaluation = sign_component({
            "executionEvaluationVersion": "1",
            "jobId": job_id,
            "evaluationSeq": 0,
            "deliveryOrRemedyAgreementHash": agreement_hash,
            "escrowJobRef": job_ref,
            "deliveryEvidenceRef": delivery_ref,
            "result": evaluation_result,
            "finding": {
                "classification": classification,
                **({"faultedParty": SELLER} if classification == "seller-fault" else {}),
                "rationaleCode": "fixture-exact-output-match" if lifecycle == "release" else "fixture-exact-output-mismatch",
            },
            "subjectEvidenceRefs": [delivery_ref],
        }, "evaluator", DOMAINS["evaluation"])
        evaluation_ref = ref(evaluation, logical(job_id, "evaluation:0"))
        decision = sign_component({
            "escrowDecisionVersion": "1",
            "jobId": job_id,
            "deliveryOrRemedyAgreementHash": agreement_hash,
            "escrowJobRef": job_ref,
            "deliveryEvidenceRef": delivery_ref,
            "basisRef": {"kind": "execution-evaluation", "ref": evaluation_ref},
            "disposition": disposition,
        }, "evaluator", DOMAINS["decision"])
        decision_ref = ref(decision, logical(job_id, "decision"))
        artifacts.update({
            "evaluation": evaluation,
            "evaluationRef": evaluation_ref,
            "decision": decision,
            "decisionRef": decision_ref,
        })

    if lifecycle == "pre-submission-rejected-refund":
        dispute = sign_component({
            "disputeOutcomeVersion": "1",
            "jobId": job_id,
            "caseId": CASE_A,
            "revision": 0,
            "deliveryOrRemedyAgreementHash": agreement_hash,
            "caseRef": {
                "kind": "storage-program",
                "locator": f"fixture:dispute:{CASE_A}",
                "contentHash": artifact_hash(dispute_case),
            },
            "subjectBundleRefs": [],
            "subjectEvidenceRefs": [funding_ref],
            "finding": {
                "classification": "no-fault",
                "rationaleCode": "fixture-agreement-authorized-pre-submission-rejection",
            },
            "recommendedDisposition": "refund-to-client",
        }, "evaluator", DOMAINS["dispute"])
        dispute_ref = ref(dispute, f"dacsx:dispute:{job_id}:{CASE_A}:outcome:0")
        decision = sign_component({
            "escrowDecisionVersion": "1",
            "jobId": job_id,
            "deliveryOrRemedyAgreementHash": agreement_hash,
            "escrowJobRef": job_ref,
            "basisRef": {"kind": "dispute-outcome", "ref": dispute_ref},
            "disposition": "refund-to-client",
        }, "evaluator", DOMAINS["decision"])
        decision_ref = ref(decision, logical(job_id, "decision"))
        artifacts.update({
            "dispute": dispute,
            "disputeRef": dispute_ref,
            "decision": decision,
            "decisionRef": decision_ref,
        })

    if lifecycle == "release":
        terminal_state, disposition, recipient, action = "released", "release-to-provider", SELLER_ACCOUNT, "complete"
    elif lifecycle in {"rejected-refund", "pre-submission-rejected-refund"}:
        terminal_state, disposition, recipient, action = "rejected-refund", "refund-to-client", BUYER_ACCOUNT, "reject"
    else:
        terminal_state, disposition, recipient, action = "expired-refund", "refund-to-client", BUYER_ACCOUNT, "claimRefund"
    terminal_body: dict[str, Any] = {
        "escrowTerminalEvidenceVersion": "1",
        "jobId": job_id,
        "deliveryOrRemedyAgreementHash": agreement_hash,
        "escrowJobRef": job_ref,
        "fundingEvidenceRef": funding_ref,
        "terminalState": terminal_state,
        "disposition": disposition,
        "token": TOKEN,
        "amountBaseUnits": "1000000",
        "recipient": recipient,
        "terminalEventRefs": [event(job_id, action, 2)],
        "finality": finality(terminal_at_sec),
        "observedAt": (terminal_at_sec + 128) * 1000,
    }
    if decision_ref is not None:
        terminal_body["decisionRef"] = decision_ref
    if delivery_ref is not None:
        terminal_body["deliveryEvidenceRef"] = delivery_ref
    terminal = sign_component(terminal_body, "orchestrator", DOMAINS["terminal"])
    artifacts["terminal"] = terminal

    external = {
        "agreementResolution": "verified",
        "railResolution": "verified",
        "codeResolution": "verified",
        "authorityResolution": "verified",
        "fundingFinality": "verified",
        "deliveryFinality": "not-applicable" if delivery is None else "verified",
        "decisionFinality": "not-applicable" if decision is None else "verified",
        "terminalFinality": "verified",
        "decisionOrdering": "not-applicable" if decision is None else "verified",
        "nativeStateResolution": "verified",
    }
    mapping_sources = {"agreementHash": agreement_hash}
    if delivery is not None:
        mapping_sources["deliveryHash"] = artifact_hash(delivery)
    if decision is not None:
        mapping_sources["decisionHash"] = artifact_hash(decision)
    native = {
        "chainId": CHAIN_ID,
        "contractAddress": CONTRACT,
        "runtimeBytecodeHash": RUNTIME_HASH,
        "client": BUYER_ACCOUNT,
        "provider": SELLER_ACCOUNT,
        "evaluator": EVALUATOR_ACCOUNT,
        "evaluatorAccountType": "eoa",
        "evaluatorBindingMode": "direct",
        "evaluatorAdapter": None,
        "terminalCaller": EVALUATOR_ACCOUNT if decision is not None else BUYER_ACCOUNT,
        "transactionSubmitter": EVALUATOR_ACCOUNT if decision is not None else BUYER_ACCOUNT,
        "token": TOKEN,
        "payoutReceiver": SELLER_ACCOUNT,
        "amountBaseUnits": "1000000",
        "fundedAtSec": funded_at_sec,
        "description": "dacs-delivery-remedy:v1:" + agreement_hash,
        "deliverable": None if delivery is None else "0x" + artifact_hash(delivery),
        "reason": None if decision is None else "0x" + artifact_hash(decision),
        "submissionCutoffSec": 1800000000,
        "submissionCutoffEnforced": True,
        "expiredAt": 1800007200,
        "expiryRecoveryAtSec": 1800007200,
        "preterminalProviderPayoutBaseUnits": "0",
        "platformFeeBP": 0,
        "evaluatorFeeBP": 0,
        "terminalState": terminal_state,
        "terminalAction": action,
        "portableStateHistory": (
            [
                "created",
                "funded",
                "submitted",
                "released" if terminal_state == "released" else "refunded",
            ]
            if delivery is not None
            else ["created", "funded", "refunded"]
        ),
    }
    native_job_id = job["nativeJobId"]
    native_event_inputs = [
        event_input(
            job["creationEvent"],
            job_id,
            native_job_id,
            "create",
            19999900,
            created_at_sec,
            "JobCreated",
            {
                "client": BUYER_ACCOUNT,
                "provider": SELLER_ACCOUNT,
                "evaluator": EVALUATOR_ACCOUNT,
                "submissionCutoffSec": agreement["submissionCutoffSec"],
                "expiredAt": agreement["evaluationDeadlineSec"],
            },
        ),
        event_input(
            funding["fundingEventRefs"][0],
            job_id,
            native_job_id,
            "fund",
            20000000,
            funded_at_sec,
            "JobFunded",
            {"token": TOKEN, "amountBaseUnits": "1000000"},
        ),
    ]
    submission_event = None
    if delivery is not None:
        submission_event = event(job_id, "submit", 0)
        native_event_inputs.append(
            event_input(
                submission_event,
                job_id,
                native_job_id,
                "submit",
                20000050,
                submitted_at_sec,
                "JobSubmitted",
                {"deliverable": native["deliverable"]},
            )
        )
    native_event_inputs.append(
        event_input(
            terminal["terminalEventRefs"][0],
            job_id,
            native_job_id,
            action,
            20000100,
            terminal_at_sec,
            {
                "complete": "JobCompleted",
                "reject": "JobRejected",
                "claimRefund": "JobExpired",
            }[action],
            {
                "token": TOKEN,
                "amountBaseUnits": "1000000",
                "recipient": recipient,
                "reason": native["reason"],
            },
        )
    )
    return {
        "candidateProfile": "delivery-or-remedy-v1",
        "fixtureOnly": True,
        "pipeline": pipeline,
        "executionContext": {
            "acceptedRails": [copy.deepcopy(agreement["railDefinitionRef"])],
            "commitmentReceipt": {
                "status": "finalized",
                "jobId": job_id,
                "agreementHash": agreement["agreementHash"],
            },
            "fundingFinalizedBeforeDelivery": True,
            "terminalGate": (
                "delivery-returned"
                if delivery is not None
                else (
                    "pre-submission-decision"
                    if decision is not None
                    else "submission-cutoff"
                )
            ),
            "lateDeliveryDisabled": True,
            "dacs5PurchaseCount": 1,
        },
        "artifacts": artifacts,
        "publicKeys": {claim: public_key(role) for role, claim in CLAIMS.items()},
        "orchestratorClaim": ORCHESTRATOR,
        "bundleRequiredSigners": [BUYER, SELLER],
        "evaluatorVetResult": "pass",
        "profileParameters": profile,
        "mappingSources": mapping_sources,
        "native": native,
        "externalEvidence": external,
        "deliveryBinding": (
            {"status": "not-applicable"}
            if delivery is None
            else {
                "status": "verified",
                "finalizedBeforeNativeSubmission": True,
                "containsNativeSubmissionObservation": False,
                "nativeSubmissionEvent": submission_event,
            }
        ),
        "reproductionInputs": {
            "publicTestSeedHex": {
                CLAIMS[role]: SEEDS[role].hex() for role in CLAIMS
            },
            "roleBundles": role_bundles,
            "vetRecords": vet_records,
            "evaluationRule": evaluation_rule,
            "deliveredArtifact": delivered_artifact if delivery is not None else None,
            "disputeCase": dispute_case if lifecycle == "pre-submission-rejected-refund" else None,
            "runtimeBytecode": {
                "encoding": "utf-8",
                "value": "synthetic DACS delivery gate runtime v1",
                "sha256": RUNTIME_HASH,
            },
            "nativeEventInputs": native_event_inputs,
        },
        "reputationProjection": {
            "buyerFault": False,
            "sellerFault": lifecycle == "rejected-refund",
            "releaseAloneEstablishesNonFinancialCompletion": False,
        },
        "submittedBeforeCutoff": lifecycle not in {"expired-pre", "pre-submission-rejected-refund"},
        "consumedDecisionHashes": [],
    }


def resign_decision_chain(fixture: dict[str, Any], evaluation_result: str, disposition: str) -> None:
    artifacts = fixture["artifacts"]
    evaluation = artifacts["evaluation"]
    evaluation["result"] = evaluation_result
    evaluation["signature"] = component_signature(evaluation, "evaluator", DOMAINS["evaluation"])
    artifacts["evaluationRef"] = ref(evaluation, logical(evaluation["jobId"], "evaluation:0"))
    decision = artifacts["decision"]
    decision["basisRef"] = {"kind": "execution-evaluation", "ref": artifacts["evaluationRef"]}
    decision["disposition"] = disposition
    decision["signature"] = component_signature(decision, "evaluator", DOMAINS["decision"])
    artifacts["decisionRef"] = ref(decision, logical(decision["jobId"], "decision"))
    terminal = artifacts["terminal"]
    terminal["decisionRef"] = artifacts["decisionRef"]
    terminal["signature"] = component_signature(terminal, "orchestrator", DOMAINS["terminal"])
    fixture["mappingSources"]["decisionHash"] = artifact_hash(decision)
    fixture["native"]["reason"] = "0x" + artifact_hash(decision)


def resign_decision_artifact(fixture: dict[str, Any]) -> None:
    """Re-sign a directly edited decision and its terminal reference."""
    artifacts = fixture["artifacts"]
    decision = artifacts["decision"]
    decision["signature"] = component_signature(decision, "evaluator", DOMAINS["decision"])
    artifacts["decisionRef"] = ref(decision, logical(decision["jobId"], "decision"))
    artifacts["terminal"]["decisionRef"] = artifacts["decisionRef"]
    resign_terminal(fixture)
    fixture["mappingSources"]["decisionHash"] = artifact_hash(decision)
    fixture["native"]["reason"] = "0x" + artifact_hash(decision)


def resign_dispute_chain(fixture: dict[str, Any]) -> None:
    """Re-sign a directly edited dispute and the dependent decision chain."""
    artifacts = fixture["artifacts"]
    dispute = artifacts["dispute"]
    dispute["signature"] = component_signature(dispute, "evaluator", DOMAINS["dispute"])
    artifacts["disputeRef"] = ref(
        dispute,
        f"dacsx:dispute:{dispute['jobId']}:{dispute['caseId']}:outcome:{dispute['revision']}",
    )
    artifacts["decision"]["basisRef"] = {
        "kind": "dispute-outcome",
        "ref": artifacts["disputeRef"],
    }
    resign_decision_artifact(fixture)


def resign_terminal(fixture: dict[str, Any]) -> None:
    terminal = fixture["artifacts"]["terminal"]
    terminal["signature"] = component_signature(terminal, "orchestrator", DOMAINS["terminal"])


def resign_funding_chain(fixture: dict[str, Any]) -> None:
    """Re-sign funding and its terminal reference after a funding-record edit."""
    artifacts = fixture["artifacts"]
    funding = artifacts["funding"]
    funding["signature"] = component_signature(funding, "orchestrator", DOMAINS["funding"])
    artifacts["terminal"]["fundingEvidenceRef"] = ref(
        funding, logical(funding["jobId"], "funding")
    )
    resign_terminal(fixture)


def resign_agreement_chain(fixture: dict[str, Any]) -> None:
    """Re-sign every downstream artifact after an authenticated overlay edit."""
    artifacts = fixture["artifacts"]
    agreement = sign_overlay(artifacts["agreement"])
    agreement_hash = artifact_hash(agreement)
    job = artifacts["job"]
    job["deliveryOrRemedyAgreementHash"] = agreement_hash
    job["signature"] = component_signature(job, "orchestrator", DOMAINS["job"])
    job_ref = ref(job, logical(agreement["jobId"], "job"))
    funding = artifacts["funding"]
    funding["deliveryOrRemedyAgreementHash"] = agreement_hash
    funding["escrowJobRef"] = job_ref
    funding["signature"] = component_signature(funding, "orchestrator", DOMAINS["funding"])
    funding_ref = ref(funding, logical(agreement["jobId"], "funding"))

    evaluation = artifacts.get("evaluation")
    if evaluation is not None:
        evaluation["deliveryOrRemedyAgreementHash"] = agreement_hash
        evaluation["escrowJobRef"] = job_ref
        evaluation["signature"] = component_signature(evaluation, "evaluator", DOMAINS["evaluation"])
        artifacts["evaluationRef"] = ref(evaluation, logical(agreement["jobId"], "evaluation:0"))
    decision = artifacts.get("decision")
    if decision is not None:
        decision["deliveryOrRemedyAgreementHash"] = agreement_hash
        decision["escrowJobRef"] = job_ref
        decision["basisRef"] = {"kind": "execution-evaluation", "ref": artifacts["evaluationRef"]}
        decision["signature"] = component_signature(decision, "evaluator", DOMAINS["decision"])
        artifacts["decisionRef"] = ref(decision, logical(agreement["jobId"], "decision"))
    terminal = artifacts["terminal"]
    terminal["deliveryOrRemedyAgreementHash"] = agreement_hash
    terminal["escrowJobRef"] = job_ref
    terminal["fundingEvidenceRef"] = funding_ref
    if decision is not None:
        terminal["decisionRef"] = artifacts["decisionRef"]
    resign_terminal(fixture)
    fixture["mappingSources"]["agreementHash"] = agreement_hash
    fixture["native"]["description"] = "dacs-delivery-remedy:v1:" + agreement_hash
    if decision is not None:
        fixture["mappingSources"]["decisionHash"] = artifact_hash(decision)
        fixture["native"]["reason"] = "0x" + artifact_hash(decision)


def refresh_canonical_records(fixture: dict[str, Any]) -> None:
    """Pin the exact canonical bytes that feed each ERC field mapping."""
    records: dict[str, Any] = {}
    for name in ("agreement", "delivery", "decision"):
        artifact = fixture["artifacts"].get(name)
        if artifact is None:
            continue
        digest = artifact_hash(artifact)
        record = {
            "canonicalUtf8Hex": jcs_canonicalize(unsigned_artifact(artifact)).encode("utf-8").hex(),
            "contentHash": digest,
        }
        if name == "agreement":
            record["mappedNativeValue"] = "dacs-delivery-remedy:v1:" + digest
        else:
            record["mappedNativeValue"] = "0x" + digest
        records[name] = record
    fixture["canonicalRecords"] = records


def vector(
    name: str,
    base: str,
    expected: str,
    rule: str,
    note: str,
    patch=None,
    rules: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "base": base,
        "expected": expected,
        "expectedRule": rule,
        "rules": sorted(set(rules or [rule])),
        "note": note,
        "patch": patch or [],
    }


def build_vector_pack() -> dict[str, Any]:
    fixtures = {
        "release": make_base("release"),
        "rejected-refund": make_base("rejected-refund"),
        "pre-submission-rejected-refund": make_base("pre-submission-rejected-refund"),
        "expired-pre": make_base("expired-pre"),
        "expired-post": make_base("expired-post"),
    }
    release_b = make_base("release", JOB_B)

    cross_delivery = copy.deepcopy(fixtures["release"])
    cross_delivery["artifacts"]["delivery"] = release_b["artifacts"]["delivery"]
    fixtures["cross-job-delivery"] = cross_delivery

    cross_decision = copy.deepcopy(fixtures["release"])
    cross_decision["artifacts"]["decision"] = release_b["artifacts"]["decision"]
    fixtures["cross-job-decision"] = cross_decision

    reject_then_release = copy.deepcopy(fixtures["release"])
    resign_decision_chain(reject_then_release, "reject", "release-to-provider")
    fixtures["reject-then-release"] = reject_then_release

    accept_then_refund = copy.deepcopy(fixtures["rejected-refund"])
    resign_decision_chain(accept_then_refund, "accept", "refund-to-client")
    fixtures["accept-then-refund"] = accept_then_refund

    partial_release = copy.deepcopy(fixtures["release"])
    partial_release["artifacts"]["terminal"]["amountBaseUnits"] = "999999"
    resign_terminal(partial_release)
    fixtures["partial-release"] = partial_release

    wrong_release_recipient = copy.deepcopy(fixtures["release"])
    wrong_release_recipient["artifacts"]["terminal"]["recipient"] = BUYER_ACCOUNT
    resign_terminal(wrong_release_recipient)
    fixtures["wrong-release-recipient"] = wrong_release_recipient

    wrong_refund_recipient = copy.deepcopy(fixtures["rejected-refund"])
    wrong_refund_recipient["artifacts"]["terminal"]["recipient"] = SELLER_ACCOUNT
    resign_terminal(wrong_refund_recipient)
    fixtures["wrong-refund-recipient"] = wrong_refund_recipient

    evaluator_account_collision = copy.deepcopy(fixtures["release"])
    evaluator_account_collision["artifacts"]["agreement"]["evaluator"]["evmAccountClaim"] = (
        f"cci-xm:evm:{CHAIN_ID}:{SELLER_ACCOUNT}"
    )
    resign_agreement_chain(evaluator_account_collision)
    fixtures["evaluator-account-collision"] = evaluator_account_collision

    evaluator_wrong_chain = copy.deepcopy(fixtures["release"])
    evaluator_wrong_chain["artifacts"]["agreement"]["evaluator"]["evmAccountClaim"] = (
        f"cci-xm:evm:10:{EVALUATOR_ACCOUNT}"
    )
    resign_agreement_chain(evaluator_wrong_chain)
    fixtures["evaluator-wrong-chain"] = evaluator_wrong_chain

    expiry_decision = copy.deepcopy(fixtures["expired-pre"])
    expiry_decision["artifacts"]["terminal"]["decisionRef"] = {
        "kind": "storage-program", "locator": "fixture:invented-decision", "contentHash": "77" * 32,
    }
    resign_terminal(expiry_decision)
    fixtures["expiry-invented-decision"] = expiry_decision

    expiry_delivery = copy.deepcopy(fixtures["expired-pre"])
    expiry_delivery["artifacts"]["terminal"]["deliveryEvidenceRef"] = {
        "kind": "storage-program", "locator": "fixture:invented-delivery", "contentHash": "88" * 32,
    }
    resign_terminal(expiry_delivery)
    fixtures["expiry-invented-delivery"] = expiry_delivery

    missing_decision = copy.deepcopy(fixtures["release"])
    for field in ("evaluation", "evaluationRef", "decision", "decisionRef"):
        del missing_decision["artifacts"][field]
    del missing_decision["mappingSources"]["decisionHash"]
    missing_decision["externalEvidence"]["decisionFinality"] = "unavailable"
    missing_decision["externalEvidence"]["decisionOrdering"] = "unavailable"
    fixtures["missing-decision"] = missing_decision

    unsupported_policy = copy.deepcopy(fixtures["release"])
    unsupported_policy["artifacts"]["agreement"]["preSubmissionRefundPolicy"] = "expiry-only"
    resign_agreement_chain(unsupported_policy)
    fixtures["unsupported-expiry-only-policy"] = unsupported_policy

    funding_pending = copy.deepcopy(fixtures["release"])
    next(
        item
        for item in funding_pending["reproductionInputs"]["nativeEventInputs"]
        if item["eventName"] == "JobFunded"
    )["confirmations"] = 63
    fixtures["funding-finality-pending"] = funding_pending

    funding_events_empty = copy.deepcopy(fixtures["release"])
    funding_events_empty["artifacts"]["funding"]["fundingEventRefs"] = []
    resign_funding_chain(funding_events_empty)
    fixtures["funding-events-empty"] = funding_events_empty

    terminal_pending = copy.deepcopy(fixtures["release"])
    next(
        item
        for item in terminal_pending["reproductionInputs"]["nativeEventInputs"]
        if item["eventName"] == "JobCompleted"
    )["confirmations"] = 63
    fixtures["terminal-finality-pending"] = terminal_pending

    terminal_events_empty = copy.deepcopy(fixtures["release"])
    terminal_events_empty["artifacts"]["terminal"]["terminalEventRefs"] = []
    resign_terminal(terminal_events_empty)
    fixtures["terminal-events-empty"] = terminal_events_empty

    decision_delivery_mismatch = copy.deepcopy(fixtures["release"])
    decision_delivery_mismatch["artifacts"]["decision"]["deliveryEvidenceRef"] = {
        "kind": "storage-program",
        "locator": "fixture:evidence:substituted",
        "contentHash": "ab" * 32,
    }
    resign_decision_artifact(decision_delivery_mismatch)
    fixtures["decision-delivery-mismatch"] = decision_delivery_mismatch

    pre_submission_with_delivery = copy.deepcopy(fixtures["pre-submission-rejected-refund"])
    pre_submission_with_delivery["artifacts"]["decision"]["deliveryEvidenceRef"] = {
        "kind": "storage-program",
        "locator": "fixture:evidence:invented",
        "contentHash": "cd" * 32,
    }
    resign_decision_artifact(pre_submission_with_delivery)
    fixtures["pre-submission-decision-with-delivery"] = pre_submission_with_delivery

    indeterminate_evaluation = copy.deepcopy(fixtures["release"])
    resign_decision_chain(indeterminate_evaluation, "indeterminate", "release-to-provider")
    fixtures["indeterminate-evaluation"] = indeterminate_evaluation

    wrong_faulted_party = copy.deepcopy(fixtures["rejected-refund"])
    wrong_faulted_party["artifacts"]["evaluation"]["finding"]["faultedParty"] = BUYER
    resign_decision_chain(wrong_faulted_party, "reject", "refund-to-client")
    fixtures["wrong-faulted-party"] = wrong_faulted_party

    nonfault_with_party = copy.deepcopy(fixtures["pre-submission-rejected-refund"])
    nonfault_with_party["artifacts"]["dispute"]["finding"]["faultedParty"] = SELLER
    resign_dispute_chain(nonfault_with_party)
    fixtures["nonfault-with-faulted-party"] = nonfault_with_party

    terminal_decision_mismatch = copy.deepcopy(fixtures["release"])
    terminal_decision_mismatch["artifacts"]["terminal"]["decisionRef"] = {
        "kind": "storage-program",
        "locator": "fixture:decision:substituted",
        "contentHash": "de" * 32,
    }
    resign_terminal(terminal_decision_mismatch)
    fixtures["terminal-decision-mismatch"] = terminal_decision_mismatch

    terminal_funding_mismatch = copy.deepcopy(fixtures["release"])
    terminal_funding_mismatch["artifacts"]["terminal"]["fundingEvidenceRef"] = {
        "kind": "storage-program",
        "locator": "fixture:funding:substituted",
        "contentHash": "ef" * 32,
    }
    resign_terminal(terminal_funding_mismatch)
    fixtures["terminal-funding-mismatch"] = terminal_funding_mismatch

    funding_job_mismatch = copy.deepcopy(fixtures["release"])
    funding_job_mismatch["artifacts"]["funding"]["escrowJobRef"] = {
        "kind": "storage-program",
        "locator": "fixture:job:substituted",
        "contentHash": "fa" * 32,
    }
    resign_funding_chain(funding_job_mismatch)
    fixtures["funding-job-mismatch"] = funding_job_mismatch

    funding_token_mismatch = copy.deepcopy(fixtures["release"])
    funding_token_mismatch["artifacts"]["funding"]["token"] = "0x" + "66" * 20
    resign_funding_chain(funding_token_mismatch)
    fixtures["funding-token-mismatch"] = funding_token_mismatch

    evaluator_requirement_mismatch = copy.deepcopy(fixtures["release"])
    evaluator_requirement_mismatch["artifacts"]["agreement"]["evaluator"]["requirementHash"] = "03" * 32
    resign_agreement_chain(evaluator_requirement_mismatch)
    fixtures["evaluator-requirement-mismatch"] = evaluator_requirement_mismatch

    rehash_delivery = hashlib.sha256(
        fixtures["release"]["mappingSources"]["deliveryHash"].encode("ascii")
    ).hexdigest()
    rehash_reason = hashlib.sha256(
        fixtures["release"]["mappingSources"]["decisionHash"].encode("ascii")
    ).hexdigest()
    reversed_delivery = bytes.fromhex(
        fixtures["release"]["mappingSources"]["deliveryHash"]
    )[::-1].hex()
    shifted_delivery = "00" + fixtures["release"]["mappingSources"]["deliveryHash"][2:]
    bad_signer = component_signature(
        fixtures["release"]["artifacts"]["evaluation"], "buyer", DOMAINS["evaluation"]
    )
    bad_decision_signer = component_signature(
        fixtures["release"]["artifacts"]["decision"], "buyer", DOMAINS["decision"]
    )

    for fixture in fixtures.values():
        refresh_canonical_records(fixture)

    common_verified_rules = [
        "DRP-1", "DRP-2", "DRP-3", "DRP-4", "DRP-5", "DRP-6", "DRP-8",
        "DRP-10", "DRP-11", "DRP-12", "DRA-1", "DRA-2", "DRA-3", "DRA-4",
        "DRA-5", "DRA-6", "DRA-7", "DRA-8", "DRA-9", "DRA-10", "DRA-11",
        "DRA-12", "DRA-13", "DRA-14", "DRA-15", "DRL-1", "DRL-2", "DRL-3",
        "DRL-4", "DRL-6", "DRL-7", "DRJ-1", "DRJ-2", "DRJ-3", "DRJ-4", "DRJ-5",
        "DRJ-7", "DRJ-8", "DRF-1", "DRF-2", "DRF-3", "DRF-4", "DRF-5",
        "DRF-6", "DRAA-1", "DRAA-2", "DRAA-6", "DREB-1", "DREB-2",
        "DREB-3", "DREB-4", "DREB-5", "DREB-6", "DREB-7", "DREB-8",
        "DREB-9", "DREB-10", "DREB-11", "DREB-12", "DREB-13", "DREB-14",
        "DREB-15", "DREB-16", "DREB-17", "DREB-19", "DREB-20", "DREB-21",
        "DREB-22", "DREB-23", "DRT-4", "DRT-7", "DRT-8", "DRT-10",
        "DRT-11", "DRT-12", "DRT-14", "DRV-1", "DRV-2", "DRV-3", "DRV-4", "DRV-6",
        "DRV-7", "DRQ-1", "DRQ-3", "DRQ-4",
    ]
    submitted_verified_rules = common_verified_rules + [
        "DRP-7", "DRP-9", "DRE-1", "DRE-2", "DRE-3", "DRE-4", "DRE-5",
        "DRE-6", "DRE-7", "DRD-1", "DRD-2", "DRD-3", "DRD-4", "DRD-8",
        "DRD-10", "DRD-11",
    ]
    release_verified_rules = submitted_verified_rules + ["DRD-5", "DRT-1", "DRT-5"]
    rejection_verified_rules = submitted_verified_rules + ["DRD-6", "DRT-2", "DRT-6"]
    pre_submission_verified_rules = common_verified_rules + [
        "DRA-16", "DRD-1", "DRD-2", "DRD-4", "DRD-6", "DRD-9", "DRD-10",
        "DRD-11", "DRD-12", "DRX-1", "DRX-2", "DRX-5", "DRX-6", "DRT-2",
        "DRT-6",
    ]
    expiry_verified_rules = common_verified_rules + [
        "DRA-16", "DRD-7", "DRL-5", "DRT-3", "DRT-6", "DRT-9", "DRT-13",
    ]

    vectors = [
        vector("release-complete-budget", "release", "verified", "DRV-7", "fund, deliver, evaluate, and release the complete budget", rules=release_verified_rules),
        vector("evaluator-rejection-refund", "rejected-refund", "verified", "DRV-7", "a signed rejection refunds the complete budget", rules=rejection_verified_rules),
        vector("pre-submission-evaluator-rejection", "pre-submission-rejected-refund", "verified", "DRV-7", "agreement-authorized pre-submission rejection uses a DisputeOutcome and omits delivery evidence", rules=pre_submission_verified_rules),
        vector("expiry-before-submission", "expired-pre", "verified", "DRV-7", "pre-submission expiry refunds without a decision or delivery reference", rules=expiry_verified_rules),
        vector("expiry-after-submission-grace", "expired-post", "verified", "DRV-7", "post-submission expiry refunds after grace without inventing a decision", rules=expiry_verified_rules + ["DRP-7", "DRP-9"]),
        vector("pipeline-missing-terminal", "release", "rejected", "DRP-1", "an unpaired escrow phase is rejected", [{"op": "remove", "path": ["pipeline", 3]}]),
        vector("pipeline-actions-reversed", "release", "rejected", "DRP-2", "escrow phases must be fund then terminal", [{"op": "replace", "path": ["pipeline", 1, "parameters", "action"], "value": "terminal"}]),
        vector("pipeline-second-delivery", "release", "rejected", "DRP-3", "only one delivery step may occur", [{"op": "add", "path": ["pipeline", 3], "value": {"kind": "deliver-inline"}}]),
        vector("pipeline-extra-payment", "release", "rejected", "DRP-4", "ordinary payment phases cannot accompany the pair", [{"op": "add", "path": ["pipeline", 4], "value": {"kind": "pay-x402"}}]),
        vector("pipeline-rail-divergence", "release", "rejected", "DRP-5", "both escrow invocations must use the same rail", [{"op": "replace", "path": ["pipeline", 3, "parameters", "rail"], "value": "pay-evm-erc8183:other"}]),
        vector("pipeline-delivery-before-final-funding", "release", "rejected", "DRP-6", "delivery cannot begin before the funding result is finalized", [{"op": "replace", "path": ["executionContext", "fundingFinalizedBeforeDelivery"], "value": False}]),
        vector("pipeline-double-counted-purchase", "release", "rejected", "DRP-8", "the paired escrow lifecycle counts as one purchase", [{"op": "replace", "path": ["executionContext", "dacs5PurchaseCount"], "value": 2}]),
        vector("pipeline-escrow-rail-not-accepted", "release", "rejected", "DRP-10", "job escrow participates in the acceptedRails selection gate", [{"op": "replace", "path": ["executionContext", "acceptedRails"], "value": []}]),
        vector("pipeline-funding-before-final-commitment", "release", "rejected", "DRP-11", "the finalized DACS-3 commitment gates value locking", [{"op": "replace", "path": ["executionContext", "commitmentReceipt", "status"], "value": "included"}]),
        vector("pipeline-terminal-before-delivery-return", "release", "rejected", "DRP-12", "terminal execution waits for the delivery return on the ordinary path", [{"op": "replace", "path": ["executionContext", "terminalGate"], "value": "submission-cutoff"}]),
        vector("pipeline-late-delivery-not-disabled", "expired-pre", "rejected", "DRP-12", "a cutoff refund permanently disables late delivery submission", [{"op": "replace", "path": ["executionContext", "lateDeliveryDisabled"], "value": False}]),
        vector("pipeline-phase-index-divergence", "release", "rejected", "DRA-11", "signed indexes must match the phase pair", [{"op": "replace", "path": ["artifacts", "agreement", "deliveryPhaseIndex"], "value": 4}]),
        vector("bilateral-agreement-reference-mismatch", "release", "rejected", "DRA-1", "the overlay must resolve the exact bilateral agreement", [{"op": "replace", "path": ["artifacts", "agreement", "agreementRef", "contentHash"], "value": "01" * 32}]),
        vector("bilateral-agreement-hash-mismatch", "release", "rejected", "DRA-2", "the overlay must carry the recomputed bilateral agreement hash", [{"op": "replace", "path": ["artifacts", "agreement", "agreementHash"], "value": "02" * 32}, {"op": "replace", "path": ["executionContext", "commitmentReceipt", "agreementHash"], "value": "02" * 32}]),
        vector("overlay-signature-missing", "release", "rejected", "DRA-3", "all three overlay signatures are required", [{"op": "remove", "path": ["artifacts", "agreement", "signatures", 2]}]),
        vector("evaluator-requirement-hash-mismatch", "evaluator-requirement-mismatch", "rejected", "DRA-8", "the evaluator requirement hash is independently recomputed"),
        vector("nonminimal-budget-base-units", "release", "error", "DRA-10", "the signed budget uses minimal unsigned decimal text", [{"op": "replace", "path": ["artifacts", "agreement", "budgetBaseUnits"], "value": "01000000"}]),
        vector("rail-definition-reference-mismatch", "release", "rejected", "DRA-12", "the selected rail definition must resolve exactly", [{"op": "replace", "path": ["artifacts", "agreement", "railDefinitionRef", "contentHash"], "value": "04" * 32}, {"op": "replace", "path": ["executionContext", "acceptedRails", 0, "contentHash"], "value": "04" * 32}]),
        vector("evaluator-added-as-bundle-party", "release", "rejected", "DRA-13", "the evaluator overlay signature does not create a third bundle party", [{"op": "add", "path": ["bundleRequiredSigners", 2], "value": EVALUATOR}]),
        vector("unsupported-disclosure-policy", "release", "rejected", "DRQ-1", "the first profile accepts only its two signed disclosure policies", [{"op": "replace", "path": ["artifacts", "agreement", "disclosurePolicy"], "value": "encrypted-transcript"}]),
        vector("transcript-input-disclosed", "release", "rejected", "DRQ-3", "the candidate input pack cannot smuggle negotiation transcript material", [{"op": "add", "path": ["reproductionInputs", "deliveredArtifact", "transcript"], "value": "forbidden"}]),
        vector("delivery-submission-circularity", "release", "rejected", "DRP-9", "delivery evidence must be fixed before and independent of the native submission event", [{"op": "replace", "path": ["deliveryBinding", "containsNativeSubmissionObservation"], "value": True}]),
        vector("description-prefix-substitution", "release", "rejected", "DREB-1", "the exact ASCII description prefix is bound", [{"op": "replace", "path": ["native", "description"], "value": "dacs-delivery:v1:" + fixtures["release"]["mappingSources"]["agreementHash"]}]),
        vector("description-sha256-prefix", "release", "rejected", "DREB-1", "a sha256: textual prefix is not inserted", [{"op": "replace", "path": ["native", "description"], "value": "dacs-delivery-remedy:v1:sha256:" + fixtures["release"]["mappingSources"]["agreementHash"]}]),
        vector("uppercase-delivery-hash", "release", "rejected", "DREB-3", "declared content hashes are lowercase", [{"op": "replace", "path": ["mappingSources", "deliveryHash"], "value": fixtures["release"]["mappingSources"]["deliveryHash"].upper()}]),
        vector("prefixed-delivery-hash", "release", "rejected", "DREB-3", "declared content hashes have no algorithm prefix", [{"op": "replace", "path": ["mappingSources", "deliveryHash"], "value": "sha256:" + fixtures["release"]["mappingSources"]["deliveryHash"]}]),
        vector("delivery-hash-text-rehash", "release", "rejected", "DREB-4", "deliverable is raw decoded hash bytes, not a text rehash", [{"op": "replace", "path": ["native", "deliverable"], "value": "0x" + rehash_delivery}]),
        vector("delivery-byte-order-reversal", "release", "rejected", "DREB-4", "deliverable byte order is not reinterpreted", [{"op": "replace", "path": ["native", "deliverable"], "value": "0x" + reversed_delivery}]),
        vector("delivery-padding-truncation", "release", "rejected", "DREB-4", "a shifted/padded digest is a binding mismatch", [{"op": "replace", "path": ["native", "deliverable"], "value": "0x" + shifted_delivery}]),
        vector("zero-deliverable", "release", "rejected", "DREB-5", "zero cannot stand in for delivery evidence", [{"op": "replace", "path": ["native", "deliverable"], "value": "0x" + "00" * 32}]),
        vector("decision-hash-text-rehash", "release", "rejected", "DREB-4", "reason is raw decoded decision hash bytes", [{"op": "replace", "path": ["native", "reason"], "value": "0x" + rehash_reason}]),
        vector("zero-decision-reason", "release", "rejected", "DREB-5", "zero cannot stand in for an evaluator decision", [{"op": "replace", "path": ["native", "reason"], "value": "0x" + "00" * 32}]),
        vector("decision-hash-substitution", "release", "rejected", "DREB-2", "declared decision hash must be independently recomputed", [{"op": "replace", "path": ["mappingSources", "decisionHash"], "value": "99" * 32}]),
        vector("evaluator-primary-claim-collision", "release", "rejected", "DRA-6", "evaluator and buyer primary claims must differ", [{"op": "replace", "path": ["artifacts", "agreement", "evaluator", "primaryClaim"], "value": BUYER}]),
        vector("evaluator-account-collision", "evaluator-account-collision", "rejected", "DRA-7", "evaluator and provider accounts must differ"),
        vector("evaluator-wrong-chain", "evaluator-wrong-chain", "rejected", "DRA-5", "role accounts are bound to the selected chain"),
        vector("native-client-mismatch", "release", "rejected", "DREB-7", "native client must equal the buyer-controlled account", [{"op": "replace", "path": ["native", "client"], "value": "0x" + "66" * 20}]),
        vector("native-provider-mismatch", "release", "rejected", "DREB-8", "native provider must equal the seller-controlled account", [{"op": "replace", "path": ["native", "provider"], "value": "0x" + "66" * 20}]),
        vector("native-evaluator-mismatch", "release", "rejected", "DREB-9", "native evaluator must equal the controlled evaluator account", [{"op": "replace", "path": ["native", "evaluator"], "value": "0x" + "66" * 20}]),
        vector("native-payout-receiver-mismatch", "release", "rejected", "DREB-10", "native payout receiver must equal the seller-controlled account", [{"op": "replace", "path": ["native", "payoutReceiver"], "value": BUYER_ACCOUNT}]),
        vector("native-token-mismatch", "release", "rejected", "DREB-11", "native token must equal the pinned rail asset", [{"op": "replace", "path": ["native", "token"], "value": "0x" + "66" * 20}]),
        vector("evaluator-vet-failure", "release", "rejected", "DRA-9", "evaluator must have a fresh pass", [{"op": "replace", "path": ["evaluatorVetResult"], "value": "fail"}]),
        vector("nonpositive-evaluation-window", "release", "rejected", "DREB-14", "registered rail windows must be positive", [{"op": "replace", "path": ["profileParameters", "minimumEvaluationWindowSec"], "value": 0}]),
        vector("evaluation-window-too-short", "release", "rejected", "DREB-14", "the bound evaluation window must meet the pinned minimum", [{"op": "replace", "path": ["profileParameters", "minimumEvaluationWindowSec"], "value": 8000}]),
        vector("detached-profile-projection-weakened", "release", "rejected", "DRP-5", "a detached profile projection cannot weaken the authenticated rail policy", [{"op": "replace", "path": ["profileParameters", "minimumEvaluationWindowSec"], "value": 1}]),
        vector("native-expiry-divergence", "release", "rejected", "DREB-12", "native expiredAt must equal the evaluation deadline", [{"op": "replace", "path": ["native", "expiredAt"], "value": 1800007201}]),
        vector("native-submission-cutoff-divergence", "release", "rejected", "DREB-13", "the native submission cutoff must equal the signed cutoff", [{"op": "replace", "path": ["native", "submissionCutoffSec"], "value": 1800000001}]),
        vector("native-submission-cutoff-unenforced", "release", "rejected", "DREB-13", "an SDK timer cannot replace native cutoff enforcement", [{"op": "replace", "path": ["native", "submissionCutoffEnforced"], "value": False}]),
        vector("native-expiry-recovery-too-early", "release", "rejected", "DREB-15", "expiry recovery cannot open before the evaluation deadline", [{"op": "replace", "path": ["native", "expiryRecoveryAtSec"], "value": 1800000000}]),
        vector("unsupported-expiry-only-policy", "unsupported-expiry-only-policy", "rejected", "DRA-15", "the MVP cannot promise expiry-only while canonical ERC permits funded rejection"),
        vector("cross-job-delivery-replay", "cross-job-delivery", "rejected", "DRD-8", "delivery from another job cannot be replayed"),
        vector("cross-job-decision-replay", "cross-job-decision", "rejected", "DRD-8", "decision from another job cannot be replayed"),
        vector("consumed-decision-replay", "release", "rejected", "DRD-8", "a terminally consumed decision is one-use", [{"op": "add", "path": ["consumedDecisionHashes", 0], "value": fixtures["release"]["mappingSources"]["decisionHash"]}]),
        vector("wrong-evaluator-signer", "release", "rejected", "DRE-1", "commercial parties cannot sign evaluator artifacts", [{"op": "replace", "path": ["artifacts", "evaluation", "signature"], "value": bad_signer}]),
        vector("wrong-decision-signer", "release", "rejected", "DRD-1", "only the agreement-bound evaluator may sign the escrow decision", [{"op": "replace", "path": ["artifacts", "decision", "signature"], "value": bad_decision_signer}]),
        vector("delivery-reference-mismatch", "release", "rejected", "DRE-2", "the delivery reference must resolve the signed delivery evidence", [{"op": "replace", "path": ["artifacts", "deliveryRef", "contentHash"], "value": "05" * 32}]),
        vector("evaluation-reference-mismatch", "release", "rejected", "DRE-7", "the evaluation reference must resolve exactly", [{"op": "replace", "path": ["artifacts", "evaluationRef", "contentHash"], "value": "06" * 32}]),
        vector("decision-delivery-reference-mismatch", "decision-delivery-mismatch", "rejected", "DRD-3", "the decision must bind the exact delivery evidence"),
        vector("decision-reference-mismatch", "release", "rejected", "DRD-4", "the decision reference must resolve exactly", [{"op": "replace", "path": ["artifacts", "decisionRef", "contentHash"], "value": "07" * 32}]),
        vector("pre-submission-decision-carries-delivery", "pre-submission-decision-with-delivery", "rejected", "DRD-9", "pre-submission decisions must omit delivery evidence"),
        vector("indeterminate-evaluation-authorizes-terminal", "indeterminate-evaluation", "rejected", "DRE-4", "an indeterminate evaluation cannot authorize settlement"),
        vector("eoa-relayed-outer-submitter", "release", "rejected", "DREB-22", "an EOA evaluator must itself submit the native transaction", [{"op": "replace", "path": ["native", "transactionSubmitter"], "value": RELAYER_ACCOUNT}]),
        vector("eip1271-relayed-execution", "release", "verified", "DRV-7", "a supported contract account remains the native caller while an outer account submits", [{"op": "replace", "path": ["native", "evaluatorAccountType"], "value": "eip1271"}, {"op": "replace", "path": ["native", "transactionSubmitter"], "value": RELAYER_ACCOUNT}], rules=release_verified_rules + ["DREB-18"]),
        vector("evaluator-binding-not-direct", "release", "rejected", "DREB-16", "the evaluator must be bound directly in the first profile", [{"op": "replace", "path": ["native", "evaluatorBindingMode"], "value": "adapter"}]),
        vector("evaluator-adapter-substitution", "release", "rejected", "DREB-20", "a generic adapter is outside the first profile", [{"op": "replace", "path": ["native", "evaluatorAdapter"], "value": RELAYER_ACCOUNT}]),
        vector("relayer-substituted-as-native-caller", "release", "rejected", "DREB-21", "a relayer cannot replace the agreement-bound evaluator as native caller", [{"op": "replace", "path": ["native", "terminalCaller"], "value": RELAYER_ACCOUNT}]),
        vector("reject-evaluation-release-action", "reject-then-release", "rejected", "DRD-2", "rejection cannot authorize release"),
        vector("accept-evaluation-refund-action", "accept-then-refund", "rejected", "DRD-2", "acceptance cannot authorize refund"),
        vector("release-decision-native-reject", "release", "rejected", "DRD-5", "a release decision maps only to native complete", [{"op": "replace", "path": ["native", "terminalAction"], "value": "reject"}]),
        vector("refund-decision-native-complete", "rejected-refund", "rejected", "DRD-6", "a refund decision maps only to native reject", [{"op": "replace", "path": ["native", "terminalAction"], "value": "complete"}]),
        vector("partial-terminal-release", "partial-release", "rejected", "DRT-5", "terminal release must cover the complete budget"),
        vector("terminal-decision-reference-mismatch", "terminal-decision-mismatch", "rejected", "DRT-1", "terminal release must reference the exact decision"),
        vector("terminal-funding-reference-mismatch", "terminal-funding-mismatch", "rejected", "DRT-11", "terminal evidence must reference the exact finalized funding record"),
        vector("funding-job-reference-mismatch", "funding-job-mismatch", "rejected", "DRF-1", "funding evidence must reference the exact escrow job"),
        vector("funding-token-mismatch", "funding-token-mismatch", "rejected", "DRF-2", "funding evidence must bind the pinned token"),
        vector("wrong-release-recipient", "wrong-release-recipient", "rejected", "DRT-5", "release goes only to the bound seller payout account"),
        vector("wrong-refund-recipient", "wrong-refund-recipient", "rejected", "DRT-6", "refund goes only to the client"),
        vector("release-overclaims-nonfinancial-completion", "release", "rejected", "DRL-6", "financial release alone cannot establish completion of every non-financial obligation", [{"op": "replace", "path": ["reputationProjection", "releaseAloneEstablishesNonFinancialCompletion"], "value": True}]),
        vector("release-invents-seller-fault", "release", "rejected", "DRT-14", "a caller projection cannot contradict an authenticated seller-fulfilled finding", [{"op": "replace", "path": ["reputationProjection", "sellerFault"], "value": True}]),
        vector("rejected-refund-erases-seller-fault", "rejected-refund", "rejected", "DRT-14", "a caller projection cannot erase the authenticated seller-fault finding", [{"op": "replace", "path": ["reputationProjection", "sellerFault"], "value": False}]),
        vector("nonzero-preterminal-payout", "release", "rejected", "DRL-7", "any preterminal provider payout is forbidden", [{"op": "replace", "path": ["native", "preterminalProviderPayoutBaseUnits"], "value": "1"}]),
        vector("nonzero-platform-fee", "release", "rejected", "DRT-7", "escrow fees must be zero", [{"op": "replace", "path": ["native", "platformFeeBP"], "value": 1}]),
        vector("creation-finality-pending", "release", "indeterminate", "DRJ-2", "an under-confirmed creation event cannot establish the native job", [{"op": "replace", "path": ["reproductionInputs", "nativeEventInputs", 0, "confirmations"], "value": 63}]),
        vector("funding-finality-pending", "funding-finality-pending", "indeterminate", "DRF-6", "under-confirmed funding-event evidence cannot unlock delivery"),
        vector("submission-finality-pending", "release", "indeterminate", "DRP-9", "an under-confirmed submission event cannot bind the delivery to the native job", [{"op": "replace", "path": ["reproductionInputs", "nativeEventInputs", 2, "confirmations"], "value": 63}]),
        vector("funding-events-empty", "funding-events-empty", "rejected", "DRF-3", "funding requires a non-empty authenticated event set"),
        vector("terminal-finality-pending", "terminal-finality-pending", "indeterminate", "DRT-8", "under-confirmed terminal-event evidence cannot establish disposition"),
        vector("terminal-events-empty", "terminal-events-empty", "rejected", "DRT-4", "terminal disposition requires a non-empty event set"),
        vector("portable-state-missing-funded", "release", "rejected", "DRL-4", "the portable lifecycle cannot skip the funded state", [{"op": "remove", "path": ["native", "portableStateHistory", 1]}]),
        vector("portable-state-unknown", "release", "rejected", "DRL-2", "additional native states require a deterministic portable mapping", [{"op": "replace", "path": ["native", "portableStateHistory", 1], "value": "claim-pending"}]),
        vector("portable-state-reopened", "release", "rejected", "DRL-4", "a terminal portable state cannot reopen", [{"op": "add", "path": ["native", "portableStateHistory", 4], "value": "funded"}]),
        vector("portable-state-terminal-mismatch", "release", "rejected", "DRL-1", "the portable history must end in the evidenced terminal state", [{"op": "replace", "path": ["native", "portableStateHistory", 3], "value": "refunded"}]),
        vector("portable-state-evidence-unavailable", "release", "indeterminate", "DRL-3", "unavailable native state cannot be guessed", [{"op": "replace", "path": ["externalEvidence", "nativeStateResolution"], "value": "unavailable"}]),
        vector("expiry-invented-decision", "expiry-invented-decision", "rejected", "DRD-7", "expiry cannot manufacture an evaluator decision"),
        vector("pre-submission-expiry-delivery-ref", "expiry-invented-delivery", "rejected", "DRT-12", "pre-submission expiry omits delivery evidence"),
        vector("expiry-invented-seller-fault", "expired-pre", "rejected", "DRT-13", "decisionless expiry cannot invent buyer or seller fault", [{"op": "replace", "path": ["reputationProjection", "sellerFault"], "value": True}]),
        vector("dispute-outcome-direct-transfer", "pre-submission-rejected-refund", "rejected", "DRX-1", "a DisputeOutcome cannot directly claim an on-chain transfer", [{"op": "add", "path": ["artifacts", "dispute", "transfer"], "value": "refund"}]),
        vector("wrong-faulted-party", "wrong-faulted-party", "rejected", "DRX-5", "faultedParty must equal the party named by the classification"),
        vector("nonfault-finding-names-party", "nonfault-with-faulted-party", "rejected", "DRX-6", "a no-fault finding cannot name a faulted party"),
        vector("rail-resolution-unavailable", "release", "indeterminate", "DRC-11", "unavailable rail authority does not become a guessed failure", [{"op": "replace", "path": ["externalEvidence", "railResolution"], "value": "unavailable"}]),
        vector("runtime-code-unavailable", "release", "indeterminate", "DRJ-7", "unresolved code remains indeterminate", [{"op": "replace", "path": ["externalEvidence", "codeResolution"], "value": "unavailable"}]),
        vector("delivery-evidence-unavailable", "release", "indeterminate", "DRE-5", "unavailable delivery evidence remains indeterminate", [{"op": "replace", "path": ["externalEvidence", "deliveryFinality"], "value": "unavailable"}]),
        vector("decision-finality-unavailable", "release", "indeterminate", "DRD-4", "unavailable decision finality cannot authorize the terminal action", [{"op": "replace", "path": ["externalEvidence", "decisionFinality"], "value": "unavailable"}]),
        vector("terminal-finality-unavailable", "release", "indeterminate", "DRT-9", "missing terminal finality evidence remains indeterminate", [{"op": "replace", "path": ["externalEvidence", "terminalFinality"], "value": "unavailable"}]),
        vector("cross-substrate-order-unavailable", "release", "indeterminate", "DRD-10", "unorderable decision and terminal evidence remains indeterminate", [{"op": "replace", "path": ["externalEvidence", "decisionOrdering"], "value": "unavailable"}]),
        vector("self-reported-time-cannot-order", "release", "indeterminate", "DRD-10", "a self-reported decidedAt value cannot replace authenticated ordering", [{"op": "add", "path": ["native", "reportedDecidedAt"], "value": 1799999999}, {"op": "replace", "path": ["externalEvidence", "decisionOrdering"], "value": "unavailable"}]),
        vector("decision-finalized-after-terminal", "release", "rejected", "DRV-6", "authenticated after-terminal decision finality is contradictory", [{"op": "replace", "path": ["externalEvidence", "decisionOrdering"], "value": "contradictory"}]),
        vector("decision-artifact-unavailable", "missing-decision", "indeterminate", "DRD-10", "missing decision evidence without contradiction remains indeterminate"),
        vector("authenticated-native-contradiction", "release", "rejected", "DRV-6", "authenticated contradictory chain evidence rejects", [{"op": "replace", "path": ["externalEvidence", "codeResolution"], "value": "contradictory"}]),
        vector("public-test-seed-mismatch", "release", "rejected", "DRV-4", "committed public test seeds must derive the published verification keys", [{"op": "replace", "path": ["reproductionInputs", "publicTestSeedHex", BUYER], "value": "00" * 32}]),
        vector("role-bundle-input-mismatch", "release", "rejected", "DRA-4", "the committed role bundle must hash to the signed overlay binding", [{"op": "replace", "path": ["reproductionInputs", "roleBundles", "buyer", "primaryClaim"], "value": SELLER}]),
        vector("evaluation-rule-input-mismatch", "release", "rejected", "DRE-6", "the exact evaluation rule input must resolve from the signed reference", [{"op": "replace", "path": ["reproductionInputs", "evaluationRule", "rule"], "value": "different-rule"}]),
        vector("delivered-artifact-input-mismatch", "release", "rejected", "DRE-3", "the delivered-artifact preimage must resolve from the signed delivery reference", [{"op": "replace", "path": ["reproductionInputs", "deliveredArtifact", "payloadUtf8"], "value": "substituted"}]),
        vector("runtime-bytecode-preimage-mismatch", "release", "rejected", "DRJ-5", "the runtime bytecode preimage must reproduce the pinned hash", [{"op": "replace", "path": ["reproductionInputs", "runtimeBytecode", "value"], "value": "substituted runtime"}]),
        vector("native-event-transaction-preimage-mismatch", "release", "rejected", "DRT-4", "event transaction hashes must reproduce from committed inputs", [{"op": "replace", "path": ["reproductionInputs", "nativeEventInputs", 3, "txHashPreimageUtf8"], "value": "substituted tx"}]),
        vector("native-event-kind-substitution", "release", "rejected", "DRT-4", "event observations retain the exact EvmEventRef discriminator", [{"op": "replace", "path": ["reproductionInputs", "nativeEventInputs", 3, "eventRef", "kind"], "value": "transaction"}]),
        vector("native-event-chain-substitution", "release", "rejected", "DRT-4", "event observations retain the selected rail chain", [{"op": "replace", "path": ["reproductionInputs", "nativeEventInputs", 3, "eventRef", "chainId"], "value": 10}]),
        vector("funding-time-caller-substitution", "release", "rejected", "DRA-9", "a caller fundedAt value cannot replace the authenticated funding-event block timestamp", [{"op": "replace", "path": ["native", "fundedAtSec"], "value": 1799990001}]),
        vector("submitted-before-cutoff-claim-substitution", "release", "rejected", "DRT-12", "submission classification derives from the authenticated event time", [{"op": "replace", "path": ["submittedBeforeCutoff"], "value": False}]),
        vector("terminal-event-payload-mismatch", "release", "rejected", "DRT-4", "terminal log inputs must match the claimed financial disposition", [{"op": "replace", "path": ["reproductionInputs", "nativeEventInputs", 3, "arguments", "amountBaseUnits"], "value": "999999"}]),
        vector("funding-finality-block-preimage-mismatch", "release", "rejected", "DRF-6", "the finalized funding block hash must reproduce from committed input", [{"op": "replace", "path": ["reproductionInputs", "nativeEventInputs", 1, "blockHashPreimageUtf8"], "value": "substituted block"}]),
        vector("nonminimal-native-job-id", "release", "error", "DRJ-1", "native job identifiers use minimal unsigned decimal text", [{"op": "replace", "path": ["artifacts", "job", "nativeJobId"], "value": "01"}]),
        vector("noninteger-evaluation-sequence", "release", "error", "DRAA-2", "numeric address segments must be unsigned integers", [{"op": "replace", "path": ["artifacts", "evaluation", "evaluationSeq"], "value": "0"}]),
        vector("first-evaluation-sequence-not-zero", "release", "rejected", "DRAA-6", "the first evaluation sequence starts at zero", [{"op": "replace", "path": ["artifacts", "evaluation", "evaluationSeq"], "value": 1}]),
        vector("noncanonical-job-id", "release", "error", "DRAA-1", "malformed JID is an input error", [{"op": "replace", "path": ["artifacts", "agreement", "jobId"], "value": "job-356"}]),
        vector("malformed-native-bytes32", "release", "error", "DRV-2", "malformed native bytes are not repaired", [{"op": "replace", "path": ["native", "deliverable"], "value": "0x1234"}]),
        vector("unsupported-profile-discriminator", "release", "error", "DRV-1", "unsupported profiles fail before action", [{"op": "replace", "path": ["candidateProfile"], "value": "delivery-or-remedy-v2"}]),
    ]
    promotion_blocked_rules = {
        "DRAA-3": "requires the normative SR-2 logical-address derivation and a conforming resolver",
        "DRAA-4": "requires authenticated SR-2 write-once behavior from the selected storage binding",
        "DRAA-5": "requires authenticated conflicting-write evidence from the selected SR-2 binding",
        "DRAA-7": "requires the post-terminal dispute-revision profile and authenticated prior-revision resolution",
        "DRAA-8": "requires an authenticated resolver that selects by logical address rather than index or reported time",
        "DRF-7": "requires the session orchestrator to anchor funding evidence through a conforming SR-2 implementation",
        "DRJ-6": "requires live proxy, implementation, and mutation-authority resolution for a selected deployment",
        "DRJ-9": "requires the session orchestrator to anchor the job reference through a conforming SR-2 implementation",
        "DRQ-2": "requires the explicit-party-supplied evidence shape and deliberate-supply proof to be specified",
        "DRQ-5": "is a future transcript-enabled profile requirement and has no current-profile positive case",
        "DRV-5": "requires transaction-submission retry orchestration against a live native job",
        "DRX-3": "requires the post-terminal dispute-revision profile, which is outside this first executable pack",
        "DRX-4": "requires a post-terminal dispute revision and authenticated observation of the fixed disposition",
    }
    payload = {
        "fixtures": fixtures,
        "vectors": vectors,
        "promotionBlockedRules": promotion_blocked_rules,
    }
    return {
        "kind": "DeliveryRemedyCandidateVectorPack",
        "status": "non-normative-review-fixture",
        "spec": "docs/delivery-or-remedy-candidate.md#11-required-conformance-evidence",
        "generator": "scripts/generate_delivery_remedy_candidate_vectors.py",
        "verifier": "scripts/verify_delivery_remedy_candidate_vectors.py",
        "scope": "offline synthetic evidence only; does not register or make a rail available",
        "hash": hashlib.sha256(canonical_bytes(payload)).hexdigest(),
        "count": len(vectors),
        **payload,
    }


def synthetic_manifest() -> dict[str, Any]:
    runtime = hashlib.sha256(b"synthetic eligible runtime").hexdigest()
    return {
        "manifestVersion": "1",
        "candidateProfile": "dacs-delivery-gate-v1",
        "fixtureOnly": True,
        "registrationStatus": "not-a-deployment",
        "implementation": {
            "name": "synthetic-drc-control",
            "revision": "fixture-only",
            "chainId": 31337,
            "contractAddress": "0x" + "de" * 20,
        },
        "capabilities": {
            "preterminalProviderPayoutPaths": [],
            "platformFeeBP": 0,
            "evaluatorFeeBP": 0,
            "feeMutationAuthorities": [],
            "expiryRecoveryPauseGated": False,
            "expiryRecoveryHookGated": False,
            "evaluatorCanBlockExpiryRecovery": False,
            "pendingClaimCanDelayFundedRecovery": False,
            "lockedFundAlternateWithdrawalAuthorities": [],
            "logicReplacementAuthorities": [],
            "hookMutable": False,
            "upgradeableSyntactically": False,
            "upgradeAuthorityIrreversiblyDisabled": True,
            "hookMode": "absent",
            "paymentTokenSemantics": {
                "transferFees": False,
                "rebasing": False,
                "callbacks": False,
                "pause": False,
                "blacklist": False,
                "externalBalanceMutation": False,
                "independentlyVerified": True,
            },
            "eventIdentityComplete": True,
            "decisionOrderingProfile": "synthetic-single-chain-finalized-before-terminal-v1",
            "deadlineProfile": "separate-submission-cutoff-v1",
            "submissionCutoffEnforced": True,
            "expiryRecoveryDeadlineEnforced": True,
        },
        "evidence": {
            "sourceRevision": "synthetic-fixture-only",
            "compilerSettingsHash": hashlib.sha256(b"synthetic compiler settings").hexdigest(),
            "runtimeBytecodeHash": runtime,
            "independentlyResolvedRuntimeBytecodeHash": runtime,
            "sourceToBytecodeReproducible": True,
            "upgradeDisablementAuthenticated": True,
            "decisionOrderingEvidenceAuthenticated": True,
            "deadlineEnforcementAuthenticated": True,
            "complete": True,
            "conflict": False,
        },
    }


def current_reference_manifest() -> dict[str, Any]:
    return {
        "manifestVersion": "1",
        "candidateProfile": "dacs-delivery-gate-v1",
        "fixtureOnly": False,
        "registrationStatus": "unregistered-ineligible-reference-source",
        "implementation": {
            "name": "erc-8183/base-contracts ERC8183.sol",
            "revision": "142e669c1fd318486a4628395b629f033654dd06",
            "sourcePath": "contracts/ERC8183.sol",
            "deployment": None,
        },
        "capabilities": {
            "preterminalProviderPayoutPaths": ["settleClaim while Funded", "approveClaim while Funded"],
            "platformFeeBP": 0,
            "evaluatorFeeBP": 0,
            "feeMutationAuthorities": ["ADMIN_ROLE:setPlatformFee", "ADMIN_ROLE:setEvaluatorFee"],
            "expiryRecoveryPauseGated": True,
            "expiryRecoveryHookGated": True,
            "evaluatorCanBlockExpiryRecovery": False,
            "pendingClaimCanDelayFundedRecovery": True,
            "lockedFundAlternateWithdrawalAuthorities": ["ADMIN_ROLE:emergencyWithdraw"],
            "logicReplacementAuthorities": ["DEFAULT_ADMIN_ROLE:_authorizeUpgrade", "ADMIN_ROLE:batchDetachHook"],
            "hookMutable": True,
            "upgradeableSyntactically": True,
            "upgradeAuthorityIrreversiblyDisabled": False,
            "hookMode": "mutable-blocking",
            "paymentTokenSemantics": {
                "transferFees": None,
                "rebasing": None,
                "callbacks": None,
                "pause": None,
                "blacklist": None,
                "externalBalanceMutation": None,
                "independentlyVerified": None,
            },
            "eventIdentityComplete": True,
            "decisionOrderingProfile": None,
            "deadlineProfile": None,
            "submissionCutoffEnforced": None,
            "expiryRecoveryDeadlineEnforced": None,
        },
        "evidence": {
            "sourceRevision": "142e669c1fd318486a4628395b629f033654dd06",
            "compilerSettingsHash": None,
            "runtimeBytecodeHash": None,
            "independentlyResolvedRuntimeBytecodeHash": None,
            "sourceToBytecodeReproducible": None,
            "upgradeDisablementAuthenticated": False,
            "decisionOrderingEvidenceAuthenticated": None,
            "deadlineEnforcementAuthenticated": None,
            "complete": False,
            "conflict": None,
        },
        "observedSourceFacts": [
            "UUPSUpgradeable with DEFAULT_ADMIN_ROLE upgrade authorization",
            "ADMIN_ROLE pause, emergencyWithdraw, mutable fees, hook whitelist, and hook detachment",
            "settleClaim and approveClaim can release provider value from Funded",
            "claimRefund is pause-gated and a pending claim can delay Funded recovery",
            "no separately enforced per-job submission cutoff is evidenced",
        ],
    }


def deployment_case(name: str, base: str, expected: str, rules: list[str], note: str, patch=None, unknown=None, covers=None) -> dict[str, Any]:
    value = {
        "name": name,
        "base": base,
        "expected": expected,
        "registrationEligible": False,
        "expectedFailedRules": rules,
        "rules": sorted(set(covers or rules)),
        "note": note,
        "patch": patch or [],
    }
    if unknown is not None:
        value["expectedUnknownRules"] = unknown
    return value


def build_deployment_pack() -> dict[str, Any]:
    manifests = {
        "synthetic-control": synthetic_manifest(),
        "current-reference-142e669": current_reference_manifest(),
    }
    cases = [
        deployment_case("synthetic-all-rules-control", "synthetic-control", "verified", [], "all DRC rules pass, but fixtureOnly keeps registration ineligible", covers=["DRL-8", "DRL-9"]),
        deployment_case("drc-1-preterminal-payout", "synthetic-control", "rejected", ["DRC-1"], "a Funded payout path violates delivery gating", [{"op": "replace", "path": ["capabilities", "preterminalProviderPayoutPaths"], "value": ["settleClaim while Funded"]}]),
        deployment_case("drc-2-mutable-fees", "synthetic-control", "rejected", ["DRC-2"], "zero defaults do not repair mutable fee authority", [{"op": "replace", "path": ["capabilities", "feeMutationAuthorities"], "value": ["admin:setFee"]}]),
        deployment_case("drc-3-blocked-expiry-recovery", "synthetic-control", "rejected", ["DRC-3"], "pause-gated expiry recovery is ineligible", [{"op": "replace", "path": ["capabilities", "expiryRecoveryPauseGated"], "value": True}]),
        deployment_case("drc-4-emergency-withdrawal", "synthetic-control", "rejected", ["DRC-4"], "an alternate locked-fund recipient is ineligible", [{"op": "replace", "path": ["capabilities", "lockedFundAlternateWithdrawalAuthorities"], "value": ["admin:withdraw"]}]),
        deployment_case("drc-5-logic-replacement", "synthetic-control", "rejected", ["DRC-5"], "mutable logic can weaken core guarantees", [{"op": "replace", "path": ["capabilities", "logicReplacementAuthorities"], "value": ["proxy-admin"]}]),
        deployment_case("drc-6-live-upgrade-authority", "synthetic-control", "rejected", ["DRC-6"], "syntactic upgradeability needs irreversible disablement proof", [{"op": "replace", "path": ["capabilities", "upgradeableSyntactically"], "value": True}, {"op": "replace", "path": ["capabilities", "upgradeAuthorityIrreversiblyDisabled"], "value": False}, {"op": "replace", "path": ["evidence", "upgradeDisablementAuthenticated"], "value": False}]),
        deployment_case("drc-7-mutable-blocking-hook", "synthetic-control", "rejected", ["DRC-7"], "hooks cannot block recovery or change later", [{"op": "replace", "path": ["capabilities", "hookMode"], "value": "mutable-blocking"}]),
        deployment_case("drc-8-fee-on-transfer-token", "synthetic-control", "rejected", ["DRC-8"], "token transfer fees break exact accounting", [{"op": "replace", "path": ["capabilities", "paymentTokenSemantics", "transferFees"], "value": True}]),
        deployment_case("drc-9-ambiguous-events", "synthetic-control", "rejected", ["DRC-9"], "events must identify the exact job and action", [{"op": "replace", "path": ["capabilities", "eventIdentityComplete"], "value": False}]),
        deployment_case("drc-10-bytecode-mismatch", "synthetic-control", "rejected", ["DRC-10"], "independently resolved code must match reproducible output", [{"op": "replace", "path": ["evidence", "independentlyResolvedRuntimeBytecodeHash"], "value": "ab" * 32}]),
        deployment_case("drc-11-conflicting-evidence", "synthetic-control", "rejected", ["DRC-11"], "conflicting deployment evidence leaves the rail unavailable", [{"op": "replace", "path": ["evidence", "conflict"], "value": True}]),
        deployment_case("drc-12-unauthenticated-ordering", "synthetic-control", "rejected", ["DRC-12"], "decision ordering must be authenticated", [{"op": "replace", "path": ["evidence", "decisionOrderingEvidenceAuthenticated"], "value": False}]),
        deployment_case("drc-13-missing-native-submission-cutoff", "synthetic-control", "rejected", ["DRC-13"], "submission and recovery deadlines must be separately enforced", [{"op": "replace", "path": ["capabilities", "submissionCutoffEnforced"], "value": False}]),
        deployment_case("source-to-bytecode-evidence-unavailable", "synthetic-control", "indeterminate", [], "missing source-to-bytecode evidence is not guessed", [{"op": "replace", "path": ["evidence", "sourceToBytecodeReproducible"], "value": None}], unknown=["DRC-10"]),
        deployment_case(
            "current-reference-142e669-ineligible",
            "current-reference-142e669",
            "rejected",
            ["DRC-1", "DRC-2", "DRC-3", "DRC-4", "DRC-5", "DRC-6", "DRC-7"],
            "the pinned reference source is not a DACS-eligible deployment",
            unknown=["DRC-8", "DRC-10", "DRC-11", "DRC-12", "DRC-13"],
        ),
        deployment_case("malformed-deployment-manifest", "synthetic-control", "error", [], "malformed capability input fails before eligibility", [{"op": "remove", "path": ["capabilities"]}]),
    ]
    payload = {"manifests": manifests, "cases": cases}
    return {
        "kind": "ERC8183DeploymentCapabilityPack",
        "status": "non-normative-review-fixture",
        "spec": "docs/delivery-or-remedy-candidate.md#84-deployment-eligibility",
        "sourcePins": {
            "canonicalErc": "https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-8183.md",
            "referenceImplementation": "https://github.com/erc-8183/base-contracts/blob/142e669c1fd318486a4628395b629f033654dd06/contracts/ERC8183.sol",
        },
        "scope": "capability evidence only; no chain deployment or DACS rail is registered",
        "hash": hashlib.sha256(canonical_bytes(payload)).hexdigest(),
        "count": len(cases),
        **payload,
    }


def rendered(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    outputs = {
        VECTOR_OUTPUT: rendered(build_vector_pack()),
        DEPLOYMENT_OUTPUT: rendered(build_deployment_pack()),
    }
    if args.write:
        for path, text in outputs.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path.relative_to(ROOT)}")
        return 0
    if args.check:
        stale = [
            path for path, text in outputs.items()
            if not path.exists() or path.read_text(encoding="utf-8") != text
        ]
        if stale:
            for path in stale:
                print(f"ERROR: {path.relative_to(ROOT)} is stale", file=sys.stderr)
            print("run this script with --write", file=sys.stderr)
            return 1
        print("delivery-or-remedy candidate packs are deterministic and current")
        return 0
    for path, text in outputs.items():
        print(f"# {path.relative_to(ROOT)}")
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
