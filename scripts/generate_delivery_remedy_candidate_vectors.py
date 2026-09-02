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
    "agreement": "dacs-delivery-remedy-agreement:v1:",
    "job": "dacs-escrow-job-ref:v1:",
    "funding": "dacs-escrow-funding-evidence:v1:",
    "delivery": "dacs-evidence:v1:",
    "evaluation": "dacs-execution-evaluation:v1:",
    "dispute": "dacs-dispute-outcome:v1:",
    "decision": "dacs-escrow-decision:v1:",
    "terminal": "dacs-escrow-terminal-evidence:v1:",
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


def finality(job_id: str, tag: str, block_number: int) -> dict[str, Any]:
    return {
        "status": "finalized",
        "chainId": CHAIN_ID,
        "blockNumber": block_number,
        "blockHash": "0x" + hashlib.sha256(f"{job_id}:{tag}:block".encode("ascii")).hexdigest(),
        "confirmations": 64,
    }


def logical(job_id: str, suffix: str) -> str:
    return f"dacsx:delivery-remedy:{job_id}:{suffix}"


def make_base(lifecycle: str, job_id: str = JOB_A) -> dict[str, Any]:
    if lifecycle not in {
        "release", "rejected-refund", "pre-submission-rejected-refund",
        "expired-pre", "expired-post",
    }:
        raise ValueError(lifecycle)
    pipeline = [
        {"kind": "commit-delivery-or-remedy-agreement"},
        {"kind": "job-escrow", "parameters": {"action": "fund", "rail": "pay-evm-erc8183:fixture-v1"}},
        {"kind": "deliver-storage-program"},
        {"kind": "job-escrow", "parameters": {"action": "terminal", "rail": "pay-evm-erc8183:fixture-v1"}},
        {"kind": "rate"},
    ]
    profile = {
        "minimumEvaluationWindowSec": 3600,
        "evaluationGracePeriodSec": 7200,
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
            "bundleHash": hashlib.sha256(b"buyer bundle #356").hexdigest(),
            "vetRecordRef": {"kind": "storage-program", "locator": "fixture:vet:buyer", "contentHash": "a1" * 32},
            "evmAccountClaim": f"cci-xm:evm:{CHAIN_ID}:{BUYER_ACCOUNT}",
        },
        "seller": {
            "primaryClaim": SELLER,
            "bundleHash": hashlib.sha256(b"seller bundle #356").hexdigest(),
            "vetRecordRef": {"kind": "storage-program", "locator": "fixture:vet:seller", "contentHash": "a2" * 32},
            "evmAccountClaim": f"cci-xm:evm:{CHAIN_ID}:{SELLER_ACCOUNT}",
        },
        "evaluator": {
            "primaryClaim": EVALUATOR,
            "bundleHash": hashlib.sha256(b"evaluator bundle #356").hexdigest(),
            "vetRecordRef": {"kind": "storage-program", "locator": "fixture:vet:evaluator", "contentHash": "a3" * 32},
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
            "contentHash": hashlib.sha256(b"exact-output-v1").hexdigest(),
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
        "finality": finality(job_id, "fund", 20000000),
        "observedAt": 1799990000000,
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
                "contentHash": hashlib.sha256(f"deliverable:{job_id}".encode("ascii")).hexdigest(),
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
                "contentHash": hashlib.sha256(f"case:{CASE_A}".encode("ascii")).hexdigest(),
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
        "finality": finality(job_id, action, 20000100),
        "observedAt": 1800007300000,
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
        "terminalCaller": EVALUATOR_ACCOUNT if decision is not None else BUYER_ACCOUNT,
        "transactionSubmitter": EVALUATOR_ACCOUNT if decision is not None else BUYER_ACCOUNT,
        "token": TOKEN,
        "amountBaseUnits": "1000000",
        "description": "dacs-delivery-remedy:v1:" + agreement_hash,
        "deliverable": None if delivery is None else "0x" + artifact_hash(delivery),
        "reason": None if decision is None else "0x" + artifact_hash(decision),
        "expiredAt": 1800000000,
        "evaluationDeadlineSec": 1800007200,
        "preterminalProviderPayoutBaseUnits": "0",
        "platformFeeBP": 0,
        "evaluatorFeeBP": 0,
        "terminalState": terminal_state,
        "terminalAction": action,
    }
    return {
        "candidateProfile": "delivery-or-remedy-v1",
        "fixtureOnly": True,
        "pipeline": pipeline,
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
            }
        ),
        "reputationProjection": {"buyerFault": False, "sellerFault": False},
        "submittedBeforeExpiry": lifecycle not in {"expired-pre", "pre-submission-rejected-refund"},
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


def resign_terminal(fixture: dict[str, Any]) -> None:
    terminal = fixture["artifacts"]["terminal"]
    terminal["signature"] = component_signature(terminal, "orchestrator", DOMAINS["terminal"])


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


def vector(name: str, base: str, expected: str, rule: str, note: str, patch=None) -> dict[str, Any]:
    return {
        "name": name,
        "base": base,
        "expected": expected,
        "expectedRule": rule,
        "rules": [rule],
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

    for fixture in fixtures.values():
        refresh_canonical_records(fixture)

    vectors = [
        vector("release-complete-budget", "release", "verified", "DRV-7", "fund, deliver, evaluate, and release the complete budget"),
        vector("evaluator-rejection-refund", "rejected-refund", "verified", "DRV-7", "a signed rejection refunds the complete budget"),
        vector("pre-submission-evaluator-rejection", "pre-submission-rejected-refund", "verified", "DRV-7", "agreement-authorized pre-submission rejection uses a DisputeOutcome and omits delivery evidence"),
        vector("expiry-before-submission", "expired-pre", "verified", "DRV-7", "pre-submission expiry refunds without a decision or delivery reference"),
        vector("expiry-after-submission-grace", "expired-post", "verified", "DRV-7", "post-submission expiry refunds after grace without inventing a decision"),
        vector("pipeline-missing-terminal", "release", "rejected", "DRP-1", "an unpaired escrow phase is rejected", [{"op": "remove", "path": ["pipeline", 3]}]),
        vector("pipeline-actions-reversed", "release", "rejected", "DRP-2", "escrow phases must be fund then terminal", [{"op": "replace", "path": ["pipeline", 1, "parameters", "action"], "value": "terminal"}]),
        vector("pipeline-second-delivery", "release", "rejected", "DRP-3", "only one delivery step may occur", [{"op": "add", "path": ["pipeline", 3], "value": {"kind": "deliver-inline"}}]),
        vector("pipeline-extra-payment", "release", "rejected", "DRP-4", "ordinary payment phases cannot accompany the pair", [{"op": "add", "path": ["pipeline", 4], "value": {"kind": "pay-x402"}}]),
        vector("pipeline-rail-divergence", "release", "rejected", "DRP-5", "both escrow invocations must use the same rail", [{"op": "replace", "path": ["pipeline", 3, "parameters", "rail"], "value": "pay-evm-erc8183:other"}]),
        vector("pipeline-phase-index-divergence", "release", "rejected", "DRA-11", "signed indexes must match the phase pair", [{"op": "replace", "path": ["artifacts", "agreement", "deliveryPhaseIndex"], "value": 4}]),
        vector("evaluator-added-as-bundle-party", "release", "rejected", "DRA-13", "the evaluator overlay signature does not create a third bundle party", [{"op": "add", "path": ["bundleRequiredSigners", 2], "value": EVALUATOR}]),
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
        vector("native-evaluator-mismatch", "release", "rejected", "DREB-9", "native evaluator must equal the controlled evaluator account", [{"op": "replace", "path": ["native", "evaluator"], "value": "0x" + "66" * 20}]),
        vector("evaluator-vet-failure", "release", "rejected", "DRA-9", "evaluator must have a fresh pass", [{"op": "replace", "path": ["evaluatorVetResult"], "value": "fail"}]),
        vector("nonpositive-evaluation-window", "release", "rejected", "DREB-14", "registered rail windows must be positive", [{"op": "replace", "path": ["profileParameters", "minimumEvaluationWindowSec"], "value": 0}]),
        vector("evaluation-deadline-divergence", "release", "rejected", "DREB-13", "deadline must equal cutoff plus pinned grace", [{"op": "replace", "path": ["profileParameters", "evaluationGracePeriodSec"], "value": 3600}]),
        vector("native-expiry-divergence", "release", "rejected", "DREB-12", "native expiry must equal the submission cutoff", [{"op": "replace", "path": ["native", "expiredAt"], "value": 1800000001}]),
        vector("cross-job-delivery-replay", "cross-job-delivery", "rejected", "DRD-8", "delivery from another job cannot be replayed"),
        vector("cross-job-decision-replay", "cross-job-decision", "rejected", "DRD-8", "decision from another job cannot be replayed"),
        vector("consumed-decision-replay", "release", "rejected", "DRD-8", "a terminally consumed decision is one-use", [{"op": "add", "path": ["consumedDecisionHashes", 0], "value": fixtures["release"]["mappingSources"]["decisionHash"]}]),
        vector("wrong-evaluator-signer", "release", "rejected", "DRE-1", "commercial parties cannot sign evaluator artifacts", [{"op": "replace", "path": ["artifacts", "evaluation", "signature"], "value": bad_signer}]),
        vector("relayed-outer-submitter", "release", "verified", "DRV-7", "an outer relay does not replace the authenticated native evaluator caller", [{"op": "replace", "path": ["native", "transactionSubmitter"], "value": RELAYER_ACCOUNT}]),
        vector("eip1271-relayed-execution", "release", "verified", "DRV-7", "a supported contract account remains the native caller while an outer account submits", [{"op": "replace", "path": ["native", "evaluatorAccountType"], "value": "eip1271"}, {"op": "replace", "path": ["native", "transactionSubmitter"], "value": RELAYER_ACCOUNT}]),
        vector("relayer-substituted-as-native-caller", "release", "rejected", "DREB-21", "a relayer cannot replace the agreement-bound evaluator as native caller", [{"op": "replace", "path": ["native", "terminalCaller"], "value": RELAYER_ACCOUNT}]),
        vector("reject-evaluation-release-action", "reject-then-release", "rejected", "DRD-2", "rejection cannot authorize release"),
        vector("accept-evaluation-refund-action", "accept-then-refund", "rejected", "DRD-2", "acceptance cannot authorize refund"),
        vector("partial-terminal-release", "partial-release", "rejected", "DRT-5", "terminal release must cover the complete budget"),
        vector("wrong-release-recipient", "wrong-release-recipient", "rejected", "DRT-5", "release goes only to the bound seller payout account"),
        vector("wrong-refund-recipient", "wrong-refund-recipient", "rejected", "DRT-6", "refund goes only to the client"),
        vector("nonzero-preterminal-payout", "release", "rejected", "DRL-7", "any preterminal provider payout is forbidden", [{"op": "replace", "path": ["native", "preterminalProviderPayoutBaseUnits"], "value": "1"}]),
        vector("nonzero-platform-fee", "release", "rejected", "DRT-7", "escrow fees must be zero", [{"op": "replace", "path": ["native", "platformFeeBP"], "value": 1}]),
        vector("expiry-invented-decision", "expiry-invented-decision", "rejected", "DRD-7", "expiry cannot manufacture an evaluator decision"),
        vector("pre-submission-expiry-delivery-ref", "expiry-invented-delivery", "rejected", "DRT-12", "pre-submission expiry omits delivery evidence"),
        vector("expiry-invented-seller-fault", "expired-pre", "rejected", "DRT-13", "decisionless expiry cannot invent buyer or seller fault", [{"op": "replace", "path": ["reputationProjection", "sellerFault"], "value": True}]),
        vector("rail-resolution-unavailable", "release", "indeterminate", "DRV-2", "unavailable rail authority does not become a guessed failure", [{"op": "replace", "path": ["externalEvidence", "railResolution"], "value": "unavailable"}]),
        vector("runtime-code-unavailable", "release", "indeterminate", "DRV-2", "unresolved code remains indeterminate", [{"op": "replace", "path": ["externalEvidence", "codeResolution"], "value": "unavailable"}]),
        vector("terminal-finality-unavailable", "release", "indeterminate", "DRV-2", "missing finality evidence remains indeterminate", [{"op": "replace", "path": ["externalEvidence", "terminalFinality"], "value": "unavailable"}]),
        vector("cross-substrate-order-unavailable", "release", "indeterminate", "DRD-10", "unorderable decision and terminal evidence remains indeterminate", [{"op": "replace", "path": ["externalEvidence", "decisionOrdering"], "value": "unavailable"}]),
        vector("self-reported-time-cannot-order", "release", "indeterminate", "DRD-10", "a self-reported decidedAt value cannot replace authenticated ordering", [{"op": "add", "path": ["native", "reportedDecidedAt"], "value": 1799999999}, {"op": "replace", "path": ["externalEvidence", "decisionOrdering"], "value": "unavailable"}]),
        vector("decision-finalized-after-terminal", "release", "rejected", "DRV-6", "authenticated after-terminal decision finality is contradictory", [{"op": "replace", "path": ["externalEvidence", "decisionOrdering"], "value": "contradictory"}]),
        vector("decision-artifact-unavailable", "missing-decision", "indeterminate", "DRD-10", "missing decision evidence without contradiction remains indeterminate"),
        vector("authenticated-native-contradiction", "release", "rejected", "DRV-6", "authenticated contradictory chain evidence rejects", [{"op": "replace", "path": ["externalEvidence", "codeResolution"], "value": "contradictory"}]),
        vector("noncanonical-job-id", "release", "error", "DRAA-1", "malformed JID is an input error", [{"op": "replace", "path": ["artifacts", "agreement", "jobId"], "value": "job-356"}]),
        vector("malformed-native-bytes32", "release", "error", "DRV-2", "malformed native bytes are not repaired", [{"op": "replace", "path": ["native", "deliverable"], "value": "0x1234"}]),
        vector("unsupported-profile-discriminator", "release", "error", "DRV-1", "unsupported profiles fail before action", [{"op": "replace", "path": ["candidateProfile"], "value": "delivery-or-remedy-v2"}]),
    ]
    payload = {"fixtures": fixtures, "vectors": vectors}
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
        },
        "evidence": {
            "sourceRevision": "synthetic-fixture-only",
            "compilerSettingsHash": hashlib.sha256(b"synthetic compiler settings").hexdigest(),
            "runtimeBytecodeHash": runtime,
            "independentlyResolvedRuntimeBytecodeHash": runtime,
            "sourceToBytecodeReproducible": True,
            "upgradeDisablementAuthenticated": True,
            "decisionOrderingEvidenceAuthenticated": True,
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
        },
        "evidence": {
            "sourceRevision": "142e669c1fd318486a4628395b629f033654dd06",
            "compilerSettingsHash": None,
            "runtimeBytecodeHash": None,
            "independentlyResolvedRuntimeBytecodeHash": None,
            "sourceToBytecodeReproducible": None,
            "upgradeDisablementAuthenticated": False,
            "decisionOrderingEvidenceAuthenticated": None,
            "complete": False,
            "conflict": None,
        },
        "observedSourceFacts": [
            "UUPSUpgradeable with DEFAULT_ADMIN_ROLE upgrade authorization",
            "ADMIN_ROLE pause, emergencyWithdraw, mutable fees, hook whitelist, and hook detachment",
            "settleClaim and approveClaim can release provider value from Funded",
            "claimRefund is pause-gated and a pending claim can delay Funded recovery",
        ],
    }


def deployment_case(name: str, base: str, expected: str, rules: list[str], note: str, patch=None, unknown=None) -> dict[str, Any]:
    value = {
        "name": name,
        "base": base,
        "expected": expected,
        "registrationEligible": False,
        "expectedFailedRules": rules,
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
        deployment_case("synthetic-all-rules-control", "synthetic-control", "verified", [], "all DRC rules pass, but fixtureOnly keeps registration ineligible"),
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
        deployment_case("source-to-bytecode-evidence-unavailable", "synthetic-control", "indeterminate", [], "missing source-to-bytecode evidence is not guessed", [{"op": "replace", "path": ["evidence", "sourceToBytecodeReproducible"], "value": None}], unknown=["DRC-10"]),
        deployment_case(
            "current-reference-142e669-ineligible",
            "current-reference-142e669",
            "rejected",
            ["DRC-1", "DRC-2", "DRC-3", "DRC-4", "DRC-5", "DRC-6", "DRC-7"],
            "the pinned reference source is not a DACS-eligible deployment",
            unknown=["DRC-8", "DRC-10", "DRC-11", "DRC-12"],
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
