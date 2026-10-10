#!/usr/bin/env python3
"""Generate deterministic non-normative delivery-or-remedy candidate packs."""
from __future__ import annotations

import argparse
import ast
import base64
import copy
import hashlib
import json
import sys
import types
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from jcs import canonicalize as jcs_canonicalize
except ModuleNotFoundError:  # imported as scripts.generate_* by another tool
    from scripts.jcs import canonicalize as jcs_canonicalize


ROOT = Path(__file__).resolve().parents[1]
VECTOR_OUTPUT = ROOT / "conformance/fixtures/delivery-remedy/candidate-vectors-v0.1.json"
DEPLOYMENT_OUTPUT = ROOT / "conformance/fixtures/delivery-remedy/deployment-capabilities-v0.1.json"
VERIFIER_PATH = ROOT / "scripts/verify_delivery_remedy_candidate_vectors.py"

JOB_A = "01J8ME0SXKQ4T9V2RC5HJ6WX7D"
JOB_B = "01J8ME0SXKQ4T9V2RC5HJ6WX7E"
CASE_A = "01J8ME0SXKQ4T9V2RC5HJ6WX7F"
# Each base lifecycle is its own job, so the positives never contend for one
# native job's terminal state.
LIFECYCLE_JOBS = {
    "release": JOB_A,
    "rejected-refund": "01J8ME0SXKQ4T9V2RC5HJ6WX7G",
    "pre-submission-rejected-refund": "01J8ME0SXKQ4T9V2RC5HJ6WX7H",
    "expired-pre": "01J8ME0SXKQ4T9V2RC5HJ6WX7J",
    "expired-post": "01J8ME0SXKQ4T9V2RC5HJ6WX7K",
}
# The failed-delivery refund positive is a further job of its own.
FAILED_DELIVERY_JOB = "01J8ME0SXKQ4T9V2RC5HJ6WX7M"
NATIVE_JOB_IDS = {
    JOB_A: "1",
    JOB_B: "2",
    **{
        job_id: str(index)
        for index, job_id in enumerate(list(LIFECYCLE_JOBS.values())[1:], start=3)
    },
    FAILED_DELIVERY_JOB: "7",
}
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
KEY_ROLE_BY_CLAIM = {claim: role for role, claim in CLAIMS.items()}
# Synthetic resolver whose public key the verifier pins.  It is deliberately
# absent from CLAIMS, so no vector carries its key or seed.
RESOLVER = "did:demos:agent:" + "99" * 32
RESOLVER_SEED = hashlib.sha256(b"DACS #356 candidate resolver key v1").digest()
RESOLVER_DOMAIN = "dacs-x-delivery-remedy-fixture-resolver:v1:"
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


def component_signature(artifact: dict[str, Any], claim: str, domain: str) -> dict[str, str]:
    role = KEY_ROLE_BY_CLAIM[claim]
    return {
        "algorithm": "ed25519",
        "signer": claim,
        "value": b64u(key(role).sign((domain + artifact_hash(artifact)).encode("ascii"))),
    }


def sign_component(artifact: dict[str, Any], claim: str, domain: str) -> dict[str, Any]:
    artifact.pop("signature", None)
    artifact["signature"] = component_signature(artifact, claim, domain)
    return artifact


def sign_overlay(agreement: dict[str, Any]) -> dict[str, Any]:
    agreement.pop("signatures", None)
    signatures = []
    for role in ("buyer", "seller", "evaluator"):
        signature = component_signature(
            agreement, agreement[role]["primaryClaim"], DOMAINS["agreement"]
        )
        signatures.append({"role": role, "party": signature.pop("signer"), **signature})
    agreement["signatures"] = signatures
    return agreement


def resign_resolver(fixture: dict[str, Any], bind: bool = True) -> None:
    """Have the pinned resolver authenticate the fixture's current record.

    With ``bind`` the record is first bound to this fixture's job, rail,
    contract, native job, and observations.
    """
    artifacts = fixture["artifacts"]
    rail = artifacts["railDefinition"]
    resolver = fixture["resolverEvidence"]
    if bind:
        resolver.update({
            "resolverEvidenceVersion": "1",
            "resolver": RESOLVER,
            "jobId": artifacts["agreement"]["jobId"],
            "railDefinitionHash": artifact_hash(rail),
            "chainId": rail["chainId"],
            "contractAddress": rail["contractAddress"],
            "nativeJobId": artifacts["job"]["nativeJobId"],
            "eventObservationsHash": content_hash(
                fixture["reproductionInputs"]["nativeEventInputs"]
            ),
        })
    resolver.pop("signature", None)
    resolver["signature"] = {
        "algorithm": "ed25519",
        "signer": RESOLVER,
        "value": b64u(
            Ed25519PrivateKey.from_private_bytes(RESOLVER_SEED).sign(
                (RESOLVER_DOMAIN + artifact_hash(resolver)).encode("ascii")
            )
        ),
    }


def apply_patch(value: Any, patch: list[dict[str, Any]]) -> Any:
    """Apply the pack's replace/add/remove operations to a fixture copy."""
    value = copy.deepcopy(value)
    for operation in patch:
        parent = value
        for segment in operation["path"][:-1]:
            parent = parent[segment]
        leaf = operation["path"][-1]
        if operation["op"] == "remove":
            del parent[leaf]
        elif operation["op"] == "add" and isinstance(parent, list):
            parent.insert(leaf, copy.deepcopy(operation["value"]))
        else:
            parent[leaf] = copy.deepcopy(operation["value"])
    return value


def resolver_patch(fixture: dict[str, Any], patch: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extend a patch so the pinned resolver authenticates the patched inputs."""
    patched = apply_patch(fixture, patch)
    resign_resolver(patched)
    return patch + [
        {"op": "replace", "path": ["resolverEvidence"], "value": patched["resolverEvidence"]}
    ]


def ref(artifact: dict[str, Any], locator: str) -> dict[str, str]:
    return {
        "kind": "storage-program",
        "locator": locator,
        "contentHash": artifact_hash(artifact),
    }


def event(tx_preimage: str, log_index: int) -> dict[str, Any]:
    return {
        "kind": "evm-event",
        "chainId": CHAIN_ID,
        "txHash": "0x" + hashlib.sha256(tx_preimage.encode("ascii")).hexdigest(),
        "logIndex": log_index,
    }


def event_input(
    ref_value: dict[str, Any],
    tx_preimage: str,
    job: dict[str, Any],
    block_number: int,
    block_timestamp_sec: int,
    event_name: str,
    arguments: dict[str, Any],
    confirmations: int = 64,
) -> dict[str, Any]:
    block_preimage = f"{tx_preimage}:block:{block_number}:{block_timestamp_sec}"
    return {
        "eventRef": copy.deepcopy(ref_value),
        "txHashPreimageUtf8": tx_preimage,
        "blockNumber": block_number,
        "blockHash": "0x" + hashlib.sha256(block_preimage.encode("ascii")).hexdigest(),
        "blockHashPreimageUtf8": block_preimage,
        "blockTimestampSec": block_timestamp_sec,
        "confirmations": confirmations,
        "contractAddress": job["contractAddress"],
        "nativeJobId": job["nativeJobId"],
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


Hooks = dict[str, Callable[[Any], None]]


def account_of(claim: str) -> str:
    """Return the address in a `cci-xm:evm:<chain>:<address>` account claim."""
    return claim.rsplit(":", 1)[1]


def make_base(
    lifecycle: str,
    job_id: str | None = None,
    *,
    delivered: bool | None = None,
    basis: str | None = None,
    evaluator_claim: str = EVALUATOR,
    terminal_tx_preimage: str | None = None,
    terminal_block: int = 20000100,
    submission_tx_preimage: str | None = None,
    hooks: Hooks | None = None,
) -> dict[str, Any]:
    """Build one signed lifecycle whose every binding derives from what it binds.

    A hook edits the named input set, artifact, reference, or finished fixture
    before it is signed or bound, and everything downstream is derived from
    the edited value.  A negative built this way differs from a consistent
    lifecycle only in its hooked edit.  ``terminal_block`` places the terminal
    event; blocks are two seconds apart.
    """
    if lifecycle not in LIFECYCLE_JOBS:
        raise ValueError(lifecycle)
    job_id = LIFECYCLE_JOBS[lifecycle] if job_id is None else job_id
    hooks = hooks or {}

    def hook(name: str, value: Any) -> Any:
        if name in hooks:
            hooks[name](value)
        return value

    if delivered is None:
        delivered = lifecycle not in {"expired-pre", "pre-submission-rejected-refund"}
    if basis is None:
        basis = {
            "release": "evaluation",
            "rejected-refund": "evaluation",
            "pre-submission-rejected-refund": "dispute",
        }.get(lifecycle)
    claims = {"buyer": BUYER, "seller": SELLER, "evaluator": evaluator_claim}
    created_at_sec = 1799989000
    funded_at_sec = 1799990000
    delivery_observed_at_ms = 1799994800000
    anchored_at_sec = 1799994900
    submitted_at_sec = 1799995000
    terminal_at_sec = (
        1799997000
        if lifecycle == "pre-submission-rejected-refund"
        else 1800007200
        if lifecycle in {"expired-pre", "expired-post"}
        else 1800001000
    ) + 2 * (terminal_block - 20000100)
    pipeline = [
        {"kind": "commit-delivery-or-remedy-agreement"},
        {"kind": "job-escrow", "parameters": {"action": "fund", "rail": "pay-evm-erc8183:fixture-v1"}},
        {"kind": "deliver-storage-program"},
        {"kind": "job-escrow", "parameters": {"action": "terminal", "rail": "pay-evm-erc8183:fixture-v1"}},
        {"kind": "rate"},
    ]
    bilateral = hook("bilateral", {
        "agreementVersion": "1",
        "jobId": job_id,
        "buyer": BUYER,
        "seller": SELLER,
        "price": {"amount": "1000000", "currency": "USDC"},
    })
    rail = hook("rail", {
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
        "profileParameters": {
            "minimumEvaluationWindowSec": 3600,
            "deadlineProfile": "separate-submission-cutoff-v1",
            "finalityBlocks": 64,
            "decisionOrderingProfile": "synthetic-single-chain-finalized-before-terminal-v1",
            "platformFeeBP": 0,
            "evaluatorFeeBP": 0,
            "capabilityProfile": "dacs-delivery-gate-v1",
        },
    })
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
            "primaryClaim": claims[role],
            "claims": [f"cci-xm:evm:{CHAIN_ID}:{role_accounts[role]}"],
        }
        for role in ("buyer", "seller", "evaluator")
    }
    inputs: dict[str, Any] = {
        "roleBundles": role_bundles,
        "vetRecords": {
            role: {
                "fixtureRecordVersion": "1",
                "kind": "vet-record-input",
                "subject": claims[role],
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
        },
        "evaluationRule": {
            "fixtureRecordVersion": "1",
            "kind": "evaluation-rule-input",
            "rule": "exact-output-v1",
        },
        "deliveredArtifact": {
            "fixtureRecordVersion": "1",
            "kind": "delivered-artifact-input",
            "jobId": job_id,
            "payloadUtf8": f"deliverable:{job_id}",
        } if delivered else None,
        "disputeCase": {
            "fixtureRecordVersion": "1",
            "kind": "dispute-case-input",
            "jobId": job_id,
            "caseId": CASE_A,
            "reason": "agreement-authorized-pre-submission-rejection",
        } if basis == "dispute" else None,
        "runtimeBytecode": {
            "encoding": "utf-8",
            "value": "synthetic DACS delivery gate runtime v1",
            "sha256": RUNTIME_HASH,
        },
    }
    hook("inputs", inputs)

    agreement = {
        "deliveryOrRemedyAgreementVersion": "1",
        "jobId": job_id,
        "agreementRef": ref(bilateral, f"fixture:agreement:{job_id}"),
        "agreementHash": artifact_hash(bilateral),
        "railDefinitionRef": ref(rail, "fixture:rail:pay-evm-erc8183:fixture-v1"),
        "fundPhaseIndex": 1,
        "deliveryPhaseIndex": 2,
        "terminalPhaseIndex": 3,
        **{
            role: {
                "primaryClaim": claims[role],
                "bundleHash": artifact_hash(inputs["roleBundles"][role]),
                "vetRecordRef": ref(inputs["vetRecords"][role], f"fixture:vet:{role}"),
                "evmAccountClaim": f"cci-xm:evm:{CHAIN_ID}:{role_accounts[role]}",
                **(
                    {"requirement": requirement, "requirementHash": content_hash(requirement)}
                    if role == "evaluator"
                    else {}
                ),
            }
            for role in ("buyer", "seller", "evaluator")
        },
        "budgetBaseUnits": "1000000",
        "submissionCutoffSec": 1800000000,
        "evaluationDeadlineSec": 1800007200,
        "preSubmissionRefundPolicy": "evaluator-rejection",
        "disclosurePolicy": "public-evidence-only",
        "evaluationRuleRef": {
            "kind": "storage-program",
            "locator": "fixture:evaluation-rule:exact-output-v1",
            "contentHash": artifact_hash(inputs["evaluationRule"]),
        },
    }
    sign_overlay(hook("agreement", agreement))
    agreement_hash = artifact_hash(agreement)
    accounts = {
        role: account_of(agreement[role]["evmAccountClaim"])
        for role in ("buyer", "seller", "evaluator")
    }
    budget = agreement["budgetBaseUnits"]
    token = rail["paymentToken"]

    creation_preimage = f"{job_id}:create"
    creation_event = event(creation_preimage, 0)
    job = sign_component(hook("job", {
        "escrowJobRefVersion": "1",
        "jobId": job_id,
        "deliveryOrRemedyAgreementHash": agreement_hash,
        "railDefinitionRef": copy.deepcopy(agreement["railDefinitionRef"]),
        "chainId": rail["chainId"],
        "contractAddress": rail["contractAddress"],
        "runtimeBytecodeHash": rail["runtimeBytecodeHash"],
        "nativeJobId": NATIVE_JOB_IDS.get(job_id, "9"),
        "creationEvent": copy.deepcopy(creation_event),
    }), ORCHESTRATOR, DOMAINS["job"])
    job_ref = ref(job, logical(job_id, "job"))
    funding_preimage = f"{job_id}:fund"
    funding_event = event(funding_preimage, 1)
    funding = sign_component(hook("funding", {
        "escrowFundingEvidenceVersion": "1",
        "jobId": job_id,
        "deliveryOrRemedyAgreementHash": agreement_hash,
        "escrowJobRef": copy.deepcopy(job_ref),
        "fundPhaseIndex": agreement["fundPhaseIndex"],
        "token": token,
        "amountBaseUnits": budget,
        "fundingEventRefs": [copy.deepcopy(funding_event)],
        "finality": finality(funded_at_sec),
        "observedAt": (funded_at_sec + 128) * 1000,
    }), ORCHESTRATOR, DOMAINS["funding"])
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
    if delivered:
        # A DACS-4 §9.7 delivery SettlementEvidence for the storage-program step.
        delivery = sign_component(hook("delivery", {
            "evidenceVersion": "1",
            "jobId": job_id,
            "phase": "deliver-storage-program",
            "outcome": "success",
            "deliverableContentHash": content_hash(inputs["deliveredArtifact"]),
            "deliverableAnchor": {
                "kind": "storage-program",
                "locator": f"dacs4:deliverable:{job_id}",
            },
            "observedAt": delivery_observed_at_ms,
        }), ORCHESTRATOR, DOMAINS["delivery"])
        delivery_ref = hook("deliveryRef", ref(delivery, f"fixture:evidence:{job_id}:delivery"))
        artifacts.update({"delivery": delivery, "deliveryRef": delivery_ref})

    finding_artifact = None
    basis_ref = None
    if basis == "evaluation":
        rejected = lifecycle != "release"
        classification = "seller-fault" if rejected else "seller-fulfilled"
        evaluation = sign_component(hook("evaluation", {
            "executionEvaluationVersion": "1",
            "jobId": job_id,
            "evaluationSeq": 0,
            "deliveryOrRemedyAgreementHash": agreement_hash,
            "escrowJobRef": copy.deepcopy(job_ref),
            **({"deliveryEvidenceRef": copy.deepcopy(delivery_ref)} if delivered else {}),
            "result": "reject" if rejected else "accept",
            "finding": {
                "classification": classification,
                **({"faultedParty": SELLER} if rejected else {}),
                "rationaleCode": (
                    "fixture-exact-output-mismatch" if rejected else "fixture-exact-output-match"
                ),
            },
            "subjectEvidenceRefs": [copy.deepcopy(delivery_ref)] if delivered else [],
        }), claims["evaluator"], DOMAINS["evaluation"])
        evaluation_ref = hook("evaluationRef", ref(evaluation, logical(job_id, "evaluation:0")))
        basis_ref = {"kind": "execution-evaluation", "ref": copy.deepcopy(evaluation_ref)}
        artifacts.update({"evaluation": evaluation, "evaluationRef": evaluation_ref})
        finding_artifact = evaluation
    elif basis == "dispute":
        dispute = sign_component(hook("dispute", {
            "disputeOutcomeVersion": "1",
            "jobId": job_id,
            "caseId": CASE_A,
            "revision": 0,
            "deliveryOrRemedyAgreementHash": agreement_hash,
            "caseRef": {
                "kind": "storage-program",
                "locator": f"fixture:dispute:{CASE_A}",
                "contentHash": artifact_hash(inputs["disputeCase"]),
            },
            "subjectBundleRefs": [],
            "subjectEvidenceRefs": [copy.deepcopy(funding_ref)],
            "finding": {
                "classification": "no-fault",
                "rationaleCode": "fixture-agreement-authorized-pre-submission-rejection",
            },
            "recommendedDisposition": "refund-to-client",
        }), claims["evaluator"], DOMAINS["dispute"])
        dispute_ref = hook("disputeRef", ref(
            dispute, f"dacsx:dispute:{job_id}:{dispute['caseId']}:outcome:{dispute['revision']}"
        ))
        basis_ref = {"kind": "dispute-outcome", "ref": copy.deepcopy(dispute_ref)}
        artifacts.update({"dispute": dispute, "disputeRef": dispute_ref})
        finding_artifact = dispute

    decision = None
    decision_ref = None
    if basis_ref is not None:
        decision = sign_component(hook("decision", {
            "escrowDecisionVersion": "1",
            "jobId": job_id,
            "deliveryOrRemedyAgreementHash": agreement_hash,
            "escrowJobRef": copy.deepcopy(job_ref),
            **({"deliveryEvidenceRef": copy.deepcopy(delivery_ref)} if delivered else {}),
            "basisRef": basis_ref,
            "disposition": "release-to-provider" if lifecycle == "release" else "refund-to-client",
        }), claims["evaluator"], DOMAINS["decision"])
        decision_ref = hook("decisionRef", ref(decision, logical(job_id, "decision")))
        artifacts.update({"decision": decision, "decisionRef": decision_ref})

    if lifecycle == "release":
        terminal_state, recipient, action = "released", accounts["seller"], "complete"
    elif lifecycle in {"rejected-refund", "pre-submission-rejected-refund"}:
        terminal_state, recipient, action = "rejected-refund", accounts["buyer"], "reject"
    else:
        terminal_state, recipient, action = "expired-refund", accounts["buyer"], "claimRefund"
    terminal_preimage = terminal_tx_preimage or f"{job_id}:{action}"
    terminal_event = event(terminal_preimage, 2)
    terminal_body: dict[str, Any] = {
        "escrowTerminalEvidenceVersion": "1",
        "jobId": job_id,
        "deliveryOrRemedyAgreementHash": agreement_hash,
        "escrowJobRef": copy.deepcopy(job_ref),
        "fundingEvidenceRef": copy.deepcopy(funding_ref),
        "terminalState": terminal_state,
        "disposition": "release-to-provider" if terminal_state == "released" else "refund-to-client",
        "token": token,
        "amountBaseUnits": budget,
        "recipient": recipient,
        "terminalEventRefs": [copy.deepcopy(terminal_event)],
        "finality": finality(terminal_at_sec),
        "observedAt": (terminal_at_sec + 128) * 1000,
    }
    if decision_ref is not None:
        terminal_body["decisionRef"] = copy.deepcopy(decision_ref)
    if delivery_ref is not None:
        terminal_body["deliveryEvidenceRef"] = copy.deepcopy(delivery_ref)
    terminal = sign_component(hook("terminal", terminal_body), ORCHESTRATOR, DOMAINS["terminal"])
    artifacts["terminal"] = terminal

    statuses = {
        "agreementResolution": "verified",
        "railResolution": "verified",
        "codeResolution": "verified",
        "authorityResolution": "verified",
        "fundingFinality": "verified",
        "deliveryFinality": "verified" if delivered else "not-applicable",
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
        "chainId": rail["chainId"],
        "contractAddress": job["contractAddress"],
        "runtimeBytecodeHash": job["runtimeBytecodeHash"],
        "client": accounts["buyer"],
        "provider": accounts["seller"],
        "evaluator": accounts["evaluator"],
        "token": token,
        "payoutReceiver": accounts["seller"],
        "amountBaseUnits": budget,
        "fundedAtSec": funded_at_sec,
        "deliverable": None if delivery is None else "0x" + artifact_hash(delivery),
        "reason": None if decision is None else "0x" + artifact_hash(decision),
        "submissionCutoffSec": agreement["submissionCutoffSec"],
        "expiredAt": agreement["evaluationDeadlineSec"],
        "terminalState": terminal_state,
        "terminalAction": action,
        "portableStateHistory": [
            "created",
            "funded",
            *(["submitted"] if delivered or terminal_state == "released" else []),
            "released" if terminal_state == "released" else "refunded",
        ],
    }
    observations = [
        event_input(
            creation_event, creation_preimage, job, 19999900, created_at_sec, "JobCreated",
            {
                "client": accounts["buyer"],
                "provider": accounts["seller"],
                "evaluator": accounts["evaluator"],
                "submissionCutoffSec": agreement["submissionCutoffSec"],
                "expiredAt": agreement["evaluationDeadlineSec"],
                "description": "dacs-delivery-remedy:v1:" + agreement_hash,
            },
        ),
        event_input(
            funding_event, funding_preimage, job, 20000000, funded_at_sec, "JobFunded",
            {"token": token, "amountBaseUnits": budget},
        ),
    ]
    submission_event = None
    if delivered:
        # The transaction identity commits to its deliverable argument.
        submission_preimage = submission_tx_preimage or f"{job_id}:submit:{native['deliverable']}"
        submission_event = event(submission_preimage, 0)
        observations.append(event_input(
            submission_event, submission_preimage, job, 20000050, submitted_at_sec,
            "JobSubmitted", {"deliverable": native["deliverable"]},
        ))
    observations.append(event_input(
        terminal_event, terminal_preimage, job, terminal_block, terminal_at_sec,
        {"complete": "JobCompleted", "reject": "JobRejected", "claimRefund": "JobExpired"}[action],
        {
            "token": terminal["token"],
            "amountBaseUnits": terminal["amountBaseUnits"],
            "recipient": terminal["recipient"],
            "reason": native["reason"],
        },
    ))
    finding = None if finding_artifact is None else finding_artifact["finding"]
    classification = finding.get("classification") if isinstance(finding, dict) else None
    terminal_caller = accounts["evaluator"] if decision is not None else accounts["buyer"]
    fixture = {
        "candidateProfile": "delivery-or-remedy-v1",
        "fixtureOnly": True,
        "pipeline": pipeline,
        "executionContext": {
            "acceptedRails": [copy.deepcopy(agreement["railDefinitionRef"])],
            "commitmentReceipt": {
                "status": "finalized",
                "jobId": agreement["jobId"],
                "agreementHash": agreement["agreementHash"],
            },
            "fundingFinalizedBeforeDelivery": True,
            "terminalGate": (
                "delivery-returned"
                if delivered
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
        "bundleRequiredSigners": [
            agreement["buyer"]["primaryClaim"], agreement["seller"]["primaryClaim"],
        ],
        "evaluatorVetResult": "pass",
        "profileParameters": copy.deepcopy(rail["profileParameters"]),
        "mappingSources": mapping_sources,
        "native": native,
        "resolverEvidence": {
            "terminalCall": {
                "txHash": terminal_event["txHash"],
                "outerSubmitter": terminal_caller,
                "nativeCaller": terminal_caller,
                "nativeCallerAccountType": "eoa",
            },
            "priorTerminals": [],
            "nativeState": {
                "submissionCutoffEnforced": True,
                "expiryRecoveryAtSec": agreement["evaluationDeadlineSec"],
                "preterminalProviderPayoutBaseUnits": "0",
                "platformFeeBP": rail["profileParameters"]["platformFeeBP"],
                "evaluatorFeeBP": rail["profileParameters"]["evaluatorFeeBP"],
                "evaluatorBindingMode": "direct",
                "evaluatorAdapter": None,
            },
            "deliveryDigestAnchor": None if delivery is None else {
                "deliverable": native["deliverable"],
                "blockNumber": 20000040,
                "blockTimestampSec": anchored_at_sec,
            },
            "statuses": statuses,
        },
        "deliveryBinding": (
            None
            if submission_event is None
            else {"nativeSubmissionEvent": copy.deepcopy(submission_event)}
        ),
        "reproductionInputs": {
            "publicTestSeedHex": {
                CLAIMS[role]: SEEDS[role].hex() for role in CLAIMS
            },
            **inputs,
            "nativeEventInputs": observations,
        },
        "reputationProjection": {
            "buyerFault": classification == "buyer-fault",
            "sellerFault": classification == "seller-fault",
            "releaseAloneEstablishesNonFinancialCompletion": False,
        },
        "submittedBeforeCutoff": delivered,
    }
    hook("fixture", fixture)
    refresh_canonical_records(fixture)
    resign_resolver(fixture)
    return fixture


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
    evaluated_with: list[str] | None = None,
) -> dict[str, Any]:
    value = {
        "name": name,
        "base": base,
        "expected": expected,
        "expectedRule": rule,
        "rules": sorted(set(rules or [rule])),
        "note": note,
        "patch": patch or [],
    }
    if evaluated_with is not None:
        value["evaluatedWith"] = evaluated_with
    return value


def put(*path_and_value: Any) -> Callable[[Any], None]:
    """Return a hook that sets one nested field."""
    *path, value = path_and_value

    def apply(body: Any) -> None:
        target = body
        for segment in path[:-1]:
            target = target[segment]
        target[path[-1]] = copy.deepcopy(value)

    return apply


def drop(*path: Any) -> Callable[[Any], None]:
    """Return a hook that removes one nested field."""

    def apply(body: Any) -> None:
        target = body
        for segment in path[:-1]:
            target = target[segment]
        del target[path[-1]]

    return apply


def each(*hooks_to_apply: Callable[[Any], None]) -> Callable[[Any], None]:
    """Return a hook that applies several hooks in order."""

    def apply(body: Any) -> None:
        for item in hooks_to_apply:
            item(body)

    return apply


def build_vector_pack() -> dict[str, Any]:
    substituted = {
        "kind": "storage-program",
        "locator": "fixture:substituted",
        "contentHash": "ab" * 32,
    }
    other_runtime = "substituted DACS delivery gate runtime"
    unbound_submission = event(f"{JOB_A}:submit", 0)
    other_job_ref = make_base("rejected-refund")["artifacts"]["funding"]["escrowJobRef"]
    unpublished_subject = {
        "kind": "storage-program",
        "locator": "fixture:unpublished-subject",
        "contentHash": "12" * 32,
    }
    fixtures = {
        "release": make_base("release"),
        "rejected-refund": make_base("rejected-refund"),
        "pre-submission-rejected-refund": make_base("pre-submission-rejected-refund"),
        "expired-pre": make_base("expired-pre"),
        "expired-post": make_base("expired-post"),
        # Pipeline and agreement negatives: the edit is signed and every
        # downstream binding follows it.
        "second-delivery-phase": make_base("release", hooks={
            "agreement": put("terminalPhaseIndex", 4),
            "fixture": lambda fixture: fixture["pipeline"].insert(3, {"kind": "deliver-entitlement"}),
        }),
        "delivery-phase-index-divergence": make_base("release", hooks={"agreement": put("deliveryPhaseIndex", 4)}),
        "bilateral-reference-mismatch": make_base("release", hooks={"agreement": put("agreementRef", "contentHash", "01" * 32)}),
        "bilateral-hash-mismatch": make_base("release", hooks={"agreement": put("agreementHash", "02" * 32)}),
        "evaluator-requirement-mismatch": make_base("release", hooks={
            "inputs": put("vetRecords", "evaluator", "requirementHash", "03" * 32),
            "agreement": put("evaluator", "requirementHash", "03" * 32),
        }),
        "evaluator-vet-requirement-mismatch": make_base("release", hooks={
            "inputs": put("vetRecords", "evaluator", "requirementHash", "04" * 32),
        }),
        "evaluator-vet-expired-at-funding": make_base("release", hooks={
            "inputs": put("vetRecords", "evaluator", "validUntilSec", 1799980000),
        }),
        "nonminimal-budget": make_base("release", hooks={"agreement": put("budgetBaseUnits", "01000000")}),
        "rail-reference-mismatch": make_base("release", hooks={"agreement": put("railDefinitionRef", "contentHash", "04" * 32)}),
        "unsupported-disclosure-policy": make_base("release", hooks={"agreement": put("disclosurePolicy", "encrypted-transcript")}),
        "transcript-in-delivered-artifact": make_base("release", hooks={"inputs": put("deliveredArtifact", "transcriptExcerpt", "forbidden")}),
        # A submission identity that does not commit to its argument can be
        # derived into the delivery it submits.
        "delivery-quotes-native-submission": make_base(
            "release",
            submission_tx_preimage=f"{JOB_A}:submit",
            hooks={"inputs": each(
                put("deliveredArtifact", "submissionTxHashSha256", hashlib.sha256(
                    unbound_submission["txHash"].encode("ascii")
                ).hexdigest()),
                put("deliveredArtifact", "submissionEventBase64", base64.b64encode(
                    canonical_bytes(unbound_submission)
                ).decode("ascii")),
            )},
        ),
        "drp-9-digest-anchor-unavailable": make_base("release", hooks={
            "fixture": put("resolverEvidence", "deliveryDigestAnchor", None),
        }),
        "drp-9-digest-anchor-other-digest": make_base("release", hooks={
            "fixture": put("resolverEvidence", "deliveryDigestAnchor", "deliverable", "0x" + "14" * 32),
        }),
        "drp-9-digest-fixed-after-submission": make_base("release", hooks={
            "inputs": put("deliveredArtifact", "submissionBlockNumber", 20000050),
            "fixture": each(
                put("resolverEvidence", "deliveryDigestAnchor", "blockNumber", 20000060),
                put("resolverEvidence", "deliveryDigestAnchor", "blockTimestampSec", 1799995020),
            ),
        }),
        "drp-9-digest-anchored-in-submission-block": make_base("release", hooks={
            "fixture": each(
                put("resolverEvidence", "deliveryDigestAnchor", "blockNumber", 20000050),
                put("resolverEvidence", "deliveryDigestAnchor", "blockTimestampSec", 1799995000),
            ),
        }),
        "drp-9-delivery-observed-after-submission": make_base("release", hooks={
            "delivery": put("observedAt", 1799995001000),
        }),
        "drp-9-digest-anchor-time-after-submission": make_base("release", hooks={
            "fixture": put("resolverEvidence", "deliveryDigestAnchor", "blockTimestampSec", 1800009000),
        }),
        # DRE-2, DRP-7: the delivery SettlementEvidence of the agreed phase.
        "dre-2-delivery-phase-kind": make_base("release", hooks={"delivery": put("phase", "deliver-entitlement")}),
        "drv-2-delivery-evidence-shape": make_base("release", hooks={"delivery": put("paymentTxRefs", [])}),
        # A §9.7 failure may omit the deliverable members it has no value for.
        "dre-2-failed-delivery-without-deliverable": make_base("rejected-refund", FAILED_DELIVERY_JOB, hooks={
            "inputs": put("deliveredArtifact", None),
            "delivery": each(
                put("outcome", "failure"),
                put("reason", "fixture-output-missing"),
                drop("deliverableContentHash"),
                drop("deliverableAnchor"),
            ),
        }),
        # DRA-1, DRD-8: every artifact describes the overlay's job.
        "dra-1-bilateral-job": make_base("release", hooks={"bilateral": put("jobId", JOB_B)}),
        "dra-1-bilateral-parties": make_base("release", hooks={
            "bilateral": each(put("buyer", SELLER), put("seller", BUYER)),
        }),
        "drd-8-evaluation-job-reference": make_base("release", hooks={"evaluation": put("escrowJobRef", other_job_ref)}),
        "drd-8-decision-job-reference": make_base("release", hooks={"decision": put("escrowJobRef", other_job_ref)}),
        "drv-4-job-overlay-hash": make_base("release", hooks={"job": put("deliveryOrRemedyAgreementHash", "05" * 32)}),
        "drf-1-funding-overlay-hash": make_base("release", hooks={"funding": put("deliveryOrRemedyAgreementHash", "05" * 32)}),
        # DRE-3, DRE-5: evaluation subject evidence.
        "dre-5-evaluation-subject-unresolved": make_base("release", hooks={
            "evaluation": put("subjectEvidenceRefs", [unpublished_subject]),
        }),
        "dre-3-evaluation-subject-contradiction": make_base("release", hooks={
            "evaluation": put("subjectEvidenceRefs", [{
                "kind": "storage-program",
                "locator": f"fixture:evidence:{JOB_A}:delivery",
                "contentHash": "13" * 32,
            }]),
        }),
        "drv-2-evaluation-subject-refs": make_base("release", hooks={"evaluation": put("subjectEvidenceRefs", None)}),
        "evaluator-claim-is-buyer": make_base("release", evaluator_claim=BUYER),
        "evaluator-account-is-seller": make_base("release", hooks={
            "agreement": put("evaluator", "evmAccountClaim", f"cci-xm:evm:{CHAIN_ID}:{SELLER_ACCOUNT}"),
        }),
        "evaluator-account-other-chain": make_base("release", hooks={
            "agreement": put("evaluator", "evmAccountClaim", f"cci-xm:evm:10:{EVALUATOR_ACCOUNT}"),
        }),
        "nonpositive-evaluation-window": make_base("release", hooks={"rail": put("profileParameters", "minimumEvaluationWindowSec", 0)}),
        "short-evaluation-window": make_base("release", hooks={"rail": put("profileParameters", "minimumEvaluationWindowSec", 8000)}),
        "unsupported-deadline-profile": make_base("release", hooks={"rail": put("profileParameters", "deadlineProfile", "shared-cutoff-v1")}),
        "expiry-only-policy": make_base("release", hooks={"agreement": put("preSubmissionRefundPolicy", "expiry-only")}),
        # Reference and binding negatives.
        "delivery-from-another-job": make_base("release", hooks={"delivery": put("jobId", JOB_B)}),
        "decision-from-another-job": make_base("release", hooks={"decision": put("jobId", JOB_B)}),
        "delivery-reference-mismatch": make_base("release", hooks={"deliveryRef": put("contentHash", "05" * 32)}),
        "evaluation-reference-mismatch": make_base("release", hooks={"evaluationRef": put("contentHash", "06" * 32)}),
        "decision-reference-mismatch": make_base("release", hooks={"decisionRef": put("contentHash", "07" * 32)}),
        "dispute-reference-mismatch": make_base("pre-submission-rejected-refund", hooks={"disputeRef": put("contentHash", "08" * 32)}),
        "decision-delivery-mismatch": make_base("release", hooks={"decision": put("deliveryEvidenceRef", substituted)}),
        "decision-basis-other-evaluation": make_base("release", hooks={"decision": put("basisRef", "ref", substituted)}),
        "decision-basis-other-dispute": make_base("pre-submission-rejected-refund", hooks={"decision": put("basisRef", "ref", substituted)}),
        "pre-submission-decision-with-delivery": make_base("pre-submission-rejected-refund", hooks={"decision": put("deliveryEvidenceRef", substituted)}),
        "release-without-delivery": make_base("release", delivered=False),
        "evaluation-refund-without-delivery": make_base("rejected-refund", delivered=False),
        "post-submission-dispute-refund": make_base("rejected-refund", basis="dispute"),
        "dispute-recommends-release": make_base("pre-submission-rejected-refund", hooks={"dispute": put("recommendedDisposition", "release-to-provider")}),
        "decision-without-basis-artifact": make_base("release", hooks={
            "fixture": each(drop("artifacts", "evaluation"), drop("artifacts", "evaluationRef")),
        }),
        "terminal-job-reference-mismatch": make_base("release", hooks={"terminal": put("escrowJobRef", substituted)}),
        "terminal-delivery-reference-mismatch": make_base("release", hooks={"terminal": put("deliveryEvidenceRef", substituted)}),
        "terminal-decision-mismatch": make_base("release", hooks={"terminal": put("decisionRef", substituted)}),
        "terminal-funding-mismatch": make_base("release", hooks={"terminal": put("fundingEvidenceRef", substituted)}),
        "funding-job-mismatch": make_base("release", hooks={"funding": put("escrowJobRef", substituted)}),
        "funding-token-mismatch": make_base("release", hooks={"funding": put("token", "0x" + "66" * 20)}),
        "funding-phase-index-mismatch": make_base("release", hooks={"funding": put("fundPhaseIndex", 2)}),
        # Evaluation, decision, and terminal negatives.
        "reject-then-release": make_base("release", hooks={"evaluation": put("result", "reject")}),
        "accept-then-refund": make_base("rejected-refund", hooks={"evaluation": put("result", "accept")}),
        "indeterminate-evaluation": make_base("release", hooks={"evaluation": put("result", "indeterminate")}),
        "drv-2-evaluation-result": make_base("release", hooks={"evaluation": put("result", "deferred")}),
        "drv-2-decision-disposition": make_base("release", hooks={"decision": put("disposition", "partial-release")}),
        "evaluation-sequence-text": make_base("release", hooks={"evaluation": put("evaluationSeq", "0")}),
        "evaluation-sequence-one": make_base("release", hooks={"evaluation": put("evaluationSeq", 1)}),
        "wrong-faulted-party": make_base("rejected-refund", hooks={"evaluation": put("finding", "faultedParty", BUYER)}),
        "nonfault-with-faulted-party": make_base("pre-submission-rejected-refund", hooks={"dispute": put("finding", "faultedParty", SELLER)}),
        "dispute-claims-transfer": make_base("pre-submission-rejected-refund", hooks={"dispute": put("transfer", "refund")}),
        "noncanonical-case-id": make_base("pre-submission-rejected-refund", hooks={"dispute": put("caseId", "case-356")}),
        "dispute-revision-text": make_base("pre-submission-rejected-refund", hooks={"dispute": put("revision", "0")}),
        "partial-release": make_base("release", hooks={"terminal": put("amountBaseUnits", "999999")}),
        "wrong-release-recipient": make_base("release", hooks={"terminal": put("recipient", BUYER_ACCOUNT)}),
        "wrong-refund-recipient": make_base("rejected-refund", hooks={"terminal": put("recipient", SELLER_ACCOUNT)}),
        "expiry-refund-to-seller": make_base("expired-pre", hooks={"terminal": put("recipient", SELLER_ACCOUNT)}),
        "expiry-invented-decision": make_base("expired-pre", hooks={"terminal": put("decisionRef", substituted)}),
        "expiry-invented-delivery": make_base("expired-pre", hooks={"terminal": put("deliveryEvidenceRef", substituted)}),
        "missing-decision": make_base("release", hooks={
            "fixture": each(
                drop("artifacts", "evaluation"),
                drop("artifacts", "evaluationRef"),
                drop("artifacts", "decision"),
                drop("artifacts", "decisionRef"),
                drop("mappingSources", "decisionHash"),
                put("resolverEvidence", "statuses", "decisionFinality", "unavailable"),
                put("resolverEvidence", "statuses", "decisionOrdering", "unavailable"),
            ),
        }),
        # Identity, job, and rail negatives.
        "noncanonical-job-id": make_base("release", "job-356"),
        "nonminimal-native-job-id": make_base("release", hooks={"job": put("nativeJobId", "01")}),
        "drp-5-job-rail": make_base("release", hooks={
            "job": put("railDefinitionRef", "locator", "fixture:rail:pay-evm-erc8183:unselected"),
        }),
        "drj-2-job-contract": make_base("release", hooks={"job": put("contractAddress", "0x" + "82" * 20)}),
        "drj-5-job-runtime": make_base("release", hooks={
            "job": put("runtimeBytecodeHash", hashlib.sha256(other_runtime.encode("ascii")).hexdigest()),
            "inputs": put("runtimeBytecode", {
                "encoding": "utf-8",
                "value": other_runtime,
                "sha256": hashlib.sha256(other_runtime.encode("ascii")).hexdigest(),
            }),
        }),
        # Finality-record and event-set negatives.
        "funding-finality-pending": make_base("release", hooks={
            "fixture": put("reproductionInputs", "nativeEventInputs", 1, "confirmations", 63),
        }),
        "terminal-finality-pending": make_base("release", hooks={
            "fixture": put("reproductionInputs", "nativeEventInputs", 3, "confirmations", 63),
        }),
        "funding-events-empty": make_base("release", hooks={"funding": put("fundingEventRefs", [])}),
        "terminal-events-empty": make_base("release", hooks={"terminal": put("terminalEventRefs", [])}),
        "funding-finality-unregistered-member": make_base("release", hooks={"funding": put("finality", "status", "pending")}),
        "funding-finality-depth-below-profile": make_base("release", hooks={"funding": put("finality", "finalityBlocks", 1)}),
        "funding-finality-predates-event": make_base("release", hooks={"funding": put("finality", "finalityObservedAt", 1799989999000)}),
        "terminal-finality-unregistered-member": make_base("release", hooks={"terminal": put("finality", "status", "pending")}),
        "terminal-finality-depth-below-profile": make_base("release", hooks={"terminal": put("finality", "finalityBlocks", 1)}),
        # Replay: one terminal per decision, per native job, and per event.
        # The release terminal is at block 20000100, log index 2.
        "release-second-terminal-transaction": make_base(
            "release", terminal_tx_preimage=f"{JOB_A}:complete:second", terminal_block=20000101,
        ),
        "release-earlier-terminal-transaction": make_base(
            "release", terminal_tx_preimage=f"{JOB_A}:complete:earlier", terminal_block=20000099,
        ),
        "release-same-position-terminal-transaction": make_base(
            "release", terminal_tx_preimage=f"{JOB_A}:complete:same-position",
        ),
        "release-job-rejection": make_base("rejected-refund", JOB_A, terminal_block=20000101),
        "other-job-reuses-release-terminal-event": make_base("release", JOB_B, terminal_tx_preimage=f"{JOB_A}:complete"),
    }

    def retime(fixture_name: str, event_name: str, timestamp_sec: int) -> list[dict[str, Any]]:
        """Patch one observation's block time with an exact block-hash preimage."""
        observations = fixtures[fixture_name]["reproductionInputs"]["nativeEventInputs"]
        index = next(i for i, item in enumerate(observations) if item["eventName"] == event_name)
        item = observations[index]
        preimage = f"{item['txHashPreimageUtf8']}:block:{item['blockNumber']}:{timestamp_sec}"
        path = ["reproductionInputs", "nativeEventInputs", index]
        return [
            {"op": "replace", "path": path + ["blockTimestampSec"], "value": timestamp_sec},
            {"op": "replace", "path": path + ["blockHashPreimageUtf8"], "value": preimage},
            {"op": "replace", "path": path + ["blockHash"], "value": "0x" + hashlib.sha256(preimage.encode("ascii")).hexdigest()},
        ]

    def authenticated(fixture_name: str, patch: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return resolver_patch(fixtures[fixture_name], patch)

    def observation(index: int, *path: Any, value: Any) -> list[dict[str, Any]]:
        return [{
            "op": "replace",
            "path": ["reproductionInputs", "nativeEventInputs", index, *path],
            "value": value,
        }]

    def status(name: str, state: str) -> list[dict[str, Any]]:
        return [{"op": "replace", "path": ["resolverEvidence", "statuses", name], "value": state}]

    def call(field: str, account: Any) -> list[dict[str, Any]]:
        return [{"op": "replace", "path": ["resolverEvidence", "terminalCall", field], "value": account}]

    def native_state(field: str, value: Any) -> list[dict[str, Any]]:
        return [{"op": "replace", "path": ["resolverEvidence", "nativeState", field], "value": value}]

    def prior_terminal(
        fixture_name: str,
        *,
        tx_preimage: str | None = None,
        native_job_id: str | None = None,
        decision_hash: str | None = None,
    ) -> dict[str, Any]:
        """One resolver-attested earlier terminal, defaulting to the fixture's own."""
        fixture = fixtures[fixture_name]
        job = fixture["artifacts"]["job"]
        ref_value = fixture["artifacts"]["terminal"]["terminalEventRefs"][0]
        return {
            "chainId": job["chainId"],
            "contractAddress": job["contractAddress"],
            "nativeJobId": job["nativeJobId"] if native_job_id is None else native_job_id,
            "txHash": ref_value["txHash"] if tx_preimage is None else event(tx_preimage, 2)["txHash"],
            "logIndex": ref_value["logIndex"],
            "decisionHash": decision_hash,
        }

    def history(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [{"op": "replace", "path": ["resolverEvidence", "priorTerminals"], "value": entries}]

    deadline = fixtures["expired-pre"]["artifacts"]["agreement"]["evaluationDeadlineSec"]
    cutoff = fixtures["release"]["artifacts"]["agreement"]["submissionCutoffSec"]
    release_hashes = fixtures["release"]["mappingSources"]
    release_decision_hash = release_hashes["decisionHash"]
    rehash_delivery = hashlib.sha256(release_hashes["deliveryHash"].encode("ascii")).hexdigest()
    rehash_reason = hashlib.sha256(release_decision_hash.encode("ascii")).hexdigest()
    reversed_delivery = bytes.fromhex(release_hashes["deliveryHash"])[::-1].hex()
    shifted_delivery = "00" + release_hashes["deliveryHash"][2:]
    bad_signer = component_signature(
        fixtures["release"]["artifacts"]["evaluation"], BUYER, DOMAINS["evaluation"]
    )
    bad_decision_signer = component_signature(
        fixtures["release"]["artifacts"]["decision"], BUYER, DOMAINS["decision"]
    )
    foreign_resolver_signature = {
        "algorithm": "ed25519",
        "signer": RESOLVER,
        "value": b64u(key("orchestrator").sign(
            (RESOLVER_DOMAIN + artifact_hash(fixtures["release"]["resolverEvidence"])).encode("ascii")
        )),
    }
    other_job_resolver = copy.deepcopy(fixtures["release"])
    other_job_resolver["resolverEvidence"]["jobId"] = JOB_B
    resign_resolver(other_job_resolver, bind=False)

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
        # Positive lifecycles.
        vector("release-complete-budget", "release", "verified", "DRV-7", "fund, deliver, evaluate, and release the complete budget", rules=release_verified_rules),
        vector("evaluator-rejection-refund", "rejected-refund", "verified", "DRV-7", "a signed rejection refunds the complete budget", rules=rejection_verified_rules),
        vector("pre-submission-evaluator-rejection", "pre-submission-rejected-refund", "verified", "DRV-7", "agreement-authorized pre-submission rejection uses a DisputeOutcome and omits delivery evidence", rules=pre_submission_verified_rules),
        vector("expiry-before-submission", "expired-pre", "verified", "DRV-7", "pre-submission expiry refunds without a decision or delivery reference", rules=expiry_verified_rules),
        vector("expiry-after-submission-grace", "expired-post", "verified", "DRV-7", "post-submission expiry refunds after grace without inventing a decision", rules=expiry_verified_rules + ["DRP-7", "DRP-9"]),
        vector("eip1271-relayed-execution", "release", "verified", "DRV-7", "a supported contract account remains the native caller while an outer account submits", authenticated("release", call("nativeCallerAccountType", "eip1271") + call("outerSubmitter", RELAYER_ACCOUNT)), rules=release_verified_rules + ["DREB-18"]),
        vector("dreb-15-recovery-after-deadline", "expired-pre", "verified", "DRV-7", "DREB-15: expiry recovery after the evaluation deadline remains valid", authenticated("expired-pre", retime("expired-pre", "JobExpired", deadline + 1)), rules=expiry_verified_rules),
        vector("drd-8-same-terminal-again", "release", "verified", "DRV-7", "DRD-8 and DRL-4: verifying the same terminal again, in any order, is idempotent", rules=["DRD-8", "DRL-4", "DRV-7"], evaluated_with=["release-complete-budget", "eip1271-relayed-execution"]),
        # DRP: pipeline shape.
        vector("pipeline-missing-terminal", "release", "rejected", "DRP-1", "an unpaired escrow phase is rejected", [{"op": "remove", "path": ["pipeline", 3]}]),
        vector("pipeline-actions-reversed", "release", "rejected", "DRP-2", "escrow phases must be fund then terminal", [{"op": "replace", "path": ["pipeline", 1, "parameters", "action"], "value": "terminal"}]),
        vector("pipeline-second-delivery", "second-delivery-phase", "rejected", "DRP-3", "only one delivery step may occur between the escrow phases"),
        vector("pipeline-extra-payment", "release", "rejected", "DRP-4", "ordinary payment phases cannot accompany the pair", [{"op": "add", "path": ["pipeline", 4], "value": {"kind": "pay-x402"}}]),
        vector("pipeline-unsupported-phase-kind", "release", "error", "DRV-2", "an unsupported phase kind is malformed input", [{"op": "add", "path": ["pipeline", 4], "value": {"kind": "notify"}}]),
        vector("pipeline-rail-divergence", "release", "rejected", "DRP-5", "both escrow invocations must name the agreement-selected rail", [{"op": "replace", "path": ["pipeline", 3, "parameters", "rail"], "value": "pay-evm-erc8183:other"}]),
        vector("drp-5-escrow-phase-rails", "release", "rejected", "DRP-5", "both escrow phases must name the agreement-selected rail", [{"op": "replace", "path": ["pipeline", 1, "parameters", "rail"], "value": "pay-evm-erc8183:other"}, {"op": "replace", "path": ["pipeline", 3, "parameters", "rail"], "value": "pay-evm-erc8183:other"}]),
        vector("pipeline-delivery-before-final-funding", "release", "rejected", "DRP-6", "delivery cannot begin before the funding result is finalized", [{"op": "replace", "path": ["executionContext", "fundingFinalizedBeforeDelivery"], "value": False}]),
        vector("pipeline-double-counted-purchase", "release", "rejected", "DRP-8", "the paired escrow lifecycle counts as one purchase", [{"op": "replace", "path": ["executionContext", "dacs5PurchaseCount"], "value": 2}]),
        vector("pipeline-escrow-rail-not-accepted", "release", "rejected", "DRP-10", "job escrow participates in the acceptedRails selection gate", [{"op": "replace", "path": ["executionContext", "acceptedRails"], "value": []}]),
        vector("pipeline-funding-before-final-commitment", "release", "rejected", "DRP-11", "the finalized DACS-3 commitment gates value locking", [{"op": "replace", "path": ["executionContext", "commitmentReceipt", "status"], "value": "included"}]),
        vector("pipeline-terminal-before-delivery-return", "release", "rejected", "DRP-12", "terminal execution waits for the delivery return on the ordinary path", [{"op": "replace", "path": ["executionContext", "terminalGate"], "value": "submission-cutoff"}]),
        vector("pipeline-late-delivery-not-disabled", "expired-pre", "rejected", "DRP-12", "a cutoff refund permanently disables late delivery submission", [{"op": "replace", "path": ["executionContext", "lateDeliveryDisabled"], "value": False}]),
        vector("pipeline-phase-index-divergence", "delivery-phase-index-divergence", "rejected", "DRA-11", "signed indexes must match the phase pair"),
        # DRA, DRQ: the signed overlay.
        vector("bilateral-agreement-reference-mismatch", "bilateral-reference-mismatch", "rejected", "DRA-1", "the overlay must resolve the exact bilateral agreement"),
        vector("bilateral-agreement-hash-mismatch", "bilateral-hash-mismatch", "rejected", "DRA-2", "the overlay must carry the recomputed bilateral agreement hash"),
        vector("overlay-signature-missing", "release", "rejected", "DRA-3", "all three overlay signatures are required", [{"op": "remove", "path": ["artifacts", "agreement", "signatures", 2]}]),
        vector("overlay-signature-invalid", "release", "rejected", "DRA-3", "each overlay signature must verify under its role's key", [{"op": "replace", "path": ["artifacts", "agreement", "signatures", 2, "value"], "value": fixtures["release"]["artifacts"]["agreement"]["signatures"][0]["value"]}]),
        vector("evaluator-requirement-hash-mismatch", "evaluator-requirement-mismatch", "rejected", "DRA-8", "the evaluator requirement hash is independently recomputed"),
        vector("evaluator-vet-requirement-mismatch", "evaluator-vet-requirement-mismatch", "rejected", "DRA-8", "the evaluator Vet record must use the bound requirement"),
        vector("evaluator-vet-not-fresh-at-funding", "evaluator-vet-expired-at-funding", "rejected", "DRA-9", "the evaluator Vet pass must be fresh at the authenticated funding time"),
        vector("nonminimal-budget-base-units", "nonminimal-budget", "error", "DRA-10", "the signed budget uses minimal unsigned decimal text"),
        vector("rail-definition-reference-mismatch", "rail-reference-mismatch", "rejected", "DRA-12", "the selected rail definition must resolve exactly"),
        vector("evaluator-added-as-bundle-party", "release", "rejected", "DRA-13", "the evaluator overlay signature does not create a third bundle party", [{"op": "add", "path": ["bundleRequiredSigners", 2], "value": EVALUATOR}]),
        vector("unsupported-disclosure-policy", "unsupported-disclosure-policy", "rejected", "DRQ-1", "the first profile accepts only its two signed disclosure policies"),
        vector("transcript-input-disclosed", "transcript-in-delivered-artifact", "rejected", "DRQ-3", "the candidate input pack cannot carry negotiation transcript material"),
        vector("evaluator-primary-claim-collision", "evaluator-claim-is-buyer", "rejected", "DRA-6", "evaluator and buyer primary claims must differ"),
        vector("evaluator-account-collision", "evaluator-account-is-seller", "rejected", "DRA-7", "evaluator and provider accounts must differ"),
        vector("evaluator-wrong-chain", "evaluator-account-other-chain", "rejected", "DRA-5", "role accounts are bound to the selected chain"),
        vector("evaluator-vet-failure", "release", "rejected", "DRA-9", "evaluator must have a fresh pass", [{"op": "replace", "path": ["evaluatorVetResult"], "value": "fail"}]),
        vector("unsupported-expiry-only-policy", "expiry-only-policy", "rejected", "DRA-15", "the MVP cannot promise expiry-only while canonical ERC permits funded rejection"),
        # DRP-9: delivery and native submission.
        vector("delivery-submission-circularity", "delivery-quotes-native-submission", "rejected", "DRP-9", "the native submission transaction identity must commit to the delivery digest it submits"),
        vector("drp-9-digest-anchor-unavailable", "drp-9-digest-anchor-unavailable", "indeterminate", "DRP-9", "without authenticated evidence that the digest was fixed before submission, ordering stays indeterminate"),
        vector("drp-9-digest-anchor-other-digest", "drp-9-digest-anchor-other-digest", "rejected", "DRP-9", "the authenticated anchor must fix this delivery evidence's digest"),
        vector("drp-9-digest-fixed-after-submission", "drp-9-digest-fixed-after-submission", "rejected", "DRP-9", "a delivery digest fixed only after the native submission may derive from it"),
        vector("drp-9-digest-anchored-in-submission-block", "drp-9-digest-anchored-in-submission-block", "indeterminate", "DRP-9", "an anchor in the submission's own block cannot be ordered before it"),
        vector("drp-9-digest-anchor-time-after-submission", "drp-9-digest-anchor-time-after-submission", "rejected", "DRP-9", "an anchor block must be earlier than the submission in time as well as in height"),
        vector("drp-9-delivery-observed-after-submission", "drp-9-delivery-observed-after-submission", "rejected","DRP-9", "hashed delivery evidence cannot record a time after its digest was fixed"),
        vector("native-submission-at-cutoff", "release", "rejected", "DRP-9", "a native submission at the cutoff is late", authenticated("release", retime("release", "JobSubmitted", cutoff)) + [{"op": "replace", "path": ["submittedBeforeCutoff"], "value": False}]),
        vector("submission-event-deliverable-mismatch", "release", "rejected", "DRP-9", "the native submission event must carry the delivery digest", authenticated("release", observation(2, "arguments", "deliverable", value="0x" + rehash_delivery))),
        vector("deliveryless-lifecycle-carries-submission-binding", "expired-pre", "rejected", "DRP-9", "a lifecycle without delivery has no native submission to bind", [{"op": "replace", "path": ["deliveryBinding"], "value": {}}]),
        vector("delivery-binding-carries-conclusions", "release", "error", "DRV-2", "the delivery binding names the submission event and nothing else", [{"op": "add", "path": ["deliveryBinding", "status"], "value": "verified"}]),
        # DREB: exact ERC field mapping.
        vector("description-prefix-substitution", "release", "rejected", "DREB-1", "the exact ASCII description prefix is bound", authenticated("release", observation(0, "arguments", "description", value="dacs-delivery:v1:" + release_hashes["agreementHash"]))),
        vector("description-sha256-prefix", "release", "rejected", "DREB-1", "a sha256: textual prefix is not inserted", authenticated("release", observation(0, "arguments", "description", value="dacs-delivery-remedy:v1:sha256:" + release_hashes["agreementHash"]))),
        vector("uppercase-delivery-hash", "release", "rejected", "DREB-3", "declared content hashes are lowercase", [{"op": "replace", "path": ["mappingSources", "deliveryHash"], "value": release_hashes["deliveryHash"].upper()}]),
        vector("prefixed-delivery-hash", "release", "rejected", "DREB-3", "declared content hashes have no algorithm prefix", [{"op": "replace", "path": ["mappingSources", "deliveryHash"], "value": "sha256:" + release_hashes["deliveryHash"]}]),
        vector("delivery-hash-text-rehash", "release", "rejected", "DREB-4", "deliverable is raw decoded hash bytes, not a text rehash", [{"op": "replace", "path": ["native", "deliverable"], "value": "0x" + rehash_delivery}]),
        vector("delivery-byte-order-reversal", "release", "rejected", "DREB-4", "deliverable byte order is not reinterpreted", [{"op": "replace", "path": ["native", "deliverable"], "value": "0x" + reversed_delivery}]),
        vector("delivery-padding-truncation", "release", "rejected", "DREB-4", "a shifted/padded digest is a binding mismatch", [{"op": "replace", "path": ["native", "deliverable"], "value": "0x" + shifted_delivery}]),
        vector("zero-deliverable", "release", "rejected", "DREB-5", "zero cannot stand in for delivery evidence", [{"op": "replace", "path": ["native", "deliverable"], "value": "0x" + "00" * 32}]),
        vector("decision-hash-text-rehash", "release", "rejected", "DREB-4", "reason is raw decoded decision hash bytes", [{"op": "replace", "path": ["native", "reason"], "value": "0x" + rehash_reason}]),
        vector("zero-decision-reason", "release", "rejected", "DREB-5", "zero cannot stand in for an evaluator decision", [{"op": "replace", "path": ["native", "reason"], "value": "0x" + "00" * 32}]),
        vector("malformed-native-reason", "release", "error", "DRV-2", "malformed native reason bytes are not repaired", [{"op": "replace", "path": ["native", "reason"], "value": "0x12"}]),
        vector("decision-hash-substitution", "release", "rejected", "DREB-2", "declared decision hash must be independently recomputed", [{"op": "replace", "path": ["mappingSources", "decisionHash"], "value": "99" * 32}]),
        vector("canonical-record-stale", "release", "rejected", "DREB-2", "pinned canonical bytes and mapped values are recomputed", [{"op": "replace", "path": ["canonicalRecords", "delivery", "mappedNativeValue"], "value": "0x" + "99" * 32}]),
        vector("native-client-mismatch", "release", "rejected", "DREB-7", "native client must equal the buyer-controlled account", [{"op": "replace", "path": ["native", "client"], "value": "0x" + "66" * 20}]),
        vector("native-provider-mismatch", "release", "rejected", "DREB-8", "native provider must equal the seller-controlled account", [{"op": "replace", "path": ["native", "provider"], "value": "0x" + "66" * 20}]),
        vector("native-evaluator-mismatch", "release", "rejected", "DREB-9", "native evaluator must equal the controlled evaluator account", [{"op": "replace", "path": ["native", "evaluator"], "value": "0x" + "66" * 20}]),
        vector("native-payout-receiver-mismatch", "release", "rejected", "DREB-10", "native payout receiver must equal the seller-controlled account", [{"op": "replace", "path": ["native", "payoutReceiver"], "value": BUYER_ACCOUNT}]),
        vector("native-token-mismatch", "release", "rejected", "DREB-11", "native token must equal the pinned rail asset", [{"op": "replace", "path": ["native", "token"], "value": "0x" + "66" * 20}]),
        vector("nonpositive-evaluation-window", "nonpositive-evaluation-window", "rejected", "DREB-14", "registered rail windows must be positive"),
        vector("evaluation-window-too-short", "short-evaluation-window", "rejected", "DREB-14", "the bound evaluation window must meet the rail's pinned minimum"),
        vector("detached-profile-projection-weakened", "release", "rejected", "DRP-5", "a detached profile projection cannot weaken the authenticated rail policy", [{"op": "replace", "path": ["profileParameters", "minimumEvaluationWindowSec"], "value": 1}]),
        vector("native-expiry-divergence", "release", "rejected", "DREB-12", "native expiredAt must equal the evaluation deadline", [{"op": "replace", "path": ["native", "expiredAt"], "value": 1800007201}]),
        vector("unsupported-native-deadline-profile", "unsupported-deadline-profile", "rejected", "DREB-13", "the rail must pin the separate-submission-cutoff deadline profile"),
        vector("native-submission-cutoff-divergence", "release", "rejected", "DREB-13", "the native submission cutoff must equal the signed cutoff", [{"op": "replace", "path": ["native", "submissionCutoffSec"], "value": 1800000001}]),
        vector("native-submission-cutoff-unenforced", "release", "rejected", "DREB-13", "the resolved native state must enforce the submission cutoff", authenticated("release", native_state("submissionCutoffEnforced", False))),
        vector("native-expiry-recovery-too-early", "release", "rejected", "DREB-15", "the resolved expiry recovery time must be the evaluation deadline", authenticated("release", native_state("expiryRecoveryAtSec", cutoff))),
        vector("dreb-15-pre-submission-recovery-time", "expired-pre", "rejected", "DREB-15", "DREB-15: expiry recovery is not callable before the evaluation deadline", authenticated("expired-pre", retime("expired-pre", "JobExpired", deadline - 1))),
        vector("dreb-15-post-submission-recovery-time", "expired-post", "rejected", "DREB-15", "DREB-15: a submitted job's expiry recovery is not callable before the evaluation deadline", authenticated("expired-post", retime("expired-post", "JobExpired", deadline - 1))),
        # DREB-16..22: direct evaluator transaction model.
        vector("evaluator-binding-not-direct", "release", "rejected", "DREB-16", "the resolved native evaluator must be bound directly", authenticated("release", native_state("evaluatorBindingMode", "adapter"))),
        vector("unsupported-evaluator-account-type", "release", "error", "DREB-18", "only EOA and supported EIP-1271 evaluator accounts are in the profile", authenticated("release", call("nativeCallerAccountType", "module"))),
        vector("evaluator-adapter-substitution", "release", "rejected", "DREB-20", "a resolved generic adapter is outside the first profile", authenticated("release", native_state("evaluatorAdapter", RELAYER_ACCOUNT))),
        vector("relayer-substituted-as-native-caller", "release", "rejected", "DREB-21", "a relayer cannot replace the agreement-bound evaluator as native caller", authenticated("release", call("nativeCaller", RELAYER_ACCOUNT) + call("outerSubmitter", RELAYER_ACCOUNT))),
        vector("dreb-21-call-record-transaction", "release", "rejected", "DREB-21", "the authenticated call record must describe the terminal transaction", authenticated("release", call("txHash", "0x" + "ee" * 32))),
        vector("eoa-relayed-outer-submitter", "release", "rejected", "DREB-22", "an EOA evaluator must itself submit the native transaction", authenticated("release", call("outerSubmitter", RELAYER_ACCOUNT))),
        vector("malformed-outer-submitter", "release", "error", "DREB-22", "the outer submitter is an EVM address", authenticated("release", call("nativeCallerAccountType", "eip1271") + call("outerSubmitter", "relayer"))),
        # DRD-8, DRL-4, DRT-4: replay of decisions and terminals.
        vector("cross-job-delivery-replay", "delivery-from-another-job", "rejected", "DRD-8", "delivery from another job cannot be replayed"),
        vector("cross-job-decision-replay", "decision-from-another-job", "rejected", "DRD-8", "decision from another job cannot be replayed"),
        vector("consumed-decision-replay", "release", "rejected", "DRD-8", "DRD-8: a decision the resolver saw consumed by another transaction is one-use", authenticated("release", history([prior_terminal("release", tx_preimage=f"{JOB_A}:complete:earlier", decision_hash=release_decision_hash)]))),
        vector("resolver-history-shows-terminal-job", "rejected-refund", "rejected", "DRL-4", "DRL-4: a native job the resolver saw reach a terminal state cannot settle again", authenticated("rejected-refund", history([prior_terminal("rejected-refund", tx_preimage="earlier-terminal", decision_hash=release_decision_hash)]))),
        vector("resolver-history-shows-event-settled-another-job", "release", "rejected", "DRT-4", "DRT-4: a terminal event the resolver saw settle another native job is not this job's", authenticated("release", history([prior_terminal("release", native_job_id="2")]))),
        # Terminals evaluated together: the earlier by authenticated event
        # position holds, in any order of evaluation.
        vector("decision-reused-by-another-terminal-transaction", "release-second-terminal-transaction", "rejected", "DRD-8", "DRD-8: a decision that authorized an earlier terminal transaction cannot authorize another", evaluated_with=["release-complete-budget"]),
        vector("second-terminal-for-terminal-job", "release-job-rejection", "rejected", "DRL-4", "DRL-4: a native job that reached a terminal state earlier cannot settle again", evaluated_with=["release-complete-budget"]),
        vector("terminal-event-settles-another-job", "other-job-reuses-release-terminal-event", "rejected", "DRT-4", "DRT-4: one terminal event cannot settle two native jobs", evaluated_with=["release-complete-budget"]),
        vector("drd-8-terminals-share-event-position", "release-same-position-terminal-transaction", "indeterminate", "DRD-8", "DRD-8: conflicting terminals at one authenticated event position cannot be ordered", evaluated_with=["release-complete-budget"]),
        vector("drd-8-earlier-terminal-prevails", "release-earlier-terminal-transaction", "verified", "DRV-7", "DRD-8 and DRL-4: of two conflicting terminals, the earlier by authenticated event position holds when the later one's attested history names it", rules=["DRD-8", "DRL-4", "DRV-7"], evaluated_with=["consumed-decision-replay"]),
        vector("drd-8-later-terminal-history-incomplete", "release-earlier-terminal-transaction", "indeterminate", "DRD-8", "DRD-8: an earlier terminal that a later conflicting terminal's attested history omits cannot be confirmed", evaluated_with=["release-complete-budget"]),
        # DRE, DRD: evaluation and decision.
        vector("wrong-evaluator-signer", "release", "rejected", "DRE-1", "commercial parties cannot sign evaluator artifacts", [{"op": "replace", "path": ["artifacts", "evaluation", "signature"], "value": bad_signer}]),
        vector("wrong-decision-signer", "release", "rejected", "DRD-1", "only the agreement-bound evaluator may sign the escrow decision", [{"op": "replace", "path": ["artifacts", "decision", "signature"], "value": bad_decision_signer}]),
        vector("delivery-reference-mismatch", "delivery-reference-mismatch", "rejected", "DRE-2", "the delivery reference must resolve the signed delivery evidence"),
        vector("dre-2-delivery-phase-kind", "dre-2-delivery-phase-kind", "rejected", "DRE-2", "delivery evidence must name the agreed delivery step", rules=["DRE-2", "DRP-7"]),
        vector("drv-2-delivery-evidence-shape", "drv-2-delivery-evidence-shape", "error", "DRV-2", "delivery evidence keeps the exact delivery SettlementEvidence shape", rules=["DRE-2", "DRV-2"]),
        vector("dre-2-failed-delivery-without-deliverable", "dre-2-failed-delivery-without-deliverable", "verified", "DRV-7", "a failed delivery's SettlementEvidence may omit the deliverable content hash and anchor", rules=["DRE-2", "DRP-7", "DRV-7"]),
        vector("dre-2-failed-delivery-carries-artifact-input", "dre-2-failed-delivery-without-deliverable", "rejected", "DRE-2", "delivery evidence that names no deliverable resolves no delivered-artifact input", [{"op": "replace", "path": ["reproductionInputs", "deliveredArtifact"], "value": {"kind": "delivered-artifact-input"}}]),
        vector("drd-8-evaluation-job-reference", "drd-8-evaluation-job-reference", "rejected", "DRD-8", "the evaluation must reference this escrow job"),
        vector("drd-8-decision-job-reference", "drd-8-decision-job-reference", "rejected", "DRD-8", "the decision must reference this escrow job"),
        vector("dre-5-evaluation-subject-unresolved", "dre-5-evaluation-subject-unresolved", "indeterminate", "DRE-5", "subject evidence that does not resolve to authenticated evidence stays indeterminate", rules=["DRE-3", "DRE-5"]),
        vector("dre-3-evaluation-subject-contradiction", "dre-3-evaluation-subject-contradiction", "rejected", "DRE-3", "a subject reference must hash-bind the authenticated record it names"),
        vector("drv-2-evaluation-subject-refs", "drv-2-evaluation-subject-refs", "error", "DRV-2", "evaluation subject references are an array of exact references", rules=["DRE-3", "DRV-2"]),
        vector("evaluation-reference-mismatch", "evaluation-reference-mismatch", "rejected", "DRE-7", "the evaluation reference must resolve exactly"),
        vector("decision-delivery-reference-mismatch", "decision-delivery-mismatch", "rejected", "DRD-3", "the decision must bind the exact delivery evidence"),
        vector("release-decision-without-delivery", "release-without-delivery", "rejected", "DRD-3", "DRD-3: a release decision needs the delivery evidence it releases against"),
        vector("decision-basis-not-the-evaluation", "decision-basis-other-evaluation", "rejected", "DRD-2", "the decision basis must resolve to the signed evaluation"),
        vector("decision-basis-not-the-dispute-outcome", "decision-basis-other-dispute", "rejected", "DRD-2", "the decision basis must resolve to the signed DisputeOutcome"),
        vector("decision-reference-mismatch", "decision-reference-mismatch", "rejected", "DRD-4", "the decision reference must resolve exactly"),
        vector("pre-submission-decision-carries-delivery", "pre-submission-decision-with-delivery", "rejected", "DRD-9", "pre-submission decisions must omit delivery evidence"),
        vector("refund-without-delivery-needs-dispute-basis", "evaluation-refund-without-delivery", "rejected", "DRD-9", "DRD-9: a refund decided before delivery uses a DisputeOutcome basis"),
        vector("dispute-decision-after-submission", "post-submission-dispute-refund", "rejected", "DRD-12", "a DisputeOutcome-based decision is a pre-submission path only"),
        vector("dispute-outcome-recommends-other-disposition", "dispute-recommends-release", "rejected", "DRD-12", "the DisputeOutcome must recommend the refund the decision makes"),
        vector("decision-without-authenticated-basis", "decision-without-basis-artifact", "rejected", "DRE-4", "a decision needs an authenticated evaluation or DisputeOutcome basis"),
        vector("indeterminate-evaluation-authorizes-terminal", "indeterminate-evaluation", "rejected", "DRE-4", "an indeterminate evaluation cannot authorize settlement"),
        vector("reject-evaluation-release-action", "reject-then-release", "rejected", "DRD-2", "rejection cannot authorize release"),
        vector("accept-evaluation-refund-action", "accept-then-refund", "rejected", "DRD-2", "acceptance cannot authorize refund"),
        vector("drv-2-evaluation-result", "drv-2-evaluation-result", "error", "DRV-2", "a signed evaluation result outside the closed set cannot authorize settlement"),
        vector("drv-2-decision-disposition", "drv-2-decision-disposition", "error", "DRV-2", "a signed decision disposition outside the closed set cannot map to a native action"),
        vector("release-decision-native-reject", "release", "rejected", "DRD-5", "a release decision maps only to native complete", [{"op": "replace", "path": ["native", "terminalAction"], "value": "reject"}]),
        vector("refund-decision-native-complete", "rejected-refund", "rejected", "DRD-6", "a refund decision maps only to native reject", [{"op": "replace", "path": ["native", "terminalAction"], "value": "complete"}]),
        # DRT: terminal evidence.
        vector("partial-terminal-release", "partial-release", "rejected", "DRT-5", "terminal release must cover the complete budget"),
        vector("terminal-decision-reference-mismatch", "terminal-decision-mismatch", "rejected", "DRT-1", "terminal release must reference the exact decision"),
        vector("terminal-funding-reference-mismatch", "terminal-funding-mismatch", "rejected", "DRT-11", "terminal evidence must reference the exact finalized funding record"),
        vector("terminal-job-reference-mismatch", "terminal-job-reference-mismatch", "rejected", "DRT-4", "terminal evidence must reference the exact escrow job"),
        vector("terminal-delivery-reference-mismatch", "terminal-delivery-reference-mismatch", "rejected", "DRT-12", "post-submission terminal evidence must reference the exact delivery"),
        vector("native-terminal-state-divergence", "release", "rejected", "DRT-4", "the native terminal state must equal the signed terminal state", [{"op": "replace", "path": ["native", "terminalState"], "value": "rejected-refund"}]),
        vector("funding-job-reference-mismatch", "funding-job-mismatch", "rejected", "DRF-1", "funding evidence must reference the exact escrow job"),
        vector("funding-phase-index-mismatch", "funding-phase-index-mismatch", "rejected", "DRF-1", "funding evidence must bind the agreement's fund phase index"),
        vector("funding-token-mismatch", "funding-token-mismatch", "rejected", "DRF-2", "funding evidence must bind the pinned token"),
        vector("wrong-release-recipient", "wrong-release-recipient", "rejected", "DRT-5", "release goes only to the bound seller payout account"),
        vector("wrong-refund-recipient", "wrong-refund-recipient", "rejected", "DRT-6", "refund goes only to the client"),
        vector("expiry-refund-wrong-recipient", "expiry-refund-to-seller", "rejected", "DRT-6", "an expiry refund goes only to the client"),
        vector("release-overclaims-nonfinancial-completion", "release", "rejected", "DRL-6", "financial release alone cannot establish completion of every non-financial obligation", [{"op": "replace", "path": ["reputationProjection", "releaseAloneEstablishesNonFinancialCompletion"], "value": True}]),
        vector("release-invents-seller-fault", "release", "rejected", "DRT-14", "a caller projection cannot contradict an authenticated seller-fulfilled finding", [{"op": "replace", "path": ["reputationProjection", "sellerFault"], "value": True}]),
        vector("rejected-refund-erases-seller-fault", "rejected-refund", "rejected", "DRT-14", "a caller projection cannot erase the authenticated seller-fault finding", [{"op": "replace", "path": ["reputationProjection", "sellerFault"], "value": False}]),
        vector("nonzero-preterminal-payout", "release", "rejected", "DRL-7", "the resolved native state shows no preterminal provider payout", authenticated("release", native_state("preterminalProviderPayoutBaseUnits", "1"))),
        vector("nonzero-platform-fee", "release", "rejected", "DRT-7", "the resolved native fees must be the rail's zero fees", authenticated("release", native_state("platformFeeBP", 1))),
        # Finality and event observations.
        vector("creation-finality-pending", "release", "indeterminate", "DRJ-2", "an under-confirmed creation event cannot establish the native job", authenticated("release", observation(0, "confirmations", value=63))),
        vector("funding-finality-pending", "funding-finality-pending", "indeterminate", "DRF-6", "under-confirmed funding-event evidence cannot unlock delivery"),
        vector("submission-finality-pending", "release", "indeterminate", "DRP-9", "an under-confirmed submission event cannot bind the delivery to the native job", authenticated("release", observation(2, "confirmations", value=63))),
        vector("funding-events-empty", "funding-events-empty", "rejected", "DRF-3", "funding requires exactly one authenticated funding event"),
        vector("terminal-finality-pending", "terminal-finality-pending", "indeterminate", "DRT-8", "under-confirmed terminal-event evidence cannot establish disposition"),
        vector("terminal-events-empty", "terminal-events-empty", "rejected", "DRT-4", "terminal disposition requires exactly one terminal event"),
        vector("funding-finality-unregistered-member", "funding-finality-unregistered-member", "error", "DRV-2", "a signed funding finality record keeps the exact DACS-4 shape"),
        vector("funding-finality-depth-below-rail-profile", "funding-finality-depth-below-profile", "rejected", "DRF-6", "a signed funding finality record must use the rail finality depth"),
        vector("funding-finality-predates-event-block", "funding-finality-predates-event", "rejected", "DRF-6", "funding finality cannot be observed before its event block"),
        vector("terminal-finality-unregistered-member", "terminal-finality-unregistered-member", "error", "DRV-2", "a signed terminal finality record keeps the exact DACS-4 shape"),
        vector("terminal-finality-depth-below-rail-profile", "terminal-finality-depth-below-profile", "rejected", "DRT-8", "a signed terminal finality record must use the rail finality depth"),
        vector("portable-state-missing-funded", "release", "rejected", "DRL-4", "the portable lifecycle cannot skip the funded state", [{"op": "remove", "path": ["native", "portableStateHistory", 1]}]),
        vector("portable-state-unknown", "release", "rejected", "DRL-2", "additional native states require a deterministic portable mapping", [{"op": "replace", "path": ["native", "portableStateHistory", 1], "value": "claim-pending"}]),
        vector("portable-state-reopened", "release", "rejected", "DRL-4", "a terminal portable state cannot reopen", [{"op": "add", "path": ["native", "portableStateHistory", 4], "value": "funded"}]),
        vector("portable-state-terminal-mismatch", "release", "rejected", "DRL-1", "the portable history must end in the evidenced terminal state", [{"op": "replace", "path": ["native", "portableStateHistory", 3], "value": "refunded"}]),
        vector("portable-state-evidence-unavailable", "release", "indeterminate", "DRL-3", "unavailable native state cannot be guessed", authenticated("release", status("nativeStateResolution", "unavailable"))),
        vector("expiry-invented-decision", "expiry-invented-decision", "rejected", "DRD-7", "expiry cannot manufacture an evaluator decision"),
        vector("expiry-terminal-action-not-recovery", "expired-pre", "rejected", "DRT-3", "a decisionless terminal must be the native expiry recovery", [{"op": "replace", "path": ["native", "terminalAction"], "value": "reject"}]),
        vector("pre-submission-expiry-delivery-ref", "expiry-invented-delivery", "rejected", "DRT-12", "pre-submission expiry omits delivery evidence"),
        vector("deliveryless-lifecycle-carries-deliverable", "expired-pre", "rejected", "DRT-12", "a lifecycle without delivery carries no native deliverable", [{"op": "replace", "path": ["native", "deliverable"], "value": "0x" + "11" * 32}]),
        vector("expiry-invented-seller-fault", "expired-pre", "rejected", "DRT-13", "decisionless expiry cannot invent buyer or seller fault", [{"op": "replace", "path": ["reputationProjection", "sellerFault"], "value": True}]),
        # DRX: DisputeOutcome.
        vector("dispute-outcome-direct-transfer", "dispute-claims-transfer", "rejected", "DRX-1", "a DisputeOutcome cannot directly claim an on-chain transfer"),
        vector("dispute-outcome-reference-mismatch", "dispute-reference-mismatch", "rejected", "DRX-2", "the DisputeOutcome reference must resolve exactly"),
        vector("dispute-case-input-mismatch", "pre-submission-rejected-refund", "rejected", "DRX-2", "the dispute-case input must resolve from the signed case reference", [{"op": "replace", "path": ["reproductionInputs", "disputeCase", "reason"], "value": "substituted"}]),
        vector("non-dispute-lifecycle-carries-case-input", "release", "rejected", "DRX-2", "a lifecycle without a DisputeOutcome carries no dispute-case input", [{"op": "replace", "path": ["reproductionInputs", "disputeCase"], "value": {"kind": "dispute-case-input"}}]),
        vector("wrong-faulted-party", "wrong-faulted-party", "rejected", "DRX-5", "faultedParty must equal the party named by the classification"),
        vector("nonfault-finding-names-party", "nonfault-with-faulted-party", "rejected", "DRX-6", "a no-fault finding cannot name a faulted party"),
        # Resolver outcomes.
        vector("rail-resolution-unavailable", "release", "indeterminate", "DRC-11", "unavailable rail authority does not become a guessed failure", authenticated("release", status("railResolution", "unavailable"))),
        vector("runtime-code-unavailable", "release", "indeterminate", "DRJ-7", "unresolved code remains indeterminate", authenticated("release", status("codeResolution", "unavailable"))),
        vector("delivery-evidence-unavailable", "release", "indeterminate", "DRE-5", "unavailable delivery evidence remains indeterminate", authenticated("release", status("deliveryFinality", "unavailable"))),
        vector("decision-finality-unavailable", "release", "indeterminate", "DRD-4", "unavailable decision finality cannot authorize the terminal action", authenticated("release", status("decisionFinality", "unavailable"))),
        vector("terminal-finality-unavailable", "release", "indeterminate", "DRT-9", "missing terminal finality evidence remains indeterminate", authenticated("release", status("terminalFinality", "unavailable"))),
        vector("cross-substrate-order-unavailable", "release", "indeterminate", "DRD-10", "unorderable decision and terminal evidence remains indeterminate", authenticated("release", status("decisionOrdering", "unavailable"))),
        vector("self-reported-time-cannot-order", "release", "indeterminate", "DRD-10", "a self-reported decidedAt value cannot replace authenticated ordering", authenticated("release", [{"op": "add", "path": ["native", "reportedDecidedAt"], "value": 1799999999}, *status("decisionOrdering", "unavailable")])),
        vector("decision-finalized-after-terminal", "release", "rejected", "DRV-6", "authenticated after-terminal decision finality is contradictory", authenticated("release", status("decisionOrdering", "contradictory"))),
        vector("decision-artifact-unavailable", "missing-decision", "indeterminate", "DRD-10", "missing decision evidence without contradiction remains indeterminate"),
        vector("authenticated-native-contradiction", "release", "rejected", "DRV-6", "authenticated contradictory chain evidence rejects", authenticated("release", status("codeResolution", "contradictory"))),
        vector("resolver-status-applicability-mismatch", "release", "error", "DRV-2", "a resolver cannot mark applicable delivery finality as not applicable", authenticated("release", status("deliveryFinality", "not-applicable"))),
        # DRV-1, DRV-6: the pinned resolver record.
        vector("drv-1-signed-status", "release", "rejected", "DRV-1", "DRV-1: a resolver status is evidence only as signed", authenticated("release", status("codeResolution", "unavailable")) + status("codeResolution", "verified")),
        vector("drv-1-signed-observation", "release", "rejected", "DRV-1", "DRV-1: an event observation is evidence only as signed", observation(0, "confirmations", value=65)),
        vector("drv-1-signed-call-record", "release", "rejected", "DRV-1", "DRV-1: the terminal call record is evidence only as signed", call("nativeCallerAccountType", "eip1271")),
        vector("drv-1-signed-history", "release", "rejected", "DRV-1", "DRV-1: prior terminal history is evidence only as signed", history([prior_terminal("release", tx_preimage="unrelated-terminal", native_job_id="2")])),
        vector("drv-1-signed-native-state", "release", "rejected", "DRV-1", "DRV-1: resolved native state is evidence only as signed", authenticated("release", native_state("evaluatorBindingMode", "adapter")) + native_state("evaluatorBindingMode", "direct")),
        vector("drv-1-resolver-key", "release", "rejected", "DRV-1", "DRV-1: the resolver key is pinned by the verifier, not supplied by a vector", [{"op": "add", "path": ["publicKeys", RESOLVER], "value": public_key("orchestrator")}, {"op": "add", "path": ["reproductionInputs", "publicTestSeedHex", RESOLVER], "value": SEEDS["orchestrator"].hex()}, {"op": "replace", "path": ["resolverEvidence", "signature"], "value": foreign_resolver_signature}]),
        vector("resolver-bound-to-another-job", "release", "rejected", "DRV-6", "the resolver record must describe this job, rail, and contract", [{"op": "replace", "path": ["resolverEvidence"], "value": other_job_resolver["resolverEvidence"]}]),
        # Reproduction inputs.
        vector("public-test-seed-mismatch", "release", "rejected", "DRV-4", "committed public test seeds must derive the published verification keys", [{"op": "replace", "path": ["reproductionInputs", "publicTestSeedHex", BUYER], "value": "00" * 32}]),
        vector("role-bundle-input-mismatch", "release", "rejected", "DRA-4", "the committed role bundle must hash to the signed overlay binding", [{"op": "replace", "path": ["reproductionInputs", "roleBundles", "buyer", "primaryClaim"], "value": SELLER}]),
        vector("vet-record-input-mismatch", "release", "rejected", "DRA-4", "the committed Vet record must resolve from the signed overlay reference", [{"op": "replace", "path": ["reproductionInputs", "vetRecords", "buyer", "validFromSec"], "value": 1799900001}]),
        vector("evaluation-rule-input-mismatch", "release", "rejected", "DRE-6", "the exact evaluation rule input must resolve from the signed reference", [{"op": "replace", "path": ["reproductionInputs", "evaluationRule", "rule"], "value": "different-rule"}]),
        vector("delivered-artifact-input-mismatch", "release", "rejected", "DRE-2", "the delivered-artifact preimage must resolve from the signed delivery evidence", [{"op": "replace", "path": ["reproductionInputs", "deliveredArtifact", "payloadUtf8"], "value": "substituted"}]),
        vector("deliveryless-lifecycle-carries-artifact-input", "expired-pre", "rejected", "DRP-7", "a lifecycle without delivery carries no delivered-artifact input", [{"op": "replace", "path": ["reproductionInputs", "deliveredArtifact"], "value": {"kind": "delivered-artifact-input"}}]),
        vector("runtime-bytecode-preimage-mismatch", "release", "rejected", "DRJ-5", "the runtime bytecode preimage must reproduce the pinned hash", [{"op": "replace", "path": ["reproductionInputs", "runtimeBytecode", "value"], "value": "substituted runtime"}]),
        vector("native-event-transaction-preimage-mismatch", "release", "rejected", "DRT-4", "event transaction hashes must reproduce from committed inputs", authenticated("release", observation(3, "txHashPreimageUtf8", value="substituted tx") + observation(3, "blockHashPreimageUtf8", value="substituted tx:block:20000100:1800001000") + observation(3, "blockHash", value="0x" + hashlib.sha256(b"substituted tx:block:20000100:1800001000").hexdigest()))),
        vector("native-event-kind-substitution", "release", "rejected", "DRT-4", "event observations retain the exact EvmEventRef discriminator", authenticated("release", observation(3, "eventRef", "kind", value="transaction"))),
        vector("native-event-chain-substitution", "release", "rejected", "DRT-4", "event observations retain the selected rail chain", authenticated("release", observation(3, "eventRef", "chainId", value=10))),
        vector("native-event-selector-substitution", "release", "rejected", "DRT-4", "each observation carries its lifecycle event selector", authenticated("release", observation(0, "eventName", value="JobOpened"))),
        vector("native-event-targets-another-job", "release", "rejected", "DRT-4", "every observation targets the escrow job's contract and native job", authenticated("release", observation(1, "nativeJobId", value="99"))),
        vector("native-events-out-of-order", "release", "rejected", "DRT-4", "lifecycle events are strictly ordered on chain", authenticated("release", retime("release", "JobCompleted", 1799994000))),
        vector("funding-time-caller-substitution", "release", "rejected", "DRA-9", "a caller fundedAt value cannot replace the authenticated funding-event block timestamp", [{"op": "replace", "path": ["native", "fundedAtSec"], "value": 1799990001}]),
        vector("submitted-before-cutoff-claim-substitution", "release", "rejected", "DRT-12", "submission classification derives from the authenticated event time", [{"op": "replace", "path": ["submittedBeforeCutoff"], "value": False}]),
        vector("creation-event-cutoff-mismatch", "release", "rejected", "DRJ-3", "the authenticated creation event must carry the signed cutoff", authenticated("release", observation(0, "arguments", "submissionCutoffSec", value=cutoff + 1))),
        vector("funding-event-amount-mismatch", "release", "rejected", "DRF-3", "the authenticated funding event must lock the complete budget", authenticated("release", observation(1, "arguments", "amountBaseUnits", value="999999"))),
        vector("terminal-event-payload-mismatch", "release", "rejected", "DRT-4", "terminal log inputs must match the claimed financial disposition", authenticated("release", observation(3, "arguments", "amountBaseUnits", value="999999"))),
        vector("funding-finality-block-preimage-mismatch", "release", "rejected", "DRF-6", "the finalized funding block identity must reproduce from committed input", authenticated("release", observation(1, "blockHashPreimageUtf8", value="substituted block") + observation(1, "blockHash", value="0x" + hashlib.sha256(b"substituted block").hexdigest()))),
        vector("funding-block-hash-mismatch", "release", "rejected", "DRF-6", "the finalized funding block hash must reproduce from its preimage", authenticated("release", observation(1, "blockHash", value="0x" + "cd" * 32))),
        # DRJ, DRAA: identifiers, job, and code.
        vector("nonminimal-native-job-id", "nonminimal-native-job-id", "error", "DRJ-1", "native job identifiers use minimal unsigned decimal text"),
        vector("noninteger-evaluation-sequence", "evaluation-sequence-text", "error", "DRAA-2", "numeric address segments must be unsigned integers"),
        vector("first-evaluation-sequence-not-zero", "evaluation-sequence-one", "rejected", "DRAA-6", "the first evaluation sequence starts at zero"),
        vector("noncanonical-job-id", "noncanonical-job-id", "error", "DRAA-1", "malformed JID is an input error"),
        vector("noncanonical-case-id", "noncanonical-case-id", "error", "DRAA-1", "malformed DisputeOutcome caseId is an input error"),
        vector("noninteger-dispute-revision", "dispute-revision-text", "error", "DRAA-2", "the dispute revision is an unsigned integer"),
        vector("drp-5-job-rail", "drp-5-job-rail", "rejected", "DRP-5", "the signed escrow job must use the agreement-selected rail definition"),
        vector("drj-2-job-contract", "drj-2-job-contract", "rejected", "DRJ-2", "the escrow job and native evidence must target the selected rail contract"),
        vector("drj-5-job-runtime", "drj-5-job-runtime", "rejected", "DRJ-5", "the escrow job runtime code must be the selected rail's"),
        vector("drv-4-job-overlay-hash", "drv-4-job-overlay-hash", "rejected", "DRV-4", "a signed escrow job cannot bind another agreement overlay"),
        vector("drf-1-funding-overlay-hash", "drf-1-funding-overlay-hash", "rejected", "DRF-1", "funding evidence must bind the exact agreement overlay"),
        vector("dra-1-bilateral-job", "dra-1-bilateral-job", "rejected", "DRA-1", "the bilateral agreement must be the one for the overlay's job"),
        vector("dra-1-bilateral-parties", "dra-1-bilateral-parties", "rejected", "DRA-1", "the bilateral agreement's buyer and seller keep their overlay roles"),
        vector("native-contract-projection-mismatch", "release", "rejected", "DRJ-2", "the native contract projection must be the escrow job's contract", [{"op": "replace", "path": ["native", "contractAddress"], "value": "0x" + "82" * 20}]),
        vector("native-runtime-projection-mismatch", "release", "rejected", "DRJ-5", "the native runtime projection must be the escrow job's code", [{"op": "replace", "path": ["native", "runtimeBytecodeHash"], "value": "ab" * 32}]),
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
    # Rules whose vectors run against a synthetic evidence shape that does
    # not yet define the normative proof.
    promotion_blocked_proofs = {
        "DRE-2": (
            "requires a normative logical address for delivery SettlementEvidence, which "
            "DACS-4 does not define; the pack binds the record to the single agreement-bound "
            "delivery step and models its resolution with the synthetic resolver"
        ),
        "DRP-7": (
            "requires authenticated resolution of the delivery SettlementEvidence produced by "
            "the intervening step; the pack binds the record to the single agreement-bound "
            "delivery step, as for DRE-2"
        ),
        "DRP-9": (
            "requires a normative proof shape showing that the exact delivery digest was "
            "fixed before the native submission; the pack models it with a synthetic "
            "resolver-attested digest anchor"
        ),
    }
    payload = {
        "fixtures": fixtures,
        "vectors": vectors,
        "promotionBlockedRules": promotion_blocked_rules,
        "promotionBlockedProofs": promotion_blocked_proofs,
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


# Negatives whose single defect a second rule also covers by construction.
# With the deciding guard removed, exactly this finding must remain.
FOLLOW_ON_FINDINGS = {
    # An unsupported evaluation result or disposition authorizes no settlement.
    "drv-2-evaluation-result": ("rejected", "DRD-2"),
    "drv-2-decision-disposition": ("rejected", "DRD-2"),
    # A release whose decision is missing has no authorizing decision.
    "decision-artifact-unavailable": ("rejected", "DRT-3"),
    # An overlay delivery index on a non-delivery step names no delivery step.
    "pipeline-phase-index-divergence": ("rejected", "DRE-2"),
    # The evaluation's subject is that same delivery reference.
    "delivery-reference-mismatch": ("rejected", "DRE-3"),
}
# Structural negatives: their deciding guard is what keeps the verifier from
# reading a structure that the negative removes, so without that guard the
# verifier raises instead of reaching a verdict.  Isolation is not claimed
# for them; the generator fails if one stops raising or another starts.
STRUCTURAL_NEGATIVES = {
    "pipeline-missing-terminal": "the pipeline has no terminal escrow step to read",
    "overlay-signature-missing": "the overlay has no signature for one role",
    "funding-events-empty": "the funding evidence has no event to read",
    "terminal-events-empty": "the terminal evidence has no event to read",
    "native-event-kind-substitution": "the terminal event has no matching observation",
    "native-event-chain-substitution": "the terminal event has no matching observation",
    "native-event-selector-substitution": "the creation observation has no lifecycle selector",
    "drp-9-digest-anchor-unavailable": "the resolver record has no digest anchor to read",
    "drv-2-evaluation-subject-refs": "the evaluation has no subject reference array to read",
}
# Pack runner and deployment-capability code are outside the lifecycle audit.
_UNAUDITED_FUNCTIONS = {
    "_status", "deployment_rule_statuses", "evaluate_deployment", "verify_vector_pack",
    "verify_deployment_pack", "main", "load_json", "_pack_hash",
}


def _is_finding(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "result"
        and bool(node.args)
        and not (isinstance(node.args[0], ast.Constant) and node.args[0].value == "verified")
    )


class _GuardSwitches(ast.NodeTransformer):
    """Make every non-verified `return result(...)` in the lifecycle verifier switchable."""

    def __init__(self) -> None:
        self.sites: list[str] = []
        self._function: str | None = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        if node.name in _UNAUDITED_FUNCTIONS:
            return node
        outer, self._function = self._function, node.name
        self.generic_visit(node)
        self._function = outer
        return node

    def visit_Return(self, node: ast.Return) -> ast.AST:
        if self._function is None or node.value is None:
            return node
        parts = node.value.elts if isinstance(node.value, ast.Tuple) else [node.value]
        finding = next((part for part in parts if _is_finding(part)), None)
        if finding is None:
            return node
        self.sites.append(
            f"{self._function}:{node.lineno} "
            f"{ast.unparse(finding.args[0])} {ast.unparse(finding.args[1])}"
        )
        switch = ast.Call(
            func=ast.Name("_guard_fires", ast.Load()),
            args=[ast.Constant(len(self.sites) - 1)],
            keywords=[],
        )
        return ast.copy_location(ast.If(test=switch, body=[node], orelse=[]), node)


class GuardedVerifier:
    """The lifecycle verifier with each guard site switchable, for guard audits."""

    def __init__(self) -> None:
        switches = _GuardSwitches()
        tree = switches.visit(ast.parse(VERIFIER_PATH.read_text(encoding="utf-8")))
        ast.fix_missing_locations(tree)
        self.sites = switches.sites
        self._disabled: int | None = None
        self._fired: list[int] = []
        module = types.ModuleType("guarded_delivery_remedy_verifier")
        module.__file__ = str(VERIFIER_PATH)
        module.__dict__["_guard_fires"] = self._guard_fires
        exec(compile(tree, str(VERIFIER_PATH), "exec"), module.__dict__)
        self.module = module

    def _guard_fires(self, site: int) -> bool:
        if site == self._disabled:
            return False
        self._fired.append(site)
        return True

    def run(
        self, value: Any, priors: list[Any] | None = None, disabled: int | None = None
    ) -> tuple[dict[str, str], list[int]]:
        """Evaluate after ``priors`` share a ledger; return the outcome and the guards that fired.

        For ``value`` this is its verdict when evaluated together with
        ``priors``: each prior records its terminal whatever its own verdict.
        """
        self._disabled = disabled
        try:
            ledger = self.module.DecisionLedger()
            for prior in priors or []:
                self.module.evaluate_protocol(copy.deepcopy(prior), ledger)
            self._fired = []
            try:
                outcome = self.module.evaluate_protocol(copy.deepcopy(value), ledger)
            except Exception as exc:  # an unguarded crash, not a guard's finding
                outcome = {"result": "exception", "rule": type(exc).__name__, "detail": str(exc)}
            return outcome, list(self._fired)
        finally:
            self._disabled = None


def negative_isolation_problems(
    pack: dict[str, Any], verifier: GuardedVerifier | None = None
) -> list[str]:
    """Return every negative vector that does not fail only at its intended guard.

    A negative is isolated when, with the guard that decides it removed, the
    verifier returns `verified`: its signatures and bindings are otherwise
    valid.  `FOLLOW_ON_FINDINGS` lists the negatives that reach one exact
    second finding instead, and `STRUCTURAL_NEGATIVES` those that make the
    verifier raise.  Any other outcome, including an exception, is a problem.
    """
    verifier = verifier or GuardedVerifier()
    by_name = {item["name"]: item for item in pack["vectors"]}
    problems = []
    for vector_value in pack["vectors"]:
        name = vector_value["name"]
        if vector_value["expected"] == "verified":
            continue
        value = verifier.module.materialize_vector(pack, vector_value)
        priors = [
            verifier.module.materialize_vector(pack, by_name[prior])
            for prior in vector_value.get("evaluatedWith", [])
        ]
        _outcome, fired = verifier.run(value, priors)
        if not fired:
            problems.append(f"{name}: no guard decides it")
            continue
        deciding = fired[-1]
        isolated, others = verifier.run(value, priors, disabled=deciding)
        without = f"{name}: without {verifier.sites[deciding]},"
        outcome = (isolated["result"], isolated["rule"])
        follow_on = FOLLOW_ON_FINDINGS.get(name)
        if name in STRUCTURAL_NEGATIVES:
            if isolated["result"] != "exception":
                problems.append(f"{without} a listed structural negative reports {outcome[0]}/{outcome[1]}")
        elif isolated["result"] == "exception":
            problems.append(f"{without} the verifier raises {isolated['rule']}: {isolated['detail']}")
        elif follow_on is not None:
            if outcome != follow_on:
                problems.append(f"{without} its listed follow-on finding {follow_on} became {outcome}")
        elif isolated["result"] != "verified":
            reporter = verifier.sites[others[-1]] if others else "an unswitched path"
            problems.append(f"{without} {reporter} reports {outcome[0]}/{outcome[1]}")
    return problems


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
        deployment_case("synthetic-all-rules-control", "synthetic-control", "verified", [], "all DRC rules pass, but a capability evaluation never establishes registration eligibility", covers=["DRL-8", "DRL-9"]),
        deployment_case("drc-11-manifest-labels", "synthetic-control", "verified", [], "eligibility needs independently resolved deployment and registry facts, not manifest labels", [{"op": "replace", "path": ["fixtureOnly"], "value": False}, {"op": "replace", "path": ["registrationStatus"], "value": "listed"}], covers=["DRC-11"]),
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
    vector_pack = build_vector_pack()
    outputs = {
        VECTOR_OUTPUT: rendered(vector_pack),
        DEPLOYMENT_OUTPUT: rendered(build_deployment_pack()),
    }
    if args.write or args.check:
        problems = negative_isolation_problems(vector_pack)
        if problems:
            print("ERROR: negative vectors do not fail only at their intended guard:", file=sys.stderr)
            for problem in problems:
                print(f"- {problem}", file=sys.stderr)
            return 1
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
