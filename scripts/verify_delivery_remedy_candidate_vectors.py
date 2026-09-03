#!/usr/bin/env python3
"""Execute the non-normative delivery-or-remedy candidate fixture pack.

This is deliberately separate from the canonical DACS vector validator.  It
implements the review candidate in ``docs/delivery-or-remedy-candidate.md``
without registering a rail or changing current conformance requirements.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

try:
    from jcs import canonicalize as jcs_canonicalize
except ModuleNotFoundError:  # imported as scripts.verify_* by the unit suite
    from scripts.jcs import canonicalize as jcs_canonicalize


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VECTOR_PACK = (
    ROOT / "conformance/fixtures/delivery-remedy/candidate-vectors-v0.1.json"
)
DEFAULT_DEPLOYMENT_PACK = (
    ROOT / "conformance/fixtures/delivery-remedy/deployment-capabilities-v0.1.json"
)

JID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
BYTES32_RE = re.compile(r"^0x[0-9a-f]{64}$")
EVM_TX_RE = re.compile(r"^0x[0-9a-f]{64}$")

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

EXTERNAL_EVIDENCE_FIELDS = {
    "agreementResolution",
    "railResolution",
    "codeResolution",
    "authorityResolution",
    "fundingFinality",
    "deliveryFinality",
    "decisionFinality",
    "terminalFinality",
    "decisionOrdering",
    "nativeStateResolution",
}
EXTERNAL_STATES = {"verified", "not-applicable", "unavailable", "contradictory"}
DRC_RULES = {f"DRC-{number}" for number in range(1, 14)}


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


def base64url_decode(value: Any) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("signature is not unpadded Base64URL")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ValueError("signature is not canonical Base64URL")
    return raw


def signature_valid(
    artifact: dict[str, Any],
    signature: Any,
    expected_signer: str,
    public_keys: dict[str, Any],
    domain: str,
) -> bool:
    if not isinstance(signature, dict):
        return False
    if signature.get("algorithm") != "ed25519":
        return False
    if signature.get("signer", signature.get("party")) != expected_signer:
        return False
    public_key = public_keys.get(expected_signer)
    try:
        Ed25519PublicKey.from_public_bytes(base64url_decode(public_key)).verify(
            base64url_decode(signature.get("value")),
            (domain + artifact_hash(artifact)).encode("ascii"),
        )
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def attestation_ref_valid(ref: Any, artifact: Any) -> bool:
    return (
        isinstance(ref, dict)
        and isinstance(ref.get("kind"), str)
        and bool(ref["kind"])
        and isinstance(ref.get("locator"), str)
        and bool(ref["locator"])
        and isinstance(artifact, dict)
        and ref.get("contentHash") == artifact_hash(artifact)
    )


def _event_refs_check(
    refs: Any, chain_id: Any, rule: str, label: str
) -> dict[str, str] | None:
    if not isinstance(refs, list) or not refs:
        return result("rejected", rule, f"{label} event set must be non-empty")
    identities: set[tuple[str, int]] = set()
    for ref_value in refs:
        if not isinstance(ref_value, dict) or set(ref_value) != {
            "kind", "chainId", "txHash", "logIndex"
        }:
            return result("error", "DRV-2", f"{label} event reference is malformed")
        tx_hash = ref_value.get("txHash")
        log_index = ref_value.get("logIndex")
        if (
            ref_value.get("kind") != "evm-event"
            or ref_value.get("chainId") != chain_id
            or not isinstance(tx_hash, str)
            or EVM_TX_RE.fullmatch(tx_hash) is None
            or type(log_index) is not int
            or log_index < 0
        ):
            return result("rejected", rule, f"{label} event identity is not canonical")
        identity = (tx_hash, log_index)
        if identity in identities:
            return result("rejected", rule, f"{label} event identity is duplicated")
        identities.add(identity)
    return None


def _finality_check(
    finality: Any,
    chain_id: Any,
    minimum_confirmations: Any,
    rule: str,
    label: str,
) -> dict[str, str] | None:
    if not isinstance(finality, dict):
        return result("error", "DRV-2", f"{label} finality must be an object")
    if finality.get("status") != "finalized":
        return result("indeterminate", rule, f"{label} finality is not finalized")
    block_number = finality.get("blockNumber")
    block_hash = finality.get("blockHash")
    confirmations = finality.get("confirmations")
    if (
        finality.get("chainId") != chain_id
        or type(block_number) is not int
        or block_number < 0
        or not isinstance(block_hash, str)
        or EVM_TX_RE.fullmatch(block_hash) is None
        or type(confirmations) is not int
        or confirmations < 0
        or type(minimum_confirmations) is not int
        or minimum_confirmations <= 0
    ):
        return result("error", "DRV-2", f"{label} finality record is malformed")
    if confirmations < minimum_confirmations:
        return result("indeterminate", rule, f"{label} finality threshold is not met")
    return None


def parse_canonical_evm_claim(value: Any) -> tuple[int, str] | None:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"cci-xm:evm:([1-9][0-9]*):(0x[0-9a-f]{40})", value)
    if match is None:
        return None
    return int(match.group(1)), match.group(2)


def result(verdict: str, rule: str, detail: str) -> dict[str, str]:
    return {"result": verdict, "rule": rule, "detail": detail}


def apply_operation(value: Any, operation: dict[str, Any]) -> Any:
    path = operation.get("path")
    if not isinstance(path, list):
        raise ValueError("patch path must be an array")
    if not path:
        if operation.get("op") in {"add", "replace"}:
            return copy.deepcopy(operation.get("value"))
        raise ValueError("document root can only be added or replaced")
    parent = value
    for segment in path[:-1]:
        parent = parent[segment]
    leaf = path[-1]
    if operation.get("op") == "remove":
        if isinstance(parent, list):
            parent.pop(leaf)
        else:
            del parent[leaf]
    elif operation.get("op") == "replace":
        parent[leaf] = copy.deepcopy(operation.get("value"))
    elif operation.get("op") == "add":
        if isinstance(parent, list):
            parent.insert(leaf, copy.deepcopy(operation.get("value")))
        else:
            parent[leaf] = copy.deepcopy(operation.get("value"))
    else:
        raise ValueError(f"unsupported patch operation: {operation.get('op')!r}")
    return value


def materialize_vector(pack: dict[str, Any], vector: dict[str, Any]) -> dict[str, Any]:
    fixtures = pack.get("fixtures")
    base = vector.get("base")
    if not isinstance(fixtures, dict) or base not in fixtures:
        raise ValueError(f"unknown vector base: {base!r}")
    value = copy.deepcopy(fixtures[base])
    for operation in vector.get("patch", []):
        value = apply_operation(value, operation)
    return value


def _pipeline_check(value: dict[str, Any]) -> dict[str, str] | None:
    pipeline = value.get("pipeline")
    agreement = value["artifacts"]["agreement"]
    if not isinstance(pipeline, list) or not pipeline:
        return result("error", "DRV-2", "pipeline must be a non-empty array")
    if not all(isinstance(step, dict) and isinstance(step.get("kind"), str) for step in pipeline):
        return result("error", "DRV-2", "every pipeline step must have a kind")

    escrow_indexes = [i for i, step in enumerate(pipeline) if step["kind"] == "job-escrow"]
    if len(escrow_indexes) != 2:
        return result("rejected", "DRP-1", "pipeline does not contain exactly two escrow steps")
    fund_index, terminal_index = escrow_indexes
    fund = pipeline[fund_index]
    terminal = pipeline[terminal_index]
    for step in (fund, terminal):
        if not isinstance(step.get("parameters"), dict):
            return result("error", "DRV-2", "job-escrow parameters must be an object")
    if fund["parameters"].get("action") != "fund" or terminal["parameters"].get("action") != "terminal":
        return result("rejected", "DRP-2", "escrow actions are not fund then terminal")
    if fund_index >= terminal_index:
        return result("rejected", "DRP-2", "terminal escrow step precedes funding")
    if fund["parameters"].get("rail") != terminal["parameters"].get("rail"):
        return result("rejected", "DRP-5", "paired escrow steps select different rails")

    delivery_indexes = [i for i, step in enumerate(pipeline) if step["kind"].startswith("deliver-")]
    if len(delivery_indexes) != 1 or not (fund_index < delivery_indexes[0] < terminal_index):
        return result("rejected", "DRP-3", "exactly one delivery must occur between escrow steps")
    prohibited = [
        step["kind"] for step in pipeline
        if step["kind"].startswith("pay-") or step["kind"] == "pay-alternative"
    ]
    if prohibited:
        return result("rejected", "DRP-4", "ordinary payment phases cannot accompany the escrow pair")
    if (
        agreement.get("fundPhaseIndex") != fund_index
        or agreement.get("deliveryPhaseIndex") != delivery_indexes[0]
        or agreement.get("terminalPhaseIndex") != terminal_index
    ):
        return result("rejected", "DRA-11", "agreement phase indexes do not match the pipeline")
    execution = value.get("executionContext")
    if not isinstance(execution, dict):
        return result("error", "DRV-2", "executionContext must be an object")
    if execution.get("acceptedRails") != [agreement.get("railDefinitionRef")]:
        return result("rejected", "DRP-10", "job escrow is not selected through acceptedRails")
    commitment = execution.get("commitmentReceipt")
    if not isinstance(commitment, dict) or commitment != {
        "status": "finalized",
        "jobId": agreement.get("jobId"),
        "agreementHash": agreement.get("agreementHash"),
    }:
        return result("rejected", "DRP-11", "funding is not gated by the finalized commitment")
    if execution.get("fundingFinalizedBeforeDelivery") is not True:
        return result("rejected", "DRP-6", "delivery began before finalized funding evidence")
    if execution.get("dacs5PurchaseCount") != 1:
        return result("rejected", "DRP-8", "the escrow pair was counted as more than one purchase")
    expected_gate = (
        "delivery-returned"
        if value["artifacts"].get("delivery") is not None
        else (
            "pre-submission-decision"
            if value["artifacts"].get("decision") is not None
            else "submission-cutoff"
        )
    )
    if (
        execution.get("terminalGate") != expected_gate
        or execution.get("lateDeliveryDisabled") is not True
    ):
        return result("rejected", "DRP-12", "terminal execution did not satisfy the delivery/cutoff gate")
    return None


def _artifact_shape_check(artifacts: dict[str, Any]) -> dict[str, str] | None:
    required = {"bilateralAgreement", "railDefinition", "agreement", "job", "funding", "terminal"}
    if not required.issubset(artifacts):
        return result("error", "DRV-2", "required candidate artifacts are missing")
    if not all(isinstance(artifacts[name], dict) for name in required):
        return result("error", "DRV-2", "candidate artifacts must be objects")
    agreement = artifacts["agreement"]
    job_id = agreement.get("jobId")
    if not isinstance(job_id, str) or JID_RE.fullmatch(job_id) is None:
        return result("error", "DRAA-1", "jobId is not canonical JID form")
    if agreement.get("deliveryOrRemedyAgreementVersion") != "1":
        return result("error", "DRV-2", "unsupported agreement overlay version")
    if not isinstance(agreement.get("budgetBaseUnits"), str) or re.fullmatch(
        r"(?:0|[1-9][0-9]*)", agreement["budgetBaseUnits"]
    ) is None:
        return result("error", "DRA-10", "budgetBaseUnits is not minimal unsigned decimal")
    for name in ("job", "funding", "delivery", "evaluation", "dispute", "decision", "terminal"):
        artifact = artifacts.get(name)
        if artifact is not None and (
            not isinstance(artifact, dict) or artifact.get("jobId") != job_id
        ):
            return result("rejected", "DRD-8", f"{name} is bound to another job")
    dispute = artifacts.get("dispute")
    if dispute is not None and (
        not isinstance(dispute.get("caseId"), str)
        or JID_RE.fullmatch(dispute["caseId"]) is None
    ):
        return result("error", "DRAA-1", "caseId is not canonical JID form")
    job = artifacts["job"]
    if not isinstance(job.get("nativeJobId"), str) or re.fullmatch(
        r"(?:0|[1-9][0-9]*)", job["nativeJobId"]
    ) is None:
        return result("error", "DRJ-1", "nativeJobId is not minimal unsigned decimal")
    evaluation = artifacts.get("evaluation")
    if evaluation is not None and (
        type(evaluation.get("evaluationSeq")) is not int
        or evaluation["evaluationSeq"] < 0
    ):
        return result("error", "DRAA-2", "evaluationSeq is not minimal unsigned integer form")
    if evaluation is not None and evaluation.get("evaluationSeq") != 0:
        return result("rejected", "DRAA-6", "first evaluation sequence is not zero")
    if dispute is not None:
        if type(dispute.get("revision")) is not int or dispute["revision"] < 0:
            return result("error", "DRAA-2", "dispute revision is not minimal unsigned integer form")
        if any(field in dispute for field in ("transfer", "recipient", "amountBaseUnits")):
            return result("rejected", "DRX-1", "DisputeOutcome directly claims a transfer")
    return None


def _canonical_record_check(value: dict[str, Any]) -> dict[str, str] | None:
    artifacts = value["artifacts"]
    records = value.get("canonicalRecords")
    if not isinstance(records, dict):
        return result("error", "DRV-2", "canonicalRecords must be an object")
    expected_names = {
        name for name in ("agreement", "delivery", "decision")
        if artifacts.get(name) is not None
    }
    if set(records) != expected_names:
        return result("error", "DRV-2", "canonical record set does not match the lifecycle")
    for name in expected_names:
        record = records.get(name)
        artifact = artifacts[name]
        if not isinstance(record, dict):
            return result("error", "DRV-2", f"{name} canonical record must be an object")
        encoded = jcs_canonicalize(unsigned_artifact(artifact)).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        expected_native = (
            "dacs-delivery-remedy:v1:" + digest if name == "agreement" else "0x" + digest
        )
        if record != {
            "canonicalUtf8Hex": encoded.hex(),
            "contentHash": digest,
            "mappedNativeValue": expected_native,
        }:
            return result("rejected", "DREB-2", f"{name} canonical bytes or mapped value are stale")
    return None


def _agreement_check(value: dict[str, Any]) -> dict[str, str] | None:
    artifacts = value["artifacts"]
    agreement = artifacts["agreement"]
    public_keys = value["publicKeys"]
    bilateral = artifacts["bilateralAgreement"]
    rail = artifacts["railDefinition"]

    if not attestation_ref_valid(agreement.get("agreementRef"), bilateral):
        return result("rejected", "DRA-1", "bilateral agreement reference does not resolve exactly")
    if agreement.get("agreementHash") != artifact_hash(bilateral):
        return result("rejected", "DRA-2", "bilateral agreement hash mismatch")
    if not attestation_ref_valid(agreement.get("railDefinitionRef"), rail):
        return result("rejected", "DRA-12", "rail definition reference does not resolve exactly")

    role_bindings = {role: agreement.get(role) for role in ("buyer", "seller", "evaluator")}
    if not all(isinstance(binding, dict) for binding in role_bindings.values()):
        return result("error", "DRV-2", "agreement role bindings must be objects")
    claims = {role: binding.get("primaryClaim") for role, binding in role_bindings.items()}
    if not all(isinstance(claim, str) and claim for claim in claims.values()):
        return result("error", "DRV-2", "agreement primary claims must be strings")
    if claims["evaluator"] in {claims["buyer"], claims["seller"]}:
        return result("rejected", "DRA-6", "evaluator primary claim collides with a commercial party")
    if value.get("bundleRequiredSigners") != [claims["buyer"], claims["seller"]]:
        return result("rejected", "DRA-13", "evaluator overlay signature changed the bilateral bundle parties")
    if agreement.get("preSubmissionRefundPolicy") != "evaluator-rejection":
        return result("rejected", "DRA-15", "pre-submission refund policy is unsupported by this profile")
    if agreement.get("disclosurePolicy") not in {
        "public-evidence-only", "explicit-party-supplied"
    }:
        return result("rejected", "DRQ-1", "unsupported evidence-disclosure policy")

    signatures = agreement.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 3:
        return result("rejected", "DRA-3", "agreement needs exactly three signatures")
    by_role = {signature.get("role"): signature for signature in signatures if isinstance(signature, dict)}
    if set(by_role) != {"buyer", "seller", "evaluator"}:
        return result("rejected", "DRA-3", "agreement signature roles are not exact")
    for role, claim in claims.items():
        signature = by_role[role]
        if signature.get("party") != claim or not signature_valid(
            agreement, signature, claim, public_keys, DOMAINS["agreement"]
        ):
            return result("rejected", "DRA-3", f"invalid {role} agreement signature")

    chain_id = value["native"].get("chainId")
    accounts: dict[str, str] = {}
    for role, binding in role_bindings.items():
        parsed = parse_canonical_evm_claim(binding.get("evmAccountClaim"))
        if parsed is None or parsed[0] != chain_id:
            return result("rejected", "DRA-5", f"{role} EVM account claim is not canonical for the rail")
        accounts[role] = parsed[1]
    if accounts["evaluator"] in {accounts["buyer"], accounts["seller"]}:
        return result("rejected", "DRA-7", "evaluator account collides with client or provider")
    for role, native_field in (("buyer", "client"), ("seller", "provider"), ("evaluator", "evaluator")):
        if value["native"].get(native_field) != accounts[role]:
            return result("rejected", f"DREB-{7 + list(('buyer', 'seller', 'evaluator')).index(role)}", f"native {native_field} mismatch")

    evaluator = role_bindings["evaluator"]
    requirement = evaluator.get("requirement")
    if not isinstance(requirement, dict) or evaluator.get("requirementHash") != content_hash(requirement):
        return result("rejected", "DRA-8", "evaluator requirement hash mismatch")
    if value.get("evaluatorVetResult") != "pass":
        return result("rejected", "DRA-9", "evaluator Vet result is not pass")
    return None


def _component_signature_check(value: dict[str, Any]) -> dict[str, str] | None:
    artifacts = value["artifacts"]
    claims = {
        role: artifacts["agreement"][role]["primaryClaim"]
        for role in ("buyer", "seller", "evaluator")
    }
    orchestrator = value.get("orchestratorClaim")
    if not isinstance(orchestrator, str):
        return result("error", "DRV-2", "orchestratorClaim is required")
    signers = {
        "job": orchestrator,
        "funding": orchestrator,
        "delivery": orchestrator,
        "evaluation": claims["evaluator"],
        "dispute": claims["evaluator"],
        "decision": claims["evaluator"],
        "terminal": orchestrator,
    }
    for name, signer in signers.items():
        artifact = artifacts.get(name)
        if artifact is None:
            continue
        if not signature_valid(
            artifact, artifact.get("signature"), signer, value["publicKeys"], DOMAINS[name]
        ):
            signature_rule = {
                "evaluation": "DRE-1",
                "decision": "DRD-1",
            }.get(name, "DRV-4")
            return result("rejected", signature_rule, f"invalid {name} signature")
    return None


def _finding_check(value: dict[str, Any]) -> dict[str, str] | None:
    agreement = value["artifacts"]["agreement"]
    parties = {
        "seller-fault": agreement["seller"]["primaryClaim"],
        "buyer-fault": agreement["buyer"]["primaryClaim"],
    }
    for name in ("evaluation", "dispute"):
        artifact = value["artifacts"].get(name)
        if artifact is None:
            continue
        finding = artifact.get("finding")
        if not isinstance(finding, dict):
            return result("error", "DRV-2", f"{name} finding must be an object")
        classification = finding.get("classification")
        faulted_party = finding.get("faultedParty")
        if classification in parties:
            if faulted_party != parties[classification]:
                return result("rejected", "DRX-5", "faultedParty does not match the classified agreement party")
        elif faulted_party is not None:
            return result("rejected", "DRX-6", "non-party-fault finding names a faulted party")
    return None


def _reference_check(value: dict[str, Any]) -> dict[str, str] | None:
    a = value["artifacts"]
    agreement_hash = artifact_hash(a["agreement"])
    for name in ("job", "funding", "evaluation", "dispute", "decision", "terminal"):
        artifact = a.get(name)
        if artifact is not None and artifact.get("deliveryOrRemedyAgreementHash") != agreement_hash:
            return result("rejected", "DRAA-4", f"{name} agreement hash mismatch")
    if not attestation_ref_valid(a["funding"].get("escrowJobRef"), a["job"]):
        return result("rejected", "DRF-1", "funding job reference mismatch")
    if not attestation_ref_valid(a["terminal"].get("escrowJobRef"), a["job"]):
        return result("rejected", "DRT-4", "terminal job reference mismatch")
    if not attestation_ref_valid(a["terminal"].get("fundingEvidenceRef"), a["funding"]):
        return result("rejected", "DRT-11", "terminal funding reference mismatch")
    if a.get("delivery") is not None:
        delivery_ref = a.get("deliveryRef")
        if not attestation_ref_valid(delivery_ref, a["delivery"]):
            return result("rejected", "DRE-2", "delivery reference mismatch")
        for name in ("evaluation", "decision"):
            artifact = a.get(name)
            if artifact is not None and artifact.get("deliveryEvidenceRef") != delivery_ref:
                return result("rejected", "DRD-3", f"{name} does not bind the exact delivery")
        if a["terminal"].get("deliveryEvidenceRef") != delivery_ref:
            return result("rejected", "DRT-12", "terminal delivery reference mismatch")
    if a.get("evaluation") is not None:
        if not attestation_ref_valid(a.get("evaluationRef"), a["evaluation"]):
            return result("rejected", "DRE-7", "evaluation reference mismatch")
        decision = a.get("decision")
        if decision is None or decision.get("basisRef") != {
            "kind": "execution-evaluation", "ref": a["evaluationRef"]
        }:
            return result("rejected", "DRD-2", "decision basis does not resolve to the evaluation")
    elif a.get("dispute") is not None:
        if not attestation_ref_valid(a.get("disputeRef"), a["dispute"]):
            return result("rejected", "DRX-2", "dispute outcome reference mismatch")
        decision = a.get("decision")
        if decision is None or decision.get("basisRef") != {
            "kind": "dispute-outcome", "ref": a["disputeRef"]
        }:
            return result("rejected", "DRD-2", "decision basis does not resolve to the dispute outcome")
    if a.get("decision") is not None:
        if not attestation_ref_valid(a.get("decisionRef"), a["decision"]):
            return result("rejected", "DRD-4", "decision reference mismatch")
        if a["terminal"].get("decisionRef") != a["decisionRef"]:
            return result("rejected", "DRT-1", "terminal decision reference mismatch")
    return None


def _external_evidence_check(value: dict[str, Any]) -> dict[str, str] | None:
    external = value.get("externalEvidence")
    if not isinstance(external, dict) or set(external) != EXTERNAL_EVIDENCE_FIELDS:
        return result("error", "DRV-2", "external evidence status set is incomplete")
    if any(state not in EXTERNAL_STATES for state in external.values()):
        return result("error", "DRV-2", "unknown external evidence status")
    contradictory = sorted(name for name, state in external.items() if state == "contradictory")
    if contradictory:
        return result("rejected", "DRV-6", "authenticated evidence contradicts: " + ", ".join(contradictory))
    unavailable = sorted(name for name, state in external.items() if state == "unavailable")
    if unavailable:
        unavailable_rules = (
            ("decisionOrdering", "DRD-10"),
            ("fundingFinality", "DRF-6"),
            ("deliveryFinality", "DRE-5"),
            ("decisionFinality", "DRD-4"),
            ("terminalFinality", "DRT-9"),
            ("nativeStateResolution", "DRL-3"),
            ("codeResolution", "DRJ-7"),
            ("authorityResolution", "DRJ-7"),
            ("railResolution", "DRC-11"),
            ("agreementResolution", "DRV-2"),
        )
        rule = next(rule for name, rule in unavailable_rules if name in unavailable)
        return result("indeterminate", rule, "required external evidence unavailable: " + ", ".join(unavailable))
    return None


def _delivery_binding_check(value: dict[str, Any]) -> dict[str, str] | None:
    delivery = value["artifacts"].get("delivery")
    binding = value.get("deliveryBinding")
    if not isinstance(binding, dict):
        return result("error", "DRV-2", "deliveryBinding must be an object")
    if delivery is None:
        if binding != {"status": "not-applicable"}:
            return result("rejected", "DRP-9", "deliveryless path carries native submission binding")
        return None
    if binding.get("status") != "verified":
        return result("indeterminate", "DRP-9", "delivery/submission ordering is unavailable")
    if (
        type(binding.get("finalizedBeforeNativeSubmission")) is not bool
        or type(binding.get("containsNativeSubmissionObservation")) is not bool
    ):
        return result("error", "DRV-2", "delivery binding booleans are malformed")
    if (
        binding["finalizedBeforeNativeSubmission"] is not True
        or binding["containsNativeSubmissionObservation"] is not False
    ):
        return result("rejected", "DRP-9", "delivery hash is circular or was fixed after native submission")
    return None


def _reproduction_input_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Validate every committed preimage needed to reconstruct fixture claims."""
    inputs = value.get("reproductionInputs")
    if not isinstance(inputs, dict):
        return result("error", "DRV-2", "reproductionInputs must be an object")
    required = {
        "publicTestSeedHex",
        "roleBundles",
        "vetRecords",
        "evaluationRule",
        "deliveredArtifact",
        "disputeCase",
        "runtimeBytecode",
        "nativeEventInputs",
        "fundingFinalityBlockHashPreimageUtf8",
        "terminalFinalityBlockHashPreimageUtf8",
    }
    if set(inputs) != required:
        return result("error", "DRV-2", "reproduction input set is incomplete")
    pending = [inputs]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            if any("transcript" in str(key).lower() for key in current):
                return result("rejected", "DRQ-3", "candidate inputs attempt to disclose transcript material")
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)

    seeds = inputs["publicTestSeedHex"]
    if not isinstance(seeds, dict) or set(seeds) != set(value["publicKeys"]):
        return result("error", "DRV-2", "public test seed set is incomplete")
    for claim, seed_hex in seeds.items():
        try:
            seed = bytes.fromhex(seed_hex)
            derived = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        except (TypeError, ValueError):
            return result("error", "DRV-2", "public test seed is malformed")
        if base64.urlsafe_b64encode(derived).decode("ascii").rstrip("=") != value["publicKeys"][claim]:
            return result("rejected", "DRV-4", "public key does not derive from the committed test seed")

    agreement = value["artifacts"]["agreement"]
    bundles = inputs["roleBundles"]
    vet_records = inputs["vetRecords"]
    if not isinstance(bundles, dict) or not isinstance(vet_records, dict):
        return result("error", "DRV-2", "role source inputs must be objects")
    funded_at = value["native"].get("fundedAtSec")
    for role in ("buyer", "seller", "evaluator"):
        binding = agreement[role]
        bundle = bundles.get(role)
        vet_record = vet_records.get(role)
        if not isinstance(bundle, dict) or binding.get("bundleHash") != artifact_hash(bundle):
            return result("rejected", "DRA-4", f"{role} bundle input does not match the overlay")
        if not attestation_ref_valid(binding.get("vetRecordRef"), vet_record):
            return result("rejected", "DRA-4", f"{role} Vet record input does not resolve")
        if (
            vet_record.get("subject") != binding.get("primaryClaim")
            or vet_record.get("bundleHash") != binding.get("bundleHash")
            or vet_record.get("result") != "pass"
            or type(funded_at) is not int
            or type(vet_record.get("validFromSec")) is not int
            or type(vet_record.get("validUntilSec")) is not int
            or not vet_record["validFromSec"] <= funded_at <= vet_record["validUntilSec"]
        ):
            return result("rejected", "DRA-9" if role == "evaluator" else "DRA-4", f"{role} Vet input is not a fresh pass at funding")
    evaluator = agreement["evaluator"]
    if inputs["vetRecords"]["evaluator"].get("requirementHash") != evaluator.get("requirementHash"):
        return result("rejected", "DRA-8", "evaluator Vet input used another requirement")
    if not attestation_ref_valid(agreement.get("evaluationRuleRef"), inputs["evaluationRule"]):
        return result("rejected", "DRE-6", "evaluation rule input does not resolve")

    artifacts = value["artifacts"]
    delivered = inputs["deliveredArtifact"]
    if artifacts.get("delivery") is None:
        if delivered is not None:
            return result("rejected", "DRE-3", "deliveryless path contains an unreferenced deliverable input")
    elif not attestation_ref_valid(artifacts["delivery"].get("artifactRef"), delivered):
        return result("rejected", "DRE-3", "delivered artifact input does not resolve")
    dispute = inputs["disputeCase"]
    if artifacts.get("dispute") is None:
        if dispute is not None:
            return result("rejected", "DRX-2", "non-dispute path contains a dispute-case input")
    elif not attestation_ref_valid(artifacts["dispute"].get("caseRef"), dispute):
        return result("rejected", "DRX-2", "dispute-case input does not resolve")

    runtime = inputs["runtimeBytecode"]
    if not isinstance(runtime, dict) or runtime.get("encoding") != "utf-8":
        return result("error", "DRV-2", "runtime-bytecode preimage is malformed")
    runtime_value = runtime.get("value")
    if not isinstance(runtime_value, str):
        return result("error", "DRV-2", "runtime-bytecode preimage must be text")
    runtime_hash = hashlib.sha256(runtime_value.encode("utf-8")).hexdigest()
    if runtime.get("sha256") != runtime_hash or artifacts["job"].get("runtimeBytecodeHash") != runtime_hash:
        return result("rejected", "DRJ-5", "runtime-bytecode preimage does not match the job")

    event_inputs = inputs["nativeEventInputs"]
    if not isinstance(event_inputs, list) or not event_inputs:
        return result("error", "DRV-2", "native event inputs must be a non-empty array")
    by_identity: dict[tuple[str, int], dict[str, Any]] = {}
    for event_input_value in event_inputs:
        if not isinstance(event_input_value, dict):
            return result("error", "DRV-2", "native event input is malformed")
        ref_value = event_input_value.get("eventRef")
        preimage = event_input_value.get("txHashPreimageUtf8")
        if (
            not isinstance(ref_value, dict)
            or not isinstance(preimage, str)
            or ref_value.get("txHash") != "0x" + hashlib.sha256(preimage.encode("utf-8")).hexdigest()
        ):
            return result("rejected", "DRT-4", "native event transaction preimage does not match")
        identity = (ref_value.get("txHash"), ref_value.get("logIndex"))
        if identity in by_identity:
            return result("rejected", "DRT-4", "native event input identity is duplicated")
        by_identity[identity] = event_input_value

    expected_refs = [artifacts["job"]["creationEvent"]]
    expected_refs.extend(artifacts["funding"]["fundingEventRefs"])
    binding = value["deliveryBinding"]
    if artifacts.get("delivery") is not None:
        expected_refs.append(binding.get("nativeSubmissionEvent"))
    expected_refs.extend(artifacts["terminal"]["terminalEventRefs"])
    expected_identities = {
        (ref_value.get("txHash"), ref_value.get("logIndex"))
        for ref_value in expected_refs
        if isinstance(ref_value, dict)
    }
    if set(by_identity) != expected_identities:
        rule = "DRF-3" if not artifacts["funding"]["fundingEventRefs"] else "DRT-4"
        return result("rejected", rule, "native event inputs do not match the referenced event set")

    finality_preimages = (
        (artifacts["funding"]["finality"], inputs["fundingFinalityBlockHashPreimageUtf8"], "DRF-6"),
        (artifacts["terminal"]["finality"], inputs["terminalFinalityBlockHashPreimageUtf8"], "DRT-8"),
    )
    for finality_value, preimage, rule in finality_preimages:
        if not isinstance(preimage, str) or finality_value.get("blockHash") != "0x" + hashlib.sha256(preimage.encode("utf-8")).hexdigest():
            return result("rejected", rule, "finality block-hash preimage does not match")
    return None


def _native_event_semantics_check(value: dict[str, Any]) -> dict[str, str] | None:
    inputs = value["reproductionInputs"]["nativeEventInputs"]
    records = {item["eventName"]: item for item in inputs}
    artifacts = value["artifacts"]
    agreement = artifacts["agreement"]
    native = value["native"]
    expected_common = {
        "contractAddress": native["contractAddress"],
        "nativeJobId": artifacts["job"]["nativeJobId"],
    }
    if any(
        item.get("contractAddress") != expected_common["contractAddress"]
        or item.get("nativeJobId") != expected_common["nativeJobId"]
        for item in inputs
    ):
        return result("rejected", "DRT-4", "native event targets another contract or job")
    created = records.get("JobCreated", {}).get("arguments")
    if created != {
        "client": native["client"],
        "provider": native["provider"],
        "evaluator": native["evaluator"],
        "submissionCutoffSec": agreement["submissionCutoffSec"],
        "expiredAt": agreement["evaluationDeadlineSec"],
    }:
        return result("rejected", "DRJ-3", "creation/configuration event does not match the agreement")
    funded = records.get("JobFunded", {}).get("arguments")
    if funded != {"token": native["token"], "amountBaseUnits": agreement["budgetBaseUnits"]}:
        return result("rejected", "DRF-3", "funding event does not match the complete budget")
    if artifacts.get("delivery") is not None:
        submitted = records.get("JobSubmitted", {}).get("arguments")
        if submitted != {"deliverable": native["deliverable"]}:
            return result("rejected", "DRP-9", "submission event does not bind the delivery digest")
    terminal_name = {
        "complete": "JobCompleted",
        "reject": "JobRejected",
        "claimRefund": "JobExpired",
    }.get(native["terminalAction"])
    terminal = records.get(terminal_name, {}).get("arguments")
    if terminal != {
        "token": native["token"],
        "amountBaseUnits": artifacts["terminal"]["amountBaseUnits"],
        "recipient": artifacts["terminal"]["recipient"],
        "reason": native["reason"],
    }:
        return result("rejected", "DRT-4", "terminal event does not match the claimed disposition")
    return None


def _native_and_terminal_check(value: dict[str, Any]) -> dict[str, str] | None:
    a = value["artifacts"]
    agreement = a["agreement"]
    native = value["native"]
    if not isinstance(native, dict):
        return result("error", "DRV-2", "native evidence must be an object")
    chain_id = native.get("chainId")
    history = native.get("portableStateHistory")
    if not isinstance(history, list) or not history:
        return result("error", "DRV-2", "portable state history must be a non-empty array")
    portable_states = {"created", "funded", "submitted", "released", "refunded", "cancelled"}
    if any(state not in portable_states for state in history):
        return result("rejected", "DRL-2", "native state cannot be mapped to one portable state")
    allowed_transitions = {
        ("created", "funded"),
        ("created", "cancelled"),
        ("funded", "submitted"),
        ("funded", "refunded"),
        ("submitted", "released"),
        ("submitted", "refunded"),
    }
    if any(pair not in allowed_transitions for pair in zip(history, history[1:])):
        return result("rejected", "DRL-4", "portable state history contains an invalid or reopened transition")
    expected_history = (
        ["created", "funded", "submitted", "released"]
        if value["artifacts"]["terminal"].get("terminalState") == "released"
        else (
            ["created", "funded", "submitted", "refunded"]
            if value.get("submittedBeforeCutoff") is True
            else ["created", "funded", "refunded"]
        )
    )
    if history != expected_history:
        return result("rejected", "DRL-1", "portable state history does not match the lifecycle evidence")
    mapping_sources = value.get("mappingSources")
    if not isinstance(mapping_sources, dict):
        return result("error", "DRV-2", "mappingSources must be an object")
    expected_sources = {"agreementHash": artifact_hash(agreement)}
    if a.get("delivery") is not None:
        expected_sources["deliveryHash"] = artifact_hash(a["delivery"])
    if a.get("decision") is not None:
        expected_sources["decisionHash"] = artifact_hash(a["decision"])
    if set(mapping_sources) != set(expected_sources):
        return result("error", "DRV-2", "mapping source set does not match the lifecycle")
    for name, expected_hash in expected_sources.items():
        declared_hash = mapping_sources[name]
        if not isinstance(declared_hash, str) or HASH_RE.fullmatch(declared_hash) is None:
            return result("rejected", "DREB-3", f"{name} is not 64 lowercase hexadecimal characters")
        if declared_hash != expected_hash:
            return result("rejected", "DREB-2", f"{name} does not match the recomputed artifact hash")

    if native.get("description") != "dacs-delivery-remedy:v1:" + mapping_sources["agreementHash"]:
        return result("rejected", "DREB-1", "native description does not contain the exact overlay hash")
    if native.get("contractAddress") != a["job"].get("contractAddress"):
        return result("rejected", "DRJ-2", "native contract address mismatch")
    if native.get("runtimeBytecodeHash") != a["job"].get("runtimeBytecodeHash"):
        return result("rejected", "DRJ-5", "runtime bytecode hash mismatch")
    if native.get("payoutReceiver") != parse_canonical_evm_claim(agreement["seller"]["evmAccountClaim"])[1]:
        return result("rejected", "DREB-10", "native payout receiver is not the bound seller account")

    cutoff = agreement.get("submissionCutoffSec")
    deadline = agreement.get("evaluationDeadlineSec")
    profile = value.get("profileParameters")
    if type(cutoff) is not int or type(deadline) is not int or not isinstance(profile, dict):
        return result("error", "DRV-2", "deadline and profile fields must be present")
    minimum = profile.get("minimumEvaluationWindowSec")
    if type(minimum) is not int:
        return result("error", "DREB-14", "minimum evaluation window must be an integer")
    if minimum <= 0:
        return result("rejected", "DREB-14", "evaluation windows must be positive")
    if deadline - cutoff < minimum:
        return result("rejected", "DREB-14", "evaluation window is shorter than the pinned minimum")
    if profile.get("deadlineProfile") != "separate-submission-cutoff-v1":
        return result("rejected", "DREB-13", "unsupported native deadline profile")
    if (
        native.get("submissionCutoffSec") != cutoff
        or native.get("submissionCutoffEnforced") is not True
    ):
        return result("rejected", "DREB-13", "native submission cutoff is not separately enforced")
    if native.get("expiredAt") != deadline:
        return result("rejected", "DREB-12", "native expiredAt is not the evaluation deadline")
    if native.get("expiryRecoveryAtSec") != deadline:
        return result("rejected", "DREB-15", "native expiry recovery is not bound to the evaluation deadline")

    if a.get("delivery") is not None:
        expected_deliverable = "0x" + mapping_sources["deliveryHash"]
        provided = native.get("deliverable")
        if not isinstance(provided, str) or BYTES32_RE.fullmatch(provided) is None:
            return result("error", "DRV-2", "native deliverable is not canonical bytes32 text")
        if provided == "0x" + "00" * 32:
            return result("rejected", "DREB-5", "zero deliverable is forbidden")
        if provided != expected_deliverable:
            return result("rejected", "DREB-4", "deliverable is not the raw decoded content hash")
    elif native.get("deliverable") is not None:
        return result("rejected", "DRT-12", "pre-submission expiry cannot carry a deliverable")

    funding = a["funding"]
    funding_events = _event_refs_check(
        funding.get("fundingEventRefs"), chain_id, "DRF-3", "funding"
    )
    if funding_events:
        return funding_events
    funding_finality = _finality_check(
        funding.get("finality"),
        chain_id,
        profile.get("finalityBlocks"),
        "DRF-6",
        "funding",
    )
    if funding_finality:
        return funding_finality
    if (
        native.get("amountBaseUnits") != agreement.get("budgetBaseUnits")
        or native.get("token") != a["railDefinition"].get("paymentToken")
    ):
        return result("rejected", "DREB-11", "native token or budget does not match the agreement rail")
    if (
        funding.get("amountBaseUnits") != native.get("amountBaseUnits")
        or funding.get("token") != native.get("token")
    ):
        return result("rejected", "DRF-2", "funding token or complete budget mismatch")
    if funding.get("fundPhaseIndex") != agreement.get("fundPhaseIndex"):
        return result("rejected", "DRF-1", "funding phase index mismatch")
    if native.get("preterminalProviderPayoutBaseUnits") != "0":
        return result("rejected", "DRL-7", "provider received value before terminal release")
    if native.get("platformFeeBP") != 0 or native.get("evaluatorFeeBP") != 0:
        return result("rejected", "DRT-7", "escrow fee is nonzero")

    terminal = a["terminal"]
    decision = a.get("decision")
    evaluation = a.get("evaluation")
    dispute = a.get("dispute")
    state = terminal.get("terminalState")
    action = native.get("terminalAction")
    buyer_account = parse_canonical_evm_claim(agreement["buyer"]["evmAccountClaim"])[1]
    seller_account = parse_canonical_evm_claim(agreement["seller"]["evmAccountClaim"])[1]
    expected_amount = agreement["budgetBaseUnits"]

    if terminal.get("amountBaseUnits") != expected_amount or terminal.get("token") != native.get("token"):
        return result("rejected", "DRT-5", "terminal token or amount is not the complete budget")
    if native.get("terminalState") != state:
        return result("rejected", "DRT-4", "native and DACS terminal states diverge")
    terminal_events = _event_refs_check(
        terminal.get("terminalEventRefs"), chain_id, "DRT-4", "terminal"
    )
    if terminal_events:
        return terminal_events
    terminal_finality = _finality_check(
        terminal.get("finality"),
        chain_id,
        profile.get("finalityBlocks"),
        "DRT-8",
        "terminal",
    )
    if terminal_finality:
        return terminal_finality

    if decision is not None:
        expected_reason = "0x" + mapping_sources["decisionHash"]
        provided_reason = native.get("reason")
        if not isinstance(provided_reason, str) or BYTES32_RE.fullmatch(provided_reason) is None:
            return result("error", "DRV-2", "native decision reason is not canonical bytes32 text")
        if provided_reason == "0x" + "00" * 32:
            return result("rejected", "DREB-5", "zero decision reason is forbidden")
        if provided_reason != expected_reason:
            return result("rejected", "DREB-4", "reason is not the raw decoded decision hash")
        if artifact_hash(decision) in value.get("consumedDecisionHashes", []):
            return result("rejected", "DRD-8", "decision was already consumed by a terminal job")
        evaluator_account_type = native.get("evaluatorAccountType")
        if evaluator_account_type not in {"eoa", "eip1271"}:
            return result("error", "DREB-18", "unsupported evaluator account type")
        if native.get("evaluatorBindingMode") != "direct":
            return result("rejected", "DREB-16", "native evaluator is not bound directly")
        if native.get("evaluatorAdapter") is not None:
            return result("rejected", "DREB-20", "generic evaluator adapters are outside the profile")
        if native.get("terminalCaller") != native.get("evaluator"):
            return result("rejected", "DREB-21", "native terminal caller is not the bound evaluator account")
        submitter = native.get("transactionSubmitter")
        if not isinstance(submitter, str) or re.fullmatch(r"0x[0-9a-f]{40}", submitter) is None:
            return result("error", "DREB-22", "outer transaction submitter is malformed")
        if evaluator_account_type == "eoa" and submitter != native.get("terminalCaller"):
            return result("rejected", "DREB-22", "an EOA evaluator cannot have another transaction submitter")
        disposition = decision.get("disposition")
        if evaluation is not None:
            if evaluation.get("result") == "indeterminate":
                return result("rejected", "DRE-4", "indeterminate evaluation cannot authorize a terminal action")
            if evaluation.get("result") == "accept" and disposition != "release-to-provider":
                return result("rejected", "DRD-2", "accept evaluation does not authorize refund")
            if evaluation.get("result") == "reject" and disposition != "refund-to-client":
                return result("rejected", "DRD-2", "reject evaluation does not authorize release")
        elif dispute is not None:
            if value.get("submittedBeforeCutoff") is not False:
                return result("rejected", "DRD-12", "dispute-based decision is not a pre-submission path")
            if agreement.get("preSubmissionRefundPolicy") != "evaluator-rejection":
                return result("rejected", "DRA-15", "agreement does not authorize pre-submission rejection")
            if "deliveryEvidenceRef" in decision or "deliveryEvidenceRef" in terminal:
                return result("rejected", "DRD-9", "pre-submission rejection carries delivery evidence")
            if dispute.get("recommendedDisposition") != disposition or disposition != "refund-to-client":
                return result("rejected", "DRD-12", "dispute outcome does not authorize the refund")
        else:
            return result("rejected", "DRE-4", "decision has no authenticated evaluation or dispute basis")
        if disposition == "release-to-provider":
            if state != "released" or action != "complete":
                return result("rejected", "DRD-5", "release decision maps to a non-release action")
            if terminal.get("disposition") != disposition or terminal.get("recipient") != seller_account:
                return result("rejected", "DRT-5", "release recipient or disposition mismatch")
            projection = value.get("reputationProjection")
            if not isinstance(projection, dict) or type(
                projection.get("releaseAloneEstablishesNonFinancialCompletion")
            ) is not bool:
                return result("error", "DRV-2", "reputation projection is malformed")
            if projection["releaseAloneEstablishesNonFinancialCompletion"]:
                return result(
                    "rejected",
                    "DRL-6",
                    "financial release overclaims non-financial completion",
                )
        elif disposition == "refund-to-client":
            if state != "rejected-refund" or action != "reject":
                return result("rejected", "DRD-6", "refund decision maps to a non-rejection action")
            if terminal.get("disposition") != disposition or terminal.get("recipient") != buyer_account:
                return result("rejected", "DRT-6", "refund recipient or disposition mismatch")
        else:
            return result("error", "DRV-2", "unknown decision disposition")
    else:
        if state != "expired-refund" or action != "claimRefund":
            return result("rejected", "DRT-3", "decisionless terminal action is not expiry refund")
        if "decisionRef" in terminal or native.get("reason") is not None:
            return result("rejected", "DRD-7", "expiry recovery manufactures an evaluator decision")
        if terminal.get("disposition") != "refund-to-client" or terminal.get("recipient") != buyer_account:
            return result("rejected", "DRT-6", "expiry refund recipient mismatch")
        submitted = value.get("submittedBeforeCutoff")
        if type(submitted) is not bool:
            return result("error", "DRV-2", "submittedBeforeCutoff must be boolean")
        has_delivery_ref = "deliveryEvidenceRef" in terminal
        if submitted != has_delivery_ref:
            return result("rejected", "DRT-12", "expiry delivery-reference presence does not match submission state")
        projection = value.get("reputationProjection")
        if not isinstance(projection, dict) or (
            type(projection.get("buyerFault")) is not bool
            or type(projection.get("sellerFault")) is not bool
        ):
            return result("error", "DRV-2", "reputation projection is malformed")
        if projection["buyerFault"] or projection["sellerFault"]:
            return result("rejected", "DRT-13", "decisionless expiry invents buyer or seller fault")

    return _native_event_semantics_check(value)


def evaluate_protocol(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return result("error", "DRV-2", "vector input must be an object")
    required = {
        "candidateProfile", "fixtureOnly", "pipeline", "artifacts", "publicKeys",
        "orchestratorClaim", "evaluatorVetResult", "profileParameters", "native",
        "externalEvidence", "mappingSources", "canonicalRecords", "deliveryBinding",
        "bundleRequiredSigners", "reputationProjection", "submittedBeforeCutoff",
        "consumedDecisionHashes",
        "reproductionInputs",
        "executionContext",
    }
    if not required.issubset(value):
        return result("error", "DRV-2", "vector input is missing required fields")
    if value.get("candidateProfile") != "delivery-or-remedy-v1" or value.get("fixtureOnly") is not True:
        return result("error", "DRV-1", "only offline candidate-profile fixtures are accepted")
    object_fields = (
        "artifacts", "publicKeys", "profileParameters", "mappingSources",
        "canonicalRecords", "native", "externalEvidence",
    )
    if not all(isinstance(value.get(field), dict) for field in object_fields):
        return result("error", "DRV-2", "candidate object fields are malformed")
    if not isinstance(value.get("consumedDecisionHashes"), list):
        return result("error", "DRV-2", "consumedDecisionHashes must be an array")

    shape = _artifact_shape_check(value["artifacts"])
    if shape:
        return shape
    pipeline = _pipeline_check(value)
    if pipeline:
        return pipeline
    agreement = _agreement_check(value)
    if agreement:
        return agreement
    signatures = _component_signature_check(value)
    if signatures:
        return signatures
    references = _reference_check(value)
    if references:
        return references
    finding = _finding_check(value)
    if finding:
        return finding
    canonical_records = _canonical_record_check(value)
    if canonical_records:
        return canonical_records
    delivery_binding = _delivery_binding_check(value)
    if delivery_binding:
        return delivery_binding
    external = _external_evidence_check(value)
    if external:
        return external
    reproduction = _reproduction_input_check(value)
    if reproduction:
        return reproduction
    native = _native_and_terminal_check(value)
    if native:
        return native
    return result("verified", "DRV-7", "all applicable candidate checks passed")


def _status(values: list[Any], predicate) -> str:
    if any(value is None for value in values):
        return "unknown"
    return "pass" if predicate(*values) else "fail"


def deployment_rule_statuses(manifest: Any) -> dict[str, str] | None:
    if not isinstance(manifest, dict):
        return None
    capabilities = manifest.get("capabilities")
    evidence = manifest.get("evidence")
    if not isinstance(capabilities, dict) or not isinstance(evidence, dict):
        return None

    statuses: dict[str, str] = {}
    paths = capabilities.get("preterminalProviderPayoutPaths")
    statuses["DRC-1"] = "unknown" if paths is None else ("pass" if paths == [] else "fail")

    fee_values = [
        capabilities.get("platformFeeBP"), capabilities.get("evaluatorFeeBP"),
        capabilities.get("feeMutationAuthorities"),
    ]
    statuses["DRC-2"] = _status(
        fee_values,
        lambda platform, evaluator, authorities: (
            type(platform) is int and platform == 0
            and type(evaluator) is int and evaluator == 0
            and authorities == []
        ),
    )

    recovery_values = [
        capabilities.get("expiryRecoveryPauseGated"),
        capabilities.get("expiryRecoveryHookGated"),
        capabilities.get("evaluatorCanBlockExpiryRecovery"),
        capabilities.get("pendingClaimCanDelayFundedRecovery"),
    ]
    statuses["DRC-3"] = _status(
        recovery_values,
        lambda *items: all(type(item) is bool and item is False for item in items),
    )

    alternate = capabilities.get("lockedFundAlternateWithdrawalAuthorities")
    statuses["DRC-4"] = "unknown" if alternate is None else ("pass" if alternate == [] else "fail")

    replacement_values = [
        capabilities.get("logicReplacementAuthorities"),
        capabilities.get("hookMutable"),
    ]
    statuses["DRC-5"] = _status(
        replacement_values,
        lambda authorities, mutable: authorities == [] and type(mutable) is bool and mutable is False,
    )

    syntactic = capabilities.get("upgradeableSyntactically")
    if syntactic is None:
        statuses["DRC-6"] = "unknown"
    elif type(syntactic) is bool and syntactic is False:
        statuses["DRC-6"] = "pass"
    elif type(syntactic) is bool:
        disabled = capabilities.get("upgradeAuthorityIrreversiblyDisabled")
        proof = evidence.get("upgradeDisablementAuthenticated")
        statuses["DRC-6"] = _status([disabled, proof], lambda left, right: left is True and right is True)
    else:
        statuses["DRC-6"] = "fail"

    hook_mode = capabilities.get("hookMode")
    statuses["DRC-7"] = "unknown" if hook_mode is None else (
        "pass" if hook_mode in {"absent", "immutable-nonblocking"} else "fail"
    )

    token = capabilities.get("paymentTokenSemantics")
    token_flags = (
        "transferFees", "rebasing", "callbacks", "pause", "blacklist", "externalBalanceMutation"
    )
    if not isinstance(token, dict) or any(token.get(name) is None for name in token_flags) or token.get("independentlyVerified") is None:
        statuses["DRC-8"] = "unknown"
    else:
        statuses["DRC-8"] = "pass" if (
            all(type(token[name]) is bool and token[name] is False for name in token_flags)
            and type(token["independentlyVerified"]) is bool
            and token["independentlyVerified"] is True
        ) else "fail"

    event_complete = capabilities.get("eventIdentityComplete")
    statuses["DRC-9"] = "unknown" if event_complete is None else (
        "pass" if type(event_complete) is bool and event_complete is True else "fail"
    )

    source_values = [
        evidence.get("sourceRevision"), evidence.get("compilerSettingsHash"),
        evidence.get("runtimeBytecodeHash"), evidence.get("independentlyResolvedRuntimeBytecodeHash"),
        evidence.get("sourceToBytecodeReproducible"),
    ]
    statuses["DRC-10"] = _status(
        source_values,
        lambda source, compiler, runtime, resolved, reproducible: (
            isinstance(source, str) and bool(source)
            and isinstance(compiler, str) and HASH_RE.fullmatch(compiler) is not None
            and isinstance(runtime, str) and HASH_RE.fullmatch(runtime) is not None
            and runtime == resolved and type(reproducible) is bool and reproducible is True
        ),
    )

    complete = evidence.get("complete")
    conflict = evidence.get("conflict")
    statuses["DRC-11"] = _status(
        [complete, conflict],
        lambda is_complete, has_conflict: (
            type(is_complete) is bool and is_complete is True
            and type(has_conflict) is bool and has_conflict is False
        ),
    )

    ordering_values = [
        capabilities.get("decisionOrderingProfile"),
        evidence.get("decisionOrderingEvidenceAuthenticated"),
    ]
    statuses["DRC-12"] = _status(
        ordering_values,
        lambda profile, authenticated: (
            isinstance(profile, str) and bool(profile)
            and type(authenticated) is bool and authenticated is True
        ),
    )
    deadline_values = [
        capabilities.get("deadlineProfile"),
        capabilities.get("submissionCutoffEnforced"),
        capabilities.get("expiryRecoveryDeadlineEnforced"),
        evidence.get("deadlineEnforcementAuthenticated"),
    ]
    statuses["DRC-13"] = _status(
        deadline_values,
        lambda profile, cutoff, recovery, authenticated: (
            profile == "separate-submission-cutoff-v1"
            and type(cutoff) is bool and cutoff is True
            and type(recovery) is bool and recovery is True
            and type(authenticated) is bool and authenticated is True
        ),
    )
    return statuses


def evaluate_deployment(manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        return {
            **result("error", "DRV-2", "deployment manifest must be an object"),
            "ruleStatuses": {},
            "registrationEligible": False,
        }
    required = {
        "manifestVersion", "candidateProfile", "fixtureOnly", "registrationStatus",
        "implementation", "capabilities", "evidence",
    }
    if not required.issubset(manifest) or manifest.get("manifestVersion") != "1":
        return {
            **result("error", "DRV-2", "malformed deployment manifest"),
            "ruleStatuses": {},
            "registrationEligible": False,
        }
    if manifest.get("candidateProfile") != "dacs-delivery-gate-v1":
        return {
            **result("error", "DRV-2", "unsupported deployment capability profile"),
            "ruleStatuses": {},
            "registrationEligible": False,
        }
    if type(manifest.get("fixtureOnly")) is not bool:
        return {
            **result("error", "DRV-2", "fixtureOnly must be boolean"),
            "ruleStatuses": {},
            "registrationEligible": False,
        }
    statuses = deployment_rule_statuses(manifest)
    if statuses is None or set(statuses) != DRC_RULES:
        return {
            **result("error", "DRV-2", "could not derive every DRC rule"),
            "ruleStatuses": {},
            "registrationEligible": False,
        }
    failed = sorted(
        (rule for rule, status in statuses.items() if status == "fail"),
        key=lambda item: int(item.split("-")[1]),
    )
    unknown = sorted(
        (rule for rule, status in statuses.items() if status == "unknown"),
        key=lambda item: int(item.split("-")[1]),
    )
    if failed:
        outcome: dict[str, Any] = result("rejected", failed[0], "failed deployment rules: " + ", ".join(failed))
    elif unknown:
        outcome = result("indeterminate", unknown[0], "unresolved deployment rules: " + ", ".join(unknown))
    else:
        outcome = result("verified", "DRC-1..DRC-13", "all candidate deployment capability rules passed")
    outcome["ruleStatuses"] = statuses
    outcome["registrationEligible"] = bool(
        outcome["result"] == "verified"
        and manifest["fixtureOnly"] is False
        and manifest.get("registrationStatus") == "registered"
    )
    return outcome


def _pack_hash(pack: dict[str, Any], fields: tuple[str, ...]) -> str:
    return hashlib.sha256(canonical_bytes({field: pack[field] for field in fields})).hexdigest()


def verify_vector_pack(pack: Any) -> list[str]:
    if not isinstance(pack, dict):
        return ["candidate vector pack must be an object"]
    required = {
        "kind", "status", "spec", "generator", "hash", "count", "fixtures",
        "vectors", "promotionBlockedRules",
    }
    if not required.issubset(pack):
        return ["candidate vector pack is missing required top-level fields"]
    errors: list[str] = []
    vectors = pack.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        return ["candidate vector pack must contain vectors"]
    if pack.get("count") != len(vectors):
        errors.append("candidate vector count is stale")
    if pack.get("hash") != _pack_hash(
        pack, ("fixtures", "vectors", "promotionBlockedRules")
    ):
        errors.append("candidate vector pack hash is stale")
    blocked = pack.get("promotionBlockedRules")
    if not isinstance(blocked, dict) or not all(
        isinstance(rule, str)
        and isinstance(reason, str)
        and bool(reason.strip())
        for rule, reason in blocked.items()
    ):
        errors.append("promotion-blocked rules must map rule IDs to non-empty reasons")
    names: set[str] = set()
    for vector in vectors:
        name = vector.get("name") if isinstance(vector, dict) else None
        if not isinstance(name, str) or not name or name in names:
            errors.append(f"invalid or duplicate candidate vector name: {name!r}")
            continue
        names.add(name)
        rules = vector.get("rules")
        if (
            not isinstance(rules, list)
            or not rules
            or any(not isinstance(rule, str) for rule in rules)
            or rules != sorted(set(rules))
        ):
            errors.append(f"{name}: rules must be a non-empty sorted unique list")
        try:
            observed = evaluate_protocol(materialize_vector(pack, vector))
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            errors.append(f"{name}: could not materialize: {exc}")
            continue
        if observed.get("result") != vector.get("expected"):
            errors.append(
                f"{name}: expected {vector.get('expected')!r}, got {observed.get('result')!r} "
                f"({observed.get('rule')}: {observed.get('detail')})"
            )
        expected_rule = vector.get("expectedRule")
        if expected_rule is not None and observed.get("rule") != expected_rule:
            errors.append(f"{name}: expected rule {expected_rule}, got {observed.get('rule')}")
    return errors


def verify_deployment_pack(pack: Any) -> list[str]:
    if not isinstance(pack, dict):
        return ["deployment capability pack must be an object"]
    required = {"kind", "status", "spec", "sourcePins", "hash", "count", "manifests", "cases"}
    if not required.issubset(pack):
        return ["deployment capability pack is missing required top-level fields"]
    errors: list[str] = []
    cases = pack.get("cases")
    manifests = pack.get("manifests")
    if not isinstance(cases, list) or not cases or not isinstance(manifests, dict):
        return ["deployment capability pack needs manifests and cases"]
    if pack.get("count") != len(cases):
        errors.append("deployment capability case count is stale")
    if pack.get("hash") != _pack_hash(pack, ("manifests", "cases")):
        errors.append("deployment capability pack hash is stale")
    names: set[str] = set()
    for case in cases:
        name = case.get("name") if isinstance(case, dict) else None
        if not isinstance(name, str) or not name or name in names:
            errors.append(f"invalid or duplicate deployment case name: {name!r}")
            continue
        names.add(name)
        rules = case.get("rules")
        if (
            not isinstance(rules, list)
            or any(not isinstance(rule, str) for rule in rules)
            or rules != sorted(set(rules))
        ):
            errors.append(f"{name}: rules must be a sorted unique list")
        base = case.get("base")
        if base not in manifests:
            errors.append(f"{name}: unknown manifest base {base!r}")
            continue
        manifest = copy.deepcopy(manifests[base])
        try:
            for operation in case.get("patch", []):
                manifest = apply_operation(manifest, operation)
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            errors.append(f"{name}: could not materialize: {exc}")
            continue
        observed = evaluate_deployment(manifest)
        if observed["result"] != case.get("expected"):
            errors.append(
                f"{name}: expected {case.get('expected')!r}, got {observed['result']!r} "
                f"({observed['rule']}: {observed['detail']})"
            )
        if observed["registrationEligible"] != case.get("registrationEligible", False):
            errors.append(f"{name}: registration eligibility was not fail-closed")
        expected_failed = case.get("expectedFailedRules")
        if expected_failed is not None:
            actual_failed = sorted(
                (rule for rule, status in observed["ruleStatuses"].items() if status == "fail"),
                key=lambda item: int(item.split("-")[1]),
            )
            if actual_failed != expected_failed:
                errors.append(f"{name}: expected failed rules {expected_failed}, got {actual_failed}")
        expected_unknown = case.get("expectedUnknownRules")
        if expected_unknown is not None:
            actual_unknown = sorted(
                (rule for rule, status in observed["ruleStatuses"].items() if status == "unknown"),
                key=lambda item: int(item.split("-")[1]),
            )
            if actual_unknown != expected_unknown:
                errors.append(f"{name}: expected unknown rules {expected_unknown}, got {actual_unknown}")
    return errors


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vectors", type=Path, default=DEFAULT_VECTOR_PACK)
    parser.add_argument("--deployments", type=Path, default=DEFAULT_DEPLOYMENT_PACK)
    args = parser.parse_args(argv)
    errors: list[str] = []
    for path, verifier in (
        (args.vectors, verify_vector_pack),
        (args.deployments, verify_deployment_pack),
    ):
        try:
            errors.extend(f"{path.relative_to(ROOT)}: {message}" for message in verifier(load_json(path)))
        except FileNotFoundError:
            errors.append(f"{path}: file not found")
        except json.JSONDecodeError as exc:
            errors.append(f"{path}: invalid JSON: {exc}")
    if errors:
        print("delivery-or-remedy candidate verification failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    vector_pack = load_json(args.vectors)
    deployment_pack = load_json(args.deployments)
    print(
        "verified delivery-or-remedy candidate packs: "
        f"{vector_pack['count']} lifecycle/mapping case(s), "
        f"{deployment_pack['count']} deployment case(s); no rail registered"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
