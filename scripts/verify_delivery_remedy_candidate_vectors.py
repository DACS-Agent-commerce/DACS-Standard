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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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

DOMAINS = {
    "agreement": "dacs-delivery-remedy-agreement:v1:",
    "job": "dacs-escrow-job-ref:v1:",
    "funding": "dacs-escrow-funding-evidence:v1:",
    "delivery": "dacs-evidence:v1:",
    "evaluation": "dacs-execution-evaluation:v1:",
    "decision": "dacs-escrow-decision:v1:",
    "terminal": "dacs-escrow-terminal-evidence:v1:",
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
}
EXTERNAL_STATES = {"verified", "not-applicable", "unavailable", "contradictory"}
DRC_RULES = {f"DRC-{number}" for number in range(1, 13)}


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


def _pipeline_check(pipeline: Any, agreement: dict[str, Any]) -> dict[str, str] | None:
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
    for name in ("job", "funding", "delivery", "evaluation", "decision", "terminal"):
        artifact = artifacts.get(name)
        if artifact is not None and (
            not isinstance(artifact, dict) or artifact.get("jobId") != job_id
        ):
            return result("rejected", "DRD-8", f"{name} is bound to another job")
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
            return result("rejected", "DRE-1" if name in {"evaluation", "decision"} else "DRV-4", f"invalid {name} signature")
    return None


def _reference_check(value: dict[str, Any]) -> dict[str, str] | None:
    a = value["artifacts"]
    agreement_hash = artifact_hash(a["agreement"])
    for name in ("job", "funding", "evaluation", "decision", "terminal"):
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
        rule = "DRD-10" if "decisionOrdering" in unavailable else "DRV-2"
        return result("indeterminate", rule, "required external evidence unavailable: " + ", ".join(unavailable))
    return None


def _native_and_terminal_check(value: dict[str, Any]) -> dict[str, str] | None:
    a = value["artifacts"]
    agreement = a["agreement"]
    native = value["native"]
    if not isinstance(native, dict):
        return result("error", "DRV-2", "native evidence must be an object")
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

    cutoff = agreement.get("submissionCutoffSec")
    deadline = agreement.get("evaluationDeadlineSec")
    profile = value.get("profileParameters")
    if type(cutoff) is not int or type(deadline) is not int or not isinstance(profile, dict):
        return result("error", "DRV-2", "deadline and profile fields must be present")
    grace = profile.get("evaluationGracePeriodSec")
    minimum = profile.get("minimumEvaluationWindowSec")
    if type(grace) is not int or type(minimum) is not int:
        return result("error", "DREB-14", "evaluation windows must be integers")
    if grace <= 0 or minimum <= 0:
        return result("rejected", "DREB-14", "evaluation windows must be positive")
    if deadline != cutoff + grace or deadline - cutoff < minimum:
        return result("rejected", "DREB-13", "evaluation deadline does not match the pinned grace and minimum")
    if native.get("expiredAt") != cutoff or native.get("evaluationDeadlineSec") != deadline:
        return result("rejected", "DREB-12", "native deadline mapping mismatch")

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
    if (
        funding.get("amountBaseUnits") != agreement.get("budgetBaseUnits")
        or native.get("amountBaseUnits") != agreement.get("budgetBaseUnits")
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
    state = terminal.get("terminalState")
    action = native.get("terminalAction")
    buyer_account = parse_canonical_evm_claim(agreement["buyer"]["evmAccountClaim"])[1]
    seller_account = parse_canonical_evm_claim(agreement["seller"]["evmAccountClaim"])[1]
    expected_amount = agreement["budgetBaseUnits"]

    if terminal.get("amountBaseUnits") != expected_amount or terminal.get("token") != native.get("token"):
        return result("rejected", "DRT-5", "terminal token or amount is not the complete budget")
    if native.get("terminalState") != state:
        return result("rejected", "DRT-4", "native and DACS terminal states diverge")
    terminal_finality = terminal.get("finality")
    if not isinstance(terminal_finality, dict):
        return result("error", "DRV-2", "terminal finality must be an object")
    if terminal_finality.get("status") != "finalized":
        return result("indeterminate", "DRT-8", "terminal finality is unavailable")

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
        if evaluation is None or evaluation.get("result") == "indeterminate":
            return result("rejected", "DRE-4", "indeterminate or absent evaluation cannot authorize a terminal action")
        disposition = decision.get("disposition")
        if evaluation.get("result") == "accept" and disposition != "release-to-provider":
            return result("rejected", "DRD-2", "accept evaluation does not authorize refund")
        if evaluation.get("result") == "reject" and disposition != "refund-to-client":
            return result("rejected", "DRD-2", "reject evaluation does not authorize release")
        if disposition == "release-to-provider":
            if state != "released" or action != "complete":
                return result("rejected", "DRD-5", "release decision maps to a non-release action")
            if terminal.get("disposition") != disposition or terminal.get("recipient") != seller_account:
                return result("rejected", "DRT-5", "release recipient or disposition mismatch")
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
        submitted = value.get("submittedBeforeExpiry")
        if type(submitted) is not bool:
            return result("error", "DRV-2", "submittedBeforeExpiry must be boolean")
        has_delivery_ref = "deliveryEvidenceRef" in terminal
        if submitted != has_delivery_ref:
            return result("rejected", "DRT-12", "expiry delivery-reference presence does not match submission state")

    return None


def evaluate_protocol(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return result("error", "DRV-2", "vector input must be an object")
    required = {
        "candidateProfile", "fixtureOnly", "pipeline", "artifacts", "publicKeys",
        "orchestratorClaim", "evaluatorVetResult", "profileParameters", "native",
        "externalEvidence", "mappingSources", "canonicalRecords", "submittedBeforeExpiry", "consumedDecisionHashes",
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
    pipeline = _pipeline_check(value["pipeline"], value["artifacts"]["agreement"])
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
    canonical_records = _canonical_record_check(value)
    if canonical_records:
        return canonical_records
    external = _external_evidence_check(value)
    if external:
        return external
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
        outcome = result("verified", "DRC-1..DRC-12", "all candidate deployment capability rules passed")
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
    required = {"kind", "status", "spec", "generator", "hash", "count", "fixtures", "vectors"}
    if not required.issubset(pack):
        return ["candidate vector pack is missing required top-level fields"]
    errors: list[str] = []
    vectors = pack.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        return ["candidate vector pack must contain vectors"]
    if pack.get("count") != len(vectors):
        errors.append("candidate vector count is stale")
    if pack.get("hash") != _pack_hash(pack, ("fixtures", "vectors")):
        errors.append("candidate vector pack hash is stale")
    names: set[str] = set()
    for vector in vectors:
        name = vector.get("name") if isinstance(vector, dict) else None
        if not isinstance(name, str) or not name or name in names:
            errors.append(f"invalid or duplicate candidate vector name: {name!r}")
            continue
        names.add(name)
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
