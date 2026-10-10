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
from typing import Any, Callable, NamedTuple

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

# The synthetic fixture resolver is a verifier-pinned trust anchor (DRV-1).
# `publicKeys` in a vector covers only DACS parties.
FIXTURE_RESOLVER_CLAIM = "did:demos:agent:" + "99" * 32
PINNED_RESOLVER_KEYS = {
    FIXTURE_RESOLVER_CLAIM: "iln7hKoVj-cofK9mAaE1yj8OiplfupJiIg1nFjqhqfA",
}
RESOLVER_DOMAIN = "dacs-x-delivery-remedy-fixture-resolver:v1:"
RESOLVER_EVIDENCE_FIELDS = {
    "resolverEvidenceVersion",
    "resolver",
    "jobId",
    "railDefinitionHash",
    "chainId",
    "contractAddress",
    "nativeJobId",
    "eventObservationsHash",
    "terminalCall",
    "priorTerminals",
    "nativeState",
    "deliveryDigestAnchor",
    "statuses",
    "signature",
}
# The block in which the exact delivery digest was anchored, or null when the
# resolver has no such evidence (DRP-9).  A synthetic fixture boundary.
DIGEST_ANCHOR_FIELDS = {"deliverable", "blockNumber", "blockTimestampSec"}
TERMINAL_CALL_FIELDS = {"txHash", "outerSubmitter", "nativeCaller", "nativeCallerAccountType"}
# One terminal transaction the resolver observed before this lifecycle's
# terminal event, for this native job or consuming this decision.
PRIOR_TERMINAL_FIELDS = {
    "chainId", "contractAddress", "nativeJobId", "txHash", "logIndex", "decisionHash",
}
# Resolved native job state and immutable capability facts (DREB-13, DREB-15,
# DREB-16, DREB-20, DRL-7, DRT-7).  The verifier reads them only from here.
NATIVE_STATE_FIELDS = {
    "submissionCutoffEnforced",
    "expiryRecoveryAtSec",
    "preterminalProviderPayoutBaseUnits",
    "platformFeeBP",
    "evaluatorFeeBP",
    "evaluatorBindingMode",
    "evaluatorAdapter",
}
# The fixture's delivery SettlementEvidence: the DACS-4 §9.7 members that a
# successful storage-program delivery carries (DRE-2, DRP-7).  A failure
# outcome adds `reason` and may omit the deliverable members, which §9.7
# makes optional.  §9.7 has no phase-index member; the phase is the single
# agreement-bound delivery step (DRP-3, DRA-11).
DELIVERY_EVIDENCE_FIELDS = {
    "evidenceVersion", "jobId", "phase", "outcome", "deliverableContentHash",
    "deliverableAnchor", "observedAt", "signature",
}
DELIVERABLE_FIELDS = {"deliverableContentHash", "deliverableAnchor"}
DELIVERY_OUTCOMES = {"success", "failure"}
EVALUATION_RESULTS = {"accept", "reject", "indeterminate"}
DECISION_DISPOSITIONS = {"release-to-provider", "refund-to-client"}
# The only evaluation results that can authorize a settlement, and the one
# disposition each authorizes.  Every other result fails closed.
SETTLEMENT_AUTHORIZATIONS = {
    "accept": "release-to-provider",
    "reject": "refund-to-client",
}

# Every resolver status and the rule an `unavailable` outcome reports, in
# reporting priority.  A new status is added here and nowhere else.
UNAVAILABLE_STATUS_RULES = {
    "decisionOrdering": "DRD-10",
    "fundingFinality": "DRF-6",
    "deliveryFinality": "DRE-5",
    "decisionFinality": "DRD-4",
    "terminalFinality": "DRT-9",
    "nativeStateResolution": "DRL-3",
    "codeResolution": "DRJ-7",
    "authorityResolution": "DRJ-7",
    "railResolution": "DRC-11",
    "agreementResolution": "DRV-2",
}
EXTERNAL_EVIDENCE_FIELDS = frozenset(UNAVAILABLE_STATUS_RULES)
EXTERNAL_STATES = {"verified", "not-applicable", "unavailable", "contradictory"}
PORTABLE_STATES = {"created", "funded", "submitted", "released", "refunded", "cancelled"}
PORTABLE_TRANSITIONS = {
    ("created", "funded"),
    ("created", "cancelled"),
    ("funded", "submitted"),
    ("funded", "refunded"),
    ("submitted", "released"),
    ("submitted", "refunded"),
}
ZERO_BYTES32 = "0x" + "00" * 32
DRC_RULES = {f"DRC-{number}" for number in range(1, 14)}
PROFILE_FIELDS = {
    "minimumEvaluationWindowSec",
    "deadlineProfile",
    "finalityBlocks",
    "decisionOrderingProfile",
    "platformFeeBP",
    "evaluatorFeeBP",
    "capabilityProfile",
}
EVENT_INPUT_FIELDS = {
    "eventRef",
    "txHashPreimageUtf8",
    "blockNumber",
    "blockHash",
    "blockHashPreimageUtf8",
    "blockTimestampSec",
    "confirmations",
    "contractAddress",
    "nativeJobId",
    "eventName",
    "arguments",
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
    signer_field: str = "signer",
) -> bool:
    if not isinstance(signature, dict):
        return False
    if signature.get("algorithm") != "ed25519":
        return False
    if signature.get(signer_field) != expected_signer:
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


def attestation_ref_shape_valid(ref: Any) -> bool:
    return (
        isinstance(ref, dict)
        and set(ref) == {"kind", "locator", "contentHash"}
        and all(isinstance(ref[name], str) and ref[name] for name in ("kind", "locator"))
        and isinstance(ref["contentHash"], str)
        and HASH_RE.fullmatch(ref["contentHash"]) is not None
    )


def _event_ref_check(
    ref_value: Any, chain_id: Any, rule: str, label: str
) -> dict[str, str] | None:
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
    return None


def _event_identity(ref_value: Any) -> tuple[Any, Any, Any, Any] | None:
    if not isinstance(ref_value, dict):
        return None
    identity = (
        ref_value.get("kind"),
        ref_value.get("chainId"),
        ref_value.get("txHash"),
        ref_value.get("logIndex"),
    )
    if not all(isinstance(part, (str, int)) for part in identity):
        return None
    return identity


def _finality_check(
    finality: Any,
    minimum_confirmations: int,
    observation: dict[str, Any],
    rule: str,
    label: str,
) -> dict[str, str] | None:
    """Check a signed DACS-4 record; its event's depth was checked when observed."""
    if not isinstance(finality, dict) or set(finality) != {
        "model", "finalityBlocks", "finalityObservedAt"
    }:
        return result("error", "DRV-2", f"{label} finality is not an exact DACS-4 block-depth record")
    finality_blocks = finality.get("finalityBlocks")
    observed_at = finality.get("finalityObservedAt")
    if (
        type(finality_blocks) is not int
        or finality_blocks <= 0
        or type(observed_at) is not int
        or observed_at < 0
    ):
        return result("error", "DRV-2", f"{label} finality record is malformed")
    if finality.get("model") != "block-depth" or finality_blocks != minimum_confirmations:
        return result("rejected", rule, f"{label} finality does not match the rail profile")
    if observed_at < observation["blockTimestampSec"] * 1000:
        return result("rejected", rule, f"{label} finality predates its event block")
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


class TerminalRecord(NamedTuple):
    """One terminal transaction: its native job, its event, and its decision.

    ``position`` is the terminal event's authenticated canonical position on
    its chain: (block number, block-scoped log index).  An EVM log index
    counts logs across the whole block, so it already orders transactions
    within a block.  A resolver-attested earlier terminal has no position:
    the resolver attests that it precedes this lifecycle's terminal.
    ``attested`` holds the identities (native job, event, decision) of the
    earlier terminals in this terminal's resolver-attested history.
    """

    job: tuple[Any, Any, Any]
    event: tuple[Any, Any, Any]
    decision: str | None
    position: tuple[int, int] | None = None
    attested: tuple[tuple[Any, Any, Any], ...] = ()


def terminal_conflict(prior: TerminalRecord, current: TerminalRecord) -> tuple[str, str] | None:
    """Return the rule and detail when two terminal records cannot both hold.

    The same terminal presented again is not a conflict.  A decision
    authorizes one terminal transaction (DRD-8); a native job reaches one
    terminal state (DRL-4); one terminal event settles one native job (DRT-4).
    """
    if prior[:3] == current[:3]:
        return None
    if current.decision is not None and prior.decision == current.decision:
        return "DRD-8", "the decision already authorized another terminal transaction"
    if prior.job == current.job:
        return "DRL-4", "the native job already reached a terminal state through another transaction"
    if prior.event == current.event:
        return "DRT-4", "the terminal event already settled another native job"
    return None


def terminal_precedes(prior: TerminalRecord, current: TerminalRecord) -> bool | None:
    """Whether ``prior`` is the earlier terminal by authenticated event position.

    Returns None when the authenticated positions cannot order the two: the
    same position, or events on different chains.  The order in which the
    verifier received the evidence is never consulted.
    """
    if prior.position is None:
        return True
    if prior.event[0] != current.event[0] or prior.position == current.position:
        return None
    return prior.position < current.position


class DecisionLedger:
    """Verifier-owned, in-memory set of authenticated terminals this verifier evaluated.

    The ledger belongs to the verifier, not to the evidence producer: a vector
    cannot seed or clear it.  It records every terminal whose lifecycle passed
    every check before the replay comparison, whatever that comparison
    decided, and lists them in canonical position order, so a verdict depends
    on the evidence seen and not on its arrival order.  It also keeps the
    verdict it last issued for each recorded terminal, so that a later
    evaluation can revise it.  It is not durable and does not enforce one use
    across processes.
    """

    def __init__(self) -> None:
        self._terminals: list[TerminalRecord] = []
        self._issued: dict[TerminalRecord, dict[str, str]] = {}

    def terminals(self) -> tuple[TerminalRecord, ...]:
        return tuple(sorted(self._terminals, key=lambda item: (
            item.position is None, item.position or (), repr(item[:3]), repr(item.attested),
        )))

    def record(self, terminal: TerminalRecord) -> None:
        if terminal not in self._terminals:
            self._terminals.append(terminal)

    def issued(self, terminal: TerminalRecord) -> dict[str, str] | None:
        """The verdict last issued for the lifecycle that recorded ``terminal``."""
        return self._issued.get(terminal)

    def issue(self, terminal: TerminalRecord, verdict: dict[str, str]) -> None:
        self._issued[terminal] = dict(verdict)


def terminal_identity(terminal: TerminalRecord) -> dict[str, Any]:
    """Name a recorded terminal exactly.

    The native job, event, and decision, as a `priorTerminals` entry names
    them, plus the event's block and the attested `priorTerminals` history.
    """
    def entry(job: tuple[Any, ...], event: tuple[Any, ...], decision: Any) -> dict[str, Any]:
        return {
            "chainId": job[0],
            "contractAddress": job[1],
            "nativeJobId": job[2],
            "txHash": event[1],
            "logIndex": event[2],
            "decisionHash": decision,
        }

    return {
        **entry(*terminal[:3]),
        "blockNumber": None if terminal.position is None else terminal.position[0],
        "priorTerminals": [entry(*prior) for prior in terminal.attested],
    }


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
    # Escrow indexes ascend, so the actions alone fix the fund-then-terminal
    # order.  Both phases' rails are bound to the selected rail later (DRP-5).
    if fund["parameters"].get("action") != "fund" or terminal["parameters"].get("action") != "terminal":
        return result("rejected", "DRP-2", "escrow actions are not fund then terminal")

    delivery_indexes = [i for i, step in enumerate(pipeline) if step["kind"].startswith("deliver-")]
    if len(delivery_indexes) != 1 or not (fund_index < delivery_indexes[0] < terminal_index):
        return result("rejected", "DRP-3", "exactly one delivery must occur between escrow steps")
    if any(step["kind"].startswith("pay-") for step in pipeline):
        return result("rejected", "DRP-4", "ordinary payment phases cannot accompany the escrow pair")
    supported_kinds = {
        "commit-delivery-or-remedy-agreement",
        "job-escrow",
        "deliver-storage-program",
        "deliver-entitlement",
        "deliver-attested-payload",
        "rate",
    }
    # Payment phases are DRP-4 findings above, not unsupported kinds.
    if any(
        step["kind"] not in supported_kinds and not step["kind"].startswith("pay-")
        for step in pipeline
    ):
        return result("error", "DRV-2", "pipeline contains an unsupported phase kind")
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
    if evaluation is not None:
        sequence = evaluation.get("evaluationSeq")
        if type(sequence) is not int or sequence < 0:
            return result("error", "DRAA-2", "evaluationSeq is not minimal unsigned integer form")
        elif sequence != 0:
            return result("rejected", "DRAA-6", "first evaluation sequence is not zero")
    if evaluation is not None and evaluation.get("result") not in tuple(EVALUATION_RESULTS):
        return result("error", "DRV-2", "evaluation result is not a supported discriminator")
    decision = artifacts.get("decision")
    if decision is not None and decision.get("disposition") not in tuple(DECISION_DISPOSITIONS):
        return result("error", "DRV-2", "decision disposition is not a supported discriminator")
    if dispute is not None:
        if type(dispute.get("revision")) is not int or dispute["revision"] < 0:
            return result("error", "DRAA-2", "dispute revision is not minimal unsigned integer form")
        if any(field in dispute for field in ("transfer", "recipient", "amountBaseUnits")):
            return result("rejected", "DRX-1", "DisputeOutcome directly claims a transfer")
    return None


def _canonical_record_check(value: dict[str, Any]) -> dict[str, str] | None:
    artifacts = value["artifacts"]
    records = value["canonicalRecords"]
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
    if bilateral.get("jobId") != agreement.get("jobId"):
        return result("rejected", "DRA-1", "bilateral agreement is for another job")
    if not attestation_ref_valid(agreement.get("railDefinitionRef"), rail):
        return result("rejected", "DRA-12", "rail definition reference does not resolve exactly")

    role_bindings = {role: agreement.get(role) for role in ("buyer", "seller", "evaluator")}
    if not all(isinstance(binding, dict) for binding in role_bindings.values()):
        return result("error", "DRV-2", "agreement role bindings must be objects")
    claims = {role: binding.get("primaryClaim") for role, binding in role_bindings.items()}
    if not all(isinstance(claim, str) and claim for claim in claims.values()):
        return result("error", "DRV-2", "agreement primary claims must be strings")
    # The overlay adds an evaluator to the existing commercial agreement; it
    # keeps that agreement's buyer and seller in their roles.
    if (bilateral.get("buyer"), bilateral.get("seller")) != (claims["buyer"], claims["seller"]):
        return result("rejected", "DRA-1", "bilateral agreement parties are not the overlay's buyer and seller")
    if claims["evaluator"] in {claims["buyer"], claims["seller"]}:
        return result("rejected", "DRA-6", "evaluator primary claim collides with a commercial party")
    if value.get("bundleRequiredSigners") != [claims["buyer"], claims["seller"]]:
        return result("rejected", "DRA-13", "evaluator overlay signature changed the bilateral bundle parties")
    if agreement.get("preSubmissionRefundPolicy") != "evaluator-rejection":
        return result("rejected", "DRA-15", "pre-submission refund policy is unsupported by this profile")
    if agreement.get("disclosurePolicy") not in (
        "public-evidence-only", "explicit-party-supplied"
    ):
        return result("rejected", "DRQ-1", "unsupported evidence-disclosure policy")

    signatures = agreement.get("signatures")
    by_role = {
        signature.get("role"): signature
        for signature in (signatures if isinstance(signatures, list) else [])
        if isinstance(signature, dict) and isinstance(signature.get("role"), str)
    }
    if (
        not isinstance(signatures, list)
        or len(signatures) != 3
        or set(by_role) != {"buyer", "seller", "evaluator"}
    ):
        return result("rejected", "DRA-3", "agreement needs exactly one signature per role")
    for role, claim in claims.items():
        if not signature_valid(
            agreement, by_role[role], claim, public_keys, DOMAINS["agreement"], "party"
        ):
            return result("rejected", "DRA-3", f"invalid {role} agreement signature")

    chain_id = rail.get("chainId")
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


def _selected_rail_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Bind the job, pipeline, and native target to the agreement-selected rail."""
    artifacts = value["artifacts"]
    agreement = artifacts["agreement"]
    rail = artifacts["railDefinition"]
    job = artifacts["job"]
    if job.get("railDefinitionRef") != agreement.get("railDefinitionRef"):
        return result("rejected", "DRP-5", "escrow job does not use the agreement-selected rail")
    if any(
        step.get("parameters", {}).get("rail") != rail.get("railId")
        for step in value["pipeline"]
        if step["kind"] == "job-escrow"
    ):
        return result("rejected", "DRP-5", "escrow phases do not name the agreement-selected rail")
    if (
        job.get("chainId") != rail.get("chainId")
        or job.get("contractAddress") != rail.get("contractAddress")
        or value["native"].get("chainId") != rail.get("chainId")
    ):
        return result("rejected", "DRJ-2", "escrow job targets another chain or contract than the selected rail")
    if job.get("runtimeBytecodeHash") != rail.get("runtimeBytecodeHash"):
        return result("rejected", "DRJ-5", "escrow job runtime code differs from the selected rail")
    return None


def _resolver_evidence_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Authenticate the pinned resolver record and its binding to this job."""
    resolver = value.get("resolverEvidence")
    if not isinstance(resolver, dict) or set(resolver) != RESOLVER_EVIDENCE_FIELDS:
        return result("error", "DRV-2", "resolver evidence shape is not exact")
    if resolver.get("resolverEvidenceVersion") != "1":
        return result("error", "DRV-2", "unsupported resolver evidence version")
    signer = resolver.get("resolver")
    if not isinstance(signer, str) or signer not in PINNED_RESOLVER_KEYS or not signature_valid(
        resolver, resolver.get("signature"), signer, PINNED_RESOLVER_KEYS, RESOLVER_DOMAIN
    ):
        return result("rejected", "DRV-1", "resolver evidence is not authenticated by the pinned resolver")
    artifacts = value["artifacts"]
    rail = artifacts["railDefinition"]
    inputs = value.get("reproductionInputs")
    observations = inputs.get("nativeEventInputs") if isinstance(inputs, dict) else None
    if resolver.get("eventObservationsHash") != content_hash(observations):
        return result("rejected", "DRV-1", "native event observations are not the resolver-authenticated set")
    if (
        resolver.get("jobId") != artifacts["agreement"].get("jobId")
        or resolver.get("railDefinitionHash") != artifact_hash(rail)
        or resolver.get("chainId") != rail.get("chainId")
        or resolver.get("contractAddress") != rail.get("contractAddress")
        or resolver.get("nativeJobId") != artifacts["job"].get("nativeJobId")
    ):
        return result("rejected", "DRV-6", "resolver evidence describes another job, rail, or contract")

    call = resolver.get("terminalCall")
    if not isinstance(call, dict) or set(call) != TERMINAL_CALL_FIELDS:
        return result("error", "DRV-2", "resolver terminal call record is malformed")
    history = resolver.get("priorTerminals")
    if not isinstance(history, list) or not all(_prior_terminal_valid(item) for item in history):
        return result("error", "DRV-2", "resolver terminal history is malformed")
    if not _native_state_valid(resolver.get("nativeState")):
        return result("error", "DRV-2", "resolver native state is malformed")
    if not _digest_anchor_valid(resolver.get("deliveryDigestAnchor")):
        return result("error", "DRV-2", "resolver delivery-digest anchor is malformed")
    statuses = resolver.get("statuses")
    if not isinstance(statuses, dict) or set(statuses) != EXTERNAL_EVIDENCE_FIELDS:
        return result("error", "DRV-2", "resolver status set is incomplete")
    if any(not isinstance(state, str) or state not in EXTERNAL_STATES for state in statuses.values()):
        return result("error", "DRV-2", "unknown resolver status")
    return None


def _prior_terminal_valid(item: Any) -> bool:
    if not isinstance(item, dict) or set(item) != PRIOR_TERMINAL_FIELDS:
        return False
    decision_hash = item["decisionHash"]
    return (
        type(item["chainId"]) is int
        and isinstance(item["contractAddress"], str)
        and re.fullmatch(r"0x[0-9a-f]{40}", item["contractAddress"]) is not None
        and isinstance(item["nativeJobId"], str)
        and re.fullmatch(r"(?:0|[1-9][0-9]*)", item["nativeJobId"]) is not None
        and isinstance(item["txHash"], str)
        and EVM_TX_RE.fullmatch(item["txHash"]) is not None
        and type(item["logIndex"]) is int
        and item["logIndex"] >= 0
        and (
            decision_hash is None
            or (isinstance(decision_hash, str) and HASH_RE.fullmatch(decision_hash) is not None)
        )
    )


def _native_state_valid(state: Any) -> bool:
    if not isinstance(state, dict) or set(state) != NATIVE_STATE_FIELDS:
        return False
    adapter = state["evaluatorAdapter"]
    payout = state["preterminalProviderPayoutBaseUnits"]
    return (
        type(state["submissionCutoffEnforced"]) is bool
        and type(state["expiryRecoveryAtSec"]) is int
        and state["expiryRecoveryAtSec"] >= 0
        and isinstance(payout, str)
        and re.fullmatch(r"(?:0|[1-9][0-9]*)", payout) is not None
        and all(
            type(state[name]) is int and state[name] >= 0
            for name in ("platformFeeBP", "evaluatorFeeBP")
        )
        and isinstance(state["evaluatorBindingMode"], str)
        and (
            adapter is None
            or (isinstance(adapter, str) and re.fullmatch(r"0x[0-9a-f]{40}", adapter) is not None)
        )
    )


def _digest_anchor_valid(anchor: Any) -> bool:
    if anchor is None:
        return True
    return (
        isinstance(anchor, dict)
        and set(anchor) == DIGEST_ANCHOR_FIELDS
        and isinstance(anchor["deliverable"], str)
        and BYTES32_RE.fullmatch(anchor["deliverable"]) is not None
        and all(
            type(anchor[name]) is int and anchor[name] >= 0
            for name in ("blockNumber", "blockTimestampSec")
        )
    )


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
        if isinstance(classification, str) and classification in parties:
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
            # Funding binds the exact overlay (DRF-1); for every other
            # artifact a valid signature cannot override the overlay (DRV-4).
            return result(
                "rejected", "DRF-1" if name == "funding" else "DRV-4",
                f"{name} binds another agreement overlay",
            )
    if not attestation_ref_valid(a["funding"].get("escrowJobRef"), a["job"]):
        return result("rejected", "DRF-1", "funding job reference mismatch")
    if not attestation_ref_valid(a["terminal"].get("escrowJobRef"), a["job"]):
        return result("rejected", "DRT-4", "terminal job reference mismatch")
    for name in ("evaluation", "decision"):
        artifact = a.get(name)
        if artifact is not None and not attestation_ref_valid(artifact.get("escrowJobRef"), a["job"]):
            return result("rejected", "DRD-8", f"{name} job reference does not resolve to this escrow job")
    if not attestation_ref_valid(a["terminal"].get("fundingEvidenceRef"), a["funding"]):
        return result("rejected", "DRT-11", "terminal funding reference mismatch")
    if a.get("delivery") is not None:
        delivery_ref = a.get("deliveryRef")
        if not attestation_ref_valid(delivery_ref, a["delivery"]):
            return result("rejected", "DRE-2", "delivery reference mismatch")
        delivery_issue = _delivery_evidence_check(value)
        if delivery_issue:
            return delivery_issue
        for name in ("evaluation", "decision"):
            artifact = a.get(name)
            if artifact is not None and artifact.get("deliveryEvidenceRef") != delivery_ref:
                return result("rejected", "DRD-3", f"{name} does not bind the exact delivery")
        if a["terminal"].get("deliveryEvidenceRef") != delivery_ref:
            return result("rejected", "DRT-12", "terminal delivery reference mismatch")
    elif a.get("decision") is not None:
        # Without delivery there is nothing to release (DRD-3), and only a
        # DisputeOutcome can authorize the pre-submission refund (DRD-9).
        decision = a["decision"]
        basis = decision.get("basisRef")
        if decision.get("disposition") == "release-to-provider":
            return result("rejected", "DRD-3", "a release decision has no delivery evidence to bind")
        elif not isinstance(basis, dict) or basis.get("kind") != "dispute-outcome":
            return result("rejected", "DRD-9", "a decision without delivery evidence must rest on a DisputeOutcome")
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


def _delivery_evidence_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Require the delivery SettlementEvidence of the agreed delivery phase (DRE-2, DRP-7).

    The pipeline has exactly one delivery step, at the overlay's
    `deliveryPhaseIndex` (DRP-3, DRA-11), so a delivery record for this job
    whose `phase` is that step's kind is that step's evidence.  A success
    carries the deliverable's content hash and anchor (DACS-4 §9.6.1); a
    failure carries a `reason` and may omit either.  The outcome is not mapped
    to a disposition here: whether a delivery supports release or refund is
    decided by the evaluation under the bound evaluation rule.
    """
    delivery = value["artifacts"]["delivery"]
    phase_index = value["artifacts"]["agreement"]["deliveryPhaseIndex"]
    outcome = delivery.get("outcome")
    failed = outcome == "failure"
    members = DELIVERY_EVIDENCE_FIELDS | {"reason"} if failed else DELIVERY_EVIDENCE_FIELDS
    required = members - DELIVERABLE_FIELDS if failed else members
    content = delivery.get("deliverableContentHash")
    anchor = delivery.get("deliverableAnchor")
    if (
        not required <= set(delivery) <= members
        or delivery["evidenceVersion"] != "1"
        or not isinstance(outcome, str)
        or outcome not in DELIVERY_OUTCOMES
        or (failed and not (isinstance(delivery["reason"], str) and delivery["reason"]))
        or not isinstance(delivery["phase"], str)
        or ("deliverableContentHash" in delivery and not (
            isinstance(content, str) and HASH_RE.fullmatch(content) is not None
        ))
        or ("deliverableAnchor" in delivery and not (
            isinstance(anchor, dict)
            and set(anchor) == {"kind", "locator"}
            and all(isinstance(anchor[name], str) and anchor[name] for name in ("kind", "locator"))
        ))
        or type(delivery["observedAt"]) is not int
        or delivery["observedAt"] < 0
    ):
        return result("error", "DRV-2", "delivery evidence is not an exact delivery SettlementEvidence")
    if delivery["phase"] != value["pipeline"][phase_index]["kind"]:
        return result("rejected", "DRE-2", "delivery evidence phase is not the agreed delivery step")
    return None


def _subject_evidence_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Resolve every evaluation subject reference to authenticated evidence (DRE-3, DRE-5).

    A subject resolves when its locator names a lifecycle evidence record that
    this verifier has authenticated: the escrow job, the funding evidence, or
    the delivery evidence.  Both first-profile disclosure policies admit those
    published records.  Any other subject would need public resolution or an
    explicit-party supply proof (DRQ-2) that the fixture does not model, so it
    stays `indeterminate`.
    """
    a = value["artifacts"]
    evaluation = a.get("evaluation")
    if evaluation is None:
        return None
    refs = evaluation.get("subjectEvidenceRefs")
    if not isinstance(refs, list) or not all(attestation_ref_shape_valid(ref) for ref in refs):
        return result("error", "DRV-2", "evaluation subject evidence references are malformed")
    # Each source reference was resolved exactly by an earlier stage.
    published = {
        ref_value["locator"]: (ref_value["kind"], artifact)
        for ref_value, artifact in (
            (a["funding"]["escrowJobRef"], a["job"]),
            (a["terminal"]["fundingEvidenceRef"], a["funding"]),
            (a.get("deliveryRef"), a.get("delivery")),
        )
        if artifact is not None
    }
    unresolved = False
    for ref_value in refs:
        record = published.get(ref_value["locator"])
        if record is None:
            unresolved = True
        elif ref_value["kind"] != record[0] or ref_value["contentHash"] != artifact_hash(record[1]):
            return result("rejected", "DRE-3", "a subject reference contradicts the authenticated record at its locator")
    if unresolved:
        return result(
            "indeterminate", "DRE-5",
            "subject evidence does not resolve to authenticated evidence under the signed disclosure policy",
        )
    return None


def _external_evidence_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Apply resolver outcomes; the record was authenticated by an earlier stage."""
    external = value["resolverEvidence"]["statuses"]
    artifacts = value["artifacts"]
    decision_applicable = artifacts["terminal"].get("terminalState") != "expired-refund"
    applicable = dict.fromkeys(EXTERNAL_EVIDENCE_FIELDS, True)
    applicable.update({
        "deliveryFinality": artifacts.get("delivery") is not None,
        "decisionFinality": decision_applicable,
        "decisionOrdering": decision_applicable,
    })
    if any(
        (external[name] == "not-applicable") is needed
        for name, needed in applicable.items()
    ):
        return result("error", "DRV-2", "resolver status applicability does not match the lifecycle")
    contradictory = sorted(name for name, state in external.items() if state == "contradictory")
    if contradictory:
        return result("rejected", "DRV-6", "authenticated evidence contradicts: " + ", ".join(contradictory))
    unavailable = [name for name in UNAVAILABLE_STATUS_RULES if external[name] == "unavailable"]
    if unavailable:
        return result(
            "indeterminate",
            UNAVAILABLE_STATUS_RULES[unavailable[0]],
            "required external evidence unavailable: " + ", ".join(sorted(unavailable)),
        )
    return None


def _delivery_binding_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Check the locator of the native submission event for a delivered lifecycle.

    The binding carries no ordering conclusion.  DRP-9 ordering comes from
    the resolver-authenticated submission observation and digest anchor.
    """
    delivery = value["artifacts"].get("delivery")
    binding = value.get("deliveryBinding")
    if delivery is None:
        if binding is not None or value["resolverEvidence"]["deliveryDigestAnchor"] is not None:
            return result("rejected", "DRP-9", "deliveryless path carries a native submission binding or digest anchor")
        return None
    if not isinstance(binding, dict) or set(binding) != {"nativeSubmissionEvent"}:
        return result("error", "DRV-2", "deliveryBinding must name only the native submission event")
    return None


def _native_event_input_check(
    value: dict[str, Any],
) -> tuple[dict[tuple[Any, Any, Any, Any], dict[str, Any]], dict[str, str] | None]:
    """Match the resolver's observations to the lifecycle's event references.

    Each signed event reference, plus the bound submission event of a
    delivered lifecycle, needs exactly one observation.  Event time, depth,
    and submission content are then read from those observations only.
    """
    inputs = value["reproductionInputs"]
    event_inputs = inputs.get("nativeEventInputs")
    if not isinstance(event_inputs, list) or not event_inputs:
        return {}, result("error", "DRV-2", "native event inputs must be a non-empty array")

    artifacts = value["artifacts"]
    chain_id = artifacts["railDefinition"].get("chainId")
    funding_refs = artifacts["funding"].get("fundingEventRefs")
    terminal_refs = artifacts["terminal"].get("terminalEventRefs")
    if not isinstance(funding_refs, list) or len(funding_refs) != 1:
        return {}, result("rejected", "DRF-3", "candidate funding event set must identify exactly one event")
    if not isinstance(terminal_refs, list) or len(terminal_refs) != 1:
        return {}, result("rejected", "DRT-4", "candidate terminal event set must identify exactly one event")
    terminal_name = {
        "released": "JobCompleted",
        "rejected-refund": "JobRejected",
        "expired-refund": "JobExpired",
    }.get(artifacts["terminal"].get("terminalState"))
    delivered = artifacts.get("delivery") is not None
    # (label, reference, event name, reference rule, block rule, depth rule)
    expected: list[tuple[str, Any, Any, str, str, str]] = [
        ("creation", artifacts["job"].get("creationEvent"), "JobCreated", "DRJ-3", "DRJ-3", "DRJ-2"),
        ("funding", funding_refs[0], "JobFunded", "DRF-3", "DRF-6", "DRF-6"),
    ]
    if delivered:
        expected.append((
            "submission", value["deliveryBinding"]["nativeSubmissionEvent"],
            "JobSubmitted", "DRP-9", "DRP-9", "DRP-9",
        ))
    expected.append(("terminal", terminal_refs[0], terminal_name, "DRT-4", "DRT-8", "DRT-8"))
    for label, ref_value, _name, reference_rule, _block_rule, _depth_rule in expected:
        issue = _event_ref_check(ref_value, chain_id, reference_rule, label)
        if issue:
            return {}, issue

    by_identity: dict[tuple[Any, Any, Any, Any], dict[str, Any]] = {}
    for event_input_value in event_inputs:
        if not isinstance(event_input_value, dict) or set(event_input_value) != EVENT_INPUT_FIELDS:
            return {}, result("error", "DRV-2", "native event input is malformed")
        by_identity[_event_identity(event_input_value["eventRef"])] = event_input_value
    roles = {_event_identity(item[1]): item for item in expected}
    if (
        len(roles) != len(expected)
        or len(event_inputs) != len(expected)
        or set(by_identity) != set(roles)
    ):
        return {}, result("rejected", "DRT-4", "native event inputs do not match the referenced event set")

    rail_profile = artifacts["railDefinition"].get("profileParameters")
    minimum_confirmations = (
        rail_profile.get("finalityBlocks") if isinstance(rail_profile, dict) else None
    )
    if type(minimum_confirmations) is not int or minimum_confirmations <= 0:
        return {}, result("error", "DRV-2", "rail finality depth must be a positive integer")
    records: dict[str, dict[str, Any]] = {}
    for identity, event_input_value in by_identity.items():
        label, ref_value, name, reference_rule, block_rule, _depth_rule = roles[identity]
        tx_preimage = event_input_value["txHashPreimageUtf8"]
        block_preimage = event_input_value["blockHashPreimageUtf8"]
        if (
            not isinstance(tx_preimage, str)
            or type(event_input_value["blockNumber"]) is not int
            or event_input_value["blockNumber"] < 0
            or type(event_input_value["blockTimestampSec"]) is not int
            or event_input_value["blockTimestampSec"] < 0
            or type(event_input_value["confirmations"]) is not int
            or event_input_value["confirmations"] < 0
            or not isinstance(event_input_value["blockHash"], str)
            or EVM_TX_RE.fullmatch(event_input_value["blockHash"]) is None
            or not isinstance(block_preimage, str)
            or not isinstance(event_input_value["contractAddress"], str)
            or not isinstance(event_input_value["nativeJobId"], str)
            or not isinstance(event_input_value["eventName"], str)
            or not isinstance(event_input_value["arguments"], dict)
        ):
            return {}, result("error", "DRV-2", "native event observation is malformed")
        if ref_value["txHash"] != "0x" + hashlib.sha256(tx_preimage.encode("utf-8")).hexdigest():
            return {}, result("rejected", reference_rule, "native event transaction preimage does not match")
        expected_block_preimage = (
            f"{tx_preimage}:block:{event_input_value['blockNumber']}:"
            f"{event_input_value['blockTimestampSec']}"
        )
        if block_preimage != expected_block_preimage:
            return {}, result("rejected", block_rule, "native event block identity preimage does not match")
        if event_input_value["blockHash"] != "0x" + hashlib.sha256(
            block_preimage.encode("utf-8")
        ).hexdigest():
            return {}, result("rejected", block_rule, "native event block-hash preimage does not match")
        if event_input_value["eventName"] != name:
            return {}, result("rejected", "DRT-4", "native event selectors do not match the lifecycle")
        records[label] = event_input_value
    for label, _ref_value, name, _reference_rule, _block_rule, depth_rule in expected:
        if records[label]["confirmations"] < minimum_confirmations:
            return {}, result(
                "indeterminate", depth_rule,
                f"{name} event has not reached the rail finality depth",
            )

    funded_at = records["funding"]["blockTimestampSec"]
    if value["native"].get("fundedAtSec") != funded_at:
        return {}, result("rejected", "DRA-9", "caller funding time differs from the authenticated event block")
    cutoff = artifacts["agreement"].get("submissionCutoffSec")
    deadline = artifacts["agreement"].get("evaluationDeadlineSec")
    if type(cutoff) is not int or type(deadline) is not int:
        return {}, result("error", "DRV-2", "signed cutoff and deadline must be integers")
    if (
        terminal_name == "JobExpired"
        and records["terminal"]["blockTimestampSec"] < deadline
    ):
        return {}, result("rejected", "DREB-15", "expiry recovery executed before the evaluation deadline")
    submitted_before_cutoff = False
    ordered = [records["creation"], records["funding"]]
    if delivered:
        submitted = records["submission"]
        anchor_issue = _delivery_digest_anchor_check(
            artifacts["delivery"], value["resolverEvidence"]["deliveryDigestAnchor"], submitted
        )
        if anchor_issue:
            return {}, anchor_issue
        submitted_before_cutoff = submitted["blockTimestampSec"] < cutoff
        if not submitted_before_cutoff:
            return {}, result("rejected", "DRP-9", "native delivery was submitted at or after the cutoff")
        ordered.append(submitted)
    ordered.append(records["terminal"])
    if any(
        earlier["blockTimestampSec"] >= later["blockTimestampSec"]
        or earlier["blockNumber"] >= later["blockNumber"]
        for earlier, later in zip(ordered, ordered[1:])
    ):
        return {}, result("rejected", "DRT-4", "native event observations are not strictly ordered")
    if value.get("submittedBeforeCutoff") is not submitted_before_cutoff:
        return {}, result("rejected", "DRT-12", "submission classification contradicts authenticated event time")
    return by_identity, None


def _delivery_digest_anchor_check(
    delivery: dict[str, Any], anchor: Any, submission: dict[str, Any]
) -> dict[str, str] | None:
    """Require authenticated evidence that the delivery digest was fixed before submission (DRP-9).

    The pinned resolver attests the block in which the exact delivery digest
    was anchored.  A digest anchored in an earlier block than the native
    submission cannot contain or derive anything from that submission, whose
    transaction identity commits to the digest.  The verifier does not search
    the delivery for encodings of the submission.  The anchor record is a
    synthetic fixture boundary, not a normative proof shape.
    """
    if anchor is None:
        return result("indeterminate", "DRP-9", "no authenticated evidence fixes the delivery digest before the native submission")
    if anchor["deliverable"] != "0x" + artifact_hash(delivery):
        return result("rejected", "DRP-9", "the anchored digest is not this delivery evidence")
    if anchor["blockNumber"] > submission["blockNumber"]:
        return result("rejected", "DRP-9", "the delivery digest was fixed only after the native submission")
    if anchor["blockNumber"] == submission["blockNumber"]:
        return result("indeterminate", "DRP-9", "the digest anchor and the native submission share a block and cannot be ordered")
    # An earlier block has an earlier timestamp, as lifecycle events do.
    if (
        anchor["blockNumber"] < submission["blockNumber"]
        and anchor["blockTimestampSec"] >= submission["blockTimestampSec"]
    ):
        return result("rejected", "DRP-9", "the digest anchor's block time is not before the native submission")
    if delivery["observedAt"] > anchor["blockTimestampSec"] * 1000:
        return result("rejected", "DRP-9", "the delivery evidence records a time after its digest was fixed")
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

    event_inputs, event_issue = _native_event_input_check(value)
    if event_issue:
        return event_issue

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
    funding_ref = value["artifacts"]["funding"]["fundingEventRefs"][0]
    funded_at = event_inputs[_event_identity(funding_ref)]["blockTimestampSec"]
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
            return result("rejected", "DRP-7", "deliveryless path contains an unreferenced deliverable input")
    elif "deliverableContentHash" not in artifacts["delivery"]:
        # A failed delivery that names no deliverable has nothing to resolve.
        if delivered is not None:
            return result("rejected", "DRE-2", "delivery evidence names no deliverable for the delivered artifact input")
    elif (
        not isinstance(delivered, dict)
        or artifacts["delivery"]["deliverableContentHash"] != content_hash(delivered)
    ):
        return result("rejected", "DRE-2", "delivered artifact input does not resolve")
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

    return None


def _native_event_semantics_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Compare authenticated event arguments with the signed artifacts they settle."""
    inputs = value["reproductionInputs"]["nativeEventInputs"]
    records = {item["eventName"]: item for item in inputs}
    artifacts = value["artifacts"]
    agreement = artifacts["agreement"]
    job = artifacts["job"]
    terminal = artifacts["terminal"]
    if any(
        item["contractAddress"] != job["contractAddress"]
        or item["nativeJobId"] != job["nativeJobId"]
        for item in inputs
    ):
        return result("rejected", "DRT-4", "native event targets another contract or job")
    created = dict(records["JobCreated"]["arguments"])
    if created.pop("description", None) != "dacs-delivery-remedy:v1:" + artifact_hash(agreement):
        return result("rejected", "DREB-1", "native job description does not contain the exact overlay hash")
    accounts = {
        role: parse_canonical_evm_claim(agreement[role]["evmAccountClaim"])[1]
        for role in ("buyer", "seller", "evaluator")
    }
    if created != {
        "client": accounts["buyer"],
        "provider": accounts["seller"],
        "evaluator": accounts["evaluator"],
        "submissionCutoffSec": agreement["submissionCutoffSec"],
        "expiredAt": agreement["evaluationDeadlineSec"],
    }:
        return result("rejected", "DRJ-3", "creation/configuration event does not match the agreement")
    funded = records["JobFunded"]["arguments"]
    if funded != {
        "token": artifacts["railDefinition"].get("paymentToken"),
        "amountBaseUnits": agreement["budgetBaseUnits"],
    }:
        return result("rejected", "DRF-3", "funding event does not match the complete budget")
    if artifacts.get("delivery") is not None:
        digest = "0x" + artifact_hash(artifacts["delivery"])
        # As an EVM transaction hash commits to its calldata, the synthetic
        # submission transaction identity commits to the submitted digest.
        if (
            records["JobSubmitted"]["arguments"] != {"deliverable": digest}
            or not records["JobSubmitted"]["txHashPreimageUtf8"].endswith(":" + digest)
        ):
            return result("rejected", "DRP-9", "the submission event and its transaction do not commit to the delivery digest")
    terminal_name = {
        "released": "JobCompleted",
        "rejected-refund": "JobRejected",
        "expired-refund": "JobExpired",
    }[terminal["terminalState"]]
    decision = artifacts.get("decision")
    if records[terminal_name]["arguments"] != {
        "token": terminal["token"],
        "amountBaseUnits": terminal["amountBaseUnits"],
        "recipient": terminal["recipient"],
        "reason": None if decision is None else "0x" + artifact_hash(decision),
    }:
        return result("rejected", "DRT-4", "terminal event does not match the claimed disposition")
    return None


def _native_and_terminal_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Compare the native projection, resolved native state, and terminal evidence."""
    a = value["artifacts"]
    agreement = a["agreement"]
    rail = a["railDefinition"]
    native = value["native"]
    state = value["resolverEvidence"]["nativeState"]
    terminal = a["terminal"]
    terminal_state = terminal.get("terminalState")
    history = native.get("portableStateHistory")
    if not isinstance(history, list) or not history:
        return result("error", "DRV-2", "portable state history must be a non-empty array")
    # A release is reachable only from `submitted`; the references stage has
    # already required delivery evidence for every release decision.
    submitted = terminal_state == "released" or value.get("submittedBeforeCutoff") is True
    expected_history = [
        "created",
        "funded",
        *(["submitted"] if submitted else []),
        "released" if terminal_state == "released" else "refunded",
    ]
    if history != expected_history:
        if any(not isinstance(item, str) or item not in PORTABLE_STATES for item in history):
            return result("rejected", "DRL-2", "native state cannot be mapped to one portable state")
        elif any(pair not in PORTABLE_TRANSITIONS for pair in zip(history, history[1:])):
            return result("rejected", "DRL-4", "portable state history contains an invalid or reopened transition")
        else:
            return result("rejected", "DRL-1", "portable state history does not match the lifecycle evidence")
    mapping_sources = value["mappingSources"]
    expected_sources = {"agreementHash": artifact_hash(agreement)}
    if a.get("delivery") is not None:
        expected_sources["deliveryHash"] = artifact_hash(a["delivery"])
    if a.get("decision") is not None:
        expected_sources["decisionHash"] = artifact_hash(a["decision"])
    if set(mapping_sources) != set(expected_sources):
        return result("error", "DRV-2", "mapping source set does not match the lifecycle")
    for name, expected_hash in expected_sources.items():
        declared_hash = mapping_sources[name]
        if declared_hash != expected_hash:
            if not isinstance(declared_hash, str) or HASH_RE.fullmatch(declared_hash) is None:
                return result("rejected", "DREB-3", f"{name} is not 64 lowercase hexadecimal characters")
            else:
                return result("rejected", "DREB-2", f"{name} does not match the recomputed artifact hash")

    accounts = {
        role: parse_canonical_evm_claim(agreement[role]["evmAccountClaim"])[1]
        for role in ("buyer", "seller", "evaluator")
    }
    if native.get("contractAddress") != a["job"].get("contractAddress"):
        return result("rejected", "DRJ-2", "native contract address mismatch")
    if native.get("runtimeBytecodeHash") != a["job"].get("runtimeBytecodeHash"):
        return result("rejected", "DRJ-5", "runtime bytecode hash mismatch")
    if native.get("payoutReceiver") != accounts["seller"]:
        return result("rejected", "DREB-10", "native payout receiver is not the bound seller account")

    cutoff = agreement["submissionCutoffSec"]
    deadline = agreement["evaluationDeadlineSec"]
    profile = rail.get("profileParameters")
    if value["profileParameters"] != profile:
        return result("rejected", "DRP-5", "detached profile projection differs from the authenticated rail")
    if not isinstance(profile, dict) or set(profile) != PROFILE_FIELDS:
        return result("error", "DRV-2", "candidate rail profile shape is not exact")
    minimum = profile["minimumEvaluationWindowSec"]
    if type(minimum) is not int:
        return result("error", "DREB-14", "minimum evaluation window must be an integer")
    elif minimum <= 0:
        return result("rejected", "DREB-14", "evaluation windows must be positive")
    elif deadline - cutoff < minimum:
        return result("rejected", "DREB-14", "evaluation window is shorter than the pinned minimum")
    if profile["deadlineProfile"] != "separate-submission-cutoff-v1":
        return result("rejected", "DREB-13", "unsupported native deadline profile")
    if native.get("submissionCutoffSec") != cutoff or state["submissionCutoffEnforced"] is not True:
        return result("rejected", "DREB-13", "native submission cutoff is not separately enforced")
    if native.get("expiredAt") != deadline:
        return result("rejected", "DREB-12", "native expiredAt is not the evaluation deadline")
    if state["expiryRecoveryAtSec"] != deadline:
        return result("rejected", "DREB-15", "native expiry recovery is not bound to the evaluation deadline")

    if a.get("delivery") is not None:
        expected_deliverable = "0x" + expected_sources["deliveryHash"]
        provided = native.get("deliverable")
        if provided != expected_deliverable:
            if not isinstance(provided, str) or BYTES32_RE.fullmatch(provided) is None:
                return result("error", "DRV-2", "native deliverable is not canonical bytes32 text")
            elif provided == ZERO_BYTES32:
                return result("rejected", "DREB-5", "zero deliverable is forbidden")
            else:
                return result("rejected", "DREB-4", "deliverable is not the raw decoded content hash")
    elif native.get("deliverable") is not None:
        return result("rejected", "DRT-12", "a deliveryless lifecycle cannot carry a native deliverable")

    funding = a["funding"]
    event_inputs = {
        _event_identity(item["eventRef"]): item
        for item in value["reproductionInputs"]["nativeEventInputs"]
    }
    funding_finality = _finality_check(
        funding.get("finality"), profile["finalityBlocks"],
        event_inputs[_event_identity(funding["fundingEventRefs"][0])], "DRF-6", "funding",
    )
    if funding_finality:
        return funding_finality
    budget = agreement["budgetBaseUnits"]
    token = rail.get("paymentToken")
    if native.get("amountBaseUnits") != budget or native.get("token") != token:
        return result("rejected", "DREB-11", "native token or budget does not match the agreement rail")
    if funding.get("amountBaseUnits") != budget or funding.get("token") != token:
        return result("rejected", "DRF-2", "funding token or complete budget mismatch")
    if funding.get("fundPhaseIndex") != agreement.get("fundPhaseIndex"):
        return result("rejected", "DRF-1", "funding phase index mismatch")
    if state["preterminalProviderPayoutBaseUnits"] != "0":
        return result("rejected", "DRL-7", "provider received value before terminal release")
    if (
        profile["platformFeeBP"] != 0
        or profile["evaluatorFeeBP"] != 0
        or state["platformFeeBP"] != profile["platformFeeBP"]
        or state["evaluatorFeeBP"] != profile["evaluatorFeeBP"]
    ):
        return result("rejected", "DRT-7", "escrow fee is nonzero")

    decision = a.get("decision")
    evaluation = a.get("evaluation")
    dispute = a.get("dispute")
    action = native.get("terminalAction")
    if terminal.get("amountBaseUnits") != budget or terminal.get("token") != token:
        return result("rejected", "DRT-5", "terminal token or amount is not the complete budget")
    if native.get("terminalState") != terminal_state:
        return result("rejected", "DRT-4", "native and DACS terminal states diverge")
    terminal_finality = _finality_check(
        terminal.get("finality"), profile["finalityBlocks"],
        event_inputs[_event_identity(terminal["terminalEventRefs"][0])], "DRT-8", "terminal",
    )
    if terminal_finality:
        return terminal_finality
    # The native caller, outer submitter, and caller account type come only
    # from the resolver's authenticated record of the terminal transaction.
    call = value["resolverEvidence"]["terminalCall"]
    if call.get("txHash") != terminal["terminalEventRefs"][0]["txHash"]:
        return result("rejected", "DREB-21", "authenticated call record is not for the terminal transaction")

    projection = value.get("reputationProjection")
    if not isinstance(projection, dict) or set(projection) != {
        "buyerFault", "sellerFault", "releaseAloneEstablishesNonFinancialCompletion"
    } or any(type(projection.get(field)) is not bool for field in projection):
        return result("error", "DRV-2", "reputation projection is malformed")
    finding_artifact = evaluation if evaluation is not None else dispute
    classification = (
        finding_artifact.get("finding", {}).get("classification")
        if isinstance(finding_artifact, dict)
        else None
    )
    expected_faults = {
        "buyerFault": classification == "buyer-fault",
        "sellerFault": classification == "seller-fault",
    }
    if any(projection[field] is not expected for field, expected in expected_faults.items()):
        if decision is None:
            return result("rejected", "DRT-13", "decisionless expiry invents buyer or seller fault")
        else:
            return result("rejected", "DRT-14", "caller projection contradicts the authenticated finding")

    if decision is not None:
        expected_reason = "0x" + expected_sources["decisionHash"]
        provided_reason = native.get("reason")
        if provided_reason != expected_reason:
            if not isinstance(provided_reason, str) or BYTES32_RE.fullmatch(provided_reason) is None:
                return result("error", "DRV-2", "native decision reason is not canonical bytes32 text")
            elif provided_reason == ZERO_BYTES32:
                return result("rejected", "DREB-5", "zero decision reason is forbidden")
            else:
                return result("rejected", "DREB-4", "reason is not the raw decoded decision hash")
        account_type = call.get("nativeCallerAccountType")
        if account_type not in ("eoa", "eip1271"):
            return result("error", "DREB-18", "unsupported evaluator account type")
        if state["evaluatorBindingMode"] != "direct":
            return result("rejected", "DREB-16", "native evaluator is not bound directly")
        if state["evaluatorAdapter"] is not None:
            return result("rejected", "DREB-20", "generic evaluator adapters are outside the profile")
        if call.get("nativeCaller") != accounts["evaluator"]:
            return result("rejected", "DREB-21", "authenticated native caller is not the bound evaluator account")
        submitter = call.get("outerSubmitter")
        if not isinstance(submitter, str) or re.fullmatch(r"0x[0-9a-f]{40}", submitter) is None:
            return result("error", "DREB-22", "outer transaction submitter is malformed")
        if account_type == "eoa" and submitter != call.get("nativeCaller"):
            return result("rejected", "DREB-22", "an EOA evaluator cannot have another transaction submitter")
        disposition = decision.get("disposition")
        if evaluation is not None:
            evaluation_result = evaluation.get("result")
            if evaluation_result == "indeterminate":
                return result("rejected", "DRE-4", "indeterminate evaluation cannot authorize a terminal action")
            elif SETTLEMENT_AUTHORIZATIONS.get(evaluation_result) != disposition:
                return result("rejected", "DRD-2", "evaluation result does not authorize the decision disposition")
        elif dispute is not None:
            if value.get("submittedBeforeCutoff") is not False:
                return result("rejected", "DRD-12", "dispute-based decision is not a pre-submission path")
            elif "deliveryEvidenceRef" in decision or "deliveryEvidenceRef" in terminal:
                return result("rejected", "DRD-9", "pre-submission rejection carries delivery evidence")
            elif dispute.get("recommendedDisposition") != disposition or disposition != "refund-to-client":
                return result("rejected", "DRD-12", "dispute outcome does not authorize the refund")
        else:
            return result("rejected", "DRE-4", "decision has no authenticated evaluation or dispute basis")
        # The shape stage closed the disposition set to these two values.
        if disposition == "release-to-provider":
            if terminal_state != "released" or action != "complete":
                return result("rejected", "DRD-5", "release decision maps to a non-release action")
            if terminal.get("disposition") != disposition or terminal.get("recipient") != accounts["seller"]:
                return result("rejected", "DRT-5", "release recipient or disposition mismatch")
            if projection["releaseAloneEstablishesNonFinancialCompletion"]:
                return result(
                    "rejected",
                    "DRL-6",
                    "financial release overclaims non-financial completion",
                )
        else:
            if terminal_state != "rejected-refund" or action != "reject":
                return result("rejected", "DRD-6", "refund decision maps to a non-rejection action")
            if terminal.get("disposition") != disposition or terminal.get("recipient") != accounts["buyer"]:
                return result("rejected", "DRT-6", "refund recipient or disposition mismatch")
    else:
        if terminal_state != "expired-refund" or action != "claimRefund":
            return result("rejected", "DRT-3", "decisionless terminal action is not expiry refund")
        if "decisionRef" in terminal or native.get("reason") is not None:
            return result("rejected", "DRD-7", "expiry recovery manufactures an evaluator decision")
        if terminal.get("disposition") != "refund-to-client" or terminal.get("recipient") != accounts["buyer"]:
            return result("rejected", "DRT-6", "expiry refund recipient mismatch")
        if value["submittedBeforeCutoff"] != ("deliveryEvidenceRef" in terminal):
            return result("rejected", "DRT-12", "expiry delivery-reference presence does not match submission state")

    return _native_event_semantics_check(value)


def _attested_terminals(value: dict[str, Any]) -> list[TerminalRecord]:
    """The resolver-attested earlier terminals for this native job or decision."""
    return [
        TerminalRecord(
            job=(item["chainId"], item["contractAddress"], item["nativeJobId"]),
            event=(item["chainId"], item["txHash"], item["logIndex"]),
            decision=item["decisionHash"],
        )
        for item in value["resolverEvidence"]["priorTerminals"]
    ]


def _terminal_record(value: dict[str, Any]) -> TerminalRecord:
    artifacts = value["artifacts"]
    job = artifacts["job"]
    ref_value = artifacts["terminal"]["terminalEventRefs"][0]
    decision = artifacts.get("decision")
    observed = next(
        item for item in value["reproductionInputs"]["nativeEventInputs"]
        if _event_identity(item["eventRef"]) == _event_identity(ref_value)
    )
    return TerminalRecord(
        job=(job["chainId"], job["contractAddress"], job["nativeJobId"]),
        event=(ref_value["chainId"], ref_value["txHash"], ref_value["logIndex"]),
        decision=None if decision is None else artifact_hash(decision),
        position=(observed["blockNumber"], ref_value["logIndex"]),
        attested=tuple(sorted({prior[:3] for prior in _attested_terminals(value)}, key=repr)),
    )


def _terminal_replay_check(
    current: TerminalRecord, ledger: DecisionLedger
) -> dict[str, str] | None:
    """Compare this terminal with every conflicting terminal (DRD-8, DRL-4, DRT-4).

    The pinned resolver attests `priorTerminals` as the complete set of
    earlier terminals for this native job or decision, so a conflict with one
    is rejected.  For a terminal in the verifier's ledger, the earlier of two
    conflicting terminals is chosen by authenticated event position, and the
    later one is rejected.  The pair stays `indeterminate` when the positions
    cannot order it, or when the later terminal's attested history omits the
    earlier one: the resolver's records then contradict each other.  One
    event claimed by two native jobs is ambiguous whichever came first.
    The finding depends only on ``current`` and the ledger's terminals.
    """
    for prior in current.attested:
        conflict = terminal_conflict(TerminalRecord(*prior), current)
        if conflict:
            return result("rejected", *conflict)
    undecided = []
    for other in ledger.terminals():
        conflict = terminal_conflict(other, current)
        if conflict is None:
            continue
        precedes = True if conflict[0] == "DRT-4" else terminal_precedes(other, current)
        if precedes is None:
            undecided.append((conflict[0], "authenticated event positions cannot order this terminal against a conflicting terminal"))
        elif not precedes and current[:3] not in other.attested:
            undecided.append((conflict[0], "a later conflicting terminal's attested history omits this terminal"))
        elif precedes:
            return result("rejected", *conflict)
    if undecided:
        return result("indeterminate", *undecided[0])
    return None


def _protocol_stages(
    value: dict[str, Any],
) -> tuple[tuple[str, Callable[[], dict[str, str] | None]], ...]:
    """Return the section 9 checks in order; the first finding is the result.

    A later gate is added as one more named stage at its place in this order;
    it reads the same authenticated inputs and needs no change to other stages.
    The replay comparison follows these stages, in `evaluate_lifecycles`.
    """
    return (
        ("artifact-shape", lambda: _artifact_shape_check(value["artifacts"])),
        ("pipeline", lambda: _pipeline_check(value)),
        ("agreement", lambda: _agreement_check(value)),
        ("component-signatures", lambda: _component_signature_check(value)),
        ("selected-rail", lambda: _selected_rail_check(value)),
        ("references", lambda: _reference_check(value)),
        ("resolver-evidence", lambda: _resolver_evidence_check(value)),
        ("finding", lambda: _finding_check(value)),
        ("canonical-records", lambda: _canonical_record_check(value)),
        ("delivery-binding", lambda: _delivery_binding_check(value)),
        ("resolver-statuses", lambda: _external_evidence_check(value)),
        ("reproduction-inputs", lambda: _reproduction_input_check(value)),
        ("native-and-terminal", lambda: _native_and_terminal_check(value)),
        ("subject-evidence", lambda: _subject_evidence_check(value)),
    )


def _lifecycle_check(value: Any) -> dict[str, str] | None:
    """Apply every check before the replay comparison to one lifecycle."""
    if not isinstance(value, dict):
        return result("error", "DRV-2", "vector input must be an object")
    required = {
        "candidateProfile", "fixtureOnly", "pipeline", "artifacts", "publicKeys",
        "orchestratorClaim", "evaluatorVetResult", "profileParameters", "native",
        "resolverEvidence", "mappingSources", "canonicalRecords", "deliveryBinding",
        "bundleRequiredSigners", "reputationProjection", "submittedBeforeCutoff",
        "reproductionInputs",
        "executionContext",
    }
    if not required.issubset(value):
        return result("error", "DRV-2", "vector input is missing required fields")
    if value.get("candidateProfile") != "delivery-or-remedy-v1" or value.get("fixtureOnly") is not True:
        return result("error", "DRV-1", "only offline candidate-profile fixtures are accepted")
    object_fields = (
        "artifacts", "publicKeys", "profileParameters", "mappingSources",
        "canonicalRecords", "native", "resolverEvidence",
    )
    if not all(isinstance(value.get(field), dict) for field in object_fields):
        return result("error", "DRV-2", "candidate object fields are malformed")

    for _name, stage in _protocol_stages(value):
        issue = stage()
        if issue:
            return issue
    return None


def _replay_verdict(terminal: TerminalRecord, ledger: DecisionLedger) -> dict[str, str]:
    return _terminal_replay_check(terminal, ledger) or result(
        "verified", "DRV-7", "all applicable candidate checks passed"
    )


def _revise_issued(ledger: DecisionLedger) -> list[dict[str, Any]]:
    """Re-judge every verdict issued earlier against the terminals now known.

    A terminal recorded later can contradict a verdict already issued: the
    pinned resolver's records for two terminals can disagree, and the second
    record may arrive after the first verdict.  Each changed verdict is
    replaced in the ledger and returned as a revision, including one for a
    terminal evaluated again in this call: an earlier verdict may have been
    issued to another lifecycle with the same terminal.  Recording a terminal
    only adds conflicts, so a revision never upgrades a verdict.
    """
    revisions = []
    for terminal in ledger.terminals():
        previous = ledger.issued(terminal)
        if previous is None:
            continue
        revised = _replay_verdict(terminal, ledger)
        if revised != previous:
            ledger.issue(terminal, revised)
            revisions.append({"terminal": terminal_identity(terminal), "previous": previous, **revised})
    return revisions


def evaluate_lifecycles(values: list[Any], ledger: DecisionLedger) -> list[dict[str, Any]]:
    """Evaluate lifecycles together against verifier-owned replay state.

    Every lifecycle that passes the checks before the replay comparison first
    records its terminal in ``ledger``, whatever that comparison will decide.
    Each is then compared with every terminal the ledger holds, so the
    verdicts do not depend on the order of ``values``.  Verifying the same
    terminal again is idempotent.

    A verdict holds for the evidence evaluated so far.  When this call changes
    a verdict the ledger issued in an earlier call, every result it returns
    lists the change under `revises`: the terminal, its `previous` verdict, and
    the verdict that replaces it.  Applying the revisions to the verdicts
    already issued gives the verdicts of evaluating everything seen so far as
    one set, whatever the arrival order.
    """
    if not isinstance(ledger, DecisionLedger):
        raise TypeError("evaluate_lifecycles requires a verifier-owned DecisionLedger")
    issues = [_lifecycle_check(value) for value in values]
    terminals = [
        None if issue else _terminal_record(value) for value, issue in zip(values, issues)
    ]
    for terminal in terminals:
        if terminal is not None:
            ledger.record(terminal)
    revisions = _revise_issued(ledger)
    verdicts: list[dict[str, Any]] = []
    for issue, terminal in zip(issues, terminals):
        verdict = issue or _replay_verdict(terminal, ledger)
        if terminal is not None:
            ledger.issue(terminal, verdict)
        verdicts.append({**verdict, "revises": revisions} if revisions else verdict)
    return verdicts


def evaluate_protocol(value: Any, ledger: DecisionLedger) -> dict[str, Any]:
    """Evaluate one lifecycle against the terminals ``ledger`` already holds.

    The verdict uses the evidence known at the time.  With the resolver's
    complete attested history it does not depend on arrival order.  When the
    resolver's records contradict an earlier verdict, the result lists that
    verdict's revision under `revises` (see `evaluate_lifecycles`).
    """
    if not isinstance(ledger, DecisionLedger):
        raise TypeError("evaluate_protocol requires a verifier-owned DecisionLedger")
    return evaluate_lifecycles([value], ledger)[0]


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
    # Capability predicates come from the manifest itself.  Its own
    # fixtureOnly and registrationStatus labels cannot establish eligibility;
    # registration needs independently resolved deployment and registry facts
    # that this evaluator does not have, so it never reports eligibility.
    outcome["registrationEligible"] = False
    return outcome


def _pack_hash(pack: dict[str, Any], fields: tuple[str, ...]) -> str:
    return hashlib.sha256(canonical_bytes({field: pack[field] for field in fields})).hexdigest()


def verify_vector_pack(pack: Any) -> list[str]:
    if not isinstance(pack, dict):
        return ["candidate vector pack must be an object"]
    required = {
        "kind", "status", "spec", "generator", "hash", "count", "fixtures",
        "vectors", "promotionBlockedRules", "promotionBlockedProofs",
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
        pack, ("fixtures", "vectors", "promotionBlockedRules", "promotionBlockedProofs")
    ):
        errors.append("candidate vector pack hash is stale")
    # `promotionBlockedRules` are not executed at all.  `promotionBlockedProofs`
    # are executed against a synthetic evidence shape whose normative proof
    # shape is still undefined.
    for field in ("promotionBlockedRules", "promotionBlockedProofs"):
        blocked = pack.get(field)
        if not isinstance(blocked, dict) or not all(
            isinstance(rule, str)
            and isinstance(reason, str)
            and bool(reason.strip())
            for rule, reason in blocked.items()
        ):
            errors.append(f"{field} must map rule IDs to non-empty reasons")
    if isinstance(pack["promotionBlockedRules"], dict) and isinstance(pack["promotionBlockedProofs"], dict) and (
        set(pack["promotionBlockedRules"]) & set(pack["promotionBlockedProofs"])
    ):
        errors.append("a rule cannot be both unexecuted and proof-blocked")
    names: set[str] = set()
    by_name: dict[str, dict[str, Any]] = {}
    for vector in vectors:
        name = vector.get("name") if isinstance(vector, dict) else None
        if not isinstance(name, str) or not name or name in names:
            errors.append(f"invalid or duplicate candidate vector name: {name!r}")
            continue
        names.add(name)
        by_name[name] = vector
        rules = vector.get("rules")
        if (
            not isinstance(rules, list)
            or not rules
            or any(not isinstance(rule, str) for rule in rules)
            or rules != sorted(set(rules))
        ):
            errors.append(f"{name}: rules must be a non-empty sorted unique list")
        # Each vector is an independent verifier run.  `evaluatedWith` names
        # earlier vectors evaluated together with it, as one set.
        companions = vector.get("evaluatedWith", [])
        if not isinstance(companions, list) or any(
            companion not in by_name or companion == name for companion in companions
        ):
            errors.append(f"{name}: evaluatedWith must name earlier vectors")
            continue
        try:
            observed = evaluate_lifecycles(
                [materialize_vector(pack, by_name[companion]) for companion in companions]
                + [materialize_vector(pack, vector)],
                DecisionLedger(),
            )[-1]
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
