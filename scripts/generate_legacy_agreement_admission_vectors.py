#!/usr/bin/env python3
"""Generate deterministic DACS-4 LAA-1..LAA-7 / DACS-3 CA-10 vectors.

The expected verdict and declared effects are computed by the single shared
verifier-owned LAA oracle (``tests/dacs5_reference.laa_admission`` /
``laa_want``) rather than hand-asserted per case, so the corpus cannot drift
from the executable reference.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "vectors" / "security"
    / "legacy-agreement-admission-v0.8.json"
)
GOVERNING_SUBSTRATE = "demos-mainnet"
ORDER_DOMAIN = "demos-mainnet:demos-bft-final:genesis-v1"

sys.path.insert(0, str(ROOT / "tests"))
import dacs5_reference as R  # noqa: E402


def merge(base: dict, changes: dict | None) -> dict:
    value = copy.deepcopy(base)
    for key, item in (changes or {}).items():
        if isinstance(item, dict) and isinstance(value.get(key), dict):
            value[key] = merge(value[key], item)
        else:
            value[key] = copy.deepcopy(item)
    return value


def base_input(*, operation: str = "historical-audit", artifact: str = "legacy") -> dict:
    return {
        "surface": "dacs4-laa",
        "operation": operation,
        "pipelineHasPayment": True,
        "sessionAuthority": {
            "state": "verified",
            "substrate": GOVERNING_SUBSTRATE,
            "orderDomain": ORDER_DOMAIN,
            "jobId": "job-a",
            "sessionId": "session-a",
            "paymentHeadPosition": "150",
        },
        "agreement": {
            "artifact": artifact,
            "shape": "valid",
            "partySignaturesValid": True,
            "contentHash": "agreement-hash-a",
            "jobId": "job-a",
            "phase": "pay-dem",
            "generatedAt": 10,
            "pbVerified": artifact in R.LAA_PAYEE_BOUND_ARTIFACTS,
            "ibhVerified": artifact in {"identity-bound", "identity-bound-payee"},
        },
        "checkpoint": {
            "resolution": "verified",
            "discriminator": "legacyAgreementCheckpointVersion:1",
            "shape": "valid",
            "signatureValid": True,
            "signatureDomain": "dacs-legacy-agreement-checkpoint:v1:",
            "stewardAuthorized": True,
            "addressMatches": True,
            "policyMatches": True,
            "receiptState": "finalized",
            "position": "100",
            "authenticatedAbsence": False,
            "absenceCoverPosition": "200",
            "createdAt": 1,
            "substrate": GOVERNING_SUBSTRATE,
            "orderDomain": ORDER_DOMAIN,
        },
        "commitment": {
            "resolution": "verified",
            "shape": "valid",
            "agreementHashMatches": True,
            "signatureValid": True,
            "receiptState": "finalized",
            "position": "80",
            "strictlyBeforeAtSamePosition": None,
            "substrate": GOVERNING_SUBSTRATE,
            "orderDomain": ORDER_DOMAIN,
        },
        "settlementEvidence": {
            "resolution": "verified",
            "shape": "valid",
            "agreementBindingMatches": True,
            "agreementHash": "agreement-hash-a",
            "job": "job-a",
            "session": "session-a",
            "phase": "pay-dem",
            "signatureValid": True,
            "receiptState": "finalized",
            "position": "90",
            "strictlyBeforeAtSamePosition": None,
            "observedAt": 20,
            "substrate": GOVERNING_SUBSTRATE,
            "orderDomain": ORDER_DOMAIN,
        },
        "presentationPosition": "150",
        "paymentPosition": "150",
    }


def case(
    name: str,
    expected: str,
    note: str,
    *,
    operation: str = "historical-audit",
    artifact: str = "legacy",
    changes: dict | None = None,
    drops: list[tuple[str, str]] | None = None,
) -> dict:
    value = merge(base_input(operation=operation, artifact=artifact), changes)
    for container, key in (drops or []):
        if isinstance(value.get(container), dict):
            value[container].pop(key, None)
    verdict = R.laa_admission(value)
    if verdict != expected:
        raise AssertionError(
            f"{name}: shared LAA oracle returns {verdict!r}, declared {expected!r}"
        )
    return {
        "name": name,
        "expected": verdict,
        "note": note,
        "input": value,
        "want": R.laa_want(value),
    }


def vectors() -> list[dict]:
    return [
        case(
            "laa-current-payee-bound-success", "pass",
            "current pay-bearing settlement uses the destination-bound artifact",
            operation="authorize-payment", artifact="payee-bound",
        ),
        case(
            "laa-payee-bound-does-not-fallback-on-checkpoint-outage", "pass",
            "checkpoint uncertainty never forces the safe current artifact onto legacy",
            operation="authorize-payment", artifact="payee-bound",
            changes={"checkpoint": {"resolution": "unavailable"}},
        ),
        case(
            "laa-identity-bound-payee-success", "pass",
            "the stronger identity-bound payee artifact is accepted wherever payee-bound is",
            operation="authorize-payment", artifact="identity-bound-payee",
        ),
        case(
            "laa-identity-bound-non-payee-rejected", "fail",
            "a non-payee identity-bound agreement cannot authorize a current pay-bearing payment",
            operation="authorize-payment", artifact="identity-bound",
        ),
        case(
            "laa-identity-bound-payee-ibh-not-verified", "fail",
            "an identity-bound payee artifact whose identity binding fails does not authorize payment",
            operation="authorize-payment", artifact="identity-bound-payee",
            changes={"agreement": {"ibhVerified": False}},
        ),
        case(
            "laa-ca10-identity-bound-payee-commit", "pass",
            "commit-identity-bound-payee-agreement is available pre-activation without payment side effects",
            operation="commit-pay-bearing", artifact="identity-bound-payee",
            changes={"surface": "dacs3-ca10"},
        ),
        case(
            "laa-zero-pay-legacy-outside-gate", "pass",
            "a pipeline with no payment introduces no runtime payout destination",
            operation="commit-pay-bearing",
            changes={"pipelineHasPayment": False},
        ),
        case(
            "laa-preactivation-authoritative-absence-allows-legacy", "pass",
            "binding-qualified absence covering the payment position proves activation has not occurred",
            operation="authorize-payment",
            changes={"checkpoint": {"resolution": "absent", "authenticatedAbsence": True}},
        ),
        case(
            "laa-stale-absence-across-activation-boundary", "indeterminate",
            "an authenticated absence proven only up to an earlier head does not cover a later payment submission",
            operation="authorize-payment",
            changes={"checkpoint": {"resolution": "absent", "authenticatedAbsence": True, "absenceCoverPosition": "50"}},
        ),
        case(
            "laa-absence-cover-position-malformed", "error",
            "a non-string absence-cover position is a structural error before the payment effect",
            operation="authorize-payment",
            changes={"checkpoint": {"resolution": "absent", "authenticatedAbsence": True, "absenceCoverPosition": 200}},
        ),
        case(
            "laa-caller-lowered-payment-position-cannot-mask-stale-absence", "indeterminate",
            "a caller-supplied low payment position cannot convert a stale absence proof into a pass",
            operation="authorize-payment",
            changes={
                "checkpoint": {"resolution": "absent", "authenticatedAbsence": True, "absenceCoverPosition": "50"},
                "paymentPosition": "40",
            },
        ),
        case(
            "laa-authenticated-head-position-non-string", "error",
            "a non-string authenticated payment-head position is a structural error",
            operation="authorize-payment",
            changes={
                "sessionAuthority": {"paymentHeadPosition": 150},
                "checkpoint": {"resolution": "absent", "authenticatedAbsence": True},
            },
        ),
        case(
            "laa-ca10-preactivation-legacy-commit", "pass",
            "CA-10 permits legacy commitment only under authenticated preactivation absence covering the commit position",
            operation="commit-pay-bearing",
            changes={"surface": "dacs3-ca10", "checkpoint": {"resolution": "absent", "authenticatedAbsence": True}},
        ),
        case(
            "laa-ca10-stale-absence-across-activation-boundary", "indeterminate",
            "CA-10 cannot rely on a stale authenticated absence for a later commit",
            operation="commit-pay-bearing",
            changes={"surface": "dacs3-ca10", "checkpoint": {"resolution": "absent", "authenticatedAbsence": True, "absenceCoverPosition": "50"}},
        ),
        case(
            "laa-fresh-legacy-after-checkpoint", "fail",
            "a current legacy agreement cannot authorize payment after activation",
            operation="authorize-payment",
            changes={"commitment": {"position": "110"}, "settlementEvidence": {"position": "120"}},
        ),
        case(
            "laa-ca10-postactivation-legacy-commit", "fail",
            "CA-10 rejects commit-agreement for a current pay-bearing session",
            operation="commit-pay-bearing", changes={"surface": "dacs3-ca10"},
        ),
        case(
            "laa-backdated-generated-at", "fail",
            "backdating agreement metadata cannot overcome a post-checkpoint commitment",
            operation="authorize-payment",
            changes={"agreement": {"generatedAt": -1000}, "commitment": {"position": "110"}},
        ),
        case(
            "laa-no-in-flight-transition", "fail",
            "a pre-checkpoint commitment cannot initiate payment after immediate activation",
            operation="authorize-payment",
            changes={"commitment": {"position": "80"}, "settlementEvidence": {"resolution": "absent"}},
        ),
        case(
            "laa-authentic-historical-settlement", "pass",
            "exact commitment and settlement evidence finalized strictly before the checkpoint",
        ),
        case(
            "laa-later-presentation-preserves-historical-era", "pass",
            "presentation after activation does not change verified original anchor order",
            changes={"presentationPosition": "9999"},
        ),
        case(
            "laa-checkpoint-unavailable", "indeterminate",
            "transport failure is not proof that activation has not occurred",
            operation="authorize-payment", changes={"checkpoint": {"resolution": "unavailable"}},
        ),
        case(
            "laa-ordinary-not-found", "indeterminate",
            "unqualified not-found is not binding-qualified authoritative absence",
            operation="authorize-payment", changes={"checkpoint": {"resolution": "absent", "authenticatedAbsence": False}},
        ),
        case(
            "laa-other-substrate-absence-is-inert", "fail",
            "authenticated absence on another substrate cannot evade this session's checkpoint",
            operation="authorize-payment",
            changes={"checkpoint": {"resolution": "absent", "authenticatedAbsence": True, "substrate": "other-mainnet"}},
        ),
        case(
            "laa-conflicting-checkpoints", "indeterminate",
            "multiple authorized checkpoint candidates do not establish an activation order",
            changes={"checkpoint": {"resolution": "conflicting"}},
        ),
        case(
            "laa-checkpoint-reorged", "indeterminate",
            "a reorged checkpoint receipt does not establish activation authority",
            changes={"checkpoint": {"resolution": "reorged"}},
        ),
        case(
            "laa-checkpoint-signature-invalid", "fail",
            "checkpoint must be signed by the authorized steward",
            changes={"checkpoint": {"signatureValid": False}},
        ),
        case(
            "laa-checkpoint-signer-unauthorized", "fail",
            "a valid signature from a non-steward is not checkpoint authority",
            changes={"checkpoint": {"stewardAuthorized": False}},
        ),
        case(
            "laa-checkpoint-address-mismatch", "fail",
            "checkpoint fetched away from its derived fixed address is rejected",
            changes={"checkpoint": {"addressMatches": False}},
        ),
        case(
            "laa-checkpoint-policy-mismatch", "fail",
            "an artifact signed for another transition policy is not this checkpoint",
            changes={"checkpoint": {"policyMatches": False}},
        ),
        case(
            "laa-checkpoint-cross-domain-signature", "fail",
            "a signature under another artifact domain cannot activate the gate",
            changes={"checkpoint": {"signatureDomain": "dacs-agreement:v1:"}},
        ),
        case(
            "laa-checkpoint-malformed", "error",
            "malformed checkpoint bytes are structural error",
            changes={"checkpoint": {"shape": "malformed"}},
        ),
        case(
            "laa-checkpoint-multiple-discriminators", "error",
            "ambiguous checkpoint type is rejected before policy action",
            changes={"checkpoint": {"discriminator": "multiple"}},
        ),
        case(
            "laa-checkpoint-not-finalized", "indeterminate",
            "included-only checkpoint does not yet establish activation",
            changes={"checkpoint": {"receiptState": "included"}},
        ),
        case(
            "laa-checkpoint-substrate-mismatch", "fail",
            "the checkpoint substrate must equal the authenticated session and receipt substrate",
            changes={"checkpoint": {"substrate": "other-mainnet"}},
        ),
        case(
            "laa-checkpoint-cross-order-domain", "indeterminate",
            "a checkpoint from another consensus ordering domain is not position-comparable",
            changes={"checkpoint": {"orderDomain": "demos-mainnet:other-finality:genesis-v1"}},
        ),
        case(
            "laa-missing-commitment-era-proof", "indeterminate",
            "historical audit cannot infer agreement era without commitment authority",
            changes={"commitment": {"resolution": "unavailable"}},
        ),
        case(
            "laa-commitment-hash-mismatch", "fail",
            "a real old commitment for different agreement bytes does not qualify",
            changes={"commitment": {"agreementHashMatches": False}},
        ),
        case(
            "laa-commitment-not-finalized", "indeterminate",
            "non-final commitment history is not era proof",
            changes={"commitment": {"receiptState": "included"}},
        ),
        case(
            "laa-commitment-substrate-mismatch", "fail",
            "a commitment receipt on another substrate cannot be ordered against this checkpoint",
            changes={"commitment": {"substrate": "other-mainnet"}},
        ),
        case(
            "laa-commitment-cross-order-domain", "indeterminate",
            "equal-looking positions from different commitment order domains are incomparable",
            changes={"commitment": {"orderDomain": "demos-mainnet:other-finality:genesis-v1"}},
        ),
        case(
            "laa-missing-settlement-era-proof", "indeterminate",
            "old agreement alone cannot prove payment happened before activation",
            changes={"settlementEvidence": {"resolution": "unavailable"}},
        ),
        case(
            "laa-settlement-binding-mismatch", "fail",
            "settlement evidence for another agreement cannot qualify history",
            changes={"settlementEvidence": {"agreementBindingMatches": False}},
        ),
        case(
            "laa-settlement-not-finalized", "indeterminate",
            "included-only settlement evidence is not historical authority",
            changes={"settlementEvidence": {"receiptState": "included"}},
        ),
        case(
            "laa-settlement-substrate-mismatch", "fail",
            "the DACS SettlementEvidence anchor receipt must share the checkpoint substrate",
            changes={"settlementEvidence": {"substrate": "other-mainnet"}},
        ),
        case(
            "laa-settlement-cross-order-domain", "indeterminate",
            "a settlement-evidence receipt from another ordering domain is incomparable",
            changes={"settlementEvidence": {"orderDomain": "demos-mainnet:other-finality:genesis-v1"}},
        ),
        case(
            "laa-same-position-unorderable", "indeterminate",
            "same block without authenticated transaction order is not strictly earlier",
            changes={"commitment": {"position": "100", "strictlyBeforeAtSamePosition": None}},
        ),
        case(
            "laa-same-position-strict-order", "pass",
            "binding-authenticated same-block transaction order can prove strict precedence",
            changes={
                "commitment": {"position": "100", "strictlyBeforeAtSamePosition": True},
                "settlementEvidence": {"position": "100", "strictlyBeforeAtSamePosition": True},
            },
        ),
        case(
            "laa-backdated-evidence-observed-at", "fail",
            "producer evidence time cannot make a post-checkpoint receipt historical",
            changes={"settlementEvidence": {"position": "101", "observedAt": -5000}},
        ),
        case(
            "laa-deterministic-mismatch-precedes-outage", "fail",
            "bad agreement signature cannot be hidden by checkpoint unavailability",
            operation="authorize-payment",
            changes={"agreement": {"partySignaturesValid": False}, "checkpoint": {"resolution": "unavailable"}},
        ),
        case(
            "laa-malformed-agreement", "error",
            "malformed agreement is an error even when checkpoint proof is unavailable",
            operation="authorize-payment",
            changes={"agreement": {"shape": "malformed"}, "checkpoint": {"resolution": "unavailable"}},
        ),
        case(
            "laa-cross-agreement-replay", "fail",
            "authentic settlement evidence bound to a different agreement cannot qualify this agreement's history",
            changes={"settlementEvidence": {"agreementHash": "agreement-hash-other"}},
        ),
        case(
            "laa-cross-job-replay", "fail",
            "settlement evidence bound to a different job cannot qualify this agreement's history",
            changes={"settlementEvidence": {"job": "job-other"}},
        ),
        case(
            "laa-cross-session-replay", "fail",
            "settlement evidence bound to a different session cannot qualify this agreement's history",
            changes={"settlementEvidence": {"session": "session-other"}},
        ),
        case(
            "laa-cross-phase-replay", "fail",
            "settlement evidence bound to a different phase cannot qualify this agreement's history",
            changes={"settlementEvidence": {"phase": "pay-evm-erc20"}},
        ),
        case(
            "laa-agreement-job-session-mismatch", "fail",
            "an agreement whose jobId does not match the authenticated session jobId cannot qualify",
            changes={"agreement": {"jobId": "job-other"}},
        ),
        case(
            "laa-malformed-agreement-wrong-container", "error",
            "a non-object agreement container is a structural error before field access",
            operation="authorize-payment",
            changes={"agreement": []},
        ),
        case(
            "laa-malformed-checkpoint-wrong-container", "error",
            "a non-object checkpoint container is a structural error before field access",
            operation="authorize-payment",
            changes={"checkpoint": []},
        ),
        case(
            "laa-malformed-commitment-missing-field", "error",
            "a commitment missing a required structural field is a structural error",
            drops=[("commitment", "shape")],
        ),
        case(
            "laa-malformed-settlement-position-scalar", "error",
            "a non-string receipt position is a structural error before ordering",
            changes={"settlementEvidence": {"position": 90}},
        ),
        case(
            "laa-malformed-checkpoint-conflicting-shape", "error",
            "a checkpoint whose discriminator is not the exact literal is a structural error",
            operation="authorize-payment",
            changes={"checkpoint": {"shape": "valid", "discriminator": ["a", "b"]}},
        ),
        case(
            "laa-malformed-agreement-artifact-unhashable", "error",
            "an unhashable agreement artifact is a structural error before membership tests",
            operation="authorize-payment",
            changes={"agreement": {"artifact": ["legacy"]}},
        ),
        case(
            "laa-malformed-settlement-position-unhashable-list", "error",
            "an unhashable list receipt position returns error, never a crash",
            changes={"settlementEvidence": {"position": ["90"]}},
        ),
        case(
            "laa-malformed-settlement-position-unhashable-dict", "error",
            "an unhashable dict receipt position returns error, never a crash",
            changes={"settlementEvidence": {"position": {"block": 90}}},
        ),
        case(
            "laa-malformed-commitment-position-unhashable", "error",
            "an unhashable commitment receipt position returns error, never a crash",
            changes={"commitment": {"position": ["80"]}},
        ),
        case(
            "laa-malformed-settlement-missing-agreement-binding", "error",
            "a settlement-evidence record missing agreementBindingMatches is a structural error, not a fail",
            drops=[("settlementEvidence", "agreementBindingMatches")],
        ),
        case(
            "laa-malformed-commitment-missing-hash-binding", "error",
            "a commitment missing agreementHashMatches is a structural error, not a fail",
            drops=[("commitment", "agreementHashMatches")],
        ),
        case(
            "laa-malformed-operation-unhashable-list", "error",
            "an unhashable list operation returns error, never a TypeError",
            changes={"operation": ["historical-audit"]},
        ),
        case(
            "laa-malformed-operation-unhashable-dict", "error",
            "an unhashable dict operation returns error, never a TypeError",
            changes={"operation": {"kind": "historical-audit"}},
        ),
        case(
            "laa-malformed-agreement-contentHash-missing", "error",
            "a legacy agreement missing contentHash is a structural error, not a hash fail",
            drops=[("agreement", "contentHash")],
        ),
        case(
            "laa-malformed-checkpoint-signatureValid-missing", "error",
            "a checkpoint missing signatureValid is a structural error, not a signature fail",
            drops=[("checkpoint", "signatureValid")],
        ),
        case(
            "laa-malformed-checkpoint-receiptState-nonstring", "error",
            "a non-string checkpoint receiptState is a structural error, not indeterminate",
            changes={"checkpoint": {"receiptState": ["finalized"]}},
        ),
        case(
            "laa-malformed-checkpoint-receiptState-unknown", "error",
            "an unknown checkpoint receiptState spelling is a structural error, not indeterminate",
            changes={"checkpoint": {"receiptState": "bogus"}},
        ),
        case(
            "laa-malformed-commitment-receiptState-missing", "error",
            "a commitment missing receiptState is a structural error, not indeterminate",
            drops=[("commitment", "receiptState")],
        ),
        case(
            "laa-malformed-settlement-receiptState-unknown", "error",
            "an unknown settlement receiptState spelling is a structural error, not indeterminate",
            changes={"settlementEvidence": {"receiptState": "bogus"}},
        ),
        case(
            "laa-malformed-commitment-signatureValid-missing", "error",
            "a commitment missing signatureValid is a structural error, not a signature fail",
            drops=[("commitment", "signatureValid")],
        ),
        case(
            "laa-malformed-settlement-signatureValid-missing", "error",
            "a settlement-evidence record missing signatureValid is a structural error",
            drops=[("settlementEvidence", "signatureValid")],
        ),
        case(
            "laa-malformed-native-order-unhashable", "error",
            "an unhashable same-block native-order flag is a structural error, not a silent fall-through",
            changes={
                "commitment": {"position": "100", "strictlyBeforeAtSamePosition": ["x"]},
                "settlementEvidence": {"position": "100", "strictlyBeforeAtSamePosition": True},
            },
        ),
        case(
            "laa-malformed-payment-head-dict", "error",
            "a non-string authenticated payment-head position is a structural error",
            operation="authorize-payment",
            changes={
                "sessionAuthority": {"paymentHeadPosition": {"block": 150}},
                "checkpoint": {"resolution": "absent", "authenticatedAbsence": True},
            },
        ),
        case(
            "laa-malformed-session-jobId-nonstring", "error",
            "a non-string authenticated session jobId is a structural error",
            changes={"sessionAuthority": {"jobId": ["job-a"]}},
        ),
        case(
            "laa-malformed-settlement-agreementHash-missing", "error",
            "a settlement-evidence record missing agreementHash is a structural error, not a binding fail",
            drops=[("settlementEvidence", "agreementHash")],
        ),
        case(
            "laa-malformed-settlement-job-missing", "error",
            "a settlement-evidence record missing the bound job is a structural error, not a replay fail",
            drops=[("settlementEvidence", "job")],
        ),
        case(
            "laa-malformed-payee-bound-contentHash-missing", "error",
            "a payee-bound agreement missing contentHash is a structural error before the current-payment pass",
            operation="authorize-payment", artifact="payee-bound",
            drops=[("agreement", "contentHash")],
        ),
        case(
            "laa-malformed-identity-bound-contentHash-missing", "error",
            "an identity-bound agreement missing contentHash is a structural error before the artifact branch",
            operation="authorize-payment", artifact="identity-bound",
            drops=[("agreement", "contentHash")],
        ),
        case(
            "laa-absence-with-malformed-operation", "error",
            "an authenticated absence branch cannot authorize before operation is validated as a scalar known value",
            operation="authorize-payment",
            changes={
                "operation": ["authorize-payment"],
                "checkpoint": {"resolution": "absent", "authenticatedAbsence": True},
            },
        ),
        # --- Identity values: empty / whitespace / non-canonical session or hash
        # identity is malformed and rejected before any payee-bound / identity-bound /
        # zero-pay / absence / checkpoint branch may otherwise authorize. ---
        case(
            "laa-payee-bound-empty-content-hash", "error",
            "an empty payee-bound contentHash is malformed identity, rejected before the current-payment pass",
            operation="authorize-payment", artifact="payee-bound",
            changes={"agreement": {"contentHash": ""}},
        ),
        case(
            "laa-payee-bound-whitespace-content-hash", "error",
            "a whitespace-only payee-bound contentHash is malformed identity",
            operation="authorize-payment", artifact="payee-bound",
            changes={"agreement": {"contentHash": "   "}},
        ),
        case(
            "laa-identity-bound-payee-padded-content-hash", "error",
            "a leading/trailing-whitespace identity-bound-payee contentHash is non-canonical",
            operation="authorize-payment", artifact="identity-bound-payee",
            changes={"agreement": {"contentHash": " agreement-hash-a "}},
        ),
        case(
            "laa-zero-pay-legacy-whitespace-content-hash", "error",
            "a whitespace-only contentHash cannot authorize the legacy zero-pay branch",
            operation="commit-pay-bearing",
            changes={"pipelineHasPayment": False, "agreement": {"contentHash": "   "}},
        ),
        case(
            "laa-empty-session-id", "error",
            "an empty authenticated sessionId is malformed identity, rejected before the checkpoint branch",
            changes={"sessionAuthority": {"sessionId": ""}},
        ),
        case(
            "laa-whitespace-session-id", "error",
            "a whitespace-only authenticated sessionId is malformed identity",
            changes={"sessionAuthority": {"sessionId": "   "}},
        ),
        case(
            "laa-padded-session-id", "error",
            "a leading/trailing-whitespace authenticated sessionId is non-canonical",
            changes={"sessionAuthority": {"sessionId": " session-a "}},
        ),
        case(
            "laa-padded-content-hash", "error",
            "a leading/trailing-whitespace agreement contentHash is non-canonical identity",
            changes={"agreement": {"contentHash": " agreement-hash-a "}},
        ),
        # --- Session identity is validated AHEAD of the payee-bound /
        # identity-bound-payee pass, so an empty / blank / padded / non-NFC
        # sessionId can never authorize a current payment on either artifact. ---
        case(
            "laa-payee-bound-empty-session-id", "error",
            "an empty payee-bound sessionId is malformed identity, rejected before the current-payment pass",
            operation="authorize-payment", artifact="payee-bound",
            changes={"sessionAuthority": {"sessionId": ""}},
        ),
        case(
            "laa-payee-bound-whitespace-session-id", "error",
            "a whitespace-only payee-bound sessionId is malformed identity",
            operation="authorize-payment", artifact="payee-bound",
            changes={"sessionAuthority": {"sessionId": "   "}},
        ),
        case(
            "laa-payee-bound-padded-session-id", "error",
            "a leading/trailing-whitespace payee-bound sessionId is non-canonical",
            operation="authorize-payment", artifact="payee-bound",
            changes={"sessionAuthority": {"sessionId": " session-a "}},
        ),
        case(
            "laa-payee-bound-noncanonical-session-id", "error",
            "a non-NFC payee-bound sessionId is malformed identity",
            operation="authorize-payment", artifact="payee-bound",
            changes={"sessionAuthority": {"sessionId": "session-a\u0301"}},
        ),
        case(
            "laa-identity-bound-payee-empty-session-id", "error",
            "an empty identity-bound-payee sessionId is malformed identity, rejected before the pass",
            operation="authorize-payment", artifact="identity-bound-payee",
            changes={"sessionAuthority": {"sessionId": ""}},
        ),
        case(
            "laa-identity-bound-payee-whitespace-session-id", "error",
            "a whitespace-only identity-bound-payee sessionId is malformed identity",
            operation="authorize-payment", artifact="identity-bound-payee",
            changes={"sessionAuthority": {"sessionId": "   "}},
        ),
        case(
            "laa-identity-bound-payee-padded-session-id", "error",
            "a leading/trailing-whitespace identity-bound-payee sessionId is non-canonical",
            operation="authorize-payment", artifact="identity-bound-payee",
            changes={"sessionAuthority": {"sessionId": " session-a "}},
        ),
        case(
            "laa-identity-bound-payee-noncanonical-session-id", "error",
            "a non-NFC identity-bound-payee sessionId is malformed identity",
            operation="authorize-payment", artifact="identity-bound-payee",
            changes={"sessionAuthority": {"sessionId": "session-a\u0301"}},
        ),
    ]


RELEASE_PIN = "0000000000000000000000000000000000000001"
CURRENT_MODULE_TUPLE = {
    "core": "0.3",
    "dacs1": "0.7",
    "dacs2": "0.6",
    "dacs3": "0.6",
    "dacs4": "0.8",
    "dacs5": "0.6",
}


def document() -> dict:
    values = vectors()
    encoded = json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {
        "set": OUTPUT.stem,
        "spec": "DACS-4 v0.8 §9.5.1 LAA-1..LAA-7; DACS-3 v0.6 §8.6 CA-10",
        "tier": "candidate",
        "profile": {
            "releasePin": RELEASE_PIN,
            "moduleVersions": CURRENT_MODULE_TUPLE,
        },
        "description": "Governed legacy-agreement activation and authenticated historical settlement admission.",
        "provenance": {
            "issue": "DACS-Agent-commerce/DACS-Standard#377",
            "generator": "scripts/generate_legacy_agreement_admission_vectors.py",
        },
        "count": len(values),
        "hash": hashlib.sha256(encoded).hexdigest(),
        "vectors": values,
    }


def render() -> bytes:
    return (json.dumps(document(), indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.write:
        OUTPUT.write_bytes(expected)
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    if not OUTPUT.exists() or OUTPUT.read_bytes() != expected:
        print(f"ERROR: {OUTPUT.relative_to(ROOT)} is not deterministic/in sync")
        return 1
    print(f"verified {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
