#!/usr/bin/env python3
"""Generate deterministic DACS-4 LAA-1..LAA-7 / DACS-3 CA-10 vectors."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "vectors" / "security"
    / "legacy-agreement-admission-v0.8.json"
)


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
        "agreement": {
            "artifact": artifact,
            "shape": "valid",
            "partySignaturesValid": True,
            "contentHash": "agreement-hash-a",
            "generatedAt": 10,
            "pbVerified": artifact == "payee-bound",
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
            "createdAt": 1,
        },
        "commitment": {
            "resolution": "verified",
            "shape": "valid",
            "agreementHashMatches": True,
            "signatureValid": True,
            "receiptState": "finalized",
            "position": "80",
            "strictlyBeforeAtSamePosition": None,
        },
        "settlementEvidence": {
            "resolution": "verified",
            "shape": "valid",
            "agreementBindingMatches": True,
            "signatureValid": True,
            "receiptState": "finalized",
            "position": "90",
            "strictlyBeforeAtSamePosition": None,
            "observedAt": 20,
        },
        "presentationPosition": "150",
    }


def case(
    name: str,
    expected: str,
    note: str,
    *,
    operation: str = "historical-audit",
    artifact: str = "legacy",
    changes: dict | None = None,
) -> dict:
    value = merge(base_input(operation=operation, artifact=artifact), changes)
    agreement = value["agreement"]
    current_eligible = (
        expected == "pass"
        and value["pipelineHasPayment"] is True
        and operation in {"authorize-payment", "commit-pay-bearing"}
    )
    historical_eligible = expected == "pass" and operation == "historical-audit"
    inspectable = agreement.get("shape") == "valid" and agreement.get("partySignaturesValid") is True
    return {
        "name": name,
        "expected": expected,
        "note": note,
        "input": value,
        "want": {
            "currentPaymentEligible": current_eligible,
            "historicalAuditEligible": historical_eligible,
            "paymentSideEffects": current_eligible,
            "legacyBytesCryptographicallyInspectable": inspectable and artifact == "legacy",
            "dacs5Admission": {
                "pass": "continue",
                "fail": "rejected",
                "error": "rejected",
                "indeterminate": "indeterminate",
            }[expected],
        },
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
            "laa-zero-pay-legacy-outside-gate", "pass",
            "a pipeline with no payment introduces no runtime payout destination",
            operation="commit-pay-bearing",
            changes={"pipelineHasPayment": False},
        ),
        case(
            "laa-preactivation-authoritative-absence-allows-legacy", "pass",
            "binding-qualified absence at an authenticated head proves activation has not occurred",
            operation="authorize-payment",
            changes={"checkpoint": {"resolution": "absent", "authenticatedAbsence": True}},
        ),
        case(
            "laa-ca10-preactivation-legacy-commit", "pass",
            "CA-10 permits legacy commitment only under authenticated preactivation absence",
            operation="commit-pay-bearing",
            changes={"surface": "dacs3-ca10", "checkpoint": {"resolution": "absent", "authenticatedAbsence": True}},
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
    ]


def document() -> dict:
    values = vectors()
    encoded = json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {
        "set": OUTPUT.stem,
        "spec": "DACS-4 v0.8 §9.5.1 LAA-1..LAA-7; DACS-3 v0.6 §8.6 CA-10",
        "tier": "candidate",
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
