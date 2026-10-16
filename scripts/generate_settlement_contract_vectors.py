#!/usr/bin/env python3
"""Deterministic PC-1 and AMEND-1 fixtures using public Atomic test keys."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

import atomic_work_reference as ref
import generate_atomic_work_vectors as atomic

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance/fixtures/settlement/payment-input-amendment-v0.1.json"


def build_fixture():
    purchase = atomic.purchase_intent()
    authority = atomic.authorization_authority(purchase)
    atomic_input = authority["paymentPhaseInput"]
    ordinary_input = copy.deepcopy(atomic_input)
    ordinary_input.pop("atomicSessionContext")
    ordinary_input["sessionContext"] = authority["sessionContextSource"]
    inputs = []

    def phase(name, binding, value, expected):
        inputs.append({"name": name, "ruleRefs": ["PC-1"], "binding": binding,
                       "input": value, "expected": expected})

    phase("ordinary-input", "ordinary", ordinary_input, "accepted")
    phase("atomic-input", "atomic", atomic_input, "accepted")
    phase("ordinary-receives-atomic", "ordinary", atomic_input, "rejected")
    phase("atomic-receives-ordinary", "atomic", ordinary_input, "rejected")
    mixed = {**ordinary_input, "atomicSessionContext": atomic_input["atomicSessionContext"]}
    for binding in ("ordinary", "atomic"):
        phase(binding + "-receives-both-contexts", binding, mixed, "rejected")
    for binding in ("ungated-purchase", "completion", "other-payment"):
        phase(binding + "-uses-ordinary-arm", binding, atomic_input, "rejected")
        phase(binding + "-accepts-ordinary-arm", binding, ordinary_input, "accepted")
    phase("ordinary-keeps-unknown-members", "ordinary",
          {**ordinary_input, "paymentAuthorization": {"opaque": True}}, "accepted")
    phase("atomic-rejects-unknown-member", "atomic",
          {**atomic_input, "paymentAuthorization": {}}, "rejected")
    missing = copy.deepcopy(ordinary_input)
    missing.pop("sessionContext")
    phase("ordinary-context-missing", "ordinary", missing, "rejected")
    for member in atomic_input:
        missing = copy.deepcopy(atomic_input)
        missing.pop(member)
        phase("atomic-missing-" + member, "atomic", missing, "rejected")

    receipt = atomic.final_receipt(purchase)
    atomic_target = atomic.settlement_evidence(purchase, receipt, "payment")
    completion = atomic.completion_intent(receipt)
    atomic_delivery = atomic.settlement_evidence(completion, atomic.final_receipt(completion), "delivery")
    ordinary_target = {
        "evidenceVersion": "1", "jobId": purchase["jobId"], "phase": "pay-dem",
        "outcome": "success", "paymentTxRefs": [{"kind": "demos", "txHash": "ab" * 32}],
        "paymentAmount": {"amount": "10", "currency": "DEM"},
        "settlementFinality": {"model": "bft-final", "finalityObservedAt": 1_800_000_030_000},
        "observedAt": 1_800_000_030_000,
    }
    targets = []

    def target_case(name, target, domain, expected, *, edit=None, resolution="finalized"):
        target = ref.sign_embedded(target, atomic.CLAIMS["orchestrator"],
                                   atomic.SEEDS["orchestrator"], domain)
        unsigned = {k: v for k, v in target.items() if k != "signature"}
        digest = ref.sha256_hex(ref.jcs_bytes(unsigned))
        locator = f"dacs4:payment:{purchase['jobId']}:fixture-{name}:2"
        target_ref = {"anchor": {"kind": "storage-program", "locator": locator},
                      "contentHash": digest}
        anchor = atomic.registry_anchor_receipt(locator, unsigned, label=name, nonce="300")
        amendment = ref.sign_embedded({
            "amendmentVersion": "1", "jobId": purchase["jobId"],
            "amendsEvidenceRef": target_ref, "amendmentType": "correction",
            "reason": "fixture correction", "observedAt": 1_800_000_040_000,
        }, atomic.CLAIMS["seller"], atomic.SEEDS["seller"], ref._AMENDMENT_DOMAIN)
        resolved = {"artifact": target, "anchorReceipt": anchor}
        if resolution == "unavailable":
            resolved = None
        elif resolution == "unanchored":
            resolved.pop("anchorReceipt")
        elif resolution == "included":
            anchor["state"] = "included"
        if edit:
            edit(resolved)
        targets.append({"name": name, "ruleRefs": ["AMEND-1"], "amendment": amendment,
                        "resolved": resolved, "expected": expected,
                        "amendmentAddress": f"dacs4:amendment:{purchase['jobId']}:{digest}:0"})

    for label, base, domain, selector, other in (
        ("ordinary", ordinary_target, b"dacs-evidence:v1:", "evidenceVersion", ref.EVIDENCE_DOMAIN),
        ("atomic", atomic_target, ref.EVIDENCE_DOMAIN, "atomicEvidenceVersion", b"dacs-evidence:v1:"),
    ):
        target_case(label + "-target", base, domain, "valid")
        target_case(label + "-unsupported-version", {**base, selector: "2"}, domain, "violation")
        target_case(label + "-wrong-domain", base, other, "violation")
        target_case(label + "-wrong-job", {**base, "jobId": "01K1DPA0000000000000000009"}, domain, "violation")
        delivery = atomic_delivery if label == "atomic" else {**base, "phase": "deliver-storage-program"}
        target_case(label + "-delivery-target", delivery, domain, "violation")
        for state in ("unavailable", "unanchored", "included"):
            target_case(label + "-" + state, base, domain, "indeterminate", resolution=state)
    target_case("ordinary-projection-phase", {**ordinary_target, "phase": "pay-alternative"}, b"dacs-evidence:v1:", "violation")
    malformed_atomic = {k: v for k, v in atomic_target.items() if k != "workReceiptRef"}
    target_case("atomic-malformed-member", malformed_atomic, ref.EVIDENCE_DOMAIN, "violation")
    target_case("ordinary-malformed-outcome", {**ordinary_target, "outcome": "unknown"}, b"dacs-evidence:v1:", "violation")
    no_selector = {k: v for k, v in atomic_target.items() if k not in ref.EVIDENCE_SELECTORS}
    target_case("no-selector", no_selector, ref.EVIDENCE_DOMAIN, "violation")
    target_case("dual-selectors", {**atomic_target, "evidenceVersion": "1"}, ref.EVIDENCE_DOMAIN, "violation")
    target_case("unsupported-selector", {**no_selector, "deliveryEvidenceVersion": "1"}, ref.EVIDENCE_DOMAIN, "violation")
    target_case("all-selectors", {**atomic_target, **{key: "1" for key in ref.EVIDENCE_SELECTORS}}, ref.EVIDENCE_DOMAIN, "violation")
    target_case("content-hash-mismatch", atomic_target, ref.EVIDENCE_DOMAIN, "violation",
                edit=lambda r: r["artifact"].update(observedAt=1_800_000_030_001))
    target_case("anchor-content-mismatch", atomic_target, ref.EVIDENCE_DOMAIN, "violation",
                edit=lambda r: r["anchorReceipt"].update(contentHash="00" * 32))
    target_case("signature-invalid", atomic_target, ref.EVIDENCE_DOMAIN, "violation",
                edit=lambda r: r["artifact"]["signature"].update(value=ref.b64u(b"\0" * 64)))
    target_case("signature-missing", atomic_target, ref.EVIDENCE_DOMAIN, "violation",
                edit=lambda r: r["artifact"].pop("signature"))
    return {"fixtureVersion": "1", "publicKeys": atomic.PUBLIC_KEYS,
            "phaseInputs": inputs, "amendmentTargets": targets}


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = json.dumps(build_fixture(), ensure_ascii=False, indent=2) + "\n"
    if args.write:
        OUTPUT.write_text(data)
    elif OUTPUT.read_text() != data:
        print("FAILED: settlement contract fixture differs")
        return 1
    print("OK: settlement contract fixture")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
