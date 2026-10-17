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
    for member in ("jobId", "agreement", "rail", "payer", "payee", "amount"):
        missing = copy.deepcopy(ordinary_input)
        missing.pop(member)
        phase("ordinary-missing-" + member, "ordinary", missing, "rejected")
    # A present member of the wrong type fails its arm before any rail call.
    session = ordinary_input["sessionContext"]
    context = atomic_input["atomicSessionContext"]
    for label, binding, base, change in (
        ("ordinary-empty-session-context", "ordinary", ordinary_input, {"sessionContext": {}}),
        ("ordinary-session-without-started-at", "ordinary", ordinary_input,
         {"sessionContext": {k: v for k, v in session.items() if k != "startedAt"}}),
        ("ordinary-session-parties-not-array", "ordinary", ordinary_input,
         {"sessionContext": {**session, "parties": {}}}),
        ("ordinary-null-payer", "ordinary", ordinary_input, {"payer": None}),
        ("ordinary-payer-without-paying-key", "ordinary", ordinary_input,
         {"payer": {k: v for k, v in ordinary_input["payer"].items() if k != "payingKey"}}),
        ("ordinary-payee-address-empty", "ordinary", ordinary_input,
         {"payee": {**ordinary_input["payee"], "payeeAddress": ""}}),
        ("ordinary-amount-number", "ordinary", ordinary_input, {"amount": 10}),
        ("ordinary-amount-zero", "ordinary", ordinary_input,
         {"amount": {**ordinary_input["amount"], "amount": "0"}}),
        ("ordinary-job-id-number", "ordinary", ordinary_input, {"jobId": 1}),
        ("ordinary-rail-string", "ordinary", ordinary_input, {"rail": "demos-native:DEM"}),
        ("ordinary-companions-not-array", "ordinary", ordinary_input, {"identityBindingCompanions": {}}),
        ("atomic-null-payer", "atomic", atomic_input, {"payer": None}),
        ("atomic-payer-extra-member", "atomic", atomic_input,
         {"payer": {**atomic_input["payer"], "note": "x"}}),
        ("atomic-paying-key-malformed", "atomic", atomic_input,
         {"payer": {**atomic_input["payer"], "payingKey": "not a claim"}}),
        ("atomic-payee-bundle-hash-uppercase", "atomic", atomic_input,
         {"payee": {**atomic_input["payee"], "bundleHash": atomic_input["payee"]["bundleHash"].upper()}}),
        ("atomic-agreement-null", "atomic", atomic_input, {"agreement": None}),
        ("atomic-context-version-2", "atomic", atomic_input,
         {"atomicSessionContext": {**context, "contextVersion": "2"}}),
        ("atomic-context-parties-reordered", "atomic", atomic_input,
         {"atomicSessionContext": {**context, "parties": context["parties"][::-1]}}),
        ("atomic-context-party-bundle-hash", "atomic", atomic_input,
         {"atomicSessionContext": {**context, "parties": [
             {**context["parties"][0], "bundleHash": atomic_input["payer"]["bundleHash"]},
             *context["parties"][1:]]}}),
        ("atomic-context-started-at-string", "atomic", atomic_input,
         {"atomicSessionContext": {**context, "startedAt": str(context["startedAt"])}}),
    ):
        phase(label, binding, {**base, **change}, "rejected")

    receipt = atomic.final_receipt(purchase)
    atomic_target = atomic.settlement_evidence(purchase, receipt, "payment")
    completion = atomic.completion_intent(receipt)
    atomic_delivery = atomic.settlement_evidence(completion, atomic.final_receipt(completion), "delivery")
    ordinary_target = {
        "evidenceVersion": "1", "jobId": purchase["jobId"], "phase": "pay-dem",
        "outcome": "success", "paymentTxRefs": [{"kind": "demos", "txHash": "ab" * 32, "blockNumber": 750}],
        "paymentAmount": {"amount": "10", "currency": "DEM"},
        "settlementFinality": {"model": "bft-final", "finalityObservedAt": 1_800_000_030_000},
        "observedAt": 1_800_000_030_000,
    }
    success_payment = {key: ordinary_target[key] for key in (
        "jobId", "phase", "outcome", "paymentTxRefs", "paymentAmount",
        "settlementFinality", "observedAt",
    )}
    legacy_target = {
        "legacyTransitionEvidenceVersion": "1", **success_payment,
        "sessionId": "session-fixture-1", "agreementHash": "cd" * 32, "phaseIndex": 2,
        "reservationRef": {"anchor": {"kind": "storage-program", "locator":
                           f"dacs4:legacy-payment-reservation:{purchase['jobId']}:2"},
                           "contentHash": "ef" * 32},
    }
    finality_target = {
        "finalityBoundEvidenceVersion": "1", **success_payment,
        "railDefinitionRef": {"anchor": {"kind": "storage-program", "locator":
                              "dacs4:rail:demos-native%3ADEM:1"},
                              "contentHash": "12" * 32, "railId": "demos-native:DEM",
                              "railVersion": 1},
    }
    targets = []

    def target_case(name, target, domain, expected, *, edit=None, resolution="finalized",
                    signer="orchestrator", address=None, anchored=None):
        target = ref.sign_embedded(target, atomic.CLAIMS[signer], atomic.SEEDS[signer], domain)
        unsigned = {k: v for k, v in target.items() if k != "signature"}
        digest = ref.sha256_hex(ref.jcs_bytes(unsigned))
        locator = f"dacs4:payment:{purchase['jobId']}:fixture-{name}:2"
        target_ref = {"anchor": {"kind": "storage-program", "locator": locator},
                      "contentHash": digest}
        # An authentic anchor may bind content other than the reference names.
        anchor = atomic.registry_anchor_receipt(locator, anchored or unsigned, label=name, nonce="300")
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
                        "amendmentAddress": address(digest) if address else
                        f"dacs4:amendment:{purchase['jobId']}:{digest}:0"})

    legacy_domain = b"dacs-legacy-transition-evidence:v1:"
    finality_domain = b"dacs-finality-bound-evidence:v1:"
    for label, base, domain, selector, other in (
        ("ordinary", ordinary_target, b"dacs-evidence:v1:", "evidenceVersion", ref.EVIDENCE_DOMAIN),
        ("atomic", atomic_target, ref.EVIDENCE_DOMAIN, "atomicEvidenceVersion", b"dacs-evidence:v1:"),
        ("legacy-transition", legacy_target, legacy_domain, "legacyTransitionEvidenceVersion", b"dacs-evidence:v1:"),
        ("finality-bound", finality_target, finality_domain, "finalityBoundEvidenceVersion", legacy_domain),
    ):
        target_case(label + "-target", base, domain, "valid")
        target_case(label + "-unsupported-version", {**base, selector: "2"}, domain, "violation")
        target_case(label + "-wrong-domain", base, other, "violation")
        target_case(label + "-wrong-job", {**base, "jobId": "01K1DPA0000000000000000009"}, domain, "violation")
        # Every evidence arm is orchestrator-signed; a known seller key is not authority.
        target_case(label + "-seller-signed", base, domain, "violation", signer="seller")
        delivery = atomic_delivery if label == "atomic" else {**base, "phase": "deliver-storage-program"}
        target_case(label + "-delivery-target", delivery, domain, "violation")
        for state in ("unavailable", "unanchored", "included"):
            target_case(label + "-" + state, base, domain, "indeterminate", resolution=state)
        for member in ("paymentAmount", "settlementFinality"):
            target_case(f"{label}-success-without-{member}",
                        {k: v for k, v in base.items() if k != member}, domain, "violation")
    target_case("legacy-transition-without-reservation-ref",
                {k: v for k, v in legacy_target.items() if k != "reservationRef"}, legacy_domain, "violation")
    target_case("finality-bound-without-rail-definition-ref",
                {k: v for k, v in finality_target.items() if k != "railDefinitionRef"}, finality_domain, "violation")
    target_case("ordinary-success-without-payment-tx-refs",
                {k: v for k, v in ordinary_target.items() if k != "paymentTxRefs"}, b"dacs-evidence:v1:", "violation")
    # The {evidenceHash} amendment-address segment binds the exact target hash.
    job = purchase["jobId"]
    signed_hash = ref.sha256_hex(ref.jcs_bytes(ref.sign_embedded(
        atomic_target, atomic.CLAIMS["orchestrator"], atomic.SEEDS["orchestrator"], ref.EVIDENCE_DOMAIN)))
    other_hash = ref.sha256_hex(ref.jcs_bytes(ordinary_target))
    for name, address in (
        ("address-signature-inclusive-hash", lambda _: f"dacs4:amendment:{job}:{signed_hash}:0"),
        ("address-other-target-hash", lambda _: f"dacs4:amendment:{job}:{other_hash}:0"),
        ("address-wrong-job", lambda digest: f"dacs4:amendment:01K1DPA0000000000000000009:{digest}:0"),
        ("address-noncanonical-index", lambda digest: f"dacs4:amendment:{job}:{digest}:01"),
        ("address-wrong-kind", lambda digest: f"dacs4:payment:{job}:{digest}:0"),
    ):
        target_case(name, atomic_target, ref.EVIDENCE_DOMAIN, "violation", address=address)
    target_case("address-later-index", atomic_target, ref.EVIDENCE_DOMAIN, "valid",
                address=lambda digest: f"dacs4:amendment:{job}:{digest}:3")
    target_case("ordinary-projection-phase", {**ordinary_target, "phase": "pay-alternative"}, b"dacs-evidence:v1:", "violation")
    malformed_atomic = {k: v for k, v in atomic_target.items() if k != "workReceiptRef"}
    target_case("atomic-malformed-member", malformed_atomic, ref.EVIDENCE_DOMAIN, "violation")
    target_case("ordinary-malformed-outcome", {**ordinary_target, "outcome": "unknown"}, b"dacs-evidence:v1:", "violation")
    no_selector = {k: v for k, v in atomic_target.items() if k not in ref.EVIDENCE_SELECTORS}
    target_case("no-selector", no_selector, ref.EVIDENCE_DOMAIN, "violation")
    target_case("dual-selectors", {**atomic_target, "evidenceVersion": "1"}, ref.EVIDENCE_DOMAIN, "violation")
    target_case("unsupported-selector", {**no_selector, "deliveryEvidenceVersion": "1"}, ref.EVIDENCE_DOMAIN, "violation")
    target_case("all-selectors", {**atomic_target, **{key: "1" for key in ref.EVIDENCE_SELECTORS}}, ref.EVIDENCE_DOMAIN, "violation")
    # The authentic anchor binds the reference's hash: other bytes are a
    # substituted resolution, not a wrong target.
    target_case("content-hash-mismatch", atomic_target, ref.EVIDENCE_DOMAIN, "indeterminate",
                edit=lambda r: r["artifact"].update(observedAt=1_800_000_030_001))
    target_case("anchor-binds-other-content", atomic_target, ref.EVIDENCE_DOMAIN, "violation",
                anchored={k: v for k, v in ordinary_target.items()})
    target_case("anchor-content-mismatch", atomic_target, ref.EVIDENCE_DOMAIN, "violation",
                edit=lambda r: r["anchorReceipt"].update(contentHash="00" * 32))
    target_case("signature-invalid", atomic_target, ref.EVIDENCE_DOMAIN, "violation",
                edit=lambda r: r["artifact"]["signature"].update(value=ref.b64u(b"\0" * 64)))
    target_case("signature-missing", atomic_target, ref.EVIDENCE_DOMAIN, "violation",
                edit=lambda r: r["artifact"].pop("signature"))
    return {"fixtureVersion": "1", "publicKeys": atomic.PUBLIC_KEYS,
            "orchestrator": atomic.CLAIMS["orchestrator"],
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
