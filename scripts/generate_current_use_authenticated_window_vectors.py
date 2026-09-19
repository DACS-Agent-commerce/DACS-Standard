#!/usr/bin/env python3
"""Deterministic fixture-only vectors for composed CUR + AWT reputation."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

from generate_current_use_reputation_vectors import (
    CLAIMS,
    CURRENT_FINALITY_JOB_IDS,
    FIXTURE_QUERY_WINDOW,
    MODELS,
    CurrentUseFixtureFactory,
    _serializable,
    canonical,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance/vectors/security/current-use-authenticated-window-v1.json"
BASIS = "verified-business-outcome-occurrence"


def _case(factory, fixture, name, requests, expected, *, dependencies=None,
          verifier_config=None, trusted_context=None, bundle_count=None):
    if dependencies is None:
        dependencies = (
            factory.replay_dependencies(requests[0], include_combined=True) if len(requests) == 1
            else fixture["dependencies"]
        )
    if verifier_config is None:
        verifier_config = (
            factory.replay_config(requests[0], include_combined=True) if len(requests) == 1
            else fixture["verifierConfig"]
        )
    if trusted_context is None:
        trusted_context = (
            factory.replay_context(requests[0], BASIS) if len(requests) == 1
            else factory.current_authority(CLAIMS["buyer"], FIXTURE_QUERY_WINDOW, BASIS)
        )
    item = {
        "name": name,
        "expected": expected,
        "replay": {
            "requests": _serializable(copy.deepcopy(requests)),
            "dependencies": _serializable(copy.deepcopy(dependencies)),
            "verifierConfig": _serializable(copy.deepcopy(verifier_config)),
            "trustedContext": _serializable(copy.deepcopy(trusted_context)),
            "verificationKeys": _serializable(factory.replay_keys()),
            "query": {
                "party": CLAIMS["buyer"],
                "windowStart": FIXTURE_QUERY_WINDOW[0],
                "windowEnd": FIXTURE_QUERY_WINDOW[1],
                "windowingBasis": BASIS,
            },
        },
    }
    if bundle_count is not None:
        item["bundleCount"] = bundle_count
    return item


def document():
    factory = CurrentUseFixtureFactory()
    fixture = factory.build()
    vectors = []
    for model in MODELS:
        request = fixture["currentRequestsByModel"][model]
        vectors.append(_case(
            factory, fixture, "combined-" + model, [request], "pass",
            bundle_count=1,
        ))
    for name, request in zip(
        ("combined-historical-binding", "combined-historical-pure"),
        fixture["historicalRequests"],
    ):
        vectors.append(_case(factory, fixture, name, [request], "pass", bundle_count=1))

    multiphase = fixture["multiPhaseRequest"]
    vectors.append(_case(
        factory, fixture, "combined-multiphase-outcome-inside",
        [multiphase], "pass", bundle_count=1,
    ))
    factory.outcome_time_proof(
        multiphase, timestamp=FIXTURE_QUERY_WINDOW[1] + 1,
    )
    vectors.append(_case(
        factory, fixture, "combined-multiphase-payment-in-outcome-out",
        [multiphase], "pass", bundle_count=0,
    ))

    requests = [
        fixture["currentRequestsByModel"]["block-depth"],
        fixture["currentRequestsByModel"]["provider-receipt"],
    ]
    outside_job = CURRENT_FINALITY_JOB_IDS["provider-receipt"]
    factory.outcome_time_proof(requests[1], timestamp=FIXTURE_QUERY_WINDOW[1] + 1)
    vectors.append(_case(
        factory, fixture, "combined-verified-outside-window-retained",
        requests, "pass", bundle_count=1,
    ))
    absent = copy.deepcopy(factory.dependencies)
    absent["outcomeTimeEvidenceByJobId"].pop(outside_job)
    vectors.append(_case(
        factory, fixture, "combined-one-requested-job-lacks-occurrence",
        requests, "indeterminate", dependencies=absent,
    ))
    sealed_request = fixture["currentRequestsByModel"]["block-depth"]
    sealed_deps = copy.deepcopy(factory.replay_dependencies(sealed_request, include_combined=True))
    sealed_config = copy.deepcopy(factory.replay_config(sealed_request, include_combined=True))
    native = sealed_request["roles"]["buyer"]["selectionContext"]["candidateBindings"][0]["nativeAddress"]
    bundle = sealed_deps["bundlesByNativeAddress"][native]
    agreement_key = canonical(bundle["agreementRef"]).decode("utf-8")
    sealed_deps["agreementsByCanonicalRef"][agreement_key]["sealedSelectionAgreementVersion"] = "1"
    sealed_deps["agreementsByCanonicalRef"][agreement_key]["selectionReceiptRef"] = {
        "anchor": {"kind": "storage-program", "locator": "missing-sealed-selection-receipt"},
        "contentHash": "00" * 32,
    }
    vectors.append(_case(
        factory, fixture, "combined-sealed-selection-without-SAC8",
        [sealed_request], "indeterminate", dependencies=sealed_deps,
        verifier_config=sealed_config,
    ))
    return {
        "set": "current-use-authenticated-window-v1",
        "spec": "DACS-5 unallocated CUAW-1..CUAW-6 composing CUR-1..CUR-8 and AWT-1..AWT-8",
        "status": "candidate-unallocated-stage-minor",
        "fixturePolicy": (
            "Synthetic signed native outcome observations are fixture-only; no production "
            "Demos outcome event, proof codec, or completeness oracle is claimed."
        ),
        "count": len(vectors),
        "hash": hashlib.sha256(canonical(vectors)).hexdigest(),
        "vectors": vectors,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = json.dumps(document(), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != rendered:
            print("stale generated corpus:", OUTPUT)
            return 1
        print("ok:", OUTPUT)
        return 0
    OUTPUT.write_text(rendered, encoding="utf-8")
    print("wrote:", OUTPUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
