"""Execute committed combined current-use + occurrence-window replay inputs."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (str(ROOT), str(ROOT / "tests")):
    if path not in sys.path:
        sys.path.insert(0, path)

from dacs5_reference import (  # noqa: E402
    _resolve_current_use_job,
    _verify_current_use_outcome_occurrence,
    derive_current_use_authenticated_window,
    replay_current_use_authenticated_window,
    require_current_use_authenticated_window_derivation,
)

VECTORS = ROOT / "conformance/vectors/security/current-use-authenticated-window-v1.json"


def decode_key_map(value):
    return {
        identity: base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
        for identity, key in value.items()
    }


def execute(replay):
    requests = copy.deepcopy(replay["requests"])
    dependencies = copy.deepcopy(replay["dependencies"])
    config = copy.deepcopy(replay["verifierConfig"])
    keys = decode_key_map(replay["verificationKeys"]["keys"])
    for identity, key in keys.items():
        config["publicKeys"][identity] = key
    for field in (
        "nativeAuthorityKeys", "settlementBindingAuthorityKeys",
        "outcomeTimeAuthorityKeys",
    ):
        config[field] = decode_key_map(config[field])
    pubkeys = {"authenticated": True, "keys": keys}
    query = replay["query"]
    result = derive_current_use_authenticated_window(
        query["party"], requests, query["windowStart"], query["windowEnd"],
        dependencies, config, pubkeys=pubkeys,
        trusted_contexts=copy.deepcopy(replay["trustedContext"]),
    )
    return result, dependencies, config, pubkeys


class CurrentUseAuthenticatedWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {case["name"]: case for case in cls.data["vectors"]}

    def test_corpus_hash_and_all_cases(self):
        encoded = json.dumps(
            self.data["vectors"], sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        self.assertEqual(self.data["count"], len(self.data["vectors"]))
        self.assertEqual(self.data["hash"], hashlib.sha256(encoded).hexdigest())
        for case in self.data["vectors"]:
            with self.subTest(case=case["name"]):
                result, deps, config, keys = execute(case["replay"])
                self.assertEqual(case["expected"], result["decision"], result["reason"])
                if result["decision"] == "pass":
                    derivation = result["derivation"]
                    self.assertEqual(case["bundleCount"], derivation["bundleCount"])
                    self.assertEqual(
                        len(case["replay"]["requests"]),
                        len(derivation["allJobResolutionContext"]),
                    )
                    replayed = replay_current_use_authenticated_window(
                        derivation, deps, config, pubkeys=keys,
                        trusted_contexts=case["replay"]["trustedContext"],
                    )
                    self.assertTrue(replayed["ok"], replayed["reason"])
                else:
                    self.assertIsNone(result["derivation"])

    def test_outside_window_job_is_retained_and_replay_mutation_fails(self):
        case = self.cases["combined-verified-outside-window-retained"]
        result, deps, config, keys = execute(case["replay"])
        self.assertEqual("pass", result["decision"], result["reason"])
        derivation = result["derivation"]
        self.assertEqual(1, derivation["bundleCount"])
        self.assertEqual(2, len(derivation["allJobResolutionContext"]))
        self.assertEqual([True, False], [
            entry["windowMember"] for entry in derivation["allJobResolutionContext"]
        ])
        self.assertEqual(1, len(derivation["bundleRefs"]))
        changed = copy.deepcopy(derivation)
        changed["allJobResolutionContext"][1]["outcomeTimeEvidence"]["nativeEvent"]["timestamp"] += 1
        replayed = replay_current_use_authenticated_window(
            changed, deps, config, pubkeys=keys,
            trusted_contexts=case["replay"]["trustedContext"],
        )
        self.assertFalse(replayed["ok"])
        self.assertEqual(derivation["metrics"], changed["metrics"])

    def test_outside_window_history_cannot_be_cherry_picked(self):
        case = self.cases["combined-verified-outside-window-retained"]
        replay = copy.deepcopy(case["replay"])
        outside_job = replay["requests"][1]["jobId"]
        replay["dependencies"]["outcomeTimeEvidenceByJobId"][outside_job].append(
            copy.deepcopy(replay["dependencies"]["outcomeTimeEvidenceByJobId"][outside_job][0])
        )
        result, _, _, _ = execute(replay)
        self.assertEqual("indeterminate", result["decision"])
        self.assertIsNone(result["derivation"])
        replay = copy.deepcopy(case["replay"])
        replay["dependencies"]["anchorReceiptHistoryByJobId"].pop(outside_job)
        result, _, _, _ = execute(replay)
        self.assertEqual("indeterminate", result["decision"])
        self.assertIsNone(result["derivation"])

    def test_missing_one_jobs_occurrence_fails_entire_request(self):
        case = self.cases["combined-one-requested-job-lacks-occurrence"]
        result, _, _, _ = execute(case["replay"])
        self.assertEqual("indeterminate", result["decision"])
        self.assertIsNone(result["derivation"])

    def test_multiphase_payment_time_does_not_replace_terminal_occurrence(self):
        case = self.cases["combined-multiphase-payment-in-outcome-out"]
        replay = case["replay"]
        request = replay["requests"][0]
        native = request["roles"]["buyer"]["selectionContext"]["candidateBindings"][0]["nativeAddress"]
        bundle = replay["dependencies"]["bundlesByNativeAddress"][native]
        self.assertEqual(["pay-evm-erc20", "rate"], [
            phase["kind"] for phase in bundle["phaseSummary"]
        ])
        authority = replay["dependencies"]["bundleAuthorityByContentHash"][
            request["roles"]["buyer"]["selectionContext"]["candidateBindings"][0]["bundleContentHash"]
        ]
        payment = next(iter(authority["finalityVerificationByCanonicalRef"].values()))["evidence"]
        self.assertLessEqual(payment["observedAt"], replay["query"]["windowEnd"])
        proof = replay["dependencies"]["outcomeTimeEvidenceByJobId"][request["jobId"]][0]
        self.assertGreater(proof["nativeEvent"]["timestamp"], replay["query"]["windowEnd"])
        result, _, _, _ = execute(replay)
        self.assertEqual("pass", result["decision"], result["reason"])
        derivation = result["derivation"]
        self.assertEqual(0, derivation["bundleCount"])
        self.assertEqual([], derivation["bundleRefs"])
        self.assertEqual([], derivation["metrics"]["observedTransactionalVolume"])
        self.assertFalse(derivation["allJobResolutionContext"][0]["windowMember"])

    def test_sealed_selection_without_reproduced_SAC8_is_nonpassing(self):
        case = self.cases["combined-sealed-selection-without-SAC8"]
        result, _, _, _ = execute(case["replay"])
        self.assertEqual("indeterminate", result["decision"])
        self.assertIn("SAC-8", result["reason"])
        self.assertIsNone(result["derivation"])

    def test_signed_alternative_and_wrong_projection_refuse_before_outcome_proof(self):
        for name in (
            "combined-signed-alternative-projection-unsupported",
            "combined-wrong-apr-projection-refused",
        ):
            with self.subTest(name=name):
                replay = self.cases[name]["replay"]
                request = replay["requests"][0]
                native = request["roles"]["buyer"]["selectionContext"]["candidateBindings"][0]["nativeAddress"]
                bundle = replay["dependencies"]["bundlesByNativeAddress"][native]
                authority = replay["dependencies"]["bundleAuthorityByContentHash"][
                    request["roles"]["buyer"]["selectionContext"]["candidateBindings"][0]["bundleContentHash"]
                ]
                self.assertEqual("pay-alternative", authority["listing"]["pipeline"][0]["kind"])
                self.assertEqual(2, len(authority["listing"]["pipeline"][0]["parameters"]["alternatives"]))
                self.assertEqual(bundle["phaseSummary"][0]["kind"], authority["effectivePipeline"][0]["kind"])
                self.assertNotEqual(authority["listing"]["pipeline"], authority["effectivePipeline"])
                # A missing proof must not be the first reason for refusal: the
                # unsupported APR authority is rejected before proof lookup.
                no_proof = copy.deepcopy(replay)
                no_proof["dependencies"]["outcomeTimeEvidenceByJobId"].clear()
                result, _, _, _ = execute(no_proof)
                self.assertEqual("indeterminate", result["decision"])
                self.assertIn("APR effective pipeline is unsupported", result["reason"])
                self.assertIsNone(result["derivation"])

    def test_distinct_unverified_pipeline_refuses_after_cur_admission(self):
        case = self.cases["combined-block-depth"]
        result, deps, config, keys = execute(case["replay"])
        self.assertEqual("pass", result["decision"])
        admitted = _resolve_current_use_job(
            case["replay"]["requests"][0], deps, config, keys,
            case["replay"]["trustedContext"],
        )
        self.assertEqual("pass", admitted["decision"], admitted["reason"])
        authority = deps["bundleAuthorityByContentHash"][
            admitted["selected"]["roleEvidence"]["binding"]["bundleContentHash"]
        ]
        authority["effectivePipeline"] = [{"kind": "pay-x402"}]
        deps["outcomeTimeEvidenceByJobId"].clear()
        decision, reason, occurrence = _verify_current_use_outcome_occurrence(
            admitted, deps, config,
        )
        self.assertEqual("indeterminate", decision)
        self.assertIn("differs from signed listing", reason)
        self.assertIsNone(occurrence)

    def test_older_or_standalone_discriminator_cannot_satisfy_combined_request(self):
        for name in (
            "currentUseReplayableDerivationVersion",
            "authenticatedWindowDerivationVersion",
            "replayableSettlementVerifiedDerivationVersion",
        ):
            with self.subTest(name=name):
                self.assertFalse(require_current_use_authenticated_window_derivation({name: "1"})["ok"])
        self.assertFalse(require_current_use_authenticated_window_derivation({
            "currentUseAuthenticatedWindowDerivationVersion": "1",
            "authenticatedWindowDerivationVersion": "1",
        })["ok"])

    def test_provider_capture_remains_provisional(self):
        case = self.cases["combined-provider-receipt"]
        result, _, _, _ = execute(case["replay"])
        self.assertEqual("pass", result["decision"], result["reason"])
        volume = result["derivation"]["metrics"]["finalityClassifiedVolume"]
        self.assertEqual([], volume["profileFinal"]["observedTransactionalVolume"])
        self.assertTrue(volume["provisionalProviderCapture"]["observedTransactionalVolume"])


if __name__ == "__main__":
    unittest.main()
