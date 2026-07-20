import importlib.util
import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_lifecycle_walkthrough.py"


def load_walkthrough():
    spec = importlib.util.spec_from_file_location("run_lifecycle_walkthrough", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LifecycleWalkthroughTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_walkthrough()
        cls.trace = cls.module.build_trace()
        cls.artifacts = {
            item["artifactId"]: item
            for stage in cls.trace["stages"]
            for item in stage["artifacts"]
        }

    def test_covers_all_five_stages_in_order(self):
        self.assertEqual(
            [stage["stage"] for stage in self.trace["stages"]],
            ["DACS-1", "DACS-2", "DACS-3", "DACS-4", "DACS-5"],
        )
        self.assertEqual(self.trace["result"]["artifactCount"], 11)

    def test_each_artifact_exposes_bytes_hash_signature_ref_and_binding(self):
        for stage in self.trace["stages"]:
            self.assertTrue(stage["rules"])
            self.assertTrue(stage["vectorIds"])
            for item in stage["artifacts"]:
                with self.subTest(artifact=item["artifactId"]):
                    self.assertEqual(json.loads(item["canonicalBytes"]), item["artifact"])
                    self.assertEqual(len(item["artifactHash"]), 64)
                    self.assertEqual(
                        item["signaturePayload"],
                        item["domainSeparator"] + item["artifactHash"],
                    )
                    self.assertTrue(item["signatureResults"])
                    self.assertTrue(
                        all(
                            result["verified"] and result["canonicalBase64Url"]
                            for result in item["signatureResults"]
                        )
                    )
                    self.assertEqual(
                        item["attestationRef"]["contentHash"], item["artifactHash"]
                    )
                    self.assertNotEqual(
                        item["logicalAddress"], item["publishedBinding"]["nativeAddress"]
                    )
                    self.assertEqual(
                        item["attestationRef"]["anchor"]["locator"],
                        item["publishedBinding"]["nativeAddress"],
                    )

    def test_sig6_and_cf1_are_enforced(self):
        with self.assertRaises(ValueError):
            self.module.decode_base64url("YWJjZA==")
        with self.assertRaises(ValueError):
            self.module.decode_base64url("YWJj+/8")
        decomposed = {"value": "Cafe\u0301"}
        precomposed = {"value": "Caf\u00e9"}
        self.assertEqual(
            self.module.canonical_json(decomposed),
            self.module.canonical_json(precomposed),
        )

    def test_cross_stage_references_and_delivery_are_complete(self):
        listing = self.artifacts["listing-minimum-lifecycle"]
        agreement = self.artifacts["agreement-payee-bound-fixed-price"]
        payment = self.artifacts["settlement-payment-success"]
        delivery = self.artifacts["settlement-delivery-success"]
        buyer_bundle = self.artifacts["attestation-bundle-buyer"]
        seller_bundle = self.artifacts["attestation-bundle-seller"]
        orchestrator_bundle = self.artifacts["attestation-bundle-orchestrator"]

        pipeline_kinds = [
            step["kind"] for step in listing["artifact"]["pipeline"]
        ]
        self.assertIn("deliver-storage-program", pipeline_kinds)
        self.assertEqual(
            agreement["artifact"]["listingRef"]["contentHash"],
            listing["artifactHash"],
        )
        self.assertEqual(payment["artifact"]["phaseIndex"], 3)
        self.assertEqual(delivery["artifact"]["phaseIndex"], 4)
        self.assertNotIn("settlementFinality", delivery["artifact"])

        bundle = buyer_bundle["artifact"]
        self.assertEqual(
            bundle["agreementRef"]["contentHash"], agreement["artifactHash"]
        )
        self.assertEqual(
            {ref["contentHash"] for ref in bundle["vetRecords"]},
            {
                self.artifacts["composite-vet-buyer"]["artifactHash"],
                self.artifacts["composite-vet-seller"]["artifactHash"],
            },
        )
        self.assertEqual(
            [ref["contentHash"] for ref in bundle["settlementEvidence"]],
            [payment["artifactHash"], delivery["artifactHash"]],
        )
        self.assertEqual(
            [entry["kind"] for entry in bundle["phaseSummary"]], pipeline_kinds
        )
        self.assertEqual(
            [entry["index"] for entry in bundle["phaseSummary"]],
            list(range(len(pipeline_kinds))),
        )
        self.assertEqual(
            buyer_bundle["artifactHash"], seller_bundle["artifactHash"]
        )
        self.assertEqual(
            buyer_bundle["artifactHash"], orchestrator_bundle["artifactHash"]
        )
        self.assertEqual(
            {
                buyer_bundle["artifact"]["anchoredByRole"],
                seller_bundle["artifact"]["anchoredByRole"],
                orchestrator_bundle["artifact"]["anchoredByRole"],
            },
            {"buyer", "seller", "orchestrator"},
        )

    def test_all_five_negative_examples_reject_or_classify(self):
        self.assertEqual(
            [case["id"] for case in self.trace["negativeExamples"]],
            [
                "malformed-identity",
                "agreement-outside-listing-policy",
                "duplicate-settlement-transaction-id",
                "delivery-failure-after-payment",
                "divergent-buyer-seller-bundles",
            ],
        )
        self.assertTrue(all(case["passed"] for case in self.trace["negativeExamples"]))

    def test_negative_examples_execute_shared_enforcement_paths(self):
        cases = {case["id"]: case for case in self.trace["negativeExamples"]}

        malformed = cases["malformed-identity"]
        self.assertEqual(malformed["enforcementPath"], "validate_identity")
        self.assertFalse(malformed["validation"]["accepted"])
        self.assertIn(
            "IdentityBundle.claims must be a non-empty array",
            malformed["validation"]["errors"],
        )
        self.assertTrue(
            all(
                result["verified"]
                for result in malformed["validation"]["verification"][
                    "signatureResults"
                ]
            )
        )

        policy = cases["agreement-outside-listing-policy"]
        self.assertEqual(
            policy["enforcementPath"], "validate_agreement_against_listing"
        )
        self.assertFalse(policy["validation"]["accepted"])
        self.assertEqual(
            policy["validation"]["reason"],
            "agreement selected a rail outside listing policy",
        )
        self.assertTrue(
            all(
                result["verified"]
                for result in policy["validation"]["signatureResults"]
            )
        )

        delivery = cases["delivery-failure-after-payment"]
        self.assertEqual(
            delivery["enforcementPath"], "evaluate_delivery_after_payment"
        )
        self.assertTrue(delivery["paymentRemainsRecorded"])
        self.assertEqual(
            delivery["resultingBundle"]["artifact"]["outcome"],
            "failed-counterparty",
        )
        self.assertEqual(
            delivery["resultingBundle"]["artifact"]["settlementEvidence"][0],
            self.artifacts["settlement-payment-success"]["attestationRef"],
        )
        self.assertTrue(
            all(
                result["verified"]
                for result in delivery["failureEvidence"]["signatureResults"]
            )
        )
        self.assertTrue(
            all(
                result["verified"]
                for result in delivery["resultingBundle"]["signatureResults"]
            )
        )

        divergent = cases["divergent-buyer-seller-bundles"]
        self.assertEqual(divergent["enforcementPath"], "consume_bundle_pair")
        self.assertEqual(divergent["consumption"]["disposition"], "divergent")
        self.assertEqual(
            divergent["consumption"]["reputationDisposition"], "exclude"
        )
        self.assertTrue(
            all(
                result["verified"]
                for results in divergent["consumption"]["signatureResults"].values()
                for result in results
            )
        )

    def test_trace_is_pinned(self):
        self.module.check_pins(self.trace)

    def test_cli_check_passes(self):
        result = subprocess.run(
            ["python3", str(SCRIPT), "--check"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("lifecycle walkthrough: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
