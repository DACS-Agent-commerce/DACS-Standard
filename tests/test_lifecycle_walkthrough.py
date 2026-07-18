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

    def test_covers_all_five_stages_in_order(self):
        self.assertEqual(
            [stage["stage"] for stage in self.trace["stages"]],
            ["DACS-1", "DACS-2", "DACS-3", "DACS-4", "DACS-5"],
        )

    def test_each_stage_exposes_bytes_hash_signature_ref_and_links(self):
        for stage in self.trace["stages"]:
            with self.subTest(stage=stage["stage"]):
                self.assertEqual(
                    json.loads(stage["canonicalBytes"]),
                    stage["artifact"],
                )
                self.assertEqual(len(stage["artifactHash"]), 64)
                self.assertTrue(stage["signaturePayload"].startswith(stage["domainSeparator"]))
                self.assertTrue(stage["signatureResults"])
                self.assertTrue(all(item["verified"] for item in stage["signatureResults"]))
                self.assertEqual(stage["attestationRef"]["contentHash"], stage["artifactHash"])
                self.assertTrue(stage["rules"])
                self.assertTrue(stage["vectorIds"])

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
