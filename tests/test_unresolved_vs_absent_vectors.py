"""Checks for conformance/vectors/security/unresolved-vs-absent-v0.3.json.

Abstract decision-model set for the §10.4.3(b) / BB-8 one-sided gate: one-sided
classification is reachable only after a resolved binding plus policy-qualified
authoritative absence; everything else is indeterminate.
"""
import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "conformance" / "vectors" / "security" / "unresolved-vs-absent-v0.3.json"

EXPECTED_NAMES = {
    "no-binding-on-any-surface-is-indeterminate",
    "binding-resolves-authoritative-absent-one-sided",
    "binding-resolves-ordinary-not-found-is-indeterminate",
    "demos-mapping-no-policy-is-indeterminate",
}


class UnresolvedVsAbsentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        cls.vectors = cls.data["vectors"]
        cls.by_name = {v["name"]: v for v in cls.vectors}

    def test_set_metadata(self):
        self.assertEqual(self.data["set"], VECTOR_PATH.stem)
        self.assertEqual(self.data["count"], len(self.vectors))
        self.assertEqual({v["name"] for v in self.vectors}, EXPECTED_NAMES)
        encoded = json.dumps(self.vectors, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
        self.assertEqual(self.data["hash"], hashlib.sha256(encoded).hexdigest())
        for v in self.vectors:
            self.assertIn(v["expected"], {"pass", "indeterminate"})

    def test_only_authoritative_absent_reaches_one_sided(self):
        for v in self.vectors:
            reachable = v["want"]["oneSidedReachable"]
            with self.subTest(vector=v["name"]):
                if v["name"] == "binding-resolves-authoritative-absent-one-sided":
                    self.assertTrue(reachable)
                    self.assertEqual(v["expected"], "pass")
                    self.assertEqual(v["want"]["readDisposition"], "absent")
                    self.assertEqual(v["want"]["reputationEffect"], "include")
                else:
                    self.assertFalse(reachable)
                    self.assertEqual(v["expected"], "indeterminate")
                    self.assertEqual(v["want"]["reputationEffect"], "exclude")

    def test_absent_vector_declares_a_full_policy(self):
        v = self.by_name["binding-resolves-authoritative-absent-one-sided"]
        policy = v["binding"]["absenceEvidencePolicy"]
        self.assertEqual(
            set(policy),
            {"finalityRule", "authentication", "independence", "threshold", "freshness", "stateConsistency"},
        )
        # the no-policy/demos vectors carry a null policy
        self.assertIsNone(self.by_name["no-binding-on-any-surface-is-indeterminate"]["binding"]["absenceEvidencePolicy"])
        self.assertIsNone(self.by_name["demos-mapping-no-policy-is-indeterminate"]["binding"]["absenceEvidencePolicy"])

    def test_spec_sync_demos_mapping_absence_sentence(self):
        demos = (ROOT / "spec" / "DEMOS-MAPPING.md").read_text(encoding="utf-8")
        self.assertIn("does not declare", demos)
        self.assertIn("`indeterminate`, not `absent`", demos)


if __name__ == "__main__":
    unittest.main()
