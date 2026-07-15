import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTOR_PATH = (
    ROOT / "conformance" / "vectors" / "security"
    / "bundle-absence-evidence-v0.3.json"
)


class BundleAbsenceEvidenceVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        cls.vectors = {vector["name"]: vector for vector in cls.data["vectors"]}

    def test_count_hash_and_case_names(self):
        vectors = self.data["vectors"]
        encoded = json.dumps(
            vectors,
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(self.data["hash"], hashlib.sha256(encoded).hexdigest())
        self.assertEqual(
            set(self.vectors),
            {
                "single-path-not-found-is-indeterminate",
                "binding-qualified-absence-allows-one-sided",
                "independent-view-reveals-divergence",
                "transport-or-inconsistent-state-remains-indeterminate",
            },
        )

    def test_unqualified_not_found_is_excluded(self):
        vector = self.vectors["single-path-not-found-is-indeterminate"]
        self.assertIsNone(vector["binding"]["absenceEvidencePolicy"])
        self.assertEqual(vector["expected"], "indeterminate")
        self.assertEqual(vector["want"]["readDispositions"]["seller"], "indeterminate")
        self.assertEqual(vector["want"]["lookupDisposition"], "indeterminate")
        self.assertEqual(vector["want"]["reputationEffect"], "exclude")
        self.assertFalse(vector["want"]["mayPerspectiveFlip"])
        self.assertFalse(vector["want"]["mayAttributeAbort"])

    def test_binding_qualified_absence_allows_one_sided_attribution(self):
        vector = self.vectors["binding-qualified-absence-allows-one-sided"]
        policy = vector["binding"]["absenceEvidencePolicy"]
        self.assertEqual(
            set(policy),
            {
                "finalityRule",
                "authentication",
                "independence",
                "threshold",
                "freshness",
                "stateConsistency",
            },
        )
        self.assertEqual(vector["expected"], "pass")
        self.assertEqual(vector["want"]["readDispositions"]["seller"], "absent")
        self.assertEqual(vector["want"]["lookupDisposition"], "one-sided")
        self.assertEqual(vector["want"]["reputationEffect"], "include")
        self.assertTrue(vector["want"]["mayPerspectiveFlip"])
        self.assertEqual(vector["want"]["scoredOutcome"], "aborted-by-self")
        self.assertTrue(vector["want"]["mayAttributeAbort"])

    def test_independent_content_view_restores_divergence(self):
        vector = self.vectors["independent-view-reveals-divergence"]
        seller_observations = vector["reads"]["seller"]["observations"]
        self.assertEqual(
            [observation["response"] for observation in seller_observations],
            ["not-found", "content"],
        )
        self.assertEqual(vector["expected"], "fail")
        self.assertEqual(vector["want"]["readDispositions"]["seller"], "present")
        self.assertEqual(vector["want"]["lookupDisposition"], "divergent")
        self.assertEqual(vector["want"]["reputationEffect"], "exclude")
        self.assertFalse(vector["want"]["maySelectCopy"])

    def test_transport_and_inconsistent_state_stay_indeterminate(self):
        vector = self.vectors["transport-or-inconsistent-state-remains-indeterminate"]
        self.assertEqual(vector["expected"], "indeterminate")
        self.assertEqual(
            [variant["wantReadDisposition"] for variant in vector["variants"]],
            ["indeterminate", "indeterminate"],
        )
        self.assertEqual(vector["want"]["lookupDisposition"], "indeterminate")
        self.assertEqual(vector["want"]["reputationEffect"], "exclude")

    def test_normative_surfaces_state_the_same_gate(self):
        core = (ROOT / "spec" / "CORE.md").read_text(encoding="utf-8")
        dacs5 = (ROOT / "spec" / "DACS-5-VERIFY.md").read_text(encoding="utf-8")
        demos = (ROOT / "spec" / "DEMOS-MAPPING.md").read_text(encoding="utf-8")

        self.assertIn("`present`, `absent`, or `indeterminate`", core)
        for policy_field in (
            "finalized state or finality rule",
            "response or proof is authenticated",
            "independence and threshold requirements",
            "freshness and state-consistency checks",
        ):
            self.assertIn(policy_field, core)
        self.assertIn("other expected address is authoritatively `absent`", dacs5)
        self.assertIn("**authoritative absence before one-copy attribution**", dacs5)
        self.assertIn("excludes the jobId from ALL metrics", dacs5)
        self.assertIn("does not declare", demos)
        self.assertIn("`indeterminate`, not `absent`", demos)


if __name__ == "__main__":
    unittest.main()
