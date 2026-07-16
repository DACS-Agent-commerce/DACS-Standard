"""Checks for conformance/vectors/security/receipt-rederivation-v0.3.json.

Abstract set for the §10.5.3 determinism-receipt clauses (3)/(4): a published
ReputationDerivation needs one resolutionContext entry per bundleRefs member, and a
one-copy jobId without a valid absenceEvidenceRef MUST NOT be published.
"""
import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "conformance" / "vectors" / "security" / "receipt-rederivation-v0.3.json"

EXPECTED_NAMES = {
    "complete-resolution-context-replays-identical",
    "miskeyed-resolution-context-is-nonconforming",
    "one-copy-without-absence-evidence-must-not-publish",
}


class ReceiptRederivationTests(unittest.TestCase):
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
            self.assertIn(v["expected"], {"pass", "fail"})

    def test_complete_context_conforms_and_is_keyed(self):
        v = self.by_name["complete-resolution-context-replays-identical"]
        self.assertEqual(v["expected"], "pass")
        self.assertTrue(v["want"]["conforming"])
        derivation = v["derivation"]
        refs = derivation["bundleRefs"]
        ctx = derivation["resolutionContext"]
        # exactly one entry per bundleRefs member, keyed by contentHash
        self.assertEqual(len(ctx), len(refs))
        self.assertEqual([e["contentHash"] for e in ctx], refs)
        # every absent-disposition entry carries absenceEvidenceRef
        for e in ctx:
            if e["counterpartyDisposition"] == "absent":
                self.assertIn("absenceEvidenceRef", e)

    def test_miskeyed_context_is_nonconforming(self):
        v = self.by_name["miskeyed-resolution-context-is-nonconforming"]
        self.assertEqual(v["expected"], "fail")
        self.assertFalse(v["want"]["conforming"])
        derivation = v["derivation"]
        self.assertNotEqual(len(derivation["resolutionContext"]), len(derivation["bundleRefs"]))

    def test_one_copy_without_evidence_must_not_publish(self):
        v = self.by_name["one-copy-without-absence-evidence-must-not-publish"]
        self.assertEqual(v["expected"], "fail")
        self.assertTrue(v["want"]["mustNotPublish"])
        (entry,) = v["derivation"]["resolutionContext"]
        self.assertEqual(entry["counterpartyDisposition"], "absent")
        self.assertNotIn("absenceEvidenceRef", entry)

    def test_spec_sync_clause_four_nonconforming_sentence(self):
        dacs5 = (ROOT / "spec" / "DACS-5-VERIFY.md").read_text(encoding="utf-8")
        self.assertIn("is not independently reproducible and is non-conforming.", dacs5)


if __name__ == "__main__":
    unittest.main()
