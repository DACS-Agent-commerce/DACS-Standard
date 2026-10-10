import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_security_vectors import (  # noqa: E402
    PER_SET_VERDICTS,
    validate_set,
)

VECTORS = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "atomic-work-receipt-absence-v0.1.json"
)

# The §7.5.1-class evidence classification this classifier emits. `coherent` is the
# positive class; `pass` must never appear, because the component is an evidence
# classifier, not a proof verifier, and `pass` would re-assert cryptographic
# verification it does not perform.
CLASSIFIER_VERDICTS = {"coherent", "fail", "indeterminate", "reject"}

# The four observation kinds `classifyVerifiedWorkEvidence` dispatches on. Any other
# kind makes the classifier throw (fail-closed non-accept).
CLASSIFIER_KINDS = {
    "work-receipt-proof",
    "absence-claim",
    "settlement-evidence",
    "payment-slot",
}


def sorted_ascii_hash(vectors):
    return hashlib.sha256(
        json.dumps(vectors, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode()
    ).hexdigest()


class AtomicWorkReceiptAbsenceVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_count_hash_and_set_are_byte_exact(self):
        self.assertEqual(self.data["set"], "atomic-work-receipt-absence-v0.1")
        self.assertEqual(self.data["count"], len(self.data["vectors"]))
        self.assertEqual(self.data["count"], 52)
        self.assertEqual(
            self.data["hash"],
            sorted_ascii_hash(self.data["vectors"]),
        )

    def test_every_vector_declares_a_classifier_verdict_never_pass(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector["name"]):
                self.assertIn(vector["expected"], CLASSIFIER_VERDICTS)
                self.assertNotEqual(vector["expected"], "pass")

    def test_every_observation_kind_is_dispatched_by_the_classifier(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector["name"]):
                self.assertIn(
                    vector["observation"]["kind"],
                    CLASSIFIER_KINDS,
                )

    def test_per_set_map_reserves_coherent_for_the_classifier_set(self):
        self.assertEqual(
            PER_SET_VERDICTS["atomic-work-receipt-absence-v0.1"],
            CLASSIFIER_VERDICTS,
        )
        self.assertNotIn("pass", PER_SET_VERDICTS["atomic-work-receipt-absence-v0.1"])
        self.assertIn("coherent", PER_SET_VERDICTS["atomic-work-receipt-absence-v0.1"])

    def test_validator_rejects_pass_in_the_classifier_set(self):
        # A global allowlist accepts `pass` in every set; the per-set map must reject it
        # here so the classifier set cannot silently re-assert verification.
        errors, count = self._validate_synthetic(expected="pass")
        self.assertEqual(count, 1)
        self.assertTrue(
            any("unknown verdict 'pass'" in e for e in errors),
            errors,
        )

    def test_validator_accepts_coherent_in_the_classifier_set(self):
        errors, count = self._validate_synthetic(expected="coherent")
        self.assertEqual(count, 1)
        self.assertEqual(errors, [])

    def test_validator_reports_malformed_set_without_throwing(self):
        for value in ([], {}, None, 1, True):
            with self.subTest(value=value):
                errors, count = self._validate_synthetic("coherent", set_value=value)
                self.assertEqual(count, 1)
                self.assertTrue(any("'set' must be a string" in error for error in errors), errors)

    def _validate_synthetic(self, expected, set_value="atomic-work-receipt-absence-v0.1"):
        vector = {
            "name": "synthetic-classifier-vector",
            "expected": expected,
            "observation": {"kind": "payment-slot"},
        }
        payload = {
            "set": set_value,
            "spec": "synthetic",
            "count": 1,
            "hash": sorted_ascii_hash([vector]),
            "vectors": [vector],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "atomic-work-receipt-absence-v0.1.json"
            path.write_text(json.dumps(payload, sort_keys=True, ensure_ascii=True), encoding="utf-8")
            return validate_set(str(path))


if __name__ == "__main__":
    unittest.main()
