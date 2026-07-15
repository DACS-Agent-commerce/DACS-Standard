import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "vectors" / "security" / "phase-kind-divergence-v0.3.json"
SPEC = ROOT / "spec" / "DACS-5-VERIFY.md"


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class PhaseKindDivergenceVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_vector_hash_and_count_are_byte_exact(self):
        self.assertEqual(self.data["count"], len(self.data["vectors"]))
        self.assertEqual(
            self.data["hash"],
            hashlib.sha256(canonical_json(self.data["vectors"])).hexdigest(),
        )

    def test_kind_is_the_only_contradiction_bearing_difference(self):
        vector = self.data["vectors"][0]
        buyer = vector["copies"]["buyer"]
        seller = vector["copies"]["seller"]
        buyer_entry = buyer["phaseSummary"][0]
        seller_entry = seller["phaseSummary"][0]

        self.assertEqual(buyer["jobId"], seller["jobId"])
        self.assertEqual(buyer["outcome"], seller["outcome"])
        self.assertEqual(buyer_entry["index"], seller_entry["index"])
        self.assertEqual(buyer_entry["outcome"], seller_entry["outcome"])
        self.assertEqual(buyer_entry.get("errorClass"), seller_entry.get("errorClass"))
        self.assertNotEqual(buyer_entry["kind"], seller_entry["kind"])
        self.assertEqual(vector["want"]["consumerVerdict"], "divergent")
        self.assertEqual(
            vector["want"]["derivationDisposition"],
            "exclude-jobId-from-all-metrics",
        )
        self.assertFalse(vector["want"]["selectPartyCopy"])

    def test_consumer_and_deriver_use_the_same_three_field_predicate(self):
        spec = SPEC.read_text(encoding="utf-8")
        predicate = "in a shared-index `phaseSummary` entry's `kind`/`outcome`/`errorClass`"
        self.assertEqual(spec.count(predicate), 2)
        self.assertIn("A difference confined to advisory fields", spec)


if __name__ == "__main__":
    unittest.main()
