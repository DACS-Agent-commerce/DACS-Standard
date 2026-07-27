import hashlib
import json
import unicodedata
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECURITY = ROOT / "conformance" / "vectors" / "security"
REFERENCE_VECTORS = SECURITY / "reputation-settlement-reference-divergence-v0.4.json"
SEMANTIC_VECTORS = SECURITY / "reputation-settlement-semantics-v0.4.json"
SPEC = ROOT / "spec" / "DACS-5-VERIFY.md"


def canonical_json(value):
    def normalize(item):
        if isinstance(item, str):
            return unicodedata.normalize("NFC", item)
        if isinstance(item, list):
            return [normalize(value) for value in item]
        if isinstance(item, dict):
            return {key: normalize(value) for key, value in item.items()}
        return item

    return json.dumps(normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def vector_set_bytes(vectors):
    return json.dumps(vectors, separators=(",", ":"), ensure_ascii=False).encode()


def evaluate_reference(vector):
    left = Counter(canonical_json(reference) for reference in vector["input"]["selfRefs"])
    right = Counter(canonical_json(reference) for reference in vector["input"]["counterpartyRefs"])
    unified = left == right
    return {
        "expected": "pass" if unified else "fail",
        "want": {"lookupDisposition": "unified" if unified else "divergent", "bundleIncluded": unified},
    }


def evaluate_semantic(vector):
    input_data = vector["input"]
    authority = input_data["authorityDisposition"]
    if authority == "indeterminate":
        expected = "indeterminate"
    elif authority == "rejected" or input_data.get("mismatch") is not None:
        expected = "reject"
    else:
        expected = "accept"

    included = expected == "accept"
    completed = included and input_data["outcome"] == "completed"
    payment = (
        input_data["presentedEvidenceCount"] > 0
        and input_data.get("evidencePhase", "pay-dem").startswith("pay-")
        and input_data.get("evidenceOutcome", "success") == "success"
    )
    volume = completed and payment
    want = {
        "bundleIncluded": included,
        "completionNumerator": 1 if completed else 0,
        "partyFaultDenominator": 1 if included else 0,
        "counterpartyAdjustedDenominator": 1 if included else 0,
        "volumeByCurrency": ["5 DEM"] if volume else [],
        "transactionCountByCurrency": [{"currency": "DEM", "count": 1}] if volume else [],
        "disposition": "eligible" if volume else ("eligible-non-volume" if included else "excluded-without-fault"),
    }
    return {"expected": expected, "want": want}


class SettlementVerifiedReputationVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = json.loads(REFERENCE_VECTORS.read_text(encoding="utf-8"))
        cls.semantic = json.loads(SEMANTIC_VECTORS.read_text(encoding="utf-8"))

    def test_vector_metadata(self):
        for data in (self.reference, self.semantic):
            with self.subTest(vector_set=data["set"]):
                vectors = data["vectors"]
                self.assertEqual(data["count"], len(vectors))
                self.assertEqual(data["hash"], hashlib.sha256(vector_set_bytes(vectors)).hexdigest())
                names = [vector["name"] for vector in vectors]
                self.assertEqual(len(names), len(set(names)))

    def test_reference_multiset_semantics(self):
        for vector in self.reference["vectors"]:
            with self.subTest(vector=vector["name"]):
                result = evaluate_reference(vector)
                self.assertEqual(result["expected"], vector["expected"])
                self.assertEqual(result["want"], vector["want"])

    def test_settlement_admission_and_volume_semantics(self):
        for vector in self.semantic["vectors"]:
            with self.subTest(vector=vector["name"]):
                result = evaluate_semantic(vector)
                self.assertEqual(result["expected"], vector["expected"])
                self.assertEqual(result["want"], vector["want"])

    def test_new_discriminators_preserve_released_v1_meaning(self):
        text = SPEC.read_text(encoding="utf-8")
        self.assertIn("**DACS-5 v0.4**", text)
        self.assertIn('settlementVerifiedDerivationVersion: "1"', text)
        self.assertIn('replayableSettlementVerifiedDerivationVersion: "1"', text)
        self.assertIn("Existing discriminators retain their released meaning.", text)
        self.assertIn("without repository-revision knowledge", text)


if __name__ == "__main__":
    unittest.main()
