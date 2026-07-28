"""Execute the DACS-5 §10.4.3 legacy implied-fault-set candidate vectors."""
import hashlib
import json
import unittest
from pathlib import Path

import dacs5_reference as R


ROOT = Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "conformance" / "vectors" / "security" / "legacy-three-party-fault-reconciliation-v0.3.json"
EXPECTED_NAMES = {
    "legacy-two-party-perspective-partners",
    "legacy-two-party-mutual-counterparty-claim",
    "legacy-three-party-distinct-orchestrator-fault",
    "legacy-three-party-distinct-orchestrator-abort",
}

OUTCOMES = (
    "completed",
    "failed-perm",
    "failed-counterparty",
    "failed-substrate",
    "aborted-by-self",
    "aborted-by-other",
)


def old_perspective_flip_diverges(a, b):
    classes = {
        "completed": "completed",
        "failed-substrate": "substrate",
        "failed-perm": "failure",
        "failed-counterparty": "failure",
        "aborted-by-self": "abort",
        "aborted-by-other": "abort",
    }
    return classes[a] != classes[b] or a != R.perspective_flip(b)


def legacy_copy(role, outcome, parties):
    return {
        "bundleVersion": "1",
        "anchoredByRole": role,
        "outcome": outcome,
        "parties": [{"role": party} for party in parties],
        "phaseSummary": [],
    }


class LegacyThreePartyFaultReconciliationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

    def test_metadata_and_hash(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["set"], VECTOR_PATH.stem)
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual({v["name"] for v in vectors}, EXPECTED_NAMES)
        encoded = json.dumps(vectors, separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(self.data["hash"], hashlib.sha256(encoded).hexdigest())

    def test_implied_fault_sets_and_executed_verdicts(self):
        for vector in self.data["vectors"]:
            parties = set(vector["parties"])
            copies = vector["copies"]
            fault_sets = [
                R.implied_fault_set(copy["outcome"], copy["anchoredByRole"], parties)
                for copy in copies
            ]
            observed_sets = [sorted(values) for values in fault_sets]
            observed_intersection = sorted(fault_sets[0] & fault_sets[1])
            observed_divergence = R.divergence(copies[0], copies[1])
            with self.subTest(vector=vector["name"]):
                self.assertEqual(observed_sets, vector["want"]["impliedFaultSets"])
                self.assertEqual(observed_intersection, vector["want"]["intersection"])
                self.assertEqual(observed_divergence, vector["expected"] == "fail")

    def test_full_outcome_table_bounds_the_compatibility_delta(self):
        changes = {}
        for parties in (("buyer", "seller"), ("buyer", "seller", "orchestrator")):
            changed_pairs = []
            for buyer_outcome in OUTCOMES:
                for seller_outcome in OUTCOMES:
                    old = old_perspective_flip_diverges(buyer_outcome, seller_outcome)
                    new = R.divergence(
                        legacy_copy("buyer", buyer_outcome, parties),
                        legacy_copy("seller", seller_outcome, parties),
                    )
                    if old != new:
                        changed_pairs.append((buyer_outcome, seller_outcome, old, new))
            changes[parties] = changed_pairs

        self.assertEqual(changes[("buyer", "seller")], [])
        self.assertEqual(
            changes[("buyer", "seller", "orchestrator")],
            [
                ("failed-counterparty", "failed-counterparty", True, False),
                ("aborted-by-other", "aborted-by-other", True, False),
            ],
        )


if __name__ == "__main__":
    unittest.main()
