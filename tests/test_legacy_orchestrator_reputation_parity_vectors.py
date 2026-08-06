"""Execute DACS-5 §10.5.1 orchestrator-neutral reputation parity vectors."""
import hashlib
import json
import unittest
from pathlib import Path

import dacs5_reference as R


ROOT = Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "conformance" / "vectors" / "security" / "legacy-orchestrator-reputation-parity-v0.3.json"
EXPECTED_NAMES = {
    "legacy-legacy-orchestrator-failure-neutral",
    "mixed-orchestrator-failure-neutral",
    "fab-fab-orchestrator-failure-neutral",
    "legacy-legacy-orchestrator-abort-neutral",
    "mixed-orchestrator-abort-neutral",
    "fab-fab-orchestrator-abort-neutral",
}


class LegacyOrchestratorReputationParityTests(unittest.TestCase):
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

    def test_all_pairings_are_orchestrator_neutral_for_both_parties(self):
        observed = {}
        for vector in self.data["vectors"]:
            copies = vector["copies"]
            hashes = [R.bundle_hash(copy) for copy in copies]
            tags = [
                {
                    "bundle": copies[0],
                    "resolvedRole": copies[0]["anchoredByRole"],
                    "counterpartyDisposition": "present",
                    "counterpartyRef": {"contentHash": hashes[1]},
                },
                {
                    "bundle": copies[1],
                    "resolvedRole": copies[1]["anchoredByRole"],
                    "counterpartyDisposition": "present",
                    "counterpartyRef": {"contentHash": hashes[0]},
                },
            ]
            per_party = []
            for party in vector["partiesToScore"]:
                derivation = R.derive(
                    party, tags, vector["window"][0], vector["window"][1], "finalisedAt")
                with self.subTest(vector=vector["name"], party=party):
                    self.assertFalse(R.divergence(copies[0], copies[1]))
                    self.assertEqual(derivation["bundleCount"], vector["want"]["bundleCount"])
                    self.assertEqual(derivation["metrics"], vector["want"]["metrics"])
                per_party.append((derivation["bundleCount"], derivation["metrics"]))
            observed[vector["name"]] = per_party

        self.assertEqual(len({json.dumps(v, sort_keys=True) for v in observed.values()}), 1)


if __name__ == "__main__":
    unittest.main()
