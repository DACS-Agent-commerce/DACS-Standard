import copy
import json
import unittest
from pathlib import Path
from scripts.settlement_finality_reference import verify_finality

class FinalityRailControls(unittest.TestCase):
    def test_existing_success_vectors_preserved(self):
        path = Path(__file__).resolve().parents[1] / "conformance/vectors/security/settlement-finality-verification.json"
        data = json.loads(path.read_text())
        for case in data["vectors"]:
            if case["expected"] == "pass":
                with self.subTest(name=case["name"]):
                    trust = copy.deepcopy(data["trustedFixturePolicy"])
                    trust.update(case.get("trustedOverrides", {}))
                    self.assertEqual(verify_finality(case["input"], trust)["decision"], "pass")
