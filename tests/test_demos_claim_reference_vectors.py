import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "conformance" / "fixtures" / "identity" / "demos-agent-claim-reference.json"
DEMOS_AGENT_IDENTIFIER = re.compile(r"^demos:agent:[0-9a-f]{64}$")


def classify(value: str) -> dict[str, object]:
    scheme, separator, identifier = value.partition(":")
    if not separator or scheme.lower() != "did":
        return {
            "classification": "unknown-scheme",
            "accepted": False,
            "canonical": None,
            "aliasesDemosAgentDid": False,
        }
    if not DEMOS_AGENT_IDENTIFIER.fullmatch(identifier):
        return {
            "classification": "invalid-demos-agent-did",
            "accepted": False,
            "canonical": None,
        }
    return {
        "classification": "demos-agent-did",
        "accepted": True,
        "canonical": f"did:{identifier}",
    }


class DemosClaimReferenceVectorTests(unittest.TestCase):
    def test_demos_agent_claim_reference_cases(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(fixture["kind"], "DemosAgentClaimReferenceCases")
        self.assertEqual(
            [case["id"] for case in fixture["cases"]],
            [
                "lowercase-canonical-form",
                "mixed-case-did-scheme-read",
                "uppercase-key-noncanonical",
                "demos-address-notation-is-unknown",
            ],
        )
        for case in fixture["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(classify(case["input"]), case["expected"])


if __name__ == "__main__":
    unittest.main()
