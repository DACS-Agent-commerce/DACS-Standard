import hashlib
import json
import unicodedata
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "vectors" / "security" / "claim-requirement-qualification-v0.3.json"
SPEC = ROOT / "spec" / "DACS-2-VET.md"


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


def applicable_results(input_data, claim_requirement, latest_by_scheme):
    expected_version = claim_requirement.get("recipeVersion")
    if expected_version is None:
        expected_version = latest_by_scheme.get(claim_requirement["scheme"])
    if expected_version is None:
        return []

    results = []
    for result in input_data["resolvedResults"]:
        if result["scheme"] != claim_requirement["scheme"]:
            continue
        if result["recipeVersion"] != expected_version:
            continue
        if "maxAge" in claim_requirement:
            expires_at = result["verifiedAt"] + claim_requirement["maxAge"] * 1000
            if input_data["generatedAt"] > expires_at:
                continue
        results.append(result)
    return results


def parameters_match(result, claim_requirement):
    for key, expected in claim_requirement.get("parameters", {}).items():
        if key not in result.get("data", {}):
            return False
        if canonical_json(result["data"][key]) != canonical_json(expected):
            return False
    return True


def classify_required(input_data, claim_requirement, latest_by_scheme):
    same_scheme = [
        result
        for result in input_data["resolvedResults"]
        if result["scheme"] == claim_requirement["scheme"]
    ]
    if not same_scheme:
        return "fail"
    results = applicable_results(input_data, claim_requirement, latest_by_scheme)
    if not results:
        return "fail"
    if any(result["decision"] == "pass" and parameters_match(result, claim_requirement) for result in results):
        return "pass"
    if any(result["decision"] in ("pass", "fail") for result in results):
        return "fail"
    if any(result["decision"] == "error" for result in results):
        return "error"
    return "indeterminate"


def evaluate(input_data, latest_by_scheme):
    decisions = [
        classify_required(input_data, claim_requirement, latest_by_scheme)
        for claim_requirement in input_data["requirement"].get("required", [])
    ]
    for group in input_data["requirement"].get("oneOf", []):
        applicable_by_member = [
            (claim_requirement, applicable_results(input_data, claim_requirement, latest_by_scheme))
            for claim_requirement in group
        ]
        if any(
            result["decision"] == "pass" and parameters_match(result, claim_requirement)
            for claim_requirement, results in applicable_by_member
            for result in results
        ):
            decisions.append("pass")
        elif any(result["decision"] == "error" for _, results in applicable_by_member for result in results):
            decisions.append("error")
        elif any(result["decision"] == "indeterminate" for _, results in applicable_by_member for result in results):
            decisions.append("indeterminate")
        else:
            decisions.append("fail")

    for decision in ("fail", "error", "indeterminate"):
        if decision in decisions:
            return decision
    return "pass"


class ClaimRequirementQualificationVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.latest_by_scheme = cls.data["recipeRegistry"]["latestByScheme"]

    def test_vector_hash_count_and_unique_names(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(self.data["hash"], hashlib.sha256(canonical_json(vectors)).hexdigest())
        names = [vector["name"] for vector in vectors]
        self.assertEqual(len(names), len(set(names)))

    def test_all_candidate_semantics(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(evaluate(vector["input"], self.latest_by_scheme), vector["expected"])

    def test_omitted_version_uses_session_start_registry(self):
        vector = next(
            vector
            for vector in self.data["vectors"]
            if vector["name"] == "vet-claim-requirement-implicit-session-pin-rejects-old-version"
        )
        claim_requirement = vector["input"]["requirement"]["required"][0]
        applicable = applicable_results(vector["input"], claim_requirement, self.latest_by_scheme)
        self.assertEqual([result["recipeVersion"] for result in applicable], [2])
        self.assertEqual(evaluate(vector["input"], self.latest_by_scheme), "fail")
        self.assertTrue(parameters_match(vector["input"]["resolvedResults"][0], claim_requirement))

    def test_spec_carries_and_reuses_exact_registry_pin(self):
        text = SPEC.read_text(encoding="utf-8")
        self.assertIn("recipeRegistryVersion?: number", text)
        self.assertIn("recipeRegistryResolver.resolve_authenticated(record.recipeRegistryVersion)", text)
        self.assertIn("An omitted `ClaimRequirement.recipeVersion` therefore does not disable version qualification.", text)


if __name__ == "__main__":
    unittest.main()
