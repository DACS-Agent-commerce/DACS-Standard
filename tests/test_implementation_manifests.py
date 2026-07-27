import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "validate_implementation_manifests.py"
EXAMPLE_DIR = ROOT / "conformance" / "implementation-manifests"


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_implementation_manifests", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_example(name="fixed-price-x402-seller.json"):
    return json.loads((EXAMPLE_DIR / name).read_text(encoding="utf-8"))


class ImplementationManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = load_validator()

    def validate(self, manifest):
        return self.validator.validate_manifest(manifest, root=ROOT, source="test-manifest")

    def test_repository_examples_are_valid(self):
        paths = sorted(EXAMPLE_DIR.glob("*.json"))
        self.assertEqual(len(paths), 4)
        for path in paths:
            with self.subTest(path=path.name):
                manifest = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(self.validate(manifest), [])

    def test_schema_and_workflow_pin_versioned_validation(self):
        schema_errors = []
        self.validator.validate_schema_file(schema_errors)
        self.assertEqual(schema_errors, [])
        workflow = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("python3 scripts/validate_implementation_manifests.py", workflow)

    def test_rejects_wrong_suite_hash_and_unknown_case(self):
        manifest = load_example()
        manifest["conformanceSuite"]["manifestSha256"] = "0" * 64
        manifest["testRuns"][0]["caseIds"] = ["not-a-pinned-case"]

        errors = self.validate(manifest)

        self.assertTrue(any("manifestSha256 mismatch" in error for error in errors))
        self.assertTrue(any("unknown pinned cases" in error for error in errors))

    def test_profile_document_versions_match_pinned_revision(self):
        manifest = load_example()
        manifest["profile"]["documents"]["DACS-4"] = "999.9"

        errors = self.validate(manifest)

        self.assertTrue(any("DACS-4 mismatch at pinned commit" in error for error in errors))

    def test_profile_and_suite_commits_must_resolve(self):
        manifest = load_example()
        manifest["profile"]["commit"] = "0" * 40
        manifest["conformanceSuite"]["commit"] = "f" * 40

        errors = self.validate(manifest)

        self.assertTrue(any("profile cannot resolve" in error for error in errors))
        self.assertTrue(any("conformanceSuite cannot resolve" in error for error in errors))

    def test_suite_hash_is_checked_at_the_declared_commit(self):
        manifest = load_example()
        manifest["conformanceSuite"]["commit"] = "db9f9c0075a63d69d4464bac62cbfb2362a3f223"

        errors = self.validate(manifest)

        self.assertTrue(any("manifestSha256 mismatch" in error for error in errors))

    def test_passing_claim_requires_passing_deterministic_evidence(self):
        manifest = load_example()
        manifest["testRuns"][0]["result"] = "fail"

        errors = self.validate(manifest)

        self.assertTrue(any("passing claim must reference only passing" in error for error in errors))
        self.assertTrue(any("passed capability must reference only passing" in error for error in errors))

    def test_passing_claim_evidence_must_cover_its_capability(self):
        manifest = load_example()
        manifest["claims"][0]["evidenceRefs"] = ["x402-vectors"]

        errors = self.validate(manifest)

        self.assertTrue(any("evidence does not cover capability" in error for error in errors))

    def test_repositories_must_be_identified(self):
        manifest = load_example()
        manifest["profile"]["repository"] = ""
        manifest["conformanceSuite"]["repository"] = ""

        errors = self.validate(manifest)

        self.assertTrue(any("profile.repository must be a non-empty string" in error for error in errors))
        self.assertTrue(any("conformanceSuite.repository must be a non-empty string" in error for error in errors))

    def test_live_test_cannot_substitute_for_deterministic_evidence(self):
        manifest = load_example()
        manifest["claims"][1]["evidenceRefs"] = ["base-sepolia-x402-live"]

        errors = self.validate(manifest)

        self.assertTrue(any("unknown deterministic runs" in error for error in errors))

    def test_passing_claim_cannot_include_unsupported_capability(self):
        manifest = load_example()
        capability = manifest["capabilities"][0]
        capability["supportStatus"] = "unsupported"
        capability["testStatus"] = "not_tested"
        capability["evidenceRefs"] = []
        capability.pop("availability")

        errors = self.validate(manifest)

        self.assertTrue(any("passing claim cannot include non-implemented" in error for error in errors))

    def test_experimental_capability_requires_x_prefix(self):
        manifest = load_example()
        capability = manifest["capabilities"][0]
        capability["supportStatus"] = "experimental"

        errors = self.validate(manifest)

        self.assertTrue(any("experimental id must start with x-" in error for error in errors))

    def test_open_nonconforming_deviation_invalidates_passing_claim(self):
        manifest = load_example()
        manifest["deviations"] = [
            {
                "id": "known-gap",
                "capabilityRefs": ["pay-x402"],
                "ruleRefs": ["SB-3"],
                "status": "open",
                "effect": "nonconforming",
                "description": "Known protocol mismatch.",
            }
        ]

        errors = self.validate(manifest)

        self.assertTrue(any("invalidated by open nonconforming deviations" in error for error in errors))

    def test_open_nonconforming_deviation_does_not_invalidate_nonpassing_claim(self):
        cases = [
            ("capability", "implemented", "implemented", "fixed-price"),
            ("experimental", "experimental", "experimental", "x-fixed-price"),
        ]
        for level, result, support_status, capability_id in cases:
            with self.subTest(result=result):
                manifest = load_example()
                claim = manifest["claims"][0]
                claim["level"] = level
                claim["result"] = result
                capability = manifest["capabilities"][0]
                capability["supportStatus"] = support_status
                capability["id"] = capability_id
                manifest["deviations"] = [
                    {
                        "id": "known-gap",
                        "capabilityRefs": ["fixed-price"],
                        "ruleRefs": ["PS-1"],
                        "status": "open",
                        "effect": "nonconforming",
                        "description": "Known protocol mismatch without a conformance claim.",
                    }
                ]

                errors = self.validate(manifest)

                self.assertEqual(errors, [])

    def test_unknown_optional_members_do_not_change_conformance_evaluation(self):
        manifest = load_example()
        manifest["registryOverride"] = {"pay-x402": "authorized"}
        manifest["implementation"]["authorization"] = "transaction-signer"
        manifest["claims"][0]["authorization"] = "runtime-bypass"

        errors = self.validate(manifest)

        self.assertEqual(errors, [])

    def test_rule_refs_must_resolve_to_a_rule_or_document_section(self):
        manifest = load_example()
        manifest["claims"][0]["ruleRefs"] = ["PS-999", "DACS-5-99.99"]

        errors = self.validate(manifest)

        self.assertTrue(any("unresolved specification references" in error for error in errors))
        self.assertTrue(any("PS-999" in error and "DACS-5-99.99" in error for error in errors))

    def test_operational_deviation_does_not_invalidate_claim(self):
        manifest = load_example("pay-dem-rfq-seller.json")

        errors = self.validate(copy.deepcopy(manifest))

        self.assertFalse(any("invalidated by open nonconforming deviations" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
