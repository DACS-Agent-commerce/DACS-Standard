import copy
import importlib.util
import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "validate_implementation_manifests.py"
EXAMPLE_DIR = ROOT / "conformance" / "implementation-manifests"
V04_COMMIT = "4bb9e48a1095ab32c06c25b7c0b52018d3ce4091"


def git_show(commit, path):
    return subprocess.run(["git", "-C", str(ROOT), "show", f"{commit}:{path}"],
                          capture_output=True, text=True, check=True).stdout


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
        self.assertEqual(len(paths), 6)
        for path in paths:
            with self.subTest(path=path.name):
                manifest = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(self.validate(manifest), [])

    def test_fixed_price_pay_dem_examples_stay_illustrative(self):
        readme = (EXAMPLE_DIR / "README.md").read_text(encoding="utf-8")
        for role in ("seller", "buyer"):
            name = f"fixed-price-pay-dem-{role}.json"
            with self.subTest(example=name):
                manifest = load_example(name)
                self.assertIn(name, readme)
                self.assertEqual(manifest["roles"], [role])
                self.assertTrue(manifest["implementation"]["name"].startswith("illustrative-"))
                self.assertTrue(manifest["implementation"]["repository"].startswith("https://example.invalid/"))
                self.assertEqual(manifest["liveTests"], [])
        self.assertIn("not a claim about any implementation", readme)

    def test_fixed_price_pay_dem_claims_stay_within_their_evidence(self):
        # IM-4 does not check case tiers or rule coverage, so the examples' own
        # scoping is pinned here against the v0.4 suite they cite.
        suite = json.loads(git_show(V04_COMMIT, "conformance/MANIFEST.json"))
        tiers = {case["id"]: case["status"] for case in suite["cases"]}
        applicable_fixed_price = {
            case["id"] for case in suite["cases"]
            if case["area"] == "negotiate" and case["status"] == "golden"
            and case["spec"] in {"§8.5.1", "§8.5.2"} and "sealed-envelope" not in case["id"]
        }
        rd5 = {case["id"] for case in suite["cases"]
               if case["status"] == "golden" and case["spec"].endswith(" RD-5")}
        # No v0.4 case exercises these; RD-1..RD-4 are registry-steward duties.
        unexercised = {"DACS-3-8.4.1", "PS-1", "PS-2"}
        steward = {"RD-1", "RD-2", "RD-3", "RD-4"}
        for role in ("seller", "buyer"):
            with self.subTest(role=role):
                manifest = load_example(f"fixed-price-pay-dem-{role}.json")
                runs = {run["id"]: run for run in manifest["testRuns"]}
                capabilities = {cap["ref"]: cap for cap in manifest["capabilities"]}
                self.assertEqual(manifest["conformanceSuite"]["commit"], V04_COMMIT)
                self.assertEqual(set(runs["fixed-price-vectors"]["caseIds"]), applicable_fixed_price)
                self.assertEqual(set(runs["rail-coherence-vectors"]["caseIds"]), rd5)
                self.assertEqual(capabilities["fixed-price"]["testStatus"], "partial")
                for claim in manifest["claims"]:
                    rules = set(claim["ruleRefs"])
                    self.assertFalse(rules & steward, claim["id"])
                    if role == "buyer":
                        self.assertFalse({rule for rule in rules if rule.startswith("PS-")}, claim["id"])
                    if claim["result"] in {"conformant", "conformance-tested"}:
                        self.assertFalse(rules & unexercised, claim["id"])
                        cases = {case for ref in claim["evidenceRefs"] for case in runs[ref]["caseIds"]}
                        self.assertEqual({tiers[case] for case in cases}, {"golden"}, claim["id"])
                fixed = next(c for c in manifest["claims"] if c["capabilityRefs"] == ["fixed-price"])
                self.assertEqual(fixed["result"], "implemented")
                self.assertTrue(unexercised - {"PS-1", "PS-2"} <= set(fixed["ruleRefs"]))
        readme = (EXAMPLE_DIR / "README.md").read_text(encoding="utf-8")
        self.assertIn("does not check\nwhether a cited case is golden or candidate", readme)

    def seller_example(self):
        manifest = load_example("fixed-price-pay-dem-seller.json")
        self.assertEqual(self.validate(copy.deepcopy(manifest)), [])
        return manifest

    def passing_claim(self, manifest):
        return next(claim for claim in manifest["claims"] if claim["result"] == "conformance-tested")

    def test_suite_manifest_path_must_stay_within_the_repository(self):
        # IM-1 pins the suite by path as well as commit and hash.
        for path in ("../MANIFEST.json", "/conformance/MANIFEST.json", "conformance/../../MANIFEST.json", ""):
            with self.subTest(path=path):
                manifest = self.seller_example()
                manifest["conformanceSuite"]["manifestPath"] = path
                errors = self.validate(manifest)
                self.assertTrue(any("manifestPath must" in error for error in errors), errors)
        manifest = self.seller_example()
        manifest["conformanceSuite"]["manifestPath"] = "conformance/vectors/golden.json"
        self.assertTrue(any("manifestPath" in error for error in self.validate(manifest)))

    def test_full_profile_claim_must_cover_every_pinned_document(self):
        manifest = self.seller_example()
        claim = self.passing_claim(manifest)
        claim.update(level="full-profile", result="conformant",
                     modules=["CORE", "DACS-1", "DACS-2", "DACS-3", "DACS-4"])
        errors = self.validate(manifest)
        self.assertTrue(any("full-profile claim must cover every pinned document" in error for error in errors))
        claim["modules"].append("DACS-5")
        errors = self.validate(manifest)
        self.assertFalse(any("full-profile claim must cover" in error for error in errors))

    def test_manifest_version_must_be_one(self):
        for version in ("2", 1, None):
            with self.subTest(version=version):
                manifest = self.seller_example()
                manifest["manifestVersion"] = version
                self.assertIn('test-manifest.manifestVersion must be "1"', self.validate(manifest))

    def test_rule_refs_resolve_at_the_pinned_profile_commit(self):
        # LAA-1 is defined in this checkout but not at the examples' v0.4 pin.
        self.assertIn("(LAA-1)", (ROOT / "spec" / "DACS-4-SETTLE.md").read_text(encoding="utf-8"))
        self.assertNotIn("(LAA-1)", git_show(V04_COMMIT, "spec/DACS-4-SETTLE.md"))
        manifest = self.seller_example()
        manifest["claims"][0]["ruleRefs"].append("LAA-1")
        errors = self.validate(manifest)
        self.assertTrue(any("unresolved specification references: LAA-1" in error for error in errors), errors)

    def test_experimental_capability_cannot_appear_in_passing_claim(self):
        # IM-6's second sentence, with a correctly x- prefixed capability.
        manifest = self.seller_example()
        claim = self.passing_claim(manifest)
        capability = next(cap for cap in manifest["capabilities"] if cap["ref"] == claim["capabilityRefs"][0])
        capability.update(supportStatus="experimental", id="x-" + capability["id"])
        errors = self.validate(manifest)
        self.assertFalse(any("experimental id must start with x-" in error for error in errors))
        self.assertTrue(any("passing claim cannot include non-implemented" in error for error in errors), errors)

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
