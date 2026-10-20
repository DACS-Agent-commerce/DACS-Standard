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
# The examples the README scopes to their evidence, and the older ones it names as not narrowed.
SCOPED_EXAMPLES = ("fixed-price-x402-seller.json", "fixed-price-pay-dem-seller.json", "fixed-price-pay-dem-buyer.json")
OLDER_EXAMPLES = ("pay-dem-rfq-buyer.json", "pay-dem-rfq-seller.json", "verifier-indexer.json")


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
        applicable_fixed_price = {
            case["id"] for case in suite["cases"]
            if case["area"] == "negotiate" and case["status"] == "golden"
            and case["spec"] in {"§8.5.1", "§8.5.2"} and "sealed-envelope" not in case["id"]
        }
        # No v0.4 case exercises §8.4.1, PS-1, PS-2, a demos-native rail or the
        # §9.6.1 DV rules, so every capability is partial and claimed as implemented.
        self.assertFalse([case["id"] for case in suite["cases"] if "DV-" in case["spec"]])
        delivery = {"settlement-delivery-pass", "settlement-delivery-missing-deliverable-fail",
                    "settlement-delivery-malformed-contenthash-fail",
                    "settlement-storage-anchored-as-entitlement-fail"}
        # The README says "four of the six"; the other two test PC-6 and SIG-5.
        golden_delivery = {case["id"] for case in suite["cases"] if case["status"] == "golden"
                           and case["id"].startswith(("settlement-delivery-", "settlement-storage-"))}
        self.assertEqual(golden_delivery - delivery, {"settlement-delivery-with-finality-fail",
                                                      "settlement-delivery-extra-payment-field-pass"})
        self.assertLess(delivery, golden_delivery)
        # §9.5.9 step 5 at the pin settles on `included`; #432 is the open fix.
        self.assertIn("5. On the transaction reaching the terminal **`included`** state",
                      git_show(V04_COMMIT, "spec/DACS-4-SETTLE.md"))
        for role in ("seller", "buyer"):
            with self.subTest(role=role):
                manifest = load_example(f"fixed-price-pay-dem-{role}.json")
                runs = {run["id"]: run for run in manifest["testRuns"]}
                claims = {claim["capabilityRefs"][0]: claim for claim in manifest["claims"]}
                self.assertEqual(manifest["conformanceSuite"]["commit"], V04_COMMIT)
                self.assertEqual(manifest["profile"]["commit"], V04_COMMIT)
                self.assertEqual(set(runs["fixed-price-vectors"]["caseIds"]), applicable_fixed_price)
                self.assertEqual(set(runs["storage-program-delivery-vectors"]["caseIds"]), delivery)
                self.assertEqual({claim["result"] for claim in manifest["claims"]}, {"implemented"})
                self.assertEqual({cap["testStatus"] for cap in manifest["capabilities"]
                                  if cap["supportStatus"] == "implemented"}, {"partial"})
                # The RD-5 cases test EVM and Solana rails, and `next` withdrew the
                # chain-ID pass case; RD-1..RD-5 are rail-author duties (§9.4.3, §9.10).
                cited = {case for run in runs.values() for case in run["caseIds"]}
                self.assertNotIn("settlement-cross-chainid-matching-kind-pass", cited)
                self.assertNotIn("rail-coherence-vectors", runs)
                self.assertEqual(claims["demos-native-dem-rail"]["ruleRefs"], ["DACS-4-9.4.2"])
                self.assertEqual(claims["demos-native-dem-rail"]["evidenceRefs"], ["pay-dem-vectors"])
                for claim in manifest["claims"]:
                    rules = set(claim["ruleRefs"])
                    self.assertFalse({rule for rule in rules if rule.startswith("RD-")}, claim["id"])
                    # PS-* are listing-publisher duties (§8.9); PB-* are checks
                    # the payer runs before submitting payment (§9.5.1).
                    other_side = "PS-" if role == "buyer" else "PB-"
                    self.assertFalse({rule for rule in rules if rule.startswith(other_side)}, claim["id"])
                self.assertEqual(claims["pay-dem"]["ruleRefs"], ["DACS-4-9.5.9", "PB-1", "PB-2", "PB-3"]
                                 if role == "buyer" else ["DACS-4-9.5.9", "SB-1", "SB-2"])
                self.assertIn("DACS-3-8.4.1", claims["fixed-price"]["ruleRefs"])
                self.assertEqual(claims["storage-program-delivery"]["ruleRefs"], ["DACS-4-9.6.1"])
        readme = (EXAMPLE_DIR / "README.md").read_text(encoding="utf-8")
        self.assertIn("does not check\nwhether a cited case is golden or candidate", readme)
        self.assertIn("RD-1..RD-5 are rail-author duties (§9.4.3, §9.10)", readme)
        flat = " ".join(readme.split())
        for text in ("PB-1..PB-3 appear only in the buyer example",
                     "four of the six golden v0.4 settlement cases",
                     "None of the six exercises DV-1..DV-4",
                     "above its 128 KB soft limit; the Demos node itself enforces 1 MiB",
                     "step 5 returns success on the `included` state; a Demos node also reports "
                     "`included` for a failed transfer. Open draft PR #432",
                     "Open draft PR #432 (head `518d30b`, 2026-10-19) proposes settling only on an executed "
                     "transaction record with independently authenticated applied-payment authority"):
            self.assertIn(text, flat)

    def test_x402_example_makes_no_passing_claim(self):
        # A conformance-tested capability claim reports the whole capability
        # (§14.10). The three cited cases exercise neither §8.4.1, PS-1, PS-2 nor
        # PS-3's pattern/pricing compatibility, so fixed-price is partial.
        manifest = load_example()
        suite_pin = manifest["conformanceSuite"]
        suite = json.loads(git_show(suite_pin["commit"], suite_pin["manifestPath"]))
        tiers = {case["id"]: case["status"] for case in suite["cases"]}
        runs = {run["id"]: run for run in manifest["testRuns"]}
        fixed = next(claim for claim in manifest["claims"] if claim["capabilityRefs"] == ["fixed-price"])
        capability = next(cap for cap in manifest["capabilities"] if cap["ref"] == "fixed-price")
        self.assertEqual((fixed["result"], fixed["ruleRefs"], capability["testStatus"]),
                         ("implemented", ["PS-1", "PS-2", "PS-3"], "partial"))
        cases = {case for ref in fixed["evidenceRefs"] for case in runs[ref]["caseIds"]}
        self.assertIn("neg-ps3-fixed-over-negotiable", cases)
        self.assertEqual({tiers[case] for case in cases}, {"golden"})
        self.assertEqual([claim["id"] for claim in manifest["claims"]
                          if claim["result"] in {"conformant", "conformance-tested"}], [])
        self.assertNotIn("passed", {cap["testStatus"] for cap in manifest["capabilities"]})
        flat = " ".join((EXAMPLE_DIR / "README.md").read_text(encoding="utf-8").split())
        self.assertIn("`fixed-price-x402-seller.json` makes no passing claim.", flat)
        self.assertIn("its PS-3 golden case covers only PS-3's negotiable band-centre clause", flat)

    def test_x402_example_pay_claim_stays_within_its_evidence(self):
        # At the pin, the only §9.5.7/§9.5.8 case is one golden pass case, so no
        # case exercises the X402-1..X402-4 rejections or SB-1..SB-3.
        manifest = load_example()
        suite_pin = manifest["conformanceSuite"]
        suite = json.loads(git_show(suite_pin["commit"], suite_pin["manifestPath"]))
        x402_cases = [(case["id"], case["status"], case["want"]) for case in suite["cases"]
                      if case["spec"] in {"§9.5.7", "§9.5.8"} or "X402-" in case["spec"] or "SB-" in case["spec"]]
        self.assertEqual(x402_cases, [("settlement-x402-pass", "golden", "pass")])
        runs = {run["id"]: run for run in manifest["testRuns"]}
        claim = next(claim for claim in manifest["claims"] if claim["capabilityRefs"] == ["pay-x402"])
        capability = next(cap for cap in manifest["capabilities"] if cap["ref"] == "pay-x402")
        cases = {case for ref in claim["evidenceRefs"] for case in runs[ref]["caseIds"]}
        self.assertEqual(cases, {"settlement-x402-pass"})
        self.assertEqual((claim["result"], capability["testStatus"]), ("implemented", "partial"))
        readme = (EXAMPLE_DIR / "README.md").read_text(encoding="utf-8")
        self.assertIn("so `pay-x402` is `partial` and claimed only as\n`implemented`", readme)
        # RD-1..RD-5 are rail-author duties (§9.10), so the seller claims the
        # rail against its §9.4.2 registry entry, as the DEM rail claims do.
        rail = next(claim for claim in manifest["claims"] if claim["capabilityRefs"] == ["x402-default-rail"])
        self.assertEqual((rail["roles"], rail["ruleRefs"]), (["seller"], ["DACS-4-9.4.2"]))
        self.assertIn("| x402:default | pay-x402 |", git_show(manifest["profile"]["commit"], "spec/DACS-4-SETTLE.md")
                      .split("#### 9.4.2 ", 1)[1].split("\n#### ", 1)[0])
        self.assertIn("claims its `x402:default` rail against the §9.4.2 registry entry", " ".join(readme.split()))

    def test_examples_share_one_rule_for_implemented_rule_refs(self):
        # In the three scoped examples, an implemented claim names the rules its
        # role implements; the result, testStatus and cited cases say how much is
        # tested. So both seller examples name the same PS-* rules although no
        # cited case exercises PS-1 or PS-2, and each seller payment claim names
        # the §9.5.8 SB-1/SB-2 settlement rules (SB-3 only where the rail defines it).
        for name in SCOPED_EXAMPLES:
            manifest = load_example(name)
            with self.subTest(example=name):
                self.assertEqual([claim["id"] for claim in manifest["claims"]
                                  if claim["result"] in {"conformant", "conformance-tested"}], [])
                self.assertNotIn("passed", {cap["testStatus"] for cap in manifest["capabilities"]})
        fixed_price, payment = {}, {}
        for name, pay in (("fixed-price-x402-seller.json", "pay-x402"), ("fixed-price-pay-dem-seller.json", "pay-dem")):
            claims = {claim["capabilityRefs"][0]: claim for claim in load_example(name)["claims"]}
            self.assertEqual((claims["fixed-price"]["result"], claims["fixed-price"]["roles"]),
                             ("implemented", ["seller"]), name)
            fixed_price[name] = sorted(rule for rule in claims["fixed-price"]["ruleRefs"] if rule.startswith("PS-"))
            payment[pay] = claims[pay]["ruleRefs"]
        self.assertEqual(list(fixed_price.values()), [["PS-1", "PS-2", "PS-3"]] * 2, fixed_price)
        self.assertEqual(payment, {"pay-x402": ["DACS-4-9.5.7", "SB-1", "SB-2", "SB-3"],
                                   "pay-dem": ["DACS-4-9.5.9", "SB-1", "SB-2"]})
        # At the FP-DEM pin, SB-3 defines bindings for pay-x402 and pay-ap2 only.
        settle = git_show(V04_COMMIT, "spec/DACS-4-SETTLE.md")
        sb3 = settle.split("- **(SB-3) ", 1)[1].split("\n", 1)[0]
        self.assertIn("v0.2 defines one for `pay-x402`; v0.3 adds the `pay-ap2`", sb3)
        self.assertNotIn("pay-dem", sb3)
        flat = " ".join((EXAMPLE_DIR / "README.md").read_text(encoding="utf-8").split())
        for text in ("These three examples, `fixed-price-x402-seller.json` and the two `fixed-price-pay-dem-*` "
                     "examples, follow one rule for `ruleRefs`: an `implemented` claim names the rules its role "
                     "implements, whether or not a cited case exercises them;",
                     "the `pay-x402` claim names SB-1..SB-3, and the `pay-dem` claim names SB-1 and SB-2, "
                     "because v0.4 defines no SB-3 binding for `pay-dem`.",
                     "Its fixed-price claim, which names PS-1..PS-3, is therefore `partial`"):
            self.assertIn(text, flat)
        self.assertNotIn("All the examples follow one rule", flat)

    def test_readme_names_the_older_examples_it_does_not_narrow(self):
        # Every example is either scoped by the README's rule or named as older
        # and not narrowed, and what the README says those older ones claim holds.
        names = {path.name for path in EXAMPLE_DIR.glob("*.json")}
        self.assertEqual(names, set(SCOPED_EXAMPLES) | set(OLDER_EXAMPLES))
        self.assertFalse(set(SCOPED_EXAMPLES) & set(OLDER_EXAMPLES))
        v04_suite = git_show(V04_COMMIT, "conformance/MANIFEST.json")
        for name in OLDER_EXAMPLES:
            manifest = load_example(name)
            suite_pin = manifest["conformanceSuite"]
            self.assertEqual((manifest["profile"]["commit"][:7], suite_pin["commit"][:7]), ("9a1ca62", "9a1ca62"))
            self.assertEqual(git_show(suite_pin["commit"], suite_pin["manifestPath"]), v04_suite)
        suite = json.loads(v04_suite)
        tiers = {case["id"]: case["status"] for case in suite["cases"]}

        def claim_cases(manifest, capability):
            runs = {run["id"]: run for run in manifest["testRuns"]}
            claim = next(claim for claim in manifest["claims"] if claim["capabilityRefs"] == [capability])
            cap = next(cap for cap in manifest["capabilities"] if cap["ref"] == capability)
            return claim, cap, [case for ref in claim["evidenceRefs"] for case in runs[ref]["caseIds"]]

        for name, role in (("pay-dem-rfq-buyer.json", "buyer"), ("pay-dem-rfq-seller.json", "seller")):
            manifest = load_example(name)
            claim, cap, cases = claim_cases(manifest, "pay-dem")
            self.assertEqual((claim["result"], cap["testStatus"], cases),
                             ("conformance-tested", "passed", ["pb2-tier1-pay-dem-intrinsic-matches"]), name)
            self.assertEqual(tiers["pb2-tier1-pay-dem-intrinsic-matches"], "candidate")
            self.assertEqual(claim["ruleRefs"], ["PB-1", "PB-2", "PB-3"], name)
            rail, _cap, _cases = claim_cases(manifest, "demos-native-dem-rail")
            self.assertEqual(rail["ruleRefs"], ["RD-1", "RD-2", "RD-3", "RD-4", "RD-5"], name)
        claim, cap, cases = claim_cases(load_example("verifier-indexer.json"), "derive-reputation")
        self.assertEqual((claim["result"], cap["testStatus"], len(cases)), ("conformance-tested", "passed", 2))
        self.assertEqual(sorted(tiers[case] for case in cases), ["candidate", "golden"])
        flat = " ".join((EXAMPLE_DIR / "README.md").read_text(encoding="utf-8").split())
        for text in ("The `pay-dem-rfq-*` and `verifier-indexer.json` examples predate this scoping and are not "
                     "narrowed by it. They pin `9a1ca62`, whose conformance manifest is byte-identical to v0.4's.",
                     "both `pay-dem-rfq-*` examples claim `pay-dem` as `conformance-tested` with test status "
                     "`passed`, and claim the DEM rail against RD-1..RD-5; the seller also names PB-1..PB-3.",
                     "`verifier-indexer.json` claims `derive-reputation` as `conformance-tested` on two cases, "
                     "one of them a candidate."):
            self.assertIn(text, flat)

    def seller_example(self):
        manifest = load_example("fixed-price-pay-dem-seller.json")
        self.assertEqual(self.validate(copy.deepcopy(manifest)), [])
        return manifest

    def x402_passing_example(self):
        # The x402 example makes no passing claim, so promote its fixed-price
        # claim and check that the promoted manifest is valid before a test changes it.
        manifest = load_example()
        claim = next(claim for claim in manifest["claims"] if claim["id"] == "claim-fixed-price")
        claim["result"] = "conformance-tested"
        capability = next(cap for cap in manifest["capabilities"] if cap["ref"] == "fixed-price")
        capability["testStatus"] = "passed"
        self.assertEqual(self.validate(copy.deepcopy(manifest)), [])
        return manifest

    def passing_claim(self, manifest):
        # The examples make no passing claim, so promote the delivery claim and
        # check that the promoted manifest is valid before the test changes it.
        claim = next(claim for claim in manifest["claims"]
                     if claim["capabilityRefs"] == ["storage-program-delivery"])
        claim["result"] = "conformance-tested"
        capability = next(cap for cap in manifest["capabilities"] if cap["ref"] == "storage-program-delivery")
        capability["testStatus"] = "passed"
        self.assertEqual(self.validate(copy.deepcopy(manifest)), [])
        return claim

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
        manifest = self.x402_passing_example()
        manifest["testRuns"][0]["result"] = "fail"

        errors = self.validate(manifest)

        self.assertTrue(any("passing claim must reference only passing" in error for error in errors))
        self.assertTrue(any("passed capability must reference only passing" in error for error in errors))

    def test_passing_claim_evidence_must_cover_its_capability(self):
        manifest = self.x402_passing_example()
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

    def assert_rejected(self, mutate, message, manifest=None):
        manifest = manifest or self.seller_example()
        mutate(manifest)
        errors = self.validate(manifest)
        self.assertTrue(any(message in error for error in errors), errors)

    def test_pins_must_name_the_standard_repository_and_full_hex_digests(self):
        # IM-1: a fork URL or a truncated or upper-case digest is not a pin.
        fork = "https://github.com/someone/dacs-standard"
        cases = [
            (lambda m: m["profile"].update(repository=fork),
             "profile.repository must identify https://github.com/dacs-agent-commerce/dacs-standard"),
            (lambda m: m["conformanceSuite"].update(repository=fork),
             "conformanceSuite.repository must identify https://github.com/dacs-agent-commerce/dacs-standard"),
            (lambda m: m["profile"].update(commit=V04_COMMIT[:39]), "profile.commit must be 40 lower-case hex"),
            (lambda m: m["conformanceSuite"].update(commit=V04_COMMIT.upper()),
             "conformanceSuite.commit must be 40 lower-case hex"),
            (lambda m: m["implementation"].update(commit="5" * 39), "implementation.commit must be 40 lower-case hex"),
            (lambda m: m["conformanceSuite"].update(manifestSha256=m["conformanceSuite"]["manifestSha256"][:63]),
             "conformanceSuite.manifestSha256 must be 64 lower-case hex"),
        ]
        for mutate, message in cases:
            with self.subTest(message=message):
                self.assert_rejected(mutate, message)

    def test_capability_status_axes_are_closed_and_consistent(self):
        # IM-2: support, availability and test status are separate closed axes,
        # and availability MAY be omitted, as the FP-DEM examples do.
        manifest = self.seller_example()
        self.assertFalse([cap["ref"] for cap in manifest["capabilities"] if "availability" in cap])

        def cap(ref, **changes):
            def mutate(m):
                next(c for c in m["capabilities"] if c["ref"] == ref).update(changes)
            return mutate

        cases = [
            (cap("fixed-price", supportStatus="shipped"), "capabilities[fixed-price].supportStatus is unsupported"),
            (cap("fixed-price", testStatus="green"), "capabilities[fixed-price].testStatus is unsupported"),
            (cap("fixed-price", availability="always"), "capabilities[fixed-price].availability is unsupported"),
            (cap("rfq", availability="live"), "capabilities[rfq] unsupported capability must omit availability"),
            (cap("rfq", evidenceRefs=["fixed-price-vectors"]),
             "capabilities[rfq] unsupported capability must be not_tested with no evidence"),
            (cap("rfq", testStatus="partial"),
             "capabilities[rfq] unsupported capability must be not_tested with no evidence"),
            (cap("fixed-price", testStatus="not_tested"),
             "capabilities[fixed-price] not_tested capability must not reference evidence"),
            (cap("fixed-price", testStatus="failed"),
             "capabilities[fixed-price] failed capability must reference a failing deterministic run"),
        ]
        for mutate, message in cases:
            with self.subTest(message=message):
                self.assert_rejected(mutate, message)

    def test_passing_claim_needs_evidence_roles_modules_and_a_passed_capability(self):
        # IM-3 and the level/result table.
        def claim(**changes):
            def mutate(m):
                next(c for c in m["claims"] if c["id"] == "claim-fixed-price").update(changes)
            return mutate

        def capability(**changes):
            def mutate(m):
                next(c for c in m["capabilities"] if c["ref"] == "fixed-price").update(changes)
            return mutate

        def extra_role(m):
            m["roles"].append("buyer")
            capability(roles=["seller", "buyer"])(m)

        label = "claims[claim-fixed-price]"
        cases = [
            (claim(evidenceRefs=[]), f"{label} passing claim must reference deterministic evidence"),
            (extra_role, f"{label} does not declare every role used by capability 'fixed-price'"),
            (capability(modules=["DACS-3", "DACS-4"]),
             f"{label} does not declare every module used by capability 'fixed-price'"),
            (capability(testStatus="partial"), f"{label} passing claim requires passed capability 'fixed-price'"),
            (claim(level="module", result="implemented"),
             f"{label} level 'module' cannot use result 'implemented'"),
            (claim(level="capability", result="conformant"),
             f"{label} level 'capability' cannot use result 'conformant'"),
        ]
        for mutate, message in cases:
            with self.subTest(message=message):
                self.assert_rejected(mutate, message, self.x402_passing_example())

    def test_live_test_cannot_substitute_for_deterministic_evidence(self):
        manifest = load_example()
        manifest["claims"][1]["evidenceRefs"] = ["base-sepolia-x402-live"]

        errors = self.validate(manifest)

        self.assertTrue(any("unknown deterministic runs" in error for error in errors))

    def test_passing_claim_cannot_include_unsupported_capability(self):
        manifest = self.x402_passing_example()
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
        manifest = self.x402_passing_example()
        manifest["deviations"] = [
            {
                "id": "known-gap",
                "capabilityRefs": ["fixed-price"],
                "ruleRefs": ["PS-3"],
                "status": "open",
                "effect": "nonconforming",
                "description": "Known protocol mismatch.",
            }
        ]

        errors = self.validate(manifest)

        self.assertTrue(any("invalidated by open nonconforming deviations" in error for error in errors))

    def test_open_nonconforming_deviation_invalidates_only_claims_on_its_capability(self):
        # IM-5 invalidates the passing claims "referencing its affected
        # capability", so a deviation on fixed-price leaves the delivery claim valid.
        manifest = self.seller_example()
        self.passing_claim(manifest)
        deviation = {
            "id": "known-gap",
            "capabilityRefs": ["fixed-price"],
            "ruleRefs": ["PS-3"],
            "status": "open",
            "effect": "nonconforming",
            "description": "Known protocol mismatch on another capability.",
        }
        manifest["deviations"] = [deviation]

        self.assertEqual(self.validate(copy.deepcopy(manifest)), [])

        deviation["capabilityRefs"] = ["storage-program-delivery"]
        errors = self.validate(manifest)
        self.assertTrue(any("claim-storage-program-delivery-seller" in error
                            and "invalidated by open nonconforming deviations on: storage-program-delivery" in error
                            for error in errors), errors)

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
        manifest = self.x402_passing_example()
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
