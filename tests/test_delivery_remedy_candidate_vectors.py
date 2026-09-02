import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from scripts.jcs import canonicalize as jcs_canonicalize
from scripts.verify_delivery_remedy_candidate_vectors import (
    DRC_RULES,
    apply_operation,
    artifact_hash,
    canonical_bytes,
    deployment_rule_statuses,
    evaluate_deployment,
    evaluate_protocol,
    materialize_vector,
    verify_deployment_pack,
    verify_vector_pack,
)


ROOT = Path(__file__).resolve().parents[1]
VECTOR_PACK = ROOT / "conformance/fixtures/delivery-remedy/candidate-vectors-v0.1.json"
DEPLOYMENT_PACK = ROOT / "conformance/fixtures/delivery-remedy/deployment-capabilities-v0.1.json"
GENERATOR = ROOT / "scripts/generate_delivery_remedy_candidate_vectors.py"
VERIFIER = ROOT / "scripts/verify_delivery_remedy_candidate_vectors.py"


class DeliveryRemedyCandidateVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vector_pack = json.loads(VECTOR_PACK.read_text(encoding="utf-8"))
        cls.deployment_pack = json.loads(DEPLOYMENT_PACK.read_text(encoding="utf-8"))
        cls.vectors = {item["name"]: item for item in cls.vector_pack["vectors"]}
        cls.deployment_cases = {
            item["name"]: item for item in cls.deployment_pack["cases"]
        }

    def test_generated_files_are_current(self):
        result = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_standalone_verifier_accepts_both_packs(self):
        result = subprocess.run(
            [sys.executable, str(VERIFIER)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("no rail registered", result.stdout)

    def test_pack_metadata_hashes_and_names_are_exact(self):
        for pack, fields in (
            (self.vector_pack, ("fixtures", "vectors")),
            (self.deployment_pack, ("manifests", "cases")),
        ):
            with self.subTest(kind=pack["kind"]):
                items = pack[fields[1]]
                self.assertEqual(pack["count"], len(items))
                self.assertEqual(len(items), len({item["name"] for item in items}))
                payload = {field: pack[field] for field in fields}
                self.assertEqual(
                    pack["hash"], hashlib.sha256(canonical_bytes(payload)).hexdigest()
                )

    def test_every_lifecycle_vector_executes_to_its_pinned_result_and_rule(self):
        self.assertEqual(verify_vector_pack(self.vector_pack), [])
        for vector in self.vector_pack["vectors"]:
            with self.subTest(vector=vector["name"]):
                observed = evaluate_protocol(
                    materialize_vector(self.vector_pack, vector)
                )
                self.assertEqual(observed["result"], vector["expected"])
                self.assertEqual(observed["rule"], vector["expectedRule"])

    def test_positive_mapping_is_byte_exact_not_text_rehashed(self):
        release = materialize_vector(
            self.vector_pack, self.vectors["release-complete-budget"]
        )
        artifacts = release["artifacts"]
        self.assertEqual(
            release["native"]["description"],
            "dacs-delivery-remedy:v1:" + artifact_hash(artifacts["agreement"]),
        )
        self.assertEqual(
            release["native"]["deliverable"],
            "0x" + artifact_hash(artifacts["delivery"]),
        )
        self.assertEqual(
            release["native"]["reason"],
            "0x" + artifact_hash(artifacts["decision"]),
        )
        self.assertEqual(
            bytes.fromhex(release["canonicalRecords"]["delivery"]["canonicalUtf8Hex"]),
            jcs_canonicalize(
                {key: value for key, value in artifacts["delivery"].items() if key != "signature"}
            ).encode("utf-8"),
        )
        self.assertNotEqual(
            release["native"]["deliverable"][2:],
            hashlib.sha256(artifact_hash(artifacts["delivery"]).encode("ascii")).hexdigest(),
        )

    def test_release_refund_and_expiry_terminal_invariants_are_distinct(self):
        release = materialize_vector(
            self.vector_pack, self.vectors["release-complete-budget"]
        )
        rejection = materialize_vector(
            self.vector_pack, self.vectors["evaluator-rejection-refund"]
        )
        expiry_pre = materialize_vector(
            self.vector_pack, self.vectors["expiry-before-submission"]
        )
        expiry_post = materialize_vector(
            self.vector_pack, self.vectors["expiry-after-submission-grace"]
        )
        pre_submission_rejection = materialize_vector(
            self.vector_pack, self.vectors["pre-submission-evaluator-rejection"]
        )
        self.assertEqual(release["native"]["terminalAction"], "complete")
        self.assertEqual(rejection["native"]["terminalAction"], "reject")
        self.assertEqual(expiry_pre["native"]["terminalAction"], "claimRefund")
        self.assertNotIn("decision", expiry_pre["artifacts"])
        self.assertNotIn("decisionRef", expiry_pre["artifacts"]["terminal"])
        self.assertNotIn("deliveryEvidenceRef", expiry_pre["artifacts"]["terminal"])
        self.assertNotIn("decision", expiry_post["artifacts"])
        self.assertIn("deliveryEvidenceRef", expiry_post["artifacts"]["terminal"])
        self.assertNotIn("delivery", pre_submission_rejection["artifacts"])
        self.assertIn("dispute", pre_submission_rejection["artifacts"])
        self.assertNotIn(
            "deliveryEvidenceRef", pre_submission_rejection["artifacts"]["decision"]
        )
        self.assertEqual(
            pre_submission_rejection["artifacts"]["decision"]["basisRef"]["kind"],
            "dispute-outcome",
        )

    def test_replay_role_mapping_and_ordering_regressions_are_present(self):
        required = {
            "cross-job-delivery-replay": "rejected",
            "cross-job-decision-replay": "rejected",
            "consumed-decision-replay": "rejected",
            "evaluator-primary-claim-collision": "rejected",
            "evaluator-account-collision": "rejected",
            "delivery-hash-text-rehash": "rejected",
            "decision-hash-text-rehash": "rejected",
            "cross-substrate-order-unavailable": "indeterminate",
            "decision-finalized-after-terminal": "rejected",
            "delivery-submission-circularity": "rejected",
            "evaluator-added-as-bundle-party": "rejected",
            "relayer-substituted-as-native-caller": "rejected",
        }
        for name, expected in required.items():
            with self.subTest(vector=name):
                self.assertEqual(self.vectors[name]["expected"], expected)

    def test_relay_never_replaces_the_native_evaluator_caller(self):
        relayed = materialize_vector(
            self.vector_pack, self.vectors["eip1271-relayed-execution"]
        )
        self.assertEqual(relayed["native"]["evaluatorAccountType"], "eip1271")
        self.assertEqual(
            relayed["native"]["terminalCaller"], relayed["native"]["evaluator"]
        )
        self.assertNotEqual(
            relayed["native"]["transactionSubmitter"],
            relayed["native"]["terminalCaller"],
        )
        self.assertEqual(evaluate_protocol(relayed)["result"], "verified")

    def test_fixture_scope_cannot_be_read_as_live_rail_registration(self):
        self.assertEqual(self.vector_pack["status"], "non-normative-review-fixture")
        for fixture in self.vector_pack["fixtures"].values():
            self.assertTrue(fixture["fixtureOnly"])
            self.assertEqual(
                fixture["artifacts"]["railDefinition"]["availability"], "mocked"
            )
            self.assertTrue(fixture["artifacts"]["railDefinition"]["fixtureOnly"])

    def test_every_deployment_case_executes_and_registration_stays_false(self):
        self.assertEqual(verify_deployment_pack(self.deployment_pack), [])
        manifests = self.deployment_pack["manifests"]
        for case in self.deployment_pack["cases"]:
            manifest = copy.deepcopy(manifests[case["base"]])
            for operation in case["patch"]:
                manifest = apply_operation(manifest, operation)
            observed = evaluate_deployment(manifest)
            with self.subTest(case=case["name"]):
                self.assertEqual(observed["result"], case["expected"])
                self.assertFalse(observed["registrationEligible"])

    def test_synthetic_control_exercises_all_drc_rules_without_registering(self):
        manifest = self.deployment_pack["manifests"]["synthetic-control"]
        statuses = deployment_rule_statuses(manifest)
        self.assertEqual(set(statuses), DRC_RULES)
        self.assertEqual(set(statuses.values()), {"pass"})
        observed = evaluate_deployment(manifest)
        self.assertEqual(observed["result"], "verified")
        self.assertTrue(manifest["fixtureOnly"])
        self.assertEqual(manifest["registrationStatus"], "not-a-deployment")
        self.assertFalse(observed["registrationEligible"])

    def test_current_reference_is_pinned_ineligible_and_never_available(self):
        manifest = self.deployment_pack["manifests"]["current-reference-142e669"]
        self.assertEqual(
            manifest["implementation"]["revision"],
            "142e669c1fd318486a4628395b629f033654dd06",
        )
        observed = evaluate_deployment(manifest)
        self.assertEqual(observed["result"], "rejected")
        self.assertEqual(
            [rule for rule in sorted(DRC_RULES, key=lambda item: int(item.split("-")[1])) if observed["ruleStatuses"][rule] == "fail"],
            ["DRC-1", "DRC-2", "DRC-3", "DRC-4", "DRC-5", "DRC-6", "DRC-7"],
        )
        self.assertEqual(
            [rule for rule in sorted(DRC_RULES, key=lambda item: int(item.split("-")[1])) if observed["ruleStatuses"][rule] == "unknown"],
            ["DRC-8", "DRC-10", "DRC-11", "DRC-12"],
        )
        self.assertFalse(observed["registrationEligible"])


if __name__ == "__main__":
    unittest.main()
