import copy
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pre_review_gate.py"
MANIFEST = ROOT / "conformance" / "pre-review-invariants.json"


def load_gate():
    spec = importlib.util.spec_from_file_location("pre_review_gate", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PreReviewGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gate = load_gate()
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_manifest_and_registered_vectors_execute(self):
        self.gate.validate_manifest(self.manifest)
        self.assertEqual(self.gate.run_vector_matrices(self.manifest), 22)
        self.assertEqual(
            self.gate.run_independent_review_evidence(self.manifest), 20
        )

    def test_required_independent_review_lens_cannot_be_removed(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["independentReviewLenses"].pop()
        with self.assertRaisesRegex(
            self.gate.GateError, "do not match the required set"
        ):
            self.gate.validate_manifest(manifest)

    def test_each_lens_requires_counterexample_and_control_evidence(self):
        for role in ("counterexampleEvidence", "controlEvidence"):
            with self.subTest(role=role):
                manifest = copy.deepcopy(self.manifest)
                manifest["independentReviewLenses"][0][role] = []
                with self.assertRaisesRegex(self.gate.GateError, role):
                    self.gate.validate_manifest(manifest)

    def test_dangling_independent_review_evidence_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["independentReviewLenses"][0]["counterexampleEvidence"] = [
            "missing-evidence"
        ]
        with self.assertRaisesRegex(
            self.gate.GateError, "dangling independent review evidence"
        ):
            self.gate.validate_manifest(manifest)

    def test_duplicate_independent_review_evidence_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        duplicate = copy.deepcopy(manifest["independentReviewEvidence"][0])
        manifest["independentReviewEvidence"].append(duplicate)
        with self.assertRaisesRegex(
            self.gate.GateError, "evidence must be unique and runnable"
        ):
            self.gate.validate_manifest(manifest)

        manifest = copy.deepcopy(self.manifest)
        duplicate = copy.deepcopy(manifest["independentReviewEvidence"][0])
        duplicate["id"] = "different-id-same-target"
        manifest["independentReviewEvidence"].append(duplicate)
        with self.assertRaisesRegex(
            self.gate.GateError, "code-pinned declaration"
        ):
            self.gate.validate_manifest(manifest)

    def test_arbitrary_zero_exit_script_cannot_substitute_for_unittest(self):
        for registry in ("unitRegressions", "independentReviewEvidence"):
            with self.subTest(registry=registry):
                manifest = copy.deepcopy(self.manifest)
                manifest[registry][0]["file"] = "scripts/jcs.py"
                with self.assertRaisesRegex(
                    self.gate.GateError, "test_.*under tests"
                ):
                    self.gate.validate_manifest(manifest)

        entries = [{
            "id": "zero-exit-substitution",
            "file": "scripts/jcs.py",
            "test": "PlausibleTests.test_claimed_evidence",
        }]
        with self.assertRaisesRegex(self.gate.GateError, "test_.*under tests"):
            self.gate._run_python_evidence(entries, "review evidence")

    def test_unittest_identity_is_safe_and_nonexistent_target_fails(self):
        unsafe = [{
            "id": "unsafe-target",
            "file": "tests/test_pr333_fix_2.py",
            "test": "--help",
        }]
        with self.assertRaisesRegex(
            self.gate.GateError, "safe dotted unittest identity"
        ):
            self.gate._run_python_evidence(unsafe, "review evidence")

        nonexistent = [{
            "id": "nonexistent-target",
            "file": "tests/test_pr333_fix_2.py",
            "test": "AuthenticatedEvidenceWireTypeAlgorithmTests.test_does_not_exist",
        }]
        with self.assertRaisesRegex(
            self.gate.GateError, "nonexistent-target: independent review evidence.*failing"
        ):
            self.gate._run_python_evidence(nonexistent, "review evidence")

    def test_helper_and_alternate_passing_regression_retargets_are_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["unitRegressions"][0]["test"] = (
            "RevocationStateCompletenessTests._fixture"
        )
        with self.assertRaisesRegex(
            self.gate.GateError, "final unittest identity must start with test_"
        ):
            self.gate.validate_manifest(manifest)

        manifest = copy.deepcopy(self.manifest)
        manifest["unitRegressions"][0]["test"] = (
            "RevocationStateCompletenessTests.test_metadata_and_hash"
        )
        with self.assertRaisesRegex(
            self.gate.GateError, "regression does not match.*code-pinned"
        ):
            self.gate.validate_manifest(manifest)

    def test_selected_skip_is_rejected(self):
        entry = {
            "id": "skip-probe",
            "file": "tests/test_pre_review_gate.py",
            "test": "PreReviewGateTests.test_skip_probe",
        }
        with mock.patch.dict(
            os.environ, {"DACS_PRE_REVIEW_SKIP_PROBE": "1"}
        ):
            with self.assertRaisesRegex(
                self.gate.GateError,
                "skip-probe: independent review evidence.*failing",
            ):
                self.gate._run_python_evidence([entry], "review evidence")

    def test_skip_probe(self):
        if os.environ.get("DACS_PRE_REVIEW_SKIP_PROBE") == "1":
            self.skipTest("selected skips must not satisfy review evidence")
        self.assertNotEqual(os.environ.get("DACS_PRE_REVIEW_SKIP_PROBE"), "1")

    def test_runner_constructs_unittest_module_command(self):
        entry = self.manifest["independentReviewEvidence"][0]
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(
            self.gate.subprocess, "run", return_value=completed
        ) as run:
            self.assertEqual(
                self.gate._run_python_evidence([entry], "review evidence"), 1
            )
        command = run.call_args.args[0]
        self.assertEqual(
            command[:3],
            [
                self.gate.sys.executable,
                "-c",
                self.gate.EXACT_UNITTEST_RUNNER,
            ],
        )
        self.assertEqual(
            command[3],
            "tests.test_pr333_fix_2."
            "AuthenticatedEvidenceWireTypeAlgorithmTests."
            "test_algorithm_array_rejected_without_exception_ebfab",
        )

    def test_two_tests_cannot_claim_every_lens_and_surface(self):
        manifest = copy.deepcopy(self.manifest)
        counter = manifest["independentReviewEvidence"][0]["id"]
        control = next(
            item["id"] for item in manifest["independentReviewEvidence"]
            if item["id"] == "type-totality-control"
        )
        for lens in manifest["independentReviewLenses"]:
            lens["counterexampleEvidence"] = [counter]
            lens["controlEvidence"] = [control]
        with self.assertRaisesRegex(self.gate.GateError, "evidence belongs to both"):
            self.gate.validate_manifest(manifest)

        manifest = copy.deepcopy(manifest)
        for evidence in manifest["independentReviewEvidence"]:
            if evidence["id"] in {counter, control}:
                evidence["surfaces"] = sorted(self.gate.EVIDENCE_SURFACES)
        with self.assertRaisesRegex(self.gate.GateError, "code-pinned declaration"):
            self.gate.validate_manifest(manifest)

    def test_pinned_evidence_id_cannot_be_retargeted(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["independentReviewEvidence"][0]["test"] = (
            "AuthenticatedEvidenceWireTypeAlgorithmTests.test_valid_algorithm_preserved"
        )
        with self.assertRaisesRegex(self.gate.GateError, "code-pinned declaration"):
            self.gate.validate_manifest(manifest)

    def test_invalid_independent_review_evidence_shape_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["independentReviewEvidence"][0]["surfaces"] = ["invented"]
        with self.assertRaisesRegex(
            self.gate.GateError, "evidence must be unique and runnable"
        ):
            self.gate.validate_manifest(manifest)

    def test_failing_independent_review_evidence_fails_the_gate(self):
        failed = mock.Mock(returncode=1, stdout="", stderr="deliberate failure")
        with mock.patch.object(self.gate.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(
                self.gate.GateError,
                "type-totality-array-ebfab-counterexample: independent review evidence.*failing",
            ):
                self.gate.run_independent_review_evidence(self.manifest)

    def test_incomplete_matrix_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["vectorMatrices"][0]["cases"].pop()
        with self.assertRaisesRegex(self.gate.GateError, "incomplete matrix"):
            self.gate.validate_manifest(manifest)

    def test_duplicate_matrix_coordinate_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        duplicate = copy.deepcopy(manifest["vectorMatrices"][0]["cases"][0])
        duplicate["caseId"] = "duplicate-case-id"
        manifest["vectorMatrices"][0]["cases"].append(duplicate)
        with self.assertRaisesRegex(self.gate.GateError, "duplicate coordinate"):
            self.gate.validate_manifest(manifest)

    def test_coverage_claim_requires_a_declared_executable_matrix(self):
        self.assertEqual(self.manifest["plannedInvariantClasses"], [])
        self.assertEqual(
            {item["id"] for item in self.manifest["coveredInvariantClasses"]},
            {
                "same-sequence-conflict",
                "closed-schema",
                "reference-reuse",
                "selector-exclusivity",
                "cross-module-composition",
            },
        )
        manifest = copy.deepcopy(self.manifest)
        manifest["coveredInvariantClasses"][0]["matrixIds"] = ["missing-matrix"]
        with self.assertRaisesRegex(self.gate.GateError, "coverage references missing matrix"):
            self.gate.validate_manifest(manifest)

        manifest = copy.deepcopy(self.manifest)
        manifest["coveredInvariantClasses"][0]["matrixIds"] = [
            "pr396-selector-exclusivity"
        ]
        with self.assertRaisesRegex(self.gate.GateError, "does not declare this invariant class"):
            self.gate.validate_manifest(manifest)

        manifest = copy.deepcopy(self.manifest)
        manifest["coveredInvariantClasses"] = [
            item for item in manifest["coveredInvariantClasses"]
            if item["id"] != "closed-schema"
        ]
        with self.assertRaisesRegex(
            self.gate.GateError, "matrix invariant classes must be claimed as covered"
        ):
            self.gate.validate_manifest(manifest)

    def test_class_cannot_be_both_covered_and_planned(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["plannedInvariantClasses"] = [
            {"id": "reference-reuse", "status": "planned"}
        ]
        with self.assertRaisesRegex(self.gate.GateError, "both covered and planned"):
            self.gate.validate_manifest(manifest)

    def test_disappeared_case_id_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["vectorMatrices"][0]["cases"][0]["caseId"] = "case-that-does-not-exist"
        self.gate.validate_manifest(manifest)
        with self.assertRaisesRegex(self.gate.GateError, "required case disappeared"):
            self.gate.run_vector_matrices(manifest)

    def test_duplicate_corpus_vector_names_are_rejected(self):
        corpus = {"vectors": [
            {"name": "same-name", "expected": "pass", "want": {}},
            {"name": "same-name", "expected": "fail", "want": {}},
        ]}
        with self.assertRaisesRegex(
            self.gate.GateError, "duplicate corpus vector name: same-name"
        ):
            self.gate._index_vectors(corpus, "duplicate-test")

    def test_incomplete_consumer_effect_expectation_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["vectorMatrices"][0]["cases"][0]["expected"].pop("session")
        with self.assertRaisesRegex(self.gate.GateError, "incomplete expected result"):
            self.gate.validate_manifest(manifest)

    def test_session_only_case_drift_is_rejected(self):
        original_load = self.gate._load_evaluator

        class SessionDrift:
            def __init__(self, evaluator):
                self.evaluator = evaluator

            def evaluate(self, *args):
                verdict, effects = self.evaluator.evaluate(*args)
                return verdict, {**effects, "session": "continue"}

        self.gate._load_evaluator = lambda relative: SessionDrift(original_load(relative))
        try:
            with self.assertRaisesRegex(self.gate.GateError, "expected.*session.*refuse"):
                self.gate.run_vector_matrices(self.manifest)
        finally:
            self.gate._load_evaluator = original_load

    def test_missing_or_extra_consumer_effect_is_rejected(self):
        original_load = self.gate._load_evaluator

        class EffectDrift:
            def __init__(self, evaluator, mode):
                self.evaluator = evaluator
                self.mode = mode

            def evaluate(self, *args):
                verdict, effects = self.evaluator.evaluate(*args)
                effects = dict(effects)
                if self.mode == "missing":
                    effects.pop("session", None)
                else:
                    effects["unexpectedEffect"] = "present"
                return verdict, effects

        for mode in ("missing", "extra"):
            with self.subTest(mode=mode):
                self.gate._load_evaluator = (
                    lambda relative, mode=mode: EffectDrift(original_load(relative), mode)
                )
                try:
                    with self.assertRaisesRegex(self.gate.GateError, "expected"):
                        self.gate.run_vector_matrices(self.manifest)
                finally:
                    self.gate._load_evaluator = original_load

    def test_control_only_drift_is_rejected(self):
        original_load = self.gate._load_evaluator
        corpus_path = ROOT / self.manifest["vectorMatrices"][0]["corpus"]
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        control_input = next(
            vector["input"] for vector in corpus["vectors"]
            if vector["name"] == "rsc-valid-active-nonmembership"
        )

        class ControlDrift:
            def __init__(self, evaluator):
                self.evaluator = evaluator

            def evaluate(self, data, *args):
                if data == control_input:
                    return "fail", {"revocationCheck": "revoked", "session": "refuse"}
                return self.evaluator.evaluate(data, *args)

        self.gate._load_evaluator = lambda relative: ControlDrift(original_load(relative))
        try:
            with self.assertRaisesRegex(self.gate.GateError, "control.*expected"):
                self.gate.run_vector_matrices(self.manifest)
        finally:
            self.gate._load_evaluator = original_load

    def test_case_must_discriminate_from_its_control(self):
        manifest = copy.deepcopy(self.manifest)
        case = manifest["vectorMatrices"][0]["cases"][0]
        case["controlCase"] = case["caseId"]
        case["controlExpected"] = copy.deepcopy(case["expected"])
        self.gate.validate_manifest(manifest)
        with self.assertRaisesRegex(self.gate.GateError, "no longer discriminates"):
            self.gate.run_vector_matrices(manifest)

    def test_each_new_invariant_class_rejects_adversarial_outcome_drift(self):
        original_load = self.gate._load_evaluator
        probes = (
            ("pr396-cross-module-composition", "rsc-rb4-discovered-marker-precedes-nonmembership"),
            ("pr396-selector-exclusivity", "rsc-selector-genesis-with-transition"),
            ("pr396-reference-reuse", "rsc-reference-duplicate-consumed"),
        )
        for matrix_id, case_id in probes:
            with self.subTest(invariant=matrix_id):
                matrix = next(
                    item for item in self.manifest["vectorMatrices"]
                    if item["id"] == matrix_id
                )
                corpus = json.loads((ROOT / matrix["corpus"]).read_text(encoding="utf-8"))
                probe_input = next(
                    item["input"] for item in corpus["vectors"]
                    if item["name"] == case_id
                )

                class DriftedCase:
                    def __init__(self, evaluator):
                        self.evaluator = evaluator

                    def evaluate(self, data, *args):
                        if data == probe_input:
                            return "pass", {"revocationCheck": "absent", "session": "continue"}
                        return self.evaluator.evaluate(data, *args)

                self.gate._load_evaluator = (
                    lambda relative: DriftedCase(original_load(relative))
                )
                try:
                    with self.assertRaisesRegex(self.gate.GateError, "expected"):
                        self.gate.run_vector_matrices({
                            "corpusPins": self.manifest["corpusPins"],
                            "vectorMatrices": [matrix],
                        })
                finally:
                    self.gate._load_evaluator = original_load

    def test_corpus_revision_and_profile_drift_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        corpus = next(iter(manifest["corpusPins"].values()))
        corpus["authoritativeProfile"]["moduleVersions"]["dacs1"] = "future"
        self.gate.validate_manifest(manifest)
        with self.assertRaisesRegex(self.gate.GateError, "revision/profile pin drifted"):
            self.gate.run_vector_matrices(manifest)

    @unittest.skipIf(os.name == "nt", "POSIX executable bit")
    def test_gate_remains_executable(self):
        self.assertTrue(os.access(SCRIPT, os.X_OK))


if __name__ == "__main__":
    unittest.main()
