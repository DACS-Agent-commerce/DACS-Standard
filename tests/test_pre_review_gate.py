import copy
import importlib.util
import json
import os
from pathlib import Path
import unittest


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
