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
        self.assertEqual(self.gate.run_vector_matrices(self.manifest), 10)

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

    def test_planned_classes_are_not_reported_as_coverage(self):
        self.assertEqual(
            {item["status"] for item in self.manifest["plannedInvariantClasses"]},
            {"planned"},
        )
        manifest = copy.deepcopy(self.manifest)
        manifest["plannedInvariantClasses"][0]["status"] = "covered"
        with self.assertRaisesRegex(self.gate.GateError, "status=planned"):
            self.gate.validate_manifest(manifest)

    def test_disappeared_case_id_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["vectorMatrices"][0]["cases"][0]["caseId"] = "case-that-does-not-exist"
        self.gate.validate_manifest(manifest)
        with self.assertRaisesRegex(self.gate.GateError, "required case disappeared"):
            self.gate.run_vector_matrices(manifest)

    def test_case_must_discriminate_from_its_control(self):
        manifest = copy.deepcopy(self.manifest)
        case = manifest["vectorMatrices"][0]["cases"][0]
        case["controlCase"] = case["caseId"]
        self.gate.validate_manifest(manifest)
        with self.assertRaisesRegex(self.gate.GateError, "no longer discriminates"):
            self.gate.run_vector_matrices(manifest)

    @unittest.skipIf(os.name == "nt", "POSIX executable bit")
    def test_gate_remains_executable(self):
        self.assertTrue(os.access(SCRIPT, os.X_OK))


if __name__ == "__main__":
    unittest.main()
