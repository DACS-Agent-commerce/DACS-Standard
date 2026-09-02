"""Regression tests for cross-run abstention and convergence semantics."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "diff_vector_runs.py"
sys.path.insert(0, str(ROOT / "scripts"))
from diff_vector_runs import load_expected  # noqa: E402
SET = "phase-kind-divergence-v0.3"
CASE = "shared-index-kind-mismatch-is-divergent"


class DiffVectorRunsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="dacs_cross_run_")
        self.addCleanup(self.tmp.cleanup)
        self.paths: list[Path] = []

    def add_run(self, impl: str, result: dict) -> None:
        path = Path(self.tmp.name) / f"run-{len(self.paths)}.json"
        path.write_text(
            json.dumps({"set": SET, "impl": impl, "results": [result]}),
            encoding="utf-8",
        )
        self.paths.append(path)

    def execute(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["python3", str(SCRIPT), *(str(path) for path in self.paths)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_two_distinct_full_runs_converge(self):
        result = {"name": CASE, "verdict": "reject"}
        self.add_run("impl-a@1", result)
        self.add_run("impl-b@1", result)
        run = self.execute()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("cross-run CONVERGED", run.stdout)
        self.assertIn("1/1 comparable agree", run.stdout)

    def test_abstention_is_not_a_matching_rejection(self):
        self.add_run(
            "impl-a@1",
            {"name": CASE, "status": "abstain", "reason": "unsupported operation"},
        )
        self.add_run("impl-b@1", {"name": CASE, "verdict": "reject"})
        run = self.execute()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("0/0 evaluated agree", run.stdout)
        self.assertIn("ABSTENTION:", run.stderr)
        self.assertIn("cross-run INCOMPLETE", run.stderr)
        self.assertNotIn("cross-run CONVERGED", run.stdout + run.stderr)

    def test_abstention_requires_reason_and_forbids_verdict(self):
        self.add_run(
            "impl-a@1",
            {"name": CASE, "status": "abstain", "verdict": "reject"},
        )
        run = self.execute()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("must not carry a verdict", run.stderr)

    def test_one_run_validates_but_cannot_claim_convergence(self):
        self.add_run("impl-a@1", {"name": CASE, "verdict": "reject"})
        run = self.execute()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("needs at least two distinct implementation ids", run.stderr)
        self.assertIn("cross-run INCOMPLETE", run.stderr)

    def test_duplicate_impl_ids_are_not_independent(self):
        result = {"name": CASE, "verdict": "reject"}
        self.add_run("impl-a@1", result)
        self.add_run("impl-a@1", result)
        run = self.execute()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("needs at least two distinct implementation ids", run.stderr)

    def test_superseded_identity_sketch_is_not_executable(self):
        with self.assertRaisesRegex(SystemExit, "superseded and not executable"):
            load_expected("control-gate-vectors")

    def test_replacement_expands_all_named_evaluations(self):
        expected = load_expected("dacs1-vet-golden-inputs-v0.1")
        self.assertEqual(34, len(expected))
        self.assertIn("dacs1-cci-lei-defect::result", expected)
        self.assertIn("dacs1-freshness-fail-closed::expiresOnly", expected)
        self.assertEqual(
            "error", expected["vet-oneof-error-over-fail::result"]
        )


if __name__ == "__main__":
    unittest.main()
