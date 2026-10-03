"""Regression tests for cross-run abstention and convergence semantics."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "diff_vector_runs.py"
sys.path.insert(0, str(ROOT / "scripts"))
import diff_vector_runs as diff_runs  # noqa: E402
from diff_vector_runs import load_expected  # noqa: E402
SET = "phase-kind-divergence-v0.3"
CASE = "shared-index-kind-mismatch-is-divergent"


class DiffVectorRunsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="dacs_cross_run_")
        self.addCleanup(self.tmp.cleanup)
        self.paths: list[Path] = []

    def add_run(self, impl: str, result: dict, *, set_name: str = SET) -> None:
        path = Path(self.tmp.name) / f"run-{len(self.paths)}.json"
        path.write_text(
            json.dumps({"set": set_name, "impl": impl, "results": [result]}),
            encoding="utf-8",
        )
        self.paths.append(path)

    def add_run_payload(self, value) -> None:
        path = Path(self.tmp.name) / f"run-{len(self.paths)}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        self.paths.append(path)

    def add_complete_run(self, impl: str, verdicts: dict[str, object]) -> None:
        self.add_run_payload({
            "set": "dacs1-vet-golden-inputs-v0.1",
            "impl": impl,
            "results": [
                {"name": name, "verdict": verdict}
                for name, verdict in sorted(verdicts.items())
            ],
        })

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
        self.assertEqual(44, len(expected))
        self.assertIn("dacs1-cci-lei-defect::result", expected)
        self.assertIn("dacs1-freshness-fail-closed::expiresOnly", expected)
        self.assertEqual(
            "error", expected["vet-oneof-error-over-fail::result"]
        )

    def test_json_boolean_and_number_verdicts_are_distinct(self):
        case = "dacs1-cci-lei-defect::result"
        expected = load_expected("dacs1-vet-golden-inputs-v0.1")
        self.add_complete_run("impl-a@1", expected)
        self.add_complete_run("impl-b@1", expected)
        control = self.execute()
        self.assertEqual(0, control.returncode, control.stderr)

        # Keep both runs complete and change only one JSON type.  This isolates
        # the bool/number mismatch from missing-case diagnostics.
        self.paths.clear()
        left = dict(expected)
        right = dict(expected)
        left[case] = False
        right[case] = 0
        self.add_complete_run("impl-a@1", left)
        self.add_complete_run("impl-b@1", right)
        run = self.execute()
        self.assertEqual(1, run.returncode)
        self.assertIn("DIVERGENCE", run.stderr)
        self.assertNotIn("cross-run CONVERGED", run.stdout + run.stderr)
        self.assertFalse(diff_runs._verdict_equal(True, 1))
        self.assertFalse(diff_runs._verdict_equal(False, 0.0))
        self.assertTrue(diff_runs._verdict_equal(1, 1.0))
        self.assertTrue(diff_runs._verdict_equal({"n": 1}, {"n": 1.0}))

    def test_expected_loader_fails_closed_on_malformed_or_incomplete_sets(self):
        invalid = {
            "null root": None,
            "list root": [],
            "no supported list": {"status": "candidate"},
            "both lists": {"vectors": [{}], "cases": [{}]},
            "empty vectors": {"vectors": []},
            "non-object case": {"vectors": [None]},
            "missing name": {"vectors": [{"expected": "pass"}]},
            "missing verdict": {"vectors": [{"name": "case"}]},
            "missing evaluated output": {
                "cases": [{"id": "case", "evaluations": {"result": {}}}],
            },
            "duplicate identity": {
                "vectors": [
                    {"name": "case", "expected": "pass"},
                    {"name": "case", "expected": "fail"},
                ],
            },
            "duplicate identity distinct labels": {
                "cases": [
                    {
                        "id": "case",
                        "evaluations": {"first": {}},
                        "expectedOutput": {"first": "pass"},
                    },
                    {
                        "id": "case",
                        "evaluations": {"second": {}},
                        "expectedOutput": {"second": "pass"},
                    },
                ],
            },
            "null verdict": {"vectors": [{"name": "case", "expected": None}]},
        }
        with mock.patch.object(diff_runs, "FIXTURE_DIRS", (self.tmp.name,)):
            for label, value in invalid.items():
                with self.subTest(label=label):
                    path = Path(self.tmp.name) / f"{label}.json"
                    path.write_text(json.dumps(value), encoding="utf-8")
                    with self.assertRaises(SystemExit):
                        load_expected(label)

    def test_run_loader_fails_closed_on_malformed_roots_and_fields(self):
        invalid = (
            None,
            [],
            {},
            {"set": SET, "impl": "impl-a", "results": {}},
            {"set": SET, "impl": [], "results": []},
            {"set": SET, "impl": "impl-a", "results": [None]},
            {
                "set": SET, "impl": "impl-a",
                "results": [{"name": [], "verdict": "reject"}],
            },
        )
        for index, value in enumerate(invalid):
            with self.subTest(index=index):
                path = Path(self.tmp.name) / f"invalid-run-{index}.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(SystemExit):
                    diff_runs.load_run(str(path))

    def test_empty_runs_cannot_claim_zero_case_convergence(self):
        self.add_run_payload({"set": SET, "impl": "impl-a", "results": []})
        self.add_run_payload({"set": SET, "impl": "impl-b", "results": []})
        run = self.execute()
        self.assertEqual(1, run.returncode)
        self.assertIn("no comparable evaluated case", run.stderr)
        self.assertNotIn("cross-run CONVERGED", run.stdout + run.stderr)

    def test_malformed_json_is_a_controlled_cli_failure(self):
        path = Path(self.tmp.name) / "malformed.json"
        path.write_text("{", encoding="utf-8")
        self.paths.append(path)
        run = self.execute()
        self.assertNotEqual(0, run.returncode)
        self.assertIn("not valid readable JSON", run.stderr)
        self.assertNotIn("Traceback", run.stderr)

    def test_duplicate_members_and_non_json_numbers_fail_closed(self):
        for index, raw in enumerate((
            b'{"set":"x","set":"y","impl":"a","results":[]}',
            b'{"set":"x","impl":"a","results":[],"n":NaN}',
            b'{"set":"x","impl":"a","results":[],"n":Infinity}',
        )):
            with self.subTest(index=index):
                path = Path(self.tmp.name) / f"invalid-raw-{index}.json"
                path.write_bytes(raw)
                self.paths = [path]
                run = self.execute()
                self.assertNotEqual(0, run.returncode)
                self.assertIn("not valid readable JSON", run.stderr)
                self.assertNotIn("Traceback", run.stderr)


if __name__ == "__main__":
    unittest.main()
