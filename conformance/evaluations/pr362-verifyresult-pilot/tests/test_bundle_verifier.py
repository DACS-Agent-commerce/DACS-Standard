#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock


RUNNER_PATH = Path(__file__).resolve().parents[1] / "runner" / "eval_pr362.py"
SPEC = importlib.util.spec_from_file_location("pr362_bundle_verifier", RUNNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {RUNNER_PATH}")
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


class BundleVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.candidate = self.root / "candidate"
        self.cases_path = self.root / "cases.json"
        self.bundle = self.root / "bundle"
        self.pin = {
            "origin": runner.EXPECTED_ORIGIN,
            "head": runner.EXPECTED_HEAD,
            "base": runner.EXPECTED_BASE,
            "statusPorcelain": "",
        }
        for relative in runner.CANDIDATE_DIGEST_PATHS.values():
            path = self.candidate / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"fixture:{relative}\n", encoding="utf-8")
        self.cases = {
            "scope": "fixture scope",
            "frozenBeforeRun": True,
            "statusVocabulary": [
                "pass", "fail", "blocked", "skipped", "not_applicable",
            ],
            "cases": [{"id": case_id} for case_id in runner.EXPECTED_CASE_IDS],
        }
        self.cases_path.write_text(
            json.dumps(self.cases, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.results = [
            {
                "caseId": case_id,
                "status": "pass",
                "observations": {"fixture": case_id},
                "actualCalls": [],
                "notes": [],
            }
            for case_id in runner.EXPECTED_CASE_IDS
        ]
        runner.CANDIDATE = self.candidate.resolve()
        runner.CASES_PATH = self.cases_path.resolve()

    def tearDown(self):
        self.temp.cleanup()

    def write_bundle(self, results=None):
        self.bundle.mkdir(parents=True, exist_ok=True)
        expected_results = copy.deepcopy(results if results is not None else self.results)
        started = max(self.cases_path.stat().st_mtime_ns, 1) + 1
        overall = "pass" if all(row["status"] == "pass" for row in expected_results) else "fail"
        harness_digest = runner.sha256_file(RUNNER_PATH)
        record = {
            "schemaVersion": runner.RESULT_SCHEMA_VERSION,
            "evaluationId": runner.EVALUATION_ID,
            "scope": self.cases["scope"],
            "assuranceBoundary": runner.ASSURANCE_BOUNDARY,
            "candidate": {
                "origin": self.pin["origin"],
                "head": self.pin["head"],
                "base": self.pin["base"],
            },
            "casesSha256": runner.sha256_file(self.cases_path),
            "harnessSha256": harness_digest,
            "startedAtUnixNs": started,
            "completedAtUnixNs": started + 1,
            "overallStatus": overall,
            "results": expected_results,
        }
        results_path = self.bundle / "results.json"
        calibration_path = self.bundle / "grader-calibration.json"
        manifest_path = self.bundle / "reproducibility-manifest.json"
        results_path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
        calibration = runner.calibrate_grader(
            record, self.pin, self.cases, expected_results, harness_digest
        )
        calibration_path.write_text(
            json.dumps(calibration, sort_keys=True) + "\n", encoding="utf-8"
        )
        recorded_output = self.bundle.resolve()
        manifest = {
            "schemaVersion": runner.BUNDLE_SCHEMA_VERSION,
            "evaluationId": runner.EVALUATION_ID,
            "candidate": record["candidate"],
            "command": [
                sys.executable, str(RUNNER_PATH),
                "--candidate", str(self.candidate.resolve()),
                "--cases", str(self.cases_path.resolve()),
                "--output-dir", str(recorded_output),
            ],
            "verificationCommand": [
                sys.executable, str(RUNNER_PATH),
                "--cases", str(self.cases_path.resolve()),
                "--bundle-dir", str(recorded_output),
            ],
            "runtime": {
                "python": runner.EXPECTED_PYTHON,
                "pythonExecutable": sys.executable,
                "implementation": "CPython",
                "cryptography": runner.EXPECTED_CRYPTOGRAPHY,
                "platform": "fixture-platform",
            },
            "executionBoundary": {
                "externalAssumptions": runner.EXECUTION_ASSUMPTIONS,
                "runnerObservations": {
                    "candidateGitStateCleanBeforeAndAfter": True,
                    "candidateOriginHeadAndBaseMatched": True,
                    "outputWritesRequestedUnder": str(recorded_output),
                },
                "runnerLimitations": runner.RUNNER_LIMITATIONS,
            },
            "oracleScope": runner.ORACLE_SCOPE,
            "digests": {
                "cases.json": runner.sha256_file(self.cases_path),
                "runner/eval_pr362.py": harness_digest,
                "results.json": runner.sha256_file(results_path),
                "grader-calibration.json": runner.sha256_file(calibration_path),
                **{
                    name: runner.sha256_file(self.candidate / relative)
                    for name, relative in runner.CANDIDATE_DIGEST_PATHS.items()
                },
            },
            "caseFreeze": {
                "casesMtimeUnixNs": self.cases_path.stat().st_mtime_ns,
                "runStartedAtUnixNs": started,
                "frozenBeforeRun": True,
            },
            "statusVocabulary": self.cases["statusVocabulary"],
            "limitations": runner.MANIFEST_LIMITATIONS,
        }
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
        return record, calibration, manifest, expected_results

    def verify(self, expected_results, *, unchanged_error=None):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(runner, "verify_candidate_pin", return_value=self.pin))
            if unchanged_error:
                stack.enter_context(mock.patch.object(
                    runner, "verify_candidate_unchanged", side_effect=RuntimeError(unchanged_error)
                ))
            else:
                stack.enter_context(mock.patch.object(
                    runner, "verify_candidate_unchanged", return_value=self.pin
                ))
            stack.enter_context(mock.patch.object(runner, "validate_frozen_cases"))
            stack.enter_context(mock.patch.object(runner, "load_candidate_modules", return_value=(None, None)))
            stack.enter_context(mock.patch.object(
                runner, "run_cases", return_value=copy.deepcopy(expected_results)
            ))
            return runner.verify_bundle(self.bundle)

    def rewrite_manifest_digest(self, manifest, name):
        manifest["digests"][name] = runner.sha256_file(self.bundle / name)
        (self.bundle / "reproducibility-manifest.json").write_text(
            json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
        )

    def test_known_good_bundle_passes_all_criteria(self):
        _, _, _, expected = self.write_bundle()
        verdict = self.verify(expected)
        self.assertEqual(verdict["runValidity"]["status"], "valid")
        self.assertEqual(verdict["candidateDisposition"], "pass")
        self.assertEqual(verdict["artifactScore"], 1.0)

    def test_relocated_bundle_is_an_alternative_valid_location(self):
        _, _, _, expected = self.write_bundle()
        relocated = self.root / "relocated bundle"
        self.bundle.rename(relocated)
        self.bundle = relocated
        verdict = self.verify(expected)
        self.assertEqual(verdict["runValidity"]["status"], "valid")

    def test_honestly_reported_candidate_failure_is_valid_evidence(self):
        failing = copy.deepcopy(self.results)
        failing[0]["status"] = "fail"
        _, _, _, expected = self.write_bundle(failing)
        verdict = self.verify(expected)
        self.assertEqual(verdict["runValidity"]["status"], "valid")
        self.assertEqual(verdict["candidateDisposition"], "fail")
        self.assertEqual(verdict["artifactScore"], 0.0)

    def test_altered_pass_shortcut_is_rejected(self):
        failing = copy.deepcopy(self.results)
        failing[0]["status"] = "fail"
        record, _, manifest, expected = self.write_bundle(failing)
        record["overallStatus"] = "pass"
        (self.bundle / "results.json").write_text(
            json.dumps(record, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.rewrite_manifest_digest(manifest, "results.json")
        with self.assertRaisesRegex(RuntimeError, "overall status"):
            self.verify(expected)

    def test_altered_grader_control_is_rejected_even_with_updated_digest(self):
        _, calibration, manifest, expected = self.write_bundle()
        calibration["cases"][0]["actual"] = "accepted"
        (self.bundle / "grader-calibration.json").write_text(
            json.dumps(calibration, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.rewrite_manifest_digest(manifest, "grader-calibration.json")
        with self.assertRaisesRegex(RuntimeError, "grader calibration"):
            self.verify(expected)

    def test_missing_and_corrupt_evidence_are_infrastructure_errors(self):
        _, _, _, expected = self.write_bundle()
        (self.bundle / "grader-calibration.json").unlink()
        with self.assertRaisesRegex(RuntimeError, "bundle inventory"):
            self.verify(expected)
        self.bundle.mkdir(exist_ok=True)
        (self.bundle / "grader-calibration.json").write_text("{broken", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "invalid JSON evidence"):
            self.verify(expected)

    def test_false_sandbox_claim_and_candidate_mutation_are_rejected(self):
        _, _, manifest, expected = self.write_bundle()
        manifest["executionBoundary"]["runnerLimitations"] = []
        (self.bundle / "reproducibility-manifest.json").write_text(
            json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(RuntimeError, "sandbox limitations"):
            self.verify(expected)

        _, _, _, expected = self.write_bundle()
        with self.assertRaisesRegex(RuntimeError, "candidate changed"):
            self.verify(expected, unchanged_error="candidate changed")


if __name__ == "__main__":
    unittest.main()
