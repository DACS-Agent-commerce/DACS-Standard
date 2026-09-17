"""Controls for the non-normative cross-run provenance proposal."""
from __future__ import annotations

import copy
import hashlib
import json
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import validate_cross_run_evidence as validator
from scripts.validate_cross_run_evidence import EvidenceError, main, validate_evidence


class CrossRunEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="dacs_provenance_")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self._git("init", "-q")
        self._git("config", "user.name", "DACS provenance fixture")
        self._git("config", "user.email", "fixture@example.invalid")
        self._git("remote", "add", "origin", "https://example.invalid/dacs-standard.git")
        corpus = self.repo / "conformance/vectors/security/fixture-set.json"
        corpus.parent.mkdir(parents=True)
        corpus.write_text(
            json.dumps(
                {
                    "set": "fixture-set",
                    "vectors": [{"name": "stable-name", "expected": "reject", "input": 1}],
                },
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        runner = self.repo / "runner.py"
        runner.write_text("print('fixture runner')\n", encoding="utf-8")
        self._git("add", ".")
        self._git("commit", "-qm", "fixture base")
        self.revision = self._git("rev-parse", "HEAD").strip()
        self.evidence = {
            "schema": "dacs-cross-run-evidence/1",
            "set": "fixture-set",
            "impl": "fixture@1",
            "corpus": self._artifact("conformance/vectors/security/fixture-set.json"),
            "implementation": {
                "id": "fixture@1",
                "repository": "https://example.invalid/dacs-standard",
                "revision": self.revision,
            },
            "runner": self._artifact("runner.py"),
            "results": [{"name": "stable-name", "verdict": "reject"}],
        }

    def _git(self, *args: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(self.repo), *args], text=True
        )

    def _artifact(self, path: str, revision: str | None = None) -> dict[str, str]:
        revision = revision or self.revision
        raw = subprocess.check_output(
            ["git", "-C", str(self.repo), "show", f"{revision}:{path}"]
        )
        blob = subprocess.check_output(
            ["git", "-C", str(self.repo), "hash-object", "--stdin"], input=raw
        ).decode().strip()
        return {
            "repository": "https://example.invalid/dacs-standard.git",
            "revision": revision,
            "path": path,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "gitBlob": blob,
        }

    def validate(self, evidence=None) -> None:
        validate_evidence(
            self.evidence if evidence is None else evidence,
            standard_checkout=self.repo,
            runner_checkout=self.repo,
            implementation_checkout=self.repo,
        )

    def test_valid_exact_git_bound_envelope(self):
        self.validate()

    def test_same_name_and_verdict_do_not_hide_changed_corpus_input(self):
        path = self.repo / "conformance/vectors/security/fixture-set.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["vectors"][0]["input"] = 2
        path.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
        self._git("add", ".")
        self._git("commit", "-qm", "change input without renaming case")
        with self.assertRaisesRegex(EvidenceError, "historical, not current evidence"):
            self.validate()

    def test_corpus_digest_mismatch_fails(self):
        evidence = copy.deepcopy(self.evidence)
        evidence["corpus"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(EvidenceError, "sha256 does not match"):
            self.validate(evidence)

    def test_missing_runner_revision_fails(self):
        evidence = copy.deepcopy(self.evidence)
        del evidence["runner"]["revision"]
        with self.assertRaisesRegex(EvidenceError, "runner.revision"):
            self.validate(evidence)

    def test_impl_label_must_match_structured_identity(self):
        evidence = copy.deepcopy(self.evidence)
        evidence["implementation"]["id"] = "different@1"
        with self.assertRaisesRegex(EvidenceError, "implementation.id"):
            self.validate(evidence)

    def test_runner_checkout_detects_wrong_source_digest(self):
        evidence = copy.deepcopy(self.evidence)
        evidence["runner"]["gitBlob"] = "f" * 40
        with self.assertRaisesRegex(EvidenceError, "gitBlob does not match"):
            self.validate(evidence)

    def test_cli_discloses_unverified_external_coordinates(self):
        evidence_path = self.repo / "evidence.json"
        evidence_path.write_text(json.dumps(self.evidence), encoding="utf-8")
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            result = main(
                ["--standard-checkout", str(self.repo), str(evidence_path)]
            )
        self.assertEqual(result, 0)
        self.assertIn("corpus Git binding verified", output.getvalue())
        self.assertIn("runner coordinates recorded but UNVERIFIED", output.getvalue())
        self.assertIn(
            "implementation coordinates recorded but UNVERIFIED", output.getvalue()
        )

    def test_git_replace_cannot_substitute_recorded_revision_bytes(self):
        original_revision = self.revision
        corpus = self.repo / "conformance/vectors/security/fixture-set.json"
        data = json.loads(corpus.read_text(encoding="utf-8"))
        data["vectors"][0]["input"] = 2
        corpus.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
        self._git("add", ".")
        self._git("commit", "-qm", "replacement corpus")
        replacement_revision = self._git("rev-parse", "HEAD").strip()
        evidence = copy.deepcopy(self.evidence)
        replacement_artifact = self._artifact(
            "conformance/vectors/security/fixture-set.json", replacement_revision
        )
        evidence["corpus"] = replacement_artifact
        evidence["corpus"]["revision"] = original_revision
        self._git("replace", original_revision, replacement_revision)
        with self.assertRaisesRegex(EvidenceError, "sha256 does not match"):
            self.validate(evidence)

    def test_runner_directory_is_not_an_artifact_file(self):
        evidence = copy.deepcopy(self.evidence)
        evidence["runner"]["path"] = "conformance"
        evidence["runner"]["gitBlob"] = self._git("rev-parse", "HEAD:conformance").strip()
        evidence["runner"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(EvidenceError, "committed regular file blob"):
            self.validate(evidence)

    def test_runner_symlink_is_not_an_artifact_file(self):
        link = self.repo / "runner-link.py"
        link.symlink_to("runner.py")
        self._git("add", "runner-link.py")
        self._git("commit", "-qm", "add runner symlink")
        revision = self._git("rev-parse", "HEAD").strip()
        evidence = copy.deepcopy(self.evidence)
        raw = b"runner.py"
        evidence["runner"].update(
            {
                "revision": revision,
                "path": "runner-link.py",
                "sha256": hashlib.sha256(raw).hexdigest(),
                "gitBlob": self._git("rev-parse", "HEAD:runner-link.py").strip(),
            }
        )
        with self.assertRaisesRegex(EvidenceError, "committed regular file blob"):
            self.validate(evidence)

    def test_duplicate_nested_key_is_rejected_before_git(self):
        evidence_path = self.repo / "duplicate.json"
        evidence_path.write_text(
            '{"schema":"dacs-cross-run-evidence/1","corpus":{"path":"a","path":"b"}}',
            encoding="utf-8",
        )
        errors = io.StringIO()
        with mock.patch.object(validator, "_git") as git_call, mock.patch(
            "sys.stderr", errors
        ):
            result = main([str(evidence_path)])
        self.assertEqual(result, 1)
        git_call.assert_not_called()
        self.assertIn("duplicate JSON object key 'path'", errors.getvalue())

    def test_non_finite_json_is_rejected_before_git(self):
        evidence_path = self.repo / "non-finite.json"
        evidence_path.write_text('{"schema":NaN}', encoding="utf-8")
        errors = io.StringIO()
        with mock.patch.object(validator, "_git") as git_call, mock.patch(
            "sys.stderr", errors
        ):
            result = main([str(evidence_path)])
        self.assertEqual(result, 1)
        git_call.assert_not_called()
        self.assertIn("non-finite JSON constant 'NaN'", errors.getvalue())

    def test_set_must_be_one_safe_filename_stem(self):
        evidence = copy.deepcopy(self.evidence)
        evidence["set"] = "../fixture-set"
        with self.assertRaisesRegex(EvidenceError, "single safe filename stem"):
            self.validate(evidence)


if __name__ == "__main__":
    unittest.main()
