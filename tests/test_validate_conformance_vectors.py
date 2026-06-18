import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_conformance_vectors.py"
VECTORS = ROOT / "conformance" / "vectors" / "dacs-v0.1-happy-path.json"
IDENTITY_EXAMPLE = ROOT / "conformance" / "vectors" / "examples" / "identity-bundle.json"
RATING_EXAMPLE = ROOT / "conformance" / "vectors" / "examples" / "rating-record.json"
BUNDLE_EXAMPLE = ROOT / "conformance" / "vectors" / "examples" / "attestation-bundle.json"
NEGATIVE_VECTOR = ROOT / "conformance" / "vectors" / "dacs-v0.1-negative-paths.json"
INDEX = ROOT / "conformance" / "vectors" / "README.md"


def run_validator(*extra_args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(SCRIPT), *extra_args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def load_vector_validator():
    import importlib.util

    spec = importlib.util.spec_from_file_location("validate_conformance_vectors", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ConformanceVectorValidationTests(unittest.TestCase):
    def test_happy_path_vector_file_exists_and_is_json_object(self):
        self.assertTrue(VECTORS.exists(), "expected canonical v0.1 happy-path conformance vector")
        data = json.loads(VECTORS.read_text())
        self.assertEqual(data["dacsVersion"], "0.1")
        self.assertEqual(data["vectorId"], "dacs-v0.1-happy-path")

    def test_validator_accepts_repository_vectors(self):
        result = run_validator()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("validated 2 vectors", result.stdout)

    def test_vector_covers_all_five_dacs_stages_in_order(self):
        data = json.loads(VECTORS.read_text())
        stages = [artifact["stage"] for artifact in data["artifacts"]]
        self.assertEqual(stages, ["DACS-1", "DACS-2", "DACS-3", "DACS-4", "DACS-5"])

    def test_artifacts_have_stable_content_hashes_spec_refs_and_registered_domains(self):
        data = json.loads(VECTORS.read_text())
        validator = load_vector_validator()
        registry = validator.load_registered_domain_separators(ROOT)
        for artifact in data["artifacts"]:
            with self.subTest(artifact=artifact["id"]):
                self.assertTrue(artifact["contentHash"].startswith("sha256:"))
                self.assertEqual(len(artifact["contentHash"].removeprefix("sha256:")), 64)
                self.assertTrue(artifact["specRefs"])
                self.assertTrue(all(ref.startswith("§") for ref in artifact["specRefs"]))
                self.assertIn(artifact["domainSeparator"], registry)

    def test_vector_readme_documents_how_to_run_validation(self):
        text = INDEX.read_text()
        self.assertIn("python3 scripts/validate_conformance_vectors.py", text)
        self.assertIn("dacs-v0.1-happy-path.json", text)
        self.assertIn("excluded from the canonical", text)
        self.assertIn("conformance/fixtures/", text)

    def test_remaining_core_artifact_examples_are_machine_readable(self):
        for path, expected_kind in [
            (IDENTITY_EXAMPLE, "IdentityBundle"),
            (RATING_EXAMPLE, "RatingRecord"),
            (BUNDLE_EXAMPLE, "AttestationBundle"),
        ]:
            with self.subTest(path=path):
                self.assertTrue(path.exists(), f"missing {path.relative_to(ROOT)}")
                data = json.loads(path.read_text())
                self.assertEqual(data["kind"], expected_kind)
                self.assertTrue(data["specRefs"])
                self.assertTrue(all(ref.startswith("§") for ref in data["specRefs"]))
                self.assertIn("artifact", data)

    def test_negative_path_vector_is_valid_and_expected_to_fail(self):
        self.assertTrue(NEGATIVE_VECTOR.exists(), "expected negative-path conformance vector")
        data = json.loads(NEGATIVE_VECTOR.read_text())
        self.assertEqual(data["vectorId"], "dacs-v0.1-negative-paths")
        self.assertIs(data["expectedResult"]["verifies"], False)
        self.assertTrue(data["expectedResult"].get("expectedFailures"))

    def _write_pr117_tree(self, base: Path) -> Path:
        conformance = base / "conformance"
        (conformance / "fixtures").mkdir(parents=True)
        (conformance / "vectors").mkdir()
        for fixture in ["bundle.json", "divergent-seller.json", "htlc9.json", "settlement.json", "delivery.json"]:
            (conformance / "fixtures" / fixture).write_text("{}\n", encoding="utf-8")
        (conformance / "MANIFEST.json").write_text(
            json.dumps(
                {
                    "dacsVersion": "0.1",
                    "generator": "github.com/mj-deving/dacs-verify",
                    "note": "Proposed / non-normative test vectors.",
                    "surfaces": {},
                    "cases": [
                        {
                            "id": "canon-key-order",
                            "area": "canonicalize",
                            "spec": "§7.1",
                            "summary": "Canonical key ordering is stable.",
                            "status": "golden",
                            "reason": "Pinned golden behavior.",
                            "want": {"ok": True},
                        },
                        {
                            "id": "candidate-address",
                            "area": "addressing",
                            "spec": "§8.2",
                            "summary": "Candidate address vector.",
                            "status": "candidate",
                            "want": {"ok": True},
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        (conformance / "vectors" / "golden.json").write_text(
            json.dumps(
                {
                    "bundle": {
                        "fixture": "conformance/fixtures/bundle.json",
                        "divergentSellerFixture": "conformance/fixtures/divergent-seller.json",
                        "htlc9Fixture": "conformance/fixtures/htlc9.json",
                        "decisions": {"valid": "pass", "badSeller": "fail"},
                    },
                    "settlement": {
                        "fixture": "conformance/fixtures/settlement.json",
                        "deliveryFixture": "conformance/fixtures/delivery.json",
                        "decisions": {"timeout": "indeterminate"},
                    },
                    "dispute": {"decisions": {"opened": "pass"}},
                    "disclosure": {"decisions": {"masked": "error"}},
                }
            ),
            encoding="utf-8",
        )
        return conformance / "MANIFEST.json"

    def test_validator_accepts_pr117_manifest_and_golden_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = self._write_pr117_tree(Path(tmp))
            result = run_validator("--manifest", str(manifest))
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("validated manifest", result.stdout)

    def test_validator_rejects_pr117_manifest_with_missing_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = self._write_pr117_tree(Path(tmp))
            (manifest.parent / "fixtures" / "bundle.json").unlink()
            result = run_validator("--manifest", str(manifest))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("missing fixture", result.stderr)
        self.assertIn("conformance/fixtures/bundle.json", result.stderr)

    def test_validator_rejects_absolute_fixture_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = self._write_pr117_tree(Path(tmp))
            golden = manifest.parent / "vectors" / "golden.json"
            data = json.loads(golden.read_text())
            data["bundle"]["fixture"] = "/etc/passwd"
            golden.write_text(json.dumps(data), encoding="utf-8")
            result = run_validator("--manifest", str(manifest))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("missing fixture: /etc/passwd", result.stderr)

    def test_explicit_manifest_does_not_validate_repository_default_vectors(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = self._write_pr117_tree(Path(tmp))
            result = run_validator("--manifest", str(manifest))
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("validated manifest", result.stdout)
        self.assertNotIn("validated 2 vectors", result.stdout)


if __name__ == "__main__":
    unittest.main()
