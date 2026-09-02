import base64
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_conformance_vectors.py"
MANIFEST = ROOT / "conformance" / "MANIFEST.json"
GOLDEN_OUTPUTS = ROOT / "conformance" / "vectors" / "golden.json"
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

    def test_registry_golden_pins_exact_spec_membership(self):
        data = json.loads(MANIFEST.read_text())
        registry_case = next(case for case in data["cases"] if case["id"] == "sig-registry-closed")
        validator = load_vector_validator()
        separators = sorted(validator.load_registered_domain_separators(ROOT))
        self.assertEqual(registry_case["spec"], "§B.7")
        self.assertEqual(
            registry_case["want"],
            {
                "count": len(separators),
                "separators": separators,
            },
        )

    def test_registry_golden_rejects_same_count_substitution(self):
        data = json.loads(MANIFEST.read_text())
        registry_case = next(case for case in data["cases"] if case["id"] == "sig-registry-closed")
        registry_case["want"]["separators"][0] = "dacs-substitute:v1:"
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "MANIFEST.json"
            manifest.write_text(json.dumps(data), encoding="utf-8")
            result = run_validator("--manifest", str(manifest))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("want.separators MUST equal the sorted closed §B.7 registry", result.stderr)

    def test_registry_golden_rejects_stale_spec_reference(self):
        data = json.loads(MANIFEST.read_text())
        registry_case = next(case for case in data["cases"] if case["id"] == "sig-registry-closed")
        registry_case["spec"] = "§7.7"
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "MANIFEST.json"
            manifest.write_text(json.dumps(data), encoding="utf-8")
            result = run_validator("--manifest", str(manifest))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("spec MUST identify the closed registry at §B.7", result.stderr)

    def test_output_only_dacsx_rows_are_candidates_not_goldens(self):
        data = json.loads(MANIFEST.read_text())
        outputs = json.loads(GOLDEN_OUTPUTS.read_text())
        dacsx = [
            case for case in data["cases"]
            if case["area"] in {"dispute", "disclosure"}
        ]
        self.assertEqual(17, len(dacsx))
        self.assertEqual(
            {"dispute": 8, "disclosure": 9},
            {
                area: sum(case["area"] == area for case in dacsx)
                for area in ("dispute", "disclosure")
            },
        )
        for case in dacsx:
            with self.subTest(case=case["id"]):
                self.assertEqual("candidate", case["status"])
                self.assertIn("output-only expectation", case["reason"])
                self.assertIn("not published", case["reason"])
        self.assertEqual(177, sum(
            case["status"] == "golden" for case in data["cases"]
        ))
        self.assertEqual(59, sum(
            case["status"] == "candidate" for case in data["cases"]
        ))
        for area in ("dispute", "disclosure"):
            with self.subTest(output_area=area):
                self.assertIn("candidate", outputs[area]["status"])
                self.assertIn("output-only expectations", outputs[area]["status"])
                self.assertNotIn("golden", outputs[area]["status"])
                self.assertIn("constructed deterministically", outputs[area]["inputs"])
                self.assertIn("exact signed input/resolver pack is not published", outputs[area]["inputs"])

    def test_vector_covers_all_five_dacs_stages_in_order(self):
        data = json.loads(VECTORS.read_text())
        stages = [artifact["stage"] for artifact in data["artifacts"]]
        self.assertEqual(stages, ["DACS-1", "DACS-2", "DACS-3", "DACS-4", "DACS-5"])

    def test_happy_path_pay_phases_bind_to_accepted_rails(self):
        data = json.loads(VECTORS.read_text())
        listing = next(artifact["artifact"] for artifact in data["artifacts"] if artifact["kind"] == "Listing")
        accepted_rails = {rail["railId"] for rail in listing["acceptedRails"]}
        pay_phases = [phase for phase in listing["pipeline"] if phase["kind"].startswith("pay-")]
        self.assertTrue(pay_phases)
        for phase in pay_phases:
            with self.subTest(kind=phase["kind"]):
                self.assertIn(phase.get("parameters", {}).get("rail"), accepted_rails)

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


class B2ConformanceHashTests(unittest.TestCase):
    """§B.2 content-hash correction + executed signature verification (#278)."""

    HAPPY = "dacs-v0.1-happy-path.json"
    NEG = "dacs-v0.1-negative-paths.json"
    # Synthetic basename in validate_conformance_vectors.LEGACY_SIG_SPELLING_FILES. No such
    # file is committed; it is the allowlisted name the dual-gate specimen is written under,
    # so the legacy padded-Base64 gate stays exercised now the lifecycle files are SIG-6.
    SYNTHETIC_LEGACY_NAME = "legacy-padded-spelling-fixture.json"

    def _respell_to_padded_base64(self, data):
        """Re-spell every canonical SIG-6 signature value in-place to padded standard
        Base64 (byte-preserving) and declare the legacy spelling — turning the migrated
        SIG-6 HAPPY structure into a self-contained legacy padded-Base64 specimen."""
        data["signatureValueSpelling"] = "legacy-padded-base64"

        def walk(node):
            if isinstance(node, dict):
                if isinstance(node.get("algorithm"), str) and isinstance(node.get("value"), str):
                    value = node["value"]
                    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
                    node["value"] = base64.b64encode(raw).decode("ascii")
                for child in node.values():
                    walk(child)
            elif isinstance(node, list):
                for child in node:
                    walk(child)

        walk(data["artifacts"])

    def _temp_vector(self, source_name, mutate=None, dest_name=None):
        data = json.loads((ROOT / "conformance" / "vectors" / source_name).read_text())
        if mutate is not None:
            mutate(data)
        tmpdir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        dest = tmpdir / (dest_name or source_name)
        dest.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return dest

    def test_artifact_hash_path_invokes_jcs_canonicalize(self):
        # Kills an import-swap back to json.dumps: the hash path MUST go through jcs.
        module = load_vector_validator()
        sentinel = RuntimeError("jcs.canonicalize sentinel")
        original = module.jcs.canonicalize

        def boom(_value):
            raise sentinel

        module.jcs.canonicalize = boom
        try:
            with self.assertRaises(RuntimeError) as ctx:
                module.artifact_hash_hex("Listing", {"payload": 1, "signature": {}})
            self.assertIs(ctx.exception, sentinel)
        finally:
            module.jcs.canonicalize = original

    def test_hash_exclusion_matches_walkthrough_signing_scope(self):
        import importlib.util

        module = load_vector_validator()
        wpath = ROOT / "scripts" / "run_lifecycle_walkthrough.py"
        wspec = importlib.util.spec_from_file_location("run_lifecycle_walkthrough", wpath)
        walk = importlib.util.module_from_spec(wspec)
        wspec.loader.exec_module(walk)
        for kind, excluded in module.HASH_EXCLUDED.items():
            with self.subTest(kind=kind):
                artifact = {"payload": 1}
                for field in excluded:
                    artifact[field] = "buyer" if field == "anchoredByRole" else [{"value": "x"}]
                scoped = walk.signing_scope(kind, dict(artifact))
                self.assertEqual(set(artifact) - set(scoped), excluded)

    def test_pinned_repository_vectors_pass_on_temp_copy(self):
        dest = self._temp_vector(self.HAPPY)
        result = run_validator(str(dest))
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_signature_byte_tamper_detected(self):
        def mutate(data):
            sig = data["artifacts"][0]["artifact"]["signature"]
            first = "A" if sig["value"][0] != "A" else "B"
            sig["value"] = first + sig["value"][1:]

        result = run_validator(str(self._temp_vector(self.HAPPY, mutate)))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("signatureChecks mismatch", result.stderr)

    def test_signer_swap_detected(self):
        buyer = "cci:db995fe25169d141cab9bbba92baa01f9f2e1ece7df4cb2ac05190f37fcc1f9d"

        def mutate(data):
            data["artifacts"][0]["artifact"]["signature"]["signer"] = buyer

        result = run_validator(str(self._temp_vector(self.HAPPY, mutate)))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("signatureChecks mismatch", result.stderr)

    def test_missing_signature_checks_errors(self):
        def mutate(data):
            del data["artifacts"][0]["signatureChecks"]

        result = run_validator(str(self._temp_vector(self.HAPPY, mutate)))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("signatureChecks MUST be a non-empty array", result.stderr)

    def test_unknown_kind_errors(self):
        def mutate(data):
            data["artifacts"][0]["kind"] = "Bogus"

        result = run_validator(str(self._temp_vector(self.HAPPY, mutate)))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("unknown artifact kind", result.stderr)

    def test_legacy_base64_dual_gate(self):
        # Padded standard Base64 is accepted only when BOTH the basename is allowlisted
        # AND the file declares signatureValueSpelling. The lifecycle fixtures are now
        # canonical SIG-6, so this exercises the gate against a SELF-CONTAINED synthetic
        # specimen constructed at test time — the migrated HAPPY structure re-spelled to
        # padded standard Base64 under the allowlisted synthetic basename. No repository
        # fixture carries legacy spelling.
        # (1) allowlisted name + flag + padded values -> pass
        ok = run_validator(str(self._temp_vector(
            self.HAPPY, self._respell_to_padded_base64, dest_name=self.SYNTHETIC_LEGACY_NAME)))
        self.assertEqual(ok.returncode, 0, ok.stderr + ok.stdout)

        # (2) allowlisted name, flag stripped -> padded no longer permitted -> red
        def padded_without_flag(data):
            self._respell_to_padded_base64(data)
            data.pop("signatureValueSpelling", None)

        no_flag = run_validator(str(self._temp_vector(
            self.HAPPY, padded_without_flag, dest_name=self.SYNTHETIC_LEGACY_NAME)))
        self.assertNotEqual(no_flag.returncode, 0, no_flag.stdout)
        self.assertIn("signatureChecks mismatch", no_flag.stderr)

        # (3) non-allowlisted name + flag + padded values -> red
        renamed = run_validator(str(self._temp_vector(
            self.HAPPY, self._respell_to_padded_base64, dest_name="not-allowlisted.json")))
        self.assertNotEqual(renamed.returncode, 0, renamed.stdout)
        self.assertIn("signatureChecks mismatch", renamed.stderr)

    def test_verifies_true_with_fail_pin_is_incoherent(self):
        def mutate(data):
            data["expectedResult"]["verifies"] = True

        result = run_validator(str(self._temp_vector(self.NEG, mutate)))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("verifies is true but a signatureChecks pin expects 'fail'", result.stderr)

    def test_json_dumps_equals_jcs_on_signature_omitted_corpus(self):
        # Pins the "json.dumps -> JCS changes no byte on this corpus" claim: for
        # every signature-omitted artifact across both files, the two encodings
        # are byte-identical (all-ASCII, float-free).
        import sys as _sys

        _sys.path.insert(0, str(ROOT / "scripts"))
        module = load_vector_validator()
        checked = 0
        for name in [self.HAPPY, self.NEG]:
            data = json.loads((ROOT / "conformance" / "vectors" / name).read_text())
            for artifact in data["artifacts"]:
                scope = module.signing_scope(artifact["kind"], artifact["artifact"])
                jcs_bytes = module.jcs.canonicalize(scope).encode("utf-8")
                dumps_bytes = json.dumps(
                    scope, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                ).encode("utf-8")
                self.assertEqual(jcs_bytes, dumps_bytes, artifact["id"])
                checked += 1
        self.assertEqual(checked, 10)

    def test_domain_separator_must_match_kind(self):
        # C1: a declared domainSeparator that disagrees with the kind's §B.7
        # separator is rejected, even when the wrong value is itself registered.
        def mutate(data):
            data["artifacts"][0]["domainSeparator"] = "dacs-composite:v1:"

        result = run_validator(str(self._temp_vector(self.HAPPY, mutate)))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("does not match the Listing §B.7 separator", result.stderr)

    def test_non_ed25519_algorithm_recorded_as_fail(self):
        # C2: a non-ed25519 suite is unverifiable here -> observed 'fail' -> the
        # declared 'verify' pin mismatches. It must not crash or silently verify.
        def mutate(data):
            data["artifacts"][0]["artifact"]["signature"]["algorithm"] = "rsa"

        result = run_validator(str(self._temp_vector(self.HAPPY, mutate)))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("signatureChecks mismatch", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_malformed_pin_is_error_not_crash(self):
        # C3: a pin missing its required 'path' is a clean validation error, never
        # a TypeError from sorting a None sort-key.
        def mutate(data):
            data["artifacts"][0]["signatureChecks"][0].pop("path")

        result = run_validator(str(self._temp_vector(self.HAPPY, mutate)))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("path MUST be a non-empty string", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_unknown_pin_key_rejected(self):
        # C3: fail-closed — an unrecognised pin key must not pass unread.
        def mutate(data):
            data["artifacts"][0]["signatureChecks"][0]["note"] = "smuggled"

        result = run_validator(str(self._temp_vector(self.HAPPY, mutate)))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("unknown keys", result.stderr)


if __name__ == "__main__":
    unittest.main()
