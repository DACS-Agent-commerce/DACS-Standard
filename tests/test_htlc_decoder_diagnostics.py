"""Controlled decoder diagnostics using injected errors, not deep input."""
import contextlib
import errno
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


class HTLCDecoderDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "htlc_decoder_diagnostic_verifier",
            ROOT / "scripts/verify_htlc9_st8_pack.py",
        )
        cls.verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.verifier)

    def test_decoder_recursion_uses_controlled_file_and_cli_diagnostics(self):
        ver = self.verifier
        with mock.patch.object(
            ver, "load_raw_json", side_effect=RecursionError("decoder recursion limit")
        ):
            for path in (ver.DEFAULT_INTERIM, ver.DEFAULT_RESOLVED):
                with self.subTest(path=path.name):
                    evidence, errors = ver.load_case(path)
                    self.assertIsNone(evidence)
                    self.assertEqual(len(errors), 1)
                    self.assertIn(path.name, errors[0])
                    self.assertIn("invalid JSON: decoder recursion limit", errors[0])
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(ver.main([]), 1)
            self.assertIn("invalid JSON: decoder recursion limit", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_shared_json_admission_keeps_decoder_type_and_position(self):
        import json
        import tempfile
        from dacs_reference import loads_unique_json

        with self.assertRaises(json.JSONDecodeError) as caught:
            loads_unique_json('{\n  "kind": }')
        self.assertIn("invalid JSON: Expecting value", str(caught.exception))
        self.assertIn("line 2 column 11", str(caught.exception))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "malformed.json"
            path.write_text('{\n  "kind": }', encoding="utf-8")
            evidence, errors = self.verifier.load_case(path)
        self.assertIsNone(evidence)
        self.assertIn("line 2 column 11", errors[0])
        with tempfile.TemporaryDirectory() as tmp:
            # A host decoder limit is still an "invalid JSON" admission failure.
            path = Path(tmp) / "huge-integer.json"
            path.write_text('{"kind": ' + "9" * 5_000 + "}", encoding="utf-8")
            evidence, errors = self.verifier.load_case(path)
        self.assertIsNone(evidence)
        self.assertIn(": invalid JSON: ", errors[0])

    def test_path_resolution_fallback_diagnostics_never_raise(self):
        # The fail-closed branch probes files for diagnostics only; an
        # unreadable path is reported, never raised to a library caller.
        ver = self.verifier
        for error in (
            PermissionError(errno.EACCES, "Permission denied"),
            OSError(errno.ELOOP, "Too many levels"),
        ):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(Path, "resolve", side_effect=RuntimeError("loop")), \
                        mock.patch.object(Path, "stat", side_effect=error), \
                        mock.patch.object(ver, "validate_interim") as validate_interim, \
                        mock.patch.object(ver, "validate_resolved") as validate_resolved:
                    errors = ver.validate_pair(
                        ver.DEFAULT_INTERIM, ver.DEFAULT_RESOLVED
                    )
                self.assertIn("pair paths could not be resolved", errors[0])
                self.assertTrue(
                    any("fixture file could not be read: " + error.strerror in e for e in errors),
                    errors,
                )
                validate_interim.assert_not_called()
                validate_resolved.assert_not_called()

    def test_path_inspection_runtime_error_rejects_before_artifact_evaluation(self):
        ver = self.verifier
        with mock.patch.object(Path, "stat", side_effect=RuntimeError("loop")), \
                mock.patch.object(ver, "validate_interim") as validate_interim, \
                mock.patch.object(ver, "validate_resolved") as validate_resolved:
            errors = ver.validate_pair(ver.DEFAULT_INTERIM, ver.DEFAULT_RESOLVED)
        self.assertIn("pair paths could not be resolved: loop", errors[0])
        self.assertTrue(
            any("fixture file could not be inspected: loop" in error for error in errors),
            errors,
        )
        for path in (ver.DEFAULT_INTERIM, ver.DEFAULT_RESOLVED):
            self.assertTrue(
                any(
                    path.name + ": fixture file could not be inspected: loop" in error
                    for error in errors
                ),
                errors,
            )
        validate_interim.assert_not_called()
        validate_resolved.assert_not_called()

    def test_missing_custom_file_retains_primary_diagnostic(self):
        import tempfile

        ver = self.verifier
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.json"
            errors = ver.validate_pair(missing, ver.DEFAULT_RESOLVED)
        self.assertTrue(
            any(
                str(missing) in error and "fixture file not found" in error
                for error in errors
            ),
            errors,
        )
        # Missing is an ordinary per-file rejection, not a path-resolution fault.
        self.assertEqual(ver.fail(missing, "fixture file not found"), errors[0])
        self.assertFalse(any("could not be resolved" in error for error in errors), errors)

    def test_path_resolution_errors_reject_pair_and_cli_without_receipt_downgrade(self):
        ver = self.verifier
        for error_type in (OSError, RuntimeError):
            with self.subTest(error=error_type.__name__):
                with mock.patch.object(Path, "resolve", side_effect=error_type("resolution unavailable")):
                    with mock.patch.object(ver, "validate_interim") as validate_interim, \
                            mock.patch.object(ver, "validate_resolved") as validate_resolved:
                        errors = ver.validate_pair(ver.DEFAULT_INTERIM, ver.DEFAULT_RESOLVED)
                        self.assertTrue(errors)
                        self.assertIn("pair paths could not be resolved", errors[0])
                        validate_interim.assert_not_called()
                        stderr = io.StringIO()
                        with contextlib.redirect_stderr(stderr):
                            self.assertEqual(ver.main([]), 1)
                        self.assertIn("pair paths could not be resolved", stderr.getvalue())
                        self.assertNotIn("Traceback", stderr.getvalue())
                        validate_interim.assert_not_called()
                        validate_resolved.assert_not_called()

    def test_committed_pair_retains_success(self):
        ver = self.verifier
        self.assertEqual(ver.validate_pair(ver.DEFAULT_INTERIM, ver.DEFAULT_RESOLVED), [])
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(ver.main([]), 0)
        self.assertIn("both signatures verified", stdout.getvalue())

    def test_exclusive_settlement_selector_keeps_unknown_members_inert(self):
        ver = self.verifier
        self.assertIsNone(ver.settlement_evidence_selector_error({
            "evidenceVersion": "1",
            "futureOptional": {"version": 2},
        }))
        invalid = (
            {},
            {"evidenceVersion": "2"},
            {"deliveryEvidenceVersion": "1"},
            {"legacyTransitionEvidenceVersion": "1"},
            {"finalityBoundEvidenceVersion": "1"},
            {"evidenceVersion": "1", "deliveryEvidenceVersion": "1"},
            {"evidenceVersion": "1", "legacyTransitionEvidenceVersion": "1"},
            {"evidenceVersion": "1", "finalityBoundEvidenceVersion": "1"},
        )
        for evidence in invalid:
            with self.subTest(evidence=evidence):
                error = ver.settlement_evidence_selector_error(evidence)
                self.assertIsInstance(error, str)
                self.assertIn("exclusively evidenceVersion '1'", error)

    def test_selector_admission_precedes_signature_and_type_interpretation(self):
        ver = self.verifier
        shapes = (
            {"deliveryEvidenceVersion": "1"},
            {"evidenceVersion": "1", "deliveryEvidenceVersion": "1"},
            {"evidenceVersion": "1", "legacyTransitionEvidenceVersion": "1"},
            {"evidenceVersion": "1", "finalityBoundEvidenceVersion": "1"},
        )
        with tempfile.TemporaryDirectory() as tmp:
            for index, evidence in enumerate(shapes):
                with self.subTest(evidence=evidence):
                    # Safe shape-only guard assertion: no signature is created
                    # and no hybrid record is re-signed or executed.
                    path = Path(tmp) / f"selector-{index}.json"
                    path.write_text(json.dumps({
                        "kind": "SettlementEvidenceCase",
                        "settlementEvidence": evidence,
                    }), encoding="utf-8")
                    with mock.patch.object(
                        ver,
                        "verify_signature",
                        side_effect=AssertionError("signature interpretation reached"),
                    ) as signature:
                        admitted, errors = ver.load_case(path)
                    self.assertIsNone(admitted)
                    self.assertTrue(any(
                        "exclusively evidenceVersion '1'" in error
                        for error in errors
                    ), errors)
                    signature.assert_not_called()
