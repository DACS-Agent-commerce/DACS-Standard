"""Controlled decoder diagnostics using injected errors, not deep input."""
import contextlib
import importlib.util
import io
from pathlib import Path
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
            ver, "loads_unique_json", side_effect=RecursionError("decoder recursion limit")
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

    def test_committed_pair_retains_success(self):
        ver = self.verifier
        self.assertEqual(ver.validate_pair(ver.DEFAULT_INTERIM, ver.DEFAULT_RESOLVED), [])
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(ver.main([]), 0)
        self.assertIn("both signatures verified", stdout.getvalue())
