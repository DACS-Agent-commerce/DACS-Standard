import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_domain_separators.py"
ROOT = Path(__file__).resolve().parents[1]


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_domain_separators", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DomainSeparatorValidationTests(unittest.TestCase):
    def test_repository_spec_domain_separators_are_registered(self):
        validator = load_validator()
        self.assertEqual(validator.validate_spec(), [])

    def test_reports_unregistered_quoted_domain_prefix(self):
        with TemporaryDirectory() as tmp:
            spec_path = Path(tmp) / "SPECIFICATION.md"
            spec_path.write_text(
                "The v0.x registry of domain separators at this revision is closed:\n"
                "| Artifact | Domain separator | Defined in |\n"
                "| --- | --- | --- |\n"
                "| Known | \"dacs-known:v1:\" | §1 |\n\n"
                "**Payload shape — single-hash vs composite.**\n\n"
                "Elsewhere: signed_bytes := \"dacs-unknown:v1:\" || artifact_hash\n",
                encoding="utf-8",
            )
            validator = load_validator()
            errors = validator.validate_spec(spec_path)
            self.assertEqual(errors, ["domain separator/prefix used but not registered in §7.7: dacs-unknown:v1:"])

    def test_ignores_logical_dacs_addresses(self):
        validator = load_validator()
        text = 'Address "dacs2:registry:v0.1" and prefix "dacs-good:v1:".'
        self.assertEqual(validator.extract_domains(text), {"dacs-good:v1:"})


if __name__ == "__main__":
    unittest.main()
