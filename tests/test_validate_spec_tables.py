import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_spec_tables.py"
ROOT = Path(__file__).resolve().parents[1]


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_spec_tables", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SpecTableValidationTests(unittest.TestCase):
    def test_repository_selected_registry_tables_are_well_formed(self):
        validator = load_validator()
        self.assertEqual(validator.validate_repo(ROOT), [])

    def test_reports_duplicate_domain_separator_registry_entries(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = root / "spec"
            spec.mkdir()
            (spec / "CORE.md").write_text(
                "The v0.x registry of domain separators at this revision is closed:\n"
                "| Artifact | Domain separator | Defined in |\n"
                "| --- | --- | --- |\n"
                "| One | \"dacs-one:v1:\" | §1 |\n"
                "| Duplicate | \"dacs-one:v1:\" | §2 |\n\n"
                "**Payload shape — single-hash vs composite.**\n",
                encoding="utf-8",
            )
            validator = load_validator()
            errors = validator.validate_repo(root)
            self.assertEqual(errors, ["spec/CORE.md: duplicate §7.7 domain separator: dacs-one:v1:"])

    def test_reports_malformed_registry_row(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = root / "spec"
            spec.mkdir()
            (spec / "CORE.md").write_text(
                "The v0.x registry of domain separators at this revision is closed:\n"
                "| Artifact | Domain separator | Defined in |\n"
                "| --- | --- | --- |\n"
                "| Bad | missing quote | §1 |\n\n"
                "**Payload shape — single-hash vs composite.**\n",
                encoding="utf-8",
            )
            validator = load_validator()
            errors = validator.validate_repo(root)
            self.assertEqual(errors, ["spec/CORE.md: §7.7 row has invalid domain separator cell: missing quote"])


if __name__ == "__main__":
    unittest.main()
