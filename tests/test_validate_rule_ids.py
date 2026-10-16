import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_rule_ids.py"
ROOT = Path(__file__).resolve().parents[1]


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_rule_ids", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RuleIdValidationTests(unittest.TestCase):
    def test_repository_rule_ids_resolve_and_index_covers_defined_families(self):
        validator = load_validator()
        self.assertEqual(validator.validate_repo(ROOT), [])

    def test_reports_reference_to_undefined_rule_in_defined_family(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = root / "spec"
            docs = root / "docs"
            spec.mkdir()
            docs.mkdir()
            (spec / "SPECIFICATION.md").write_text(
                "# Spec\n\n"
                "Conformance: (ABC-1) Producers MUST do the thing.\n\n"
                "The §14 plan references ABC-2, which does not exist.\n",
                encoding="utf-8",
            )
            (docs / "rule-id-index.md").write_text(
                "# Rule-ID index\n\n"
                "| Rule family | Role / surface | Spec section | Test-plan hook |\n"
                "|-------------|----------------|--------------|----------------|\n"
                "| ABC-* | Example rules | §1 | §14 |\n",
                encoding="utf-8",
            )
            validator = load_validator()
            errors = validator.validate_repo(root)
            self.assertEqual(errors, ["spec/SPECIFICATION.md: referenced rule ABC-2 is not defined"])

    def test_reports_missing_rule_family_index_entry(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = root / "spec"
            docs = root / "docs"
            spec.mkdir()
            docs.mkdir()
            (spec / "SPECIFICATION.md").write_text("Conformance: (XYZ-1) Readers MUST reject bad input.\n", encoding="utf-8")
            (docs / "rule-id-index.md").write_text(
                "# Rule-ID index\n\n"
                "| Rule family | Role / surface | Spec section | Test-plan hook |\n"
                "|-------------|----------------|--------------|----------------|\n",
                encoding="utf-8",
            )
            validator = load_validator()
            errors = validator.validate_repo(root)
            self.assertEqual(errors, ["docs/rule-id-index.md: missing rule family entry: XYZ-*"])

    def test_capabilities_use_table_definitions_without_a_rule_family_index_entry(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "spec").mkdir()
            (root / "spec" / "CORE.md").write_text(
                "# Core\n\n"
                "| ID | Capability | Description | Used by |\n"
                "| --- | --- | --- | --- |\n"
                "| SR-1 | Identity | Optional aggregation | DACS-1 |\n"
                "| SR-2 | Storage | Anchored storage | DACS-1 |\n",
                encoding="utf-8",
            )
            module = root / "spec" / "DACS-1-IDENTIFY.md"
            module.write_text("Uses SR-1 and SR-2; composes EIP-4361 and ERC-8004.\n", encoding="utf-8")
            validator = load_validator()
            self.assertEqual(validator.validate_repo(root), [])
            # A parenthesized reference must not become a capability definition.
            module.write_text("Uses SR-99 (SR-99), which is absent from CORE's table.\n", encoding="utf-8")
            self.assertEqual(validator.validate_repo(root), [
                "spec/SPECIFICATION.md: referenced substrate capability SR-99 is not defined"
            ])

    def test_missing_capability_table_does_not_silently_accept_a_reference(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "spec").mkdir()
            (root / "spec" / "SPECIFICATION.md").write_text("Requires SR-2.\n", encoding="utf-8")
            self.assertEqual(load_validator().validate_repo(root), [
                "spec/SPECIFICATION.md: referenced substrate capability SR-2 is not defined"
            ])

    def test_sr2_rules_still_require_definitions_and_index_entries(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "spec").mkdir()
            (root / "spec" / "SPECIFICATION.md").write_text(
                "(SR2-1) Readers MUST check receipts. See SR2-99.\n", encoding="utf-8"
            )
            self.assertEqual(load_validator().validate_repo(root), [
                "spec/SPECIFICATION.md: referenced rule SR2-99 is not defined",
                "docs/rule-id-index.md: missing rule family entry: SR2-*",
            ])


if __name__ == "__main__":
    unittest.main()
