import importlib.util
import re
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_rule_ids.py"
ROOT = Path(__file__).resolve().parents[1]
# A `next` commit whose CORE §5 table lists exactly SR-1 through SR-5.
CORE_PIN = "df7bc202ebdc179a59d61a8221072f33f482b933"


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
                "## 5. Substrate capabilities\n\n"
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

    def test_repository_capabilities_are_the_core_section_5_rows(self):
        validator = load_validator()
        # The live set may grow (a later SR-6 is not this test's concern); it must parse.
        live = validator.defined_capability_ids(validator.specsource.spec_text(ROOT))
        self.assertTrue(live)
        self.assertTrue(all(re.fullmatch(r"SR-\d+", capability) for capability in live), live)
        # The exact set is pinned to CORE at a fixed commit, so the parser is checked on real text.
        core = subprocess.run(["git", "-C", str(ROOT), "show", f"{CORE_PIN}:spec/CORE.md"],
                              capture_output=True, text=True)
        if core.returncode != 0:
            self.skipTest(f"CORE at {CORE_PIN} is unavailable (shallow clone?): {core.stderr.strip()}")
        self.assertEqual(validator.defined_capability_ids(core.stdout), {"SR-1", "SR-2", "SR-3", "SR-4", "SR-5"})

    def test_capability_rows_outside_the_core_section_5_table_define_nothing(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "spec").mkdir()
            (root / "spec" / "CORE.md").write_text(
                "# Core\n\n"
                "| SR-91 | Row before the section |\n\n"
                "## 5. Substrate capabilities\n\n"
                "```text\n"
                "| SR-92 | Fenced example |\n"
                "```\n\n"
                "| ID | Capability | Description | Used by |\n"
                "| --- | --- | --- | --- |\n"
                "| SR-1 | Identity | Optional aggregation | DACS-1 |\n\n"
                "| SR-93 | Later table in the section |\n\n"
                "### 5.1 Write lifecycle\n\n"
                "| SR-94 | Subsection row |\n",
                encoding="utf-8",
            )
            (root / "spec" / "DACS-4-SETTLE.md").write_text(
                "# Settle\n\n"
                "## 5. Substrate capabilities\n\n"
                "| SR-95 | Second section with the same heading |\n\n"
                "Uses SR-1, SR-91, SR-92, SR-93, SR-94 and SR-95.\n",
                encoding="utf-8",
            )
            self.assertEqual(load_validator().validate_repo(root), [
                f"spec/SPECIFICATION.md: referenced substrate capability SR-{n} is not defined"
                for n in range(91, 96)
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
