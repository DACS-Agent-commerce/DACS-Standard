import importlib.util
import unittest
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_rule_id_index.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_rule_id_index", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RuleIdIndexPointerTests(unittest.TestCase):
    def test_repository_index_pointers_resolve(self):
        validator = load_validator()
        self.assertEqual(validator.main(), 0)

    def test_family_in_section_detects_membership(self):
        validator = load_validator()
        secmap = {"6.3.3": "... (MA-1) ...", "8.5.2": "unrelated text"}
        self.assertTrue(validator.family_in_section("MA", "6.3.3", secmap))
        self.assertFalse(validator.family_in_section("MA", "8.5.2", secmap))
        # subsection match
        secmap2 = {"7.4.1": "... (PSP-3) ..."}
        self.assertTrue(validator.family_in_section("PSP", "7.4", secmap2))

    def test_defining_section_outranks_a_reference_site(self):
        # The defining section carries the family's full rule set; a section
        # that only name-drops one rule (the D8 / PIPE-in-§9.5.1 failure mode)
        # must rank below it.
        validator = load_validator()
        secmap = {
            "9.9": "- (PIPE-1) ...\n- (PIPE-2) ...\n- (PIPE-3) ...",
            "9.5.1": "repeated pay-* phases (PIPE-5) do not collide",
        }
        ranked = validator.defining_sections("PIPE", secmap)
        self.assertEqual(ranked[0][1], "9.9")
        self.assertGreater(
            len(validator.covered_numbers("PIPE", "9.9", secmap)),
            len(validator.covered_numbers("PIPE", "9.5.1", secmap)),
        )

    def test_handles_table_and_range_definition_forms(self):
        validator = load_validator()
        # table-cell form: | (PA-1) Bootstrap |
        self.assertEqual(
            validator.distinct_rule_numbers("PA", "| (PA-1) x |\n| (PA-2) y |"),
            {"1", "2"},
        )
        # range form: (IT-1..IT-3)
        self.assertEqual(
            validator.distinct_rule_numbers("IT", "derivation (IT-1..IT-3)"),
            {"1", "3"},
        )
        # rule phrasing: (rule CF-1)
        self.assertEqual(validator.distinct_rule_numbers("CF", "(rule CF-1)"), {"1"})


if __name__ == "__main__":
    unittest.main()
