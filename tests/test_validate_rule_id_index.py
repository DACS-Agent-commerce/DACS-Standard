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


if __name__ == "__main__":
    unittest.main()
