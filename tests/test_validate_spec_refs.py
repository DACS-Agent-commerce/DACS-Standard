import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_spec_refs.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_spec_refs", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SpecRefResolutionTests(unittest.TestCase):
    def test_repository_conformance_refs_resolve(self):
        with mock.patch.object(sys, "argv", ["validate_spec_refs.py"]):
            self.assertEqual(load_validator().main(), 0)

    def test_resolves_exact_and_ancestor_but_not_deeper(self):
        v = load_validator()
        headings = {"7.5", "10.4.3", "B.2"}
        self.assertTrue(v.resolves("7.5", headings))      # exact
        self.assertTrue(v.resolves("10.4", headings))     # ancestor of 10.4.3
        self.assertTrue(v.resolves("B", headings))        # ancestor of B.2
        self.assertFalse(v.resolves("10.4.3.1", headings))  # deeper than any heading
        self.assertFalse(v.resolves("9.99", headings))    # nonexistent

    def test_dot_segments_not_substring(self):
        # §1.2 must not "resolve" against a §1.23 heading by prefix-string match
        v = load_validator()
        self.assertFalse(v.resolves("1.2", {"1.23"}))


if __name__ == "__main__":
    unittest.main()
