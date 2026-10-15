import importlib.util
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAP = ROOT / "docs" / "fp-dem-current-rules.md"
SCRIPT_PATH = ROOT / "scripts" / "validate_rule_id_index.py"


def load_index_validator():
    spec = importlib.util.spec_from_file_location("validate_rule_id_index", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def table_rows(text, heading):
    """Body rows of the first Markdown table under ``heading``, as lists of cells."""
    section = text.split(heading, 1)[1].split("\n## ", 1)[0]
    rows = []
    for line in section.splitlines():
        if not line.startswith("|") or set(line) <= set("|- "):
            continue
        rows.append([cell.strip() for cell in line.strip("|").split("|")])
    return rows[1:]


class FpDemCurrentRulesMapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = MAP.read_text(encoding="utf-8")
        cls.index = load_index_validator()
        cls.secmap = cls.index.section_text()

    def test_each_family_points_at_its_defining_section(self):
        rows = table_rows(self.text, "## Current rules")
        self.assertGreater(len(rows), 20)
        checked = 0
        for _stage, sections, families, _covers in rows:
            refs = [s.rstrip(".") for s in re.findall(r"§([\w.]+)", sections)]
            self.assertTrue(refs, f"row without a section: {sections!r}")
            for ref in refs:
                self.assertIn(ref, self.secmap, f"§{ref} is not a spec section")
            if families == "—":
                continue
            for family in re.findall(r"([A-Z][A-Z0-9-]*?)-?\*", families):
                with self.subTest(family=family, sections=sections):
                    cited = max(len(self.index.covered_numbers(family, ref, self.secmap)) for ref in refs)
                    ranked = self.index.defining_sections(family, self.secmap)
                    self.assertGreater(cited, 0)
                    self.assertGreaterEqual(cited, ranked[0][0])
                    checked += 1
        self.assertGreater(checked, 30)

    def test_gaps_name_issues_or_pull_requests_by_number(self):
        rows = table_rows(self.text, "## Known gaps")
        self.assertTrue(rows)
        for number, kind, _section, what in rows:
            with self.subTest(number=number):
                self.assertRegex(number, r"^#\d+(, #\d+)*$")
                self.assertRegex(kind, r"^(issue|PR|draft PR)(, (issue|PR|draft PR))*$")
                self.assertTrue(what)

    def test_readme_and_historical_readiness_page_link_the_map(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        readiness = (ROOT / "IMPLEMENTATION_READINESS.md").read_text(encoding="utf-8")
        self.assertIn("(./docs/fp-dem-current-rules.md)", readme)
        self.assertIn("**Historical.**", readiness.split("\n\n", 2)[1])
        self.assertIn("(./docs/fp-dem-current-rules.md)", readiness)
        self.assertIn("(../spec/PROFILE.md)", self.text)


if __name__ == "__main__":
    unittest.main()
