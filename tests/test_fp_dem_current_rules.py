import collections
import importlib.util
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAP = ROOT / "docs" / "fp-dem-current-rules.md"
PIN = "df7bc202ebdc179a59d61a8221072f33f482b933"
MODULES = ("CORE.md", "DACS-1-IDENTIFY.md", "DACS-2-VET.md", "DACS-3-NEGOTIATE.md",
           "DACS-4-SETTLE.md", "DACS-5-VERIFY.md", "CONFORMANCE-PLAN.md")
# Other rails, alternative payment, other negotiation patterns, metered pricing,
# private negotiation channels and attested-payload delivery are outside FP-DEM.
EXCLUDED = {"AP2", "APR", "DPA", "HTLC", "MTR", "RFQ", "SAC", "SE", "X402", "CH"}
RULE = r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)?-?\d+"


def rule_family(rule):
    return re.sub(r"\d+$", "", rule).rstrip("-")


def definition_sections(sources):
    """Locate definition labels, excluding incidental references and code comments."""
    result = collections.defaultdict(set)
    for name, text in sources.items():
        section = None
        for line in text.splitlines():
            heading = re.match(r"^#{2,6}\s+(?:Chapter\s+)?§?([A-C]?\.?\d[\w.]*)", line)
            if heading:
                section = heading[1].rstrip(".")
            labels = []
            label = re.match(rf"^\s*(?:-\s+|\d+[a-z]?\.\s+)?(?:\*\*)?\(({RULE})\)", line)
            if label:
                labels = [label[1]]
            if ("A conforming publisher MUST:" in line or "A conforming reader MUST:" in line
                    or (line.startswith("**Conformance") and "MUST:" in line)):
                labels = re.findall(rf"\(({RULE})\)", line)
            if name == "CORE.md":
                for prefix, rule in (
                    ("**Rule CF-4 ", "CF-4"),
                    ("- **Unicode normalisation (rule CF-1)", "CF-1"),
                    ("- **Raw JSON admission (rule CF-5)", "CF-5"),
                    ("- **Canonical decimal (rule CD-1)", "CD-1"),
                ):
                    if line.startswith(prefix):
                        labels = [rule]
            if line.startswith("**Phase disclosure."):
                labels = re.findall(r"\((GOV-\d+)\)", line)
            if line.startswith("**Reuse / caching."):
                labels = ["VP-C1"]
            if line.startswith("**Exact current delivery mapping (PDE-8)"):
                labels = ["PDE-8"]
            if name == "DACS-2-VET.md" and line.startswith("| ("):
                labels = re.findall(rf"\(({RULE})\)", line)[:1]
            for rule in labels:
                if rule_family(rule) not in EXCLUDED:
                    result[rule].add(section)
    return dict(result)


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
        cls.sources = {
            name: subprocess.run(["git", "-C", str(ROOT), "show", f"{PIN}:spec/{name}"],
                                 capture_output=True, text=True, check=True).stdout
            for name in MODULES
        }
        cls.definitions = definition_sections(cls.sources)

    def test_each_rule_points_at_all_its_defining_sections_in_pinned_spec(self):
        self.assertIn(f"`{PIN[:7]}`", self.text)
        actual = {}
        for _stage, sections, rules, _covers in table_rows(self.text, "## Current rules"):
            if rules == "—":
                continue
            refs = set(re.findall(r"§([\w.]+)", sections))
            self.assertTrue(refs)
            self.assertNotIn("*", rules)
            for rule in re.findall(RULE, rules):
                self.assertNotIn(rule, actual, f"duplicate rule {rule}")
                actual[rule] = refs
        self.assertEqual(actual, self.definitions)
        self.assertEqual(actual["DV-5"], {"9.6.2"})
        self.assertEqual(actual["DV-6"], {"9.6.2"})
        self.assertEqual(actual["PDE-8"], {"9.7.0", "10.4.3"})
        self.assertEqual(actual["CD-1"], {"B.2"})
        # Refunds and corrections are conditional within FP-DEM, not excluded rails.
        self.assertIn("refunds and corrections", self.text.split("## Current rules", 1)[1])
        for rule in ("AMEND-1", "AMEND-2", "AMEND-3", "AMEND-4"):
            self.assertEqual(actual[rule], {"9.7.1"})

    def test_definition_locator_covers_the_full_applicable_rule_inventory(self):
        # Independently enumerate labels with the repo's existing rule-ID validator,
        # so a missed definition format cannot silently reduce map coverage.
        path = ROOT / "scripts" / "validate_rule_ids.py"
        sys.path.insert(0, str(path.parent))
        spec = importlib.util.spec_from_file_location("map_rule_ids", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        labels = module.defined_rule_ids("\n".join(self.sources.values()))
        expected = {rule for rule in labels if rule_family(rule) not in EXCLUDED}
        self.assertNotIn("AMEND", EXCLUDED)
        self.assertTrue({"AMEND-1", "AMEND-2", "AMEND-3", "AMEND-4"} <= expected)
        self.assertEqual(set(self.definitions), expected)

    def test_issue_330_is_dispositioned_against_current_delivery_contract(self):
        disposition = self.text.split("Issue #330 also remains open.", 1)[1]
        for text in ("DeliveryEvidence", "PDE-5", "DV-5", "PDE-8", "§9.7", "§9.6.2", "§10.4.3"):
            self.assertIn(text, disposition)
        self.assertIn("without asserting a remaining normative defect", disposition)

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
