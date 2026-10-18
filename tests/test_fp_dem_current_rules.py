import collections
import importlib.util
import json
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
# Other rails, alternative payment, other negotiation patterns, private
# negotiation channels and attested-payload delivery are outside FP-DEM.
EXCLUDED = {"AP2", "APR", "DPA", "HTLC", "RFQ", "SAC", "SE", "X402", "CH"}
# Split families are excluded rule by rule: DV-5 and DV-6 govern
# deliver-entitlement credentials (§9.6.2), not deliver-storage-program.
EXCLUDED_RULES = {"DV-5", "DV-6"}
RULE = r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)?-?\d+"


def rule_family(rule):
    return re.sub(r"\d+$", "", rule).rstrip("-")


def excluded(rule):
    return rule_family(rule) in EXCLUDED or rule in EXCLUDED_RULES


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
                if not excluded(rule):
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
        # MTR-5 rejects an unrecognized pricing kind for every agreement; MTR-1..4
        # apply when PS-3 runs fixed-price over a metered listing.
        for rule in ("MTR-1", "MTR-2", "MTR-3", "MTR-4", "MTR-5"):
            self.assertEqual(actual[rule], {"8.5.2"})
        self.assertIn("MTR-5 applies to every agreement", self.text)
        self.assertNotIn("DV-5", actual)
        self.assertNotIn("DV-6", actual)
        self.assertEqual(actual["DV-1"], {"9.6.1"})
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
        expected = {rule for rule in labels if not excluded(rule)}
        self.assertNotIn("AMEND", EXCLUDED)
        self.assertNotIn("MTR", EXCLUDED)
        self.assertTrue(EXCLUDED_RULES <= labels)
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

    def test_gaps_cover_cross_profile_changes_vector_gaps_and_upstream_blockers(self):
        rows = {number: (kind, sections) for number, kind, sections, _what in
                table_rows(self.text, "## Known gaps")}
        # Open PR #336 changes §9.4.3, PC-1 and AMEND-1 for every profile.
        self.assertEqual(rows["#336, #320"], ("PR, issue", "§9.4.3, §9.5.1, §9.7.1, §10.4.3"))
        self.assertEqual(rows["#341"], ("draft PR", "§6.3.4"))
        self.assertEqual(rows["#99"][1], "§10.4.2, §10.4.3, §11.2.1")
        gaps = self.text.split("## Known gaps", 1)[1]
        untracked = gaps.split("No open issue tracks these vector gaps yet:", 1)[1].split("\n\n", 2)[1]
        for text in ("§8.4.1", "auto-accept", "PS-1", "PS-2"):
            self.assertIn(text, untracked)
        # PS-1/PS-2 lack vectors, not checks: the reference and listing code
        # named in the gap reject missing, duplicate and non-adjacent phases.
        self.assertIn("no committed conformance vector or v0.4 suite case exercises PS-1 or PS-2", untracked)
        regression = (ROOT / "tests" / "test_current_evidence_boundary_regressions.py").read_text(encoding="utf-8")
        listing = (ROOT / "scripts" / "listing_artifact.py").read_text(encoding="utf-8")
        self.assertIn('for mutation in ("missing", "duplicate", "nonadjacent"):', regression)
        self.assertIn("commitments[0] != negotiations[0] + 1", listing)
        for path in ("tests/test_current_evidence_boundary_regressions.py", "scripts/listing_artifact.py"):
            self.assertIn(f"`{path}`", untracked.replace("\n  ", " "))
        # PS-3's pattern/pricing compatibility and the §9.6.1 extended pointer
        # have no committed vector either; the PS-3 vectors test only the band centre.
        flat = untracked.replace("\n  ", " ")
        self.assertIn("pricing model be compatible with the chosen pattern", flat)
        self.assertIn("cover only the negotiable band-centre clause", flat)
        self.assertIn("§9.6.1 extended pointer (`externalUrl`, `externalContentHash`)", flat)
        manifest = subprocess.run(["git", "-C", str(ROOT), "show", f"{PIN}:conformance/MANIFEST.json"],
                                  capture_output=True, text=True, check=True).stdout
        self.assertNotIn("externalUrl", manifest)
        self.assertEqual([case["id"] for case in json.loads(manifest)["cases"] if "PS-3" in case["spec"]
                          or "ps3" in case["id"]], ["neg-ps3-fixed-over-negotiable"])
        self.assertNotIn("DV-", " ".join(case["spec"] for case in json.loads(manifest)["cases"]))
        upstream = gaps.split("also depend on two open upstream", 1)[1]
        for text in ("DACS-Agent-commerce/dacs-sdk#284", "kynesyslabs/node#994"):
            self.assertIn(text, upstream)
        # The DEM rail is a §9.4.2 registry row; §9.4.3 covers authoring and resolution.
        registry = self.sources["DACS-4-SETTLE.md"].split("#### 9.4.2 ", 1)[1].split("\n#### ", 1)[0]
        self.assertIn("| demos-native:DEM |", registry)
        self.assertIn("registry entry (§9.4.2; resolved per §9.4.3)", gaps)
        self.assertIn("other\nthan the pull request adding this map", gaps)

    def test_gaps_record_that_included_is_not_an_executed_pay_dem_transfer(self):
        # At the pin §9.5.9 returns success on `included`, which a node also
        # reports for a failed record; #432 is the open fix.
        rows = {number: (kind, sections, what) for number, kind, sections, what in
                table_rows(self.text, "## Known gaps")}
        kind, sections, what = rows["#432"]
        self.assertEqual((kind, sections), ("draft PR", "§9.5.9, §9.5.1, §9.5.8, §9.7.0"))
        self.assertIn("executed transaction record", what)
        self.assertIn("`included` status is not settlement", what)
        settle = self.sources["DACS-4-SETTLE.md"].split("#### 9.5.9 pay-dem", 1)[1].split("\n#### ", 1)[0]
        self.assertIn("5. On the transaction reaching the terminal **`included`** state", settle)
        note = self.text.split("#432 concerns the payment step itself.", 1)[1].split("\n\n", 1)[0]
        note = " ".join(note.split())
        for text in ("§9.5.9 step 5 returns success once the transfer reaches the terminal `included` state",
                     "`kynesyslabs/node` at `61b8e75aa8db5e408c49e1c3a89db4d673f45578`",
                     "`@kynesyslabs/demosdk` 4.0.16 (npm integrity `sha512-",
                     "report a failed transfer as settled",
                     "an observation of a live node, not a pin",
                     "does not change §9.5.9"):
            self.assertIn(text, note)
        self.assertIn("other\nthan the pull request adding this map were enumerated on 2026-10-18", self.text)

    def test_gaps_record_the_storage_program_cap_difference(self):
        # §9.6.1 says 128 KB; the pinned node and SDK enforce 1 MiB.
        delivery = self.sources["DACS-4-SETTLE.md"].split("#### 9.6.1 ", 1)[1].split("\n#### ", 1)[0]
        self.assertIn("Storage Programs have a 128 KB cap", delivery)
        gaps = " ".join(self.text.split("## Known gaps", 1)[1].split())
        self.assertIn("§9.6.1 gives that soft limit as a 128 KB Storage Program cap. "
                      "The Demos node enforces 1 MiB (`STORAGE_PROGRAM_MAX_SIZE_BYTES = 1048576`", gaps)
        self.assertIn("No open issue tracks the difference.", gaps)

    def test_covers_column_follows_the_rule_id_index_at_the_pin(self):
        index = subprocess.run(["git", "-C", str(ROOT), "show", f"{PIN}:docs/rule-id-index.md"],
                               capture_output=True, text=True, check=True).stdout
        surfaces = {family.rstrip("*").rstrip("-"): surface
                    for family, surface, *_rest in table_rows(index, "## Rule families")}
        checked = 0
        for _stage, _sections, rules, covers in table_rows(self.text, "## Current rules"):
            if rules == "—":
                continue
            for family in {rule_family(rule) for rule in re.findall(RULE, rules)}:
                with self.subTest(family=family):
                    self.assertEqual(covers, surfaces[family])
                    checked += 1
        self.assertGreater(checked, 60)

    def test_readme_and_historical_readiness_page_link_the_map(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        readiness = (ROOT / "IMPLEMENTATION_READINESS.md").read_text(encoding="utf-8")
        self.assertIn("(./docs/fp-dem-current-rules.md)", readme)
        self.assertIn("**Historical.**", readiness.split("\n\n", 2)[1])
        self.assertIn("(./docs/fp-dem-current-rules.md)", readiness)
        self.assertIn("(../spec/PROFILE.md)", self.text)


if __name__ == "__main__":
    unittest.main()
