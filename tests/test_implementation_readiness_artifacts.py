import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ImplementationReadinessArtifactTests(unittest.TestCase):
    def test_ci_workflow_runs_required_validators_on_pull_requests(self):
        workflow = ROOT / ".github" / "workflows" / "validate.yml"
        self.assertTrue(workflow.exists(), "missing PR validation workflow")
        text = workflow.read_text(encoding="utf-8")
        self.assertIn("pull_request", text)
        self.assertIn("python3 scripts/validate_conformance_vectors.py", text)
        self.assertIn("python3 scripts/validate_implementation_manifests.py", text)
        self.assertIn("python3 scripts/validate_domain_separators.py", text)
        self.assertIn("python3 scripts/validate_rule_ids.py", text)
        self.assertIn("python3 scripts/validate_spec_tables.py", text)
        self.assertIn("python3 scripts/validate-docs.py", text)
        self.assertIn("concurrency:", text)
        # unit tests still run every suite over tests/ (R5: now via a fail-closed wrapper, not the bare
        # `python3 -m unittest discover tests -v`, so a skipped crypto suite turns the build RED).
        self.assertIn('discover("tests")', text)
        # crypto dependency is installed and gated fail-closed (xm33 B2: CI must actually verify signatures).
        self.assertIn("cryptography", text)
        self.assertIn("crypto import gate (fail-closed)", text)
        # skip-gate: any unittest skip fails the job, so skipped=6 can never silently recur.
        self.assertIn("result.skipped", text)

    def test_glossary_index_links_key_terms_to_spec_sections(self):
        glossary = ROOT / "docs" / "glossary-index.md"
        self.assertTrue(glossary.exists(), "missing glossary index")
        text = glossary.read_text(encoding="utf-8")
        for term in ["IdentityBundle", "AttestationBundle", "RatingRecord", "ClaimReference", "SettlementEvidence"]:
            with self.subTest(term=term):
                self.assertIn(term, text)
        self.assertIn("../spec/GLOSSARY.md", text)

    def test_rule_id_index_covers_expected_rule_families(self):
        index = ROOT / "docs" / "rule-id-index.md"
        self.assertTrue(index.exists(), "missing rule-ID index")
        text = index.read_text(encoding="utf-8")
        for family in ["BP-", "LP-", "SIG-", "PC-", "RT-", "RAV-"]:
            with self.subTest(family=family):
                self.assertIn(family, text)
        self.assertIn("../spec/CONFORMANCE-PLAN.md#148-substrate-capability-tests", text)

    def test_operational_builder_guide_outline_covers_ops_topics(self):
        guide = ROOT / "docs" / "operational-builder-guide.md"
        self.assertTrue(guide.exists(), "missing operational builder guide outline")
        text = guide.read_text(encoding="utf-8").lower()
        for topic in ["capital", "float", "undercapitalised", "key custody", "settlement finality"]:
            with self.subTest(topic=topic):
                self.assertIn(topic, text)

    def test_issue_templates_match_contributing_feedback_format(self):
        template_dir = ROOT / ".github" / "ISSUE_TEMPLATE"
        expected = {
            "spec-defect.yml": "Spec defect",
            "implementation-report.yml": "Implementation report",
            "editorial-fix.yml": "Editorial fix",
        }
        for filename, title in expected.items():
            with self.subTest(filename=filename):
                path = template_dir / filename
                self.assertTrue(path.exists(), f"missing {filename}")
                text = path.read_text(encoding="utf-8")
                self.assertIn(title, text)
                self.assertIn("section", text.lower())
                self.assertIn("artifact", text.lower())
                self.assertIn("alternate", text.lower())

    def test_implementation_readiness_document_reports_all_items_complete(self):
        readiness = (ROOT / "IMPLEMENTATION_READINESS.md").read_text(encoding="utf-8")
        self.assertIn("10 of 10", readiness)
        self.assertNotIn("[ ]", readiness)
        for item in ["validate.yml", "identity-bundle.json", "glossary-index.md", "rule-id-index.md", "operational-builder-guide.md", "ISSUE_TEMPLATE"]:
            with self.subTest(item=item):
                self.assertIn(item, readiness)


if __name__ == "__main__":
    unittest.main()
