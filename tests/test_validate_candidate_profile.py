import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_candidate_profile.py"
ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "delivery-or-remedy-candidate.md"
MATRIX = ROOT / "conformance" / "candidates" / "delivery-or-remedy" / "rule-case-matrix.json"


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_candidate_profile", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mutate(text: str, old: str, new: str) -> str:
    assert text.count(old) == 1, f"mutation anchor not unique: {old!r}"
    return text.replace(old, new)


class CandidateProfileValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = load_validator()
        cls.text = DOC.read_text(encoding="utf-8")

    def structural_errors(self, text: str) -> list[str]:
        """Errors that remain even after the matrix is regenerated."""
        with TemporaryDirectory() as tmp:
            doc = Path(tmp) / "candidate.md"
            doc.write_text(text, encoding="utf-8")
            return self.validator.validate(doc, None)

    def ci_errors(self, text: str) -> list[str]:
        """Errors CI reports against the committed matrix."""
        with TemporaryDirectory() as tmp:
            doc = Path(tmp) / "candidate.md"
            doc.write_text(text, encoding="utf-8")
            return self.validator.validate(doc, MATRIX)

    def assert_structural(self, text: str, fragment: str):
        errors = self.structural_errors(text)
        self.assertTrue(any(fragment in error for error in errors), errors)

    def assert_stale_only(self, text: str):
        self.assertEqual(self.structural_errors(text), [])
        self.assertEqual(
            self.ci_errors(text),
            [
                "rule-to-case matrix is stale; review the normative change and run "
                "scripts/validate_candidate_profile.py --write"
            ],
        )

    def test_repository_candidate_and_matrix_are_valid(self):
        self.assertEqual(self.validator.validate(), [])

    def test_matrix_pins_every_rule_and_case(self):
        matrix = self.validator.build_matrix(self.text)
        rules = {rule["id"]: rule for rule in matrix["rules"]}
        self.assertEqual(len(rules), len(matrix["rules"]))
        for rule in matrix["rules"]:
            if rule["requirement"]:
                self.assertTrue(rule["cases"], rule["id"])
        self.assertEqual(matrix["checkedAgainst"], "df7bc202ebdc179a59d61a8221072f33f482b933")
        self.assertEqual(matrix["executableVectorCount"], 0)
        self.assertIn("R19", {case["id"] for case in matrix["cases"]})

    def test_signing_domains_follow_sig4_and_type_versions(self):
        domains, errors = self.validator.signing_domains(self.text)
        self.assertEqual(errors, [])
        self.assertTrue(domains)
        for entry in domains:
            self.assertTrue(entry["domain"].startswith("dacs-x-"), entry)
            self.assertTrue(entry["domain"].endswith(":v1:"), entry)

    # Semantic edits: no structural invariant breaks, but CI fails until the
    # matrix is regenerated and the diff is reviewed.
    def test_m01_inverted_preterminal_payout_rule_is_caught_as_stale(self):
        self.assert_stale_only(mutate(
            self.text,
            "(DRL-7) Value MUST NOT reach the seller or any seller payout destination before `released`.",
            "(DRL-7) Value MAY reach the seller or any seller payout destination before `released`.",
        ))

    def test_m02_expiry_mapped_to_cutoff_is_caught_as_stale(self):
        self.assert_stale_only(mutate(
            self.text,
            "(DREB-12) ERC `expiredAt` MUST equal `evaluationDeadlineSec`.",
            "(DREB-12) ERC `expiredAt` MUST equal `submissionCutoffSec`.",
        ))

    def test_m05_deliverable_rehash_is_caught_as_stale(self):
        self.assert_stale_only(mutate(
            self.text,
            "| `deliverable` | `decode_hex_32(contentHash(DeliveryEvidence))`",
            "| `deliverable` | `sha256(contentHash(DeliveryEvidence))`",
        ))

    def test_m09_nonzero_fee_type_is_caught_as_stale(self):
        self.assert_stale_only(mutate(self.text, "  platformFeeBP: 0\n", "  platformFeeBP: number\n"))

    def test_m12_release_without_decision_is_caught_as_stale(self):
        self.assert_stale_only(mutate(
            self.text,
            "(DRT-1) `released` MUST carry and verify `decisionRef`, its basis, and `deliveryEvidenceRef`.",
            "(DRT-1) `released` MUST carry `deliveryEvidenceRef` and MAY omit `decisionRef`.",
        ))

    # Structural edits: rejected even with a regenerated matrix.
    def test_m03_unregistered_non_extension_domain(self):
        self.assert_structural(
            mutate(self.text, '"dacs-x-escrow-decision:v1:"', '"dacs-escrow-decision:v1:"'),
            "non-extension domain is not registered in CORE: dacs-escrow-decision:v1:",
        )

    def test_m04_duplicate_rule_id(self):
        self.assert_structural(
            mutate(self.text, "- (DRT-2) `rejected-refund`", "- (DRT-1) `rejected-refund`"),
            "duplicate rule ID: DRT-1",
        )

    def test_m06_deleted_rule_leaves_gap_and_dangling_case(self):
        line = next(l for l in self.text.splitlines() if l.startswith("- (DRA-7) "))
        text = mutate(self.text, line + "\n", "")
        self.assert_structural(text, "rule family DRA has gaps: DRA-7")
        self.assert_structural(text, "case R6 lists undefined rule DRA-7")

    def test_m07_dangling_spec_reference(self):
        self.assert_structural(
            mutate(self.text, "the `dacs-x-` extension-domain form required by CORE SIG-4.",
                   "the `dacs-x-` extension-domain form required by CORE SIG-99."),
            "reference to rule SIG-99 that spec/ does not define",
        )

    def test_m08_domain_version_mismatch(self):
        self.assert_structural(
            mutate(self.text, '  escrowDecisionVersion: "1"', '  escrowDecisionVersion: "2"'),
            'signing domain dacs-x-escrow-decision:v1: does not match EscrowDecision version "2"',
        )

    def test_m10_removed_case_uncovers_rules(self):
        line = next(l for l in self.text.splitlines() if l.startswith("- **R17** "))
        text = mutate(self.text, line + "\n", "")
        self.assert_structural(text, "requirement DREB-14 is not exercised by any section 11 case")
        self.assert_structural(text, "case family R has gaps: R17")

    def test_m11_non_dacs_result_vocabulary(self):
        self.assert_structural(
            mutate(self.text, "5. Return `indeterminate` when", "5. Return `verified` when"),
            "non-DACS verifier result `verified` used",
        )
        self.assert_structural(
            mutate(self.text, '"pass" | "fail" | "indeterminate" | "error"\n',
                   '"verified" | "rejected" | "indeterminate" | "error"\n'),
            "section 9 result vocabulary must be exactly",
        )

    def test_unlabelled_requirement_and_no_may_prohibition(self):
        self.assert_structural(
            mutate(self.text, "DRP-13 states what it must not do instead.\n",
                   "It MUST NOT strip either phase.\n"),
            "capitalized requirement keyword outside a labelled rule",
        )
        self.assert_structural(
            mutate(self.text, "(DRC-4) An authority MUST NOT be able to withdraw",
                   "(DRC-4) No authority MAY withdraw"),
            "prohibition phrased as 'No ... MAY'",
        )

    def test_candidate_cannot_claim_normative_status_or_drop_revision_pin(self):
        self.assert_structural(
            mutate(self.text, "**Status:** pre-normative review candidate", "**Status:** normative"),
            "status line must remain 'pre-normative review candidate'",
        )
        self.assert_structural(
            mutate(self.text, "**Checked against:** DACS-Standard `next` at `df7bc202",
                   "**Checked against:** DACS-Standard `next` at `df7bc2"),
            "missing '**Checked against:**",
        )

    def test_rule_family_colliding_with_spec_is_rejected(self):
        spec_text = (
            "- (DRA-1) A promoted rule that reuses the candidate family.\n"
            "The v0.x registry of domain separators at this revision is closed:\n"
            "| Known | \"dacs-known:v1:\" | §1 |\n"
            "**Payload shape — single-hash vs composite.**\n"
        )
        errors = self.validator.validate_text(self.text, spec_text)
        self.assertIn("candidate rule family DRA collides with a spec/ rule family", errors)


if __name__ == "__main__":
    unittest.main()
