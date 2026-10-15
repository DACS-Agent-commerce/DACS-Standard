import importlib.util
import os
import subprocess
import sys
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
        kinds = {case["id"]: case["id"][0] for case in matrix["cases"]}
        for rule in matrix["rules"]:
            if rule["requirement"]:
                self.assertTrue(rule["cases"], rule["id"])
                self.assertTrue(any(kinds[c] != "P" for c in rule["cases"]), rule["id"])
        self.assertRegex(matrix["checkedAgainst"], r"^[0-9a-f]{40}$")
        self.assertEqual(self.validator.pin_errors(ROOT, matrix["checkedAgainst"]), [])
        self.assertEqual(matrix["executableVectorCount"], 0)
        self.assertIn("R19", {case["id"] for case in matrix["cases"]})
        for case in matrix["cases"]:
            self.assertTrue(case["expected"], case["id"])

    def test_signing_domains_follow_sig4_and_type_versions(self):
        domains, errors = self.validator.signing_domains(self.text)
        self.assertEqual(errors, [])
        self.assertEqual({entry["signs"] for entry in domains}, set(self.validator.SIGNED_TYPES))
        self.assertEqual(len(domains), len(self.validator.SIGNED_TYPES))
        for entry in domains:
            self.assertTrue(entry["domain"].startswith("dacs-x-"), entry)
            self.assertTrue(entry["domain"].endswith(":v1:"), entry)

    # Promotion-relevant semantics from the sweep: each anchor must stay in the doc.
    def test_sweep_semantic_anchors_are_present(self):
        for anchor in (
            "`terms.price.currency` MUST equal the rail's `asset.symbol`",
            "asset: { kind: \"erc20\"; chainId: number; contract: string; symbol: string; decimals: number }",
            "governance: {",
            "availability: RailAvailability",
            "decisionStage: \"pre-submission\" | \"post-submission\"",
            "| `EscrowDecision` | `dacs4:x-job-escrow:{jobId}:decision:{decisionStage}` |",
            "A `DisputeOutcome` used as an `EscrowDecision` basis MUST carry `recommendedDisposition`",
            "`finality.finalityObservedAt` and `observedAt` MUST both equal 1000 times",
            "Duration in seconds: `minimumEvaluationWindowSec`",
            "https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-55.md",
            "`terms.rail` MUST be present and canonically equal",
            "Its `outcome` MUST be `success`",
            "compare their decoded chain IDs and DRW-1 20-byte addresses",
            "the entitled participants are the buyer, the seller, the evaluator, and the session orchestrator",
            "multiplied by 1000",
        ):
            self.assertIn(anchor, self.text)
        self.assertNotIn("EIPS/eip-55.md", self.text)
        self.assertNotIn("`job-escrow`", self.text)

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

    # Checked-against pin: it must be a real commit whose spec/ equals the tree.
    def test_wrong_well_formed_pin_is_rejected(self):
        pin = self.validator.checked_against(self.text)
        self.assert_structural(
            mutate(self.text, f"`next` at `{pin}`", "`next` at `" + "0" * 40 + "`"),
            f"**Checked against** commit {'0' * 40} is not a commit in this repository",
        )

    def test_stale_pin_whose_spec_differs_is_rejected(self):
        pin = self.validator.checked_against(self.text)
        last_spec_change = subprocess.run(
            ["git", "-C", str(ROOT), "log", "-n", "1", "--format=%H", pin, "--", "spec/"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        older = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", f"{last_spec_change}^"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        self.assert_structural(
            mutate(self.text, f"`next` at `{pin}`", f"`next` at `{older}`"),
            f"spec/ differs from the **Checked against** commit {older}",
        )

    def test_external_pin_must_link_to_a_commit(self):
        self.assert_structural(
            mutate(self.text, "ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-55.md",
                   "ERCs/blob/master/ERCS/erc-55.md"),
            "external pin https://github.com/ethereum/ERCs/blob/master/ERCS/erc-55.md does not link to a 40-hex commit",
        )

    # Signed-type inventory: no signed artifact may lose its version or domain.
    def test_deleted_version_member_is_rejected(self):
        self.assert_structural(
            mutate(self.text, '  escrowDecisionVersion: "1"\n', ""),
            "signed type EscrowDecision must declare exactly one version member escrowDecisionVersion",
        )

    def test_deleted_signing_domain_is_rejected(self):
        self.assert_structural(
            mutate(self.text, '"dacs-x-escrow-decision:v1:" || escrow_decision_hash\n', ""),
            "signed type EscrowDecision has 0 signing domains; exactly one is required",
        )

    def test_wrong_hash_operand_is_rejected(self):
        text = mutate(self.text, '"dacs-x-escrow-decision:v1:" || escrow_decision_hash',
                      '"dacs-x-escrow-decision:v1:" || escrow_job_ref_hash')
        self.assert_structural(text, "signed type EscrowDecision has 0 signing domains")
        self.assert_structural(text, "signed type EscrowJobRef has 2 signing domains")

    def test_registered_production_domain_is_rejected(self):
        self.assert_structural(
            mutate(self.text, '"dacs-x-escrow-decision:v1:" || escrow_decision_hash',
                   '"dacs-evidence:v1:" || escrow_decision_hash'),
            "candidate signing domain dacs-evidence:v1: must use the dacs-x- form",
        )

    def test_malformed_signing_domain_line_is_rejected(self):
        self.assert_structural(
            mutate(self.text, '"dacs-x-escrow-decision:v1:" || escrow_decision_hash',
                   '"dacs-x-escrow-decision:v7:" || sha256(escrow_decision)'),
            'malformed signing-domain line: "dacs-x-escrow-decision:v7:" || sha256(escrow_decision)',
        )

    def test_domain_reused_for_two_artifacts_is_rejected(self):
        self.assert_structural(
            mutate(self.text, '"dacs-x-dispute-case:v1:" || dispute_case_hash',
                   '"dacs-x-dispute-outcome:v1:" || dispute_case_hash'),
            "candidate signing domain used for more than one artifact: dacs-x-dispute-outcome:v1:",
        )

    def test_reordered_domain_blocks_still_bind_by_operand(self):
        block = '```text\n"dacs-x-dispute-case:v1:" || dispute_case_hash\n```\n\n'
        text = mutate(self.text, block, "")
        text = mutate(text, '"dacs-x-dispute-outcome:v1:" || dispute_outcome_hash\n```\n',
                      '"dacs-x-dispute-outcome:v1:" || dispute_outcome_hash\n```\n\n' + block)
        self.assertEqual(self.structural_errors(text), [])
        domains, _ = self.validator.signing_domains(text)
        self.assertIn({"domain": "dacs-x-dispute-case:v1:", "signs": "DisputeCase"}, domains)

    def test_signed_type_outside_inventory_is_rejected(self):
        extra = '```text\ntype ExtraArtifact = {\n  extraArtifactVersion: "1"\n  signature: ComponentSignature\n}\n```\n\n'
        self.assert_structural(
            mutate(self.text, "### 6.5 Candidate logical addresses\n", extra + "### 6.5 Candidate logical addresses\n"),
            "signed type ExtraArtifact is not in the signed-type inventory",
        )

    def test_registered_candidate_domain_collision(self):
        spec_text = (
            "The v0.x registry of domain separators at this revision is closed:\n"
            "| Decision | \"dacs-x-escrow-decision:v1:\" | §1 |\n"
            "**Payload shape — single-hash vs composite.**\n"
        )
        errors = self.validator.validate_text(self.text, spec_text)
        self.assertIn("candidate domain collides with a registered domain: dacs-x-escrow-decision:v1:", errors)

    # Case coverage and expected results.
    def test_positive_only_requirement_is_rejected(self):
        self.assert_structural(
            mutate(self.text, "*Rules:* DRT-1, DRT-2, DRT-3, DRD-7.", "*Rules:* DRT-2, DRT-3, DRD-7."),
            "requirement DRT-1 is exercised only by positive cases",
        )

    def test_case_expected_result_must_fit_its_kind(self):
        self.assert_structural(
            mutate(self.text, "and release the complete budget. *Expected:* `pass`.",
                   "and release the complete budget. *Expected:* `fail`."),
            "case P1 expects fail; P cases may expect only pass",
        )
        self.assert_structural(
            mutate(self.text, "*Expected:* `fail`. *Rules:* DRP-9.", "*Expected:* `pass`. *Rules:* DRP-9."),
            "case R13 expects pass; R cases may expect only error, fail",
        )
        self.assert_structural(
            mutate(self.text, "missing finality evidence. *Expected:* `indeterminate`.",
                   "missing finality evidence. *Expected:* none."),
            "case I3 declares no expected result",
        )

    def test_malformed_case_lines_are_rejected(self):
        self.assert_structural(
            mutate(self.text, "the native submission event. *Expected:* `fail`. *Rules:* DRP-9.",
                   "the native submission event. *Rules:* DRP-9."),
            "malformed case line",
        )
        self.assert_structural(
            mutate(self.text, "*Expected:* `fail`. *Rules:* DRP-9.", "*Expected:* `fail`. *Rules:* DRP-9"),
            "malformed case line",
        )

    def test_duplicate_and_missing_cases(self):
        self.assert_structural(mutate(self.text, "- **R2** —", "- **R1** —"), "duplicate case ID: R1")
        self.assert_structural(self.text.replace("- **", "- __"), "section 11 defines no cases")

    def test_may_only_restriction_is_a_requirement(self):
        rules = self.validator.parse_rules("- (DRZ-1) An account MAY be used only when it is supported.\n")
        self.assertTrue(rules[0]["requirement"])
        rules = self.validator.parse_rules("- (DRZ-1) An account MAY be used.\n")
        self.assertFalse(rules[0]["requirement"])

    def test_fenced_rules_and_cases_are_not_parsed(self):
        fenced = "```text\n- (DRZ-1) A fenced line MUST NOT count.\n- **P99** — fenced. *Expected:* `pass`. *Rules:* DRZ-1.\n```\n"
        self.assertEqual(self.validator.parse_rules(fenced), [])
        self.assertEqual(self.validator.parse_cases(fenced), [])

    def test_undefined_candidate_reference(self):
        self.assert_structural(
            mutate(self.text, "DRP-13 states what it must not do instead.", "DRP-99 states what it must not do instead."),
            "reference to undefined candidate rule DRP-99",
        )

    def test_short_document_reports_instead_of_crashing(self):
        spec_text = (
            "The v0.x registry of domain separators at this revision is closed:\n"
            "**Payload shape — single-hash vs composite.**\n"
        )
        errors = self.validator.validate_text("# Title\n", spec_text)
        self.assertIn("status line must remain 'pre-normative review candidate' until executable vectors exist", errors)

    def test_missing_matrix_is_reported(self):
        with TemporaryDirectory() as tmp:
            doc = Path(tmp) / "candidate.md"
            doc.write_text(self.text, encoding="utf-8")
            errors = self.validator.validate(doc, Path(tmp) / "absent.json")
        self.assertIn(f"missing rule-to-case matrix: {Path(tmp) / 'absent.json'}", errors)


class CandidateProfileCliTests(unittest.TestCase):
    """The CI step runs the script; its exit status is the gate."""

    @classmethod
    def setUpClass(cls):
        cls.text = DOC.read_text(encoding="utf-8")

    def run_cli(self, *args: str) -> subprocess.CompletedProcess:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run([sys.executable, str(SCRIPT_PATH), *args], capture_output=True, text=True, env=env)

    def test_committed_document_exits_zero(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("candidate profile OK", result.stdout)

    def test_stale_matrix_exits_one(self):
        with TemporaryDirectory() as tmp:
            doc = Path(tmp) / "candidate.md"
            doc.write_text(mutate(self.text, "(DRL-7) Value MUST NOT reach", "(DRL-7) Value MAY reach"), encoding="utf-8")
            result = self.run_cli("--doc", str(doc), "--matrix", str(MATRIX))
        self.assertEqual(result.returncode, 1)
        self.assertIn("rule-to-case matrix is stale", result.stderr)

    def test_structural_error_exits_one_and_write_refuses(self):
        with TemporaryDirectory() as tmp:
            doc = Path(tmp) / "candidate.md"
            doc.write_text(mutate(self.text, '  escrowDecisionVersion: "1"\n', ""), encoding="utf-8")
            matrix = Path(tmp) / "matrix.json"
            checked = self.run_cli("--doc", str(doc), "--matrix", str(MATRIX))
            written = self.run_cli("--doc", str(doc), "--matrix", str(matrix), "--write")
            self.assertFalse(matrix.exists())
        self.assertEqual(checked.returncode, 1)
        self.assertIn("signed type EscrowDecision must declare exactly one version member", checked.stderr)
        self.assertEqual(written.returncode, 1)

    def test_write_regenerates_a_stale_matrix(self):
        with TemporaryDirectory() as tmp:
            doc = Path(tmp) / "candidate.md"
            doc.write_text(mutate(self.text, "(DRL-7) Value MUST NOT reach", "(DRL-7) Value MAY reach"), encoding="utf-8")
            matrix = Path(tmp) / "matrix.json"
            matrix.write_text(MATRIX.read_text(encoding="utf-8"), encoding="utf-8")
            written = self.run_cli("--doc", str(doc), "--matrix", str(matrix), "--write")
            checked = self.run_cli("--doc", str(doc), "--matrix", str(matrix))
            self.assertNotEqual(matrix.read_text(encoding="utf-8"), MATRIX.read_text(encoding="utf-8"))
        self.assertEqual(written.returncode, 0, written.stderr)
        self.assertEqual(checked.returncode, 0, checked.stderr)


if __name__ == "__main__":
    unittest.main()
