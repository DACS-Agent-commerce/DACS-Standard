import copy
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_candidate_profile.py"
ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "delivery-or-remedy-candidate.md"
MATRIX = ROOT / "conformance" / "candidates" / "delivery-or-remedy" / "rule-case-matrix.json"
SR2_REFERENCE_PATH = ROOT / "scripts" / "sr2_resolution_reference.py"
SR2_VECTORS = ROOT / "conformance" / "vectors" / "security" / "sr2-logical-native-resolution-v0.1.json"
# A labelled spec rule: `- (ID) ...` or the bold form `- **(ID) Title.** ...` / `- **(ID)** ...`.
SPEC_RULE_LABEL_RE = re.compile(r"^- (?:\*\*)?\(([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)\)")


def shallow_checkout() -> bool:
    try:
        result = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--is-shallow-repository"],
                                capture_output=True, text=True)
    except FileNotFoundError:
        return False
    return result.stdout.strip() == "true"


# The pin check needs full history; in a shallow clone it reports that instead.
SHALLOW = shallow_checkout()
SHALLOW_REASON = "the **Checked against** pin needs full history (git fetch --unshallow)"


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_validator():
    return load_script("validate_candidate_profile", SCRIPT_PATH)


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True)


def as_committed_candidate(validator):
    """Check a scratch copy of the candidate at the committed candidate's latest revision.

    A scratch copy lies outside the repository, so pin_errors alone would compare
    the pin with the working tree's spec/, and every later spec/ change on `next`
    would fail checks that are not about the pin. DRG-2 asks for a re-pin only
    when the candidate itself is revised.
    """
    revision = validator.candidate_revision(git, ROOT, DOC)
    return mock.patch.object(validator, "candidate_revision", lambda _git, _root, _doc: revision)


def run_main(validator, *args: str) -> tuple[int, str]:
    """Run the CLI entry point in-process; its return value is the script's exit status."""
    stderr = io.StringIO()
    with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
        status = validator.main(list(args))
    return status, stderr.getvalue()


def mutate(text: str, old: str, new: str) -> str:
    assert text.count(old) == 1, f"mutation anchor not unique: {old!r}"
    return text.replace(old, new)


class CandidateProfileValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = load_validator()
        cls.text = DOC.read_text(encoding="utf-8")

    def without_shallow(self, errors: list[str]) -> list[str]:
        """In a shallow clone, drop the one pin error so the other checks still run."""
        return [e for e in errors if not (SHALLOW and e == self.validator.SHALLOW_CLONE_ERROR)]

    def structural_errors(self, text: str) -> list[str]:
        """Errors that remain even after the matrix is regenerated."""
        with TemporaryDirectory() as tmp, as_committed_candidate(self.validator):
            doc = Path(tmp) / "candidate.md"
            doc.write_text(text, encoding="utf-8")
            return self.without_shallow(self.validator.validate(doc, None))

    def ci_errors(self, text: str) -> list[str]:
        """Errors CI reports against the committed matrix."""
        with TemporaryDirectory() as tmp, as_committed_candidate(self.validator):
            doc = Path(tmp) / "candidate.md"
            doc.write_text(text, encoding="utf-8")
            return self.without_shallow(self.validator.validate(doc, MATRIX))

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
        self.assertEqual(self.without_shallow(self.validator.validate()), [])

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
        self.assertEqual(self.without_shallow(self.validator.pin_errors(ROOT, matrix["checkedAgainst"])), [])
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
            # Sweep 3: a dispute-outcome basis is the hash-bound revision, never an absence proof.
            "The basis is exactly the revision whose content hash `basisRef` binds",
            "a verifier MUST NOT require or search for the absence of a later revision",
            # Sweep 3: hashed evidence members are derived, so DRT-16 holds across producers.
            "`fundingEventRefs` and `terminalEventRefs` MUST each list exactly the section 4.1 \"Required events\"",
            "in ascending `logIndex` order",
            "and MUST omit `signer`",
            # Sweep 3: the ABI pin decodes logs and configuration unambiguously.
            "inputs: { name: string; type: string; indexed: boolean }[]",
            "two entries MUST NOT share a `name` or `topic0`",
            "MUST be read from the pinned input of that entry whose `name` equals the canonical parameter name",
            "`configurationEvidence.eventTopic0` MUST equal the `topic0` of exactly one pinned `events` entry",
            "`preSubmissionPolicyValue` is the 32-byte ABI word",
            # Sweep 3: the Demos timestamp unit rests on a pinned node source.
            "`kynesyslabs/node` at commit `ac8f45f02fc9c25082ce9b83595c2e3916b49c5a`",
            "so the product is a lower bound on the anchor's finality",
            "This extends DACS-3 §8.5.2 check 3",
            "maps it to exactly one section 4.1 native status",
            # Sweep 4: one logical-address anchor per artifact, so duplicate writes keep DRT-16.
            "Its `anchor` MUST be `{kind: \"storage-program\", locator: L}`, where `L` is the artifact's exact logical address",
            "and `dacs4:delivery:{jobId}:{deliveryPhaseIndex}` for `deliveryEvidenceRef` (DRP-7)",
            "The reference MUST NOT carry a native address.",
            "or a native `stor-` address as its locator",
            # Sweep 5: a second write follows CORE §5.1 equivocation, even for equal bytes.
            "so the reference does not depend on the native address",
            "A producer MUST NOT write a second copy at one of these addresses once a write there "
            "has a qualifying CORE `AnchorReceipt`, even with byte-identical content.",
            "MUST apply the CORE §5.1 equivocation rule, even when the two copies are byte-identical. "
            "It retains both, selects neither, and yields `indeterminate`.",
            "A consumer that holds a qualifying receipt for only one write MUST NOT require proof that no other write exists.",
            "- **P13** — the funding evidence and the post-submission decision each written once on Demos",
            "- **I8** — the funding evidence or the post-submission decision written twice on Demos with byte-identical content",
            "record the unit of the Demos block `content.timestamp` in DEMOS-MAPPING before promoting DRC-19",
            # Sweep 4: configuration inputs are one-word value types; the node pin is linked.
            "which MUST have an input named `jobId` of type `uint256`",
            "an elementary value type that fills one ABI word",
            "a `PaymentReleased` event whose payee input is named `recipient`",
            "https://github.com/kynesyslabs/node/blob/ac8f45f02fc9c25082ce9b83595c2e3916b49c5a/src/libs/consensus/v2/types/secretaryManager.ts#L177",
            # Sweep 8: the job-escrow rail domain reaches every reader of the rail record.
            "In LRR-3 the schema is `JobEscrowRailDefinition`",
            "MUST come from a snapshot named by the reader's CORE §B.6 out-of-band agreement",
            "For a job-escrow rail the rows govern",
            "with the DRA-20 and DRA-22 extensions",
            "regenerate every existing Demos-anchored vector whose `blockRef.timestamp` is not a whole multiple of 1000",
            "amend CORE CF-3, or narrow DRW-5 to the DRA-6 and DRA-7 collision checks",
            # Sweep 9: envelope, address spelling, budget spelling, and bytes32 inputs are explicit.
            "which replaces the DACS-4 `RailDefinition.signature` envelope for this type",
            "`token`, `recipient`, `asset.contract`)",
            "A `budgetBaseUnits` that is not in minimal unsigned decimal form.",
            "MUST have type `bytes32`, which the section 8.1 mapping fills",
            "A `deliverable` or `reason` input that is not `bytes32`.",
            # Sweep 10: the ABI signature form, zero budgets, and the spec/ coupling are stated.
            "separated by single commas with no spaces and enclosed in parentheses",
            "a `signature` that contains a space",
            "DRF-2 fails a zero-budget funding only because DACS-4 `PriceTerm.amount` positivity",
            "must exist in the working tree's spec/. A later spec/ change that removes or renames one therefore fails",
        ):
            self.assertIn(anchor, self.text)
        for removed in (
            "EIPS/eip-55.md",
            "`job-escrow`",
            "with no finalized later revision before the decision",
            "a superseded revision",
            "so every field of these records is a function of authenticated chain facts",
            "submissionCutoffField",
            "the SR-2 binding's spelling of that artifact's finalized anchor",
            "a producer-chosen anchor spelling",
            "Each MUST name an input of a static ABI type",
            "a second write at a single-artifact address",
            "`consensus/v2/routines` code",
            "A consumer MUST accept any copy",
            "so two writes of identical bytes at two native addresses give one reference",
            "A second write of byte-identical content is not a distinct artifact",
            "each written twice on Demos with identical bytes",
            "MUST apply RAV-R1 through RAV-R5 unchanged",
            "any other authenticated binding mismatch are `permanent`",
            "Neither policy authorizes",
            "a `disabled`, `failed`, or `mocked` rail selected",
        ):
            self.assertNotIn(removed, self.text)

    # Sweep 5: CORE §5.1 makes two receipts for one immutable address an equivocation,
    # so the candidate's duplicate-write case must expect what the CORE reference returns.
    def test_duplicate_identical_write_matches_the_core_reference(self):
        reference = load_script("sr2_resolution_reference", SR2_REFERENCE_PATH)
        vectors = json.loads(SR2_VECTORS.read_text(encoding="utf-8"))["vectors"]
        case = copy.deepcopy(next(v for v in vectors if v["name"] == "equivalent-reference-and-receipt-collapse")["input"])
        first = case["carriers"][0]
        self.assertEqual(first["kind"], "anchor-receipt")
        case["carriers"] = [first]
        self.assertEqual(reference.evaluate_resolution(case), "pass")
        # Write-input mapping: the same bytes written again get a new native address,
        # transaction, and nonce under the same logical address and content hash.
        native = first["receipt"]["nativeAddress"]
        second = copy.deepcopy(first)
        second["receipt"]["nativeAddress"] = native + "b"
        second["receipt"]["transactionRef"]["value"] += "b"
        second["receipt"]["nonce"] += "b"
        case["storage"][native + "b"] = copy.deepcopy(case["storage"][native])
        case["carriers"] = [first, second]
        self.assertEqual(reference.evaluate_resolution(case), "indeterminate")
        del case["expectedContentHash"]
        self.assertEqual(reference.evaluate_resolution(case), "indeterminate")

        cases = {c["id"]: c for c in self.validator.parse_cases(self.text)}
        self.assertEqual(cases["I8"]["expected"], ["indeterminate"])
        self.assertLessEqual({"DRAA-4", "DRC-15"}, set(cases["I8"]["rules"]))
        for positive in (c for c in cases.values() if c["kind"] == "P"):
            self.assertNotIn("written twice", positive["description"], positive["id"])

    def spec_at_pin(self, path: str) -> str:
        """A spec/ file at the **Checked against** commit, which every cited rule means."""
        pin = self.validator.checked_against(self.text)
        return subprocess.run(["git", "-C", str(ROOT), "show", f"{pin}:{path}"],
                              capture_output=True, text=True, check=True).stdout

    # Sweep 8: DRP-17 classifies the payout binding as the DACS-4 PB failure modes do,
    # so a destination mismatch is `counterparty`, not `permanent`.
    @unittest.skipIf(SHALLOW, SHALLOW_REASON)
    def test_payout_binding_error_classes_follow_the_pb_failure_modes(self):
        settle = self.spec_at_pin("spec/DACS-4-SETTLE.md")
        block = settle.split("**PB failure modes (all pay rails).**", 1)[1].split("####", 1)[0]
        modes = [line for line in block.splitlines() if line.startswith("- PB-")]
        rule = {r["id"]: r["text"] for r in self.validator.parse_rules(self.text)}["DRP-17"]
        expected = (
            ("malformed or incomplete", "permanent",
             "A malformed or incomplete payout binding is `permanent`."),
            ("destination mismatch, or PB-2 tier-2 resolving to a different address", "counterparty",
             "A PB-1 destination mismatch, or a PB-2 tier-2 resolution to a different address, is `counterparty`."),
            ("applicable-but-unresolvable", "substrate",
             "A PB-2 applicable-but-unresolvable binding is `substrate`."),
        )
        self.assertEqual(len(modes), len(expected), modes)
        for mode, (trigger, error_class, statement) in zip(modes, expected):
            self.assertIn(trigger, mode)
            self.assertEqual(re.findall(r"`(permanent|counterparty|substrate)`", mode)[0], error_class, mode)
            self.assertIn(statement, rule)
        r42 = {c["id"]: c for c in self.validator.parse_cases(self.text)}["R42"]
        self.assertIn("A PB-1 payout destination mismatch classified `permanent`", r42["description"])
        self.assertEqual(r42["expected"], ["fail"])
        self.assertLessEqual({"DRP-17", "DRA-20"}, set(r42["rules"]))

    def spec_rules_at_pin(self) -> dict[str, str]:
        """Every labelled spec rule at the pin, `- (ID)` or `- **(ID)**`, with its wrapped lines."""
        pin = self.validator.checked_against(self.text)
        files = git("ls-tree", "--name-only", f"{pin}:spec").stdout.split()
        rules: dict[str, str] = {}
        for name in (f for f in files if f.endswith(".md")):
            current = None
            for line in self.spec_at_pin(f"spec/{name}").splitlines():
                match = SPEC_RULE_LABEL_RE.match(line)
                if match:
                    current = match.group(1)
                    rules[current] = line
                elif current and line.startswith("  ") and line.strip():
                    rules[current] += " " + line.strip()
                else:
                    current = None
        return rules

    def test_spec_rule_label_matches_plain_and_bold_labels(self):
        self.assertEqual(SPEC_RULE_LABEL_RE.match("- (RD-1) sign the rail").group(1), "RD-1")
        self.assertEqual(SPEC_RULE_LABEL_RE.match("- **(FV-1) Exact rail authority.** A").group(1), "FV-1")
        self.assertEqual(SPEC_RULE_LABEL_RE.match("- **(MTR-5)** a transacting reader").group(1), "MTR-5")
        self.assertIsNone(SPEC_RULE_LABEL_RE.match("See (FV-1) for details."))

    # Sweeps 8 and 9: every spec rule that verifies or reads a rail definition's steward
    # signature is one DRR-2 adapts, whatever its label form or wording; otherwise LRR-2,
    # LRR-3 or FV-1 rejects every correctly signed job-escrow rail.
    @unittest.skipIf(SHALLOW, SHALLOW_REASON)
    def test_every_rail_domain_rule_is_adapted_for_the_job_escrow_rail(self):
        steward = re.compile(r"steward signature|steward-signed rail")
        named = {
            rule_id for rule_id, text in self.spec_rules_at_pin().items()
            if "dacs-rail:v1:" in text or (steward.search(text) and re.search(r"\brail", text))
        }
        # A new reader of the rail record at a later pin must be added to DRR-2 (DRG-2 re-audit).
        self.assertEqual(named, {"RD-1", "LRR-2", "LRR-3", "RAV-R5", "FV-1"})
        rules = {r["id"]: r["text"] for r in self.validator.parse_rules(self.text)}
        self.assertTrue(rules["DRR-2"].startswith("RD-1 through RD-7 apply"))
        for rule_id in named - {"RD-1"}:
            self.assertIn(rule_id, rules["DRR-2"])
        self.assertIn("step 3 of the DACS-4 §9.4.3 consumer resolution", rules["DRR-2"])
        self.assertIn('signed under `"dacs-rail:v1:"` does not verify and MUST yield `fail`', rules["DRR-2"])
        self.assertNotIn("unchanged", rules["DRR-5"])
        r21 = {c["id"]: c for c in self.validator.parse_cases(self.text)}["R21"]
        self.assertIn('a `JobEscrowRailDefinition` signed under `"dacs-rail:v1:"`', r21["description"])
        self.assertIn("fail", r21["expected"])
        self.assertIn("DRR-2", r21["rules"])

    # Sweep 9: FV-1 and FV-2 read finality-bound evidence members that the job-escrow
    # artifacts do not carry, so DRF-9 must say what each one means for this profile.
    @unittest.skipIf(SHALLOW, SHALLOW_REASON)
    def test_fv1_and_fv2_members_are_mapped_for_job_escrow_evidence(self):
        spec_rules = self.spec_rules_at_pin()
        rules = {r["id"]: r["text"] for r in self.validator.parse_rules(self.text)}
        self.assertIn("FV-1 through FV-10", rules["DRF-8"])
        for member, rule_id in (
            ("`finalityBoundEvidenceVersion`", "FV-1"),
            ("`railDefinitionRef`", "FV-1"),
            ("`evidence.phase`", "FV-1"),
            ("steward signature", "FV-1"),
            ("equal the reference", "FV-1"),
            ("`settlementFinality", "FV-2"),
        ):
            self.assertIn(member, spec_rules[rule_id], (rule_id, member))
            self.assertIn(member, rules["DRF-9"], member)
        for mapping in (
            "by the artifact's own version member under DRV-8",
            "Its `railDefinitionRef` is the overlay's `railDefinitionRef`",
            "FV-1's requirement to equal the reference reads its `railId` and `railVersion` members",
            "`railId` and `railVersion` MUST equal the reference's and those of the selected",
            'under the DRR-2 domain `"dacs-x-job-escrow-rail:v1:"`',
            "the resolved `phaseHandler` MUST equal `x-job-escrow`",
            "the artifact's `finality` member",
        ):
            self.assertIn(mapping, rules["DRF-9"])
        cases = {c["id"]: c for c in self.validator.parse_cases(self.text)}
        self.assertIn("DRF-9", cases["R21"]["rules"])
        self.assertIn("other than the overlay's `railDefinitionRef`", cases["R21"]["description"])
        self.assertIn("DRF-9", cases["I1"]["rules"])

    # Sweep 10: FV-1 compares (railId, railVersion) with the reference, so the reference must
    # be the DACS-4 RailDefinitionRef, and the optional PaymentRailRef.railVersion is required.
    @unittest.skipIf(SHALLOW, SHALLOW_REASON)
    def test_rail_definition_refs_carry_what_fv1_compares(self):
        settle = self.spec_at_pin("spec/DACS-4-SETTLE.md")
        reference = re.search(r"^type RailDefinitionRef = AttestationRef & \{\n(.*?)^\}", settle, re.M | re.S)
        self.assertIsNotNone(reference)
        self.assertEqual(re.findall(r"^\s+(\w+):", reference.group(1), re.M), ["railId", "railVersion"])
        self.assertIn("railDefinitionRef: RailDefinitionRef", settle)
        self.assertRegex(settle, r"(?m)^\s+railVersion\?: number")
        types = dict(self.validator.type_bodies(self.text))
        for name in ("DeliveryOrRemedyAgreement", "EscrowJobRef"):
            self.assertIn("  railDefinitionRef: RailDefinitionRef", types[name], name)
        self.assertNotIn("railDefinitionRef: AttestationRef", self.text)
        rules = {r["id"]: r["text"] for r in self.validator.parse_rules(self.text)}
        self.assertIn("a job-escrow `PaymentRailRef` without `railVersion` MUST yield `error`", rules["DRR-3"])
        self.assertIn("a `terms.rail` without the `railVersion` that DRR-3 requires MUST yield `error`", rules["DRA-22"])
        r21 = {c["id"]: c for c in self.validator.parse_cases(self.text)}["R21"]
        self.assertIn("A `railDefinitionRef` whose `railVersion` differs from the resolved definition's",
                      r21["description"])
        self.assertIn("a selected `PaymentRailRef` or `terms.rail` without `railVersion`", r21["description"])
        self.assertIn("and the missing `railVersion`; `fail` otherwise", r21["expectedText"])
        self.assertLessEqual({"DRR-3", "DRA-22", "DRF-9"}, set(r21["rules"]))

    # Sweep 9: the candidate's commit step is none of the five DACS-3 commitment kinds,
    # so every DACS-3 rule that reads the agreement commitment phase must be adapted.
    @unittest.skipIf(SHALLOW, SHALLOW_REASON)
    def test_every_commitment_phase_reader_is_adapted_for_the_commit_step(self):
        readers = {
            rule_id for rule_id, text in self.spec_rules_at_pin().items()
            if re.search(r"agreement commitment phase", text, re.I)
        }
        # A new reader at a later pin must be added to DRP-18 (DRG-2 re-audit).
        self.assertEqual(readers, {"PS-2", "CA-1", "MTR-5", "RFQ-3", "SE-8"})
        rules = {r["id"]: r["text"] for r in self.validator.parse_rules(self.text)}
        for rule_id in readers:
            self.assertIn(rule_id, rules["DRP-18"])
        # The §8.5.2 validation before check 1 is unlabelled prose with the same five-kind gate.
        negotiate = self.spec_at_pin("spec/DACS-3-NEGOTIATE.md")
        self.assertIn("exactly one recognized negotiation phase and exactly one\nof the five agreement commitment phases",
                      negotiate)
        for clause in (
            "the §8.5.2 validation before check 1, check 9",
            "MUST treat the one `x-commit-delivery-or-remedy-agreement` step as that phase",
            "the commit step MUST immediately follow the single `negotiate-*` step",
        ):
            self.assertIn(clause, rules["DRP-18"])
        sketch = self.text.split("```text\n", 2)[1]
        self.assertTrue(sketch.startswith("negotiate-*\nx-commit-delivery-or-remedy-agreement "), sketch)
        r20 = {c["id"]: c for c in self.validator.parse_cases(self.text)}["R20"]
        self.assertIn("DRP-18", r20["rules"])
        self.assertIn("a commit step that does not immediately follow the negotiation", r20["description"])

    @staticmethod
    def cited_rules(text: str) -> set[str]:
        """Candidate rule IDs a text cites, with every "X through Y" range expanded."""
        cited = set(re.findall(r"\bDR[A-Z]+-\d+\b", text))
        for start, end in re.findall(r"\b(DR[A-Z]+-\d+) through (DR[A-Z]+-\d+)\b", text):
            family, first = start.rsplit("-", 1)
            if end.rsplit("-", 1)[0] == family:
                cited |= {f"{family}-{n}" for n in range(int(first), int(end.rsplit("-", 1)[1]) + 1)}
        return cited

    def implementation_duties_outside_the_gate(self, text: str) -> list[str]:
        """Rules that bind the selected implementation but are not in the capabilityProfile."""
        rules = {r["id"]: r["text"] for r in self.validator.parse_rules(text)}
        meaning = re.search(r"`capabilityProfile` `dacs-delivery-gate-v1` means ([^.]+)\.", rules["DRC-14"])
        self.assertIsNotNone(meaning, rules["DRC-14"])
        gate = self.cited_rules(meaning.group(1))
        # A duty that a gate member restates by citing it is gated too.
        cited = {ref for member in gate for ref in self.cited_rules(rules.get(member, ""))}
        duty = re.compile(r"\b[Ss]elected (implementation|contract) MUST\b")
        return sorted(rule_id for rule_id, body in rules.items()
                      if duty.search(body) and rule_id not in gate | cited)

    # Sweep 9: an obligation on the selected implementation is a deployment capability, so
    # an eligible deployment must prove it; DRD-13's status-bound `reject` was left out.
    def test_every_implementation_duty_is_in_the_capability_gate(self):
        self.assertEqual(self.implementation_duties_outside_the_gate(self.text), [])
        ungated = mutate(self.text, "means DRC-1 through DRC-13, DRC-22, DRC-23, and DREB-24.",
                         "means DRC-1 through DRC-13 and DREB-24.")
        self.assertEqual(self.implementation_duties_outside_the_gate(ungated), ["DRC-22", "DRC-23", "DRD-13"])
        # §8.4 and §12 state the same eligibility range, which reaches the last DRC rule.
        last = max(int(r["id"].rsplit("-", 1)[1]) for r in self.validator.parse_rules(self.text)
                   if r["id"].startswith("DRC-"))
        ranges = re.findall(r"(?:independently prove|satisfying) DRC-1 through DRC-(\d+) and DREB-24", self.text)
        self.assertEqual(ranges, [str(last), str(last)])
        self.assertIn("with no expected prior status, so a pre-submission rejection can execute after a native "
                      "`submit` (DRD-13, DRC-22)", self.text)
        cases = {c["id"]: c for c in self.validator.parse_cases(self.text)}
        self.assertIn("DRC-22", cases["R10"]["rules"])
        self.assertIn("executes against `Submitted` for a decision issued against `Funded`", cases["R10"]["description"])

    # Sweep 9: DRR-5 imports RAV-R2, which forbids `mocked` only for a production session
    # and lets trusted local policy configure non-production use.
    @unittest.skipIf(SHALLOW, SHALLOW_REASON)
    def test_mocked_rail_case_follows_the_rav_r2_production_split(self):
        rav_r2 = self.spec_rules_at_pin()["RAV-R2"]
        self.assertIn("For a new production session, it additionally MUST NOT select a rail with availability `mocked`",
                      rav_r2)
        r37 = {c["id"]: c for c in self.validator.parse_cases(self.text)}["R37"]
        self.assertNotIn("`mocked` rail selected, or", r37["description"])
        self.assertNotIn("`failed`, or `mocked`", r37["description"])
        self.assertIn("A `mocked` rail selected for a production session", r37["description"])
        self.assertIn("instead of trusted local policy (RAV-R2)", r37["description"])
        self.assertIn("DRR-5", r37["rules"])

    # DRG-3: every registry name the candidate introduces uses the CORE §B.6 `x-` form.
    def test_candidate_registry_names_use_the_x_form(self):
        literals = re.findall(r'^\s+(?:railType|phaseHandler): ("[^"]+")', self.text, re.M)
        for name, lines in self.validator.type_bodies(self.text):
            if name.endswith("PhaseStep"):
                literals += re.findall(r'^\s+kind: ("[^"]+")', "\n".join(lines), re.M)
        self.assertEqual(len(literals), 4, literals)
        for literal in literals:
            self.assertTrue(literal.startswith('"x-'), literal)
        addresses = dict(self.validator.sections(self.text))["6.5 Candidate logical addresses"]
        rows = re.findall(r"^\| `[A-Za-z]+` \| `([^`]+)` \|$", addresses, re.M)
        self.assertEqual(len(rows), 9)
        for address in rows:
            self.assertTrue(address.startswith("dacs4:x-job-escrow:"), address)

    # Sweep 8: an unsupported version of any signed artifact is `error` before hashing.
    def test_every_signed_version_member_has_a_refusal_rule_and_case(self):
        rules = {r["id"]: r for r in self.validator.parse_rules(self.text)}
        cases = [c for c in self.validator.parse_cases(self.text) if "DRV-8" in c["rules"]]
        self.assertTrue(rules["DRV-8"]["requirement"])
        self.assertIn("MUST yield `error` under step 1 before any hash or signature check", rules["DRV-8"]["text"])
        for member, _operand in self.validator.SIGNED_TYPES.values():
            self.assertIn(f"`{member}`", rules["DRV-8"]["text"], member)
            self.assertTrue(any(f"`{member}`" in c["description"] and c["expected"] == ["error"] for c in cases),
                            member)
        for text in [rules["DRV-8"]["text"]] + [c["description"] for c in cases]:
            self.assertIn("`railType` is not `x-evm-erc8183`", text)

    # Sweep 8: a case that lists a rule describes a violation of the clause it is listed for.
    def test_clause_level_sub_cases_list_their_rules(self):
        cases = {c["id"]: c for c in self.validator.parse_cases(self.text)}
        for case_id, rule_id, clause in (
            ("R6", "DRA-8", "whose hash differs from `requirementHash`"),
            ("R6", "DRA-8", "composite result that does not meet that requirement"),
            ("R22", "DRA-4", "resolves but fails verification"),
            ("I1", "DRA-4", "EVM account claim that cannot be resolved"),
            ("R3", "DRJ-4", "through an intermediary contract"),
            ("R3", "DRJ-4", "taken from `getJob` or an `eth_call`"),
            ("R25", "DRE-8", "a rule whose `jobId` differs from the overlay's"),
            ("R25", "DRE-8", "a rule finalized after the overlay"),
            ("R20", "DRP-13", "An older reader that drops either `x-job-escrow` step"),
            ("R29", "DRX-5", "names the agreement party the finding does not fault"),
            ("R1", "DRA-20", "one keyed at `terminalPhaseIndex`"),
            ("R35", "DRQ-3", "on the authority of `public-evidence-only`"),
            ("R37", "DRR-5", 'read from a `"dacs-rail:v1:"` record'),
            ("I1", "DRR-3", "holds no registry snapshot named by a CORE §B.6 out-of-band agreement"),
        ):
            self.assertIn(rule_id, cases[case_id]["rules"], case_id)
            self.assertIn(clause, cases[case_id]["description"], (case_id, rule_id))
        # R28 tests time units and freshness, so it no longer stands in for DRA-8.
        self.assertNotIn("DRA-8", cases["R28"]["rules"])
        rules = {r["id"]: r for r in self.validator.parse_rules(self.text)}
        self.assertTrue(rules["DRQ-3"]["requirement"])

    # Sweep 8: selectors, topics, and log layout rest on a pinned ABI specification, and
    # keccak-256 is the Ethereum function, which differs from FIPS 202 SHA3-256.
    def test_abi_specification_and_keccak_are_pinned(self):
        lines = self.text.splitlines()
        self.assertEqual(self.validator.external_pin_errors(lines), [])
        start = lines.index(self.validator.EXTERNAL_PINS_HEADING) + 2
        pins = lines[start:lines.index("", start)]
        abi = "https://github.com/ethereum/solidity/blob/f401782df49be312ea4ef52a2d467cf5183b5906/docs/abi-spec.rst"
        self.assertTrue(any(f"]({abi})" in line for line in pins), pins)
        empty_code_hash = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        self.assertIn(f"keccak-256 of empty input is the DRW-2 empty-code hash `{empty_code_hash}`", self.text)
        rules = {r["id"]: r["text"] for r in self.validator.parse_rules(self.text)}
        self.assertIn(empty_code_hash, rules["DRW-2"])
        self.assertNotEqual("0x" + hashlib.sha3_256(b"").hexdigest(), empty_code_hash)
        # Sweep 10: ERC-20 and EIP-161 are relied on by DRC-8, DRF-3 and DRW-2, so they are pinned too.
        for pinned in ("https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-20.md",
                       "https://github.com/ethereum/EIPs/blob/c1a1eb21b465c9c42704a8a5743ad0694aedbff7/EIPS/eip-161.md"):
            self.assertTrue(any(f"]({pinned})" in line for line in pins), pinned)

    def signed_type_members(self, text: str) -> dict[str, list[str]]:
        """Top-level members of every signed type, read from its type block."""
        members: dict[str, list[str]] = {}
        for name, lines in self.validator.type_bodies(text):
            if name in self.validator.SIGNED_TYPES:
                members[name] = [m.group(1) for m in map(re.compile(r"^  ([A-Za-z]+)\??: ").match, lines)
                                 if m and m.group(1) not in ("signature", "signatures")]
        return members

    def unnamed_members(self, text: str) -> list[str]:
        """Signed-type members that no labelled rule names, as `m`, `m.<path>`, or `<Type>.m`."""
        rules = "\n".join(r["text"] for r in self.validator.parse_rules(text))
        return [f"{name}.{member}" for name, members in self.signed_type_members(text).items() for member in members
                if not re.search(rf"`(?:{member}|{member}\.[^`]*|[A-Za-z]+\.{member})`", rules)]

    # Sweep 10: a member of a signed artifact that no rule names is a field nothing compares.
    # Derived from the type blocks, so a member added later must be bound by a rule.
    def test_every_signed_type_member_is_named_by_a_rule(self):
        self.assertEqual(self.unnamed_members(self.text), [])
        extra = mutate(self.text, '  disposition: "release-to-provider" | "refund-to-client"\n  signature: ComponentSignature\n',
                       '  disposition: "release-to-provider" | "refund-to-client"\n  extraBinding: string\n'
                       "  signature: ComponentSignature\n")
        self.assertEqual(self.unnamed_members(extra), ["EscrowDecision.extraBinding"])

    def unbound_job_artifacts(self, text: str) -> list[str]:
        """Signed types that carry a job binding member but are not named by DRV-9."""
        binding = ("jobId", "deliveryOrRemedyAgreementHash", "escrowJobRef")
        # The overlay is the binding itself, and the rail is not job-specific.
        exempt = {"DeliveryOrRemedyAgreement", "JobEscrowRailDefinition"}
        drv9 = {r["id"]: r["text"] for r in self.validator.parse_rules(text)}["DRV-9"]
        for member in binding:
            self.assertIn(f"`{member}`", drv9, member)
        return sorted(name for name, members in self.signed_type_members(text).items()
                      if name not in exempt and set(members) & set(binding) and f"`{name}`" not in drv9)

    # Sweep 10: every artifact's jobId, overlay hash and escrowJobRef are compared with the job
    # under verification, so another job's evaluation or decision cannot authorize this one.
    def test_every_job_bound_artifact_is_compared_with_the_job(self):
        self.assertEqual(self.unbound_job_artifacts(self.text), [])
        self.assertEqual(self.unbound_job_artifacts(mutate(self.text, "`ExecutionEvaluation`, `EscrowDecision`, `DisputeCase`",
                                                           "`EscrowDecision`, `DisputeCase`")),
                         ["ExecutionEvaluation"])
        rules = {r["id"]: r["text"] for r in self.validator.parse_rules(self.text)}
        self.assertIn("A mismatch MUST yield `fail`", rules["DRV-9"])
        r4 = {c["id"]: c for c in self.validator.parse_cases(self.text)}["R4"]
        self.assertIn("DRV-9", r4["rules"])
        self.assertIn("names another job that is not yet terminal", r4["description"])
        self.assertEqual(r4["expected"], ["fail"])

    # Sweep 10: canonical ERC-8183 events carry no token and DRC-18 decodes only pinned events,
    # so the token comes from one contract-wide pin that the capability gate covers.
    def test_token_identity_comes_from_the_contract_pin(self):
        rules = {r["id"]: r["text"] for r in self.validator.parse_rules(self.text)}
        self.assertIn("MUST NOT let any caller choose or change a job's token", rules["DRC-23"])
        self.assertIn("`parameters.paymentToken`", rules["DRC-23"])
        for rule_id in ("DRF-2", "DREB-11", "DRT-4"):
            self.assertIn("DRC-23 contract token", rules[rule_id], rule_id)
        self.assertNotIn("token", rules["DRT-4"].split(".")[0])
        self.assertNotIn("DRC-23", self.implementation_duties_outside_the_gate(self.text))
        self.assertIn("set by `setBudget(jobId, token, amount, optParams)` and announced only in `BudgetSet`", self.text)
        r10 = {c["id"]: c for c in self.validator.parse_cases(self.text)}["R10"]
        self.assertIn("lets a caller choose or change a job's payment token", r10["description"])
        self.assertLessEqual({"DRC-23", "DRF-2", "DREB-11"}, set(r10["rules"]))

    # Sweep 10: a rule is covered only by a case that fails its violation.
    def test_retry_and_refund_rules_have_violating_cases(self):
        cases = {c["id"]: c for c in self.validator.parse_cases(self.text)}
        self.assertEqual(cases["R46"]["rules"], ["DRV-5"])
        self.assertEqual(cases["R46"]["expected"], ["fail"])
        self.assertIn("before reconciling the original native job and action", cases["R46"]["description"])
        self.assertIn("A refund move without the full-budget `Refunded` event", cases["R24"]["description"])
        self.assertIn("DRL-11", cases["R24"]["rules"])
        self.assertIn("Terminal evidence whose `terminalState` differs", cases["R24"]["description"])
        self.assertIn("DRL-10", cases["R24"]["rules"])
        self.assertIn("A first revision other than zero", cases["R29"]["description"])
        self.assertLessEqual({"DRAA-7", "DRX-10"}, set(cases["R29"]["rules"]))

    # Sweep 10: the candidate has no executable oracle, so nothing outside it may claim its
    # names or domains. A spec/ file, MANIFEST row, vector, or implementation manifest that
    # did would let an implementation be presented as conforming to unchecked MUSTs.
    def test_no_conformance_artifact_claims_the_candidate_profile(self):
        self.assertEqual(json.loads(MATRIX.read_text(encoding="utf-8"))["executableVectorCount"], 0)
        domains = [entry["domain"] for entry in self.validator.signing_domains(self.text)[0]]
        names = ["x-commit-delivery-or-remedy-agreement", "x-job-escrow", "x-evm-erc8183", *domains]
        for name in names:
            self.assertIn(name, self.text, name)
        claims = []
        for path in sorted([*(ROOT / "spec").rglob("*"), *(ROOT / "conformance").rglob("*")]):
            if not path.is_file() or MATRIX.parent in path.parents:
                continue
            content = path.read_bytes().decode("utf-8", errors="replace")
            claims += [f"{path.relative_to(ROOT)}: {name}" for name in names if name in content]
        self.assertEqual(claims, [])

    # Sweep 10: DRV-8 fixes the value, so a type bumped together with its domain is refused.
    def test_version_member_value_must_be_the_drv8_value(self):
        text = mutate(self.text, '  escrowDecisionVersion: "1"', '  escrowDecisionVersion: "2"')
        text = mutate(text, '"dacs-x-escrow-decision:v1:"', '"dacs-x-escrow-decision:v2:"')
        self.assertEqual(self.validator.signing_domains(text)[1],
                         ['signed type EscrowDecision version escrowDecisionVersion must be "1" (DRV-8)'])
        self.assertEqual(self.validator.SIGNED_TYPE_VERSION, "1")
        rules = {r["id"]: r["text"] for r in self.validator.parse_rules(self.text)}
        self.assertIn('with the value `"1"`', rules["DRV-8"])

    # Sweep 10 (P3): branches that surviving mutants showed no test reached.
    def test_rejected_result_token_is_refused(self):
        self.assert_structural(
            mutate(self.text, "5. Return `indeterminate` when", "5. Return `rejected` when"),
            "non-DACS verifier result `rejected` used",
        )

    def test_shall_and_required_are_requirements(self):
        for keyword in ("SHALL", "SHALL NOT", "REQUIRED"):
            rule = self.validator.parse_rules(f"- (DRZ-1) The binding {keyword} hold.\n")[0]
            self.assertEqual(rule["keywords"], [keyword])
            self.assertTrue(rule["requirement"], keyword)
        self.assertFalse(self.validator.parse_rules("- (DRZ-1) The binding SHOULD hold.\n")[0]["requirement"])

    def test_family_gaps_at_the_first_and_second_to_last_number(self):
        rules = [l for l in self.text.splitlines() if l.startswith("- (DRA-")]
        for removed, gap in ((rules[0], "DRA-1"), (rules[-2], f"DRA-{len(rules) - 1}")):
            errors = self.structural_errors(mutate(self.text, removed + "\n", ""))
            self.assertIn(f"rule family DRA has gaps: {gap}", errors)
        rejection = [l for l in self.text.splitlines() if l.startswith("- **R")]
        for removed, gap in ((rejection[0], "R1"), (rejection[-2], f"R{len(rejection) - 1}")):
            errors = self.structural_errors(mutate(self.text, removed + "\n", ""))
            self.assertIn(f"case family R has gaps: {gap}", errors)

    def test_first_external_pin_item_directly_under_the_heading_is_checked(self):
        lines = ["**External pins:**", "- ERC at [`x`](https://github.com/o/r/blob/master/f.md);", ""]
        self.assertEqual(self.validator.external_pin_errors(lines),
                         ["external pin https://github.com/o/r/blob/master/f.md does not link to a 40-hex commit"])

    def test_fenced_heading_does_not_start_a_section(self):
        text = "intro\n```text\n## Not a heading\n```\n## Real\nbody\n"
        self.assertEqual([heading for heading, _body in self.validator.sections(text)], ["preamble", "Real"])

    def test_status_line_is_the_third_line(self):
        spec_text = self.validator.specsource.spec_text(ROOT)
        status = "status line must remain 'pre-normative review candidate' until executable vectors exist"
        self.assertNotIn(status, self.validator.validate_text(f"# T\n\n{self.validator.STATUS_PREFIX}\n", spec_text))
        self.assertIn(status, self.validator.validate_text(f"# T\n{self.validator.STATUS_PREFIX}\n", spec_text))

    def test_messages_name_the_document_line(self):
        text = mutate(self.text, "DRP-13 states what it must not do instead.\n", "It MUST NOT strip either phase.\n")
        number = next(n for n, line in enumerate(text.splitlines(), start=1) if "It MUST NOT strip either phase." in line)
        self.assertIn(f"line {number}: capitalized requirement keyword outside a labelled rule",
                      self.structural_errors(text))

    # A later spec/ PR on `next` that does not revise the candidate must not fail
    # these tests: only the pin check may see spec/, and it pins the committed revision.
    @unittest.skipIf(SHALLOW, SHALLOW_REASON)
    def test_scratch_copies_ignore_a_later_spec_change(self):
        if self.validator.candidate_revision(git, ROOT, DOC) is None:
            self.skipTest("the candidate has uncommitted edits, so the working tree is its revision")
        pin = self.validator.checked_against(self.text)
        real_run = subprocess.run

        def run(cmd, *args, **kwargs):
            # Only the working tree's spec/ differs from the pin, as on `next` after a spec/ PR.
            if cmd[3:] == ["diff", "--quiet", pin, "--", "spec/"]:
                return subprocess.CompletedProcess(cmd, 1, "", "")
            return real_run(cmd, *args, **kwargs)

        drifted = (f"spec/ differs from the **Checked against** commit {pin} at the working tree; "
                   "re-audit every cited rule and update the pin (DRG-2)")
        with mock.patch.object(self.validator.subprocess, "run", run):
            with TemporaryDirectory() as tmp:
                doc = Path(tmp) / "candidate.md"
                doc.write_text(self.text, encoding="utf-8")
                self.assertEqual(self.validator.validate(doc, None), [drifted])
            self.assertEqual(self.validator.validate(), [])
            self.assertEqual(self.structural_errors(self.text), [])
            self.assert_stale_only(mutate(self.text, "(DRL-7) Value MUST NOT reach", "(DRL-7) Value MAY reach"))
            with TemporaryDirectory() as tmp, as_committed_candidate(self.validator):
                doc = Path(tmp) / "candidate.md"
                doc.write_text(self.text, encoding="utf-8")
                matrix = Path(tmp) / "matrix.json"
                self.assertEqual(run_main(self.validator, "--doc", str(doc), "--matrix", str(matrix), "--write"), (0, ""))

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

    def test_unknown_substrate_capability_is_rejected(self):
        text = mutate(self.text, "job reference through SR-2.", "job reference through SR-99.")
        self.assert_structural(text, "reference to substrate capability SR-99 that spec/ does not define")

    def test_candidate_cannot_define_its_own_substrate_capability(self):
        text = mutate(self.text, "job reference through SR-2.", "job reference through SR-99.")
        text += "\n| SR-99 | Candidate-only capability | Unregistered | DACS-4 |\n"
        self.assert_structural(text, "reference to substrate capability SR-99 that spec/ does not define")

    def test_inline_code_substrate_capability_is_rejected(self):
        text = mutate(self.text, "job reference through SR-2.", "job reference through `SR-99`.")
        self.assert_structural(text, "reference to substrate capability SR-99 that spec/ does not define")

    def test_example_capability_row_in_spec_does_not_define_a_capability(self):
        spec_text = self.validator.specsource.spec_text(ROOT) + (
            "\n```text\n| SR-99 | invalid example |\n```\n\n| SR-98 | unrelated table |\n"
        )
        capability_errors = [
            e for e in self.validator.validate_text(self.text, spec_text) if "substrate capability" in e
        ]
        self.assertEqual(capability_errors, [])
        text = mutate(self.text, "job reference through SR-2.", "job reference through SR-99 and `SR-98`.")
        errors = self.validator.validate_text(text, spec_text)
        for capability in ("SR-98", "SR-99"):
            self.assertTrue(
                any(f"reference to substrate capability {capability} that spec/ does not define" in e for e in errors),
                errors,
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

    # Sweep 8: RFC 2119 RECOMMENDED and OPTIONAL, and RFC 8174 NOT RECOMMENDED, are keywords too.
    def test_recommended_and_optional_are_requirement_keywords(self):
        for keyword in ("RECOMMENDED", "NOT RECOMMENDED", "OPTIONAL"):
            self.assert_structural(
                mutate(self.text, "DRP-13 states what it must not do instead.\n",
                       f"Stripping either phase is {keyword}.\n"),
                "capitalized requirement keyword outside a labelled rule",
            )
        rule = self.validator.parse_rules("- (DRX-1) Stripping either phase is NOT RECOMMENDED.\n")[0]
        self.assertEqual(rule["keywords"], ["NOT RECOMMENDED"])
        self.assertFalse(rule["requirement"])

    def test_candidate_cannot_claim_normative_status_or_drop_revision_pin(self):
        self.assert_structural(
            mutate(self.text, "**Status:** pre-normative review candidate", "**Status:** normative"),
            "status line must remain 'pre-normative review candidate'",
        )
        pin = self.validator.checked_against(self.text)
        self.assert_structural(
            mutate(self.text, f"`next` at `{pin}`", f"`next` at `{pin[:6]}`"),
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
    @unittest.skipIf(SHALLOW, SHALLOW_REASON)
    def test_wrong_well_formed_pin_is_rejected(self):
        pin = self.validator.checked_against(self.text)
        self.assert_structural(
            mutate(self.text, f"`next` at `{pin}`", "`next` at `" + "0" * 40 + "`"),
            f"**Checked against** commit {'0' * 40} is not a commit in this repository",
        )

    @unittest.skipIf(SHALLOW, SHALLOW_REASON)
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
        revision = self.validator.candidate_revision(git, ROOT, DOC)
        where = "the working tree" if revision is None else f"commit {revision}, the candidate's latest revision"
        self.assert_structural(
            mutate(self.text, f"`next` at `{pin}`", f"`next` at `{older}`"),
            f"spec/ differs from the **Checked against** commit {older} at {where}",
        )

    def test_external_pin_must_link_to_a_commit(self):
        self.assert_structural(
            mutate(self.text, "ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-55.md",
                   "ERCs/blob/master/ERCS/erc-55.md"),
            "external pin https://github.com/ethereum/ERCs/blob/master/ERCS/erc-55.md does not link to a 40-hex commit",
        )
        self.assert_structural(
            mutate(self.text, "ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-55.md",
                   "ERCs/blob/a078cab/ERCS/erc-55.md"),
            "external pin https://github.com/ethereum/ERCs/blob/a078cab/ERCS/erc-55.md does not link to a 40-hex commit",
        )

    # Sweep 9: a wrapped item continues the list, so links after it are still checked.
    def test_wrapped_external_pin_item_does_not_end_the_list(self):
        wrapped = mutate(self.text, "- EIP-1271 at [`ethereum/ERCs@a078cab`]", "- EIP-1271 at\n  [`ethereum/ERCs@a078cab`]")
        self.assertEqual(self.validator.external_pin_errors(wrapped.splitlines()), [])
        unpinned = mutate(wrapped, "ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-2771.md",
                          "ERCs/blob/master/ERCS/erc-2771.md")
        self.assert_structural(
            unpinned,
            "external pin https://github.com/ethereum/ERCs/blob/master/ERCS/erc-2771.md does not link to a 40-hex commit",
        )
        wrapped_link = mutate(self.text, "- EIP-1271 at [`ethereum/ERCs@a078cab`](https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-1271.md);",
                              "- EIP-1271 at\n  [`ethereum/ERCs@master`](https://github.com/ethereum/ERCs/blob/master/ERCS/erc-1271.md);")
        self.assert_structural(
            wrapped_link,
            "external pin https://github.com/ethereum/ERCs/blob/master/ERCS/erc-1271.md does not link to a 40-hex commit",
        )

    # Sweep 9: the ABI-pin literal, the External pins entry, and the §8 link name one ERC-8183 text.
    def test_canonical_erc_revision_must_match_the_erc8183_pin(self):
        self.assertEqual(self.validator.erc8183_revision_errors(self.text), [])
        other = "1" * 40
        self.assert_structural(
            mutate(self.text, 'canonicalErcRevision: "ethereum/ERCs@a078cab5cc8e9581c15f76c091ed96eed28f02f7"',
                   f'canonicalErcRevision: "ethereum/ERCs@{other}"'),
            f"ERC-8183 links and canonicalErcRevision name different commits: {other}, "
            "a078cab5cc8e9581c15f76c091ed96eed28f02f7",
        )
        section8 = "The first binding composes the canonical ERC-8183 interface at [`ethereum/ERCs@a078cab`](https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-8183.md)."
        self.assert_structural(
            mutate(self.text, section8, section8.replace("a078cab5cc8e9581c15f76c091ed96eed28f02f7", other)),
            "ERC-8183 links and canonicalErcRevision name different commits",
        )
        self.assert_structural(
            mutate(self.text, '  canonicalErcRevision: "ethereum/ERCs@a078cab5cc8e9581c15f76c091ed96eed28f02f7"\n', ""),
            "expected exactly one canonicalErcRevision literal, found 0",
        )
        self.assertEqual(
            self.validator.erc8183_revision_errors(self.text.replace("/ERCS/erc-8183.md", "/ERCS/erc-8183-draft.md")),
            ["no commit-pinned link to canonical ERC-8183 (ethereum/ERCs .../ERCS/erc-8183.md)"],
        )

    # Sweep 9: both validators treat ``` and ~~~ fences, indented or not, as code.
    def test_tilde_and_indented_fences_are_code(self):
        for fence in ("~~~", "  ```", "   ~~~"):
            fenced = f"{fence}text\n- (DRZ-1) A fenced line MUST NOT count.\n{fence}\n"
            self.assertEqual(self.validator.parse_rules(fenced), [], fence)
            self.assertEqual(self.validator.split_lines(fenced)[1][2], True, fence)
        text = mutate(self.text, "### 6.5 Candidate logical addresses\n",
                      "~~~text\n- (DRZ-1) An example inside a tilde fence MUST NOT count.\n~~~\n\n"
                      "### 6.5 Candidate logical addresses\n")
        self.assertNotIn("DRZ-1", [r["id"] for r in self.validator.parse_rules(text)])
        self.assertEqual(self.structural_errors(text), [])
        for line, expected in (("```", True), ("~~~text", True), ("    ```", True), ("text ```", False), ("- ~", False)):
            self.assertEqual(self.validator.validate_rule_ids.is_fence(line), expected, line)

    def test_missing_or_empty_external_pin_list(self):
        self.assert_structural(
            mutate(self.text, "**External pins:**\n", "**Pins:**\n"),
            "missing '**External pins:**' list",
        )
        start = self.text.index("**External pins:**\n")
        end = self.text.index("**Roadmap gates")
        self.assert_structural(
            self.text[:start] + "**External pins:**\n\n" + self.text[end:],
            "'**External pins:**' list is empty",
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

    def test_signed_type_without_signature_member_is_rejected(self):
        self.assert_structural(
            mutate(self.text, '  disposition: "release-to-provider" | "refund-to-client"\n  signature: ComponentSignature\n',
                   '  disposition: "release-to-provider" | "refund-to-client"\n'),
            "signed type EscrowDecision has no signature member",
        )

    def test_signed_type_missing_or_defined_twice_is_rejected(self):
        self.assert_structural(
            mutate(self.text, "type DisputeCase = {", "type DisputeCaseDraft = {"),
            "signed type DisputeCase is not defined",
        )
        start = self.text.index("type DisputeCase = {")
        block = "```text\n" + self.text[start:self.text.index("\n}\n", start) + 3] + "```\n\n"
        self.assert_structural(
            mutate(self.text, "### 6.5 Candidate logical addresses\n", block + "### 6.5 Candidate logical addresses\n"),
            "signed type DisputeCase is defined more than once",
        )

    def test_unknown_hash_operand_is_rejected(self):
        self.assert_structural(
            mutate(self.text, '"dacs-x-escrow-decision:v1:" || escrow_decision_hash',
                   '"dacs-x-escrow-decision:v1:" || escrow_decision_draft_hash'),
            "signing domain dacs-x-escrow-decision:v1: signs unknown operand escrow_decision_draft_hash",
        )

    def test_version_member_name_and_count_are_checked(self):
        fragment = "signed type EscrowDecision must declare exactly one version member escrowDecisionVersion"
        self.assert_structural(
            mutate(self.text, '  escrowDecisionVersion: "1"\n', '  decisionVersion: "1"\n'),
            fragment,
        )
        self.assert_structural(
            mutate(self.text, '  escrowDecisionVersion: "1"\n', '  escrowDecisionVersion: "1"\n  decisionVersion: "1"\n'),
            fragment,
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
            "requirement DRT-1 is exercised only by positive or process cases",
        )

    # A process case expects only `pass`, so it cannot fail an implementation.
    def test_process_case_is_not_negative_coverage(self):
        text = mutate(self.text, "*Rules:* DRT-1, DRT-2, DRT-3, DRD-7.", "*Rules:* DRT-2, DRT-3, DRD-7.")
        text = mutate(text, "*Rules:* DRG-2, DRC-10, DRC-11.", "*Rules:* DRG-2, DRC-10, DRC-11, DRT-1.")
        self.assert_structural(text, "process case Q1 lists DRT-1, which is not a process rule")
        self.assert_structural(text, "requirement DRT-1 is exercised only by positive or process cases")

    def test_runtime_signing_rules_have_rejection_coverage(self):
        cases = {case["id"]: case for case in self.validator.parse_cases(self.text)}
        self.assertEqual(set(cases["Q1"]["rules"]), self.validator.PROCESS_RULES)
        for rule_id in ("DRJ-9", "DRF-7"):
            self.assertIn(rule_id, cases["R44"]["rules"])

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
        self.assert_structural(
            mutate(self.text, "missing finality evidence. *Expected:* `indeterminate`.",
                   "missing finality evidence. *Expected:* `pass`."),
            "case I3 expects pass; I cases may expect only indeterminate",
        )
        self.assert_structural(
            mutate(self.text, "*Expected:* `pass`. *Rules:* DRG-2,", "*Expected:* `fail`. *Rules:* DRG-2,"),
            "case Q1 expects fail; Q cases may expect only pass",
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

    @unittest.skipIf(SHALLOW, SHALLOW_REASON)
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

    @unittest.skipIf(SHALLOW, SHALLOW_REASON)
    def test_write_regenerates_a_stale_matrix(self):
        # In-process, so the scratch copy is pinned at the committed candidate's revision.
        validator = load_validator()
        with TemporaryDirectory() as tmp, as_committed_candidate(validator):
            doc = Path(tmp) / "candidate.md"
            doc.write_text(mutate(self.text, "(DRL-7) Value MUST NOT reach", "(DRL-7) Value MAY reach"), encoding="utf-8")
            matrix = Path(tmp) / "matrix.json"
            matrix.write_text(MATRIX.read_text(encoding="utf-8"), encoding="utf-8")
            written, written_stderr = run_main(validator, "--doc", str(doc), "--matrix", str(matrix), "--write")
            checked, checked_stderr = run_main(validator, "--doc", str(doc), "--matrix", str(matrix))
            self.assertNotEqual(matrix.read_text(encoding="utf-8"), MATRIX.read_text(encoding="utf-8"))
        self.assertEqual(written, 0, written_stderr)
        self.assertEqual(checked, 0, checked_stderr)

    @unittest.skipIf(SHALLOW, SHALLOW_REASON)
    def test_write_creates_a_new_nested_matrix_directory(self):
        validator = load_validator()
        with TemporaryDirectory() as tmp, as_committed_candidate(validator):
            doc = Path(tmp) / "candidate.md"
            doc.write_text(self.text, encoding="utf-8")
            matrix = Path(tmp) / "new" / "nested" / "matrix.json"
            self.assertEqual(run_main(validator, "--doc", str(doc), "--matrix", str(matrix), "--write"), (0, ""))
            self.assertEqual(matrix.read_text(encoding="utf-8"), MATRIX.read_text(encoding="utf-8"))


class CheckedAgainstPinTests(unittest.TestCase):
    """pin_errors on a scratch repository: only a revision of the candidate must re-pin."""

    @classmethod
    def setUpClass(cls):
        cls.validator = load_validator()

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.repo = self.tmp / "repo"
        (self.repo / "spec").mkdir(parents=True)
        (self.repo / "docs").mkdir()
        self.spec = self.repo / "spec" / "CORE.md"
        self.doc = self.repo / "docs" / "candidate.md"
        self.git("init", "-q")
        self.spec.write_text("core 1\n", encoding="utf-8")
        self.doc.write_text("candidate 1\n", encoding="utf-8")
        self.pin = self.commit("pin")

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.repo), "-c", "user.name=test", "-c", "user.email=test@example.invalid",
             "-c", "commit.gpgsign=false", *args],
            capture_output=True, text=True, check=True,
        ).stdout.strip()

    def commit(self, message: str) -> str:
        self.git("add", "spec", "docs")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def pin_errors(self, pin: str, root: Path | None = None, doc: Path | None = None) -> list[str]:
        return self.validator.pin_errors(root or self.repo, pin, doc or self.doc)

    def test_unrelated_spec_change_keeps_the_pin_valid(self):
        self.spec.write_text("core 2\n", encoding="utf-8")
        self.commit("unrelated spec change")
        self.assertEqual(self.pin_errors(self.pin), [])
        self.spec.write_text("core 3\n", encoding="utf-8")
        self.assertEqual(self.pin_errors(self.pin), [])

    def test_candidate_revision_must_repin(self):
        self.spec.write_text("core 2\n", encoding="utf-8")
        current = self.commit("spec change")
        self.doc.write_text("candidate 2\n", encoding="utf-8")
        self.assertEqual(self.pin_errors(self.pin), [
            f"spec/ differs from the **Checked against** commit {self.pin} at the working tree; "
            "re-audit every cited rule and update the pin (DRG-2)"
        ])
        revision = self.commit("candidate revision without a re-pin")
        self.assertEqual(self.pin_errors(self.pin), [
            f"spec/ differs from the **Checked against** commit {self.pin} at commit {revision}, "
            "the candidate's latest revision; re-audit every cited rule and update the pin (DRG-2)"
        ])
        self.assertEqual(self.pin_errors(current), [])

    def test_merge_onto_a_newer_spec_must_repin(self):
        # PR CI checks the merge of the PR head into a base whose spec/ moved past the pin.
        self.git("checkout", "-q", "-b", "pr")
        self.doc.write_text("candidate 2\n", encoding="utf-8")
        self.commit("candidate revision")
        self.assertEqual(self.pin_errors(self.pin), [])
        self.git("checkout", "-q", "-")
        self.spec.write_text("core 2\n", encoding="utf-8")
        newer = self.commit("spec change on the base")
        stale = "re-audit every cited rule and update the pin (DRG-2)"
        self.git("merge", "-q", "--no-ff", "--no-edit", "pr")
        merge = self.git("rev-parse", "HEAD")
        self.assertEqual(self.pin_errors(self.pin), [
            f"spec/ differs from the **Checked against** commit {self.pin} at commit {merge}, "
            f"the candidate's latest revision; {stale}"
        ])
        self.assertEqual(self.pin_errors(newer), [])
        # The same tree landed as a squash gives the same verdict.
        self.git("reset", "-q", "--hard", newer)
        self.git("merge", "-q", "--squash", "pr")
        squash = self.commit("squash of the candidate revision")
        self.assertEqual(self.pin_errors(self.pin), [
            f"spec/ differs from the **Checked against** commit {self.pin} at commit {squash}, "
            f"the candidate's latest revision; {stale}"
        ])

    def test_failed_spec_comparison_is_reported(self):
        # git diff exits 128 when objects are missing, as in a damaged or partial clone.
        real_run = subprocess.run

        def run(cmd, *args, **kwargs):
            if cmd[:2] == ["git", "-C"] and cmd[3:5] == ["diff", "--quiet"] and cmd[-1] == "spec/":
                return subprocess.CompletedProcess(cmd, 128, "", "fatal: bad object\n")
            return real_run(cmd, *args, **kwargs)

        error = f"could not compare spec/ with the **Checked against** commit {self.pin}: fatal: bad object"
        outside = self.tmp / "candidate.md"
        outside.write_text("candidate 2\n", encoding="utf-8")
        with mock.patch.object(self.validator.subprocess, "run", run):
            self.assertEqual(self.pin_errors(self.pin), [error])
            self.assertEqual(self.pin_errors(self.pin, doc=outside), [error])

    def test_document_outside_the_repository_is_compared_with_the_working_tree(self):
        outside = self.tmp / "candidate.md"
        outside.write_text("candidate 2\n", encoding="utf-8")
        self.assertEqual(self.pin_errors(self.pin, doc=outside), [])
        self.spec.write_text("core 2\n", encoding="utf-8")
        self.assertEqual(len(self.pin_errors(self.pin, doc=outside)), 1)

    def test_pin_off_the_history_is_rejected(self):
        self.git("checkout", "-q", "-b", "side")
        self.spec.write_text("side\n", encoding="utf-8")
        side = self.commit("side branch")
        self.git("checkout", "-q", "-")
        self.assertEqual(self.pin_errors(side), [f"**Checked against** commit {side} is not an ancestor of HEAD"])

    def test_shallow_clone_asks_for_full_history(self):
        self.spec.write_text("core 2\n", encoding="utf-8")
        self.commit("second")
        clone = self.tmp / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1", self.repo.as_uri(), str(clone)],
                       capture_output=True, check=True)
        self.assertEqual(self.pin_errors(self.pin, clone, clone / "docs" / "candidate.md"),
                         [self.validator.SHALLOW_CLONE_ERROR])

    def test_missing_git_is_reported(self):
        with TemporaryDirectory() as empty, mock.patch.dict(os.environ, {"PATH": empty}):
            errors = self.pin_errors(self.pin)
        self.assertEqual(errors, ["git is required to verify the **Checked against** pin"])


if __name__ == "__main__":
    unittest.main()
