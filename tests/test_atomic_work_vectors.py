"""Determinism and semantic conformance tests for Atomic DACS Work vectors."""

from __future__ import annotations

import __future__
import ast
import contextlib
import copy
import inspect
import io
import json
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import atomic_work_reference as ref  # noqa: E402
import generate_atomic_work_vectors as generator  # noqa: E402
import validate_atomic_work_vectors as validator  # noqa: E402
import validate_atomic_work_schemas as schema_validator  # noqa: E402


COMPLETENESS_WORD = re.compile(
    r"(?i)\b(complete(ly|ness)?|full(y)?|exhaustive(ly)?|comprehensive(ly)?)\b"
)
COVERAGE_WORD = re.compile(r"(?i)\b(cover(s|ed|age|ing)?|exercis(e|es|ed|ing))\b")
# The gate counts rule references; it cannot show that a fixture exercises
# its rule, so "every rule is exercised" claims it even without a completeness
# word.  The passive form claims something only of a totality subject ("the
# test is exercised only in CI" says nothing about rules).
EXERCISED_CLAIM = re.compile(r"(?i)\b(is|are|was|were|be|been|being)\s+(\w+\s+)?(exercised)\b")
TOTALITY = re.compile(r"(?i)\b(every|each|all|any)\b")
NEGATION = re.compile(r"(?i)\b(not|no|never|cannot)\b|n't\b")
# Idioms that contain a negation word but affirm the claim ("not only fully
# covered", "no question that", "no gaps prevent full coverage").
AFFIRMATIVE_IDIOM = re.compile(
    r"(?i)\bnot\s+only\b|\bno\s+(?:question|doubt)\b"
    r"|\b(?:no\s+\w+|nothing)\s+(?:prevents?|stops?|blocks?)\b"
)
# A negated predicate after the claim qualifies it ("full semantic coverage
# is not established", "full coverage is not claimed").
NEGATED_PREDICATE = re.compile(
    r"(?i)\b(?:(?:is|are|was|were|has|have|had)(?:\s+been)?\s+(?:not|never)"
    r"|isn't|aren't|wasn't|weren't|hasn't|haven't)\s+(?:been\s+)?(?:yet\s+)?"
    r"(?:established|claimed|shown|demonstrated|proven|proved|met|achieved|guaranteed)\b"
)
KEPT_OPEN = re.compile(r"(?i)\bremains? open\b")
CLAUSE_BREAK = re.compile(
    r"[,;:()]|\s[—–-]\s|—"
    r"|\s(?:and|but|while|whereas|yet|so|although|though|however)\s",
    re.IGNORECASE,
)


def unqualified_claim(clause):
    """True when ``clause`` claims coverage and does not itself qualify it."""
    words = [m.end() for m in COMPLETENESS_WORD.finditer(clause)]
    covers = [m.end() for m in COVERAGE_WORD.finditer(clause)]
    exercised = EXERCISED_CLAIM.search(clause)
    if words and covers:
        claim_end = max(words + covers)
    elif exercised and TOTALITY.search(clause, 0, exercised.start(3)):
        claim_end = exercised.end(3)
    else:
        return False
    # A negation qualifies the claim only before its last claim word ("does
    # not claim full coverage", "is not exercised") and only when it is not
    # part of an affirmative idiom; after the claim, only a negated predicate
    # ("is not established") does.  "remains open" qualifies only after the
    # claim, with the claim as its subject ("full coverage remains open").
    idioms = [m.span() for m in AFFIRMATIVE_IDIOM.finditer(clause)]
    if any(
        negation.start() < claim_end
        and not any(start <= negation.start() < end for start, end in idioms)
        for negation in NEGATION.finditer(clause)
    ):
        return False
    if NEGATED_PREDICATE.search(clause, claim_end):
        return False
    kept_open = KEPT_OPEN.search(clause, claim_end)
    return kept_open is None


def coverage_overclaims(text):
    """Return the sentences of ``text`` that claim complete coverage.

    A clause pairing a completeness word (complete, full, exhaustive,
    comprehensive and their -ly forms) with a coverage word (cover, exercise),
    or claiming that every/each/all/any of something "is exercised", is an
    overclaim unless that same clause negates the claim or keeps it open. A
    qualifier in another clause, sentence or list item does not count: clauses
    break at , ; : ( ) dashes and at and/but/while/whereas/yet/so/although/
    though/however, with or without a comma. This is a lexical guard for the
    Atomic coverage texts, not a semantic prose oracle.
    """
    blocks = re.split(r"\n\s*\n|\n(?=\s*(?:[-*+]|[0-9]+\.)\s)", text)
    return [
        sentence
        for block in blocks
        for sentence in re.split(r"(?<=[.!?])\s+", " ".join(block.split()))
        if any(unqualified_claim(clause) for clause in CLAUSE_BREAK.split(sentence))
    ]


class AtomicWorkVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = [
            ROOT / "conformance" / "vectors" / "security" / f"{name}.json"
            for name in generator.SET_SPECS
        ]
        cls.sets = [json.loads(path.read_text(encoding="utf-8")) for path in cls.paths]

    def test_strict_validator_accepts_corpus(self):
        errors, set_count, vector_count = validator.validate_all()
        self.assertEqual(errors, [])
        self.assertEqual(set_count, 6)
        self.assertEqual(vector_count, 552)

    def test_proof_byte_limit_uses_canonical_material_size(self):
        execution = next(
            data for data in self.sets
            if data["set"] == "atomic-work-execution-recovery-v0.1"
        )
        by_name = {vector["name"]: vector for vector in execution["vectors"]}
        at_limit = by_name["aw-proof-byte-limit-equality"]
        over_limit = by_name["aw-proof-byte-limit-one-over"]
        limit = at_limit["input"]["capability"]["limits"]["maxProofBytes"]
        self.assertEqual(
            len(ref.proof_package_bytes(
                at_limit["input"]["proofMaterial"],
                at_limit["input"]["proofReservationEvidence"],
            )),
            limit,
        )
        self.assertEqual(
            len(ref.proof_package_bytes(
                over_limit["input"]["proofMaterial"],
                over_limit["input"]["proofReservationEvidence"],
            )),
            limit + 1,
        )
        self.assertEqual(ref.evaluate_vector(at_limit)[0], "pass")
        self.assertEqual(ref.evaluate_vector(over_limit)[0], "fail")

    def test_receipt_storage_and_signed_slot_payload_are_exact(self):
        execution = next(
            data for data in self.sets
            if data["set"] == "atomic-work-execution-recovery-v0.1"
        )
        by_name = {vector["name"]: vector for vector in execution["vectors"]}
        accepted = by_name["aw-receipt-complete-and-final"]
        intent = accepted["input"]["intent"]
        receipt = accepted["input"]["receipt"]
        signed_slot = intent["operations"][4]["payload"]
        self.assertEqual(receipt["paymentSlot"]["before"], signed_slot["expected"])
        self.assertEqual(
            receipt["paymentSlot"]["after"]["conflictDigest"],
            signed_slot["conflictDigest"],
        )
        for name in (
            "aw-receipt-storage-output-missing",
            "aw-receipt-slot-before-generation-mismatch",
            "aw-receipt-slot-after-generation-mismatch",
            "aw-receipt-slot-after-digest-mismatch",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(by_name[name])[0], "fail")

    def test_slot_authority_derives_accounts_and_exact_commitment(self):
        settlement = next(
            data for data in self.sets
            if data["set"] == "atomic-work-settlement-slot-v0.1"
        )
        by_name = {vector["name"]: vector for vector in settlement["vectors"]}
        accepted = by_name["aws-structured-network-slot-cas"]
        payer = accepted["input"]["slotAuthority"]["paymentPhaseInput"]["payer"]
        self.assertNotIn("nativeAccount", payer)
        self.assertEqual(ref.evaluate_vector(accepted)[0], "pass")
        for name in (
            "aws-commitment-other-job-substitution",
            "aws-arbitrary-payer-account",
            "aws-arbitrary-payee-account",
            "aws-arbitrary-roster-native-account",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(by_name[name])[0], "fail")
        profiles = next(
            data for data in self.sets
            if data["set"] == "atomic-work-purchase-completion-v0.1"
        )
        profiles_by_name = {
            vector["name"]: vector for vector in profiles["vectors"]
        }
        for name in (
            "awp-commitment-job-binding",
            "awp-commitment-listing-binding",
        ):
            with self.subTest(name=name):
                self.assertEqual(
                    ref.evaluate_vector(profiles_by_name[name])[0], "fail"
                )

    def test_projected_anchor_uses_complete_core_shape(self):
        execution = next(
            data for data in self.sets
            if data["set"] == "atomic-work-execution-recovery-v0.1"
        )
        by_name = {vector["name"]: vector for vector in execution["vectors"]}
        accepted = by_name["aw-anchor-projection"]
        anchor = accepted["input"]["anchorReceipt"]
        self.assertEqual(
            set(anchor),
            {
                "receiptVersion", "substrate", "finalityProfile",
                "logicalAddress", "nativeAddress", "contentHash",
                "transactionRef", "writer", "nonce", "state",
                "observationDisposition", "observedAt", "blockRef", "evidence",
            },
        )
        self.assertNotIn("networkId", anchor)
        self.assertEqual(ref.evaluate_vector(accepted)[0], "pass")
        for name in (
            "aw-anchor-finality-field-missing",
            "aw-anchor-nonce-mutated",
            "aw-anchor-networkid-shortcut-rejected",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(by_name[name])[0], "fail")

    def test_base64url_is_canonical_and_ed25519_lengths_are_exact(self):
        self.assertEqual(ref.b64u_decode("_w"), b"\xff")
        with self.assertRaisesRegex(ref.Invalid, "non-canonical"):
            ref.b64u_decode("_x")
        with self.assertRaisesRegex(ref.Invalid, "unpadded"):
            ref.b64u_decode("A")

        authorization = next(
            data for data in self.sets
            if data["set"] == "atomic-work-authorization-v0.1"
        )
        by_name = {vector["name"]: vector for vector in authorization["vectors"]}
        for name in (
            "aw-auth-signature-base64url-alias",
            "aw-auth-signature-wrong-length",
            "aw-auth-public-key-wrong-length",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(by_name[name])[0], "fail")

    def test_capability_scope_is_consumed_by_authorization_and_receipts(self):
        authorization = next(
            data for data in self.sets
            if data["set"] == "atomic-work-authorization-v0.1"
        )
        execution = next(
            data for data in self.sets
            if data["set"] == "atomic-work-execution-recovery-v0.1"
        )
        auth_by_name = {vector["name"]: vector for vector in authorization["vectors"]}
        receipt_by_name = {vector["name"]: vector for vector in execution["vectors"]}
        for name in (
            "aw-auth-capability-network-substitution",
            "aw-auth-capability-execution-substitution",
            "aw-auth-capability-profile-substitution",
            "aw-auth-capability-schema-substitution",
            "aw-auth-capability-operation-kind-duplicate",
            "aw-auth-capability-proof-profile-substitution",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(auth_by_name[name])[0], "fail")
        for name in (
            "aw-receipt-capability-proof-profile-substitution",
            "aw-receipt-capability-schema-substitution",
            "aw-receipt-malformed-operation-payload",
            "aw-completion-storage-bytes-content-hash-mismatch",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(receipt_by_name[name])[0], "fail")

    def test_lifecycle_evidence_binds_exact_native_transaction_ref(self):
        execution = next(
            data for data in self.sets
            if data["set"] == "atomic-work-execution-recovery-v0.1"
        )
        by_name = {vector["name"]: vector for vector in execution["vectors"]}
        accepted = by_name["aw-lifecycle-noninclusion-proof"]
        self.assertEqual(
            accepted["input"]["evidence"]["nativeTransactionRef"],
            accepted["input"]["nativeTransactionRef"],
        )
        self.assertEqual(ref.evaluate_vector(accepted)[0], "pass")
        for name in (
            "aw-attempt-evidence-native-ref-mismatch",
            "aw-lifecycle-native-ref-mismatch",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(by_name[name])[0], "fail")

    def test_all_normative_rules_have_vector_coverage(self):
        covered = {
            rule
            for data in self.sets
            for vector in data["vectors"]
            for rule in vector["ruleRefs"]
        }
        self.assertEqual(covered, validator.EXPECTED_RULES)

    def test_applicable_polarity_coverage_is_complete_and_honest(self):
        report = validator.coverage_report()
        self.assertEqual(
            report["classification"],
            "candidate-complete-applicable-polarity",
        )
        self.assertTrue(report["completeApplicablePolarity"])
        self.assertFalse(report["nonGatingPolarityGaps"])
        self.assertEqual(set(report["byRule"]), validator.EXPECTED_RULES)
        self.assertEqual(report["missing"], {"P": [], "N": [], "B": []})
        self.assertEqual(
            report["applicabilityConflicts"],
            {"P": [], "N": [], "B": []},
        )
        self.assertTrue(report["notApplicable"]["P"])
        self.assertTrue(report["notApplicable"]["N"])
        self.assertTrue(report["notApplicable"]["B"])
        self.assertIn("X", "".join(report["byRule"].values()))

    def test_changelog_atomic_coverage_agrees_with_strict_gate(self):
        # The gate is mechanical: it counts rule references by verdict class.
        # The CHANGELOG, the security README and every generated coverage
        # note must say so, and must keep the CONFORMANCE-PLAN §14.8
        # semantically meaningful fixture requirement open, not claim it met.
        # The validator's summary line claims only rule references.
        self.assertTrue(validator.coverage_report()["completeApplicablePolarity"])
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        entry = changelog.split("- **Atomic Purchase and Completion Works**", 1)[1]
        entry = entry.split("\n- **", 1)[0]
        readme = (ROOT / "conformance" / "vectors" / "security" / "README.md").read_text(
            encoding="utf-8"
        )
        atomic = readme.split("## Atomic Work candidate test profile", 1)[1]
        atomic = atomic.split("\n## ", 1)[0]
        documents = [("CHANGELOG", entry), ("README", atomic)]
        for data in self.sets:
            # The machine classification stays; only its prose is qualified.
            self.assertEqual(
                data["coverage"]["classification"],
                "candidate-complete-applicable-polarity",
            )
            documents.append((f"{data['set']} coverage note", data["coverage"]["note"]))
        for name, source in documents:
            # The guard reads the source layout, so a list item cannot lend
            # its qualifier to the next one; the phrase checks read joined text.
            text = " ".join(source.split())
            with self.subTest(document=name):
                self.assertNotRegex(text, r"(?i)coverage[^.]*\bblocker\b")
                self.assertEqual(coverage_overclaims(source), [])
                self.assertNotIn("actually exercised", text)
                self.assertRegex(text, r"rule-referenced fixture of the (matching|right)")
                self.assertRegex(text, r"non-applicable cell\w* (carries|with) an explicit rationale")
                self.assertRegex(text, r"generator and (the )?strict validator both refuse")
                self.assertIn("does not", text.split("rule references by", 1)[1][:60])
                self.assertIn(
                    "Some cells are currently decided by self-reported or "
                    "caller-supplied values",
                    text,
                )
                self.assertIn(
                    "semantically meaningful fixtures CONFORMANCE-PLAN §14.8 "
                    "requires remains open for this candidate",
                    text,
                )
                self.assertNotRegex(text, r"\b(AWS?|AWP|AWB)-[0-9]+\b[^.]*self-reported")
        output = io.StringIO()
        with mock.patch.object(validator, "validate_all", return_value=([], 6, 315)):
            with contextlib.redirect_stdout(output):
                self.assertEqual(validator.main(), 0)
        summary = output.getvalue().splitlines()[0]
        with self.subTest(document="validator summary"):
            self.assertIn("rules with every applicable P/N/B cell rule-referenced;", summary)
            self.assertEqual(coverage_overclaims(summary), [])
        # The note is generated: one text for all six sets.
        self.assertEqual(
            len({data["coverage"]["note"] for data in self.sets}), 1,
            "the six generated coverage notes differ",
        )

    def test_semantic_fixture_precondition_and_general_changes_are_recorded(self):
        # CONFORMANCE-PLAN §14.8 makes semantically meaningful fixtures a
        # precondition for advertising AtomicWorkCapabilityV1, which this
        # candidate does not yet meet; only that MUST is so conditioned.
        def joined(text):
            return " ".join(text.split())

        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        entry = changelog.split("- **Atomic Purchase and Completion Works**", 1)[1]
        entry = joined(entry.split("\n- **", 1)[0])
        readme = (ROOT / "conformance" / "vectors" / "security" / "README.md").read_text(
            encoding="utf-8"
        )
        atomic = joined(
            readme.split("## Atomic Work candidate test profile", 1)[1].split("\n## ", 1)[0]
        )
        plan = joined((ROOT / "spec" / "CONFORMANCE-PLAN.md").read_text(encoding="utf-8"))
        bullet = plan.split("- **Atomic DACS Work (AW-1..AW-77).**", 1)[1].split(" - **", 1)[0]
        for name, text in (("CHANGELOG", entry), ("README", atomic), ("CONFORMANCE-PLAN", bullet)):
            with self.subTest(document=name):
                self.assertRegex(text, r"(?i)\bbefore `AtomicWorkCapabilityV1` may be advertised")
                self.assertIn("does not yet meet", text)
        self.assertIn(
            "a non-applicable cell MUST be machine-readable and carry a non-empty "
            "rationale. Before `AtomicWorkCapabilityV1` may be advertised for this "
            "profile, every applicable cell MUST also have at least one semantically "
            "meaningful fixture.",
            bullet,
        )
        self.assertIn("`AtomicWorkCapabilityV1` stays closed.", bullet)
        # The DACS-4 rules that bind every profile are recorded as general
        # normative changes, not as Atomic-only rules.
        heading = "### Changed — general normative changes in candidate DACS-4 v0.8 (every profile)"
        self.assertIn(heading, changelog)
        changed = joined(changelog.split(heading, 1)[1].split("\n### ", 1)[0])
        self.assertIn("These are general normative changes, not Atomic-only rules", changed)
        for rule in (
            "**Rail resolution** (DACS-4 §9.4.3 RTB-1)",
            "**Payment input arm** (DACS-4 §9.5.1 PC-1)",
            "**Amendment target** (DACS-4 §9.7.1 AMEND-1)",
            "**Evidence selectors** (DACS-4 §9.7)",
        ):
            with self.subTest(rule=rule):
                self.assertIn(rule, changed)
        # One phrase per PC-1 / AMEND-1 obligation, so a bullet cannot lag the rule.
        for phrase in (
            "authenticated phase binding before it reads any input member",
            "requires `sessionContext` and rejects `atomicSessionContext`",
            "nested party, `PriceTerm` and session-context shapes, is rejected",
            "`AgreementArtifact` and `RailDefinition` discriminators and members",
            "permanent (`ok: false`, `errorClass: \"permanent\"`) and precedes any rail call",
            "recompute its content hash before reading any target member",
            "`LegacyTransitionSettlementEvidence`, `FinalityBoundSettlementEvidence`",
            "signer MUST be the session's phase orchestrator",
            "`{evidenceHash}` segment MUST equal the target's content hash",
            "unfinalized target, or resolved bytes that differ from an authentic anchor, "
            "leaves the amendment `indeterminate`",
            "anchor receipt whose proof does not bind its own fields",
            "Only an authentic anchor that binds another content hash is a violation",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, changed)

    def test_coverage_overclaim_guard_cases(self):
        for sentence, overclaims in (
            ("This is full P/N/B coverage.", True),
            ("The six sets give full coverage.", True),
            ("Every rule is fully covered.", True),
            ("Every rule ID is completely covered.", True),
            ("Coverage of every rule is exhaustive.", True),
            ("Every rule is fully exercised by its fixtures.", True),
            # A qualifier in another clause does not qualify the claim.
            ("Every rule is fully covered, not just referenced.", True),
            ("Every rule is fully exercised and nothing remains open.", True),
            ("This is full semantic coverage, not merely partial coverage.", True),
            ("Coverage is exhaustive, not incomplete.", True),
            ("Full coverage is achieved; one separate follow-up remains open.", True),
            ("Coverage is complete with no gaps.", True),
            # "although", "though" and "however" end a clause even without a
            # comma, so a later negated predicate does not lend its negation.
            ("Every rule is fully covered although production execution is "
             "not established.", True),
            ("Every rule is fully covered though full semantic coverage is "
             "not shown.", True),
            ("Every rule is fully exercised however the semantic check is "
             "not demonstrated.", True),
            ("Although every rule is referenced, full coverage is not "
             "claimed.", False),
            ("Full semantic coverage is not established though every rule "
             "is referenced.", False),
            # Exercise claims and wider completeness wording.
            ("The fixtures fully exercise every rule.", True),
            ("Every applicable cell is exercised by a fixture of the matching class.", True),
            ("Every rule ID is comprehensively covered.", True),
            # A negation word inside an affirmative idiom does not negate the
            # claim, and "remains open" qualifies only a claim before it.
            ("Not only is every rule fully covered, the gate refuses gaps.", True),
            ("The corpus is not only fully covered but independently tested.", True),
            ("There is no question that coverage is complete.", True),
            ("No gaps prevent full semantic coverage.", True),
            ("Nothing remains open because every rule is fully covered.", True),
            # Accurate sentences: a negated predicate after the claim, and a
            # passive "exercised" without a totality subject.
            ("Full semantic coverage is not established.", False),
            ("Rule references are counted, but full coverage is not claimed.", False),
            ("The test is exercised only in CI.", False),
            ("Specific canonicalization boundaries are exercised.", False),
            ("It does not claim full semantic coverage.", False),
            ("Full semantic coverage under §14.8 remains open.", False),
            ("This gate counts rule references by class; it does not show "
             "that each fixture exercises its rule.", False),
            ("It is not shown that each cell is exercised.", False),
            ("The generator and the strict validator both refuse any gap.", False),
        ):
            with self.subTest(sentence=sentence):
                self.assertEqual(
                    coverage_overclaims("Some prefix. " + sentence),
                    [sentence] if overclaims else [],
                )
        # An unpunctuated list item does not borrow the next item's qualifier.
        self.assertEqual(
            coverage_overclaims("- Every rule is fully covered\n- It does not claim more."),
            ["- Every rule is fully covered"],
        )
        self.assertEqual(
            coverage_overclaims(
                "* Every rule is fully covered\n* Full semantic coverage remains open."
            ),
            ["* Every rule is fully covered"],
        )

    def test_boundary_attribution_is_rule_specific(self):
        for data in self.sets:
            for vector in data["vectors"]:
                boundary_rules = vector.get("boundaryRuleRefs")
                if vector.get("boundary") is True:
                    self.assertTrue(boundary_rules)
                    self.assertLessEqual(
                        set(boundary_rules), set(vector["ruleRefs"])
                    )
                    self.assertLessEqual(
                        set(boundary_rules), generator.BOUNDARY_APPLICABLE_RULES
                    )
                else:
                    self.assertNotIn("boundaryRuleRefs", vector)

    def test_job_ids_and_signers_use_normative_wire_shapes(self):
        # These negatives carry a malformed jobId or ClaimReference signer on
        # purpose; each must be refused, and every other vector uses the JID-1
        # and CF-2 wire shapes.
        malformed_job_id = re.compile(
            r"job-id-(first-character-[89]|not-ulid)$|^aw-claim-parameter-"
        )

        def walk(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key == "jobId":
                        self.assertIsInstance(child, str)
                        self.assertRegex(child, ref.JOB_ID)
                    if key == "signer":
                        self.assertIsInstance(child, str)
                        self.assertRegex(child, ref.CLAIM_REFERENCE)
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        for data in self.sets:
            for vector in data["vectors"]:
                if malformed_job_id.search(vector["name"]):
                    self.assertIn(vector["expected"], {"fail", "error"}, vector["name"])
                    continue
                walk(vector)

        malformed = generator.purchase_intent()
        malformed["roleRoster"][0]["signer"] = {
            "kind": "did", "value": generator.CLAIMS["buyer"]
        }
        with self.assertRaisesRegex(ref.Invalid, "signer|ClaimReference"):
            ref.validate_intent(malformed)

    def test_atomic_settlement_evidence_uses_normative_shape(self):
        settlement = next(
            data for data in self.sets
            if data["set"] == "atomic-work-settlement-slot-v0.1"
        )
        accepted = next(
            vector for vector in settlement["vectors"]
            if vector["name"] == "aws-final-work-receipt-bound"
        )["input"]["evidence"]
        self.assertNotIn("kind", accepted)
        self.assertNotIn("workReceiptHash", accepted)
        self.assertNotIn("settlementPayload", accepted)
        self.assertIn("workReceiptRef", accepted)
        self.assertEqual(
            set(accepted["workReceiptRef"]),
            {"refVersion", "networkId", "workId", "receiptCommitment", "contentHash", "locator"},
        )
        self.assertEqual(
            set(accepted["operationRef"]),
            {"kind", "networkId", "workId", "operationIndex", "operationId", "operationKind"},
        )
        self.assertEqual(
            set(accepted["operationProof"]["subject"]),
            {
                "networkId", "workId", "winningAttemptId", "operationReceiptRoot",
                "operationIndex", "operationId", "operationKind", "receiptContentHash",
            },
        )
        self.assertEqual(accepted["paymentAmount"], {"amount": "10", "currency": "DEM"})
        self.assertEqual(accepted["settlementFinality"]["model"], "bft-final")
        self.assertEqual(accepted["signature"]["signer"], generator.CLAIMS["orchestrator"])
        self.assertEqual(
            ref.settlement_id(accepted["operationRef"]),
            ref.settlement_id({**accepted["operationRef"], "extra": True}),
        )

    def test_expiry_boundary_is_strict(self):
        identity = next(
            data for data in self.sets if data["set"] == "atomic-work-identity-v0.1"
        )
        by_name = {vector["name"]: vector for vector in identity["vectors"]}
        self.assertEqual(
            ref.evaluate_vector(by_name["aw-expiry-last-valid-millisecond"])[0], "pass"
        )
        self.assertEqual(
            ref.evaluate_vector(by_name["aw-expiry-equality-rejected-before-op"])[0], "fail"
        )

    def test_payload_schemas_are_complete_authenticated_and_closed(self):
        identity = next(
            data for data in self.sets if data["set"] == "atomic-work-identity-v0.1"
        )
        by_name = {vector["name"]: vector for vector in identity["vectors"]}
        exact = by_name["aw-payload-schema-exact-profile"]
        self.assertEqual(
            exact["input"]["capability"]["payloadSchemas"], ref.PAYLOAD_SCHEMAS
        )
        self.assertEqual(ref.evaluate_vector(exact)[0], "pass")
        self.assertEqual(
            ref.evaluate_vector(by_name["aw-payload-schema-kind-missing"])[0], "fail"
        )
        self.assertEqual(
            ref.evaluate_vector(by_name["aw-payload-schema-version-unsupported"])[0], "fail"
        )
        self.assertEqual(
            ref.evaluate_vector(by_name["aw-payload-schema-no-caller-inference"])[0], "fail"
        )

    def test_role_anchor_uses_external_party_maps_and_both_works(self):
        role_set = next(
            data for data in self.sets if data["set"] == "atomic-work-audit-role-v0.1"
        )
        by_name = {vector["name"]: vector for vector in role_set["vectors"]}
        self.assertEqual(ref.evaluate_vector(by_name["awb-completion-receipt-not-final"])[0], "fail")
        self.assertEqual(ref.evaluate_vector(by_name["awb-receipt-dependent-bundle-in-completion"])[0], "fail")
        self.assertEqual(ref.evaluate_vector(by_name["awb-work-carried-bundle-profile-deferred"])[0], "indeterminate")
        self.assertEqual(ref.evaluate_vector(by_name["awb-purchase-evidence-required"])[0], "indeterminate")
        self.assertEqual(ref.evaluate_vector(by_name["awb-purchase-completion-mismatch"])[0], "indeterminate")
        self.assertEqual(ref.evaluate_vector(by_name["awb-self-consistent-forged-roster"])[0], "indeterminate")
        self.assertEqual(ref.evaluate_vector(by_name["awb-audit-dependency-proof-missing"])[0], "indeterminate")
        self.assertEqual(
            by_name["awb-audit-dependency-proof-missing"]["input"]["sessionStateAfter"],
            "audit-pending",
        )
        self.assertEqual(ref.evaluate_vector(by_name["awb-audit-premature-finalisation"])[0], "fail")
        self.assertEqual(ref.evaluate_vector(by_name["awb-repair-never-replays-purchase"])[0], "fail")
        self.assertIn("AWB-9", by_name["awb-repair-never-replays-purchase"]["ruleRefs"])

    def test_receipt_slot_transition_and_retry_intent_are_bound(self):
        execution = next(
            data for data in self.sets
            if data["set"] == "atomic-work-execution-recovery-v0.1"
        )
        receipt_input = next(
            vector["input"] for vector in execution["vectors"]
            if vector["name"] == "aw-receipt-complete-and-final"
        )
        intent, receipt = receipt_input["intent"], receipt_input["receipt"]
        self.assertEqual(
            receipt["paymentSlot"]["key"],
            {
                "networkId": intent["networkId"], "railId": intent["railId"],
                "jobId": intent["jobId"], "phaseIndex": intent["phaseIndex"],
            },
        )
        self.assertEqual(receipt["paymentSlot"]["before"]["state"], "vacant")
        self.assertEqual(receipt["paymentSlot"]["after"]["state"], "settled")
        self.assertEqual(receipt["receiptCommitment"], ref._receipt_commitment(receipt))
        self.assertEqual(ref.receipt_hash(receipt), ref.sha256_hex(ref.jcs_bytes(receipt)))

        slot_set = next(
            data for data in self.sets
            if data["set"] == "atomic-work-settlement-slot-v0.1"
        )
        retry = next(
            vector["input"] for vector in slot_set["vectors"]
            if vector["name"] == "aws-retry-after-rollback"
        )
        retry_intent = retry["work"]["intent"]
        self.assertEqual(
            retry_intent["priorFailureReceiptCommitment"],
            retry["ledgerProof"]["state"]["failureReceiptCommitment"],
        )
        self.assertEqual(retry["work"]["workId"], ref.work_id(retry_intent))
        self.assertEqual(
            retry_intent["operations"][4]["payload"]["expected"],
            {
                "state": "rolled-back",
                "generation": retry["ledgerProof"]["state"]["generation"],
            },
        )
        self.assertEqual(
            retry["newState"]["generation"],
            retry["ledgerProof"]["state"]["generation"] + 1,
        )

        by_name = {vector["name"]: vector for vector in slot_set["vectors"]}
        for name in (
            "aws-retry-committed-receipt-generation",
            "aws-retry-rollback-receipt-generation",
        ):
            with self.subTest(name=name):
                candidate = by_name[name]
                self.assertEqual(ref.evaluate_vector(candidate)[0], "pass")
                before = candidate["input"]["receipt"]["paymentSlot"]["before"]
                after = candidate["input"]["receipt"]["paymentSlot"]["after"]
                self.assertEqual(after["generation"], before["generation"] + 1)

    def test_composed_admission_is_the_whole_profile_verdict(self):
        profiles = next(
            data for data in self.sets
            if data["set"] == "atomic-work-purchase-completion-v0.1"
        )
        by_name = {vector["name"]: vector for vector in profiles["vectors"]}
        self.assertEqual(
            ref.evaluate_vector(by_name["awp-purchase-composed-admission"])[0],
            "pass",
        )
        self.assertEqual(
            ref.evaluate_vector(
                by_name["awp-purchase-signed-sequential-admission"]
            )[0],
            "pass",
        )
        self.assertEqual(
            ref.evaluate_vector(by_name["awp-completion-composed-admission"])[0],
            "pass",
        )
        self.assertEqual(
            ref.evaluate_vector(
                by_name["awp-purchase-composed-retry-admission"]
            )[0],
            "pass",
        )
        self.assertNotIn(
            "commitmentReceipt",
            by_name["awp-purchase-composed-admission"]["input"]["authority"],
        )
        for name, verdict in (
            (
                "awp-completion-composed-claims-evidence-and-bundle-finalized",
                "fail",
            ),
            ("awp-composed-profile-empty-required-roles", "fail"),
            ("awp-composed-common-receipt-missing", "indeterminate"),
            ("awp-composed-winner-receipt-mismatch", "fail"),
            ("awp-purchase-composed-retry-generation-skip", "fail"),
            ("awp-composed-slot-cross-work-substitution", "fail"),
            ("awp-composed-capability-limit-enforced", "fail"),
            ("awp-purchase-caller-gate-mode-mismatch", "fail"),
            ("awp-purchase-agreement-seller-differs-from-listing", "fail"),
            ("awp-completion-gate-mode-differs-from-purchase", "fail"),
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(by_name[name])[0], verdict)

        completion = copy.deepcopy(
            by_name["awp-completion-composed-admission"]["input"]
        )
        ref.evaluate_completion_admission(completion)
        explicit_false = copy.deepcopy(completion)
        explicit_false["claimsEvidenceFinalized"] = False
        explicit_false["claimsBundleFinalized"] = False
        ref.evaluate_completion_admission(explicit_false)
        for field in (
            "claimsEvidenceFinalized",
            "claimsBundleFinalized",
        ):
            forbidden = copy.deepcopy(completion)
            forbidden[field] = True
            with self.subTest(field=field, claim=True):
                with self.assertRaises(ref.Invalid):
                    ref.evaluate_completion_admission(forbidden)
            for malformed in (None, 0, 1, "false", [], {}):
                candidate = copy.deepcopy(completion)
                candidate[field] = malformed
                with self.subTest(field=field, malformed=malformed):
                    with self.assertRaises(ref.Invalid):
                        ref.evaluate_completion_admission(candidate)
        both_forbidden = copy.deepcopy(completion)
        both_forbidden["claimsEvidenceFinalized"] = True
        both_forbidden["claimsBundleFinalized"] = True
        with self.assertRaises(ref.Invalid):
            ref.evaluate_completion_admission(both_forbidden)

    def test_closed_capability_and_algorithm_confusion_are_rejected(self):
        identity = next(
            data for data in self.sets
            if data["set"] == "atomic-work-identity-v0.1"
        )
        authorization = next(
            data for data in self.sets
            if data["set"] == "atomic-work-authorization-v0.1"
        )
        identity_by_name = {
            vector["name"]: vector for vector in identity["vectors"]
        }
        auth_by_name = {
            vector["name"]: vector for vector in authorization["vectors"]
        }
        for name in (
            "aw-capability-validator-set-empty",
            "aw-capability-fee-rule-unsupported",
            "aw-capability-authorization-algorithm-duplicate",
            "aw-capability-closed-extension",
            "aw-capability-boolean-limit",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(identity_by_name[name])[0], "fail")
        for name in (
            "aw-auth-ecdsa-label-confusion",
            "aw-auth-sr1-label-confusion",
            "aw-auth-boolean-phase-index",
            "aw-auth-boolean-operation-index",
            "aw-auth-rail-phase-handler-mismatch",
            "aw-auth-self-consistent-session-orchestrator-rekey",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(auth_by_name[name])[0], "fail")
        self.assertEqual(
            ref.evaluate_vector(auth_by_name["aw-auth-cf3-parameter-identity"])[0],
            "pass",
        )

    def test_vet_records_require_current_production_authorization(self):
        purchase = next(
            data for data in self.sets
            if data["set"] == "atomic-work-purchase-completion-v0.1"
        )
        by_name = {vector["name"]: vector for vector in purchase["vectors"]}
        self.assertEqual(
            ref.evaluate_vector(by_name["awp-purchase-composed-admission"])[0],
            "pass",
        )
        for name, expected in (
            ("awp-purchase-vet-record-historical-authority", "fail"),
            ("awp-purchase-vet-record-not-current-admitted", "indeterminate"),
        ):
            with self.subTest(name=name):
                verdict, reason = ref.evaluate_vector(by_name[name])
                self.assertEqual(verdict, expected)
                self.assertIn("current-profile admission", reason)

    def _purchase_vectors(self):
        purchase = next(
            data for data in self.sets
            if data["set"] == "atomic-work-purchase-completion-v0.1"
        )
        return {vector["name"]: vector for vector in purchase["vectors"]}

    def test_composed_slot_transition_follows_the_signed_cas(self):
        by_name = self._purchase_vectors()
        for name in (
            "awp-purchase-composed-admission",
            "awp-composed-slot-transition-derived-claim",
            "awp-purchase-composed-retry-admission",
            "awp-composed-slot-transition-derived-retry",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(by_name[name])[0], "pass")
        self.assertNotIn(
            "action",
            by_name["awp-composed-slot-transition-derived-claim"]["input"]["slotAdmission"],
        )
        for name, reason in (
            ("awp-composed-slot-transition-observation-only",
             "an observation is not composed Purchase slot admission"),
            ("awp-composed-slot-transition-committed-observation",
             "an observation is not composed Purchase slot admission"),
            ("awp-composed-slot-transition-caller-mismatch",
             "caller slot action differs from the signed slot transition"),
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(by_name[name]), ("fail", reason))

    def test_composed_business_effects_come_from_the_ledger_inventory(self):
        by_name = self._purchase_vectors()
        for name, expected in (
            ("awp-composed-effect-inventory-missing",
             ("indeterminate", "authenticated Work-ledger effect inventory unavailable")),
            ("awp-composed-effect-inventory-empty",
             ("fail", "Work-ledger effect inventory omits the ledger-selected winner")),
            ("awp-composed-effect-inventory-late-attempt",
             ("fail", "late/competing attempt was not fenced")),
            ("awp-composed-effect-inventory-other-attempt",
             ("fail", "Work-ledger effect inventory omits the ledger-selected winner")),
            ("awp-composed-effect-inventory-winner-reference-mismatch",
             ("fail", "Work-ledger effect inventory winner reference mismatch")),
            ("awp-composed-effect-source-unauthenticated",
             ("fail", "a caller-supplied business-effect list is not Work-ledger authority")),
            ("awp-composed-effect-source-unauthenticated-late-inventory",
             ("fail", "a caller-supplied business-effect list is not Work-ledger authority")),
            ("awp-composed-effect-inventory-other-block",
             ("fail", "Work-ledger effect inventory is not taken at the finalized receipt block")),
            ("awp-composed-effect-inventory-participant-signed",
             ("fail", "signature signer is not the authenticated authority")),
            ("awp-composed-effect-inventory-signature-invalid",
             ("fail", "invalid signature")),
            ("awp-composed-effect-inventory-unsigned",
             ("indeterminate", "missing signature")),
            ("awp-composed-effect-inventory-other-work",
             ("fail", "Work-ledger effect inventory names another Work")),
            ("awp-composed-effect-inventory-other-proof-profile",
             ("fail", "Work-ledger effect inventory proof-profile binding mismatch")),
            ("awp-composed-effect-inventory-other-validator-set",
             ("fail", "Work-ledger effect inventory proof-profile binding mismatch")),
            ("awp-composed-effect-inventory-repeated-attempt",
             ("fail", "Work-ledger effect inventory repeats an attempt")),
            ("awp-composed-effect-source-caller-empty",
             ("fail", "a caller-supplied business-effect list is not Work-ledger authority")),
            ("awp-composed-effect-inventory-unknown-member",
             ("fail", "synthetic Work-ledger effect inventory shape mismatch")),
            ("awp-composed-effect-inventory-entry-unknown-member",
             ("fail", "Work-ledger effect inventory entry malformed")),
            ("awp-composed-effect-inventory-version-unsupported",
             ("fail", "synthetic Work-ledger effect inventory shape mismatch")),
            ("awp-completion-composed-effect-inventory-late-attempt",
             ("fail", "late/competing attempt was not fenced")),
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(by_name[name]), expected)
        self.assertEqual(
            ref.evaluate_vector(by_name["awp-completion-composed-admission"])[0], "pass"
        )

        control = by_name["awp-purchase-composed-admission"]
        control_inventory = control["input"]["ledgerInventory"]
        public_keys = control["input"]["publicKeys"]
        # Signer and binding cases carry a verifying signature, so they reach
        # the check they name; the altered inventory keeps the control body.
        for name, signer in (
            ("awp-composed-effect-inventory-participant-signed", "payer"),
            ("awp-composed-effect-inventory-other-work", "network"),
            ("awp-composed-effect-inventory-other-proof-profile", "network"),
            ("awp-composed-effect-inventory-other-validator-set", "network"),
            ("awp-composed-effect-inventory-repeated-attempt", "network"),
            ("awp-composed-effect-inventory-unknown-member", "network"),
            ("awp-composed-effect-inventory-entry-unknown-member", "network"),
            ("awp-composed-effect-inventory-version-unsupported", "network"),
        ):
            with self.subTest(name=name):
                inventory = by_name[name]["input"]["ledgerInventory"]
                ref.verify_embedded(
                    inventory, public_keys, ref._LEDGER_INVENTORY_TEST_DOMAIN
                )
                self.assertEqual(
                    inventory["signature"]["signer"], generator.CLAIMS[signer]
                )
        altered = by_name["awp-composed-effect-inventory-signature-invalid"][
            "input"
        ]["ledgerInventory"]
        self.assertEqual(
            {k: v for k, v in altered.items() if k != "signature"},
            {k: v for k, v in control_inventory.items() if k != "signature"},
        )
        self.assertNotEqual(altered["signature"], control_inventory["signature"])

        caller_list = copy.deepcopy(control)
        caller_list["input"]["businessEffectAttempts"] = [
            control["input"]["winningAttemptId"]
        ]
        self.assertEqual(
            ref.evaluate_vector(caller_list),
            ("fail", "a caller-supplied business-effect list is not Work-ledger authority"),
        )

        receipt = control["input"]["receipt"]
        earlier_block = copy.deepcopy(control)
        earlier_block["input"]["ledgerInventory"] = generator.effect_inventory(
            ref.work_id(control["input"]["intent"]),
            [(
                receipt["winningAttempt"]["attemptId"],
                receipt["winningAttempt"]["nativeTransactionRef"],
            )],
            block_id="block-900",
        )
        earlier_block["input"] = generator.add_composed_limit_evidence(
            earlier_block["input"]
        )
        self.assertEqual(
            ref.evaluate_vector(earlier_block),
            ("fail", "Work-ledger effect inventory is not taken at the finalized receipt block"),
        )

    def test_attempt_effects_require_a_ledger_selected_winner(self):
        execution = next(
            data for data in self.sets
            if data["set"] == "atomic-work-execution-recovery-v0.1"
        )
        by_name = {vector["name"]: vector for vector in execution["vectors"]}
        control = by_name["aw-replacement-with-noninclusion"]
        recorded = by_name["aw-replacement-effect-without-winner"]
        self.assertEqual(ref.evaluate_vector(control), ("pass", "predicate accepted"))
        self.assertIsNone(recorded["input"]["winningAttemptId"])
        self.assertEqual(
            [entry["attemptId"] for entry in recorded["input"]["ledgerInventory"]["effectAttempts"]],
            ["attempt-a"],
        )
        self.assertEqual(
            {k: v for k, v in recorded["input"].items() if k != "ledgerInventory"},
            {k: v for k, v in control["input"].items() if k != "ledgerInventory"},
        )
        self.assertEqual(
            ref.evaluate_vector(recorded),
            ("fail", "business effect recorded without a ledger-selected winner"),
        )

    def _execution_vectors(self):
        execution = next(
            data for data in self.sets
            if data["set"] == "atomic-work-execution-recovery-v0.1"
        )
        return {vector["name"]: vector for vector in execution["vectors"]}

    def test_rolled_back_winner_records_no_business_effect(self):
        # DACS-4 §9.5.10: a rolled-back Work claims no committed business
        # effect, so the inventory lists no attempt, the winner included.
        by_name = self._execution_vectors()
        clean = by_name["aw-rolled-back-winner-records-no-business-effect"]
        recorded = by_name["aw-rolled-back-winner-business-effect-recorded"]
        self.assertEqual(clean["input"]["receipt"]["outcome"], "rolled-back")
        self.assertEqual(
            clean["input"]["attempts"][0]["lifecycleEvidence"]["state"],
            "included-rolled-back",
        )
        self.assertEqual(clean["input"]["ledgerInventory"]["effectAttempts"], [])
        self.assertEqual(
            [entry["attemptId"] for entry in recorded["input"]["ledgerInventory"]["effectAttempts"]],
            [clean["input"]["winningAttemptId"]],
        )
        self.assertEqual(
            {k: v for k, v in recorded["input"].items() if k != "ledgerInventory"},
            {k: v for k, v in clean["input"].items() if k != "ledgerInventory"},
        )
        self.assertEqual(ref.evaluate_vector(clean), ("pass", "predicate accepted"))
        self.assertEqual(
            ref.evaluate_vector(recorded),
            ("fail", "Work-ledger effect inventory records a business effect for a rolled-back winner"),
        )
        # The committed receipt beside a rolled-back winner still fails for
        # the outcome mismatch, with the inventory the ledger would sign.
        mismatch = by_name["aw-receipt-ledger-outcome-mismatch"]
        self.assertEqual(mismatch["input"]["ledgerInventory"]["effectAttempts"], [])
        self.assertEqual(
            ref.evaluate_vector(mismatch),
            ("fail", "receipt outcome differs from authenticated winner lifecycle state"),
        )

    def test_inventory_block_is_bound_on_every_path(self):
        by_name = self._execution_vectors()
        # Without a receipt, the inventory is taken at the block of the
        # authenticated lifecycle evidence that resolves the Work.
        for name in (
            "aw-attempt-byte-identity", "aw-single-ledger-winner",
            "aw-exact-replay-returns-winner", "aw-replacement-with-noninclusion",
        ):
            with self.subTest(name=name):
                vector = by_name[name]
                self.assertNotIn("receipt", vector["input"])
                blocks = {
                    attempt["lifecycleEvidence"]["blockId"]
                    for attempt in vector["input"]["attempts"]
                    if "lifecycleEvidence" in attempt
                    and (
                        vector["input"]["winningAttemptId"] is None
                        or attempt["attemptId"] == vector["input"]["winningAttemptId"]
                    )
                }
                self.assertEqual(
                    {vector["input"]["ledgerInventory"]["blockId"]}, blocks
                )
                self.assertEqual(ref.evaluate_vector(vector), ("pass", "predicate accepted"))
        stale = by_name["aw-effect-inventory-stale-without-receipt"]
        control = by_name["aw-replacement-with-noninclusion"]
        self.assertEqual(
            {k: v for k, v in stale["input"].items() if k != "ledgerInventory"},
            {k: v for k, v in control["input"].items() if k != "ledgerInventory"},
        )
        self.assertEqual(
            ref.evaluate_vector(stale),
            ("fail", "Work-ledger effect inventory is not taken at the authenticated lifecycle-evidence block"),
        )
        unbound = by_name["aw-effect-inventory-unbound-without-receipt"]
        self.assertFalse(any(
            "lifecycleEvidence" in attempt for attempt in unbound["input"]["attempts"]
        ))
        self.assertEqual(
            ref.evaluate_vector(unbound),
            ("indeterminate", "authenticated ledger block for the Work-ledger effect inventory unavailable"),
        )

    def test_composed_retry_ignores_caller_attempt_observation(self):
        # Composed admission consumes only authenticated slot evidence, so a
        # derived retry from a held slot fails whatever a caller observed.
        vector = self._purchase_vectors()["awp-composed-slot-retry-caller-observation-ignored"]
        slot_admission = vector["input"]["slotAdmission"]
        self.assertEqual(slot_admission["ledgerProof"]["state"]["state"], "in-flight")
        self.assertEqual(slot_admission["attemptObservation"], "indeterminate")
        for observation in ("indeterminate", "not-found", "timeout", None):
            with self.subTest(observation=observation):
                variant = copy.deepcopy(vector)
                if observation is None:
                    del variant["input"]["slotAdmission"]["attemptObservation"]
                else:
                    variant["input"]["slotAdmission"]["attemptObservation"] = observation
                variant["input"] = generator.add_composed_limit_evidence(variant["input"])
                self.assertEqual(
                    ref.evaluate_vector(variant), ("fail", "retry without terminal rollback")
                )

    def test_unsigned_effect_inventory_has_one_classification(self):
        control = self._purchase_vectors()["awp-purchase-composed-admission"]
        verdicts = set()
        for label in ("signature absent", "signature null"):
            with self.subTest(label=label):
                unsigned = copy.deepcopy(control)
                inventory = unsigned["input"]["ledgerInventory"]
                if label == "signature absent":
                    del inventory["signature"]
                else:
                    inventory["signature"] = None
                unsigned["input"] = generator.add_composed_limit_evidence(
                    unsigned["input"]
                )
                verdicts.add(ref.evaluate_vector(unsigned))
        self.assertEqual(verdicts, {("indeterminate", "missing signature")})

    def test_commitment_receipt_without_finality_evidence_is_unavailable(self):
        by_name = self._purchase_vectors()
        self.assertEqual(
            ref.evaluate_vector(by_name["awp-purchase-signed-sequential-admission"])[0],
            "pass",
        )
        self.assertEqual(
            ref.evaluate_vector(
                by_name["awp-purchase-sequential-commitment-evidence-null"]
            ),
            ("indeterminate", "missing test-anchor-finality evidence"),
        )

    def test_atomic_evidence_discriminator_is_exclusive(self):
        # AWS-17: atomicEvidenceVersion is exclusive of every other DACS-4
        # evidence selector.  The schema and the reference's own check each
        # refuse the extra selector, and the DACS-5 reference agrees.
        settlement = next(
            data for data in self.sets
            if data["set"] == "atomic-work-settlement-slot-v0.1"
        )
        by_name = {vector["name"]: vector for vector in settlement["vectors"]}
        control = by_name["aws-distinct-atomic-evidence"]
        cases = (
            ("evidenceVersion", "aws-both-evidence-discriminators"),
            ("deliveryEvidenceVersion", "aws-atomic-and-delivery-evidence-discriminators"),
            ("finalityBoundEvidenceVersion", "aws-atomic-and-finality-bound-evidence-discriminators"),
            ("legacyTransitionEvidenceVersion", "aws-atomic-and-legacy-transition-evidence-discriminators"),
        )
        self.assertEqual(
            set(ref.EVIDENCE_SELECTORS), {selector for selector, _ in cases} | {"atomicEvidenceVersion"}
        )
        if str(ROOT / "tests") not in sys.path:
            sys.path.insert(0, str(ROOT / "tests"))
        import dacs5_reference

        dacs5_keys = {
            claim: ref.b64u_decode(value) for claim, value in control["input"]["publicKeys"].items()
        }
        self.assertEqual(
            dacs5_reference._authenticated_evidence_wire_type(
                control["input"]["evidence"], dacs5_keys
            ),
            "atomic",
        )
        self.assertEqual(ref.evaluate_vector(control), ("pass", "predicate accepted"))
        for selector, name in cases:
            vector = by_name[name]
            evidence = vector["input"]["evidence"]
            with self.subTest(selector=selector):
                self.assertEqual(evidence[selector], "1")
                self.assertEqual(
                    {k: v for k, v in evidence.items() if k not in {selector, "signature"}},
                    {k: v for k, v in control["input"]["evidence"].items() if k != "signature"},
                )
                ref.verify_embedded(evidence, vector["input"]["publicKeys"], ref.EVIDENCE_DOMAIN)
                self.assertEqual(vector["expected"], "fail")
                self.assertEqual(ref.evaluate_vector(vector)[0], "fail")
                with self.assertRaises(ref.Invalid):
                    ref.validate_schema(evidence, "atomic-settlement-evidence-v1.schema.json")
                # Without the schema layer, the reference's own check refuses it.
                with mock.patch.object(ref, "validate_schema", lambda *args, **kwargs: None):
                    self.assertEqual(
                        ref.evaluate_vector(vector),
                        ("fail", "Atomic evidence discriminator must be the only evidence selector"),
                    )
                self.assertIsNone(
                    dacs5_reference._authenticated_evidence_wire_type(evidence, dacs5_keys)
                )
        with mock.patch.object(ref, "validate_schema", lambda *args, **kwargs: None):
            self.assertEqual(ref.evaluate_vector(control), ("pass", "predicate accepted"))
            self.assertEqual(
                ref.evaluate_vector(by_name["aws-neither-evidence-discriminator"]),
                ("fail", "Atomic evidence discriminator must be the only evidence selector"),
            )

    def test_presented_by_resolves_to_exactly_one_distinct_claim(self):
        def signed(bundle):
            unsigned = {k: v for k, v in bundle.items() if k != "presentation"}
            digest = ref.sha256_hex(ref.jcs_bytes(unsigned))
            bundle["presentation"]["signatures"][0]["signature"] = ref.b64u(
                ref.ed25519_sign(
                    generator.SEEDS["buyer"],
                    b"dacs-bundle-presentation:v1:" + digest.encode("ascii"),
                )
            )
            return bundle

        bundle = generator.identity_bundle("buyer", [generator.CLAIMS["payer"]])
        ref._verify_identity_bundle(bundle, generator.PUBLIC_KEYS)

        repeated = copy.deepcopy(bundle)
        repeated["claims"].append(copy.deepcopy(repeated["claims"][0]))
        ref._verify_identity_bundle(signed(repeated), generator.PUBLIC_KEYS)

        ambiguous = copy.deepcopy(bundle)
        distinct = copy.deepcopy(ambiguous["claims"][0])
        distinct["metadata"] = {"nativeAccount": "dem-test-other"}
        ambiguous["claims"].append(distinct)
        with self.assertRaisesRegex(ref.Invalid, "multiple distinct claims"):
            ref._verify_identity_bundle(signed(ambiguous), generator.PUBLIC_KEYS)

    def test_native_account_claim_collapses_identical_repeats(self):
        # DACS-1 exact presented-claim resolution also governs the claim a
        # native account is read from: identical repeats collapse, distinct
        # matches stay ambiguous.
        bundle = generator.identity_bundle("seller")
        seller = generator.CLAIMS["seller"]
        self.assertEqual(
            ref._bundle_native_account(bundle, seller, "payee"), "dem-test-seller"
        )
        repeated = copy.deepcopy(bundle)
        repeated["claims"].append(copy.deepcopy(repeated["claims"][0]))
        self.assertEqual(
            ref._bundle_native_account(repeated, seller, "payee"), "dem-test-seller"
        )
        ambiguous = copy.deepcopy(bundle)
        ambiguous["claims"].append(
            {"ref": seller, "metadata": {"nativeAccount": "dem-test-other"}}
        )
        with self.assertRaisesRegex(ref.Unknown, "unique authenticated payee native-account"):
            ref._bundle_native_account(ambiguous, seller, "payee")
        purchase = next(
            data for data in self.sets
            if data["set"] == "atomic-work-purchase-completion-v0.1"
        )
        by_name = {vector["name"]: vector for vector in purchase["vectors"]}
        for name in (
            "awp-purchase-presenter-identical-duplicate",
            "awp-purchase-payee-presenter-identical-duplicate",
            "awp-purchase-listing-seller-presenter-identical-duplicate",
            "awp-completion-payee-presenter-identical-duplicate",
        ):
            with self.subTest(name=name):
                self.assertEqual(
                    ref.evaluate_vector(by_name[name]), ("pass", "predicate accepted")
                )

    def test_malformed_bundle_claim_is_a_structural_error(self):
        bundle = generator.identity_bundle("buyer", [generator.CLAIMS["payer"]])
        for label, claims in (
            ("non-object claim", [*bundle["claims"], generator.CLAIMS["buyer"]]),
            ("claim without ref", [*bundle["claims"], {"metadata": {}}]),
            ("non-string ref", [*bundle["claims"], {"ref": None}]),
            ("non-array container", {"0": bundle["claims"][0]}),
        ):
            with self.subTest(label=label):
                malformed = {**copy.deepcopy(bundle), "claims": claims}
                with self.assertRaises(ref.Malformed):
                    ref._verify_identity_bundle(malformed, generator.PUBLIC_KEYS)

    def test_whole_profile_admission_resolves_exactly_one_presented_claim(self):
        purchase = next(
            data for data in self.sets
            if data["set"] == "atomic-work-purchase-completion-v0.1"
        )
        by_name = {vector["name"]: vector for vector in purchase["vectors"]}
        ambiguous = "IdentityBundle presentedBy resolves to multiple distinct claims"
        for name, expected, reason in (
            ("awp-purchase-presenter-identical-duplicate", "pass", "predicate accepted"),
            ("awp-purchase-payer-presenter-ambiguous", "fail", ambiguous),
            ("awp-purchase-payee-presenter-ambiguous", "fail", ambiguous),
            ("awp-purchase-listing-seller-presenter-ambiguous", "fail", ambiguous),
            ("awp-completion-payer-presenter-ambiguous", "fail", ambiguous),
            (
                "awp-purchase-payer-bundle-claim-malformed", "error",
                "IdentityBundle claim container or claim is malformed",
            ),
        ):
            with self.subTest(name=name):
                vector = by_name[name]
                self.assertEqual(vector["expected"], expected)
                self.assertEqual(ref.evaluate_vector(vector), (expected, reason))

    def test_publication_proof_authenticates_create_only_prior_state(self):
        settlement = next(
            data for data in self.sets
            if data["set"] == "atomic-work-settlement-slot-v0.1"
        )
        by_name = {vector["name"]: vector for vector in settlement["vectors"]}
        self.assertEqual(
            ref.evaluate_vector(by_name["aws-atomic-publication-exact-replay"])[0],
            "pass",
        )
        for name, verdict in (
            ("aws-atomic-publication-write-condition-missing", "indeterminate"),
            ("aws-atomic-publication-prior-state-contradiction", "fail"),
            ("aws-atomic-publication-unsigned-mode-flip", "fail"),
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(by_name[name])[0], verdict)

    def test_receipt_witnesses_are_encoded_in_declared_evidence_fields(self):
        execution = next(
            data for data in self.sets
            if data["set"] == "atomic-work-execution-recovery-v0.1"
        )
        receipt = next(
            vector["input"]["receipt"] for vector in execution["vectors"]
            if vector["name"] == "aw-receipt-complete-and-final"
        )
        self.assertNotIn("stateWitness", receipt)
        self.assertEqual(
            set(receipt["businessState"]["evidence"]), {"kind", "value"}
        )
        self.assertEqual(set(receipt["finalityEvidence"]), {"kind", "value"})
        self.assertEqual(set(receipt["slotStateEvidence"]), {"kind", "value"})
        state_witness = json.loads(
            ref.b64u_decode(receipt["businessState"]["evidence"]["value"]).decode()
        )
        checkpoint = json.loads(
            ref.b64u_decode(receipt["finalityEvidence"]["value"]).decode()
        )
        self.assertEqual(
            receipt["businessState"]["preRoot"],
            ref.state_root(state_witness["preState"]),
        )
        ref.verify_embedded(
            state_witness, execution["publicKeys"], ref._STATE_TEST_DOMAIN
        )
        ref.verify_embedded(
            checkpoint, execution["publicKeys"], ref._CHECKPOINT_TEST_DOMAIN
        )

    def test_jcs_vector_hashes_recompute_exactly(self):
        for path, data in zip(self.paths, self.sets):
            with self.subTest(path=path.name):
                self.assertEqual(data["count"], len(data["vectors"]))
                self.assertEqual(data["hash"], ref.vector_hash(data["vectors"]))

    def test_every_expected_verdict_is_computed(self):
        verdict_counts = {verdict: 0 for verdict in ref.VERDICTS}
        for data in self.sets:
            for vector in data["vectors"]:
                actual, diagnostic = ref.evaluate_vector(vector)
                with self.subTest(set=data["set"], vector=vector["name"]):
                    self.assertEqual(actual, vector["expected"], diagnostic)
                verdict_counts[actual] += 1
        self.assertGreater(verdict_counts["pass"], 0)
        self.assertGreater(verdict_counts["fail"], 0)
        self.assertGreater(verdict_counts["indeterminate"], 0)
        # DACS uses ``error`` for a malformed/non-canonical address, distinct
        # from a well-formed semantic mismatch (``fail``).
        self.assertGreater(verdict_counts["error"], 0)

    def test_incidental_exception_is_error_never_fail(self):
        # Only a predicate's own Invalid is ``fail``.  A rejection that comes
        # from an incidental Python exception reports malformed input.
        by_name = {
            vector["name"]: vector
            for data in self.sets
            for vector in data["vectors"]
        }
        for name in ("aw-receipt-complete-and-final", "aws-final-work-receipt-bound"):
            vector = copy.deepcopy(by_name[name])
            self.assertEqual(ref.evaluate_vector(vector)[0], "pass")
            del vector["input"]["publicKeys"]
            with self.subTest(vector=name, dropped="publicKeys"):
                verdict, diagnostic = ref.evaluate_vector(vector)
                self.assertEqual(verdict, "error", diagnostic)
                self.assertTrue(diagnostic.startswith("KeyError"), diagnostic)
        for exception in (KeyError("x"), TypeError("x"), IndexError("x"), ValueError("x")):
            def evaluator(_data, exception=exception):
                raise exception
            with self.subTest(raised=type(exception).__name__):
                with mock.patch.dict(ref.EVALUATORS, {"receipt": evaluator}):
                    verdict, _ = ref.evaluate_vector({"surface": "receipt", "input": {}})
                self.assertEqual(verdict, "error")

        def invalid(_data):
            raise ref.Invalid("predicate rejected")
        with mock.patch.dict(ref.EVALUATORS, {"receipt": invalid}):
            self.assertEqual(
                ref.evaluate_vector({"surface": "receipt", "input": {}}),
                ("fail", "predicate rejected"),
            )

    def test_fixed_seed_signatures_without_optional_crypto(self):
        seed = bytes.fromhex("9d" * 32)
        message = b"Atomic DACS Work deterministic signature self-test"
        public = ref.ed25519_public_key(seed)
        signature = ref.ed25519_sign(seed, message)
        self.assertTrue(ref.ed25519_verify(public, message, signature))
        self.assertFalse(ref.ed25519_verify(public, message + b"!", signature))

    def test_rfc8032_ed25519_known_answer(self):
        seed = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc4"
            "4449c5697b326919703bac031cae7f60"
        )
        public = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a"
            "0ee172f3daa62325af021a68f707511a"
        )
        signature = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a"
            "84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46b"
            "d25bf5f0595bbe24655141438e7a100b"
        )
        self.assertEqual(ref.ed25519_public_key(seed), public)
        self.assertEqual(ref.ed25519_sign(seed, b""), signature)
        self.assertTrue(ref.ed25519_verify(public, b"", signature))

    def test_ed25519_refuses_off_curve_point_encodings(self):
        # RFC 8032 §5.1.3: y names a curve point only when u/v is a square
        # mod p (u = y^2 - 1, v = d*y^2 + 1).  Euler's criterion finds the
        # first canonical y that names none, independently of the decoder.
        q = 2**255 - 19
        d = (-121665 * pow(121666, q - 2, q)) % q
        y = next(
            candidate for candidate in range(2, 1000)
            if pow(
                (candidate * candidate - 1)
                * pow(d * candidate * candidate + 1, q - 2, q) % q,
                (q - 1) // 2,
                q,
            ) == q - 1
        )
        off_curve = int.to_bytes(y, 32, "little")
        with self.assertRaisesRegex(ref.Invalid, "not on the curve"):
            ref._decode_point(off_curve)
        seed = bytes.fromhex("9d" * 32)
        message = b"Atomic DACS Work off-curve public key"
        signature = ref.ed25519_sign(seed, message)
        self.assertFalse(ref.ed25519_verify(off_curve, message, signature))
        # The same encoding as R is refused before the group equation.
        self.assertFalse(
            ref.ed25519_verify(
                ref.ed25519_public_key(seed), message, off_curve + signature[32:]
            )
        )

    def test_ed25519_refuses_x_zero_with_the_sign_bit_set(self):
        # RFC 8032 §5.1.3 step 4: decoding fails when x = 0 and the sign bit
        # is 1.  y = 1 and y = p - 1 are the two curve points with x = 0, so
        # the on-curve check accepts them and only the canonical re-encoding
        # refuses the sign-bit twin.
        for name, clear, signed in (
            ("y = 1", "01" + "00" * 31, "01" + "00" * 30 + "80"),
            ("y = p - 1", "ec" + "ff" * 30 + "7f", "ec" + "ff" * 31),
        ):
            with self.subTest(point=name):
                self.assertEqual(ref._decode_point(bytes.fromhex(clear))[0], 0)
                with self.assertRaisesRegex(ref.Invalid, "non-canonical Ed25519 encoding"):
                    ref._decode_point(bytes.fromhex(signed))

    def test_ed25519_refuses_non_reduced_s(self):
        # RFC 8032 §5.1.7: s MUST be < L.  s + L is the classic malleated
        # twin: it satisfies the group equation, so only this bound refuses it.
        seed = bytes.fromhex("9d" * 32)
        message = b"Atomic DACS Work signature malleability"
        public = ref.ed25519_public_key(seed)
        signature = ref.ed25519_sign(seed, message)
        self.assertTrue(ref.ed25519_verify(public, message, signature))
        s = int.from_bytes(signature[32:], "little")
        malleated = signature[:32] + int.to_bytes(s + ref._L, 32, "little")
        self.assertFalse(ref.ed25519_verify(public, message, malleated))

    def test_rfc6962_tree_does_not_duplicate_odd_leaf(self):
        leaves = [
            {
                "operationId": f"op-{i}",
                "operationIndex": i,
                "operationKind": "assert-artifact",
                "inputHash": f"{i:064x}",
                "status": "committed",
            }
            for i in range(3)
        ]
        root = ref.operation_receipt_root(leaves)
        for index, leaf in enumerate(leaves):
            path = ref.inclusion_path(leaves, index)
            self.assertTrue(ref.verify_inclusion(leaf, path, root))
        duplicated = ref.operation_receipt_root(leaves + [leaves[-1]])
        self.assertNotEqual(root, duplicated)

    def test_generator_check_is_byte_exact(self):
        run = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "generate_atomic_work_vectors.py"), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("6 byte-identical sets", run.stdout)


def _without_calls(function, callee: str):
    """Recompile ``function`` with every bare ``callee(...)`` statement removed."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    removed = []

    class StripCalls(ast.NodeTransformer):
        def visit_Expr(self, node):
            call = node.value
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == callee
            ):
                removed.append(call)
                return None
            return node

    tree = ast.fix_missing_locations(StripCalls().visit(tree))
    namespace = {}
    exec(
        compile(
            tree, inspect.getsourcefile(function), "exec",
            flags=__future__.annotations.compiler_flag, dont_inherit=True,
        ),
        function.__globals__, namespace,
    )
    return namespace[function.__name__], len(removed)


def _without_assignment(function, source: str):
    """Recompile ``function`` with every assignment whose source is ``source`` removed."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    removed = []

    class StripAssignment(ast.NodeTransformer):
        def visit_Assign(self, node):
            if ast.unparse(node) != source:
                return node
            removed.append(node)
            return ast.copy_location(ast.Pass(), node)

    tree = ast.fix_missing_locations(StripAssignment().visit(tree))
    namespace = {}
    exec(
        compile(
            tree, inspect.getsourcefile(function), "exec",
            flags=__future__.annotations.compiler_flag, dont_inherit=True,
        ),
        function.__globals__, namespace,
    )
    return namespace[function.__name__], len(removed)


class AtomicPresenterWiringWitnessTests(unittest.TestCase):
    """The whole-profile vectors, not only the helper test, pin the wiring."""

    def _run(self, method_name):
        result = unittest.TestResult()
        unittest.TestSuite([AtomicWorkVectorTests(method_name)]).run(result)
        self.assertEqual(1, result.testsRun)
        return result

    def test_authority_context_presenter_wiring_is_load_bearing(self):
        consumer = "test_whole_profile_admission_resolves_exactly_one_presented_claim"
        helper = "test_presented_by_resolves_to_exactly_one_distinct_claim"
        control = self._run(consumer)
        self.assertEqual([], control.failures + control.errors + control.skipped)

        # Wrong implementation: the authority context no longer consumes the
        # exact presented-claim resolution for the payer and payee bundles.
        mutant, removed = _without_calls(
            ref._verified_authority_context, "_verify_identity_bundle"
        )
        self.assertEqual(removed, 2)
        with mock.patch.object(ref, "_verified_authority_context", mutant):
            caught = self._run(consumer)
            helper_only = self._run(helper)
        self.assertEqual([], caught.errors + caught.skipped)
        self.assertTrue(caught.failures, "whole-profile vectors did not catch the mutation")
        failures = "\n".join(test.id() for test, _ in caught.failures)
        self.assertIn("awp-purchase-payee-presenter-ambiguous", failures)
        self.assertIn("awp-completion-payer-presenter-ambiguous", failures)
        # The direct helper test alone cannot see the missing consumer wiring.
        self.assertEqual([], helper_only.failures + helper_only.errors)


def _without_guard(function, reason: str, operand: int | None = None):
    """Recompile ``function`` without the ``if`` guard that raises ``reason``.

    ``reason`` is the raised string constant, or the source text of a raised
    f-string such as ``f'... {field}'``.  With ``operand``, only that operand
    of the guard's boolean condition is removed; otherwise the whole guard is.
    """
    tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    removed = []

    def raised_text(argument):
        if isinstance(argument, ast.Constant):
            return argument.value
        return ast.unparse(argument) if isinstance(argument, ast.JoinedStr) else None

    class StripGuard(ast.NodeTransformer):
        def visit_If(self, node):
            self.generic_visit(node)
            raised = node.body[0] if len(node.body) == 1 else None
            if not (
                isinstance(raised, ast.Raise)
                and isinstance(raised.exc, ast.Call)
                and len(raised.exc.args) == 1
                and raised_text(raised.exc.args[0]) == reason
            ):
                return node
            removed.append(node)
            if operand is None:
                # ``pass`` keeps an enclosing block valid when the guard is
                # its only statement.
                return ast.copy_location(ast.Pass(), node)
            kept = [v for i, v in enumerate(node.test.values) if i != operand]
            node.test = kept[0] if len(kept) == 1 else ast.BoolOp(node.test.op, kept)
            return node

    tree = ast.fix_missing_locations(StripGuard().visit(tree))
    namespace = {}
    exec(
        compile(
            tree, inspect.getsourcefile(function), "exec",
            flags=__future__.annotations.compiler_flag, dont_inherit=True,
        ),
        function.__globals__, namespace,
    )
    return namespace[function.__name__], len(removed)


class AtomicEffectInventoryGuardWitnessTests(unittest.TestCase):
    """Twenty-one AW-44 inventory and AWS-4 slot guards, each caught by a committed vector.

    Equivalent mutants, which no vector can distinguish and which are
    therefore not rows: the ``_composed_slot_action`` raise for a signed CAS
    naming neither ``vacant`` nor ``rolled-back`` (its ``None`` action fails
    as an unknown slot transition), and the retry extension of the
    slot-before-payment order check in ``evaluate_slot`` (``_profile_shape``
    already requires that order on every admission path).  The repeated-entry
    and observation guards are pinned by the reason their vectors move to.
    """

    PASS = ("pass", "predicate accepted")
    # (function, wrong implementation, (vector, exact result without the
    # guard)).  The expected result is where the verdict moves: to ``pass``,
    # or, where a later guard keeps the verdict, to that guard's reason.  An
    # exact result keeps a recompiled function that is merely broken from
    # counting as caught.
    WRONG_IMPLEMENTATIONS = (
        ("_verify_effect_inventory", ("call", "verify_embedded"), (
            ("awp-composed-effect-inventory-signature-invalid", PASS),
            ("awp-composed-effect-inventory-unsigned",
             ("fail", "signer is not a canonical ClaimReference string")),
        )),
        ("_verify_effect_inventory", ("call", "require_signer"), (
            ("awp-composed-effect-inventory-participant-signed", PASS),
        )),
        ("_verify_effect_inventory",
         ("guard", "authenticated Work-ledger effect inventory unavailable", None), (
            # Without the guard, the absent inventory reaches the shape check,
            # whose incidental TypeError is malformed input, not ``fail``.
            ("awp-composed-effect-inventory-missing",
             ("error", "TypeError: 'NoneType' object is not iterable")),
        )),
        ("_verify_effect_inventory",
         ("guard", "synthetic Work-ledger effect inventory shape mismatch", None), (
            ("awp-composed-effect-inventory-unknown-member", PASS),
            ("awp-composed-effect-inventory-version-unsupported", PASS),
        )),
        ("_verify_effect_inventory",
         ("guard", "synthetic Work-ledger effect inventory shape mismatch", 1), (
            ("awp-composed-effect-inventory-version-unsupported", PASS),
        )),
        ("_verify_effect_inventory",
         ("guard", "Work-ledger effect inventory names another Work", None), (
            ("awp-composed-effect-inventory-other-work", PASS),
        )),
        ("_verify_effect_inventory",
         ("guard", "Work-ledger effect inventory proof-profile binding mismatch", 0), (
            ("awp-composed-effect-inventory-other-proof-profile", PASS),
        )),
        ("_verify_effect_inventory",
         ("guard", "Work-ledger effect inventory proof-profile binding mismatch", 1), (
            ("awp-composed-effect-inventory-other-validator-set", PASS),
        )),
        ("_verify_effect_inventory",
         ("guard", "Work-ledger effect inventory is not taken at the finalized receipt block", None), (
            ("awp-composed-effect-inventory-other-block", PASS),
        )),
        ("_verify_effect_inventory",
         ("guard", "authenticated ledger block for the Work-ledger effect inventory unavailable", None), (
            ("aw-effect-inventory-unbound-without-receipt",
             ("fail", "Work-ledger effect inventory is not taken at the authenticated lifecycle-evidence block")),
        )),
        ("_verify_effect_inventory",
         ("guard", "Work-ledger effect inventory is not taken at the authenticated lifecycle-evidence block", None), (
            ("aw-effect-inventory-stale-without-receipt", PASS),
        )),
        ("_verify_effect_inventory",
         ("guard", "Work-ledger effect inventory entry malformed", None), (
            ("awp-composed-effect-inventory-entry-unknown-member", PASS),
        )),
        ("_verify_effect_inventory",
         ("guard", "Work-ledger effect inventory repeats an attempt", None), (
            ("awp-composed-effect-inventory-repeated-attempt",
             ("fail", "late/competing attempt was not fenced")),
        )),
        ("evaluate_attempts",
         ("guard", "a caller-supplied business-effect list is not Work-ledger authority", None), (
            ("awp-composed-effect-source-unauthenticated",
             ("indeterminate", "authenticated Work-ledger effect inventory unavailable")),
            ("awp-composed-effect-source-caller-empty", PASS),
            ("awp-composed-effect-source-unauthenticated-late-inventory",
             ("fail", "late/competing attempt was not fenced")),
        )),
        ("evaluate_attempts",
         ("guard", "business effect recorded without a ledger-selected winner", None), (
            ("aw-replacement-effect-without-winner", PASS),
        )),
        ("evaluate_attempts",
         ("guard", "Work-ledger effect inventory records a business effect for a rolled-back winner", None), (
            ("aw-rolled-back-winner-business-effect-recorded", PASS),
        )),
        ("evaluate_attempts",
         ("guard", "Work-ledger effect inventory omits the ledger-selected winner", None), (
            ("awp-composed-effect-inventory-other-attempt", PASS),
        )),
        ("evaluate_attempts",
         ("guard", "late/competing attempt was not fenced", None), (
            ("awp-composed-effect-inventory-late-attempt", PASS),
            ("awp-completion-composed-effect-inventory-late-attempt", PASS),
        )),
        ("evaluate_attempts",
         ("guard", "Work-ledger effect inventory winner reference mismatch", None), (
            ("awp-composed-effect-inventory-winner-reference-mismatch", PASS),
        )),
        ("_evaluate_composed_admission",
         ("guard", "an observation is not composed Purchase slot admission", None), (
            ("awp-composed-slot-transition-observation-only",
             ("fail", "caller slot action differs from the signed slot transition")),
            ("awp-composed-slot-transition-committed-observation",
             ("fail", "caller slot action differs from the signed slot transition")),
        )),
        ("_evaluate_composed_admission",
         ("guard", "caller slot action differs from the signed slot transition", None), (
            ("awp-composed-slot-transition-caller-mismatch", PASS),
        )),
    )

    def test_each_effect_inventory_and_slot_guard_is_load_bearing(self):
        by_name = {}
        for name in (
            "atomic-work-purchase-completion-v0.1", "atomic-work-execution-recovery-v0.1",
        ):
            data = json.loads(
                (ROOT / "conformance" / "vectors" / "security" / f"{name}.json")
                .read_text(encoding="utf-8")
            )
            by_name.update((vector["name"], vector) for vector in data["vectors"])
        for function_name, (kind, *target), caught_by in self.WRONG_IMPLEMENTATIONS:
            with self.subTest(function=function_name, removed=target):
                function = getattr(ref, function_name)
                for name, moved in caught_by:
                    control = ref.evaluate_vector(by_name[name])
                    self.assertEqual(control[0], by_name[name]["expected"], name)
                    self.assertNotEqual(moved, control, name)
                if kind == "call":
                    wrong, removed = _without_calls(function, *target)
                else:
                    wrong, removed = _without_guard(function, *target)
                self.assertEqual(removed, 1)
                # A surface that dispatches to the function directly is
                # patched too, not only callers that look it up by name.
                dispatch = {
                    surface: wrong for surface, evaluator in ref.EVALUATORS.items()
                    if evaluator is function
                }
                with mock.patch.object(ref, function_name, wrong), \
                        mock.patch.dict(ref.EVALUATORS, dispatch):
                    for name, moved in caught_by:
                        self.assertEqual(ref.evaluate_vector(by_name[name]), moved, name)


class AtomicPredicatePinWitnessTests(unittest.TestCase):
    """Each re-signed predicate-pinning vector is caught by its own guard.

    The ``predicate_pin_vectors`` cases re-derive every signature, hash,
    root, commitment, address and publication, so removing the one guard
    each targets moves its verdict: to ``pass``, or, where a second guard
    also enforces the rule, to that guard's exact result.  Rejections that
    the JSON Schema decides first are pinned by the layered tests below and
    by scripts/validate_atomic_work_schemas.py.
    """

    PASS = ("pass", "predicate accepted")
    # (function, raised reason, ((vector, exact result without the guard), ...))
    GUARDS = (
        ("verify_receipt", "Purchase Work does not carry exactly one signed payment slot", (
            ("aw-receipt-multiple-signed-slot-operations", PASS),
            # No earlier predicate rejects a zero-slot Purchase: without the
            # guard the single-slot read itself fails.
            ("aw-receipt-no-signed-slot-operation", ("error", "IndexError: list index out of range")),
        )),
        ("verify_receipt", "retry receipt is not bound to complete prior rolled-back state", (
            ("aw-receipt-retry-prior-failure-commitment-differs", PASS),
            ("aw-receipt-retry-prior-digest-differs", PASS),
        )),
        ("validate_intent", "duplicate operationId", (
            ("aw-operation-id-duplicate", PASS),
        )),
        ("verify_receipt", "Purchase signed slot key differs from top-level intent tuple", (
            ("aw-receipt-signed-slot-tuple-differs", PASS),
        )),
        ("evaluate_profile", "Purchase signed Listing pay-dem phase tuple mismatch", (
            ("awp-profile-pay-dem-tuple-differs", PASS),
        )),
        ("evaluate_expiry", "Work expired before its first operation", (
            ("aw-expiry-equality-after-first-operation", PASS),
        )),
        ("_verify_rail_registry_resolution", "rail definition was not accepted and pinned by session start", (
            ("aw-auth-rail-registry-index-receipt-after-session", PASS),
            ("aw-auth-rail-rail-definition-receipt-after-session", PASS),
        )),
        ("_verified_authority_context", "payer roster account is not bundle-derived", (
            ("aw-auth-roster-payer-account-not-bundle-derived", PASS),
        )),
        ("_verified_authority_context", "seller roster account is not bundle-derived", (
            ("aw-auth-roster-seller-account-not-bundle-derived", PASS),
        )),
        ("verify_receipt", "receipt workId mismatch", (
            ("aw-receipt-of-another-work", PASS),
        )),
        ("verify_receipt", "receipt operation count mismatch", (
            ("aw-receipt-results-count-short", PASS),
        )),
        ("verify_receipt", "receipt operation order or identity mismatch", (
            ("aw-receipt-operation-identity-swapped", PASS),
        )),
        ("verify_receipt", "operation receipt inputHash mismatch", (
            ("aw-receipt-input-hash-consistent-mismatch", PASS),
        )),
        ("verify_receipt", "synthetic proof profile outputHash mismatch", (
            ("aw-receipt-output-hash-consistent-mismatch", PASS),
        )),
        ("verify_receipt", "operationReceiptRoot mismatch", (
            ("aw-receipt-root-claim-consistent-mismatch", PASS),
        )),
        ("verify_receipt", "business-state root mismatch", (
            ("aw-receipt-pre-root-consistent-mismatch", PASS),
        )),
        ("verify_receipt", "synthetic proof profile effectsRoot mismatch", (
            ("aw-receipt-effects-root-consistent-mismatch", PASS),
        )),
        ("verify_receipt", "receipt paymentSlot key does not match Work intent", (
            ("aw-receipt-slot-key-other-phase", PASS),
        )),
        ("verify_receipt", "receiptCommitment does not match canonical receipt core", (
            ("aw-receipt-field-changed-after-commitment", PASS),
        )),
        ("_validated_storage_output", "storageOutput contradicts the signed storage payload", (
            ("aw-receipt-storage-output-address-differs", PASS),
        )),
        ("consume_capability_for_intent", "capability networkId does not admit the Work intent", (
            ("aw-receipt-capability-other-network", PASS),
            ("aws-settlement-capability-other-network", ("fail", "authenticated capability/Listing/agreement/rail/phase namespace mismatch")),
        )),
        ("_verified_authority_context", "AtomicPaymentPhaseInputV1 is not the closed v1 shape", (
            ("aw-auth-pc1-ordinary-arm-not-coerced", ("fail", "authenticated capability/Listing/agreement/rail/phase namespace mismatch")),
            ("aw-auth-pc1-both-arm-members", PASS),
            ("awp-composed-pc1-ordinary-arm-not-coerced", ("fail", "authenticated capability/Listing/agreement/rail/phase namespace mismatch")),
        )),
        ("_verify_identity_bundle", "pinned payer IdentityBundle malformed", (
            ("awp-composed-payer-bundle-version-2", PASS),
        )),
        ("verify_receipt", "rolled-back receipt changed business state", (
            ("aw-rolled-back-receipt-changes-business-state", ("fail", "rollback output changed or non-membership contradicted")),
        )),
        ("verify_receipt", "rollback leaf status mismatch", (
            ("aw-rolled-back-later-operation-marked-rolled-back", PASS),
        )),
        ("verify_receipt", "rolled-back Purchase slot transition contradicts signed CAS payload", (
            ("aw-rolled-back-slot-generation-advanced", PASS),
        )),
        ("verify_receipt", "Completion Work unexpectedly changed payment slot", (
            ("aw-completion-receipt-slot-after-changed", PASS),
        )),
        ("verify_receipt", "Completion slot state is not the verified Purchase terminal state", (
            ("aw-completion-slot-not-copied-from-purchase", PASS),
            ("awp-completion-composed-slot-not-copied-from-purchase", PASS),
        )),
        ("verify_receipt", "Completion embedded receipt differs from verified Purchase receipt", (
            ("aw-completion-embeds-other-purchase-receipt", ("fail", "Completion slot state is not the verified Purchase terminal state")),
        )),
        ("verify_receipt", "Completion/Purchase tuple mismatch", (
            ("aw-completion-receipt-for-other-job", PASS),
        )),
        ("verify_receipt", "Completion prior Purchase lacks committed native transfer", (
            ("aw-completion-after-rolled-back-purchase", ("fail", "Completion slot state is not the verified Purchase terminal state")),
        )),
        ("verify_receipt", "rolled-back Completion changed Purchase slot metadata", (
            ("aw-completion-rolled-back-slot-changed", PASS),
        )),
        ("evaluate_attempts", "attempt changes canonical Work bytes or workId", (
            ("aw-attempt-changed-bytes-inventory-consistent", PASS),
        )),
        ("evaluate_attempts", "ledger selected more than one included attempt", (
            ("aw-two-included-attempts-inventory-names-one", PASS),
        )),
        ("evaluate_attempts", "included or unresolved attempt cannot be replaced", (
            ("aw-replacement-for-included-attempt", PASS),
        )),
        ("evaluate_attempts", "attempt evidence tuple mismatch", (
            ("aw-lifecycle-evidence-names-other-attempt", PASS),
        )),
        ("evaluate_attempts", "exact replay did not return selected winner", (
            ("aw-replay-returns-other-winner", PASS),
        )),
        ("evaluate_attempts", "invalid or duplicate attemptId", (
            ("aw-attempts-duplicate-attempt-id", PASS),
        )),
        ("evaluate_limits", "canonical Work exceeds node byte limit", (
            ("aw-canonical-byte-limit-one-over", PASS),
        )),
        ("evaluate_limits", "Work exceeds node operation limit", (
            ("aw-operation-count-limit-one-over", PASS),
        )),
        ("evaluate_limits", "Work exceeds node execution-time limit", (
            ("aw-execution-time-limit-one-over", PASS),
        )),
        ("evaluate_projection", "operation leaf inclusion proof invalid", (
            ("aw-anchor-inclusion-path-consistent-invalid", PASS),
        )),
        ("evaluate_projection", "projected receipt evidence does not resolve verified Work proof", (
            ("aw-anchor-resolved-receipt-hash-differs", PASS),
        )),
        ("_profile_shape", "profile operation order/dependencies/roles mismatch", (
            ("awp-composed-payment-required-roles-empty", PASS),
            ("awp-composed-operation-kind-differs", PASS),
            ("awp-composed-dependencies-differ", PASS),
            ("awp-completion-delivery-required-roles-empty", PASS),
        )),
        ("_verify_agreement_listing", "Agreement fixed price differs from Listing", (
            ("awp-composed-agreement-price-differs-from-listing", PASS),
        )),
        ("_verify_agreement_listing", "Agreement deliverable differs from Listing DeliverableSpec", (
            ("awp-composed-agreement-deliverable-hash-differs", PASS),
        )),
        ("_verify_agreement_listing", "Agreement deadline exceeds Listing commitment-relative bound", (
            ("awp-composed-deadline-exceeds-listing-bound", PASS),
        )),
        ("_verify_agreement_listing", "Listing expired before commitment", (
            ("awp-composed-listing-expired-before-commit", PASS),
        )),
        ("_verify_agreement_listing", "Agreement pattern differs from Listing pipeline", (
            ("awp-composed-listing-negotiation-pattern-differs", PASS),
        )),
        ("_verify_agreement_listing", "Agreement artifact discriminator mismatches commitment phase", (
            ("awp-composed-listing-commit-phase-differs", PASS),
        )),
        ("_verify_agreement_listing", "Agreement rail does not match pinned Listing pipeline", (
            ("awp-composed-agreement-rail-not-accepted", PASS),
            ("awp-composed-two-pay-dem-phases", ("fail", "pinned Listing does not define exactly one pay-dem phase")),
        )),
        ("_verify_agreement_listing", "Agreement does not pin exact Listing", (
            ("awp-composed-agreement-pins-other-listing-version", PASS),
        )),
        ("_verify_listing", "Listing signer does not match seller IdentityBundle", (
            ("awp-composed-listing-signed-by-orchestrator", PASS),
        )),
        ("_verify_listing", "pinned Listing malformed", (
            ("awp-composed-listing-dacs-version-2", PASS),
        )),
        ("_verify_rail_definition", "native-DEM RailDefinition violates RD-3/RD-5/RD-6/RAV-1", (
            ("awp-composed-rail-phase-handler-not-pay-dem", PASS),
        )),
        ("_verify_rail_registry_resolution", "rail-registry index snapshot is malformed or unpinned", (
            ("awp-composed-registry-index-version-differs", PASS),
        )),
        ("_verify_rail_registry_resolution", "pinned registry rail content hash mismatch", (
            ("awp-composed-registry-index-content-hash-differs", PASS),
        )),
        ("_verify_identity_bundle", "payer IdentityBundle presentation signature invalid", (
            ("awp-composed-payer-bundle-presentation-invalid", PASS),
        )),
        ("_agreement_artifact_kind", "agreement artifact discriminator version unsupported", (
            ("awp-composed-agreement-discriminator-version-2", PASS),
        )),
        ("_verify_current_profile_admission", "current Atomic payment requires IdentityBoundPayeeAgreementDocument", (
            ("awp-composed-payee-bound-agreement-with-current-admission", PASS),
        )),
        ("evaluate_profile", "commitment artifact discriminator mismatch", (
            ("awp-composed-commitment-version-2", PASS),
        )),
        ("_verify_commitment_subject", "finality commitment does not bind exact job/agreement/listing tuple", (
            ("awp-composed-commitment-subject-other-job", PASS),
        )),
        ("_verify_composite_record", "Vet artifact is not a CompositeVerificationRecord v1", (
            ("awp-composed-vet-record-version-2", PASS),
        )),
        ("_verify_composite_record", "CompositeVerificationRecord subject/bundle binding mismatch", (
            ("awp-composed-vet-record-bundle-hash-differs", PASS),
        )),
        ("_verify_composite_record", "CompositeVerificationRecord does not establish a pass decision", (
            ("awp-composed-vet-record-decision-fail", PASS),
        )),
        ("_verify_anchor_receipt", "AnchorReceipt does not establish finalized artifact binding", (
            ("awp-sequential-commitment-receipt-other-content", ("fail", "AnchorReceipt finality proof subject mismatch")),
        )),
        ("_verify_atomic_payment_session_context", "AtomicPaymentSessionContextV1 is not the closed v1 shape", (
            ("awp-composed-session-context-version-2", ("fail", "Atomic payment session is not the authenticated source projection")),
        )),
        ("_verify_atomic_payment_session_context", "authenticated SessionContext source contradicts DACS authority", (
            ("awp-composed-session-source-prior-agreement-differs", PASS),
        )),
        ("_verify_atomic_payment_session_context", "Atomic payment session evidence subject mismatch", (
            ("awp-composed-session-evidence-for-other-context", PASS),
        )),
        ("_verified_authority_context", "AtomicPaymentPhaseInputV1 is not bound to authenticated parties/agreement", (
            ("awp-composed-payment-input-amount-differs", ("fail", "AtomicPaymentPhaseInputV1 is not bound to verified bundles, rail, and agreement")),
        )),
        ("_verify_composed_static_limits", "composed Work exceeds authenticated canonical-byte limit", (
            ("awp-composed-canonical-bytes-over", PASS),
        )),
        ("_verify_composed_static_limits", "composed Work exceeds authenticated operation limit", (
            ("awp-composed-operation-count-over", PASS),
        )),
        ("_verify_composed_result_limits", "authenticated composed-limit metrics are malformed or mismatched", (
            ("awp-composed-limit-metrics-for-other-work", PASS),
        )),
        ("_verify_proof_reservation", "authenticated proof-byte reservation is mismatched", (
            ("awp-composed-reservation-for-other-work", PASS),
        )),
        ("evaluate_profile", "Vet storage operation address/write condition mismatch", (
            ("awp-profile-vet-address-consistent-receipt", PASS),
        )),
        ("evaluate_profile", "signed commitment address/write condition mismatch", (
            ("awp-profile-commitment-address-consistent-receipt", PASS),
            ("awp-profile-commitment-cas-consistent-receipt", PASS),
        )),
        ("evaluate_profile", "Purchase commitment projection selects the wrong operation", (
            ("awp-completion-commitment-projection-selects-buyer-vet", PASS),
        )),
        ("verify_settlement", "paymentAmount does not match payment operation", (
            ("aws-settlement-payment-amount-differs", PASS),
        )),
        ("verify_settlement", "evidence signer is not authenticated phase orchestrator", (
            ("aws-settlement-signed-by-buyer-not-orchestrator", PASS),
        )),
        ("verify_settlement", "Atomic Work receipt reference mismatch", (
            ("aws-settlement-receipt-ref-content-hash-differs", PASS),
        )),
        ("verify_settlement", "settlement operation reference mismatch", (
            ("aws-settlement-operation-ref-differs-from-subject", PASS),
        )),
        ("verify_settlement", "operation proof subject required member mismatch", (
            ("aws-settlement-subject-winner-differs", PASS),
        )),
        ("verify_settlement", "operation receipt inclusion path invalid", (
            ("aws-settlement-inclusion-path-for-other-leaf", PASS),
        )),
        ("verify_settlement", "success evidence does not select a committed operation", (
            ("aws-settlement-success-on-rolled-back-receipt", PASS),
        )),
        ("verify_settlement", "failure evidence does not select a rollback operation", (
            ("aws-settlement-failure-on-committed-receipt", PASS),
        )),
        ("verify_settlement", "deliverable content hash mismatch", (
            ("aws-settlement-delivery-content-hash-differs", PASS),
        )),
        ("verify_settlement", "deliverable anchor mismatch", (
            ("aws-settlement-delivery-anchor-differs", PASS),
        )),
        ("verify_embedded", "unsupported signature algorithm", (
            ("aws-settlement-signature-algorithm-label", PASS),
        )),
        ("verify_atomic_evidence_address", "Atomic payment address generation mismatch", (
            ("aws-settlement-address-other-generation", ("fail", "Atomic evidence address mismatch")),
        )),
        ("verify_atomic_evidence_address", "Atomic payment jobId is not a ULID", (
            ("aws-evidence-address-job-id-not-ulid", ("fail", "Atomic evidence address mismatch")),
            ("aws-evidence-address-job-id-first-character-8", ("fail", "Atomic evidence address mismatch")),
        )),
        ("cf4_decode", "non-canonical CF-4 escape", (
            ("aws-evidence-address-rail-cf4-lowercase-escape", ("error", "non-canonical CF-4 segment")),
        )),
        ("verify_atomic_evidence_address", "invalid Atomic payment address shape", (
            ("aws-evidence-address-atomic-label-missing", ("fail", "Atomic evidence address mismatch")),
            ("aws-evidence-address-segment-count", ("error", "IndexError: list index out of range")),
        )),
        ("verify_atomic_evidence_address", "Atomic payment settlement ID is not lowercase hex", (
            ("aws-evidence-address-settlement-id-uppercase", ("fail", "Atomic evidence address mismatch")),
        )),
        ("evaluate_slot", "invalid claim CAS transition", (
            ("aws-slot-claim-generation-advanced", PASS),
        )),
        ("evaluate_slot", "replay is not exact", (
            ("aws-slot-inflight-replay-other-work", PASS),
        )),
        ("evaluate_slot", "settled replay did not return receipt", (
            ("aws-slot-settled-replay-other-receipt", PASS),
        )),
        ("evaluate_slot", "replay executes another transfer", (
            ("aws-slot-replay-executes-transfer", PASS),
        )),
        ("evaluate_slot", "slot jobId is not a canonical uppercase ULID", (
            ("aws-slot-job-id-first-character-8", ("fail", "slot key differs component-wise or by type")),
        )),
        ("evaluate_audit", "audit dependency proof does not bind a finalized Work operation", (
            ("awb-audit-dependency-proof-wrong-receipt-hash", PASS),
        )),
        ("verify_capability", "capability network authority differs from trusted registry", (
            ("aw-capability-self-declared-authority", PASS),
        )),
        ("verify_capability", "capability attestation hash mismatch", (
            ("aw-capability-attestation-for-other-capability", PASS),
        )),
    )
    ENVELOPE = "f'authorization envelope mismatch: {field}'"
    RAIL_TIME = "rail definition was not accepted and pinned by session start"
    INTENT_SCHEMA = "atomic-dacs-work-intent-v1.schema.json"
    EVIDENCE_SCHEMA = "atomic-settlement-evidence-v1.schema.json"
    JOB_ID_SCHEMAS = {
        "atomic-dacs-work-intent-v1.schema.json": ("properties", "jobId"),
        "atomic-work-authorization-v1.schema.json": ("properties", "jobId"),
        "atomic-payment-slot-cas-payload-v1.schema.json": ("properties", "slotKey", "properties", "jobId"),
        "atomic-work-receipt-v1.schema.json": ("$defs", "paymentSlotKey", "properties", "jobId"),
        "atomic-settlement-evidence-v1.schema.json": ("properties", "jobId"),
    }

    @classmethod
    def setUpClass(cls):
        cls.by_name = {}
        for name in generator.SET_SPECS:
            data = json.loads(
                (ROOT / "conformance" / "vectors" / "security" / f"{name}.json")
                .read_text(encoding="utf-8")
            )
            cls.by_name.update((vector["name"], vector) for vector in data["vectors"])

    def _evaluate(self, name):
        return ref.evaluate_vector(self.by_name[name])

    @contextlib.contextmanager
    def _without(self, function_name, reason, operand=None, removed=1):
        function = getattr(ref, function_name)
        wrong, count = _without_guard(function, reason, operand)
        self.assertEqual(count, removed, (function_name, reason))
        dispatch = {
            surface: wrong for surface, evaluator in ref.EVALUATORS.items()
            if evaluator is function
        }
        with mock.patch.object(ref, function_name, wrong), \
                mock.patch.dict(ref.EVALUATORS, dispatch):
            yield

    @contextlib.contextmanager
    def _schema_bypassed(self, schema_name):
        real = ref.validate_schema

        def validate(value, name):
            if name != schema_name:
                real(value, name)
        with mock.patch.object(ref, "validate_schema", validate):
            yield

    def _assert_moves(self, caught_by, *without, **options):
        for name, moved in caught_by:
            control = self._evaluate(name)
            self.assertEqual(control[0], self.by_name[name]["expected"], name)
            self.assertNotEqual(moved, control, name)
        with self._without(*without, **options):
            for name, moved in caught_by:
                self.assertEqual(self._evaluate(name), moved, name)

    def test_each_pinning_vector_is_caught_by_its_own_guard(self):
        for function_name, reason, caught_by in self.GUARDS:
            with self.subTest(function=function_name, reason=reason):
                self._assert_moves(caught_by, function_name, reason)

    def test_validly_signed_authorization_envelope_binds_every_member(self):
        # AW-31/AW-33/AW-36/AW-38: the payer's own valid signature over another
        # Work or context, or another signer's, is not this authorization.
        unexpected = ("fail", "unexpected or duplicate operation authorization")
        self._assert_moves((
            ("aw-auth-validly-signed-for-another-work", self.PASS),
            ("aw-auth-orchestrator-signs-as-payer", self.PASS),
            ("aw-auth-validly-signed-other-network", self.PASS),
            ("aw-auth-validly-signed-other-session", self.PASS),
            ("aw-auth-validly-signed-other-phase", self.PASS),
            ("aw-auth-validly-signed-other-rail", self.PASS),
            ("aw-auth-validly-signed-other-operation-index", unexpected),
            ("aw-auth-validly-signed-other-role", unexpected),
        ), "verify_authorizations", self.ENVELOPE, removed=2)

    def test_each_rail_receipt_time_bound_is_its_own_clause(self):
        # DACS-4 RTB-1: removing only the two receipt-time comparisons keeps
        # the acceptedAt bound, so its vector still fails for that reason.
        accepted_after = self._evaluate("aw-auth-rail-accepted-after-session")
        self.assertEqual(accepted_after, ("fail", self.RAIL_TIME))
        self._assert_moves((
            ("aw-auth-rail-registry-index-receipt-after-session", self.PASS),
            ("aw-auth-rail-rail-definition-receipt-after-session", self.PASS),
        ), "_verify_rail_registry_resolution", self.RAIL_TIME, operand=3)
        with self._without("_verify_rail_registry_resolution", self.RAIL_TIME, operand=3):
            self.assertEqual(
                self._evaluate("aw-auth-rail-accepted-after-session"), accepted_after
            )

    def test_sequential_listing_checks_read_the_commitment_anchor_time(self):
        # DACS-3 §8.5.2 checks 5 and 6: under the sequential gate committedAt
        # is the commitment AnchorReceipt time, where the authority context
        # reads it and where composed admission re-checks the Listing.
        past_bound = "awp-sequential-deadline-past-anchor-bound"
        at_anchor = "awp-sequential-listing-not-after-at-anchor-time"
        expired = ("fail", "Listing expired before commitment")
        self.assertEqual(
            self._evaluate(past_bound),
            ("fail", "Agreement deadline exceeds Listing commitment-relative bound"),
        )
        self.assertEqual(self._evaluate(at_anchor), self.PASS)
        # Wrong clock: the authority context keeps the later Work receipt time.
        wrong, removed = _without_assignment(
            ref._verified_authority_context, "effective_timestamp = anchor_timestamp"
        )
        self.assertEqual(removed, 1)
        with mock.patch.object(ref, "_verified_authority_context", wrong):
            self.assertEqual(self._evaluate(past_bound), self.PASS)
            self.assertEqual(self._evaluate(at_anchor), expired)
        # Composed admission passes the independently verified clock. The
        # focused surface also derives it when called without that keyword.
        with mock.patch.object(ref, "evaluate_profile", wraps=ref.evaluate_profile) as profile:
            self.assertEqual(self._evaluate(at_anchor), self.PASS)
            self.assertEqual(profile.call_args.kwargs["committed_at"], 1_800_000_000_000)

    def test_v1_four_role_roster_is_enforced_by_schema_and_reference(self):
        # AW-10: with the intent schema bypassed the reference still rejects
        # each short roster; without both layers each one is accepted.
        names = (
            "aw-v1-purchase-roster-missing-buyer",
            "aw-v1-purchase-roster-two-roles",
            "aw-v1-completion-roster-missing-payer",
        )
        reason = "v1 roleRoster does not carry all four roles"
        for name in names:
            self.assertEqual(self._evaluate(name)[0], "fail", name)
            self.assertIn("roleRoster", self._evaluate(name)[1], name)
        with self._schema_bypassed(self.INTENT_SCHEMA):
            for name in names:
                self.assertEqual(self._evaluate(name), ("fail", reason), name)
            with self._without("validate_intent", reason):
                for name in names:
                    self.assertEqual(self._evaluate(name), self.PASS, name)

    def test_unsupported_atomic_evidence_version_is_rejected_without_the_schema(self):
        # AWS-17: the explicit version comparison stays load-bearing if schema
        # validation is bypassed or widened.
        name = "aws-atomic-evidence-version-unsupported"
        reason = "legacy transaction reference is not Atomic settlement evidence"
        self.assertIn("atomicEvidenceVersion", self._evaluate(name)[1])
        with self._schema_bypassed(self.EVIDENCE_SCHEMA):
            self.assertEqual(self._evaluate(name), ("fail", reason))
            with self._without("verify_settlement", reason, operand=0):
                self.assertEqual(self._evaluate(name), self.PASS)

    # DACS-5 ST-11 / AWB-10 audit closure and DACS-3 AWP-17/AWP-18 remedies:
    # (function, raised reason, ((vector, exact result without the guard), ...))
    CLOSURE_GUARDS = (
        ("evaluate_audit", "audit-pending cannot transition before the ST-11 publication closure is complete", (
            ("awb-audit-finalised-without-st11-closure", ("indeterminate", "ST-11 publication closure unavailable")),
            ("awb-audit-bundle-missing", ("indeterminate", "completed bundle unavailable")),
            ("awb-audit-evidence-publication-missing", ("indeterminate", "Atomic evidence publication is not finalized")),
        )),
        ("_verify_st11_closure", "ST-11 publication closure unavailable", (
            ("awb-audit-finalised-without-st11-closure", ("error", "AttributeError: 'NoneType' object has no attribute 'get'")),
            ("awb-audit-st11-closure-pending", ("error", "AttributeError: 'NoneType' object has no attribute 'get'")),
        )),
        ("_verify_published_evidence", "Atomic evidence publication is not finalized", (
            ("awb-audit-evidence-publication-unfinalized-pending", ("fail", "Atomic publication AnchorReceipt binding mismatch")),
            ("awp-refund-amendment-original-unpublished", ("indeterminate", "finalized Atomic evidence publication unavailable")),
        )),
        ("_verify_published_evidence", "f'settlement evidence {field} does not match the verified Work'", (
            ("awb-audit-evidence-not-this-work", ("fail", "settlement evidence names another Work operation")),
        )),
        ("_verify_st11_closure", "completed bundle unavailable", (
            ("awb-audit-bundle-missing", ("error", "AttributeError: 'NoneType' object has no attribute 'get'")),
        )),
        ("_verify_st11_closure", "bundle settlementEvidence differs from the published Atomic evidence", (
            ("awb-audit-bundle-evidence-ref-mismatch", PASS),
        )),
        ("_verify_role_bundle_publication", "role-specific bundle anchor is not established", (
            ("awb-audit-bundle-anchor-unfinalized", PASS),
            ("awp-post-purchase-failure-record-anchor-missing", ("error", "TypeError: 'NoneType' object is not subscriptable")),
        )),
        ("_verify_role_bundle_publication", "BundleBinding does not bind the anchored bundle copy", (
            ("awb-audit-bundle-binding-mismatch", PASS),
        )),
        ("_verify_failure_record", "role-specific failure bundle unavailable", (
            ("awp-post-purchase-failure-record-missing", ("error", "AttributeError: 'NoneType' object has no attribute 'get'")),
        )),
        ("_verify_failure_record", "failure record is not this job's failed EvidenceBoundFaultAttestationBundle", (
            ("awp-post-purchase-failure-record-wrong-job", PASS),
        )),
        ("_verify_failure_record", "faultedParty is outside the permissible set for this outcome and role", (
            ("awp-post-purchase-failure-record-attribution-invalid", PASS),
        )),
        ("_verify_failure_record", "failure bundle is not signed by its anchoring role holder", (
            ("awp-post-purchase-failure-record-unsigned", PASS),
        )),
        ("_verify_failure_record", "failure record omits or reverses the final Purchase payment", (
            ("awp-post-purchase-failure-record-omits-payment", PASS),
        )),
        ("_verify_refund_amendment", "a versioned SettlementAmendment is unavailable", (
            ("awp-refund-amendment-missing", ("error", "AttributeError: 'NoneType' object has no attribute 'get'")),
        )),
        ("_verify_refund_amendment", "SettlementAmendment is not linked to the original evidence", (
            ("awp-unlinked-refund", PASS),
        )),
        ("_verify_refund_amendment", "refund is not bounded by the original successful payment", (
            ("awp-refund-amendment-exceeds-payment", PASS),
        )),
        ("_verify_refund_amendment", "amendment address does not bind the original evidence hash", (
            ("awp-refund-amendment-address-mismatch", PASS),
        )),
        ("_verify_refund_amendment", "SettlementAmendment publication is not finalized", (
            ("awp-refund-amendment-receipt-missing", ("error", "AttributeError: 'NoneType' object has no attribute 'get'")),
        )),
    )

    def test_each_st11_closure_and_post_purchase_guard_is_load_bearing(self):
        for function_name, reason, caught_by in self.CLOSURE_GUARDS:
            with self.subTest(function=function_name, reason=reason):
                self._assert_moves(caught_by, function_name, reason)

    def test_each_unsupported_version_comparison_is_load_bearing(self):
        # Version members compared inside a compound guard: removing only the
        # version operand admits the vector.
        for function_name, reason, name in (
            ("evaluate_projection", "projection changed receipt finality/lifecycle context",
             "aw-anchor-projection-receipt-version-unsupported"),
            ("_verify_atomic_publication", "Atomic publication AnchorReceipt binding mismatch",
             "aws-atomic-publication-anchor-version-unsupported"),
        ):
            with self.subTest(name=name):
                self._assert_moves(((name, self.PASS),), function_name, reason, operand=0)
        # Version members the schema decides first: the explicit comparison
        # stays load-bearing if schema validation is bypassed or widened.
        for schema_name, function_name, reason, name in (
            ("atomic-work-receipt-v1.schema.json", "verify_receipt",
             "unsupported receipt version", "aw-receipt-version-unsupported"),
            ("atomic-settlement-evidence-v1.schema.json", "verify_settlement",
             "Atomic Work receipt reference mismatch",
             "aws-settlement-receipt-ref-version-unsupported"),
        ):
            with self.subTest(name=name):
                self.assertIn(schema_name, self._evaluate(name)[1])
                with self._schema_bypassed(schema_name):
                    self.assertEqual(self._evaluate(name), ("fail", reason))
                    with self._without(function_name, reason):
                        self.assertEqual(self._evaluate(name), self.PASS)

    def test_job_id_grammar_comes_from_the_normative_fixture(self):
        # JID-1, taken from the job-id grammar fixture rather than ref.JOB_ID.
        fixture = json.loads(
            (ROOT / "conformance" / "vectors" / "security" / "job-id-grammar-v0.1.json")
            .read_text(encoding="utf-8")
        )
        grammar = fixture["grammar"]
        self.assertEqual(ref.JOB_ID.pattern, grammar)
        for schema_name, path in self.JOB_ID_SCHEMAS.items():
            node = json.loads(
                (ROOT / "spec" / "schemas" / schema_name).read_text(encoding="utf-8")
            )
            for part in path:
                node = node[part]
            self.assertEqual(node.get("pattern"), grammar, schema_name)
        normative = re.compile(grammar)
        accepted = [
            vector["jobId"] for vector in fixture["vectors"]
            if vector["operation"] == "validate" and vector["expected"] == "pass"
        ]
        self.assertIn("7ZZZZZZZZZZZZZZZZZZZZZZZZZ", accepted)
        rejected = [
            "8" + "0" * 25, "9" + "0" * 25, "01arz3ndektsv4rrffq69g5fav",
            "01ARZ3NDEKTSV4RRFFQ69G5FAU", "01ARZ3NDEKTSV4RRFFQ69G5FAI",
            "01ARZ3NDEKTSV4RRFFQ69G5FA", "01ARZ3NDEKTSV4RRFFQ69G5FAVV",
        ]
        for value in accepted:
            self.assertTrue(normative.fullmatch(value) and ref.JOB_ID.fullmatch(value), value)
        for value in rejected:
            self.assertIsNone(normative.fullmatch(value), value)
            self.assertIsNone(ref.JOB_ID.fullmatch(value), value)
        for first in ("8", "9"):
            self.assertEqual(self._evaluate(f"aw-job-id-first-character-{first}")[0], "fail")
        self.assertEqual(self._evaluate("aw-job-id-largest-128-bit"), self.PASS)


class AtomicGateNegativePathTests(unittest.TestCase):
    """CONFORMANCE-PLAN: each CI gate fails on a tampered corpus.

    Each tamper re-hashes the set, so only the targeted check can fire.
    """

    SET = "atomic-work-audit-role-v0.1"

    @classmethod
    def setUpClass(cls):
        cls.security = ROOT / "conformance" / "vectors" / "security"
        cls.data = json.loads((cls.security / f"{cls.SET}.json").read_text(encoding="utf-8"))

    @contextlib.contextmanager
    def _tampered_root(self, edit, *, rehash=True):
        data = copy.deepcopy(self.data)
        edit(data)
        if rehash:
            data["hash"] = ref.vector_hash(data["vectors"])
        with tempfile.TemporaryDirectory() as tmp:
            security = Path(tmp) / "conformance" / "vectors" / "security"
            security.mkdir(parents=True)
            for name in generator.SET_SPECS:
                if name != self.SET:
                    (security / f"{name}.json").symlink_to(self.security / f"{name}.json")
            (security / f"{self.SET}.json").write_text(json.dumps(data), encoding="utf-8")
            with mock.patch.object(validator, "ROOT", Path(tmp)):
                yield security / f"{self.SET}.json"

    def _set_errors(self, edit, **options):
        with self._tampered_root(edit, **options) as path:
            return validator.validate_set(path)[0]

    def test_validate_set_rejects_each_tampered_member(self):
        first_pass = next(i for i, v in enumerate(self.data["vectors"]) if v["expected"] == "pass")
        boundary = next(i for i, v in enumerate(self.data["vectors"]) if v.get("boundary"))

        def flip_verdict(data):
            data["vectors"][first_pass].update(expected="fail", caseClass="rejection")

        cases = (
            ("set must equal filename stem", lambda d: d.update(set="other"), True),
            ("spec declaration differs", lambda d: d.update(spec="other"), True),
            ("vectors is not an array", lambda d: d.update(vectors={}), True),
            ("vector is not an object", lambda d: d["vectors"].__setitem__(0, None), True),
            ("publicKeys/seeds test provenance missing", lambda d: d.pop("seeds"), True),
            ("name missing", lambda d: d["vectors"][0].pop("name"), True),
            ("ruleRefs must be a non-empty array", lambda d: d["vectors"][0].update(ruleRefs=[]), True),
            ("ruleRefs must be a non-empty array", lambda d: d["vectors"][0].update(ruleRefs="AWB-1"), True),
            ("duplicate ruleRef", lambda d: d["vectors"][0].update(ruleRefs=["AWB-1", "AWB-1"]), True),
            ("invalid ruleRef", lambda d: d["vectors"][0].update(ruleRefs=["unknown"]), True),
            ("unknown expected verdict", lambda d: d["vectors"][0].update(expected="unknown"), True),
            ("boundary marker must be boolean true", lambda d: d["vectors"][0].update(boundary=False), True),
            ("duplicate boundaryRuleRef", lambda d: d["vectors"][boundary].update(boundaryRuleRefs=["AWB-2", "AWB-2"]), True),
            ("invalid boundaryRuleRef", lambda d: d["vectors"][boundary].update(boundaryRuleRefs=["AWB-999"]), True),
            ("is not in ruleRefs", lambda d: d["vectors"][boundary].update(ruleRefs=["AWB-1"], boundaryRuleRefs=["AWB-2"]), True),
            ("has no applicable Atomic v0.1 boundary", lambda d: d["vectors"][boundary].update(ruleRefs=["AWB-1"], boundaryRuleRefs=["AWB-1"]), True),
            ("boundaryRuleRefs requires boundary: true", lambda d: (d["vectors"][first_pass].pop("boundary", None), d["vectors"][first_pass].update(boundaryRuleRefs=["AWB-1"])), True),
            ("reason missing", lambda d: d["vectors"][0].pop("reason"), True),
            ("input is not an object", lambda d: d["vectors"][0].update(input=None), True),
            ("expected fail, evaluator returned pass", flip_verdict, True),
            ("duplicate name", lambda d: d["vectors"][1].update(name=d["vectors"][0]["name"]), True),
            ("does not match verdict class", lambda d: d["vectors"][0].update(caseClass="malformed"), True),
            ("boundary requires non-empty boundaryRuleRefs", lambda d: d["vectors"][boundary].pop("boundaryRuleRefs"), True),
            ("out-of-range ruleRef", lambda d: d["vectors"][0].update(ruleRefs=["AW-999"]), True),
            ("count", lambda d: d.update(count=d["count"] + 1), True),
            ("rejectionRuleCount does not match", lambda d: d["coverage"].update(rejectionRuleCount=d["coverage"]["rejectionRuleCount"] + 1), True),
            ("!= JCS SHA-256", lambda d: d["vectors"][0].update(reason="edited after hashing"), False),
        )
        self.assertEqual(self._set_errors(lambda d: None), [])
        for message, edit, rehash in cases:
            with self.subTest(message=message):
                errors = self._set_errors(edit, rehash=rehash)
                self.assertTrue(any(message in error for error in errors), errors)

    def test_validate_all_fails_on_an_uncovered_applicable_cell(self):
        # AWB-8 has rejection vectors only in this set; dropping them leaves an
        # applicable N cell uncovered, and the gate must fail on it.
        def drop_awb8_rejections(data):
            data["vectors"] = [
                v for v in data["vectors"]
                if not (v["caseClass"] == "rejection" and "AWB-8" in v["ruleRefs"])
            ]

        with self._tampered_root(drop_awb8_rejections), \
                mock.patch.object(validator, "validate_set", lambda path: ([], set(validator.EXPECTED_RULES), 0)):
            errors, _, _ = validator.validate_all()
        self.assertIn("applicable N polarity coverage missing: AWB-8", errors)

    def test_validator_rejects_missing_and_extra_sets(self):
        with self._tampered_root(lambda d: None) as path:
            path.unlink()
            extra = path.with_name("atomic-work-unregistered.json")
            extra.write_text("{}")
            with mock.patch.object(validator, "validate_set", return_value=([], set(validator.EXPECTED_RULES), 0)):
                errors, _, _ = validator.validate_all()
        self.assertTrue(any("required set missing" in error for error in errors), errors)
        self.assertTrue(any("unregistered Atomic Work set" in error for error in errors), errors)

    def test_validator_cli_exits_nonzero_on_an_invalid_corpus(self):
        with self._tampered_root(lambda d: d.update(spec="wrong")) as path:
            scripts = path.parents[3] / "scripts"
            scripts.mkdir()
            (scripts / "validate_atomic_work_vectors.py").write_text(
                (ROOT / "scripts/validate_atomic_work_vectors.py").read_text()
            )
            for name in ("atomic_work_reference.py", "generate_atomic_work_vectors.py", "jcs.py"):
                (scripts / name).symlink_to(ROOT / "scripts" / name)
            result = subprocess.run(
                [sys.executable, str(scripts / "validate_atomic_work_vectors.py")],
                capture_output=True, text=True,
            )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("spec declaration differs", result.stderr)
        self.assertIn("validation FAILED", result.stderr)

    def test_generator_refuses_uncovered_or_conflicting_polarity(self):
        # Only the audit set is built, so most applicable cells are uncovered;
        # marking an observed AWB-8 rejection not applicable is a conflict.
        builders = {
            name: builder if name == self.SET else list
            for name, builder in generator.BUILDERS.items()
        }
        with mock.patch.dict(generator.BUILDERS, builders), \
                mock.patch.object(generator, "predicate_pin_vectors", lambda built: {}):
            with self.assertRaisesRegex(AssertionError, r"uncovered applicable Atomic polarity: P: .*\bAW-1\b"):
                generator.build_sets()
            conflicting = {**generator.POLARITY_NOT_APPLICABLE["N"], "AWB-8": "probe"}
            with mock.patch.dict(generator.POLARITY_NOT_APPLICABLE, {"N": conflicting}):
                with self.assertRaisesRegex(AssertionError, r"observed Atomic polarity marked not applicable: N: AWB-8"):
                    generator.build_sets()

    def test_generator_check_fails_on_a_changed_set(self):
        # --check compares the rendered sets with the files byte for byte.
        sets = {self.SET: copy.deepcopy(self.data)}
        for edit, code in ((lambda text: text, 0), (lambda text: text.replace('"count"', '"count" ', 1), 1)):
            with tempfile.TemporaryDirectory() as tmp, \
                    mock.patch.object(generator, "build_sets", lambda: sets), \
                    mock.patch.object(generator, "VECTOR_DIR", Path(tmp)), \
                    mock.patch.object(generator, "ROOT", Path(tmp)), \
                    mock.patch.object(sys, "argv", ["generate_atomic_work_vectors.py", "--check"]), \
                    contextlib.redirect_stdout(io.StringIO()) as out, \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                (Path(tmp) / f"{self.SET}.json").write_text(
                    edit(generator.render(self.data)), encoding="utf-8"
                )
                self.assertEqual(generator.main(), code)
            if code:
                self.assertIn(f"regeneration FAILED: {self.SET}", err.getvalue())
            else:
                self.assertIn("regeneration OK (1 byte-identical sets)", out.getvalue())

    def test_schema_validator_fails_on_a_bad_fixture_or_boundary_outcome(self):
        real_named = schema_validator.named

        def capability_version_two(set_name, vector_name):
            vector = copy.deepcopy(real_named(set_name, vector_name))
            if vector_name == "aw-capability-authenticated":
                vector["input"]["capability"]["capabilityVersion"] = "2"
            return vector

        class Permissive:
            check_schema = staticmethod(lambda schema: None)

            def __init__(self, schema, registry=None):
                pass

            def iter_errors(self, instance):
                return iter(())

        for label, patch, message in (
            ("fixture", mock.patch.object(schema_validator, "named", capability_version_two),
             "atomic-work-capability-v1.schema.json:capabilityVersion"),
            ("boundary", mock.patch.object(schema_validator, "Draft202012Validator", Permissive),
             "unexpectedly accepted invalid fixture"),
        ):
            with self.subTest(label), patch, \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(schema_validator.main(), 1)
            self.assertIn(message, err.getvalue())

    def test_validator_clis_report_success(self):
        # Dropping a __main__ guard makes a CI step exit 0 without validating,
        # so each step must also print its success line.
        for script, line in (
            ("validate_atomic_work_vectors.py", "Atomic Work vectors OK (6 sets, "),
            ("validate_atomic_work_schemas.py", "Atomic Work schemas OK ("),
        ):
            with self.subTest(script=script):
                run = subprocess.run(
                    [sys.executable, str(ROOT / "scripts" / script)],
                    cwd=ROOT, capture_output=True, text=True, check=False,
                )
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertIn(line, run.stdout)


class AtomicMissingInputTests(unittest.TestCase):
    """AW-60, AWS-23, AWB-7: absent authority or evidence is indeterminate.

    Each passing vector loses one authority or evidence member; the result is
    ``indeterminate``, never a crash (``error``) or a rejection (``fail``).
    """

    MISSING = {
        "aw-auth-complete-envelope": (
            "authority", "authorizations", "capability", "expectedNetworkAuthority",
            "expectedProofProfile", "expectedRailRegistryAuthority",
        ),
        "aw-attempt-byte-identity": (
            "authority", "capability", "expectedNetworkAuthority",
            "expectedProofProfile", "expectedRailRegistryAuthority",
            "ledgerInventory",
        ),
        "aw-receipt-complete-and-final": (
            "capability", "expectedNetworkAuthority", "expectedProofProfile",
        ),
        "aw-anchor-projection": (
            "capability", "expectedNetworkAuthority", "expectedProofProfile",
            "operationEvidence",
        ),
        "awp-purchase-composed-admission": (
            "attempts", "authority", "authorizations", "capability", "expectedNetworkAuthority",
            "expectedProofProfile", "expectedRailRegistryAuthority",
            "ledgerInventory", "limitEvidence", "proofReservationBytes",
            "proofReservationEvidence", "receipt", "settlement", "slotAdmission",
        ),
        "awp-completion-payee-presenter-identical-duplicate": (
            "attempts", "authority", "authorizations", "capability", "expectedNetworkAuthority",
            "expectedProofProfile", "expectedRailRegistryAuthority",
            "ledgerInventory", "limitEvidence", "proofReservationBytes",
            "proofReservationEvidence", "purchaseCommitmentProjection",
            "purchaseIntent", "purchaseReceipt", "receipt", "settlement",
        ),
        "awp-purchase-exact-profile": (
            "atomicReceipt", "capability", "expectedNetworkAuthority",
            "expectedProofProfile", "listing",
        ),
        "aws-distinct-atomic-evidence": (
            "auditPublication", "authenticatedContext", "authority",
            "capability", "evidence", "expectedNetworkAuthority",
            "expectedProofProfile", "expectedRailRegistryAuthority", "intent",
            "receipt",
        ),
        "aws-structured-network-slot-cas": (
            "capability", "expectedNetworkAuthority", "expectedProofProfile",
            "expectedRailRegistryAuthority", "ledgerProof", "slotAuthority",
        ),
        "awb-idempotent-nonpaying-audit-tail": (
            "capability", "completionIntent", "completionReceipt",
            "dependencyProofs", "expectedNetworkAuthority",
            "expectedProofProfile", "lifecycleEvidence", "nativeTransactionRef",
            "priorAnchor", "purchaseIntent", "purchaseReceipt", "replayAnchor",
        ),
    }
    # A signer key absent from the verifier's key directory is unavailable
    # authority, not a bad signature.
    MISSING_KEYS = {
        "aw-auth-complete-envelope": "did:dacs:test:payer",
        "aws-distinct-atomic-evidence": "did:dacs:test:orchestrator",
    }

    @classmethod
    def setUpClass(cls):
        cls.by_name = {}
        for name in generator.SET_SPECS:
            data = json.loads(
                (ROOT / "conformance" / "vectors" / "security" / f"{name}.json")
                .read_text(encoding="utf-8")
            )
            cls.by_name.update((vector["name"], vector) for vector in data["vectors"])

    def test_each_missing_authority_or_evidence_member_is_indeterminate(self):
        for name, members in self.MISSING.items():
            control = self.by_name[name]
            self.assertEqual(control["expected"], "pass", name)
            for member in members:
                with self.subTest(vector=name, member=member):
                    vector = copy.deepcopy(control)
                    del vector["input"][member]
                    self.assertEqual(ref.evaluate_vector(vector)[0], "indeterminate")

    def test_missing_signer_key_is_indeterminate(self):
        for name, claim in self.MISSING_KEYS.items():
            with self.subTest(vector=name, claim=claim):
                vector = copy.deepcopy(self.by_name[name])
                del vector["input"]["publicKeys"][claim]
                self.assertEqual(ref.evaluate_vector(vector)[0], "indeterminate")


if __name__ == "__main__":
    unittest.main()
