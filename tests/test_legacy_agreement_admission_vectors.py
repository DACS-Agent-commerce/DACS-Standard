import base64
import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - environment-dependent
    HAVE_CRYPTO = False


ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import dacs5_reference as R  # noqa: E402

VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "legacy-agreement-admission-v0.8.json"
)
SPEC3 = ROOT / "spec" / "DACS-3-NEGOTIATE.md"
SPEC4 = ROOT / "spec" / "DACS-4-SETTLE.md"
SPEC5 = ROOT / "spec" / "DACS-5-VERIFY.md"
CORE = ROOT / "spec" / "CORE.md"
PLAN = ROOT / "spec" / "CONFORMANCE-PLAN.md"
README = ROOT / "conformance" / "vectors" / "security" / "README.md"
WORKFLOW = ROOT / ".github" / "workflows" / "validate.yml"


def canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


class LegacyAgreementAdmissionVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {case["name"]: case for case in cls.data["vectors"]}

    def test_hash_count_and_names_are_exact(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["count"], 166)
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(len({case["name"] for case in vectors}), len(vectors))
        self.assertEqual(
            self.data["hash"], hashlib.sha256(canonical_json(vectors)).hexdigest()
        )

    def test_corrective_profile_pin_and_tuple_are_present(self):
        profile = self.data["profile"]
        self.assertEqual(
            profile,
            {
                "releasePin": "0000000000000000000000000000000000000001",
                "moduleVersions": {
                    "core": "0.3",
                    "dacs1": "0.8",
                    "dacs2": "0.6",
                    "dacs3": "0.6",
                    "dacs4": "0.8",
                    "dacs5": "0.7",
                },
            },
        )

    def test_every_vector_executes_to_declared_result_and_effects(self):
        for case in self.data["vectors"]:
            with self.subTest(case=case["name"]):
                verdict = R.laa_admission(case["input"])
                self.assertEqual(verdict, case["expected"])
                self.assertEqual(R.laa_want(case["input"]), case["want"])

    def test_historical_pass_is_current_ineligible_not_continue(self):
        for case in self.data["vectors"]:
            if case["input"]["operation"] != "historical-audit":
                continue
            with self.subTest(case=case["name"]):
                if case["expected"] == "pass":
                    self.assertEqual(case["want"]["dacs5Admission"], "historical-only")
                    self.assertFalse(case["want"]["currentMetricEligible"])
                    self.assertFalse(case["want"]["currentPaymentEligible"])
                    self.assertFalse(case["want"]["paymentSideEffects"])
                    self.assertTrue(case["want"]["historicalAuditEligible"])

    def test_transition_audit_is_valid_but_current_profile_ineligible(self):
        case = self.cases["laa-transition-completion-audit"]
        self.assertEqual(R.laa_admission(case["input"]), "pass")
        self.assertNotIn("reservationHash", case["input"]["settlementEvidence"])
        transition = case["input"]["transitionEvidence"]
        self.assertEqual(
            transition["legacyTransitionEvidenceVersion"], "1"
        )
        self.assertNotIn("evidenceVersion", transition)
        self.assertEqual(
            transition["reservationRef"]["contentHash"],
            case["input"]["reservation"]["contentHash"],
        )
        self.assertEqual(
            transition["reservationRef"]["anchor"]["locator"],
            "dacs4:legacy-payment-reservation:job-a:2",
        )
        self.assertEqual(
            transition["signature"]["signer"],
            case["input"]["sessionAuthority"]["orchestratorPrimaryClaim"],
        )
        self.assertEqual(
            transition["receiptWriter"],
            case["input"]["sessionAuthority"]["orchestratorPrimaryClaim"],
        )
        self.assertEqual(
            case["input"]["paymentAuthority"]["idempotencyResolution"],
            "consumed",
        )
        self.assertEqual(
            case["input"]["paymentAuthority"]["idempotencyKey"],
            case["input"]["reservation"]["projection"]["idempotencyKey"],
        )
        self.assertEqual(case["want"]["dacs5Admission"], "transition-only")
        self.assertFalse(case["want"]["historicalAuditEligible"])
        self.assertTrue(case["want"]["transitionAuditEligible"])
        self.assertFalse(case["want"]["currentPaymentEligible"])
        self.assertFalse(case["want"]["paymentSideEffects"])
        self.assertFalse(case["want"]["currentMetricEligible"])

    def test_nested_signature_algorithm_containers_return_error(self):
        for operation, case_name in (
            ("authorize-payment", "laa-exact-precheckpoint-commitment-transition"),
            ("transition-audit", "laa-transition-completion-audit"),
        ):
            control = self.cases[case_name]["input"]
            self.assertEqual(R.laa_admission(control), "pass")
            for malformed in (["ed25519"], {"name": "ed25519"}):
                slots = range(3) if operation == "authorize-payment" else (None,)
                for slot in slots:
                    with self.subTest(operation=operation, malformed=malformed, slot=slot):
                        value = copy.deepcopy(control)
                        if slot is None:
                            value["transitionEvidence"]["signature"]["algorithm"] = malformed
                        else:
                            value["reservation"]["signatures"][slot]["algorithm"] = malformed
                        self.assertEqual(R.laa_admission(value), "error")
                        self.assertFalse(R.laa_want(value)["paymentSideEffects"])

    def test_preactivation_payment_remains_current_eligible(self):
        case = self.cases["laa-preactivation-authoritative-absence-allows-legacy"]
        self.assertEqual(R.laa_admission(case["input"]), "pass")
        self.assertEqual(case["want"]["dacs5Admission"], "current-eligible")
        self.assertTrue(case["want"]["currentPaymentEligible"])
        self.assertTrue(case["want"]["currentMetricEligible"])

    def test_transition_evidence_phase_and_txref_shape_are_strict(self):
        malformed = (
            "laa-transition-audit-txrefs-empty-object",
            "laa-transition-audit-txrefs-boolean",
            "laa-transition-audit-txrefs-string",
            "laa-transition-audit-phase-index-negative",
            "laa-transition-audit-phase-index-noninteger",
        )
        for name in malformed:
            with self.subTest(case=name):
                self.assertEqual(R.laa_admission(self.cases[name]["input"]), "error")

        bool_case = self.cases[
            "laa-transition-audit-phase-index-boolean-equals-one"
        ]["input"]
        self.assertIs(bool_case["transitionEvidence"]["phaseIndex"], True)
        self.assertEqual(bool_case["reservation"]["projection"]["phaseIndex"], 1)
        self.assertEqual(R.laa_admission(bool_case), "error")

        for name in (
            "laa-transition-audit-txrefs-duplicate",
            "laa-transition-audit-txrefs-rail-substitution",
        ):
            with self.subTest(case=name):
                self.assertEqual(R.laa_admission(self.cases[name]["input"]), "fail")

    def test_generic_bundle_and_derive_paths_share_one_admission(self):
        for case in self.data["vectors"]:
            with self.subTest(case=case["name"]):
                admission = case["want"]["dacs5Admission"]
                for kind in R.LAA_BUNDLE_TYPES:
                    self.assertEqual(case["want"]["bundleAdmission"][kind], admission)
                for path in R.LAA_DERIVATION_PATHS:
                    self.assertEqual(case["want"]["derivationAdmission"][path], admission)

    def test_commit_pass_has_zero_payment_side_effects(self):
        commit_pass = self.cases["laa-ca10-preactivation-legacy-commit"]
        self.assertEqual(R.laa_admission(commit_pass["input"]), "pass")
        self.assertTrue(commit_pass["want"]["commitmentPermitted"])
        self.assertFalse(commit_pass["want"]["paymentSideEffects"])
        self.assertFalse(commit_pass["want"]["currentPaymentEligible"])
        self.assertEqual(commit_pass["want"]["dacs5Admission"], "commit-permitted")
        self.assertFalse(commit_pass["want"]["currentMetricEligible"])
        # A later payment re-runs LAA. Only the exact pre-checkpoint bounded
        # commitment is transition-only; a post-checkpoint commitment is refused.
        transition = self.cases["laa-exact-precheckpoint-commitment-transition"]
        self.assertEqual(R.laa_admission(transition["input"]), "pass")
        self.assertEqual(transition["want"]["dacs5Admission"], "transition-only")
        self.assertTrue(transition["want"]["paymentSideEffects"])
        self.assertFalse(transition["want"]["currentMetricEligible"])
        self.assertEqual(
            transition["input"]["paymentAuthority"]["idempotencyResolution"],
            "unused",
        )
        post = self.cases["laa-fresh-legacy-after-checkpoint"]
        self.assertEqual(R.laa_admission(post["input"]), "fail")
        self.assertFalse(post["want"]["paymentSideEffects"])

    def test_lowered_caller_position_cannot_mask_stale_absence(self):
        case = self.cases["laa-caller-lowered-payment-position-cannot-mask-stale-absence"]
        value = case["input"]
        self.assertEqual(value["paymentPosition"], "40")
        self.assertEqual(value["sessionAuthority"]["paymentHeadPosition"], "80")
        self.assertEqual(value["checkpoint"]["absenceCoverPosition"], "50")
        self.assertEqual(R.laa_admission(value), "indeterminate")
        self.assertFalse(case["want"]["paymentSideEffects"])

    def test_acceptance_criteria_and_precedence_are_covered(self):
        required = {
            "laa-current-payee-bound-success",
            "laa-fresh-legacy-after-checkpoint",
            "laa-backdated-generated-at",
            "laa-authentic-historical-settlement",
            "laa-missing-commitment-era-proof",
            "laa-exact-precheckpoint-commitment-transition",
            "laa-precheckpoint-payment-reservation",
            "laa-precheckpoint-reservation-writer-missing",
            "laa-precheckpoint-reservation-wrong-writer",
            "laa-postcheckpoint-payment-reservation",
            "laa-transition-reservation-signature-algorithm-list",
            "laa-transition-reservation-signature-algorithm-object",
            "laa-transition-audit-signature-algorithm-list",
            "laa-transition-audit-signature-algorithm-object",
            "laa-transition-reservation-writer-missing",
            "laa-transition-reservation-wrong-writer",
            "laa-transition-audit-reservation-writer-missing",
            "laa-transition-audit-reservation-wrong-writer",
            "laa-transition-completion-audit",
            "laa-transition-payee-substitution",
            "laa-transition-job-substitution",
            "laa-transition-agreement-substitution",
            "laa-transition-amount-substitution",
            "laa-transition-rail-substitution",
            "laa-transition-terms-substitution",
            "laa-transition-cross-session-request",
            "laa-transition-cross-phase-request",
            "laa-transition-reservation-unavailable",
            "laa-transition-reservation-signature-invalid",
            "laa-transition-reservation-missing-seller-signature",
            "laa-transition-reservation-duplicate-signer",
            "laa-transition-reservation-swapped-party-signers",
            "laa-transition-reservation-unauthorized-extra-signer",
            "laa-transition-reservation-changed-orchestrator",
            "laa-transition-reservation-orchestrator-coincident",
            "laa-transition-attacker-paying-key",
            "laa-transition-payer-bundle-substitution",
            "laa-transition-payee-bundle-substitution",
            "laa-transition-deadline-expired",
            "laa-transition-deadline-authority-unavailable",
            "laa-transition-missing-payment-authority",
            "laa-transition-clock-domain-incomparable",
            "laa-transition-idempotency-consumed",
            "laa-transition-idempotency-authority-unavailable",
            "laa-transition-audit-without-checkpoint",
            "laa-transition-audit-missing-commitment",
            "laa-transition-audit-missing-settlement",
            "laa-transition-audit-reservation-mismatch",
            "laa-transition-audit-missing-distinct-evidence",
            "laa-transition-audit-unknown-evidence-type",
            "laa-transition-audit-ordinary-evidence-coercion",
            "laa-transition-audit-evidence-signature-invalid",
            "laa-transition-audit-reservation-ref-malformed",
            "laa-transition-audit-reservation-ref-hash-only",
            "laa-transition-audit-reservation-ref-foreign-anchor",
            "laa-transition-audit-evidence-signature-missing",
            "laa-transition-audit-evidence-wrong-signer",
            "laa-transition-audit-evidence-writer-missing",
            "laa-transition-audit-evidence-wrong-writer",
            "laa-transition-audit-evidence-swapped-signer-writer",
            "laa-transition-audit-idempotency-key-missing",
            "laa-transition-audit-idempotency-authority-unavailable",
            "laa-transition-audit-idempotency-wrong-key",
            "laa-transition-audit-idempotency-unused",
            "laa-transition-audit-txrefs-empty-object",
            "laa-transition-audit-txrefs-boolean",
            "laa-transition-audit-txrefs-string",
            "laa-transition-audit-phase-index-boolean-equals-one",
            "laa-transition-audit-phase-index-negative",
            "laa-transition-audit-phase-index-noninteger",
            "laa-transition-audit-txrefs-duplicate",
            "laa-transition-audit-txrefs-rail-substitution",
            "laa-same-position-unorderable",
            "laa-deterministic-mismatch-precedes-outage",
            "laa-ca10-postactivation-legacy-commit",
            "laa-other-substrate-absence-is-inert",
            "laa-checkpoint-substrate-mismatch",
            "laa-checkpoint-cross-order-domain",
            "laa-commitment-substrate-mismatch",
            "laa-commitment-cross-order-domain",
            "laa-settlement-substrate-mismatch",
            "laa-settlement-cross-order-domain",
            "laa-cross-agreement-replay",
            "laa-stale-absence-across-activation-boundary",
            "laa-ca10-stale-absence-across-activation-boundary",
            "laa-absence-cover-position-malformed",
            "laa-malformed-agreement-wrong-container",
            "laa-malformed-checkpoint-wrong-container",
            "laa-malformed-commitment-missing-field",
            "laa-malformed-settlement-position-scalar",
            "laa-malformed-checkpoint-conflicting-shape",
            "laa-identity-bound-payee-success",
            "laa-identity-bound-non-payee-rejected",
            "laa-caller-lowered-payment-position-cannot-mask-stale-absence",
            "laa-authenticated-head-position-non-string",
            "laa-cross-job-replay",
            "laa-cross-session-replay",
            "laa-cross-phase-replay",
            "laa-malformed-agreement-artifact-unhashable",
            "laa-malformed-settlement-position-unhashable-list",
            "laa-malformed-settlement-position-unhashable-dict",
            "laa-malformed-settlement-missing-agreement-binding",
            "laa-malformed-payee-bound-contentHash-missing",
            "laa-malformed-identity-bound-contentHash-missing",
            "laa-absence-with-malformed-operation",
        }
        self.assertTrue(required.issubset(self.cases))
        case = self.cases["laa-deterministic-mismatch-precedes-outage"]
        self.assertEqual(R.laa_admission(case["input"]), "fail")
        self.assertTrue(
            self.cases["laa-fresh-legacy-after-checkpoint"]["want"]
            ["legacyBytesCryptographicallyInspectable"]
        )

    def test_all_comparable_receipts_share_one_authenticated_order_domain(self):
        value = self.cases["laa-authentic-historical-settlement"]["input"]
        authority = value["sessionAuthority"]
        for record_name in ("checkpoint", "commitment", "settlementEvidence"):
            record = value[record_name]
            self.assertEqual(record["substrate"], authority["substrate"])
            self.assertEqual(record["orderDomain"], authority["orderDomain"])
        self.assertEqual(R.laa_admission(value), "pass")
        self.assertEqual(
            R.laa_admission(self.cases["laa-other-substrate-absence-is-inert"]["input"]),
            "fail",
        )
        self.assertEqual(
            R.laa_admission(self.cases["laa-commitment-cross-order-domain"]["input"]),
            "indeterminate",
        )

    def test_generator_check_is_enforced(self):
        result = subprocess.run(
            [sys.executable, "scripts/generate_legacy_agreement_admission_vectors.py", "--check"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_normative_surfaces_registry_plan_readme_and_ci_are_linked(self):
        spec3 = SPEC3.read_text(encoding="utf-8")
        spec4 = SPEC4.read_text(encoding="utf-8")
        spec5 = SPEC5.read_text(encoding="utf-8")
        core = CORE.read_text(encoding="utf-8")
        plan = PLAN.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for rule in range(1, 8):
            self.assertIn(f"(LAA-{rule})", spec4)
        self.assertIn("(CA-10)", spec3)
        self.assertIn("LAA-1..LAA-7", spec5)
        self.assertIn("LAA `fail` or `error` yields RSV `rejected`", spec5)
        self.assertIn("inFlightTransition: \"signed-payment-reservation\"", spec4)
        self.assertIn("transition-only", spec4)
        self.assertIn("transition-only", spec5)
        self.assertIn("LegacyTransitionSettlementEvidence", spec4)
        self.assertIn("LegacyTransitionSettlementEvidence", spec5)
        self.assertIn("generatedAt", spec4)
        self.assertIn('"dacs-legacy-agreement-checkpoint:v1:"', core)
        self.assertIn('"dacs-legacy-payment-reservation:v1:"', core)
        self.assertIn('"dacs-legacy-transition-evidence:v1:"', core)
        self.assertIn(VECTORS.name, plan)
        self.assertIn(VECTORS.name, readme)
        self.assertIn("generate_legacy_agreement_admission_vectors.py --check", workflow)

    # --- Gap 2: the LAA oracle is total; every malformed input is ``error``. ---

    def test_malformed_oracle_returns_error_for_every_linked_probe(self):
        """Every named malformed-input probe in the corpus is ``error``, never an
        exception, ``fail``, or ``indeterminate``."""
        probe_names = {
            "laa-malformed-operation-unhashable-list",
            "laa-malformed-operation-unhashable-dict",
            "laa-malformed-agreement-contentHash-missing",
            "laa-malformed-checkpoint-signatureValid-missing",
            "laa-malformed-checkpoint-receiptState-nonstring",
            "laa-malformed-checkpoint-receiptState-unknown",
            "laa-malformed-commitment-receiptState-missing",
            "laa-malformed-settlement-receiptState-unknown",
            "laa-malformed-commitment-signatureValid-missing",
            "laa-malformed-settlement-signatureValid-missing",
            "laa-malformed-native-order-unhashable",
            "laa-malformed-payment-head-dict",
            "laa-malformed-session-jobId-nonstring",
            "laa-malformed-settlement-agreementHash-missing",
            "laa-malformed-settlement-job-missing",
            "laa-malformed-payee-bound-contentHash-missing",
            "laa-malformed-identity-bound-contentHash-missing",
            "laa-absence-with-malformed-operation",
        }
        self.assertTrue(probe_names.issubset(self.cases))
        for name in sorted(probe_names):
            with self.subTest(probe=name):
                case = self.cases[name]
                self.assertEqual(case["expected"], "error")
                self.assertEqual(R.laa_admission(case["input"]), "error")
                self.assertEqual(case["want"]["dacs5Admission"], "rejected")
                self.assertFalse(case["want"]["paymentSideEffects"])

    def test_oracle_is_total_on_adversarial_containers(self):
        """Arbitrary untrusted containers never raise TypeError/AttributeError."""
        base = copy.deepcopy(
            self.cases["laa-authentic-historical-settlement"]["input"]
        )
        adversarial = [
            None,
            3,
            "not-an-object",
            [],
            {"agreement": None},
            {"agreement": []},
            {"agreement": "x"},
            {"operation": ["historical-audit"], "pipelineHasPayment": True,
             "agreement": copy.deepcopy(base["agreement"]),
             "sessionAuthority": copy.deepcopy(base["sessionAuthority"]),
             "checkpoint": copy.deepcopy(base["checkpoint"]),
             "commitment": copy.deepcopy(base["commitment"]),
             "settlementEvidence": copy.deepcopy(base["settlementEvidence"])},
        ]
        for value in adversarial:
            with self.subTest(value=repr(value)[:60]):
                verdict = R.laa_admission(value)
                self.assertIn(verdict, {"pass", "fail", "indeterminate", "error"})

    def test_idempotency_keys_are_canonical_nonempty_before_equality(self):
        for case_name in (
            "laa-exact-precheckpoint-commitment-transition",
            "laa-transition-completion-audit",
        ):
            base = self.cases[case_name]["input"]
            self.assertEqual("pass", R.laa_admission(base))
            for malformed in ("", " ", "\t", " padded-key ", "e\u0301"):
                value = copy.deepcopy(base)
                value["paymentAuthority"]["idempotencyKey"] = malformed
                with self.subTest(case=case_name, malformed=repr(malformed)):
                    self.assertEqual("error", R.laa_admission(value))
            mismatch = copy.deepcopy(base)
            mismatch["paymentAuthority"]["idempotencyKey"] = "0" * 64
            with self.subTest(case=case_name, mismatch=True):
                self.assertEqual("fail", R.laa_admission(mismatch))

    # --- Gap 2a: session/hash identity values must be non-empty canonical. ---

    @staticmethod
    def _mutate(input_value, container, key, replacement):
        value = copy.deepcopy(input_value)
        if isinstance(value.get(container), dict):
            value[container][key] = replacement
        return value

    def test_empty_or_whitespace_content_hash_rejected_before_effects(self):
        """Empty or whitespace-only ``agreement.contentHash`` is malformed and
        rejected (``error``) BEFORE a payee-bound / identity-bound / zero-pay /
        absence branch could otherwise authorize."""
        probes = [
            "laa-current-payee-bound-success",       # payee-bound current payment
            "laa-identity-bound-payee-success",      # identity-bound-payee
            "laa-zero-pay-legacy-outside-gate",      # legacy zero-pay / absence branch
        ]
        for name in probes:
            base = self.cases[name]["input"]
            for bad in ("", "   ", "\t", " agreement-hash-a ", " agreement-hash-a"):
                with self.subTest(case=name, contentHash=repr(bad)):
                    value = self._mutate(base, "agreement", "contentHash", bad)
                    self.assertEqual(R.laa_admission(value), "error")
                    self.assertFalse(R.laa_want(value)["paymentSideEffects"])

    def test_empty_or_whitespace_session_id_rejected_before_effects(self):
        """Empty or whitespace-only ``sessionAuthority.sessionId`` is malformed and
        rejected (``error``) BEFORE the legacy checkpoint/absence branch could
        otherwise authorize."""
        base = self.cases["laa-authentic-historical-settlement"]["input"]
        for bad in ("", "   ", "\t", " session-a ", " session-a"):
            with self.subTest(sessionId=repr(bad)):
                value = self._mutate(base, "sessionAuthority", "sessionId", bad)
                self.assertEqual(R.laa_admission(value), "error")
                self.assertFalse(R.laa_want(value)["paymentSideEffects"])

    def test_noncanonical_identity_values_rejected_before_effects(self):
        """Non-canonical (leading/trailing-whitespace or non-NFC) identity values
        are malformed and rejected (``error``), never a silently differing key."""
        base = self.cases["laa-authentic-historical-settlement"]["input"]
        # contentHash with leading/trailing whitespace or non-NFC spelling.
        for bad in ("agreement-hash-a ", " agreement-hash-a", "agreement-hash-a\u0301"):
            with self.subTest(field="contentHash", value=repr(bad)):
                value = self._mutate(base, "agreement", "contentHash", bad)
                self.assertEqual(R.laa_admission(value), "error")
        # sessionId with leading/trailing whitespace or non-NFC spelling.
        for bad in ("session-a ", " session-a", "session-a\u0301"):
            with self.subTest(field="sessionId", value=repr(bad)):
                value = self._mutate(base, "sessionAuthority", "sessionId", bad)
                self.assertEqual(R.laa_admission(value), "error")

    def test_every_early_oracle_branch_rejects_invalid_session_and_hash_identity(self):
        """Every oracle branch — payee-bound, identity-bound-payee, identity-bound,
        and legacy zero-pay — rejects empty / blank / padded / non-NFC / surrogate
        ``sessionId`` and ``contentHash`` BEFORE any pass or paymentSideEffects."""
        session_spellings = ("", "   ", "\t", " session-a ", " session-a",
                             "session-a\u0301", "bad\ud800")
        content_spellings = ("", "   ", "\t", " agreement-hash-a ",
                             " agreement-hash-a", "agreement-hash-a\u0301", "bad\ud800")
        probes = (
            "laa-current-payee-bound-success",        # payee-bound
            "laa-identity-bound-payee-success",       # identity-bound-payee
            "laa-identity-bound-non-payee-rejected",  # identity-bound (non-payee)
            "laa-zero-pay-legacy-outside-gate",       # legacy zero-pay
        )
        for name in probes:
            base = self.cases[name]["input"]
            for bad in session_spellings:
                with self.subTest(case=name, field="sessionId", value=repr(bad)):
                    value = self._mutate(base, "sessionAuthority", "sessionId", bad)
                    self.assertEqual(R.laa_admission(value), "error")
                    self.assertFalse(R.laa_want(value)["paymentSideEffects"])
            for bad in content_spellings:
                with self.subTest(case=name, field="contentHash", value=repr(bad)):
                    value = self._mutate(base, "agreement", "contentHash", bad)
                    self.assertEqual(R.laa_admission(value), "error")
                    self.assertFalse(R.laa_want(value)["paymentSideEffects"])

    # --- Gap 1a: derive/count/replay/job-bound consumers apply LAA. ---
    # A caller-supplied disposition is never authority: derive() executes the
    # shared LAA oracle on the verifier-owned full ``laa`` admission input and
    # counts only a ``current-eligible`` result.

    @staticmethod
    def _derive_bundle(job_id, role):
        return {
            "bundleVersion": "1",
            "jobId": job_id,
            "anchoredByRole": role,
            "outcome": "completed",
            "parties": [
                {"role": "buyer", "primaryClaim": "did:demos:buyer"},
                {"role": "seller", "primaryClaim": "did:demos:seller"},
            ],
            "finalisedAt": 1780004000000,
        }

    def _derive_tag(self, job_id, role, *, laa=None, laaDisposition=None, resolved_job=None):
        tag = {
            "bundle": self._derive_bundle(job_id, role),
            "resolvedRole": role,
            "counterpartyDisposition": "absent",
            "absenceEvidenceRef": {"contentHash": "a" * 64},
        }
        if resolved_job is not None:
            tag["resolvedJobId"] = resolved_job
        if laa is not None:
            tag["laa"] = laa
        if laaDisposition is not None:
            tag["laaDisposition"] = laaDisposition
        return tag

    def _laa_input(self, name):
        return copy.deepcopy(self.cases[name]["input"])

    @staticmethod
    def _session_authority(mapping=None):
        """Verifier-owned session authority mapping ``jobId`` -> ``sessionId``.

        The current-eligible payee-bound LAA fixture authenticates session
        ``session-a`` for job ``job-a``; the verifier owns that binding and the
        derive/replay paths recover the expected session from it (never from an
        optional tag/bundle ``sessionId``).
        """
        return {"job-a": "session-a"} if mapping is None else mapping

    def test_derive_excludes_historical_only_legacy_bundle(self):
        """A historical authentic LAA pass is current-ineligible and is excluded
        from bundleCount and bundleRefs by derive(); the shared oracle decides."""
        party = "did:demos:seller"
        tags = [
            self._derive_tag(
                "job-a", "seller",
                laa=self._laa_input("laa-current-payee-bound-success"),
            ),
            self._derive_tag(
                "job-historical", "seller",
                laa=self._laa_input("laa-authentic-historical-settlement"),
            ),
        ]
        d = R.derive(party, tags, 1780000000000, 1780900000000, "finalisedAt",
                     session_authority=self._session_authority())
        self.assertEqual(d["bundleCount"], 1)
        self.assertEqual(len(d["bundleRefs"]), 1)
        # job-historical is absent from every metric and bundleRef.
        self.assertEqual(d["resolutionContext"][0]["resolvedRole"], "seller")

    def test_derive_excludes_rejected_and_indeterminate_legacy(self):
        """rejected / indeterminate / commit-permitted / admitted-non-payment
        verdicts and a malformed ``laa`` input are all non-authorizing and
        excluded; a caller-supplied ``laaDisposition`` string is never authority,
        and a legacy bundle carrying no full ``laa`` object (released-v1 /
        audit-only evidence) is excluded from every current metric."""
        party = "did:demos:seller"
        for name in (
            "laa-fresh-legacy-after-checkpoint",        # fail -> rejected
            "laa-checkpoint-unavailable",               # indeterminate
            "laa-ca10-preactivation-legacy-commit",     # commit-permitted
            "laa-zero-pay-legacy-outside-gate",         # admitted-non-payment
            "laa-exact-precheckpoint-commitment-transition",  # transition-only
        ):
            with self.subTest(disposition=name):
                d = R.derive(
                    party,
                    [self._derive_tag("job-x", "seller", laa=self._laa_input(name))],
                    1780000000000, 1780900000000, "finalisedAt",
                )
                self.assertEqual(d["bundleCount"], 0, name)
        # A malformed/unknown ``laa`` input is non-authorizing (excluded).
        d = R.derive(
            party,
            [self._derive_tag("job-bad", "seller", laa="historical-pass")],
            1780000000000, 1780900000000, "finalisedAt",
        )
        self.assertEqual(d["bundleCount"], 0)
        # A caller-supplied ``laaDisposition`` string is never authority: a bare
        # disposition (without the verifier-owned full ``laa`` object) excludes.
        for disposition in ("current-eligible", "historical-only", "rejected"):
            with self.subTest(forged_disposition=disposition):
                d = R.derive(
                    party,
                    [self._derive_tag("job-forged", "seller", laaDisposition=disposition)],
                    1780000000000, 1780900000000, "finalisedAt",
                )
                self.assertEqual(d["bundleCount"], 0, disposition)
        # A completed legacy bundle is a legacy-payment bundle: absence of an
        # LAA marker does NOT authorize it on the current path (fail-closed).
        d = R.derive(
            party,
            [self._derive_tag("job-v1", "seller")],
            1780000000000, 1780900000000, "finalisedAt",
        )
        self.assertEqual(d["bundleCount"], 0)
        self.assertEqual(d["bundleRefs"], [])
        # Only the explicit pre-LAA historical/audit-only path reproduces the
        # frozen released behaviour; it can never be reached by current
        # metrics/payment/replay defaults.
        d_hist = R.derive_legacy_audit_only(
            party,
            [self._derive_tag("job-v1", "seller")],
            1780000000000, 1780900000000, "finalisedAt",
        )
        self.assertEqual(d_hist["bundleCount"], 1)

    def test_derive_requires_full_laa_object_for_legacy(self):
        """A legacy-payment bundle requires a verifier-owned authenticated full
        LAA object. A malformed, unknown, or non-current-eligible ``laa`` is
        excluded; only a current-eligible full input counts."""
        party = "did:demos:seller"
        # Malformed / unknown ``laa`` (wrong type or non-current-eligible) exclude.
        for bad in ("historical-pass", [], 7, {"operation": ["historical-audit"]},
                    {"operation": "authorize-payment", "agreement": None}):
            with self.subTest(bad=repr(bad)[:40]):
                d = R.derive(
                    party,
                    [self._derive_tag("job-bad", "seller", laa=bad)],
                    1780000000000, 1780900000000, "finalisedAt",
                )
                self.assertEqual(d["bundleCount"], 0)
        # A current-eligible full object counts exactly once.
        d = R.derive(
            party,
            [self._derive_tag("job-a", "seller",
                              laa=self._laa_input("laa-current-payee-bound-success"))],
            1780000000000, 1780900000000, "finalisedAt",
            session_authority=self._session_authority(),
        )
        self.assertEqual(d["bundleCount"], 1)

    def test_job_bound_derive_excludes_historical_only_legacy_bundle(self):
        """derive_job_bound applies the same verifier-owned LAA admission gate."""
        party = "did:demos:seller"
        tags = [
            self._derive_tag(
                "job-a", "seller", resolved_job="job-a",
                laa=self._laa_input("laa-current-payee-bound-success"),
            ),
            self._derive_tag(
                "job-historical", "seller", resolved_job="job-historical",
                laa=self._laa_input("laa-authentic-historical-settlement"),
            ),
        ]
        d = R.derive_job_bound(party, tags, 1780000000000, 1780900000000, "finalisedAt",
                               session_authority=self._session_authority())
        self.assertEqual(d["bundleCount"], 1)
        self.assertEqual(len(d["bundleRefs"]), 1)

    def test_job_bound_derive_excludes_legacy_without_full_laa(self):
        """derive_job_bound requires the same verifier-owned full LAA object: a
        legacy bundle carrying a malformed or caller-only ``laa`` marker is
        excluded from the job-bound current metrics."""
        party = "did:demos:seller"
        cases = [
            self._derive_tag("job-malformed", "seller", resolved_job="job-malformed",
                             laa="historical-pass"),
            self._derive_tag("job-unknown", "seller", resolved_job="job-unknown",
                             laa=self._laa_input("laa-authentic-historical-settlement")),
            self._derive_tag("job-forged", "seller", resolved_job="job-forged",
                             laaDisposition="current-eligible"),
        ]
        d = R.derive_job_bound(party, cases, 1780000000000, 1780900000000, "finalisedAt")
        self.assertEqual(d["bundleCount"], 0)
        self.assertEqual(d["bundleRefs"], [])
        # The current-eligible full object alone is counted.
        d = R.derive_job_bound(
            party,
            [self._derive_tag("job-a", "seller", resolved_job="job-a",
                              laa=self._laa_input("laa-current-payee-bound-success"))],
            1780000000000, 1780900000000, "finalisedAt",
            session_authority=self._session_authority(),
        )
        self.assertEqual(d["bundleCount"], 1)

    def test_caller_copy_laa_disposition_is_never_authority(self):
        """A caller-supplied ``laaDisposition`` copy (any value) is never authority:
        it never selects, never excludes, and never upgrades a legacy bundle to
        current eligibility. Only the shared laa_admission oracle on the full
        verifier-owned ``laa`` input decides."""
        party = "did:demos:seller"
        for disposition in (
            "current-eligible", "historical-only", "rejected", "indeterminate",
            "commit-permitted", "admitted-non-payment",
        ):
            with self.subTest(disposition=disposition):
                d = R.derive(
                    party,
                    [self._derive_tag("job-caller", "seller", laaDisposition=disposition)],
                    1780000000000, 1780900000000, "finalisedAt",
                )
                self.assertEqual(d["bundleCount"], 0)
                self.assertEqual(d["bundleRefs"], [])
        # A caller-copy disposition alongside a NON-current-eligible full object
        # must not rescue it either (the oracle result, not the copy, decides).
        d = R.derive(
            party,
            [self._derive_tag(
                "job-historical", "seller",
                laa=self._laa_input("laa-authentic-historical-settlement"),
                laaDisposition="current-eligible",
            )],
            1780000000000, 1780900000000, "finalisedAt",
        )
        self.assertEqual(d["bundleCount"], 0)

    def test_replay_path_requires_full_laa(self):
        """The replay path reconstructs tags from a receipt's resolutionContext and
        re-runs the shared derive gate. derive() carries the verifier-owned full
        LAA input into the resolutionContext entry so replay can re-execute
        laa_admission; a receipt whose carried ``laa`` is malformed or non-current-
        eligible excludes the legacy bundle (never default-eligible)."""
        party = "did:demos:seller"
        laa = self._laa_input("laa-current-payee-bound-success")
        receipt = R.derive(
            party,
            [self._derive_tag("job-a", "seller", laa=laa)],
            1780000000000, 1780900000000, "finalisedAt",
            session_authority=self._session_authority(),
        )
        self.assertEqual(receipt["bundleCount"], 1)
        # The full LAA input is carried in the receipt so replay can re-execute it.
        self.assertIsInstance(receipt["resolutionContext"][0].get("laa"), dict)
        self.assertEqual(
            R.laa_want(receipt["resolutionContext"][0]["laa"])["dacs5Admission"],
            "current-eligible",
        )
        # A forged receipt that substitutes a non-current-eligible (historical-only)
        # LAA input is re-evaluated by replay and excludes the legacy bundle.
        historical = self._laa_input("laa-authentic-historical-settlement")
        self.assertEqual(R.laa_want(historical)["dacs5Admission"], "historical-only")
        forged = self._derive_tag("job-replay", "seller", laa=historical)
        d = R.derive(party, [forged], 1780000000000, 1780900000000, "finalisedAt")
        self.assertEqual(d["bundleCount"], 0)
        self.assertEqual(d["bundleRefs"], [])
        # A forged receipt that strips the ``laa`` marker but still claims a
        # legacy-payment via a bare disposition is also excluded (never eligible).
        bare = self._derive_tag("job-replay", "seller", laaDisposition="current-eligible")
        d = R.derive(party, [bare], 1780000000000, 1780900000000, "finalisedAt")
        self.assertEqual(d["bundleCount"], 0)
        self.assertEqual(d["bundleRefs"], [])

    def test_derive_and_job_bound_bind_laa_to_the_same_job_and_session(self):
        """A current-eligible LAA whose authenticated job or session does not bind
        to the tagged bundle is non-authorizing: cross-job and cross-session LAA
        exclude on both the direct and job-bound derivation paths."""
        party = "did:demos:seller"
        laa = self._laa_input("laa-current-payee-bound-success")  # job-a / session-a
        # Cross-job: a current-eligible LAA for job-a attached to a job-b bundle.
        for derive in (R.derive, R.derive_job_bound):
            with self.subTest(path=derive.__name__, kind="cross-job"):
                tags = [self._derive_tag("job-b", "seller", resolved_job="job-b",
                                         laa=laa)]
                d = derive(party, tags, 1780000000000, 1780900000000, "finalisedAt")
                self.assertEqual(d["bundleCount"], 0)
                self.assertEqual(d["bundleRefs"], [])
        # Cross-session: the tag carries a session identity that differs from the
        # authenticated LAA sessionId.
        cross_session = self._derive_tag("job-a", "seller", laa=laa)
        cross_session["sessionId"] = "session-other"
        self.assertEqual(R.derive(party, [cross_session],
                                  1780000000000, 1780900000000, "finalisedAt")["bundleCount"], 0)
        # Same-job + same-session: counted exactly once on both paths.
        for derive in (R.derive, R.derive_job_bound):
            with self.subTest(path=derive.__name__, kind="same-job"):
                d = derive(party, [self._derive_tag("job-a", "seller",
                                                    resolved_job="job-a", laa=laa)],
                           1780000000000, 1780900000000, "finalisedAt",
                           session_authority=self._session_authority())
                self.assertEqual(d["bundleCount"], 1)
                self.assertEqual(len(d["bundleRefs"]), 1)

    def test_job_bound_derive_excludes_missing_and_cross_job_laa(self):
        """derive_job_bound fails closed exactly like derive: a completed legacy
        bundle with no full LAA object, or with a cross-job LAA, never counts."""
        party = "did:demos:seller"
        # Missing LAA (completed legacy bundle carries no marker): excluded.
        d = R.derive_job_bound(
            party,
            [self._derive_tag("job-missing", "seller", resolved_job="job-missing")],
            1780000000000, 1780900000000, "finalisedAt",
        )
        self.assertEqual(d["bundleCount"], 0)
        # Caller-only disposition (no full LAA): excluded.
        d = R.derive_job_bound(
            party,
            [self._derive_tag("job-caller", "seller", resolved_job="job-caller",
                              laaDisposition="current-eligible")],
            1780000000000, 1780900000000, "finalisedAt",
        )
        self.assertEqual(d["bundleCount"], 0)
        # Cross-job LAA: excluded.
        d = R.derive_job_bound(
            party,
            [self._derive_tag("job-other", "seller", resolved_job="job-other",
                              laa=self._laa_input("laa-current-payee-bound-success"))],
            1780000000000, 1780900000000, "finalisedAt",
        )
        self.assertEqual(d["bundleCount"], 0)

    # --- Gap 1b: full replay revalidates the carried same-job LAA; stripped or
    # cross-job LAA fails the replay byte-identity check. ---

    def _replay_harness(self, job_id, laa):
        """Build a full legacy replay harness for a completed legacy bundle whose
        successful payment is LAA-gated: a completed bundle (both signatures), an
        address-backed roleEvidence, and a bound absent counterparty with absence
        evidence. Returns (receipt, deref, anchor_deref, evidence_deref)."""
        party = "did:demos:seller"
        bundle = {
            "bundleVersion": "1",
            "jobId": job_id,
            "anchoredByRole": "seller",
            "outcome": "completed",
            "parties": [
                {"role": "buyer", "primaryClaim": "did:demos:buyer"},
                {"role": "seller", "primaryClaim": "did:demos:seller"},
            ],
            "finalisedAt": 1780004000000,
            "signatures": [
                {"party": "did:demos:buyer", "algorithm": "ed25519", "value": "AA"},
                {"party": "did:demos:seller", "algorithm": "ed25519", "value": "AA"},
            ],
        }
        content_hash = R.bundle_hash(bundle)
        seller_addr = R.legacy_logical_address(job_id, "seller")
        buyer_addr = R.legacy_logical_address(job_id, "buyer")
        absence = {
            "kind": "non-membership-proof",
            "nativeAddress": "stor-absent-" + job_id,
            "finalizedStateRef": "demos-testnet:finalized-1780004000000",
        }
        absence_hash = R._canon_sha(absence)
        absence_binding = {
            "bindingVersion": "1",
            "jobId": job_id,
            "role": "buyer",
            "logicalAddress": buyer_addr,
            "nativeAddress": "stor-absent-" + job_id,
            "bundleContentHash": "0" * 64,
            "signer": "did:demos:buyer",
            "signature": {"signer": "did:demos:buyer", "algorithm": "ed25519",
                          "value": "AA"},
        }
        tag = {
            "bundle": bundle,
            "resolvedRole": "seller",
            "counterpartyDisposition": "absent",
            "absenceEvidenceRef": {
                "kind": "non-membership-proof",
                "locator": "stor-absent-" + job_id,
                "contentHash": absence_hash,
            },
            "absenceBinding": absence_binding,
            "roleEvidence": {"kind": "address", "resolvedAddress": seller_addr},
            "laa": copy.deepcopy(laa),
        }
        receipt = R.derive(party, [tag], 1780000000000, 1780900000000, "finalisedAt",
                           session_authority=self._session_authority())
        deref = {content_hash: bundle}
        anchor = {seller_addr: bundle}
        evidence = {absence_hash: absence}
        return (
            receipt,
            lambda h: deref.get(h),
            lambda a: anchor.get(a),
            lambda h: evidence.get(h),
        )

    def test_replay_revalidates_full_same_job_laa_and_fails_on_stripped_or_cross_job(self):
        """The full replay path revalidates the carried same-job LAA (intact=true),
        and fails the byte-identity check when the LAA is stripped (legacyPayment
        marker remains but ``laa`` is absent) or cross-job (LAA bound to another
        job)."""
        party = "did:demos:seller"
        laa = self._laa_input("laa-current-payee-bound-success")  # job-a

        # Intact: the receipt carries legacyPayment + full laa; replay is byte-identical.
        receipt, deref, anchor, evidence = self._replay_harness("job-a", laa)
        self.assertEqual(receipt["bundleCount"], 1)
        entry = receipt["resolutionContext"][0]
        self.assertIs(entry.get("legacyPayment"), True)
        self.assertIsInstance(entry.get("laa"), dict)
        same, _ = R.replay_legacy_receipt(
            receipt, deref, party, 1780000000000, 1780900000000, evidence, None, anchor,
            session_authority=self._session_authority(),
        )
        self.assertTrue(same, "intact receipt must replay byte-identically")

        # Stripped: the carried full LAA is removed but the legacyPayment marker
        # remains; replay must NOT validate (stripped LAA fails closed).
        stripped = copy.deepcopy(receipt)
        stripped["resolutionContext"][0].pop("laa", None)
        same_stripped, _ = R.replay_legacy_receipt(
            stripped, deref, party, 1780000000000, 1780900000000, evidence, None, anchor,
            session_authority=self._session_authority(),
        )
        self.assertFalse(same_stripped, "stripped LAA must fail the replay check")

        # Cross-job: derive already excludes the cross-job LAA, so no receipt is
        # produced (bundleCount 0), and a forged receipt cannot be replayed.
        cross_receipt, cross_deref, cross_anchor, cross_evidence = self._replay_harness(
            "job-b", laa
        )
        self.assertEqual(cross_receipt["bundleCount"], 0)
        self.assertEqual(cross_receipt["bundleRefs"], [])

    # --- Gap 1c: LAA session binding is verifier-owned and fail-closed. ---

    def test_derive_laa_session_binding_requires_verifier_authority(self):
        """The expected session is never derived from an optional tag/bundle
        ``sessionId``: derive() binds the LAA ``sessionAuthority.sessionId`` to the
        verifier-owned session authority for the bundle's ``jobId``. An omitted tag
        sessionId with a cross-session LAA, an absent session authority, or a
        mismatched authority all exclude the legacy bundle."""
        party = "did:demos:seller"
        laa = self._laa_input("laa-current-payee-bound-success")  # job-a / session-a

        # Cross-session LAA with NO tag sessionId: the verifier-owned authority
        # resolves job-a -> session-a, but the LAA authenticates session-other.
        cross = copy.deepcopy(laa)
        cross["sessionAuthority"]["sessionId"] = "session-other"
        d = R.derive(
            party,
            [self._derive_tag("job-a", "seller", laa=cross)],
            1780000000000, 1780900000000, "finalisedAt",
            session_authority=self._session_authority(),
        )
        self.assertEqual(d["bundleCount"], 0)
        self.assertEqual(d["bundleRefs"], [])

        # Absent verifier-owned session authority: fail closed.
        d = R.derive(
            party,
            [self._derive_tag("job-a", "seller", laa=laa)],
            1780000000000, 1780900000000, "finalisedAt",
            session_authority=None,
        )
        self.assertEqual(d["bundleCount"], 0)

        # Mismatched verifier-owned session authority: fail closed.
        d = R.derive(
            party,
            [self._derive_tag("job-a", "seller", laa=laa)],
            1780000000000, 1780900000000, "finalisedAt",
            session_authority={"job-a": "session-wrong"},
        )
        self.assertEqual(d["bundleCount"], 0)

        # A caller/tag sessionId is never authority either: a tag that CLAIMS a
        # session must match the authenticated LAA sessionId.
        contradictory = self._derive_tag("job-a", "seller", laa=laa)
        contradictory["sessionId"] = "session-other"
        d = R.derive(
            party, [contradictory], 1780000000000, 1780900000000, "finalisedAt",
            session_authority=self._session_authority(),
        )
        self.assertEqual(d["bundleCount"], 0)

        # Valid exact binding: counted exactly once.
        d = R.derive(
            party,
            [self._derive_tag("job-a", "seller", laa=laa)],
            1780000000000, 1780900000000, "finalisedAt",
            session_authority=self._session_authority(),
        )
        self.assertEqual(d["bundleCount"], 1)
        self.assertEqual(len(d["bundleRefs"]), 1)

    def test_replay_laa_carrier_binds_exact_legacy_payment(self):
        """The replay LAA carrier commits the exact legacy-payment marker, full
        LAA, job, authenticated session, and agreement/bundle content hashes. Any
        marker removal, LAA removal, carrier removal, agreement contentHash
        substitution, session substitution, marker/LAA disagreement, or cross-job
        entry fails replay fail-closed; only the exact current receipt replays
        byte-identically."""
        party = "did:demos:seller"
        laa = self._laa_input("laa-current-payee-bound-success")  # job-a / session-a
        receipt, deref, anchor, evidence = self._replay_harness("job-a", laa)
        self.assertEqual(receipt["bundleCount"], 1)
        entry = receipt["resolutionContext"][0]
        self.assertIs(entry.get("legacyPayment"), True)
        self.assertIsInstance(entry.get("laa"), dict)
        self.assertIsInstance(entry.get("legacyPaymentCarrier"), str)

        def _same(r):
            return R.replay_legacy_receipt(
                r, deref, party, 1780000000000, 1780900000000, evidence, None, anchor,
                session_authority=self._session_authority(),
            )[0]

        # Valid exact current replay: byte-identical.
        self.assertTrue(_same(receipt))

        # Marker removal (legacyPayment removed, laa + carrier kept).
        marker_removed = copy.deepcopy(receipt)
        marker_removed["resolutionContext"][0].pop("legacyPayment", None)
        self.assertFalse(_same(marker_removed))

        # LAA removal (laa removed, marker + carrier kept).
        laa_removed = copy.deepcopy(receipt)
        laa_removed["resolutionContext"][0].pop("laa", None)
        self.assertFalse(_same(laa_removed))

        # Carrier removal (marker + laa kept, carrier stripped).
        carrier_removed = copy.deepcopy(receipt)
        carrier_removed["resolutionContext"][0].pop("legacyPaymentCarrier", None)
        self.assertFalse(_same(carrier_removed))

        # Same-job different agreement contentHash (still canonical + current-eligible).
        hash_sub = copy.deepcopy(receipt)
        hash_sub["resolutionContext"][0]["laa"]["agreement"]["contentHash"] = "agreement-hash-other"
        self.assertFalse(_same(hash_sub))

        # Same-job different authenticated session (LAA sessionId).
        session_sub = copy.deepcopy(receipt)
        session_sub["resolutionContext"][0]["laa"]["sessionAuthority"]["sessionId"] = "session-other"
        self.assertFalse(_same(session_sub))

        # Marker/LAA disagreement: marker kept but the full LAA is substituted
        # for a non-current-eligible historical LAA.
        disagreement = copy.deepcopy(receipt)
        disagreement["resolutionContext"][0]["laa"] = copy.deepcopy(
            self._laa_input("laa-authentic-historical-settlement")
        )
        self.assertFalse(_same(disagreement))

        # Cross-job: derive already excludes the cross-job LAA (no receipt).
        cross_receipt, _, _, _ = self._replay_harness("job-b", laa)
        self.assertEqual(cross_receipt["bundleCount"], 0)
        self.assertEqual(cross_receipt["bundleRefs"], [])

    def test_legacy_payment_carrier_shape_is_closed(self):
        """The ResolutionContextEntry legacy-payment carrier is a CLOSED shape:
        the marker, full LAA, and canonical carrier commitment are emitted
        together on the current path, and the structural gate refuses any
        legacy-payment entry that omits or de-types any of the three (no optional
        omission/downgrade)."""
        party = "did:demos:seller"
        laa = self._laa_input("laa-current-payee-bound-success")
        receipt, _, _, _ = self._replay_harness("job-a", laa)
        self.assertEqual(receipt["bundleCount"], 1)
        entry = receipt["resolutionContext"][0]
        self.assertIs(entry.get("legacyPayment"), True)
        self.assertIsInstance(entry.get("laa"), dict)
        self.assertIsInstance(entry.get("legacyPaymentCarrier"), str)
        self.assertEqual(len(entry["legacyPaymentCarrier"]), 64)

        # The structural gate accepts the exact closed carrier.
        ok, _ = R._entry_structural_gate(entry, 0)
        self.assertTrue(ok)

        # Omitting any one member makes the entry structurally non-conforming.
        for field in ("legacyPayment", "laa", "legacyPaymentCarrier"):
            with self.subTest(missing=field):
                malformed = copy.deepcopy(entry)
                malformed.pop(field, None)
                ok, reason = R._entry_structural_gate(malformed, 0)
                self.assertFalse(ok)
                self.assertIn("legacy-payment", reason)

        # A de-typed member (legacyPayment not exactly true, laa not an object,
        # carrier not a sha256 hex string) also refuses structurally.
        de_typed = copy.deepcopy(entry)
        de_typed["legacyPayment"] = "true"
        ok, reason = R._entry_structural_gate(de_typed, 0)
        self.assertFalse(ok)
        self.assertIn("legacy-payment", reason)

        # The explicit historical/audit-only path is non-authorizing: a frozen
        # pre-LAA legacy-payment bundle (no laa) retains the released marker but
        # carries neither laa nor carrier, and can never be replayed as current.
        audit = R.derive_legacy_audit_only(
            party,
            [self._derive_tag("job-a", "seller")],
            1780000000000, 1780900000000, "finalisedAt",
        )
        self.assertEqual(audit["bundleCount"], 1)
        audit_entry = audit["resolutionContext"][0]
        self.assertIs(audit_entry.get("legacyPayment"), True)
        self.assertNotIn("laa", audit_entry)
        self.assertNotIn("legacyPaymentCarrier", audit_entry)

    # --- Gap 2b: legacy-payment classification is verifier-derived from the
    # dereferenced bundle, so removing the entire legacyPayment / laa /
    # legacyPaymentCarrier triad cannot downgrade a completed legacy-payment
    # entry to released-v1 reconciliation. Both replay APIs must refuse. ---

    @staticmethod
    def _excluded_metrics():
        return {
            "completionRate": None,
            "counterpartyAdjustedCompletionRate": None,
            "counterpartyFaultRate": None,
        }

    @staticmethod
    def _strip_legacy_triad_and_downgrade(receipt):
        forged = copy.deepcopy(receipt)
        entry = forged["resolutionContext"][0]
        for field in ("legacyPayment", "laa", "legacyPaymentCarrier"):
            entry.pop(field, None)
        forged["bundleCount"] = 0
        forged["metrics"] = LegacyAgreementAdmissionVectorTests._excluded_metrics()
        return forged

    def test_replay_legacy_all_three_removed_downgrade_rejected(self):
        """Removing the entire legacyPayment / laa / legacyPaymentCarrier triad
        from a completed legacy-payment entry, while downgrading metrics /
        bundleCount to the excluded result and retaining the original legacy
        bundleRef/context entry, MUST refuse replay fail-closed (classification
        is verifier-derived from the dereferenced bundle, never from optional
        receipt fields)."""
        party = "did:demos:seller"
        laa = self._laa_input("laa-current-payee-bound-success")
        receipt, deref, anchor, evidence = self._replay_harness("job-a", laa)
        self.assertEqual(receipt["bundleCount"], 1)
        entry = receipt["resolutionContext"][0]
        self.assertIs(entry.get("legacyPayment"), True)
        self.assertIsInstance(entry.get("laa"), dict)
        self.assertIsInstance(entry.get("legacyPaymentCarrier"), str)

        # Exact valid control: the intact current receipt replays byte-identically.
        same, _ = R.replay_legacy_receipt(
            receipt, deref, party, 1780000000000, 1780900000000, evidence, None,
            anchor, session_authority=self._session_authority(),
        )
        self.assertTrue(same)

        # All-three removal + excluded metrics/bundleCount; the original legacy
        # bundleRef and context entry (roleEvidence/absence evidence) are retained.
        forged = self._strip_legacy_triad_and_downgrade(receipt)
        self.assertEqual(forged["bundleRefs"], receipt["bundleRefs"])
        self.assertEqual(forged["resolutionContext"][0]["contentHash"],
                         receipt["resolutionContext"][0]["contentHash"])
        same_forged, _ = R.replay_legacy_receipt(
            forged, deref, party, 1780000000000, 1780900000000, evidence, None,
            anchor, session_authority=self._session_authority(),
        )
        self.assertFalse(same_forged, "all-three-removal must not replay as a downgraded receipt")

        # Extra caller-supplied admission marker beyond the closed triad refuses.
        extra = copy.deepcopy(receipt)
        extra["resolutionContext"][0]["laaDisposition"] = "current-eligible"
        self.assertFalse(R.replay_legacy_receipt(
            extra, deref, party, 1780000000000, 1780900000000, evidence, None,
            anchor, session_authority=self._session_authority(),
        )[0], "extra admission marker must refuse the closed triad")

    @unittest.skipUnless(HAVE_CRYPTO, "requires the cryptography package")
    def test_replay_receipt_all_three_removed_downgrade_rejected(self):
        """The fully-admitted current replay path shares the same verifier-derived
        classification: a completed legacy-payment bundle whose entry has lost the
        entire triad refuses before any metrics comparison, even with real Ed25519
        bundle/binding signatures and trusted current profile/query/role/entry/
        session authorities."""
        job_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
        buyer = "did:demos:buyer"
        seller = "did:demos:seller"
        session_id = "session-a"
        buyer_priv = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
        seller_priv = Ed25519PrivateKey.from_private_bytes(b"\x22" * 32)

        def pub_bytes(priv):
            return priv.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        def sig_value(priv, domain, content_hash):
            return base64.urlsafe_b64encode(
                priv.sign((domain + content_hash).encode("utf-8"))
            ).rstrip(b"=").decode("ascii")

        laa = self._laa_input("laa-current-payee-bound-success")
        laa["agreement"]["jobId"] = job_id
        laa["sessionAuthority"]["jobId"] = job_id
        laa["sessionAuthority"]["sessionId"] = session_id
        session_authority = {job_id: session_id}

        bundle = {
            "bundleVersion": "1",
            "jobId": job_id,
            "anchoredByRole": "seller",
            "outcome": "completed",
            "parties": [
                {"role": "buyer", "primaryClaim": buyer},
                {"role": "seller", "primaryClaim": seller},
            ],
            "finalisedAt": 100,
        }
        content_hash = R.bundle_hash(bundle)
        bundle["signatures"] = [
            {"party": buyer, "algorithm": "ed25519",
             "value": sig_value(buyer_priv, R.BUNDLE_DOMAIN, content_hash)},
            {"party": seller, "algorithm": "ed25519",
             "value": sig_value(seller_priv, R.BUNDLE_DOMAIN, content_hash)},
        ]
        seller_addr = R._current_logical_address(job_id, "seller")
        buyer_addr = R._current_logical_address(job_id, "buyer")
        absence = {
            "kind": "non-membership-proof",
            "nativeAddress": "stor-absent-" + job_id,
            "finalizedStateRef": "demos-testnet:finalized-100",
        }
        absence_hash = R._canon_sha(absence)
        absence_binding = {
            "bindingVersion": "1",
            "jobId": job_id,
            "role": "buyer",
            "logicalAddress": buyer_addr,
            "nativeAddress": "stor-absent-" + job_id,
            "bundleContentHash": "0" * 64,
            "signer": buyer,
        }
        absence_binding["signature"] = {
            "signer": buyer,
            "algorithm": "ed25519",
            "value": sig_value(buyer_priv, R.BINDING_DOMAIN,
                               R.binding_hash(absence_binding)),
        }
        tag = {
            "bundle": bundle,
            "resolvedRole": "seller",
            "counterpartyDisposition": "absent",
            "absenceEvidenceRef": {
                "kind": "non-membership-proof",
                "locator": "stor-absent-" + job_id,
                "contentHash": absence_hash,
            },
            "absenceBinding": absence_binding,
            "roleEvidence": {"kind": "address", "resolvedAddress": seller_addr},
            "laa": laa,
        }
        receipt = R.derive(seller, [tag], 0, 200, "finalisedAt",
                           session_authority=session_authority)
        self.assertEqual(receipt["bundleCount"], 1)
        entry = receipt["resolutionContext"][0]
        self.assertIs(entry.get("legacyPayment"), True)
        self.assertIsInstance(entry.get("laa"), dict)
        self.assertIsInstance(entry.get("legacyPaymentCarrier"), str)

        keys = R.trusted_verification_keys({
            buyer: pub_bytes(buyer_priv), seller: pub_bytes(seller_priv)})
        authority = R.trusted_current_context(
            [
                R.trusted_role_authority(job_id, "seller", seller),
                R.trusted_role_authority(job_id, "buyer", buyer),
            ],
            query=R.trusted_query_authority(seller, 0, 200, "finalisedAt"),
            entry_authorities=[R.trusted_entry_authority(
                content_hash, job_id, "seller", seller,
                counterparty_disposition="absent",
                counterparty_role="buyer",
                counterparty_participant_identity=buyer,
            )],
        )
        deref = lambda h: {content_hash: bundle}.get(h)
        anchor = lambda a: {seller_addr: bundle}.get(a)
        evidence = lambda h: {absence_hash: absence}.get(h)

        def replay(r):
            return R.replay_receipt(
                r, deref, seller, 0, 200, evidence_deref=evidence,
                pubkeys=keys, anchor_deref=anchor, trusted_contexts=authority,
                windowing_basis="finalisedAt", session_authority=session_authority)

        # Exact valid control: intact triad replays byte-identically.
        same, replayed = replay(receipt)
        self.assertTrue(same, "intact current receipt must replay byte-identically")
        self.assertEqual(replayed["bundleCount"], 1)

        # All-three removal + excluded metrics/bundleCount refuses fail-closed.
        forged = self._strip_legacy_triad_and_downgrade(receipt)
        self.assertEqual(forged["bundleRefs"], receipt["bundleRefs"])
        same_forged, _ = replay(forged)
        self.assertFalse(same_forged, "all-three-removal must not replay through the current API")

        # Partial omission (marker kept, laa + carrier removed) also refuses.
        partial = copy.deepcopy(receipt)
        partial["resolutionContext"][0].pop("laa", None)
        partial["resolutionContext"][0].pop("legacyPaymentCarrier", None)
        self.assertFalse(replay(partial)[0])

    def test_legacy_payment_classification_is_bundle_derived(self):
        """The classification is verifier-derived from the dereferenced copy
        alone: a completed legacy AttestationBundle is legacy-payment; a
        non-completed legacy bundle, a fault/evidence-bound bundle, an ambiguous
        (multi-discriminator) bundle, and a non-dict are NOT — so the closed
        triad is required only for the former and never for the rest."""
        completed = {"bundleVersion": "1", "outcome": "completed"}
        self.assertTrue(R._bundle_is_legacy_payment(completed))

        # Non-completed legacy bundle (no successful payment): not legacy-payment.
        self.assertFalse(R._bundle_is_legacy_payment(
            {"bundleVersion": "1", "outcome": "aborted-by-self"}))
        self.assertFalse(R._bundle_is_legacy_payment(
            {"bundleVersion": "1", "outcome": "failed-perm"}))

        # Non-legacy current bundles (fault / evidence-bound): not legacy-payment.
        self.assertFalse(R._bundle_is_legacy_payment(
            {"faultBundleVersion": "1", "outcome": "completed"}))
        self.assertFalse(R._bundle_is_legacy_payment(
            {"evidenceBoundFaultBundleVersion": "1", "outcome": "completed"}))

        # Ambiguous classification (multiple/unknown discriminators) fails closed
        # to not-legacy-payment; the replay path refuses such a copy via
        # _bundle_signatures_valid's discriminator gate before any metrics compare.
        self.assertFalse(R._bundle_is_legacy_payment(
            {"bundleVersion": "1", "faultBundleVersion": "1", "outcome": "completed"}))
        self.assertFalse(R._bundle_is_legacy_payment(
            {"unknownBundleVersion": "1", "outcome": "completed"}))

        # Non-dict / bare dict are never legacy-payment.
        self.assertFalse(R._bundle_is_legacy_payment(None))
        self.assertFalse(R._bundle_is_legacy_payment({"outcome": "completed"}))

        # A non-legacy entry carries no required triad: _entry_laa_carrier_ok
        # passes without any legacy-payment field (no misclassification).
        self.assertTrue(R._entry_laa_carrier_ok(
            {}, {"faultBundleVersion": "1", "outcome": "completed"}, None))
        self.assertTrue(R._entry_laa_carrier_ok(
            {}, {"bundleVersion": "1", "outcome": "aborted-by-self"}, None))

    # --- Gap 3: stateful verifier-owned commit -> payment trust boundary. ---

    def _commit_input(self):
        return copy.deepcopy(
            self.cases["laa-ca10-preactivation-legacy-commit"]["input"]
        )

    def _reservation_input(self):
        return copy.deepcopy(
            self.cases["laa-precheckpoint-payment-reservation"]["input"]
        )

    def _record_reservation(self, ledger):
        reservation = self._reservation_input()
        self.assertEqual(ledger.reserve(reservation), "reservation-recorded")
        return reservation

    def test_ledger_commit_records_bounded_commitment_without_payment(self):
        ledger = R.LegacyAgreementLedger()
        commit = self._commit_input()
        disposition = ledger.commit(commit)
        self.assertEqual(disposition, "commit-permitted")
        session_id = commit["sessionAuthority"]["sessionId"]
        content_hash = commit["agreement"]["contentHash"]
        self.assertTrue(ledger.commitment_recorded(session_id, content_hash))
        self.assertEqual(ledger.retained_head(session_id, content_hash), "80")
        # The commit itself has zero payment side effects.
        self.assertFalse(R.laa_want(commit)["paymentSideEffects"])

    def test_ledger_reservation_rejects_session_storage_poisoning(self):
        """Reservation storage is keyed by the immutable committed session.

        Caller changes to identities, bundle authority, payer keys,
        orchestrator, or authenticated head are rejected before any reservation
        can be retained.
        """
        mutations = (
            ("sessionId", "session-other"),
            ("jobId", "job-other"),
            ("payerPrimaryClaim", "did:demos:attacker"),
            ("payeePrimaryClaim", "did:demos:attacker"),
            ("payerBundleHash", "buyer-bundle-hash-other"),
            ("payeeBundleHash", "seller-bundle-hash-other"),
            ("payerAuthorizedKeys", ["key:demos:attacker"]),
            ("orchestratorPrimaryClaim", "did:demos:orchestrator-other"),
            ("paymentHeadPosition", "81"),
        )
        for field, replacement in mutations:
            with self.subTest(field=field):
                ledger = R.LegacyAgreementLedger()
                commit = self._commit_input()
                self.assertEqual(ledger.commit(commit), "commit-permitted")
                reservation = self._reservation_input()
                reservation["sessionAuthority"][field] = replacement
                self.assertEqual(ledger.reserve(reservation), "rejected")
                self.assertFalse(
                    ledger.reservation_recorded("session-a", "agreement-hash-a")
                )

    def test_ledger_payment_uses_retained_head_not_caller_nested_copy(self):
        """Lowering the caller-supplied nested payment-head cannot turn a stale
        absence into a pass: the ledger re-runs LAA on the retained head."""
        ledger = R.LegacyAgreementLedger()
        commit = self._commit_input()
        ledger.commit(commit)
        reservation = self._record_reservation(ledger)

        payment = copy.deepcopy(reservation)
        payment["operation"] = "authorize-payment"
        payment["sessionAuthority"]["paymentHeadPosition"] = "40"
        payment["checkpoint"]["resolution"] = "absent"
        payment["checkpoint"]["authenticatedAbsence"] = True
        payment["checkpoint"]["absenceCoverPosition"] = "50"

        # Without the retained head the caller's lowered assertion passes.
        self.assertEqual(R.laa_admission(payment), "pass")
        # The verifier-owned ledger refuses because absence (<=50) is stale
        # against the retained authenticated head (80).
        self.assertEqual(ledger.authorize_payment(payment), "indeterminate")
        # The nested caller mutation did not leak into retained state.
        self.assertEqual(ledger.retained_head("session-a", "agreement-hash-a"), "80")

    def test_ledger_rejects_payment_without_prior_commitment(self):
        ledger = R.LegacyAgreementLedger()
        payment = self._commit_input()
        payment["operation"] = "authorize-payment"
        self.assertEqual(ledger.authorize_payment(payment), "rejected")

    def test_ledger_authorize_payment_requires_exact_commitment_identity(self):
        """authorize_payment must cite the exact recorded (sessionId, contentHash)
        commitment; a different session or agreement hash is refused."""
        ledger = R.LegacyAgreementLedger()
        commit = self._commit_input()
        ledger.commit(commit)
        reservation = self._record_reservation(ledger)

        payment = copy.deepcopy(reservation)
        payment["operation"] = "authorize-payment"

        wrong_session = copy.deepcopy(payment)
        wrong_session["sessionAuthority"]["sessionId"] = "session-other"
        self.assertEqual(ledger.authorize_payment(wrong_session), "rejected")

        wrong_hash = copy.deepcopy(payment)
        wrong_hash["agreement"]["contentHash"] = "agreement-hash-other"
        self.assertEqual(ledger.authorize_payment(wrong_hash), "rejected")

    def test_ledger_non_identical_retry_cannot_overwrite_retained_head(self):
        """The first verifier-owned session/head record is immutable: a retry that
        lowers the nested payment-head or the top-level payment position must not
        overwrite the retained authenticated head."""
        ledger = R.LegacyAgreementLedger()
        commit = self._commit_input()
        ledger.commit(commit)
        session_id = commit["sessionAuthority"]["sessionId"]
        content_hash = commit["agreement"]["contentHash"]

        nested_lowered = copy.deepcopy(commit)
        nested_lowered["sessionAuthority"]["paymentHeadPosition"] = "40"
        self.assertEqual(ledger.commit(nested_lowered), "commit-permitted")
        self.assertEqual(ledger.retained_head(session_id, content_hash), "80")

        top_lowered = copy.deepcopy(commit)
        top_lowered["paymentPosition"] = "40"
        self.assertEqual(ledger.commit(top_lowered), "commit-permitted")
        self.assertEqual(ledger.retained_head(session_id, content_hash), "80")

    def test_ledger_idempotent_commit_and_no_expanded_payment_authority(self):
        ledger = R.LegacyAgreementLedger()
        commit = self._commit_input()
        self.assertEqual(ledger.commit(commit), "commit-permitted")
        # Retry the identical commit: idempotent, still a single bounded commitment.
        self.assertEqual(ledger.commit(copy.deepcopy(commit)), "commit-permitted")
        session_id = commit["sessionAuthority"]["sessionId"]
        content_hash = commit["agreement"]["contentHash"]
        self.assertEqual(ledger.retained_head(session_id, content_hash), "80")

        reservation = self._record_reservation(ledger)
        self.assertTrue(ledger.reservation_recorded(session_id, content_hash))

        # An exact post-activation completion may use the original bounded
        # authority, but it grants no expanded or repeat payment authority.
        payment = copy.deepcopy(reservation)
        payment["operation"] = "authorize-payment"
        payment["checkpoint"]["resolution"] = "verified"
        payment["checkpoint"]["authenticatedAbsence"] = False
        payment["settlementEvidence"]["resolution"] = "absent"
        self.assertEqual(ledger.authorize_payment(payment), "transition-only")

    def test_adapter_effect_is_called_once_only_for_exact_transition(self):
        """The adapter boundary, not merely ``laa_want``, gates a fake payment.

        One exact pre-checkpoint commitment and signed reservation may call the
        effect once. Every
        substitution, unavailable authority, post-checkpoint commitment,
        expired deadline, and duplicate/retry leaves the call count unchanged.
        This fixture demonstrates in-process call ordering and idempotency only;
        it does not claim crash-durable atomicity or provider reconciliation.
        """
        calls = []

        def effect(request):
            calls.append(request)

        def merge(target, changes):
            for key, replacement in changes.items():
                if isinstance(replacement, dict) and isinstance(target.get(key), dict):
                    merge(target[key], replacement)
                else:
                    target[key] = replacement

        def prepared(payment_changes=None):
            ledger = R.LegacyAgreementLedger()
            commit = self._commit_input()
            self.assertEqual(ledger.commit(commit), "commit-permitted")
            reservation = self._record_reservation(ledger)
            payment = copy.deepcopy(reservation)
            payment["operation"] = "authorize-payment"
            payment["checkpoint"]["resolution"] = "verified"
            payment["checkpoint"]["authenticatedAbsence"] = False
            payment["settlementEvidence"]["resolution"] = "absent"
            merge(payment, payment_changes or {})
            return ledger, payment

        # Substitutions and unavailable/expired authority never reach the effect.
        rejected = (
            {"paymentEffect": {"payeeAddress": "demos1attackeraddress"}},
            {"paymentEffect": {"payingKey": "key:demos:attacker"}},
            {"paymentEffect": {"payerBundleHash": "buyer-bundle-hash-other"}},
            {"paymentEffect": {"payeeBundleHash": "seller-bundle-hash-other"}},
            {"paymentEffect": {"jobId": "job-other"}},
            {"agreement": {"contentHash": "agreement-hash-other"}},
            {"paymentEffect": {"amount": {"amount": "11.00"}}},
            {"railAuthority": {"railId": "evm-erc20"}},
            {"agreement": {"listingRef": {"contentHash": "listing-hash-other"}}},
            {"paymentEffect": {"sessionId": "session-other"}},
            {"paymentEffect": {"phase": "pay-evm-erc20"}},
            {"paymentAuthority": {"resolution": "unavailable"}},
            {"paymentAuthority": {"authenticatedNowMs": 2001}},
        )
        for payment_changes in rejected:
            with self.subTest(payment=payment_changes):
                ledger, payment = prepared(payment_changes)
                before = len(calls)
                self.assertNotIn(
                    ledger.execute_payment(payment, effect),
                    {"transition-only", "current-eligible"},
                )
                self.assertEqual(len(calls), before)

        # Missing verifier authority is indeterminate and side-effect free.
        ledger, payment = prepared()
        payment.pop("paymentAuthority")
        before = len(calls)
        self.assertEqual(ledger.execute_payment(payment, effect), "indeterminate")
        self.assertEqual(len(calls), before)

        # The exact original transition calls once; identical retry calls zero.
        ledger, payment = prepared()
        self.assertEqual(ledger.execute_payment(payment, effect), "transition-only")
        self.assertEqual(len(calls), before + 1)
        self.assertEqual(calls[-1]["payerBundleHash"], "buyer-bundle-hash-a")
        self.assertEqual(calls[-1]["payeeBundleHash"], "seller-bundle-hash-a")
        self.assertEqual(calls[-1]["payingKey"], "key:demos:buyer-paying")
        self.assertEqual(calls[-1]["payeeAddress"], "demos1selleraddress")
        self.assertEqual(ledger.execute_payment(copy.deepcopy(payment), effect), "rejected")
        self.assertEqual(len(calls), before + 1)

        # A commitment attempted directly against the verified activation
        # checkpoint is rejected and never stored, so no later payment can call
        # the adapter. This avoids a causally impossible absence proof.
        ledger = R.LegacyAgreementLedger()
        post = self._commit_input()
        post["checkpoint"]["resolution"] = "verified"
        post["checkpoint"]["authenticatedAbsence"] = False
        post["commitment"]["position"] = "110"
        self.assertEqual(ledger.commit(post), "rejected")
        self.assertFalse(ledger.commitment_recorded("session-a", "agreement-hash-a"))
        payment = copy.deepcopy(post)
        payment["operation"] = "authorize-payment"
        before = len(calls)
        self.assertEqual(ledger.execute_payment(payment, effect), "rejected")
        self.assertEqual(len(calls), before)

    def test_ledger_completed_precheckpoint_historical_audit_still_passes(self):
        """A finalized pre-checkpoint settlement remains an authentic historical
        audit (historical-only), not a current payment."""
        ledger = R.LegacyAgreementLedger()
        historical = copy.deepcopy(
            self.cases["laa-authentic-historical-settlement"]["input"]
        )
        self.assertEqual(R.laa_admission(historical), "pass")
        want = R.laa_want(historical)
        self.assertEqual(want["dacs5Admission"], "historical-only")
        self.assertFalse(want["currentMetricEligible"])

    def test_ledger_rejects_empty_or_whitespace_identity_keys(self):
        """commit / authorize_payment key on ``(sessionId, contentHash)``: empty,
        whitespace, or non-canonical identity values are rejected before any
        commitment is recorded or any payment is authorized."""
        ledger = R.LegacyAgreementLedger()
        commit = self._commit_input()
        for field, container in (
            ("sessionId", "sessionAuthority"),
            ("contentHash", "agreement"),
        ):
            for bad in ("", "   ", " session-a ", " session-a"):
                with self.subTest(field=field, value=repr(bad)):
                    bad_commit = self._mutate(commit, container, field, bad)
                    self.assertEqual(ledger.commit(bad_commit), "rejected")
        # authorize_payment with an empty/whitespace session or hash is refused.
        ledger.commit(commit)
        payment = copy.deepcopy(commit)
        payment["operation"] = "authorize-payment"
        for field, container in (
            ("sessionId", "sessionAuthority"),
            ("contentHash", "agreement"),
        ):
            bad_payment = self._mutate(payment, container, field, "")
            self.assertEqual(ledger.authorize_payment(bad_payment), "rejected")

    def test_ledger_noncanonical_identity_keys_do_not_collide(self):
        """A padded or non-NFC spelling is not the canonical commitment key: it is
        rejected, and a canonical key is never silently matched by a padded one."""
        ledger = R.LegacyAgreementLedger()
        commit = self._commit_input()
        self.assertEqual(ledger.commit(commit), "commit-permitted")
        session_id = commit["sessionAuthority"]["sessionId"]
        content_hash = commit["agreement"]["contentHash"]
        # Padded / non-canonical lookups are refused and never recorded.
        padded = copy.deepcopy(commit)
        padded["agreement"]["contentHash"] = content_hash + " "
        self.assertEqual(ledger.commit(padded), "rejected")
        self.assertFalse(
            ledger.commitment_recorded(session_id, content_hash + " ")
        )
        self.assertFalse(ledger.commitment_recorded(session_id + " ", content_hash))


if __name__ == "__main__":
    unittest.main()
