"""Repeatable witnesses that selected Vet and HTLC regressions are load-bearing.

These tests deliberately patch only in-process Python objects.  Each selected
test is first run unchanged as a control, then rerun with one narrowly scoped
wrong implementation.  The witness succeeds only when the existing assertions
reject that implementation with an assertion failure rather than an error.
"""

import ast
import copy
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import dacs5_reference as dacs5  # noqa: E402
import test_bundle_settlement_evidence_bijection_vectors as seb  # noqa: E402
import test_current_evidence_boundary_regressions as released  # noqa: E402
import test_dacs1_vet_golden_inputs as vet  # noqa: E402
import test_identity_risk_and_dacsx_pack as htlc_pack  # noqa: E402
import test_pr366_feature_interactions as interactions  # noqa: E402
import test_presence_only_claim_vectors as presence  # noqa: E402


class ReviewGuardWitnessTests(unittest.TestCase):
    def _run_test(self, test_class, method_name):
        result = unittest.TestResult()
        suite = unittest.TestSuite([test_class(method_name)])
        suite.run(result)
        self.assertEqual(1, result.testsRun)
        return result

    def _run_vet_test(self, method_name):
        return self._run_test(vet.Dacs1VetGoldenInputTests, method_name)

    def _assert_clean_control(self, result):
        self.assertEqual([], result.failures)
        self.assertEqual([], result.errors)
        self.assertEqual([], result.skipped)
        self.assertEqual([], result.expectedFailures)
        self.assertEqual([], result.unexpectedSuccesses)

    def _assert_mutation_caught(self, result, *expected_fragments):
        self.assertEqual([], result.errors)
        self.assertEqual([], result.skipped)
        self.assertEqual([], result.expectedFailures)
        self.assertEqual([], result.unexpectedSuccesses)
        self.assertTrue(result.failures, "selected test did not catch the mutation")
        failures = "\n".join(traceback for _, traceback in result.failures)
        for fragment in expected_fragments:
            self.assertIn(fragment, failures)

    def test_non_pass_origin_predicates_are_load_bearing(self):
        selected = "test_cached_non_pass_requires_equal_complete_origin_parameters"
        self._assert_clean_control(self._run_vet_test(selected))

        # Wrong implementation: every non-pass result is eligible even when
        # its verifier-owned origin binds different requirement parameters.
        with mock.patch.object(
            vet, "non_pass_origin_is_eligible", return_value=True
        ):
            mutated = self._run_vet_test(selected)
        self._assert_mutation_caught(
            mutated,
            "signed overallDecision does not match replay",
            "oneOf group: at least one claim indeterminate",
        )

    def test_external_input_acceptance_is_load_bearing(self):
        selected = "test_external_vet_entry_requires_exact_cf5_admission"
        self._assert_clean_control(self._run_vet_test(selected))

        # Wrong implementation: the external admission boundary rejects every
        # input, including the test's valid canonical JSON accepting control.
        with mock.patch.object(
            vet.VetReferenceRuntime,
            "admit_external_input",
            side_effect=ValueError("guard-witness always-reject mutation"),
        ):
            mutated = self._run_vet_test(selected)
        self._assert_mutation_caught(mutated, "True is not 'error'")

    def test_selector_negative_is_load_bearing(self):
        selected = "test_required_verified_selector_member_disables_the_presence_path"
        self._assert_clean_control(self._run_vet_test(selected))

        # Wrong implementation: selector authorization always succeeds, so a
        # different verified claim can launder an exact presence selector.
        with mock.patch.object(vet, "selector_authorized", return_value=True):
            mutated = self._run_vet_test(selected)
        self._assert_mutation_caught(mutated, "'fail' != 'pass'")

    def test_deferred_scheme_scope_and_no_alias_guards_are_load_bearing(self):
        selected = (
            "test_cci_lei_compatibility_scope_is_explicit_closed_and_discriminating"
        )
        self._assert_clean_control(self._run_vet_test(selected))

        real_registered_schemes = vet.VetReferenceRuntime._registered_schemes

        def admit_deferred_scheme_everywhere(runtime, context):
            schemes = real_registered_schemes(runtime, context)
            return (
                None if schemes is None
                else frozenset(set(schemes) | {"cci-lei"})
            )

        # Wrong implementation: every invocation silently admits the deferred
        # scheme, including the current closed-registry refusal arm.
        with mock.patch.object(
            vet.VetReferenceRuntime,
            "_registered_schemes",
            admit_deferred_scheme_everywhere,
        ):
            mutated = self._run_vet_test(selected)
        self._assert_mutation_caught(mutated, "Tuples differ")

        real_parse_ref = vet.parse_ref

        def alias_cci_lei(value, registered_schemes=None):
            scheme, identifier = real_parse_ref(value, registered_schemes)
            return ("lei", identifier) if scheme == "cci-lei" else (scheme, identifier)

        # Wrong implementation: the explicit compatibility parser aliases the
        # deferred scheme to bare LEI instead of preserving exact scheme identity.
        with mock.patch.object(vet, "parse_ref", side_effect=alias_cci_lei):
            mutated = self._run_vet_test(selected)
        self._assert_mutation_caught(mutated, "Tuples differ")

    def test_deferred_scheme_requirement_binding_is_load_bearing(self):
        selected = (
            "test_cci_lei_profile_is_bound_to_its_exact_verifier_requirement"
        )
        self._assert_clean_control(self._run_vet_test(selected))

        # Wrong implementation: the profile-bearing capability admits any
        # candidate requirement, so retargeting the bound bare-lei member to
        # cci-lei passes under the fixture-only registry.
        with mock.patch.object(
            vet, "compatibility_requirement_bound", return_value=True
        ):
            mutated = self._run_vet_test(selected)
        self._assert_mutation_caught(mutated, "False is not True")

        real_bound = vet.compatibility_requirement_bound

        def unbound_requirement_free_questions(req, admission):
            return True if req is None else real_bound(req, admission)

        # Wrong implementation: only requirement evaluation is bound, so a
        # requirement-free control decision reuses the profile registry.
        with mock.patch.object(
            vet,
            "compatibility_requirement_bound",
            side_effect=unbound_requirement_free_questions,
        ):
            mutated = self._run_vet_test(selected)
        self._assert_mutation_caught(mutated, "'error' != 'pass'")

        # Wrong implementation: a profile is admitted without its paired
        # verifier-owned requirement binding (or a binding without a profile).
        with mock.patch.object(
            vet.VetReferenceRuntime,
            "_compatibility_binding_valid",
            return_value=True,
        ):
            mutated = self._run_vet_test(selected)
        self._assert_mutation_caught(mutated, "False is not True")

    def test_htlc_interim_supersession_guard_is_load_bearing(self):
        selected = "test_htlc9_interim_rejects_resolved_only_supersession_reference"
        test_class = htlc_pack.IdentityRiskAndDacsXPackTests
        self._assert_clean_control(self._run_test(test_class, selected))

        # Wrong implementation: the interim accepts the known resolved-only
        # supersedesEvidenceRef member, as before the DACS-4 §9.5.4 repair.
        _, verifier = test_class._load_pack_modules()
        with mock.patch.object(
            verifier, "interim_supersession_errors", return_value=[]
        ):
            mutated = self._run_test(test_class, selected)
        self._assert_mutation_caught(mutated, "2 != 0")

    def _aggregate_with_default_registry_at(self, check_index):
        """Restore one reviewed default-registry call in an isolated function."""

        tree = ast.parse(Path(vet.__file__).read_text(encoding="utf-8"))
        function = copy.deepcopy(next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "authenticate_production_aggregate"
        ))
        checks = sorted(
            (
                node for node in ast.walk(function)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "valid_requirement"
            ),
            key=lambda node: node.lineno,
        )
        self.assertEqual(2, len(checks))
        selected = checks[check_index]
        self.assertEqual(2, len(selected.args))
        self.assertEqual(
            "admission.registered_schemes", ast.unparse(selected.args[1])
        )
        selected.args.pop()
        module = ast.fix_missing_locations(ast.Module(
            body=[function], type_ignores=[]
        ))
        namespace = dict(vars(vet))
        exec(compile(module, str(vet.__file__), "exec"), namespace)
        return namespace["authenticate_production_aggregate"]

    def test_profile_aggregate_attribution_registry_guard_is_load_bearing(self):
        selected = "test_profile_aggregate_rejects_unattributable_committed_result"
        self._assert_clean_control(self._run_vet_test(selected))
        # Wrong implementation: the attribution guard validates the bound
        # requirement against the current registry instead of its admitted one.
        with mock.patch.object(
            vet, "authenticate_production_aggregate",
            self._aggregate_with_default_registry_at(0),
        ):
            mutated = self._run_vet_test(selected)
        self._assert_mutation_caught(mutated, "aggregation authority invalid")

    def test_profile_aggregate_current_freshness_registry_guard_is_load_bearing(self):
        selected_tests = (
            "test_profile_aggregate_requalifies_max_age_with_accepting_boundary",
            "test_profile_aggregate_requalifies_governing_claim_freshness",
        )
        for selected in selected_tests:
            with self.subTest(test=selected):
                self._assert_clean_control(self._run_vet_test(selected))
                # Wrong implementation: current requalification uses the
                # default registry while the later evaluation uses the profile.
                with mock.patch.object(
                    vet, "authenticate_production_aggregate",
                    self._aggregate_with_default_registry_at(1),
                ):
                    mutated = self._run_vet_test(selected)
                self._assert_mutation_caught(mutated, "aggregation authority invalid")

    def test_htlc_future_evidence_selector_guard_is_load_bearing(self):
        selected = "test_htlc9_rejects_signed_future_evidence_selector"
        test_class = htlc_pack.IdentityRiskAndDacsXPackTests
        self._assert_clean_control(self._run_test(test_class, selected))
        _, verifier = test_class._load_pack_modules()

        # Wrong implementation: only the four registered selectors are
        # recognised, as before this repair, so a signed future
        # *EvidenceVersion beside evidenceVersion is silently ignored.
        with mock.patch.object(
            verifier,
            "is_evidence_selector_name",
            side_effect=lambda name: name in verifier.DACS4_EVIDENCE_SELECTORS,
        ):
            mutated = self._run_test(test_class, selected)
        self._assert_mutation_caught(
            mutated, "Lists differ", "futureEvidenceVersion"
        )

        # Wrong implementation: the selector guard is removed entirely.
        with mock.patch.object(
            verifier, "settlement_evidence_selector_error", return_value=None
        ):
            mutated = self._run_test(test_class, selected)
        self._assert_mutation_caught(
            mutated, "Lists differ", "futureEvidenceVersion"
        )

    def test_dacs5_st8_interim_supersession_guard_is_load_bearing(self):
        selected = (
            (
                seb.BundleSettlementEvidenceBijectionTests,
                "test_transitive_st8_interim_cannot_itself_carry_a_supersession_edge",
                "!= ('pass', 'ok', ['2:pay-cross-chain-htlc'])",
            ),
            (
                released.CurrentFabDeliveryAdmissionTests,
                "test_released_copies_reject_an_st8_interim_carrying_a_supersession_edge",
                "!= ('pass', ",
            ),
        )
        for test_class, method_name, fragment in selected:
            with self.subTest(test=method_name):
                self._assert_clean_control(self._run_test(test_class, method_name))

                # Wrong implementation: the transitive DACS-5 consumer accepts
                # an authenticated interim failure that itself carries the
                # resolved-only supersedesEvidenceRef, as before this guard.
                with mock.patch.object(
                    dacs5, "_st8_interim_supersession_failure", return_value=None
                ):
                    mutated = self._run_test(test_class, method_name)
                self._assert_mutation_caught(mutated, "Tuples differ", fragment)

    def test_stale_primary_expiry_guard_is_load_bearing(self):
        selected = (
            "test_stale_primary_selector_reaches_freshness_guard_with_valid_control"
        )
        self._assert_clean_control(self._run_vet_test(selected))

        real_matching_claims = vet.matching_claims
        real_freshness_window = vet.freshness_window

        def ignore_claim_expiry_for_matching(
            value, req, decision_time, exact_ref=None, *, registered_schemes=None
        ):
            changed = copy.deepcopy(value)
            for claim in changed["bundle"]["claims"]:
                claim.pop("expiresAt", None)
            return real_matching_claims(
                changed,
                req,
                decision_time,
                exact_ref,
                registered_schemes=registered_schemes,
            )

        def ignore_claim_expiry_for_control(result, claim, recipes, decision_time):
            changed = copy.deepcopy(claim)
            changed.pop("expiresAt", None)
            return real_freshness_window(result, changed, recipes, decision_time)

        # Wrong implementation: the authenticated claim expiry is ignored by
        # both member selection and exact selected-claim control.
        with mock.patch.object(
            vet, "matching_claims", side_effect=ignore_claim_expiry_for_matching
        ), mock.patch.object(
            vet, "freshness_window", side_effect=ignore_claim_expiry_for_control
        ):
            mutated = self._run_vet_test(selected)
        self._assert_mutation_caught(mutated, "True is not false")

    def test_non_key_controlled_donor_guard_is_load_bearing(self):
        selected = "test_non_key_controlled_donor_cannot_authorize_selected_claim"
        self._assert_clean_control(self._run_vet_test(selected))
        real_selector_authorized = vet.selector_authorized

        def borrow_same_scheme_control(
            value,
            requirement,
            recipes,
            result_context,
            decision_time,
            *,
            registered_schemes=None,
        ):
            if real_selector_authorized(
                value,
                requirement,
                recipes,
                result_context,
                decision_time,
                registered_schemes=registered_schemes,
            ):
                return True
            presented = vet.presented_claim(
                value["bundle"], registered_schemes
            )
            if presented is None:
                return False
            selected_scheme, _ = vet.parse_ref(
                presented["ref"], registered_schemes
            )
            if selected_scheme == "key":
                return False
            return any(
                not vet.same_identity(
                    claim["ref"], presented["ref"], registered_schemes
                )
                and vet.parse_ref(claim["ref"], registered_schemes)[0]
                == selected_scheme
                and vet.claim_establishes_control(
                    value,
                    claim,
                    recipes,
                    result_context,
                    decision_time,
                    registered_schemes=registered_schemes,
                )
                for claim in value["bundle"]["claims"]
            )

        # Wrong implementation: a genuine holder-bound non-key donor may
        # supply control for a different same-scheme selected claim. Scheme and
        # key guards stay intact, isolating BR-5/PCR-5 exact-claim control in
        # both the universal presenter gate and selector authorization.
        with mock.patch.object(
            vet, "selector_authorized", side_effect=borrow_same_scheme_control
        ), mock.patch.object(
            vet, "presented_control", return_value=True
        ):
            mutated = self._run_vet_test(selected)
        self._assert_mutation_caught(mutated, "True is not false")

    def test_one_use_admission_across_aggregate_modes_is_load_bearing(self):
        test_class = interactions.Pr366VetInteractionTests
        selected = "test_one_use_admission_spans_current_and_historical_aggregate_use"
        self._assert_clean_control(self._run_test(test_class, selected))
        real_aggregate_output = vet.aggregate_output

        def scratch_ledger_history(
            value, trusted_context, recipes, result_context, runtime, *,
            input_admission, authorize_current=True,
        ):
            if authorize_current:
                return real_aggregate_output(
                    value, trusted_context, recipes, result_context, runtime,
                    input_admission=input_admission,
                )
            live = runtime.nonce_ledger
            runtime.nonce_ledger = vet.NonceLedger(
                trusted_context["nonceIssuances"],
                registered_schemes=vet.KNOWN_SCHEMES,
            )
            try:
                return real_aggregate_output(
                    value, trusted_context, recipes, result_context, runtime,
                    input_admission=input_admission, authorize_current=False,
                )
            finally:
                runtime.nonce_ledger = live

        # Wrong implementation: non-authorizing reconstruction admits through
        # a scratch ledger, so it neither consumes nor respects the issuer's
        # one-use SN-4 record.
        with mock.patch.object(vet, "aggregate_output", scratch_ledger_history):
            mutated = self._run_test(test_class, selected)
        self._assert_mutation_caught(
            mutated, "aggregation authority invalid", "False is not true"
        )

    def test_current_selector_requalification_is_load_bearing(self):
        test_class = interactions.Pr366VetInteractionTests
        selected = "test_production_selector_evidence_is_requalified_at_trusted_now"
        self._assert_clean_control(self._run_test(test_class, selected))

        # Wrong implementation: production authorization trusts the signed
        # historical selector result without requalifying its exact control
        # and governing freshness window at trustedNow.
        with mock.patch.object(
            vet, "current_selector_authorized", return_value=True
        ):
            mutated = self._run_test(test_class, selected)
        self._assert_mutation_caught(
            mutated, "current authorization accepted expired selector evidence"
        )

    def test_no_selector_presenter_control_is_load_bearing(self):
        test_class = interactions.Pr366VetInteractionTests
        selected = "test_no_selector_still_requires_exact_presenter_control"
        self._assert_clean_control(self._run_test(test_class, selected))

        # Wrong implementation: membership and another valid claim signature
        # are treated as control of the exact declared presenter.
        with mock.patch.object(vet, "presented_control", return_value=True):
            mutated = self._run_test(test_class, selected)
        self._assert_mutation_caught(mutated, "False is not True")

    def test_no_selector_current_control_is_load_bearing(self):
        test_class = interactions.Pr366VetInteractionTests
        selected = "test_no_selector_result_control_is_current_outside_member_predicates"
        self._assert_clean_control(self._run_test(test_class, selected))

        # Wrong implementation: an exact non-key control proof is trusted at
        # generatedAt even after its governing DACS-1 window expires.
        with mock.patch.object(
            vet, "current_presenter_controlled", return_value=True
        ):
            mutated = self._run_test(test_class, selected)
        self._assert_mutation_caught(mutated, "aggregation authority invalid")

    def test_presence_pack_universal_presenter_control_is_load_bearing(self):
        selected = "test_presenter_control_vectors_are_distinguishing"
        test_class = presence.PresenceOnlyClaimVectorTests
        self._assert_clean_control(self._run_test(test_class, selected))

        # Wrong implementation: any included key signature controls the exact
        # declared presenter, recreating the selector-absent aggregation gap.
        with mock.patch.object(
            presence, "exact_presenter_key_controlled", return_value=True
        ):
            mutated = self._run_test(test_class, selected)
        self._assert_mutation_caught(mutated)

    def test_presence_pack_presenter_uniqueness_is_load_bearing(self):
        selected = "test_presented_claim_uniqueness_is_order_independent"
        test_class = presence.PresenceOnlyClaimVectorTests
        self._assert_clean_control(self._run_test(test_class, selected))

        def first_cf3_match(bundle, claims):
            presented = presence.parse_claim_reference(
                bundle.get("presentedBy"),
                registered_schemes=presence.KNOWN_SCHEMES,
            )
            return next(
                (
                    (claim, parsed)
                    for claim, parsed in claims
                    if parsed.identity == presented.identity
                ),
                None,
            )

        # Wrong implementation: array order selects the first of multiple
        # canonical-distinct claims that share the presented CF-3 identity.
        with mock.patch.object(
            presence, "exact_presented_claim", side_effect=first_cf3_match
        ):
            mutated = self._run_test(test_class, selected)
        self._assert_mutation_caught(mutated)

    def test_absent_presenter_semantic_boundary_is_load_bearing(self):
        vet_test = "test_presented_by_must_resolve_to_a_signed_bundle_claim"
        presence_test = "test_presented_claim_uniqueness_is_order_independent"
        self._assert_clean_control(self._run_vet_test(vet_test))
        self._assert_clean_control(self._run_test(
            presence.PresenceOnlyClaimVectorTests, presence_test
        ))

        original_vet_verify = vet.verify_bundle
        def old_vet_structural_gate(bundle, admission=None, *, registered_schemes=None):
            if not original_vet_verify(
                bundle, admission, registered_schemes=registered_schemes
            ):
                return False
            schemes = vet.KNOWN_SCHEMES if registered_schemes is None else registered_schemes
            presented = vet.parse_ref(bundle["presentedBy"], schemes)
            return any(
                vet.parse_ref(item["ref"], schemes) == presented
                for item in bundle["claims"]
            )

        # This is the previous wrong implementation: the valid zero-match
        # bundle is rejected as malformed before semantic matching runs.
        with mock.patch.object(vet, "verify_bundle", side_effect=old_vet_structural_gate):
            self._assert_mutation_caught(self._run_vet_test(vet_test))

        original_presence_verify = presence.verify_bundle
        def old_presence_structural_gate(bundle, admission=None):
            if not original_presence_verify(bundle, admission):
                return False
            presented = presence.parse_claim_reference(
                bundle["presentedBy"], registered_schemes=presence.KNOWN_SCHEMES
            )
            return any(
                presence.parse_claim_reference(
                    item["ref"], registered_schemes=presence.KNOWN_SCHEMES
                ).identity == presented.identity
                for item in bundle["claims"]
            )

        with mock.patch.object(
            presence, "verify_bundle", side_effect=old_presence_structural_gate
        ):
            self._assert_mutation_caught(self._run_test(
                presence.PresenceOnlyClaimVectorTests, presence_test
            ))

    def test_principal_bundle_cf3_signature_membership_is_load_bearing(self):
        selected = "test_presented_by_must_resolve_to_a_signed_bundle_claim"
        self._assert_clean_control(self._run_vet_test(selected))

        def raw_reference_membership(signature_ref, claims, **_):
            return any(
                isinstance(item, dict) and item.get("ref") == signature_ref
                for item in claims
            )

        # Wrong implementation: a signer is considered a bundle member only
        # when its complete CF-2-qualified reference is byte-equal to a claim.
        with mock.patch.object(
            vet,
            "signature_ref_matches_claim",
            side_effect=raw_reference_membership,
        ):
            mutated = self._run_vet_test(selected)
        self._assert_mutation_caught(mutated)

    def test_verifier_identity_exact_key_signature_is_load_bearing(self):
        test_class = interactions.Pr366VetInteractionTests
        selected = (
            "test_production_verifier_identity_requires_exact_expected_key_signature"
        )
        self._assert_clean_control(self._run_test(test_class, selected))

        # Wrong implementation: a valid signature by any included cosigner is
        # accepted as the verifier's own presentation proof.
        with mock.patch.object(
            vet, "verifier_identity_has_exact_key_control", return_value=True
        ):
            mutated = self._run_test(test_class, selected)
        self._assert_mutation_caught(mutated, "aggregation authority invalid")

    def test_verifier_identity_canonical_claim_dedup_is_load_bearing(self):
        selected = "test_verifier_identity_identical_claim_repetition_collapses"
        self._assert_clean_control(self._run_vet_test(selected))

        def raw_match_collection(claims, identity, *, registered_schemes=None):
            schemes = (
                vet.KNOWN_SCHEMES
                if registered_schemes is None
                else registered_schemes
            )
            return [
                vet.canonical_bytes(item) for item in claims
                if vet.parse_ref(item.get("ref"), schemes) == identity
            ]

        # Wrong implementation: count raw CF-3 matches without collapsing
        # byte-identical complete BundleClaim values.
        with mock.patch.object(
            vet,
            "canonical_distinct_identity_claims",
            side_effect=raw_match_collection,
        ):
            mutated = self._run_vet_test(selected)
        self._assert_mutation_caught(mutated, "aggregation authority invalid")

    def test_profile_aggregate_bundle_registry_is_load_bearing(self):
        test_class = interactions.Pr366VetInteractionTests
        selected = (
            "test_bound_profile_admits_profile_only_presence_claims_in_production_aggregation"
        )
        self._assert_clean_control(self._run_test(test_class, selected))
        real_matching_claims = vet.matching_claims

        def default_registry_matching(
            value, req, decision_time, exact_ref=None, *, registered_schemes=None
        ):
            return real_matching_claims(value, req, decision_time, exact_ref)

        # Wrong implementation: member matching drops the admitted profile
        # registry and parses the bound bundle's claims under default rules.
        with mock.patch.object(
            vet, "matching_claims", side_effect=default_registry_matching
        ):
            mutated = self._run_test(test_class, selected)
        self._assert_mutation_caught(mutated, "invalid aggregation input")

        # Wrong implementation: the verifier-owned profile falls back to the
        # current closed registry for every invocation.
        with mock.patch.object(
            vet.VetReferenceRuntime,
            "_registered_schemes",
            lambda runtime, context: frozenset(vet.KNOWN_SCHEMES),
        ):
            mutated = self._run_test(test_class, selected)
        self._assert_mutation_caught(mutated, "aggregation authority invalid")

    def test_htlc_receipt_mode_supersession_anchor_context_is_load_bearing(self):
        selected = "test_htlc9_receipt_mode_binds_supersession_anchor_through_pair_entry_point"
        test_class = htlc_pack.IdentityRiskAndDacsXPackTests
        self._assert_clean_control(self._run_test(test_class, selected))
        _, verifier = test_class._load_pack_modules()
        real_binding = verifier.supersession_binding_errors

        def dropped_receipt_mode(
            reference, interim, *, expected_phase_orchestrator, require_fixture_receipt
        ):
            return real_binding(
                reference, interim,
                expected_phase_orchestrator=expected_phase_orchestrator,
                require_fixture_receipt=False,
            )

        # Wrong implementation: validate_resolved drops the pair's receipt
        # policy when binding the supersession reference.
        with mock.patch.object(
            verifier, "supersession_binding_errors", side_effect=dropped_receipt_mode
        ):
            mutated = self._run_test(test_class, selected)
        self._assert_mutation_caught(mutated, "Lists differ", "anchor MUST match")

        # Wrong implementation: an equivalent committed path no longer selects
        # the committed-fixture policy.
        with mock.patch.object(
            verifier, "requires_fixture_receipts", return_value=False
        ):
            mutated = self._run_test(test_class, selected)
        self._assert_mutation_caught(mutated, "False is not true")

    def test_htlc_numeric_identity_guards_are_load_bearing(self):
        selected = "test_htlc9_number_spelling_is_verdict_neutral_while_type_guards_hold"
        test_class = htlc_pack.IdentityRiskAndDacsXPackTests
        self._assert_clean_control(self._run_test(test_class, selected))
        _, verifier = test_class._load_pack_modules()
        safe_integer = 2**53 - 1

        def integer_type_only(value, *, minimum=None):
            return (
                type(value) is int
                and -safe_integer <= value <= safe_integer
                and (minimum is None or value >= minimum)
            )

        # Wrong implementation: the pre-correction host-type rule, under which
        # a JSON-equivalent number spelling changes the verdict.
        with mock.patch.object(
            verifier, "exact_safe_integer", side_effect=integer_type_only
        ):
            mutated = self._run_test(test_class, selected)
        self._assert_mutation_caught(mutated, "observedAt MUST be an integer unix-ms")

        def any_number(value, *, minimum=None):
            return isinstance(value, (int, float)) and (
                minimum is None or value >= minimum
            )

        # Wrong implementation: booleans and fractions pass as integers.
        with mock.patch.object(verifier, "exact_safe_integer", side_effect=any_number):
            mutated = self._run_test(test_class, selected)
        self._assert_mutation_caught(mutated, "guard did not reject")

    def test_no_duplicate_class_local_test_definitions(self):
        duplicates = []
        for path in sorted(TESTS.glob("test_*.py")):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (OSError, SyntaxError, UnicodeError) as error:
                self.fail(f"cannot AST-inspect {path.relative_to(ROOT)}: {error}")
            for class_node in (
                node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
            ):
                definitions = {}
                for item in class_node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                        item.name.startswith("test_")
                    ):
                        definitions.setdefault(item.name, []).append(item.lineno)
                for name, lines in definitions.items():
                    if len(lines) > 1:
                        locations = ", ".join(
                            f"{path.relative_to(ROOT)}:{line}" for line in lines
                        )
                        duplicates.append(
                            f"{locations} ({class_node.name}.{name})"
                        )
        self.assertEqual(
            [],
            duplicates,
            "duplicate class-local test definitions:\n" + "\n".join(duplicates),
        )


if __name__ == "__main__":
    unittest.main()
