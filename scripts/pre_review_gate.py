#!/usr/bin/env python3
"""Execute the small, permanent pre-review invariant registry."""
from __future__ import annotations

import argparse
import importlib.util
import itertools
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import secrets
import signal
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "conformance" / "pre-review-invariants.json"
EVIDENCE_SURFACES = {
    "public-api", "direct-helper", "composed-caller", "compatibility-path",
}


def _pinned(file: str, test: str, *surfaces: str) -> dict:
    return {"file": file, "test": test, "surfaces": frozenset(surfaces)}


PINNED_REVIEW_EVIDENCE = {
    "type-totality-array-ebfab-counterexample": _pinned(
        "tests/test_pr333_fix_2.py",
        "AuthenticatedEvidenceWireTypeAlgorithmTests.test_algorithm_array_rejected_without_exception_ebfab",
        "public-api",
    ),
    "type-totality-array-disposition-counterexample": _pinned(
        "tests/test_pr333_fix_2.py",
        "AuthenticatedEvidenceWireTypeAlgorithmTests.test_algorithm_array_rejected_without_exception_disposition",
        "public-api",
    ),
    "type-totality-object-counterexample": _pinned(
        "tests/test_pr333_fix_2.py",
        "AuthenticatedEvidenceWireTypeAlgorithmTests.test_algorithm_object_rejected_without_exception",
        "public-api",
    ),
    "type-totality-null-counterexample": _pinned(
        "tests/test_pr333_fix_2.py",
        "AuthenticatedEvidenceWireTypeAlgorithmTests.test_algorithm_null_rejected_without_exception",
        "public-api",
    ),
    "type-totality-boolean-counterexample": _pinned(
        "tests/test_pr333_fix_2.py",
        "AuthenticatedEvidenceWireTypeAlgorithmTests.test_algorithm_boolean_rejected_without_exception",
        "public-api",
    ),
    "type-totality-number-counterexample": _pinned(
        "tests/test_pr333_fix_2.py",
        "AuthenticatedEvidenceWireTypeAlgorithmTests.test_algorithm_number_rejected_without_exception",
        "public-api",
    ),
    "type-totality-unsupported-string-counterexample": _pinned(
        "tests/test_pr333_fix_2.py",
        "AuthenticatedEvidenceWireTypeAlgorithmTests.test_algorithm_unsupported_string_rejected_without_exception",
        "public-api",
    ),
    "type-totality-control": _pinned(
        "tests/test_pr333_fix_2.py",
        "AuthenticatedEvidenceWireTypeAlgorithmTests.test_valid_algorithm_preserved",
        "public-api",
    ),
    "credential-ref-type-counterexample": _pinned(
        "tests/test_current_evidence_boundary_regressions.py",
        "EntitlementCredentialRefBoundaryTests.test_present_malformed_credential_ref_is_typed_error_on_both_apis",
        "public-api",
    ),
    "credential-ref-positive-control": _pinned(
        "tests/test_current_evidence_boundary_regressions.py",
        "EntitlementCredentialRefBoundaryTests.test_absent_and_valid_private_credential_modes_still_pass",
        "public-api", "compatibility-path",
    ),
    "delivery-binding-counterexample": _pinned(
        "tests/test_current_evidence_boundary_regressions.py",
        "CurrentFabDeliveryAdmissionTests.test_current_fab_delivery_exact_bindings_are_load_bearing",
        "composed-caller",
    ),
    "delivery-binding-control": _pinned(
        "tests/test_current_evidence_boundary_regressions.py",
        "CurrentFabDeliveryAdmissionTests.test_genuine_current_fab_delivery_closure_passes",
        "composed-caller",
    ),
    "era-downgrade-counterexample": _pinned(
        "tests/test_current_evidence_boundary_regressions.py",
        "ExplicitReconciliationReceiptContractTests.test_archival_ebfab_is_comparison_only",
        "composed-caller",
    ),
    "era-downgrade-control": _pinned(
        "tests/test_current_evidence_boundary_regressions.py",
        "ExplicitReconciliationReceiptContractTests.test_current_ebfab_remains_selectable_but_dual_era_refuses",
        "composed-caller", "compatibility-path",
    ),
    "helper-composition-counterexample": _pinned(
        "tests/test_settlement_finality_verification_vectors.py",
        "SettlementFinalityVerificationVectorTests.test_provider_attestation_map_boundary_is_typed_on_direct_and_composed_paths",
        "direct-helper", "composed-caller",
    ),
    "helper-composition-control": _pinned(
        "tests/test_settlement_finality_verification_vectors.py",
        "SettlementFinalityVerificationVectorTests.test_actual_dacs5_strong_bundle_consumer_passes_all_six_models",
        "composed-caller",
    ),
    "historical-helper-binding-counterexample": _pinned(
        "tests/test_current_evidence_boundary_regressions.py",
        "HistoricalEvidenceBindingTests.test_wrong_job_and_malformed_historical_evidence_refuse_without_throwing",
        "direct-helper", "compatibility-path",
    ),
    "historical-helper-binding-control": _pinned(
        "tests/test_current_evidence_boundary_regressions.py",
        "HistoricalEvidenceBindingTests.test_authenticated_historical_fab_delivery_is_not_current_authority",
        "direct-helper", "compatibility-path",
    ),
    "compatibility-counterexample": _pinned(
        "tests/test_settlement_finality_verification_vectors.py",
        "SettlementFinalityVerificationVectorTests.test_historical_pointer_fixture_cannot_bypass_current_profile_admission",
        "compatibility-path",
    ),
    "compatibility-control": _pinned(
        "tests/test_settlement_finality_verification_vectors.py",
        "SettlementFinalityVerificationVectorTests.test_new_new_and_all_new_older_reconciliation_paths_execute",
        "compatibility-path", "composed-caller",
    ),
}

PINNED_UNIT_REGRESSIONS = {
    "pr396-core-b2-jcs-unsupported-integer": {
        "file": "tests/test_revocation_state_completeness_vectors.py",
        "test": "RevocationStateCompletenessTests.test_legacy_sorted_json_unsupported_integer_is_rejected_end_to_end",
    },
    "prior-blocker-round10-lossy-signature-dedup": {
        "file": "tests/test_round10_validation_predicate_vectors.py",
        "test": "Round10ValidationPredicateTests.test_r10_2_duplicate_invalid_defect",
    },
    "prior-blocker-round11-four-probe-grid": {
        "file": "tests/test_round11_receipt_ingress_vectors.py",
        "test": "Round11ReceiptIngressTests.test_r11_grid_covers_randoms_four",
    },
    "prior-blocker-round12-replay-context-completeness": {
        "file": "tests/test_round12_replay_completeness_vectors.py",
        "test": "Round12ReplayCompletenessTests.test_T1_missing_resolution_context",
    },
    "prior-blocker-round14-full-standing-equivocation": {
        "file": "tests/test_round14_hub_reproduction_vectors.py",
        "test": "Round14VerificationCompletion.test_b_bb6_two_full_standing_forms_are_indeterminate",
    },
    "pr333-ordinary-listing-publisher-role-join": {
        "file": "tests/test_bundle_settlement_evidence_bijection_vectors.py",
        "test": "BundleSettlementEvidenceBijectionTests.test_authenticated_listing_publisher_must_match_ordinary_bundle_seller",
    },
    "pr333-listing-publisher-join-preserves-shared-actor-roles": {
        "file": "tests/test_bundle_settlement_evidence_bijection_vectors.py",
        "test": "BundleSettlementEvidenceBijectionTests.test_listing_seller_join_allows_one_actor_in_both_bundle_roles",
    },
    "pr333-current-fab-listing-publisher-role-join": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_current_fab_rejects_authenticated_listing_with_wrong_publisher_role",
    },
    "pr333-encrypted-stored-byte-separation": {
        "file": "tests/test_bundle_settlement_evidence_bijection_vectors.py",
        "test": "BundleSettlementEvidenceBijectionTests.test_encrypted_storage_rejects_exact_plaintext_bytes",
    },
    "pr333-current-boolean-archival-delivery-separation": {
        "file": "tests/test_bundle_settlement_evidence_bijection_vectors.py",
        "test": "BundleSettlementEvidenceBijectionTests.test_current_boolean_rejects_legacy_delivery_while_named_archival_passes",
    },
    "pr333-repeated-legacy-vector-discrimination": {
        "file": "tests/test_phase_bound_delivery_vectors.py",
        "test": "PhaseBoundDeliveryVectorTests.test_legacy_repetition_fails_only_after_both_phase_authorities_exist",
    },
    "pr333-current-fab-failed-payment-control": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_current_fab_failed_payment_admission_and_omission",
    },
    "pr333-current-fab-presented-payment-bindings": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_current_fab_presented_payment_members_are_fully_bound",
    },
    "pr333-method-evidence-receipt-tristate": {
        "file": "tests/test_bundle_settlement_evidence_bijection_vectors.py",
        "test": "BundleSettlementEvidenceBijectionTests.test_method_evidence_missing_authority_does_not_become_a_contradiction",
    },
    "pr333-cross-phase-inner-ownership-load-bearing": {
        "file": "tests/test_bundle_settlement_evidence_bijection_vectors.py",
        "test": "BundleSettlementEvidenceBijectionTests.test_cross_phase_inner_dependency_ownership_is_load_bearing",
    },
    "pr333-encrypted-storage-receipt-commitment": {
        "file": "tests/test_phase_bound_delivery_vectors.py",
        "test": "PhaseBoundDeliveryVectorTests.test_storage_delivery_hashes_exact_utf8_in_current_and_legacy_arms",
    },
    "pr333-encrypted-attested-receipt-commitment": {
        "file": "tests/test_phase_bound_delivery_vectors.py",
        "test": "PhaseBoundDeliveryVectorTests.test_attested_payload_storage_closure_uses_authenticated_receipt",
    },
    "pr333-credential-binding-omission-disposition": {
        "file": "tests/test_bundle_settlement_evidence_bijection_vectors.py",
        "test": "BundleSettlementEvidenceBijectionTests.test_missing_credential_binding_is_fail_not_error",
    },
    "pr333-receipt-key-and-listing-identity-totality": {
        "file": "tests/test_bundle_settlement_evidence_bijection_vectors.py",
        "test": "BundleSettlementEvidenceBijectionTests.test_malformed_receipt_key_and_listing_identity_are_total",
    },
    "pr333-fab-delivery-lifecycle-tristate": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_current_fab_delivery_lifecycle_missing_vs_malformed",
    },
    "pr333-indeterminate-inner-receipt-is-nonauthorizing": {
        "file": "tests/test_bundle_settlement_evidence_bijection_vectors.py",
        "test": "BundleSettlementEvidenceBijectionTests.test_indeterminate_inner_receipt_cannot_authorize_delivery",
    },
    "pr333-ordinary-current-agreement-reconciliation": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_ordinary_reconciliation_requires_current_agreement_carrier",
    },
    "pr333-ordinary-current-delivery-reconciliation": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_ordinary_current_delivery_reconciliation_needs_closure_authority",
    },
    "pr333-legacy-delivery-excluded-from-current-use": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "HistoricalEvidenceBindingTests.test_authenticated_historical_fab_delivery_is_not_current_authority",
    },
    "pr333-credential-reuse-outage-order": {
        "file": "tests/test_bundle_settlement_evidence_bijection_vectors.py",
        "test": "BundleSettlementEvidenceBijectionTests.test_authenticated_credential_ref_reuse_survives_unrelated_outage",
    },
    "pr333-method-reuse-outage-order": {
        "file": "tests/test_bundle_settlement_evidence_bijection_vectors.py",
        "test": "BundleSettlementEvidenceBijectionTests.test_authenticated_method_identity_reuse_survives_native_observation_outage",
    },
    "pr333-signed-pointer-real-validator": {
        "file": "tests/test_bundle_settlement_evidence_bijection_vectors.py",
        "test": "BundleSettlementEvidenceBijectionTests.test_signed_phase_pointers_are_checked_by_real_seb_validator",
    },
    "pr333-phase-bound-oracle-totality": {
        "file": "tests/test_phase_bound_delivery_vectors.py",
        "test": "PhaseBoundDeliveryVectorTests.test_malformed_nested_attested_members_are_errors",
    },
    "pr333-payload-oracle-totality": {
        "file": "tests/test_payload_attestation_vectors.py",
        "test": "PayloadAttestationVectorTests.test_malformed_nested_projection_members_are_errors",
    },
    "pr333-identity-only-agreement-not-current-payment": {
        "file": "tests/test_bundle_settlement_evidence_bijection_vectors.py",
        "test": "BundleSettlementEvidenceBijectionTests.test_identity_only_agreement_cannot_authorize_current_payment",
    },
    "pr333-payment-only-fab-agreement-gate": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "ExplicitReconciliationReceiptContractTests.test_payment_only_fab_requires_current_agreement_authority",
    },
    "pr333-payment-only-fab-agreement-gate-controls": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "ExplicitReconciliationReceiptContractTests.test_current_payment_only_fab_agreement_gate_has_positive_and_negative_controls",
    },
    "pr333-malformed-laa-binding-is-error": {
        "file": "tests/test_bundle_settlement_evidence_bijection_vectors.py",
        "test": "BundleSettlementEvidenceBijectionTests.test_malformed_laa_binding_is_error_not_value_mismatch",
    },
    "pr333-released-fab-late-failure-record-inert": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_later_failed_payment_record_cannot_flip_a_released_fab",
    },
    "pr333-released-fab-omission-variants": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_current_fab_failed_payment_omission_variants_keep_released_semantics",
    },
    "pr333-released-fab-omitted-success-residual": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_omitted_success_contradicting_released_fab_is_specified_residual",
    },
    "pr333-released-fab-st8-presented-vs-omitted": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_presented_st8_interim_is_checked_while_omitted_interim_stays_released",
    },
    "pr333-legacy-delivery-current-ineligible-tristate": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_authentic_legacy_delivery_is_current_ineligible_on_every_consumer",
    },
    "pr333-contradictory-legacy-delivery-fails": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_contradictory_legacy_delivery_still_fails_before_ineligibility",
    },
    "pr333-stored-receipt-conflict": {
        "file": "tests/test_bundle_settlement_evidence_bijection_vectors.py",
        "test": "BundleSettlementEvidenceBijectionTests.test_two_stored_receipts_at_one_signed_address_conflict",
    },
    "pr333-finality-bound-seb5-pointer": {
        "file": "tests/test_settlement_finality_verification_vectors.py",
        "test": "SettlementFinalityVerificationVectorTests.test_finality_bound_seb5_pointer_must_equal_its_top_level_member",
    },
    "pr333-attested-reuse-outage-order": {
        "file": "tests/test_bundle_settlement_evidence_bijection_vectors.py",
        "test": "BundleSettlementEvidenceBijectionTests.test_attested_reuse_is_not_masked_by_unrelated_outages",
    },
    "pr333-oracle-reuse-outage-order": {
        "file": "tests/test_phase_bound_delivery_vectors.py",
        "test": "PhaseBoundDeliveryVectorTests.test_oracle_reuse_is_not_masked_by_unrelated_outages",
    },
    "pr333-oracle-ownership-ledger-load-bearing": {
        "file": "tests/test_phase_bound_delivery_vectors.py",
        "test": "PhaseBoundDeliveryVectorTests.test_current_inner_ownership_negatives_are_load_bearing",
    },
    "pr333-released-legacy-era-payment-current-ineligible": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_legacy_era_payments_on_released_copies_are_current_ineligible",
    },
    "pr333-released-st8-successor-edge": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_released_copies_admit_only_authentic_st8_successors",
    },
    "pr333-released-omitted-success-indeterminate": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_omitted_successful_payment_member_is_indeterminate_on_released_copies",
    },
    "pr333-pde7-shared-contradictions": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_pde7_contradictions_fail_on_every_consumer_and_archival_lane",
    },
    "pr333-attestation-bundle-presented-members": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_attestation_bundle_presented_payment_members_are_validated",
    },
    "pr333-reconciliation-label-normalized": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "ExplicitReconciliationReceiptContractTests.test_current_payment_only_fab_agreement_gate_has_positive_and_negative_controls",
    },
    "pr333-older-copy-phase-kind-totality": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_non_string_phase_kind_is_error_not_an_exception",
    },
    "pr333-top-level-indeterminate-observation": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_top_level_indeterminate_observation_is_typed_indeterminate",
    },
    "pr333-delivery-execution-authority-tristate": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_delivery_execution_authority_unavailable_versus_malformed",
    },
    "pr333-pointer-canonicalization-totality": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_pointer_to_non_canonicalizable_bundle_is_error",
    },
    "pr333-divergence-outranks-pending-older-copy": {
        "file": "tests/test_settlement_finality_verification_vectors.py",
        "test": "SettlementFinalityVerificationVectorTests.test_reconciliation_executes_conflict_absence_and_indeterminate_paths",
    },
    "pr333-current-use-unlisted-records-inert": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_unlisted_payment_records_are_inert_for_current_use",
    },
    "pr333-ab-without-current-delivery-indeterminate": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_attestation_bundle_without_current_delivery_evidence_is_indeterminate",
    },
    "pr333-released-st8-interim-four-state": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_released_st8_interim_authority_is_four_state_typed",
    },
    "pr333-ebfab-listing-totality": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_ebfab_malformed_listing_is_typed_error_not_an_exception",
    },
    "pr333-released-gate-order-independence": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_released_gate_verdict_is_independent_of_member_order",
    },
    "pr333-lifecycle-outage-keeps-reuse-detection": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_lifecycle_outage_does_not_mask_payment_invocation_reuse",
    },
    "pr333-member-error-outranks-cross-member-conflict": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_member_error_outranks_a_cross_member_conflict_in_any_order",
    },
    "pr333-conflict-reason-order-independence": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_conflicting_member_reason_is_independent_of_member_order",
    },
    "pr333-st8-contradiction-bound-to-orchestrator-receipt": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_st8_contradiction_requires_the_orchestrators_bound_receipt",
    },
    "pr333-incomplete-delivery-set-not-masked": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_unrelated_outage_does_not_mask_an_incomplete_delivery_set",
    },
    "pr333-unfillable-member-does-not-mask-delivery-gap": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_member_that_cannot_fill_a_missing_invocation_does_not_mask_it",
    },
    "pr333-authority-excluded-member-does-not-mask-delivery-gap": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_member_excluded_by_execution_authority_does_not_mask_a_gap",
    },
    "pr333-legacy-address-excluded-member-does-not-mask-delivery-gap": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_legacy_member_excluded_by_execution_address_does_not_mask_a_gap",
    },
    "pr333-delivery-reuse-without-optional-pointer": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_delivery_reuse_is_detected_without_the_optional_pointer",
    },
    "pr333-finality-pointer-typed-disposition": {
        "file": "tests/test_settlement_finality_verification_vectors.py",
        "test": "SettlementFinalityVerificationVectorTests.test_finality_bound_joins_laa_and_fv_agreements",
    },
    "pr333-finality-reconcile-listing-totality": {
        "file": "tests/test_settlement_finality_verification_vectors.py",
        "test": "SettlementFinalityVerificationVectorTests.test_malformed_strong_listing_is_typed_error_in_reconciliation",
    },
    "pr333-seb6-receipt-observation-pending": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "SebSixPendingPrecedenceTests.test_receipt_observation_is_pending_until_independent_checks_run",
    },
    "pr333-seb6-laa-unavailable-pending": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "SebSixPendingPrecedenceTests.test_unavailable_laa_authority_is_pending",
    },
    "pr333-seb6-delivery-execution-unavailable-pending": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "SebSixPendingPrecedenceTests.test_unavailable_delivery_execution_authority_is_pending",
    },
    "pr333-seb6-unplaced-member-fills-only-missing-invocation": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "SebSixPendingPrecedenceTests.test_unplaced_member_can_fill_only_a_missing_invocation",
    },
    "pr333-finality-bound-pending-precedence": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "FinalityBoundPendingPrecedenceTests.test_pending_authority_never_masks_a_lifecycle_rejection",
    },
    "pr333-released-trace-optional-fields": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_released_traces_admit_omitted_optional_fields",
    },
    "pr333-released-trace-present-contradiction": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_released_traces_still_reject_present_contradictions",
    },
    "pr333-released-trace-incomplete-pending": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_incomplete_released_trace_is_pending_not_a_verdict",
    },
    "pr333-dependency-receipt-precedence": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "DependencyReceiptPrecedenceTests.test_public_entry_receipt_classes_survive_missing_resolvability",
    },
    "pr333-self-signed-contradiction-fail": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "SelfSignedMethodDispositionTests.test_public_entry_classifies_authenticated_contradictions_as_fail",
    },
    "pr333-unselected-candidate-inert": {
        "file": "tests/test_unselected_candidate_inertness.py",
        "test": "CurrentUseUnselectedCandidateTests.test_unselected_invalid_fault_party_is_inert",
    },
    "pr333-job-bound-unselected-inert": {
        "file": "tests/test_unselected_candidate_inertness.py",
        "test": "DeriveJobBoundUnselectedCandidateTests.test_unselected_candidates_are_inert",
    },
    "pr333-ebfab-agreement-ref-join": {
        "file": "tests/test_bundle_settlement_evidence_bijection_vectors.py",
        "test": "BundleSettlementEvidenceBijectionTests.test_present_agreement_ref_joins_every_laa_qualified_payment",
    },
    "pr333-released-agreement-ref-join": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_released_copies_join_present_agreement_ref_to_laa_agreement",
    },
    "pr333-ebfab-pointer-agreement-ref-join": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_ebfab_pointer_joins_present_agreement_ref_to_laa_agreement",
    },
    "pr333-finality-bound-agreement-ref-join": {
        "file": "tests/test_settlement_finality_verification_vectors.py",
        "test": "SettlementFinalityVerificationVectorTests.test_finality_bound_joins_present_agreement_ref_to_laa",
    },
    "pr333-laa2-identity-only-payment-refused": {
        "file": "tests/test_identity_bundle_hash_binding_vectors.py",
        "test": "IdentityBundleHashBindingVectorTests.test_retained_admission_is_exact_and_reused_without_readmission",
    },
    "pr333-laa2-sealed-losing-bidder-payment-refused": {
        "file": "tests/test_identity_bundle_hash_binding_vectors.py",
        "test": "IdentityBundleHashBindingVectorTests.test_sealed_envelope_losing_bidder_compatibility",
    },
    "pr333-seb6-unplaced-payment-own-contradictions": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "SebSixSameMemberPrecedenceTests.test_unplaced_payment_keeps_its_own_contradictions",
    },
    "pr333-seb6-unavailable-execution-binds-receipt": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "SebSixSameMemberPrecedenceTests.test_unavailable_execution_still_binds_the_present_receipt",
    },
    "pr333-seb5-missing-invocation-pointers": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "SebSixSameMemberPrecedenceTests.test_pointers_for_missing_invocations_name_distinct_fitting_members",
    },
    "pr333-seb4-receipt-named-invocation-injective": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "SebSixSameMemberPrecedenceTests.test_receipt_named_invocation_is_injective",
    },
    "pr333-seb6-no-single-outage-downgrade-sweep": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "SebSixSameMemberPrecedenceTests.test_no_single_outage_downgrades_a_shipped_rejection",
    },
    "pr333-agreement-join-error-precedence": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "LaaAgreementJoinPrecedenceTests.test_join_mismatch_never_outranks_malformed_authority",
    },
    "pr333-finality-fv-error-outranks-join-fail": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "LaaAgreementJoinPrecedenceTests.test_finality_verification_error_outranks_a_join_fail",
    },
    "pr333-st8-successor-scan-nonce-pin": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "AdmittingEntryBoundaryTests.test_successor_scan_respects_the_unavailable_nonce_pin",
    },
    "pr333-st8-successor-scan-archival-integer-nonce": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "AdmittingEntryBoundaryTests.test_archival_successor_scan_pins_integer_nonces",
    },
    "pr333-transition-payment-signed-invocation": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "AdmittingEntryBoundaryTests.test_receiptless_transition_payment_fills_only_its_signed_invocation",
    },
    "pr333-finality-verification-skips-rejected-records": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "FinalityBoundPendingPrecedenceTests.test_verification_skips_records_the_core_rejected",
    },
    "pr333-pending-receipt-laa-precedence": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "PendingReceiptPaymentPrecedenceTests.test_receipt_independent_laa_checks_outrank_a_pending_receipt",
    },
    "pr333-pending-receipt-defers-only-receipt-fields": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "PendingReceiptPaymentPrecedenceTests.test_only_receipt_bound_carrier_fields_are_deferred",
    },
    "pr333-receiptless-payment-sb1-exclusion": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "PendingReceiptPaymentPrecedenceTests.test_available_execution_authority_excludes_receiptless_candidates",
    },
    "pr333-finality-bound-pending-receipt-precedence": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "PendingReceiptPaymentPrecedenceTests.test_finality_bound_core_keeps_the_same_precedence",
    },
    "pr333-released-pending-payment-receipt": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_released_pending_payment_receipt_keeps_its_own_contradictions",
    },
    "pr333-released-payment-receipt-state-independence": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_released_payment_verdict_is_independent_of_receipt_state",
    },
    "pr333-receiptless-candidate-rail-and-nonce": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "PendingReceiptPaymentPrecedenceTests.test_receiptless_candidate_needs_the_bindable_rail_and_nonce",
    },
    "pr333-laa-pending-mode-is-explicit": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "PendingReceiptPaymentPrecedenceTests.test_laa_never_infers_pending_mode_from_a_missing_receipt",
    },
    "pr333-released-payment-checks-outrank-other-outages": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_released_payment_checks_outrank_other_outages",
    },
    "pr333-released-settlement-closed-shape-before-phase-dispatch": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_authenticated_settlement_members_require_closed_shape_before_phase_dispatch",
    },
    "pr333-released-finality-closed-shape-before-phase-dispatch": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_authenticated_finality_members_require_closed_shape_before_phase_dispatch",
    },
    "pr333-f1-current-member-authority-dispositions": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "SebMemberAuthorityDispositionTests.test_payment_and_delivery_authority_matrix_across_all_consumers",
    },
    "pr333-f1-current-receipt-shape-table": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "SebMemberAuthorityDispositionTests.test_current_receipt_shape_table_is_typed_for_payment_and_delivery",
    },
    "pr333-f1-current-receipt-binding-mismatch": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "SebMemberAuthorityDispositionTests.test_well_typed_receipt_binding_mismatches_remain_fail",
    },
    "pr333-f1-current-receipt-state-and-archival-controls": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "SebMemberAuthorityDispositionTests.test_valid_nonqualifying_state_is_fail_and_archival_receipts_stay_frozen",
    },
    "pr333-f1-current-root-map-authority-dispositions": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "SebMemberAuthorityDispositionTests.test_current_root_maps_distinguish_unavailable_from_malformed",
    },
    "pr333-f1-member-order-precedence": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "SebMemberAuthorityDispositionTests.test_member_order_cannot_downgrade_error_or_hide_delivery_rejection",
    },
    "pr333-f1-frozen-historical-authority-semantics": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "SebMemberAuthorityDispositionTests.test_frozen_historical_authority_outcomes_keep_their_exact_reasons",
    },
    "pr333-f1-finality-bound-member-authority-dispositions": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "FinalityBoundPendingPrecedenceTests.test_finality_bound_member_authority_matrix_is_typed",
    },
    "pr333-f2-unit-dependency-receipt-precedence": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "DependencyReceiptPrecedenceTests.test_missing_or_unavailable_entry_defers_only_availability",
    },
    "pr333-f2-ebfab-dependency-receipt-precedence": {
        "file": "tests/test_pr333_disposition_precedence_regressions.py",
        "test": "DependencyReceiptPrecedenceTests.test_public_ebfab_defers_only_missing_dependency_entries",
    },
    "pr333-f2-six-dependency-signed-matrix": {
        "file": "tests/test_phase_bound_delivery_vectors.py",
        "test": "PhaseBoundDeliveryVectorTests.test_dependency_receipt_precedence_matrix_covers_all_six_dependencies",
    },
    "pr333-f2-six-dependency-primary-closure": {
        "file": "tests/test_phase_bound_delivery_vectors.py",
        "test": "PhaseBoundDeliveryVectorTests.test_primary_closure_keeps_receipt_precedence_for_all_six_dependencies",
    },
    "pr333-f2-released-fab-ab-receipt-precedence": {
        "file": "tests/test_current_evidence_boundary_regressions.py",
        "test": "CurrentFabDeliveryAdmissionTests.test_released_fab_and_ab_keep_dependency_receipt_precedence",
    },
    "pr366-authenticated-absent-presenter-outcome": {
        "file": "tests/test_dacs1_vet_golden_inputs.py",
        "test": "Dacs1VetGoldenInputTests.test_presented_by_must_resolve_to_a_signed_bundle_claim",
    },
    "pr366-absent-presenter-current-historical-aggregate": {
        "file": "tests/test_dacs1_vet_golden_inputs.py",
        "test": "Dacs1VetGoldenInputTests.test_authenticated_absent_presenter_is_fail_in_current_and_historical_aggregate",
    },
    "pr366-absent-presenter-vector-consumer": {
        "file": "tests/test_presence_only_claim_vectors.py",
        "test": "PresenceOnlyClaimVectorTests.test_presented_claim_uniqueness_is_order_independent",
    },
    "pr366-absent-presenter-structural-gate-witness": {
        "file": "tests/test_review_guard_witnesses.py",
        "test": "ReviewGuardWitnessTests.test_absent_presenter_semantic_boundary_is_load_bearing",
    },
    "pr366-presence-current-selector-expiry": {
        "file": "tests/test_presence_only_claim_vectors.py",
        "test": "PresenceOnlyClaimVectorTests.test_selector_current_time_preserves_only_the_historical_presence_arm",
    },
    "pr366-presence-current-selector-guard-witness": {
        "file": "tests/test_review_guard_witnesses.py",
        "test": "ReviewGuardWitnessTests.test_presence_pack_current_selector_requalification_is_load_bearing",
    },
    "pr366-presence-outsider-signature-membership": {
        "file": "tests/test_presence_only_claim_vectors.py",
        "test": "PresenceOnlyClaimVectorTests.test_authentic_outsider_signature_is_a_structural_error",
    },
    "pr366-presence-signer-membership-guard-witness": {
        "file": "tests/test_review_guard_witnesses.py",
        "test": "ReviewGuardWitnessTests.test_presence_pack_signer_membership_is_load_bearing",
    },
    "pr366-presence-challenge-issue-time": {
        "file": "tests/test_presence_only_claim_vectors.py",
        "test": "PresenceOnlyClaimVectorTests.test_active_acceptance_requires_record_after_verifier_challenge_issue",
    },
    "pr366-presence-challenge-issue-time-guard-witness": {
        "file": "tests/test_review_guard_witnesses.py",
        "test": "ReviewGuardWitnessTests.test_presence_pack_challenge_issue_time_is_load_bearing",
    },
    "pr366-main-vet-mixed-signer-membership": {
        "file": "tests/test_dacs1_vet_golden_inputs.py",
        "test": "Dacs1VetGoldenInputTests.test_authentic_member_and_outsider_signatures_reject_direct_and_external",
    },
    "pr366-main-vet-mixed-signer-guard-witness": {
        "file": "tests/test_review_guard_witnesses.py",
        "test": "ReviewGuardWitnessTests.test_main_vet_all_signers_claim_membership_is_load_bearing",
    },
    "pr366-presence-signed-nonce-consumption": {
        "file": "tests/test_presence_only_claim_vectors.py",
        "test": "PresenceOnlyClaimVectorTests.test_presentation_nonce_consumption_ignores_caller_projection",
    },
    "pr366-presence-signed-nonce-consumption-guard-witness": {
        "file": "tests/test_review_guard_witnesses.py",
        "test": "ReviewGuardWitnessTests.test_presence_pack_signed_nonce_consumption_is_load_bearing",
    },
    "pr366-missing-bundle-nonauthorizing-diagnostic": {
        "file": "tests/test_presence_only_claim_vectors.py",
        "test": "PresenceOnlyClaimVectorTests.test_missing_bundle_diagnostic_never_admits_active_use",
    },
    "pr366-missing-bundle-active-admission-guard-witness": {
        "file": "tests/test_review_guard_witnesses.py",
        "test": "ReviewGuardWitnessTests.test_missing_bundle_diagnostic_is_not_active_admission",
    },
}

EXACT_UNITTEST_COMPLETION_MARKER = "DACS-EXACT-UNITTEST-COMPLETE"
# Registered tests normally finish in seconds. Two minutes leaves substantial
# room for a slow CI worker while keeping one stalled target from hanging the
# complete gate indefinitely.
SELECTED_TEST_TIMEOUT_SECONDS = 120
SELECTED_TEST_CLEANUP_TIMEOUT_SECONDS = 5
EXACT_UNITTEST_SUMMARY = {
    "errors": 0,
    "expectedFailures": 0,
    "failures": 0,
    "skipped": 0,
    "testsRun": 1,
    "unexpectedSuccesses": 0,
}

# The runner reads a per-run nonce from stdin before the pinned test file is
# loaded, and only after the selected test has run to completion does it emit
# a completion record carrying that nonce.  An exit status of 0 alone (for
# example SystemExit(0) at import or in setUpClass, or os._exit(0)) is never
# accepted as evidence.
EXACT_UNITTEST_RUNNER = """\
import importlib.util
import json
import os
import sys
import unittest


def _run():
    nonce = sys.stdin.readline().strip()
    sys.stdin.close()
    if len(nonce) != 64:
        raise SystemExit("missing completion nonce")
    record_fd = os.dup(1)
    spec = importlib.util.spec_from_file_location("_dacs_exact_review_test", sys.argv[1])
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load code-pinned test file")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromName(sys.argv[2], module)
    result = unittest.TestResult()
    suite.run(result)
    summary = {
        "testsRun": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "expectedFailures": len(result.expectedFailures),
        "unexpectedSuccesses": len(result.unexpectedSuccesses),
    }
    accepted = (
        result.testsRun == 1
        and result.wasSuccessful()
        and not result.failures
        and not result.errors
        and not result.skipped
        and not result.expectedFailures
        and not result.unexpectedSuccesses
    )
    if not accepted:
        print(
            "exact unittest contract failed: " + json.dumps(summary, sort_keys=True),
            file=sys.stderr,
        )
        raise SystemExit(1)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:
            pass
    record = "\\n%s %s %s\\n" % (
        sys.argv[3], nonce, json.dumps(summary, sort_keys=True)
    )
    os.write(record_fd, record.encode("ascii"))


_run()
"""

REQUIRED_REVIEW_LENSES = {
    "hostile-json-type-totality": {
        "counterexampleEvidence": frozenset({
            "type-totality-array-ebfab-counterexample",
            "type-totality-array-disposition-counterexample",
            "type-totality-object-counterexample",
            "type-totality-null-counterexample",
            "type-totality-boolean-counterexample",
            "type-totality-number-counterexample",
            "type-totality-unsupported-string-counterexample",
            "credential-ref-type-counterexample",
        }),
        "controlEvidence": frozenset({
            "type-totality-control", "credential-ref-positive-control",
        }),
        "requiredSurfaces": {
            "counterexampleEvidence": {"public-api"},
            "controlEvidence": {"public-api"},
        },
    },
    "binding-axis-isolation-current-fab-delivery": {
        "counterexampleEvidence": frozenset({"delivery-binding-counterexample"}),
        "controlEvidence": frozenset({"delivery-binding-control"}),
        "requiredSurfaces": {
            "counterexampleEvidence": {"composed-caller"},
            "controlEvidence": {"composed-caller"},
        },
    },
    "current-archival-downgrade-fallback": {
        "counterexampleEvidence": frozenset({"era-downgrade-counterexample"}),
        "controlEvidence": frozenset({"era-downgrade-control"}),
        "requiredSurfaces": {
            "counterexampleEvidence": {"composed-caller"},
            "controlEvidence": {"composed-caller"},
        },
    },
    "direct-helper-composed-path-parity": {
        "counterexampleEvidence": frozenset({
            "helper-composition-counterexample",
            "historical-helper-binding-counterexample",
        }),
        "controlEvidence": frozenset({
            "helper-composition-control",
            "historical-helper-binding-control",
        }),
        "requiredSurfaces": {
            "counterexampleEvidence": {"direct-helper", "composed-caller"},
            "controlEvidence": {"direct-helper", "composed-caller"},
        },
    },
    "compatibility-legitimate-positive-preservation": {
        "counterexampleEvidence": frozenset({"compatibility-counterexample"}),
        "controlEvidence": frozenset({"compatibility-control"}),
        "requiredSurfaces": {
            "counterexampleEvidence": {"compatibility-path"},
            "controlEvidence": {"compatibility-path"},
        },
    },
}
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class GateError(ValueError):
    pass


def _unittest_module(relative: str, test: str, label: str) -> str:
    """Validate a manifest unittest target and return its importable module."""
    path = PurePosixPath(relative)
    module_parts = (*path.parts[:-1], path.stem)
    if (
        path.is_absolute()
        or len(path.parts) < 2
        or path.parts[0] != "tests"
        or path.suffix != ".py"
        or not path.name.startswith("test_")
        or not all(part.isidentifier() for part in module_parts)
    ):
        raise GateError(
            f"{label}: file must name an importable test_*.py module under tests/"
        )
    test_parts = test.split(".")
    if len(test_parts) < 2 or not all(part.isidentifier() for part in test_parts):
        raise GateError(
            f"{label}: test must be a safe dotted unittest identity"
        )
    if not test_parts[-1].startswith("test_"):
        raise GateError(f"{label}: final unittest identity must start with test_")
    return ".".join(module_parts)


def load_manifest(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError(f"cannot load {path}: {exc}") from exc
    validate_manifest(value)
    return value


def validate_manifest(manifest: object) -> None:
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1:
        raise GateError("manifest must be a schemaVersion 1 object")
    matrices = manifest.get("vectorMatrices")
    regressions = manifest.get("unitRegressions")
    corpus_pins = manifest.get("corpusPins")
    covered = manifest.get("coveredInvariantClasses")
    planned = manifest.get("plannedInvariantClasses")
    review_evidence = manifest.get("independentReviewEvidence")
    review_lenses = manifest.get("independentReviewLenses")
    if not isinstance(matrices, list) or not matrices:
        raise GateError("vectorMatrices must be a nonempty list")
    if not isinstance(regressions, list) or not regressions:
        raise GateError("unitRegressions must be a nonempty list")
    if not isinstance(corpus_pins, dict) or not corpus_pins:
        raise GateError("corpusPins must be a nonempty object")
    if not isinstance(covered, list):
        raise GateError("coveredInvariantClasses must be a list")
    if not isinstance(planned, list):
        raise GateError("plannedInvariantClasses must be a list")
    if not isinstance(review_evidence, list) or not review_evidence:
        raise GateError("independentReviewEvidence must be a nonempty list")
    if not isinstance(review_lenses, list) or not review_lenses:
        raise GateError("independentReviewLenses must be a nonempty list")

    for corpus_name, pin in corpus_pins.items():
        if (
            not isinstance(corpus_name, str) or not corpus_name
            or not isinstance(pin, dict)
            or set(pin) != {"spec", "authoritativeProfile"}
            or not isinstance(pin.get("spec"), str)
            or not isinstance(pin.get("authoritativeProfile"), dict)
        ):
            raise GateError("corpusPins entries require spec and authoritativeProfile")

    ids: set[str] = set()
    matrix_classes: dict[str, set[str]] = {}
    for matrix in matrices:
        if not isinstance(matrix, dict) or not isinstance(matrix.get("id"), str):
            raise GateError("every vector matrix needs a string id")
        if matrix["id"] in ids:
            raise GateError(f"duplicate invariant id: {matrix['id']}")
        ids.add(matrix["id"])
        invariant_classes = matrix.get("invariantClasses")
        if (
            not isinstance(invariant_classes, list)
            or not invariant_classes
            or not all(isinstance(item, str) and item for item in invariant_classes)
            or len(set(invariant_classes)) != len(invariant_classes)
        ):
            raise GateError(f"{matrix['id']}: invariantClasses must be unique strings")
        matrix_classes[matrix["id"]] = set(invariant_classes)
        corpus_name = matrix.get("corpus")
        if corpus_name not in corpus_pins:
            raise GateError(f"{matrix['id']}: corpus has no exact revision/profile pin")
        dimensions = matrix.get("dimensions")
        cases = matrix.get("cases")
        if not isinstance(dimensions, dict) or not dimensions:
            raise GateError(f"{matrix['id']}: dimensions must be nonempty")
        if not isinstance(cases, list):
            raise GateError(f"{matrix['id']}: cases must be a list")
        dimension_names = list(dimensions)
        values = []
        for name in dimension_names:
            domain = dimensions[name]
            if not isinstance(domain, list) or not domain or len(set(domain)) != len(domain):
                raise GateError(f"{matrix['id']}: invalid dimension {name}")
            values.append(domain)
        required = {tuple(zip(dimension_names, product)) for product in itertools.product(*values)}
        actual = set()
        case_ids = set()
        for case in cases:
            if not isinstance(case, dict) or not isinstance(case.get("caseId"), str):
                raise GateError(f"{matrix['id']}: case missing caseId")
            case_id = case["caseId"]
            if case_id in case_ids:
                raise GateError(f"{matrix['id']}: duplicate caseId {case_id}")
            case_ids.add(case_id)
            coordinates = case.get("coordinates")
            if not isinstance(coordinates, dict) or set(coordinates) != set(dimension_names):
                raise GateError(f"{matrix['id']}/{case_id}: coordinates do not match dimensions")
            coordinate = tuple((name, coordinates[name]) for name in dimension_names)
            if coordinate not in required:
                raise GateError(f"{matrix['id']}/{case_id}: coordinate is outside the matrix")
            if coordinate in actual:
                raise GateError(f"{matrix['id']}: duplicate coordinate {dict(coordinate)}")
            actual.add(coordinate)
            for expectation_name in ("expected", "controlExpected"):
                expected = case.get(expectation_name)
                if not isinstance(expected, dict) or set(expected) != {
                    "verdict", "revocationCheck", "session",
                }:
                    raise GateError(
                        f"{matrix['id']}/{case_id}: incomplete {expectation_name} result"
                    )
            if not isinstance(case.get("controlCase"), str):
                raise GateError(f"{matrix['id']}/{case_id}: missing discriminating controlCase")
        if actual != required:
            missing = [dict(item) for item in sorted(required - actual)]
            raise GateError(f"{matrix['id']}: incomplete matrix; missing {missing}")

    for regression in regressions:
        if (
            not isinstance(regression, dict)
            or set(regression) != {"id", "file", "test"}
            or not all(isinstance(regression[key], str) for key in regression)
        ):
            raise GateError("unit regression entries require string id/file/test")
        if regression["id"] in ids:
            raise GateError(f"duplicate invariant id: {regression['id']}")
        ids.add(regression["id"])
        _unittest_module(
            regression["file"], regression["test"], regression["id"]
        )
        _within_test_root(regression["file"])
        observed = {"file": regression["file"], "test": regression["test"]}
        if PINNED_UNIT_REGRESSIONS.get(regression["id"]) != observed:
            raise GateError(
                f"{regression['id']}: regression does not match its "
                "code-pinned declaration"
            )

    regression_ids = {regression["id"] for regression in regressions}
    missing_regressions = PINNED_UNIT_REGRESSIONS.keys() - regression_ids
    extra_regressions = regression_ids - PINNED_UNIT_REGRESSIONS.keys()
    if missing_regressions or extra_regressions:
        raise GateError(
            "unit regressions do not match the code-pinned registry: "
            f"missing={sorted(missing_regressions)}, extra={sorted(extra_regressions)}"
        )

    covered_ids: set[str] = set()
    for item in covered:
        if not isinstance(item, dict) or set(item) != {"id", "matrixIds"}:
            raise GateError("covered invariant classes require id and matrixIds")
        class_id = item.get("id")
        evidence = item.get("matrixIds")
        if (
            not isinstance(class_id, str) or not class_id
            or class_id in covered_ids
            or not isinstance(evidence, list) or not evidence
            or not all(isinstance(matrix_id, str) for matrix_id in evidence)
            or len(set(evidence)) != len(evidence)
        ):
            raise GateError("covered invariant classes require a unique id and matrix evidence")
        covered_ids.add(class_id)
        for matrix_id in evidence:
            if matrix_id not in matrix_classes:
                raise GateError(f"{class_id}: coverage references missing matrix {matrix_id}")
            if class_id not in matrix_classes[matrix_id]:
                raise GateError(
                    f"{class_id}: matrix {matrix_id} does not declare this invariant class"
                )

    planned_ids: set[str] = set()
    for item in planned:
        if (
            not isinstance(item, dict)
            or set(item) != {"id", "status"}
            or not isinstance(item.get("id"), str)
            or not item["id"]
            or item.get("status") != "planned"
        ):
            raise GateError("planned invariant classes must be explicitly status=planned")
        if item["id"] in planned_ids:
            raise GateError(f"duplicate planned invariant class: {item['id']}")
        planned_ids.add(item["id"])
        if item["id"] in covered_ids:
            raise GateError(f"invariant class cannot be both covered and planned: {item['id']}")

    declared_matrix_classes = set().union(*matrix_classes.values())
    unclaimed_matrix_classes = declared_matrix_classes - covered_ids
    if unclaimed_matrix_classes:
        raise GateError(
            "matrix invariant classes must be claimed as covered: "
            f"{sorted(unclaimed_matrix_classes)}"
        )

    evidence_by_id: dict[str, dict] = {}
    evidence_targets: set[tuple[str, str]] = set()
    for evidence in review_evidence:
        if not isinstance(evidence, dict) or set(evidence) != {
            "id", "file", "test", "surfaces",
        }:
            raise GateError(
                "independent review evidence requires id/file/test/surfaces"
            )
        evidence_id = evidence.get("id")
        file_name = evidence.get("file")
        test_name = evidence.get("test")
        surfaces = evidence.get("surfaces")
        if (
            not isinstance(evidence_id, str) or not evidence_id
            or evidence_id in evidence_by_id
            or not isinstance(file_name, str) or not file_name
            or not isinstance(test_name, str) or not test_name
            or not isinstance(surfaces, list) or not surfaces
            or not all(isinstance(surface, str) for surface in surfaces)
            or len(set(surfaces)) != len(surfaces)
            or not set(surfaces).issubset(EVIDENCE_SURFACES)
        ):
            raise GateError("independent review evidence must be unique and runnable")
        _unittest_module(file_name, test_name, evidence_id)
        _within_test_root(file_name)
        pinned = PINNED_REVIEW_EVIDENCE.get(evidence_id)
        observed = {
            "file": file_name,
            "test": test_name,
            "surfaces": frozenset(surfaces),
        }
        if pinned != observed:
            raise GateError(
                f"{evidence_id}: evidence does not match its code-pinned declaration"
            )
        target = (file_name, test_name)
        if target in evidence_targets:
            raise GateError(f"duplicate independent review evidence target: {target}")
        evidence_targets.add(target)
        evidence_by_id[evidence_id] = evidence

    missing_evidence = PINNED_REVIEW_EVIDENCE.keys() - evidence_by_id.keys()
    extra_evidence = evidence_by_id.keys() - PINNED_REVIEW_EVIDENCE.keys()
    if missing_evidence or extra_evidence:
        raise GateError(
            "independent review evidence does not match the code-pinned registry: "
            f"missing={sorted(missing_evidence)}, extra={sorted(extra_evidence)}"
        )

    lenses_by_id: dict[str, dict] = {}
    evidence_owners: dict[str, tuple[str, str]] = {}
    for lens in review_lenses:
        if not isinstance(lens, dict) or set(lens) != {
            "id", "counterexampleEvidence", "controlEvidence",
        }:
            raise GateError(
                "independent review lenses require id/counterexampleEvidence/controlEvidence"
            )
        lens_id = lens.get("id")
        if not isinstance(lens_id, str) or not lens_id or lens_id in lenses_by_id:
            raise GateError("independent review lens ids must be unique strings")
        lenses_by_id[lens_id] = lens
        role_sets = []
        for role in ("counterexampleEvidence", "controlEvidence"):
            evidence_ids = lens.get(role)
            if (
                not isinstance(evidence_ids, list) or not evidence_ids
                or not all(isinstance(item, str) and item for item in evidence_ids)
                or len(set(evidence_ids)) != len(evidence_ids)
            ):
                raise GateError(f"{lens_id}: {role} must contain unique evidence ids")
            missing = set(evidence_ids) - evidence_by_id.keys()
            if missing:
                raise GateError(
                    f"{lens_id}: dangling independent review evidence {sorted(missing)}"
                )
            role_sets.append(set(evidence_ids))
            for evidence_id in evidence_ids:
                if evidence_id in evidence_owners:
                    owner = evidence_owners[evidence_id]
                    raise GateError(
                        f"{evidence_id}: evidence belongs to both "
                        f"{owner[0]}/{owner[1]} and {lens_id}/{role}"
                    )
                evidence_owners[evidence_id] = (lens_id, role)
        if role_sets[0] & role_sets[1]:
            raise GateError(
                f"{lens_id}: counterexample and control evidence must be distinct"
            )

    missing_lenses = set(REQUIRED_REVIEW_LENSES) - lenses_by_id.keys()
    extra_lenses = lenses_by_id.keys() - set(REQUIRED_REVIEW_LENSES)
    if missing_lenses or extra_lenses:
        raise GateError(
            "independent review lenses do not match the required set: "
            f"missing={sorted(missing_lenses)}, extra={sorted(extra_lenses)}"
        )
    orphaned_evidence = evidence_by_id.keys() - evidence_owners.keys()
    if orphaned_evidence:
        raise GateError(
            f"unclaimed independent review evidence: {sorted(orphaned_evidence)}"
        )
    for lens_id, contract in REQUIRED_REVIEW_LENSES.items():
        lens = lenses_by_id[lens_id]
        for role in ("counterexampleEvidence", "controlEvidence"):
            observed_ids = set(lens[role])
            if observed_ids != contract[role]:
                raise GateError(
                    f"{lens_id}/{role}: evidence set does not match "
                    "the code-pinned registry contract"
                )
            observed_surfaces = set()
            for evidence_id in lens[role]:
                observed_surfaces.update(evidence_by_id[evidence_id]["surfaces"])
            missing_surfaces = (
                contract["requiredSurfaces"][role] - observed_surfaces
            )
            if missing_surfaces:
                raise GateError(
                    f"{lens_id}/{role}: missing required evidence surfaces "
                    f"{sorted(missing_surfaces)}"
                )


def _within_root(relative: str) -> Path:
    path = (ROOT / relative).resolve()
    if ROOT != path and ROOT not in path.parents:
        raise GateError(f"path escapes repository: {relative}")
    if not path.is_file():
        raise GateError(f"required file disappeared: {relative}")
    return path


def _within_test_root(relative: str) -> Path:
    path = _within_root(relative)
    test_root = (ROOT / "tests").resolve()
    if test_root not in path.parents:
        raise GateError(f"unittest file escapes tests/: {relative}")
    return path


def _load_evaluator(relative: str):
    path = _within_root(relative)
    module_name = "_dacs_pre_review_evaluator"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise GateError(f"cannot load evaluator: {relative}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(getattr(module, "evaluate", None)):
        raise GateError(f"evaluator has no callable evaluate(): {relative}")
    return module


def _complete_outcome(result: object, label: str) -> dict:
    if not isinstance(result, tuple) or len(result) != 2 or not isinstance(result[1], dict):
        raise GateError(f"{label}: evaluator returned a malformed outcome")
    verdict, effects = result
    if "verdict" in effects:
        raise GateError(f"{label}: consumer effects must not redefine verdict")
    return {"verdict": verdict, **effects}


def _corpus_outcome(vector: dict, label: str) -> dict:
    effects = vector.get("want")
    if not isinstance(effects, dict) or "verdict" in effects:
        raise GateError(f"{label}: corpus has a malformed expected outcome")
    return {"verdict": vector.get("expected"), **effects}


def _index_vectors(corpus: dict, label: str) -> dict[str, dict]:
    vectors: dict[str, dict] = {}
    for item in corpus.get("vectors", []):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        name = item["name"]
        if name in vectors:
            raise GateError(f"{label}: duplicate corpus vector name: {name}")
        vectors[name] = item
    return vectors


def run_vector_matrices(manifest: dict) -> int:
    executed = 0
    loaded = {}
    for matrix in manifest["vectorMatrices"]:
        corpus_path = _within_root(matrix["corpus"])
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        pin = manifest["corpusPins"][matrix["corpus"]]
        observed_pin = {
            "spec": corpus.get("spec"),
            "authoritativeProfile": corpus.get("authoritativeProfile"),
        }
        if observed_pin != pin:
            raise GateError(
                f"{matrix['id']}: corpus revision/profile pin drifted: "
                f"expected {pin}, got {observed_pin}"
            )
        vectors = _index_vectors(corpus, matrix["id"])
        if matrix["evaluator"] not in loaded:
            loaded[matrix["evaluator"]] = _load_evaluator(matrix["evaluator"])
        evaluator = loaded[matrix["evaluator"]]
        for case in matrix["cases"]:
            case_id = case["caseId"]
            if case_id not in vectors:
                raise GateError(f"{matrix['id']}: required case disappeared: {case_id}")
            control_id = case["controlCase"]
            if control_id not in vectors:
                raise GateError(f"{matrix['id']}: control case disappeared: {control_id}")
            vector = vectors[case_id]
            control = vectors[control_id]
            result = evaluator.evaluate(
                vector.get("input"), corpus.get("publicKeys"),
                vector.get("trustedProfileAdmission"),
            )
            observed = _complete_outcome(result, f"{matrix['id']}/{case_id}")
            if observed != case["expected"]:
                raise GateError(f"{matrix['id']}/{case_id}: expected {case['expected']}, got {observed}")
            if case["expected"] != _corpus_outcome(vector, f"{matrix['id']}/{case_id}"):
                raise GateError(f"{matrix['id']}/{case_id}: registry and corpus expectations diverge")
            control_result = evaluator.evaluate(
                control.get("input"), corpus.get("publicKeys"),
                control.get("trustedProfileAdmission"),
            )
            control_label = f"{matrix['id']}/{case_id} control {control_id}"
            control_observed = _complete_outcome(control_result, control_label)
            if control_observed != case["controlExpected"]:
                raise GateError(
                    f"{control_label}: expected {case['controlExpected']}, got {control_observed}"
                )
            if case["controlExpected"] != _corpus_outcome(control, control_label):
                raise GateError(f"{control_label}: registry and corpus expectations diverge")
            if observed == control_observed:
                raise GateError(
                    f"{matrix['id']}/{case_id}: no longer discriminates from control {control_id}"
                )
            executed += 1
    return executed


def run_unit_regressions(manifest: dict) -> int:
    return _run_python_evidence(manifest["unitRegressions"], "regression")


def _exact_unittest_completed(stdout: str, nonce: str) -> bool:
    """Return whether the runner reported this run's exact passing summary."""
    expected = " ".join((
        EXACT_UNITTEST_COMPLETION_MARKER,
        nonce,
        json.dumps(EXACT_UNITTEST_SUMMARY, sort_keys=True),
    ))
    records = [line for line in stdout.splitlines() if nonce in line]
    return records == [expected]


def _terminate_selected_test_process(process: subprocess.Popen) -> str | None:
    """Bound abnormal cleanup and return any platform cleanup limitation."""
    cleanup_issue = None
    if os.name == "posix":
        try:
            # Each selected test starts a new session, so its process id is also
            # the process-group id inherited by ordinary descendants.
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            cleanup_issue = f"could not kill POSIX test process group: {exc}"
            try:
                process.kill()
            except OSError:
                pass
        # POSIX communicate() uses selectors rather than background reader
        # threads, so closing these local pipe ends cannot wait on a reader
        # lock and prevents an escaped descendant from keeping them open here.
        for stream_name in ("stdin", "stdout", "stderr"):
            stream = getattr(process, stream_name, None)
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
    else:
        # Python has no portable descendant-process-tree termination API.
        # On Windows, communicate() can leave background reader threads holding
        # buffered-stream locks after a timeout, so synchronously closing those
        # streams can itself hang. Kill and reap only the selected runner here.
        try:
            process.kill()
        except OSError as exc:
            cleanup_issue = f"could not kill selected test runner: {exc}"

    try:
        process.wait(timeout=SELECTED_TEST_CLEANUP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        cleanup_issue = (
            cleanup_issue + "; " if cleanup_issue else ""
        ) + "selected test runner could not be reaped within cleanup deadline"
    return cleanup_issue


def _run_python_evidence(entries: list[dict], label: str) -> int:
    python_path = os.pathsep.join((str(ROOT), str(ROOT / "tests")))
    for entry in entries:
        _unittest_module(entry["file"], entry["test"], entry["id"])
        test_path = _within_test_root(entry["file"])
        nonce = secrets.token_hex(32)
        command = [
            sys.executable,
            "-c",
            EXACT_UNITTEST_RUNNER,
            str(test_path),
            entry["test"],
            EXACT_UNITTEST_COMPLETION_MARKER,
        ]
        failure_kind = (
            "regression" if label == "regression"
            else "independent review evidence"
        )
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "PYTHONPATH": python_path},
            start_new_session=os.name == "posix",
        )
        try:
            stdout, stderr = process.communicate(
                input=nonce + "\n",
                timeout=SELECTED_TEST_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            cleanup_issue = _terminate_selected_test_process(process)
            message = (
                f"{entry['id']}: {failure_kind} timed out after "
                f"{SELECTED_TEST_TIMEOUT_SECONDS:g} seconds"
            )
            if cleanup_issue:
                message += f"; {cleanup_issue}"
            raise GateError(message) from None
        except BaseException as exc:
            # start_new_session isolates the selected runner from terminal
            # signals sent to this gate. Preserve subprocess.run-style cleanup
            # by terminating the isolated group before propagating interrupts.
            cleanup_issue = _terminate_selected_test_process(process)
            if cleanup_issue and hasattr(exc, "add_note"):
                exc.add_note(f"selected test cleanup: {cleanup_issue}")
            raise
        if process.returncode or not _exact_unittest_completed(stdout, nonce):
            detail = (stdout + stderr).strip()
            raise GateError(
                f"{entry['id']}: {failure_kind} is missing or failing\n{detail}"
            )
    return len(entries)


def run_independent_review_evidence(manifest: dict) -> int:
    return _run_python_evidence(
        manifest["independentReviewEvidence"], "review evidence"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    try:
        if os.name != "nt" and not os.access(Path(__file__), os.X_OK):
            raise GateError("scripts/pre_review_gate.py must remain executable")
        manifest = load_manifest(args.manifest.resolve())
        matrix_count = run_vector_matrices(manifest)
        regression_count = run_unit_regressions(manifest)
        review_evidence_count = run_independent_review_evidence(manifest)
    except (GateError, OSError, json.JSONDecodeError) as exc:
        print(f"pre-review gate FAILED: {exc}", file=sys.stderr)
        return 1
    print(
        f"pre-review gate OK ({matrix_count} matrix cases; "
        f"{regression_count} prior blocker regressions; "
        f"{len(manifest['independentReviewLenses'])} independent review lenses; "
        f"{review_evidence_count} independent review evidence tests)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
