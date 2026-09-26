"""Regression coverage for current and archival evidence admission boundaries."""

import base64
import copy
import hashlib
import itertools
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import dacs5_reference as R
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_bundle_settlement_evidence_bijection_vectors import (
    bind_laa_authority_to_bundle,
    laa_authority_for_bundle,
    refreshed_laa_phase_carriers,
    replace_payment_with_transition_evidence,
    replace_top_record,
    resign_ebfab,
    resign_inner_artifact,
    resign_listing,
)


ROOT = Path(__file__).resolve().parents[1]
DELIVERY_VECTORS = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "bundle-settlement-evidence-bijection-v0.4.json"
)
FINALITY_VECTORS = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "settlement-finality-verification.json"
)
CURRENT_JOB = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


def _decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class CurrentFabDeliveryAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(DELIVERY_VECTORS.read_text(encoding="utf-8"))
        cls.pubkeys = {
            claim: _decode(value) for claim, value in cls.data["publicKeys"].items()
        }

    def _sign(self, role, domain, digest):
        private = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(self.data["seeds"][role])
        )
        return _encode(private.sign((domain + digest).encode("utf-8")))

    def _resign_record(self, record, *, signer_role="seller"):
        signer = next(
            claim for claim in self.pubkeys if claim.endswith(":" + signer_role)
        )
        record["signature"] = {
            "signer": signer,
            "algorithm": "ed25519",
            "value": "",
        }
        record["signature"]["value"] = self._sign(
            signer_role,
            R.DELIVERY_EVIDENCE_DOMAIN,
            R.delivery_evidence_hash(record),
        )

    def _resign_payment_record(self, record, *, signer_role=None):
        if signer_role is None:
            current_signer = record.get("signature", {}).get("signer")
            signer_role = next(
                role for role in ("buyer", "seller", "orchestrator")
                if isinstance(current_signer, str)
                and current_signer.endswith(":" + role)
            )
        signer = next(
            claim for claim in self.pubkeys if claim.endswith(":" + signer_role)
        )
        record["signature"] = {
            "signer": signer,
            "algorithm": "ed25519",
            "value": "",
        }
        record["signature"]["value"] = self._sign(
            signer_role,
            R.SETTLEMENT_EVIDENCE_DOMAIN,
            R.settlement_evidence_hash(record),
        )

    def _resign_bundle_and_pointer(self, value):
        bundle = value["bundle"]
        claims = {
            party["role"]: party["primaryClaim"] for party in bundle["parties"]
        }
        bundle["signatures"] = []
        digest = R.bundle_hash(bundle)
        bundle["signatures"] = [
            {
                "party": claims[role],
                "algorithm": "ed25519",
                "value": self._sign(role, R.FAULT_BUNDLE_DOMAIN, digest),
            }
            for role in R._required_bundle_signers(bundle)
        ]
        digest = R.bundle_hash(bundle)
        pointer = value["pointer"]
        pointer["fullBundleContentHash"] = digest
        pointer["signature"] = {
            "signer": claims[bundle["anchoredByRole"]],
            "algorithm": "ed25519",
            "value": "",
        }
        pointer["signature"]["value"] = self._sign(
            bundle["anchoredByRole"],
            R.FAULT_POINTER_DOMAIN,
            R.pointer_hash(pointer),
        )

    def _fixture(self):
        source = copy.deepcopy(
            self.data["executionAuthorities"]["completed-storage-delivery"]
        )
        bundle = source["bundle"]
        bundle.pop("evidenceBoundFaultBundleVersion")
        bundle["faultBundleVersion"] = "1"
        bundle["jobId"] = CURRENT_JOB

        old_ref = copy.deepcopy(bundle["settlementEvidence"][0])
        old_key = R.canonical(old_ref).decode("utf-8")
        resolution = source["referenceValidationByCanonicalRef"].pop(old_key)
        record = resolution["record"]
        old_deliverable_ref = {
            "anchor": copy.deepcopy(record["deliverableAnchor"]),
            "contentHash": record["deliverableContentHash"],
        }
        old_deliverable_key = R.canonical(old_deliverable_ref).decode("utf-8")

        record["jobId"] = CURRENT_JOB
        record["deliverableAnchor"]["locator"] = (
            "dacs4:deliverable:%s:0" % CURRENT_JOB
        )
        self._resign_record(record, signer_role="orchestrator")
        new_ref = copy.deepcopy(old_ref)
        new_ref["contentHash"] = R.delivery_evidence_hash(record)
        new_key = R.canonical(new_ref).decode("utf-8")
        source["referenceValidationByCanonicalRef"][new_key] = resolution

        top_receipt = source["verifiedReceiptByCanonicalRef"].pop(old_key)
        top_receipt["logicalAddress"] = "dacs4:delivery:%s:0" % CURRENT_JOB
        top_receipt["contentHash"] = new_ref["contentHash"]
        source["verifiedReceiptByCanonicalRef"][new_key] = top_receipt

        new_deliverable_ref = {
            "anchor": copy.deepcopy(record["deliverableAnchor"]),
            "contentHash": record["deliverableContentHash"],
        }
        deliverable_authority = source["verifiedReceiptByCanonicalRef"].pop(
            old_deliverable_key
        )
        deliverable_receipt = deliverable_authority["receipt"]
        deliverable_receipt["logicalAddress"] = new_deliverable_ref["anchor"][
            "locator"
        ]
        deliverable_receipt["nativeAddress"] = new_deliverable_ref["anchor"][
            "locator"
        ]
        source["verifiedReceiptByCanonicalRef"][
            R.canonical(new_deliverable_ref).decode("utf-8")
        ] = deliverable_authority
        closure = source["deliveryArtifactAuthorityByPhaseKey"][
            "0:deliver-storage-program"
        ]["deliverable"]
        closure["logicalAddress"] = new_deliverable_ref["anchor"]["locator"]
        closure["nativeAddress"] = new_deliverable_ref["anchor"]["locator"]
        execution = source["sessionExecutionAuthorityByPhaseKey"][
            "0:deliver-storage-program"
        ]
        execution["jobId"] = CURRENT_JOB
        execution["evidenceLogicalAddress"] = "dacs4:delivery:%s:0" % CURRENT_JOB

        bundle["settlementEvidence"] = [new_ref]
        bundle["phaseSummary"][0]["attestationRef"] = copy.deepcopy(new_ref)
        pointer = {
            "faultBundleVersion": "1",
            "pointerKind": "extended",
            "fullBundleUrl": "fixture:current-fab-delivery",
            "fullBundleContentHash": "",
            "signature": {},
        }
        role = bundle["anchoredByRole"]
        signer = next(
            party["primaryClaim"] for party in bundle["parties"]
            if party["role"] == role
        )
        value = {
            "bundle": bundle,
            "pointer": pointer,
            "authority": source,
            "role": role,
            "trusted": R.trusted_profile_context(CURRENT_JOB, signer, role=role),
            "keys": R.trusted_verification_keys(copy.deepcopy(self.pubkeys)),
        }
        self._resign_bundle_and_pointer(value)
        return value

    def _failed_payment_fixture(self):
        source = copy.deepcopy(
            self.data["executionAuthorities"]["single-htlc-expired"]
        )
        bundle = source["bundle"]
        old_ref = bundle["settlementEvidence"][0]
        old_key = R.canonical(old_ref).decode("utf-8")
        resolution = source["referenceValidationByCanonicalRef"].pop(old_key)
        receipt = source["verifiedReceiptByCanonicalRef"].pop(old_key)
        record = resolution["record"]
        bundle["jobId"] = CURRENT_JOB
        record["jobId"] = CURRENT_JOB
        self._resign_payment_record(record)
        new_ref = copy.deepcopy(old_ref)
        new_ref["contentHash"] = R.settlement_evidence_hash(record)
        new_key = R.canonical(new_ref).decode("utf-8")
        receipt["logicalAddress"] = (
            "dacs4:payment:%s:test-rail:2" % CURRENT_JOB
        )
        receipt["contentHash"] = new_ref["contentHash"]
        source["referenceValidationByCanonicalRef"][new_key] = resolution
        source["verifiedReceiptByCanonicalRef"][new_key] = receipt
        source["sessionExecutionAuthorityByPhaseKey"][
            "2:pay-cross-chain-htlc"
        ]["jobId"] = CURRENT_JOB
        bundle["settlementEvidence"] = [new_ref]
        bundle["phaseSummary"][-1]["attestationRef"] = copy.deepcopy(new_ref)
        bundle.pop("evidenceBoundFaultBundleVersion")
        bundle["faultBundleVersion"] = "1"
        pointer = {
            "faultBundleVersion": "1",
            "pointerKind": "extended",
            "fullBundleUrl": "fixture:current-fab-payment",
            "fullBundleContentHash": "",
            "signature": {},
        }
        role = bundle["anchoredByRole"]
        signer = next(
            party["primaryClaim"] for party in bundle["parties"]
            if party["role"] == role
        )
        value = {
            "bundle": bundle,
            "pointer": pointer,
            "authority": source,
            "role": role,
            "trusted": R.trusted_profile_context(
                bundle["jobId"], signer, role=role
            ),
            "keys": R.trusted_verification_keys(copy.deepcopy(self.pubkeys)),
        }
        self._resign_bundle_and_pointer(value)
        return value

    def _replace_payment_record(
        self, value, mutate, *, update_ref=True, update_receipt=True
    ):
        authority = value["authority"]
        bundle = value["bundle"]
        old_ref = bundle["settlementEvidence"][0]
        old_key = R.canonical(old_ref).decode("utf-8")
        resolution = authority["referenceValidationByCanonicalRef"].pop(old_key)
        receipt = authority["verifiedReceiptByCanonicalRef"].pop(old_key)
        record = resolution["record"]
        mutate(record)
        self._resign_payment_record(record)
        new_ref = copy.deepcopy(old_ref)
        if update_ref:
            new_ref["contentHash"] = R.settlement_evidence_hash(record)
        new_key = R.canonical(new_ref).decode("utf-8")
        if update_receipt:
            receipt["contentHash"] = new_ref["contentHash"]
        authority["referenceValidationByCanonicalRef"][new_key] = resolution
        authority["verifiedReceiptByCanonicalRef"][new_key] = receipt
        bundle["settlementEvidence"] = [new_ref]
        for entry in bundle["phaseSummary"]:
            if entry.get("attestationRef") == old_ref:
                entry["attestationRef"] = copy.deepcopy(new_ref)
        self._resign_bundle_and_pointer(value)

    def _replace_record(self, value, mutate, *, signer_role="seller"):
        authority = value["authority"]
        bundle = value["bundle"]
        old_ref = bundle["settlementEvidence"][0]
        old_key = R.canonical(old_ref).decode("utf-8")
        resolution = authority["referenceValidationByCanonicalRef"].pop(old_key)
        receipt = authority["verifiedReceiptByCanonicalRef"].pop(old_key)
        mutate(resolution["record"])
        self._resign_record(resolution["record"], signer_role=signer_role)
        new_ref = copy.deepcopy(old_ref)
        new_ref["contentHash"] = R.delivery_evidence_hash(resolution["record"])
        new_key = R.canonical(new_ref).decode("utf-8")
        receipt["contentHash"] = new_ref["contentHash"]
        authority["referenceValidationByCanonicalRef"][new_key] = resolution
        authority["verifiedReceiptByCanonicalRef"][new_key] = receipt
        bundle["settlementEvidence"] = [new_ref]
        bundle["phaseSummary"][0]["attestationRef"] = copy.deepcopy(new_ref)
        self._resign_bundle_and_pointer(value)

    def _resolve(self, value):
        return R.resolve_absolute_fault_pointer(
            value["pointer"],
            value["bundle"],
            pubkeys=value["keys"],
            ebfab_authority=value["authority"],
            trusted_contexts=value["trusted"],
            expected_jobid=value["bundle"]["jobId"],
            expected_role=value["role"],
        )

    def _reconcile(self, value, *, authority=True):
        bundle = value["bundle"]
        role = value["role"]
        other_role = "seller" if role == "buyer" else "buyer"
        writer = next(
            party["primaryClaim"] for party in bundle["parties"]
            if party["role"] == role
        )
        presence = {
            "bundleHash": R.bundle_hash(bundle),
            "nativeAddress": "dacs5:bundle:%s:%s" % (bundle["jobId"], role),
            "writer": writer,
        }
        trust = {
            "copyPresenceByJobRole": {
                bundle["jobId"] + ":" + role: copy.deepcopy(presence),
            },
            "copyDispositionByJobRole": {
                bundle["jobId"] + ":" + other_role: "absent",
            },
        }
        entries = [
            {
                "bundle": bundle,
                "expectedJobId": bundle["jobId"],
                "expectedRole": role,
                "copyPresence": presence,
                "authority": value["authority"] if authority else None,
            },
            {
                "disposition": "absent",
                "expectedJobId": bundle["jobId"],
                "expectedRole": other_role,
            },
        ]
        return R.reconcile_authenticated_finality_copies(
            entries, self.pubkeys, trust
        )

    def test_genuine_current_fab_delivery_closure_passes(self):
        value = self._fixture()
        result = self._resolve(value)
        self.assertTrue(result["ok"], result["reason"])
        reconciled = self._reconcile(value)
        self.assertEqual("pass", reconciled["decision"], reconciled["reason"])

    def test_ordinary_reconciliation_requires_current_agreement_carrier(self):
        for authority_name in ("standard-completed", "repeated-pay-completed"):
            with self.subTest(authority=authority_name):
                authority = copy.deepcopy(self.data["executionAuthorities"][authority_name])
                bundle = authority["bundle"]
                bundle.pop("evidenceBoundFaultBundleVersion")
                bundle.pop("faultedParty", None)
                bundle["bundleVersion"] = "1"
                claims = {
                    party["role"]: party["primaryClaim"] for party in bundle["parties"]
                }
                bundle["signatures"] = []
                digest = R.bundle_hash(bundle)
                bundle["signatures"] = [
                    {
                        "party": claims[role],
                        "algorithm": "ed25519",
                        "value": self._sign(role, R.BUNDLE_DOMAIN, digest),
                    }
                    for role in R._required_bundle_signers(bundle)
                ]
                authority["legacyAgreementAuthorityByPhaseKey"] = (
                    refreshed_laa_phase_carriers(authority)
                )
                value = {
                    "bundle": bundle,
                    "authority": authority,
                    "role": bundle["anchoredByRole"],
                }
                positive = self._reconcile(value)
                self.assertEqual("pass", positive["decision"], positive["reason"])
                carrier_key = next(iter(authority["legacyAgreementAuthorityByPhaseKey"]))
                original_carrier = copy.deepcopy(
                    authority["legacyAgreementAuthorityByPhaseKey"][carrier_key]
                )
                authority["legacyAgreementAuthorityByPhaseKey"][carrier_key] = []
                malformed = self._reconcile(value)
                self.assertEqual("error", malformed["decision"], malformed["reason"])
                authority["legacyAgreementAuthorityByPhaseKey"][carrier_key] = (
                    original_carrier
                )
                authority["legacyAgreementAuthorityByPhaseKey"][carrier_key][
                    "binding"
                ]["agreementContentHash"] = "0" * 64
                contradiction = self._reconcile(value)
                self.assertEqual("fail", contradiction["decision"], contradiction["reason"])
                authority["legacyAgreementAuthorityByPhaseKey"][carrier_key] = (
                    original_carrier
                )
                del authority["legacyAgreementAuthorityByPhaseKey"]
                missing = self._reconcile(value)
                self.assertEqual("indeterminate", missing["decision"], missing["reason"])
                self.assertIn("legacy agreement", missing["reason"])

    def _assert_payment_admission_paths(self, value, expected):
        direct, reason = R._validate_current_fab_delivery_admission(
            value["bundle"], value["authority"], self.pubkeys
        )
        self.assertEqual(expected, direct, reason)
        resolved = self._resolve(value)
        if expected == "pass":
            self.assertTrue(resolved["ok"], resolved["reason"])
        else:
            self.assertFalse(resolved["ok"], resolved["reason"])
            self.assertEqual(expected, resolved.get("disposition"), resolved)
        reconciled = self._reconcile(value)
        self.assertEqual(expected, reconciled["decision"], reconciled["reason"])

    def _current_use(self, value):
        """Run the composed current-use job gate over one authenticated copy."""
        result = self._current_use_result(value)
        return result["decision"], result["reason"]

    def _current_use_result(self, value):
        """The full current-use job result, including fault attribution."""
        bundle = value["bundle"]
        claims = {
            party["role"]: party["primaryClaim"] for party in bundle["parties"]
        }
        role = bundle["anchoredByRole"]
        other_role = "seller" if role == "buyer" else "buyer"
        presence = {
            "bundleHash": R.bundle_hash(bundle),
            "nativeAddress": "dacs5:bundle:%s:%s" % (bundle["jobId"], role),
            "writer": claims[role],
        }
        resolved = {
            role: {
                "decision": "pass",
                "disposition": "present",
                "bundle": bundle,
                "presence": presence,
            },
            other_role: {"decision": "pass", "disposition": "absent"},
        }
        dependencies = {
            "bundleAuthorityByContentHash": {
                R.bundle_hash(bundle): value["authority"],
            },
        }
        config = {
            "publicKeys": self.pubkeys,
            "finalityTrust": {},
            "partyRolesByJob": {bundle["jobId"]: claims},
            "scoredParty": claims[role],
        }
        job = {
            "jobId": bundle["jobId"],
            "substrate": "fixture",
            "roles": {"buyer": {}, "seller": {}},
        }
        with patch(
            "dacs5_reference._resolve_current_use_role",
            side_effect=lambda _job, requested_role, *_args, **_kwargs: (
                copy.deepcopy(resolved[requested_role])
            ),
        ):
            result = R._resolve_current_use_job(job, dependencies, config, {}, {})
        return result

    def _payment_admission_dispositions(self, value):
        direct, _reason = R._validate_current_fab_delivery_admission(
            value["bundle"], value["authority"], self.pubkeys
        )
        resolved = self._resolve(value)
        return {
            "direct": direct,
            "pointer": "pass" if resolved["ok"] else resolved.get("disposition"),
            "reconcile": self._reconcile(value)["decision"],
            "current-use": self._current_use(value)[0],
        }

    def _assert_learning_omitted_record_is_inert(self, before, after):
        """A record learned after a released FAB was made cannot move its verdict."""
        self.assertEqual(
            R.bundle_hash(before["bundle"]), R.bundle_hash(after["bundle"])
        )
        baseline = self._payment_admission_dispositions(before)
        learned = self._payment_admission_dispositions(after)
        self.assertEqual(baseline, learned)
        self.assertEqual(
            {"direct": "pass", "pointer": "pass", "reconcile": "pass"},
            {path: learned[path] for path in ("direct", "pointer", "reconcile")},
        )
        # CUR-5 independently holds an incomplete historical trace as
        # indeterminate; it never turns an omitted record into a rejection.
        self.assertNotIn(learned["current-use"], {"fail", "error"})

    def _omit_failed_payment_member(self, value):
        bundle = value["bundle"]
        ref = bundle["settlementEvidence"].pop()
        bundle["phaseSummary"][-1].pop("attestationRef", None)
        key = R.canonical(ref).decode("utf-8")
        learned = (
            value["authority"]["referenceValidationByCanonicalRef"].pop(key),
            value["authority"]["verifiedReceiptByCanonicalRef"].pop(key),
        )
        self._resign_bundle_and_pointer(value)
        return key, learned

    def _move_failed_payment_orchestrator(self, value, role):
        """Rebind the failed payment phase to another authenticated orchestrator."""
        authority = value["authority"]
        bundle = value["bundle"]
        claim = next(
            party["primaryClaim"] for party in bundle["parties"]
            if party["role"] == role
        )
        authority["sessionExecutionAuthorityByPhaseKey"][
            "2:pay-cross-chain-htlc"
        ]["phaseOrchestrator"] = claim
        self._replace_payment_record(
            value,
            lambda record: self._resign_payment_record(record, signer_role=role),
        )
        new_key = R.canonical(bundle["settlementEvidence"][0]).decode("utf-8")
        authority["verifiedReceiptByCanonicalRef"][new_key]["writer"] = claim

    def test_current_fab_failed_payment_admission_and_omission(self):
        self._assert_payment_admission_paths(
            self._failed_payment_fixture(), "pass"
        )

        counterparty_failure = self._failed_payment_fixture()
        self._replace_payment_record(
            counterparty_failure,
            lambda record: record.__setitem__("reason", "operator-declined"),
        )
        counterparty_failure["bundle"]["phaseSummary"][-1][
            "errorClass"
        ] = "counterparty"
        self._resign_bundle_and_pointer(counterparty_failure)
        self._assert_payment_admission_paths(counterparty_failure, "pass")

        # Released FAB has no consumer-side failed-payment membership rule
        # (DACS-5 §10.4.3): omission stays admissible even when the verifier
        # already holds the exact authenticated failure record.
        omitted = self._failed_payment_fixture()
        omitted["bundle"]["settlementEvidence"] = []
        omitted["bundle"]["phaseSummary"][-1].pop("attestationRef", None)
        self._resign_bundle_and_pointer(omitted)
        self._assert_payment_admission_paths(omitted, "pass")

        pointer_only = self._failed_payment_fixture()
        pointer_only["bundle"]["settlementEvidence"] = []
        self._resign_bundle_and_pointer(pointer_only)
        self._assert_payment_admission_paths(pointer_only, "pass")

        omitted_counterparty = counterparty_failure
        omitted_counterparty["bundle"]["settlementEvidence"] = []
        omitted_counterparty["bundle"]["phaseSummary"][-1].pop(
            "attestationRef", None
        )
        self._resign_bundle_and_pointer(omitted_counterparty)
        self._assert_payment_admission_paths(omitted_counterparty, "pass")

    def test_later_failed_payment_record_cannot_flip_a_released_fab(self):
        # buyer: the faulted counterparty orchestrates the failed payment;
        # seller: the FAB's own author orchestrates it.
        for orchestrator in ("buyer", "seller"):
            for timing in ("before-fab", "after-fab"):
                before = self._failed_payment_fixture()
                if orchestrator == "buyer":
                    self._move_failed_payment_orchestrator(before, "buyer")
                    self._assert_payment_admission_paths(
                        copy.deepcopy(before), "pass"
                    )
                key, (resolution, receipt) = self._omit_failed_payment_member(
                    before
                )
                after = copy.deepcopy(before)
                if timing == "after-fab":
                    late = 9 * 10 ** 12
                    self.assertGreater(late, before["bundle"]["finalisedAt"])
                    receipt["blockRef"]["height"] = str(10 ** 9)
                    receipt["blockRef"]["timestamp"] = late
                    receipt["observedAt"] = late
                after["authority"]["referenceValidationByCanonicalRef"][key] = (
                    resolution
                )
                after["authority"]["verifiedReceiptByCanonicalRef"][key] = receipt
                with self.subTest(orchestrator=orchestrator, timing=timing):
                    self._assert_learning_omitted_record_is_inert(before, after)

    def test_omitted_success_contradicting_released_fab_is_specified_residual(self):
        def with_success_record(*, present):
            value = self._failed_payment_fixture()
            authority = value["authority"]
            bundle = value["bundle"]
            source = self.data["executionAuthorities"]["single-htlc-completed"]
            source_ref = source["bundle"]["settlementEvidence"][0]
            source_key = R.canonical(source_ref).decode("utf-8")
            resolution = copy.deepcopy(
                source["referenceValidationByCanonicalRef"][source_key]
            )
            record = resolution["record"]
            record["jobId"] = bundle["jobId"]
            record.pop("supersedesEvidenceRef", None)
            self._resign_payment_record(record)
            ref = copy.deepcopy(source_ref)
            ref["contentHash"] = R.settlement_evidence_hash(record)
            receipt = copy.deepcopy(
                source["verifiedReceiptByCanonicalRef"][source_key]
            )
            receipt["logicalAddress"] = "dacs4:payment:%s:test-rail:2" % (
                bundle["jobId"]
            )
            receipt["contentHash"] = ref["contentHash"]
            self._omit_failed_payment_member(value)
            bundle["phaseSummary"][-1]["errorClass"] = "counterparty"
            key = R.canonical(ref).decode("utf-8")
            if present:
                bundle["settlementEvidence"] = [ref]
            self._resign_bundle_and_pointer(value)
            learned = copy.deepcopy(value)
            learned["authority"]["referenceValidationByCanonicalRef"][key] = resolution
            learned["authority"]["verifiedReceiptByCanonicalRef"][key] = receipt
            return value, learned

        # A presented success contradicting the co-signed fail row is rejected.
        _unlearned, presented = with_success_record(present=True)
        self._assert_payment_admission_paths(presented, "fail")
        # An omitted one is outside released-FAB consumer membership; only an
        # EBFAB's SEB-4 bijection makes that omission detectable.
        before, after = with_success_record(present=False)
        self._assert_learning_omitted_record_is_inert(before, after)

    def test_current_fab_failed_payment_omission_variants_keep_released_semantics(self):
        no_pointer = self._failed_payment_fixture()
        no_pointer["bundle"]["phaseSummary"][-1].pop("attestationRef", None)
        self._resign_bundle_and_pointer(no_pointer)
        self._assert_payment_admission_paths(no_pointer, "pass")

        no_record = self._failed_payment_fixture()
        ref = no_record["bundle"]["settlementEvidence"].pop()
        key = R.canonical(ref).decode("utf-8")
        no_record["bundle"]["phaseSummary"][-1].pop("attestationRef", None)
        no_record["authority"]["referenceValidationByCanonicalRef"].pop(key)
        no_record["authority"]["verifiedReceiptByCanonicalRef"].pop(key)
        self._resign_bundle_and_pointer(no_record)
        self._assert_payment_admission_paths(no_record, "pass")

        no_receipt = self._failed_payment_fixture()
        ref = no_receipt["bundle"]["settlementEvidence"].pop()
        key = R.canonical(ref).decode("utf-8")
        no_receipt["bundle"]["phaseSummary"][-1].pop("attestationRef", None)
        no_receipt["authority"]["verifiedReceiptByCanonicalRef"].pop(key)
        self._resign_bundle_and_pointer(no_receipt)
        self._assert_payment_admission_paths(no_receipt, "pass")

        unestablished = self._failed_payment_fixture()
        ref = unestablished["bundle"]["settlementEvidence"].pop()
        key = R.canonical(ref).decode("utf-8")
        unestablished["bundle"]["phaseSummary"][-1].pop("attestationRef", None)
        unestablished["authority"]["referenceValidationByCanonicalRef"][key][
            "lifecycle"
        ]["state"] = "pending"
        self._resign_bundle_and_pointer(unestablished)
        self._assert_payment_admission_paths(unestablished, "pass")

        unrelated = copy.deepcopy(no_record)
        foreign = self._failed_payment_fixture()
        self._replace_payment_record(
            foreign,
            lambda record: record.__setitem__("jobId", "OTHER-PAYMENT-JOB"),
        )
        foreign_ref = foreign["bundle"]["settlementEvidence"][0]
        foreign_key = R.canonical(foreign_ref).decode("utf-8")
        unrelated["authority"]["referenceValidationByCanonicalRef"][foreign_key] = (
            foreign["authority"]["referenceValidationByCanonicalRef"][foreign_key]
        )
        unrelated["authority"]["verifiedReceiptByCanonicalRef"][foreign_key] = (
            foreign["authority"]["verifiedReceiptByCanonicalRef"][foreign_key]
        )
        self._assert_payment_admission_paths(unrelated, "pass")

    def test_presented_st8_interim_is_checked_while_omitted_interim_stays_released(self):
        presented = self._failed_payment_fixture()
        before = copy.deepcopy(presented)
        self._omit_failed_payment_member(before)
        after = copy.deepcopy(before)
        for value in (presented, after):
            self._add_known_st8_successor(value)
        self._assert_payment_admission_paths(presented, "fail")
        self._assert_learning_omitted_record_is_inert(before, after)

    def _add_known_st8_successor(self, value):
        interim_ref = copy.deepcopy(
            self._failed_payment_fixture()["bundle"]["settlementEvidence"][0]
        )
        source = self.data["executionAuthorities"]["single-htlc-completed"]
        successor_ref = source["bundle"]["settlementEvidence"][0]
        successor_key = R.canonical(successor_ref).decode("utf-8")
        resolution = copy.deepcopy(
            source["referenceValidationByCanonicalRef"][successor_key]
        )
        record = resolution["record"]
        record["jobId"] = value["bundle"]["jobId"]
        record["supersedesEvidenceRef"] = interim_ref
        self._resign_payment_record(record)
        new_ref = copy.deepcopy(successor_ref)
        new_ref["contentHash"] = R.settlement_evidence_hash(record)
        new_key = R.canonical(new_ref).decode("utf-8")
        receipt = copy.deepcopy(source["verifiedReceiptByCanonicalRef"][successor_key])
        receipt["logicalAddress"] = "dacs4:payment:%s:test-rail:2:resolved" % (
            value["bundle"]["jobId"]
        )
        receipt["contentHash"] = new_ref["contentHash"]
        value["authority"]["referenceValidationByCanonicalRef"][new_key] = (
            resolution
        )
        value["authority"]["verifiedReceiptByCanonicalRef"][new_key] = receipt

    def test_current_fab_presented_payment_members_are_fully_bound(self):
        cases = []

        wrong_job = self._failed_payment_fixture()
        self._replace_payment_record(
            wrong_job,
            lambda record: record.__setitem__(
                "jobId", "SEB-AUTHORITY-other-payment-job"
            ),
        )
        cases.append(("job", wrong_job, "fail"))

        stale_hash = self._failed_payment_fixture()
        self._replace_payment_record(
            stale_hash,
            lambda record: record.__setitem__(
                "observedAt", record["observedAt"] + 1
            ),
            update_ref=False,
        )
        cases.append(("hash", stale_hash, "fail"))

        wrong_phase = self._failed_payment_fixture()
        self._replace_payment_record(
            wrong_phase,
            lambda record: record.__setitem__("phase", "pay-dem"),
        )
        cases.append(("phase", wrong_phase, "fail"))

        wrong_st8_reason = self._failed_payment_fixture()
        self._replace_payment_record(
            wrong_st8_reason,
            lambda record: record.__setitem__("reason", "operator-declined"),
        )
        cases.append(("st8-reason", wrong_st8_reason, "fail"))

        wrong_st8_class = self._failed_payment_fixture()
        wrong_st8_class["bundle"]["phaseSummary"][-1][
            "errorClass"
        ] = "counterparty"
        self._resign_bundle_and_pointer(wrong_st8_class)
        cases.append(("st8-class", wrong_st8_class, "fail"))

        failed_supersession = self._failed_payment_fixture()
        self._replace_payment_record(
            failed_supersession,
            lambda record: record.__setitem__(
                "supersedesEvidenceRef",
                {
                    "anchor": {
                        "kind": "storage-program",
                        "locator": "dacs4:payment:unrelated",
                    },
                    "contentHash": "11" * 32,
                },
            ),
        )
        cases.append(("failed-supersession", failed_supersession, "fail"))

        wrong_receipt = self._failed_payment_fixture()
        receipt_key = R.canonical(
            wrong_receipt["bundle"]["settlementEvidence"][0]
        ).decode("utf-8")
        wrong_receipt["authority"]["verifiedReceiptByCanonicalRef"][receipt_key][
            "logicalAddress"
        ] = "dacs4:payment:%s:test-rail:3" % wrong_receipt["bundle"]["jobId"]
        cases.append(("receipt-index", wrong_receipt, "fail"))

        wrong_lifecycle = self._failed_payment_fixture()
        lifecycle_key = R.canonical(
            wrong_lifecycle["bundle"]["settlementEvidence"][0]
        ).decode("utf-8")
        wrong_lifecycle["authority"]["referenceValidationByCanonicalRef"][lifecycle_key][
            "lifecycle"
        ]["state"] = "pending"
        cases.append(("lifecycle-receipt", wrong_lifecycle, "fail"))

        unavailable_lifecycle = self._failed_payment_fixture()
        lifecycle_key = R.canonical(
            unavailable_lifecycle["bundle"]["settlementEvidence"][0]
        ).decode("utf-8")
        unavailable_lifecycle["authority"]["referenceValidationByCanonicalRef"][lifecycle_key].pop(
            "lifecycle"
        )
        cases.append(("lifecycle-authority", unavailable_lifecycle, "indeterminate"))

        malformed_lifecycle = self._failed_payment_fixture()
        lifecycle_key = R.canonical(
            malformed_lifecycle["bundle"]["settlementEvidence"][0]
        ).decode("utf-8")
        malformed_lifecycle["authority"]["referenceValidationByCanonicalRef"][lifecycle_key][
            "lifecycle"
        ] = []
        cases.append(("lifecycle-malformed", malformed_lifecycle, "error"))

        wrong_outcome = self._failed_payment_fixture()
        success_source = copy.deepcopy(
            self.data["executionAuthorities"]["single-htlc-direct-completed"]
        )
        success_ref = success_source["bundle"]["settlementEvidence"][0]
        success_record = success_source["referenceValidationByCanonicalRef"][
            R.canonical(success_ref).decode("utf-8")
        ]["record"]

        def make_success(record):
            record.pop("reason", None)
            record["outcome"] = "success"
            for field in (
                "paymentTxRefs", "paymentAmount", "paymentFee",
                "settlementFinality",
            ):
                if field in success_record:
                    record[field] = copy.deepcopy(success_record[field])
                else:
                    record.pop(field, None)

        self._replace_payment_record(wrong_outcome, make_success)
        cases.append(("outcome", wrong_outcome, "fail"))

        malformed = self._failed_payment_fixture()
        self._replace_payment_record(
            malformed,
            lambda record: record.__setitem__("outcome", "unknown"),
        )
        cases.append(("shape", malformed, "error"))

        unavailable = self._failed_payment_fixture()
        unavailable["authority"].pop("sessionExecutionAuthorityByPhaseKey")
        cases.append(("execution-authority", unavailable, "indeterminate"))

        unavailable_receipt = self._failed_payment_fixture()
        unavailable_receipt["authority"].pop("verifiedReceiptByCanonicalRef")
        cases.append(("receipt-authority", unavailable_receipt, "indeterminate"))

        missing_exact_receipt = self._failed_payment_fixture()
        exact_ref_key = R.canonical(
            missing_exact_receipt["bundle"]["settlementEvidence"][0]
        ).decode("utf-8")
        missing_exact_receipt["authority"][
            "verifiedReceiptByCanonicalRef"
        ].pop(exact_ref_key)
        cases.append(("exact-receipt-missing", missing_exact_receipt, "indeterminate"))

        malformed_exact_receipt = self._failed_payment_fixture()
        exact_ref_key = R.canonical(
            malformed_exact_receipt["bundle"]["settlementEvidence"][0]
        ).decode("utf-8")
        malformed_exact_receipt["authority"][
            "verifiedReceiptByCanonicalRef"
        ][exact_ref_key] = []
        cases.append(("exact-receipt-malformed", malformed_exact_receipt, "error"))

        missing_exact_execution = self._failed_payment_fixture()
        missing_exact_execution["authority"][
            "sessionExecutionAuthorityByPhaseKey"
        ].pop("2:pay-cross-chain-htlc")
        cases.append(("exact-execution-missing", missing_exact_execution, "indeterminate"))

        malformed_exact_execution = self._failed_payment_fixture()
        malformed_exact_execution["authority"][
            "sessionExecutionAuthorityByPhaseKey"
        ]["2:pay-cross-chain-htlc"] = []
        cases.append(("exact-execution-malformed", malformed_exact_execution, "error"))

        for name, value, expected in cases:
            with self.subTest(binding=name):
                self._assert_payment_admission_paths(value, expected)

    def test_current_fab_rejects_authenticated_listing_with_wrong_publisher_role(self):
        value = self._fixture()
        listing = value["authority"]["listing"]
        buyer = next(
            party["primaryClaim"] for party in value["bundle"]["parties"]
            if party["role"] == "buyer"
        )
        listing["sellerPrimaryClaim"] = buyer
        listing["signature"] = {
            "signer": buyer,
            "algorithm": "ed25519",
            "value": "",
        }
        listing["signature"]["value"] = self._sign(
            "buyer", R.LISTING_DOMAIN, R.listing_hash(listing)
        )
        value["bundle"]["listingRef"]["contentHash"] = R.listing_hash(listing)
        self._resign_bundle_and_pointer(value)
        result = self._resolve(value)
        self.assertFalse(result["ok"])
        self.assertIn("Listing publisher differs", result["reason"])
        reconciled = self._reconcile(value)
        self.assertEqual("fail", reconciled["decision"])

    def test_genuine_current_delivery_is_historical_nonpayment_evidence(self):
        value = self._fixture()
        bundle = value["bundle"]
        claims = {
            party["role"]: party["primaryClaim"] for party in bundle["parties"]
        }
        dependencies = {
            "bundleAuthorityByContentHash": {
                R.bundle_hash(bundle): value["authority"]
            }
        }
        config = {
            "publicKeys": self.pubkeys,
            "partyRolesByJob": {bundle["jobId"]: claims},
        }
        decision, reason = R._validate_current_use_historical_nonpayment(
            bundle, dependencies, config
        )
        self.assertEqual("pass", decision, reason)

    def _ordinary_current_delivery(self, value):
        bundle = value["bundle"]
        bundle.pop("faultBundleVersion")
        bundle.pop("faultedParty")
        bundle["bundleVersion"] = "1"
        claims = {
            party["role"]: party["primaryClaim"] for party in bundle["parties"]
        }
        bundle["signatures"] = []
        digest = R.bundle_hash(bundle)
        bundle["signatures"] = [
            {
                "party": claims[role],
                "algorithm": "ed25519",
                "value": self._sign(role, R.BUNDLE_DOMAIN, digest),
            }
            for role in R._required_bundle_signers(bundle)
        ]
        signed, reason = R._bundle_signatures_valid_for_family(
            bundle, self.pubkeys, "legacy"
        )
        self.assertTrue(signed, reason)
        dependencies = {
            "bundleAuthorityByContentHash": {R.bundle_hash(bundle): value["authority"]}
        }
        config = {
            "publicKeys": self.pubkeys,
            "partyRolesByJob": {bundle["jobId"]: claims},
        }
        return bundle, value["authority"], dependencies, config

    def test_ordinary_current_delivery_passes_historical_nonpayment_gate(self):
        bundle, _authority, dependencies, config = self._ordinary_current_delivery(
            self._fixture()
        )
        decision, reason = R._validate_current_use_historical_nonpayment(
            bundle, dependencies, config
        )
        self.assertEqual("pass", decision, reason)

    def _legacy_delivery_value(
        self, kind, *, authority_name="legacy-storage-completed", mutate=None
    ):
        """Convert an archival-profile EBFAB fixture into an older-family copy."""
        authority = copy.deepcopy(self.data["executionAuthorities"][authority_name])
        bundle = authority["bundle"]
        # Pointer resolution requires a ULID job; rebind the signed record,
        # its unindexed deliverable anchor and closure, its receipt address,
        # and the execution authority to CURRENT_JOB.
        old_job = bundle["jobId"]

        def rebind(record):
            record["jobId"] = CURRENT_JOB
            record["deliverableAnchor"]["locator"] = record["deliverableAnchor"][
                "locator"
            ].replace(old_job, CURRENT_JOB)

        replace_top_record(
            authority, "deliver-storage-program", rebind, self.data["seeds"]
        )
        for closure in authority["deliveryArtifactAuthorityByPhaseKey"].values():
            for dependency in closure.values():
                if not isinstance(dependency, dict):
                    continue
                for field in ("logicalAddress", "nativeAddress"):
                    if isinstance(dependency.get(field), str):
                        dependency[field] = dependency[field].replace(
                            old_job, CURRENT_JOB
                        )
        bundle["jobId"] = CURRENT_JOB
        for receipt in authority["verifiedReceiptByCanonicalRef"].values():
            if isinstance(receipt.get("logicalAddress"), str):
                receipt["logicalAddress"] = receipt["logicalAddress"].replace(
                    old_job, CURRENT_JOB
                )
        for execution in authority["sessionExecutionAuthorityByPhaseKey"].values():
            execution["jobId"] = CURRENT_JOB
            execution["evidenceLogicalAddress"] = execution[
                "evidenceLogicalAddress"
            ].replace(old_job, CURRENT_JOB)
        if mutate is not None:
            replace_top_record(
                authority, "deliver-storage-program", mutate, self.data["seeds"]
            )
        bundle.pop("evidenceBoundFaultBundleVersion")
        role = bundle["anchoredByRole"]
        signer = next(
            party["primaryClaim"] for party in bundle["parties"]
            if party["role"] == role
        )
        value = {
            "bundle": bundle,
            "authority": authority,
            "role": role,
            "pointer": {
                "faultBundleVersion": "1",
                "pointerKind": "extended",
                "fullBundleUrl": "fixture:legacy-delivery",
                "fullBundleContentHash": "",
                "signature": {},
            },
            "trusted": R.trusted_profile_context(bundle["jobId"], signer, role=role),
            "keys": R.trusted_verification_keys(copy.deepcopy(self.pubkeys)),
        }
        if kind == "fault":
            bundle["faultBundleVersion"] = "1"
            self._resign_bundle_and_pointer(value)
        else:
            bundle.pop("faultedParty", None)
            bundle["bundleVersion"] = "1"
            claims = {
                party["role"]: party["primaryClaim"] for party in bundle["parties"]
            }
            bundle["signatures"] = []
            digest = R.bundle_hash(bundle)
            bundle["signatures"] = [
                {
                    "party": claims[signer_role],
                    "algorithm": "ed25519",
                    "value": self._sign(signer_role, R.BUNDLE_DOMAIN, digest),
                }
                for signer_role in R._required_bundle_signers(bundle)
            ]
        return value

    def _historical_current_use(self, value):
        bundle = value["bundle"]
        claims = {
            party["role"]: party["primaryClaim"] for party in bundle["parties"]
        }
        return R._validate_current_use_historical_nonpayment(
            bundle,
            {"bundleAuthorityByContentHash": {
                R.bundle_hash(bundle): value["authority"],
            }},
            {"publicKeys": self.pubkeys, "partyRolesByJob": {bundle["jobId"]: claims}},
        )

    def test_authentic_legacy_delivery_is_current_ineligible_on_every_consumer(self):
        source = self.data["executionAuthorities"]["legacy-storage-completed"]
        archival = R.validate_archival_audit_ebfab_disposition(
            source["bundle"], source["listing"], self.pubkeys,
            source["referenceValidationByCanonicalRef"], source["bundleLifecycle"],
            source["sessionExecutionAuthorityByPhaseKey"],
            source["verifiedReceiptByCanonicalRef"],
            source["deliveryArtifactAuthorityByPhaseKey"],
            source["trustedNativeTransactionObservationsByCanonicalRef"],
        )
        self.assertEqual("pass", archival[0], archival[1])
        for kind in ("legacy", "fault"):
            for contract in (None, "archival"):
                value = self._legacy_delivery_value(kind)
                if contract is not None:
                    value["authority"]["evidenceReceiptContract"] = contract
                with self.subTest(kind=kind, contract=contract):
                    reconciled = self._reconcile(value)
                    self.assertEqual(
                        "indeterminate", reconciled["decision"], reconciled["reason"]
                    )
                    self.assertIn("current-ineligible", reconciled["reason"])
                    if contract == "archival":
                        # A verifier archival label never enters the current gate.
                        self.assertIn("comparison-only", reconciled["reason"])
                    self.assertIsNone(reconciled["bundle"])
                    decision, reason = self._current_use(value)
                    self.assertEqual("indeterminate", decision, reason)
                    self.assertIn("current-ineligible", reason)
                    decision, reason = self._historical_current_use(value)
                    self.assertEqual("indeterminate", decision, reason)
                    self.assertIn("current-ineligible", reason)
                    if kind == "fault" and contract is None:
                        direct, reason = R._validate_current_fab_delivery_admission(
                            value["bundle"], value["authority"], self.pubkeys
                        )
                        self.assertEqual("current-ineligible", direct, reason)
                        resolved = self._resolve(value)
                        self.assertFalse(resolved["ok"], resolved["reason"])
                        self.assertEqual("indeterminate", resolved["disposition"])
                        self.assertIn("current-ineligible", resolved["reason"])
                        self.assertIs(False, resolved["currentEligible"])

    def test_contradictory_legacy_delivery_still_fails_before_ineligibility(self):
        def at_current_indexed_address(value):
            # PDE-2's address space belongs to DeliveryEvidence; a legacy
            # record there is not an unindexed PDE-7 read.
            authority = value["authority"]
            address = "dacs4:delivery:%s:0" % CURRENT_JOB
            authority["sessionExecutionAuthorityByPhaseKey"][
                "0:deliver-storage-program"
            ]["evidenceLogicalAddress"] = address
            key = R.canonical(value["bundle"]["settlementEvidence"][0]).decode("utf-8")
            authority["verifiedReceiptByCanonicalRef"][key]["logicalAddress"] = address

        def completed_but_only_included(value):
            # ST-11: a completed bundle's delivery must be finalized.
            key = R.canonical(value["bundle"]["settlementEvidence"][0]).decode("utf-8")
            authority = value["authority"]
            authority["referenceValidationByCanonicalRef"][key]["lifecycle"] = {
                "state": "included", "independentlyResolvable": False,
            }
            authority["verifiedReceiptByCanonicalRef"][key]["state"] = "included"

        cases = (
            ("repeated", {"authority_name": "legacy-repeated-storage-invalid"}, None),
            ("wrong-job", {
                "mutate": lambda record: record.__setitem__("jobId", "OTHER-JOB"),
            }, None),
            ("current-indexed-address", {}, at_current_indexed_address),
            ("completed-included-only", {}, completed_but_only_included),
        )
        for kind in ("legacy", "fault"):
            for name, options, adjust in cases:
                value = self._legacy_delivery_value(kind, **options)
                if adjust is not None:
                    adjust(value)
                with self.subTest(kind=kind, case=name):
                    reconciled = self._reconcile(value)
                    self.assertEqual("fail", reconciled["decision"], reconciled["reason"])
                    decision, reason = self._current_use(value)
                    self.assertEqual("fail", decision, reason)
                    decision, reason = self._historical_current_use(value)
                    self.assertEqual("fail", decision, reason)

    # --- round-2 regressions: released-copy payments, PDE-7, receipts, totality

    def _resign_released(self, value, kind):
        bundle = value["bundle"]
        bundle.pop("evidenceBoundFaultBundleVersion", None)
        if kind == "fault":
            bundle["faultBundleVersion"] = "1"
            self._resign_bundle_and_pointer(value)
            return
        bundle.pop("faultedParty", None)
        bundle["bundleVersion"] = "1"
        claims = {party["role"]: party["primaryClaim"] for party in bundle["parties"]}
        bundle["signatures"] = []
        digest = R.bundle_hash(bundle)
        bundle["signatures"] = [
            {
                "party": claims[role],
                "algorithm": "ed25519",
                "value": self._sign(role, R.BUNDLE_DOMAIN, digest),
            }
            for role in R._required_bundle_signers(bundle)
        ]

    def _released_value(self, authority_name, kind):
        """An EBFAB fixture re-expressed as a released AttestationBundle or FAB."""
        authority = copy.deepcopy(self.data["executionAuthorities"][authority_name])
        value = {
            "bundle": authority["bundle"],
            "authority": authority,
            "role": authority["bundle"]["anchoredByRole"],
            "pointer": {
                "faultBundleVersion": "1",
                "pointerKind": "extended",
                "fullBundleUrl": "fixture:released-copy",
                "fullBundleContentHash": "",
                "signature": {},
            },
        }
        self._resign_released(value, kind)
        authority["legacyAgreementAuthorityByPhaseKey"] = (
            refreshed_laa_phase_carriers(authority)
        )
        return value

    def _direct(self, value, kind):
        return R._validate_current_fab_delivery_admission(
            value["bundle"], value["authority"], self.pubkeys,
            **({"ordinary_current": True} if kind == "legacy" else {}),
        )

    def test_legacy_era_payments_on_released_copies_are_current_ineligible(self):
        # DACS-5 legacy-agreement era: a historical-only or transition-only
        # LAA pass is audit-valid but current-ineligible, never a contradiction.
        for kind in ("legacy", "fault"):
            control = self._released_value("standard-completed", kind)
            with self.subTest(kind=kind, operation="current-agreement"):
                self.assertEqual("pass", self._direct(control, kind)[0])
                self.assertEqual("pass", self._reconcile(control)["decision"])
            for operation in ("historical-audit", "transition-audit"):
                value = self._released_value("standard-completed", kind)
                authority = value["authority"]
                laa = laa_authority_for_bundle(authority, operation=operation)
                if operation == "transition-audit":
                    replace_payment_with_transition_evidence(
                        authority, laa, self.data["seeds"]
                    )
                    self._resign_released(value, kind)
                authority["legacyAgreementAuthorityByPhaseKey"] = {
                    "2:pay-dem": bind_laa_authority_to_bundle(authority, laa)
                }
                with self.subTest(kind=kind, operation=operation):
                    self.assertEqual(
                        (
                            "current-ineligible",
                            "legacy-agreement payment is audit-valid but current-ineligible",
                        ),
                        self._direct(value, kind),
                    )
                    reconciled = self._reconcile(value)
                    self.assertEqual("indeterminate", reconciled["decision"], reconciled["reason"])
                    self.assertIn("current-ineligible", reconciled["reason"])
                    self.assertIsNone(reconciled["bundle"])
                    decision, reason = self._current_use(value)
                    self.assertEqual("indeterminate", decision, reason)
                    self.assertIn("current-ineligible", reason)

    def test_released_copies_admit_only_authentic_st8_successors(self):
        def edge_missing(record):
            record.pop("supersedesEvidenceRef")

        def edge_to_unknown_interim(record):
            record["supersedesEvidenceRef"]["contentHash"] = "0" * 64

        for kind in ("legacy", "fault"):
            value = self._released_value("single-htlc-completed", kind)
            with self.subTest(kind=kind, successor="authentic"):
                self.assertEqual("pass", self._direct(value, kind)[0])
                self.assertEqual("pass", self._reconcile(value)["decision"])
                # CUR-5 still holds a successful historical payment.
                decision, reason = self._current_use(value)
                self.assertEqual("indeterminate", decision, reason)
                self.assertIn("stronger finality", reason)
            for name, mutate, reason_part in (
                ("edge-missing", edge_missing, "lacks its signed supersession edge"),
                ("edge-to-unknown-interim", edge_to_unknown_interim, "interim record"),
            ):
                bad = self._released_value("single-htlc-completed", kind)
                replace_top_record(
                    bad["authority"], "pay-cross-chain-htlc", mutate, self.data["seeds"]
                )
                self._resign_released(bad, kind)
                bad["authority"]["legacyAgreementAuthorityByPhaseKey"] = (
                    refreshed_laa_phase_carriers(bad["authority"])
                )
                with self.subTest(kind=kind, successor=name):
                    direct = self._direct(bad, kind)
                    self.assertEqual("fail", direct[0], direct[1])
                    self.assertIn(reason_part, direct[1])
                    self.assertEqual("fail", self._reconcile(bad)["decision"])
            interim_top_level = self._released_value("single-htlc-completed", kind)
            bundle = interim_top_level["bundle"]
            successor_key = R.canonical(bundle["settlementEvidence"][0]).decode("utf-8")
            interim_ref = interim_top_level["authority"]["referenceValidationByCanonicalRef"][
                successor_key
            ]["record"]["supersedesEvidenceRef"]
            bundle["settlementEvidence"].append(copy.deepcopy(interim_ref))
            self._resign_released(interim_top_level, kind)
            interim_top_level["authority"]["legacyAgreementAuthorityByPhaseKey"] = (
                refreshed_laa_phase_carriers(interim_top_level["authority"])
            )
            with self.subTest(kind=kind, successor="interim-also-top-level"):
                self.assertEqual("fail", self._direct(interim_top_level, kind)[0])
                self.assertEqual("fail", self._reconcile(interim_top_level)["decision"])

    def test_omitted_successful_payment_member_is_indeterminate_on_released_copies(self):
        for kind in ("legacy", "fault"):
            value = self._released_value("standard-completed", kind)
            bundle = value["bundle"]
            resolutions = value["authority"]["referenceValidationByCanonicalRef"]
            bundle["settlementEvidence"] = [
                ref for ref in bundle["settlementEvidence"]
                if resolutions[R.canonical(ref).decode("utf-8")]["record"]["phase"]
                != "pay-dem"
            ]
            for entry in bundle["phaseSummary"]:
                if entry["kind"] == "pay-dem":
                    entry.pop("attestationRef", None)
            self._resign_released(value, kind)
            value["authority"]["legacyAgreementAuthorityByPhaseKey"] = {}
            expected = (
                "indeterminate",
                "successful payment lacks a presented LAA-qualified evidence member",
            )
            with self.subTest(kind=kind):
                self.assertEqual(expected, self._direct(value, kind))
                reconciled = self._reconcile(value)
                self.assertEqual(expected, (reconciled["decision"], reconciled["reason"]))
                self.assertEqual(expected, self._current_use(value))

    def test_pde7_contradictions_fail_on_every_consumer_and_archival_lane(self):
        # Pipeline repeats the delivery kind; only its first step executed.
        for kind in ("legacy", "fault"):
            value = self._legacy_delivery_value(kind)
            authority = value["authority"]
            listing = authority["listing"]
            listing["pipeline"].append(copy.deepcopy(listing["pipeline"][0]))
            resign_listing(listing, self.data["seeds"]["seller"])
            value["bundle"]["listingRef"]["contentHash"] = R.listing_hash(listing)
            value["bundle"]["outcome"] = "aborted-by-self"
            if kind == "fault":
                value["bundle"]["faultedParty"] = value["bundle"]["anchoredByRole"]
                self._resign_bundle_and_pointer(value)
            else:
                self._resign_released(value, kind)
            reason = "legacy delivery evidence cannot satisfy a repeated delivery invocation"
            with self.subTest(kind=kind, case="pipeline-repeats-kind"):
                self.assertEqual(("fail", reason), self._reconcile_pair(value))
                self.assertEqual(("fail", reason), self._current_use(value))
                self.assertEqual(("fail", reason), self._historical_current_use(value))
                if kind == "fault":
                    self.assertEqual(
                        ("fail", reason),
                        R._validate_current_fab_delivery_admission(
                            value["bundle"], authority, self.pubkeys
                        ),
                    )
        # The legacy artifact closure is enforced, not just the address.
        for kind in ("legacy", "fault"):
            value = self._legacy_delivery_value(
                kind,
                mutate=lambda record: record.__setitem__(
                    "deliverableContentHash", "ab" * 32
                ),
            )
            with self.subTest(kind=kind, case="legacy-closure-contradiction"):
                self.assertEqual("fail", self._reconcile(value)["decision"])
                self.assertEqual("fail", self._current_use(value)[0])
                self.assertEqual("fail", self._historical_current_use(value)[0])
        # Both archival lanes reject a legacy record at the PDE-2 address.
        def archival_lanes(source):
            args = (
                source["bundle"], source["listing"], self.pubkeys,
                source["referenceValidationByCanonicalRef"], source["bundleLifecycle"],
                source["sessionExecutionAuthorityByPhaseKey"],
                source["verifiedReceiptByCanonicalRef"],
                source.get("deliveryArtifactAuthorityByPhaseKey"),
                source.get("trustedNativeTransactionObservationsByCanonicalRef"),
            )
            return (
                R.validate_archival_audit_ebfab_disposition(*args)[:2],
                R.validate_legacy_ebfab_disposition(*args)[:2],
            )

        for name in (
            "legacy-storage-completed",
            "legacy-entitlement-completed",
            "legacy-attested-completed",
        ):
            source = copy.deepcopy(self.data["executionAuthorities"][name])
            key = R.canonical(source["bundle"]["settlementEvidence"][0]).decode("utf-8")
            receipt = source["verifiedReceiptByCanonicalRef"][key]
            source["verifiedReceiptByCanonicalRef"][key] = {
                field: receipt[field]
                for field in ("logicalAddress", "nativeAddress", "contentHash", "writer")
            } | {"transaction": "demos:test:legacy-anchor", "nonce": 0}
            legacy_receipt_source = copy.deepcopy(source)
            source = copy.deepcopy(self.data["executionAuthorities"][name])
            audit_baseline, _ = archival_lanes(source)
            _, receipt_baseline = archival_lanes(legacy_receipt_source)
            with self.subTest(archival=name, case="authentic"):
                self.assertEqual("pass", audit_baseline[0], audit_baseline[1])
                self.assertEqual("pass", receipt_baseline[0], receipt_baseline[1])
            for lane_source, lane in ((source, 0), (legacy_receipt_source, 1)):
                phase_key = next(iter(lane_source["sessionExecutionAuthorityByPhaseKey"]))
                address = "dacs4:delivery:%s:%s" % (
                    lane_source["bundle"]["jobId"], phase_key.split(":")[0]
                )
                lane_source["sessionExecutionAuthorityByPhaseKey"][phase_key][
                    "evidenceLogicalAddress"
                ] = address
                lane_source["verifiedReceiptByCanonicalRef"][key]["logicalAddress"] = address
                with self.subTest(archival=name, lane=lane, case="indexed-evidence-address"):
                    self.assertEqual(
                        ("fail", "legacy delivery evidence occupies a current phase-indexed address"),
                        archival_lanes(lane_source)[lane],
                    )

    def _reconcile_pair(self, value):
        result = self._reconcile(value)
        return (result["decision"], result["reason"])

    def test_attestation_bundle_presented_payment_members_are_validated(self):
        # DACS-5 §10.4.3: every presented payment member of a released copy is
        # fully validated, including a failure-only AttestationBundle.
        def as_ordinary(value):
            value["bundle"].pop("faultBundleVersion", None)
            self._resign_released(value, "legacy")
            return value

        control = as_ordinary(self._failed_payment_fixture())
        self.assertEqual("pass", self._reconcile(control)["decision"])
        unavailable = copy.deepcopy(control)
        unavailable["authority"].pop("sessionExecutionAuthorityByPhaseKey")
        self.assertEqual("indeterminate", self._reconcile(unavailable)["decision"])
        for name, mutate, expected in (
            ("wrong-job", lambda record: record.__setitem__("jobId", "01ARZ3NDEKTSV4RRFFQ69G5FZZ"), "fail"),
            ("success-for-fail-row", lambda record: (record.__setitem__("outcome", "success"), record.pop("reason", None)), "error"),
        ):
            value = self._failed_payment_fixture()
            self._replace_payment_record(value, mutate)
            as_ordinary(value)
            with self.subTest(case=name):
                self.assertEqual(expected, self._reconcile(value)["decision"])
                self.assertEqual(expected, self._current_use(value)[0])
        bad_signature = self._failed_payment_fixture()
        ref = bad_signature["bundle"]["settlementEvidence"][0]
        record = bad_signature["authority"]["referenceValidationByCanonicalRef"][
            R.canonical(ref).decode("utf-8")
        ]["record"]
        record["signature"]["value"] = record["signature"]["value"][:-4] + "AAAA"
        as_ordinary(bad_signature)
        self.assertEqual("error", self._reconcile(bad_signature)["decision"])

    def test_non_string_phase_kind_is_error_not_an_exception(self):
        value = self._released_value("repeated-pay-completed", "legacy")
        value["bundle"]["phaseSummary"][0]["kind"] = ["pay-dem"]
        self._resign_released(value, "legacy")
        self.assertEqual(
            ("error", "older bundle phaseSummary is malformed"),
            self._reconcile_pair(value),
        )

    def test_top_level_indeterminate_observation_is_typed_indeterminate(self):
        def with_observation(value_or_source, key, *, preserved, logical_address=None):
            receipts = value_or_source["verifiedReceiptByCanonicalRef"]
            prior = copy.deepcopy(receipts[key])
            receipts[key]["observationDisposition"] = "indeterminate"
            receipts[key]["preservedReceiptHash"] = (
                hashlib.sha256(R.canonical(prior)).hexdigest() if preserved else []
            )
            if logical_address is not None:
                receipts[key]["logicalAddress"] = logical_address

        for variant, expected in (("well-formed", "indeterminate"), ("malformed", "error"), ("mis-bound", "fail")):
            value = self._fixture()
            key = R.canonical(value["bundle"]["settlementEvidence"][0]).decode("utf-8")
            with_observation(
                value["authority"], key, preserved=variant != "malformed",
                logical_address="dacs4:delivery:%s:9" % CURRENT_JOB if variant == "mis-bound" else None,
            )
            with self.subTest(variant=variant):
                direct, _ = R._validate_current_fab_delivery_admission(
                    value["bundle"], value["authority"], self.pubkeys
                )
                self.assertEqual(expected, direct)
                resolved = self._resolve(value)
                self.assertFalse(resolved["ok"])
                self.assertEqual(expected, resolved.get("disposition", "fail"))
                self.assertEqual(expected, self._reconcile(value)["decision"])
                self.assertEqual(expected, self._current_use(value)[0])
            source = copy.deepcopy(self.data["executionAuthorities"]["completed-storage-delivery"])
            key = R.canonical(source["bundle"]["settlementEvidence"][0]).decode("utf-8")
            job = source["bundle"]["jobId"]
            with_observation(
                source, key, preserved=variant != "malformed",
                logical_address="dacs4:delivery:%s:9" % job if variant == "mis-bound" else None,
            )
            with self.subTest(variant=variant, family="evidence-bound"):
                disposition, reason, _ = R.validate_ebfab_disposition(
                    source["bundle"], source["listing"], self.pubkeys,
                    source["referenceValidationByCanonicalRef"], source["bundleLifecycle"],
                    source["sessionExecutionAuthorityByPhaseKey"],
                    source["verifiedReceiptByCanonicalRef"],
                    source["deliveryArtifactAuthorityByPhaseKey"],
                    source["trustedNativeTransactionObservationsByCanonicalRef"],
                    legacy_agreement_authority_by_phase_key=source["legacyAgreementAuthorityByPhaseKey"],
                )
                self.assertEqual(expected, disposition, reason)

    def test_delivery_execution_authority_unavailable_versus_malformed(self):
        for label, factory in (
            ("current", self._fixture),
            ("legacy", lambda: self._legacy_delivery_value("fault")),
        ):
            for malformed in ([], "x", 7, {"jobId": []}):
                value = factory()
                value["authority"]["sessionExecutionAuthorityByPhaseKey"][
                    "0:deliver-storage-program"
                ] = malformed
                with self.subTest(delivery=label, execution=malformed):
                    self.assertEqual(
                        ("error", "delivery execution authority is malformed"),
                        R._validate_current_fab_delivery_admission(
                            value["bundle"], value["authority"], self.pubkeys
                        ),
                    )
                    self.assertEqual("error", self._reconcile(value)["decision"])
            value = factory()
            del value["authority"]["sessionExecutionAuthorityByPhaseKey"][
                "0:deliver-storage-program"
            ]
            with self.subTest(delivery=label, execution="absent"):
                self.assertEqual(
                    ("indeterminate", "delivery execution authority is unavailable"),
                    R._validate_current_fab_delivery_admission(
                        value["bundle"], value["authority"], self.pubkeys
                    ),
                )

    def test_pointer_to_non_canonicalizable_bundle_is_error(self):
        for name, mutate in (
            ("unsafe-integer", lambda bundle: bundle.__setitem__("finalisedAt", 2 ** 70)),
            ("lone-surrogate", lambda bundle: bundle["phaseSummary"][0].__setitem__("kind", "\ud800")),
        ):
            value = self._fixture()
            mutate(value["bundle"])
            with self.subTest(case=name):
                resolved = self._resolve(value)
                self.assertFalse(resolved["ok"])
                self.assertEqual("error", resolved["disposition"], resolved["reason"])

    # --- round-3 regressions: current-use scope, AB delivery, ST-8 typing,
    # EBFAB totality, order independence

    def _key(self, ref):
        return R.canonical(ref).decode("utf-8")

    def test_unlisted_payment_records_are_inert_for_current_use(self):
        # F-A: only evidence the copy lists (and its signed rows) can put the
        # job on the CUR-5 hold; anything else in verifier authority is inert.
        source = self.data["executionAuthorities"]["standard-completed"]
        success_key = next(
            key for key, resolution in source["referenceValidationByCanonicalRef"].items()
            if resolution["record"].get("phase") == "pay-dem"
            and resolution["record"].get("outcome") == "success"
        )

        def same_job_signed(value):
            resolution = copy.deepcopy(source["referenceValidationByCanonicalRef"][success_key])
            resolution["record"]["jobId"] = value["bundle"]["jobId"]
            self._resign_payment_record(resolution["record"], signer_role="seller")
            ref = {
                "anchor": {"kind": "storage-program", "locator": "learned-later"},
                "contentHash": R.settlement_evidence_hash(resolution["record"]),
            }
            value["authority"]["referenceValidationByCanonicalRef"][self._key(ref)] = resolution

        def foreign_job(value):
            value["authority"]["referenceValidationByCanonicalRef"][success_key] = (
                copy.deepcopy(source["referenceValidationByCanonicalRef"][success_key])
            )

        def unsigned_bare(value):
            value["authority"]["referenceValidationByCanonicalRef"]["bare"] = {
                "record": {"phase": "pay-dem", "outcome": "success"},
            }

        for kind in ("fault", "legacy"):
            baseline_value = self._released_value("failed-delivery", kind)
            baseline = self._current_use_result(baseline_value)
            with self.subTest(kind=kind, learned="none"):
                self.assertEqual("pass", baseline["decision"], baseline["reason"])
            for name, learn in (
                ("same-job-signed", same_job_signed),
                ("foreign-job", foreign_job),
                ("unsigned-bare", unsigned_bare),
            ):
                value = self._released_value("failed-delivery", kind)
                learn(value)
                result = self._current_use_result(value)
                with self.subTest(kind=kind, learned=name):
                    self.assertEqual(
                        R.bundle_hash(baseline_value["bundle"]), R.bundle_hash(value["bundle"])
                    )
                    self.assertEqual("pass", result["decision"], result["reason"])
                    self.assertEqual(
                        R.bundle_hash(baseline["bundle"]), R.bundle_hash(result["bundle"])
                    )
                    self.assertEqual(baseline.get("roleOfParty"), result.get("roleOfParty"))
                    self.assertEqual(baseline.get("pairFaults"), result.get("pairFaults"))
                    self.assertEqual("pass", self._direct(value, kind)[0])
                    self.assertEqual("pass", self._reconcile(value)["decision"])
            # CUR-5 still holds a copy that itself lists a successful payment.
            listed = self._released_value("standard-completed", kind)
            decision, reason = self._current_use(listed)
            with self.subTest(kind=kind, learned="listed-success"):
                self.assertEqual("indeterminate", decision, reason)
                self.assertIn("stronger finality", reason)

    def test_attestation_bundle_without_current_delivery_evidence_is_indeterminate(self):
        # F-B: PDE-8 applies once a bundle references current DeliveryEvidence;
        # the FAB-only delivery gate has no AttestationBundle counterpart.
        def keep_only(value, keep):
            bundle = value["bundle"]
            resolutions = value["authority"]["referenceValidationByCanonicalRef"]
            bundle["settlementEvidence"] = [
                ref for ref in bundle["settlementEvidence"]
                if keep(resolutions[self._key(ref)]["record"]["phase"])
            ]
            for entry in bundle["phaseSummary"]:
                if not keep(entry["kind"]):
                    entry.pop("attestationRef", None)

        for label, keep in (
            ("no-members", lambda phase: False),
            ("payment-member-only", lambda phase: phase.startswith("pay-")),
        ):
            for kind, expected in (
                ("legacy", ("indeterminate", "ordinary bundle delivery row lacks current DeliveryEvidence")),
                ("fault", ("fail", "FAB DeliveryEvidence is not the exact delivery invocation set")),
            ):
                value = self._released_value("standard-completed", kind)
                keep_only(value, keep)
                self._resign_released(value, kind)
                value["authority"]["legacyAgreementAuthorityByPhaseKey"] = (
                    refreshed_laa_phase_carriers(value["authority"])
                    if label == "payment-member-only" else {}
                )
                with self.subTest(kind=kind, case=label):
                    self.assertEqual(expected, self._direct(value, kind))
                    self.assertEqual(expected, self._reconcile_pair(value))
                    self.assertEqual(expected, self._current_use(value))
        # Once a copy presents current DeliveryEvidence, PDE-8's one-to-one
        # mapping applies to AttestationBundle and FAB alike.
        for kind in ("legacy", "fault"):
            value = self._released_value("repeated-self-signed-distinct-proof-completed", kind)
            bundle = value["bundle"]
            dropped = bundle["settlementEvidence"].pop()
            for entry in bundle["phaseSummary"]:
                if entry.get("attestationRef") == dropped:
                    entry.pop("attestationRef")
            self._resign_released(value, kind)
            value["authority"]["legacyAgreementAuthorityByPhaseKey"] = (
                refreshed_laa_phase_carriers(value["authority"])
            )
            with self.subTest(kind=kind, case="one-current-delivery-of-two"):
                self.assertEqual(
                    ("fail", "FAB DeliveryEvidence is not the exact delivery invocation set"),
                    self._direct(value, kind),
                )
                self.assertEqual("fail", self._reconcile(value)["decision"])

    def _st8_resolved_value(self, kind):
        """single-htlc-completed as a released copy, rebound to a ULID job."""
        value = self._released_value("single-htlc-completed", kind)
        authority, bundle = value["authority"], value["bundle"]
        old_job = bundle["jobId"]
        resolutions = authority["referenceValidationByCanonicalRef"]
        receipts = authority["verifiedReceiptByCanonicalRef"]
        successor_ref = bundle["settlementEvidence"][0]
        successor = resolutions.pop(self._key(successor_ref))
        successor_receipt = receipts.pop(self._key(successor_ref))
        interim_ref = successor["record"]["supersedesEvidenceRef"]
        interim = resolutions.pop(self._key(interim_ref))
        interim_receipt = receipts.pop(self._key(interim_ref))
        interim["record"]["jobId"] = CURRENT_JOB
        self._resign_payment_record(interim["record"])
        new_interim_ref = copy.deepcopy(interim_ref)
        new_interim_ref["contentHash"] = R.settlement_evidence_hash(interim["record"])
        interim_receipt["contentHash"] = new_interim_ref["contentHash"]
        interim_receipt["logicalAddress"] = interim_receipt["logicalAddress"].replace(
            old_job, CURRENT_JOB
        )
        resolutions[self._key(new_interim_ref)] = interim
        receipts[self._key(new_interim_ref)] = interim_receipt
        successor["record"]["jobId"] = CURRENT_JOB
        successor["record"]["supersedesEvidenceRef"] = new_interim_ref
        self._resign_payment_record(successor["record"])
        new_successor_ref = copy.deepcopy(successor_ref)
        new_successor_ref["contentHash"] = R.settlement_evidence_hash(successor["record"])
        successor_receipt["contentHash"] = new_successor_ref["contentHash"]
        successor_receipt["logicalAddress"] = successor_receipt["logicalAddress"].replace(
            old_job, CURRENT_JOB
        )
        resolutions[self._key(new_successor_ref)] = successor
        receipts[self._key(new_successor_ref)] = successor_receipt
        bundle["settlementEvidence"] = [new_successor_ref]
        for entry in bundle["phaseSummary"]:
            if entry.get("attestationRef") == successor_ref:
                entry["attestationRef"] = copy.deepcopy(new_successor_ref)
        for execution in authority["sessionExecutionAuthorityByPhaseKey"].values():
            execution["jobId"] = CURRENT_JOB
        bundle["jobId"] = CURRENT_JOB
        self._resign_released(value, kind)
        signer = next(
            party["primaryClaim"] for party in bundle["parties"]
            if party["role"] == value["role"]
        )
        value["trusted"] = R.trusted_profile_context(CURRENT_JOB, signer, role=value["role"])
        value["keys"] = R.trusted_verification_keys(copy.deepcopy(self.pubkeys))
        authority["legacyAgreementAuthorityByPhaseKey"] = refreshed_laa_phase_carriers(authority)
        value["interimKey"] = self._key(new_interim_ref)
        return value

    def test_released_copies_join_present_agreement_ref_to_laa_agreement(self):
        """AB/FAB direct, pointer, and reconcile share the §10.4.3 agreement join."""
        def rebind(value, kind, content_hash, *, identity_only=False):
            value["bundle"]["agreementRef"] = {
                "anchor": {
                    "kind": "storage-program",
                    "locator": "dacs3:agreement:" + CURRENT_JOB,
                },
                "contentHash": content_hash,
            }
            self._resign_released(value, kind)
            authority = value["authority"]
            if identity_only:
                for carrier in authority["legacyAgreementAuthorityByPhaseKey"].values():
                    carrier["laa"]["agreement"].update({
                        "artifact": "identity-bound",
                        "ibhVerified": True,
                        "pbVerified": False,
                    })
            authority["legacyAgreementAuthorityByPhaseKey"] = (
                refreshed_laa_phase_carriers(authority)
            )
            return value

        for kind in ("legacy", "fault"):
            probe = self._st8_resolved_value(kind)
            joined = next(iter(
                probe["authority"]["legacyAgreementAuthorityByPhaseKey"].values()
            ))["laa"]["agreement"]["contentHash"]
            for name, content_hash, identity_only, expected, reason in (
                ("joined", joined, False, "pass", None),
                ("valid-unrelated-agreement", "c" * 64, False, "fail",
                 "does not bind the signed bundle agreementRef"),
                ("identity-only-agreement", joined, True, "fail",
                 "current payment agreement lacks payee binding"),
            ):
                value = rebind(
                    self._st8_resolved_value(kind), kind, content_hash,
                    identity_only=identity_only,
                )
                with self.subTest(kind=kind, case=name):
                    direct = self._direct(value, kind)
                    self.assertEqual(expected, direct[0], direct[1])
                    if reason is not None:
                        self.assertIn(reason, direct[1])
                    reconciled = self._reconcile(value)
                    self.assertEqual(expected, reconciled["decision"], reconciled["reason"])
                    if kind == "fault":
                        resolved = self._resolve(value)
                        self.assertEqual(expected == "pass", resolved["ok"], resolved["reason"])
                        if expected != "pass":
                            self.assertEqual(expected, resolved["disposition"])

    def test_released_pending_payment_receipt_keeps_its_own_contradictions(self):
        """A presented payment's receipt outage defers only receipt checks."""
        def released(kind, *, mismatch=False, pending=None, foreign=False):
            value = self._released_value("standard-completed", kind)
            authority = value["authority"]
            joined = next(iter(
                authority["legacyAgreementAuthorityByPhaseKey"].values()
            ))["laa"]["agreement"]["contentHash"]
            value["bundle"]["agreementRef"] = {
                "anchor": {
                    "kind": "storage-program",
                    "locator": "dacs3:agreement:" + value["bundle"]["jobId"],
                },
                "contentHash": "d" * 64 if mismatch else joined,
            }
            self._resign_released(value, kind)
            authority["legacyAgreementAuthorityByPhaseKey"] = (
                refreshed_laa_phase_carriers(authority)
            )
            payment = next(
                key for key, resolution in authority["referenceValidationByCanonicalRef"].items()
                if resolution["record"]["phase"] == "pay-dem"
            )
            if foreign:
                authority["sessionExecutionAuthorityByPhaseKey"]["2:pay-dem"][
                    "phaseOrchestrator"
                ] = "did:demos:buyer"
            receipts = authority["verifiedReceiptByCanonicalRef"]
            if pending == "removed":
                del receipts[payment]
            elif pending == "observation":
                prior = copy.deepcopy(receipts[payment])
                receipts[payment].update({
                    "observationDisposition": "indeterminate",
                    "preservedReceiptHash": hashlib.sha256(R.canonical(prior)).hexdigest(),
                    "observedAt": prior["observedAt"] + 1000,
                })
            return value

        for kind in ("fault", "legacy"):
            for label, kwargs, expected in (
                ("joined", {}, "pass"),
                ("joined, receipt removed", {"pending": "removed"}, "indeterminate"),
                ("joined, receipt observation", {"pending": "observation"}, "indeterminate"),
                ("mismatched agreementRef, receipt removed",
                 {"mismatch": True, "pending": "removed"}, "fail"),
                ("mismatched agreementRef, receipt observation",
                 {"mismatch": True, "pending": "observation"}, "fail"),
                ("another orchestrator, receipt removed",
                 {"foreign": True, "pending": "removed"}, "fail"),
            ):
                value = released(kind, **kwargs)
                with self.subTest(kind=kind, case=label):
                    direct = self._direct(value, kind)
                    self.assertEqual(expected, direct[0], direct[1])
                    self.assertEqual(expected, self._reconcile(value)["decision"])
        # The FAB pointer consumer reaches the same released gate.
        for label, foreign, expected in (
            ("genuine, receipt removed", False, "indeterminate"),
            ("another orchestrator, receipt removed", True, "fail"),
        ):
            value = self._failed_payment_fixture()
            authority = value["authority"]
            if foreign:
                authority["sessionExecutionAuthorityByPhaseKey"]["2:pay-cross-chain-htlc"][
                    "phaseOrchestrator"
                ] = "did:demos:buyer"
            del authority["verifiedReceiptByCanonicalRef"][
                self._key(value["bundle"]["settlementEvidence"][0])
            ]
            with self.subTest(path="pointer", case=label):
                resolved = self._resolve(value)
                self.assertFalse(resolved["ok"])
                self.assertEqual(expected, resolved["disposition"], resolved["reason"])

    def _receipt_state(self, value, ref_key, state):
        receipts = value["authority"]["verifiedReceiptByCanonicalRef"]
        if state == "absent":
            del receipts[ref_key]
        elif state == "observation":
            prior = copy.deepcopy(receipts[ref_key])
            receipts[ref_key].update({
                "observationDisposition": "indeterminate",
                "preservedReceiptHash": hashlib.sha256(R.canonical(prior)).hexdigest(),
                "observedAt": prior["observedAt"] + 1000,
            })
        return value

    def test_released_payment_verdict_is_independent_of_receipt_state(self):
        """Absent or observed receipts defer only receipt checks (released gate)."""
        def payment_key(value):
            return next(
                key for key, resolution
                in value["authority"]["referenceValidationByCanonicalRef"].items()
                if resolution["record"]["phase"] == "pay-dem"
            )

        def failure_on_ok_row(kind):
            def build():
                value = self._released_value("standard-completed", kind)

                def to_failure(record):
                    record["outcome"] = "failure"
                    record["reason"] = "insufficient-funds"
                    for field in ("paymentTxRefs", "paymentAmount", "paymentFee",
                                  "settlementFinality"):
                        record.pop(field, None)

                replace_top_record(value["authority"], "pay-dem", to_failure,
                                   self.data["seeds"])
                self._resign_released(value, kind)
                return value, payment_key(value)
            return build

        def failed_payment(mutate):
            def build():
                value = self._failed_payment_fixture()
                mutate(value)
                return value, self._key(value["bundle"]["settlementEvidence"][0])
            return build

        def omit_terminal_row(value):
            value["bundle"]["phaseSummary"] = value["bundle"]["phaseSummary"][:-1]
            self._resign_bundle_and_pointer(value)

        def wrong_interim_reason(value):
            self._replace_payment_record(
                value, lambda record: record.__setitem__("reason", "counterparty-timeout")
            )

        def entry_field(field, value_):
            def build():
                value = self._released_value("standard-completed", "fault")
                authority = value["authority"]
                key = payment_key(value)
                authority["sessionExecutionAuthorityByPhaseKey"]["2:pay-dem"][field] = value_
                if field == "railId":
                    from urllib.parse import quote
                    authority["verifiedReceiptByCanonicalRef"][key]["logicalAddress"] = (
                        "dacs4:payment:%s:%s:2" % (
                            value["bundle"]["jobId"], quote(value_, safe="-._~")
                        )
                    )
                authority["legacyAgreementAuthorityByPhaseKey"] = (
                    refreshed_laa_phase_carriers(authority)
                )
                return value, key
            return build

        cases = (
            ("fault", "failure record on an ok row", failure_on_ok_row("fault"),
             ("fail", "fail", "fail")),
            ("legacy", "failure record on an ok row", failure_on_ok_row("legacy"),
             ("fail", "fail", "fail")),
            ("fault", "terminal row omitted beside a presented payment",
             failed_payment(omit_terminal_row), ("fail", "fail", "fail")),
            ("fault", "expired interim with the wrong reason",
             failed_payment(wrong_interim_reason), ("fail", "fail", "fail")),
            ("fault", "entry pins no nonce (null)", entry_field("anchorNonce", None),
             ("pass", "indeterminate", "indeterminate")),
            ("fault", "entry rail outside the canonical identity form",
             entry_field("railId", "rail-e\u0301"), ("pass", "indeterminate", "indeterminate")),
        )
        for kind, label, build, expected in cases:
            observed = []
            for state in ("established", "absent", "observation"):
                value, ref_key = build()
                self._receipt_state(value, ref_key, state)
                observed.append(R._validate_current_fab_delivery_admission(
                    value["bundle"], value["authority"], self.pubkeys,
                    **({"ordinary_current": True} if kind == "legacy" else {}),
                )[0])
            with self.subTest(kind=kind, case=label):
                self.assertEqual(expected, tuple(observed))

    def test_released_payment_checks_outrank_other_outages(self):
        """Row, lifecycle, edge and LAA checks decide beside unrelated outages."""
        def mismatch_agreement(value, kind):
            value["bundle"]["agreementRef"] = {
                "anchor": {
                    "kind": "storage-program",
                    "locator": "dacs3:agreement:" + value["bundle"]["jobId"],
                },
                "contentHash": "d" * 64,
            }
            self._resign_released(value, kind)
            value["authority"]["legacyAgreementAuthorityByPhaseKey"] = (
                refreshed_laa_phase_carriers(value["authority"])
            )

        def to_failure(record):
            record["outcome"] = "failure"
            record["reason"] = "insufficient-funds"
            for field in ("paymentTxRefs", "paymentAmount", "paymentFee",
                          "settlementFinality"):
                record.pop(field, None)

        def payment(*mutations):
            def build(kind):
                value = self._released_value("standard-completed", kind)
                authority = value["authority"]
                for mutate in mutations:
                    mutate(value, kind)
                key = next(
                    key for key, resolution
                    in authority["referenceValidationByCanonicalRef"].items()
                    if resolution["record"]["phase"] == "pay-dem"
                )
                return value, key
            return build

        def successor(*mutations):
            def build(kind):
                value = self._st8_resolved_value(kind)
                for mutate in mutations:
                    mutate(value, kind)
                return value, self._key(value["bundle"]["settlementEvidence"][0])
            return build

        def without_entry(value, kind):
            del value["authority"]["sessionExecutionAuthorityByPhaseKey"]["2:pay-dem"]

        def failure_on_ok_row(value, kind):
            replace_top_record(value["authority"], "pay-dem", to_failure, self.data["seeds"])
            self._resign_released(value, kind)

        def member_lifecycle(lifecycle):
            def mutate(value, kind):
                resolutions = value["authority"]["referenceValidationByCanonicalRef"]
                for resolution in resolutions.values():
                    if resolution["record"]["phase"] == "pay-dem":
                        resolution["lifecycle"] = (
                            dict(resolution["lifecycle"], **lifecycle)
                            if isinstance(lifecycle, dict) else lifecycle
                        )
            return mutate

        def interim_not_finalized(value, kind):
            resolution = value["authority"]["referenceValidationByCanonicalRef"][
                value["interimKey"]
            ]
            resolution["lifecycle"] = dict(resolution["lifecycle"], state="included")

        def without_interim(value, kind):
            del value["authority"]["referenceValidationByCanonicalRef"][value["interimKey"]]

        def other_receipt_writer(value, kind):
            for carrier in value["authority"]["legacyAgreementAuthorityByPhaseKey"].values():
                carrier["binding"]["receiptWriter"] = "did:demos:buyer"

        def float_invocation(value, kind):
            value["authority"]["sessionExecutionAuthorityByPhaseKey"]["2:pay-dem"][
                "phaseIndex"
            ] = 2.0

        fail, error, pending = ("fail",) * 3, ("error",) * 3, ("indeterminate",) * 3
        cases = (
            ("row execution authority unavailable", payment(without_entry), pending),
            ("agreementRef mismatch, row execution authority unavailable",
             payment(mismatch_agreement, without_entry), fail),
            ("failure record on an ok row, row execution authority unavailable",
             payment(failure_on_ok_row, without_entry), fail),
            ("member lifecycle not finalized on a completed copy",
             payment(member_lifecycle({"state": "included"})), fail),
            ("member lifecycle of the wrong JSON type",
             payment(member_lifecycle("not-an-object")), error),
            ("carrier receipt writer is not the evidence signer",
             payment(other_receipt_writer), fail),
            ("non-integer row invocation", payment(float_invocation), error),
            ("ST-8 successor", successor(), ("pass", "indeterminate", "indeterminate")),
            ("ST-8 interim dependency not finalized",
             successor(interim_not_finalized), fail),
            ("ST-8 interim authority unavailable", successor(without_interim), pending),
            ("agreementRef mismatch, ST-8 interim authority unavailable",
             successor(mismatch_agreement, without_interim), fail),
        )
        for kind in ("fault", "legacy"):
            for label, build, expected in cases:
                observed = []
                for state in ("established", "absent", "observation"):
                    value, ref_key = build(kind)
                    self._receipt_state(value, ref_key, state)
                    observed.append(R._validate_current_fab_delivery_admission(
                        value["bundle"], value["authority"], self.pubkeys,
                        **({"ordinary_current": True} if kind == "legacy" else {}),
                    )[0])
                with self.subTest(kind=kind, case=label):
                    self.assertEqual(expected, tuple(observed))

    def test_ebfab_pointer_joins_present_agreement_ref_to_laa_agreement(self):
        for name, unrelated, expected in (
            ("joined", False, "pass"), ("valid-unrelated-agreement", True, "fail"),
        ):
            authority, pointer, signer, role = self._ebfab_pointer_case()
            bundle = authority["bundle"]
            joined = next(iter(
                authority["legacyAgreementAuthorityByPhaseKey"].values()
            ))["laa"]["agreement"]["contentHash"]
            bundle["agreementRef"] = {
                "anchor": {
                    "kind": "storage-program",
                    "locator": "dacs3:agreement:" + CURRENT_JOB,
                },
                "contentHash": "c" * 64 if unrelated else joined,
            }
            resign_ebfab(bundle, self.data["seeds"])
            authority["legacyAgreementAuthorityByPhaseKey"] = (
                refreshed_laa_phase_carriers(authority)
            )
            pointer["fullBundleContentHash"] = R.bundle_hash(bundle)
            pointer["signature"]["value"] = ""
            pointer["signature"]["value"] = self._sign(
                role, R.EVIDENCE_BOUND_FAULT_POINTER_DOMAIN, R.pointer_hash(pointer)
            )
            resolved = R.resolve_absolute_fault_pointer(
                pointer, bundle,
                pubkeys=R.trusted_verification_keys(copy.deepcopy(self.pubkeys)),
                ebfab_authority=authority,
                trusted_contexts=R.trusted_profile_context(CURRENT_JOB, signer, role=role),
                expected_jobid=CURRENT_JOB, expected_role=role,
            )
            with self.subTest(case=name):
                self.assertEqual(expected == "pass", resolved["ok"], resolved["reason"])
                if expected != "pass":
                    self.assertEqual(expected, resolved["disposition"], resolved["reason"])
                    self.assertIn("agreementRef", resolved["reason"])

    def test_released_st8_interim_authority_is_four_state_typed(self):
        # F-C: an exact authentic :resolved success whose interim authority is
        # unavailable is indeterminate; malformed authority is error; real
        # contradictions stay fail. EBFAB keeps its stricter behavior.
        def drop_resolution(a, k): a["referenceValidationByCanonicalRef"].pop(k)
        def drop_receipt(a, k): a["verifiedReceiptByCanonicalRef"].pop(k)
        def drop_lifecycle(a, k): a["referenceValidationByCanonicalRef"][k].pop("lifecycle")
        def drop_record(a, k): a["referenceValidationByCanonicalRef"][k].pop("record")
        def bad_resolution(a, k): a["referenceValidationByCanonicalRef"][k] = []
        def bad_receipt(a, k): a["verifiedReceiptByCanonicalRef"][k] = []
        def bad_lifecycle(a, k): a["referenceValidationByCanonicalRef"][k]["lifecycle"] = []
        def bad_record_shape(a, k): a["referenceValidationByCanonicalRef"][k]["record"]["phase"] = []

        def wrong_pc2_address(a, k):
            a["verifiedReceiptByCanonicalRef"][k]["logicalAddress"] = (
                "dacs4:payment:%s:test-rail:9" % CURRENT_JOB
            )

        def interim_other_reason(a, k):
            a["referenceValidationByCanonicalRef"][k]["record"]["reason"] = "operator-declined"

        cases = (
            ("resolution-missing", drop_resolution, "indeterminate"),
            ("receipt-missing", drop_receipt, "indeterminate"),
            ("lifecycle-missing", drop_lifecycle, "indeterminate"),
            ("record-missing", drop_record, "indeterminate"),
            ("resolution-malformed", bad_resolution, "error"),
            ("receipt-malformed", bad_receipt, "error"),
            ("lifecycle-malformed", bad_lifecycle, "error"),
            ("record-shape-malformed", bad_record_shape, "error"),
            ("receipt-at-wrong-pc2-address", wrong_pc2_address, "fail"),
            ("interim-record-mismatch", interim_other_reason, "fail"),
        )
        for kind in ("legacy", "fault"):
            control = self._st8_resolved_value(kind)
            with self.subTest(kind=kind, case="control"):
                self.assertEqual("pass", self._direct(control, kind)[0])
                self.assertEqual("pass", self._reconcile(control)["decision"])
                if kind == "fault":
                    self.assertTrue(self._resolve(control)["ok"])
            for name, mutate, expected in cases:
                value = self._st8_resolved_value(kind)
                mutate(value["authority"], value["interimKey"])
                with self.subTest(kind=kind, case=name):
                    direct = self._direct(value, kind)
                    self.assertEqual(expected, direct[0], direct[1])
                    self.assertEqual(expected, self._reconcile(value)["decision"])
                    if kind == "fault":
                        resolved = self._resolve(value)
                        self.assertFalse(resolved["ok"])
                        self.assertEqual(expected, resolved["disposition"], resolved["reason"])
                    # CUR-5 holds any listed success, so current-use is never pass.
                    current_use = self._current_use(value)[0]
                    self.assertEqual(
                        "indeterminate" if expected == "indeterminate" else expected,
                        current_use,
                    )
            # The top-level receipt keeps its own typing, independent of the interim.
            top = self._st8_resolved_value(kind)
            top["authority"]["verifiedReceiptByCanonicalRef"].pop(
                self._key(top["bundle"]["settlementEvidence"][0])
            )
            with self.subTest(kind=kind, case="top-level-receipt-missing"):
                self.assertEqual("indeterminate", self._direct(top, kind)[0])
        # EBFAB behavior is unchanged by the released-copy typing.
        source = copy.deepcopy(self.data["executionAuthorities"]["single-htlc-completed"])
        successor = source["referenceValidationByCanonicalRef"][
            self._key(source["bundle"]["settlementEvidence"][0])
        ]["record"]
        source["referenceValidationByCanonicalRef"].pop(
            self._key(successor["supersedesEvidenceRef"])
        )
        disposition, reason, _ = R.validate_ebfab_disposition(
            source["bundle"], source["listing"], self.pubkeys,
            source["referenceValidationByCanonicalRef"], source["bundleLifecycle"],
            source["sessionExecutionAuthorityByPhaseKey"], source["verifiedReceiptByCanonicalRef"],
            source["deliveryArtifactAuthorityByPhaseKey"],
            source["trustedNativeTransactionObservationsByCanonicalRef"],
            legacy_agreement_authority_by_phase_key=source["legacyAgreementAuthorityByPhaseKey"],
        )
        self.assertEqual(
            ("fail", "ST-8 interim record lacks authenticated resolution"),
            (disposition, reason),
        )

    def _ebfab_pointer_case(self):
        """A current EBFAB pointer case on a ULID job (single-htlc-direct-completed)."""
        authority = copy.deepcopy(self.data["executionAuthorities"]["single-htlc-direct-completed"])
        authority["bundle"]["jobId"] = CURRENT_JOB
        replace_top_record(
            authority, "pay-cross-chain-htlc",
            lambda record: record.__setitem__("jobId", CURRENT_JOB), self.data["seeds"],
        )
        execution = authority["sessionExecutionAuthorityByPhaseKey"]["2:pay-cross-chain-htlc"]
        execution["jobId"] = CURRENT_JOB
        ref = authority["bundle"]["phaseSummary"][2]["attestationRef"]
        authority["verifiedReceiptByCanonicalRef"][self._key(ref)]["logicalAddress"] = (
            "dacs4:payment:%s:%s:2" % (CURRENT_JOB, execution["railId"])
        )
        resign_ebfab(authority["bundle"], self.data["seeds"])
        authority["legacyAgreementAuthorityByPhaseKey"] = refreshed_laa_phase_carriers(authority)
        bundle = authority["bundle"]
        role = bundle["anchoredByRole"]
        signer = next(p["primaryClaim"] for p in bundle["parties"] if p["role"] == role)
        pointer = {
            "evidenceBoundFaultBundleVersion": "1",
            "pointerKind": "extended",
            "fullBundleUrl": "https://fixtures.example/ebfab-listing-totality",
            "fullBundleContentHash": R.bundle_hash(bundle),
            "signature": {"signer": signer, "algorithm": "ed25519", "value": ""},
        }
        pointer["signature"]["value"] = self._sign(
            role, R.EVIDENCE_BOUND_FAULT_POINTER_DOMAIN, R.pointer_hash(pointer)
        )
        return authority, pointer, signer, role

    def test_ebfab_malformed_listing_is_typed_error_not_an_exception(self):
        # F-D: producer-authored Listing values JCS cannot hash are malformed.
        mutations = (
            ("control", lambda listing: None, "pass"),
            ("unsafe-integer", lambda listing: listing.__setitem__("listingVersion", 2 ** 53), "error"),
            ("lone-surrogate", lambda listing: listing["pipeline"][0].__setitem__("kind", "\ud800"), "error"),
        )
        for name, mutate, expected in mutations:
            source = copy.deepcopy(self.data["executionAuthorities"]["standard-completed"])
            mutate(source["listing"])
            bundle = source["bundle"]
            role = bundle["anchoredByRole"]
            other = "seller" if role == "buyer" else "buyer"
            writer = next(p["primaryClaim"] for p in bundle["parties"] if p["role"] == role)
            presence = {
                "bundleHash": R.bundle_hash(bundle),
                "nativeAddress": "dacs5:bundle:%s:%s" % (bundle["jobId"], role),
                "writer": writer,
            }
            trust = {
                "copyPresenceByJobRole": {bundle["jobId"] + ":" + role: copy.deepcopy(presence)},
                "copyDispositionByJobRole": {bundle["jobId"] + ":" + other: "absent"},
            }
            entries = [
                {
                    "bundle": bundle, "expectedJobId": bundle["jobId"], "expectedRole": role,
                    "copyPresence": presence, "authority": source,
                    "evidenceReceiptContract": "current",
                },
                {"disposition": "absent", "expectedJobId": bundle["jobId"], "expectedRole": other},
            ]
            with self.subTest(path="reconcile", case=name):
                result = R.reconcile_authenticated_finality_copies(entries, self.pubkeys, trust)
                self.assertEqual(expected, result["decision"], result["reason"])
            # The boundary sits at the public entry points, so direct callers
            # get the same typed result as reconciliation and pointers.
            args = (
                bundle, source["listing"], self.pubkeys,
                source["referenceValidationByCanonicalRef"], source["bundleLifecycle"],
                source["sessionExecutionAuthorityByPhaseKey"],
                source["verifiedReceiptByCanonicalRef"],
                source["deliveryArtifactAuthorityByPhaseKey"],
                source["trustedNativeTransactionObservationsByCanonicalRef"],
            )
            laa = {
                "legacy_agreement_authority_by_phase_key":
                    source["legacyAgreementAuthorityByPhaseKey"],
            }
            with self.subTest(path="direct-disposition", case=name):
                disposition, reason, _ = R.validate_ebfab_disposition(*args, **laa)
                self.assertEqual(expected, disposition, reason)
            with self.subTest(path="direct-boolean", case=name):
                ok, reason, _ = R.validate_ebfab(*args, **laa)
                self.assertEqual(expected == "pass", ok, reason)
                if expected != "pass":
                    self.assertEqual(expected, getattr(reason, "disposition", "fail"), reason)
            authority, pointer, signer, role = self._ebfab_pointer_case()
            mutate(authority["listing"])
            with self.subTest(path="pointer", case=name):
                resolved = R.resolve_absolute_fault_pointer(
                    pointer, authority["bundle"],
                    pubkeys=R.trusted_verification_keys(copy.deepcopy(self.pubkeys)),
                    ebfab_authority=authority,
                    trusted_contexts=R.trusted_profile_context(CURRENT_JOB, signer, role=role),
                    expected_jobid=CURRENT_JOB, expected_role=role,
                )
                if expected == "pass":
                    self.assertTrue(resolved["ok"], resolved["reason"])
                else:
                    self.assertFalse(resolved["ok"])
                    self.assertEqual(expected, resolved["disposition"], resolved["reason"])

    def test_released_gate_verdict_is_independent_of_member_order(self):
        # F-E: deferred outages never pre-empt a later deterministic result,
        # and error outranks fail regardless of array order.
        def build(kind, order, payment_mutation, delivery_mutation):
            value = self._released_value("standard-completed", kind)
            authority, bundle = value["authority"], value["bundle"]
            resolutions = authority["referenceValidationByCanonicalRef"]
            payment = next(
                ref for ref in bundle["settlementEvidence"]
                if resolutions[self._key(ref)]["record"]["phase"] == "pay-dem"
            )
            delivery = next(ref for ref in bundle["settlementEvidence"] if ref is not payment)
            payment_mutation(authority, self._key(payment))
            delivery_mutation(authority, self._key(delivery))
            bundle["settlementEvidence"] = (
                [payment, delivery] if order == "payment-first" else [delivery, payment]
            )
            self._resign_released(value, kind)
            if payment_mutation is not drop_laa:
                authority["legacyAgreementAuthorityByPhaseKey"] = (
                    refreshed_laa_phase_carriers(authority)
                )
            else:
                authority["legacyAgreementAuthorityByPhaseKey"] = {}
            return value

        def no_change(a, k): pass
        def drop_lifecycle(a, k): a["referenceValidationByCanonicalRef"][k].pop("lifecycle")
        def drop_laa(a, k): pass
        def malformed_lifecycle(a, k): a["referenceValidationByCanonicalRef"][k]["lifecycle"] = []

        def st11_contradiction(a, k):
            a["referenceValidationByCanonicalRef"][k]["lifecycle"] = {
                "state": "included", "independentlyResolvable": True,
            }
            a["verifiedReceiptByCanonicalRef"][k]["state"] = "included"

        cases = (
            ("lifecycle-outage+contradiction", drop_lifecycle, st11_contradiction, "fail"),
            ("contradiction+delivery-lifecycle-outage", st11_contradiction, drop_lifecycle, "fail"),
            ("laa-outage+contradiction", drop_laa, st11_contradiction, "fail"),
            ("malformed+contradiction", malformed_lifecycle, st11_contradiction, "error"),
            ("contradiction+malformed", st11_contradiction, malformed_lifecycle, "error"),
            ("lifecycle-outage+delivery-outage", drop_lifecycle, drop_lifecycle, "indeterminate"),
            ("lifecycle-outage-only", drop_lifecycle, no_change, "indeterminate"),
        )
        for kind in ("legacy", "fault"):
            for name, payment_mutation, delivery_mutation, expected in cases:
                verdicts = set()
                for order in ("payment-first", "delivery-first"):
                    value = build(kind, order, payment_mutation, delivery_mutation)
                    direct = self._direct(value, kind)
                    reconciled = self._reconcile(value)
                    with self.subTest(kind=kind, case=name, order=order):
                        self.assertEqual(expected, direct[0], direct[1])
                        self.assertEqual(expected, reconciled["decision"], reconciled["reason"])
                    verdicts.add((direct, reconciled["decision"]))
                with self.subTest(kind=kind, case=name, invariant="same-verdict-and-reason"):
                    self.assertEqual(1, len(verdicts), verdicts)

    def test_lifecycle_outage_does_not_mask_payment_invocation_reuse(self):
        # F-E within one member: a lifecycle outage is deferred, so the same
        # member still registers its invocation and a second authentic record
        # for that invocation fails as reuse, in either array order.
        def build(kind, drop_lifecycle, order):
            value = self._failed_payment_fixture()
            authority, bundle = value["authority"], value["bundle"]
            resolutions = authority["referenceValidationByCanonicalRef"]
            receipts = authority["verifiedReceiptByCanonicalRef"]
            ref = bundle["settlementEvidence"][0]
            twin = copy.deepcopy(resolutions[self._key(ref)])
            twin_receipt = copy.deepcopy(receipts[self._key(ref)])
            twin["record"]["observedAt"] += 1
            self._resign_payment_record(twin["record"])
            twin_ref = copy.deepcopy(ref)
            twin_ref["contentHash"] = R.settlement_evidence_hash(twin["record"])
            twin_receipt["contentHash"] = twin_ref["contentHash"]
            resolutions[self._key(twin_ref)] = twin
            receipts[self._key(twin_ref)] = twin_receipt
            if drop_lifecycle:
                resolutions[self._key(ref)].pop("lifecycle")
            bundle["settlementEvidence"] = (
                [ref, twin_ref] if order == "original-first" else [twin_ref, ref]
            )
            if kind == "legacy":
                bundle.pop("faultBundleVersion")
            self._resign_released(value, kind)
            return value

        for kind in ("legacy", "fault"):
            control = self._failed_payment_fixture()
            if kind == "legacy":
                control["bundle"].pop("faultBundleVersion")
            self._resign_released(control, kind)
            with self.subTest(kind=kind, case="control"):
                self.assertEqual("pass", self._direct(control, kind)[0])
                self.assertEqual("pass", self._reconcile(control)["decision"])
            for drop_lifecycle in (False, True):
                for order in ("original-first", "twin-first"):
                    value = build(kind, drop_lifecycle, order)
                    with self.subTest(kind=kind, lifecycle_outage=drop_lifecycle, order=order):
                        self.assertEqual(
                            ("fail", "FAB reuses a payment invocation"),
                            self._direct(value, kind),
                        )
                        self.assertEqual("fail", self._reconcile(value)["decision"])
                        if kind == "fault":
                            resolved = self._resolve(value)
                            self.assertFalse(resolved["ok"])
                            self.assertEqual("fail", resolved["disposition"], resolved["reason"])

    def _reordered(self, value, kind, order):
        """The same copy with settlementEvidence in the given order, re-signed.

        LAA carriers commit to the exact bundle, member order included, so
        they are refreshed for the new order.
        """
        value = copy.deepcopy(value)
        value["bundle"]["settlementEvidence"] = [copy.deepcopy(ref) for ref in order]
        self._resign_released(value, kind)
        value["authority"]["legacyAgreementAuthorityByPhaseKey"] = (
            refreshed_laa_phase_carriers(value["authority"])
        )
        return value

    def test_member_error_outranks_a_cross_member_conflict_in_any_order(self):
        # Found by permutation fuzzing: two members that share one credential
        # identity conflict, and one of them also has malformed lifecycle
        # authority. That member's own error must win in every array order,
        # not only when it happens to run before the conflict is detected.
        for kind in ("legacy", "fault"):
            base = self._released_value("cross-phase-semantic-credential-reuse", kind)
            refs = base["bundle"]["settlementEvidence"]
            self.assertEqual(2, len(refs))
            with self.subTest(kind=kind, case="control"):
                self.assertEqual("fail", self._direct(base, kind)[0])
            for malformed in refs:
                verdicts = set()
                for order in (refs, list(reversed(refs))):
                    value = self._reordered(base, kind, order)
                    value["authority"]["referenceValidationByCanonicalRef"][
                        self._key(malformed)
                    ]["lifecycle"] = "0" * 64
                    direct = self._direct(value, kind)
                    reconciled = self._reconcile(value)
                    with self.subTest(kind=kind, malformed=malformed["anchor"]["locator"],
                                      first=order[0]["anchor"]["locator"]):
                        self.assertEqual(
                            ("error", "FAB delivery lifecycle authority is malformed"), direct
                        )
                        self.assertEqual("error", reconciled["decision"], reconciled["reason"])
                    verdicts.add(direct)
                self.assertEqual(1, len(verdicts), verdicts)

    def test_conflicting_member_reason_is_independent_of_member_order(self):
        # Two authentic records for one delivery invocation: which member
        # reports the conflict, and why, is fixed by canonical order rather
        # than by where each member sits in the array.
        for kind in ("legacy", "fault"):
            base = self._released_value("standard-completed", kind)
            authority, bundle = base["authority"], base["bundle"]
            resolutions = authority["referenceValidationByCanonicalRef"]
            receipts = authority["verifiedReceiptByCanonicalRef"]
            delivery = next(
                ref for ref in bundle["settlementEvidence"]
                if "deliveryEvidenceVersion" in resolutions[self._key(ref)]["record"]
            )
            twin = copy.deepcopy(resolutions[self._key(delivery)])
            twin_receipt = copy.deepcopy(receipts[self._key(delivery)])
            twin["record"]["observedAt"] += 1
            self._resign_record(
                twin["record"],
                signer_role=twin["record"]["signature"]["signer"].rsplit(":", 1)[1],
            )
            twin_ref = copy.deepcopy(delivery)
            twin_ref["contentHash"] = R.delivery_evidence_hash(twin["record"])
            twin_receipt["contentHash"] = twin_ref["contentHash"]
            resolutions[self._key(twin_ref)] = twin
            receipts[self._key(twin_ref)] = twin_receipt
            members = bundle["settlementEvidence"] + [twin_ref]
            for outage in (False, True):
                verdicts = set()
                for order in (members, list(reversed(members))):
                    value = self._reordered(base, kind, order)
                    if outage:
                        value["authority"]["referenceValidationByCanonicalRef"][
                            self._key(delivery)
                        ].pop("lifecycle")
                    direct = self._direct(value, kind)
                    with self.subTest(kind=kind, outage=outage, first=order[0]["contentHash"]):
                        self.assertEqual("fail", direct[0], direct[1])
                        self.assertEqual("fail", self._reconcile(value)["decision"])
                    verdicts.add(direct)
                with self.subTest(kind=kind, outage=outage, invariant="same-verdict-and-reason"):
                    self.assertEqual(1, len(verdicts), verdicts)

    def _claim(self, role):
        return next(claim for claim in self.pubkeys if claim.endswith(":" + role))

    def _add_ordinary_address_receipt(
        self, value, *, writer_role, nonce=None, key_kind="storage-program",
        key_locator=None, key_hash=None,
    ):
        """Hold one more receipt at the interim's ordinary PC-2 address.

        It commits to other content and is listed nowhere in the copy.
        """
        authority = value["authority"]
        receipts = authority["verifiedReceiptByCanonicalRef"]
        extra = copy.deepcopy(receipts[value["interimKey"]])
        extra["contentHash"] = "ab" * 32
        extra["nativeAddress"] = "stor-" + "cd" * 32
        extra["writer"] = self._claim(writer_role)
        extra["transactionRef"] = {"kind": "tx", "value": "other-ordinary-write"}
        if nonce is not None:
            extra["nonce"] = nonce
        key = {
            "anchor": {"kind": key_kind, "locator": key_locator or extra["nativeAddress"]},
            "contentHash": key_hash or extra["contentHash"],
        }
        receipts[self._key(key)] = extra

    def test_st8_contradiction_requires_the_orchestrators_bound_receipt(self):
        # Round-4 N1: only the phase orchestrator's own SR-2 receipt for this
        # invocation, nonce-bound where pinned and bound to the reference it
        # is held under, can contradict a released ST-8 edge. Any other
        # receipt at the ordinary address is inert, so it can neither reverse
        # an admitted copy nor turn unavailable interim authority into fail.
        def pin_nonce(value):
            execution = value["authority"]["sessionExecutionAuthorityByPhaseKey"][
                "2:pay-cross-chain-htlc"
            ]
            execution["anchorNonce"] = "2"
            value["authority"]["legacyAgreementAuthorityByPhaseKey"] = (
                refreshed_laa_phase_carriers(value["authority"])
            )

        def drop_interim_receipt(value):
            value["authority"]["verifiedReceiptByCanonicalRef"].pop(value["interimKey"])

        inert = "inert"
        cases = (
            ("other-writer", {"writer_role": "buyer"}, None, inert),
            ("orchestrator-key-native-mismatch",
             {"writer_role": "seller", "key_locator": "stor-" + "ef" * 32}, None, inert),
            ("orchestrator-key-hash-mismatch",
             {"writer_role": "seller", "key_hash": "12" * 32}, None, inert),
            ("orchestrator-key-malformed",
             {"writer_role": "seller", "key_kind": "demos-storage"}, None, inert),
            ("orchestrator-wrong-pinned-nonce",
             {"writer_role": "seller", "nonce": "9"}, pin_nonce, inert),
            ("orchestrator-bound", {"writer_role": "seller"}, None, "fail"),
            ("orchestrator-bound-pinned-nonce",
             {"writer_role": "seller", "nonce": "2"}, pin_nonce, "fail"),
        )
        for kind in ("legacy", "fault"):
            for interim_receipt_missing in (False, True):
                for name, receipt, prepare, expected in cases:
                    value = self._st8_resolved_value(kind)
                    if prepare is not None:
                        prepare(value)
                    self._add_ordinary_address_receipt(value, **receipt)
                    if interim_receipt_missing:
                        drop_interim_receipt(value)
                    if expected == inert:
                        # Inert: the same result as without the extra receipt.
                        direct_expected = (
                            "indeterminate" if interim_receipt_missing else "pass"
                        )
                    else:
                        direct_expected = expected
                    with self.subTest(kind=kind, case=name,
                                      interim_receipt_missing=interim_receipt_missing):
                        direct = self._direct(value, kind)
                        self.assertEqual(direct_expected, direct[0], direct[1])
                        self.assertEqual(direct_expected, self._reconcile(value)["decision"])
                        if kind == "fault":
                            resolved = self._resolve(value)
                            if direct_expected == "pass":
                                self.assertTrue(resolved["ok"], resolved["reason"])
                            else:
                                self.assertFalse(resolved["ok"])
                                self.assertEqual(direct_expected, resolved["disposition"])
                        # CUR-5 holds a listed success, so a pass is indeterminate here.
                        self.assertEqual(
                            "indeterminate" if direct_expected == "pass" else direct_expected,
                            self._current_use(value)[0],
                        )
        # EBFAB is unchanged: an unrelated writer's receipt there is inert too.
        source = copy.deepcopy(self.data["executionAuthorities"]["single-htlc-completed"])
        successor = source["referenceValidationByCanonicalRef"][
            self._key(source["bundle"]["settlementEvidence"][0])
        ]["record"]
        value = {"authority": source, "interimKey": self._key(successor["supersedesEvidenceRef"])}
        self._add_ordinary_address_receipt(value, writer_role="buyer")
        disposition, reason, _ = R.validate_ebfab_disposition(
            source["bundle"], source["listing"], self.pubkeys,
            source["referenceValidationByCanonicalRef"], source["bundleLifecycle"],
            source["sessionExecutionAuthorityByPhaseKey"], source["verifiedReceiptByCanonicalRef"],
            source["deliveryArtifactAuthorityByPhaseKey"],
            source["trustedNativeTransactionObservationsByCanonicalRef"],
            legacy_agreement_authority_by_phase_key=source["legacyAgreementAuthorityByPhaseKey"],
        )
        self.assertEqual("pass", disposition, reason)

    def _omit_members(self, value, kind, predicate):
        """Drop presented members (and their row pointers) and re-sign the copy.

        The predicate sees each member's record, or None when unresolved.
        """
        bundle = value["bundle"]
        resolutions = value["authority"]["referenceValidationByCanonicalRef"]
        removed = [
            ref for ref in bundle["settlementEvidence"]
            if predicate(resolutions.get(self._key(ref), {}).get("record"))
        ]
        bundle["settlementEvidence"] = [
            ref for ref in bundle["settlementEvidence"] if ref not in removed
        ]
        for entry in bundle["phaseSummary"]:
            if entry.get("attestationRef") in removed:
                entry.pop("attestationRef")
        self._resign_released(value, kind)
        value["authority"]["legacyAgreementAuthorityByPhaseKey"] = (
            refreshed_laa_phase_carriers(value["authority"])
        )

    def _add_unknown_member(self, value, kind, locator):
        """Present one more member whose resolution the verifier does not hold."""
        value["bundle"]["settlementEvidence"].append({
            "anchor": {"kind": "storage-program", "locator": locator},
            "contentHash": hashlib.sha256(locator.encode("utf-8")).hexdigest(),
        })
        self._resign_released(value, kind)
        value["authority"]["legacyAgreementAuthorityByPhaseKey"] = (
            refreshed_laa_phase_carriers(value["authority"])
        )

    def test_unrelated_outage_does_not_mask_an_incomplete_delivery_set(self):
        # Round-4 N2: an incomplete delivery-invocation set stays fail unless
        # an unresolved member could still fill every missing invocation.
        def is_delivery(record):
            return record["phase"].startswith("deliver-")

        def payment_ref(value):
            resolutions = value["authority"]["referenceValidationByCanonicalRef"]
            return next(
                ref for ref in value["bundle"]["settlementEvidence"]
                if resolutions[self._key(ref)]["record"]["phase"].startswith("pay-")
            )

        payment_outages = {
            "payment-receipt": lambda v: v["authority"]["verifiedReceiptByCanonicalRef"].pop(
                self._key(payment_ref(v))),
            "payment-lifecycle": lambda v: v["authority"]["referenceValidationByCanonicalRef"][
                self._key(payment_ref(v))].pop("lifecycle"),
            "payment-laa-carrier": lambda v: v["authority"].pop(
                "legacyAgreementAuthorityByPhaseKey"),
        }

        def verdicts(value, kind):
            return (
                self._direct(value, kind)[0],
                self._reconcile(value)["decision"],
                self._current_use(value)[0],
            )

        for kind in ("legacy", "fault"):
            for name, outage in payment_outages.items():
                value = self._released_value("standard-completed", kind)
                self._omit_members(value, kind, is_delivery)
                outage(value)
                # An AttestationBundle presenting no current DeliveryEvidence
                # keeps its round-3 indeterminate (F-B); a FAB rejects.
                expected = "indeterminate" if kind == "legacy" else "fail"
                with self.subTest(kind=kind, case="no-delivery+" + name):
                    self.assertEqual((expected,) * 3, verdicts(value, kind))
            twin = "repeated-self-signed-distinct-proof-completed"
            for name in ("lifecycle", "receipt"):
                value = self._released_value(twin, kind)
                self._omit_members(value, kind, lambda record: record.get("phaseIndex") == 1)
                remaining = self._key(value["bundle"]["settlementEvidence"][0])
                if name == "lifecycle":
                    value["authority"]["referenceValidationByCanonicalRef"][remaining].pop(
                        "lifecycle")
                else:
                    value["authority"]["verifiedReceiptByCanonicalRef"].pop(remaining)
                with self.subTest(kind=kind, case="one-of-two-delivered+other-" + name):
                    self.assertEqual(("fail",) * 3, verdicts(value, kind))

            # Controls: a member that could still fill the gap defers it.
            value = self._released_value("standard-completed", kind)
            resolutions = value["authority"]["referenceValidationByCanonicalRef"]
            delivery = next(
                ref for ref in value["bundle"]["settlementEvidence"]
                if is_delivery(resolutions[self._key(ref)]["record"])
            )
            value["authority"]["verifiedReceiptByCanonicalRef"].pop(self._key(delivery))
            with self.subTest(kind=kind, case="delivery-member-receipt-missing"):
                self.assertEqual(("indeterminate",) * 3, verdicts(value, kind))
            legacy = self._legacy_delivery_value(kind)
            legacy["authority"]["verifiedReceiptByCanonicalRef"].pop(
                self._key(legacy["bundle"]["settlementEvidence"][0]))
            with self.subTest(kind=kind, case="legacy-delivery-receipt-missing"):
                self.assertEqual("indeterminate", self._direct(legacy, kind)[0])
                self.assertEqual("indeterminate", self._reconcile(legacy)["decision"])
            value = self._released_value(twin, kind)
            first, second = value["bundle"]["settlementEvidence"]
            value["authority"]["referenceValidationByCanonicalRef"].pop(self._key(second))
            with self.subTest(kind=kind, case="pointer-bound-member-unresolved"):
                self.assertEqual("indeterminate", self._direct(value, kind)[0])
            self._omit_members(value, kind, lambda record: record is not None)
            with self.subTest(kind=kind, case="pointer-bound-member-unresolved+other-omitted"):
                # The unresolved member can fill only the invocation its row
                # pointer names, never the other, omitted one.
                if kind == "fault":
                    self.assertEqual("fail", self._direct(value, kind)[0])

        # Members of unknown identity: each could fill at most one invocation.
        value = self._released_value("standard-completed", "fault")
        self._omit_members(value, "fault", is_delivery)
        self._add_unknown_member(value, "fault", "stor-" + "01" * 32)
        with self.subTest(case="one-missing+one-unknown"):
            self.assertEqual(("indeterminate",) * 3, verdicts(value, "fault"))
        value = self._released_value(twin, "fault")
        self._omit_members(value, "fault", is_delivery)
        self._add_unknown_member(value, "fault", "stor-" + "01" * 32)
        with self.subTest(case="two-missing+one-unknown"):
            self.assertEqual(("fail",) * 3, verdicts(value, "fault"))
        self._add_unknown_member(value, "fault", "stor-" + "02" * 32)
        with self.subTest(case="two-missing+two-unknown"):
            self.assertEqual(("indeterminate",) * 3, verdicts(value, "fault"))

    def test_member_that_cannot_fill_a_missing_invocation_does_not_mask_it(self):
        # Round-5 R4-1: a signed row pointer names the only member that may
        # fill its invocation (PDE-8), and a mapped member's signed outcome
        # equals its row. A member that cannot fill a missing invocation,
        # whether of unknown identity or deferred on missing authority, must
        # not turn the deterministic exact-set rejection into indeterminate.
        exact_set = ("fail", "FAB DeliveryEvidence is not the exact delivery invocation set")

        def unknown(fill):
            locator = "stor-" + fill * 32
            return {
                "anchor": {"kind": "storage-program", "locator": locator},
                "contentHash": hashlib.sha256(locator.encode("utf-8")).hexdigest(),
            }

        def other_record(value, member, *, phase_index=None, failure=False):
            """Another authentic record for ``member``'s invocation, receipt unavailable."""
            resolutions = value["authority"]["referenceValidationByCanonicalRef"]
            resolution = copy.deepcopy(resolutions[self._key(member)])
            record = resolution["record"]
            record["observedAt"] += 1
            if phase_index is not None:
                record["phaseIndex"] = phase_index
            if failure:
                record["outcome"] = "failure"
                record["reason"] = "delivery-failed"
                record.pop("deliverableContentHash", None)
                record.pop("deliverableAnchor", None)
            self._resign_record(
                record, signer_role=record["signature"]["signer"].rsplit(":", 1)[1]
            )
            ref = copy.deepcopy(member)
            ref["contentHash"] = R.delivery_evidence_hash(record)
            resolutions[self._key(ref)] = resolution
            return ref

        def verdicts(value, kind, members):
            """Each lane's disposition, required to be identical in every member order."""
            seen = set()
            for order in itertools.permutations(members):
                value["bundle"]["settlementEvidence"] = list(order)
                self._resign_released(value, kind)
                value["authority"]["legacyAgreementAuthorityByPhaseKey"] = (
                    refreshed_laa_phase_carriers(value["authority"])
                )
                direct = self._direct(value, kind)
                reconciled = self._reconcile(value)
                current_use = self._current_use(value)
                lanes = [
                    (direct[0], str(direct[1])),
                    (reconciled["decision"], str(reconciled["reason"])),
                    (current_use[0], str(current_use[1])),
                ]
                if "keys" in value:
                    resolved = self._resolve(value)
                    lanes.append(("pass" if resolved["ok"] else resolved["disposition"],))
                seen.add(tuple(lanes))
            self.assertEqual(1, len(seen), seen)
            lanes = seen.pop()
            return lanes[0], tuple(lane[0] for lane in lanes)

        def drop_receipt(value, member):
            value["authority"]["verifiedReceiptByCanonicalRef"].pop(self._key(member))
            return [member]

        def drop_resolution(value, member):
            value["authority"]["referenceValidationByCanonicalRef"].pop(self._key(member))
            return [member]

        # A current FAB with one delivery D whose row pointer names D, on the
        # direct, reconciliation, current-use and pointer lanes.
        fab_cases = (
            ("pointer-bound-missing+unknown", True,
             lambda v, d: [unknown("01")], "fail"),
            ("pointer-bound-missing+two-unknown", True,
             lambda v, d: [unknown("01"), unknown("02")], "fail"),
            ("pointer-bound-missing+deferred-other-record", True,
             lambda v, d: [other_record(v, d)], "fail"),
            ("pointer-bound-missing+deferred-other-record+unknown", True,
             lambda v, d: [other_record(v, d), unknown("01")], "fail"),
            ("pointer-bound-missing+deferred-rowless-record", True,
             lambda v, d: [other_record(v, d, phase_index=7)], "fail"),
            ("unpointed-missing+deferred-contradicting-outcome", False,
             lambda v, d: [other_record(v, d, failure=True)], "fail"),
            # Controls: a member that could still fill the gap defers it.
            ("unpointed-missing+unknown", False,
             lambda v, d: [unknown("01")], "indeterminate"),
            ("unpointed-missing+deferred-other-record", False,
             lambda v, d: [other_record(v, d)], "indeterminate"),
            ("pointed-member-receipt-missing", True, drop_receipt, "indeterminate"),
            ("pointed-member-unresolved", True, drop_resolution, "indeterminate"),
        )
        for label, keep_pointer, members, expected in fab_cases:
            value = self._fixture()
            delivery = value["bundle"]["settlementEvidence"][0]
            self.assertEqual(delivery, value["bundle"]["phaseSummary"][0]["attestationRef"])
            if not keep_pointer:
                value["bundle"]["phaseSummary"][0].pop("attestationRef")
            with self.subTest(kind="fault", case=label):
                direct, dispositions = verdicts(value, "fault", members(value, delivery))
                self.assertEqual((expected,) * 4, dispositions, direct)
                if expected == "fail":
                    self.assertEqual(exact_set, direct)

        # The same rule binds a PDE-7 legacy delivery member deferred on
        # missing receipt authority: a row pointer that names another
        # reference leaves its invocation unfillable.
        for label, aim_pointer, expected in (
            ("legacy-delivery-receipt-missing+pointer-names-other", True, "fail"),
            ("legacy-delivery-receipt-missing", False, "indeterminate"),
        ):
            value = self._legacy_delivery_value("fault")
            legacy = value["bundle"]["settlementEvidence"][0]
            value["authority"]["verifiedReceiptByCanonicalRef"].pop(self._key(legacy))
            if aim_pointer:
                value["bundle"]["phaseSummary"][0]["attestationRef"] = unknown("09")
            with self.subTest(kind="fault", case=label):
                direct, dispositions = verdicts(value, "fault", [legacy])
                self.assertEqual((expected,) * 4, dispositions, direct)
                if expected == "fail":
                    self.assertEqual(exact_set, direct)

        # Repeated delivery phases. Once a copy presents a resolved current
        # delivery, PDE-8 applies to an AttestationBundle as to a FAB.
        twin = "repeated-self-signed-distinct-proof-completed"
        twin_cases = (
            ("one-of-two-pointer-bound-missing+unknown", "kept",
             lambda v, d0, d1: [d0, unknown("01")], "fail"),
            ("row-1-pointer-names-d0+unknown", "d0",
             lambda v, d0, d1: [d0, unknown("01")], "fail"),
            ("one-of-two-pointer-bound-missing+deferred-other-record", "kept",
             lambda v, d0, d1: [d0, other_record(v, d1)], "fail"),
            ("one-of-two-unpointed-missing+unknown", "removed",
             lambda v, d0, d1: [d0, unknown("01")], "indeterminate"),
            ("one-of-two-unpointed-missing+deferred-other-record", "removed",
             lambda v, d0, d1: [d0, other_record(v, d1)], "indeterminate"),
        )
        for kind in ("legacy", "fault"):
            for label, row_1_pointer, members, expected in twin_cases:
                value = self._released_value(twin, kind)
                resolutions = value["authority"]["referenceValidationByCanonicalRef"]
                d0, d1 = sorted(
                    value["bundle"]["settlementEvidence"],
                    key=lambda ref: resolutions[self._key(ref)]["record"]["phaseIndex"],
                )
                row_1 = next(
                    entry for entry in value["bundle"]["phaseSummary"] if entry["index"] == 1
                )
                self.assertEqual(d1, row_1["attestationRef"])
                if row_1_pointer == "d0":
                    row_1["attestationRef"] = copy.deepcopy(d0)
                elif row_1_pointer == "removed":
                    row_1.pop("attestationRef")
                with self.subTest(kind=kind, case=label):
                    direct, dispositions = verdicts(value, kind, members(value, d0, d1))
                    self.assertEqual((expected,) * 3, dispositions, direct)
                    if expected == "fail":
                        self.assertEqual(exact_set, direct)

    def test_member_excluded_by_execution_authority_does_not_mask_a_gap(self):
        # Round-6 R5-1: SB-1 binds a delivery member only through the execution
        # entry for its invocation, which must name this job, that invocation
        # and the member's signer as phase orchestrator. When that entry is
        # present and well-formed and excludes the member, no receipt can let
        # it fill the gap, so its receipt outage must not turn the exact-set
        # rejection into indeterminate. Unavailable or malformed execution
        # authority keeps the deferral.
        exact_set = ("fail", "FAB DeliveryEvidence is not the exact delivery invocation set")
        delivery_key = "0:deliver-storage-program"

        def signer_of(value, member):
            return value["authority"]["referenceValidationByCanonicalRef"][
                self._key(member)
            ]["record"]["signature"]["signer"]

        def stand_in(value, member, role, *, with_receipt=False):
            """Another authentic record for ``member``'s invocation, signed by ``role``."""
            authority = value["authority"]
            resolution = copy.deepcopy(
                authority["referenceValidationByCanonicalRef"][self._key(member)]
            )
            record = resolution["record"]
            # Evidence hashes exclude the signature, so a distinct reference
            # needs a distinct signed body.
            record["observedAt"] += 1
            ref = copy.deepcopy(member)
            if "deliveryEvidenceVersion" in record:
                self._resign_record(record, signer_role=role)
                ref["contentHash"] = R.delivery_evidence_hash(record)
            else:
                # A PDE-7 legacy delivery is SettlementEvidence.
                self._resign_payment_record(record, signer_role=role)
                ref["contentHash"] = R.settlement_evidence_hash(record)
            authority["referenceValidationByCanonicalRef"][self._key(ref)] = resolution
            if with_receipt:
                receipt = copy.deepcopy(
                    authority["verifiedReceiptByCanonicalRef"][self._key(member)]
                )
                receipt["contentHash"] = ref["contentHash"]
                authority["verifiedReceiptByCanonicalRef"][self._key(ref)] = receipt
            return ref

        def verdicts(value, kind, members):
            """Each lane's disposition, required to be identical in every member order."""
            seen = set()
            for order in itertools.permutations(members):
                value["bundle"]["settlementEvidence"] = list(order)
                self._resign_released(value, kind)
                value["authority"]["legacyAgreementAuthorityByPhaseKey"] = (
                    refreshed_laa_phase_carriers(value["authority"])
                )
                direct = self._direct(value, kind)
                reconciled = self._reconcile(value)
                current_use = self._current_use(value)
                lanes = [
                    (direct[0], str(direct[1])),
                    (reconciled["decision"], str(reconciled["reason"])),
                    (current_use[0], str(current_use[1])),
                ]
                if kind == "fault" and "keys" in value:
                    resolved = self._resolve(value)
                    lanes.append(("pass" if resolved["ok"] else resolved["disposition"],))
                seen.add(tuple(lanes))
            self.assertEqual(1, len(seen), seen)
            lanes = seen.pop()
            return lanes[0], tuple(lane[0] for lane in lanes)

        def check(kind, label, value, members, expected, *, with_receipt=False):
            lane_count = 4 if kind == "fault" and "keys" in value else 3
            with self.subTest(kind=kind, case=label):
                direct, dispositions = verdicts(value, kind, members)
                self.assertEqual((expected,) * lane_count, dispositions, direct)
                if expected == "fail" and not with_receipt:
                    self.assertEqual(exact_set, direct)

        def entry(value):
            return value["authority"]["sessionExecutionAuthorityByPhaseKey"][delivery_key]

        def other_job(value):
            entry(value)["jobId"] = "01ARZ3NDEKTSV4RRFFQ69G5FAW"

        def other_phase(value):
            entry(value)["phaseIndex"] = 3

        def no_receipts(value):
            value["authority"].pop("verifiedReceiptByCanonicalRef")

        def no_entry(value):
            value["authority"]["sessionExecutionAuthorityByPhaseKey"].pop(delivery_key)

        def no_execution(value):
            value["authority"].pop("sessionExecutionAuthorityByPhaseKey")

        def malformed_entry(value):
            entry(value)["phaseOrchestrator"] = 7

        # Current DeliveryEvidence: omit D and its row pointer (the pointer
        # rule is covered above), then present a stand-in whose receipt is
        # unavailable unless the case holds it.
        current_cases = (
            ("buyer-signed", "buyer", False, None, "fail"),
            ("seller-signed", "seller", False, None, "fail"),
            ("buyer-signed+receipt-map-absent", "buyer", False, no_receipts, "fail"),
            ("orchestrator-signed+execution-names-another-job", "orchestrator", False, other_job, "fail"),
            ("orchestrator-signed+execution-names-another-phase", "orchestrator", False, other_phase, "fail"),
            ("buyer-signed-with-receipt", "buyer", True, None, "fail"),
            # Controls: the stand-in could fill, or the deciding authority is
            # itself unavailable or malformed.
            ("orchestrator-signed", "orchestrator", False, None, "indeterminate"),
            ("buyer-signed+execution-entry-absent", "buyer", False, no_entry, "indeterminate"),
            ("buyer-signed+execution-map-absent", "buyer", False, no_execution, "indeterminate"),
            ("buyer-signed+execution-entry-malformed", "buyer", False, malformed_entry, "indeterminate"),
        )
        for kind in ("fault", "legacy"):
            for label, role, with_receipt, change, expected in current_cases:
                value = self._fixture()
                delivery = value["bundle"]["settlementEvidence"][0]
                self.assertEqual(signer_of(value, delivery), entry(value)["phaseOrchestrator"])
                self.assertTrue(signer_of(value, delivery).endswith(":orchestrator"))
                value["bundle"]["phaseSummary"][0].pop("attestationRef")
                if kind == "legacy":
                    value["bundle"].pop("faultBundleVersion")
                member = stand_in(value, delivery, role, with_receipt=with_receipt)
                if change is not None:
                    change(value)
                check(kind, label, value, [member], expected, with_receipt=with_receipt)

        # PDE-7 legacy delivery on a FAB, on all four lanes.
        legacy_cases = (
            ("legacy-buyer-signed", "buyer", False, None, "fail"),
            ("legacy-buyer-signed-with-receipt", "buyer", True, None, "fail"),
            ("legacy-own-record-receipt-missing", None, False, None, "indeterminate"),
            ("legacy-buyer-signed+execution-entry-absent", "buyer", False, no_entry, "indeterminate"),
        )
        for label, role, with_receipt, change, expected in legacy_cases:
            value = self._legacy_delivery_value("fault")
            legacy = value["bundle"]["settlementEvidence"][0]
            self.assertEqual(signer_of(value, legacy), entry(value)["phaseOrchestrator"])
            value["bundle"]["phaseSummary"][0].pop("attestationRef")
            if role is None:
                value["authority"]["verifiedReceiptByCanonicalRef"].pop(self._key(legacy))
                members = [legacy]
            else:
                members = [stand_in(value, legacy, role, with_receipt=with_receipt)]
            if change is not None:
                change(value)
            check("fault", label, value, members, expected, with_receipt=with_receipt)

        # Repeated delivery phases, AttestationBundle and FAB, in every order.
        twin = "repeated-self-signed-distinct-proof-completed"
        for kind in ("legacy", "fault"):
            for label, excluded, expected in (
                ("twin-non-orchestrator-stand-in-for-d1", True, "fail"),
                ("twin-orchestrator-stand-in-for-d1", False, "indeterminate"),
            ):
                value = self._released_value(twin, kind)
                resolutions = value["authority"]["referenceValidationByCanonicalRef"]
                d0, d1 = sorted(
                    value["bundle"]["settlementEvidence"],
                    key=lambda ref: resolutions[self._key(ref)]["record"]["phaseIndex"],
                )
                orchestrator = value["authority"]["sessionExecutionAuthorityByPhaseKey"][
                    "1:deliver-attested-payload"
                ]["phaseOrchestrator"]
                self.assertEqual(signer_of(value, d1), orchestrator)
                role = (
                    next(r for r in ("buyer", "seller") if not orchestrator.endswith(":" + r))
                    if excluded else orchestrator.rsplit(":", 1)[1]
                )
                row_1 = next(
                    row for row in value["bundle"]["phaseSummary"] if row["index"] == 1
                )
                row_1.pop("attestationRef")
                check(kind, label, value, [d0, stand_in(value, d1, role)], expected)

    def test_legacy_member_excluded_by_execution_address_does_not_mask_a_gap(self):
        # Round-7 R6-1: a PDE-7 legacy delivery binds only at its execution
        # entry's own evidenceLogicalAddress, and a legacy record at a PDE-2
        # indexed address is rejected. An entry naming a PDE-2 address, or
        # none, therefore excludes every legacy member, so its receipt outage
        # must not defer the FAB exact-set rejection. An AttestationBundle
        # presenting no current DeliveryEvidence stays CUR-5 indeterminate,
        # so its reason is not pinned here.
        exact_set = ("fail", "FAB DeliveryEvidence is not the exact delivery invocation set")
        delivery_key = "0:deliver-storage-program"
        pde2 = "dacs4:delivery:%s:0" % CURRENT_JOB

        def verdicts(value, kind):
            """Each lane's disposition, required to be identical in every member order."""
            seen = set()
            for order in itertools.permutations(value["bundle"]["settlementEvidence"]):
                value["bundle"]["settlementEvidence"] = list(order)
                if kind == "legacy":
                    value["bundle"].pop("faultBundleVersion", None)
                self._resign_released(value, kind)
                value["authority"]["legacyAgreementAuthorityByPhaseKey"] = (
                    refreshed_laa_phase_carriers(value["authority"])
                )
                direct = self._direct(value, kind)
                reconciled = self._reconcile(value)
                current_use = self._current_use(value)
                lanes = [
                    (direct[0], str(direct[1])),
                    (reconciled["decision"], str(reconciled["reason"])),
                    (current_use[0], str(current_use[1])),
                ]
                if kind == "fault":
                    resolved = self._resolve(value)
                    lanes.append(("pass" if resolved["ok"] else resolved["disposition"],))
                seen.add(tuple(lanes))
            self.assertEqual(1, len(seen), seen)
            lanes = seen.pop()
            return lanes[0], tuple(lane[0] for lane in lanes)

        def legacy_record_ref(source, member, *, role=None, bump=0):
            """A copy of ``source``'s PDE-7 record for ``member``, optionally re-signed."""
            resolution = copy.deepcopy(
                source["authority"]["referenceValidationByCanonicalRef"][self._key(member)]
            )
            record = resolution["record"]
            record["observedAt"] += bump
            if role is not None or bump:
                self._resign_payment_record(record, signer_role=role)
            ref = copy.deepcopy(member)
            ref["contentHash"] = R.settlement_evidence_hash(record)
            return ref, resolution

        def hold_receipt(value, template, member, ref, address):
            receipt = copy.deepcopy(
                template["authority"]["verifiedReceiptByCanonicalRef"][self._key(member)]
            )
            receipt["contentHash"] = ref["contentHash"]
            receipt["logicalAddress"] = address
            value["authority"]["verifiedReceiptByCanonicalRef"][self._key(ref)] = receipt

        def legacy_era(address, *, receipt=None, stand_ins=1, pointer=True):
            """The PDE-7 fixture with its execution address set and receipt unavailable.

            ``address`` and ``receipt`` may be ``own``: the fixture's unindexed
            evidence address, at which the legacy record could bind.
            """
            value = self._legacy_delivery_value("fault")
            member = value["bundle"]["settlementEvidence"][0]
            entry = value["authority"]["sessionExecutionAuthorityByPhaseKey"][delivery_key]
            own = entry["evidenceLogicalAddress"]
            self.assertFalse(R._is_current_delivery_evidence_address(own, CURRENT_JOB))
            self.assertEqual(
                R._delivery_execution_authority_status(
                    value["authority"]["sessionExecutionAuthorityByPhaseKey"], delivery_key
                ),
                None,
            )
            template = copy.deepcopy(value)
            value["authority"]["verifiedReceiptByCanonicalRef"].pop(self._key(member))
            members = []
            for bump in range(stand_ins):
                ref, resolution = legacy_record_ref(value, member, bump=bump)
                value["authority"]["referenceValidationByCanonicalRef"][self._key(ref)] = (
                    resolution
                )
                members.append(ref)
            if receipt is not None:
                hold_receipt(
                    value, template, member, members[0], own if receipt == "own" else receipt
                )
            if address is None:
                entry.pop("evidenceLogicalAddress")
            elif address != "own":
                entry["evidenceLogicalAddress"] = address
            if not pointer:
                value["bundle"]["phaseSummary"][0].pop("attestationRef")
            value["bundle"]["settlementEvidence"] = members
            return value

        def current_era(*, legacy_stand_in=True, receipt=False):
            """A current FAB (PDE-2 execution address), D omitted, stand-in presented."""
            value = self._fixture()
            delivery = value["bundle"]["settlementEvidence"][0]
            entry = value["authority"]["sessionExecutionAuthorityByPhaseKey"][delivery_key]
            self.assertEqual(pde2, entry["evidenceLogicalAddress"])
            value["bundle"]["phaseSummary"][0].pop("attestationRef")
            if not legacy_stand_in:
                # Control: current DeliveryEvidence ignores the entry address.
                resolution = copy.deepcopy(
                    value["authority"]["referenceValidationByCanonicalRef"][self._key(delivery)]
                )
                resolution["record"]["observedAt"] += 1
                self._resign_record(resolution["record"], signer_role="orchestrator")
                ref = copy.deepcopy(delivery)
                ref["contentHash"] = R.delivery_evidence_hash(resolution["record"])
                value["authority"]["referenceValidationByCanonicalRef"][self._key(ref)] = resolution
                value["bundle"]["settlementEvidence"] = [ref]
                return value
            legacy = self._legacy_delivery_value("fault")
            member = legacy["bundle"]["settlementEvidence"][0]
            ref, resolution = legacy_record_ref(legacy, member, role="orchestrator")
            self.assertEqual(entry["phaseOrchestrator"], resolution["record"]["signature"]["signer"])
            value["authority"]["referenceValidationByCanonicalRef"][self._key(ref)] = resolution
            if receipt:
                hold_receipt(value, legacy, member, ref, pde2)
                value["authority"]["verifiedReceiptByCanonicalRef"][self._key(ref)][
                    "writer"
                ] = entry["phaseOrchestrator"]
            value["bundle"]["settlementEvidence"] = [ref]
            return value

        cases = (
            # label, build, FAB expected, AB expected, receipt held
            ("entry-names-pde2-address", lambda: legacy_era(pde2), "fail", "indeterminate", False),
            ("entry-names-pde2-address+no-row-pointer",
             lambda: legacy_era(pde2, pointer=False), "fail", "indeterminate", False),
            ("entry-lacks-address", lambda: legacy_era(None), "fail", "indeterminate", False),
            ("entry-lacks-address+no-row-pointer",
             lambda: legacy_era(None, pointer=False), "fail", "indeterminate", False),
            ("entry-names-pde2-address+two-stand-ins",
             lambda: legacy_era(pde2, stand_ins=2), "fail", "indeterminate", False),
            ("current-era-orchestrator-pde7-stand-in", current_era, "fail", "indeterminate", False),
            # Oracles: the same members with a receipt are deterministic failures.
            ("entry-names-pde2-address-with-receipt-there",
             lambda: legacy_era(pde2, receipt=pde2), "fail", "fail", True),
            ("entry-lacks-address-with-receipt-at-own-address",
             lambda: legacy_era(None, receipt="own"), "fail", "fail", True),
            ("current-era-orchestrator-pde7-stand-in-with-receipt",
             lambda: current_era(receipt=True), "fail", "fail", True),
            # Controls: the member could still bind, so the deferral stays;
            # malformed address authority keeps its typed error.
            ("own-unindexed-address-receipt-missing",
             lambda: legacy_era("own"), "indeterminate", "indeterminate", False),
            ("entry-address-malformed", lambda: legacy_era(5), "error", "error", False),
            ("current-era-orchestrator-delivery-evidence-stand-in",
             lambda: current_era(legacy_stand_in=False), "indeterminate", "indeterminate", False),
        )
        for kind in ("fault", "legacy"):
            for label, build, fab_expected, ab_expected, with_receipt in cases:
                expected = fab_expected if kind == "fault" else ab_expected
                with self.subTest(kind=kind, case=label):
                    direct, dispositions = verdicts(build(), kind)
                    self.assertEqual((expected,) * (4 if kind == "fault" else 3), dispositions, direct)
                    if kind == "fault" and expected == "fail" and not with_receipt:
                        self.assertEqual(exact_set, direct)

    def test_delivery_reuse_is_detected_without_the_optional_pointer(self):
        # Round-4 N3: phaseSummary[].attestationRef is OPTIONAL, so a second
        # authentic record for one delivery invocation must still fail as
        # reuse when the first-evaluated member's lifecycle is unavailable.
        for kind in ("legacy", "fault"):
            for drop_lifecycle in (False, True):
                for reverse in (False, True):
                    value = self._fixture()
                    authority, bundle = value["authority"], value["bundle"]
                    first_ref = bundle["settlementEvidence"][0]
                    resolutions = authority["referenceValidationByCanonicalRef"]
                    receipts = authority["verifiedReceiptByCanonicalRef"]
                    twin = copy.deepcopy(resolutions[self._key(first_ref)])
                    twin["record"]["observedAt"] += 1
                    self._resign_record(twin["record"], signer_role="orchestrator")
                    twin_ref = copy.deepcopy(first_ref)
                    twin_ref["contentHash"] = R.delivery_evidence_hash(twin["record"])
                    twin_receipt = copy.deepcopy(receipts[self._key(first_ref)])
                    twin_receipt["contentHash"] = twin_ref["contentHash"]
                    resolutions[self._key(twin_ref)] = twin
                    receipts[self._key(twin_ref)] = twin_receipt
                    members = [first_ref, twin_ref]
                    bundle["settlementEvidence"] = list(reversed(members)) if reverse else members
                    bundle["phaseSummary"][0].pop("attestationRef")
                    if drop_lifecycle:
                        canonical_first = min(members, key=R.canonical)
                        resolutions[self._key(canonical_first)].pop("lifecycle")
                    if kind == "legacy":
                        bundle.pop("faultBundleVersion")
                    self._resign_released(value, kind)
                    with self.subTest(kind=kind, lifecycle_outage=drop_lifecycle, reverse=reverse):
                        self.assertEqual(
                            ("fail", "FAB reuses a delivery invocation"),
                            self._direct(value, kind),
                        )
                        self.assertEqual("fail", self._reconcile(value)["decision"])
                        self.assertEqual("fail", self._current_use(value)[0])
                        if kind == "fault":
                            resolved = self._resolve(value)
                            self.assertFalse(resolved["ok"])
                            self.assertEqual("fail", resolved["disposition"], resolved["reason"])

    def test_ordinary_current_delivery_reconciliation_needs_closure_authority(self):
        value = self._fixture()
        bundle, authority, _dependencies, _config = self._ordinary_current_delivery(
            value
        )
        value["bundle"] = bundle
        value["authority"] = authority
        positive = self._reconcile(value)
        self.assertEqual("pass", positive["decision"], positive["reason"])
        missing = self._reconcile(value, authority=False)
        self.assertEqual("indeterminate", missing["decision"], missing["reason"])

    def test_ordinary_current_delivery_rejects_authenticated_wrong_job(self):
        value = self._fixture()
        self._replace_record(
            value, lambda record: record.__setitem__("jobId", "different-job"),
            signer_role="orchestrator",
        )
        bundle, _authority, dependencies, config = self._ordinary_current_delivery(
            value
        )
        decision, reason = R._validate_current_use_historical_nonpayment(
            bundle, dependencies, config
        )
        self.assertEqual("fail", decision, reason)

    def test_ordinary_current_delivery_missing_authority_is_indeterminate(self):
        for missing in ("resolution", "receipt"):
            bundle, authority, dependencies, config = self._ordinary_current_delivery(
                self._fixture()
            )
            ref_key = R.canonical(bundle["settlementEvidence"][0]).decode("utf-8")
            if missing == "resolution":
                del authority["referenceValidationByCanonicalRef"][ref_key]
            else:
                del authority["verifiedReceiptByCanonicalRef"][ref_key]
            with self.subTest(missing=missing):
                decision, reason = R._validate_current_use_historical_nonpayment(
                    bundle, dependencies, config
                )
                self.assertEqual("indeterminate", decision, reason)

    def test_reconciliation_uses_the_same_current_fab_delivery_gate(self):
        value = self._fixture()
        self._replace_record(
            value,
            lambda record: record.__setitem__(
                "jobId", "01ARZ3NDEKTSV4RRFFQ69G5FAW"
            ),
        )
        rejected = self._reconcile(value)
        self.assertEqual("fail", rejected["decision"], rejected["reason"])

        unavailable = self._reconcile(self._fixture(), authority=False)
        self.assertEqual(
            "indeterminate", unavailable["decision"], unavailable["reason"]
        )

    def test_current_fab_delivery_exact_bindings_are_load_bearing(self):
        value = self._fixture()
        rebound_job = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
        value["bundle"]["jobId"] = rebound_job
        signer = next(
            party["primaryClaim"] for party in value["bundle"]["parties"]
            if party["role"] == value["role"]
        )
        value["trusted"] = R.trusted_profile_context(
            rebound_job, signer, role=value["role"]
        )
        self._resign_bundle_and_pointer(value)
        rebound = R.resolve_absolute_fault_pointer(
            value["pointer"],
            value["bundle"],
            pubkeys=value["keys"],
            ebfab_authority=value["authority"],
            trusted_contexts=value["trusted"],
            expected_jobid=rebound_job,
            expected_role=value["role"],
        )
        self.assertFalse(rebound["ok"])
        self.assertEqual("fail", rebound.get("disposition"), rebound["reason"])

        mutations = {
            "wrong-job": lambda record: record.__setitem__(
                "jobId", "01ARZ3NDEKTSV4RRFFQ69G5FAW"
            ),
            "wrong-index": lambda record: record.__setitem__("phaseIndex", 1),
            "wrong-kind": lambda record: record.__setitem__(
                "phase", "deliver-entitlement"
            ),
        }
        for name, mutate in mutations.items():
            value = self._fixture()
            self._replace_record(value, mutate)
            with self.subTest(name=name):
                result = self._resolve(value)
                self.assertFalse(result["ok"])
                self.assertEqual("fail", result.get("disposition"), result["reason"])

        value = self._fixture()
        key = R.canonical(value["bundle"]["settlementEvidence"][0]).decode("utf-8")
        value["authority"]["verifiedReceiptByCanonicalRef"][key][
            "logicalAddress"
        ] = "dacs4:delivery:wrong:0"
        result = self._resolve(value)
        self.assertFalse(result["ok"])
        self.assertEqual("fail", result.get("disposition"), result["reason"])

        value = self._fixture()
        self._replace_record(value, lambda _record: None, signer_role="buyer")
        result = self._resolve(value)
        self.assertFalse(result["ok"])
        self.assertEqual("fail", result.get("disposition"), result["reason"])

    def test_current_fab_missing_delivery_authority_is_indeterminate(self):
        value = self._fixture()
        value["authority"]["deliveryArtifactAuthorityByPhaseKey"] = {}
        result = self._resolve(value)
        self.assertFalse(result["ok"])
        self.assertEqual("indeterminate", result.get("disposition"), result["reason"])

        value = self._fixture()
        result = R.resolve_absolute_fault_pointer(
            value["pointer"],
            value["bundle"],
            pubkeys=value["keys"],
            trusted_contexts=value["trusted"],
            expected_jobid=CURRENT_JOB,
            expected_role=value["role"],
        )
        self.assertFalse(result["ok"])
        self.assertEqual("indeterminate", result.get("disposition"), result["reason"])

        value = self._fixture()
        value["authority"].pop("verifiedReceiptByCanonicalRef")
        result = self._resolve(value)
        self.assertFalse(result["ok"])
        self.assertEqual("indeterminate", result.get("disposition"), result["reason"])

    def test_missing_signed_delivery_row_cannot_bypass_authenticated_pipeline(self):
        value = self._fixture()
        value["bundle"]["phaseSummary"] = []
        value["bundle"]["settlementEvidence"] = []
        self._resign_bundle_and_pointer(value)
        without_authority = R.resolve_absolute_fault_pointer(
            value["pointer"],
            value["bundle"],
            pubkeys=value["keys"],
            trusted_contexts=value["trusted"],
            expected_jobid=CURRENT_JOB,
            expected_role=value["role"],
        )
        self.assertFalse(without_authority["ok"])
        self.assertEqual("indeterminate", without_authority.get("disposition"))

        with_authority = self._resolve(value)
        self.assertFalse(with_authority["ok"])
        self.assertEqual("fail", with_authority.get("disposition"))

    def test_current_fab_malformed_authority_and_member_are_errors(self):
        for field in (
            "listing",
            "referenceValidationByCanonicalRef",
            "sessionExecutionAuthorityByPhaseKey",
            "verifiedReceiptByCanonicalRef",
            "deliveryArtifactAuthorityByPhaseKey",
        ):
            value = self._fixture()
            value["authority"][field] = []
            with self.subTest(field=field):
                result = self._resolve(value)
                self.assertFalse(result["ok"])
                self.assertEqual("error", result.get("disposition"), result["reason"])

        value = self._fixture()
        ref = value["bundle"]["settlementEvidence"][0]
        key = R.canonical(ref).decode("utf-8")
        value["authority"]["referenceValidationByCanonicalRef"][key]["record"][
            "signature"
        ]["algorithm"] = []
        result = self._resolve(value)
        self.assertFalse(result["ok"])
        self.assertEqual("error", result.get("disposition"), result["reason"])

        value = self._fixture()
        ref = value["bundle"]["settlementEvidence"][0]
        key = R.canonical(ref).decode("utf-8")
        value["authority"]["referenceValidationByCanonicalRef"][key] = []
        result = self._resolve(value)
        self.assertFalse(result["ok"])
        self.assertEqual("error", result.get("disposition"), result["reason"])

        value = self._fixture()
        ref = value["bundle"]["settlementEvidence"][0]
        key = R.canonical(ref).decode("utf-8")
        value["authority"]["verifiedReceiptByCanonicalRef"][key] = []
        result = self._resolve(value)
        self.assertFalse(result["ok"])
        self.assertEqual("error", result.get("disposition"), result["reason"])

    def test_current_fab_delivery_lifecycle_missing_vs_malformed(self):
        for lifecycle, expected in (("missing", "indeterminate"), ([], "error"), (None, "error")):
            value = self._fixture()
            ref = value["bundle"]["settlementEvidence"][0]
            resolution = value["authority"]["referenceValidationByCanonicalRef"][
                R.canonical(ref).decode("utf-8")
            ]
            if lifecycle == "missing":
                resolution.pop("lifecycle")
            else:
                resolution["lifecycle"] = lifecycle
            with self.subTest(lifecycle=lifecycle):
                disposition, reason = R._validate_current_fab_delivery_admission(
                    value["bundle"], value["authority"], self.pubkeys
                )
                self.assertEqual(disposition, expected, reason)

    def test_pointer_signature_algorithms_refuse_without_exceptions(self):
        for malformed in ([], {}, None, True, 123, "rsa-sha256"):
            value = self._fixture()
            value["pointer"]["signature"]["algorithm"] = malformed
            with self.subTest(malformed=malformed, path="current"):
                result = self._resolve(value)
                self.assertFalse(result["ok"])
                self.assertEqual(
                    "absolute-pointer family cannot be authenticated before parsing",
                    result["reason"],
                )
            with self.subTest(malformed=malformed, path="legacy"):
                result = R.resolve_legacy_absolute_fault_pointer(
                    value["pointer"],
                    value["bundle"],
                    pubkeys=self.pubkeys,
                    ebfab_authority=value["authority"],
                    expected_jobid=CURRENT_JOB,
                    expected_role=value["role"],
                )
                self.assertFalse(result["ok"])
                self.assertEqual(
                    "absolute-pointer family cannot be authenticated before parsing",
                    result["reason"],
                )

    # --- released AB/FAB traces keep released optional-field semantics

    def _failed_delivery_value(self, authority_name):
        """A current-job released FAB from a failed single-delivery EBFAB vector."""
        source = copy.deepcopy(self.data["executionAuthorities"][authority_name])
        bundle = source["bundle"]
        bundle.pop("evidenceBoundFaultBundleVersion")
        bundle["faultBundleVersion"] = "1"
        bundle["jobId"] = CURRENT_JOB
        old_ref = copy.deepcopy(bundle["settlementEvidence"][0])
        old_key = R.canonical(old_ref).decode("utf-8")
        resolution = source["referenceValidationByCanonicalRef"].pop(old_key)
        record = resolution["record"]
        record["jobId"] = CURRENT_JOB
        self._resign_record(record, signer_role="orchestrator")
        new_ref = copy.deepcopy(old_ref)
        new_ref["contentHash"] = R.delivery_evidence_hash(record)
        new_key = R.canonical(new_ref).decode("utf-8")
        source["referenceValidationByCanonicalRef"][new_key] = resolution
        receipt = source["verifiedReceiptByCanonicalRef"].pop(old_key)
        receipt["logicalAddress"] = "dacs4:delivery:%s:0" % CURRENT_JOB
        receipt["contentHash"] = new_ref["contentHash"]
        source["verifiedReceiptByCanonicalRef"][new_key] = receipt
        execution = source["sessionExecutionAuthorityByPhaseKey"]["0:deliver-storage-program"]
        execution["jobId"] = CURRENT_JOB
        execution["evidenceLogicalAddress"] = "dacs4:delivery:%s:0" % CURRENT_JOB
        bundle["settlementEvidence"] = [new_ref]
        bundle["phaseSummary"][0]["attestationRef"] = copy.deepcopy(new_ref)
        role = bundle["anchoredByRole"]
        signer = next(p["primaryClaim"] for p in bundle["parties"] if p["role"] == role)
        value = {
            "bundle": bundle,
            "pointer": {
                "faultBundleVersion": "1",
                "pointerKind": "extended",
                "fullBundleUrl": "fixture:released-trace-" + authority_name,
                "fullBundleContentHash": "",
                "signature": {},
            },
            "authority": source,
            "role": role,
            "trusted": R.trusted_profile_context(CURRENT_JOB, signer, role=role),
            "keys": R.trusted_verification_keys(copy.deepcopy(self.pubkeys)),
        }
        self._resign_bundle_and_pointer(value)
        return value

    def _as_released_kind(self, value, kind):
        """Re-sign a current-job value as a released FAB or AttestationBundle."""
        bundle = value["bundle"]
        if kind == "fault":
            self._resign_bundle_and_pointer(value)
            return value
        bundle.pop("faultBundleVersion", None)
        bundle.pop("faultedParty", None)
        bundle["bundleVersion"] = "1"
        claims = {party["role"]: party["primaryClaim"] for party in bundle["parties"]}
        bundle["signatures"] = []
        digest = R.bundle_hash(bundle)
        bundle["signatures"] = [
            {
                "party": claims[role],
                "algorithm": "ed25519",
                "value": self._sign(role, R.BUNDLE_DOMAIN, digest),
            }
            for role in R._required_bundle_signers(bundle)
        ]
        return value

    def _released_trace_dispositions(self, value, kind):
        results = {
            "direct": R._validate_current_fab_delivery_admission(
                value["bundle"], value["authority"], self.pubkeys,
                **({"ordinary_current": True} if kind == "legacy" else {}),
            )[0],
            "reconcile": self._reconcile(copy.deepcopy(value))["decision"],
            "current-use": self._current_use(copy.deepcopy(value))[0],
        }
        if kind == "fault":
            resolved = self._resolve(copy.deepcopy(value))
            results["pointer"] = (
                "pass" if resolved["ok"] else resolved.get("disposition", "fail")
            )
        return results

    def test_released_traces_admit_omitted_optional_fields(self):
        def last(value):
            return value["bundle"]["phaseSummary"][-1]

        def drop(*fields):
            return lambda value: [last(value).pop(field, None) for field in fields]

        def outcome(name, faulted):
            def mutate(value):
                value["bundle"]["outcome"] = name
                value["bundle"]["faultedParty"] = faulted
                last(value).pop("errorClass", None)
            return mutate

        def retry_marker(index):
            return lambda value: value["bundle"]["phaseSummary"][index].__setitem__(
                "retryExhausted", True
            )

        failed = lambda: self._failed_delivery_value("failed-delivery")
        transient = lambda: self._failed_delivery_value("transient-retry-exhausted")
        cases = (
            ("permanent control", failed, None),
            ("errorClass omitted", failed, drop("errorClass")),
            ("retryExhausted on a permanent terminal", failed, retry_marker(-1)),
            ("failed-substrate without errorClass", failed, outcome("failed-substrate", "none")),
            ("failed-counterparty without errorClass", failed,
             outcome("failed-counterparty", "buyer")),
            ("transient without retryExhausted", transient, drop("retryExhausted")),
            ("transient without either field", transient, drop("errorClass", "retryExhausted")),
            ("retryExhausted on a completed ok row", self._fixture, retry_marker(0)),
        )
        for label, factory, mutate in cases:
            for kind in ("fault", "legacy"):
                value = factory()
                if mutate is not None:
                    mutate(value)
                self._as_released_kind(value, kind)
                results = self._released_trace_dispositions(value, kind)
                with self.subTest(case=label, kind=kind):
                    self.assertEqual({path: "pass" for path in results}, results)

    def test_released_traces_still_reject_present_contradictions(self):
        for label, error_class in (
            ("counterparty under failed-perm", "counterparty"),
            ("substrate under failed-perm", "substrate"),
        ):
            for kind in ("fault", "legacy"):
                value = self._failed_delivery_value("failed-delivery")
                value["bundle"]["phaseSummary"][-1]["errorClass"] = error_class
                self._as_released_kind(value, kind)
                results = self._released_trace_dispositions(value, kind)
                with self.subTest(case=label, kind=kind):
                    self.assertEqual({path: "fail" for path in results}, results)
        # EBFAB keeps SEB-1 exact completeness for both optional fields.
        for name in ("invalid-transient-not-exhausted", "invalid-failed-outcome-error-class"):
            source = copy.deepcopy(self.data["executionAuthorities"][name])
            with self.subTest(ebfab=name):
                disposition, reason, _ = R.validate_ebfab_disposition(
                    source["bundle"], source["listing"], self.pubkeys,
                    source["referenceValidationByCanonicalRef"], source["bundleLifecycle"],
                    source["sessionExecutionAuthorityByPhaseKey"],
                    source["verifiedReceiptByCanonicalRef"],
                    source["deliveryArtifactAuthorityByPhaseKey"],
                    source["trustedNativeTransactionObservationsByCanonicalRef"],
                    legacy_agreement_authority_by_phase_key=source[
                        "legacyAgreementAuthorityByPhaseKey"
                    ],
                )
                self.assertEqual("fail", disposition, reason)

    def test_incomplete_released_trace_is_pending_not_a_verdict(self):
        def drop_terminal(value, *, keep_member):
            value["bundle"]["phaseSummary"].pop()
            if not keep_member:
                value["bundle"]["settlementEvidence"] = []

        for kind in ("fault", "legacy"):
            value = self._failed_delivery_value("failed-delivery")
            drop_terminal(value, keep_member=False)
            self._as_released_kind(value, kind)
            results = self._released_trace_dispositions(value, kind)
            if kind == "legacy":
                # With no member and no delivery row, reconciliation of an
                # AttestationBundle never enters the delivery gate.
                results.pop("reconcile")
            with self.subTest(kind=kind, member="omitted"):
                self.assertEqual({path: "indeterminate" for path in results}, results)
            # A presented member for an invocation the signed trace omits is a
            # deterministic contradiction; the pending trace cannot mask it.
            value = self._failed_delivery_value("failed-delivery")
            drop_terminal(value, keep_member=True)
            self._as_released_kind(value, kind)
            results = self._released_trace_dispositions(value, kind)
            with self.subTest(kind=kind, member="presented"):
                self.assertEqual({path: "fail" for path in results}, results)

    def test_released_st8_interim_row_may_omit_its_error_class(self):
        for kind in ("fault", "legacy"):
            value = self._failed_payment_fixture()
            value["bundle"]["phaseSummary"][-1].pop("errorClass")
            self._as_released_kind(value, kind)
            results = self._released_trace_dispositions(value, kind)
            with self.subTest(kind=kind, outcome="failed-counterparty"):
                # CUR-5 still holds historical cross-chain settlement.
                self.assertEqual("indeterminate", results.pop("current-use"))
                self.assertEqual({path: "pass" for path in results}, results)
            # The interim class is inferred only from the co-signed outcome.
            value = self._failed_payment_fixture()
            value["bundle"]["phaseSummary"][-1].pop("errorClass")
            value["bundle"]["outcome"] = "failed-perm"
            value["bundle"]["faultedParty"] = "seller"
            self._as_released_kind(value, kind)
            with self.subTest(kind=kind, outcome="failed-perm"):
                results = self._released_trace_dispositions(value, kind)
                self.assertEqual({path: "fail" for path in results}, results)

class ExplicitReconciliationReceiptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FINALITY_VECTORS.read_text(encoding="utf-8"))
        cls.trust = copy.deepcopy(cls.data["trustedFixturePolicy"])
        cls.pubkeys = {
            signer: _decode(value)
            for signer, value in cls.trust["partyKeys"].items()
        }

    def _entry(self, bundle, authority, contract=None):
        role = bundle["anchoredByRole"]
        party = next(item for item in bundle["parties"] if item["role"] == role)
        presence = {
            "bundleHash": R.bundle_hash(bundle),
            "nativeAddress": "dacs5:bundle:%s:%s" % (bundle["jobId"], role),
            "writer": party["primaryClaim"],
        }
        self.trust.setdefault("copyPresenceByJobRole", {})[
            bundle["jobId"] + ":" + role
        ] = copy.deepcopy(presence)
        entry = {
            "bundle": bundle,
            "expectedJobId": bundle["jobId"],
            "expectedRole": role,
            "copyPresence": presence,
            "authority": authority,
        }
        if contract is not None:
            entry["evidenceReceiptContract"] = contract
        return entry

    def _current_entry(self, bundle, authority):
        entry = self._entry(
            copy.deepcopy(bundle), copy.deepcopy(authority), "current"
        )
        for receipt in entry["authority"][
            "verifiedReceiptByCanonicalRef"
        ].values():
            legacy_transaction = receipt.pop("transaction")
            receipt["nonce"] = str(receipt["nonce"])
            receipt.update({
                "receiptVersion": "1",
                "substrate": "fixture-current",
                "finalityProfile": "fixture-final",
                "transactionRef": {
                    "kind": "fixture-transaction",
                    "value": legacy_transaction,
                },
                "state": "finalized",
                "observationDisposition": "established",
                "observedAt": 1_900_000_000_000,
                "blockRef": {"id": "fixture-current-block"},
                "evidence": {"kind": "fixture-proof", "value": "verified"},
            })
        authority = entry["authority"]
        bundle = entry["bundle"]
        phase_key, execution = next(iter(
            authority["sessionExecutionAuthorityByPhaseKey"].items()
        ))
        ref = bundle["phaseSummary"][execution["phaseIndex"]]["attestationRef"]
        ref_key = R.canonical(ref).decode("utf-8")
        record = authority["referenceValidationByCanonicalRef"][ref_key]["record"]
        receipt = authority["verifiedReceiptByCanonicalRef"][ref_key]
        agreement_hash = hashlib.sha256(
            (bundle["jobId"] + ":current-agreement").encode()
        ).hexdigest()
        laa = {
            "operation": "authorize-payment",
            "pipelineHasPayment": True,
            "agreement": {
                "artifact": "payee-bound",
                "shape": "valid",
                "partySignaturesValid": True,
                "contentHash": agreement_hash,
                "jobId": bundle["jobId"],
                "phase": record["phase"],
                "listingRef": copy.deepcopy(bundle["listingRef"]),
                "pbVerified": True,
            },
            "sessionAuthority": {
                "state": "verified",
                "jobId": bundle["jobId"],
                "sessionId": bundle["jobId"] + ":session",
                "orchestratorPrimaryClaim": execution["phaseOrchestrator"],
            },
        }
        authority["referenceValidationByCanonicalRef"][ref_key].update({
            "agreementHash": agreement_hash,
            "sessionId": laa["sessionAuthority"]["sessionId"],
        })
        authority["legacyAgreementAuthorityByPhaseKey"] = {
            phase_key: R.make_laa_phase_carrier(
                laa,
                bundle,
                authority["listing"],
                phase_key,
                record,
                ref,
                receipt,
                execution,
            )
        }
        return entry

    def _with_authenticated_absence(self, present_entry):
        role = present_entry["expectedRole"]
        other_role = "seller" if role == "buyer" else "buyer"
        job_id = present_entry["expectedJobId"]
        trust = copy.deepcopy(self.trust)
        trust.setdefault("copyDispositionByJobRole", {})[
            job_id + ":" + other_role
        ] = "absent"
        absent = {
            "disposition": "absent",
            "expectedJobId": job_id,
            "expectedRole": other_role,
        }
        return absent, trust

    def test_contract_is_required_typed_and_never_inferred_from_strong_peer(self):
        case = next(
            item for item in self.data["dacs5"]["strongBundleCases"]
            if item["model"] == "block-depth"
        )
        compatibility = self.data["dacs5"]["compatibility"]
        strong = self._entry(case["bundle"], case["authority"])
        older = self._entry(
            compatibility["copies"]["evidence-bound"],
            compatibility["evidenceBoundAuthority"],
        )
        missing = R.reconcile_authenticated_finality_copies(
            [strong, older], self.pubkeys, self.trust
        )
        self.assertEqual("indeterminate", missing["decision"])
        self.assertIn("contract authority is unavailable", missing["reason"])

        for malformed in (None, [], {}, True, 1, "legacy", "CURRENT"):
            entry = copy.deepcopy(older)
            entry["evidenceReceiptContract"] = malformed
            with self.subTest(malformed=malformed):
                result = R.reconcile_authenticated_finality_copies(
                    [strong, entry], self.pubkeys, self.trust
                )
                self.assertEqual("error", result["decision"])

        archival = copy.deepcopy(older)
        archival["evidenceReceiptContract"] = "archival"
        result = R.reconcile_authenticated_finality_copies(
            [strong, archival], self.pubkeys, self.trust
        )
        self.assertEqual("pass", result["decision"], result["reason"])

        current_positive = self._current_entry(
            compatibility["copies"]["evidence-bound"],
            compatibility["evidenceBoundAuthority"],
        )
        result = R.reconcile_authenticated_finality_copies(
            [strong, current_positive], self.pubkeys, self.trust
        )
        self.assertEqual("pass", result["decision"], result["reason"])

        current = copy.deepcopy(older)
        current["evidenceReceiptContract"] = "current"
        no_fallback = R.reconcile_authenticated_finality_copies(
            [strong, current], self.pubkeys, self.trust
        )
        self.assertEqual("fail", no_fallback["decision"])
        self.assertIn("receipt", no_fallback["reason"])

    def test_payment_only_fab_requires_current_agreement_authority(self):
        compatibility = self.data["dacs5"]["compatibility"]
        payment_only = self._entry(
            compatibility["copies"]["fault"], None
        )
        absent, trust = self._with_authenticated_absence(payment_only)
        result = R.reconcile_authenticated_finality_copies(
            [payment_only, absent], self.pubkeys, trust
        )
        self.assertEqual("indeterminate", result["decision"], result["reason"])

    def test_current_payment_only_fab_agreement_gate_has_positive_and_negative_controls(self):
        compatibility = self.data["dacs5"]["compatibility"]
        present = self._current_entry(
            compatibility["copies"]["fault"],
            compatibility["evidenceBoundAuthority"],
        )
        present["authority"]["evidenceReceiptContract"] = "current"
        absent, trust = self._with_authenticated_absence(present)
        self.assertEqual(
            "pass", R.reconcile_authenticated_finality_copies(
                [present, absent], self.pubkeys, trust
            )["decision"]
        )

        missing = copy.deepcopy(present)
        missing["authority"].pop("legacyAgreementAuthorityByPhaseKey")
        self.assertEqual(
            "indeterminate", R.reconcile_authenticated_finality_copies(
                [missing, absent], self.pubkeys, trust
            )["decision"]
        )

        malformed = copy.deepcopy(present)
        phase_key = next(iter(malformed["authority"]["legacyAgreementAuthorityByPhaseKey"]))
        malformed["authority"]["legacyAgreementAuthorityByPhaseKey"][phase_key] = []
        self.assertEqual(
            "error", R.reconcile_authenticated_finality_copies(
                [malformed, absent], self.pubkeys, trust
            )["decision"]
        )

        # The entry is the label's home for every copy kind; the released
        # authority-level field is an alias that must agree with it.
        for entry_label, authority_label in (
            ("archival", "archival"), ("archival", None), (None, "archival"),
        ):
            archival = copy.deepcopy(present)
            archival.pop("evidenceReceiptContract", None)
            archival["authority"].pop("evidenceReceiptContract", None)
            if entry_label is not None:
                archival["evidenceReceiptContract"] = entry_label
            if authority_label is not None:
                archival["authority"]["evidenceReceiptContract"] = authority_label
            with self.subTest(entry=entry_label, authority=authority_label):
                archival_result = R.reconcile_authenticated_finality_copies(
                    [archival, absent], self.pubkeys, trust
                )
                self.assertEqual("indeterminate", archival_result["decision"])
                self.assertIn("comparison-only", archival_result["reason"])
        disagreeing = copy.deepcopy(present)
        disagreeing["evidenceReceiptContract"] = "current"
        disagreeing["authority"]["evidenceReceiptContract"] = "archival"
        result = R.reconcile_authenticated_finality_copies(
            [disagreeing, absent], self.pubkeys, trust
        )
        self.assertEqual("error", result["decision"], result["reason"])
        for malformed in ("CURRENT", [], None, 1):
            for location in ("entry", "authority"):
                bad = copy.deepcopy(present)
                bad.pop("evidenceReceiptContract", None)
                bad["authority"].pop("evidenceReceiptContract", None)
                if location == "entry":
                    bad["evidenceReceiptContract"] = malformed
                else:
                    bad["authority"]["evidenceReceiptContract"] = malformed
                with self.subTest(malformed=malformed, location=location):
                    result = R.reconcile_authenticated_finality_copies(
                        [bad, absent], self.pubkeys, trust
                    )
                    self.assertEqual("error", result["decision"], result["reason"])

    def test_archival_ebfab_is_comparison_only(self):
        case = next(
            item for item in self.data["dacs5"]["strongBundleCases"]
            if item["model"] == "block-depth"
        )
        compatibility = self.data["dacs5"]["compatibility"]
        archival = self._entry(
            compatibility["copies"]["evidence-bound"],
            compatibility["evidenceBoundAuthority"],
            "archival",
        )
        absent, trust = self._with_authenticated_absence(archival)
        archival_only = R.reconcile_authenticated_finality_copies(
            [archival, absent], self.pubkeys, trust
        )
        self.assertEqual("indeterminate", archival_only["decision"])
        self.assertIsNone(archival_only["bundle"])

        invalid_authority = copy.deepcopy(case["authority"])
        key = next(iter(invalid_authority["finalityVerificationByCanonicalRef"]))
        invalid_authority["finalityVerificationByCanonicalRef"][key]["context"][
            "observation"
        ]["transactionRef"]["txHash"] = "ff" * 32
        invalid_strong = self._entry(case["bundle"], invalid_authority)
        blocked = R.reconcile_authenticated_finality_copies(
            [invalid_strong, archival], self.pubkeys, self.trust
        )
        self.assertEqual("fail", blocked["decision"])
        self.assertIsNone(blocked["bundle"])

    def test_current_ebfab_remains_selectable_but_dual_era_refuses(self):
        compatibility = self.data["dacs5"]["compatibility"]
        current = self._current_entry(
            compatibility["copies"]["evidence-bound"],
            compatibility["evidenceBoundAuthority"],
        )
        absent, trust = self._with_authenticated_absence(current)
        current_only = R.reconcile_authenticated_finality_copies(
            [current, absent], self.pubkeys, trust
        )
        self.assertEqual("pass", current_only["decision"], current_only["reason"])
        self.assertEqual("evidence-bound", R.bundle_type(current_only["bundle"]))

        archival_bundle = copy.deepcopy(
            compatibility["copies"]["evidence-bound"]
        )
        archival_bundle["anchoredByRole"] = (
            "seller" if current["expectedRole"] == "buyer" else "buyer"
        )
        archival = self._entry(
            archival_bundle,
            compatibility["evidenceBoundAuthority"],
            "archival",
        )
        dual_era = R.reconcile_authenticated_finality_copies(
            [current, archival], self.pubkeys, self.trust
        )
        self.assertEqual("indeterminate", dual_era["decision"])
        self.assertIsNone(dual_era["bundle"])

    def _current_use_ebfab_pair(self):
        compatibility = self.data["dacs5"]["compatibility"]
        seller = self._current_entry(
            compatibility["copies"]["evidence-bound"],
            compatibility["evidenceBoundAuthority"],
        )
        seller["authority"]["evidenceReceiptContract"] = "current"
        buyer = copy.deepcopy(seller)
        buyer["bundle"]["anchoredByRole"] = "buyer"
        buyer["expectedRole"] = "buyer"
        buyer["copyPresence"]["nativeAddress"] = (
            "dacs5:bundle:%s:buyer" % buyer["bundle"]["jobId"]
        )
        buyer["copyPresence"]["writer"] = "did:demos:buyer"
        job = {
            "jobId": seller["bundle"]["jobId"],
            "substrate": "fixture",
            "roles": {"buyer": {}, "seller": {}},
        }
        return job, buyer, seller

    def test_current_use_preflight_audits_two_current_ebfabs_once_each(self):
        job, buyer, seller = self._current_use_ebfab_pair()
        dependencies = {
            "bundleAuthorityByContentHash": {
                R.bundle_hash(seller["bundle"]): seller["authority"],
            },
        }
        resolved = [
            {"decision": "pass", "disposition": "present", "bundle": entry["bundle"],
             "presence": entry["copyPresence"]}
            for entry in (buyer, seller)
        ]
        current_validator = R.validate_ebfab_disposition
        with patch(
            "dacs5_reference._resolve_current_use_role", side_effect=resolved
        ), patch(
            "dacs5_reference.validate_ebfab_disposition", wraps=current_validator
        ) as current, patch(
            "dacs5_reference.validate_legacy_ebfab_disposition",
            side_effect=AssertionError("current receipt must not use archival validation"),
        ) as archival:
            result = R._resolve_current_use_job(
                job, dependencies, {"publicKeys": self.pubkeys, "finalityTrust": copy.deepcopy(self.trust)}, {}, {}
            )
        self.assertEqual("indeterminate", result["decision"], result["reason"])
        self.assertIn("lacks exact stronger finality", result["reason"])
        self.assertEqual(2, current.call_count)
        self.assertEqual(
            ["buyer", "seller"],
            [call.args[0]["anchoredByRole"] for call in current.call_args_list],
        )
        archival.assert_not_called()

    def test_current_use_preflight_requires_typed_verifier_contract_before_audit(self):
        job, buyer, seller = self._current_use_ebfab_pair()
        for contract, expected in ((None, "indeterminate"), ("legacy", "error")):
            authority = copy.deepcopy(seller["authority"])
            if contract is None:
                authority.pop("evidenceReceiptContract")
            else:
                authority["evidenceReceiptContract"] = contract
            dependencies = {
                "bundleAuthorityByContentHash": {
                    R.bundle_hash(seller["bundle"]): authority,
                },
            }
            resolved = [
                {"decision": "pass", "disposition": "present", "bundle": entry["bundle"],
                 "presence": entry["copyPresence"]}
                for entry in (buyer, seller)
            ]
            with self.subTest(contract=contract), patch(
                "dacs5_reference._resolve_current_use_role", side_effect=resolved
            ), patch(
                "dacs5_reference.validate_ebfab_disposition"
            ) as current, patch(
                "dacs5_reference.validate_legacy_ebfab_disposition"
            ) as archival:
                result = R._resolve_current_use_job(
                    job, dependencies, {"publicKeys": self.pubkeys, "finalityTrust": copy.deepcopy(self.trust)}, {}, {}
                )
                self.assertEqual(expected, result["decision"], result["reason"])
                current.assert_not_called()
                archival.assert_not_called()

    def test_copy_conflict_precedes_missing_stronger_finality_hold(self):
        job, buyer, seller = self._current_use_ebfab_pair()
        resolved = [
            {"decision": "pass", "disposition": "present", "bundle": entry["bundle"],
             "presence": entry["copyPresence"]}
            for entry in (buyer, seller)
        ]
        with patch("dacs5_reference._resolve_current_use_role", side_effect=resolved), patch(
            "dacs5_reference._job_successful_payment_without_strong_finality",
            return_value=True,
        ), patch("dacs5_reference._authority_for_bundle", return_value=seller["authority"]), patch(
            "dacs5_reference.reconcile_authenticated_finality_copies",
            return_value={"decision": "fail", "reason": "authenticated copies conflict"},
        ) as reconciler:
            result = R._resolve_current_use_job(
                job, {}, {"publicKeys": self.pubkeys, "finalityTrust": copy.deepcopy(self.trust)}, {}, {}
            )
        self.assertEqual("fail", result["decision"])
        self.assertIn("copies conflict", result["reason"])
        reconciler.assert_called_once()


class EntitlementCredentialRefBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(DELIVERY_VECTORS.read_text(encoding="utf-8"))
        cls.pubkeys = {
            claim: _decode(value) for claim, value in cls.data["publicKeys"].items()
        }

    def _current_results(self, authority):
        args = (
            authority["bundle"],
            authority["listing"],
            self.pubkeys,
            authority["referenceValidationByCanonicalRef"],
            authority["bundleLifecycle"],
            authority["sessionExecutionAuthorityByPhaseKey"],
            authority["verifiedReceiptByCanonicalRef"],
            authority["deliveryArtifactAuthorityByPhaseKey"],
            authority.get("trustedNativeTransactionObservationsByCanonicalRef"),
        )
        kwargs = {
            "legacy_agreement_authority_by_phase_key": (
                refreshed_laa_phase_carriers(authority)
            )
        }
        boolean_result = R.validate_ebfab(*args, **kwargs)
        disposition_result = R.validate_ebfab_disposition(*args, **kwargs)
        return boolean_result, disposition_result

    def _mutate_entitlement(self, authority, mutation, *, credential_free=False):
        closure = authority["deliveryArtifactAuthorityByPhaseKey"][
            "2:deliver-entitlement"
        ]
        entitlement = closure["entitlementRecord"]["artifact"]
        if credential_free:
            entitlement.pop("credentialRef")
            closure.pop("credential")
        else:
            entitlement["credentialRef"] = copy.deepcopy(mutation)
        resign_inner_artifact(
            entitlement, self.data["seeds"]["seller"], R.ENTITLEMENT_DOMAIN
        )
        entitlement_hash = R._signed_envelope_content_hash(entitlement)

        def bind(record):
            record["deliverableContentHash"] = entitlement_hash
            if credential_free:
                record.pop("credentialDelivery")

        replace_top_record(
            authority,
            "deliver-entitlement",
            bind,
            self.data["seeds"],
        )

    def test_present_malformed_credential_ref_is_typed_error_on_both_apis(self):
        for malformed in (
            None,
            [],
            "credential",
            1,
            True,
            {},
            {"ref": None, "accessModel": "buyer-only"},
            {
                "ref": {
                    "anchor": {"kind": "storage-program", "locator": "credential"},
                    "contentHash": "11" * 32,
                },
                "accessModel": "public",
            },
        ):
            authority = copy.deepcopy(
                self.data["executionAuthorities"]["repeated-pay-completed"]
            )
            self._mutate_entitlement(authority, malformed)
            with self.subTest(malformed=malformed):
                boolean_result, disposition_result = self._current_results(authority)
                self.assertFalse(boolean_result[0])
                self.assertEqual("error", getattr(boolean_result[1], "disposition", None))
                self.assertEqual("error", disposition_result[0])
                self.assertIn("credentialRef", disposition_result[1])

    def test_absent_and_valid_private_credential_modes_still_pass(self):
        buyer_only = copy.deepcopy(
            self.data["executionAuthorities"]["repeated-pay-completed"]
        )
        boolean_result, disposition_result = self._current_results(buyer_only)
        self.assertTrue(boolean_result[0], boolean_result[1])
        self.assertEqual("pass", disposition_result[0], disposition_result[1])

        credential_free = copy.deepcopy(buyer_only)
        self._mutate_entitlement(credential_free, None, credential_free=True)
        boolean_result, disposition_result = self._current_results(credential_free)
        self.assertTrue(boolean_result[0], boolean_result[1])
        self.assertEqual("pass", disposition_result[0], disposition_result[1])

        encrypted = copy.deepcopy(buyer_only)
        closure = encrypted["deliveryArtifactAuthorityByPhaseKey"][
            "2:deliver-entitlement"
        ]
        entitlement = closure["entitlementRecord"]["artifact"]
        entitlement["credentialRef"]["accessModel"] = "encrypt-to-buyer"
        closure["credential"]["credentialRef"]["accessModel"] = (
            "encrypt-to-buyer"
        )
        closure["credential"]["storedBytesBase64url"] = "ZW5jcnlwdGVk"
        encrypted_hash = hashlib.sha256(b"encrypted").hexdigest()
        closure["credential"]["storedContentHash"] = encrypted_hash
        credential_ref = entitlement["credentialRef"]["ref"]
        old_ref = copy.deepcopy(credential_ref)
        credential_ref["contentHash"] = encrypted_hash
        closure["credential"]["credentialRef"]["ref"]["contentHash"] = encrypted_hash
        resign_inner_artifact(
            entitlement, self.data["seeds"]["seller"], R.ENTITLEMENT_DOMAIN
        )
        old_key = R.canonical(old_ref).decode("utf-8")
        credential_authority = encrypted["verifiedReceiptByCanonicalRef"].pop(old_key)
        credential_receipt = credential_authority["receipt"]
        credential_receipt["contentHash"] = encrypted_hash
        credential_authority["storageBinding"] = {
            "effectiveAccessMode": "encrypt-to-buyer",
            "storedContentHash": encrypted_hash,
            "encryption": {
                "recipient": "did:demos:buyer",
                "ciphertextContentHash": encrypted_hash,
            },
        }
        encrypted["verifiedReceiptByCanonicalRef"][
            R.canonical(credential_ref).decode("utf-8")
        ] = credential_authority
        entitlement_hash = R._signed_envelope_content_hash(entitlement)

        def bind(record):
            record["deliverableContentHash"] = entitlement_hash
            record["credentialDelivery"]["credentialRef"] = copy.deepcopy(
                entitlement["credentialRef"]
            )

        replace_top_record(
            encrypted,
            "deliver-entitlement",
            bind,
            self.data["seeds"],
        )
        boolean_result, disposition_result = self._current_results(encrypted)
        self.assertTrue(boolean_result[0], boolean_result[1])
        self.assertEqual("pass", disposition_result[0], disposition_result[1])


class HistoricalEvidenceBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(DELIVERY_VECTORS.read_text(encoding="utf-8"))
        cls.pubkeys = {
            claim: _decode(value) for claim, value in cls.data["publicKeys"].items()
        }

    def _sign_bundle(self, bundle, *, domain=R.FAULT_BUNDLE_DOMAIN):
        claims = {
            party["role"]: party["primaryClaim"] for party in bundle["parties"]
        }
        bundle["signatures"] = []
        digest = R.bundle_hash(bundle)
        for role in R._required_bundle_signers(bundle):
            private = Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(self.data["seeds"][role])
            )
            bundle["signatures"].append({
                "party": claims[role],
                "algorithm": "ed25519",
                "value": _encode(private.sign(
                    (domain + digest).encode("utf-8")
                )),
            })

    def _fixture(self):
        authority = copy.deepcopy(
            self.data["executionAuthorities"]["legacy-storage-completed"]
        )
        bundle = authority["bundle"]
        bundle.pop("evidenceBoundFaultBundleVersion")
        bundle["faultBundleVersion"] = "1"
        self._sign_bundle(bundle)
        roles = {
            party["role"]: party["primaryClaim"] for party in bundle["parties"]
        }
        dependencies = {
            "bundleAuthorityByContentHash": {R.bundle_hash(bundle): authority}
        }
        config = {
            "publicKeys": self.pubkeys,
            "partyRolesByJob": {
                bundle["jobId"]: {
                    "buyer": roles["buyer"],
                    "seller": roles["seller"],
                }
            },
        }
        return bundle, authority, dependencies, config

    def test_authenticated_historical_fab_delivery_is_not_current_authority(self):
        # Audit-valid PDE-7 delivery is current-ineligible, like a historical
        # LAA payment: never pass, and not reported as a contradiction.
        bundle, _authority, dependencies, config = self._fixture()
        decision, reason = R._validate_current_use_historical_nonpayment(
            bundle, dependencies, config
        )
        self.assertEqual("indeterminate", decision, reason)
        self.assertIn("legacy delivery", reason)
        self.assertIn("current-ineligible", reason)

    def test_unrelated_current_resolution_does_not_reclassify_ordinary_historical_delivery(self):
        bundle, authority, _dependencies, config = self._fixture()
        bundle.pop("faultBundleVersion")
        bundle.pop("faultedParty")
        bundle["bundleVersion"] = "1"
        self._sign_bundle(bundle, domain=R.BUNDLE_DOMAIN)
        dependencies = {
            "bundleAuthorityByContentHash": {R.bundle_hash(bundle): authority}
        }
        baseline, reason = R._validate_current_use_historical_nonpayment(
            bundle, dependencies, config
        )
        self.assertEqual("indeterminate", baseline, reason)
        self.assertIn("current-ineligible", reason)

        unrelated = self.data["executionAuthorities"]["completed-storage-delivery"]
        unrelated_ref = unrelated["bundle"]["settlementEvidence"][0]
        unrelated_key = R.canonical(unrelated_ref).decode("utf-8")
        authority["referenceValidationByCanonicalRef"][unrelated_key] = copy.deepcopy(
            unrelated["referenceValidationByCanonicalRef"][unrelated_key]
        )
        decision, reason = R._validate_current_use_historical_nonpayment(
            bundle, dependencies, config
        )
        self.assertEqual("indeterminate", decision, reason)
        self.assertIn("current-ineligible", reason)

    def test_wrong_job_and_malformed_historical_evidence_refuse_without_throwing(self):
        for mutation in ("wrong-job", "malformed"):
            bundle, authority, _dependencies, config = self._fixture()
            ref = bundle["settlementEvidence"][0]
            key = R.canonical(ref).decode("utf-8")
            record = authority["referenceValidationByCanonicalRef"][key]["record"]
            if mutation == "wrong-job":
                record["jobId"] = "different-job"
            else:
                record["phase"] = []
            dependencies = {
                "bundleAuthorityByContentHash": {R.bundle_hash(bundle): authority}
            }
            with self.subTest(mutation=mutation):
                decision, reason = R._validate_current_use_historical_nonpayment(
                    bundle, dependencies, config
                )
                self.assertEqual("fail", decision)
                self.assertIn("not authenticated", reason)

    def test_missing_historical_resolution_is_indeterminate_not_tamper(self):
        for mutation, expected in (("missing", "indeterminate"), ("tampered", "fail")):
            bundle, authority, dependencies, config = self._fixture()
            ref = bundle["settlementEvidence"][0]
            key = R.canonical(ref).decode("utf-8")
            if mutation == "missing":
                del authority["referenceValidationByCanonicalRef"][key]
            else:
                authority["referenceValidationByCanonicalRef"][key]["record"]["jobId"] = "different-job"
            with self.subTest(mutation=mutation):
                decision, _reason = R._validate_current_use_historical_nonpayment(
                    bundle, dependencies, config
                )
                self.assertEqual(expected, decision)

    def test_current_use_historical_branch_propagates_four_state_disposition(self):
        job = {
            "jobId": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "substrate": "fixture",
            "roles": {"buyer": {}, "seller": {}},
        }
        bundle = {
            "evidenceBoundFaultBundleVersion": "1",
            "jobId": job["jobId"],
            "outcome": "completed",
        }
        resolved = {
            "decision": "pass",
            "disposition": "present",
            "bundle": bundle,
            "presence": {"bundleHash": "fixture", "nativeAddress": "fixture", "writer": "fixture"},
        }
        for disposition in ("error", "indeterminate", "fail"):
            with self.subTest(disposition=disposition), patch(
                "dacs5_reference._resolve_current_use_role",
                side_effect=[copy.deepcopy(resolved), copy.deepcopy(resolved)],
            ), patch(
                "dacs5_reference._job_successful_payment_without_strong_finality",
                return_value=True,
            ), patch(
                "dacs5_reference._authority_for_bundle",
                return_value={"evidenceReceiptContract": "archival"},
            ), patch(
                "dacs5_reference.reconcile_authenticated_finality_copies",
                return_value={"decision": disposition, "reason": "archival disposition"},
            ) as reconciler:
                result = R._resolve_current_use_job(
                    job,
                    {},
                    {"publicKeys": self.pubkeys, "finalityTrust": {}},
                    {},
                    {},
                )
                self.assertEqual(disposition, result["decision"])
                self.assertIn("archival disposition", result["reason"])
                reconciler.assert_called_once()


if __name__ == "__main__":
    unittest.main()
