"""Regression coverage for current and archival evidence admission boundaries."""

import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import dacs5_reference as R
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_bundle_settlement_evidence_bijection_vectors import (
    refreshed_laa_phase_carriers,
    replace_top_record,
    resign_inner_artifact,
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
            expected_jobid=CURRENT_JOB,
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

        archival = copy.deepcopy(present)
        archival["authority"]["evidenceReceiptContract"] = "archival"
        archival_result = R.reconcile_authenticated_finality_copies(
            [archival, absent], self.pubkeys, trust
        )
        self.assertEqual("indeterminate", archival_result["decision"])
        self.assertIn("comparison-only", archival_result["reason"])

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

    def _sign_bundle(self, bundle):
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
                    (R.FAULT_BUNDLE_DOMAIN + digest).encode("utf-8")
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

    def test_legitimate_historical_fab_binding_passes_without_type_error(self):
        bundle, _authority, dependencies, config = self._fixture()
        decision, reason = R._validate_current_use_historical_nonpayment(
            bundle, dependencies, config
        )
        self.assertEqual("pass", decision, reason)

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
