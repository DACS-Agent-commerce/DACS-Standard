"""Regressions for four-state disposition precedence and authority joins.

Each control runs through the public entry points (direct disposition,
Boolean compatibility, extended pointer, and reconciliation) so a repair in
one core cannot silently diverge from another consumer.
"""

import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path

import dacs5_reference as R
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_bundle_pointer_admission_delivery_authority import (
    BUYER,
    JOB,
    PHASE_INDEX,
    PHASE_KIND,
    SELLER,
    dependency_authority,
)
from test_bundle_settlement_evidence_bijection_vectors import (
    bind_laa_authority_to_bundle,
    derive_phase_disposition,
    encode,
    laa_authority_for_bundle,
    move_verified_receipt,
    refreshed_laa_phase_carriers,
    relink_payload_attestation,
    replace_payment_with_transition_evidence,
    replace_top_record,
    resign_ebfab,
    resign_evidence,
    resign_listing,
)


ROOT = Path(__file__).resolve().parents[1]
SEB_VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "bundle-settlement-evidence-bijection-v0.4.json"
)
FINALITY_VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "settlement-finality-verification.json"
)
CURRENT_JOB = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


def _decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _key(ref):
    return R.canonical(ref).decode("utf-8")


class _SebFixtures:
    """Signed EBFAB fixtures and the four public consumers."""

    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(SEB_VECTORS.read_text(encoding="utf-8"))
        cls.pubkeys = {
            claim: _decode(value) for claim, value in cls.data["publicKeys"].items()
        }

    def _sign(self, role, domain, digest):
        private = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(self.data["seeds"][role])
        )
        return _encode(private.sign((domain + digest).encode("utf-8")))

    def _source(self, name):
        return copy.deepcopy(self.data["executionAuthorities"][name])

    def _member_key(self, source, phase):
        return next(
            _key(ref) for ref in source["bundle"]["settlementEvidence"]
            if source["referenceValidationByCanonicalRef"][_key(ref)]["record"]["phase"] == phase
        )

    def _args(self, source):
        return (
            source["bundle"], source["listing"], self.pubkeys,
            source["referenceValidationByCanonicalRef"], source["bundleLifecycle"],
            source["sessionExecutionAuthorityByPhaseKey"],
            source["verifiedReceiptByCanonicalRef"],
            source["deliveryArtifactAuthorityByPhaseKey"],
            source["trustedNativeTransactionObservationsByCanonicalRef"],
        )

    def _laa(self, source):
        return {
            "legacy_agreement_authority_by_phase_key":
                source["legacyAgreementAuthorityByPhaseKey"],
        }

    def _direct(self, source):
        return R.validate_ebfab_disposition(
            *self._args(copy.deepcopy(source)), **self._laa(source)
        )[:2]

    def _boolean(self, source):
        ok, reason, _ = R.validate_ebfab(
            *self._args(copy.deepcopy(source)), **self._laa(source)
        )
        return ("pass" if ok else getattr(reason, "disposition", "fail"), reason)

    def _reconcile(self, source):
        source = copy.deepcopy(source)
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
        result = R.reconcile_authenticated_finality_copies(
            [
                {
                    "bundle": bundle, "expectedJobId": bundle["jobId"],
                    "expectedRole": role, "copyPresence": presence,
                    "authority": source, "evidenceReceiptContract": "current",
                },
                {"disposition": "absent", "expectedJobId": bundle["jobId"], "expectedRole": other},
            ],
            self.pubkeys,
            trust,
        )
        return result["decision"], result["reason"]

    def _pointer(self, source):
        source = copy.deepcopy(source)
        bundle = source["bundle"]
        role = bundle["anchoredByRole"]
        signer = next(p["primaryClaim"] for p in bundle["parties"] if p["role"] == role)
        pointer = {
            "evidenceBoundFaultBundleVersion": "1",
            "pointerKind": "extended",
            "fullBundleUrl": "https://fixtures.example/seb6-precedence",
            "fullBundleContentHash": R.bundle_hash(bundle),
            "signature": {"signer": signer, "algorithm": "ed25519", "value": ""},
        }
        pointer["signature"]["value"] = self._sign(
            role, R.EVIDENCE_BOUND_FAULT_POINTER_DOMAIN, R.pointer_hash(pointer)
        )
        result = R.resolve_absolute_fault_pointer(
            pointer, bundle,
            pubkeys=R.trusted_verification_keys(copy.deepcopy(self.pubkeys)),
            ebfab_authority=source,
            trusted_contexts=R.trusted_profile_context(bundle["jobId"], signer, role=role),
            expected_jobid=bundle["jobId"], expected_role=role,
        )
        return ("pass" if result["ok"] else result.get("disposition", "fail"), result["reason"])

    def _assert_paths(self, source, expected, *, pointer=False):
        paths = [("direct", self._direct), ("boolean", self._boolean), ("reconcile", self._reconcile)]
        if pointer:
            paths.append(("pointer", self._pointer))
        for path, consumer in paths:
            with self.subTest(path=path):
                disposition, reason = consumer(source)
                self.assertEqual(expected, disposition, reason)

    # --- mutations of verifier-owned authority (no re-signing needed)

    def _observe(self, source, phase, *, variant="well-formed"):
        key = self._member_key(source, phase)
        receipts = source["verifiedReceiptByCanonicalRef"]
        prior = copy.deepcopy(receipts[key])
        receipts[key]["observationDisposition"] = "indeterminate"
        receipts[key]["preservedReceiptHash"] = (
            [] if variant == "malformed"
            else hashlib.sha256(R.canonical(prior)).hexdigest()
        )
        if variant == "mis-bound":
            receipts[key]["writer"] = "did:demos:buyer"
        if variant == "later":
            # A real observation is a later snapshot, not a byte copy of the
            # established receipt that the LAA carrier binds.
            receipts[key]["observedAt"] = prior["observedAt"] + 1000
        return source

    def _without_lifecycle_finality(self, source):
        source["bundleLifecycle"] = dict(source["bundleLifecycle"], state="included")
        return source

    # --- ULID-job variants for the extended-pointer consumer

    def _ulid_payment_source(self):
        source = self._source("single-htlc-direct-completed")
        source["bundle"]["jobId"] = CURRENT_JOB
        replace_top_record(
            source, "pay-cross-chain-htlc",
            lambda record: record.__setitem__("jobId", CURRENT_JOB), self.data["seeds"],
        )
        execution = source["sessionExecutionAuthorityByPhaseKey"]["2:pay-cross-chain-htlc"]
        execution["jobId"] = CURRENT_JOB
        ref = source["bundle"]["phaseSummary"][2]["attestationRef"]
        source["verifiedReceiptByCanonicalRef"][_key(ref)]["logicalAddress"] = (
            "dacs4:payment:%s:%s:2" % (CURRENT_JOB, execution["railId"])
        )
        resign_ebfab(source["bundle"], self.data["seeds"])
        source["legacyAgreementAuthorityByPhaseKey"] = refreshed_laa_phase_carriers(source)
        return source

    def _ulid_delivery_source(self):
        source = self._source("completed-storage-delivery")
        bundle = source["bundle"]
        bundle["jobId"] = CURRENT_JOB
        old_ref = copy.deepcopy(bundle["settlementEvidence"][0])
        resolution = source["referenceValidationByCanonicalRef"].pop(_key(old_ref))
        record = resolution["record"]
        old_deliverable_ref = {
            "anchor": copy.deepcopy(record["deliverableAnchor"]),
            "contentHash": record["deliverableContentHash"],
        }
        record["jobId"] = CURRENT_JOB
        record["deliverableAnchor"]["locator"] = "dacs4:deliverable:%s:0" % CURRENT_JOB
        signer = record["signature"]["signer"]
        record["signature"] = {"signer": signer, "algorithm": "ed25519", "value": ""}
        record["signature"]["value"] = self._sign(
            signer.rsplit(":", 1)[1], R.DELIVERY_EVIDENCE_DOMAIN,
            R.delivery_evidence_hash(record),
        )
        new_ref = copy.deepcopy(old_ref)
        new_ref["contentHash"] = R.delivery_evidence_hash(record)
        source["referenceValidationByCanonicalRef"][_key(new_ref)] = resolution
        top_receipt = source["verifiedReceiptByCanonicalRef"].pop(_key(old_ref))
        top_receipt["logicalAddress"] = "dacs4:delivery:%s:0" % CURRENT_JOB
        top_receipt["contentHash"] = new_ref["contentHash"]
        source["verifiedReceiptByCanonicalRef"][_key(new_ref)] = top_receipt
        locator = record["deliverableAnchor"]["locator"]
        new_deliverable_ref = {
            "anchor": copy.deepcopy(record["deliverableAnchor"]),
            "contentHash": record["deliverableContentHash"],
        }
        deliverable = source["verifiedReceiptByCanonicalRef"].pop(_key(old_deliverable_ref))
        deliverable["receipt"]["logicalAddress"] = locator
        deliverable["receipt"]["nativeAddress"] = locator
        source["verifiedReceiptByCanonicalRef"][_key(new_deliverable_ref)] = deliverable
        closure = source["deliveryArtifactAuthorityByPhaseKey"]["0:deliver-storage-program"]
        closure["deliverable"]["logicalAddress"] = locator
        closure["deliverable"]["nativeAddress"] = locator
        execution = source["sessionExecutionAuthorityByPhaseKey"]["0:deliver-storage-program"]
        execution["jobId"] = CURRENT_JOB
        execution["evidenceLogicalAddress"] = "dacs4:delivery:%s:0" % CURRENT_JOB
        bundle["settlementEvidence"] = [new_ref]
        bundle["phaseSummary"][0]["attestationRef"] = copy.deepcopy(new_ref)
        resign_ebfab(bundle, self.data["seeds"])
        return source


class SebSixPendingPrecedenceTests(_SebFixtures, unittest.TestCase):
    """SEB-6: an availability-only member result never masks fail or error."""

    def test_controls_are_discriminating(self):
        self._assert_paths(self._source("standard-completed"), "pass")
        self._assert_paths(self._source("invalid-deliverable-locator-closure"), "fail")
        self._assert_paths(
            self._without_lifecycle_finality(self._source("standard-completed")), "fail"
        )
        self._assert_paths(self._ulid_payment_source(), "pass", pointer=True)
        self._assert_paths(self._ulid_delivery_source(), "pass", pointer=True)

    def test_receipt_observation_is_pending_until_independent_checks_run(self):
        # The payment member precedes the delivery member, so an early return
        # on its observation used to hide the later delivery-closure failure.
        cases = (
            ("alone", self._observe(self._source("standard-completed"), "pay-dem"), "indeterminate"),
            ("cross-member closure fail",
             self._observe(self._source("invalid-deliverable-locator-closure"), "pay-dem"), "fail"),
            ("bundle lifecycle fail", self._without_lifecycle_finality(
                self._observe(self._source("standard-completed"), "pay-dem")), "fail"),
            ("delivery member alone", self._observe(
                self._source("standard-completed"), "deliver-attested-payload"), "indeterminate"),
            ("malformed observation", self._observe(
                self._source("invalid-deliverable-locator-closure"), "pay-dem",
                variant="malformed"), "error"),
            ("mis-bound observation", self._observe(
                self._source("standard-completed"), "pay-dem", variant="mis-bound"), "fail"),
            ("later snapshot alone", self._observe(
                self._source("standard-completed"), "pay-dem", variant="later"), "indeterminate"),
            ("later snapshot, cross-member closure fail", self._observe(
                self._source("invalid-deliverable-locator-closure"), "pay-dem",
                variant="later"), "fail"),
        )
        for label, source, expected in cases:
            with self.subTest(case=label):
                self._assert_paths(source, expected)
        payment = "pay-cross-chain-htlc"
        for label, source, expected in (
            ("pointer alone", self._observe(self._ulid_payment_source(), payment), "indeterminate"),
            ("pointer lifecycle fail", self._without_lifecycle_finality(
                self._observe(self._ulid_payment_source(), payment)), "fail"),
            ("pointer delivery alone", self._observe(
                self._ulid_delivery_source(), "deliver-storage-program"), "indeterminate"),
            ("pointer delivery lifecycle fail", self._without_lifecycle_finality(
                self._observe(self._ulid_delivery_source(), "deliver-storage-program")), "fail"),
        ):
            with self.subTest(case=label):
                self._assert_paths(source, expected, pointer=True)

    def test_unavailable_laa_authority_is_pending(self):
        def without_laa(source, phase_key):
            del source["legacyAgreementAuthorityByPhaseKey"][phase_key]
            return source

        for label, source, expected in (
            ("alone", without_laa(self._source("standard-completed"), "2:pay-dem"), "indeterminate"),
            ("cross-member closure fail", without_laa(
                self._source("invalid-deliverable-locator-closure"), "2:pay-dem"), "fail"),
            ("bundle lifecycle fail", self._without_lifecycle_finality(
                without_laa(self._source("standard-completed"), "2:pay-dem")), "fail"),
        ):
            with self.subTest(case=label):
                self._assert_paths(source, expected)
        for label, source, expected in (
            ("pointer alone", without_laa(
                self._ulid_payment_source(), "2:pay-cross-chain-htlc"), "indeterminate"),
            ("pointer lifecycle fail", self._without_lifecycle_finality(without_laa(
                self._ulid_payment_source(), "2:pay-cross-chain-htlc")), "fail"),
        ):
            with self.subTest(case=label):
                self._assert_paths(source, expected, pointer=True)

    def _delivery_first(self, source):
        """Order the delivery member first so its outage precedes the payment."""
        bundle = source["bundle"]
        bundle["settlementEvidence"].sort(
            key=lambda ref: source["referenceValidationByCanonicalRef"][_key(ref)]
            ["record"]["phase"] != "deliver-attested-payload"
        )
        resign_ebfab(bundle, self.data["seeds"])
        source["legacyAgreementAuthorityByPhaseKey"] = refreshed_laa_phase_carriers(source)
        return source

    def test_unavailable_delivery_execution_authority_is_pending(self):
        delivery_key = "3:deliver-attested-payload"

        def without_execution(source, phase_key=delivery_key):
            del source["sessionExecutionAuthorityByPhaseKey"][phase_key]
            return source

        def foreign_payment_writer(source):
            key = self._member_key(source, "pay-dem")
            source["verifiedReceiptByCanonicalRef"][key]["writer"] = "did:demos:buyer"
            return source

        reordered = self._delivery_first(self._source("standard-completed"))
        self._assert_paths(reordered, "pass")
        for label, source, expected in (
            ("alone", without_execution(self._source("standard-completed")), "indeterminate"),
            ("alone, delivery first", without_execution(copy.deepcopy(reordered)), "indeterminate"),
            ("cross-member payment binding fail", foreign_payment_writer(
                without_execution(copy.deepcopy(reordered))), "fail"),
            ("same-member signed anchor fail", without_execution(
                self._source("invalid-deliverable-locator-closure")), "fail"),
            ("bundle lifecycle fail", self._without_lifecycle_finality(
                without_execution(self._source("standard-completed"))), "fail"),
            ("receipt unavailable alone", self._without_receipt(
                self._source("standard-completed"), "deliver-attested-payload"), "indeterminate"),
            ("receipt unavailable, closure fail", self._without_receipt(
                self._source("invalid-deliverable-locator-closure"),
                "deliver-attested-payload"), "fail"),
        ):
            with self.subTest(case=label):
                self._assert_paths(source, expected)
        for label, source, expected in (
            ("pointer alone", without_execution(
                self._ulid_delivery_source(), "0:deliver-storage-program"), "indeterminate"),
            ("pointer lifecycle fail", self._without_lifecycle_finality(without_execution(
                self._ulid_delivery_source(), "0:deliver-storage-program")), "fail"),
        ):
            with self.subTest(case=label):
                self._assert_paths(source, expected, pointer=True)

    def _without_receipt(self, source, phase):
        del source["verifiedReceiptByCanonicalRef"][self._member_key(source, phase)]
        return source

    def test_present_execution_authority_still_excludes_a_deferred_member(self):
        # An unavailable receipt defers only a member that present SB-1
        # authority does not already exclude.
        source = self._without_receipt(
            self._source("standard-completed"), "deliver-attested-payload"
        )
        source["sessionExecutionAuthorityByPhaseKey"]["3:deliver-attested-payload"][
            "phaseOrchestrator"
        ] = "did:demos:buyer"
        self._assert_paths(source, "fail")

    def test_unplaced_member_can_fill_only_a_missing_invocation(self):
        payment_key = "2:pay-dem"
        source = self._source("standard-completed")
        del source["referenceValidationByCanonicalRef"][self._member_key(source, "pay-dem")]
        self._assert_paths(source, "indeterminate")
        self._assert_paths(self._without_lifecycle_finality(copy.deepcopy(source)), "fail")
        # Unavailable payment execution authority is keyed by the receipt's
        # exact address, as on the released-FAB gate.
        source = self._source("standard-completed")
        del source["sessionExecutionAuthorityByPhaseKey"][payment_key]
        self._assert_paths(source, "indeterminate")
        # A signed optional pointer that names a placed member for the missing
        # invocation is a deterministic SEB-5 disagreement.
        source = self._source("standard-completed")
        payment_member = self._member_key(source, "pay-dem")
        del source["referenceValidationByCanonicalRef"][payment_member]
        delivery_ref = next(
            ref for ref in source["bundle"]["settlementEvidence"] if _key(ref) != payment_member
        )
        source["bundle"]["phaseSummary"][2]["attestationRef"] = copy.deepcopy(delivery_ref)
        resign_ebfab(source["bundle"], self.data["seeds"])
        self._assert_paths(source, "fail")
        self.assertEqual(
            ("fail", "optional phase pointer contradicts settlementEvidence"),
            self._direct(source),
        )


class SebSixSameMemberPrecedenceTests(_SebFixtures, unittest.TestCase):
    """A pending member still runs every check that its own content decides."""

    def _payment_record_source(self, mutate, *, drop_receipt=False, drop_execution=False):
        source = self._source("standard-completed")
        replace_top_record(source, "pay-dem", mutate, self.data["seeds"])
        source["legacyAgreementAuthorityByPhaseKey"] = refreshed_laa_phase_carriers(source)
        payment = next(
            _key(ref) for ref in source["bundle"]["settlementEvidence"]
            if source["referenceValidationByCanonicalRef"][_key(ref)]["record"]["phase"]
            in R.PAYMENT_PHASES
        )
        if drop_receipt:
            del source["verifiedReceiptByCanonicalRef"][payment]
        if drop_execution:
            del source["sessionExecutionAuthorityByPhaseKey"]["2:pay-dem"]
        return source

    def test_unplaced_payment_keeps_its_own_contradictions(self):
        def failure(record):
            record["outcome"] = "failure"
            record["reason"] = "insufficient-funds"
            for field in ("settlementFinality", "paymentTxRefs", "paymentAmount"):
                record.pop(field, None)

        def foreign_kind(record):
            failure(record)
            record["phase"] = "pay-x402"

        base = self._source("standard-completed")
        delivery_ref = next(
            ref for ref in base["bundle"]["settlementEvidence"]
            if _key(ref) == self._member_key(base, "deliver-attested-payload")
        )

        def top_level_edge(record):
            record["supersedesEvidenceRef"] = copy.deepcopy(delivery_ref)

        for label, mutate in (
            ("outcome contradicts every signed row", failure),
            ("kind outside the signed pipeline", foreign_kind),
            ("supersession edge names a top-level member", top_level_edge),
        ):
            for drop in ("receipt", "execution"):
                with self.subTest(case=label, unavailable=drop):
                    self._assert_paths(self._payment_record_source(
                        mutate, drop_receipt=drop == "receipt",
                        drop_execution=drop == "execution",
                    ), "fail")

    def test_unavailable_execution_still_binds_the_present_receipt(self):
        receipt_mutations = (
            ("writer is not the evidence signer", "writer", "did:demos:buyer"),
            ("contentHash differs from the reference", "contentHash", "ab" * 32),
        )
        for phase, phase_key in (
            ("pay-dem", "2:pay-dem"),
            ("deliver-attested-payload", "3:deliver-attested-payload"),
        ):
            source = self._source("standard-completed")
            del source["sessionExecutionAuthorityByPhaseKey"][phase_key]
            with self.subTest(phase=phase, case="control"):
                self._assert_paths(source, "indeterminate")
            for label, field, value in receipt_mutations + (
                ("established state contradicts the lifecycle", "state", "included"),
            ):
                source = self._source("standard-completed")
                source["verifiedReceiptByCanonicalRef"][self._member_key(source, phase)][field] = value
                del source["sessionExecutionAuthorityByPhaseKey"][phase_key]
                with self.subTest(phase=phase, case=label):
                    self._assert_paths(source, "fail")
        source = self._source("standard-completed")
        key = self._member_key(source, "deliver-attested-payload")
        source["verifiedReceiptByCanonicalRef"][key]["logicalAddress"] = (
            "dacs4:delivery:%s:2" % source["bundle"]["jobId"]
        )
        del source["sessionExecutionAuthorityByPhaseKey"]["3:deliver-attested-payload"]
        self._assert_paths(source, "fail")
        # The archival PDE-7 lane keeps its indexed-address contradiction.
        legacy = self._source("legacy-storage-completed")
        receipt = legacy["verifiedReceiptByCanonicalRef"][_key(legacy["bundle"]["settlementEvidence"][0])]
        receipt["logicalAddress"] = "dacs4:delivery:%s:0" % legacy["bundle"]["jobId"]
        del legacy["sessionExecutionAuthorityByPhaseKey"]["0:deliver-storage-program"]
        self.assertEqual("fail", R.validate_archival_audit_ebfab_disposition(
            *self._args(legacy), **self._laa(legacy)
        )[0])

    def test_pointers_for_missing_invocations_name_distinct_fitting_members(self):
        def pointed(first, second, drop):
            source = self._source("standard-completed")
            payment = self._member_key(source, "pay-dem")
            delivery = self._member_key(source, "deliver-attested-payload")
            refs = {_key(ref): ref for ref in source["bundle"]["settlementEvidence"]}
            names = {"pay": refs[payment], "del": refs[delivery]}
            source["bundle"]["phaseSummary"][2]["attestationRef"] = copy.deepcopy(names[first])
            source["bundle"]["phaseSummary"][3]["attestationRef"] = copy.deepcopy(names[second])
            resign_ebfab(source["bundle"], self.data["seeds"])
            source["legacyAgreementAuthorityByPhaseKey"] = refreshed_laa_phase_carriers(source)
            for item in drop:
                collection, member = item.split(":")
                target = payment if member == "pay" else delivery
                del source[collection][target]
            return source

        resolutions = "referenceValidationByCanonicalRef"
        receipts = "verifiedReceiptByCanonicalRef"
        for label, source, expected in (
            ("one member reused by two pointers", pointed(
                "pay", "pay", (resolutions + ":pay", resolutions + ":del")), "fail"),
            ("pointer names a member of another kind", pointed(
                "del", "pay", (receipts + ":pay", resolutions + ":del")), "fail"),
            ("swapped pointers, contents unknown", pointed(
                "del", "pay", (resolutions + ":pay", resolutions + ":del")), "indeterminate"),
        ):
            with self.subTest(case=label):
                self._assert_paths(source, expected)

    def test_receipt_named_invocation_is_injective(self):
        source = self._source("repeated-pay-completed")
        second = next(
            _key(ref) for ref in source["bundle"]["settlementEvidence"]
            if source["verifiedReceiptByCanonicalRef"][_key(ref)]["logicalAddress"].endswith(":1")
        )
        receipt = source["verifiedReceiptByCanonicalRef"][second]
        receipt["logicalAddress"] = receipt["logicalAddress"][:-2] + ":0"
        del source["sessionExecutionAuthorityByPhaseKey"]["0:pay-dem"]
        self._assert_paths(source, "fail")

    def test_no_single_outage_downgrades_a_shipped_rejection(self):
        # A missing supersession edge contradicts only a :resolved receipt
        # address, so without that receipt the member may be ordinary.
        receipt_dependent = {
            ("invalid-completed-st8-missing-supersedes", "receipt:pay-cross-chain-htlc"),
        }

        def disposition(source):
            verifier = (
                R.validate_archival_audit_ebfab_disposition
                if source.get("deliveryEvidenceProfile") == "archival"
                else R.validate_ebfab_disposition
            )
            return verifier(
                *self._args(copy.deepcopy(source)),
                legacy_agreement_authority_by_phase_key=source.get(
                    "legacyAgreementAuthorityByPhaseKey", {}
                ),
            )[0]

        downgraded = []
        for name in self.data["executionAuthorities"]:
            base = self._source(name)
            if disposition(base) not in {"fail", "error"}:
                continue
            outages = [("execution:" + key, "sessionExecutionAuthorityByPhaseKey", key)
                       for key in base["sessionExecutionAuthorityByPhaseKey"]]
            for ref in base["bundle"]["settlementEvidence"]:
                resolution = base["referenceValidationByCanonicalRef"].get(_key(ref))
                if isinstance(resolution, dict) and isinstance(resolution.get("record"), dict):
                    outages.append(("receipt:" + str(resolution["record"].get("phase")),
                                    "verifiedReceiptByCanonicalRef", _key(ref)))
            for label, collection, member in outages:
                source = self._source(name)
                source[collection].pop(member, None)
                if (
                    disposition(source) == "indeterminate"
                    and (name, label) not in receipt_dependent
                ):
                    downgraded.append((name, label))
        self.assertEqual([], downgraded)


class AdmittingEntryBoundaryTests(_SebFixtures, unittest.TestCase):
    """The admitting entry never widens a check whose binding success rejects."""

    def _expired_with_successor(self, pin_nonce, successor_nonce, *, drop_execution):
        completed = self._source("single-htlc-completed")
        source = self._source("single-htlc-expired")
        interim_ref = source["bundle"]["settlementEvidence"][0]
        execution_key = "2:pay-cross-chain-htlc"
        if pin_nonce is not None:
            source["sessionExecutionAuthorityByPhaseKey"][execution_key]["anchorNonce"] = pin_nonce
        successor = next(
            copy.deepcopy(resolution)
            for resolution in completed["referenceValidationByCanonicalRef"].values()
            if resolution["record"]["outcome"] == "success"
        )
        record = successor["record"]
        record["jobId"] = source["bundle"]["jobId"]
        record["supersedesEvidenceRef"] = copy.deepcopy(interim_ref)
        resign_evidence(record, self.data["seeds"]["seller"])
        digest = R.settlement_evidence_hash(record)
        successor_ref = {
            "anchor": {"kind": "storage-program", "locator": "stor-successor-nonce"},
            "contentHash": digest,
        }
        successor["lifecycle"] = {"state": "finalized", "independentlyResolvable": True}
        source["referenceValidationByCanonicalRef"][_key(successor_ref)] = successor
        receipt = copy.deepcopy(source["verifiedReceiptByCanonicalRef"][_key(interim_ref)])
        receipt.update({
            "logicalAddress": receipt["logicalAddress"] + ":resolved",
            "nativeAddress": "stor-successor-nonce",
            "contentHash": digest,
            "nonce": successor_nonce,
            "state": "finalized",
            "transactionRef": {"kind": "demos-transaction", "value": "tx-successor-nonce"},
        })
        source["verifiedReceiptByCanonicalRef"][_key(successor_ref)] = receipt
        if drop_execution:
            del source["sessionExecutionAuthorityByPhaseKey"][execution_key]
        return source

    def test_successor_scan_respects_the_unavailable_nonce_pin(self):
        for label, pin, nonce, drop, expected in (
            ("unpinned entry, bound successor", None, "2", False, "fail"),
            ("pinned entry, inert successor", "2", "999", False, "pass"),
            ("pin unavailable, successor binds only unpinned", "2", "999", True, "indeterminate"),
            ("pin unavailable, successor matches the member nonce", "2", "2", True, "fail"),
        ):
            with self.subTest(case=label):
                self._assert_paths(
                    self._expired_with_successor(pin, nonce, drop_execution=drop), expected
                )

    def test_archival_successor_scan_pins_integer_nonces(self):
        def archival(pin, member_nonce, successor_nonce, drop):
            source = self._expired_with_successor(pin, "unused", drop_execution=drop)
            interim = _key(source["bundle"]["settlementEvidence"][0])
            for key, receipt in source["verifiedReceiptByCanonicalRef"].items():
                receipt["transaction"] = receipt["transactionRef"]["value"]
                receipt["nonce"] = member_nonce if key == interim else successor_nonce
            return R.validate_legacy_ebfab_disposition(
                *self._args(source), **self._laa(source)
            )[:2]

        for label, pin, member_nonce, successor_nonce, drop, expected in (
            ("pinned entry, inert successor", 2, 2, 999, False, "pass"),
            ("pin unavailable, successor binds only unpinned", 2, 2, 999, True, "indeterminate"),
            ("pin unavailable, successor matches the member nonce", 2, 2, 2, True, "fail"),
        ):
            with self.subTest(case=label):
                disposition, reason = archival(pin, member_nonce, successor_nonce, drop)
                self.assertEqual(expected, disposition, reason)

    def _transition_source(self, phase_index=None, *, drop_receipt=False):
        source = self._source("standard-completed")
        laa = laa_authority_for_bundle(source, operation="transition-audit")
        record = replace_payment_with_transition_evidence(source, laa, self.data["seeds"])
        source["legacyAgreementAuthorityByPhaseKey"] = {
            "2:pay-dem": bind_laa_authority_to_bundle(source, laa)
        }
        old_ref = next(
            ref for ref in source["bundle"]["settlementEvidence"]
            if source["referenceValidationByCanonicalRef"][_key(ref)]["record"] is record
        )
        if phase_index is not None:
            resolution = source["referenceValidationByCanonicalRef"].pop(_key(old_ref))
            receipt = source["verifiedReceiptByCanonicalRef"].pop(_key(old_ref))
            record["phaseIndex"] = phase_index
            record["signature"]["value"] = ""
            digest = R.settlement_evidence_hash(record)
            record["signature"]["value"] = self._sign(
                "orchestrator", R.LEGACY_TRANSITION_SETTLEMENT_EVIDENCE_DOMAIN, digest
            )
            new_ref = dict(copy.deepcopy(old_ref), contentHash=digest)
            receipt["contentHash"] = digest
            source["referenceValidationByCanonicalRef"][_key(new_ref)] = resolution
            source["verifiedReceiptByCanonicalRef"][_key(new_ref)] = receipt
            source["bundle"]["settlementEvidence"] = [
                new_ref if ref == old_ref else ref
                for ref in source["bundle"]["settlementEvidence"]
            ]
            for entry in source["bundle"]["phaseSummary"]:
                if entry.get("attestationRef") == old_ref:
                    entry["attestationRef"] = new_ref
            resign_ebfab(source["bundle"], self.data["seeds"])
            old_ref = new_ref
        if drop_receipt:
            del source["verifiedReceiptByCanonicalRef"][_key(old_ref)]
        return source

    def test_receiptless_transition_payment_fills_only_its_signed_invocation(self):
        for label, index, drop, expected in (
            ("genuine transition", None, False, "pass"),
            ("genuine transition, receipt unavailable", None, True, "indeterminate"),
            ("signed index outside the pipeline", 7, True, "fail"),
            ("signed index of another kind", 0, True, "fail"),
        ):
            with self.subTest(case=label):
                disposition, reason = self._direct(
                    self._transition_source(index, drop_receipt=drop)
                )
                self.assertEqual(expected, disposition, reason)


class PendingReceiptPaymentPrecedenceTests(_SebFixtures, unittest.TestCase):
    """A pending payment receipt defers only checks that need that receipt."""

    PAYMENT = "pay-cross-chain-htlc"
    PAYMENT_KEY = "2:pay-cross-chain-htlc"

    def _with_agreement_ref(self, source, *, mismatch=False, mutate_laa=None):
        carrier = next(iter(source["legacyAgreementAuthorityByPhaseKey"].values()))
        joined = carrier["laa"]["agreement"]["contentHash"]
        source["bundle"]["agreementRef"] = {
            "anchor": {
                "kind": "storage-program",
                "locator": "dacs3:agreement:" + source["bundle"]["jobId"],
            },
            "contentHash": "d" * 64 if mismatch else joined,
        }
        resign_ebfab(source["bundle"], self.data["seeds"])
        if mutate_laa is not None:
            for carrier in source["legacyAgreementAuthorityByPhaseKey"].values():
                mutate_laa(carrier["laa"])
        source["legacyAgreementAuthorityByPhaseKey"] = refreshed_laa_phase_carriers(source)
        return source

    def _pending(self, source, how):
        if how == "removed":
            del source["verifiedReceiptByCanonicalRef"][
                self._member_key(source, self.PAYMENT)
            ]
        elif how == "observation":
            self._observe(source, self.PAYMENT, variant="later")
        return source

    def _cases(self, factory, pointer):
        for how in ("present", "removed", "observation"):
            yield ("joined agreementRef", how, self._pending(
                self._with_agreement_ref(factory()), how,
            ), "pass" if how == "present" else "indeterminate")
            yield ("mismatched agreementRef", how, self._pending(
                self._with_agreement_ref(factory(), mismatch=True), how,
            ), "fail")
        for label, mutate, expected in (
            ("malformed agreement shape",
             lambda laa: laa["agreement"].__setitem__("shape", "malformed"), "error"),
            ("identity-only agreement",
             lambda laa: laa["agreement"].update(
                 {"artifact": "identity-bound", "ibhVerified": True, "pbVerified": False}
             ), "fail"),
            ("unverified session",
             lambda laa: laa["sessionAuthority"].__setitem__("state", "pending"),
             "indeterminate"),
        ):
            yield (label, "removed", self._pending(
                self._with_agreement_ref(factory(), mutate_laa=mutate), "removed",
            ), expected)

    def test_receipt_independent_laa_checks_outrank_a_pending_receipt(self):
        for factory, pointer in (
            (lambda: self._source("single-htlc-direct-completed"), False),
            (self._ulid_payment_source, True),
        ):
            for label, how, source, expected in self._cases(factory, pointer):
                with self.subTest(case=label, receipt=how, pointer=pointer):
                    self._assert_paths(source, expected, pointer=pointer)

    def test_only_receipt_bound_carrier_fields_are_deferred(self):
        def other_receipt(source):
            for carrier in source["legacyAgreementAuthorityByPhaseKey"].values():
                carrier["binding"]["evidenceReceiptHash"] = "e" * 64
            return source

        present = other_receipt(self._source("single-htlc-direct-completed"))
        self._assert_paths(present, "fail")
        removed = self._pending(
            other_receipt(self._source("single-htlc-direct-completed")), "removed"
        )
        self._assert_paths(removed, "indeterminate")

    def test_available_execution_authority_excludes_receiptless_candidates(self):
        def contradict(field, value):
            def mutate(source):
                source["sessionExecutionAuthorityByPhaseKey"][self.PAYMENT_KEY][field] = value
                return source
            return mutate

        for factory, pointer in (
            (lambda: self._source("single-htlc-direct-completed"), False),
            (self._ulid_payment_source, True),
        ):
            with self.subTest(case="genuine, receipt removed", pointer=pointer):
                self._assert_paths(
                    self._pending(factory(), "removed"), "indeterminate", pointer=pointer
                )
            unavailable = self._pending(factory(), "removed")
            del unavailable["sessionExecutionAuthorityByPhaseKey"][self.PAYMENT_KEY]
            with self.subTest(case="execution and receipt unavailable", pointer=pointer):
                self._assert_paths(unavailable, "indeterminate", pointer=pointer)
            for label, mutate in (
                ("another orchestrator", contradict("phaseOrchestrator", "did:demos:buyer")),
                ("another job", contradict("jobId", "01ARZ3NDEKTSV4RRFFQ69G5FAW")),
                ("another invocation", contradict("phaseIndex", 1)),
            ):
                for how in ("present", "removed"):
                    with self.subTest(case=label, receipt=how, pointer=pointer):
                        self._assert_paths(
                            self._pending(mutate(factory()), how), "fail", pointer=pointer
                        )

    def test_finality_bound_core_keeps_the_same_precedence(self):
        import scripts.generate_settlement_finality_verification_vectors as finality
        from test_settlement_finality_verification_vectors import decode_public_keys

        def result(mismatch=False, drop_receipt=False, foreign=False):
            factory = finality.FixtureFactory()
            case = factory.strong_bundle_case("bft-final")
            verification = next(iter(
                case["authority"]["finalityVerificationByCanonicalRef"].values()
            ))
            case["bundle"]["agreementRef"] = factory.reference(
                "agreement:bft-final",
                "33" * 32 if mismatch
                else finality.artifact_hash(verification["agreement"], "signatures"),
            )
            factory.sign_bundle(case["bundle"], finality.FINALITY_BUNDLE_DOMAIN)
            factory.bind_current_laa_authority(case["bundle"], case["authority"])
            authority = case["authority"]
            if foreign:
                for entry in authority["sessionExecutionAuthorityByPhaseKey"].values():
                    entry["phaseOrchestrator"] = "did:demos:intruder"
            if drop_receipt:
                del authority["verifiedReceiptByCanonicalRef"][
                    _key(case["bundle"]["settlementEvidence"][0])
                ]
            return R.validate_finality_bound_ebfab(
                case["bundle"], authority["listing"], decode_public_keys(factory.trusted),
                authority["referenceValidationByCanonicalRef"], authority["bundleLifecycle"],
                authority["sessionExecutionAuthorityByPhaseKey"],
                authority["verifiedReceiptByCanonicalRef"],
                authority.get("finalityVerificationByCanonicalRef"), factory.trusted,
                legacy_agreement_authority_by_phase_key=authority.get(
                    "legacyAgreementAuthorityByPhaseKey"
                ),
            )[:2]

        for label, kwargs, expected in (
            ("joined", {}, "pass"),
            ("joined, receipt removed", {"drop_receipt": True}, "indeterminate"),
            ("mismatched agreementRef, receipt removed",
             {"mismatch": True, "drop_receipt": True}, "fail"),
            ("another orchestrator, receipt removed",
             {"foreign": True, "drop_receipt": True}, "fail"),
        ):
            with self.subTest(case=label):
                disposition, reason = result(**kwargs)
                self.assertEqual(expected, disposition, reason)


class LaaAgreementJoinPrecedenceTests(_SebFixtures, unittest.TestCase):
    """The agreementRef join keeps error > fail > indeterminate."""

    def _joined_source(self, mutate, agreement_hash=None):
        source = self._source("standard-completed")
        joined = next(iter(source["legacyAgreementAuthorityByPhaseKey"].values()))[
            "laa"]["agreement"]["contentHash"]
        source["bundle"]["agreementRef"] = {
            "anchor": {
                "kind": "storage-program",
                "locator": "dacs3:agreement:" + source["bundle"]["jobId"],
            },
            "contentHash": agreement_hash or joined,
        }
        resign_ebfab(source["bundle"], self.data["seeds"])
        mutate(source, joined)
        source["legacyAgreementAuthorityByPhaseKey"] = refreshed_laa_phase_carriers(source)
        return source

    def test_join_mismatch_never_outranks_malformed_authority(self):
        def carriers(source):
            return list(source["legacyAgreementAuthorityByPhaseKey"].values())

        def agreement(field, value):
            return lambda source, joined: [
                carrier["laa"]["agreement"].__setitem__(field, value(joined))
                for carrier in carriers(source)
            ]

        def session_pending(source, joined):
            for carrier in carriers(source):
                carrier["laa"]["sessionAuthority"]["state"] = "pending"

        unrelated = "c" * 64
        for label, mutate, agreement_hash, expected in (
            ("joined", lambda source, joined: None, None, "pass"),
            ("unrelated", lambda source, joined: None, unrelated, "fail"),
            ("malformed carrier shape beside an unrelated ref",
             agreement("shape", lambda joined: "malformed"), unrelated, "error"),
            ("non-string operation beside an unrelated ref",
             lambda source, joined: [carrier["laa"].__setitem__("operation", 7)
                                     for carrier in carriers(source)], unrelated, "error"),
            ("padded agreement contentHash",
             agreement("contentHash", lambda joined: " " + joined), None, "error"),
            ("unverified session beside an unrelated ref", session_pending, unrelated, "fail"),
        ):
            with self.subTest(case=label):
                source = self._joined_source(mutate, agreement_hash)
                self.assertEqual(expected, self._direct(source)[0], self._direct(source)[1])

    def test_finality_verification_error_outranks_a_join_fail(self):
        import scripts.generate_settlement_finality_verification_vectors as finality
        from test_settlement_finality_verification_vectors import decode_public_keys

        for label, unrelated in (("joined", False), ("unrelated", True)):
            factory = finality.FixtureFactory()
            case = factory.strong_bundle_case("block-depth")
            verification = next(iter(
                case["authority"]["finalityVerificationByCanonicalRef"].values()
            ))
            case["bundle"]["agreementRef"] = factory.reference(
                "agreement:block-depth",
                "33" * 32 if unrelated
                else finality.artifact_hash(verification["agreement"], "signatures"),
            )
            factory.sign_bundle(case["bundle"], finality.FINALITY_BUNDLE_DOMAIN)
            factory.bind_current_laa_authority(case["bundle"], case["authority"])
            verification["agreement"] = "not-an-object"
            authority = case["authority"]
            with self.subTest(case=label):
                disposition, reason, _ = R.validate_finality_bound_ebfab(
                    case["bundle"], authority["listing"],
                    decode_public_keys(factory.trusted),
                    authority["referenceValidationByCanonicalRef"],
                    authority["bundleLifecycle"],
                    authority["sessionExecutionAuthorityByPhaseKey"],
                    authority["verifiedReceiptByCanonicalRef"],
                    authority.get("finalityVerificationByCanonicalRef"), factory.trusted,
                    legacy_agreement_authority_by_phase_key=authority.get(
                        "legacyAgreementAuthorityByPhaseKey"
                    ),
                )
                self.assertEqual("error", disposition, reason)


class DependencyReceiptPrecedenceTests(_SebFixtures, unittest.TestCase):
    """PDE-6: missing entry authority cannot downgrade receipt error or fail."""

    def _unit(self, entry, receipt, reference):
        receipts = {_key(reference): receipt}
        return R._resolved_delivery_dependency(
            entry, reference, receipts, True, "dependency",
            job_id=JOB, phase_index=PHASE_INDEX, phase_kind=PHASE_KIND,
            expected_writer=SELLER,
        )[0][0]

    def test_unit_receipt_classes_survive_missing_entry_authority(self):
        reference, entry, receipt, _ = dependency_authority()
        malformed = copy.deepcopy(receipt)
        malformed.pop("evidence")
        contradictory = copy.deepcopy(receipt)
        contradictory["writer"] = BUYER
        non_final = copy.deepcopy(receipt)
        non_final["state"] = "included"
        self.assertEqual("pass", self._unit(entry, receipt, reference))
        self.assertEqual("error", self._unit(entry, malformed, reference))
        self.assertEqual("fail", self._unit(entry, contradictory, reference))
        for missing in ("independentlyResolvable", "nativeAddress"):
            partial = copy.deepcopy(entry)
            partial.pop(missing)
            with self.subTest(missing=missing):
                self.assertEqual("indeterminate", self._unit(partial, receipt, reference))
                self.assertEqual("error", self._unit(partial, malformed, reference))
                self.assertEqual("fail", self._unit(partial, contradictory, reference))
        partial = copy.deepcopy(entry)
        partial.pop("independentlyResolvable")
        self.assertEqual("fail", self._unit(partial, non_final, reference))
        present_malformed = dict(entry, independentlyResolvable="yes")
        self.assertEqual("error", self._unit(present_malformed, contradictory, reference))
        self.assertEqual("fail", self._unit(dict(entry, independentlyResolvable=False), receipt, reference))

    def test_public_entry_receipt_classes_survive_missing_resolvability(self):
        phase_key = "3:deliver-attested-payload"
        for dependency in ("deliverable", "payloadAttestationRecord", "methodEvidence"):
            for mutation, expected in (("none", "pass"), ("malformed", "error"), ("contradictory", "fail")):
                for missing in (False, True):
                    source = self._source("standard-completed")
                    entry = source["deliveryArtifactAuthorityByPhaseKey"][phase_key][dependency]
                    receipt = next(
                        value["receipt"]
                        for value in source["verifiedReceiptByCanonicalRef"].values()
                        if isinstance(value, dict)
                        and isinstance(value.get("receipt"), dict)
                        and value["receipt"].get("nativeAddress") == entry["nativeAddress"]
                    )
                    if mutation == "malformed":
                        receipt.pop("evidence")
                    elif mutation == "contradictory":
                        receipt["writer"] = "did:demos:buyer"
                    if missing:
                        entry.pop("independentlyResolvable")
                    want = "indeterminate" if missing and mutation == "none" else expected
                    with self.subTest(dependency=dependency, receipt=mutation, missing=missing):
                        self._assert_paths(source, want)


class SelfSignedMethodDispositionTests(_SebFixtures, unittest.TestCase):
    """DPA-7: authenticated self-signed contradictions fail; malformed input errors."""

    def _self_signed_source(self, mutate_proof):
        source = self._source("standard-completed")
        closure = source["deliveryArtifactAuthorityByPhaseKey"]["3:deliver-attested-payload"]
        record = closure["payloadAttestationRecord"]["artifact"]
        old_method_ref = copy.deepcopy(record["methodEvidenceRef"])
        deliverable = source["listing"]["offering"]["deliverable"]
        method = {"kind": "self-signed"}
        deliverable["verificationMethod"] = method
        assertion = closure["deliverable"]["cleartextUtf8"]
        proof_key = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(self.data["seeds"]["seller"])
        )
        proof = {
            "kind": "self-signed-payload",
            "payloadContentHash": closure["deliverable"]["cleartextHash"],
            "methodInput": {
                "identifier": proof_key.public_key().public_bytes_raw().hex(),
                "assertion": assertion,
                "signature": encode(proof_key.sign(assertion.encode("utf-8"))),
            },
        }
        mutate_proof(proof)
        closure["methodEvidence"]["artifact"] = proof
        record["deliverableSpecHash"] = R._complete_object_hash(deliverable)
        record["verificationMethod"] = "self-signed"
        record["verificationMethodHash"] = R._complete_object_hash(method)
        # The complete proof hash binds the mutated content, so a contradiction
        # below is authenticated content rather than malformed input.
        record["methodEvidenceRef"]["contentHash"] = R._complete_object_hash(proof)
        move_verified_receipt(source, old_method_ref, record["methodEvidenceRef"])
        record.pop("methodTransactionRef")
        source["trustedNativeTransactionObservationsByCanonicalRef"] = {}
        resign_listing(source["listing"], self.data["seeds"]["seller"])
        source["bundle"]["listingRef"]["contentHash"] = R.listing_hash(source["listing"])
        relink_payload_attestation(source, self.data["seeds"])
        source["legacyAgreementAuthorityByPhaseKey"] = refreshed_laa_phase_carriers(source)
        return source

    def test_unit_predicate_separates_shape_from_contradiction(self):
        payload = b"benign self-signed payload"
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        digest = hashlib.sha256(payload).hexdigest()

        def evidence(**changes):
            proof = {
                "kind": "self-signed-payload",
                "payloadContentHash": digest,
                "methodInput": {
                    "identifier": key.public_key().public_bytes_raw().hex(),
                    "assertion": payload.decode("utf-8"),
                    "signature": encode(key.sign(payload)),
                },
            }
            for field, value in changes.items():
                if value is None:
                    proof.pop(field, None)
                else:
                    proof[field] = value
            return proof

        def result(proof):
            return R.validate_delivery_method_evidence(
                {"kind": "self-signed"}, proof, None, {},
                delivered_cleartext=payload.decode("utf-8"), delivered_bytes=payload,
                payload_content_hash=digest, require_finalized=True,
            )[0]

        without_assertion = evidence()
        without_assertion["methodInput"].pop("assertion")
        wrong_kind_without_assertion = evidence(kind="demos-web2-request")
        wrong_kind_without_assertion["methodInput"].pop("assertion")
        bad_key_wrong_kind = evidence(kind="demos-web2-request")
        bad_key_wrong_kind["methodInput"]["identifier"] = "zz"
        for label, proof, expected in (
            ("genuine", evidence(), "pass"),
            ("wrong kind", evidence(kind="demos-web2-request"), "fail"),
            ("wrong payload hash", evidence(payloadContentHash="ab" * 32), "fail"),
            ("kind not a string", evidence(kind=7), "error"),
            ("kind missing", evidence(kind=None), "error"),
            ("payload hash malformed", evidence(payloadContentHash="not-a-hash"), "error"),
            ("malformed key beside wrong kind", bad_key_wrong_kind, "error"),
            ("assertion unavailable", without_assertion, "indeterminate"),
            ("assertion unavailable beside wrong kind", wrong_kind_without_assertion, "fail"),
        ):
            with self.subTest(case=label):
                self.assertEqual(expected, result(proof))

    def test_public_entry_classifies_authenticated_contradictions_as_fail(self):
        for label, mutate, expected in (
            ("genuine", lambda proof: None, "pass"),
            ("wrong method kind", lambda proof: proof.__setitem__("kind", "demos-web2-request"), "fail"),
            ("wrong payload hash", lambda proof: proof.__setitem__("payloadContentHash", "ab" * 32), "fail"),
            ("malformed payload hash", lambda proof: proof.__setitem__("payloadContentHash", "not-a-hash"), "error"),
            ("malformed method input", lambda proof: proof["methodInput"].__setitem__("extra", "x"), "error"),
        ):
            with self.subTest(case=label):
                self._assert_paths(self._self_signed_source(mutate), expected)


class FinalityBoundPendingPrecedenceTests(unittest.TestCase):
    """The finality-bound consumer defers FV, LAA and SEB outages the same way."""

    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FINALITY_VECTORS.read_text(encoding="utf-8"))
        cls.trust = cls.data["trustedFixturePolicy"]
        cls.pubkeys = {
            signer: _decode(value) for signer, value in cls.trust["partyKeys"].items()
        }
        cls.case = next(
            case for case in cls.data["dacs5"]["strongBundleCases"]
            if case["model"] == "bft-final"
        )

    def _direct(self, case):
        authority = case["authority"]
        return R.validate_finality_bound_ebfab(
            case["bundle"], authority["listing"], self.pubkeys,
            authority["referenceValidationByCanonicalRef"], authority["bundleLifecycle"],
            authority["sessionExecutionAuthorityByPhaseKey"],
            authority["verifiedReceiptByCanonicalRef"],
            authority.get("finalityVerificationByCanonicalRef"), self.trust,
            legacy_agreement_authority_by_phase_key=authority.get(
                "legacyAgreementAuthorityByPhaseKey"
            ),
        )[:2]

    def _reconcile(self, case):
        bundle = case["bundle"]
        role = bundle["anchoredByRole"]
        other = "seller" if role == "buyer" else "buyer"
        party = next(p for p in bundle["parties"] if p["role"] == role)
        presence = {
            "bundleHash": R.bundle_hash(bundle),
            "nativeAddress": "dacs5:bundle:%s:%s" % (bundle["jobId"], role),
            "writer": party["primaryClaim"],
        }
        trust = copy.deepcopy(self.trust)
        trust["copyPresenceByJobRole"] = {bundle["jobId"] + ":" + role: copy.deepcopy(presence)}
        trust["copyDispositionByJobRole"] = {bundle["jobId"] + ":" + other: "absent"}
        result = R.reconcile_authenticated_finality_copies(
            [
                {"bundle": bundle, "expectedJobId": bundle["jobId"], "expectedRole": role,
                 "copyPresence": presence, "authority": case["authority"]},
                {"disposition": "absent", "expectedJobId": bundle["jobId"], "expectedRole": other},
            ],
            self.pubkeys,
            trust,
        )
        return result["decision"], result["reason"]

    def _mutated(self, mutate, *, lifecycle_fail=False):
        case = copy.deepcopy(self.case)
        mutate(case["authority"], _key(case["bundle"]["settlementEvidence"][0]))
        if lifecycle_fail:
            case["authority"]["bundleLifecycle"] = dict(
                case["authority"]["bundleLifecycle"], state="included"
            )
        return case

    def test_pending_authority_never_masks_a_lifecycle_rejection(self):
        def observe(authority, key):
            receipts = authority["verifiedReceiptByCanonicalRef"]
            prior = copy.deepcopy(receipts[key])
            receipts[key]["observationDisposition"] = "indeterminate"
            receipts[key]["preservedReceiptHash"] = hashlib.sha256(
                R.canonical(prior)
            ).hexdigest()

        def later_observe(authority, key):
            observed_at = authority["verifiedReceiptByCanonicalRef"][key]["observedAt"]
            observe(authority, key)
            authority["verifiedReceiptByCanonicalRef"][key]["observedAt"] = observed_at + 1000

        mutations = {
            "control": lambda authority, key: None,
            "receipt observation": observe,
            "later receipt observation": later_observe,
            "LAA unavailable": lambda authority, key: authority.__setitem__(
                "legacyAgreementAuthorityByPhaseKey", {}
            ),
            "FV unavailable": lambda authority, key: authority.pop(
                "finalityVerificationByCanonicalRef"
            ),
            "resolution unavailable": lambda authority, key: authority[
                "referenceValidationByCanonicalRef"
            ].pop(key),
        }
        for label, mutate in mutations.items():
            for lifecycle_fail in (False, True):
                case = self._mutated(mutate, lifecycle_fail=lifecycle_fail)
                expected = (
                    "fail" if lifecycle_fail
                    else "pass" if label == "control" else "indeterminate"
                )
                for path, consumer in (("direct", self._direct), ("reconcile", self._reconcile)):
                    with self.subTest(case=label, lifecycle_fail=lifecycle_fail, path=path):
                        disposition, reason = consumer(case)
                        self.assertEqual(expected, disposition, reason)

    def test_verification_skips_records_the_core_rejected(self):
        # A record without its selector is rejected by the SEB core; FV must
        # not re-read it and turn that rejection into an exception or error.
        def unselected(phase):
            def mutate(authority, key):
                record = authority["referenceValidationByCanonicalRef"][key]["record"]
                record.pop("finalityBoundEvidenceVersion")
                record["phase"] = phase
            return mutate

        for label, phase in (("list phase", ["pay-dem"]), ("string phase", "pay-dem")):
            case = self._mutated(unselected(phase))
            with self.subTest(case=label):
                disposition, reason = self._direct(case)
                self.assertEqual("fail", disposition, reason)


if __name__ == "__main__":
    unittest.main()
