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
    derive_phase_disposition,
    encode,
    move_verified_receipt,
    refreshed_laa_phase_carriers,
    relink_payload_attestation,
    replace_top_record,
    resign_ebfab,
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


if __name__ == "__main__":
    unittest.main()
