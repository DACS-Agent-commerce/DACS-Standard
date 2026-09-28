"""Benign boundary controls for #333 bundle and delivery admission repairs.

These tests construct only unsigned local objects.  They do not regenerate signed
fixtures or exercise the held adversarial mutation/corpus workflows.
"""

import base64
import copy
import hashlib
import unittest

import dacs5_reference as R
from test_phase_bound_delivery_vectors import evaluate


BUYER = "cci:" + "11" * 32
SELLER = "cci:" + "22" * 32
JOB = "01K333BENIGN00000000000000"
PHASE_INDEX = 2
PHASE_KIND = "deliver-storage-program"


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def dependency_authority(raw=b"\x00\xffbenign payload"):
    digest = hashlib.sha256(raw).hexdigest()
    locator = f"dacs4:deliverable:{JOB}:{PHASE_INDEX}"
    reference = {
        "anchor": {"kind": "storage-program", "locator": locator},
        "contentHash": digest,
        "signer": SELLER,
    }
    entry = {
        "available": True,
        "nativeAddress": "stor-native-benign",
        "independentlyResolvable": True,
    }
    receipt = {
        "receiptVersion": "1",
        "substrate": "benign-test-substrate",
        "finalityProfile": "benign-final",
        "logicalAddress": locator,
        "nativeAddress": entry["nativeAddress"],
        "contentHash": digest,
        "transactionRef": {"kind": "benign-transaction", "value": "tx-benign"},
        "writer": SELLER,
        "nonce": "2",
        "state": "finalized",
        "observationDisposition": "established",
        "observedAt": 1786000000000,
        "blockRef": {"id": "block-benign"},
        "evidence": {"kind": "benign-proof", "value": "proof-benign"},
    }
    receipts = {R.canonical(reference).decode("utf-8"): receipt}
    return reference, entry, receipt, receipts


class BundlePointerAdmissionDeliveryAuthorityTests(unittest.TestCase):
    def test_current_and_historical_receipts_use_explicit_contracts(self):
        _, _, current, _ = dependency_authority()
        self.assertEqual(
            R._validate_current_evidence_receipt(current, "2"), (True, "ok")
        )
        self.assertFalse(R._validate_current_evidence_receipt(current, "3")[0])
        integer_nonce = {**current, "nonce": 2}
        self.assertFalse(R._validate_current_evidence_receipt(integer_nonce, None)[0])
        self.assertFalse(R._validate_legacy_evidence_receipt(current, None)[0])

        historical = {
            "transaction": "historical-benign-transaction",
            "nonce": 0,
        }
        self.assertEqual(
            R._validate_legacy_evidence_receipt(historical, None), (True, "ok")
        )
        self.assertFalse(R._validate_current_evidence_receipt(historical, None)[0])

    def test_storage_authority_shape_and_value_dispositions(self):
        digest = "a" * 64
        valid = {"effectiveAccessMode": "buyer-only", "storedContentHash": digest,
                 "acl": {"mode": "restricted", "allowed": [BUYER]}}
        def result(value):
            return R._validate_authenticated_storage_binding(
                value, "buyer-only", BUYER, digest, digest, "unsigned storage model")[0]
        self.assertEqual(result(valid), "pass")
        self.assertEqual(result(None), "indeterminate")
        for changes in ({"storedContentHash": None}, {"storedContentHash": "bad"},
                        {"acl": []}, {"acl": {"mode": "restricted", "allowed": None}},
                        {"acl": {"mode": "restricted", "allowed": [None]}}):
            with self.subTest(changes=changes):
                self.assertEqual(result({**valid, **changes}), "error")
        self.assertEqual(result({**valid, "storedContentHash": "b" * 64}), "fail")
        self.assertEqual(result({**valid, "acl": {"mode": "restricted", "allowed": [SELLER]}}), "fail")
        encrypted = {"effectiveAccessMode": "encrypt-to-buyer", "storedContentHash": digest,
                     "encryption": {"recipient": BUYER, "ciphertextContentHash": digest}}
        for value in (None, [], {"recipient": BUYER, "ciphertextContentHash": "bad"}):
            self.assertEqual(R._validate_authenticated_storage_binding(
                {**encrypted, "encryption": value}, "encrypt-to-buyer", BUYER,
                digest, digest, "unsigned encryption model")[0], "error")

    def test_optional_reference_signer_preserves_receipt_writer_authority(self):
        reference, entry, receipt, _ = dependency_authority()
        reference.pop("signer")
        def result(writer, expected=SELLER):
            receipts = {R.canonical(reference).decode(): {**receipt, "writer": writer}}
            return R._resolved_delivery_dependency(
                entry, reference, receipts, True, "unsigned optional signer model",
                job_id=JOB, phase_index=PHASE_INDEX, phase_kind=PHASE_KIND,
                expected_writer=expected)[0][0]
        self.assertEqual(result(SELLER), "pass")
        self.assertEqual(result(BUYER), "fail")
        self.assertEqual(result(SELLER, None), "pass")
        reference["signer"] = SELLER
        self.assertEqual(result(BUYER, None), "fail")

    def test_supported_selectors_are_exact_and_unknown_members_remain_inert(self):
        current = {
            "bundleVersion": "1",
            "futureBundleVersion": "signed-inert-member",
        }
        self.assertEqual(R.bundle_type(current), "legacy")
        self.assertTrue(R._full_bundle_family_shape_valid(current, "legacy"))
        self.assertIsNone(R.bundle_type({"futureBundleVersion": "1"}))
        self.assertIsNone(R.bundle_type({"bundleVersion": "2"}))
        self.assertIsNone(R.bundle_type({
            "bundleVersion": "1", "faultBundleVersion": "1"
        }))
        self.assertFalse(R._full_bundle_family_shape_valid(
            {"bundleVersion": "1", "pointerKind": "extended"}, "legacy"
        ))

        self.assertTrue(R._pointer_family_shape_valid({
            "faultBundleVersion": "1",
            "pointerKind": "extended",
            "futureBundleVersion": "signed-inert-member",
        }, "fault"))
        self.assertFalse(R._pointer_family_shape_valid({
            "faultBundleVersion": "1",
            "evidenceBoundFaultBundleVersion": "1",
            "pointerKind": "extended",
        }, "fault"))
        self.assertFalse(R.resolve_absolute_fault_pointer({}, {})["ok"])
        self.assertEqual(R._tagged_copy_validation_for_derive({
            "bundle": current,
            "expectedFamily": "legacy",
        })[0], "indeterminate")
        self.assertEqual(R._tagged_copy_validation_for_derive({
            "bundle": current,
            "bundleAdmissionAuthority": {"publicKeys": {}},
            "expectedFamily": "legacy",
        })[0], "error")

    def test_exact_binary_storage_and_authenticated_private_modes(self):
        cleartext = b"\x00\xff\x80payload\x00"
        cleartext_hash = hashlib.sha256(cleartext).hexdigest()
        base = {
            "cleartextBytesBase64url": b64url(cleartext),
            "cleartextHash": cleartext_hash,
            "storedBytesBase64url": b64url(cleartext),
            "storedContentHash": cleartext_hash,
        }

        public = R._validate_resolved_storage(
            base,
            cleartext_hash,
            "public",
            "binary storage",
            authenticated_storage_binding={
                "effectiveAccessMode": "public",
                "storedContentHash": cleartext_hash,
            },
            buyer=BUYER,
        )
        self.assertEqual(public[0], "pass")

        buyer_only = R._validate_resolved_storage(
            base,
            cleartext_hash,
            "buyer-only",
            "buyer-only storage",
            authenticated_storage_binding={
                "effectiveAccessMode": "buyer-only",
                "storedContentHash": cleartext_hash,
                "acl": {"mode": "restricted", "allowed": [BUYER]},
            },
            buyer=BUYER,
        )
        self.assertEqual(buyer_only[0], "pass")

        ciphertext = b"benign ciphertext bytes"
        ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()
        encrypted = copy.deepcopy(base)
        encrypted["storedBytesBase64url"] = b64url(ciphertext)
        encrypted["storedContentHash"] = ciphertext_hash
        encrypted_result = R._validate_resolved_storage(
            encrypted,
            cleartext_hash,
            "encrypt-to-buyer",
            "encrypted storage",
            authenticated_storage_binding={
                "effectiveAccessMode": "encrypt-to-buyer",
                "storedContentHash": ciphertext_hash,
                "encryption": {
                    "recipient": BUYER,
                    "ciphertextContentHash": ciphertext_hash,
                },
            },
            buyer=BUYER,
        )
        self.assertEqual(encrypted_result[0], "pass")

        overprovisioned = R._validate_resolved_storage(
            base,
            cleartext_hash,
            "public",
            "over-provisioned storage",
            authenticated_storage_binding={
                "effectiveAccessMode": "buyer-only",
                "storedContentHash": cleartext_hash,
                "acl": {"mode": "restricted", "allowed": [BUYER]},
            },
            buyer=BUYER,
        )
        self.assertEqual(overprovisioned[0], "pass")

        contradictory = copy.deepcopy(base)
        contradictory["cleartextUtf8"] = "different"
        self.assertEqual(R._validate_resolved_storage(
            contradictory,
            cleartext_hash,
            "public",
            "contradictory storage",
            authenticated_storage_binding={
                "effectiveAccessMode": "public",
                "storedContentHash": cleartext_hash,
            },
            buyer=BUYER,
        )[0], "fail")
        self.assertEqual(R._validate_resolved_storage(
            base, cleartext_hash, "public", "missing authority", buyer=BUYER
        )[0], "indeterminate")
        malformed_bytes = copy.deepcopy(base)
        malformed_bytes["cleartextBytesBase64url"] = "AA=="
        self.assertEqual(R._validate_resolved_storage(
            malformed_bytes,
            cleartext_hash,
            "public",
            "malformed binary storage",
            authenticated_storage_binding={
                "effectiveAccessMode": "public",
                "storedContentHash": cleartext_hash,
            },
            buyer=BUYER,
        )[0], "error")
        self.assertEqual(R._validate_resolved_storage(
            encrypted,
            cleartext_hash,
            "encrypt-to-buyer",
            "wrong encrypted recipient",
            authenticated_storage_binding={
                "effectiveAccessMode": "encrypt-to-buyer",
                "storedContentHash": ciphertext_hash,
                "encryption": {
                    "recipient": SELLER,
                    "ciphertextContentHash": ciphertext_hash,
                },
            },
            buyer=BUYER,
        )[0], "fail")

    def test_full_reference_receipt_and_lifecycle_are_required(self):
        reference, entry, receipt, receipts = dependency_authority()
        result, _, observed = R._resolved_delivery_dependency(
            entry,
            reference,
            receipts,
            True,
            "benign dependency",
            job_id=JOB,
            phase_index=PHASE_INDEX,
            phase_kind=PHASE_KIND,
            expected_writer=SELLER,
        )
        self.assertEqual(result[0], "pass")
        self.assertEqual(observed, receipt)

        included_receipt = copy.deepcopy(receipt)
        included_receipt["state"] = "included"
        included_receipts = {
            R.canonical(reference).decode("utf-8"): included_receipt
        }
        included_entry = copy.deepcopy(entry)
        included_entry["independentlyResolvable"] = False
        self.assertEqual(R._resolved_delivery_dependency(
            included_entry,
            reference,
            included_receipts,
            False,
            "non-completed dependency",
            job_id=JOB,
            phase_index=PHASE_INDEX,
            phase_kind=PHASE_KIND,
            expected_writer=SELLER,
        )[0][0], "pass")

        self.assertEqual(R._resolved_delivery_dependency(
            entry,
            reference,
            None,
            True,
            "missing receipt",
            job_id=JOB,
            phase_index=PHASE_INDEX,
            phase_kind=PHASE_KIND,
            expected_writer=SELLER,
        )[0][0], "indeterminate")

        missing_native = copy.deepcopy(entry)
        missing_native.pop("nativeAddress")
        self.assertEqual(R._resolved_delivery_dependency(
            missing_native,
            reference,
            receipts,
            True,
            "missing native authority",
            job_id=JOB,
            phase_index=PHASE_INDEX,
            phase_kind=PHASE_KIND,
            expected_writer=SELLER,
        )[0][0], "indeterminate")

        malformed = {R.canonical(reference).decode("utf-8"): []}
        self.assertEqual(R._resolved_delivery_dependency(
            entry,
            reference,
            malformed,
            True,
            "malformed receipt",
            job_id=JOB,
            phase_index=PHASE_INDEX,
            phase_kind=PHASE_KIND,
            expected_writer=SELLER,
        )[0][0], "error")

        accepted_receipt = copy.deepcopy(receipt)
        accepted_receipt["state"] = "accepted"
        accepted_receipt.pop("blockRef")
        accepted = {R.canonical(reference).decode("utf-8"): accepted_receipt}
        self.assertEqual(R._resolved_delivery_dependency(
            entry,
            reference,
            accepted,
            True,
            "non-final receipt",
            job_id=JOB,
            phase_index=PHASE_INDEX,
            phase_kind=PHASE_KIND,
            expected_writer=SELLER,
        )[0][0], "fail")

        contradictory_receipt = copy.deepcopy(receipt)
        contradictory_receipt["writer"] = BUYER
        contradictory = {
            R.canonical(reference).decode("utf-8"): contradictory_receipt
        }
        self.assertEqual(R._resolved_delivery_dependency(
            entry,
            reference,
            contradictory,
            True,
            "contradictory receipt",
            job_id=JOB,
            phase_index=PHASE_INDEX,
            phase_kind=PHASE_KIND,
            expected_writer=SELLER,
        )[0][0], "fail")

    def test_standalone_attestation_binds_complete_locator_context(self):
        method = {"kind": "self-signed"}
        method_hash = R._complete_object_hash(method)
        record = {
            "payloadAttestationVersion": "1",
            "jobId": JOB,
            "verificationMethod": "self-signed",
            "verificationMethodHash": method_hash,
            "attempt": 0,
            "signature": {"signer": SELLER},
        }
        locator = (
            f"dacs4:payload-attestation:{JOB}:{PHASE_INDEX}:{method_hash}:0"
        )
        reference = {
            "anchor": {"kind": "storage-program", "locator": locator},
            "contentHash": R._signed_envelope_content_hash(record),
            "signer": SELLER,
        }
        execution = {
            "jobId": JOB,
            "phaseIndex": PHASE_INDEX,
            "phaseKind": "deliver-attested-payload",
        }
        self.assertEqual(R.validate_payload_attestation_locator_context(
            record, reference, execution, method
        )[0], "pass")
        wrong_locator = copy.deepcopy(reference)
        wrong_locator["anchor"]["locator"] += ":other"
        self.assertEqual(R.validate_payload_attestation_locator_context(
            record, wrong_locator, execution, method
        )[0], "fail")
        self.assertEqual(R.validate_payload_attestation_locator_context(
            record, {"anchor": reference["anchor"]}, execution, method
        )[0], "error")

    def test_alternate_evaluator_handles_malformed_collections_without_exception(self):
        self.assertEqual(evaluate({
            "pipeline": [None], "bundle": {}, "evidenceRecords": []
        }), "error")
        self.assertEqual(evaluate({
            "pipeline": [{"index": [], "kind": "deliver-storage-program"}],
            "bundle": {},
            "evidenceRecords": [],
        }), "error")
        self.assertEqual(evaluate({
            "pipeline": [],
            "bundle": {},
            "evidenceRecords": [],
            "artifactRecords": [None],
        }), "error")
        self.assertEqual(evaluate({
            "pipeline": [],
            "bundle": {},
            "evidenceRecords": [],
            "deliveryAuthorities": "not-a-collection",
        }), "error")
        self.assertEqual(evaluate({
            "pipeline": [],
            "bundle": {"parties": [None], "signatures": []},
            "evidenceRecords": [],
        }), "error")


if __name__ == "__main__":
    unittest.main()
