"""Regression tests for total signature-algorithm validation.

Repro: standard-completed authority, resolved deliver-attested-payload
signature.algorithm=[] -> both validate_ebfab and validate_ebfab_disposition
raise unhashable-list TypeError.

Acceptance: arrays, objects, null, booleans, numbers, unsupported strings
rejected without exceptions; valid signatures preserved; evidence and full-bundle
entry points exercised.
"""

import copy
import json
import unittest
from pathlib import Path

import dacs5_reference as R


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance/vectors/security/bundle-settlement-evidence-bijection-v0.4.json"


def decode(value):
    import base64
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class AuthenticatedEvidenceWireTypeAlgorithmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.pubkeys = {
            claim: decode(value)
            for claim, value in cls.data["publicKeys"].items()
        }

    def _get_authority(self, name="standard-completed"):
        return copy.deepcopy(self.data["executionAuthorities"][name])

    def _get_delivery_record(self, authority):
        for resolution in authority["referenceValidationByCanonicalRef"].values():
            if not isinstance(resolution, dict):
                continue
            record = resolution.get("record")
            if isinstance(record, dict) and record.get("phase") == "deliver-attested-payload":
                return record
        raise AssertionError("deliver-attested-payload record not found")

    def _mutate_algorithm(self, authority, new_algorithm):
        record = self._get_delivery_record(authority)
        record["signature"]["algorithm"] = new_algorithm

    def _call_validate_ebfab(self, authority):
        return R.validate_ebfab(
            authority.get("bundle"),
            authority.get("listing"),
            self.pubkeys,
            authority.get("referenceValidationByCanonicalRef"),
            authority.get("bundleLifecycle"),
            authority.get("sessionExecutionAuthorityByPhaseKey"),
            authority.get("verifiedReceiptByCanonicalRef"),
            authority.get("deliveryArtifactAuthorityByPhaseKey"),
            authority.get("trustedNativeTransactionObservationsByCanonicalRef"),
            **R._legacy_agreement_authority_kwargs(authority),
        )

    def _call_validate_ebfab_disposition(self, authority):
        return R.validate_ebfab_disposition(
            authority.get("bundle"),
            authority.get("listing"),
            self.pubkeys,
            authority.get("referenceValidationByCanonicalRef"),
            authority.get("bundleLifecycle"),
            authority.get("sessionExecutionAuthorityByPhaseKey"),
            authority.get("verifiedReceiptByCanonicalRef"),
            authority.get("deliveryArtifactAuthorityByPhaseKey"),
            authority.get("trustedNativeTransactionObservationsByCanonicalRef"),
            **R._legacy_agreement_authority_kwargs(authority),
        )

    def test_algorithm_array_rejected_without_exception_ebfab(self):
        authority = self._get_authority()
        self._mutate_algorithm(authority, [])
        ok, reason, keys = self._call_validate_ebfab(authority)
        self.assertFalse(ok)
        self.assertIsNone(keys)

    def test_algorithm_array_rejected_without_exception_disposition(self):
        authority = self._get_authority()
        self._mutate_algorithm(authority, [])
        disposition, reason, keys = self._call_validate_ebfab_disposition(authority)
        self.assertNotEqual(disposition, "pass")
        self.assertIsNone(keys)

    def test_algorithm_object_rejected_without_exception(self):
        authority = self._get_authority()
        self._mutate_algorithm(authority, {"alg": "ed25519"})
        ok, reason, keys = self._call_validate_ebfab(authority)
        self.assertFalse(ok)
        disposition, reason, keys = self._call_validate_ebfab_disposition(authority)
        self.assertNotEqual(disposition, "pass")

    def test_algorithm_null_rejected_without_exception(self):
        authority = self._get_authority()
        self._mutate_algorithm(authority, None)
        ok, reason, keys = self._call_validate_ebfab(authority)
        self.assertFalse(ok)
        disposition, reason, keys = self._call_validate_ebfab_disposition(authority)
        self.assertNotEqual(disposition, "pass")

    def test_algorithm_boolean_rejected_without_exception(self):
        authority = self._get_authority()
        self._mutate_algorithm(authority, True)
        ok, reason, keys = self._call_validate_ebfab(authority)
        self.assertFalse(ok)
        disposition, reason, keys = self._call_validate_ebfab_disposition(authority)
        self.assertNotEqual(disposition, "pass")

    def test_algorithm_number_rejected_without_exception(self):
        authority = self._get_authority()
        self._mutate_algorithm(authority, 123)
        ok, reason, keys = self._call_validate_ebfab(authority)
        self.assertFalse(ok)
        disposition, reason, keys = self._call_validate_ebfab_disposition(authority)
        self.assertNotEqual(disposition, "pass")

    def test_algorithm_unsupported_string_rejected_without_exception(self):
        authority = self._get_authority()
        self._mutate_algorithm(authority, "rsa-sha256")
        ok, reason, keys = self._call_validate_ebfab(authority)
        self.assertFalse(ok)
        disposition, reason, keys = self._call_validate_ebfab_disposition(authority)
        self.assertNotEqual(disposition, "pass")

    def test_valid_algorithm_preserved(self):
        authority = self._get_authority()
        ok, reason, keys = self._call_validate_ebfab(authority)
        self.assertTrue(ok, reason)
        self.assertIsNotNone(keys)
        disposition, reason, keys = self._call_validate_ebfab_disposition(authority)
        self.assertEqual(disposition, "pass", reason)
        self.assertIsNotNone(keys)

    def test_bundle_signature_algorithms_are_total_on_wrapper_and_family_paths(self):
        for malformed in ([], {}, None, True, 123, "rsa-sha256"):
            authority = self._get_authority()
            bundle = authority["bundle"]
            bundle["signatures"][0]["algorithm"] = malformed
            family = R.bundle_type(bundle)
            with self.subTest(malformed=malformed, path="wrapper"):
                ok, _reason = R._bundle_signatures_valid(bundle, self.pubkeys)
                self.assertFalse(ok)
            with self.subTest(malformed=malformed, path="direct-family"):
                ok, reason = R._bundle_signatures_valid_for_family(
                    bundle, self.pubkeys, family
                )
                self.assertFalse(ok)
                self.assertIn("unsupported or missing signature algorithm", reason)

    def test_valid_bundle_signature_algorithm_is_preserved(self):
        authority = self._get_authority()
        bundle = authority["bundle"]
        family = R.bundle_type(bundle)
        self.assertEqual((True, "ok"), R._bundle_signatures_valid(bundle, self.pubkeys))
        self.assertEqual(
            (True, "ok"),
            R._bundle_signatures_valid_for_family(bundle, self.pubkeys, family),
        )


if __name__ == "__main__":
    unittest.main()
