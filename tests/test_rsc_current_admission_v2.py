"""Versioned current RSC admission and independent capacity contracts.

The versioned ``rsc-current-admission-v2`` policy and the 16,384-octet
signature-omitted canonical Listing cap are exercised here at the contract
layer. The frozen v1 corpus is intentionally unchanged and is not re-run as
fresh v2 admission; see ``test_revocation_state_completeness_vectors`` for the
recorded-policy replay oracle.
"""
import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import jcs
from rsc_current_admission import (
    CURRENT_ADMISSION_POLICY, CURRENT_VALUES_POLICY, CONFORMANCE_SUBSTRATE,
    CONFORMANCE_FINALITY, TrustedNativeRecordBinding, listing_content_size,
    validate_listing_capacity, joined_current_state,
)
import listing_artifact


def native_encode(listing):
    return jcs.canonicalize({"record": listing, "encoding": "fixture-json-v1"}).encode("utf-8")


def binding(limit=65536):
    return TrustedNativeRecordBinding(CONFORMANCE_SUBSTRATE, CONFORMANCE_FINALITY,
                                     "fixture-json-v1", limit, native_encode)


def signed_evidence(state_id):
    return {"policy": CURRENT_VALUES_POLICY, "finalizedStateId": state_id}


def trusted_state(state_id="fixture-finalized-evaluation-300"):
    return {
        "admissionPolicy": CURRENT_ADMISSION_POLICY,
        "evaluationState": {
            "policy": CURRENT_VALUES_POLICY,
            "finalizedStateId": state_id,
            "substrate": CONFORMANCE_SUBSTRATE,
            "finalityProfile": CONFORMANCE_FINALITY,
        },
    }


class ListingCapacityTests(unittest.TestCase):
    def disposition(self, value, adapter):
        return validate_listing_capacity(value, adapter, substrate=CONFORMANCE_SUBSTRATE,
                                         finality_profile=CONFORMANCE_FINALITY)

    def test_exact_content_boundaries_and_preserved_extensions(self):
        value = {"extension": "", "signature": {"value": "signature"}}
        remaining = 16384 - listing_content_size(value)
        value["extension"] = "a" * remaining
        self.assertEqual(listing_content_size(value), 16384)
        self.assertEqual(self.disposition(value, binding()), "pass")
        value["extension"] += "a"
        self.assertEqual(self.disposition(value, binding()), "fail")
        self.assertEqual(listing_content_size({"signatures": ["kept"]}), len(b'{"signatures":["kept"]}'))

    def test_utf8_octets_and_complete_native_record(self):
        value = {"extension": "é", "signature": {"value": "short"}}
        original_size = listing_content_size(value)
        adapter = binding(len(native_encode(value)))
        self.assertEqual(self.disposition(value, adapter), "pass")
        value["signature"]["value"] += "longer"
        self.assertEqual(listing_content_size(value), original_size)
        self.assertEqual(self.disposition(value, adapter), "fail")

    def test_unknown_native_encoding_never_defaults_to_canonical_size(self):
        value = {"extension": "ordinary", "signature": {"value": "signature"}}
        self.assertEqual(self.disposition(value, None), "indeterminate")
        self.assertEqual(self.disposition(value, {"record_limit": 65536}), "indeterminate")
        adapter = TrustedNativeRecordBinding(CONFORMANCE_SUBSTRATE, CONFORMANCE_FINALITY,
                                            "unsupported", 65536, lambda value: None)
        self.assertEqual(self.disposition(value, adapter), "indeterminate")


class JoinedCurrentStateTests(unittest.TestCase):
    def test_common_state_joins_distinct_authenticated_values(self):
        self.assertTrue(joined_current_state(
            signed_evidence("fixture-finalized-evaluation-300"),
            signed_evidence("fixture-finalized-evaluation-300"),
            trusted_state(),
        ))

    def test_different_states_do_not_join(self):
        self.assertFalse(joined_current_state(
            signed_evidence("fixture-finalized-evaluation-300"),
            signed_evidence("fixture-finalized-evaluation-301"),
            trusted_state(),
        ))

    def test_missing_or_mismatched_policy_is_indeterminate_not_pass(self):
        self.assertFalse(joined_current_state(None, None, trusted_state()))
        base = trusted_state()
        for field in ("admissionPolicy", "evaluationState"):
            changed = copy.deepcopy(base)
            changed.pop(field)
            self.assertFalse(joined_current_state(
                signed_evidence("fixture-finalized-evaluation-300"),
                signed_evidence("fixture-finalized-evaluation-300"),
                changed,
            ))
        changed = copy.deepcopy(base)
        changed["evaluationState"]["substrate"] = "other-substrate"
        self.assertFalse(joined_current_state(
            signed_evidence("fixture-finalized-evaluation-300"),
            signed_evidence("fixture-finalized-evaluation-300"),
            changed,
        ))


class ListingArtifactDispatchTests(unittest.TestCase):
    def test_classify_listing_artifact_discriminator(self):
        self.assertEqual(listing_artifact.classify_listing_artifact({"dacsVersion": "1"}),
                         ("Listing", "dacs-listing:v1:"))
        self.assertEqual(
            listing_artifact.classify_listing_artifact({"revocationBoundListingVersion": "1"}),
            ("RevocationBoundListing", "dacs-revocation-bound-listing:v1:"),
        )
        for bad in ({}, {"dacsVersion": "1", "revocationBoundListingVersion": "1"},
                    {"dacsVersion": "2"}, []):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    listing_artifact.classify_listing_artifact(bad)

    def test_sealed_session_deadline_gates_both_modes(self):
        pipeline = [
            {"kind": "negotiate-sealed-envelope", "parameters": {"commitDeadline": 100_060_000}},
        ]
        listing = {"pipeline": pipeline}
        self.assertTrue(listing_artifact.validate_sealed_session_deadline(listing, 100_000_000)[0])
        self.assertFalse(listing_artifact.validate_sealed_session_deadline(listing, 100_000_001)[0])
        # A non-sealed pipeline has nothing to gate and remains valid.
        self.assertTrue(listing_artifact.validate_sealed_session_deadline(
            {"pipeline": [{"kind": "negotiate-fixed-price"}]}, 100_000_000)[0])
        for bad in ({"pipeline": "nope"}, {"pipeline": [None]}, None):
            with self.subTest(bad=bad):
                ok, _ = listing_artifact.validate_sealed_session_deadline(bad, 100_000_000)
                self.assertFalse(ok)

    def test_listing_window_is_one_trusted_instant(self):
        listing = {"validity": {"notBefore": 100, "notAfter": 200}}
        self.assertTrue(listing_artifact.validate_listing_window(listing, 150)[0])
        self.assertFalse(listing_artifact.validate_listing_window(listing, 99)[0])
        self.assertFalse(listing_artifact.validate_listing_window(listing, 201)[0])
        self.assertFalse(listing_artifact.validate_listing_window(listing, None)[0])
        self.assertFalse(listing_artifact.validate_listing_window(
            {"validity": {"notBefore": 200, "notAfter": 100}}, 150)[0])


if __name__ == "__main__":
    unittest.main()
