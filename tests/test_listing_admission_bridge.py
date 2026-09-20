"""Exact Listing admission bridge: fail-closed, no caller-minted authority.

These tests distinguish a retained committed-session Listing capability from
new-session use. The bridge has no authoritative ordered DACS-1 evaluator;
partial shape, signature, current-state labels, and capacity checks cannot
issue a new-session :class:`AdmittedListing`.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import jcs  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import listing_admission  # noqa: E402
import listing_artifact  # noqa: E402
from rsc_current_admission import (  # noqa: E402
    CURRENT_ADMISSION_POLICY,
    CURRENT_VALUES_POLICY,
    CONFORMANCE_SUBSTRATE,
    CONFORMANCE_FINALITY,
    TrustedNativeRecordBinding,
)

IBH = ROOT / "conformance/vectors/security/identity-bundle-hash-binding-v0.1.json"
SELLER_SEED = b"dacs-390-seller"
COMMITTED_BOUNDARY = "past-authenticated-agreement-commitment"


def _seller_private() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(SELLER_SEED).digest())


def _public_hex(priv: Ed25519PrivateKey) -> str:
    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def _sign(value: dict, domain: str, priv: Ed25519PrivateKey) -> dict:
    unsigned = {k: v for k, v in value.items() if k != "signature"}
    digest = hashlib.sha256(jcs.canonicalize(unsigned).encode()).hexdigest()
    signature = base64.urlsafe_b64encode(
        priv.sign((domain + digest).encode())
    ).rstrip(b"=").decode()
    return {
        "algorithm": "ed25519",
        "signer": "key:" + _public_hex(priv),
        "value": signature,
    }


def _legacy_listing() -> dict:
    raw = json.loads(IBH.read_text(encoding="utf-8"))
    return copy.deepcopy(raw["scenarios"]["identityBoundAgreement"]["listing"])


def _revocation_bound_listing() -> dict:
    listing = _legacy_listing()
    listing.pop("dacsVersion")
    listing["revocationBoundListingVersion"] = "1"
    listing["revocationState"] = {
        "revocationStateRefVersion": "1",
        "logicalAddress": "dacs1-revocations:key%3A" + _public_hex(_seller_private()),
        "anchor": {"kind": "storage-program", "locator": "storage-program:revocation-line-a"},
        "checkpointSequence": "0",
        "checkpointHeadHash": "00" * 32,
    }
    priv = _seller_private()
    listing["signature"] = _sign(
        listing, listing_artifact.LISTING_DOMAINS[listing_artifact.REVOCATION_BOUND_LISTING], priv
    )
    return listing


def _normative_current_listing() -> dict:
    """The RSC Listing wire shape retains dacsVersion and its original domain."""
    listing = _revocation_bound_listing()
    listing.pop("revocationBoundListingVersion")
    listing["dacsVersion"] = "1"
    listing["signature"] = _sign(
        listing, listing_artifact.LISTING_DOMAINS[listing_artifact.LEGACY_LISTING],
        _seller_private(),
    )
    return listing


def _native_binding(record_limit: int = 65536) -> TrustedNativeRecordBinding:
    return TrustedNativeRecordBinding(
        CONFORMANCE_SUBSTRATE,
        CONFORMANCE_FINALITY,
        "bridge-fixture-native-envelope-v1",
        record_limit,
        lambda value: jcs.canonicalize({"record": value}).encode("utf-8"),
    )


def _signed_evidence(state_id: str) -> dict:
    return {"policy": CURRENT_VALUES_POLICY, "finalizedStateId": state_id}


def _trusted_state(state_id: str) -> dict:
    return {
        "admissionPolicy": CURRENT_ADMISSION_POLICY,
        "evaluationState": {
            "policy": CURRENT_VALUES_POLICY,
            "finalizedStateId": state_id,
            "substrate": CONFORMANCE_SUBSTRATE,
            "finalityProfile": CONFORMANCE_FINALITY,
        },
    }


class AdmitListingLegacyTests(unittest.TestCase):
    def setUp(self):
        self.listing = _legacy_listing()
        self.key = _public_hex(_seller_private())

    def test_committed_label_without_authenticated_commitment_is_inert(self):
        verdict, reason, record = listing_admission.admit_listing(
            self.listing,
            inclusion_key=self.key,
            session_boundary=COMMITTED_BOUNDARY,
            native_binding=_native_binding(),
        )
        self.assertEqual(verdict, "indeterminate")
        self.assertIn("authenticated committed-session", reason)
        self.assertIsNone(record)

    def test_substituted_listing_is_rejected(self):
        substituted = copy.deepcopy(self.listing)
        substituted["offering"]["title"] = "substituted"
        verdict, reason, record = listing_admission.admit_listing(
            substituted,
            inclusion_key=self.key,
            session_boundary=COMMITTED_BOUNDARY,
            native_binding=_native_binding(),
        )
        self.assertEqual(verdict, "rejected")
        self.assertIsNone(record)
        self.assertIn("signature", reason)

    def test_wrong_inclusion_key_is_rejected(self):
        other_key = "33" * 32
        verdict, reason, record = listing_admission.admit_listing(
            self.listing,
            inclusion_key=other_key,
            session_boundary=COMMITTED_BOUNDARY,
            native_binding=_native_binding(),
        )
        self.assertEqual(verdict, "rejected")
        self.assertIsNone(record)

    def test_publisher_key_mismatch_is_rejected(self):
        verdict, reason, record = listing_admission.admit_listing(
            self.listing,
            inclusion_key="44" * 32,
            session_boundary=COMMITTED_BOUNDARY,
            native_binding=_native_binding(),
        )
        self.assertEqual(verdict, "rejected")
        self.assertIsNone(record)

    def test_unsupported_boundary_is_indeterminate(self):
        verdict, reason, _ = listing_admission.admit_listing(
            self.listing,
            inclusion_key=self.key,
            session_boundary="not-a-boundary",
            native_binding=_native_binding(),
        )
        self.assertEqual(verdict, "indeterminate")

    def test_native_cap_failure_is_rejected(self):
        verdict, reason, record = listing_admission.admit_listing(
            self.listing,
            inclusion_key=self.key,
            session_boundary=COMMITTED_BOUNDARY,
            native_binding=_native_binding(record_limit=1),
        )
        self.assertEqual(verdict, "rejected")
        self.assertIn("capacity", reason)
        self.assertIsNone(record)

    def test_native_cap_unavailable_is_indeterminate(self):
        binding = TrustedNativeRecordBinding(
            CONFORMANCE_SUBSTRATE,
            CONFORMANCE_FINALITY,
            "bridge-fixture-native-envelope-v1",
            65536,
            lambda value: None,
        )
        verdict, reason, _ = listing_admission.admit_listing(
            self.listing,
            inclusion_key=self.key,
            session_boundary=COMMITTED_BOUNDARY,
            native_binding=binding,
        )
        self.assertEqual(verdict, "indeterminate")

    def test_committed_label_cannot_bypass_missing_native_capacity(self):
        verdict, reason, record = listing_admission.admit_listing(
            self.listing,
            inclusion_key=self.key,
            session_boundary=COMMITTED_BOUNDARY,
        )
        self.assertEqual(verdict, "indeterminate")
        self.assertIn("authenticated committed-session", reason)
        self.assertIsNone(record)

    def test_new_session_requires_native_binding_even_for_signed_listing(self):
        verdict, reason, record = listing_admission.admit_listing(
            self.listing,
            inclusion_key=self.key,
            session_boundary="new-session",
        )
        self.assertEqual(verdict, "indeterminate")
        self.assertIn("native-capacity", reason)
        self.assertIsNone(record)

    def test_new_session_requires_current_revocation_state(self):
        verdict, reason, record = listing_admission.admit_listing(
            self.listing,
            inclusion_key=self.key,
            session_boundary="new-session",
            native_binding=_native_binding(),
        )
        self.assertEqual(verdict, "indeterminate")
        self.assertIn("revocation-state", reason)
        self.assertIsNone(record)


class AdmitListingRevocationBoundTests(unittest.TestCase):
    def setUp(self):
        self.listing = _revocation_bound_listing()
        self.key = _public_hex(_seller_private())

    def test_join_required_for_bound_listing(self):
        # Missing current-state evidence must never admit a bound listing.
        verdict, reason, record = listing_admission.admit_listing(
            self.listing,
            inclusion_key=self.key,
            session_boundary="new-session",
            native_binding=_native_binding(),
        )
        self.assertEqual(verdict, "indeterminate")
        self.assertIsNone(record)
        self.assertIn("full DACS-1", reason)

    def test_old_reader_without_v2_admission_cannot_admit_bound_listing(self):
        # RSC-10 downgrade-safe boundary: a reader that only checks the Listing
        # signature has no currentness authority. A validly signed bound Listing
        # without the v2 common-state join is indeterminate, never verified, so
        # an unsupported old reader must refuse rather than silently proceed.
        verdict, reason, record = listing_admission.admit_listing(
            self.listing,
            inclusion_key=self.key,
            session_boundary="new-session",
            native_binding=_native_binding(),
        )
        self.assertEqual(verdict, "indeterminate")
        self.assertIsNone(record)

    def test_mismatched_join_evidence_is_indeterminate(self):
        verdict, reason, _ = listing_admission.admit_listing(
            self.listing,
            inclusion_key=self.key,
            session_boundary="new-session",
            native_binding=_native_binding(),
            current_listing_evidence=_signed_evidence("state-300"),
            current_state_evidence=_signed_evidence("state-301"),
            trusted_state=_trusted_state("state-300"),
        )
        self.assertEqual(verdict, "indeterminate")

    def test_matching_raw_state_labels_never_mint_admission(self):
        verdict, reason, record = listing_admission.admit_listing(
            self.listing,
            inclusion_key=self.key,
            session_boundary="new-session",
            native_binding=_native_binding(),
            current_listing_evidence=_signed_evidence("state-300"),
            current_state_evidence=_signed_evidence("state-300"),
            trusted_state=_trusted_state("state-300"),
        )
        self.assertEqual(verdict, "indeterminate")
        self.assertIn("full DACS-1", reason)
        self.assertIsNone(record)

    def test_committed_bound_listing_requires_prior_admission_not_fresh_rsc(self):
        verdict, reason, record = listing_admission.admit_listing(
            self.listing,
            inclusion_key=self.key,
            session_boundary=COMMITTED_BOUNDARY,
            native_binding=_native_binding(),
        )
        self.assertEqual(verdict, "indeterminate")
        self.assertIn("authenticated committed-session", reason)
        self.assertIsNone(record)


class CurrentNormativeListingBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.listing = _normative_current_listing()
        self.key = _public_hex(_seller_private())

    def admit(self, listing=None, **overrides):
        arguments = {
            "inclusion_key": self.key,
            "session_boundary": "new-session",
            "native_binding": _native_binding(),
        }
        arguments.update(overrides)
        return listing_admission.admit_listing(
            self.listing if listing is None else listing, **arguments
        )

    def resign(self, listing):
        listing["signature"] = _sign(
            listing, listing_artifact.LISTING_DOMAINS[listing_artifact.LEGACY_LISTING],
            _seller_private(),
        )
        return listing

    def test_signed_normative_rsc_listing_never_skips_full_admission(self):
        self.assertEqual(
            listing_artifact.classify_listing_artifact(self.listing),
            ("Listing", "dacs-listing:v1:"),
        )
        verdict, reason, record = self.admit()
        self.assertEqual(verdict, "indeterminate")
        self.assertIn("full DACS-1", reason)
        self.assertIsNone(record)

    def test_raw_matching_or_mismatched_state_labels_are_inert(self):
        for listing_state, revocation_state in (
            ("state-300", "state-300"), ("state-300", "state-301")
        ):
            with self.subTest(listing_state=listing_state, revocation_state=revocation_state):
                verdict, _, record = self.admit(
                    current_listing_evidence=_signed_evidence(listing_state),
                    current_state_evidence=_signed_evidence(revocation_state),
                    trusted_state=_trusted_state("state-300"),
                )
                self.assertEqual(verdict, "indeterminate")
                self.assertIsNone(record)

    def test_raw_content_receipt_and_profile_substitutions_are_inert(self):
        for field, value in (
            ("listingContentHash", "00" * 32),
            ("listingReceiptHash", "11" * 32),
            ("headReceiptHash", "22" * 32),
            ("conflictingHeadsHash", "33" * 32),
        ):
            with self.subTest(field=field):
                evidence = _signed_evidence("state-300")
                evidence[field] = value
                trusted = _trusted_state("state-300")
                trusted["profileAdmission"] = {"authenticated": True, "releasePin": "wrong"}
                verdict, _, record = self.admit(
                    current_listing_evidence=evidence,
                    current_state_evidence=copy.deepcopy(evidence),
                    trusted_state=trusted,
                )
                self.assertEqual(verdict, "indeterminate")
                self.assertIsNone(record)

    def test_caller_cannot_relabel_an_uncommitted_attempt_as_committed(self):
        listing = copy.deepcopy(self.listing)
        listing["seller"]["identity"].pop("presentation")
        listing["pipeline"][3]["parameters"]["rail"] = "unknown:rail"
        listing["acceptedRails"] = [{"railId": "unknown:rail"}]
        self.resign(listing)
        verdict, reason, record = self.admit(
            listing, session_boundary=COMMITTED_BOUNDARY, native_binding=None,
            current_listing_evidence=_signed_evidence("state-300"),
            current_state_evidence=_signed_evidence("state-300"),
            trusted_state=_trusted_state("state-300"),
        )
        self.assertEqual(verdict, "indeterminate")
        self.assertIn("authenticated committed-session", reason)
        self.assertIsNone(record)

    def test_native_binding_omitted_malformed_or_unsupported(self):
        unsupported = TrustedNativeRecordBinding(
            CONFORMANCE_SUBSTRATE, CONFORMANCE_FINALITY,
            "unsupported", 65536, lambda value: None,
        )
        for binding in (None, {"record_limit": 65536}, unsupported):
            with self.subTest(binding=binding):
                verdict, reason, record = self.admit(native_binding=binding)
                self.assertEqual(verdict, "indeterminate")
                self.assertIn("native-capacity", reason)
                self.assertIsNone(record)

    def test_native_record_over_limit_rejects(self):
        verdict, reason, record = self.admit(native_binding=_native_binding(1))
        self.assertEqual(verdict, "rejected")
        self.assertIn("native-capacity", reason)
        self.assertIsNone(record)

    def test_partial_checks_cannot_authorize_time_bundle_or_rail(self):
        variants = {}
        expired = copy.deepcopy(self.listing)
        expired["validity"]["notBefore"] = 0
        expired["validity"]["notAfter"] = 1
        variants["expired"] = self.resign(expired)
        future = copy.deepcopy(self.listing)
        future["validity"]["notBefore"] = 9_000_000_000_000
        future["validity"]["notAfter"] = 9_000_000_000_001
        variants["future"] = self.resign(future)
        malformed_bundle = copy.deepcopy(self.listing)
        malformed_bundle["seller"]["identity"].pop("presentation")
        variants["malformed-bundle"] = self.resign(malformed_bundle)
        unregistered_rail = copy.deepcopy(self.listing)
        unregistered_rail["pipeline"][3]["parameters"]["rail"] = "unknown:rail"
        unregistered_rail["acceptedRails"] = [{"railId": "unknown:rail"}]
        variants["unregistered-rail"] = self.resign(unregistered_rail)
        for name, listing in variants.items():
            with self.subTest(name=name):
                verdict, _, record = self.admit(listing)
                self.assertEqual(verdict, "indeterminate")
                self.assertIsNone(record)


class CurrentSealedPhaseShapeTests(unittest.TestCase):
    def listing(self, *, procurement=False):
        listing = _legacy_listing()
        listing["pricing"] = {"kind": "auction", "selectionRule": "lowest-price"}
        negotiation = (
            "negotiate-sealed-envelope-procurement-complete"
            if procurement else "negotiate-sealed-envelope-complete"
        )
        parameters = {
            "commitDeadline": 200_000,
            "revealWindow": 60,
            "selectionRule": "lowest-price",
            "candidateSetBinding": {
                "bindingId": "fixture-candidate-set",
                "bindingVersion": "1",
                "definitionRef": {
                    "anchor": {"kind": "storage-program", "locator": "storage-program:binding-1"},
                    "contentHash": "11" * 32,
                },
            },
        }
        if procurement:
            parameters["auctionMode"] = "procurement"
        listing["pipeline"] = [
            {"kind": "vet-credentials"},
            {"kind": negotiation, "parameters": parameters},
            {"kind": "commit-selection-bound-agreement"},
            {"kind": "pay-dem", "parameters": {"rail": "demos-native:DEM"}},
            {"kind": "deliver-storage-program"},
        ]
        return listing

    def test_both_current_complete_sealed_shapes_are_supported(self):
        for procurement in (False, True):
            with self.subTest(procurement=procurement):
                listing = self.listing(procurement=procurement)
                self.assertTrue(listing_artifact.validate_listing_shape(listing)[0])
                self.assertTrue(listing_artifact.validate_sealed_session_deadline(
                    listing, 100_000
                )[0])

    def test_complete_phase_pairing_and_binding_are_required(self):
        listing = self.listing()
        listing["pipeline"][2]["kind"] = "commit-agreement"
        self.assertFalse(listing_artifact.validate_listing_shape(listing)[0])
        listing = self.listing()
        del listing["pipeline"][1]["parameters"]["candidateSetBinding"]
        self.assertFalse(listing_artifact.validate_listing_shape(listing)[0])
        listing = self.listing()
        listing["pipeline"][1]["parameters"]["candidateSetBinding"]["bindingVersion"] = "01"
        self.assertFalse(listing_artifact.validate_listing_shape(listing)[0])
        for invalid_ref in (
            {},
            {"contentHash": "11" * 32},
            {"anchor": {"kind": "storage-program", "locator": "storage-program:binding-1"},
             "contentHash": "not-a-hash"},
            {"anchor": {"kind": "storage-program", "locator": "storage-program:binding-1"},
             "contentHash": "11" * 32, "unexpected": True},
        ):
            with self.subTest(invalid_ref=invalid_ref):
                listing = self.listing()
                listing["pipeline"][1]["parameters"]["candidateSetBinding"]["definitionRef"] = invalid_ref
                self.assertFalse(listing_artifact.validate_listing_shape(listing)[0])


class RetainedAdmissionTests(unittest.TestCase):
    def test_retained_partial_bridge_cannot_mint_but_rejects_substitution(self):
        listing = _legacy_listing()
        key = _public_hex(_seller_private())
        raw = json.loads(IBH.read_text(encoding="utf-8"))
        ref = copy.deepcopy(
            raw["scenarios"]["identityBoundAgreement"]["agreement"]["listingRef"]
        )
        capability = listing_admission.retained_listing_admission(
            listing, ref,
            inclusion_key=key,
            session_boundary=COMMITTED_BOUNDARY,
            native_binding=_native_binding(),
        )
        verdict, reason, record = capability.verify(
            listing, ref, COMMITTED_BOUNDARY
        )
        self.assertEqual(verdict, "indeterminate")
        self.assertIsNone(record)

        substituted = copy.deepcopy(listing)
        substituted["offering"]["title"] = "stale"
        verdict, reason, record = capability.verify(
            substituted, ref, COMMITTED_BOUNDARY
        )
        self.assertEqual(verdict, "rejected")
        self.assertIsNone(record)

    def test_retained_capability_rejects_wrong_ref_and_boundary(self):
        listing = _legacy_listing()
        key = _public_hex(_seller_private())
        raw = json.loads(IBH.read_text(encoding="utf-8"))
        ref = copy.deepcopy(
            raw["scenarios"]["identityBoundAgreement"]["agreement"]["listingRef"]
        )
        capability = listing_admission.retained_listing_admission(
            listing, ref,
            inclusion_key=key,
            session_boundary=COMMITTED_BOUNDARY,
            native_binding=_native_binding(),
        )
        wrong_ref = copy.deepcopy(ref)
        wrong_ref["contentHash"] = "00" * 32
        verdict, _, _ = capability.verify(listing, wrong_ref, COMMITTED_BOUNDARY)
        self.assertEqual(verdict, "rejected")
        verdict, _, _ = capability.verify(listing, ref, "new-session")
        self.assertEqual(verdict, "rejected")


if __name__ == "__main__":
    unittest.main()
