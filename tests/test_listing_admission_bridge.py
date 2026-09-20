"""Exact Listing admission bridge: fail-closed, no caller-minted authority.

These tests exercise the minimal adapter that consumes the portable
``rsc-current-admission-v2`` result (the common-state join plus the native
capacity check) and issues a verifier-owned :class:`AdmittedListing`. They
distinguish permanent rejection (substitution, wrong publisher/key, capacity)
from indeterminate (missing/untrusted current-state evidence).
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

    def test_positive_exact_admission(self):
        verdict, reason, record = listing_admission.admit_listing(
            self.listing,
            inclusion_key=self.key,
            session_boundary=COMMITTED_BOUNDARY,
            native_binding=_native_binding(),
        )
        self.assertEqual((verdict, reason), ("verified", "verified"))
        self.assertEqual(record.publisher, "key:" + self.key)
        self.assertEqual(record.listing_type, "Listing")

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
        self.assertIn("current-state", reason)

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

    def test_common_state_join_admits_bound_listing(self):
        verdict, reason, record = listing_admission.admit_listing(
            self.listing,
            inclusion_key=self.key,
            session_boundary="new-session",
            native_binding=_native_binding(),
            current_listing_evidence=_signed_evidence("state-300"),
            current_state_evidence=_signed_evidence("state-300"),
            trusted_state=_trusted_state("state-300"),
        )
        self.assertEqual((verdict, reason), ("verified", "verified"))
        self.assertEqual(record.listing_type, "RevocationBoundListing")


class RetainedAdmissionTests(unittest.TestCase):
    def test_retained_capability_replays_and_rejects_substitution(self):
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
        self.assertEqual(verdict, "verified")
        self.assertIsInstance(record, listing_admission.AdmittedListing)

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
