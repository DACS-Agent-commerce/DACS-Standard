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
import re
import subprocess
import sys
import unicodedata
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


def _normative_current_listing() -> dict:
    """The RSC Listing wire shape retains dacsVersion and its original domain."""
    listing = _legacy_listing()
    listing["revocationState"] = {
        "revocationStateRefVersion": "1",
        "logicalAddress": "dacs1-revocations:key%3A" + _public_hex(_seller_private()),
        "anchor": {"kind": "storage-program", "locator": "storage-program:revocation-line-a"},
        "checkpointSequence": "0",
        "checkpointHeadHash": "00" * 32,
    }
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

    def test_non_primary_claim_may_sign_with_inclusion_key(self):
        listing = copy.deepcopy(self.listing)
        listing["seller"]["identity"]["presentedBy"] = "did:example:seller"
        listing["seller"]["identity"]["claims"].append(
            {"ref": "did:example:seller"}
        )
        listing["signature"] = _sign(
            listing, listing_artifact.LISTING_DOMAINS[listing_artifact.LEGACY_LISTING],
            _seller_private(),
        )
        verdict, reason, record = listing_admission.admit_listing(
            listing, inclusion_key=self.key, session_boundary=COMMITTED_BOUNDARY,
            native_binding=_native_binding(),
        )
        self.assertEqual(verdict, "indeterminate")
        self.assertIn("authenticated committed-session", reason)
        self.assertIsNone(record)

    def test_claimed_did_signer_remains_unresolved(self):
        listing = copy.deepcopy(self.listing)
        listing["seller"]["identity"]["claims"].append(
            {"ref": "did:example:seller"}
        )
        listing["signature"] = _sign(
            listing, listing_artifact.LISTING_DOMAINS[listing_artifact.LEGACY_LISTING],
            _seller_private(),
        )
        listing["signature"]["signer"] = "did:example:seller"
        verdict, reason, record = listing_admission.admit_listing(
            listing, inclusion_key=self.key, session_boundary=COMMITTED_BOUNDARY,
            native_binding=_native_binding(),
        )
        self.assertEqual(verdict, "indeterminate")
        self.assertIn("resolution", reason)
        self.assertIsNone(record)

    def test_signer_absent_from_claims_is_rejected(self):
        listing = copy.deepcopy(self.listing)
        listing["seller"]["identity"]["claims"] = [{"ref": "did:example:seller"}]
        verdict, reason, record = listing_admission.admit_listing(
            listing, inclusion_key=self.key, session_boundary=COMMITTED_BOUNDARY,
            native_binding=_native_binding(),
        )
        self.assertEqual(verdict, "rejected")
        self.assertIn("absent", reason)
        self.assertIsNone(record)

    def test_claimed_self_auth_key_with_invalid_signature_is_rejected(self):
        listing = copy.deepcopy(self.listing)
        listing["signature"]["value"] = "not-a-signature"
        verdict, reason, record = listing_admission.admit_listing(
            listing, inclusion_key=self.key, session_boundary=COMMITTED_BOUNDARY,
            native_binding=_native_binding(),
        )
        self.assertEqual(verdict, "rejected")
        self.assertIn("signature", reason)
        self.assertIsNone(record)

    def test_unsupported_boundary_is_indeterminate(self):
        verdict, reason, _ = listing_admission.admit_listing(
            self.listing,
            inclusion_key=self.key,
            session_boundary="not-a-boundary",
            native_binding=_native_binding(),
        )
        self.assertEqual(verdict, "indeterminate")

    def test_wrong_typed_boundary_is_unsupported(self):
        for boundary in ({}, [], ["new-session"], None, 1, True, False):
            with self.subTest(boundary=boundary):
                self.assertEqual(
                    listing_admission.admit_listing(
                        self.listing,
                        inclusion_key=self.key,
                        session_boundary=boundary,
                        native_binding=_native_binding(),
                    ),
                    ("indeterminate", "listing admission session boundary is unsupported", None),
                )

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

    def test_undefined_discriminator_is_rejected_even_with_valid_listing_signature(self):
        for include_normative_version in (False, True):
            with self.subTest(include_normative_version=include_normative_version):
                listing = copy.deepcopy(self.listing)
                if not include_normative_version:
                    listing.pop("dacsVersion")
                listing["revocationBoundListingVersion"] = "1"
                self.resign(listing)
                verdict, reason, record = self.admit(listing)
                self.assertEqual(verdict, "rejected")
                self.assertIn("discriminator", reason)
                self.assertIsNone(record)
                publication, candidate = listing_artifact.prepare_listing_publication(
                    listing,
                    _native_binding(),
                    substrate=CONFORMANCE_SUBSTRATE,
                    finality_profile=CONFORMANCE_FINALITY,
                )
                self.assertEqual(publication, "fail")
                self.assertIsNone(candidate)

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


def _wrong_typed(known: str) -> tuple:
    """Every non-string JSON type, including containers that hold a known member."""
    return (
        ("object", {}),
        ("object holding a known member", {known: known}),
        ("array", []),
        ("array holding a known member", [known]),
        ("null", None),
        ("integer", 1),
        ("negative integer", -1),
        ("float", 1.5),
        ("boolean", True),
        ("boolean false", False),
    )


class ListingShapeWrongTypeTests(unittest.TestCase):
    """Wrong-typed or unsupported closed-union members are shape failures, never exceptions."""

    def assert_shape_failure(self, listing, reason):
        self.assertEqual(
            listing_artifact.validate_listing_shape(listing),
            (False, reason, "Listing", "dacs-listing:v1:"),
        )
        self.assertEqual(
            listing_admission.admit_listing(
                listing,
                inclusion_key=_public_hex(_seller_private()),
                session_boundary="new-session",
                native_binding=_native_binding(),
            ),
            ("rejected", "listing shape is invalid", None),
        )
        self.assertEqual(
            listing_artifact.prepare_listing_publication(
                listing,
                _native_binding(),
                substrate=CONFORMANCE_SUBSTRATE,
                finality_profile=CONFORMANCE_FINALITY,
            ),
            ("fail", None),
        )

    def test_fixture_listing_is_shape_valid(self):
        self.assertTrue(listing_artifact.validate_listing_shape(_legacy_listing())[0])

    def test_wrong_typed_pipeline_kind_is_a_shape_failure(self):
        for index in (0, -1):
            for name, value in _wrong_typed("vet-credentials"):
                with self.subTest(step=index, kind=name):
                    listing = _legacy_listing()
                    listing["pipeline"][index]["kind"] = value
                    self.assert_shape_failure(listing, "invalid or unsupported pipeline")

    def test_wrong_typed_capability_item_is_a_shape_failure(self):
        listing = _legacy_listing()
        listing["requiredCapabilities"] = ["SR-1"]
        self.assertTrue(listing_artifact.validate_listing_shape(listing)[0])
        for name, value in _wrong_typed("SR-1"):
            for items in ([value], ["SR-1", value]):
                with self.subTest(capability=name, preceded_by_valid=len(items) > 1):
                    listing = _legacy_listing()
                    listing["requiredCapabilities"] = items
                    self.assert_shape_failure(listing, "invalid requiredCapabilities")

    def test_unsupported_pipeline_kind_string_is_a_shape_failure(self):
        for index in (0, -1):
            for kind in ("negotiate-future-mode", "Vet-Credentials", "vet-credentials ", ""):
                with self.subTest(step=index, kind=kind):
                    listing = _legacy_listing()
                    listing["pipeline"][index]["kind"] = kind
                    self.assert_shape_failure(listing, "invalid or unsupported pipeline")

    def test_unsupported_capability_string_is_a_shape_failure(self):
        for value in ("SR-6", "sr-1", "SR-1 ", ""):
            for items in ([value], ["SR-1", value]):
                with self.subTest(capability=value, preceded_by_valid=len(items) > 1):
                    listing = _legacy_listing()
                    listing["requiredCapabilities"] = items
                    self.assert_shape_failure(listing, "invalid requiredCapabilities")

    def test_supported_argument_must_be_a_collection_holding_the_type(self):
        listing = _legacy_listing()
        for supported in (None, {"Listing"}, frozenset({"Listing"}), ["Listing"], ("Listing",)):
            with self.subTest(supported=supported):
                self.assertTrue(
                    listing_artifact.validate_listing_shape(listing, supported=supported)[0]
                )
        for supported in (5, True, "xxListingxx", "Listing", {"Listing": True}, [], set()):
            with self.subTest(supported=supported):
                self.assertEqual(
                    listing_artifact.validate_listing_shape(listing, supported=supported),
                    (False, "listing type is unsupported by this consumer", None, None),
                )


class ListingShapeBoundsTests(unittest.TestCase):
    """DACS-1 §6.3.4 length bounds and closed ListingTerms/signature unions."""

    assert_shape_failure = ListingShapeWrongTypeTests.assert_shape_failure

    def assert_publishable(self, listing):
        self.assertEqual(listing_artifact.validate_listing_shape(listing)[:2], (True, None))
        self.assertEqual(
            listing_artifact.prepare_listing_publication(
                listing,
                _native_binding(),
                substrate=CONFORMANCE_SUBSTRATE,
                finality_profile=CONFORMANCE_FINALITY,
            )[0],
            "pass",
        )

    def test_string_and_tag_bounds(self):
        cases = (
            ("seller", "displayName", 200, "invalid seller"),
            ("offering", "title", 200, "invalid offering"),
            ("offering", "description", 2000, "invalid offering"),
        )
        for section, field, limit, reason in cases:
            with self.subTest(field=field):
                listing = _legacy_listing()
                # Bounds count characters, not UTF-8 octets.
                listing[section][field] = "é" * limit
                self.assert_publishable(listing)
                listing[section][field] += "a"
                self.assert_shape_failure(listing, reason)
            with self.subTest(field=field, form="NFD"):
                # Bounds count the CF-1 (NFC) form that is hashed and signed, so
                # a decomposed spelling of the same signed content is in bounds.
                listing = _legacy_listing()
                listing[section][field] = unicodedata.normalize("NFD", "ệ" * limit)
                self.assertEqual(len(listing[section][field]), 3 * limit)
                self.assert_publishable(listing)
                listing[section][field] += unicodedata.normalize("NFD", "ệ")
                self.assert_shape_failure(listing, reason)
        listing = _legacy_listing()
        listing["offering"]["tags"] = ["t" * 32] * 16
        self.assert_publishable(listing)
        listing["offering"]["tags"] = [unicodedata.normalize("NFD", "ệ" * 32)] * 16
        self.assert_publishable(listing)
        for tags in (
            ["t" * 32] * 17, ["t" * 33], ["ok", "t" * 33],
            [unicodedata.normalize("NFD", "ệ" * 33)],
        ):
            with self.subTest(tags=len(tags), longest=max(map(len, tags))):
                listing = _legacy_listing()
                listing["offering"]["tags"] = tags
                self.assert_shape_failure(listing, "invalid offering")

    def test_closed_terms_unions(self):
        cases = {
            "conflictOfLawsRule": (
                ("buyer-jurisdiction", "seller-jurisdiction", "rule-ref:https://example.test/law"),
                ("court-of-mars", "Buyer-Jurisdiction", "rule-ref", "", "rule-ref:", "rule-ref: ",
                 "rule-ref:https://example.test/ law", "rule-ref:https://example.test/law\n",
                 "rule-ref:\x00"),
            ),
            "acceptanceModel": (("auto-accept",), ("manual", "Auto-Accept", "")),
            "cancellationPolicy": (
                ("none", "pre-commit", "with-fee"), ("free", "Pre-Commit", ""),
            ),
            "transcriptDisclosurePolicy": (
                ("none", "encrypted-anchored-recommended", "encrypted-anchored-required"),
                ("public", "encrypted-anchored", ""),
            ),
        }
        for field, (valid, invalid) in cases.items():
            for value in valid:
                with self.subTest(field=field, value=value):
                    listing = _legacy_listing()
                    listing["terms"][field] = value
                    self.assert_publishable(listing)
            for value in invalid + tuple(value for _, value in _wrong_typed(valid[0])):
                with self.subTest(field=field, value=value):
                    listing = _legacy_listing()
                    listing["terms"][field] = value
                    self.assert_shape_failure(listing, "invalid terms")

    def test_optional_terms_members_have_their_declared_types(self):
        not_numbers = ("60", "soon", None, True, False, [], [60], {})
        cases = {
            "termsOfServiceUrl": (
                ("https://example.test/tos",),
                tuple(value for _, value in _wrong_typed("https://example.test/tos")) + (9,),
            ),
            "termsOfServiceHash": (
                ("ab" * 32,), tuple(value for _, value in _wrong_typed("ab" * 32)),
            ),
            "jurisdictions": (
                ([], ["DE"], ["US", "DE"]),
                ("DE", "US", [5], ["DE", None], [["DE"]], {"DE": "DE"}, None, 1, True),
            ),
            "deadlineSecAfterCommit": ((0, 60, 1.5), not_numbers),
            "retentionYears": ((1, 7), not_numbers + ("1",)),
        }
        for field, (valid, invalid) in cases.items():
            for value in valid:
                with self.subTest(field=field, value=value):
                    listing = _legacy_listing()
                    listing["terms"][field] = value
                    self.assert_publishable(listing)
            for value in invalid:
                with self.subTest(field=field, value=value):
                    listing = _legacy_listing()
                    listing["terms"][field] = value
                    self.assert_shape_failure(listing, "invalid terms")

    def test_optional_offering_and_deliverable_members_have_their_declared_types(self):
        url = "https://example.test/more"
        method = {"kind": "tlsnotary", "endpoint": "https://example.test/notary"}
        not_numbers = ("big", "1024", None, True, False, [], {})
        not_objects = ("tlsnotary", [], [method], None, 1, True)
        deliverables = {
            "storage-program": {"kind": "storage-program"},
            "attested-payload": {"kind": "attested-payload", "payloadFormat": "application/json"},
            "external": {"kind": "external", "description": "consulting hours"},
        }
        cases = (
            ("offering", "extendedDescriptionUrl", (url,),
             tuple(value for _, value in _wrong_typed(url))),
            ("offering", "extendedDescriptionHash", ("ab" * 32,),
             tuple(value for _, value in _wrong_typed("ab" * 32))),
            ("storage-program", "schemaUrl", (url,),
             tuple(value for _, value in _wrong_typed(url))),
            ("storage-program", "expectedSizeBytes", (0, 1024), not_numbers),
            ("attested-payload", "expectedSizeBytes", (0, 1024), not_numbers),
            ("attested-payload", "verificationMethod", (method,), not_objects),
            ("external", "verificationMethod", (method,), not_objects),
        )
        for target, field, valid, invalid in cases:
            # Pair each value with its outcome: False == 0, so membership would lie.
            for value, publishable in [(value, True) for value in valid] + [
                (value, False) for value in invalid
            ]:
                with self.subTest(target=target, field=field, value=value):
                    listing = _legacy_listing()
                    if target == "offering":
                        member = listing["offering"]
                    else:
                        member = copy.deepcopy(deliverables[target])
                        listing["offering"]["deliverable"] = member
                    member[field] = value
                    if publishable:
                        self.assert_publishable(listing)
                    else:
                        self.assert_shape_failure(listing, "invalid offering")

    def test_auction_rule_ref_names_a_rule(self):
        def auction(rule):
            listing = _legacy_listing()
            listing["pricing"] = {"kind": "auction", "selectionRule": rule}
            listing["pipeline"] = [
                {"kind": "vet-credentials"},
                {"kind": "negotiate-sealed-envelope", "parameters": {
                    "commitDeadline": 200_000, "revealWindow": 60, "selectionRule": rule,
                }},
                {"kind": "commit-agreement"},
                {"kind": "pay-dem", "parameters": {"rail": "demos-native:DEM"}},
                {"kind": "deliver-storage-program"},
            ]
            return listing

        for rule in (
            "lowest-price", "rule-ref:" + "12" * 32 + ":https://rules.example/select",
            "rule-ref:" + "14" * 32 + ":stor-rule",
        ):
            with self.subTest(rule=rule):
                self.assertEqual(
                    listing_artifact.validate_listing_shape(auction(rule))[:2], (True, None),
                )
        for rule in ("rule-ref:", "rule-ref: ", "rule-ref:" + "12" * 32 + ": https://x",
                     "rule-ref:https://rules.example/\tselect", "rule-ref"):
            with self.subTest(rule=rule):
                self.assertEqual(
                    listing_artifact.validate_listing_shape(auction(rule)),
                    (False, "invalid pricing", "Listing", "dacs-listing:v1:"),
                )

    def test_signature_algorithm_is_closed(self):
        for algorithm in ("ed25519", "ecdsa-secp256k1", "sr1-aggregate"):
            with self.subTest(algorithm=algorithm):
                listing = _legacy_listing()
                listing["signature"]["algorithm"] = algorithm
                self.assert_publishable(listing)
        for algorithm in ("rsa", "Ed25519", "ed25519 ", "") + tuple(
            value for _, value in _wrong_typed("ed25519")
        ):
            with self.subTest(algorithm=algorithm):
                listing = _legacy_listing()
                listing["signature"]["algorithm"] = algorithm
                self.assert_shape_failure(listing, "invalid listing signature shape")

    def test_storage_program_access_model_is_closed(self):
        for access_model in ("public", "buyer-only", "encrypt-to-buyer"):
            with self.subTest(access_model=access_model):
                listing = _legacy_listing()
                listing["offering"]["deliverable"] = {
                    "kind": "storage-program", "accessModel": access_model,
                }
                self.assert_publishable(listing)
        for access_model in ("everyone", "Public", "") + tuple(
            value for _, value in _wrong_typed("public")
        ):
            with self.subTest(access_model=access_model):
                listing = _legacy_listing()
                listing["offering"]["deliverable"] = {
                    "kind": "storage-program", "accessModel": access_model,
                }
                self.assert_shape_failure(listing, "invalid offering")

    def test_rail_version_is_a_number(self):
        listing = _legacy_listing()
        listing["acceptedRails"][0]["railVersion"] = 1
        self.assert_publishable(listing)
        for value in ("1", {}, [1], None, True, False):
            with self.subTest(rail_version=value):
                listing = _legacy_listing()
                listing["acceptedRails"][0]["railVersion"] = value
                self.assert_shape_failure(listing, "invalid acceptedRails")


def _spec_union(text: str, anchor: str, field: str | None = None) -> set:
    """Quoted members of a spec union: a ``type X =`` block or one field after ``anchor``."""
    start = text.index(anchor) + len(anchor)
    if field is None:
        lines = []
        for line in text[start:].splitlines()[1:]:
            if not line.strip().startswith(("|", "//")):
                break
            lines.append(line.split("//")[0] if line.strip().startswith("|") else "")
        return set(re.findall(r'"([^"]*)"', "\n".join(lines)))
    match = re.compile(rf'\b{field}\??: ((?:"[^"]*"\s*\|?\s*)+)').search(text, start)
    return set(re.findall(r'"([^"]*)"', match.group(1)))


class ListingSpecTableTests(unittest.TestCase):
    """The module's mirrored closed sets equal the Standard's type definitions."""

    def test_mirrored_tables_match_the_standard(self):
        dacs1 = (ROOT / "spec/DACS-1-IDENTIFY.md").read_text(encoding="utf-8")
        dacs4 = (ROOT / "spec/DACS-4-SETTLE.md").read_text(encoding="utf-8")
        self.assertEqual(_spec_union(dacs1, "type PhaseType ="), set(listing_artifact.KNOWN_PHASES))
        self.assertEqual(
            _spec_union(dacs1, "type SubstrateRequirement ="),
            set(listing_artifact._CAPABILITIES),
        )
        self.assertEqual(
            _spec_union(dacs1, "type ListingSignature = {", "algorithm"),
            set(listing_artifact._SIGNATURE_ALGORITHMS),
        )
        for field, allowed in listing_artifact._TERMS_ENUMS.items():
            with self.subTest(field=field):
                expected = set(allowed) | (
                    {"rule-ref:<uri>"} if field == "conflictOfLawsRule" else set()
                )
                self.assertEqual(_spec_union(dacs1, "type ListingTerms = {", field), expected)
        self.assertEqual(
            _spec_union(dacs4, "type DeliverableSpec =", "accessModel"),
            set(listing_artifact._ACCESS_MODELS),
        )
        for field, limit in (
            ("displayName", listing_artifact._MAX_DISPLAY_NAME),
            ("title", listing_artifact._MAX_TITLE),
            ("description", listing_artifact._MAX_DESCRIPTION),
        ):
            with self.subTest(field=field):
                self.assertRegex(dacs1, rf"\n\s+{field}: string\s+// max {limit} chars\n")
        self.assertRegex(
            dacs1,
            rf"\n\s+tags: string\[\]\s+// max {listing_artifact._MAX_TAGS} tags, "
            rf"max {listing_artifact._MAX_TAG} chars each\n",
        )


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


def _deep_signed_listing(depth: int = 1500) -> dict:
    listing = _legacy_listing()
    node = {}
    listing["extension"] = node
    for _ in range(depth):
        node["nested"] = {}
        node = node["nested"]
    listing["signature"] = _sign(
        listing,
        listing_artifact.LISTING_DOMAINS[listing_artifact.LEGACY_LISTING],
        _seller_private(),
    )
    return listing


class DeepListingCopyTests(unittest.TestCase):
    """GHSA-5fhq: uncopyable nesting fails closed at both copy boundaries."""

    def setUp(self):
        self.listing = _deep_signed_listing()
        self.assertTrue(listing_artifact.validate_listing_shape(self.listing)[0])

    def test_publication_fails_closed_on_uncopyable_extension(self):
        publication, candidate = listing_artifact.prepare_listing_publication(
            self.listing,
            _native_binding(),
            substrate=CONFORMANCE_SUBSTRATE,
            finality_profile=CONFORMANCE_FINALITY,
        )
        self.assertEqual(publication, "fail")
        self.assertIsNone(candidate)

    def test_retained_admission_never_issues_on_uncopyable_extension(self):
        key = _public_hex(_seller_private())
        raw = json.loads(IBH.read_text(encoding="utf-8"))
        ref = copy.deepcopy(
            raw["scenarios"]["identityBoundAgreement"]["agreement"]["listingRef"]
        )
        capability = listing_admission.retained_listing_admission(
            self.listing, ref,
            inclusion_key=key,
            session_boundary=COMMITTED_BOUNDARY,
            native_binding=_native_binding(),
        )
        self.assertIsInstance(capability, listing_admission.ListingAdmissionCapability)
        for boundary in (COMMITTED_BOUNDARY, "new-session"):
            verdict, reason, record = capability.verify(self.listing, ref, boundary)
            self.assertEqual(verdict, "indeterminate")
            self.assertIn("could not be retained", reason)
            self.assertIsNone(record)


class ImportModeTests(unittest.TestCase):
    def test_package_import_uses_repository_modules_without_path_mutation(self):
        code = (
            "import scripts.listing_admission as a; "
            "import scripts.listing_artifact as b; "
            "import scripts.rsc_current_admission as c; "
            "import scripts.jcs as j; "
            "assert a.jcs_canonicalize is j.canonicalize; "
            "assert b.jcs_canonicalize is j.canonicalize; "
            "assert c.jcs is j; "
            "assert b.prepare_listing_publication({}, None, substrate='x', finality_profile='y')[0] == 'fail'"
        )
        subprocess.run([sys.executable, "-c", code], cwd=ROOT, check=True)

    def test_direct_script_import_without_path_mutation(self):
        code = (
            "import listing_admission as a; "
            "import listing_artifact as b; "
            "import rsc_current_admission as c; "
            "import jcs; "
            "assert a.jcs_canonicalize is jcs.canonicalize; "
            "assert b.jcs_canonicalize is jcs.canonicalize; "
            "assert c.jcs is jcs; "
            "assert b.prepare_listing_publication({}, None, substrate='x', finality_profile='y')[0] == 'fail'"
        )
        subprocess.run([sys.executable, "-c", code], cwd=ROOT / "scripts", check=True)


if __name__ == "__main__":
    unittest.main()
