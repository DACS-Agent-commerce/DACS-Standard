"""CORE §11.1.2 admission at the real current DACS-5 consumer boundaries."""

import copy
import hashlib
import unittest
from pathlib import Path
from unittest import mock

import dacs5_reference as R


JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
OTHER_JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
BUYER = "did:demos:buyer"
SELLER = "did:demos:seller"
ROOT = Path(__file__).resolve().parents[1]


def expected_address(job_id, role):
    preimage = job_id.encode("ascii") + b"-bundle-" + role.encode("ascii")
    return "stor-" + hashlib.sha256(preimage).hexdigest()


def profile_context(identity, *, session_id=JOB_ID, profile=None,
                    authenticated=True, duplicate=False):
    return R.trusted_profile_context(
        session_id,
        identity,
        profile=profile,
        authenticated=authenticated,
        duplicate=duplicate,
    )


def binding(role, signer, content_hash):
    address = expected_address(JOB_ID, role)
    return {
        "bindingVersion": "1",
        "jobId": JOB_ID,
        "role": role,
        "signer": signer,
        "logicalAddress": address,
        "nativeAddress": address,
        "bundleContentHash": content_hash,
        "signature": {
            "signer": signer,
            "algorithm": "ed25519",
            "value": "fixture-only",
        },
    }


def current_receipt_fixture():
    base = {
        "faultBundleVersion": "1",
        "jobId": JOB_ID,
        "outcome": "completed",
        "faultedParty": "none",
        "parties": [
            {"role": "buyer", "primaryClaim": BUYER},
            {"role": "seller", "primaryClaim": SELLER},
        ],
        "phaseSummary": [],
        "finalisedAt": 100,
        "signatures": [
            {"party": BUYER, "algorithm": "ed25519", "value": "fixture-only"},
            {"party": SELLER, "algorithm": "ed25519", "value": "fixture-only"},
        ],
    }
    seller_bundle = {**base, "anchoredByRole": "seller"}
    buyer_bundle = {**base, "anchoredByRole": "buyer"}
    content_hash = R.bundle_hash(seller_bundle)
    seller_binding = binding("seller", SELLER, content_hash)
    buyer_binding = binding("buyer", BUYER, content_hash)
    tagged = [{
        "bundle": seller_bundle,
        "resolvedRole": "seller",
        "counterpartyDisposition": "present",
        "counterpartyRef": {"contentHash": content_hash},
        "counterpartyRoleEvidence": {
            "kind": "binding",
            "binding": buyer_binding,
        },
        "roleEvidence": {"kind": "binding", "binding": seller_binding},
        "bb6Context": {
            "candidateBindings": [seller_binding],
            "partyMap": {SELLER: "seller"},
            "budget": 8,
        },
    }]
    receipt = R.derive(SELLER, tagged, 0, 200, "finalisedAt")
    address_tagged = [{
        "bundle": seller_bundle,
        "resolvedRole": "seller",
        "counterpartyDisposition": "present",
        "counterpartyRef": {"contentHash": content_hash},
        "counterpartyRoleEvidence": {
            "kind": "address",
            "resolvedAddress": buyer_binding["logicalAddress"],
        },
        "roleEvidence": {
            "kind": "address",
            "resolvedAddress": seller_binding["logicalAddress"],
        },
    }]
    address_receipt = R.derive(
        SELLER, address_tagged, 0, 200, "finalisedAt"
    )
    by_address = {
        seller_binding["nativeAddress"]: seller_bundle,
        buyer_binding["nativeAddress"]: buyer_bundle,
    }
    return {
        "receipt": receipt,
        "address_receipt": address_receipt,
        "binding": seller_binding,
        "deref": lambda requested_hash: (
            seller_bundle if requested_hash == content_hash else None
        ),
        "anchor_deref": lambda address: by_address.get(address),
    }


def invalid_authorities():
    partial_profile = {
        "releasePin": R.AUTHORITATIVE_RELEASE_PIN,
        "moduleVersions": {
            key: value
            for key, value in R.AUTHORITATIVE_MODULE_VERSIONS.items()
            if key != "dacs5"
        },
    }
    wrong_release = {
        "releasePin": "f" * 40,
        "moduleVersions": R.AUTHORITATIVE_MODULE_VERSIONS,
    }
    wrong_modules = {
        "releasePin": R.AUTHORITATIVE_RELEASE_PIN,
        "moduleVersions": {
            **R.AUTHORITATIVE_MODULE_VERSIONS,
            "dacs5": "0.4",
        },
    }
    return {
        "missing": None,
        "partial-tuple": [
            profile_context(SELLER, profile=partial_profile),
            profile_context(BUYER, profile=partial_profile),
        ],
        "duplicate-participant": [
            profile_context(SELLER, duplicate=True),
            profile_context(BUYER, duplicate=True),
        ],
        "release-mismatch": [
            profile_context(SELLER, profile=wrong_release),
            profile_context(BUYER, profile=wrong_release),
        ],
        "module-mismatch": [
            profile_context(SELLER, profile=wrong_modules),
            profile_context(BUYER, profile=wrong_modules),
        ],
        "session-mismatch": [
            profile_context(SELLER, session_id=OTHER_JOB_ID),
            profile_context(BUYER, session_id=OTHER_JOB_ID),
        ],
        "identity-mismatch": [
            profile_context("did:demos:not-seller"),
            profile_context("did:demos:not-buyer"),
        ],
        "malformed": [
            {
                "sessionId": JOB_ID,
                "expectedPeerIdentity": SELLER,
                "participants": "not-an-array",
            }
        ],
        "untrusted": [
            profile_context(SELLER, authenticated=False),
            profile_context(BUYER, authenticated=False),
        ],
    }


class CurrentProfileConsumerAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = current_receipt_fixture()
        self.authority = [profile_context(SELLER), profile_context(BUYER)]

    def test_current_address_bb5_context_and_replay_positive_controls(self):
        self.assertEqual(
            expected_address(JOB_ID, "seller"),
            R.logical_address(
                JOB_ID,
                "seller",
                participant_identity=SELLER,
                trusted_contexts=self.authority,
            ),
        )
        verified = R.verify_binding(
            self.fixture["binding"],
            None,
            expected_jobid=JOB_ID,
            expected_role="seller",
            participant_identity=SELLER,
            trusted_contexts=self.authority,
        )
        self.assertTrue(verified["ok"], verified["reason"])
        valid, reasons = R.validate_resolution_context(
            self.fixture["receipt"],
            self.fixture["deref"],
            anchor_deref=self.fixture["anchor_deref"],
            trusted_contexts=self.authority,
        )
        self.assertTrue(valid, reasons)
        same, replayed = R.replay_receipt(
            self.fixture["receipt"],
            self.fixture["deref"],
            SELLER,
            0,
            200,
            anchor_deref=self.fixture["anchor_deref"],
            trusted_contexts=self.authority,
        )
        self.assertTrue(same)
        self.assertIsNotNone(replayed)

    def test_current_context_address_arm_profiles_before_mapping(self):
        mapping_calls = []

        def map_address(job_id, role):
            mapping_calls.append((job_id, role))
            return expected_address(job_id, role)

        valid, reasons = R.validate_resolution_context(
            self.fixture["address_receipt"],
            self.fixture["deref"],
            anchor_deref=self.fixture["anchor_deref"],
            pure_mapping_resolver=map_address,
        )
        self.assertFalse(valid)
        self.assertTrue(any("current-profile-admission" in r for r in reasons))
        self.assertEqual(mapping_calls, [])

        valid, reasons = R.validate_resolution_context(
            self.fixture["address_receipt"],
            self.fixture["deref"],
            anchor_deref=self.fixture["anchor_deref"],
            pure_mapping_resolver=map_address,
            trusted_contexts=self.authority,
        )
        self.assertTrue(valid, reasons)
        self.assertEqual(
            mapping_calls,
            [(JOB_ID, "seller"), (JOB_ID, "buyer")],
        )

    def test_every_current_consumer_refuses_bad_authority_before_address_derivation(self):
        for authority_name, authority in invalid_authorities().items():
            with self.subTest(authority=authority_name), mock.patch.object(
                R, "_current_logical_address", wraps=R._current_logical_address
            ) as derive_address:
                with self.assertRaisesRegex(ValueError, "current-profile-admission"):
                    R.logical_address(
                        JOB_ID,
                        "seller",
                        participant_identity=SELLER,
                        trusted_contexts=authority,
                    )
                verified = R.verify_binding(
                    self.fixture["binding"],
                    None,
                    expected_jobid=JOB_ID,
                    expected_role="seller",
                    participant_identity=SELLER,
                    trusted_contexts=authority,
                )
                self.assertFalse(verified["ok"])
                self.assertEqual(verified["reason"], "current-profile-admission")
                valid, reasons = R.validate_resolution_context(
                    self.fixture["receipt"],
                    self.fixture["deref"],
                    anchor_deref=self.fixture["anchor_deref"],
                    trusted_contexts=authority,
                )
                self.assertFalse(valid)
                self.assertTrue(any("current-profile-admission" in r for r in reasons))
                self.assertEqual(
                    R.replay_receipt(
                        self.fixture["receipt"],
                        self.fixture["deref"],
                        SELLER,
                        0,
                        200,
                        anchor_deref=self.fixture["anchor_deref"],
                        trusted_contexts=authority,
                    ),
                    (False, None),
                )
                derive_address.assert_not_called()

    def test_pre_correction_canonical_ulid_and_copied_profile_never_promote(self):
        artifact = copy.deepcopy(self.fixture["binding"])
        artifact["peerProfile"] = R.AUTHORITATIVE_LOCAL_PROFILE
        artifact["peerProfileRef"] = "fixture:current-profile"
        current = R.verify_binding(
            artifact,
            None,
            expected_jobid=JOB_ID,
            expected_role="seller",
            participant_identity=SELLER,
        )
        self.assertFalse(current["ok"])
        self.assertEqual(current["reason"], "current-profile-admission")
        self.assertTrue(R.verify_legacy_binding(
            artifact,
            None,
            expected_jobid=JOB_ID,
            expected_role="seller",
        )["ok"])

        receipt = copy.deepcopy(self.fixture["receipt"])
        receipt["peerProfile"] = R.AUTHORITATIVE_LOCAL_PROFILE
        receipt["peerProfileRef"] = "fixture:current-profile"
        self.assertEqual(
            R.replay_receipt(
                receipt,
                self.fixture["deref"],
                SELLER,
                0,
                200,
                anchor_deref=self.fixture["anchor_deref"],
            ),
            (False, None),
        )
        self.assertTrue(R.replay_legacy_receipt(
            receipt,
            self.fixture["deref"],
            SELLER,
            0,
            200,
            anchor_deref=self.fixture["anchor_deref"],
        )[0])

    def test_normative_current_and_legacy_boundaries_are_explicit(self):
        spec = (ROOT / "spec/DACS-5-VERIFY.md").read_text(encoding="utf-8")
        self.assertIn("current-profile consumer resolves", spec)
        self.assertIn("verifier- or orchestrator-owned trusted context", spec)
        self.assertIn("explicitly selected archival/legacy replay path", spec)
        self.assertIn("explicitly selected legacy replay", spec)


if __name__ == "__main__":
    unittest.main()
