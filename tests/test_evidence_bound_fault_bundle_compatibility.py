"""Signed compatibility and mixed-pair checks for DACS-5 v0.4 EBFAB."""

import base64
import copy
import json
import unittest
from pathlib import Path

import dacs5_reference as R

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "conformance" / "fixtures" / "evidence-bound-fault-bundle-compatibility-v0.4.json"


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class EvidenceBoundFaultBundleCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.pubkeys = {
            claim: decode(value)
            for claim, value in cls.data["publicKeys"].items()
        }

    def test_public_keys_match_disclosed_seeds(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        for role, seed in self.data["seeds"].items():
            public = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).public_key().public_bytes_raw()
            self.assertEqual(public, self.pubkeys[f"did:demos:{role}"])

    def test_valid_ebfab_signatures_verify_under_new_domain(self):
        case = next(case for case in self.data["cases"] if case["name"] == "valid-ebfab")
        bundle = case["bundle"]
        self.assertEqual(R.bundle_type(bundle), "evidence-bound")
        self.assertEqual(R.bundle_hash(bundle), self.data["validBundleHash"])
        ok, reason = R._bundle_signatures_valid(bundle, self.pubkeys)
        self.assertTrue(ok, reason)

        payload = (R.EVIDENCE_BOUND_FAULT_BUNDLE_DOMAIN + R.bundle_hash(bundle)).encode("utf-8")
        for signature in bundle["signatures"]:
            Ed25519PublicKey.from_public_bytes(self.pubkeys[signature["party"]]).verify(
                decode(signature["value"]), payload
            )

    def test_discriminator_exclusivity_unknown_and_cross_type_replay(self):
        for case in self.data["cases"]:
            bundle = case["bundle"]
            with self.subTest(case=case["name"]):
                self.assertEqual(R.bundle_type(bundle), case["want"]["type"])
                ok, _ = R._bundle_signatures_valid(bundle, self.pubkeys)
                self.assertEqual(ok, case["want"]["signaturesValid"])
                seb_ok, _, _ = R.validate_ebfab(
                    bundle,
                    self.data["listing"],
                    self.pubkeys,
                    self.data["referenceValidationByCanonicalRef"],
                    case.get(
                        "bundleLifecycle",
                        self.data["bundleLifecycleByHash"].get(R.bundle_hash(bundle), {}),
                    ),
                )
                self.assertEqual(seb_ok, case["want"]["sebValid"])

        stripped = next(
            case["bundle"]
            for case in self.data["cases"]
            if case["name"] == "stripped-to-fab-cross-type-replay"
        )
        self.assertEqual(R.bundle_type(stripped), "fault")
        self.assertEqual(R.bundle_domain(stripped), R.FAULT_BUNDLE_DOMAIN)
        self.assertNotEqual(R.bundle_hash(stripped), self.data["validBundleHash"])

    def test_all_new_mixed_pairs_are_classified_and_ebfab_wins(self):
        names = {case["name"] for case in self.data["pairCases"]}
        self.assertEqual(
            names,
            {
                "ebfab-ebfab",
                "ebfab-ebfab-member-skew-diverges",
                "ebfab-fab-older-cannot-erase-seb",
                "ebfab-legacy-older-cannot-erase-seb",
            },
        )
        for case in self.data["pairCases"]:
            copies = list(case["copies"].values())
            with self.subTest(case=case["name"]):
                for bundle in copies:
                    ok, reason = R._bundle_signatures_valid(bundle, self.pubkeys)
                    self.assertTrue(ok, reason)
                    if R.bundle_type(bundle) == "evidence-bound":
                        seb_ok, seb_reason, _ = R.validate_ebfab(
                            bundle,
                            self.data["listing"],
                            self.pubkeys,
                            self.data["referenceValidationByCanonicalRef"],
                            self.data["bundleLifecycleByHash"][R.bundle_hash(bundle)],
                        )
                        self.assertTrue(seb_ok, seb_reason)
                self.assertEqual(R.divergence(copies[0], copies[1]), case["want"]["divergent"])
                if case["want"]["divergent"]:
                    continue
                authoritative = max(copies, key=R.bundle_type_rank)
                self.assertEqual(R.bundle_type(authoritative), case["want"]["authoritativeType"])
                self.assertEqual(R.bundle_hash(authoritative), case["want"]["authoritativeBundleHash"])
                self.assertTrue(authoritative["settlementEvidence"])
                seb_ok, reason, phase_keys = R.validate_ebfab(
                    authoritative,
                    self.data["listing"],
                    self.pubkeys,
                    self.data["referenceValidationByCanonicalRef"],
                    self.data["bundleLifecycleByHash"][R.bundle_hash(authoritative)],
                )
                self.assertEqual(seb_ok, case["want"]["sebValid"], reason)
                self.assertEqual(phase_keys, ["0:pay-dem"])
                if R.bundle_type(copies[1]) != "evidence-bound":
                    self.assertEqual(
                        copies[1]["settlementEvidence"],
                        authoritative["settlementEvidence"],
                    )

    def test_derive_gate_rejects_signed_but_seb_invalid_ebfab_before_ranking(self):
        invalid = next(
            case["bundle"]
            for case in self.data["cases"]
            if case["name"] == "signed-seb-missing-member-reject"
        )
        tag = {
            "bundle": invalid,
            "ebfabAuthority": {
                "listing": self.data["listing"],
                "publicKeys": self.pubkeys,
                "referenceValidationByCanonicalRef": self.data["referenceValidationByCanonicalRef"],
                "bundleLifecycle": self.data["bundleLifecycleByHash"][R.bundle_hash(invalid)],
            },
            "selectedByRoleResolution": True,
            "resolvedJobId": invalid["jobId"],
        }
        self.assertFalse(R._tagged_copy_valid_for_derive(tag))

        valid_fab = next(
            case["copies"]["seller"]
            for case in self.data["pairCases"]
            if case["name"] == "ebfab-fab-older-cannot-erase-seb"
        )
        derivation = R.derive_job_bound(
            "did:demos:buyer",
            [
                {
                    **tag,
                    "resolvedRole": "buyer",
                    "counterpartyDisposition": "present",
                },
                {
                    "bundle": valid_fab,
                    "resolvedJobId": valid_fab["jobId"],
                    "resolvedRole": "seller",
                    "counterpartyDisposition": "present",
                },
            ],
            invalid["finalisedAt"] - 1,
            invalid["finalisedAt"] + 1,
        )
        self.assertEqual(derivation["bundleCount"], 0)

        valid_ebfab = next(
            case["bundle"]
            for case in self.data["cases"]
            if case["name"] == "valid-ebfab"
        )
        valid_tag = {
            "bundle": valid_ebfab,
            "selectedByRoleResolution": True,
            "resolvedJobId": valid_ebfab["jobId"],
            "resolvedRole": "buyer",
            "counterpartyDisposition": "present",
            "ebfabAuthority": {
                "listing": self.data["listing"],
                "publicKeys": self.pubkeys,
                "referenceValidationByCanonicalRef": self.data["referenceValidationByCanonicalRef"],
                "bundleLifecycle": self.data["bundleLifecycleByHash"][R.bundle_hash(valid_ebfab)],
            },
        }
        derivation_with_losing_candidate = R.derive_job_bound(
            "did:demos:buyer",
            [valid_tag, {**tag, "selectedByRoleResolution": False}],
            valid_ebfab["finalisedAt"] - 1,
            valid_ebfab["finalisedAt"] + 1,
        )
        self.assertEqual(derivation_with_losing_candidate["bundleCount"], 1)
        self.assertTrue(R.is_job_bound_replayable_derivation(derivation_with_losing_candidate))
        self.assertFalse(R.is_replayable_derivation(derivation_with_losing_candidate))
        self.assertEqual(
            derivation_with_losing_candidate["resolutionContext"][0]["resolvedJobId"],
            valid_ebfab["jobId"],
        )

        legacy_receipt = R.derive(
            "did:demos:buyer",
            [valid_tag],
            valid_ebfab["finalisedAt"] - 1,
            valid_ebfab["finalisedAt"] + 1,
        )
        self.assertTrue(R.is_replayable_derivation(legacy_receipt))
        self.assertEqual(legacy_receipt["bundleCount"], 0)

        malformed_losing_candidate = {
            "bundle": {"evidenceBoundFaultBundleVersion": "1"},
            "selectedByRoleResolution": False,
        }
        derivation_with_malformed_loser = R.derive_job_bound(
            "did:demos:buyer",
            [valid_tag, malformed_losing_candidate],
            valid_ebfab["finalisedAt"] - 1,
            valid_ebfab["finalisedAt"] + 1,
        )
        self.assertEqual(derivation_with_malformed_loser["bundleCount"], 1)

        invalid_discriminator = next(
            case["bundle"]
            for case in self.data["cases"]
            if case["name"] == "known-plus-unknown-discriminator-reject"
        )
        invalid_discriminator_tag = {
            "bundle": invalid_discriminator,
            "selectedByRoleResolution": True,
            "resolvedJobId": invalid_discriminator["jobId"],
        }
        self.assertFalse(R._tagged_copy_valid_for_derive(invalid_discriminator_tag))
        discriminator_rejection = R.derive_job_bound(
            "did:demos:buyer",
            [
                invalid_discriminator_tag,
                {
                    "bundle": valid_fab,
                    "resolvedJobId": valid_fab["jobId"],
                    "resolvedRole": "seller",
                    "counterpartyDisposition": "present",
                },
            ],
            invalid_discriminator["finalisedAt"] - 1,
            invalid_discriminator["finalisedAt"] + 1,
        )
        self.assertEqual(discriminator_rejection["bundleCount"], 0)

        withheld_job = {**tag, "bundle": dict(invalid)}
        withheld_job["bundle"].pop("jobId")
        withheld_job_rejection = R.derive_job_bound(
            "did:demos:buyer",
            [
                withheld_job,
                {
                    "bundle": valid_fab,
                    "resolvedJobId": valid_fab["jobId"],
                    "resolvedRole": "seller",
                    "counterpartyDisposition": "present",
                },
            ],
            invalid["finalisedAt"] - 1,
            invalid["finalisedAt"] + 1,
        )
        self.assertEqual(withheld_job_rejection["bundleCount"], 0)

        wrong_job_older = dict(valid_fab)
        wrong_job_older["jobId"] = "OLDER-COPY-WRONG-JOB"
        wrong_job_fallback = R.derive_job_bound(
            "did:demos:buyer",
            [
                tag,
                {
                    "bundle": wrong_job_older,
                    "resolvedJobId": invalid["jobId"],
                    "resolvedRole": "seller",
                    "counterpartyDisposition": "present",
                },
            ],
            invalid["finalisedAt"] - 1,
            invalid["finalisedAt"] + 1,
        )
        self.assertEqual(wrong_job_fallback["bundleCount"], 0)

        missing_resolution_context = dict(tag)
        missing_resolution_context.pop("resolvedJobId")
        with self.assertRaisesRegex(ValueError, "trusted resolvedJobId"):
            R.derive_job_bound(
                "did:demos:buyer",
                [missing_resolution_context],
                invalid["finalisedAt"] - 1,
                invalid["finalisedAt"] + 1,
            )

    def test_job_bound_receipt_discriminator_and_job_binding_fail_closed(self):
        valid = next(
            case["bundle"]
            for case in self.data["cases"]
            if case["name"] == "valid-ebfab"
        )
        tag = {
            "bundle": valid,
            "selectedByRoleResolution": True,
            "resolvedJobId": valid["jobId"],
            "resolvedRole": "buyer",
            "counterpartyDisposition": "present",
            "roleEvidence": {"kind": "address", "resolvedAddress": "buyer-address"},
            "ebfabAuthority": {
                "listing": self.data["listing"],
                "publicKeys": self.pubkeys,
                "referenceValidationByCanonicalRef": self.data["referenceValidationByCanonicalRef"],
                "bundleLifecycle": self.data["bundleLifecycleByHash"][R.bundle_hash(valid)],
            },
        }
        receipt = R.derive_job_bound(
            "did:demos:buyer", [tag], valid["finalisedAt"] - 1, valid["finalisedAt"] + 1)
        self.assertTrue(R.require_job_bound_replayable_derivation(receipt)["ok"])

        missing = copy.deepcopy(receipt)
        missing["resolutionContext"][0].pop("resolvedJobId")
        ok, reasons = R.validate_resolution_context(
            missing, lambda _h: valid, anchor_deref=lambda _address: valid)
        self.assertFalse(ok)
        self.assertTrue(any("resolvedJobId must be a non-empty string" in reason for reason in reasons))

        mismatch = copy.deepcopy(receipt)
        mismatch["resolutionContext"][0]["resolvedJobId"] = "another-job"
        ok, reasons = R.validate_resolution_context(
            mismatch, lambda _h: valid, anchor_deref=lambda _address: valid)
        self.assertFalse(ok)
        self.assertTrue(any("winner copy jobId != trusted resolvedJobId" in reason for reason in reasons))

        for mutation in (
            {**receipt, "replayableDerivationVersion": "1"},
            {key: value for key, value in receipt.items()
             if key != "jobBoundReplayableDerivationVersion"},
            {**receipt, "jobBoundReplayableDerivationVersion": "2"},
        ):
            with self.subTest(keys=sorted(mutation)):
                self.assertFalse(R._require_supported_replay_derivation(mutation)["ok"])
                self.assertEqual(
                    R.replay_receipt(
                        mutation,
                        lambda _h: valid,
                        "did:demos:buyer",
                        valid["finalisedAt"] - 1,
                        valid["finalisedAt"] + 1,
                    ),
                    (False, None),
                )

    def test_extended_pointer_type_and_domain_match_dereferenced_bundle(self):
        for case in self.data["pointerCases"]:
            with self.subTest(case=case["name"]):
                result = R.resolve_absolute_fault_pointer(
                    case["pointer"],
                    case["bundle"],
                    binding=case.get("binding"),
                    pubkeys=self.pubkeys,
                )
                self.assertEqual(result["ok"], case["want"]["ok"], result["reason"])

    def test_malformed_pointer_inputs_fail_closed_without_exceptions(self):
        valid = self.data["pointerCases"][0]
        for pointer, bundle, binding in (
            (None, valid["bundle"], None),
            ([], valid["bundle"], None),
            (valid["pointer"], None, None),
            (valid["pointer"], [], None),
            (valid["pointer"], valid["bundle"], []),
        ):
            with self.subTest(pointer=type(pointer).__name__, bundle=type(bundle).__name__):
                result = R.resolve_absolute_fault_pointer(
                    pointer,
                    bundle,
                    binding=binding,
                    pubkeys=self.pubkeys,
                )
                self.assertFalse(result["ok"])
        self.assertFalse(R.resolve_fab_pointer(None, {}, None)["ok"])
        self.assertFalse(R.resolve_fab_pointer({}, None, None)["ok"])
        self.assertFalse(R.resolve_fab_pointer({}, {}, [])["ok"])


if __name__ == "__main__":
    unittest.main()
