"""Signed compatibility and mixed-pair checks for DACS-5 v0.4 EBFAB."""

import base64
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
                    self.data["referenceLifecycleByContentHash"],
                    self.data["referencePhaseKeyByContentHash"],
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
                self.assertEqual(R.divergence(copies[0], copies[1]), case["want"]["divergent"])
                authoritative = max(copies, key=R.bundle_type_rank)
                self.assertEqual(R.bundle_type(authoritative), case["want"]["authoritativeType"])
                self.assertEqual(R.bundle_hash(authoritative), case["want"]["authoritativeBundleHash"])
                self.assertTrue(authoritative["settlementEvidence"])
                seb_ok, reason, phase_keys = R.validate_ebfab(
                    authoritative,
                    self.data["listing"],
                    self.pubkeys,
                    self.data["referenceLifecycleByContentHash"],
                    self.data["referencePhaseKeyByContentHash"],
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
                "referenceLifecycleByContentHash": self.data["referenceLifecycleByContentHash"],
                "referencePhaseKeyByContentHash": self.data["referencePhaseKeyByContentHash"],
            },
        }
        self.assertFalse(R._tagged_copy_valid_for_derive(tag))


if __name__ == "__main__":
    unittest.main()
