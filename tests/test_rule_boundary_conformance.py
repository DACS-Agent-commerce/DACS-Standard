"""Portable witnesses for signature admission, missing authority and HTLC submission."""
import json
import copy
import subprocess
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SECURITY = ROOT / "conformance/vectors/security"
sys.path.insert(0, str(ROOT / "tests"))
from scripts.signature_authorization_reference import (  # noqa: E402
    TYPES, authorize_signatures, decode, digest, verify_envelope,
)
from scripts.htlc_submission_reference import (  # noqa: E402
    HtlcSubmissionAuthority, verify_htlc_submission,
)


class RuleBoundaryCoverageTests(unittest.TestCase):
    def test_session_party_key_absence_is_portable_for_both_parties(self):
        data = json.loads((SECURITY / "settlement-finality-verification.json").read_text())
        cases = {v["name"]: v for v in data["vectors"]}
        for party, other in (("buyer", "seller"), ("seller", "buyer")):
            name = "fv-trusted-party-key-for-" + party + "-absent"
            self.assertIn(name, list(cases))
            self.assertEqual("indeterminate", cases[name]["expected"])
            self.assertEqual("fail", cases[name + "-" + other + "-signature-invalid"]["expected"])

    def test_signature_authorization_has_a_portable_type_matrix(self):
        self.assertTrue((SECURITY / "signature-authorization-v0.1.json").is_file(),
                        "SIG-7 needs signed type-specific authorization vectors")

    def test_actual_source_finality_has_a_handler_witness(self):
        self.assertTrue((SECURITY / "htlc-submission-safety-v0.1.json").is_file(),
                        "HTLC-8 needs an authenticated actual-finality submission gate")

    def test_every_signature_type_executes_both_envelope_and_artifact_verdicts(self):
        data = json.loads((SECURITY / "signature-authorization-v0.1.json").read_text())
        self.assertEqual(set(TYPES), {v["signatureType"] for v in data["vectors"]})
        for case in data["vectors"]:
            with self.subTest(case=case["name"]):
                trusted = case["trusted"]
                self.assertEqual(case["want"], authorize_signatures(
                    case["input"], case["signatureType"], trusted["keys"],
                    trusted["authorizedClaims"], implemented=trusted["implemented"]))

    def test_outside_set_signatures_are_genuine_and_cover_the_exact_artifacts(self):
        data = json.loads((SECURITY / "signature-authorization-v0.1.json").read_text())
        for case in data["vectors"]:
            if not case["name"].endswith("ed448-outside-set"):
                continue
            typ = case["signatureType"]
            domain, member, field, _ = TYPES[typ]
            signatures = case["input"][member]
            if member != "signatures":
                signatures = [signatures]
            for signature in signatures:
                public = case["trusted"]["keys"][signature[field]]["publicKey"]
                Ed448PublicKey.from_public_bytes(decode(public)).verify(
                    decode(signature["value"]), (domain + digest(case["input"], typ)).encode("ascii"))

    def test_existing_listing_revocation_and_terminal_bundle_consumers(self):
        from scripts.listing_admission import _verify_listing_signature
        from test_revocation_state_completeness_vectors import verify_artifact
        import dacs5_reference as d5
        data = json.loads((SECURITY / "signature-authorization-v0.1.json").read_text())
        for typ in ("ListingSignature", "RevocationSignature", "BundleSignature"):
            for variant, allowed in (("ed25519-valid", True), ("ed448-outside-set", False)):
                case = next(v for v in data["vectors"] if v["name"] == typ + "-" + variant)
                value, keys = case["input"], case["trusted"]["keys"]
                with self.subTest(case=case["name"]):
                    if typ == "ListingSignature":
                        # The allowed signer is the second seller claim.
                        signer = value["signature"]["signer"]
                        self.assertNotEqual(value["seller"]["identity"]["presentedBy"], signer)
                        actual = _verify_listing_signature(value, TYPES[typ][0], decode(keys[signer]["publicKey"]).hex())
                    elif typ == "RevocationSignature":
                        signer = value["signature"]["signer"]
                        actual = verify_artifact(value, decode(keys[signer]["publicKey"]).hex(), TYPES[typ][0])
                    else:
                        actual, _ = d5._bundle_signatures_valid_for_family(
                            value, {s: decode(k["publicKey"]) for s, k in keys.items()}, "legacy")
                    self.assertEqual(allowed, actual)

    def test_htlc_submission_uses_authenticated_actual_finality(self):
        data = json.loads((SECURITY / "htlc-submission-safety-v0.1.json").read_text())
        for case in data["vectors"]:
            with self.subTest(case=case["name"]):
                authority = HtlcSubmissionAuthority(**copy.deepcopy(data["trustedFixtureAuthority"]))
                result = verify_htlc_submission(case["input"]["sourceObservation"], authority=authority)
                self.assertEqual(case["expected"], result["decision"])
                self.assertEqual(case["want"]["maySubmit"], result["maySubmit"])
        self.assertEqual({"decision": "indeterminate", "maySubmit": False,
                          "reason": "authenticated HTLC submission authority unavailable"},
                         verify_htlc_submission(None, authority=data["trustedFixtureAuthority"]))

    def test_boundary_corpora_are_deterministic(self):
        subprocess.run([sys.executable, str(ROOT / "scripts/generate_rule_boundary_vectors.py"), "--check"], check=True)

    def test_spa_checks_key_metadata_and_decoded_format_before_availability(self):
        from scripts.reputation_evidence import verify_detached_signature_status
        data = json.loads((SECURITY / "signature-authorization-v0.1.json").read_text())
        case = next(v for v in data["vectors"] if v["name"] == "ComponentSignature-ecdsa-valid")
        envelope = copy.deepcopy(case["input"]["signature"])
        args = dict(domain=TYPES["ComponentSignature"][0], digest=digest(case["input"], "ComponentSignature"), signer_field="signer")
        # Well-formed registered algorithm, no authenticated incompatible key.
        self.assertEqual("indeterminate", verify_detached_signature_status(envelope, **args))
        envelope["signer"] = "key:" + "00" * 32
        self.assertEqual("fail", verify_detached_signature_status(envelope, **args))
        envelope["signer"] = "did:example:unresolved"
        envelope["value"] = "AA"
        self.assertEqual("fail", verify_detached_signature_status(envelope, **args))

    def test_signature_type_aliases_and_channel_pin_include_sig7(self):
        vet = (ROOT / "spec/DACS-2-VET.md").read_text()
        for typ in ("VerifyResultSignature", "RecipeSignature"):
            self.assertIn("type " + typ + " = ComponentSignature", vet)
        from channel_message_fixture_authority import CURRENT_RELEASE_PIN
        core = subprocess.check_output(["git", "show", CURRENT_RELEASE_PIN + ":spec/CORE.md"], cwd=ROOT, text=True)
        self.assertIn("(SIG-7)", core)

    def test_ap2_unsupported_cases_have_an_explicit_implemented_set(self):
        data = json.loads((SECURITY / "settlement-finality-verification.json").read_text())
        self.assertEqual(["0.2"], data["fixturePolicyMetadata"]["implementedAP2ProtocolVersions"])


if __name__ == "__main__":
    unittest.main()
