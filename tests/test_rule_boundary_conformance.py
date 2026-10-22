"""Portable witnesses for signature admission, missing authority and HTLC submission."""
import json
import copy
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

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

    def test_required_signers_are_distinct_from_authorized_signers(self):
        data = json.loads((SECURITY / "signature-authorization-v0.1.json").read_text())
        for typ in ("AgreementSignature", "BundleSignature"):
            case = next(v for v in data["vectors"] if v["name"] == typ + "-ed25519-valid")
            trusted = case["trusted"]
            result = authorize_signatures(case["input"], typ, trusted["keys"],
                                          trusted["authorizedClaims"] + ["did:example:optional"],
                                          required_claims=trusted["authorizedClaims"])
            self.assertEqual({"envelope": "pass", "artifact": "pass"}, result)

    def test_missing_required_signatures_still_refuse_without_keys(self):
        data = json.loads((SECURITY / "signature-authorization-v0.1.json").read_text())
        for typ in ("AgreementSignature", "BundleSignature"):
            for suffix in ("required-signature-missing", "required-signature-missing-key-unavailable"):
                case = next(v for v in data["vectors"] if v["name"] == typ + "-" + suffix)
                self.assertEqual("fail", case["want"]["artifact"])
        for outcome in ("self", "other"):
            case = next(v for v in data["vectors"] if v["name"] == "BundleSignature-abort-" + outcome + "-single-signed")
            self.assertEqual({"envelope": "pass", "artifact": "pass"}, case["want"])

    def test_channel_signature_version_is_required_under_the_selected_type(self):
        data = json.loads((SECURITY / "signature-authorization-v0.1.json").read_text())
        for suffix in ("missing", "unsupported", "nonstring"):
            case = next(v for v in data["vectors"] if v["name"] == "ChannelMessageSignature-signature-version-" + suffix)
            self.assertEqual({"envelope": "error", "artifact": "error"}, case["want"])

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

    def test_signature_type_aliases(self):
        vet = (ROOT / "spec/DACS-2-VET.md").read_text()
        for typ in ("VerifyResultSignature", "RecipeSignature"):
            self.assertIn("type " + typ + " = ComponentSignature", vet)

    def test_channel_pin_includes_sig7(self):
        from channel_message_fixture_authority import CURRENT_RELEASE_PIN
        env = {**os.environ, "GIT_NO_LAZY_FETCH": "1"}
        try:
            available = subprocess.run(
                ["git", "cat-file", "-e", CURRENT_RELEASE_PIN + "^{commit}"],
                cwd=ROOT, capture_output=True, env=env)
        except FileNotFoundError:
            self.skipTest("release-pin history check requires git and the pinned commit locally")
        if available.returncode:
            self.skipTest("release pin unavailable locally; source archives and shallow clones may omit history")
        core = subprocess.check_output(["git", "show", CURRENT_RELEASE_PIN + ":spec/CORE.md"], cwd=ROOT, text=True, env=env)
        self.assertIn("(SIG-7)", core)

    def test_channel_pin_history_check_skips_only_when_history_is_unavailable(self):
        for unavailable in (FileNotFoundError("git unavailable"), subprocess.CompletedProcess([], 1)):
            with self.subTest(unavailable=type(unavailable).__name__):
                kwargs = {"side_effect": unavailable} if isinstance(unavailable, Exception) else {"return_value": unavailable}
                with mock.patch.object(subprocess, "run", **kwargs), mock.patch.object(subprocess, "check_output") as show:
                    with self.assertRaises(unittest.SkipTest):
                        self.test_channel_pin_includes_sig7()
                    show.assert_not_called()
                self.test_signature_type_aliases()

    def test_ap2_unsupported_cases_have_an_explicit_implemented_set(self):
        data = json.loads((SECURITY / "settlement-finality-verification.json").read_text())
        self.assertEqual(["0.2"], data["fixturePolicyMetadata"]["implementedAP2ProtocolVersions"])


if __name__ == "__main__":
    unittest.main()
