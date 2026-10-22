"""DACS-1 read identities at native-payment boundaries."""
import copy
import unittest

from scripts.demos_identity import demos_key_claim, demos_party_address
try:
    from tests import test_pay_dem_execution_vectors as pay_dem
except ImportError:  # unittest discovery with tests/ on sys.path
    import test_pay_dem_execution_vectors as pay_dem


class DemosIdentityTests(unittest.TestCase):
    def test_schemes_case_fold_without_changing_identifiers_or_input(self):
        key = "ab" * 32
        for scheme, identifier in (("KEY", key), ("KeY", key), ("DID", "demos:agent:" + key)):
            for suffix in ("", "?jurisdiction=US", "?a=%3A&unknown=", "?z=1&a=2", "?unknown=1&unknown=2"):
                reference = scheme + ":" + identifier + suffix
                with self.subTest(reference=reference):
                    self.assertEqual((scheme.lower(), key), demos_key_claim(reference))
                    self.assertEqual(key, demos_party_address(reference))
                    self.assertEqual(scheme + ":" + identifier + suffix, reference)
        for value in ("KEY:" + key.upper(), "DID:DEMOS:agent:" + key, "key:0x" + key):
            self.assertIsNone(demos_key_claim(value))
            self.assertIsNone(demos_party_address(value))

    def test_malformed_qualifiers_never_project_as_controlled_keys(self):
        key = "ab" * 32
        for suffix in ("?", "?oops", "?=US", "?a=b\nc", "?a=b&", "?a=b?c=d", "?a=%xx"):
            with self.subTest(suffix=suffix):
                with self.assertRaises(ValueError):
                    demos_key_claim("key:" + key + suffix)
                self.assertIsNone(demos_party_address("key:" + key + suffix))
        for address in (key, "0x" + key):
            self.assertEqual(key, demos_party_address(address))
            self.assertIsNone(demos_party_address(address + "?a=b"))

    def test_unresolved_inclusion_and_malformed_claim_have_one_verdict(self):
        import json
        from scripts.settlement_finality_reference import _verify_inclusion_path, verify_finality
        fv = json.loads((pay_dem.ROOT / "conformance/vectors/security/settlement-finality-verification.json").read_text())
        case = next(v for v in fv["vectors"] if v["name"] == "fv-bft-final-malformed-claim-inclusion-below-threshold")
        # Corpus overrides replace complete policy members. Deep-merging an
        # empty authority map would leave the default authorities trusted and
        # make this test pass without the DEM-7 verdict-order check.
        trust = dict(copy.deepcopy(fv["trustedFixturePolicy"]), **copy.deepcopy(case["trustedOverrides"]))
        inputs = case["input"]
        self.assertEqual({}, trust["observationAuthorityKeys"])
        self.assertEqual("indeterminate", _verify_inclusion_path(
            inputs["context"]["observation"], inputs["rail"]["consumerFinalityProfile"]["settlement"],
            inputs["evidence"]["paymentTxRefs"][0], trust,
        )[0])
        fv_decision = verify_finality(inputs, trust)["decision"]
        valid_claims = dict(trust, demosPayerKeyClaims=fv["trustedFixturePolicy"]["demosPayerKeyClaims"])
        self.assertEqual("indeterminate", verify_finality(inputs, valid_claims)["decision"])
        data = pay_dem.generator.load_vectors(pay_dem.VECTORS.read_text())
        consumer = next(v for v in data["vectors"] if v["name"] == "consumer-malformed-claim-inclusion-below-threshold")
        self.assertEqual("error", fv_decision)
        self.assertEqual(fv_decision, pay_dem.evaluate(consumer)[0])

    def test_every_authorized_key_remains_eligible(self):
        """Canonical read matching never reduces a bundle to its first key."""
        data = pay_dem.generator.load_vectors(pay_dem.VECTORS.read_text())
        case = copy.deepcopy(next(v for v in data["vectors"] if v["name"] == "consumer-confirmed-gate-passes"))
        key = pay_dem.generator.PAYER_KEY
        case["protocolInput"]["phase"]["payerKeyClaims"] = [
            {"claim": "key:" + pay_dem.generator.OTHER_KEY, "control": "presentation-signature"},
            {"claim": "KEY:" + key + "?unknown=ok", "control": "presentation-signature"},
        ]
        self.assertEqual("pass", pay_dem.evaluate(case)[0])
        case["protocolInput"]["phase"]["payerKeyClaims"][1]["control"] = "none"
        self.assertNotEqual("pass", pay_dem.evaluate(case)[0])


if __name__ == "__main__":
    unittest.main()
