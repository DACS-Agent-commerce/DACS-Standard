"""Producer witnesses for DACS-4 §9.4 and DEMOS-MAPPING §A.5."""
import base64
import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import generate_rail_availability_selection_vectors as issuer


class RailStewardIssuanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / "conformance/vectors/security/rail-availability-selection-v0.1.json"
        cls.data = json.loads(path.read_text())
        cls.corpus = cls.data["stewardIssuance"]
        cls.template = next(v["rail"] for v in cls.data["vectors"]
                            if v["name"] == "tank-live-signed-node-incomplete")

    def test_steward_issuance_corpus(self):
        self.assertEqual(9, len(self.corpus["vectors"]))
        for case in self.corpus["vectors"]:
            rail = issuer.unsigned_rail(copy.deepcopy(self.template))
            rail["availability"] = case["availability"]
            with self.subTest(case=case["name"]), patch.object(
                issuer, "sign_rail", wraps=issuer.sign_rail
            ) as sign:
                if case["expected"] == "fail":
                    with self.assertRaisesRegex(ValueError, "pinned node"):
                        issuer.issue_rail(rail, node_pin=case["nodePin"],
                                          trusted_node_capabilities=self.corpus["trustedNodeCapabilities"])
                    sign.assert_not_called()
                else:
                    result = issuer.issue_rail(rail, node_pin=case["nodePin"],
                                               trusted_node_capabilities=self.corpus["trustedNodeCapabilities"])
                    sign.assert_called_once()
                    self.assertEqual(rail, issuer.unsigned_rail(result))
                    public = issuer.Ed25519PrivateKey.from_private_bytes(issuer.STEWARD_SEED).public_key()
                    public.verify(base64.urlsafe_b64decode(result["signature"]["value"] + "=="),
                                  (issuer.DOMAIN + issuer.rail_digest(rail)).encode("ascii"))

    def test_each_completion_condition_and_the_exact_node_pin_are_required(self):
        snapshots = self.corpus["trustedNodeCapabilities"]
        self.assertEqual({"completeSignedOperation": False, "routeRegistryPublished": False},
                         snapshots[issuer.INCOMPLETE_NODE_PIN])
        self.assertEqual({"content": None, "signature": {"type": "", "data": ""}, "routeRegistry": None},
                         self.corpus["incompleteNodeOutput"])
        self.assertTrue(issuer.COMPLETE_NODE_PIN.startswith("fixture:"))
        rail = issuer.unsigned_rail(self.template)
        for field in ("completeSignedOperation", "routeRegistryPublished"):
            for value in (False, None, 1, "true"):
                broken = copy.deepcopy(snapshots)
                broken[issuer.COMPLETE_NODE_PIN][field] = value
                with self.subTest(field=field, value=value), patch.object(issuer, "sign_rail") as sign:
                    with self.assertRaises(ValueError):
                        issuer.issue_rail(rail, node_pin=issuer.COMPLETE_NODE_PIN,
                                          trusted_node_capabilities=broken)
                    sign.assert_not_called()
        with self.assertRaises(ValueError):
            issuer.issue_rail(rail, node_pin=issuer.INCOMPLETE_NODE_PIN,
                              trusted_node_capabilities=snapshots)

    def test_non_tank_live_issuance_does_not_need_tank_capability(self):
        rail = issuer.unsigned_rail(self.data["vectors"][0]["rail"])
        self.assertEqual("live", rail["availability"])
        self.assertEqual(rail, issuer.unsigned_rail(issuer.issue_rail(
            rail, node_pin=issuer.INCOMPLETE_NODE_PIN, trusted_node_capabilities={})))


if __name__ == "__main__":
    unittest.main()
