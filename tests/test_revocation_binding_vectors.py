import base64
import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "vectors" / "security" / "revocation-binding-v0.3.json"


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def marker_hash(marker):
    unsigned = {key: value for key, value in marker.items() if key != "signature"}
    return hashlib.sha256(canonical_json(unsigned)).hexdigest()


def demos_native_address(write_inputs):
    preimage = ":".join(
        [
            write_inputs["deployerAddress"],
            write_inputs["storageProgramName"],
            str(write_inputs["nonce"]),
            write_inputs["salt"],
        ]
    )
    return "stor-" + hashlib.sha256(preimage.encode("utf-8")).hexdigest()[:40]


def cf4_encode(value):
    encoded = value
    for raw, escaped in [("%", "%25"), (":", "%3A"), ("?", "%3F"), ("&", "%26"), ("=", "%3D")]:
        encoded = encoded.replace(raw, escaped)
    return encoded


class RevocationBindingVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_fixture_marker_hashes_are_byte_exact(self):
        markers = self.data["fixtures"]["markers"]
        bindings = self.data["fixtures"]["bindings"]
        valid_hash = marker_hash(markers["valid-v3"])
        self.assertEqual(valid_hash, bindings["opaque-name"]["markerContentHash"])
        self.assertEqual(valid_hash, bindings["convention-name"]["markerContentHash"])
        self.assertEqual(
            marker_hash(markers["valid-wrong-v4"]),
            "a0a735d6e41fe883ce0aa1430537b4875abe8338aab018c103a4d850f6fa19b7",
        )

    def test_fixture_native_addresses_follow_demos_write_input_mapping(self):
        for name, binding in self.data["fixtures"]["bindings"].items():
            with self.subTest(binding=name):
                self.assertEqual(
                    demos_native_address(binding["producerWriteInputs"]),
                    binding["markerAnchor"]["locator"],
                )

    def test_fixture_logical_addresses_follow_cf4(self):
        listing = self.data["fixtures"]["listing"]
        expected = (
            "dacs1-revoked:"
            + cf4_encode(listing["sellerPrimaryClaim"])
            + f":{listing['listingId']}:v{listing['listingVersion']}"
        )
        for name, binding in self.data["fixtures"]["bindings"].items():
            with self.subTest(binding=name):
                self.assertEqual(binding["logicalAddress"], expected)

    def test_fixture_key_and_signatures_have_ed25519_lengths(self):
        public_key = next(iter(self.data["publicKeys"].values()))
        self.assertEqual(len(base64.urlsafe_b64decode(public_key + "=")), 32)
        for marker in self.data["fixtures"]["markers"].values():
            self.assertEqual(len(base64.b64decode(marker["signature"]["value"])), 64)

    def test_scenario_matrix_covers_required_verdicts_and_failures(self):
        cases = {vector["name"]: vector for vector in self.data["vectors"]}
        self.assertEqual(self.data["count"], len(cases))
        required = {
            "opaque-name-binding-resolves-revoked",
            "convention-name-binding-resolves-revoked",
            "binding-logical-address-mismatch",
            "binding-marker-content-hash-mismatch",
            "validly-signed-marker-wrong-listing-version",
            "marker-signature-invalid",
            "revoked-status-missing-binding",
            "marker-anchor-unreachable",
            "well-known-index-hash-mismatch",
            "fresh-active-record-establishes-absent",
            "active-record-carrying-binding-is-inconsistent",
            "stale-catalog-record-cannot-establish-absent",
            "valid-revocation-precedes-active-mirror",
            "indeterminate-precedes-active-mirror",
        }
        self.assertEqual(set(cases), required)
        self.assertEqual(cases["fresh-active-record-establishes-absent"]["expected"], "pass")
        self.assertEqual(cases["opaque-name-binding-resolves-revoked"]["want"]["revocationCheck"], "revoked")
        for name, case in cases.items():
            with self.subTest(case=name):
                self.assertIn(case["expected"], {"pass", "fail", "indeterminate"})
                if case["want"]["session"] == "refuse":
                    self.assertIn(case["expected"], {"fail", "indeterminate"})


if __name__ == "__main__":
    unittest.main()
