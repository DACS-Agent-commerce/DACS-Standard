"""Ordinary legacy payload controls using public fixture keys and a fake resolver."""

import json
import unittest

import generate_payload_attestation_vectors as generator
import test_payload_attestation_vectors as consumer


class PayloadAdmissionContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seeds = json.loads(consumer.VECTORS.read_text())["publicTestSeeds"]

    def test_known_legacy_delivery_with_admitted_resolution(self):
        self.assertEqual(consumer.evaluate(generator.base_case(), self.seeds), "pass")

    def test_unavailable_resolution_is_indeterminate(self):
        case = generator.base_case()
        case.pop("trustedMethodEvidenceByCanonicalRef")
        self.assertEqual(consumer.evaluate(case, self.seeds), "indeterminate")

    def test_equivalent_explicit_payload_bytes(self):
        case = generator.base_case()
        case["payloadBytesBase64url"] = generator.b64url(case["payloadUtf8"].encode("utf-8"))
        self.assertEqual(consumer.evaluate(case, self.seeds), "pass")


if __name__ == "__main__":
    unittest.main()
