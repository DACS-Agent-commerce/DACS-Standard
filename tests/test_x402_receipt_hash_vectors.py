import base64
import binascii
import hashlib
import json
import unicodedata
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "vectors" / "security" / "x402-receipt-hash-v0.1.json"
SPEC = ROOT / "spec" / "DACS-4-SETTLE.md"

EXPECTED_HEADERS = {
    "1": "X-PAYMENT-RESPONSE",
    "2": "PAYMENT-RESPONSE",
}


def nfc_deep(value):
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [nfc_deep(item) for item in value]
    if isinstance(value, dict):
        return {key: nfc_deep(item) for key, item in value.items()}
    return value


def canonical_json(value):
    # The fixtures use only strings, booleans, objects, and arrays, for which
    # this byte form is the RFC 8785 JCS form after DACS CF-1's NFC pre-pass.
    return json.dumps(
        nfc_deep(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def direct_jcs_without_nfc(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def decode_header(vector):
    raw = base64.b64decode(vector["responseHeader"]["value"], validate=True)
    return json.loads(raw.decode("utf-8"))


class X402ReceiptHashVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.by_name = {vector["name"]: vector for vector in cls.data["vectors"]}

    def test_vector_hash_and_count_are_byte_exact(self):
        self.assertEqual(self.data["count"], len(self.data["vectors"]))
        self.assertEqual(
            self.data["hash"],
            hashlib.sha256(canonical_json(self.data["vectors"])).hexdigest(),
        )

    def test_version_selects_exact_header_name(self):
        for vector in self.data["vectors"]:
            expected_header = EXPECTED_HEADERS[vector["protocolVersion"]]
            actual_header = vector["responseHeader"]["name"]
            if vector["name"] == "v2-wrong-v1-response-header":
                self.assertNotEqual(actual_header, expected_header)
                self.assertEqual(vector["expected"], "error")
            else:
                self.assertEqual(actual_header, expected_header, vector["name"])

    def test_valid_base64_receipts_have_byte_exact_jcs_hashes(self):
        for vector in self.data["vectors"]:
            if vector["name"] == "v2-invalid-base64":
                with self.assertRaises(binascii.Error):
                    decode_header(vector)
                continue
            if vector["name"] == "v2-wrong-v1-response-header":
                continue

            receipt = decode_header(vector)
            digest = hashlib.sha256(canonical_json(receipt)).hexdigest()
            wanted = vector["want"].get("paymentReceiptHash") or vector["want"].get(
                "computedPaymentReceiptHash"
            )
            if wanted is not None:
                self.assertEqual(digest, wanted, vector["name"])
            if "canonicalReceipt" in vector["want"]:
                self.assertEqual(canonical_json(receipt).decode(), vector["want"]["canonicalReceipt"])

    def test_reordering_and_whitespace_do_not_change_hash(self):
        compact = self.by_name["v2-success-payment-response"]
        pretty = self.by_name["v2-reordered-pretty-json-same-hash"]
        self.assertNotEqual(compact["responseHeader"]["value"], pretty["responseHeader"]["value"])
        self.assertEqual(decode_header(compact), decode_header(pretty))
        self.assertEqual(compact["evidence"]["paymentReceiptHash"], pretty["evidence"]["paymentReceiptHash"])

    def test_decomposed_unicode_gets_cf1_nfc_prepass(self):
        vector = self.by_name["v2-decomposed-unicode-is-nfc-normalised"]
        receipt = decode_header(vector)
        note = receipt["extensions"]["org.example.receipt-note"]["note"]
        self.assertNotEqual(note, unicodedata.normalize("NFC", note))
        self.assertNotEqual(
            hashlib.sha256(direct_jcs_without_nfc(receipt)).hexdigest(),
            vector["want"]["paymentReceiptHash"],
        )
        self.assertEqual(
            hashlib.sha256(canonical_json(receipt)).hexdigest(),
            vector["want"]["paymentReceiptHash"],
        )

    def test_extensions_are_preserved_and_mutation_breaks_the_hash(self):
        original = self.by_name["v2-extension-member-is-committed"]
        mutated = self.by_name["v2-extension-mutation-breaks-hash"]
        original_receipt = decode_header(original)
        mutated_receipt = decode_header(mutated)
        self.assertIn("extensions", original_receipt)
        self.assertNotEqual(original_receipt, mutated_receipt)
        self.assertNotEqual(
            hashlib.sha256(canonical_json(original_receipt)).hexdigest(),
            hashlib.sha256(canonical_json(mutated_receipt)).hexdigest(),
        )
        self.assertEqual(mutated["want"]["action"], "reject")

    def test_transaction_hash_placeholder_and_consistency_mismatches_reject(self):
        placeholder = self.by_name["transaction-hash-placeholder-is-not-receipt-hash"]
        self.assertNotEqual(
            placeholder["evidence"]["paymentReceiptHash"],
            placeholder["want"]["computedPaymentReceiptHash"],
        )

        tx_mismatch = self.by_name["v2-transaction-mismatch"]
        self.assertNotEqual(
            decode_header(tx_mismatch)["transaction"],
            tx_mismatch["evidence"]["settlementTxHash"],
        )
        network_mismatch = self.by_name["v2-network-chainid-mismatch"]
        self.assertNotEqual(
            int(decode_header(network_mismatch)["network"].split(":", 1)[1]),
            network_mismatch["evidence"]["chainId"],
        )
        self.assertEqual(tx_mismatch["expected"], "fail")
        self.assertEqual(network_mismatch["expected"], "fail")

    def test_non_success_cannot_produce_success_evidence(self):
        vector = self.by_name["v2-non-success-response"]
        self.assertIs(decode_header(vector)["success"], False)
        self.assertEqual(vector["want"]["action"], "reject")

    def test_normative_text_pins_the_same_algorithm_and_exclusions(self):
        spec = SPEC.read_text(encoding="utf-8")
        self.assertIn(
            "paymentReceiptHash = lowerhex(SHA-256(UTF8(JCS(nfcSettlementResponse))))",
            spec,
        )
        self.assertIn("recursively NFC-normalise every JSON string value", spec)
        self.assertIn('Version `"1"` selects `X-PAYMENT-RESPONSE`', spec)
        self.assertIn('version `"2"` selects `PAYMENT-RESPONSE`', spec)
        self.assertIn("including `extensions` and unrecognised members", spec)
        self.assertIn("`settlementTxHash` alone are not conforming preimages", spec)


if __name__ == "__main__":
    unittest.main()
