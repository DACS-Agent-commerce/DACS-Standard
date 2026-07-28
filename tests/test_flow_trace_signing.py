import base64
import hashlib
import json
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
FLOW_TRACE = ROOT / "docs" / "flow-trace.md"
GOLDEN = ROOT / "conformance" / "vectors" / "golden.json"


class FlowTraceSigningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signing = json.loads(GOLDEN.read_text())["signing"]
        canonical = json.dumps(
            cls.signing["doc"],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        cls.digest_hex = hashlib.sha256(canonical).hexdigest()
        cls.signature = base64.urlsafe_b64decode(cls.signing["signature"] + "==")
        cls.public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(cls.signing["publicKeyHex"]))

    def test_flow_trace_uses_ascii_hex_artifact_hash(self):
        text = FLOW_TRACE.read_text()
        self.assertIn('concat(utf8(domainSep(kind, "v1")), utf8(artifactHash))', text)
        self.assertNotIn("hexBytes(artifactHash)", text)

    def test_golden_signature_verifies_over_core_b7_preimage(self):
        preimage = self.signing["separator"].encode("utf-8") + self.digest_hex.encode("ascii")
        self.assertEqual(len(preimage), 80)
        self.public_key.verify(self.signature, preimage)

    def test_golden_signature_rejects_raw_digest_preimage(self):
        preimage = self.signing["separator"].encode("utf-8") + bytes.fromhex(self.digest_hex)
        self.assertEqual(len(preimage), 48)
        with self.assertRaises(InvalidSignature):
            self.public_key.verify(self.signature, preimage)


if __name__ == "__main__":
    unittest.main()
