"""HTLC-5 preimage derivation vectors: recompute with an independent HKDF.

The generator writes HKDF out from RFC 5869 with hmac/hashlib. This test
recomputes every vector with ``cryptography``'s HKDF (a second implementation,
installed by requirements-ap2-reference.txt), checks the by-hand HKDF against
all three RFC 5869 SHA-256 test cases, and shows that each named encoding
mistake really changes the preimage.
"""
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path(__file__).resolve().parents[1]
SET = ROOT / "conformance" / "vectors" / "security" / "htlc-preimage-derivation-v0.1.json"
GENERATOR = ROOT / "scripts" / "generate_htlc_preimage_derivation_vectors.py"
SPEC = ROOT / "spec" / "DACS-4-SETTLE.md"

# RFC 5869 Appendix A, SHA-256 cases: (IKM, salt, info, L, OKM).
RFC_5869 = (
    ("0b" * 22, "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42,
     "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
    ("".join(f"{i:02x}" for i in range(0x00, 0x50)),
     "".join(f"{i:02x}" for i in range(0x60, 0xb0)),
     "".join(f"{i:02x}" for i in range(0xb0, 0x100)), 82,
     "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
     "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
     "cc30c58179ec3e87c14c01d5c1f3434f1d87"),
    ("0b" * 22, "", "", 42,
     "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
)


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_htlc_preimage_derivation_vectors", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def independent_hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt or None, info=info).derive(ikm)


class HtlcPreimageDerivationVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gen = load_generator()
        cls.data = json.loads(SET.read_text(encoding="utf-8"))
        cls.by_name = {vector["name"]: vector for vector in cls.data["vectors"]}

    def test_by_hand_hkdf_matches_rfc_5869(self):
        for ikm, salt, info, length, okm in RFC_5869:
            with self.subTest(okm=okm[:16]):
                got = self.gen.hkdf(bytes.fromhex(ikm), bytes.fromhex(salt), bytes.fromhex(info), length)
                self.assertEqual(got.hex(), okm)
                self.assertEqual(independent_hkdf(bytes.fromhex(ikm), bytes.fromhex(salt),
                                                  bytes.fromhex(info), length).hex(), okm)

    def test_every_vector_recomputes_with_an_independent_hkdf(self):
        self.assertEqual(self.data["count"], 6)
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                d = vector["derivation"]
                self.assertEqual(d["length"], 32)
                preimage = independent_hkdf(bytes.fromhex(d["ikmHex"]), bytes.fromhex(d["saltHex"]),
                                            bytes.fromhex(d["infoHex"]), 32)
                self.assertEqual(preimage.hex(), vector["want"]["preimageHex"])
                self.assertEqual(hashlib.sha256(preimage).hexdigest(), vector["want"]["hashlockSha256Hex"])

    def test_pass_vectors_use_the_pinned_encodings(self):
        for vector in self.data["vectors"]:
            if vector["expected"] != "pass":
                continue
            with self.subTest(vector=vector["name"]):
                inp, d = vector["input"], vector["derivation"]
                self.assertEqual(bytes.fromhex(d["ikmHex"]), bytes.fromhex(inp["buyerSaltHex"]))
                self.assertGreaterEqual(len(bytes.fromhex(inp["buyerSaltHex"])), 16)  # HTLC-1
                self.assertEqual(bytes.fromhex(d["saltHex"]), inp["jobId"].encode("ascii"))
                self.assertRegex(inp["agreementHash"], r"^[0-9a-f]{64}$")
                self.assertEqual(bytes.fromhex(d["infoHex"]), inp["agreementHash"].encode("ascii"))
                self.assertEqual(
                    self.gen.derive(bytes.fromhex(inp["buyerSaltHex"]), inp["jobId"], inp["agreementHash"]).hex(),
                    vector["want"]["preimageHex"])

    def test_each_named_mistake_changes_the_preimage(self):
        canonical = self.by_name["canonical-derivation"]
        c_in = canonical["input"]
        salt32 = bytes.fromhex(c_in["buyerSaltHex"])
        right = canonical["want"]["preimageHex"]
        mistakes = {
            "info-as-decoded-bytes-is-wrong": (c_in["jobId"].encode("ascii"), bytes.fromhex(c_in["agreementHash"])),
            "uppercase-hex-info-is-wrong": (c_in["jobId"].encode("ascii"), c_in["agreementHash"].upper().encode("ascii")),
            "salt-and-info-swapped-is-wrong": (c_in["agreementHash"].encode("ascii"), c_in["jobId"].encode("ascii")),
        }
        wrong = set()
        for name, (salt, info) in mistakes.items():
            with self.subTest(vector=name):
                vector = self.by_name[name]
                self.assertEqual(vector["expected"], "fail")
                self.assertEqual(vector["input"], c_in, "a fail vector shares canonical-derivation's inputs")
                got = independent_hkdf(salt32, salt, info, 32).hex()
                self.assertEqual(got, vector["want"]["preimageHex"])
                self.assertNotEqual(got, right)
                wrong.add(got)
        self.assertEqual(len(wrong), 3)
        other = self.by_name["other-job-id-other-preimage"]
        self.assertNotEqual(other["want"]["preimageHex"], right)
        self.assertNotEqual(other["input"]["jobId"], c_in["jobId"])

    def test_committed_set_is_what_the_generator_produces(self):
        rendered = json.dumps(self.gen.document(), indent=2, ensure_ascii=False) + "\n"
        self.assertEqual(SET.read_text(encoding="utf-8"), rendered)
        vectors = self.data["vectors"]
        self.assertEqual(self.data["hash"], hashlib.sha256(self.gen.canonical_bytes(vectors)).hexdigest())

    def test_spec_pins_the_same_encodings(self):
        text = SPEC.read_text(encoding="utf-8")
        for sentence in (
            "IKM is the `buyerSalt` bytes",
            "`salt` is the exact ASCII bytes of the JID-1 `jobId`",
            "`info` is the ASCII bytes of the 64-character lowercase hexadecimal `agreementHash`",
            "not the 32 decoded bytes",
            "L = 32",
            "`conformance/vectors/security/htlc-preimage-derivation-v0.1.json`",
        ):
            self.assertIn(sentence, text)


if __name__ == "__main__":
    unittest.main()
