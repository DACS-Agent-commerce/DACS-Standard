import base64
import binascii
import hashlib
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "vectors" / "security" / "signature-value-encoding-v0.1.json"
CORE = ROOT / "spec" / "CORE.md"
PLAN = ROOT / "spec" / "CONFORMANCE-PLAN.md"
MIGRATED_FIXTURES = [
    ROOT / "conformance" / "vectors" / "examples" / "attestation-bundle.json",
    ROOT / "conformance" / "vectors" / "security" / "listing-preserve-unknown-v0.1.json",
    ROOT / "conformance" / "vectors" / "security" / "payee-destination-binding-v0.1.json",
    ROOT / "conformance" / "vectors" / "security" / "revocation-binding-v0.3.json",
]
BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
LOWER_HEX = re.compile(r"^(?:[0-9a-f]{2})+$")


class EncodingError(ValueError):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def encode_base64url(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_canonical(value):
    if not isinstance(value, str) or not value:
        raise EncodingError("non-base64url-character")
    if "+" in value or "/" in value:
        raise EncodingError("standard-base64-alphabet-and-padding")
    if "=" in value:
        raise EncodingError("padding-forbidden")
    if not BASE64URL.fullmatch(value):
        raise EncodingError("non-base64url-character")
    if len(value) % 4 == 1:
        raise EncodingError("impossible-base64url-length")
    padded = value + "=" * (-len(value) % 4)
    try:
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EncodingError("invalid-base64url") from exc
    if encode_base64url(raw) != value:
        raise EncodingError("reencode-mismatch")
    return raw


def import_legacy(value, declared_encoding):
    if declared_encoding == "standard-base64-padded":
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise EncodingError("invalid-declared-encoding") from exc
        if base64.b64encode(raw).decode("ascii") != value:
            raise EncodingError("invalid-declared-encoding")
    elif declared_encoding == "lowercase-hex":
        if not isinstance(value, str) or not LOWER_HEX.fullmatch(value):
            raise EncodingError("invalid-declared-encoding")
        raw = bytes.fromhex(value)
    else:
        raise EncodingError("source-encoding-required")
    return encode_base64url(raw)


def evaluate(vector):
    if vector["mode"] == "legacy-import":
        try:
            canonical = import_legacy(vector["value"], vector.get("declaredEncoding"))
        except EncodingError as exc:
            return "reject", "legacy-import", exc.reason, None
        return "accept", None, None, canonical

    try:
        raw = decode_canonical(vector["value"])
    except EncodingError as exc:
        return "reject", "wire", exc.reason, None
    if vector.get("algorithm") == "ed25519" and len(raw) != 64:
        return "reject", "algorithm", "wrong-ed25519-length", None
    return "accept", None, None, vector["value"]


def signature_envelopes(value):
    if isinstance(value, dict):
        if isinstance(value.get("algorithm"), str) and isinstance(value.get("value"), str):
            yield value
        for child in value.values():
            yield from signature_envelopes(child)
    elif isinstance(value, list):
        for child in value:
            yield from signature_envelopes(child)


class SignatureValueEncodingVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_count_and_hash_are_byte_exact(self):
        vectors = self.data["vectors"]
        encoded = json.dumps(
            vectors,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(self.data["hash"], hashlib.sha256(encoded).hexdigest())

    def test_canonical_and_standard_base64_spellings_decode_to_same_bytes(self):
        raw = bytes.fromhex(self.data["signatureBytesHex"])
        self.assertEqual(len(raw), 64)
        self.assertEqual(encode_base64url(raw), self.data["canonicalValue"])
        self.assertRegex(self.data["canonicalValue"], r"^[A-Za-z0-9_-]+$")
        self.assertNotIn("=", self.data["canonicalValue"])
        self.assertTrue(any(char in self.data["canonicalValue"] for char in "-_"))
        standard = next(
            vector["value"]
            for vector in self.data["vectors"]
            if vector["name"] == "standard-base64-same-bytes-rejected"
        )
        self.assertEqual(base64.b64decode(standard), raw)
        self.assertTrue(any(char in standard for char in "+/"))

    def test_every_vector_reaches_its_pinned_result_and_failure_stage(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                result, stage, reason, canonical = evaluate(vector)
                self.assertEqual(result, vector["expected"])
                want = vector["want"]
                if "failureStage" in want:
                    self.assertEqual(stage, want["failureStage"])
                if "reason" in want:
                    self.assertEqual(reason, want["reason"])
                if "canonicalValue" in want:
                    self.assertEqual(canonical, want["canonicalValue"])
                if "decodedLength" in want:
                    self.assertEqual(
                        len(decode_canonical(vector["value"])),
                        want["decodedLength"],
                    )

    def test_legacy_import_is_explicit_and_never_the_conforming_path(self):
        standard = next(
            vector
            for vector in self.data["vectors"]
            if vector["name"] == "declared-standard-base64-legacy-import"
        )
        with self.assertRaises(EncodingError):
            decode_canonical(standard["value"])
        self.assertEqual(
            import_legacy(standard["value"], standard["declaredEncoding"]),
            self.data["canonicalValue"],
        )

    def test_migrated_signature_envelopes_are_canonical(self):
        checked = 0
        for path in MIGRATED_FIXTURES:
            data = json.loads(path.read_text(encoding="utf-8"))
            for envelope in signature_envelopes(data):
                with self.subTest(path=path.name, signer=envelope.get("signer") or envelope.get("party")):
                    decode_canonical(envelope["value"])
                    checked += 1
        self.assertGreaterEqual(checked, 60)

    def test_normative_and_per_stage_surfaces_reference_sig6(self):
        core = CORE.read_text(encoding="utf-8")
        self.assertIn("(SIG-6) **Canonical signature value.**", core)
        self.assertIn("It MUST NOT auto-detect by trying decoders", core)
        self.assertIn("Solana `ChainTxRef.signature`", core)
        for name in [
            "DACS-1-IDENTIFY.md",
            "DACS-2-VET.md",
            "DACS-3-NEGOTIATE.md",
            "DACS-4-SETTLE.md",
            "DACS-5-VERIFY.md",
        ]:
            with self.subTest(spec=name):
                self.assertIn("SIG-6", (ROOT / "spec" / name).read_text(encoding="utf-8"))
        self.assertIn("signature-value-encoding-v0.1.json", PLAN.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
