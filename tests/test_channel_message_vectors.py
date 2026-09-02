"""Executable oracle for canonical and historical DACS-3 channel messages."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
import unicodedata
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import jcs  # noqa: E402


VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "canonical-channel-message-v0.6.json"
)
LEGACY = (
    ROOT / "conformance" / "vectors" / "security"
    / "channel-message-replay-v0.1.json"
)
GENERATOR = ROOT / "scripts" / "generate_channel_message_vectors.py"
DACS3 = ROOT / "spec" / "DACS-3-NEGOTIATE.md"
CORE = ROOT / "spec" / "CORE.md"
DEMOS = ROOT / "spec" / "DEMOS-MAPPING.md"
CURRENT_DOMAIN = b"dacs-canonical-channel-message:v1:"
LEGACY_DOMAIN = b"dacs-channelmsg:v1:"
LEGACY_FILE_SHA256 = "ce43b226e358e15cb126b4b7d53b8638648c14ca55250eb57e6db68e451ba13f"
LEGACY_VECTOR_HASH = "3f0664c434a6727f7578434cba9ea47b804e0dff12249081c7abdd4fdc03803b"
LOWER_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
LOWER_HEX_128 = re.compile(r"^[0-9a-f]{128}$")
BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
CLAIM_SCHEME = re.compile(r"^[a-z][a-z0-9-]*$")
MESSAGE_TYPES = {
    "offer", "counter", "accept", "reject", "sealed-envelope-commit",
    "sealed-envelope-reveal", "abort",
}
ALGORITHMS = {"ed25519", "ecdsa-secp256k1", "sr1-aggregate"}


def canonical_bytes(value):
    return jcs.canonicalize(value).encode("utf-8")


def message_digest(unsigned):
    return hashlib.sha256(canonical_bytes(unsigned)).digest()


def decode_b64url(value):
    if not isinstance(value, str) or not value or not BASE64URL.fullmatch(value):
        raise ValueError("not unpadded Base64URL")
    if len(value) % 4 == 1:
        raise ValueError("impossible Base64URL length")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ValueError("non-canonical Base64URL")
    return raw


def parse_claim_ref(value):
    if (
        not isinstance(value, str)
        or value != unicodedata.normalize("NFC", value)
        or ":" not in value
    ):
        raise ValueError("malformed ClaimReference")
    scheme, identifier = value.split(":", 1)
    if not CLAIM_SCHEME.fullmatch(scheme) or not identifier:
        raise ValueError("malformed ClaimReference")
    if scheme == "cci" and not LOWER_HEX_64.fullmatch(identifier):
        raise ValueError("malformed CCI ClaimReference")
    return scheme, identifier


def validate_context(ctx):
    if not isinstance(ctx, dict) or set(ctx) != {
        "sessionChannelId", "lastSequence", "priorChannelIds"
    }:
        return False
    return (
        isinstance(ctx["sessionChannelId"], str)
        and bool(ctx["sessionChannelId"])
        and isinstance(ctx["lastSequence"], int)
        and not isinstance(ctx["lastSequence"], bool)
        and ctx["lastSequence"] >= 0
        and isinstance(ctx["priorChannelIds"], list)
        and all(isinstance(item, str) and item for item in ctx["priorChannelIds"])
    )


def common_shape(message):
    required = {"channelId", "sequence", "sender", "sentAt", "type", "body", "signature"}
    if not required <= set(message):
        return False
    try:
        parse_claim_ref(message["sender"])
        canonical_bytes({key: value for key, value in message.items() if key != "signature"})
    except (TypeError, ValueError):
        return False
    refs = message.get("refs")
    return (
        isinstance(message["channelId"], str)
        and bool(message["channelId"])
        and isinstance(message["sequence"], int)
        and not isinstance(message["sequence"], bool)
        and message["sequence"] >= 1
        and isinstance(message["sentAt"], int)
        and not isinstance(message["sentAt"], bool)
        and message["sentAt"] >= 0
        and message["type"] in MESSAGE_TYPES
        and (
            refs is None
            or (
                isinstance(refs, dict)
                and set(refs) <= {"repliesTo"}
                and (
                    "repliesTo" not in refs
                    or (
                        isinstance(refs["repliesTo"], int)
                        and not isinstance(refs["repliesTo"], bool)
                        and refs["repliesTo"] >= 1
                    )
                )
            )
        )
    )


def resolve_ed25519(sender):
    scheme, identifier = parse_claim_ref(sender)
    if scheme != "cci":
        return None
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(identifier))


def verify_ed25519(public_key, signature, payload):
    try:
        public_key.verify(signature, payload)
    except (InvalidSignature, ValueError):
        return False
    return True


def apply_channel_policy(message, ctx):
    if message["channelId"] != ctx["sessionChannelId"]:
        return "fail"
    if message["channelId"] in ctx["priorChannelIds"]:
        return "fail"
    if message["sequence"] <= ctx["lastSequence"]:
        return "fail"
    return "pass"


def evaluate_current(message, ctx):
    if message.get("canonicalChannelMessageVersion") != "1" or not common_shape(message):
        return "error"
    signature = message.get("signature")
    if not isinstance(signature, dict) or set(signature) != {
        "signatureVersion", "signer", "algorithm", "value"
    }:
        return "error"
    if signature.get("signatureVersion") != "1":
        return "error"
    algorithm = signature.get("algorithm")
    if algorithm not in ALGORITHMS:
        return "error"
    try:
        parse_claim_ref(signature.get("signer"))
        raw_signature = decode_b64url(signature.get("value"))
    except (TypeError, ValueError):
        return "error"
    if signature["signer"] != message["sender"]:
        return "fail"
    try:
        public_key = resolve_ed25519(message["sender"])
    except ValueError:
        return "error"
    if public_key is None:
        return "indeterminate"
    if algorithm != "ed25519":
        return "fail"
    if len(raw_signature) != 64:
        return "fail"
    unsigned = {key: value for key, value in message.items() if key != "signature"}
    payload = CURRENT_DOMAIN + message_digest(unsigned).hex().encode("ascii")
    if not verify_ed25519(public_key, raw_signature, payload):
        return "fail"
    return apply_channel_policy(message, ctx)


def evaluate_legacy(message, ctx):
    if "canonicalChannelMessageVersion" in message or not common_shape(message):
        return "error"
    if not isinstance(message.get("signature"), str) or not LOWER_HEX_128.fullmatch(message["signature"]):
        return "error"
    try:
        public_key = resolve_ed25519(message["sender"])
    except ValueError:
        return "error"
    if public_key is None:
        return "indeterminate"
    unsigned = {key: value for key, value in message.items() if key != "signature"}
    payload = LEGACY_DOMAIN + message_digest(unsigned)
    if not verify_ed25519(public_key, bytes.fromhex(message["signature"]), payload):
        return "fail"
    return apply_channel_policy(message, ctx)


def evaluate(vector):
    message = vector.get("message")
    ctx = vector.get("ctx")
    if not validate_context(ctx) or not isinstance(message, dict):
        return "error"
    # Structural dispatch occurs once, before crypto. Presence of the current
    # discriminator always selects the current arm, even when the rest is a
    # malformed mixture. Legacy is selected only by its exact frozen shape.
    if "canonicalChannelMessageVersion" in message:
        return evaluate_current(message, ctx)
    if isinstance(message.get("signature"), str) and LOWER_HEX_128.fullmatch(message["signature"]):
        return evaluate_legacy(message, ctx)
    return "error"


class ChannelMessageVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.legacy = json.loads(LEGACY.read_text(encoding="utf-8"))

    def test_generator_is_byte_deterministic(self):
        subprocess.run(
            ["python3", str(GENERATOR), "--check"], cwd=ROOT, check=True
        )

    def test_header_count_hash_and_unique_names(self):
        vectors = self.document["vectors"]
        self.assertEqual(self.document["count"], len(vectors))
        self.assertEqual(
            self.document["hash"], hashlib.sha256(canonical_bytes(vectors)).hexdigest()
        )
        names = [vector["name"] for vector in vectors]
        self.assertEqual(len(names), len(set(names)))

    def test_all_current_and_dispatch_vectors_execute(self):
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(vector["expected"], evaluate(vector))

    def test_frozen_historical_corpus_executes_without_reinterpretation(self):
        self.assertEqual(
            LEGACY_FILE_SHA256, hashlib.sha256(LEGACY.read_bytes()).hexdigest()
        )
        self.assertEqual(LEGACY_VECTOR_HASH, self.legacy["hash"])
        for vector in self.legacy["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(vector["expected"], evaluate(vector))

    def test_legacy_import_preserves_signature_bytes(self):
        vector = next(
            item for item in self.document["vectors"]
            if item["name"] == "legacy-byte-preserving-read-only-import"
        )
        raw = bytes.fromhex(vector["message"]["signature"])
        self.assertEqual(
            vector["expectedSignatureBytesBase64Url"],
            base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"),
        )
        self.assertEqual("pass", evaluate(vector))

    def test_four_mixed_wire_barriers_are_distinguishing(self):
        by_name = {item["name"]: item for item in self.document["vectors"]}
        expected = {
            "mixed-current-discriminator-legacy-signature": "error",
            "neither-selector-no-discriminator-current-envelope": "error",
            "mixed-current-raw-digest-framing": "fail",
            "mixed-legacy-hex-digest-framing": "fail",
        }
        for name, verdict in expected.items():
            with self.subTest(vector=name):
                self.assertEqual(verdict, evaluate(by_name[name]))

    def test_current_and_historical_payloads_pin_digest_representation(self):
        current = self.document["vectors"][0]["message"]
        current_unsigned = {
            key: value for key, value in current.items() if key != "signature"
        }
        current_payload = CURRENT_DOMAIN + message_digest(current_unsigned).hex().encode("ascii")
        self.assertEqual(len(CURRENT_DOMAIN) + 64, len(current_payload))
        current_public = resolve_ed25519(current["sender"])
        self.assertTrue(verify_ed25519(
            current_public, decode_b64url(current["signature"]["value"]), current_payload
        ))
        self.assertFalse(verify_ed25519(
            current_public,
            decode_b64url(current["signature"]["value"]),
            CURRENT_DOMAIN + message_digest(current_unsigned),
        ))

        legacy = self.legacy["vectors"][0]["message"]
        legacy_unsigned = {
            key: value for key, value in legacy.items() if key != "signature"
        }
        legacy_payload = LEGACY_DOMAIN + message_digest(legacy_unsigned)
        self.assertEqual(len(LEGACY_DOMAIN) + 32, len(legacy_payload))
        legacy_public = resolve_ed25519(legacy["sender"])
        self.assertTrue(verify_ed25519(
            legacy_public, bytes.fromhex(legacy["signature"]), legacy_payload
        ))
        self.assertFalse(verify_ed25519(
            legacy_public,
            bytes.fromhex(legacy["signature"]),
            LEGACY_DOMAIN + message_digest(legacy_unsigned).hex().encode("ascii"),
        ))

    def test_spec_and_mapping_define_the_accepted_boundary(self):
        dacs3 = DACS3.read_text(encoding="utf-8")
        core = CORE.read_text(encoding="utf-8")
        demos = DEMOS.read_text(encoding="utf-8")
        for rule in range(7, 11):
            self.assertIn(f"(CH-{rule})", dacs3)
        for text in (
            "type CanonicalChannelMessage = {",
            "type ChannelMessageSignature = {",
            "type LegacyDemosChannelMessage = {",
            'UTF8("dacs-canonical-channel-message:v1:") || ASCII(message_hash)',
            'UTF8("dacs-channelmsg:v1:") || legacy_message_hash_bytes',
            "MUST NOT try the other arm",
        ):
            self.assertIn(text, dacs3)
        self.assertIn('"dacs-canonical-channel-message:v1:"', core)
        self.assertIn("read/import-only", core)
        self.assertIn("@kynesyslabs/demosdk@4.0.16", demos)
        self.assertIn("historical read/import arm", demos)


if __name__ == "__main__":
    unittest.main()
