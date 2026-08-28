"""Execute the CORE §B.2 canonical-JSON candidate vectors."""
from __future__ import annotations

import json
import struct
import sys
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_canonical_json_vectors as generator  # noqa: E402
import jcs  # noqa: E402


class AdapterAbstention(Exception):
    """The host language cannot construct the requested distinct native type."""


def decode_tagged(value: Any) -> Any:
    if isinstance(value, list):
        return [decode_tagged(item) for item in value]
    if isinstance(value, dict):
        tag = value.get("$dacsType")
        if tag == "binary64":
            return struct.unpack(">d", bytes.fromhex(value["hex"]))[0]
        if tag == "bigint":
            # Python's arbitrary-precision `int` is also its ordinary JSON
            # number type. Coercing this tag to int would turn a language/API
            # distinction into a false implementation verdict.
            raise AdapterAbstention("Python has no distinct native BigInt type")
        if tag == "unicode-code-units":
            raw = bytes.fromhex(value["hex"])
            return raw.decode("utf-16-be", errors="surrogatepass")
        return {key: decode_tagged(item) for key, item in value.items()}
    return value


class CanonicalJsonVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = (
            ROOT
            / "conformance"
            / "vectors"
            / "security"
            / "canonical-json-v0.1.json"
        )
        cls.data = json.loads(cls.path.read_text(encoding="utf-8"))

    def test_committed_file_is_deterministic(self):
        self.assertEqual(self.path.read_text(encoding="utf-8"), generator.rendered())

    def test_reported_cross_run_divergences_are_pinned(self):
        names = {vector["name"] for vector in self.data["vectors"]}
        self.assertTrue(
            {
                "fraction-one-half",
                "fraction-one-e-minus-seven",
                "fraction-binary-sum",
                "fraction-one-tenth",
                "fraction-negative-one-and-half",
                "nfd-member-name-preserved",
                "nfc-and-nfd-member-names-remain-distinct",
            }.issubset(names)
        )

    def test_vectors_produce_exact_expected_bytes_rejection_or_honest_abstention(self):
        abstentions = []
        for vector in self.data["vectors"]:
            with self.subTest(name=vector["name"]):
                try:
                    value = decode_tagged(vector["input"])
                except AdapterAbstention as exc:
                    abstentions.append((vector["name"], str(exc)))
                    continue
                if vector["expected"] == "pass":
                    actual = jcs.canonicalize(value).encode("utf-8").hex()
                    self.assertEqual(actual, vector["canonicalUtf8Hex"])
                else:
                    with self.assertRaises((TypeError, ValueError)):
                        jcs.canonicalize(value)
        self.assertEqual(
            abstentions,
            [("bigint-native-type", "Python has no distinct native BigInt type")],
        )


if __name__ == "__main__":
    unittest.main()
