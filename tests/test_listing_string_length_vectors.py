"""DACS-1 §6.3.4 string bounds: the unit is Unicode scalar values of the NFC form.

Each vector replaces one string field of the pinned IBH fixture Listing (which
passes ``validate_listing_shape``) and asserts the reference check's verdict.
Two controls swap the reference's counting unit for the two wrong ones and
show which vectors flip.
"""
import copy
import hashlib
import importlib.util
import json
import sys
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import listing_artifact  # noqa: E402

SET = ROOT / "conformance" / "vectors" / "security" / "listing-string-length-v0.1.json"
GENERATOR = ROOT / "scripts" / "generate_listing_string_length_vectors.py"
IBH = ROOT / "conformance" / "vectors" / "security" / "identity-bundle-hash-binding-v0.1.json"
SPEC = ROOT / "spec" / "DACS-1-IDENTIFY.md"


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_listing_string_length_vectors", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def with_field(listing, field, value):
    listing = copy.deepcopy(listing)
    if field == "displayName":
        listing["seller"]["displayName"] = value
    elif field == "tag":
        listing["offering"]["tags"] = [value]
    else:
        listing["offering"][field] = value
    return listing


class ListingStringLengthVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gen = load_generator()
        cls.data = json.loads(SET.read_text(encoding="utf-8"))
        raw = json.loads(IBH.read_text(encoding="utf-8"))
        cls.listing = raw["scenarios"]["identityBoundAgreement"]["listing"]
        assert listing_artifact.validate_listing_shape(cls.listing)[:2] == (True, None)

    def verdict(self, vector):
        ok, _reason, _type, _domain = listing_artifact.validate_listing_shape(
            with_field(self.listing, vector["field"], vector["value"]))
        return "pass" if ok else "fail"

    def test_counts_are_what_the_vector_says(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                value = vector["value"]
                self.assertEqual(vector["counts"], {
                    "scalarValuesNfc": len(unicodedata.normalize("NFC", value)),
                    "scalarValuesAsReceived": len(value),
                    "utf16CodeUnits": len(value.encode("utf-16-le")) // 2,
                    "utf8Bytes": len(value.encode("utf-8")),
                })
                self.assertEqual(vector["expected"],
                                 "pass" if vector["counts"]["scalarValuesNfc"] <= vector["limit"] else "fail")

    def test_reference_check_gives_each_verdict(self):
        self.assertEqual(self.data["count"], 13)
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(self.verdict(vector), vector["expected"])

    def test_vectors_separate_the_unit_from_the_wrong_units(self):
        # The set must contain vectors that a UTF-16 count, a byte count, and a
        # pre-NFC count would each get wrong; otherwise it does not pin the unit.
        by_name = {vector["name"]: vector for vector in self.data["vectors"]}
        utf16_wrong = [v["name"] for v in self.data["vectors"]
                       if (v["counts"]["utf16CodeUnits"] <= v["limit"]) != (v["expected"] == "pass")]
        bytes_wrong = [v["name"] for v in self.data["vectors"]
                       if (v["counts"]["utf8Bytes"] <= v["limit"]) != (v["expected"] == "pass")]
        pre_nfc_wrong = [v["name"] for v in self.data["vectors"]
                         if (v["counts"]["scalarValuesAsReceived"] <= v["limit"]) != (v["expected"] == "pass")]
        # A UTF-16 count also rejects the decomposed vector: e + U+0301 is two code units.
        self.assertEqual(utf16_wrong, ["display-name-101-emoji", "display-name-200-decomposed",
                                       "title-mixed-200-after-nfc", "description-1001-emoji", "tag-17-emoji"])
        self.assertIn("display-name-101-emoji", bytes_wrong)
        self.assertEqual(pre_nfc_wrong, ["display-name-200-decomposed", "title-mixed-200-after-nfc"])
        self.assertEqual(by_name["display-name-201-precomposed"]["expected"], "fail")

    def test_every_bound_has_an_at_bound_pass_and_a_one_over_fail(self):
        # Control: a strict `<` comparison on any one field fails at least one vector.
        for field, limit in {"displayName": 200, "title": 200, "description": 2000, "tag": 32}.items():
            with self.subTest(field=field):
                at = [v for v in self.data["vectors"] if v["field"] == field
                      and v["counts"]["scalarValuesNfc"] == limit]
                over = [v for v in self.data["vectors"] if v["field"] == field
                        and v["counts"]["scalarValuesNfc"] == limit + 1]
                self.assertEqual([v["expected"] for v in at], ["pass"] * len(at))
                self.assertEqual([v["expected"] for v in over], ["fail"] * len(over))
                self.assertTrue(at and over)
        strict = lambda value: len(unicodedata.normalize("NFC", value)) + 1  # noqa: E731
        with mock.patch.object(listing_artifact, "_chars", strict):
            flipped = [v["name"] for v in self.data["vectors"] if self.verdict(v) != v["expected"]]
        self.assertEqual(flipped, ["display-name-200-ascii", "display-name-200-decomposed",
                                   "title-mixed-200-after-nfc", "description-2000-ascii", "tag-32-ascii"])

    def test_controls_a_wrong_unit_in_the_reference_flips_those_vectors(self):
        def flipped(counter):
            with mock.patch.object(listing_artifact, "_chars", counter):
                return [v["name"] for v in self.data["vectors"] if self.verdict(v) != v["expected"]]
        self.assertEqual(flipped(lambda value: len(value.encode("utf-16-le")) // 2),
                         ["display-name-101-emoji", "display-name-200-decomposed",
                          "title-mixed-200-after-nfc", "description-1001-emoji", "tag-17-emoji"])
        self.assertEqual(flipped(len), ["display-name-200-decomposed", "title-mixed-200-after-nfc"])
        self.assertEqual(flipped(lambda value: len(unicodedata.normalize("NFC", value))), [])

    def test_committed_set_is_what_the_generator_produces(self):
        rendered = json.dumps(self.gen.document(), indent=2, ensure_ascii=False) + "\n"
        self.assertEqual(SET.read_text(encoding="utf-8"), rendered)
        self.assertEqual(self.data["hash"],
                         hashlib.sha256(self.gen.canonical_bytes(self.data["vectors"])).hexdigest())

    def test_spec_pins_the_unit(self):
        text = SPEC.read_text(encoding="utf-8")
        for sentence in (
            "counts Unicode scalar values of the value's CF-1 (NFC) form",
            "not UTF-16 code units, UTF-8 bytes, or the code points of a decomposed input",
            "`conformance/vectors/security/listing-string-length-v0.1.json`",
        ):
            self.assertIn(sentence, text)


if __name__ == "__main__":
    unittest.main()
