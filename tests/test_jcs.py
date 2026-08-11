"""Unit tests for the stdlib-only RFC 8785 (JCS) canonicaliser used by section B.2.

All special characters are built with chr()/escapes so the source is pure ASCII
with no literal control or non-ASCII bytes (robust against editor normalisation).
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import jcs  # noqa: E402

E_ACUTE = chr(0x00E9)             # precomposed e-acute
E_DECOMP = "e" + chr(0x0301)      # e + combining acute; NFC folds to U+00E9
BMP_PUA = chr(0xE000)             # BMP private-use, NFC-stable, single UTF-16 unit E000
ASTRAL = chr(0x10000)             # surrogate pair D800 DC00 in UTF-16

# RFC 8785 section 3.2.3 property-sorting example. The RFC's example values are
# strings (no float substitution needed); the KEY ordering is what is under test.
# UTF-16 code-unit order of the seven keys (hand-derived, independent of the
# implementation): U+000D, '1', U+0080, U+00F6, U+20AC, U+1F600 (lead unit D83D),
# U+FB33 (FB33). Note D83D < FB33, so the emoji sorts before the Hebrew letter.
RFC_KEYS = {
    chr(0x20AC): "Euro Sign",
    chr(0x000D): "Carriage Return",
    chr(0xFB33): "Hebrew Letter Dalet With Dagesh",
    "1": "One",
    chr(0x1F600): "Emoji Grinning Face",
    chr(0x0080): "Control",
    chr(0x00F6): "Latin Small Letter O With Diaeresis",
}
RFC_EXPECTED_KEY_ORDER = [chr(0x000D), "1", chr(0x0080), chr(0x00F6), chr(0x20AC), chr(0x1F600), chr(0xFB33)]


class JcsCanonicalizeTests(unittest.TestCase):
    def test_literals_and_empty_containers(self):
        self.assertEqual(jcs.canonicalize(None), "null")
        self.assertEqual(jcs.canonicalize(True), "true")
        self.assertEqual(jcs.canonicalize(False), "false")
        self.assertEqual(jcs.canonicalize({}), "{}")
        self.assertEqual(jcs.canonicalize([]), "[]")

    def test_bool_is_not_int(self):
        self.assertEqual(jcs.canonicalize({"a": True, "b": False}), '{"a":true,"b":false}')

    def test_integers_and_safe_bound(self):
        self.assertEqual(jcs.canonicalize(0), "0")
        self.assertEqual(jcs.canonicalize(-42), "-42")
        self.assertEqual(jcs.canonicalize(2 ** 53 - 1), "9007199254740991")
        with self.assertRaises(ValueError):
            jcs.canonicalize(2 ** 53)
        with self.assertRaises(ValueError):
            jcs.canonicalize(-(2 ** 53))

    def test_floats_and_nonfinite_raise(self):
        # RFC 8785 Appendix B number vectors are inapplicable by design here:
        # non-integral numbers are rejected fail-closed (see jcs module docstring).
        for bad in (1.5, 1.0, float("nan"), float("inf"), float("-inf")):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    jcs.canonicalize(bad)

    def test_string_short_escapes(self):
        # RFC 8785 3.2.2.2 short escapes: \b \t \n \f \r \" \\
        self.assertEqual(jcs.canonicalize("\b\t\n\f\r\"\\"), '"\\b\\t\\n\\f\\r\\"\\\\"')

    def test_string_control_escapes_lowercase_u(self):
        self.assertEqual(jcs.canonicalize(chr(0x01)), '"\\u0001"')
        self.assertEqual(jcs.canonicalize(chr(0x1F)), '"\\u001f"')

    def test_non_ascii_emitted_literally(self):
        self.assertEqual(jcs.canonicalize(E_ACUTE), '"' + E_ACUTE + '"')

    def test_key_ordering_is_utf16_not_codepoint(self):
        # Code-point order puts U+E000 (57344) before U+10000 (65536); UTF-16 order
        # puts U+10000 (leading unit D800 = 55296) before U+E000. RFC 8785 -> UTF-16.
        out = jcs.canonicalize({BMP_PUA: 1, ASTRAL: 2})
        self.assertEqual(out, '{"' + ASTRAL + '":2,"' + BMP_PUA + '":1}')
        self.assertLess(out.index(ASTRAL), out.index(BMP_PUA))

    def test_rfc8785_property_sorting_example(self):
        out = jcs.canonicalize(RFC_KEYS)
        # Values are unique ASCII markers; assert they appear in the UTF-16 key order.
        marker_positions = [out.index(RFC_KEYS[k]) for k in RFC_EXPECTED_KEY_ORDER]
        self.assertEqual(marker_positions, sorted(marker_positions))
        # Keys are as-received (not NFC): U+FB33 stays a single unit and sorts last;
        # the carriage-return key is escaped in output.
        self.assertIn('"\\r":"Carriage Return"', out)
        self.assertLess(out.index("Emoji Grinning Face"), out.index("Hebrew Letter Dalet With Dagesh"))

    def test_basic_key_sorting_and_nesting(self):
        self.assertEqual(
            jcs.canonicalize({"b": [1, 2], "a": {"z": None, "y": True}}),
            '{"a":{"y":true,"z":null},"b":[1,2]}',
        )

    def test_nfc_normalises_values(self):
        self.assertEqual(jcs.canonicalize(E_DECOMP), jcs.canonicalize(E_ACUTE))
        self.assertEqual(jcs.canonicalize(E_DECOMP), '"' + E_ACUTE + '"')

    def test_member_names_are_not_nfc_normalised(self):
        # Values-only NFC: a decomposed key is serialised as received, so a
        # decomposed and a precomposed key are DISTINCT members (no collision).
        out = jcs.canonicalize({E_DECOMP: 1, E_ACUTE: 2})
        self.assertEqual(out.count(":"), 2)  # two distinct members survived

    def test_lone_surrogate_raises(self):
        with self.assertRaises(ValueError):
            jcs.canonicalize(chr(0xD800))
        with self.assertRaises(ValueError):
            jcs.canonicalize({chr(0xD800): 1})

    def test_non_string_key_raises(self):
        with self.assertRaises(ValueError):
            jcs.canonicalize({1: "a"})


if __name__ == "__main__":
    unittest.main()
