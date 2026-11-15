"""CF-1's pinned repertoire, ordering and wrong-implementation witnesses."""

import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import jcs  # noqa: E402
import raw_json_profile as raw_json  # noqa: E402
import dacs_reference  # noqa: E402
import run_lifecycle_walkthrough as walkthrough  # noqa: E402
import validate_conformance_vectors as conformance  # noqa: E402


class Cf1UnicodeVersionTests(unittest.TestCase):
    def test_later_assignment_is_rejected_before_normalization(self):
        with mock.patch.object(jcs.unicodedata, "normalize") as normalize:
            for value in [
                chr(0x105C9), chr(0x2EBF0), chr(0x1611E) * 2, chr(0x0378),
                "a" + chr(0x0897) + chr(0x0316), chr(0x105D2) + chr(0x0307),
                "a" + chr(0x1ACF) + chr(0x0316),
            ]:
                with self.subTest(value=ascii(value)):
                    with self.assertRaises(jcs.UnicodeRepertoireError) as raised:
                        jcs.canonicalize({"extension": [value]})
                    self.assertEqual(raised.exception.code, "UNASSIGNED-CODE-POINT")
            normalize.assert_not_called()

    def test_received_bytes_pass_cf5_then_fail_cf1(self):
        raw = json.dumps({"extension": chr(0x105C9)}).encode()
        for parser in [raw_json.loads, raw_json.loads_reference]:
            with self.subTest(parser=parser.__name__):
                value = parser(raw)
                self.assertEqual(value, {"extension": chr(0x105C9)})
                with self.assertRaises(jcs.UnicodeRepertoireError):
                    jcs.canonicalize(value)

    def test_shared_hash_and_conformance_consumers_refuse_before_hashing(self):
        value = {"extension": chr(0x105C9)}
        jcs._assigned_in_unicode_15()
        for consumer in [
            dacs_reference.canonical_bytes,
            dacs_reference.canonical_hash,
            walkthrough.canonical_json,
            conformance.canonical_json,
        ]:
            with self.subTest(consumer=consumer.__module__ + "." + consumer.__name__):
                with mock.patch.object(dacs_reference.hashlib, "sha256") as digest:
                    with self.assertRaises(jcs.UnicodeRepertoireError):
                        consumer(value)
                    digest.assert_not_called()

    def test_earlier_cf5_duplicate_and_surrogate_errors_keep_precedence(self):
        for parser in [raw_json.loads, raw_json.loads_reference]:
            for raw, code in [
                (b'{"x":"\\ud801\\uddc9","x":1}', "DUPLICATE-MEMBER"),
                (b'{"x":"\\ud800"}', "INVALID-UNICODE"),
            ]:
                with self.subTest(parser=parser.__name__, code=code):
                    with self.assertRaises(raw_json.RawJsonProfileError) as raised:
                        parser(raw)
                    self.assertEqual(raised.exception.stage, "profile")
                    self.assertEqual(raised.exception.code, code)

    def test_member_names_are_outside_repertoire_filter_and_nfc(self):
        value = {chr(0x105C9): 1, chr(0x0378): 2, "e\u0301": 3, "\u00e9": 4}
        expected = '{"e\u0301":3,"\u00e9":4,"\u0378":2,"\U000105c9":1}'
        for parser in [raw_json.loads, raw_json.loads_reference]:
            self.assertEqual(jcs.canonicalize(parser(json.dumps(value).encode())), expected)

    def test_all_noncharacters_and_private_use_boundaries_are_admitted(self):
        noncharacters = list(range(0xFDD0, 0xFDF0))
        for plane in range(17):
            noncharacters.extend([plane * 0x10000 + 0xFFFE, plane * 0x10000 + 0xFFFF])
        self.assertEqual(len(noncharacters), 66)
        for cp in noncharacters + [0xE000, 0xF8FF, 0xF0000, 0xFFFFD, 0x100000, 0x10FFFD]:
            with self.subTest(cp=hex(cp)):
                self.assertEqual(jcs.canonicalize(chr(cp)), '"' + chr(cp) + '"')

    def test_unicode15_boundary_and_nfd_positive_control(self):
        value = {"new15": chr(0x1FAE8), "label": "e\u0301"}
        self.assertEqual(jcs.canonicalize(value), '{"label":"\u00e9","new15":"\U0001fae8"}')

    def test_surrogates_are_invalid_unicode_even_with_numeric_age(self):
        for cp in [0xD800, 0xDBFF, 0xDC00, 0xDFFF]:
            for value in [chr(cp), {chr(cp): 1}]:
                with self.subTest(cp=hex(cp)):
                    with self.assertRaisesRegex(ValueError, "not valid UTF-8"):
                        jcs.canonicalize(value)

    def test_pinned_table_bytes_and_tamper_refusal(self):
        source = jcs._AGE_PATH.read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), jcs._AGE_SHA256)
        jcs._assigned_in_unicode_15.cache_clear()
        try:
            with mock.patch.object(jcs, "_AGE_PATH") as source_path:
                source_path.read_bytes.return_value = source + b"# changed\n"
                with self.assertRaisesRegex(ValueError, "source hash mismatch"):
                    jcs.canonicalize("ascii")
        finally:
            jcs._assigned_in_unicode_15.cache_clear()

    def test_older_normalizer_is_refused(self):
        with mock.patch.object(jcs.unicodedata, "unidata_version", "14.0.0"):
            with self.assertRaisesRegex(ValueError, "15.0.0 or newer"):
                jcs.canonicalize("ascii")

    def test_repertoire_guard_is_load_bearing(self):
        # Bounded mutant: without the guard the same admitted scalar reaches
        # canonical bytes. The negative test above must kill this regression.
        value = {"extension": chr(0x105C9)}
        with mock.patch.object(jcs, "_reject_unassigned", return_value=None):
            self.assertEqual(
                jcs.canonicalize(value), '{"extension":"\U000105c9"}'
            )
        with self.assertRaises(jcs.UnicodeRepertoireError):
            jcs.canonicalize(value)


if __name__ == "__main__":
    unittest.main()
