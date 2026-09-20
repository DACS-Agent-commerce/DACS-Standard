"""Execute the CORE §B.2 CF-5 raw JSON admission corpus."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_raw_json_profile_vectors as generator  # noqa: E402
import jcs  # noqa: E402
import raw_json_profile as profile  # noqa: E402


def raw_bytes(vector: dict) -> bytes:
    if "rawHex" in vector:
        return bytes.fromhex(vector["rawHex"])
    return vector["rawUtf8Text"].encode("utf-8")


class RawJsonProfileVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = ROOT / "conformance/vectors/security/raw-json-profile-v0.1.json"
        cls.data = json.loads(cls.path.read_text(encoding="utf-8"))

    def test_committed_file_is_deterministic(self):
        self.assertEqual(self.path.read_text(encoding="utf-8"), generator.rendered())

    def test_two_independent_parsers_agree_on_every_vector(self):
        for vector in self.data["vectors"]:
            with self.subTest(name=vector["name"]):
                raw = raw_bytes(vector)
                results = []
                for parser in (profile.loads, profile.loads_reference):
                    verdict, code = profile.classify(parser, raw)
                    results.append((verdict, code))
                self.assertEqual(results[0], results[1])
                if vector["expected"] == "accept":
                    self.assertEqual(results[0], ("accept", None))
                else:
                    self.assertEqual(
                        results[0],
                        (
                            "reject-" + vector["expectedStage"],
                            vector["expectedErrorCode"],
                        ),
                    )

    def test_accepted_raw_text_reaches_exact_jcs_bytes(self):
        for vector in self.data["vectors"]:
            if vector["expected"] != "accept":
                continue
            with self.subTest(name=vector["name"]):
                first = profile.loads(raw_bytes(vector))
                second = profile.loads_reference(raw_bytes(vector))
                self.assertEqual(first, second)
                self.assertEqual(
                    jcs.canonicalize(first).encode("utf-8").hex(),
                    vector["canonicalUtf8Hex"],
                )

    def test_rejections_never_have_canonical_output(self):
        for vector in self.data["vectors"]:
            if vector["expected"] == "reject":
                with self.subTest(name=vector["name"]):
                    self.assertNotIn("canonicalUtf8Hex", vector)

    def test_raw_duplicate_and_unsafe_tokens_are_not_collapsed(self):
        cases = {vector["name"]: vector for vector in self.data["vectors"]}
        duplicate = raw_bytes(cases["duplicate-top-level-member"])
        unsafe = raw_bytes(cases["positive-rounded-unsafe-integer"])

        # These are the exact losses CF-5 prevents.  A normal object parser
        # keeps only one duplicate and its binary64 equivalent would round the
        # unsafe integer before a later object-model canonicalizer sees it.
        self.assertEqual(json.loads(duplicate), {"amount": "100"})
        self.assertEqual(float("9007199254740993"), 9007199254740992.0)

        for raw, code in (
            (duplicate, "DUPLICATE-MEMBER"),
            (unsafe, "NUMBER-OUTSIDE-DACS-MAGNITUDE"),
        ):
            with self.assertRaises(profile.RawJsonProfileError) as raised:
                profile.loads(raw)
            self.assertEqual(raised.exception.stage, "profile")
            self.assertEqual(raised.exception.code, code)

    def test_parse_profile_and_canonicalization_are_distinct_stages(self):
        cases = {vector["name"]: vector for vector in self.data["vectors"]}
        parse_vector = cases["trailing-non-whitespace"]
        profile_vector = cases["positive-two-to-the-53"]
        accepted_vector = cases["negative-zero"]

        with self.assertRaises(profile.RawJsonProfileError) as parse_error:
            profile.loads(raw_bytes(parse_vector))
        self.assertEqual(parse_error.exception.stage, "parse")

        with self.assertRaises(profile.RawJsonProfileError) as profile_error:
            profile.loads(raw_bytes(profile_vector))
        self.assertEqual(profile_error.exception.stage, "profile")

        admitted = profile.loads(raw_bytes(accepted_vector))
        self.assertEqual(jcs.canonicalize(admitted), '{"n":0}')

    def test_external_admission_requires_exact_received_bytes(self):
        malformed = bytes.fromhex("7b2273223a22ff227d")
        lossy_text = malformed.decode("utf-8", errors="replace")

        for parser in (profile.loads, profile.loads_reference):
            with self.subTest(parser=parser.__name__, form="malformed-bytes"):
                with self.assertRaises(profile.RawJsonProfileError) as raised:
                    parser(malformed)
                self.assertEqual(raised.exception.stage, "parse")
                self.assertEqual(raised.exception.code, "INVALID-UTF8")

            with self.subTest(parser=parser.__name__, form="lossy-decoded-str"):
                with self.assertRaisesRegex(TypeError, "exact received JSON bytes"):
                    parser(lossy_text)  # type: ignore[arg-type]

            with self.subTest(parser=parser.__name__, form="exact-valid-utf8"):
                self.assertEqual(parser(b'{"s":"caf\xc3\xa9"}'), {"s": "café"})

            with self.subTest(parser=parser.__name__, form="literal-replacement"):
                self.assertEqual(
                    parser(b'{"s":"\xef\xbf\xbd"}'),
                    {"s": "�"},
                )

    def test_deep_inputs_never_escape_as_recursion_errors(self):
        for raw in (
            b"[" * 600 + b"0" + b"]" * 600,
            b'{"a":' * 600 + b"0" + b"}" * 600,
        ):
            for parser in (profile.loads, profile.loads_reference):
                with self.subTest(parser=parser.__name__, prefix=raw[:1]):
                    self.assertEqual(
                        profile.classify(parser, raw),
                        ("reject-profile", "JSON-NESTING-TOO-DEEP"),
                    )

    def test_nesting_boundary_is_independent_of_host_stack(self):
        probe = textwrap.dedent(
            r"""
            import sys

            root, limit_text = sys.argv[1:]
            sys.path.insert(0, root + "/scripts")
            import jcs
            import raw_json_profile as profile

            limit = int(limit_text)
            sys.setrecursionlimit(limit)

            def nested(kind, depth):
                value = b"0"
                for index in range(depth):
                    if kind == "array" or (kind == "mixed" and index % 2 == 0):
                        value = b"[" + value + b"]"
                    else:
                        value = b'{"a":' + value + b"}"
                return value

            def invoke(frames, function, *args):
                if frames == 0:
                    return function(*args)
                return invoke(frames - 1, function, *args)

            def check(condition, details):
                if not condition:
                    raise AssertionError(details)

            for kind in ("array", "object", "mixed"):
                raw = nested(kind, 128)
                for parser in (profile.loads, profile.loads_reference):
                    admitted = invoke(16, parser, raw)
                    canonical = invoke(16, jcs.canonicalize, admitted).encode("utf-8")
                    check(canonical == raw, (limit, kind, parser.__name__, canonical))

            for kind in ("array", "object", "mixed"):
                raw = nested(kind, 129)
                for parser in (profile.loads, profile.loads_reference):
                    try:
                        invoke(16, parser, raw)
                    except profile.RawJsonProfileError as error:
                        check(
                            (error.stage, error.code)
                            == ("profile", "JSON-NESTING-TOO-DEEP"),
                            (limit, kind, parser.__name__, error.stage, error.code),
                        )
                    else:
                        raise AssertionError((limit, kind, parser.__name__, "accepted"))

            controls = (
                (b"null", b"null"),
                (b'{"z":"cafe\\u0301","n":-0.0}',
                 '{"n":0,"z":"caf\u00e9"}'.encode("utf-8")),
                (b'[true,false,{"x":1e0}]', b'[true,false,{"x":1}]'),
            )
            for raw, expected in controls:
                for parser in (profile.loads, profile.loads_reference):
                    admitted = invoke(16, parser, raw)
                    check(
                        invoke(16, jcs.canonicalize, admitted).encode("utf-8")
                        == expected,
                        (limit, raw, parser.__name__),
                    )

            malformed = (
                (b'{"a":1,}', "parse", "INVALID-JSON"),
                (b"[0 1]", "parse", "INVALID-JSON"),
                (b'{"a" 1}', "parse", "INVALID-JSON"),
                (b'"unterminated', "parse", "INVALID-JSON"),
                (b"0 1", "parse", "TRAILING-DATA"),
                (b'{"a":1,"\\u0061":2}', "profile", "DUPLICATE-MEMBER"),
            )
            for raw, stage, code in malformed:
                results = []
                for parser in (profile.loads, profile.loads_reference):
                    try:
                        invoke(16, parser, raw)
                    except profile.RawJsonProfileError as error:
                        results.append((error.stage, error.code))
                    else:
                        results.append(("accept", None))
                check(
                    results == [(stage, code), (stage, code)],
                    (limit, raw, results),
                )

            check(sys.getrecursionlimit() == limit, (limit, sys.getrecursionlimit()))
            print("ok", limit)
            """
        )
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        for limit in (80, 150, 200, 260):
            with self.subTest(limit=limit):
                completed = subprocess.run(
                    [sys.executable, "-c", probe, str(ROOT), str(limit)],
                    cwd=ROOT,
                    env=environment,
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                self.assertEqual(
                    completed.returncode,
                    0,
                    msg=(
                        f"stdout:\n{completed.stdout}\n"
                        f"stderr:\n{completed.stderr}"
                    ),
                )
                self.assertEqual(completed.stdout.strip(), f"ok {limit}")

    def test_required_boundaries_and_hostile_forms_are_present(self):
        names = {vector["name"] for vector in self.data["vectors"]}
        self.assertTrue(
            {
                "maximum-safe-positive-integer",
                "maximum-safe-exponent-spelling",
                "positive-two-to-the-53",
                "negative-two-to-the-53",
                "positive-rounded-unsafe-integer",
                "negative-rounded-unsafe-integer",
                "exponent-equivalent-one",
                "negative-zero",
                "valid-fraction-one-tenth",
                "literal-replacement-character",
                "duplicate-top-level-member",
                "duplicate-nested-member",
                "duplicate-member-inside-array",
                "maximum-container-depth-array",
                "maximum-container-depth-object",
                "over-maximum-container-depth-array",
                "over-maximum-container-depth-object",
                "trailing-non-whitespace",
                "nan-extension",
                "positive-infinity-extension",
                "lone-high-surrogate-value",
                "invalid-utf8",
            }.issubset(names)
        )

    def test_spec_makes_raw_admission_load_bearing(self):
        core = (ROOT / "spec/CORE.md").read_text(encoding="utf-8")
        self.assertIn("Raw JSON admission (rule CF-5)", core)
        self.assertIn("MUST complete before", core)
        self.assertIn("duplicate decoded object member name", core)
        self.assertIn("MUST NOT first decode or parse an external document", core)
        self.assertIn("MUST accept the exact received byte sequence", core)
        self.assertIn("caller assertion, decoded string, or re-serialised object", core)
        self.assertIn("container nesting depth exceeds **128**", core)
        self.assertIn("JSON-NESTING-TOO-DEEP", core)


if __name__ == "__main__":
    unittest.main()
