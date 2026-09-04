#!/usr/bin/env python3
"""Generate CORE CF-5 raw-JSON admission vectors.

The raw text is data in this file, not parsed JSON source, so duplicate member
names and hostile numeric spellings survive into the committed corpus.  Exact
canonical outputs are reviewable constants and are not obtained from the
implementation under test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance/vectors/security/raw-json-profile-v0.1.json"
MAX_NESTING_DEPTH = 128


def nested_array(depth: int) -> str:
    return "[" * depth + "0" + "]" * depth


def nested_object(depth: int) -> str:
    return '{"a":' * depth + "0" + "}" * depth


def accepted(name: str, raw: str, canonical: str, note: str) -> dict[str, Any]:
    return {
        "name": name,
        "operation": "admit-raw-json-then-canonicalize",
        "rawUtf8Text": raw,
        "expected": "accept",
        "canonicalUtf8Hex": canonical.encode("utf-8").hex(),
        "rule": "CORE §B.2 CF-5",
        "note": note,
    }


def rejected(
    name: str,
    raw: str | None,
    stage: str,
    code: str,
    note: str,
    *,
    raw_hex: str | None = None,
) -> dict[str, Any]:
    vector: dict[str, Any] = {
        "name": name,
        "operation": "admit-raw-json-then-canonicalize",
        "expected": "reject",
        "expectedStage": stage,
        "expectedErrorCode": code,
        "rule": "CORE §B.2 CF-5",
        "note": note,
    }
    if raw_hex is not None:
        vector["rawHex"] = raw_hex
    else:
        assert raw is not None
        vector["rawUtf8Text"] = raw
    return vector


def build_vectors() -> list[dict[str, Any]]:
    return [
        accepted("empty-object", "{}", "{}", "A well-formed JSON object is admitted."),
        accepted(
            "maximum-safe-positive-integer",
            '{"n":9007199254740991}',
            '{"n":9007199254740991}',
            "The positive DACS safe-magnitude boundary is inclusive.",
        ),
        accepted(
            "maximum-safe-negative-integer",
            '{"n":-9007199254740991}',
            '{"n":-9007199254740991}',
            "The negative DACS safe-magnitude boundary is inclusive.",
        ),
        accepted(
            "maximum-safe-exponent-spelling",
            '{"n":9.007199254740991e15}',
            '{"n":9007199254740991}',
            "An exponent spelling exactly at the safe boundary is admitted.",
        ),
        accepted(
            "exponent-equivalent-one",
            '{"n":1e0}',
            '{"n":1}',
            "A valid exponent spelling may normalize under JCS.",
        ),
        accepted(
            "uppercase-exponent-plus",
            '{"n":1E+0}',
            '{"n":1}',
            "Lexical spelling is not confused with numeric profile admission.",
        ),
        accepted(
            "negative-zero",
            '{"n":-0.0}',
            '{"n":0}',
            "Negative zero is admitted and JCS serializes it as zero.",
        ),
        accepted(
            "valid-fraction-one-tenth",
            '{"n":0.1}',
            '{"n":0.1}',
            "Finite bounded fractions remain valid after #345.",
        ),
        accepted(
            "valid-fraction-trailing-zero",
            '{"n":4.50}',
            '{"n":4.5}',
            "A valid fractional lexical form may normalize under JCS.",
        ),
        accepted(
            "minimum-positive-binary64",
            '{"n":5e-324}',
            '{"n":5e-324}',
            "The minimum non-zero binary64 subnormal is representable.",
        ),
        accepted(
            "escaped-member-name",
            '{"\\u0061":1}',
            '{"a":1}',
            "Duplicate detection compares decoded names; one escaped name is valid.",
        ),
        accepted(
            "valid-surrogate-pair",
            '{"s":"\\ud800\\udc00"}',
            '{"s":"𐀀"}',
            "A valid pair decodes to one Unicode scalar value.",
        ),
        accepted(
            "values-only-nfc-after-admission",
            ' \n {"s":"cafe\\u0301"}\t',
            '{"s":"café"}',
            "CF-5 admission precedes the existing values-only CF-1 NFC step.",
        ),
        accepted(
            "nfc-and-nfd-member-names-distinct",
            '{"é":1,"e\\u0301":2}',
            '{"é":2,"é":1}',
            "Member names remain distinct and are not NFC-folded.",
        ),
        accepted(
            "nested-distinct-members",
            '{"a":{"x":1},"b":[{"x":2}]}',
            '{"a":{"x":1},"b":[{"x":2}]}',
            "The same member spelling may occur in distinct objects.",
        ),
        accepted(
            "maximum-container-depth-array",
            nested_array(MAX_NESTING_DEPTH),
            nested_array(MAX_NESTING_DEPTH),
            "The host-independent 128-container depth boundary is inclusive for arrays.",
        ),
        accepted(
            "maximum-container-depth-object",
            nested_object(MAX_NESTING_DEPTH),
            nested_object(MAX_NESTING_DEPTH),
            "The host-independent 128-container depth boundary is inclusive for objects.",
        ),
        rejected(
            "over-maximum-container-depth-array",
            nested_array(MAX_NESTING_DEPTH + 1),
            "profile",
            "JSON-NESTING-TOO-DEEP",
            "Depth 129 is rejected before parser recursion or canonicalization.",
        ),
        rejected(
            "over-maximum-container-depth-object",
            nested_object(MAX_NESTING_DEPTH + 1),
            "profile",
            "JSON-NESTING-TOO-DEEP",
            "Object nesting uses the same depth rule as arrays.",
        ),
        rejected(
            "positive-two-to-the-53",
            '{"n":9007199254740992}',
            "profile",
            "NUMBER-OUTSIDE-DACS-MAGNITUDE",
            "2^53 is outside the inclusive DACS magnitude bound.",
        ),
        rejected(
            "negative-two-to-the-53",
            '{"n":-9007199254740992}',
            "profile",
            "NUMBER-OUTSIDE-DACS-MAGNITUDE",
            "-2^53 is outside the inclusive DACS magnitude bound.",
        ),
        rejected(
            "positive-rounded-unsafe-integer",
            '{"n":9007199254740993}',
            "profile",
            "NUMBER-OUTSIDE-DACS-MAGNITUDE",
            "The raw token is checked before a binary64 parser can round it.",
        ),
        rejected(
            "negative-rounded-unsafe-integer",
            '{"n":-9007199254740993}',
            "profile",
            "NUMBER-OUTSIDE-DACS-MAGNITUDE",
            "The raw negative token is checked before binary64 rounding.",
        ),
        rejected(
            "unsafe-exponent-spelling",
            '{"n":9.007199254740992e15}',
            "profile",
            "NUMBER-OUTSIDE-DACS-MAGNITUDE",
            "Exponent notation cannot bypass the mathematical magnitude check.",
        ),
        rejected(
            "binary64-overflow",
            '{"n":1e309}',
            "profile",
            "NUMBER-NOT-BINARY64",
            "A syntactically valid number that overflows binary64 is refused.",
        ),
        rejected(
            "binary64-underflow",
            '{"n":1e-9999}',
            "profile",
            "NUMBER-NOT-BINARY64",
            "A non-zero token that collapses to binary64 zero is refused.",
        ),
        rejected(
            "duplicate-top-level-member",
            '{"amount":"1","amount":"100"}',
            "profile",
            "DUPLICATE-MEMBER",
            "A parser's first/last-member policy cannot choose the signed amount.",
        ),
        rejected(
            "duplicate-nested-member",
            '{"terms":{"price":1,"price":2}}',
            "profile",
            "DUPLICATE-MEMBER",
            "Duplicate rejection applies at every object nesting level.",
        ),
        rejected(
            "duplicate-member-inside-array",
            '[{"sequence":1,"sequence":2}]',
            "profile",
            "DUPLICATE-MEMBER",
            "Objects inside arrays receive the same duplicate check.",
        ),
        rejected(
            "duplicate-escape-equivalent-member",
            '{"a":1,"\\u0061":2}',
            "profile",
            "DUPLICATE-MEMBER",
            "Names are compared after JSON escape decoding, before object collapse.",
        ),
        rejected(
            "lone-high-surrogate-value",
            '{"s":"\\ud800"}',
            "profile",
            "INVALID-UNICODE",
            "A lone high surrogate is not a Unicode scalar value.",
        ),
        rejected(
            "lone-low-surrogate-value",
            '{"s":"\\udc00"}',
            "profile",
            "INVALID-UNICODE",
            "A lone low surrogate is not a Unicode scalar value.",
        ),
        rejected(
            "lone-surrogate-member-name",
            '{"\\ud800":1}',
            "profile",
            "INVALID-UNICODE",
            "Member names must also contain only Unicode scalar values.",
        ),
        rejected(
            "nan-extension",
            '{"n":NaN}',
            "parse",
            "NON-JSON-CONSTANT",
            "NaN is a parser extension, not JSON.",
        ),
        rejected(
            "positive-infinity-extension",
            '{"n":Infinity}',
            "parse",
            "NON-JSON-CONSTANT",
            "Infinity is a parser extension, not JSON.",
        ),
        rejected(
            "negative-infinity-extension",
            '{"n":-Infinity}',
            "parse",
            "NON-JSON-CONSTANT",
            "Negative Infinity is a parser extension, not JSON.",
        ),
        rejected(
            "trailing-non-whitespace",
            '{"n":1} trailing',
            "parse",
            "TRAILING-DATA",
            "Non-whitespace bytes after the JSON value are refused.",
        ),
        rejected(
            "two-json-values",
            '{"n":1}{"n":2}',
            "parse",
            "TRAILING-DATA",
            "A second JSON value cannot be ignored.",
        ),
        rejected(
            "utf8-bom",
            '\ufeff{"n":1}',
            "parse",
            "BOM",
            "A BOM is not silently stripped from signed wire bytes.",
        ),
        rejected(
            "invalid-utf8",
            None,
            "parse",
            "INVALID-UTF8",
            "Ill-formed UTF-8 is rejected before JSON parsing.",
            raw_hex="7b2273223a22eda080227d",
        ),
        rejected(
            "leading-zero-number",
            '{"n":01}',
            "parse",
            "INVALID-JSON",
            "A non-JSON leading-zero form is refused rather than normalized.",
        ),
        rejected(
            "leading-plus-number",
            '{"n":+1}',
            "parse",
            "INVALID-JSON",
            "A leading plus sign is not JSON number syntax.",
        ),
        rejected(
            "unterminated-object",
            '{"n":1',
            "parse",
            "INVALID-JSON",
            "Incomplete JSON never reaches canonicalization.",
        ),
        rejected(
            "unescaped-control",
            '{"s":"\x01"}',
            "parse",
            "INVALID-JSON",
            "Unescaped C0 controls are invalid JSON string content.",
        ),
        rejected(
            "invalid-string-escape",
            '{"s":"\\x41"}',
            "parse",
            "INVALID-JSON",
            "Non-JSON escape extensions are refused.",
        ),
        rejected(
            "comment-extension",
            '{"n":1/*comment*/}',
            "parse",
            "INVALID-JSON",
            "Comments are not JSON and cannot be stripped before hashing.",
        ),
    ]


def document() -> dict[str, Any]:
    vectors = build_vectors()
    encoded = json.dumps(
        vectors, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "set": "raw-json-profile-v0.1",
        "spec": "CORE §B.2 CF-5 raw JSON admission",
        "tier": "candidate",
        "description": (
            "Raw UTF-8 JSON texts that preserve duplicate names and numeric tokens; "
            "two independent parsers must agree before JCS canonicalization."
        ),
        "count": len(vectors),
        "hash": hashlib.sha256(encoded).hexdigest(),
        "vectors": vectors,
    }


def rendered() -> str:
    return json.dumps(document(), ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = rendered()
    if args.write:
        OUTPUT.write_text(expected, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)} ({document()['count']} vectors)")
        return 0
    try:
        actual = OUTPUT.read_text(encoding="utf-8")
    except FileNotFoundError:
        actual = ""
    if actual != expected:
        print("raw JSON profile vectors are stale; run with --write")
        return 1
    print(f"raw JSON profile vectors OK ({document()['count']} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
