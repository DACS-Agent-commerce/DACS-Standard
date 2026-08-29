#!/usr/bin/env python3
"""Generate the CORE §B.2 canonical-JSON candidate vectors.

Expected canonical strings are independent seed constants, not output from the
implementation under test. Their UTF-8 hex gives each adapter an exact-byte
oracle. The generic CROSS-RUN run file records verdicts only, so byte evidence
must remain enforced by the adapter (and be attached separately when needed).
Run with --check to verify byte-for-byte determinism or --write to regenerate
the committed set.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "canonical-json-v0.1.json"
)

E_ACUTE = "caf" + chr(0x00E9)
E_DECOMP = "cafe" + chr(0x0301)
BMP_PUA = chr(0xE000)
ASTRAL = chr(0x10000)


def binary64(hex_bits: str) -> dict[str, str]:
    return {"$dacsType": "binary64", "hex": hex_bits}


def bigint(decimal: str) -> dict[str, str]:
    return {"$dacsType": "bigint", "decimal": decimal}


def unicode_code_units(hex_units: str) -> dict[str, str]:
    return {"$dacsType": "unicode-code-units", "hex": hex_units}


def accepted(
    name: str,
    value: Any,
    canonical: str,
    rule: str,
    note: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "operation": "canonicalize",
        "input": value,
        "expected": "pass",
        "canonicalUtf8Hex": canonical.encode("utf-8").hex(),
        "rule": rule,
        "note": note,
    }


def rejected(
    name: str,
    value: Any,
    error_code: str,
    rule: str,
    note: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "operation": "canonicalize",
        "input": value,
        "expected": "fail",
        "expectedErrorCode": error_code,
        "rule": rule,
        "note": note,
    }


def build_vectors() -> list[dict[str, Any]]:
    return [
        accepted(
            "fraction-one-half",
            0.5,
            "0.5",
            "CORE §B.2 numeric safe-magnitude constraint",
            "A finite fractional JSON number inside the DACS bound is valid.",
        ),
        accepted(
            "fraction-one-e-minus-seven",
            1e-7,
            "1e-7",
            "RFC 8785 section 3.2.2.3",
            "Magnitudes below 1e-6 use ECMAScript scientific notation.",
        ),
        accepted(
            "fraction-binary-sum",
            0.30000000000000004,
            "0.30000000000000004",
            "RFC 8785 section 3.2.2.3",
            "The shortest round-trippable binary64 digits are preserved.",
        ),
        accepted(
            "fraction-one-tenth",
            0.1,
            "0.1",
            "RFC 8785 section 3.2.2.3",
            "A common non-integral metric canonicalizes without coercion.",
        ),
        accepted(
            "fraction-negative-one-and-half",
            -1.5,
            "-1.5",
            "CORE §B.2 numeric safe-magnitude constraint",
            "The DACS magnitude profile is symmetric around zero.",
        ),
        accepted(
            "fixed-notation-lower-threshold",
            binary64("3eb0c6f7a0b5ed8d"),
            "0.000001",
            "RFC 8785 Appendix B",
            "Exactly 1e-6 uses fixed notation.",
        ),
        accepted(
            "scientific-notation-below-threshold",
            binary64("3eb0c6f7a0b5ed8c"),
            "9.999999999999997e-7",
            "RFC 8785 Appendix B",
            "The adjacent binary64 below 1e-6 uses scientific notation.",
        ),
        accepted(
            "negative-zero",
            binary64("8000000000000000"),
            "0",
            "RFC 8785 Appendix B",
            "ECMAScript serializes negative zero as 0.",
        ),
        accepted(
            "minimum-positive-binary64",
            binary64("0000000000000001"),
            "5e-324",
            "RFC 8785 Appendix B",
            "Subnormal binary64 values are valid when within the DACS magnitude bound.",
        ),
        accepted(
            "minimum-negative-binary64",
            binary64("8000000000000001"),
            "-5e-324",
            "RFC 8785 Appendix B",
            "The minimum negative subnormal retains its sign and shortest exponent form.",
        ),
        accepted(
            "integral-binary64-one",
            binary64("3ff0000000000000"),
            "1",
            "RFC 8785 Appendix B",
            "An integral binary64 serializes as an integer token without a decimal suffix.",
        ),
        accepted(
            "round-to-even",
            binary64("43143ff3c1cb0959"),
            "1424953923781206.2",
            "RFC 8785 Appendix B note 4",
            "The shortest representation applies ECMAScript's round-to-even rule.",
        ),
        accepted(
            "maximum-dacs-magnitude",
            9007199254740991,
            "9007199254740991",
            "CORE §B.2 numeric safe-magnitude constraint",
            "The inclusive positive DACS magnitude boundary is accepted.",
        ),
        accepted(
            "maximum-dacs-magnitude-binary64",
            binary64("433fffffffffffff"),
            "9007199254740991",
            "CORE §B.2 numeric safe-magnitude constraint",
            "The inclusive positive boundary is also accepted through the binary64 path.",
        ),
        accepted(
            "minimum-dacs-magnitude-binary64",
            binary64("c33fffffffffffff"),
            "-9007199254740991",
            "CORE §B.2 numeric safe-magnitude constraint",
            "The inclusive negative boundary is accepted through the binary64 path.",
        ),
        rejected(
            "number-over-dacs-magnitude",
            9007199254740992,
            "NUMBER-OUTSIDE-DACS-MAGNITUDE",
            "CORE §B.2 numeric safe-magnitude constraint",
            "A number one above the DACS bound must use string carriage.",
        ),
        rejected(
            "number-one-e-plus-twenty-one",
            1e21,
            "NUMBER-OUTSIDE-DACS-MAGNITUDE",
            "CORE §B.2 numeric safe-magnitude constraint",
            "JCS can encode this value, but the stricter DACS magnitude profile rejects it.",
        ),
        rejected(
            "not-a-number",
            binary64("7ff8000000000000"),
            "NON-FINITE-NUMBER",
            "RFC 8785 section 3.2.2.3",
            "NaN is not a JSON number.",
        ),
        rejected(
            "positive-infinity",
            binary64("7ff0000000000000"),
            "NON-FINITE-NUMBER",
            "RFC 8785 section 3.2.2.3",
            "Infinity is not a JSON number.",
        ),
        rejected(
            "bigint-native-type",
            bigint("1"),
            "UNSUPPORTED-NATIVE-TYPE",
            "RFC 8785 section 3.1; CORE §B.2",
            "A native BigInt is not JSON; an adapter must test rejection or abstain explicitly.",
        ),
        accepted(
            "nfd-string-value-normalizes-to-nfc",
            {"label": E_DECOMP},
            '{"label":"' + E_ACUTE + '"}',
            "CORE §B.2 CF-1",
            "CF-1 normalizes string values before JCS serialization.",
        ),
        accepted(
            "nfd-member-name-preserved",
            {E_DECOMP: 1},
            '{"' + E_DECOMP + '":1}',
            "CORE §B.2 CF-1; RFC 8785 section 3.2.3",
            "CF-1 does not normalize object member names.",
        ),
        accepted(
            "nfc-and-nfd-member-names-remain-distinct",
            {E_ACUTE: 2, E_DECOMP: 1},
            '{"' + E_DECOMP + '":1,"' + E_ACUTE + '":2}',
            "CORE §B.2 CF-1; RFC 8785 section 3.2.3",
            "Canonical-equivalent member names do not collide and sort as received.",
        ),
        accepted(
            "member-name-order-is-utf16",
            {BMP_PUA: 1, ASTRAL: 2},
            '{"' + ASTRAL + '":2,"' + BMP_PUA + '":1}',
            "RFC 8785 section 3.2.3",
            "An astral key sorts before U+E000 by UTF-16 code units, not code points.",
        ),
        rejected(
            "lone-surrogate-string",
            unicode_code_units("d800"),
            "INVALID-UNICODE",
            "RFC 8785 section 3.2.2.2",
            "Invalid Unicode terminates canonicalization.",
        ),
    ]


def build_document() -> dict[str, Any]:
    vectors = build_vectors()
    vector_bytes = json.dumps(
        vectors,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")
    return {
        "set": "canonical-json-v0.1",
        "spec": "CORE §B.2 RFC 8785 JCS + CF-1",
        "tier": "candidate",
        "description": (
            "Byte-discriminating canonicalization cases for DACS fractional-number, "
            "safe-magnitude, Unicode-value, and member-name rules."
        ),
        "taggedValueSemantics": {
            "binary64": "Decode the 16 lowercase hex digits as one IEEE-754 binary64 value.",
            "bigint": "Construct the language's native arbitrary-precision integer type, not a JSON number.",
            "unicode-code-units": "Construct a string from the listed UTF-16 code units, including invalid lone surrogates.",
        },
        "count": len(vectors),
        "hash": hashlib.sha256(vector_bytes).hexdigest(),
        "vectors": vectors,
    }


def rendered() -> str:
    # ASCII escapes keep NFD/NFC source bytes reviewable and immune to editor
    # normalization. canonicalUtf8Hex remains the output authority.
    return json.dumps(build_document(), indent=2, ensure_ascii=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()

    expected = rendered()
    if args.write:
        OUTPUT.write_text(expected, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0

    try:
        current = OUTPUT.read_text(encoding="utf-8")
    except FileNotFoundError:
        current = ""
    if current != expected:
        print(
            "ERROR: canonical JSON vectors are stale or absent — run "
            "python3 scripts/generate_canonical_json_vectors.py --write"
        )
        return 1
    print("canonical JSON vectors OK (deterministic bytes, count, and hash)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
