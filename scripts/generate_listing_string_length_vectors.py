#!/usr/bin/env python3
"""Generate deterministic boundary vectors for the DACS-1 §6.3.4 Listing string bounds.

Every ``max N chars`` bound in the Listing type counts Unicode scalar values of
the value's CF-1 (NFC) form, the form that is hashed and signed; not UTF-16
code units, not UTF-8 bytes, and not the code points of a decomposed input.
Each vector gives one field value, the verdict, and the four counts that
differ, so an implementation that fails a vector can see which unit it used.
Dependency-free (stdlib only); values are built from fixed characters.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import unicodedata
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "vectors" / "security" / "listing-string-length-v0.1.json"
)
SET = "listing-string-length-v0.1"
SPEC = "DACS-1 §6.3.4 Listing `max N chars` bounds: Unicode scalar values of the CF-1 (NFC) form"

LIMITS = {"displayName": 200, "title": 200, "description": 2000, "tag": 32}
EMOJI = "\U0001F600"          # one scalar value, two UTF-16 code units, four UTF-8 bytes
DECOMPOSED_E = "é"      # two scalar values as received, one after NFC
PRECOMPOSED_E = "é"      # one scalar value, two UTF-8 bytes


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def counts(value: str) -> dict:
    nfc = unicodedata.normalize("NFC", value)
    return {
        "scalarValuesNfc": len(nfc),
        "scalarValuesAsReceived": len(value),
        "utf16CodeUnits": len(value.encode("utf-16-le")) // 2,
        "utf8Bytes": len(value.encode("utf-8")),
    }


def vector(name, field, value, note):
    limit = LIMITS[field]
    c = counts(value)
    expected = "pass" if c["scalarValuesNfc"] <= limit else "fail"
    return {
        "name": name,
        "rule": "§6.3.4",
        "field": field,
        "limit": limit,
        "expected": expected,
        "value": value,
        "counts": c,
        "note": note,
    }


def document() -> dict:
    vectors = [
        vector("display-name-200-ascii", "displayName", "a" * 200,
               "At the bound. Every unit agrees."),
        vector("display-name-201-ascii", "displayName", "a" * 201,
               "One over the bound. Every unit agrees."),
        vector("display-name-101-emoji", "displayName", EMOJI * 101,
               "101 scalar values, 202 UTF-16 code units, 404 UTF-8 bytes. Passes; a UTF-16 "
               "or byte count rejects it."),
        vector("display-name-200-decomposed", "displayName", DECOMPOSED_E * 200,
               "400 code points as received (and 400 UTF-16 code units), 200 after NFC. Passes; "
               "a count taken before normalisation, or in UTF-16 units, rejects it."),
        vector("display-name-201-precomposed", "displayName", PRECOMPOSED_E * 201,
               "201 scalar values in both forms. Fails; a byte count would also fail it, for "
               "the wrong reason."),
        vector("title-mixed-200-after-nfc", "title",
               "a" * 100 + EMOJI * 50 + DECOMPOSED_E * 50,
               "100 + 50 + 50 = 200 scalar values after NFC (250 as received, 300 UTF-16 "
               "units, 450 bytes). Passes only under the pinned unit."),
        vector("title-mixed-201-after-nfc", "title",
               "a" * 101 + EMOJI * 50 + DECOMPOSED_E * 50,
               "One more ASCII character than the previous vector: 201 after NFC. Fails."),
        vector("description-2000-ascii", "description", "x" * 2000,
               "At the 2000 bound. A strict less-than comparison rejects it."),
        vector("description-1001-emoji", "description", EMOJI * 1001,
               "1001 scalar values, 2002 UTF-16 code units. Passes under the 2000 bound."),
        vector("description-2001-ascii", "description", "x" * 2001, "One over the 2000 bound."),
        vector("tag-32-ascii", "tag", "x" * 32,
               "At the 32 bound. A strict less-than comparison rejects it."),
        vector("tag-17-emoji", "tag", EMOJI * 17,
               "17 scalar values, 34 UTF-16 code units. Passes under the 32 bound."),
        vector("tag-33-ascii", "tag", "x" * 33, "One over the 32 bound."),
    ]
    assert [v["expected"] for v in vectors] == [
        "pass", "fail", "pass", "pass", "fail", "pass", "fail",
        "pass", "pass", "fail", "pass", "pass", "fail"]
    # Every bound has an at-bound pass and a one-over fail, so a `<` comparison
    # on any field fails at least one vector.
    for field, limit in LIMITS.items():
        at = [v for v in vectors if v["field"] == field and v["counts"]["scalarValuesNfc"] == limit]
        over = [v for v in vectors if v["field"] == field and v["counts"]["scalarValuesNfc"] == limit + 1]
        assert at and over, field
    return {
        "set": SET,
        "spec": SPEC,
        "decisionModel": (
            "Each vector replaces one Listing string field with `value` in an otherwise "
            "valid Listing. `pass`: the §6.3.4 bound admits the value; `fail`: the bound "
            "rejects it. The bound counts counts.scalarValuesNfc; the other three counts "
            "are given so a failing implementation can identify the unit it used. "
            "`listingId` is URL-safe ASCII, where every unit coincides, and tags are "
            "counted per tag."
        ),
        "count": len(vectors),
        "hash": hashlib.sha256(canonical_bytes(vectors)).hexdigest(),
        "vectors": vectors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify the committed file")
    args = parser.parse_args()
    rendered = json.dumps(document(), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != rendered:
            print("stale generated corpus:", OUTPUT)
            return 1
        print("ok:", OUTPUT)
        return 0
    OUTPUT.write_text(rendered, encoding="utf-8")
    print("wrote:", OUTPUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
