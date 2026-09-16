#!/usr/bin/env python3
"""Validate the candidate security-vector sets under conformance/vectors/security/.

The canonical lifecycle validator (``validate_conformance_vectors.py``) globs
``conformance/vectors/*.json`` non-recursively on purpose — the security sets
are verifier-input/output pairs with per-set schemas, not five-stage lifecycle
bundles. That deliberate exclusion meant the candidate tier had no CI checks
at all: a set could claim ``count: 17`` while carrying 16 vectors, cite a
stale self-``hash``, or typo a verdict (``"pas"``) and merge silently.

This validator checks each set against its own claims:

- required top-level fields (``set``, ``spec``, ``count``, ``hash``,
  ``vectors``) and ``set`` == filename stem;
- ``count`` equals ``len(vectors)``;
- ``hash`` recomputes as sha256 over the canonical JSON of the ``vectors``
  array. Sets from different authors used slightly different canonical
  encodings (insertion-order vs sorted keys; ASCII-escaped vs raw UTF-8), so
  any of the four compact-JSON variants is accepted — but the hash MUST match
  one of them, so a stale hash after an edit still fails;
- every vector carries a unique, non-empty ``name``;
- every vector carries a verdict field (``expected``; legacy sb2 uses
  ``decision``) whose value is a known DACS verdict — the §7.5.1 four-value
  set plus the documented set-specific vocabularies (FR-4 reconciliation
  trichotomy, DV-6 readability four-way, agreement-listing accept/reject).
  Sets with a ``PER_SET_VERDICTS`` entry are checked against only their own
  vocabulary, so the RFC #320 set cannot silently re-declare ``pass`` where
  the evidence classifier establishes ``coherent``.

Dependency-free stdlib, matching the other validators.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECURITY_DIR = os.path.join(ROOT, "conformance", "vectors", "security")

REQUIRED_FIELDS = ("set", "spec", "count", "hash", "vectors")

# §7.5.1 four-value + documented per-set vocabularies.
#
# §7.5.1 four-value set is pass/fail/indeterminate/error; the set-specific vocabularies below
# are documented per set (FR-4 reconciliation trichotomy, DV-6 readability four-way,
# agreement-listing accept/reject, and the RFC #320 classifier's coherent/fail/indeterminate/reject).
# This is the GLOBAL union, used only as a fallback for sets without a per-set map below.
KNOWN_VERDICTS = {
    "pass", "fail", "indeterminate", "error",
    "coherent",
    "accept", "reject",
    "reconciles", "diverged",
    "readable", "clean-negative", "ACL-dropped",
}

# RFC #320 classifies supplied verification results; its positive verdict is
# `coherent`, not `pass`. Other sets retain their existing vocabulary behavior.
PER_SET_VERDICTS = {
    "atomic-work-receipt-absence-v0.1": {"coherent", "fail", "indeterminate", "reject"},
}

VERDICT_FIELDS = ("expected", "decision")


def canonical_encodings(vectors: list) -> dict[str, bytes]:
    """The accepted canonical encodings of the vectors array (see docstring)."""
    return {
        "compact insertion-order (ascii)": json.dumps(
            vectors, separators=(",", ":"), ensure_ascii=True).encode(),
        "compact insertion-order (utf-8)": json.dumps(
            vectors, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
        "compact sorted-keys (ascii)": json.dumps(
            vectors, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode(),
        "compact sorted-keys (utf-8)": json.dumps(
            vectors, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8"),
    }


def validate_set(path: str) -> tuple[list[str], int]:
    """Return (errors, vector_count) for one set file."""
    errors: list[str] = []
    name = os.path.basename(path)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{name}: unreadable/invalid JSON — {exc}"], 0

    for field in REQUIRED_FIELDS:
        if field not in data:
            errors.append(f"{name}: missing required top-level field '{field}'")
    if errors:
        return errors, 0

    stem = name[:-len(".json")]
    if not isinstance(data["set"], str):
        errors.append(f"{name}: 'set' must be a string")
    elif data["set"] != stem:
        errors.append(f"{name}: 'set' is '{data['set']}' but filename stem is '{stem}'")

    vectors = data["vectors"]
    if not isinstance(vectors, list) or not vectors:
        errors.append(f"{name}: 'vectors' must be a non-empty array")
        return errors, 0

    if data["count"] != len(vectors):
        errors.append(
            f"{name}: 'count' claims {data['count']} but vectors array has {len(vectors)}")

    want_hash = data["hash"]
    matched = None
    for label, encoded in canonical_encodings(vectors).items():
        if hashlib.sha256(encoded).hexdigest() == want_hash:
            matched = label
            break
    if matched is None:
        errors.append(
            f"{name}: 'hash' does not match sha256 of the vectors array under any "
            f"accepted canonical encoding — stale hash after an edit?")

    seen_names: set[str] = set()
    for i, vec in enumerate(vectors):
        if not isinstance(vec, dict):
            errors.append(f"{name}: vectors[{i}] is not an object")
            continue
        vname = vec.get("name")
        if not isinstance(vname, str) or not vname.strip():
            errors.append(f"{name}: vectors[{i}] missing a non-empty 'name'")
        elif vname in seen_names:
            errors.append(f"{name}: duplicate vector name '{vname}'")
        else:
            seen_names.add(vname)

        verdict = None
        for field in VERDICT_FIELDS:
            if field in vec:
                verdict = vec[field]
                break
        if verdict is None:
            errors.append(
                f"{name}: vectors[{i}] ('{vname}') has no verdict field "
                f"({' / '.join(VERDICT_FIELDS)})")
        else:
            allowed = PER_SET_VERDICTS.get(stem, KNOWN_VERDICTS)
            if verdict not in allowed:
                errors.append(
                    f"{name}: vectors[{i}] ('{vname}') has unknown verdict '{verdict}' "
                    f"for set '{data['set']}' "
                    f"(permitted: {', '.join(sorted(allowed))})")

    return errors, len(vectors)


def main() -> int:
    paths = sorted(glob.glob(os.path.join(SECURITY_DIR, "*.json")))
    if not paths:
        print("no security vector sets found — nothing to validate")
        return 0

    all_errors: list[str] = []
    total_vectors = 0
    for path in paths:
        errors, count = validate_set(path)
        all_errors.extend(errors)
        total_vectors += count

    if all_errors:
        for err in all_errors:
            print(f"ERROR: {err}", file=sys.stderr)
        print(f"security vector validation FAILED ({len(all_errors)} error(s))",
              file=sys.stderr)
        return 1

    print(f"security vector sets OK ({len(paths)} sets, {total_vectors} vectors; "
          f"counts, hashes, names, verdicts all verified)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
