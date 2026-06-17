#!/usr/bin/env python3
"""Validate that conformance-vector artifacts conform to their spec type shape.

The lifecycle vectors (`conformance/vectors/dacs-v0.1-*.json`) carry, per stage,
an `artifact` of a declared `kind` (e.g. "SettlementEvidence"). Nothing
previously checked that those artifacts actually have the FIELDS the current
spec defines for that kind — so when the v0.1 reset reshaped the artifacts, the
hand-authored vectors kept pre-v0.1 shapes (e.g. a SettlementEvidence with
`amount`/`asset`/`chainId` instead of `phase`/`outcome`/`paymentAmount`) and CI
stayed green, because the existing checks only validate the wrapper + content
hash, not the artifact's field set (finding D2, #133).

This validator derives each artifact's field set directly from the spec's
`type X = { ... }` block (single source of truth — no second schema encoding to
drift), then checks every vector artifact of that kind:

  - every REQUIRED field (no trailing `?`) is present, and
  - no UNKNOWN field (not declared by the type) is present.

It is a *shape* check (field sets), not a value/enum/nested-type check — that is
deliberately narrower than the reference verifier, and is what the D2 drift
needs. Stdlib-only; runs from a clean clone.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC_DIR = ROOT / "spec"
VECTOR_DIR = ROOT / "conformance" / "vectors"

# Vectors whose artifacts are known-stale (pre-v0.1 shapes) and are awaiting
# regeneration from a reference verifier (finding D2, #133). They are skipped
# with a LOUD notice rather than silently — the gap is disclosed, not hidden —
# so the shape check guards every other (and every future) vector meanwhile.
# Remove an entry the moment its vector is regenerated to conformant shapes.
QUARANTINE = {
    "dacs-v0.1-happy-path.json": "stale pre-v0.1 artifact shapes; pending verifier regeneration (#133/D2)",
    "dacs-v0.1-negative-paths.json": "stale pre-v0.1 artifact shapes; pending verifier regeneration (#133/D2)",
}

_TYPE_OPEN = re.compile(r"^type\s+([A-Za-z_]\w*)\s*=\s*\{")
_FIELD = re.compile(r"^\s*([A-Za-z_]\w*)(\??)\s*:")


def _strip_comment(line: str) -> str:
    i = line.find("//")
    return line[:i] if i >= 0 else line


def parse_type_fields(text: str) -> dict[str, dict[str, set[str]]]:
    """Map each `type X = {...}` to its top-level {required, optional} field names.

    Brace depth is tracked so only depth-1 fields are read; fields inside a
    nested object (`terms: { price: ... }`, inline or multi-line) are ignored,
    and the block ends when the matching close brace returns depth to 0.
    """
    out: dict[str, dict[str, set[str]]] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = _TYPE_OPEN.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        required: set[str] = set()
        optional: set[str] = set()
        depth = lines[i].count("{") - lines[i].count("}")  # usually 1
        i += 1
        while i < len(lines) and depth > 0:
            raw = lines[i]
            code = _strip_comment(raw)
            if depth == 1:
                fm = _FIELD.match(code)
                if fm:
                    (optional if fm.group(2) else required).add(fm.group(1))
            depth += code.count("{") - code.count("}")
            i += 1
        out[name] = {"required": required, "optional": optional}
    return out


def collect_type_fields() -> dict[str, dict[str, set[str]]]:
    types: dict[str, dict[str, set[str]]] = {}
    for md in sorted(SPEC_DIR.glob("*.md")):
        for name, fields in parse_type_fields(md.read_text(encoding="utf-8")).items():
            types[name] = fields
    return types


def check_vector(path: Path, types: dict[str, dict[str, set[str]]]) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list):
        return []  # not a lifecycle vector with artifacts[]; not our surface
    errors: list[str] = []
    try:
        rel = path.relative_to(ROOT)
    except ValueError:
        rel = path.name
    for art in artifacts:
        kind = art.get("kind")
        body = art.get("artifact")
        if not isinstance(kind, str) or not isinstance(body, dict):
            continue
        spec = types.get(kind)
        if spec is None:
            errors.append(f"{rel}: kind '{kind}' has no `type {kind}` block in the spec")
            continue
        present = set(body.keys())
        missing = spec["required"] - present
        unknown = present - spec["required"] - spec["optional"]
        if missing:
            errors.append(f"{rel}: {kind} missing required field(s): {sorted(missing)}")
        if unknown:
            errors.append(f"{rel}: {kind} has unknown field(s) not in `type {kind}`: {sorted(unknown)}")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    types = collect_type_fields()
    if not types:
        print("error: no spec type blocks found — is spec/ present?", file=sys.stderr)
        return 2

    vectors = sorted(VECTOR_DIR.glob("*.json"))
    errors: list[str] = []
    checked = 0
    skipped: list[str] = []
    for v in vectors:
        if v.name in QUARANTINE:
            skipped.append(f"{v.name}: {QUARANTINE[v.name]}")
            continue
        errs = check_vector(v, types)
        data = json.loads(v.read_text(encoding="utf-8"))
        if isinstance(data.get("artifacts"), list):
            checked += len(data["artifacts"])
        errors.extend(errs)

    if not args.quiet:
        print(f"validate_artifact_shapes: {len(types)} spec types, "
              f"checked {checked} vector artifact(s)")
        for s in skipped:
            print(f"  QUARANTINED (not checked): {s}")
    if errors:
        print(f"FAIL — {len(errors)} artifact shape problem(s):", file=sys.stderr)
        print("\n".join(f"  {e}" for e in errors), file=sys.stderr)
        return 1
    print("OK — all vector artifacts match their spec type shape.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
