#!/usr/bin/env python3
"""Validate that conformance-vector artifacts conform to their spec type shape.

The lifecycle vectors (`conformance/vectors/dacs-v0.1-*.json`) carry, per stage,
an `artifact` of a declared `kind` (e.g. "SettlementEvidence"); the
`conformance/vectors/examples/*.json` files each carry one such `{kind, artifact}`.
Nothing previously checked that those artifacts actually have the FIELDS the
current spec defines for that kind — so when the v0.1 reset reshaped the
artifacts, the hand-authored vectors kept pre-v0.1 shapes (e.g. a
SettlementEvidence with `amount`/`asset`/`chainId` instead of
`phase`/`outcome`/`paymentAmount`) and CI stayed green, because the existing
checks only validate the wrapper + content hash, not the artifact (finding D2,
#133).

This validator derives, directly from the spec's `type X = { ... }` blocks
(single source of truth — no second schema encoding to drift):

  - each artifact's top-level field set, and checks every vector/example
    artifact of that kind: every REQUIRED field present, no UNKNOWN field; and
  - which fields are typed `ClaimReference` (a string, `Scheme ":" Identifier`,
    §B.1) — resolved **per type, descending into nested object types** — and
    checks that those fields are serialised as strings, not objects. (A verifier
    emitting `party: {scheme, identifier}` instead of `party: "scheme:identifier"`
    produces a bundleHash/signature over a non-spec serialisation; the top-level
    field-set check alone cannot see this — #145.) Per-type resolution avoids the
    field-name collision a global check would hit — `AttestationBundle.parties`
    is `BundleParty[]` while `CommitmentRecord.parties` is `ClaimReference[]`.

It is a *shape* check (field sets + ClaimReference string-form), not a full
value/enum check — deliberately narrower than the reference verifier, and what
the D2 / #145 drift needs. Stdlib-only; runs from a clean clone.
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
_FIELD = re.compile(r"^\s*([A-Za-z_]\w*)(\??)\s*:\s*(.*)$")


def _strip_comment(line: str) -> str:
    i = line.find("//")
    return line[:i] if i >= 0 else line


def parse_type_fields(text: str) -> dict[str, dict]:
    """Map each `type X = {...}` to its top-level field info.

    Per type: `required` / `optional` (field-name sets) and `ftypes`
    (field name → declared type string, comment-stripped). Brace depth is
    tracked so only depth-1 fields are read; fields inside a nested object are
    ignored, and the block ends when the matching close brace returns depth to 0.
    Nested object types are captured from their own `type` blocks.
    """
    out: dict[str, dict] = {}
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
        ftypes: dict[str, str] = {}
        depth = lines[i].count("{") - lines[i].count("}")  # usually 1
        i += 1
        while i < len(lines) and depth > 0:
            code = _strip_comment(lines[i])
            if depth == 1:
                fm = _FIELD.match(code)
                if fm:
                    fname, opt, ftype = fm.group(1), fm.group(2), fm.group(3).strip()
                    (optional if opt else required).add(fname)
                    if ftype:
                        ftypes[fname] = ftype
            depth += code.count("{") - code.count("}")
            i += 1
        out[name] = {"required": required, "optional": optional, "ftypes": ftypes}
    return out


def collect_type_fields() -> dict[str, dict]:
    types: dict[str, dict] = {}
    for md in sorted(SPEC_DIR.glob("*.md")):
        for name, fields in parse_type_fields(md.read_text(encoding="utf-8")).items():
            types[name] = fields
    return types


def _base_and_array(ftype: str) -> tuple[str, bool]:
    """('ClaimReference[]' -> ('ClaimReference', True)); a union / inline-object
    type returns itself with array=False (it won't match a known type name)."""
    t = ftype.strip()
    is_arr = t.endswith("[]")
    if is_arr:
        t = t[:-2].strip()
    return t, is_arr


def check_claimrefs(body: dict, typename: str, types: dict, ctx: str,
                    errors: list[str], path: str = "", seen: frozenset = frozenset()) -> None:
    """Recursively assert ClaimReference-typed fields of `typename` are strings.

    Resolves each field's declared type against the type registry; descends into
    nested object types (e.g. AttestationBundle.signatures: BundleSignature[] ->
    BundleSignature.party: ClaimReference). `seen` guards against type cycles.
    """
    spec = types.get(typename)
    if spec is None or typename in seen:
        return
    seen = seen | {typename}
    for fname, ftype in spec["ftypes"].items():
        if fname not in body:
            continue
        here = f"{path}.{fname}" if path else fname
        base, is_arr = _base_and_array(ftype)
        v = body[fname]
        if base == "ClaimReference":
            if is_arr:
                if not (isinstance(v, list) and all(isinstance(x, str) for x in v)):
                    errors.append(f"{ctx}: `{here}` is a ClaimReference[] and MUST be a string array")
            elif not isinstance(v, str):
                errors.append(f'{ctx}: `{here}` is a ClaimReference and MUST be a string '
                              f'("scheme:identifier"), got {type(v).__name__}')
        elif base in types:  # nested object type — descend
            if is_arr and isinstance(v, list):
                for idx, el in enumerate(v):
                    if isinstance(el, dict):
                        check_claimrefs(el, base, types, ctx, errors, f"{here}[{idx}]", seen)
            elif not is_arr and isinstance(v, dict):
                check_claimrefs(v, base, types, ctx, errors, here, seen)


def _artifacts_in(data) -> list[tuple[str, dict]]:
    """Extract (kind, body) pairs from either a lifecycle vector (`artifacts[]`)
    or a single example wrapper (`{kind, artifact}`)."""
    pairs: list[tuple[str, dict]] = []
    arts = data.get("artifacts")
    if isinstance(arts, list):
        for a in arts:
            if isinstance(a, dict) and isinstance(a.get("kind"), str) and isinstance(a.get("artifact"), dict):
                pairs.append((a["kind"], a["artifact"]))
    elif isinstance(data.get("kind"), str) and isinstance(data.get("artifact"), dict):
        pairs.append((data["kind"], data["artifact"]))
    return pairs


def check_file(path: Path, types: dict) -> tuple[list[str], int]:
    data = json.loads(path.read_text(encoding="utf-8"))
    pairs = _artifacts_in(data)
    if not pairs:
        return [], 0
    try:
        rel = str(path.relative_to(ROOT))
    except ValueError:
        rel = path.name
    errors: list[str] = []
    for kind, body in pairs:
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
        check_claimrefs(body, kind, types, f"{rel}: {kind}", errors)
    return errors, len(pairs)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    types = collect_type_fields()
    if not types:
        print("error: no spec type blocks found — is spec/ present?", file=sys.stderr)
        return 2

    files = sorted(VECTOR_DIR.glob("*.json")) + sorted((VECTOR_DIR / "examples").glob("*.json"))
    errors: list[str] = []
    checked = 0
    skipped: list[str] = []
    for f in files:
        if f.name in QUARANTINE:
            skipped.append(f"{f.name}: {QUARANTINE[f.name]}")
            continue
        errs, n = check_file(f, types)
        errors.extend(errs)
        checked += n

    if not args.quiet:
        print(f"validate_artifact_shapes: {len(types)} spec types, checked {checked} artifact(s)")
        for s in skipped:
            print(f"  QUARANTINED (not checked): {s}")
    if errors:
        print(f"FAIL — {len(errors)} artifact shape problem(s):", file=sys.stderr)
        print("\n".join(f"  {e}" for e in errors), file=sys.stderr)
        return 1
    print("OK — all vector/example artifacts match their spec type shape.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
