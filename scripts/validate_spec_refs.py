#!/usr/bin/env python3
"""Validate that every § section reference in the conformance corpus resolves.

The conformance MANIFEST cases carry a ``spec`` pointer (e.g. ``"§7.1"``) and the
vector artifacts carry ``specRefs`` (e.g. ``["§10.4.1", "§10.5.1"]``). Nothing
previously checked that those pointers actually resolve to a section that exists
in the spec — so when the v0.1 restructure moved/renumbered sections, a vector
could cite a section that no longer exists and CI would stay green.

This complements (it does not duplicate):
  - validate_rule_id_index.py  — resolves rule-FAMILY pointers in the nav index
  - validate-docs.py           — resolves markdown links
This validator resolves the §N.M *section* pointers carried by conformance
artifacts (MANIFEST cases + vector specRefs) against the actual spec headings.

Intentionally stdlib-only so implementers can run it from a clean clone:

    python3 scripts/validate_spec_refs.py
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC_DIR = ROOT / "spec"
CONFORMANCE_DIR = ROOT / "conformance"

# A section number is digit-led (7.5.1) or a single appendix letter (A, B.2) —
# NOT a multi-letter word, so prose headings like "## DACS v0.1" are not mistaken
# for a "DACS" section (Opus review, 2026-06-16).
_SECTION = r"(?:[0-9]+|[A-Z])(?:\.[0-9]+)*"
# Markdown heading carrying a section number, optional leading §.
_HEADING_RE = re.compile(rf"^#{{2,6}}\s+§?({_SECTION})\b")
# A §-reference anywhere in a string value.
_REF_RE = re.compile(rf"§({_SECTION})")


def collect_headings() -> set[str]:
    """Every section number defined by a heading across all spec module files."""
    headings: set[str] = set()
    for md in sorted(SPEC_DIR.glob("*.md")):
        for line in md.read_text(encoding="utf-8").splitlines():
            m = _HEADING_RE.match(line)
            if m:
                headings.add(m.group(1))
    return headings


def resolves(ref: str, headings: set[str]) -> bool:
    """A ref resolves if it is itself a heading, or an ancestor of one
    (§10.4 is valid when §10.4.3 exists). Dot-segment prefix, not substring.

    The reverse direction (a ref *deeper* than any heading) is intentionally NOT
    accepted: the live corpus needs none of it, and allowing it would let bogus
    refs like §A.99 / §3.999 falsely pass (Opus review, 2026-06-16). If a future
    policy wants to tolerate sub-sections that carry no heading of their own, make
    it an explicit, documented opt-in."""
    if ref in headings:
        return True
    ref_segs = ref.split(".")
    for h in headings:
        h_segs = h.split(".")
        if len(h_segs) > len(ref_segs) and h_segs[: len(ref_segs)] == ref_segs:
            return True
    return False


def _walk_strings(node):
    """Yield every string scalar in a JSON structure."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _walk_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_strings(v)


def collect_refs() -> dict[str, set[str]]:
    """Map each conformance file path -> set of §refs it cites."""
    refs: dict[str, set[str]] = {}
    for jf in sorted(CONFORMANCE_DIR.rglob("*.json")):
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue  # malformed JSON is validate_conformance_vectors.py's job
        found: set[str] = set()
        for s in _walk_strings(data):
            found.update(_REF_RE.findall(s))
        if found:
            refs[str(jf.relative_to(ROOT))] = found
    return refs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quiet", action="store_true", help="only print failures")
    args = ap.parse_args()

    headings = collect_headings()
    if not headings:
        print("error: no spec headings found — is spec/ present?", file=sys.stderr)
        return 2

    refs = collect_refs()
    failures: list[str] = []
    checked = 0
    for path, cited in sorted(refs.items()):
        for ref in sorted(cited):
            checked += 1
            if not resolves(ref, headings):
                failures.append(f"  {path}: §{ref} does not resolve to any spec section")

    if not args.quiet:
        print(f"validate_spec_refs: {len(headings)} sections, "
              f"checked {checked} §-references across {len(refs)} conformance file(s)")
    if failures:
        print(f"FAIL — {len(failures)} unresolved section reference(s):", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("OK — all conformance §-references resolve.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
