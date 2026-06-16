#!/usr/bin/env python3
"""Validate docs/rule-id-index.md against the specification.

The rule-ID index is a non-normative navigation aid that maps each labelled
rule family (e.g. ``SIG-*``) to the spec section that defines it and a §14
test-plan hook. Nothing previously checked that those pointers actually
resolve to the section that defines the family — so they drifted silently
across the v0.1 restructure (finding D8, issue #133).

This validator, for each indexed family, confirms that at least one labelled
rule of that family (``(FAM-1)``, ``(FAM-R1)``, …) actually appears in the
cited spec section (or one of its subsections), and that the §14 test-plan
hook resolves to a real CONFORMANCE-PLAN section. Dependency-free stdlib.
"""
from __future__ import annotations

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(ROOT, "spec")
INDEX = os.path.join(ROOT, "docs", "rule-id-index.md")

HEADING = re.compile(r"#{2,4}\s+(?:Chapter\s+)?(§?[A-C]?\.?\d[\w.]*)")


def section_text() -> dict[str, str]:
    """Map every spec section number to its text (concatenated across files)."""
    out: dict[str, str] = {}
    for fp in glob.glob(os.path.join(SPEC, "*.md")):
        cur, buf = None, []
        for ln in open(fp, encoding="utf-8"):
            m = HEADING.match(ln)
            if m:
                if cur is not None:
                    out[cur] = out.get(cur, "") + "\n".join(buf)
                cur = m.group(1).lstrip("§").rstrip(".")
                buf = [ln]
            else:
                buf.append(ln)
        if cur is not None:
            out[cur] = out.get(cur, "") + "\n".join(buf)
    return out


def distinct_rule_numbers(fam: str, txt: str) -> set[str]:
    """Distinct numeric rule IDs of `fam` appearing in `txt`.

    Handles plain ``(PIPE-3)``, the ``(rule CF-1)`` / ``(rules CF-2, CF-3)``
    phrasing, and ranges like ``(IT-1..IT-3)``.
    """
    f = re.escape(fam)
    nums: set[str] = set()
    for m in re.finditer(
        rf"\((?:rules?\s+)?{f}-?([A-Z]?\d+)(?:\s*\.\.\s*{f}?-?([A-Z]?\d+))?", txt
    ):
        nums.add(m.group(1))
        if m.group(2):
            nums.add(m.group(2))
    return nums


def covered_numbers(fam: str, sec: str, secmap: dict[str, str]) -> set[str]:
    """Distinct rule numbers of `fam` across `sec` and its subsections."""
    out: set[str] = set()
    for num, txt in secmap.items():
        if num == sec or num.startswith(sec + "."):
            out |= distinct_rule_numbers(fam, txt)
    return out


def defining_sections(fam: str, secmap: dict[str, str]) -> list[tuple[int, str]]:
    """Sections ranked by how many distinct `fam` rule numbers they carry.

    The defining section carries the family's full rule set; a section that
    merely *references* the family carries one stray number. Pointer
    correctness is therefore: the cited section(s) cover at least as many
    distinct rule numbers as any other single section. This is robust to the
    spec's varied definition formatting — list items, table cells
    (``| (PA-1) Bootstrap |``), and ``MUST: (IT-1)`` enumerations alike —
    where syntax-matching a "definition line" is not.

    Blind spot (documented): a single-rule family (e.g. CD-1) cannot be
    distinguished definition-from-reference by count alone; such pointers are
    accepted if they mention the rule.
    """
    scored = [(len(distinct_rule_numbers(fam, t)), s) for s, t in secmap.items()]
    return sorted((x for x in scored if x[0]), reverse=True)


def family_in_section(fam: str, sec: str, secmap: dict[str, str]) -> bool:
    # retained for the unit test: does `sec` (or a subsection) mention the family?
    return bool(covered_numbers(fam, sec, secmap))


def main() -> int:
    secmap = section_text()
    known = set(secmap)
    idx = open(INDEX, encoding="utf-8").read()
    rows = re.findall(
        r"\|\s*([A-Z][\w-]*?)\*\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|",
        idx,
    )
    errors: list[str] = []
    checked = 0
    for fam_raw, _desc, secs, hook in rows:
        fam = fam_raw.rstrip("-")
        if fam in ("Rule famil",) or not fam:
            continue
        checked += 1
        secrefs = [s.rstrip(".") for s in re.findall(r"§([\w.]+)", secs)]
        if not secrefs:
            errors.append(f"{fam}-*: no §section reference in '{secs.strip()}'")
            continue
        cited = max((len(covered_numbers(fam, s, secmap)) for s in secrefs), default=0)
        ranked = defining_sections(fam, secmap)
        best = ranked[0][0] if ranked else 0
        if cited == 0:
            errors.append(
                f"{fam}-*: no ({fam}-N) rule found in cited section(s) {secrefs}"
            )
        elif cited < best:
            top = [f"§{s} ({n})" for n, s in ranked[:3]]
            errors.append(
                f"{fam}-*: cited {secrefs} carry {cited} of the family's rule "
                f"numbers, but {top[0]} carries more — pointer likely names a "
                f"reference site, not the defining section (candidates: {', '.join(top)})"
            )
        for h in [s.rstrip(".") for s in re.findall(r"§([\w.]+)", hook)]:
            if h not in known:
                errors.append(f"{fam}-*: test-plan hook §{h} is not a real section")
    if errors:
        print("rule-id index pointer check FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"rule-id index OK ({checked} families, all pointers resolve)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
