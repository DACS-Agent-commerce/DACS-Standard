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


def family_in_section(fam: str, sec: str, secmap: dict[str, str]) -> bool:
    pat = re.compile(r"\(" + re.escape(fam) + r"-?[A-Z]?\d")
    for num, txt in secmap.items():
        if (num == sec or num.startswith(sec + ".")) and pat.search(txt):
            return True
    return False


def main() -> int:
    secmap = section_text()
    known = set(secmap)
    idx = open(INDEX, encoding="utf-8").read()
    rows = re.findall(
        r"\|\s*([A-Z][\w-]*)\-\*\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|",
        idx,
    )
    errors: list[str] = []
    checked = 0
    for fam, _desc, secs, hook in rows:
        checked += 1
        secrefs = [s.rstrip(".") for s in re.findall(r"§([\w.]+)", secs)]
        if not secrefs:
            errors.append(f"{fam}-*: no §section reference in '{secs.strip()}'")
            continue
        if not any(family_in_section(fam, s, secmap) for s in secrefs):
            errors.append(
                f"{fam}-*: no ({fam}-N) rule found in cited section(s) {secrefs} "
                f"— pointer does not resolve to the defining section"
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
