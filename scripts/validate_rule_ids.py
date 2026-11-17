#!/usr/bin/env python3
"""Validate labelled DACS rule IDs and the non-normative rule-ID index.

The checker is intentionally conservative. It validates labelled rule families
and the substrate capabilities defined by the CORE §5 table, then reports:

- references to numbered rules in those families that have no definition;
- references to substrate capabilities absent from that table;
- defined rule families missing from docs/rule-id-index.md.

It deliberately ignores standards names such as EIP-4361 and ERC-8004.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import specsource  # noqa: E402
SPEC = ROOT / "spec" / "SPECIFICATION.md"
INDEX = ROOT / "docs" / "rule-id-index.md"
RULE_ID_RE = re.compile(r"\b([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)?-?\d+)\b")
PAREN_DEF_RE = re.compile(r"\(([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)?-?\d+)\)")
RULE_WORD_DEF_RE = re.compile(r"\b[Rr]ule\s+([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)?-?\d+)\b")
CAPABILITY_HEADING_RE = re.compile(r"^## (?:\d+\. )?Substrate capabilities$")
CAPABILITY_DEF_RE = re.compile(r"^\|\s*(SR-\d+)\s*\|")
CAPABILITY_REF_RE = re.compile(r"\bSR-\d+\b")
HEADING_RE = re.compile(r"^#{1,6}\s")
FENCE_PREFIXES = ("```", "~~~")
SKIP_PREFIXES = {"AP", "CAIP", "DACS", "EIP", "ERC", "HTTP", "IEEE", "L", "NAICS", "P", "RE", "SR", "UTF"}


def is_fence(line: str) -> bool:
    """A ``` or ~~~ code-fence line, indented or not."""
    return line.lstrip().startswith(FENCE_PREFIXES)


def rule_family(rule_id: str) -> str:
    return re.sub(r"\d+$", "", rule_id).rstrip("-")


def is_rule_like(rule_id: str) -> bool:
    family = rule_family(rule_id)
    return family not in SKIP_PREFIXES and ("-" in rule_id)


def display(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def defined_rule_ids(spec_text: str) -> set[str]:
    ids = set(PAREN_DEF_RE.findall(spec_text)) | set(RULE_WORD_DEF_RE.findall(spec_text))
    return {rule_id for rule_id in ids if is_rule_like(rule_id)}


def referenced_rule_ids(spec_text: str) -> set[str]:
    return {rule_id for rule_id in RULE_ID_RE.findall(spec_text) if is_rule_like(rule_id)}


def defined_capability_ids(spec_text: str) -> set[str]:
    """SR capabilities are rows of the first table in CORE §5, separate from labelled SR2-* rules.

    Only the first "Substrate capabilities" section counts (CORE comes first in
    spec_text). An SR row in a code fence, a later table, or any other section
    defines nothing."""
    in_section = in_code = False
    rows: list[str] = []
    for line in spec_text.splitlines():
        if is_fence(line):
            in_code = not in_code
            if rows:
                break
            continue
        if in_code:
            continue
        if HEADING_RE.match(line):
            if in_section:
                break
            in_section = CAPABILITY_HEADING_RE.match(line) is not None
            continue
        if not in_section:
            continue
        if line.startswith("|"):
            rows.append(line)
        elif rows:
            break
    return {match.group(1) for row in rows if (match := CAPABILITY_DEF_RE.match(row))}


def indexed_families(index_text: str) -> set[str]:
    families: set[str] = set()
    for line in index_text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if not cells or not cells[0].endswith("*"):
            continue
        family = cells[0].removesuffix("*").rstrip("-")
        if family:
            families.add(family)
    return families


def validate_repo(root: Path = ROOT) -> list[str]:
    root = root.resolve()
    spec_path = root / "spec" / "SPECIFICATION.md"
    index_path = root / "docs" / "rule-id-index.md"
    errors: list[str] = []
    spec_text = specsource.spec_text(root)
    index_text = index_path.read_text(encoding="utf-8") if index_path.exists() else ""

    defined = defined_rule_ids(spec_text)
    defined_by_family: dict[str, set[str]] = defaultdict(set)
    for rule_id in defined:
        defined_by_family[rule_family(rule_id)].add(rule_id)

    for rule_id in sorted(referenced_rule_ids(spec_text)):
        family = rule_family(rule_id)
        if family in defined_by_family and rule_id not in defined_by_family[family]:
            errors.append(f"{display(spec_path, root)}: referenced rule {rule_id} is not defined")

    capabilities = defined_capability_ids(spec_text)
    for capability in sorted(set(CAPABILITY_REF_RE.findall(spec_text)) - capabilities):
        errors.append(f"{display(spec_path, root)}: referenced substrate capability {capability} is not defined")

    indexed = indexed_families(index_text)
    for family in sorted(defined_by_family):
        if family not in indexed:
            errors.append(f"{display(index_path, root)}: missing rule family entry: {family}-*")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate DACS labelled rule IDs")
    parser.add_argument("root", nargs="?", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    errors = validate_repo(args.root)
    if errors:
        print("rule-ID validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("rule IDs OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
