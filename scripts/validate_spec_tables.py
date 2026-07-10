#!/usr/bin/env python3
"""Smoke-test selected machine-readable tables in the DACS spec."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import specsource  # noqa: E402
SPEC = ROOT / "spec" / "SPECIFICATION.md"
DOMAIN_CELL_RE = re.compile(r'^"(dacs[-a-z0-9]*:v1:)"$')


def display(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def section_between(text: str, start_marker: str, end_marker: str) -> str:
    start = text.find(start_marker)
    if start == -1:
        raise ValueError(f"missing section marker: {start_marker}")
    end = text.find(end_marker, start)
    if end == -1:
        raise ValueError(f"missing section end marker: {end_marker}")
    return text[start:end]


def markdown_table_rows(section: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if cells and all(set(cell) <= {"-", ":", " "} for cell in cells):
            continue
        rows.append(cells)
    return rows


def validate_domain_registry(path: Path, root: Path, text: str | None = None) -> list[str]:
    errors: list[str] = []
    if text is None:
        text = path.read_text(encoding="utf-8")
    section = section_between(
        text,
        "The v0.x registry of domain separators at this revision is closed:",
        "**Payload shape — single-hash vs composite.**",
    )
    rows = markdown_table_rows(section)
    if not rows:
        return [f"{display(path, root)}: missing §7.7 domain separator registry table"]
    header, data_rows = rows[0], rows[1:]
    if header != ["Artifact", "Domain separator", "Defined in"]:
        errors.append(f"{display(path, root)}: unexpected §7.7 domain separator registry header")
    seen_domains: set[str] = set()
    seen_artifacts: set[str] = set()
    for row in data_rows:
        if len(row) != 3:
            errors.append(f"{display(path, root)}: §7.7 row has {len(row)} cells, expected 3")
            continue
        artifact, domain_cell, defined_in = row
        match = DOMAIN_CELL_RE.match(domain_cell)
        if not match:
            errors.append(f"{display(path, root)}: §7.7 row has invalid domain separator cell: {domain_cell}")
            continue
        domain = match.group(1)
        if artifact in seen_artifacts:
            errors.append(f"{display(path, root)}: duplicate §7.7 artifact row: {artifact}")
        seen_artifacts.add(artifact)
        if domain in seen_domains:
            errors.append(f"{display(path, root)}: duplicate §7.7 domain separator: {domain}")
        seen_domains.add(domain)
        if not defined_in.startswith("§"):
            errors.append(f"{display(path, root)}: §7.7 row has non-section Defined in cell: {defined_in}")
    return errors


def validate_repo(root: Path = ROOT) -> list[str]:
    root = root.resolve()
    return validate_domain_registry(root / "spec" / "CORE.md", root, text=specsource.spec_text(root))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate selected DACS specification tables")
    parser.add_argument("root", nargs="?", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    errors = validate_repo(args.root)
    if errors:
        print("spec table validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("spec tables OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
