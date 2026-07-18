#!/usr/bin/env python3
"""Validate DACS markdown documentation links.

This repository is currently spec/docs heavy. Keep validation dependency-free so
contributors can run it with only Python 3:

    python3 scripts/validate-docs.py

Checks:
- relative markdown links point to existing files/directories;
- markdown heading anchors in relative links resolve using GitHub-style slugs.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlparse

LINK_RE = re.compile(r"(?<!!)\[[^\]\n]+\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
SKIP_DIRS = {".context", ".git", ".github", ".mypy_cache", ".pytest_cache", "__pycache__"}


def github_slug(heading: str, seen: Counter[str]) -> str:
    """Return the GitHub-style markdown anchor slug for a heading."""
    text = re.sub(r"<[^>]+>", "", heading).strip().lower()
    text = re.sub(r"[`*_~]", "", text)
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    text = re.sub(r"\s+", "-", text).strip("-")
    base = text
    count = seen[base]
    seen[base] += 1
    if count:
        return f"{base}-{count}"
    return base


def markdown_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*.md"):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        files.append(path)
    return sorted(files)


def anchors_for(path: Path) -> set[str]:
    seen: Counter[str] = Counter()
    anchors = {""}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = HEADING_RE.match(line)
        if not match:
            continue
        anchors.add(github_slug(match.group(2), seen))
    return anchors


def is_external_or_special(target: str) -> bool:
    parsed = urlparse(target)
    return bool(parsed.scheme) or target.startswith(("mailto:", "tel:", "#"))


def iter_markdown_links(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    return [match.group(1) for match in LINK_RE.finditer(text)]


def validate_repo(root: Path) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    anchor_cache: dict[Path, set[str]] = {}

    for source in markdown_files(root):
        rel_source = source.relative_to(root)
        for raw_target in iter_markdown_links(source):
            if is_external_or_special(raw_target):
                continue

            parsed = urlparse(raw_target)
            link_path = unquote(parsed.path)
            if not link_path:
                continue

            target = (source.parent / link_path).resolve()
            try:
                target.relative_to(root)
            except ValueError:
                errors.append(f"{rel_source}: link escapes repo: {raw_target}")
                continue

            if not target.exists():
                errors.append(f"{rel_source}: missing target: {raw_target}")
                continue

            if parsed.fragment and target.is_file() and target.suffix.lower() == ".md":
                anchors = anchor_cache.setdefault(target, anchors_for(target))
                fragment = unquote(parsed.fragment)
                if fragment not in anchors:
                    errors.append(f"{rel_source}: missing anchor #{fragment} in {target.relative_to(root)}")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate relative markdown links in the DACS docs")
    parser.add_argument("root", nargs="?", default=".", type=Path, help="repository root to validate")
    args = parser.parse_args(argv)

    errors = validate_repo(args.root)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print("markdown documentation links OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
