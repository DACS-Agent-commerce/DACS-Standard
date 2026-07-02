#!/usr/bin/env python3
"""Generate (or verify) the set-index table in conformance/vectors/security/README.md.

Every security-vector PR used to hand-edit the same intro sentence and set
list in the README, so any two concurrent contributions collided on the same
lines (the #203 and #207 merges both needed manual conflict resolution for
exactly this). The index table is instead generated from the set JSONs
themselves — each already carries ``set`` / ``spec`` / ``count`` and its
vector verdicts — between marker comments, so adding a set never edits a
line another PR is editing.

Modes (mirrors the other repo validators' conventions):

- default / ``--check``: verify the README block matches what the set files
  generate; exit 1 with instructions if stale (this is the CI mode);
- ``--write``: regenerate the block in place.

The hand-written per-set prose sections below the table are untouched — this
owns only the block between the BEGIN/END markers. Dependency-free stdlib.
"""
from __future__ import annotations

import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECURITY_DIR = os.path.join(ROOT, "conformance", "vectors", "security")
README = os.path.join(SECURITY_DIR, "README.md")

BEGIN = "<!-- BEGIN GENERATED: security-vector-index (scripts/generate_security_vector_index.py) -->"
END = "<!-- END GENERATED: security-vector-index -->"

VERDICT_FIELDS = ("expected", "decision")


def build_table() -> str:
    rows = []
    for path in sorted(glob.glob(os.path.join(SECURITY_DIR, "*.json"))):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        verdicts: list[str] = []
        for vec in data.get("vectors", []):
            for field in VERDICT_FIELDS:
                if field in vec and vec[field] not in verdicts:
                    verdicts.append(vec[field])
                    break
        rows.append((
            os.path.basename(path),
            str(data.get("spec", "")).replace("|", "\\|"),
            str(len(data.get("vectors", []))),
            " / ".join(f"`{v}`" for v in sorted(verdicts, key=str)),
        ))

    lines = [
        BEGIN,
        "",
        "| Set | Spec surface | Vectors | Verdicts used |",
        "| --- | --- | --- | --- |",
    ]
    for name, spec, count, verdicts in rows:
        lines.append(f"| [`{name}`]({name}) | {spec} | {count} | {verdicts} |")
    lines += [
        "",
        "_This table is generated from the set files — do not edit by hand._",
        f"_Regenerate with `python3 scripts/generate_security_vector_index.py --write`._",
        "",
        END,
    ]
    return "\n".join(lines)


def spliced_readme(table: str) -> str:
    with open(README, encoding="utf-8") as fh:
        text = fh.read()
    if BEGIN in text and END in text:
        head, rest = text.split(BEGIN, 1)
        _, tail = rest.split(END, 1)
        return head + table + tail
    # First run: insert the block immediately before "## Included sets".
    anchor = "## Included sets"
    if anchor not in text:
        raise SystemExit(f"README has neither the generated-block markers nor "
                         f"the '{anchor}' anchor — cannot place the index")
    return text.replace(anchor, table + "\n\n" + anchor, 1)


def main() -> int:
    write = "--write" in sys.argv[1:]
    table = build_table()
    new_text = spliced_readme(table)
    with open(README, encoding="utf-8") as fh:
        current = fh.read()

    if new_text == current:
        print("security vector index OK (README block matches the set files)")
        return 0
    if write:
        with open(README, "w", encoding="utf-8") as fh:
            fh.write(new_text)
        print("security vector index regenerated in README.md")
        return 0
    print("ERROR: the README set-index block is stale (or missing) — run\n"
          "  python3 scripts/generate_security_vector_index.py --write",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
