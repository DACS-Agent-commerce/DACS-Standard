#!/usr/bin/env python3
"""Diff security-vector runs — the cross-run half of the candidate→golden path.

A candidate set is promoted only when independent implementations produce the
same verdicts on it. Until now each impl's runner printed its own "15/15" to a
terminal and humans compared tables in issue threads (#146, #159, #170). This
script makes the comparison mechanical.

An implementation emits a **run file** (any path, any impl language):

    {
      "set":  "vp-replay-v0.1",          // set name (resolves the expected file)
      "impl": "pathos-dacs-ref@1.4.0",   // free-form implementation id
      "results": [
        { "name": "valid-holder-binding", "verdict": "pass" },
        ...                              // one entry per vector, keyed by name
      ]
    }

Usage:

    python3 scripts/diff_vector_runs.py RUN.json [RUN2.json ...]

Each run is checked against the set's expected verdicts, and — when two or
more runs target the same set — against each other, case by case. Any
mismatch, missing case, or unknown case name is reported and exits 1; full
agreement prints a convergence summary (the artifact to cite when asking the
steward to promote the set). Dependency-free stdlib.
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECURITY_DIR = os.path.join(ROOT, "conformance", "vectors", "security")
# A set's expected verdicts may live as a security vector set (`vectors[{name}]`) or as a golden
# identity fixture (`cases[{id}]`, e.g. control-gate-vectors) — resolve either without a hand-built mirror.
FIXTURE_DIRS = (
    SECURITY_DIR,
    os.path.join(ROOT, "conformance", "fixtures", "identity"),
)

VERDICT_FIELDS = ("expected", "decision")


def _verdict_of(entry: dict) -> str | None:
    """A vector/case's expected verdict: a bare string, or an object carrying `.decision`
    (the vet-control `{decision, throws}` shape — only the decision participates in agreement)."""
    for field in VERDICT_FIELDS:
        if field in entry:
            value = entry[field]
            return value.get("decision") if isinstance(value, dict) else value
    return None


def load_expected(set_name: str) -> dict[str, str]:
    """Map case name -> expected verdict for a set.

    Resolves ``<set>.json`` from the security-vectors dir (``vectors[{name}]``) or the identity
    fixtures dir (``cases[{id}]``). Case identity is ``name`` or ``id``; the verdict is a bare
    string or an object with ``.decision``. Cross-impl agreement is over decisions only.
    """
    path = next(
        (os.path.join(d, set_name + ".json")
         for d in FIXTURE_DIRS
         if os.path.exists(os.path.join(d, set_name + ".json"))),
        None,
    )
    if path is None:
        searched = " | ".join(os.path.join(d, set_name + ".json") for d in FIXTURE_DIRS)
        raise SystemExit(f"ERROR: unknown set '{set_name}' — none of: {searched}")
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    expected: dict[str, str] = {}
    for entry in data.get("vectors") or data.get("cases") or []:
        name = entry.get("name") or entry.get("id")
        verdict = _verdict_of(entry)
        if name and verdict is not None:
            expected[name] = verdict
    return expected


def load_run(path: str) -> tuple[str, str, dict[str, str]]:
    """Return (set_name, impl_id, {vector name -> verdict}) for a run file."""
    with open(path, encoding="utf-8") as fh:
        run = json.load(fh)
    for field in ("set", "impl", "results"):
        if field not in run:
            raise SystemExit(f"ERROR: {path}: run file missing '{field}'")
    verdicts: dict[str, str] = {}
    for i, res in enumerate(run["results"]):
        name, verdict = res.get("name") or res.get("id"), res.get("verdict")
        if not name or verdict is None:
            raise SystemExit(f"ERROR: {path}: results[{i}] needs 'name' and 'verdict'")
        if name in verdicts:
            raise SystemExit(f"ERROR: {path}: duplicate result for '{name}'")
        verdicts[name] = verdict
    return run["set"], run["impl"], verdicts


def main() -> int:
    run_paths = [a for a in sys.argv[1:] if not a.startswith("-")]
    if not run_paths:
        print(__doc__.split("Usage:")[1].split("Each run")[0].strip(), file=sys.stderr)
        return 2

    runs = [load_run(p) for p in run_paths]
    problems: list[str] = []

    # 1. Every run vs the set's expected verdicts.
    for (set_name, impl, verdicts), path in zip(runs, run_paths):
        expected = load_expected(set_name)
        missing = sorted(expected.keys() - verdicts.keys())
        unknown = sorted(verdicts.keys() - expected.keys())
        for case in missing:
            problems.append(f"{impl} vs {set_name}: no result for case '{case}'")
        for case in unknown:
            problems.append(f"{impl} vs {set_name}: result for unknown case '{case}'")
        agree = 0
        for case in sorted(expected.keys() & verdicts.keys()):
            if verdicts[case] == expected[case]:
                agree += 1
            else:
                problems.append(
                    f"{impl} vs {set_name}: '{case}' — expected "
                    f"'{expected[case]}', got '{verdicts[case]}'")
        print(f"{impl} vs expected ({set_name}): {agree}/{len(expected)} agree")

    # 2. Run vs run, per shared set (the cross-impl convergence check).
    by_set: dict[str, list[tuple[str, dict[str, str]]]] = {}
    for set_name, impl, verdicts in runs:
        by_set.setdefault(set_name, []).append((impl, verdicts))
    for set_name, entries in by_set.items():
        for i in range(len(entries)):
            for j in range(i + 1, len(entries)):
                (impl_a, va), (impl_b, vb) = entries[i], entries[j]
                shared = sorted(va.keys() & vb.keys())
                diffs = [c for c in shared if va[c] != vb[c]]
                for case in diffs:
                    problems.append(
                        f"{impl_a} vs {impl_b} ({set_name}): '{case}' — "
                        f"'{va[case]}' vs '{vb[case]}'")
                print(f"{impl_a} vs {impl_b} ({set_name}): "
                      f"{len(shared) - len(diffs)}/{len(shared)} agree")

    if problems:
        print(file=sys.stderr)
        for p in problems:
            print(f"DIVERGENCE: {p}", file=sys.stderr)
        print(f"\ncross-run FAILED ({len(problems)} divergence(s))", file=sys.stderr)
        return 1
    print("\ncross-run CONVERGED — all runs agree with the expected verdicts "
          "and with each other")
    return 0


if __name__ == "__main__":
    sys.exit(main())
