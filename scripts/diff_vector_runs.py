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
        { "name": "native-bigint", "status": "abstain",
          "reason": "native BigInt is unavailable in this language" },
        ...                              // one entry per vector, keyed by name
      ]
    }

Usage:

    python3 scripts/diff_vector_runs.py RUN.json [RUN2.json ...]

Each run is checked against the set's expected verdicts, and — when two or
more runs target the same set — against each other, case by case. Any
mismatch, missing case, unknown case name, or abstention exits 1. Abstentions
are excluded from agreement denominators and can never satisfy an expected
verdict or full-set promotion. Full agreement from at least two distinct
implementation ids prints a convergence summary (the artifact to cite when
asking the steward to promote the set). Dependency-free stdlib.
"""
from __future__ import annotations

from dataclasses import dataclass
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


@dataclass(frozen=True)
class RunResult:
    verdict: str | None
    abstention_reason: str | None = None


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


def load_run(path: str) -> tuple[str, str, dict[str, RunResult]]:
    """Return (set_name, impl_id, {vector name -> result}) for a run file."""
    with open(path, encoding="utf-8") as fh:
        run = json.load(fh)
    for field in ("set", "impl", "results"):
        if field not in run:
            raise SystemExit(f"ERROR: {path}: run file missing '{field}'")
    for field in ("set", "impl"):
        if not isinstance(run[field], str) or not run[field].strip():
            raise SystemExit(
                f"ERROR: {path}: run file '{field}' must be a non-empty string"
            )
    if not isinstance(run["results"], list):
        raise SystemExit(f"ERROR: {path}: run file 'results' must be an array")
    results: dict[str, RunResult] = {}
    for i, res in enumerate(run["results"]):
        if not isinstance(res, dict):
            raise SystemExit(f"ERROR: {path}: results[{i}] must be an object")
        name = res.get("name") or res.get("id")
        if not name:
            raise SystemExit(f"ERROR: {path}: results[{i}] needs 'name'")
        if name in results:
            raise SystemExit(f"ERROR: {path}: duplicate result for '{name}'")
        status = res.get("status", "evaluated")
        if status == "abstain":
            reason = res.get("reason")
            if res.get("verdict") is not None:
                raise SystemExit(
                    f"ERROR: {path}: abstention '{name}' must not carry a verdict")
            if not isinstance(reason, str) or not reason.strip():
                raise SystemExit(
                    f"ERROR: {path}: abstention '{name}' needs a non-empty reason")
            results[name] = RunResult(None, reason.strip())
        elif status == "evaluated":
            verdict = res.get("verdict")
            if verdict is None:
                raise SystemExit(
                    f"ERROR: {path}: evaluated result '{name}' needs 'verdict'")
            results[name] = RunResult(verdict)
        else:
            raise SystemExit(
                f"ERROR: {path}: result '{name}' has unknown status '{status}' "
                "(expected 'evaluated' or 'abstain')")
    return run["set"], run["impl"], results


def main() -> int:
    run_paths = [a for a in sys.argv[1:] if not a.startswith("-")]
    if not run_paths:
        print(__doc__.split("Usage:")[1].split("Each run")[0].strip(), file=sys.stderr)
        return 2

    runs = [load_run(p) for p in run_paths]
    problems: list[str] = []
    abstentions: list[str] = []
    incomplete: list[str] = []

    # 1. Every run vs the set's expected verdicts.
    for (set_name, impl, results), path in zip(runs, run_paths):
        expected = load_expected(set_name)
        missing = sorted(expected.keys() - results.keys())
        unknown = sorted(results.keys() - expected.keys())
        for case in missing:
            problems.append(f"{impl} vs {set_name}: no result for case '{case}'")
        for case in unknown:
            problems.append(f"{impl} vs {set_name}: result for unknown case '{case}'")
        agree = 0
        evaluated = 0
        abstained = 0
        for case in sorted(expected.keys() & results.keys()):
            result = results[case]
            if result.verdict is None:
                abstained += 1
                abstentions.append(
                    f"{impl} vs {set_name}: '{case}' — {result.abstention_reason}")
                continue
            evaluated += 1
            if result.verdict == expected[case]:
                agree += 1
            else:
                problems.append(
                    f"{impl} vs {set_name}: '{case}' — expected "
                    f"'{expected[case]}', got '{result.verdict}'")
        suffix = f"; {abstained} abstain" if abstained else ""
        print(
            f"{impl} vs expected ({set_name}): {agree}/{evaluated} evaluated agree"
            f" ({len(expected)} expected{suffix})"
        )

    # 2. Run vs run, per shared set (the cross-impl convergence check).
    by_set: dict[str, list[tuple[str, dict[str, RunResult]]]] = {}
    for set_name, impl, results in runs:
        by_set.setdefault(set_name, []).append((impl, results))
    for set_name, entries in by_set.items():
        distinct_impls = {impl for impl, _ in entries}
        if len(distinct_impls) < 2:
            incomplete.append(
                f"{set_name}: needs at least two distinct implementation ids; "
                f"got {len(distinct_impls)}")
        for i in range(len(entries)):
            for j in range(i + 1, len(entries)):
                (impl_a, va), (impl_b, vb) = entries[i], entries[j]
                shared = sorted(va.keys() & vb.keys())
                comparable = [
                    case for case in shared
                    if va[case].verdict is not None and vb[case].verdict is not None
                ]
                diffs = [
                    case for case in comparable
                    if va[case].verdict != vb[case].verdict
                ]
                for case in diffs:
                    problems.append(
                        f"{impl_a} vs {impl_b} ({set_name}): '{case}' — "
                        f"'{va[case].verdict}' vs '{vb[case].verdict}'")
                pair_abstained = len(shared) - len(comparable)
                suffix = f"; {pair_abstained} not comparable" if pair_abstained else ""
                print(
                    f"{impl_a} vs {impl_b} ({set_name}): "
                    f"{len(comparable) - len(diffs)}/{len(comparable)} comparable agree"
                    f"{suffix}"
                )

    if abstentions:
        print(file=sys.stderr)
        for item in abstentions:
            print(f"ABSTENTION: {item}", file=sys.stderr)

    if problems:
        print(file=sys.stderr)
        for p in problems:
            print(f"DIVERGENCE: {p}", file=sys.stderr)
        print(
            f"\ncross-run FAILED ({len(problems)} divergence(s), "
            f"{len(abstentions)} abstention(s))",
            file=sys.stderr,
        )
        return 1
    if abstentions or incomplete:
        if incomplete:
            print(file=sys.stderr)
            for item in incomplete:
                print(f"INCOMPLETE: {item}", file=sys.stderr)
        print(
            f"\ncross-run INCOMPLETE ({len(abstentions)} abstention(s)); "
            "full-set convergence was not established",
            file=sys.stderr,
        )
        return 1
    print("\ncross-run CONVERGED — all runs agree with the expected verdicts "
          "and with each other across at least two distinct implementation ids")
    return 0


if __name__ == "__main__":
    sys.exit(main())
