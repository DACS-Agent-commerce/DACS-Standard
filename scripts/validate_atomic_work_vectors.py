#!/usr/bin/env python3
"""Strict semantic validator for the Atomic DACS Work candidate vectors."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import atomic_work_reference as ref  # noqa: E402
from generate_atomic_work_vectors import SET_SPECS  # noqa: E402


EXPECTED_RULES = {
    *{f"AW-{i}" for i in range(1, 78)},
    *{f"AWP-{i}" for i in range(1, 22)},
    *{f"AWS-{i}" for i in range(1, 30)},
    *{f"AWB-{i}" for i in range(1, 11)},
}
RULE_PATTERN = re.compile(r"^(AW|AWP|AWS|AWB)-([1-9][0-9]*)$")


def rule_sort_key(rule: str) -> tuple[str, int]:
    family, number = rule.split("-")
    return family, int(number)


def coverage_summary(paths: set[Path] | None = None) -> dict[str, str]:
    """Return honest global positive/negative/boundary marks for every rule.

    ``P`` means an acceptance case names the rule, ``N`` means a rejection
    case names it, and ``B`` means a case explicitly marks a genuine boundary.
    A dash is a reported draft gap.  These polarity gaps are deliberately
    non-gating; only absence of a rule ID from the corpus is a coverage error.
    """
    if paths is None:
        paths = {
            ROOT / "conformance" / "vectors" / "security" / f"{name}.json"
            for name in SET_SPECS
        }
    observed = {rule: set() for rule in EXPECTED_RULES}
    for path in sorted(paths):
        try:
            vectors = json.loads(path.read_text(encoding="utf-8")).get("vectors", [])
        except (OSError, json.JSONDecodeError, AttributeError):
            continue
        if not isinstance(vectors, list):
            continue
        for vector in vectors:
            if not isinstance(vector, dict) or not isinstance(vector.get("ruleRefs"), list):
                continue
            marks: set[str] = set()
            if vector.get("caseClass") == "acceptance":
                marks.add("P")
            elif vector.get("caseClass") == "rejection":
                marks.add("N")
            if vector.get("boundary") is True:
                marks.add("B")
            for rule in vector["ruleRefs"]:
                if rule in observed:
                    observed[rule].update(marks)
    return {
        rule: "".join(mark if mark in observed[rule] else "-" for mark in "PNB")
        for rule in sorted(EXPECTED_RULES, key=rule_sort_key)
    }


def coverage_report(paths: set[Path] | None = None) -> dict[str, Any]:
    by_rule = coverage_summary(paths)
    return {
        "classification": "candidate-partial-polarity",
        "nonGatingPolarityGaps": True,
        "legend": {"P": "acceptance", "N": "rejection", "B": "boundary", "-": "missing"},
        "byRule": by_rule,
        "missing": {
            "P": [rule for rule, marks in by_rule.items() if marks[0] == "-"],
            "N": [rule for rule, marks in by_rule.items() if marks[1] == "-"],
            "B": [rule for rule, marks in by_rule.items() if marks[2] == "-"],
        },
    }


def _error(errors: list[str], location: str, message: str) -> None:
    errors.append(f"{location}: {message}")


def validate_set(path: Path) -> tuple[list[str], set[str], int]:
    errors: list[str] = []
    covered: set[str] = set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{path}: cannot read JSON: {exc}"], covered, 0
    location = path.relative_to(ROOT).as_posix()
    stem = path.stem
    if data.get("set") != stem:
        _error(errors, location, f"set must equal filename stem {stem!r}")
    if data.get("spec") != SET_SPECS.get(stem):
        _error(errors, location, "spec declaration differs from generator registry")
    vectors = data.get("vectors")
    if not isinstance(vectors, list):
        _error(errors, location, "vectors is not an array")
        return errors, covered, 0
    if data.get("count") != len(vectors):
        _error(errors, location, f"count {data.get('count')!r} != {len(vectors)}")
    coverage = data.get("coverage")
    if not isinstance(coverage, dict) or coverage.get("classification") != "candidate-partial-polarity":
        _error(errors, location, "coverage must explicitly declare candidate-partial-polarity")
    try:
        computed_hash = ref.vector_hash(vectors)
    except (ValueError, TypeError) as exc:
        _error(errors, location, f"vectors are not JCS-canonicalizable: {exc}")
        computed_hash = None
    if data.get("hash") != computed_hash:
        _error(errors, location, f"hash {data.get('hash')!r} != JCS SHA-256 {computed_hash!r}")
    public_keys = data.get("publicKeys")
    seeds = data.get("seeds")
    if not isinstance(public_keys, dict) or not isinstance(seeds, dict):
        _error(errors, location, "publicKeys/seeds test provenance missing")
    else:
        for role, seed_hex in seeds.items():
            claim = f"did:dacs:test:{role}"
            try:
                derived = ref.b64u(ref.ed25519_public_key(bytes.fromhex(seed_hex)))
            except (ValueError, TypeError) as exc:
                _error(errors, location, f"bad {role} seed: {exc}")
                continue
            if public_keys.get(claim) != derived:
                _error(errors, location, f"{claim} public key does not derive from disclosed seed")
    names: set[str] = set()
    polarity = {"acceptance": set(), "rejection": set(), "boundary": set()}
    for index, vector in enumerate(vectors):
        where = f"{location}:vectors[{index}]"
        if not isinstance(vector, dict):
            _error(errors, where, "vector is not an object")
            continue
        name = vector.get("name")
        if not isinstance(name, str) or not name:
            _error(errors, where, "name missing")
        elif name in names:
            _error(errors, where, f"duplicate name {name!r}")
        else:
            names.add(name)
        rules = vector.get("ruleRefs")
        if not isinstance(rules, list) or not rules:
            _error(errors, where, "ruleRefs must be a non-empty array")
        else:
            if len(rules) != len(set(rules)):
                _error(errors, where, "duplicate ruleRef")
            for rule in rules:
                if not isinstance(rule, str) or not RULE_PATTERN.fullmatch(rule):
                    _error(errors, where, f"invalid ruleRef {rule!r}")
                elif rule not in EXPECTED_RULES:
                    _error(errors, where, f"out-of-range ruleRef {rule}")
                else:
                    covered.add(rule)
        expected = vector.get("expected")
        if expected not in ref.VERDICTS:
            _error(errors, where, f"unknown expected verdict {expected!r}")
        expected_case_class = {
            "pass": "acceptance", "fail": "rejection",
            "indeterminate": "indeterminate", "error": "malformed",
        }.get(expected)
        if vector.get("caseClass") != expected_case_class:
            _error(
                errors, where,
                f"caseClass {vector.get('caseClass')!r} does not match verdict class {expected_case_class!r}",
            )
        if "boundary" in vector and vector["boundary"] is not True:
            _error(errors, where, "boundary marker must be boolean true when present")
        if vector.get("caseClass") in {"acceptance", "rejection"} and isinstance(rules, list):
            polarity[vector["caseClass"]].update(r for r in rules if r in EXPECTED_RULES)
        if vector.get("boundary") is True and isinstance(rules, list):
            polarity["boundary"].update(r for r in rules if r in EXPECTED_RULES)
        if not isinstance(vector.get("reason"), str) or not vector["reason"]:
            _error(errors, where, "reason missing")
        if not isinstance(vector.get("input"), dict):
            _error(errors, where, "input is not an object")
            continue
        actual, diagnostic = ref.evaluate_vector(vector)
        if actual != expected:
            _error(errors, where, f"expected {expected}, evaluator returned {actual}: {diagnostic}")
    if isinstance(coverage, dict):
        for label, field in (
            ("acceptance", "acceptanceRuleCount"),
            ("rejection", "rejectionRuleCount"),
            ("boundary", "boundaryRuleCount"),
        ):
            if coverage.get(field) != len(polarity[label]):
                _error(errors, location, f"{field} does not match explicit vector metadata")
    return errors, covered, len(vectors)


def validate_all() -> tuple[list[str], int, int]:
    errors: list[str] = []
    covered: set[str] = set()
    total = 0
    expected_paths = {ROOT / "conformance" / "vectors" / "security" / f"{name}.json" for name in SET_SPECS}
    actual_paths = set((ROOT / "conformance" / "vectors" / "security").glob("atomic-work-*.json"))
    for missing in sorted(expected_paths - actual_paths):
        _error(errors, missing.relative_to(ROOT).as_posix(), "required set missing")
    for extra in sorted(actual_paths - expected_paths):
        _error(errors, extra.relative_to(ROOT).as_posix(), "unregistered Atomic Work set")
    for path in sorted(expected_paths & actual_paths):
        set_errors, set_covered, count = validate_set(path)
        errors.extend(set_errors)
        covered.update(set_covered)
        total += count
    missing_rules = sorted(EXPECTED_RULES - covered, key=rule_sort_key)
    if missing_rules:
        errors.append("rule coverage missing: " + ", ".join(missing_rules))
    return errors, len(actual_paths), total


def main() -> int:
    errors, set_count, total = validate_all()
    if errors:
        for message in errors:
            print(f"ERROR: {message}", file=sys.stderr)
        print(f"Atomic Work vector validation FAILED ({len(errors)} errors)", file=sys.stderr)
        return 1
    report = coverage_report()
    print(
        f"Atomic Work vectors OK ({set_count} sets, {total} vectors; "
        f"{len(EXPECTED_RULES)} rules covered; hashes/signatures/semantics verified)"
    )
    print("Atomic Work draft P/N/B coverage (polarity gaps are non-gating):")
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
