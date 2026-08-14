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
from generate_atomic_work_vectors import (  # noqa: E402
    ATOMIC_RULES,
    BOUNDARY_APPLICABLE_RULES,
    POLARITY_NOT_APPLICABLE,
    SET_SPECS,
)


EXPECTED_RULES = ATOMIC_RULES
RULE_PATTERN = re.compile(r"^(AW|AWP|AWS|AWB)-([1-9][0-9]*)$")


def rule_sort_key(rule: str) -> tuple[str, int]:
    family, number = rule.split("-")
    return family, int(number)


def coverage_summary(paths: set[Path] | None = None) -> dict[str, str]:
    """Return gated global positive/negative/boundary marks for every rule.

    ``P`` means an acceptance case names the rule, ``N`` means a rejection
    case names it, and ``B`` means ``boundaryRuleRefs`` attributes a genuine
    edge to the rule. ``X`` is an explicitly justified non-applicable cell;
    a dash is an uncovered applicable polarity and therefore a gate failure.
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
            if vector.get("caseClass") == "acceptance":
                for rule in vector["ruleRefs"]:
                    if rule in observed:
                        observed[rule].add("P")
            elif vector.get("caseClass") == "rejection":
                for rule in vector["ruleRefs"]:
                    if rule in observed:
                        observed[rule].add("N")
            for rule in vector.get("boundaryRuleRefs", []):
                if rule in observed:
                    observed[rule].add("B")
    not_applicable = {
        "P": set(POLARITY_NOT_APPLICABLE["P"]),
        "N": set(POLARITY_NOT_APPLICABLE["N"]),
        "B": EXPECTED_RULES - BOUNDARY_APPLICABLE_RULES,
    }
    return {
        rule: "".join(
            mark if mark in observed[rule]
            else "X" if rule in not_applicable[mark]
            else "-"
            for mark in "PNB"
        )
        for rule in sorted(EXPECTED_RULES, key=rule_sort_key)
    }


def coverage_report(paths: set[Path] | None = None) -> dict[str, Any]:
    by_rule = coverage_summary(paths)
    missing = {
        mark: [
            rule for rule, marks in by_rule.items()
            if marks[index] == "-"
        ]
        for index, mark in enumerate("PNB")
    }
    not_applicable_rules = {
        "P": set(POLARITY_NOT_APPLICABLE["P"]),
        "N": set(POLARITY_NOT_APPLICABLE["N"]),
        "B": EXPECTED_RULES - BOUNDARY_APPLICABLE_RULES,
    }
    applicability_conflicts = {
        mark: [
            rule for rule in sorted(rules, key=rule_sort_key)
            if by_rule[rule][index] == mark
        ]
        for index, (mark, rules) in enumerate(not_applicable_rules.items())
    }
    return {
        "classification": "candidate-complete-applicable-polarity",
        "completeApplicablePolarity": (
            not any(missing.values()) and not any(applicability_conflicts.values())
        ),
        "nonGatingPolarityGaps": False,
        "legend": {
            "P": "acceptance", "N": "rejection", "B": "boundary",
            "X": "not applicable with explicit rationale",
            "-": "missing applicable fixture",
        },
        "byRule": by_rule,
        "missing": missing,
        "applicabilityConflicts": applicability_conflicts,
        "notApplicable": {
            mark: [
                rule for rule, marks in by_rule.items()
                if marks[index] == "X"
            ]
            for index, mark in enumerate("PNB")
        },
        "notApplicableReasons": {
            "P": dict(sorted(POLARITY_NOT_APPLICABLE["P"].items())),
            "N": dict(sorted(POLARITY_NOT_APPLICABLE["N"].items())),
            "B": {
                "reason": "The rule has no quantitative, cardinality, lifecycle, discriminator, proof-availability, or version/profile-scope edge in Atomic v0.1.",
                "rules": sorted(
                    EXPECTED_RULES - BOUNDARY_APPLICABLE_RULES,
                    key=rule_sort_key,
                ),
            },
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
    if not isinstance(coverage, dict) or coverage.get("classification") != "candidate-complete-applicable-polarity":
        _error(
            errors, location,
            "coverage must explicitly declare candidate-complete-applicable-polarity",
        )
    elif coverage.get("applicabilityProfile") != "atomic-v0.1-explicit":
        _error(errors, location, "coverage applicabilityProfile is not atomic-v0.1-explicit")
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
        boundary_rules = vector.get("boundaryRuleRefs")
        if vector.get("boundary") is True:
            if not isinstance(boundary_rules, list) or not boundary_rules:
                _error(errors, where, "boundary requires non-empty boundaryRuleRefs")
            else:
                if len(boundary_rules) != len(set(boundary_rules)):
                    _error(errors, where, "duplicate boundaryRuleRef")
                for rule in boundary_rules:
                    if not isinstance(rule, str) or rule not in EXPECTED_RULES:
                        _error(errors, where, f"invalid boundaryRuleRef {rule!r}")
                    elif not isinstance(rules, list) or rule not in rules:
                        _error(errors, where, f"boundaryRuleRef {rule} is not in ruleRefs")
                    elif rule not in BOUNDARY_APPLICABLE_RULES:
                        _error(errors, where, f"rule {rule} has no applicable Atomic v0.1 boundary")
        elif boundary_rules is not None:
            _error(errors, where, "boundaryRuleRefs requires boundary: true")
        if vector.get("caseClass") in {"acceptance", "rejection"} and isinstance(rules, list):
            polarity[vector["caseClass"]].update(r for r in rules if r in EXPECTED_RULES)
        if isinstance(boundary_rules, list):
            polarity["boundary"].update(
                r for r in boundary_rules if r in EXPECTED_RULES
            )
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
    report = coverage_report(expected_paths & actual_paths)
    for mark, rules in report["missing"].items():
        if rules:
            errors.append(
                f"applicable {mark} polarity coverage missing: " + ", ".join(rules)
            )
    for mark, rules in report["applicabilityConflicts"].items():
        if rules:
            errors.append(
                f"observed {mark} polarity marked not applicable: "
                + ", ".join(rules)
            )
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
        f"{len(EXPECTED_RULES)} rules with complete applicable P/N/B coverage; "
        "hashes/signatures/semantics verified)"
    )
    print("Atomic Work applicable P/N/B coverage (X = justified not applicable):")
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
