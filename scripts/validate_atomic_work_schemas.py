#!/usr/bin/env python3
"""Validate Atomic Work JSON Schemas and representative generated fixtures."""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError:
    print("ERROR: jsonschema is required (CI pins jsonschema==4.25.1)", file=sys.stderr)
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "spec" / "schemas"
VECTOR_DIR = ROOT / "conformance" / "vectors" / "security"


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def named(set_name: str, vector_name: str):
    data = load(VECTOR_DIR / f"{set_name}.json")
    return next(vector for vector in data["vectors"] if vector["name"] == vector_name)


def main() -> int:
    schema_names = (
        "atomic-assert-artifact-payload-v1.schema.json",
        "atomic-storage-program-put-payload-v1.schema.json",
        "atomic-payment-slot-cas-payload-v1.schema.json",
        "atomic-native-dem-transfer-payload-v1.schema.json",
        "atomic-assert-work-receipt-payload-v1.schema.json",
        "atomic-dacs-work-intent-v1.schema.json",
        "atomic-work-authorization-v1.schema.json",
        "atomic-work-attempt-v1.schema.json",
        "atomic-work-receipt-v1.schema.json",
        "atomic-settlement-evidence-v1.schema.json",
    )
    schemas = {name: load(SCHEMA_DIR / name) for name in schema_names}
    registry = Registry()
    for name, schema in schemas.items():
        resource = Resource.from_contents(schema)
        registry = registry.with_resource(schema["$id"], resource)
        registry = registry.with_resource(name, resource)

    validators = {}
    for name in schema_names:
        schema = schemas[name]
        Draft202012Validator.check_schema(schema)
        validators[name] = Draft202012Validator(schema, registry=registry)

    identity = named("atomic-work-identity-v0.1", "aw-canonical-intent-and-id")
    authorization = named("atomic-work-authorization-v0.1", "aw-auth-complete-envelope")
    execution = named("atomic-work-execution-recovery-v0.1", "aw-receipt-complete-and-final")
    attempt = named("atomic-work-execution-recovery-v0.1", "aw-attempt-byte-identity")
    settlement = named("atomic-work-settlement-slot-v0.1", "aws-final-work-receipt-bound")

    fixtures = (
        ("atomic-dacs-work-intent-v1.schema.json", identity["input"]["intent"]),
        ("atomic-work-authorization-v1.schema.json", authorization["input"]["authorizations"][0]),
        ("atomic-work-attempt-v1.schema.json", attempt["input"]["attempts"][0]),
        ("atomic-work-receipt-v1.schema.json", execution["input"]["receipt"]),
        ("atomic-settlement-evidence-v1.schema.json", settlement["input"]["evidence"]),
    )
    errors = []
    for schema_name, fixture in fixtures:
        for error in validators[schema_name].iter_errors(fixture):
            location = "/".join(str(part) for part in error.absolute_path) or "<root>"
            errors.append(f"{schema_name}:{location}: {error.message}")

    # Exercise representative boundaries which the positive generated fixtures
    # alone cannot distinguish.  These checks deliberately stay at the JSON
    # Schema layer; cross-artifact and cryptographic predicates are covered by
    # validate_atomic_work_vectors.py.
    schema_checks = []

    def expect_valid(schema_name: str, label: str, fixture) -> None:
        schema_checks.append((schema_name, label, fixture, True))

    def expect_invalid(schema_name: str, label: str, fixture) -> None:
        schema_checks.append((schema_name, label, fixture, False))

    for amount in ("0.5", "1", "1.25"):
        expect_valid(
            "atomic-native-dem-transfer-payload-v1.schema.json",
            f"positive canonical decimal {amount}",
            {"from": "payer", "to": "payee", "asset": "DEM", "amount": amount},
        )
    for amount in ("0", "0.0", "00.5", "1.20", "-0.5", 0.5):
        expect_invalid(
            "atomic-native-dem-transfer-payload-v1.schema.json",
            f"non-positive-or-noncanonical decimal {amount!r}",
            {"from": "payer", "to": "payee", "asset": "DEM", "amount": amount},
        )

    additive_settlement = deepcopy(settlement["input"]["evidence"])
    additive_settlement["operationRef"]["futureSignedMember"] = {"version": 2}
    additive_settlement["workReceiptRef"]["futureSignedMember"] = ["preserve", "me"]
    expect_valid(
        "atomic-settlement-evidence-v1.schema.json",
        "unknown signed reference members are additive",
        additive_settlement,
    )

    legacy_discriminator = deepcopy(settlement["input"]["evidence"])
    legacy_discriminator["evidenceVersion"] = "1"
    expect_invalid(
        "atomic-settlement-evidence-v1.schema.json",
        "legacy and Atomic evidence discriminators cannot coexist",
        legacy_discriminator,
    )

    unsafe_phase_index = deepcopy(settlement["input"]["evidence"])
    unsafe_phase_index["phaseIndex"] = 9007199254740992
    expect_invalid(
        "atomic-settlement-evidence-v1.schema.json",
        "phase index exceeds the JSON safe-integer boundary",
        unsafe_phase_index,
    )

    unknown_transfer_member = {
        "from": "payer",
        "to": "payee",
        "asset": "DEM",
        "amount": "0.5",
        "futureAction": True,
    }
    expect_invalid(
        "atomic-native-dem-transfer-payload-v1.schema.json",
        "action-bearing operation payload grammar is closed",
        unknown_transfer_member,
    )

    for schema_name, label, fixture, should_be_valid in schema_checks:
        validation_errors = list(validators[schema_name].iter_errors(fixture))
        if should_be_valid and validation_errors:
            detail = validation_errors[0]
            location = "/".join(str(part) for part in detail.absolute_path) or "<root>"
            errors.append(f"{schema_name}:{label}:{location}: {detail.message}")
        elif not should_be_valid and not validation_errors:
            errors.append(f"{schema_name}:{label}: unexpectedly accepted invalid fixture")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(
        "Atomic Work schemas OK "
        f"(10 schemas; 5 representative fixtures; {len(schema_checks)} boundary checks)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
