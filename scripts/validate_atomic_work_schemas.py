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
        "atomic-work-capability-v1.schema.json",
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

    capability_vector = named(
        "atomic-work-identity-v0.1", "aw-capability-authenticated"
    )
    identity = named("atomic-work-identity-v0.1", "aw-canonical-intent-and-id")
    authorization = named("atomic-work-authorization-v0.1", "aw-auth-complete-envelope")
    execution = named("atomic-work-execution-recovery-v0.1", "aw-receipt-complete-and-final")
    attempt = named("atomic-work-execution-recovery-v0.1", "aw-attempt-byte-identity")
    settlement = named("atomic-work-settlement-slot-v0.1", "aws-final-work-receipt-bound")
    # Materialize a mutable representative of the normal-class arm. During a
    # staged generator edit this also keeps schema checks independent of when
    # the generated corpus is rewritten.
    attempt_fixture = deepcopy(attempt["input"]["attempts"][0])
    attempt_fixture.setdefault("attemptClass", "normal")

    fixtures = (
        (
            "atomic-work-capability-v1.schema.json",
            capability_vector["input"]["capability"],
        ),
        ("atomic-dacs-work-intent-v1.schema.json", identity["input"]["intent"]),
        ("atomic-work-authorization-v1.schema.json", authorization["input"]["authorizations"][0]),
        ("atomic-work-attempt-v1.schema.json", attempt_fixture),
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

    capability = capability_vector["input"]["capability"]
    missing_validator_set = deepcopy(capability)
    del missing_validator_set["validatorSetId"]
    expect_invalid(
        "atomic-work-capability-v1.schema.json",
        "validator-set identifier is required",
        missing_validator_set,
    )

    empty_fee_rule = deepcopy(capability)
    empty_fee_rule["limits"]["feeRule"] = ""
    expect_invalid(
        "atomic-work-capability-v1.schema.json",
        "fee rule is non-empty",
        empty_fee_rule,
    )

    unsupported_authorization_algorithm = deepcopy(capability)
    unsupported_authorization_algorithm["authorizationAlgorithms"] = [
        "ecdsa-secp256k1"
    ]
    expect_invalid(
        "atomic-work-capability-v1.schema.json",
        "Atomic Work authorization v1 is Ed25519-only",
        unsupported_authorization_algorithm,
    )

    duplicate_profile = deepcopy(capability)
    duplicate_profile["profiles"].append("dacs-purchase-v1")
    expect_invalid(
        "atomic-work-capability-v1.schema.json",
        "capability profile array is canonical and duplicate-free",
        duplicate_profile,
    )

    boolean_limit = deepcopy(capability)
    boolean_limit["limits"]["maxOperations"] = True
    expect_invalid(
        "atomic-work-capability-v1.schema.json",
        "boolean is not a positive integer limit",
        boolean_limit,
    )

    extended_capability = deepcopy(capability)
    extended_capability["unversionedExtension"] = True
    expect_invalid(
        "atomic-work-capability-v1.schema.json",
        "capability v1 has a closed trust-gate shape",
        extended_capability,
    )

    authorization_fixture = authorization["input"]["authorizations"][0]
    unsupported_envelope_algorithm = deepcopy(authorization_fixture)
    unsupported_envelope_algorithm["algorithm"] = "ecdsa-secp256k1"
    expect_invalid(
        "atomic-work-authorization-v1.schema.json",
        "authorization envelope cannot relabel an Ed25519 signature",
        unsupported_envelope_algorithm,
    )

    malformed_authorization_signer = deepcopy(authorization_fixture)
    malformed_authorization_signer["signer"] = "abc"
    expect_invalid(
        "atomic-work-authorization-v1.schema.json",
        "authorization signer is a canonical ClaimReference",
        malformed_authorization_signer,
    )

    malformed_roster_signer = deepcopy(identity["input"]["intent"])
    malformed_roster_signer["roleRoster"][0]["signer"] = "abc"
    expect_invalid(
        "atomic-dacs-work-intent-v1.schema.json",
        "role-roster signer is a canonical ClaimReference",
        malformed_roster_signer,
    )

    missing_gate_mode = deepcopy(identity["input"]["intent"])
    del missing_gate_mode["gateMode"]
    expect_invalid(
        "atomic-dacs-work-intent-v1.schema.json",
        "signed commitment gate mode is required",
        missing_gate_mode,
    )

    unknown_gate_mode = deepcopy(identity["input"]["intent"])
    unknown_gate_mode["gateMode"] = "caller-default"
    expect_invalid(
        "atomic-dacs-work-intent-v1.schema.json",
        "signed commitment gate mode is closed",
        unknown_gate_mode,
    )

    boolean_authorization_phase = deepcopy(authorization_fixture)
    boolean_authorization_phase["phaseIndex"] = True
    expect_invalid(
        "atomic-work-authorization-v1.schema.json",
        "boolean is not an authorization phase index",
        boolean_authorization_phase,
    )

    missing_attempt_class = deepcopy(attempt_fixture)
    del missing_attempt_class["attemptClass"]
    expect_invalid(
        "atomic-work-attempt-v1.schema.json",
        "attempt class discriminator is required",
        missing_attempt_class,
    )

    unknown_attempt_class = deepcopy(attempt_fixture)
    unknown_attempt_class["attemptClass"] = "retry"
    expect_invalid(
        "atomic-work-attempt-v1.schema.json",
        "attempt class discriminator is closed",
        unknown_attempt_class,
    )

    extended_attempt = deepcopy(attempt_fixture)
    extended_attempt["unversionedAction"] = True
    expect_invalid(
        "atomic-work-attempt-v1.schema.json",
        "attempt envelope has a closed class grammar",
        extended_attempt,
    )

    normal_with_replacement = deepcopy(attempt_fixture)
    normal_with_replacement["replacementFor"] = "attempt-prior"
    expect_invalid(
        "atomic-work-attempt-v1.schema.json",
        "normal class cannot carry replacement fields",
        normal_with_replacement,
    )

    normal_without_profile_fee_fields = deepcopy(attempt_fixture)
    del normal_without_profile_fee_fields["nonce"]
    del normal_without_profile_fee_fields["fee"]
    del normal_without_profile_fee_fields["lifecycleEvidence"]
    expect_valid(
        "atomic-work-attempt-v1.schema.json",
        "generic normal arm does not hard-code profile fee fields",
        normal_without_profile_fee_fields,
    )

    observed_with_lifecycle = deepcopy(attempt_fixture)
    observed_with_lifecycle["observation"] = "not-found"
    expect_invalid(
        "atomic-work-attempt-v1.schema.json",
        "authenticated lifecycle evidence and local observation are exclusive",
        observed_with_lifecycle,
    )

    replacement_attempt = deepcopy(attempt_fixture)
    replacement_attempt["attemptClass"] = "replacement"
    replacement_attempt["replacementFor"] = "attempt-prior"
    expect_valid(
        "atomic-work-attempt-v1.schema.json",
        "replacement arm requires its superseded attempt",
        replacement_attempt,
    )

    replacement_without_prior = deepcopy(replacement_attempt)
    del replacement_without_prior["replacementFor"]
    expect_invalid(
        "atomic-work-attempt-v1.schema.json",
        "replacement arm cannot omit its superseded attempt",
        replacement_without_prior,
    )

    replay_attempt = deepcopy(attempt_fixture)
    replay_attempt["attemptClass"] = "replay"
    replay_attempt["fee"] = "0"
    del replay_attempt["nonce"]
    del replay_attempt["lifecycleEvidence"]
    replay_attempt["replayOf"] = "attempt-winner"
    replay_attempt["returnedWinner"] = "attempt-winner"
    replay_attempt["replayEffects"] = {
        "nonceConsumed": False,
        "feeCharged": "0",
    }
    expect_valid(
        "atomic-work-attempt-v1.schema.json",
        "replay arm carries the exact generic replay fields",
        replay_attempt,
    )

    replay_with_profile_fee = deepcopy(replay_attempt)
    replay_with_profile_fee["nonce"] = "profile-selected-replay-nonce"
    replay_with_profile_fee["fee"] = "7"
    replay_with_profile_fee["replayEffects"] = {
        "nonceConsumed": True,
        "feeCharged": "7",
    }
    expect_valid(
        "atomic-work-attempt-v1.schema.json",
        "generic replay arm leaves fee policy to the selected profile",
        replay_with_profile_fee,
    )

    replay_without_fee = deepcopy(replay_attempt)
    del replay_without_fee["fee"]
    expect_valid(
        "atomic-work-attempt-v1.schema.json",
        "generic replay arm does not require a fee field",
        replay_without_fee,
    )

    replay_with_lifecycle = deepcopy(replay_attempt)
    replay_with_lifecycle["lifecycleEvidence"] = deepcopy(
        attempt_fixture["lifecycleEvidence"]
    )
    expect_invalid(
        "atomic-work-attempt-v1.schema.json",
        "replay arm cannot claim another lifecycle inclusion",
        replay_with_lifecycle,
    )

    extended_native_ref = deepcopy(attempt_fixture)
    extended_native_ref["nativeTransactionRef"]["action"] = "submit"
    expect_invalid(
        "atomic-work-attempt-v1.schema.json",
        "native transaction reference is closed",
        extended_native_ref,
    )

    extended_lifecycle = deepcopy(attempt_fixture)
    extended_lifecycle["lifecycleEvidence"]["clientAction"] = "replace"
    expect_valid(
        "atomic-work-attempt-v1.schema.json",
        "lifecycle witness members are selected by the authenticated profile",
        extended_lifecycle,
    )

    empty_lifecycle = deepcopy(attempt_fixture)
    empty_lifecycle["lifecycleEvidence"] = {}
    expect_invalid(
        "atomic-work-attempt-v1.schema.json",
        "profile-selected lifecycle evidence cannot be an empty placeholder",
        empty_lifecycle,
    )

    extended_replay_effects = deepcopy(replay_attempt)
    extended_replay_effects["replayEffects"]["executed"] = False
    expect_invalid(
        "atomic-work-attempt-v1.schema.json",
        "replay effects are exact and closed",
        extended_replay_effects,
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

    malformed_settlement_signer = deepcopy(settlement["input"]["evidence"])
    malformed_settlement_signer["signature"]["signer"] = "abc"
    expect_invalid(
        "atomic-settlement-evidence-v1.schema.json",
        "settlement signer is a canonical ClaimReference",
        malformed_settlement_signer,
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
        f"(11 schemas; 6 representative fixtures; {len(schema_checks)} boundary checks)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
