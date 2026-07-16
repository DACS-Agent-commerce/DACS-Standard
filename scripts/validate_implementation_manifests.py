#!/usr/bin/env python3
"""Validate DACS §14.10 ImplementationManifest reports without dependencies."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIR = ROOT / "conformance" / "implementation-manifests"
SCHEMA = ROOT / "conformance" / "implementation-manifest.schema.json"

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ROLES = {"buyer", "seller", "orchestrator", "verifier", "directory-indexer"}
MODULES = {"CORE", "DACS-1", "DACS-2", "DACS-3", "DACS-4", "DACS-5"}
CAPABILITY_KINDS = {
    "claim-scheme",
    "verification-method",
    "negotiation-pattern",
    "payment-phase",
    "payment-rail",
    "delivery-type",
    "substrate-capability",
    "bundle-operation",
    "reputation-operation",
    "directory-operation",
}
SUPPORT_STATUSES = {"implemented", "experimental", "unsupported"}
AVAILABILITY_STATUSES = {
    "live",
    "operator_gated",
    "closed_data",
    "bilateral",
    "mocked",
    "disabled",
    "failed",
}
TEST_STATUSES = {"not_tested", "partial", "passed", "failed"}
CLAIM_RESULTS = {"conformant", "conformance-tested", "implemented", "experimental"}
CLAIM_LEVEL_RESULTS = {
    "full-profile": {"conformant"},
    "module": {"conformant"},
    "role": {"conformant"},
    "capability": {"conformance-tested", "implemented"},
    "experimental": {"experimental"},
}
TOP_LEVEL_REQUIRED = {
    "manifestVersion",
    "generatedAt",
    "implementation",
    "profile",
    "roles",
    "conformanceSuite",
    "claims",
    "capabilities",
    "testRuns",
    "liveTests",
    "deviations",
}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def is_rfc3339(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def check_string_list(
    value: Any,
    label: str,
    errors: list[str],
    *,
    allowed: set[str] | None = None,
    nonempty: bool = False,
) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        errors.append(f"{label} must be an array of non-empty strings")
        return []
    if nonempty and not value:
        errors.append(f"{label} must not be empty")
    if len(value) != len(set(value)):
        errors.append(f"{label} must not contain duplicates")
    if allowed is not None:
        unknown = sorted(set(value) - allowed)
        if unknown:
            errors.append(f"{label} contains unsupported values: {', '.join(unknown)}")
    return value


def require_object(value: Any, label: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return {}
    return value


def require_fields(value: dict[str, Any], fields: set[str], label: str, errors: list[str]) -> None:
    missing = sorted(fields - set(value))
    if missing:
        errors.append(f"{label} missing required fields: {', '.join(missing)}")


def require_nonempty_string(value: dict[str, Any], field: str, label: str, errors: list[str]) -> None:
    if not isinstance(value.get(field), str) or not value.get(field):
        errors.append(f"{label}.{field} must be a non-empty string")


def index_unique(
    items: Any,
    label: str,
    id_field: str,
    errors: list[str],
) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list):
        errors.append(f"{label} must be an array")
        return {}
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            errors.append(f"{label}[{index}] must be an object")
            continue
        identifier = item.get(id_field)
        if not isinstance(identifier, str) or not identifier:
            errors.append(f"{label}[{index}].{id_field} must be a non-empty string")
            continue
        if identifier in result:
            errors.append(f"{label} contains duplicate {id_field} {identifier!r}")
            continue
        result[identifier] = item
    return result


def validate_schema_file(errors: list[str]) -> None:
    try:
        schema = read_json(SCHEMA)
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"schema is unreadable: {exc}")
        return
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append("schema must declare JSON Schema draft 2020-12")
    if schema.get("properties", {}).get("manifestVersion", {}).get("const") != "1":
        errors.append("schema must pin manifestVersion to \"1\"")
    if not TOP_LEVEL_REQUIRED <= set(schema.get("required", [])):
        errors.append("schema required fields do not cover the §14.10 top-level shape")


def resolve_suite_manifest(
    suite: dict[str, Any],
    label: str,
    root: Path,
    errors: list[str],
) -> tuple[Path | None, set[str]]:
    require_fields(suite, {"repository", "commit", "manifestPath", "manifestSha256"}, label, errors)
    require_nonempty_string(suite, "repository", label, errors)
    if not HEX40.fullmatch(str(suite.get("commit", ""))):
        errors.append(f"{label}.commit must be 40 lower-case hex")
    if not HEX64.fullmatch(str(suite.get("manifestSha256", ""))):
        errors.append(f"{label}.manifestSha256 must be 64 lower-case hex")
    raw_path = suite.get("manifestPath")
    if not isinstance(raw_path, str) or not raw_path:
        errors.append(f"{label}.manifestPath must be a non-empty relative path")
        return None, set()
    rel = Path(raw_path)
    if rel.is_absolute() or ".." in rel.parts:
        errors.append(f"{label}.manifestPath must stay within the repository")
        return None, set()
    path = root / rel
    if not path.is_file():
        errors.append(f"{label}.manifestPath does not exist: {raw_path}")
        return None, set()
    actual_hash = sha256_file(path)
    if suite.get("manifestSha256") != actual_hash:
        errors.append(
            f"{label}.manifestSha256 mismatch: declared {suite.get('manifestSha256')}, actual {actual_hash}"
        )
    try:
        manifest = read_json(path)
    except json.JSONDecodeError as exc:
        errors.append(f"{label}.manifestPath is invalid JSON: {exc}")
        return path, set()
    cases = manifest.get("cases")
    if not isinstance(cases, list):
        errors.append(f"{label}.manifestPath must contain cases[]")
        return path, set()
    case_ids = {case.get("id") for case in cases if isinstance(case, dict) and isinstance(case.get("id"), str)}
    return path, case_ids


def validate_manifest(data: Any, *, root: Path = ROOT, source: str = "manifest") -> list[str]:
    errors: list[str] = []
    manifest = require_object(data, source, errors)
    if not manifest:
        return errors
    require_fields(manifest, TOP_LEVEL_REQUIRED, source, errors)
    if manifest.get("manifestVersion") != "1":
        errors.append(f"{source}.manifestVersion must be \"1\"")
    if not is_rfc3339(manifest.get("generatedAt")):
        errors.append(f"{source}.generatedAt must be an RFC 3339 timestamp with a timezone")

    implementation = require_object(manifest.get("implementation"), f"{source}.implementation", errors)
    require_fields(implementation, {"name", "version", "repository", "commit"}, f"{source}.implementation", errors)
    for field in ("name", "version", "repository"):
        require_nonempty_string(implementation, field, f"{source}.implementation", errors)
    if not HEX40.fullmatch(str(implementation.get("commit", ""))):
        errors.append(f"{source}.implementation.commit must be 40 lower-case hex")

    profile = require_object(manifest.get("profile"), f"{source}.profile", errors)
    require_fields(profile, {"id", "repository", "commit", "documents"}, f"{source}.profile", errors)
    if profile.get("id") != "DACS-v0.1":
        errors.append(f"{source}.profile.id must be DACS-v0.1")
    require_nonempty_string(profile, "repository", f"{source}.profile", errors)
    if not HEX40.fullmatch(str(profile.get("commit", ""))):
        errors.append(f"{source}.profile.commit must be 40 lower-case hex")
    documents = require_object(profile.get("documents"), f"{source}.profile.documents", errors)
    if set(documents) != MODULES:
        errors.append(f"{source}.profile.documents must pin exactly {', '.join(sorted(MODULES))}")
    for module, version in documents.items():
        if not isinstance(version, str) or not version:
            errors.append(f"{source}.profile.documents.{module} must be a non-empty version")

    roles = set(
        check_string_list(manifest.get("roles"), f"{source}.roles", errors, allowed=ROLES, nonempty=True)
    )
    suite = require_object(manifest.get("conformanceSuite"), f"{source}.conformanceSuite", errors)
    _, case_ids = resolve_suite_manifest(suite, f"{source}.conformanceSuite", root, errors)

    claims = index_unique(manifest.get("claims"), f"{source}.claims", "id", errors)
    capabilities = index_unique(manifest.get("capabilities"), f"{source}.capabilities", "ref", errors)
    test_runs = index_unique(manifest.get("testRuns"), f"{source}.testRuns", "id", errors)
    live_tests = index_unique(manifest.get("liveTests"), f"{source}.liveTests", "id", errors)
    deviations = index_unique(manifest.get("deviations"), f"{source}.deviations", "id", errors)

    for run_id, run in test_runs.items():
        label = f"{source}.testRuns[{run_id}]"
        require_fields(run, {"id", "result", "caseIds", "command"}, label, errors)
        if run.get("result") not in {"pass", "fail"}:
            errors.append(f"{label}.result must be pass or fail")
        run_cases = check_string_list(run.get("caseIds"), f"{label}.caseIds", errors, nonempty=True)
        unknown_cases = sorted(set(run_cases) - case_ids)
        if unknown_cases:
            errors.append(f"{label}.caseIds contains unknown pinned cases: {', '.join(unknown_cases)}")
        if not isinstance(run.get("command"), str) or not run.get("command"):
            errors.append(f"{label}.command must be a non-empty string")

    for cap_ref, capability in capabilities.items():
        label = f"{source}.capabilities[{cap_ref}]"
        require_fields(
            capability,
            {"ref", "kind", "id", "modules", "roles", "supportStatus", "testStatus", "evidenceRefs"},
            label,
            errors,
        )
        if capability.get("kind") not in CAPABILITY_KINDS:
            errors.append(f"{label}.kind is unsupported")
        cap_id = capability.get("id")
        if not isinstance(cap_id, str) or not cap_id:
            errors.append(f"{label}.id must be a non-empty string")
        cap_modules = set(
            check_string_list(capability.get("modules"), f"{label}.modules", errors, allowed=MODULES, nonempty=True)
        )
        cap_roles = set(
            check_string_list(capability.get("roles"), f"{label}.roles", errors, allowed=ROLES, nonempty=True)
        )
        if not cap_roles <= roles:
            errors.append(f"{label}.roles must be declared in top-level roles")
        if not cap_modules <= MODULES:
            errors.append(f"{label}.modules contains an unsupported module")
        support = capability.get("supportStatus")
        test_status = capability.get("testStatus")
        if support not in SUPPORT_STATUSES:
            errors.append(f"{label}.supportStatus is unsupported")
        if test_status not in TEST_STATUSES:
            errors.append(f"{label}.testStatus is unsupported")
        if "availability" in capability and capability.get("availability") not in AVAILABILITY_STATUSES:
            errors.append(f"{label}.availability is unsupported")
        evidence = check_string_list(capability.get("evidenceRefs"), f"{label}.evidenceRefs", errors)
        missing_evidence = sorted(set(evidence) - set(test_runs))
        if missing_evidence:
            errors.append(f"{label}.evidenceRefs contains unknown deterministic runs: {', '.join(missing_evidence)}")
        if support == "experimental" and (not isinstance(cap_id, str) or not cap_id.startswith("x-")):
            errors.append(f"{label} experimental id must start with x-")
        if support == "unsupported":
            if test_status != "not_tested" or evidence:
                errors.append(f"{label} unsupported capability must be not_tested with no evidence")
            if "availability" in capability:
                errors.append(f"{label} unsupported capability must omit availability")
        if test_status == "not_tested" and evidence:
            errors.append(f"{label} not_tested capability must not reference evidence")
        if test_status in {"partial", "passed", "failed"} and not evidence:
            errors.append(f"{label} {test_status} capability must reference deterministic evidence")
        evidence_results = {test_runs[ref].get("result") for ref in evidence if ref in test_runs}
        if test_status == "passed" and evidence_results != {"pass"}:
            errors.append(f"{label} passed capability must reference only passing deterministic runs")
        if test_status == "failed" and "fail" not in evidence_results:
            errors.append(f"{label} failed capability must reference a failing deterministic run")

    for claim_id, claim in claims.items():
        label = f"{source}.claims[{claim_id}]"
        require_fields(
            claim,
            {"id", "level", "result", "roles", "modules", "capabilityRefs", "ruleRefs", "evidenceRefs"},
            label,
            errors,
        )
        level = claim.get("level")
        result = claim.get("result")
        if result not in CLAIM_RESULTS:
            errors.append(f"{label}.result is unsupported")
        if level not in CLAIM_LEVEL_RESULTS:
            errors.append(f"{label}.level is unsupported")
        elif result not in CLAIM_LEVEL_RESULTS[level]:
            errors.append(f"{label} level {level!r} cannot use result {result!r}")
        claim_roles = set(
            check_string_list(claim.get("roles"), f"{label}.roles", errors, allowed=ROLES, nonempty=True)
        )
        claim_modules = set(
            check_string_list(claim.get("modules"), f"{label}.modules", errors, allowed=MODULES, nonempty=True)
        )
        cap_refs = check_string_list(claim.get("capabilityRefs"), f"{label}.capabilityRefs", errors, nonempty=True)
        check_string_list(claim.get("ruleRefs"), f"{label}.ruleRefs", errors, nonempty=True)
        evidence_refs = check_string_list(claim.get("evidenceRefs"), f"{label}.evidenceRefs", errors)
        if not claim_roles <= roles:
            errors.append(f"{label}.roles must be declared in top-level roles")
        unknown_caps = sorted(set(cap_refs) - set(capabilities))
        if unknown_caps:
            errors.append(f"{label}.capabilityRefs contains unknown refs: {', '.join(unknown_caps)}")
        unknown_runs = sorted(set(evidence_refs) - set(test_runs))
        if unknown_runs:
            errors.append(f"{label}.evidenceRefs contains unknown deterministic runs: {', '.join(unknown_runs)}")
        if level == "full-profile" and claim_modules != MODULES:
            errors.append(f"{label} full-profile claim must cover every pinned document")
        for cap_ref in set(cap_refs) & set(capabilities):
            capability = capabilities[cap_ref]
            if not set(capability.get("roles", [])) <= claim_roles:
                errors.append(f"{label} does not declare every role used by capability {cap_ref!r}")
            if not set(capability.get("modules", [])) <= claim_modules:
                errors.append(f"{label} does not declare every module used by capability {cap_ref!r}")
        if result in {"conformant", "conformance-tested"}:
            if not evidence_refs:
                errors.append(f"{label} passing claim must reference deterministic evidence")
            if any(test_runs[ref].get("result") != "pass" for ref in evidence_refs if ref in test_runs):
                errors.append(f"{label} passing claim must reference only passing deterministic runs")
            for cap_ref in set(cap_refs) & set(capabilities):
                capability = capabilities[cap_ref]
                if capability.get("supportStatus") != "implemented":
                    errors.append(f"{label} passing claim cannot include non-implemented capability {cap_ref!r}")
                if capability.get("testStatus") != "passed":
                    errors.append(f"{label} passing claim requires passed capability {cap_ref!r}")
                missing_cap_evidence = sorted(set(capability.get("evidenceRefs", [])) - set(evidence_refs))
                if missing_cap_evidence:
                    errors.append(
                        f"{label} evidence does not cover capability {cap_ref!r}: "
                        f"{', '.join(missing_cap_evidence)}"
                    )
        if result == "implemented":
            for cap_ref in set(cap_refs) & set(capabilities):
                if capabilities[cap_ref].get("supportStatus") != "implemented":
                    errors.append(f"{label} implemented claim requires implemented capability {cap_ref!r}")
        if level == "experimental":
            for cap_ref in set(cap_refs) & set(capabilities):
                if capabilities[cap_ref].get("supportStatus") != "experimental":
                    errors.append(f"{label} experimental claim requires experimental capability {cap_ref!r}")

    for live_id, live in live_tests.items():
        label = f"{source}.liveTests[{live_id}]"
        require_fields(live, {"id", "capabilityRefs", "result", "executedAt", "evidence"}, label, errors)
        cap_refs = check_string_list(live.get("capabilityRefs"), f"{label}.capabilityRefs", errors, nonempty=True)
        unknown_caps = sorted(set(cap_refs) - set(capabilities))
        if unknown_caps:
            errors.append(f"{label}.capabilityRefs contains unknown refs: {', '.join(unknown_caps)}")
        if live.get("result") not in {"pass", "fail", "inconclusive"}:
            errors.append(f"{label}.result is unsupported")
        if not is_rfc3339(live.get("executedAt")):
            errors.append(f"{label}.executedAt must be an RFC 3339 timestamp with a timezone")
        if not isinstance(live.get("evidence"), str) or not live.get("evidence"):
            errors.append(f"{label}.evidence must be a non-empty string")

    open_nonconforming: set[str] = set()
    for deviation_id, deviation in deviations.items():
        label = f"{source}.deviations[{deviation_id}]"
        require_fields(
            deviation,
            {"id", "capabilityRefs", "ruleRefs", "status", "effect", "description"},
            label,
            errors,
        )
        cap_refs = check_string_list(deviation.get("capabilityRefs"), f"{label}.capabilityRefs", errors, nonempty=True)
        check_string_list(deviation.get("ruleRefs"), f"{label}.ruleRefs", errors, nonempty=True)
        unknown_caps = sorted(set(cap_refs) - set(capabilities))
        if unknown_caps:
            errors.append(f"{label}.capabilityRefs contains unknown refs: {', '.join(unknown_caps)}")
        if deviation.get("status") not in {"open", "resolved"}:
            errors.append(f"{label}.status is unsupported")
        if deviation.get("effect") not in {"nonconforming", "operational"}:
            errors.append(f"{label}.effect is unsupported")
        if not isinstance(deviation.get("description"), str) or not deviation.get("description"):
            errors.append(f"{label}.description must be a non-empty string")
        if deviation.get("status") == "open" and deviation.get("effect") == "nonconforming":
            open_nonconforming.update(cap_refs)

    for claim_id, claim in claims.items():
        if claim.get("result") in {"conformant", "conformance-tested"}:
            affected = sorted(set(claim.get("capabilityRefs", [])) & open_nonconforming)
            if affected:
                errors.append(
                    f"{source}.claims[{claim_id}] passing claim is invalidated by open nonconforming deviations on: {', '.join(affected)}"
                )

    return errors


def default_paths() -> list[Path]:
    return sorted(path for path in DEFAULT_DIR.glob("*.json") if path.is_file())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, help="manifest files; defaults to repository examples")
    args = parser.parse_args(argv)
    paths = args.paths or default_paths()
    schema_errors: list[str] = []
    validate_schema_file(schema_errors)
    all_errors = [f"schema: {error}" for error in schema_errors]
    if not paths:
        all_errors.append("no implementation manifests found")
    for path in paths:
        try:
            data = read_json(path)
        except (OSError, json.JSONDecodeError) as exc:
            all_errors.append(f"{path}: unreadable JSON: {exc}")
            continue
        try:
            source = str(path.relative_to(ROOT))
        except ValueError:
            source = str(path)
        all_errors.extend(validate_manifest(data, root=ROOT, source=source))
    if all_errors:
        for error in all_errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"implementation manifests OK ({len(paths)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
