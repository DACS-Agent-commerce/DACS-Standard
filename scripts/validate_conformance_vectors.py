#!/usr/bin/env python3
"""Validate DACS conformance vector files.

This is intentionally stdlib-only so implementers can run it from a clean clone:

    python3 scripts/validate_conformance_vectors.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import specsource  # noqa: E402
DEFAULT_VECTOR_DIR = ROOT / "conformance" / "vectors"
DEFAULT_MANIFEST = ROOT / "conformance" / "MANIFEST.json"
EXPECTED_STAGES = ["DACS-1", "DACS-2", "DACS-3", "DACS-4", "DACS-5"]
MANIFEST_REQUIRED_CASE = {"id", "area", "spec", "summary", "status", "want"}
MANIFEST_STATUSES = {"golden", "candidate"}
REGISTRY_CASE_ID = "sig-registry-closed"
GOLDEN_DECISIONS = {"pass", "fail", "indeterminate", "error"}
REQUIRED_TOP_LEVEL = {
    "vectorId",
    "title",
    "dacsVersion",
    "description",
    "artifacts",
    "expectedResult",
}
REQUIRED_ARTIFACT = {
    "id",
    "stage",
    "kind",
    "specRefs",
    "domainSeparator",
    "artifact",
    "contentHash",
}
DOMAIN_RE = re.compile(r'"(dacs[-a-z0-9]*:v1:)"')


def load_registered_domain_separators(root: Path = ROOT) -> set[str]:
    spec_text = specsource.spec_text(root)
    start_marker = "The v0.x registry of domain separators at this revision is closed:"
    end_marker = "**Payload shape — single-hash vs composite.**"
    start = spec_text.find(start_marker)
    end = spec_text.find(end_marker, start)
    if start == -1 or end == -1:
        return set()
    return set(DOMAIN_RE.findall(spec_text[start:end]))


def canonical_json(value: Any) -> bytes:
    """Return stable JSON bytes approximating RFC 8785 for these vectors.

    The vectors deliberately avoid floats and non-string map keys, so sorted-key JSON
    with compact separators is sufficient for deterministic test fixtures.
    """

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_uri(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def fail(path: Path, message: str) -> str:
    return f"{display_path(path)}: {message}"


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def fixture_exists(manifest_dir: Path, fixture: str) -> bool:
    """Return true when a fixture path exists relative to common vector roots.

    PR #117-style golden outputs use repository-root paths such as
    `conformance/fixtures/example.json`, while smaller local harness tests may use
    manifest-relative paths such as `fixtures/example.json`. Accept both so the
    structural validator composes with either layout without rewriting vectors.
    Absolute paths and traversal outside those roots are rejected.
    """

    fixture_path = Path(fixture)
    if fixture_path.is_absolute():
        return False

    allowed_roots = [manifest_dir, manifest_dir.parent]
    candidates = [manifest_dir / fixture_path, manifest_dir.parent / fixture_path]
    return any(
        candidate.is_file() and is_within(candidate, root)
        for candidate, root in zip(candidates, allowed_roots)
    )


def validate_vector(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [fail(path, f"invalid JSON: {exc}")]

    if not isinstance(data, dict):
        return [fail(path, "top-level value MUST be an object")]

    missing = sorted(REQUIRED_TOP_LEVEL - set(data))
    if missing:
        errors.append(fail(path, f"missing top-level keys: {', '.join(missing)}"))

    if data.get("dacsVersion") != "0.1":
        errors.append(fail(path, "dacsVersion MUST be '0.1' for this vector set"))

    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append(fail(path, "artifacts MUST be a non-empty array"))
        return errors

    stages = []
    artifact_ids = set()
    for idx, artifact in enumerate(artifacts):
        prefix = f"artifact[{idx}]"
        if not isinstance(artifact, dict):
            errors.append(fail(path, f"{prefix} MUST be an object"))
            continue

        missing_artifact = sorted(REQUIRED_ARTIFACT - set(artifact))
        if missing_artifact:
            errors.append(fail(path, f"{prefix} missing keys: {', '.join(missing_artifact)}"))
            continue

        artifact_id = artifact["id"]
        if artifact_id in artifact_ids:
            errors.append(fail(path, f"duplicate artifact id: {artifact_id}"))
        artifact_ids.add(artifact_id)

        stage = artifact["stage"]
        stages.append(stage)
        if stage not in EXPECTED_STAGES:
            errors.append(fail(path, f"{artifact_id}: unknown stage {stage!r}"))

        refs = artifact["specRefs"]
        if not isinstance(refs, list) or not refs or not all(isinstance(ref, str) and ref.startswith("§") for ref in refs):
            errors.append(fail(path, f"{artifact_id}: specRefs MUST be non-empty § references"))

        separator = artifact["domainSeparator"]
        registry = load_registered_domain_separators(ROOT)
        if not isinstance(separator, str) or not separator.endswith(":v1:"):
            errors.append(fail(path, f"{artifact_id}: domainSeparator SHOULD end with ':v1:'"))
        elif registry and separator not in registry:
            errors.append(fail(path, f"{artifact_id}: domainSeparator is not registered in §7.7: {separator}"))

        expected_hash = sha256_uri(artifact["artifact"])
        if artifact["contentHash"] != expected_hash:
            errors.append(
                fail(
                    path,
                    f"{artifact_id}: contentHash mismatch; expected {expected_hash}, got {artifact['contentHash']}",
                )
            )

    if stages != EXPECTED_STAGES:
        errors.append(fail(path, f"artifacts MUST cover stages in order: {EXPECTED_STAGES}; got {stages}"))

    expected = data.get("expectedResult", {})
    if not isinstance(expected, dict) or not isinstance(expected.get("verifies"), bool):
        errors.append(fail(path, "expectedResult.verifies MUST be a boolean"))
    elif expected.get("verifies") is False:
        failures = expected.get("expectedFailures")
        if not isinstance(failures, list) or not failures:
            errors.append(fail(path, "negative-path vectors MUST list expectedResult.expectedFailures"))

    return errors


def validate_manifest(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [fail(path, "manifest file not found")]
    except json.JSONDecodeError as exc:
        return [fail(path, f"invalid JSON: {exc}")]

    if not isinstance(data, dict):
        return [fail(path, "top-level value MUST be an object")]

    if data.get("dacsVersion") != "0.1":
        errors.append(fail(path, "dacsVersion MUST be '0.1' for this manifest"))

    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append(fail(path, "cases MUST be a non-empty array"))
        return errors

    case_ids: set[str] = set()
    for idx, case in enumerate(cases):
        prefix = f"case[{idx}]"
        if not isinstance(case, dict):
            errors.append(fail(path, f"{prefix} MUST be an object"))
            continue

        missing = sorted(MANIFEST_REQUIRED_CASE - set(case))
        if missing:
            errors.append(fail(path, f"{prefix} missing keys: {', '.join(missing)}"))

        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id:
            errors.append(fail(path, f"{prefix}.id MUST be a non-empty string"))
        elif case_id in case_ids:
            errors.append(fail(path, f"duplicate case id: {case_id}"))
        else:
            case_ids.add(case_id)

        for key in ["area", "spec", "summary", "status"]:
            value = case.get(key)
            if not isinstance(value, str) or not value:
                errors.append(fail(path, f"{prefix}.{key} MUST be a non-empty string"))

        spec = case.get("spec")
        if isinstance(spec, str) and spec and not spec.startswith("§"):
            errors.append(fail(path, f"{prefix}.spec MUST start with '§'"))

        status = case.get("status")
        if isinstance(status, str) and status and status not in MANIFEST_STATUSES:
            errors.append(fail(path, f"{prefix}.status MUST be one of: {', '.join(sorted(MANIFEST_STATUSES))}"))

        reason = case.get("reason")
        if status == "golden" and (not isinstance(reason, str) or not reason):
            errors.append(fail(path, f"{prefix}.reason MUST be a non-empty string for golden cases"))

        if case_id == REGISTRY_CASE_ID:
            registry = sorted(load_registered_domain_separators(ROOT))
            want = case.get("want")
            if not registry:
                errors.append(fail(path, f"{prefix}: could not parse the closed §7.7 domain-separator registry"))
            elif not isinstance(want, dict):
                errors.append(fail(path, f"{prefix}.want MUST pin the registry count and exact separator set"))
            else:
                if want.get("count") != len(registry):
                    errors.append(
                        fail(
                            path,
                            f"{prefix}.want.count mismatch; expected {len(registry)}, got {want.get('count')!r}",
                        )
                    )
                if want.get("separators") != registry:
                    errors.append(
                        fail(
                            path,
                            f"{prefix}.want.separators MUST equal the sorted closed §7.7 registry",
                        )
                    )

    golden_path = path.parent / "vectors" / "golden.json"
    if golden_path.exists():
        errors.extend(validate_golden_outputs(golden_path, path))

    return errors


def validate_golden_outputs(path: Path, manifest_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [fail(path, f"invalid JSON: {exc}")]

    if not isinstance(data, dict):
        return [fail(path, "top-level value MUST be an object")]

    manifest_dir = manifest_path.parent
    fixture_keys = {
        "bundle": ["fixture", "divergentSellerFixture", "htlc9Fixture"],
        "settlement": ["fixture", "deliveryFixture"],
    }
    for section, keys in fixture_keys.items():
        section_data = data.get(section)
        if section_data is None:
            continue
        if not isinstance(section_data, dict):
            errors.append(fail(path, f"{section} MUST be an object"))
            continue
        for key in keys:
            fixture = section_data.get(key)
            if fixture is None:
                continue
            if not isinstance(fixture, str) or not fixture:
                errors.append(fail(path, f"{section}.{key} MUST be a non-empty fixture path string"))
                continue
            if not fixture_exists(manifest_dir, fixture):
                errors.append(fail(path, f"{section}.{key} missing fixture: {fixture}"))

    for section in ["bundle", "dispute", "disclosure", "settlement"]:
        section_data = data.get(section)
        if section_data is None:
            continue
        if not isinstance(section_data, dict):
            errors.append(fail(path, f"{section} MUST be an object"))
            continue
        decisions = section_data.get("decisions")
        if decisions is None:
            continue
        if not isinstance(decisions, dict):
            errors.append(fail(path, f"{section}.decisions MUST be an object"))
            continue
        for decision_key, decision in decisions.items():
            if decision not in GOLDEN_DECISIONS:
                errors.append(
                    fail(
                        path,
                        f"{section}.decisions.{decision_key} MUST be one of: {', '.join(sorted(GOLDEN_DECISIONS))}",
                    )
                )

    return errors


def iter_vector_files(vector_dir: Path) -> list[Path]:
    return sorted(p for p in vector_dir.glob("*.json") if p.is_file())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate DACS conformance vector JSON files")
    parser.add_argument("paths", nargs="*", help="Specific five-stage vector files to validate")
    parser.add_argument("--manifest", type=Path, help="PR117-style MANIFEST.json to validate")
    args = parser.parse_args(argv)

    manifest_path = args.manifest
    if manifest_path is None and not args.paths and DEFAULT_MANIFEST.exists():
        manifest_path = DEFAULT_MANIFEST

    if args.paths:
        paths = [Path(p) for p in args.paths]
    elif args.manifest is not None:
        paths = []
    else:
        paths = iter_vector_files(DEFAULT_VECTOR_DIR)
    if manifest_path is not None:
        golden_path = manifest_path.parent / "vectors" / "golden.json"
        paths = [path for path in paths if path.resolve() != golden_path.resolve()]

    if not paths and manifest_path is None:
        print(f"no vector files found under {DEFAULT_VECTOR_DIR.relative_to(ROOT)}", file=sys.stderr)
        return 1

    all_errors: list[str] = []
    for path in paths:
        all_errors.extend(validate_vector(path))
    if manifest_path is not None:
        all_errors.extend(validate_manifest(manifest_path))

    if all_errors:
        print("conformance vector validation failed:", file=sys.stderr)
        for error in all_errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    if paths:
        plural = "s" if len(paths) != 1 else ""
        print(f"validated {len(paths)} vector{plural}")
    if manifest_path is not None:
        print(f"validated manifest: {display_path(manifest_path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
