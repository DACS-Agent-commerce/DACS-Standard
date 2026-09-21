#!/usr/bin/env python3
"""Execute the small, permanent pre-review invariant registry."""
from __future__ import annotations

import argparse
import importlib.util
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "conformance" / "pre-review-invariants.json"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class GateError(ValueError):
    pass


def load_manifest(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError(f"cannot load {path}: {exc}") from exc
    validate_manifest(value)
    return value


def validate_manifest(manifest: object) -> None:
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1:
        raise GateError("manifest must be a schemaVersion 1 object")
    matrices = manifest.get("vectorMatrices")
    regressions = manifest.get("unitRegressions")
    planned = manifest.get("plannedInvariantClasses")
    if not isinstance(matrices, list) or not matrices:
        raise GateError("vectorMatrices must be a nonempty list")
    if not isinstance(regressions, list) or not regressions:
        raise GateError("unitRegressions must be a nonempty list")
    if not isinstance(planned, list):
        raise GateError("plannedInvariantClasses must be a list")

    ids: set[str] = set()
    for matrix in matrices:
        if not isinstance(matrix, dict) or not isinstance(matrix.get("id"), str):
            raise GateError("every vector matrix needs a string id")
        if matrix["id"] in ids:
            raise GateError(f"duplicate invariant id: {matrix['id']}")
        ids.add(matrix["id"])
        dimensions = matrix.get("dimensions")
        cases = matrix.get("cases")
        if not isinstance(dimensions, dict) or not dimensions:
            raise GateError(f"{matrix['id']}: dimensions must be nonempty")
        if not isinstance(cases, list):
            raise GateError(f"{matrix['id']}: cases must be a list")
        dimension_names = list(dimensions)
        values = []
        for name in dimension_names:
            domain = dimensions[name]
            if not isinstance(domain, list) or not domain or len(set(domain)) != len(domain):
                raise GateError(f"{matrix['id']}: invalid dimension {name}")
            values.append(domain)
        required = {tuple(zip(dimension_names, product)) for product in itertools.product(*values)}
        actual = set()
        case_ids = set()
        for case in cases:
            if not isinstance(case, dict) or not isinstance(case.get("caseId"), str):
                raise GateError(f"{matrix['id']}: case missing caseId")
            case_id = case["caseId"]
            if case_id in case_ids:
                raise GateError(f"{matrix['id']}: duplicate caseId {case_id}")
            case_ids.add(case_id)
            coordinates = case.get("coordinates")
            if not isinstance(coordinates, dict) or set(coordinates) != set(dimension_names):
                raise GateError(f"{matrix['id']}/{case_id}: coordinates do not match dimensions")
            coordinate = tuple((name, coordinates[name]) for name in dimension_names)
            if coordinate not in required:
                raise GateError(f"{matrix['id']}/{case_id}: coordinate is outside the matrix")
            if coordinate in actual:
                raise GateError(f"{matrix['id']}: duplicate coordinate {dict(coordinate)}")
            actual.add(coordinate)
            for expectation_name in ("expected", "controlExpected"):
                expected = case.get(expectation_name)
                if not isinstance(expected, dict) or set(expected) != {
                    "verdict", "revocationCheck", "session",
                }:
                    raise GateError(
                        f"{matrix['id']}/{case_id}: incomplete {expectation_name} result"
                    )
            if not isinstance(case.get("controlCase"), str):
                raise GateError(f"{matrix['id']}/{case_id}: missing discriminating controlCase")
        if actual != required:
            missing = [dict(item) for item in sorted(required - actual)]
            raise GateError(f"{matrix['id']}: incomplete matrix; missing {missing}")

    for regression in regressions:
        if (
            not isinstance(regression, dict)
            or set(regression) != {"id", "file", "test"}
            or not all(isinstance(regression[key], str) for key in regression)
        ):
            raise GateError("unit regression entries require string id/file/test")
        if regression["id"] in ids:
            raise GateError(f"duplicate invariant id: {regression['id']}")
        ids.add(regression["id"])

    for item in planned:
        if not isinstance(item, dict) or item.get("status") != "planned":
            raise GateError("planned invariant classes must be explicitly status=planned")
        if item.get("id") in ids:
            raise GateError(f"planned invariant is falsely registered as covered: {item.get('id')}")


def _within_root(relative: str) -> Path:
    path = (ROOT / relative).resolve()
    if ROOT != path and ROOT not in path.parents:
        raise GateError(f"path escapes repository: {relative}")
    if not path.is_file():
        raise GateError(f"required file disappeared: {relative}")
    return path


def _load_evaluator(relative: str):
    path = _within_root(relative)
    module_name = "_dacs_pre_review_evaluator"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise GateError(f"cannot load evaluator: {relative}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(getattr(module, "evaluate", None)):
        raise GateError(f"evaluator has no callable evaluate(): {relative}")
    return module


def _complete_outcome(result: object, label: str) -> dict:
    if not isinstance(result, tuple) or len(result) != 2 or not isinstance(result[1], dict):
        raise GateError(f"{label}: evaluator returned a malformed outcome")
    verdict, effects = result
    if "verdict" in effects:
        raise GateError(f"{label}: consumer effects must not redefine verdict")
    return {"verdict": verdict, **effects}


def _corpus_outcome(vector: dict, label: str) -> dict:
    effects = vector.get("want")
    if not isinstance(effects, dict) or "verdict" in effects:
        raise GateError(f"{label}: corpus has a malformed expected outcome")
    return {"verdict": vector.get("expected"), **effects}


def run_vector_matrices(manifest: dict) -> int:
    executed = 0
    loaded = {}
    for matrix in manifest["vectorMatrices"]:
        corpus_path = _within_root(matrix["corpus"])
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        vectors = {item.get("name"): item for item in corpus.get("vectors", []) if isinstance(item, dict)}
        if matrix["evaluator"] not in loaded:
            loaded[matrix["evaluator"]] = _load_evaluator(matrix["evaluator"])
        evaluator = loaded[matrix["evaluator"]]
        for case in matrix["cases"]:
            case_id = case["caseId"]
            if case_id not in vectors:
                raise GateError(f"{matrix['id']}: required case disappeared: {case_id}")
            control_id = case["controlCase"]
            if control_id not in vectors:
                raise GateError(f"{matrix['id']}: control case disappeared: {control_id}")
            vector = vectors[case_id]
            control = vectors[control_id]
            result = evaluator.evaluate(
                vector.get("input"), corpus.get("publicKeys"),
                vector.get("trustedProfileAdmission"),
            )
            observed = _complete_outcome(result, f"{matrix['id']}/{case_id}")
            if observed != case["expected"]:
                raise GateError(f"{matrix['id']}/{case_id}: expected {case['expected']}, got {observed}")
            if case["expected"] != _corpus_outcome(vector, f"{matrix['id']}/{case_id}"):
                raise GateError(f"{matrix['id']}/{case_id}: registry and corpus expectations diverge")
            control_result = evaluator.evaluate(
                control.get("input"), corpus.get("publicKeys"),
                control.get("trustedProfileAdmission"),
            )
            control_label = f"{matrix['id']}/{case_id} control {control_id}"
            control_observed = _complete_outcome(control_result, control_label)
            if control_observed != case["controlExpected"]:
                raise GateError(
                    f"{control_label}: expected {case['controlExpected']}, got {control_observed}"
                )
            if case["controlExpected"] != _corpus_outcome(control, control_label):
                raise GateError(f"{control_label}: registry and corpus expectations diverge")
            if observed == control_observed:
                raise GateError(
                    f"{matrix['id']}/{case_id}: no longer discriminates from control {control_id}"
                )
            executed += 1
    return executed


def run_unit_regressions(manifest: dict) -> int:
    python_path = os.pathsep.join(
        part for part in (str(ROOT), str(ROOT / "tests"), os.environ.get("PYTHONPATH", ""))
        if part
    )
    for regression in manifest["unitRegressions"]:
        path = _within_root(regression["file"])
        completed = subprocess.run(
            [sys.executable, str(path), regression["test"]],
            cwd=ROOT,
            text=True,
            capture_output=True,
            env={**os.environ, "PYTHONPATH": python_path},
        )
        if completed.returncode:
            detail = (completed.stdout + completed.stderr).strip()
            raise GateError(f"{regression['id']}: regression is missing or failing\n{detail}")
    return len(manifest["unitRegressions"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    try:
        if os.name != "nt" and not os.access(Path(__file__), os.X_OK):
            raise GateError("scripts/pre_review_gate.py must remain executable")
        manifest = load_manifest(args.manifest.resolve())
        matrix_count = run_vector_matrices(manifest)
        regression_count = run_unit_regressions(manifest)
    except (GateError, OSError, json.JSONDecodeError) as exc:
        print(f"pre-review gate FAILED: {exc}", file=sys.stderr)
        return 1
    print(
        f"pre-review gate OK ({matrix_count} matrix cases; "
        f"{regression_count} prior blocker regressions)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
