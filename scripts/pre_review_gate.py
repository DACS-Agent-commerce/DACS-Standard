#!/usr/bin/env python3
"""Execute the small, permanent pre-review invariant registry."""
from __future__ import annotations

import argparse
import importlib.util
import itertools
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "conformance" / "pre-review-invariants.json"
EVIDENCE_SURFACES = {
    "public-api", "direct-helper", "composed-caller", "compatibility-path",
}


def _pinned(file: str, test: str, *surfaces: str) -> dict:
    return {"file": file, "test": test, "surfaces": frozenset(surfaces)}


PINNED_REVIEW_EVIDENCE = {
    "type-totality-array-ebfab-counterexample": _pinned(
        "tests/test_pr333_fix_2.py",
        "AuthenticatedEvidenceWireTypeAlgorithmTests.test_algorithm_array_rejected_without_exception_ebfab",
        "public-api",
    ),
    "type-totality-array-disposition-counterexample": _pinned(
        "tests/test_pr333_fix_2.py",
        "AuthenticatedEvidenceWireTypeAlgorithmTests.test_algorithm_array_rejected_without_exception_disposition",
        "public-api",
    ),
    "type-totality-object-counterexample": _pinned(
        "tests/test_pr333_fix_2.py",
        "AuthenticatedEvidenceWireTypeAlgorithmTests.test_algorithm_object_rejected_without_exception",
        "public-api",
    ),
    "type-totality-null-counterexample": _pinned(
        "tests/test_pr333_fix_2.py",
        "AuthenticatedEvidenceWireTypeAlgorithmTests.test_algorithm_null_rejected_without_exception",
        "public-api",
    ),
    "type-totality-boolean-counterexample": _pinned(
        "tests/test_pr333_fix_2.py",
        "AuthenticatedEvidenceWireTypeAlgorithmTests.test_algorithm_boolean_rejected_without_exception",
        "public-api",
    ),
    "type-totality-number-counterexample": _pinned(
        "tests/test_pr333_fix_2.py",
        "AuthenticatedEvidenceWireTypeAlgorithmTests.test_algorithm_number_rejected_without_exception",
        "public-api",
    ),
    "type-totality-unsupported-string-counterexample": _pinned(
        "tests/test_pr333_fix_2.py",
        "AuthenticatedEvidenceWireTypeAlgorithmTests.test_algorithm_unsupported_string_rejected_without_exception",
        "public-api",
    ),
    "type-totality-control": _pinned(
        "tests/test_pr333_fix_2.py",
        "AuthenticatedEvidenceWireTypeAlgorithmTests.test_valid_algorithm_preserved",
        "public-api",
    ),
    "credential-ref-type-counterexample": _pinned(
        "tests/test_current_evidence_boundary_regressions.py",
        "EntitlementCredentialRefBoundaryTests.test_present_malformed_credential_ref_is_typed_error_on_both_apis",
        "public-api",
    ),
    "credential-ref-positive-control": _pinned(
        "tests/test_current_evidence_boundary_regressions.py",
        "EntitlementCredentialRefBoundaryTests.test_absent_and_valid_private_credential_modes_still_pass",
        "public-api", "compatibility-path",
    ),
    "delivery-binding-counterexample": _pinned(
        "tests/test_current_evidence_boundary_regressions.py",
        "CurrentFabDeliveryAdmissionTests.test_current_fab_delivery_exact_bindings_are_load_bearing",
        "composed-caller",
    ),
    "delivery-binding-control": _pinned(
        "tests/test_current_evidence_boundary_regressions.py",
        "CurrentFabDeliveryAdmissionTests.test_genuine_current_fab_delivery_closure_passes",
        "composed-caller",
    ),
    "era-downgrade-counterexample": _pinned(
        "tests/test_current_evidence_boundary_regressions.py",
        "ExplicitReconciliationReceiptContractTests.test_archival_ebfab_is_comparison_only",
        "composed-caller",
    ),
    "era-downgrade-control": _pinned(
        "tests/test_current_evidence_boundary_regressions.py",
        "ExplicitReconciliationReceiptContractTests.test_current_ebfab_remains_selectable_but_dual_era_refuses",
        "composed-caller", "compatibility-path",
    ),
    "helper-composition-counterexample": _pinned(
        "tests/test_settlement_finality_verification_vectors.py",
        "SettlementFinalityVerificationVectorTests.test_provider_attestation_map_boundary_is_typed_on_direct_and_composed_paths",
        "direct-helper", "composed-caller",
    ),
    "helper-composition-control": _pinned(
        "tests/test_settlement_finality_verification_vectors.py",
        "SettlementFinalityVerificationVectorTests.test_actual_dacs5_strong_bundle_consumer_passes_all_six_models",
        "composed-caller",
    ),
    "historical-helper-binding-counterexample": _pinned(
        "tests/test_current_evidence_boundary_regressions.py",
        "HistoricalEvidenceBindingTests.test_wrong_job_and_malformed_historical_evidence_refuse_without_throwing",
        "direct-helper", "compatibility-path",
    ),
    "historical-helper-binding-control": _pinned(
        "tests/test_current_evidence_boundary_regressions.py",
        "HistoricalEvidenceBindingTests.test_legitimate_historical_fab_binding_passes_without_type_error",
        "direct-helper", "compatibility-path",
    ),
    "compatibility-counterexample": _pinned(
        "tests/test_settlement_finality_verification_vectors.py",
        "SettlementFinalityVerificationVectorTests.test_historical_pointer_fixture_cannot_bypass_current_profile_admission",
        "compatibility-path",
    ),
    "compatibility-control": _pinned(
        "tests/test_settlement_finality_verification_vectors.py",
        "SettlementFinalityVerificationVectorTests.test_new_new_and_all_new_older_reconciliation_paths_execute",
        "compatibility-path", "composed-caller",
    ),
}

REQUIRED_REVIEW_LENSES = {
    "hostile-json-type-totality": {
        "counterexampleEvidence": frozenset({
            "type-totality-array-ebfab-counterexample",
            "type-totality-array-disposition-counterexample",
            "type-totality-object-counterexample",
            "type-totality-null-counterexample",
            "type-totality-boolean-counterexample",
            "type-totality-number-counterexample",
            "type-totality-unsupported-string-counterexample",
            "credential-ref-type-counterexample",
        }),
        "controlEvidence": frozenset({
            "type-totality-control", "credential-ref-positive-control",
        }),
        "requiredSurfaces": {
            "counterexampleEvidence": {"public-api"},
            "controlEvidence": {"public-api"},
        },
    },
    "binding-axis-isolation-current-fab-delivery": {
        "counterexampleEvidence": frozenset({"delivery-binding-counterexample"}),
        "controlEvidence": frozenset({"delivery-binding-control"}),
        "requiredSurfaces": {
            "counterexampleEvidence": {"composed-caller"},
            "controlEvidence": {"composed-caller"},
        },
    },
    "current-archival-downgrade-fallback": {
        "counterexampleEvidence": frozenset({"era-downgrade-counterexample"}),
        "controlEvidence": frozenset({"era-downgrade-control"}),
        "requiredSurfaces": {
            "counterexampleEvidence": {"composed-caller"},
            "controlEvidence": {"composed-caller"},
        },
    },
    "direct-helper-composed-path-parity": {
        "counterexampleEvidence": frozenset({
            "helper-composition-counterexample",
            "historical-helper-binding-counterexample",
        }),
        "controlEvidence": frozenset({
            "helper-composition-control",
            "historical-helper-binding-control",
        }),
        "requiredSurfaces": {
            "counterexampleEvidence": {"direct-helper", "composed-caller"},
            "controlEvidence": {"direct-helper", "composed-caller"},
        },
    },
    "compatibility-legitimate-positive-preservation": {
        "counterexampleEvidence": frozenset({"compatibility-counterexample"}),
        "controlEvidence": frozenset({"compatibility-control"}),
        "requiredSurfaces": {
            "counterexampleEvidence": {"compatibility-path"},
            "controlEvidence": {"compatibility-path"},
        },
    },
}
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class GateError(ValueError):
    pass


def _unittest_module(relative: str, test: str, label: str) -> str:
    """Validate a manifest unittest target and return its importable module."""
    path = PurePosixPath(relative)
    module_parts = (*path.parts[:-1], path.stem)
    if (
        path.is_absolute()
        or len(path.parts) < 2
        or path.parts[0] != "tests"
        or path.suffix != ".py"
        or not path.name.startswith("test_")
        or not all(part.isidentifier() for part in module_parts)
    ):
        raise GateError(
            f"{label}: file must name an importable test_*.py module under tests/"
        )
    test_parts = test.split(".")
    if len(test_parts) < 2 or not all(part.isidentifier() for part in test_parts):
        raise GateError(
            f"{label}: test must be a safe dotted unittest identity"
        )
    return ".".join(module_parts)


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
    corpus_pins = manifest.get("corpusPins")
    covered = manifest.get("coveredInvariantClasses")
    planned = manifest.get("plannedInvariantClasses")
    review_evidence = manifest.get("independentReviewEvidence")
    review_lenses = manifest.get("independentReviewLenses")
    if not isinstance(matrices, list) or not matrices:
        raise GateError("vectorMatrices must be a nonempty list")
    if not isinstance(regressions, list) or not regressions:
        raise GateError("unitRegressions must be a nonempty list")
    if not isinstance(corpus_pins, dict) or not corpus_pins:
        raise GateError("corpusPins must be a nonempty object")
    if not isinstance(covered, list):
        raise GateError("coveredInvariantClasses must be a list")
    if not isinstance(planned, list):
        raise GateError("plannedInvariantClasses must be a list")
    if not isinstance(review_evidence, list) or not review_evidence:
        raise GateError("independentReviewEvidence must be a nonempty list")
    if not isinstance(review_lenses, list) or not review_lenses:
        raise GateError("independentReviewLenses must be a nonempty list")

    for corpus_name, pin in corpus_pins.items():
        if (
            not isinstance(corpus_name, str) or not corpus_name
            or not isinstance(pin, dict)
            or set(pin) != {"spec", "authoritativeProfile"}
            or not isinstance(pin.get("spec"), str)
            or not isinstance(pin.get("authoritativeProfile"), dict)
        ):
            raise GateError("corpusPins entries require spec and authoritativeProfile")

    ids: set[str] = set()
    matrix_classes: dict[str, set[str]] = {}
    for matrix in matrices:
        if not isinstance(matrix, dict) or not isinstance(matrix.get("id"), str):
            raise GateError("every vector matrix needs a string id")
        if matrix["id"] in ids:
            raise GateError(f"duplicate invariant id: {matrix['id']}")
        ids.add(matrix["id"])
        invariant_classes = matrix.get("invariantClasses")
        if (
            not isinstance(invariant_classes, list)
            or not invariant_classes
            or not all(isinstance(item, str) and item for item in invariant_classes)
            or len(set(invariant_classes)) != len(invariant_classes)
        ):
            raise GateError(f"{matrix['id']}: invariantClasses must be unique strings")
        matrix_classes[matrix["id"]] = set(invariant_classes)
        corpus_name = matrix.get("corpus")
        if corpus_name not in corpus_pins:
            raise GateError(f"{matrix['id']}: corpus has no exact revision/profile pin")
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
        _unittest_module(
            regression["file"], regression["test"], regression["id"]
        )
        _within_test_root(regression["file"])

    covered_ids: set[str] = set()
    for item in covered:
        if not isinstance(item, dict) or set(item) != {"id", "matrixIds"}:
            raise GateError("covered invariant classes require id and matrixIds")
        class_id = item.get("id")
        evidence = item.get("matrixIds")
        if (
            not isinstance(class_id, str) or not class_id
            or class_id in covered_ids
            or not isinstance(evidence, list) or not evidence
            or not all(isinstance(matrix_id, str) for matrix_id in evidence)
            or len(set(evidence)) != len(evidence)
        ):
            raise GateError("covered invariant classes require a unique id and matrix evidence")
        covered_ids.add(class_id)
        for matrix_id in evidence:
            if matrix_id not in matrix_classes:
                raise GateError(f"{class_id}: coverage references missing matrix {matrix_id}")
            if class_id not in matrix_classes[matrix_id]:
                raise GateError(
                    f"{class_id}: matrix {matrix_id} does not declare this invariant class"
                )

    planned_ids: set[str] = set()
    for item in planned:
        if (
            not isinstance(item, dict)
            or set(item) != {"id", "status"}
            or not isinstance(item.get("id"), str)
            or not item["id"]
            or item.get("status") != "planned"
        ):
            raise GateError("planned invariant classes must be explicitly status=planned")
        if item["id"] in planned_ids:
            raise GateError(f"duplicate planned invariant class: {item['id']}")
        planned_ids.add(item["id"])
        if item["id"] in covered_ids:
            raise GateError(f"invariant class cannot be both covered and planned: {item['id']}")

    declared_matrix_classes = set().union(*matrix_classes.values())
    unclaimed_matrix_classes = declared_matrix_classes - covered_ids
    if unclaimed_matrix_classes:
        raise GateError(
            "matrix invariant classes must be claimed as covered: "
            f"{sorted(unclaimed_matrix_classes)}"
        )

    evidence_by_id: dict[str, dict] = {}
    evidence_targets: set[tuple[str, str]] = set()
    for evidence in review_evidence:
        if not isinstance(evidence, dict) or set(evidence) != {
            "id", "file", "test", "surfaces",
        }:
            raise GateError(
                "independent review evidence requires id/file/test/surfaces"
            )
        evidence_id = evidence.get("id")
        file_name = evidence.get("file")
        test_name = evidence.get("test")
        surfaces = evidence.get("surfaces")
        if (
            not isinstance(evidence_id, str) or not evidence_id
            or evidence_id in evidence_by_id
            or not isinstance(file_name, str) or not file_name
            or not isinstance(test_name, str) or not test_name
            or not isinstance(surfaces, list) or not surfaces
            or not all(isinstance(surface, str) for surface in surfaces)
            or len(set(surfaces)) != len(surfaces)
            or not set(surfaces).issubset(EVIDENCE_SURFACES)
        ):
            raise GateError("independent review evidence must be unique and runnable")
        _unittest_module(file_name, test_name, evidence_id)
        _within_test_root(file_name)
        pinned = PINNED_REVIEW_EVIDENCE.get(evidence_id)
        observed = {
            "file": file_name,
            "test": test_name,
            "surfaces": frozenset(surfaces),
        }
        if pinned != observed:
            raise GateError(
                f"{evidence_id}: evidence does not match its code-pinned declaration"
            )
        target = (file_name, test_name)
        if target in evidence_targets:
            raise GateError(f"duplicate independent review evidence target: {target}")
        evidence_targets.add(target)
        evidence_by_id[evidence_id] = evidence

    missing_evidence = PINNED_REVIEW_EVIDENCE.keys() - evidence_by_id.keys()
    extra_evidence = evidence_by_id.keys() - PINNED_REVIEW_EVIDENCE.keys()
    if missing_evidence or extra_evidence:
        raise GateError(
            "independent review evidence does not match the code-pinned registry: "
            f"missing={sorted(missing_evidence)}, extra={sorted(extra_evidence)}"
        )

    lenses_by_id: dict[str, dict] = {}
    evidence_owners: dict[str, tuple[str, str]] = {}
    for lens in review_lenses:
        if not isinstance(lens, dict) or set(lens) != {
            "id", "counterexampleEvidence", "controlEvidence",
        }:
            raise GateError(
                "independent review lenses require id/counterexampleEvidence/controlEvidence"
            )
        lens_id = lens.get("id")
        if not isinstance(lens_id, str) or not lens_id or lens_id in lenses_by_id:
            raise GateError("independent review lens ids must be unique strings")
        lenses_by_id[lens_id] = lens
        role_sets = []
        for role in ("counterexampleEvidence", "controlEvidence"):
            evidence_ids = lens.get(role)
            if (
                not isinstance(evidence_ids, list) or not evidence_ids
                or not all(isinstance(item, str) and item for item in evidence_ids)
                or len(set(evidence_ids)) != len(evidence_ids)
            ):
                raise GateError(f"{lens_id}: {role} must contain unique evidence ids")
            missing = set(evidence_ids) - evidence_by_id.keys()
            if missing:
                raise GateError(
                    f"{lens_id}: dangling independent review evidence {sorted(missing)}"
                )
            role_sets.append(set(evidence_ids))
            for evidence_id in evidence_ids:
                if evidence_id in evidence_owners:
                    owner = evidence_owners[evidence_id]
                    raise GateError(
                        f"{evidence_id}: evidence belongs to both "
                        f"{owner[0]}/{owner[1]} and {lens_id}/{role}"
                    )
                evidence_owners[evidence_id] = (lens_id, role)
        if role_sets[0] & role_sets[1]:
            raise GateError(
                f"{lens_id}: counterexample and control evidence must be distinct"
            )

    missing_lenses = set(REQUIRED_REVIEW_LENSES) - lenses_by_id.keys()
    extra_lenses = lenses_by_id.keys() - set(REQUIRED_REVIEW_LENSES)
    if missing_lenses or extra_lenses:
        raise GateError(
            "independent review lenses do not match the required set: "
            f"missing={sorted(missing_lenses)}, extra={sorted(extra_lenses)}"
        )
    orphaned_evidence = evidence_by_id.keys() - evidence_owners.keys()
    if orphaned_evidence:
        raise GateError(
            f"unclaimed independent review evidence: {sorted(orphaned_evidence)}"
        )
    for lens_id, contract in REQUIRED_REVIEW_LENSES.items():
        lens = lenses_by_id[lens_id]
        for role in ("counterexampleEvidence", "controlEvidence"):
            observed_ids = set(lens[role])
            if observed_ids != contract[role]:
                raise GateError(
                    f"{lens_id}/{role}: evidence set does not match "
                    "the code-pinned registry contract"
                )
            observed_surfaces = set()
            for evidence_id in lens[role]:
                observed_surfaces.update(evidence_by_id[evidence_id]["surfaces"])
            missing_surfaces = (
                contract["requiredSurfaces"][role] - observed_surfaces
            )
            if missing_surfaces:
                raise GateError(
                    f"{lens_id}/{role}: missing required evidence surfaces "
                    f"{sorted(missing_surfaces)}"
                )


def _within_root(relative: str) -> Path:
    path = (ROOT / relative).resolve()
    if ROOT != path and ROOT not in path.parents:
        raise GateError(f"path escapes repository: {relative}")
    if not path.is_file():
        raise GateError(f"required file disappeared: {relative}")
    return path


def _within_test_root(relative: str) -> Path:
    path = _within_root(relative)
    test_root = (ROOT / "tests").resolve()
    if test_root not in path.parents:
        raise GateError(f"unittest file escapes tests/: {relative}")
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


def _index_vectors(corpus: dict, label: str) -> dict[str, dict]:
    vectors: dict[str, dict] = {}
    for item in corpus.get("vectors", []):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        name = item["name"]
        if name in vectors:
            raise GateError(f"{label}: duplicate corpus vector name: {name}")
        vectors[name] = item
    return vectors


def run_vector_matrices(manifest: dict) -> int:
    executed = 0
    loaded = {}
    for matrix in manifest["vectorMatrices"]:
        corpus_path = _within_root(matrix["corpus"])
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        pin = manifest["corpusPins"][matrix["corpus"]]
        observed_pin = {
            "spec": corpus.get("spec"),
            "authoritativeProfile": corpus.get("authoritativeProfile"),
        }
        if observed_pin != pin:
            raise GateError(
                f"{matrix['id']}: corpus revision/profile pin drifted: "
                f"expected {pin}, got {observed_pin}"
            )
        vectors = _index_vectors(corpus, matrix["id"])
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
    return _run_python_evidence(manifest["unitRegressions"], "regression")


def _run_python_evidence(entries: list[dict], label: str) -> int:
    python_path = os.pathsep.join(
        part for part in (str(ROOT), str(ROOT / "tests"), os.environ.get("PYTHONPATH", ""))
        if part
    )
    for entry in entries:
        module = _unittest_module(entry["file"], entry["test"], entry["id"])
        _within_test_root(entry["file"])
        completed = subprocess.run(
            [sys.executable, "-m", "unittest", f"{module}.{entry['test']}"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            env={**os.environ, "PYTHONPATH": python_path},
        )
        if completed.returncode:
            detail = (completed.stdout + completed.stderr).strip()
            failure_kind = (
                "regression" if label == "regression"
                else "independent review evidence"
            )
            raise GateError(
                f"{entry['id']}: {failure_kind} is missing or failing\n{detail}"
            )
    return len(entries)


def run_independent_review_evidence(manifest: dict) -> int:
    return _run_python_evidence(
        manifest["independentReviewEvidence"], "review evidence"
    )


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
        review_evidence_count = run_independent_review_evidence(manifest)
    except (GateError, OSError, json.JSONDecodeError) as exc:
        print(f"pre-review gate FAILED: {exc}", file=sys.stderr)
        return 1
    print(
        f"pre-review gate OK ({matrix_count} matrix cases; "
        f"{regression_count} prior blocker regressions; "
        f"{len(manifest['independentReviewLenses'])} independent review lenses; "
        f"{review_evidence_count} independent review evidence tests)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
