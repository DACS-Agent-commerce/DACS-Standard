#!/usr/bin/env python3
"""Bounded, deterministic, offline evaluation for DACS Standard PR #362."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.dont_write_bytecode = True


CANDIDATE = Path("/private/tmp/dacs-repairs-20260914/pr362")
OUTPUT = Path("/private/tmp/dacs-pr362-eval-20260915")
CASES_PATH = OUTPUT / "cases.json"
RESULTS_PATH = OUTPUT / "results.json"
MANIFEST_PATH = OUTPUT / "reproducibility-manifest.json"
GRADER_CALIBRATION_PATH = OUTPUT / "grader-calibration.json"
EXPECTED_HEAD = "37010daa0a7c5900afcda6e314f1ae53f3afeb7b"
EXPECTED_BASE = "ff8c289d22d07e09a1733b1ae7791100bfdbd923"
EXPECTED_ORIGIN = "https://github.com/DACS-Agent-commerce/DACS-Standard.git"
VERIFY_DOMAIN = "dacs-verifyresult:v1:"
WRONG_DOMAIN = "dacs-eval-wrong-domain:v1:"
SAFE_INTEGER = 9_007_199_254_740_991
EXPECTED_CASE_IDS = [
    "EVAL-001", "EVAL-002", "EVAL-003", "EVAL-004", "EVAL-005",
    "EVAL-006", "EVAL-007", "EVAL-008", "EVAL-009", "EVAL-010",
    "EVAL-011", "CAL-001",
]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=CANDIDATE, check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout.strip()


def verify_candidate_pin() -> dict[str, str]:
    actual = {
        "origin": git("remote", "get-url", "origin"),
        "head": git("rev-parse", "HEAD"),
        "base": git("rev-parse", f"{EXPECTED_BASE}^{{commit}}"),
        "statusPorcelain": git("status", "--porcelain"),
    }
    if actual["origin"] != EXPECTED_ORIGIN:
        raise RuntimeError(f"candidate origin mismatch: {actual['origin']!r}")
    if actual["head"] != EXPECTED_HEAD:
        raise RuntimeError(f"candidate head mismatch: {actual['head']!r}")
    if actual["base"] != EXPECTED_BASE:
        raise RuntimeError(f"candidate base mismatch: {actual['base']!r}")
    if actual["statusPorcelain"]:
        raise RuntimeError("candidate is not clean")
    return actual


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_candidate_modules():
    sys.path.insert(0, str(CANDIDATE / "scripts"))
    consumer = load_module(
        "pr362_candidate_consumer", CANDIDATE / "tests" / "test_presence_only_claim_vectors.py"
    )
    producer = load_module(
        "pr362_candidate_producer", CANDIDATE / "scripts" / "generate_presence_only_claim_vectors.py"
    )
    return consumer, producer


def _safe_ascii_integer_domain(value: Any, path: str = "$") -> None:
    """Reject everything outside the subset where stdlib sorting exactly matches JCS."""
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if abs(value) > SAFE_INTEGER:
            raise ValueError(f"{path}: integer outside DACS safe magnitude")
        return
    if type(value) is str:
        if not value.isascii():
            raise ValueError(f"{path}: non-ASCII string outside oracle scope")
        return
    if type(value) is list:
        for index, item in enumerate(value):
            _safe_ascii_integer_domain(item, f"{path}[{index}]")
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str or not key.isascii():
                raise ValueError(f"{path}: non-ASCII/non-string member name")
            _safe_ascii_integer_domain(item, f"{path}.{key}")
        return
    raise ValueError(f"{path}: {type(value).__name__} outside oracle scope")


def oracle_canonical(value: Any) -> bytes:
    _safe_ascii_integer_domain(value)
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def oracle_hash(value: Any) -> str:
    return hashlib.sha256(oracle_canonical(value)).hexdigest()


def oracle_artifact_hash(artifact: dict[str, Any]) -> str:
    return oracle_hash({key: value for key, value in artifact.items() if key != "signature"})


def strict_b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value or not value.isascii():
        raise ValueError("non-canonical Base64URL")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError("non-canonical Base64URL")
    return decoded


def oracle_verify(artifact: dict[str, Any], domain: str = VERIFY_DOMAIN) -> bool:
    signature = artifact.get("signature")
    if not isinstance(signature, dict) or set(signature) != {"algorithm", "signer", "value"}:
        return False
    if signature.get("algorithm") != "ed25519":
        return False
    signer = signature.get("signer")
    if not isinstance(signer, str) or not signer.startswith("key:"):
        return False
    try:
        public_key = bytes.fromhex(signer[4:])
        payload = (domain + oracle_artifact_hash(artifact)).encode("ascii")
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            strict_b64url_decode(signature["value"]), payload
        )
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def verify_custom_preimage(artifact: dict[str, Any], payload: bytes) -> bool:
    signature = artifact["signature"]
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(signature["signer"][4:])).verify(
            strict_b64url_decode(signature["value"]), payload
        )
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def reversed_maps(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: reversed_maps(value[key]) for key in reversed(list(value))}
    if isinstance(value, list):
        return [reversed_maps(item) for item in value]
    return value


def build_positive(producer, name: str, *, result: dict[str, Any] | None = None,
                   label: str | None = None) -> dict[str, Any]:
    artifact = result or producer.verify_result(producer.DID_REF, "pass")
    ref = producer.result_ref(artifact, label or name)
    bundle = producer.signed_bundle([
        producer.claim(producer.PRESENTER_REF, issuedAt=producer.NOW - 500_000),
        producer.claim(producer.DID_REF, verifiedBy=ref),
    ])
    req = producer.requirement([
        producer.presence("key"), producer.verified("did")
    ])
    return producer.case(
        name, "pass", bundle, req, refs=[ref], resolved=[(ref, artifact)],
        note="evaluation-generated coherent positive",
    )


def fresh_context(producer, vector: dict[str, Any]) -> dict[str, Any]:
    return producer.trusted_context([vector])


def candidate_decision(consumer, producer, vector: dict[str, Any],
                       context: dict[str, Any] | None = None) -> str:
    ctx = context or fresh_context(producer, vector)
    return consumer.evaluate(vector, ctx, consumer.PresenceEvaluationRuntime(ctx))


def candidate_authentication(consumer, vector: dict[str, Any],
                             context: dict[str, Any]) -> bool:
    item = vector["resolvedResults"][0]
    return consumer.authenticate_result(
        item["artifact"], item["ref"], context,
        vector["compositeRecord"]["generatedAt"],
    )


def corrupt_signature(artifact: dict[str, Any]) -> None:
    value = artifact["signature"]["value"]
    artifact["signature"]["value"] = ("A" if value[0] != "A" else "B") + value[1:]


def resign_result(producer, artifact: dict[str, Any], *, domain: str = VERIFY_DOMAIN,
                  raw_digest: bool = False) -> dict[str, Any]:
    unsigned = {key: value for key, value in artifact.items() if key != "signature"}
    digest = bytes.fromhex(oracle_hash(unsigned)) if raw_digest else None
    if raw_digest:
        payload = domain.encode("ascii") + digest
        value = producer.b64url(producer.AUTHORITY.sign(payload))
        return {
            **copy.deepcopy(unsigned),
            "signature": {"algorithm": "ed25519", "signer": producer.AUTHORITY_REF, "value": value},
        }
    return producer.sign_component(unsigned, producer.AUTHORITY, producer.AUTHORITY_REF, domain)


def result(case_id: str, passed: bool, observations: dict[str, Any],
           calls: list[dict[str, Any]], *, notes: list[str] | None = None) -> dict[str, Any]:
    return {
        "caseId": case_id,
        "status": "pass" if passed else "fail",
        "observations": observations,
        "actualCalls": calls,
        "forbiddenEffectsObserved": [],
        "notes": notes or [],
    }


def run_cases(consumer, producer) -> list[dict[str, Any]]:
    outputs: list[dict[str, Any]] = []

    baseline = build_positive(producer, "eval-001-valid")
    artifact = baseline["resolvedResults"][0]["artifact"]
    ref = baseline["resolvedResults"][0]["ref"]
    ctx = fresh_context(producer, baseline)
    digest = oracle_artifact_hash(artifact)
    auth = oracle_verify(artifact)
    candidate_auth = candidate_authentication(consumer, baseline, ctx)
    decision = candidate_decision(consumer, producer, baseline, ctx)
    obs = {"oracleHash": digest, "referenceHash": ref["contentHash"],
           "oracleHashMatchesReference": digest == ref["contentHash"],
           "oracleSignatureValid": auth, "candidateAuthenticateResult": candidate_auth,
           "candidateConsumerDecision": decision}
    outputs.append(result("EVAL-001", all([obs["oracleHashMatchesReference"], auth,
                                           candidate_auth, decision == "pass"]), obs,
        [{"call": "candidate.authenticate_result", "output": candidate_auth},
         {"call": "candidate.evaluate", "output": decision}]))

    vector = build_positive(producer, "eval-002-signature-only")
    original_hash = oracle_artifact_hash(vector["resolvedResults"][0]["artifact"])
    corrupt_signature(vector["resolvedResults"][0]["artifact"])
    artifact = vector["resolvedResults"][0]["artifact"]
    ref = vector["resolvedResults"][0]["ref"]
    ctx = fresh_context(producer, vector)
    digest = oracle_artifact_hash(artifact)
    auth = oracle_verify(artifact)
    candidate_auth = candidate_authentication(consumer, vector, ctx)
    decision = candidate_decision(consumer, producer, vector, ctx)
    obs = {"originalOracleHash": original_hash, "mutatedOracleHash": digest,
           "referenceHash": ref["contentHash"], "oracleHashUnchanged": digest == original_hash,
           "oracleHashMatchesReference": digest == ref["contentHash"],
           "oracleSignatureValid": auth, "candidateAuthenticateResult": candidate_auth,
           "candidateConsumerDecision": decision, "intendedGuardReached": not candidate_auth}
    outputs.append(result("EVAL-002", obs["oracleHashUnchanged"] and obs["oracleHashMatchesReference"]
        and not auth and not candidate_auth and decision == "error", obs,
        [{"call": "candidate.authenticate_result", "output": candidate_auth},
         {"call": "candidate.evaluate", "output": decision}]))

    vector = build_positive(producer, "eval-003-stale-ref")
    item = vector["resolvedResults"][0]
    original_hash = oracle_artifact_hash(item["artifact"])
    item["artifact"]["reason"] = "coherent content mutation for stale reference"
    item["artifact"] = resign_result(producer, item["artifact"])
    digest = oracle_artifact_hash(item["artifact"])
    ctx = fresh_context(producer, vector)
    auth = oracle_verify(item["artifact"])
    candidate_auth = candidate_authentication(consumer, vector, ctx)
    decision = candidate_decision(consumer, producer, vector, ctx)
    obs = {"originalOracleHash": original_hash, "mutatedOracleHash": digest,
           "staleReferenceHash": item["ref"]["contentHash"], "oracleHashChanged": digest != original_hash,
           "oracleHashMatchesReference": digest == item["ref"]["contentHash"],
           "oracleSignatureValid": auth, "candidateAuthenticateResult": candidate_auth,
           "candidateConsumerDecision": decision,
           "intendedGuardReached": auth and digest != item["ref"]["contentHash"] and not candidate_auth}
    outputs.append(result("EVAL-003", obs["oracleHashChanged"] and not obs["oracleHashMatchesReference"]
        and auth and not candidate_auth and decision == "error", obs,
        [{"call": "candidate.authenticate_result", "output": candidate_auth},
         {"call": "candidate.evaluate", "output": decision}]))

    base_artifact = producer.verify_result(producer.DID_REF, "pass")
    base_artifact["reason"] = "coherent content mutation with regenerated closure"
    changed_artifact = resign_result(producer, base_artifact)
    vector = build_positive(producer, "eval-004-regenerated", result=changed_artifact)
    item = vector["resolvedResults"][0]
    ctx = fresh_context(producer, vector)
    digest = oracle_artifact_hash(item["artifact"])
    auth = oracle_verify(item["artifact"])
    candidate_auth = candidate_authentication(consumer, vector, ctx)
    decision = candidate_decision(consumer, producer, vector, ctx)
    obs = {"oracleHash": digest, "referenceHash": item["ref"]["contentHash"],
           "oracleHashMatchesReference": digest == item["ref"]["contentHash"],
           "oracleSignatureValid": auth, "candidateAuthenticateResult": candidate_auth,
           "candidateConsumerDecision": decision}
    outputs.append(result("EVAL-004", obs["oracleHashMatchesReference"] and auth and
        candidate_auth and decision == "pass", obs,
        [{"call": "candidate.authenticate_result", "output": candidate_auth},
         {"call": "candidate.evaluate", "output": decision}]))

    original = build_positive(producer, "eval-005-order")
    reordered = reversed_maps(original)
    original_artifact = original["resolvedResults"][0]["artifact"]
    reordered_artifact = reordered["resolvedResults"][0]["artifact"]
    minified = oracle_canonical(original_artifact)
    pretty_reparsed = json.loads(json.dumps(original_artifact, indent=3))
    ctx = fresh_context(producer, original)
    decision = candidate_decision(consumer, producer, reordered, ctx)
    obs = {"originalOracleHash": oracle_artifact_hash(original_artifact),
           "reorderedOracleHash": oracle_artifact_hash(reordered_artifact),
           "prettyReparsedOracleHash": oracle_artifact_hash(pretty_reparsed),
           "minifiedByteLength": len(minified), "prettyByteLength": len(json.dumps(original_artifact, indent=3)),
           "oracleHashUnchanged": oracle_artifact_hash(original_artifact) == oracle_artifact_hash(reordered_artifact) == oracle_artifact_hash(pretty_reparsed),
           "candidateConsumerDecision": decision}
    outputs.append(result("EVAL-005", obs["oracleHashUnchanged"] and decision == "pass", obs,
        [{"call": "candidate.evaluate(reversed-map object)", "output": decision}],
        notes=["Whitespace check reparses semantically identical JSON; exact raw-byte CF-5 admission is outside this object-model consumer API."]))

    unauthorized = producer.verify_result(
        producer.DID_REF, "pass", signer_key=producer.UNAUTHORIZED_AUTHORITY,
        signer_ref=producer.UNAUTHORIZED_AUTHORITY_REF,
    )
    vector = build_positive(producer, "eval-006-wrong-authority", result=unauthorized)
    item = vector["resolvedResults"][0]
    ctx = fresh_context(producer, vector)
    claimed_auth = oracle_verify(item["artifact"])
    trusted_match = item["artifact"]["signature"]["signer"] == ctx["verifyResultAuthorities"][1]["signer"]
    candidate_auth = candidate_authentication(consumer, vector, ctx)
    decision = candidate_decision(consumer, producer, vector, ctx)
    obs = {"oracleSignatureValidForClaimedSigner": claimed_auth,
           "artifactSigner": item["artifact"]["signature"]["signer"],
           "trustedSigner": ctx["verifyResultAuthorities"][1]["signer"],
           "trustedAuthorityMatches": trusted_match, "candidateAuthenticateResult": candidate_auth,
           "candidateConsumerDecision": decision, "intendedGuardReached": claimed_auth and not trusted_match and not candidate_auth}
    outputs.append(result("EVAL-006", claimed_auth and not trusted_match and not candidate_auth
        and decision == "error", obs,
        [{"call": "candidate.authenticate_result", "output": candidate_auth},
         {"call": "candidate.evaluate", "output": decision}]))

    vector = build_positive(producer, "eval-007-authority-twin", result=copy.deepcopy(unauthorized))
    item = vector["resolvedResults"][0]
    ctx = fresh_context(producer, vector)
    ctx["verifyResultAuthorities"][1]["signer"] = producer.UNAUTHORIZED_AUTHORITY_REF
    claimed_auth = oracle_verify(item["artifact"])
    trusted_match = item["artifact"]["signature"]["signer"] == ctx["verifyResultAuthorities"][1]["signer"]
    candidate_auth = candidate_authentication(consumer, vector, ctx)
    decision = candidate_decision(consumer, producer, vector, ctx)
    obs = {"oracleSignatureValid": claimed_auth, "trustedAuthorityMatches": trusted_match,
           "candidateAuthenticateResult": candidate_auth, "candidateConsumerDecision": decision}
    outputs.append(result("EVAL-007", claimed_auth and trusted_match and candidate_auth
        and decision == "pass", obs,
        [{"call": "candidate.authenticate_result", "output": candidate_auth},
         {"call": "candidate.evaluate", "output": decision}]))

    vector = build_positive(producer, "eval-008-nonce-reuse")
    ctx = fresh_context(producer, vector)
    runtime = consumer.PresenceEvaluationRuntime(ctx)
    first = consumer.evaluate(vector, ctx, runtime)
    second = consumer.evaluate(vector, ctx, runtime)
    obs = {"firstCandidateConsumerDecision": first, "secondCandidateConsumerDecision": second,
           "intendedGuardReached": first == "pass" and second == "error"}
    outputs.append(result("EVAL-008", first == "pass" and second == "error", obs,
        [{"call": "candidate.evaluate(first, shared runtime)", "output": first},
         {"call": "candidate.evaluate(second, shared runtime)", "output": second}]))

    artifact = producer.verify_result(producer.DID_REF, "pass")
    artifact = resign_result(producer, artifact, domain=WRONG_DOMAIN)
    vector = build_positive(producer, "eval-009-wrong-domain", result=artifact)
    item = vector["resolvedResults"][0]
    ctx = fresh_context(producer, vector)
    required_auth = oracle_verify(item["artifact"])
    wrong_auth = oracle_verify(item["artifact"], WRONG_DOMAIN)
    candidate_auth = candidate_authentication(consumer, vector, ctx)
    decision = candidate_decision(consumer, producer, vector, ctx)
    digest = oracle_artifact_hash(item["artifact"])
    obs = {"oracleHash": digest, "referenceHash": item["ref"]["contentHash"],
           "oracleHashMatchesReference": digest == item["ref"]["contentHash"],
           "signatureValidUnderInjectedWrongDomain": wrong_auth,
           "oracleSignatureValid": required_auth, "candidateAuthenticateResult": candidate_auth,
           "candidateConsumerDecision": decision,
           "intendedGuardReached": wrong_auth and not required_auth and not candidate_auth}
    outputs.append(result("EVAL-009", obs["oracleHashMatchesReference"] and wrong_auth and
        not required_auth and not candidate_auth and decision == "error", obs,
        [{"call": "candidate.authenticate_result", "output": candidate_auth},
         {"call": "candidate.evaluate", "output": decision}]))

    artifact = producer.verify_result(producer.DID_REF, "pass")
    artifact = resign_result(producer, artifact, raw_digest=True)
    vector = build_positive(producer, "eval-010-raw-digest", result=artifact)
    item = vector["resolvedResults"][0]
    ctx = fresh_context(producer, vector)
    digest = oracle_artifact_hash(item["artifact"])
    custom_payload = VERIFY_DOMAIN.encode("ascii") + bytes.fromhex(digest)
    raw_valid = verify_custom_preimage(item["artifact"], custom_payload)
    required_auth = oracle_verify(item["artifact"])
    candidate_auth = candidate_authentication(consumer, vector, ctx)
    decision = candidate_decision(consumer, producer, vector, ctx)
    obs = {"oracleHash": digest, "referenceHash": item["ref"]["contentHash"],
           "oracleHashMatchesReference": digest == item["ref"]["contentHash"],
           "signatureValidUnderInjectedRawDigestPreimage": raw_valid,
           "oracleSignatureValid": required_auth, "candidateAuthenticateResult": candidate_auth,
           "candidateConsumerDecision": decision,
           "intendedGuardReached": raw_valid and not required_auth and not candidate_auth}
    outputs.append(result("EVAL-010", obs["oracleHashMatchesReference"] and raw_valid and
        not required_auth and not candidate_auth and decision == "error", obs,
        [{"call": "candidate.authenticate_result", "output": candidate_auth},
         {"call": "candidate.evaluate", "output": decision}]))

    vector = build_positive(producer, "eval-011-algorithm")
    item = vector["resolvedResults"][0]
    original_hash = oracle_artifact_hash(item["artifact"])
    item["artifact"]["signature"]["algorithm"] = "Ed25519"
    digest = oracle_artifact_hash(item["artifact"])
    ctx = fresh_context(producer, vector)
    required_auth = oracle_verify(item["artifact"])
    candidate_auth = candidate_authentication(consumer, vector, ctx)
    decision = candidate_decision(consumer, producer, vector, ctx)
    obs = {"originalOracleHash": original_hash, "mutatedOracleHash": digest,
           "referenceHash": item["ref"]["contentHash"], "oracleHashUnchanged": digest == original_hash,
           "oracleHashMatchesReference": digest == item["ref"]["contentHash"],
           "oracleSignatureValid": required_auth, "candidateAuthenticateResult": candidate_auth,
           "candidateConsumerDecision": decision, "intendedGuardReached": not candidate_auth}
    outputs.append(result("EVAL-011", obs["oracleHashUnchanged"] and obs["oracleHashMatchesReference"]
        and not required_auth and not candidate_auth and decision == "error", obs,
        [{"call": "candidate.authenticate_result", "output": candidate_auth},
         {"call": "candidate.evaluate", "output": decision}]))

    vector = build_positive(producer, "cal-001-mutant")
    before = copy.deepcopy(vector["resolvedResults"][0]["artifact"])
    after = copy.deepcopy(before)
    corrupt_signature(after)
    correct_before = oracle_artifact_hash(before)
    correct_after = oracle_artifact_hash(after)
    mutant_before = oracle_hash(before)
    mutant_after = oracle_hash(after)
    detected = correct_before == correct_after and mutant_before != mutant_after
    obs = {"correctHashBefore": correct_before, "correctHashAfter": correct_after,
           "mutantFullObjectHashBefore": mutant_before, "mutantFullObjectHashAfter": mutant_after,
           "mutantHashChangesOnSignatureOnlyMutation": mutant_before != mutant_after,
           "defectDetected": detected,
           "candidateConsumerDecision": {"status": "not_applicable", "reason": "test-only mutant was not executed in candidate"}}
    outputs.append(result("CAL-001", detected, obs,
        [{"call": "test-only mutant full-object SHA-256", "output": mutant_before != mutant_after}],
        notes=["Calibration detects the historical full-signed-object hashing defect without modifying candidate code."]))
    return outputs


def validate_frozen_cases(document: dict[str, Any]) -> None:
    ids = [case.get("id") for case in document.get("cases", [])]
    if ids != EXPECTED_CASE_IDS:
        raise RuntimeError(f"case set changed or reordered: {ids!r}")
    if document.get("frozenBeforeRun") is not True:
        raise RuntimeError("cases are not marked frozen before run")


def validate_result_record(record: dict[str, Any], pin: dict[str, str],
                           cases: dict[str, Any], expected_results: list[dict[str, Any]]) -> None:
    errors = []
    expected_keys = {
        "schemaVersion", "evaluationId", "scope", "assuranceBoundary",
        "candidate", "casesSha256", "harnessSha256", "startedAtUnixNs",
        "completedAtUnixNs", "overallStatus", "results",
    }
    if set(record) != expected_keys:
        errors.append("result record fields are missing or unexpected")
    if record.get("schemaVersion") != "1":
        errors.append("result schema version is wrong")
    if record.get("evaluationId") != "dacs-standard-pr362-verifyresult-pilot-v1":
        errors.append("result evaluation ID is wrong")
    if record.get("scope") != cases.get("scope"):
        errors.append("result scope is stale or wrong")
    if record.get("assuranceBoundary") != "offline deterministic object-model evaluation; no network, chain, payment, delivery, or production effects":
        errors.append("result assurance boundary is stale or wrong")
    started = record.get("startedAtUnixNs")
    completed = record.get("completedAtUnixNs")
    if type(started) is not int or type(completed) is not int or completed < started:
        errors.append("result run timestamps are malformed")
    if record.get("candidate", {}).get("head") != pin["head"]:
        errors.append("result candidate head is stale or wrong")
    if record.get("candidate", {}).get("origin") != pin["origin"]:
        errors.append("result candidate origin is stale or wrong")
    if record.get("candidate", {}).get("base") != pin["base"]:
        errors.append("result candidate base is stale or wrong")
    if record.get("casesSha256") != sha256_file(CASES_PATH):
        errors.append("result case-set digest is stale or wrong")
    if record.get("harnessSha256") != sha256_file(Path(__file__)):
        errors.append("result harness digest is stale or wrong")
    result_ids = [item.get("caseId") for item in record.get("results", [])]
    if result_ids != EXPECTED_CASE_IDS:
        errors.append("result case IDs are incomplete, reordered, or stale")
    if record.get("overallStatus") != "pass":
        errors.append("result overall status differs from deterministic rerun")
    if record.get("results") != expected_results:
        errors.append("one or more stable case result fields differ from deterministic rerun")
    if errors:
        raise RuntimeError("; ".join(errors))


def verify_results(path: Path) -> None:
    pin = verify_candidate_pin()
    record = json.loads(path.read_text(encoding="utf-8"))
    cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    validate_frozen_cases(cases)
    consumer, producer = load_candidate_modules()
    expected_results = run_cases(consumer, producer)
    validate_result_record(record, pin, cases, expected_results)
    print(json.dumps({"status": "pass", "verifiedResult": str(path), "candidateHead": pin["head"]}, sort_keys=True))


def calibrate_grader(record: dict[str, Any], pin: dict[str, str], cases: dict[str, Any],
                     expected_results: list[dict[str, Any]]) -> dict[str, Any]:
    scenarios: list[tuple[str, str, Callable[[dict[str, Any]], None]]] = [
        ("GRADER-001", "overallStatus changed to fail",
         lambda value: value.__setitem__("overallStatus", "fail")),
        ("GRADER-002", "EVAL-001 status changed to fail",
         lambda value: value["results"][0].__setitem__("status", "fail")),
        ("GRADER-003", "EVAL-001 observations emptied",
         lambda value: value["results"][0].__setitem__("observations", {})),
        ("GRADER-004", "one case result deleted",
         lambda value: value["results"].pop()),
        ("GRADER-005", "two case results reordered",
         lambda value: value["results"].__setitem__(slice(0, 2), list(reversed(value["results"][:2])))),
        ("GRADER-006", "candidate head changed",
         lambda value: value["candidate"].__setitem__("head", "0" * 40)),
        ("GRADER-007", "candidate origin changed",
         lambda value: value["candidate"].__setitem__("origin", "https://example.invalid/wrong.git")),
    ]
    rows = []
    validate_result_record(copy.deepcopy(record), pin, cases, expected_results)
    for case_id, mutation, mutate in scenarios:
        tampered = copy.deepcopy(record)
        mutate(tampered)
        rejected = False
        error = None
        try:
            validate_result_record(tampered, pin, cases, expected_results)
        except RuntimeError as exc:
            rejected = True
            error = str(exc)
        rows.append({
            "caseId": case_id, "mutation": mutation, "expected": "rejected",
            "actual": "rejected" if rejected else "accepted", "status": "pass" if rejected else "fail",
            "evidence": error,
        })
    return {
        "schemaVersion": "1",
        "scope": "Result-verifier calibration only; distinct from the 12 protocol evaluation cases.",
        "beforeFixFinding": "The prior metadata-only verifier could accept altered overall/case statuses and empty observations when pins and case IDs remained unchanged.",
        "afterFixBehavior": "The verifier reruns all deterministic cases in memory and compares every stable case result field; only run timestamps vary.",
        "untamperedBaseline": {"expected": "accepted", "actual": "accepted", "status": "pass"},
        "cases": rows,
        "overallStatus": "pass" if all(row["status"] == "pass" for row in rows) else "fail",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-results", type=Path)
    args = parser.parse_args()
    if args.verify_results:
        verify_results(args.verify_results)
        return 0

    started_ns = time.time_ns()
    pin = verify_candidate_pin()
    cases_doc = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    validate_frozen_cases(cases_doc)
    cases_digest = sha256_file(CASES_PATH)
    harness_digest = sha256_file(Path(__file__))
    consumer, producer = load_candidate_modules()
    case_results = run_cases(consumer, producer)
    overall = "pass" if all(item["status"] == "pass" for item in case_results) else "fail"
    record = {
        "schemaVersion": "1", "evaluationId": "dacs-standard-pr362-verifyresult-pilot-v1",
        "scope": cases_doc["scope"], "assuranceBoundary": "offline deterministic object-model evaluation; no network, chain, payment, delivery, or production effects",
        "candidate": {"origin": pin["origin"], "head": pin["head"], "base": pin["base"]},
        "casesSha256": cases_digest, "harnessSha256": harness_digest,
        "startedAtUnixNs": started_ns, "completedAtUnixNs": time.time_ns(),
        "overallStatus": overall, "results": case_results,
    }
    RESULTS_PATH.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    grader_calibration = calibrate_grader(record, pin, cases_doc, case_results)
    GRADER_CALIBRATION_PATH.write_text(
        json.dumps(grader_calibration, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest = {
        "schemaVersion": "1", "evaluationId": record["evaluationId"],
        "candidate": record["candidate"],
        "command": [sys.executable, str(Path(__file__))],
        "verificationCommand": [sys.executable, str(Path(__file__)), "--verify-results", str(RESULTS_PATH)],
        "runtime": {"python": platform.python_version(), "pythonExecutable": sys.executable,
                    "implementation": platform.python_implementation(),
                    "cryptography": importlib.metadata.version("cryptography"),
                    "platform": platform.platform()},
        "permissions": {"network": False, "liveSystems": False,
                        "candidateWrites": False, "outputRoot": str(OUTPUT)},
        "oracleScope": "Independent stdlib canonicalizer restricted to recursively safe ASCII strings/member names, booleans/null, arrays/objects, and integer JSON numbers with |n| <= 2^53-1. Floats and non-ASCII are rejected. In this domain Python Unicode sorting equals JCS UTF-16 sorting and stdlib integer serialization equals JCS.",
        "digests": {
            str(CASES_PATH): cases_digest,
            str(Path(__file__)): harness_digest,
            str(CANDIDATE / "tests" / "test_presence_only_claim_vectors.py"): sha256_file(CANDIDATE / "tests" / "test_presence_only_claim_vectors.py"),
            str(CANDIDATE / "scripts" / "generate_presence_only_claim_vectors.py"): sha256_file(CANDIDATE / "scripts" / "generate_presence_only_claim_vectors.py"),
            str(CANDIDATE / "spec" / "CORE.md"): sha256_file(CANDIDATE / "spec" / "CORE.md"),
            str(CANDIDATE / "spec" / "DACS-2-VET.md"): sha256_file(CANDIDATE / "spec" / "DACS-2-VET.md"),
            str(CANDIDATE / "conformance" / "vectors" / "security" / "presence-only-claim-requirement-v0.7.json"): sha256_file(CANDIDATE / "conformance" / "vectors" / "security" / "presence-only-claim-requirement-v0.7.json"),
            str(RESULTS_PATH): sha256_file(RESULTS_PATH),
            str(GRADER_CALIBRATION_PATH): sha256_file(GRADER_CALIBRATION_PATH),
        },
        "caseFreeze": {"casesMtimeUnixNs": CASES_PATH.stat().st_mtime_ns,
                       "runStartedAtUnixNs": started_ns,
                       "frozenBeforeRun": CASES_PATH.stat().st_mtime_ns <= started_ns},
        "statusVocabulary": cases_doc["statusVocabulary"],
        "limitations": [
            "Narrow pilot only; PR #362 changes additional Standard surfaces that are not evaluated here.",
            "The actual consumer accepts parsed Python objects; this pilot does not claim CORE CF-5 raw-byte admission coverage.",
            "The independent canonical oracle deliberately rejects non-ASCII and fractional-number cases rather than claiming full RFC 8785 coverage.",
            "No payment, delivery, chain, network, latency, memory, or production behavior was exercised.",
            "Per-case forbiddenEffectsObserved records the asserted protocol decision guard only; the harness does not provide general filesystem, network, payment, or delivery effect tracing.",
            "Evaluation evidence is not a contributor approval, maintainer approval, merge gate, or release authorization."
        ]
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"overallStatus": overall, "caseCount": len(case_results),
                      "results": str(RESULTS_PATH), "graderCalibration": str(GRADER_CALIBRATION_PATH),
                      "manifest": str(MANIFEST_PATH)}, sort_keys=True))
    return 0 if overall == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
