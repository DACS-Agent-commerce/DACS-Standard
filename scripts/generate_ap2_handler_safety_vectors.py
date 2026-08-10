#!/usr/bin/env python3
"""Generate the candidate AP2-6/AP2-7 handler-safety vector family."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import unicodedata
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance" / "vectors" / "security" / "ap2-handler-safety-v0.5.json"
DOMAIN = b"dacs-ap2-idem:v1:"


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def derive_key(job_id: str, phase_index: int) -> str:
    if not isinstance(job_id, str) or not job_id:
        raise ValueError("jobId must be a non-empty string")
    if type(phase_index) is not int or phase_index < 0:
        raise ValueError("phaseIndex must be a non-negative integer")
    preimage = (
        DOMAIN
        + unicodedata.normalize("NFC", job_id).encode("utf-8")
        + b":"
        + str(phase_index).encode("ascii")
    )
    return hashlib.sha256(preimage).hexdigest()


def key_case(name: str, job_id: object, phase_index: object, expected: str, note: str,
             *, normalized_job_id: str | None = None) -> dict[str, object]:
    case: dict[str, object] = {
        "name": name,
        "op": "derive-idempotency-key",
        "jobId": job_id,
        "phaseIndex": phase_index,
        "expected": expected,
        "note": note,
    }
    if expected == "pass":
        case["expectedKey"] = derive_key(job_id, phase_index)  # type: ignore[arg-type]
    if normalized_job_id is not None:
        case["normalizedJobId"] = normalized_job_id
    return case


def binding(transaction_id: str, job_id: str, phase_index: int, state: str) -> dict[str, object]:
    return {
        "transactionId": transaction_id,
        "jobId": job_id,
        "phaseIndex": phase_index,
        "state": state,
    }


def vectors() -> list[dict[str, object]]:
    job_a = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    job_b = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
    tx = "NivWhuqfzcvZNapvIEJ2-3tsdQLkiuIcye2g46WVgX8"
    return [
        key_case(
            "ap2-key-base", job_a, 3, "pass",
            "the same session phase always derives the same lower-case 64-hex provider key",
        ),
        key_case(
            "ap2-key-phase-separation", job_a, 4, "pass",
            "a repeated AP2 phase receives a distinct provider key",
        ),
        key_case(
            "ap2-key-job-separation", job_b, 3, "pass",
            "a different job receives a distinct provider key at the same phase index",
        ),
        key_case(
            "ap2-key-nfc-normalization", "cafe\u0301-job", 0, "pass",
            "decomposed and composed job identifiers derive identical bytes",
            normalized_job_id="caf\u00e9-job",
        ),
        key_case(
            "ap2-key-negative-phase-error", job_a, -1, "error",
            "a negative phase index refuses before hashing",
        ),
        key_case(
            "ap2-key-string-phase-error", job_a, "03", "error",
            "a textual phase index cannot introduce a non-minimal decimal spelling",
        ),
        {
            "name": "ap2-first-presentation-binds",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [],
            "expected": "pass",
            "want": {"action": "bind-new", "submitNewPayment": True},
            "note": "the first valid presentation atomically reserves the transaction for this tuple",
        },
        {
            "name": "ap2-same-tuple-inflight-resumes",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [binding(tx, job_a, 3, "in-flight")],
            "expected": "pass",
            "want": {"action": "resume-existing", "submitNewPayment": False},
            "note": "an exact retry resumes with the same AP2-6 key rather than becoming replay",
        },
        {
            "name": "ap2-same-tuple-settled-resumes-evidence",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [binding(tx, job_a, 3, "settled")],
            "expected": "pass",
            "want": {"action": "resume-settlement", "submitNewPayment": False},
            "note": "a settled retry reuses the existing provider result and never counts twice",
        },
        {
            "name": "ap2-cross-job-replay-rejects",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_b,
            "phaseIndex": 3,
            "priorBindings": [binding(tx, job_a, 3, "in-flight")],
            "expected": "fail",
            "want": {"action": "reject-replay", "submitNewPayment": False},
            "note": "one checkout transaction cannot authorize a different DACS session",
        },
        {
            "name": "ap2-cross-phase-replay-rejects",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 4,
            "priorBindings": [binding(tx, job_a, 3, "in-flight")],
            "expected": "fail",
            "want": {"action": "reject-replay", "submitNewPayment": False},
            "note": "one checkout transaction cannot settle two repeated phases in a session",
        },
        {
            "name": "ap2-conflicting-stored-bindings-error",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [
                binding(tx, job_a, 3, "in-flight"),
                binding(tx, job_b, 3, "in-flight"),
            ],
            "expected": "error",
            "want": {"action": "refuse-conflict", "submitNewPayment": False},
            "note": "a corrupt or racy binding store fails closed instead of selecting a winner",
        },
        {
            "name": "ap2-checkout-randomized-signature-pass",
            "op": "checkout-signature-policy",
            "algorithm": "ES256",
            "signatureGeneration": "non-deterministic",
            "expected": "pass",
            "note": "the merchant checkout JWT satisfies the upstream AP2 v0.2 property",
        },
        {
            "name": "ap2-checkout-ed25519-reject",
            "op": "checkout-signature-policy",
            "algorithm": "Ed25519",
            "signatureGeneration": "deterministic",
            "expected": "fail",
            "note": "AP2 v0.2 explicitly excludes deterministic Ed25519 for the merchant checkout JWT",
        },
        {
            "name": "ap2-checkout-deterministic-ecdsa-reject",
            "op": "checkout-signature-policy",
            "algorithm": "ES256",
            "signatureGeneration": "deterministic",
            "expected": "fail",
            "note": "the security property is non-deterministic generation, not an algorithm label alone",
        },
        {
            "name": "ap2-split-credentials-registration-pass",
            "op": "registration-eligibility",
            "createCredential": True,
            "statusOnlyCredential": True,
            "credentialsDistinct": True,
            "createCredentialRelayed": False,
            "expected": "pass",
            "note": "the privileged key stays local and a distinct status-only key may transit SR-3",
        },
        {
            "name": "ap2-missing-status-credential-reject",
            "op": "registration-eligibility",
            "createCredential": True,
            "statusOnlyCredential": False,
            "credentialsDistinct": True,
            "createCredentialRelayed": False,
            "expected": "fail",
            "note": "an integration unable to provision status-only access cannot register pay-ap2",
        },
        {
            "name": "ap2-shared-provider-credential-reject",
            "op": "registration-eligibility",
            "createCredential": True,
            "statusOnlyCredential": True,
            "credentialsDistinct": False,
            "createCredentialRelayed": False,
            "expected": "fail",
            "note": "one credential cannot serve both the privileged and relayed scopes",
        },
        {
            "name": "ap2-privileged-credential-relayed-reject",
            "op": "registration-eligibility",
            "createCredential": True,
            "statusOnlyCredential": True,
            "credentialsDistinct": True,
            "createCredentialRelayed": True,
            "expected": "fail",
            "note": "a credential capable of creating or moving value must never transit SR-3",
        },
    ]


def render() -> str:
    cases = vectors()
    document = {
        "set": "ap2-handler-safety-v0.5",
        "spec": "DACS-4 §9.5.6 AP2-3/AP2-6/AP2-7",
        "scope": (
            "candidate handler predicates: key derivation and retry/replay consumption are "
            "executed; provider capability and checkout signature generation are modeled inputs"
        ),
        "hash": hashlib.sha256(canonical_json(cases)).hexdigest(),
        "count": len(cases),
        "vectors": cases,
    }
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    expected = render()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != expected:
            print(f"ERROR: {OUTPUT.relative_to(ROOT)} is not deterministic; run with --write", file=sys.stderr)
            return 1
        print(f"verified {OUTPUT.relative_to(ROOT)}")
        return 0
    OUTPUT.write_text(expected, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
