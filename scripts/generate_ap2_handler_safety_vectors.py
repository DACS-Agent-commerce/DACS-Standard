#!/usr/bin/env python3
"""Generate the candidate AP2 checkout/admission handler-safety vectors."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance" / "vectors" / "security" / "ap2-handler-safety-v0.6.json"
DOMAIN = b"dacs-ap2-idem:v1:"
MISSING = object()
COMPACT_JWS_RE = re.compile(
    r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\Z"
)
HASH_ALGORITHMS = {
    "sha-256": hashlib.sha256,
}


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


def base64url_nopad(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def derive_transaction_id(checkout_jws: object, sd_alg: object = MISSING) -> str:
    """Apply the DACS AP2 digest selection to exact compact-JWS bytes."""
    if (
        not isinstance(checkout_jws, str)
        or not COMPACT_JWS_RE.fullmatch(checkout_jws)
    ):
        raise ValueError("checkoutJws must be an unpadded RFC 7515 compact JWS")
    algorithm = "sha-256" if sd_alg is MISSING else sd_alg
    if not isinstance(algorithm, str) or algorithm not in HASH_ALGORITHMS:
        raise ValueError("_sd_alg is unsupported")
    digest = HASH_ALGORITHMS[algorithm](checkout_jws.encode("ascii")).digest()
    return base64url_nopad(digest)


def transaction_id_case(
    name: str,
    checkout_jws: object,
    expected: str,
    case_class: str,
    note: str,
    *,
    sd_alg: object = MISSING,
    different_from_transaction_id: str | None = None,
) -> dict[str, object]:
    case: dict[str, object] = {
        "name": name,
        "op": "derive-transaction-id",
        "caseClass": case_class,
        "checkoutJws": checkout_jws,
        "expected": expected,
        "note": note,
    }
    if sd_alg is not MISSING:
        case["_sd_alg"] = sd_alg
    if expected == "pass":
        case["expectedTransactionId"] = derive_transaction_id(checkout_jws, sd_alg)
    if different_from_transaction_id is not None:
        case["differentFromTransactionId"] = different_from_transaction_id
    return case


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
    header = base64url_nopad(b'{"alg":"ES256","typ":"JWT"}')
    payload = base64url_nopad(
        b'{"checkout_id":"checkout-123","currency":"USD","total":"10.00"}'
    )
    signature = base64url_nopad(bytes(range(1, 65)))
    changed_signature = base64url_nopad(bytes(range(1, 64)) + b"A")
    checkout_jws = f"{header}.{payload}.{signature}"
    changed_signature_jws = f"{header}.{payload}.{changed_signature}"
    tx = derive_transaction_id(checkout_jws)
    changed_signature_tx = derive_transaction_id(changed_signature_jws)
    admission_common: dict[str, object] = {
        "op": "checkout-payment-admission",
        "checkoutMandatePresent": True,
        "checkoutMandateVerified": True,
        "paymentMandatePresent": True,
        "paymentMandateVerified": True,
        "checkoutJws": checkout_jws,
        "algorithm": "ES256",
        "signatureGeneration": "non-deterministic",
        "paymentTransactionId": tx,
    }
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
        transaction_id_case(
            "ap2-transaction-id-sha256-default",
            checkout_jws,
            "pass",
            "positive",
            "an absent CheckoutMandate _sd_alg selects SHA-256 over the exact compact JWS bytes",
        ),
        transaction_id_case(
            "ap2-transaction-id-sha256-explicit",
            checkout_jws,
            "pass",
            "boundary",
            "an explicit CheckoutMandate _sd_alg selects the required SHA-256 algorithm",
            sd_alg="sha-256",
        ),
        transaction_id_case(
            "ap2-transaction-id-signature-byte-change",
            changed_signature_jws,
            "pass",
            "boundary",
            "changing only the merchant signature bytes changes transaction_id",
            different_from_transaction_id=tx,
        ),
        transaction_id_case(
            "ap2-transaction-id-unsupported-algorithm-error",
            checkout_jws,
            "error",
            "negative",
            "an unsupported CheckoutMandate _sd_alg refuses before admission",
            sd_alg="dacs-unknown-hash",
        ),
        transaction_id_case(
            "ap2-transaction-id-malformed-compact-jws-error",
            "header.payload",
            "error",
            "negative",
            "a value that is not an unpadded three-segment compact JWS refuses before hashing",
        ),
        {
            **admission_common,
            "name": "ap2-admission-complete-chain-match",
            "caseClass": "positive",
            "expected": "pass",
            "want": {
                "derivedTransactionId": tx,
                "reserveAp2Binding": True,
                "submitProviderPayment": True,
            },
            "note": (
                "separate verified CheckoutMandate and PaymentMandate artifacts with a "
                "matching digest admit side effects"
            ),
        },
        {
            **admission_common,
            "name": "ap2-admission-transaction-id-mismatch",
            "caseClass": "negative",
            "paymentTransactionId": changed_signature_tx,
            "expected": "fail",
            "want": {
                "derivedTransactionId": tx,
                "reserveAp2Binding": False,
                "submitProviderPayment": False,
            },
            "note": (
                "a PaymentMandate mismatch rejects before AP2-7 reservation or provider "
                "submission"
            ),
        },
        {
            **admission_common,
            "name": "ap2-admission-checkout-mandate-missing",
            "caseClass": "negative",
            "checkoutMandatePresent": False,
            "checkoutMandateVerified": False,
            "expected": "fail",
            "want": {
                "reserveAp2Binding": False,
                "submitProviderPayment": False,
            },
            "note": "a standalone PaymentMandate is not a complete AP2 checkout chain",
        },
        {
            **admission_common,
            "name": "ap2-admission-payment-mandate-missing",
            "caseClass": "negative",
            "paymentMandatePresent": False,
            "paymentMandateVerified": False,
            "expected": "fail",
            "want": {
                "reserveAp2Binding": False,
                "submitProviderPayment": False,
            },
            "note": "a CheckoutMandate alone cannot authorize payment",
        },
        {
            **admission_common,
            "name": "ap2-admission-deterministic-signature-rejects",
            "caseClass": "negative",
            "algorithm": "Ed25519",
            "signatureGeneration": "deterministic",
            "expected": "fail",
            "want": {
                "reserveAp2Binding": False,
                "submitProviderPayment": False,
            },
            "note": "the DACS strict signature profile is enforced before either side effect",
        },
        {
            **admission_common,
            "name": "ap2-admission-unsupported-algorithm-errors",
            "caseClass": "boundary",
            "_sd_alg": "dacs-unknown-hash",
            "expected": "error",
            "want": {
                "reserveAp2Binding": False,
                "submitProviderPayment": False,
            },
            "note": "unsupported digest selection fails before AP2-7 reservation or provider submission",
        },
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
            "note": "the merchant checkout JWT satisfies the DACS strict AP2 signature profile",
        },
        {
            "name": "ap2-checkout-ed25519-reject",
            "op": "checkout-signature-policy",
            "algorithm": "Ed25519",
            "signatureGeneration": "deterministic",
            "expected": "fail",
            "note": "DACS chooses AP2 v0.2's stricter branch and rejects deterministic Ed25519",
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
        "set": "ap2-handler-safety-v0.6",
        "spec": "DACS-4 v0.6 §9.5.6 checkout admission + AP2-3/AP2-6/AP2-7",
        "scope": (
            "candidate handler predicates: idempotency-key and transaction-id derivation, "
            "checkout/payment admission ordering, and retry/replay consumption are executed; "
            "provider capability, mandate cryptographic verification, and signature generation "
            "are modeled inputs"
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
