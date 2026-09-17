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
JOB_ID_RE = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}\Z", re.ASCII)


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def derive_key(job_id: str, phase_index: int) -> str:
    if not isinstance(job_id, str) or JOB_ID_RE.fullmatch(job_id) is None:
        raise ValueError("jobId must satisfy JID-1")
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


def key_case(name: str, job_id: object, phase_index: object, expected: str,
             note: str) -> dict[str, object]:
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
    return case


def fixture_provider_request(job_id):
    """Deterministic local provider request; never used as a consumer fallback."""
    return {
        "providerEndpoint": "https://provider.example.invalid/payments",
        "paymentMandate": "fixture-payment-mandate-v1",
        "checkoutId": "checkout-123",
        "payee": "merchant-fixture",
        "amount": "10.00",
        "currency": "USD",
        "instrument": "fixture-instrument-1",
        "metadata": {"dacs_job_id": job_id},
    }


def operation_payload(transaction_id, job_id, phase_index, provider_request):
    """Bind the complete effect-bearing provider request, including metadata."""
    return {
        "transactionId": transaction_id,
        "jobId": job_id,
        "phaseIndex": phase_index,
        "providerRequest": provider_request,
    }


def operation_fingerprint(payload: object) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def binding(
    transaction_id: str,
    job_id: str,
    phase_index: int,
    state: str,
    *,
    provider_recovery_reference: str | None = None,
    settlement: dict[str, object] | None = None,
    payload: dict[str, object] | None = None,
    idempotency_key: str | None = None,
    fingerprint: str | None = None,
) -> dict[str, object]:
    exact_payload = operation_payload(transaction_id, job_id, phase_index, fixture_provider_request(job_id)) if payload is None else payload
    result: dict[str, object] = {
        "transactionId": transaction_id,
        "jobId": job_id,
        "phaseIndex": phase_index,
        "state": state,
        "idempotencyKey": derive_key(job_id, phase_index) if idempotency_key is None else idempotency_key,
        "operationFingerprint": operation_fingerprint(exact_payload) if fingerprint is None else fingerprint,
        "operationPayload": exact_payload,
    }
    if provider_recovery_reference is not None:
        result["providerRecoveryReference"] = provider_recovery_reference
    if state == "settled" and settlement is None:
        settlement = {"status": "captured", "transactionId": transaction_id, "operationFingerprint": operation_fingerprint(exact_payload)}
    if settlement is not None:
        result["settlement"] = settlement
    return result


def admission_want(
    *,
    hash_calls: int = 0,
    resolver_calls: int = 0,
    metadata_calls: int = 0,
    binding_store_calls: int = 0,
    provider_status_calls: int = 0,
    provider_request_calls: int | None = None,
    binding_action: str | None = None,
    reserve: bool = False,
    submit: bool = False,
    submit_new: bool | None = None,
    idempotency_key: str | None = None,
    derived_transaction_id: object = MISSING,
) -> dict[str, object]:
    operation_order: list[str] = []
    if binding_store_calls:
        operation_order.append("atomicBindingStoreDecision")
    if provider_status_calls:
        operation_order.append("fetchProviderStatus")
    if metadata_calls:
        operation_order.append("constructProviderMetadata")
    if submit:
        operation_order.append("submitProviderPayment")
    want: dict[str, object] = {
        "hashCalls": hash_calls,
        "resolverCalls": resolver_calls,
        "metadataCalls": metadata_calls,
        "bindingStoreCalls": binding_store_calls,
        "providerStatusCalls": provider_status_calls,
        "providerRequestCalls": (
            int(submit) if provider_request_calls is None else provider_request_calls
        ),
        "bindingAction": binding_action,
        "operationOrder": operation_order,
        "reserveAp2Binding": reserve,
        "submitProviderPayment": submit,
        "submitNewPayment": submit if submit_new is None else submit_new,
        "idempotencyKeys": [idempotency_key] if idempotency_key is not None else [],
    }
    if derived_transaction_id is not MISSING:
        want["derivedTransactionId"] = derived_transaction_id
    return want


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
        "jobId": job_a,
        "phaseIndex": 3,
        "peerIdentity": "did:demos:agent:" + "22" * 32,
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
            "ap2-key-noncanonical-unicode-error", "cafe\u0301-job", 0, "error",
            "a decomposed non-JID-1 identifier refuses before hashing",
        ),
        key_case(
            "ap2-key-overflow-job-error", "8" + job_a[1:], 0, "error",
            "a 130-bit overflow-form ULID refuses before hashing",
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
            "want": admission_want(
                hash_calls=2,
                resolver_calls=1,
                metadata_calls=1,
                binding_store_calls=1,
                binding_action="bind-new",
                reserve=True,
                submit=True,
                idempotency_key=derive_key(job_a, 3),
                derived_transaction_id=tx,
            ),
            "note": (
                "separate verified CheckoutMandate and PaymentMandate artifacts with a "
                "matching digest admit side effects"
            ),
        },
        {
            **admission_common,
            "name": "ap2-composed-same-tuple-inflight-resumes",
            "caseClass": "positive",
            "expected": "pass",
            "want": admission_want(
                hash_calls=2,
                resolver_calls=1,
                binding_store_calls=1,
                binding_action="resubmit-same-key",
                submit=True,
                submit_new=False,
                idempotency_key=derive_key(job_a, 3),
                derived_transaction_id=tx,
            ),
            "note": (
                "the composed handler re-dispatches the retained in-flight operation "
                "with its exact AP2-6 key and no new-payment authority"
            ),
        },
        {
            **admission_common,
            "name": "ap2-composed-same-tuple-settled-resumes",
            "caseClass": "positive",
            "expected": "pass",
            "want": admission_want(
                hash_calls=2,
                resolver_calls=1,
                binding_store_calls=1,
                binding_action="resume-settlement",
                derived_transaction_id=tx,
            ),
            "note": (
                "the composed handler resolves a settled exact-tuple retry without "
                "metadata construction or another provider payment"
            ),
        },
        {
            **admission_common,
            "name": "ap2-recovery-lost-response-resubmits-same-key",
            "caseClass": "positive",
            "expected": "pass",
            "want": admission_want(
                hash_calls=2,
                resolver_calls=1,
                binding_store_calls=1,
                binding_action="resubmit-same-key",
                submit=True,
                submit_new=False,
                idempotency_key=derive_key(job_a, 3),
                derived_transaction_id=tx,
            ),
            "note": (
                "an ambiguous lost response is retried with the retained exact operation "
                "and AP2-6 key, without a new payment authorization"
            ),
        },
        {
            **admission_common,
            "name": "ap2-recovery-reference-reconciles-captured",
            "caseClass": "positive",
            "expected": "pass",
            "providerStatus": "captured",
            "want": admission_want(
                hash_calls=2,
                resolver_calls=1,
                binding_store_calls=1,
                provider_status_calls=1,
                binding_action="resume-settlement",
                derived_transaction_id=tx,
            ),
            "note": "a retained provider reference reconciles captured status into reusable settlement",
        },
        {
            **admission_common,
            "name": "ap2-recovery-reference-not-captured-resubmits-same-key",
            "caseClass": "boundary",
            "expected": "pass",
            "providerStatus": "not-captured",
            "want": admission_want(
                hash_calls=2,
                resolver_calls=1,
                binding_store_calls=1,
                provider_status_calls=1,
                binding_action="resubmit-same-key",
                submit=True,
                submit_new=False,
                idempotency_key=derive_key(job_a, 3),
                derived_transaction_id=tx,
            ),
            "note": (
                "confirmed non-capture permits only a same-key same-operation provider "
                "request, never a distinct payment authorization"
            ),
        },
        {
            **admission_common,
            "name": "ap2-composed-cross-job-replay-refuses",
            "caseClass": "negative",
            "jobId": job_b,
            "expected": "fail",
            "want": admission_want(
                hash_calls=2,
                resolver_calls=1,
                binding_store_calls=1,
                binding_action="reject-replay",
                derived_transaction_id=tx,
            ),
            "note": (
                "a valid current-profile presentation for another session is rejected "
                "by the authoritative store before provider work"
            ),
        },
        {
            **admission_common,
            "name": "ap2-composed-cross-phase-replay-refuses",
            "caseClass": "negative",
            "phaseIndex": 4,
            "expected": "fail",
            "want": admission_want(
                hash_calls=2,
                resolver_calls=1,
                binding_store_calls=1,
                binding_action="reject-replay",
                derived_transaction_id=tx,
            ),
            "note": (
                "a valid presentation at another phase is rejected by the authoritative "
                "store before provider work"
            ),
        },
        {
            **admission_common,
            "name": "ap2-composed-duplicate-bindings-refuse",
            "caseClass": "negative",
            "expected": "error",
            "want": admission_want(
                hash_calls=2,
                resolver_calls=1,
                binding_store_calls=1,
                binding_action="refuse-conflict",
                derived_transaction_id=tx,
            ),
            "note": "duplicate authoritative entries fail closed before provider work",
        },
        {
            **admission_common,
            "name": "ap2-composed-conflicting-bindings-refuse",
            "caseClass": "negative",
            "expected": "error",
            "want": admission_want(
                hash_calls=2,
                resolver_calls=1,
                binding_store_calls=1,
                binding_action="refuse-conflict",
                derived_transaction_id=tx,
            ),
            "note": "conflicting authoritative entries fail closed before provider work",
        },
        {
            **admission_common,
            "name": "ap2-composed-caller-store-assertion-cannot-authorize",
            "caseClass": "negative",
            "priorBindings": [],
            "expected": "pass",
            "want": admission_want(
                hash_calls=2,
                resolver_calls=1,
                binding_store_calls=1,
                binding_action="resubmit-same-key",
                submit=True,
                submit_new=False,
                idempotency_key=derive_key(job_a, 3),
                derived_transaction_id=tx,
            ),
            "note": (
                "a caller-supplied empty-store assertion is ignored; the handler-owned "
                "in-flight binding permits only exact retained-operation same-key recovery"
            ),
        },
        {
            **admission_common,
            "name": "ap2-admission-transaction-id-mismatch",
            "caseClass": "negative",
            "paymentTransactionId": changed_signature_tx,
            "expected": "fail",
            "want": admission_want(
                hash_calls=2,
                resolver_calls=1,
                derived_transaction_id=tx,
            ),
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
            "want": admission_want(),
            "note": "a standalone PaymentMandate is not a complete AP2 checkout chain",
        },
        {
            **admission_common,
            "name": "ap2-admission-payment-mandate-missing",
            "caseClass": "negative",
            "paymentMandatePresent": False,
            "paymentMandateVerified": False,
            "expected": "fail",
            "want": admission_want(),
            "note": "a CheckoutMandate alone cannot authorize payment",
        },
        {
            **admission_common,
            "name": "ap2-admission-deterministic-signature-rejects",
            "caseClass": "negative",
            "algorithm": "Ed25519",
            "signatureGeneration": "deterministic",
            "expected": "fail",
            "want": admission_want(),
            "note": "the DACS strict signature profile is enforced before either side effect",
        },
        {
            **admission_common,
            "name": "ap2-admission-unsupported-algorithm-errors",
            "caseClass": "boundary",
            "_sd_alg": "dacs-unknown-hash",
            "expected": "error",
            "want": admission_want(hash_calls=1, resolver_calls=1),
            "note": "unsupported digest selection fails before AP2-7 reservation or provider submission",
        },
        {
            **admission_common,
            "name": "ap2-admission-noncanonical-job-errors",
            "caseClass": "negative",
            "jobId": "cafe\u0301-job",
            "expected": "error",
            "want": admission_want(),
            "note": "a non-JID-1 session refuses before hashes, resolution, metadata, binding, or provider calls",
        },
        {
            **admission_common,
            "name": "ap2-admission-overflow-job-errors",
            "caseClass": "boundary",
            "jobId": "8" + job_a[1:],
            "expected": "error",
            "want": admission_want(),
            "note": "an overflow-form ULID refuses before every modeled job-specific effect",
        },
        {
            **admission_common,
            "name": "ap2-admission-negative-phase-errors",
            "caseClass": "boundary",
            "phaseIndex": -1,
            "expected": "error",
            "want": admission_want(),
            "note": "an invalid phase index refuses before every modeled job-specific effect",
        },
        {
            **admission_common,
            "name": "ap2-admission-unauthenticated-profile-refuses",
            "caseClass": "negative",
            "expected": "fail",
            "want": admission_want(),
            "note": "trusted context that does not authenticate the expected peer refuses before protocol action",
        },
        {
            **admission_common,
            "name": "ap2-admission-caller-profile-refuses",
            "caseClass": "negative",
            "peerProfile": {
                "releasePin": "0000000000000000000000000000000000000001",
                "moduleVersions": {
                    "core": "0.3",
                    "dacs1": "0.8",
                    "dacs2": "0.6",
                    "dacs3": "0.6",
                    "dacs4": "0.8",
                    "dacs5": "0.6",
                },
            },
            "expected": "fail",
            "want": admission_want(),
            "note": "matching caller-supplied profile bytes do not substitute for authenticated peer evidence",
        },
        {
            **admission_common,
            "name": "ap2-admission-duplicate-profile-refuses",
            "caseClass": "negative",
            "expected": "fail",
            "want": admission_want(),
            "note": "duplicate authenticated records for the expected peer fail closed before protocol action",
        },
        {
            **admission_common,
            "name": "ap2-admission-peer-identity-mismatch-refuses",
            "caseClass": "negative",
            "expected": "fail",
            "want": admission_want(),
            "note": "a current profile authenticated for a different peer cannot authorize this participant",
        },
        {
            **admission_common,
            "name": "ap2-admission-session-mismatch-refuses",
            "caseClass": "negative",
            "expected": "fail",
            "want": admission_want(),
            "note": "profile evidence authenticated for another session cannot authorize AP2 effects",
        },
        {
            **admission_common,
            "name": "ap2-admission-copied-profile-reference-refuses",
            "caseClass": "negative",
            "peerProfileRef": "fixture:peer-current",
            "expected": "fail",
            "want": admission_want(),
            "note": "a caller cannot copy a locally meaningful label to manufacture trusted context",
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
            "want": {"action": "resubmit-same-key", "submitNewPayment": False},
            "note": "an exact retry re-dispatches the retained operation with the same AP2-6 key and no new-payment authority",
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
            "name": "ap2-recovery-pending-without-reference-resubmits-same-key",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [binding(tx, job_a, 3, "recovery-pending")],
            "expected": "pass",
            "want": {"action": "resubmit-same-key", "submitNewPayment": False},
            "note": "lost response recovery retains one operation and its exact AP2-6 key",
        },
        {
            "name": "ap2-recovery-pending-with-reference-reconciles",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [binding(
                tx, job_a, 3, "recovery-pending",
                provider_recovery_reference="provider-payment-123",
            )],
            "expected": "pass",
            "want": {"action": "reconcile-reference", "submitNewPayment": False},
            "note": "a retained provider reference is checked before any same-key resubmission",
        },
        {
            "name": "ap2-operation-payload-conflict-errors",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [binding(
                tx, job_a, 3, "recovery-pending",
                payload={
                    "transactionId": tx,
                    "jobId": job_a,
                    "phaseIndex": 3,
                    "amount": "different-operation",
                },
            )],
            "expected": "error",
            "want": {"action": "refuse-conflict", "submitNewPayment": False},
            "note": "same transaction and tuple cannot replace the immutable operation payload",
        },
        {
            "name": "ap2-idempotency-key-continuity-errors",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [binding(
                tx, job_a, 3, "recovery-pending", idempotency_key="0" * 64
            )],
            "expected": "error",
            "want": {"action": "refuse-conflict", "submitNewPayment": False},
            "note": "a stored key inconsistent with the reserved tuple fails closed",
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
            "name": "ap2-null-binding-store-errors",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": None,
            "expected": "error",
            "want": {"action": "refuse-conflict", "submitNewPayment": False},
            "note": "a null authoritative store snapshot fails closed",
        },
        {
            "name": "ap2-scalar-binding-store-errors",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": "empty",
            "expected": "error",
            "want": {"action": "refuse-conflict", "submitNewPayment": False},
            "note": "a scalar authoritative store snapshot fails closed",
        },
        {
            "name": "ap2-null-binding-entry-errors",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [None],
            "expected": "error",
            "want": {"action": "refuse-conflict", "submitNewPayment": False},
            "note": "a null store member fails closed rather than raising",
        },
        {
            "name": "ap2-scalar-binding-entry-errors",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [7],
            "expected": "error",
            "want": {"action": "refuse-conflict", "submitNewPayment": False},
            "note": "a scalar store member fails closed rather than raising",
        },
        {
            "name": "ap2-partial-binding-entry-errors",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [{"transactionId": tx, "jobId": job_a, "phaseIndex": 3}],
            "expected": "error",
            "want": {"action": "refuse-conflict", "submitNewPayment": False},
            "note": "a partial store member fails the closed decision shape",
        },
        {
            "name": "ap2-wrong-type-transaction-id-entry-errors",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [binding(tx, job_a, 3, "in-flight") | {"transactionId": 1}],
            "expected": "error",
            "want": {"action": "refuse-conflict", "submitNewPayment": False},
            "note": "a non-string stored transactionId fails closed",
        },
        {
            "name": "ap2-wrong-type-job-id-entry-errors",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [binding(tx, job_a, 3, "in-flight") | {"jobId": 1}],
            "expected": "error",
            "want": {"action": "refuse-conflict", "submitNewPayment": False},
            "note": "a non-string stored jobId fails closed",
        },
        {
            "name": "ap2-wrong-type-phase-index-entry-errors",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [binding(tx, job_a, 3, "in-flight") | {"phaseIndex": "3"}],
            "expected": "error",
            "want": {"action": "refuse-conflict", "submitNewPayment": False},
            "note": "a non-integer stored phaseIndex fails closed",
        },
        {
            "name": "ap2-wrong-type-state-entry-errors",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [binding(tx, job_a, 3, "in-flight") | {"state": 1}],
            "expected": "error",
            "want": {"action": "refuse-conflict", "submitNewPayment": False},
            "note": "a non-string stored state fails closed",
        },
        {
            "name": "ap2-unknown-state-entry-errors",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [binding(tx, job_a, 3, "pending")],
            "expected": "error",
            "want": {"action": "refuse-conflict", "submitNewPayment": False},
            "note": "an unknown stored state fails closed",
        },
        {
            "name": "ap2-extra-field-binding-entry-errors",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [binding(tx, job_a, 3, "in-flight") | {"trusted": True}],
            "expected": "error",
            "want": {"action": "refuse-conflict", "submitNewPayment": False},
            "note": "an open-shaped store member cannot add a caller-controlled decision field",
        },
        {
            "name": "ap2-duplicate-stored-bindings-error",
            "op": "transaction-binding",
            "transactionId": tx,
            "jobId": job_a,
            "phaseIndex": 3,
            "priorBindings": [
                binding(tx, job_a, 3, "in-flight"),
                binding(tx, job_a, 3, "in-flight"),
            ],
            "expected": "error",
            "want": {"action": "refuse-conflict", "submitNewPayment": False},
            "note": "even byte-identical duplicate store entries fail closed",
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
    for case in cases:
        if case["op"] in {"checkout-payment-admission", "transaction-binding"}:
            case["providerRequest"] = fixture_provider_request(case["jobId"])
    document = {
        "set": "ap2-handler-safety-v0.6",
        "spec": "DACS-4 v0.8 profile: §9.5.6 AP2-3/AP2-6/AP2-7 plus CORE §11.1.2 and JID-1",
        "scope": (
            "candidate handler predicates: idempotency-key and transaction-id derivation, "
            "authenticated synthetic-profile and JID/phase admission ordering, checkout/payment "
            "admission atomically composed with handler-owned AP2-7 store decisions, and "
            "retry/replay consumption are executed; the fixture release pin is "
            "not a published release or live deployment profile; "
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
