#!/usr/bin/env python3
"""Generate the DPA-1..DPA-9 payload-attestation candidate vectors.

The fixture seeds are public test inputs. Every DACS signature is a genuine
Ed25519 signature over the record's registered domain plus its canonical hash.
Run with --check to verify byte-for-byte determinism or --write to regenerate.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "payload-attestation-binding-v0.1.json"
)

PAYLOAD_DOMAIN = "dacs-payload-attestation:v1:"
EVIDENCE_DOMAIN = "dacs-evidence:v1:"
VERIFIER_SEED = bytes.fromhex("31" * 32)
ORCHESTRATOR_SEED = bytes.fromhex("32" * 32)
VERIFIER = "did:demos:agent:" + "31" * 32
ORCHESTRATOR = "did:demos:agent:" + "32" * 32
JOB_ID = "01K1DPA0000000000000000000"
AGREEMENT_HASH = "a1" * 32
PAYLOAD_TEXT = '{"classification":"approved","score":0.98}'


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def hash_hex(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def sign_artifact(artifact: dict, seed: bytes, domain: str) -> None:
    unsigned = {k: v for k, v in artifact.items() if k != "signature"}
    digest = hash_hex(unsigned)
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(
        domain.encode("utf-8") + digest.encode("ascii")
    )
    artifact["signature"]["value"] = b64url(signature)


def attestation_ref(record: dict) -> dict:
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    return {
        "anchor": {
            "kind": "storage-program",
            "locator": (
                "dacs4:payload-attestation:"
                f"{record['jobId']}:{record['verificationMethodHash']}:{record['attempt']}"
            ),
        },
        "contentHash": hash_hex(unsigned),
        "signer": record["signature"]["signer"],
    }


def base_case() -> dict:
    method = {
        "kind": "consensus-backed-proxy",
        "endpoint": {
            "method": "GET",
            "urlTemplate": "https://api.example.test/classification/42",
        },
    }
    deliverable = {
        "kind": "attested-payload",
        "payloadFormat": "application/json",
        "verificationMethod": method,
    }
    payload_hash = hash_bytes(PAYLOAD_TEXT.encode("utf-8"))
    method_evidence = {
        "kind": "demos-web2-request",
        "request": {
            "method": "GET",
            "url": "https://api.example.test/classification/42",
        },
        "response": {
            "status": 200,
            "data": PAYLOAD_TEXT,
            "responseHash": payload_hash,
            "responseHeadersHash": "b2" * 32,
        },
        "transaction": {
            "kind": "demos-web2-request",
            "value": "c3" * 32,
            "state": "finalized",
            "authenticated": True,
        },
        "proofValid": True,
    }
    method_ref = {
        "anchor": {
            "kind": "https",
            "locator": "https://rpc.example.test/tx/" + "c3" * 32,
        },
        "contentHash": hash_hex(method_evidence),
        "signer": "substrate-validator-set:demos-mainnet:42",
    }
    record = {
        "payloadAttestationVersion": "1",
        "jobId": JOB_ID,
        "agreementHash": AGREEMENT_HASH,
        "deliverableSpecHash": hash_hex(deliverable),
        "payloadFormat": "application/json",
        "payloadContentHash": payload_hash,
        "verificationMethod": "consensus-backed-proxy",
        "verificationMethodHash": hash_hex(method),
        "attempt": 0,
        "decision": "pass",
        "reason": "DAHR response commitment verified",
        "methodEvidenceRef": method_ref,
        "methodTransactionRef": {
            "kind": "demos-web2-request",
            "value": "c3" * 32,
        },
        "verifiedAt": 1785495600000,
        "signature": {
            "algorithm": "ed25519",
            "signer": VERIFIER,
            "value": "",
        },
    }
    sign_artifact(record, VERIFIER_SEED, PAYLOAD_DOMAIN)
    record_ref = attestation_ref(record)
    settlement = {
        "evidenceVersion": "1",
        "jobId": JOB_ID,
        "phase": "deliver-attested-payload",
        "outcome": "success",
        "deliverableContentHash": payload_hash,
        "deliverableAnchor": {
            "kind": "storage-program",
            "locator": "dacs4:deliverable:" + JOB_ID,
        },
        "attestationRef": record_ref,
        "observedAt": 1785495601000,
        "signature": {
            "algorithm": "ed25519",
            "signer": ORCHESTRATOR,
            "value": "",
        },
    }
    sign_artifact(settlement, ORCHESTRATOR_SEED, EVIDENCE_DOMAIN)
    return {
        "listing": {
            "offering": {"deliverable": deliverable},
            "pipeline": [{"kind": "deliver-attested-payload"}],
        },
        "agreement": {
            "jobId": JOB_ID,
            "agreementHash": AGREEMENT_HASH,
            "deliverable": {
                "deliverableType": "attested-payload",
                "hash": hash_hex(deliverable),
            },
        },
        "payloadUtf8": PAYLOAD_TEXT,
        "methodEvidence": method_evidence,
        "payloadAttestationRecord": record,
        "payloadAttestationRef": record_ref,
        "settlementEvidence": settlement,
    }


def refresh_record_and_evidence(case: dict, record_domain: str = PAYLOAD_DOMAIN) -> None:
    record = case["payloadAttestationRecord"]
    sign_artifact(record, VERIFIER_SEED, record_domain)
    ref = attestation_ref(record)
    case["payloadAttestationRef"] = ref
    case["settlementEvidence"]["attestationRef"] = copy.deepcopy(ref)
    sign_artifact(case["settlementEvidence"], ORCHESTRATOR_SEED, EVIDENCE_DOMAIN)


def vector(name: str, expected: str, reason: str, mutate=None) -> dict:
    case = base_case()
    if mutate is not None:
        mutate(case)
    return {"name": name, **case, "expected": expected, "reason": reason}


def build_vectors() -> list[dict]:
    vectors: list[dict] = []
    vectors.append(vector(
        "dahr-payload-bound-success",
        "pass",
        "finalized DAHR request/response commitment binds the exact UTF-8 payload and commerce tuple",
    ))

    def self_signed(case: dict) -> None:
        method = {"kind": "self-signed"}
        deliverable = case["listing"]["offering"]["deliverable"]
        deliverable["verificationMethod"] = method
        case["agreement"]["deliverable"]["hash"] = hash_hex(deliverable)
        proof = {
            "kind": "self-signed-payload",
            "payloadContentHash": hash_bytes(case["payloadUtf8"].encode("utf-8")),
            "signer": VERIFIER,
            "signatureValid": True,
        }
        case["methodEvidence"] = proof
        record = case["payloadAttestationRecord"]
        record["deliverableSpecHash"] = hash_hex(deliverable)
        record["verificationMethod"] = "self-signed"
        record["verificationMethodHash"] = hash_hex(method)
        record["reason"] = "explicit minimal-trust self-signed payload proof verified"
        record["methodEvidenceRef"] = {
            "anchor": {
                "kind": "storage-program",
                "locator": "dacs4:self-signed-proof:" + JOB_ID,
            },
            "contentHash": hash_hex(proof),
            "signer": VERIFIER,
        }
        record.pop("methodTransactionRef")
        refresh_record_and_evidence(case)

    vectors.append(vector(
        "explicit-self-signed-tier-still-carries-proof",
        "pass",
        "self-signed is permitted only as an explicit minimal-trust method with a payload-bound proof",
        self_signed,
    ))

    def missing_method(case: dict) -> None:
        case["listing"]["offering"]["deliverable"].pop("verificationMethod")

    vectors.append(vector(
        "listing-method-missing-rejected-before-payment",
        "fail",
        "DPA-1 rejects an unfulfillable listing before any payment",
        missing_method,
    ))

    def missing_attestation_ref(case: dict) -> None:
        case["settlementEvidence"].pop("attestationRef")
        sign_artifact(case["settlementEvidence"], ORCHESTRATOR_SEED, EVIDENCE_DOMAIN)

    vectors.append(vector(
        "seller-settlement-signature-cannot-substitute",
        "fail",
        "success evidence without attestationRef is seller/orchestrator self-assertion, not attested delivery",
        missing_attestation_ref,
    ))

    def wrong_discriminator(case: dict) -> None:
        record = case["payloadAttestationRecord"]
        record.pop("payloadAttestationVersion")
        record["resultVersion"] = "1"
        refresh_record_and_evidence(case)

    vectors.append(vector(
        "verifyresult-discriminator-cannot-coerce",
        "fail",
        "DPA-9 refuses a claim VerifyResult shape as a payload attestation",
        wrong_discriminator,
    ))

    def unsupported_version(case: dict) -> None:
        case["payloadAttestationRecord"]["payloadAttestationVersion"] = "2"
        refresh_record_and_evidence(case)

    vectors.append(vector(
        "unsupported-payload-attestation-version",
        "fail",
        "unknown structural discriminator is refused before field interpretation",
        unsupported_version,
    ))

    def wrong_signature(case: dict) -> None:
        value = case["payloadAttestationRecord"]["signature"]["value"]
        case["payloadAttestationRecord"]["signature"]["value"] = (
            ("A" if value[0] != "A" else "B") + value[1:]
        )
        case["payloadAttestationRef"] = attestation_ref(case["payloadAttestationRecord"])
        case["settlementEvidence"]["attestationRef"] = copy.deepcopy(
            case["payloadAttestationRef"]
        )
        sign_artifact(case["settlementEvidence"], ORCHESTRATOR_SEED, EVIDENCE_DOMAIN)

    vectors.append(vector(
        "payload-record-signature-invalid",
        "fail",
        "record signature must verify under the payload-attestation domain",
        wrong_signature,
    ))

    def cross_domain(case: dict) -> None:
        refresh_record_and_evidence(case, EVIDENCE_DOMAIN)

    vectors.append(vector(
        "settlement-domain-signature-replay-rejected",
        "fail",
        "a valid signature under dacs-evidence:v1 cannot authenticate the payload record",
        cross_domain,
    ))

    def record_job_mismatch(case: dict) -> None:
        case["payloadAttestationRecord"]["jobId"] = "01K1DPA0000000000000000001"
        refresh_record_and_evidence(case)

    vectors.append(vector(
        "record-job-mismatch",
        "fail",
        "payload record jobId must equal the agreement and SettlementEvidence jobId",
        record_job_mismatch,
    ))

    def agreement_mismatch(case: dict) -> None:
        case["payloadAttestationRecord"]["agreementHash"] = "d4" * 32
        refresh_record_and_evidence(case)

    vectors.append(vector(
        "record-agreement-mismatch",
        "fail",
        "proof from another committed agreement cannot be reused",
        agreement_mismatch,
    ))

    def spec_mismatch(case: dict) -> None:
        case["payloadAttestationRecord"]["deliverableSpecHash"] = "d5" * 32
        refresh_record_and_evidence(case)

    vectors.append(vector(
        "record-deliverable-spec-mismatch",
        "fail",
        "record must bind the exact signed-listing DeliverableSpec",
        spec_mismatch,
    ))

    def payload_mismatch(case: dict) -> None:
        case["payloadAttestationRecord"]["payloadContentHash"] = "d6" * 32
        refresh_record_and_evidence(case)

    vectors.append(vector(
        "record-payload-digest-mismatch",
        "fail",
        "method proof, record, delivered bytes, and SettlementEvidence must share one digest",
        payload_mismatch,
    ))

    def method_mismatch(case: dict) -> None:
        case["payloadAttestationRecord"]["verificationMethodHash"] = "d7" * 32
        refresh_record_and_evidence(case)

    vectors.append(vector(
        "record-method-mismatch",
        "fail",
        "method substitution is detected against the signed listing",
        method_mismatch,
    ))

    def method_ref_hash_mismatch(case: dict) -> None:
        case["payloadAttestationRecord"]["methodEvidenceRef"]["contentHash"] = "d8" * 32
        refresh_record_and_evidence(case)

    vectors.append(vector(
        "method-evidence-content-hash-mismatch",
        "fail",
        "resolved native evidence must match its AttestationRef",
        method_ref_hash_mismatch,
    ))

    def unavailable(case: dict) -> None:
        case["methodEvidence"] = {"disposition": "unavailable"}

    vectors.append(vector(
        "method-evidence-unresolvable",
        "indeterminate",
        "non-observation is not a clean negative and cannot produce success",
        unavailable,
    ))

    def missing_tx(case: dict) -> None:
        case["payloadAttestationRecord"].pop("methodTransactionRef")
        refresh_record_and_evidence(case)

    vectors.append(vector(
        "dahr-transaction-reference-missing",
        "fail",
        "generic SDK optionality does not permit a DAHR-backed pass without txHash",
        missing_tx,
    ))

    def unauthenticated_tx(case: dict) -> None:
        case["methodEvidence"]["transaction"]["authenticated"] = False
        case["payloadAttestationRecord"]["methodEvidenceRef"]["contentHash"] = hash_hex(
            case["methodEvidence"]
        )
        refresh_record_and_evidence(case)

    vectors.append(vector(
        "dahr-transaction-not-authenticated",
        "fail",
        "broadcast/RPC acknowledgement is not consensus evidence",
        unauthenticated_tx,
    ))

    def request_mismatch(case: dict) -> None:
        case["methodEvidence"]["request"]["url"] = "https://evil.example/payload"
        case["payloadAttestationRecord"]["methodEvidenceRef"]["contentHash"] = hash_hex(
            case["methodEvidence"]
        )
        refresh_record_and_evidence(case)

    vectors.append(vector(
        "dahr-request-does-not-match-method",
        "fail",
        "DAHR request URL and method must match the signed verificationMethod",
        request_mismatch,
    ))

    def response_mismatch(case: dict) -> None:
        case["methodEvidence"]["response"]["data"] = '{"classification":"rejected"}'
        case["payloadAttestationRecord"]["methodEvidenceRef"]["contentHash"] = hash_hex(
            case["methodEvidence"]
        )
        refresh_record_and_evidence(case)

    vectors.append(vector(
        "dahr-response-bytes-do-not-match-commitment",
        "fail",
        "delivered UTF-8 bytes must hash to DAHR responseHash",
        response_mismatch,
    ))

    def nonpass(case: dict) -> None:
        case["payloadAttestationRecord"]["decision"] = "indeterminate"
        case["payloadAttestationRecord"]["reason"] = "authority returned incomplete result"
        refresh_record_and_evidence(case)

    vectors.append(vector(
        "nonpass-payload-record-cannot-support-success",
        "fail",
        "DPA-5 never collapses indeterminate to pass",
        nonpass,
    ))

    def wrong_record_ref(case: dict) -> None:
        case["settlementEvidence"]["attestationRef"]["contentHash"] = "d9" * 32
        sign_artifact(case["settlementEvidence"], ORCHESTRATOR_SEED, EVIDENCE_DOMAIN)

    vectors.append(vector(
        "settlement-reference-does-not-match-record",
        "fail",
        "SettlementEvidence must reference the exact signed payload record",
        wrong_record_ref,
    ))

    def replay_other_session(case: dict) -> None:
        case["settlementEvidence"]["jobId"] = "01K1DPA0000000000000000002"
        sign_artifact(case["settlementEvidence"], ORCHESTRATOR_SEED, EVIDENCE_DOMAIN)

    vectors.append(vector(
        "cross-session-record-replay",
        "fail",
        "a valid record from one job cannot support another job",
        replay_other_session,
    ))
    return vectors


def build_document() -> dict:
    vectors = build_vectors()
    return {
        "set": "payload-attestation-binding-v0.1",
        "spec": "DACS-4 §9.6.3 DPA-1..DPA-9; §9.7; CORE §B.7; Demos §A.3",
        "decisionModel": (
            "A successful attested-payload delivery requires a distinct signed "
            "PayloadAttestationRecord, a passing exact-byte method proof, and "
            "matching listing/agreement/settlement bindings. Resolved contradictions "
            "fail; unavailable otherwise-valid evidence remains indeterminate."
        ),
        "hashRecipe": "sha256(compact sorted-key UTF-8 JSON of vectors)",
        "hash": hashlib.sha256(canonical_bytes(vectors)).hexdigest(),
        "count": len(vectors),
        "publicTestSeeds": {
            "verifierEd25519": VERIFIER_SEED.hex(),
            "orchestratorEd25519": ORCHESTRATOR_SEED.hex(),
        },
        "vectors": vectors,
    }


def rendered_document() -> str:
    return json.dumps(build_document(), indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = rendered_document()
    if args.write:
        OUTPUT.write_text(rendered, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != rendered:
        print(
            "payload-attestation vectors are stale; run "
            "python3 scripts/generate_payload_attestation_vectors.py --write"
        )
        return 1
    print("payload-attestation vectors deterministic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
