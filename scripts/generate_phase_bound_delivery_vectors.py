#!/usr/bin/env python3
"""Generate PDE-1..PDE-8 phase-bound delivery-evidence vectors.

All DACS signatures are genuine deterministic Ed25519 signatures over RFC 8785
JCS hashes and their registered domains. Run with --write to regenerate or
--check to verify byte-for-byte determinism.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import jcs  # noqa: E402

OUTPUT = ROOT / "conformance" / "vectors" / "security" / "phase-bound-delivery-evidence-v0.7.json"

DELIVERY_DOMAIN = "dacs-delivery-evidence:v1:"
LEGACY_DOMAIN = "dacs-evidence:v1:"
ENTITLEMENT_DOMAIN = "dacs-entitlement:v1:"
PAYLOAD_DOMAIN = "dacs-payload-attestation:v1:"
BUNDLE_DOMAIN = "dacs-fault-bundle:v1:"
ORCHESTRATOR_SEED = bytes.fromhex("41" * 32)
SELLER_SEED = bytes.fromhex("42" * 32)
VERIFIER_SEED = bytes.fromhex("43" * 32)
BUYER_SEED = bytes.fromhex("44" * 32)


def claim(seed: bytes) -> str:
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    return "cci:" + pub.hex()


ORCHESTRATOR = claim(ORCHESTRATOR_SEED)
SELLER = claim(SELLER_SEED)
VERIFIER = claim(VERIFIER_SEED)
BUYER = claim(BUYER_SEED)
JOB = "01K2PDE0000000000000000000"
OTHER_JOB = "01K2PDE9999999999999999999"
AGREEMENT_HASH = "a1" * 32


def canonical_bytes(value: Any) -> bytes:
    return jcs.canonicalize(value).encode("utf-8")


def hash_hex(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def bytes_hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def sign(artifact: dict, seed: bytes, domain: str) -> None:
    unsigned = {k: v for k, v in artifact.items() if k != "signature"}
    payload = domain.encode("ascii") + hash_hex(unsigned).encode("ascii")
    artifact.setdefault("signature", {})["value"] = b64url(
        Ed25519PrivateKey.from_private_bytes(seed).sign(payload)
    )


def ref(address: str, artifact: dict) -> dict:
    unsigned = {k: v for k, v in artifact.items() if k != "signature"}
    return {
        "anchor": {"kind": "storage-program", "locator": address},
        "contentHash": hash_hex(unsigned),
        "signer": artifact["signature"]["signer"],
    }


def evidence_ref(entry: dict) -> dict:
    return ref(entry["logicalAddress"], entry["artifact"])


def evidence(index: int, phase: str, **fields: Any) -> dict:
    artifact = {
        "deliveryEvidenceVersion": "1",
        "jobId": JOB,
        "phaseIndex": index,
        "phase": phase,
        "outcome": "success",
        **fields,
        "observedAt": 1786000000000 + index,
        "signature": {"algorithm": "ed25519", "signer": ORCHESTRATOR, "value": ""},
    }
    sign(artifact, ORCHESTRATOR_SEED, DELIVERY_DOMAIN)
    return artifact


def legacy_evidence(phase: str, **fields: Any) -> dict:
    artifact = {
        "evidenceVersion": "1",
        "jobId": JOB,
        "phase": phase,
        "outcome": "success",
        **fields,
        "observedAt": 1786000000000,
        "signature": {"algorithm": "ed25519", "signer": ORCHESTRATOR, "value": ""},
    }
    sign(artifact, ORCHESTRATOR_SEED, LEGACY_DOMAIN)
    return artifact


def payment_evidence(index: int) -> dict:
    artifact = {
        "evidenceVersion": "1",
        "jobId": JOB,
        "phase": "pay-evm-erc20",
        "outcome": "success",
        "paymentTxRefs": [{
            "kind": "evm-event",
            "chainId": 1,
            "txHash": "ab" * 32,
            "logIndex": index,
        }],
        "paymentAmount": {"amount": "5", "currency": "USDC"},
        "settlementFinality": {
            "model": "block-depth",
            "finalityBlocks": 12,
            "finalityObservedAt": 1786000000000 + index,
        },
        "observedAt": 1786000000000 + index,
        "signature": {"algorithm": "ed25519", "signer": ORCHESTRATOR, "value": ""},
    }
    sign(artifact, ORCHESTRATOR_SEED, LEGACY_DOMAIN)
    return artifact


def phase(index: int, kind: str, pointer: dict | None = None) -> dict:
    result = {"index": index, "kind": kind, "outcome": "ok"}
    if pointer is not None:
        result["attestationRef"] = copy.deepcopy(pointer)
    return result


def sign_bundle(artifact: dict) -> None:
    unsigned = {k: v for k, v in artifact.items() if k not in {"signatures", "anchoredByRole"}}
    payload = BUNDLE_DOMAIN.encode("ascii") + hash_hex(unsigned).encode("ascii")
    artifact["signatures"] = []
    for party, seed in [(BUYER, BUYER_SEED), (SELLER, SELLER_SEED), (ORCHESTRATOR, ORCHESTRATOR_SEED)]:
        artifact["signatures"].append({
            "party": party, "algorithm": "ed25519",
            "value": b64url(Ed25519PrivateKey.from_private_bytes(seed).sign(payload)),
        })


def bundle(case: dict, pointers: bool = False) -> None:
    refs = [evidence_ref(entry) for entry in case["evidenceRecords"]]
    case["bundle"] = {
        "faultBundleVersion": "1",
        "jobId": JOB,
        "outcome": "completed",
        "faultedParty": "none",
        "anchoredByRole": "buyer",
        "listingRef": {"listingId": "phase-bound-delivery", "version": 1, "contentHash": "91" * 32},
        "agreementRef": {
            "anchor": {"kind": "storage-program", "locator": f"dacs3:agreement:{JOB}"},
            "contentHash": AGREEMENT_HASH, "signer": SELLER,
        },
        "parties": [
            {"role": "buyer", "bundleHash": "51" * 32, "primaryClaim": BUYER},
            {"role": "seller", "bundleHash": "52" * 32, "primaryClaim": SELLER},
            {"role": "orchestrator", "bundleHash": "53" * 32, "primaryClaim": ORCHESTRATOR},
        ],
        "phaseSummary": [
            phase(step["index"], step["kind"], refs[i] if pointers else None)
            for i, step in enumerate(case["pipeline"])
        ],
        "vetRecords": [],
        "settlementEvidence": copy.deepcopy(refs),
        "recipeRegistryVersion": 1,
        "railRegistryVersion": 1,
        "finalisedAt": 1786000010000,
        "signatures": [],
    }
    sign_bundle(case["bundle"])


def refresh_evidence(case: dict, position: int, domain: str = DELIVERY_DOMAIN) -> None:
    entry = case["evidenceRecords"][position]
    sign(entry["artifact"], ORCHESTRATOR_SEED, domain)
    new = evidence_ref(entry)
    case["bundle"]["settlementEvidence"][position] = copy.deepcopy(new)
    summary = case["bundle"]["phaseSummary"][position]
    if "attestationRef" in summary:
        summary["attestationRef"] = copy.deepcopy(new)


def storage_case(pointers: bool = False) -> dict:
    case = {"pipeline": [], "evidenceRecords": [], "artifactRecords": [], "credentials": []}
    for index, text in [(1, b"first delivery"), (2, b"second delivery")]:
        address = f"dacs4:deliverable:{JOB}:{index}"
        digest = bytes_hash(text)
        case["pipeline"].append({"index": index, "kind": "deliver-storage-program"})
        case["artifactRecords"].append({
            "kind": "deliverable", "logicalAddress": address,
            "cleartextHash": digest, "storedHash": digest, "available": True,
        })
        case["evidenceRecords"].append({
            "logicalAddress": f"dacs4:delivery:{JOB}:{index}",
            "artifact": evidence(
                index, "deliver-storage-program",
                deliverableContentHash=digest,
                deliverableAnchor={"kind": "storage-program", "locator": address},
            ),
        })
    bundle(case, pointers)
    return case


def failed_storage_case() -> dict:
    index = 1
    artifact = evidence(index, "deliver-storage-program")
    artifact["outcome"] = "failure"
    artifact["reason"] = "seller could not publish the deliverable"
    sign(artifact, ORCHESTRATOR_SEED, DELIVERY_DOMAIN)
    case = {
        "pipeline": [{"index": index, "kind": "deliver-storage-program"}],
        "evidenceRecords": [{
            "logicalAddress": f"dacs4:delivery:{JOB}:{index}",
            "artifact": artifact,
        }],
        "artifactRecords": [],
        "credentials": [],
    }
    bundle(case, True)
    case["bundle"]["outcome"] = "failed-counterparty"
    case["bundle"]["faultedParty"] = "seller"
    case["bundle"]["phaseSummary"][0]["outcome"] = "fail"
    case["bundle"]["phaseSummary"][0]["errorClass"] = "counterparty"
    return case


def failed_storage_before_second_delivery_case() -> dict:
    case = failed_storage_case()
    case["pipeline"].append({"index": 2, "kind": "deliver-storage-program"})
    return case


def mixed_payment_delivery_case() -> dict:
    case = storage_case()
    index = 0
    rail = "evm-erc20%3A1%3AUSDC"
    case["pipeline"].insert(0, {"index": index, "kind": "pay-evm-erc20"})
    case["evidenceRecords"].insert(0, {
        "logicalAddress": f"dacs4:payment:{JOB}:{rail}:{index}",
        "artifact": payment_evidence(index),
    })
    bundle(case, True)
    return case


def entitlement_record(index: int, renewal: int, credential_ref: dict | None = None) -> dict:
    artifact = {
        "entitlementVersion": "1", "jobId": JOB, "grantee": "cci:" + "55" * 32,
        "grantor": SELLER, "startsAt": 1786000000000, "endsAt": 1786086400000,
        "scope": {"service": "https://service.example.test", "tier": "pro"},
        "serviceEndpoint": "https://service.example.test/access", "renewable": True,
        "renewalSeq": renewal,
        "signature": {"algorithm": "ed25519", "signer": SELLER, "value": ""},
    }
    if credential_ref is not None:
        artifact["credentialRef"] = copy.deepcopy(credential_ref)
    sign(artifact, SELLER_SEED, ENTITLEMENT_DOMAIN)
    return artifact


def entitlement_case(renewals: tuple[int, int] = (0, 0)) -> dict:
    case = {"pipeline": [], "evidenceRecords": [], "artifactRecords": [], "credentials": []}
    for index, renewal in zip((3, 4), renewals):
        record = entitlement_record(index, renewal)
        address = f"dacs4:entitlement:{JOB}:{index}:{renewal}"
        case["pipeline"].append({"index": index, "kind": "deliver-entitlement"})
        case["artifactRecords"].append({
            "kind": "EntitlementRecord", "logicalAddress": address,
            "artifact": record, "available": True,
        })
        case["evidenceRecords"].append({
            "logicalAddress": f"dacs4:delivery:{JOB}:{index}",
            "artifact": evidence(
                index, "deliver-entitlement",
                deliverableContentHash=hash_hex({k: v for k, v in record.items() if k != "signature"}),
                deliverableAnchor={"kind": "storage-program", "locator": address},
            ),
        })
    bundle(case)
    return case


def credential_case(access_model: str = "buyer-only", include_credential: bool = True) -> dict:
    index, renewal = 5, 0
    cleartext = b"api-key:correct-horse-battery-staple"
    clear_hash = bytes_hash(cleartext)
    ciphertext_hash = bytes_hash(b"ml-kem-aes:ciphertext")
    stored_hash = clear_hash if access_model == "buyer-only" else ciphertext_hash
    credential_ref = {
        "ref": {
            "anchor": {"kind": "storage-program", "locator": f"dacs4:credential:{JOB}:{index}:{renewal}"},
            "contentHash": stored_hash,
            "signer": SELLER,
        },
        "accessModel": access_model,
    }
    record = entitlement_record(index, renewal, credential_ref if include_credential else None)
    address = f"dacs4:entitlement:{JOB}:{index}:{renewal}"
    fields: dict[str, Any] = {
        "deliverableContentHash": hash_hex({k: v for k, v in record.items() if k != "signature"}),
        "deliverableAnchor": {"kind": "storage-program", "locator": address},
    }
    if include_credential:
        fields["credentialDelivery"] = {
            "credentialRef": copy.deepcopy(credential_ref),
            "credentialCleartextHash": clear_hash,
            "renewalSeq": renewal,
        }
    case = {
        "pipeline": [{"index": index, "kind": "deliver-entitlement"}],
        "evidenceRecords": [{
            "logicalAddress": f"dacs4:delivery:{JOB}:{index}",
            "artifact": evidence(index, "deliver-entitlement", **fields),
        }],
        "artifactRecords": [{
            "kind": "EntitlementRecord", "logicalAddress": address,
            "artifact": record, "available": True,
        }],
        "credentials": ([{
            "credentialRef": copy.deepcopy(credential_ref), "cleartextHash": clear_hash,
            "storedHash": stored_hash, "ciphertextHash": ciphertext_hash,
            "available": True,
        }] if include_credential else []),
    }
    bundle(case)
    return case


def payload_record(index: int, payload_text: str) -> tuple[dict, dict, dict, dict]:
    payload_hash = bytes_hash(payload_text.encode("utf-8"))
    endpoint = f"https://api.example.test/delivery/{index}"
    method = {
        "kind": "consensus-backed-proxy",
        "endpoint": {"method": "GET", "urlTemplate": endpoint},
    }
    transaction_value = hashlib.sha256(f"dahr:{JOB}:{index}".encode()).hexdigest()
    method_proof = {
        "kind": "demos-web2-request",
        "request": {"method": "GET", "url": endpoint},
        "response": {
            "status": 200,
            "data": payload_text,
            "responseHash": payload_hash,
            "responseHeadersHash": "b2" * 32,
        },
        "transaction": {
            "kind": "demos-web2-request",
            "value": transaction_value,
            "state": "finalized",
            "authenticated": True,
        },
        "proofValid": True,
    }
    method_address = f"dacs4:method-evidence:{JOB}:{index}"
    method_proof_ref = {
        "anchor": {"kind": "storage-program", "locator": method_address},
        "contentHash": hash_hex(method_proof),
        "signer": VERIFIER,
    }
    deliverable = {
        "kind": "attested-payload",
        "payloadFormat": "application/octet-stream",
        "verificationMethod": method,
    }
    agreement = {
        "jobId": JOB,
        "agreementHash": AGREEMENT_HASH,
        "deliverable": {
            "deliverableType": "attested-payload",
            "hash": hash_hex(deliverable),
        },
    }
    artifact = {
        "payloadAttestationVersion": "1", "jobId": JOB,
        "agreementHash": AGREEMENT_HASH, "deliverableSpecHash": hash_hex(deliverable),
        "payloadFormat": "application/octet-stream", "payloadContentHash": payload_hash,
        "verificationMethod": "consensus-backed-proxy", "verificationMethodHash": hash_hex(method),
        "attempt": 0, "decision": "pass", "reason": "deterministic test proof",
        "methodEvidenceRef": method_proof_ref,
        "methodTransactionRef": {"kind": "demos-web2-request", "value": transaction_value},
        "verifiedAt": 1786000001000 + index,
        "signature": {"algorithm": "ed25519", "signer": VERIFIER, "value": ""},
    }
    sign(artifact, VERIFIER_SEED, PAYLOAD_DOMAIN)
    return artifact, method_proof, deliverable, agreement


def attested_case() -> dict:
    case = {
        "pipeline": [], "evidenceRecords": [], "artifactRecords": [], "credentials": [],
        "deliveryAuthorities": [],
    }
    for index, payload in [(6, b"attested one"), (7, b"attested two")]:
        digest = bytes_hash(payload)
        payload_text = payload.decode("utf-8")
        record, method_proof, deliverable, agreement = payload_record(index, payload_text)
        method_hash = record["verificationMethodHash"]
        record_address = f"dacs4:payload-attestation:{JOB}:{index}:{method_hash}:0"
        payload_address = f"dacs4:deliverable:{JOB}:{index}"
        method_address = record["methodEvidenceRef"]["anchor"]["locator"]
        case["pipeline"].append({"index": index, "kind": "deliver-attested-payload"})
        case["artifactRecords"].extend([
            {"kind": "deliverable", "logicalAddress": payload_address,
             "cleartextHash": digest, "cleartextUtf8": payload_text,
             "storedHash": digest, "available": True},
            {"kind": "PayloadAttestationRecord", "logicalAddress": record_address,
             "artifact": record, "available": True},
            {"kind": "methodEvidence", "logicalAddress": method_address,
             "artifact": method_proof, "available": True},
        ])
        case["deliveryAuthorities"].append({
            "phaseIndex": index,
            "deliverable": deliverable,
            "agreement": agreement,
        })
        case["evidenceRecords"].append({
            "logicalAddress": f"dacs4:delivery:{JOB}:{index}",
            "artifact": evidence(
                index, "deliver-attested-payload",
                deliverableContentHash=digest,
                deliverableAnchor={"kind": "storage-program", "locator": payload_address},
                attestationRef=ref(record_address, record),
            ),
        })
    bundle(case)
    return case


def legacy_case(repeated: bool = False) -> dict:
    address = f"dacs4:deliverable:{JOB}"
    digest = bytes_hash(b"legacy delivery")
    pipeline = [{"index": 1, "kind": "deliver-storage-program"}]
    if repeated:
        pipeline.append({"index": 2, "kind": "deliver-storage-program"})
    artifact = legacy_evidence(
        "deliver-storage-program", deliverableContentHash=digest,
        deliverableAnchor={"kind": "storage-program", "locator": address},
    )
    case = {
        "pipeline": pipeline,
        "evidenceRecords": [{"logicalAddress": f"legacy:dacs4:evidence:{JOB}", "artifact": artifact}],
        "artifactRecords": [{"kind": "deliverable", "logicalAddress": address,
                             "cleartextHash": digest, "storedHash": digest, "available": True}],
        "credentials": [],
    }
    bundle(case)
    return case


def legacy_credential_case() -> dict:
    current = credential_case()
    record = current["artifactRecords"][0]["artifact"]
    address = f"dacs4:entitlement:{JOB}:0"
    artifact = legacy_evidence(
        "deliver-entitlement",
        deliverableContentHash=hash_hex({k: v for k, v in record.items() if k != "signature"}),
        deliverableAnchor={"kind": "storage-program", "locator": address},
    )
    case = {
        "pipeline": [{"index": 5, "kind": "deliver-entitlement"}],
        "evidenceRecords": [{
            "logicalAddress": f"legacy:dacs4:evidence:{JOB}:entitlement",
            "artifact": artifact,
        }],
        "artifactRecords": [{
            "kind": "EntitlementRecord",
            "logicalAddress": address,
            "artifact": record,
            "available": True,
        }],
        "credentials": current["credentials"],
    }
    bundle(case)
    return case


def make(name: str, expected: str, reason: str, factory: Callable[[], dict], mutate: Callable[[dict], None] | None = None, **extra: Any) -> dict:
    case = factory()
    case.setdefault("executionAuthority", {"phaseOrchestrator": ORCHESTRATOR})
    for entry in case["evidenceRecords"]:
        entry.setdefault("receiptWriter", ORCHESTRATOR)
    if mutate:
        mutate(case)
    sign_bundle(case["bundle"])
    return {"name": name, **case, **extra, "expected": expected, "reason": reason}


def build_vectors() -> list[dict]:
    vectors: list[dict] = []
    vectors.append(make("repeated-storage-distinct-without-phase-pointers", "pass", "signed phase indexes and addresses establish the one-to-one mapping", storage_case))
    vectors.append(make("repeated-storage-distinct-with-phase-pointers", "pass", "optional pointers equal the authoritative top-level refs", lambda: storage_case(True)))

    def reuse_evidence(case: dict) -> None:
        case["bundle"]["settlementEvidence"][1] = copy.deepcopy(case["bundle"]["settlementEvidence"][0])
    vectors.append(make("one-evidence-ref-reused-for-two-indexes", "fail", "one evidence reference cannot satisfy two invocations", storage_case, reuse_evidence))

    def wrong_index(case: dict) -> None:
        case["evidenceRecords"][1]["artifact"]["phaseIndex"] = 1
        refresh_evidence(case, 1)
    vectors.append(make("signed-phase-index-mismatch", "fail", "signed phaseIndex must equal the authenticated pipeline index", storage_case, wrong_index))

    def wrong_kind(case: dict) -> None:
        case["evidenceRecords"][1]["artifact"]["phase"] = "deliver-entitlement"
        refresh_evidence(case, 1)
    vectors.append(make("signed-phase-kind-mismatch", "fail", "signed phase must equal the authenticated pipeline kind", storage_case, wrong_kind))

    def wrong_job(case: dict) -> None:
        index = 2
        entry = case["evidenceRecords"][1]
        entry["artifact"]["jobId"] = OTHER_JOB
        entry["artifact"]["deliverableAnchor"]["locator"] = f"dacs4:deliverable:{OTHER_JOB}:{index}"
        entry["logicalAddress"] = f"dacs4:delivery:{OTHER_JOB}:{index}"
        case["artifactRecords"][1]["logicalAddress"] = f"dacs4:deliverable:{OTHER_JOB}:{index}"
        refresh_evidence(case, 1)
    vectors.append(make("signed-delivery-job-mismatch", "fail", "signed delivery jobId must equal the authenticated bundle job", storage_case, wrong_job))

    def wrong_evidence_address(case: dict) -> None:
        case["evidenceRecords"][1]["logicalAddress"] = f"dacs4:delivery:{JOB}:99"
        bundle(case)
    vectors.append(make("delivery-evidence-address-mismatch", "fail", "evidence address must carry the signed phaseIndex", storage_case, wrong_evidence_address))

    def wrong_authority(case: dict) -> None:
        case["executionAuthority"]["phaseOrchestrator"] = SELLER
    vectors.append(make("delivery-signer-not-authenticated-phase-orchestrator", "fail", "a valid signature by another session party is not phase authority", storage_case, wrong_authority))

    def wrong_payload_address(case: dict) -> None:
        case["evidenceRecords"][1]["artifact"]["deliverableAnchor"]["locator"] = f"dacs4:deliverable:{JOB}:1"
        refresh_evidence(case, 1)
    vectors.append(make("deliverable-address-cross-phase-replay", "fail", "deliverable anchor must carry the same phaseIndex", storage_case, wrong_payload_address))

    vectors.append(make("legacy-single-delivery-readable", "pass", "one unambiguous legacy delivery remains readable unchanged", legacy_case))
    vectors.append(make("legacy-unindexed-evidence-cannot-cover-repetition", "fail", "legacy evidence never satisfies repeated delivery", lambda: legacy_case(True)))
    vectors.append(make("legacy-credential-entitlement-cannot-claim-dv5", "fail", "legacy entitlement evidence is audit-only and cannot establish the DV-5 delivered gate", legacy_credential_case, requestedGate="dv5-verified"))
    vectors.append(make("repeated-entitlements-each-renewal-zero", "pass", "phaseIndex separates two renewalSeq zero streams", entitlement_case))
    vectors.append(make("entitlement-renewal-streams-independent", "pass", "each repeated phase can independently reach renewalSeq one", lambda: entitlement_case((1, 1))))

    def unindexed_entitlement(case: dict) -> None:
        entry = case["evidenceRecords"][0]
        entry["artifact"]["deliverableAnchor"]["locator"] = f"dacs4:entitlement:{JOB}:0"
        refresh_evidence(case, 0)
    vectors.append(make("current-entitlement-uses-legacy-unindexed-address", "fail", "current entitlement address must contain phaseIndex before renewalSeq", entitlement_case, unindexed_entitlement))

    def wrong_renewal_address(case: dict) -> None:
        entry = case["evidenceRecords"][0]
        entry["artifact"]["deliverableAnchor"]["locator"] = f"dacs4:entitlement:{JOB}:3:9"
        refresh_evidence(case, 0)
    vectors.append(make("entitlement-renewal-address-mismatch", "fail", "address renewal discriminator must equal the signed record", entitlement_case, wrong_renewal_address))

    def wrong_entitlement_hash(case: dict) -> None:
        case["evidenceRecords"][0]["artifact"]["deliverableContentHash"] = "e2" * 32
        refresh_evidence(case, 0)
    vectors.append(make("entitlement-record-content-hash-mismatch", "fail", "delivery evidence must bind the exact signed EntitlementRecord content hash", entitlement_case, wrong_entitlement_hash))

    def invalid_entitlement_signature(case: dict) -> None:
        signature = case["artifactRecords"][0]["artifact"]["signature"]
        value = signature["value"]
        signature["value"] = ("A" if value[0] != "A" else "B") + value[1:]
    vectors.append(make("entitlement-record-signature-invalid", "fail", "an invalid EntitlementRecord signature cannot satisfy delivery", entitlement_case, invalid_entitlement_signature))

    vectors.append(make("repeated-attested-payload-each-attempt-zero", "pass", "phaseIndex separates identical attempt counters", attested_case))

    def replay_attestation(case: dict) -> None:
        case["evidenceRecords"][1]["artifact"]["attestationRef"] = copy.deepcopy(case["evidenceRecords"][0]["artifact"]["attestationRef"])
        refresh_evidence(case, 1)
    vectors.append(make("payload-attestation-cross-phase-replay", "fail", "one phase-indexed payload record cannot satisfy another invocation", attested_case, replay_attestation))

    def wrong_attestation_address(case: dict) -> None:
        ref_value = case["evidenceRecords"][1]["artifact"]["attestationRef"]
        ref_value["anchor"]["locator"] = ref_value["anchor"]["locator"].replace(f":{JOB}:7:", f":{JOB}:6:")
        refresh_evidence(case, 1)
    vectors.append(make("payload-attestation-address-index-mismatch", "fail", "attestationRef locator must carry evidence phaseIndex", attested_case, wrong_attestation_address))

    vectors.append(make("credential-buyer-only-exact-binding", "pass", "exact ref, cleartext digest, and renewal establish delivered only", credential_case))
    vectors.append(make("credential-encrypt-to-buyer-cleartext-binding", "pass", "cleartext digest is distinct from ciphertext anchor hash", lambda: credential_case("encrypt-to-buyer")))

    def mutate_credential(field_mutator: Callable[[dict], None]) -> Callable[[dict], None]:
        def apply(case: dict) -> None:
            field_mutator(case["evidenceRecords"][0]["artifact"])
            refresh_evidence(case, 0)
        return apply

    vectors.append(make("credential-binding-missing", "fail", "credentialRef entitlement requires credentialDelivery", credential_case, mutate_credential(lambda e: e.pop("credentialDelivery"))))
    vectors.append(make("credential-ref-mismatch", "fail", "complete AttestationRef must equal the signed entitlement", credential_case, mutate_credential(lambda e: e["credentialDelivery"]["credentialRef"]["ref"].update({"contentHash": "f0" * 32}))))
    vectors.append(make("credential-access-model-mismatch", "fail", "accessModel is inside the exact binding", credential_case, mutate_credential(lambda e: e["credentialDelivery"]["credentialRef"].update({"accessModel": "encrypt-to-buyer"}))))
    vectors.append(make("credential-cleartext-digest-mismatch", "fail", "credential cleartext digest must resolve exactly", credential_case, mutate_credential(lambda e: e["credentialDelivery"].update({"credentialCleartextHash": "e1" * 32}))))

    def ciphertext_substitution(e: dict) -> None:
        e["credentialDelivery"]["credentialCleartextHash"] = bytes_hash(b"ml-kem-aes:ciphertext")
    vectors.append(make("credential-ciphertext-hash-substitution", "fail", "ciphertext digest cannot substitute for cleartext", lambda: credential_case("encrypt-to-buyer"), mutate_credential(ciphertext_substitution)))
    vectors.append(make("credential-renewal-mismatch", "fail", "binding renewal must equal signed record and address", credential_case, mutate_credential(lambda e: e["credentialDelivery"].update({"renewalSeq": 1}))))
    vectors.append(make("renewal-zero-evidence-replayed-as-renewal-one", "fail", "renewal evidence cannot be relabelled", credential_case, mutate_credential(lambda e: (e["credentialDelivery"].update({"renewalSeq": 1}), e["deliverableAnchor"].update({"locator": f"dacs4:entitlement:{JOB}:5:1"})))))
    vectors.append(make("credential-overclaims-valid-readable", "error", "action-bearing gate assertions require a new type", credential_case, mutate_credential(lambda e: e["credentialDelivery"].update({"asserts": ["delivered", "valid", "readable"]}))))
    for field, value in (
        ("valid", True),
        ("readable", True),
        ("asserts", ["delivered", "valid", "readable"]),
    ):
        vectors.append(make(
            f"delivery-evidence-top-level-{field}-extension",
            "error",
            f"unknown top-level {field} is an unsupported action-bearing extension",
            credential_case,
            mutate_credential(lambda evidence, field=field, value=value: evidence.update({field: value})),
        ))

    def unresolved(case: dict) -> None:
        case["credentials"][0]["available"] = False
    vectors.append(make("credential-well-formed-but-unresolvable", "indeterminate", "unavailability never becomes fail or readable", credential_case, unresolved))
    vectors.append(make("entitlement-without-credential-needs-no-binding", "pass", "credentialDelivery is absent iff the entitlement has no credentialRef", lambda: credential_case(include_credential=False)))

    vectors.append(make("failure-delivery-omits-success-closure", "pass", "failure evidence does not require success-only deliverable closure", failed_storage_case))
    vectors.append(make("failed-first-delivery-does-not-require-unexecuted-second", "pass", "PDE-8 and SEB derive executed delivery membership from the authenticated failed phaseSummary prefix", failed_storage_before_second_delivery_case))

    def success_without_closure(case: dict) -> None:
        artifact = case["evidenceRecords"][0]["artifact"]
        artifact["outcome"] = "success"
        artifact.pop("reason", None)
        refresh_evidence(case, 0)
        case["bundle"]["outcome"] = "completed"
        case["bundle"]["faultedParty"] = "none"
        case["bundle"]["phaseSummary"][0]["outcome"] = "ok"
        case["bundle"]["phaseSummary"][0].pop("errorClass", None)
    vectors.append(make("success-delivery-missing-closure", "fail", "success evidence requires deliverableContentHash and deliverableAnchor", failed_storage_case, success_without_closure))

    def delivery_outcome_contradicts_summary(case: dict) -> None:
        artifact = case["evidenceRecords"][0]["artifact"]
        artifact["outcome"] = "failure"
        artifact["reason"] = "signed contradiction with the successful phase result"
        refresh_evidence(case, 0)
    vectors.append(make(
        "delivery-outcome-contradicts-phase-summary",
        "fail",
        "signed DeliveryEvidence outcome must match the authenticated phaseSummary result",
        credential_case,
        delivery_outcome_contradicts_summary,
    ))

    vectors.append(make("mixed-payment-and-delivery-evidence", "pass", "PDE-8 maps current delivery members without redefining payment membership", mixed_payment_delivery_case))

    def missing_top_level_delivery_ref(case: dict) -> None:
        case["bundle"]["settlementEvidence"].pop()
    vectors.append(make("bundle-missing-one-delivery-reference", "fail", "every executed delivery requires one authoritative top-level reference", storage_case, missing_top_level_delivery_ref))

    def missing_delivery_summary(case: dict) -> None:
        case["bundle"]["phaseSummary"].pop()
    vectors.append(make("bundle-missing-one-delivery-summary", "fail", "delivery phaseSummary membership must equal the authenticated delivery pipeline", storage_case, missing_delivery_summary))

    def wrong_phase_pointer(case: dict) -> None:
        case["bundle"]["phaseSummary"][1]["attestationRef"] = copy.deepcopy(
            case["bundle"]["settlementEvidence"][0]
        )
    vectors.append(make("bundle-delivery-pointer-mismatch", "fail", "an optional per-phase pointer must equal that phase's authoritative top-level reference", lambda: storage_case(True), wrong_phase_pointer))

    def binding_without_credential(case: dict) -> None:
        sample = credential_case()["evidenceRecords"][0]["artifact"]["credentialDelivery"]
        case["evidenceRecords"][0]["artifact"]["credentialDelivery"] = sample
        refresh_evidence(case, 0)
    vectors.append(make("credential-binding-present-without-credential-ref", "fail", "binding presence is exact iff", lambda: credential_case(include_credential=False), binding_without_credential))

    def both_discriminators(case: dict) -> None:
        case["evidenceRecords"][0]["artifact"]["evidenceVersion"] = "1"
        refresh_evidence(case, 0)
    vectors.append(make("delivery-evidence-both-discriminators", "error", "cross-type coercion is malformed", credential_case, both_discriminators))

    vectors.append(make("older-reader-refuses-delivery-evidence", "error", "an older reader must reject the new type as unsupported", credential_case, consumerVersion="pre-0.7"))

    def cross_domain(case: dict) -> None:
        refresh_evidence(case, 0, LEGACY_DOMAIN)
    vectors.append(make("delivery-signature-under-settlement-domain", "fail", "cross-domain signature replay fails", credential_case, cross_domain))

    def signature_mutation(case: dict) -> None:
        value = case["evidenceRecords"][0]["artifact"]["signature"]["value"]
        case["evidenceRecords"][0]["artifact"]["signature"]["value"] = ("A" if value[0] != "A" else "B") + value[1:]
        bundle(case)
    vectors.append(make("delivery-signature-mutation", "fail", "every signed binding is integrity protected", credential_case, signature_mutation))
    return vectors


def build_document() -> dict:
    vectors = build_vectors()
    return {
        "set": "phase-bound-delivery-evidence-v0.7",
        "spec": "DACS-4 §9.7 PDE-1..PDE-8; §9.6 DV-5/DPA-1..DPA-9; DACS-5 §10.4.3; CORE §B.1/§B.7",
        "decisionModel": "Current delivery evidence signs exact phase identity and artifact/credential closure; attested delivery resolves the payload, method proof, and authenticated native transaction; contradictions fail, malformed/unsupported input errors, and unavailable otherwise-valid private evidence remains indeterminate.",
        "hashRecipe": "sha256(RFC 8785 JCS of vectors)",
        "hash": hash_hex(vectors),
        "count": len(vectors),
        "publicTestSeeds": {
            "orchestratorEd25519": ORCHESTRATOR_SEED.hex(),
            "sellerEd25519": SELLER_SEED.hex(),
            "verifierEd25519": VERIFIER_SEED.hex(),
            "buyerEd25519": BUYER_SEED.hex(),
        },
        "vectors": vectors,
    }


def render() -> str:
    return json.dumps(build_document(), indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.write:
        OUTPUT.write_text(expected, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
    if current != expected:
        print(f"ERROR: {OUTPUT.relative_to(ROOT)} is stale; run --write", file=sys.stderr)
        return 1
    print("phase-bound delivery vectors are deterministic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
