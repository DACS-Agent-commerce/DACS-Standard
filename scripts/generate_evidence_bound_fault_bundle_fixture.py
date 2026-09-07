#!/usr/bin/env python3
"""Generate the signed DACS-5 v0.4 EBFAB compatibility fixture.

The fixture uses published synthetic Ed25519 test seeds. It proves the new bundle
domain over real signatures, discriminator exclusivity/refusal, cross-type replay
failure, and the EBFAB > FAB > legacy authority rule for non-divergent pairs.
"""

import argparse
import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import quote

import jcs


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "conformance" / "fixtures" / "evidence-bound-fault-bundle-compatibility-v0.4.json"
SEEDS = {
    "buyer": "a1" * 32,
    "seller": "c3" * 32,
    "orchestrator": "0e" * 32,
}
CLAIMS = {role: f"did:demos:{role}" for role in SEEDS}
DOMAINS = {
    "legacy": "dacs-bundle:v1:",
    "fault": "dacs-fault-bundle:v1:",
    "evidence-bound": "dacs-evidence-bound-fault-bundle:v1:",
}
LISTING_DOMAIN = "dacs-listing:v1:"
SETTLEMENT_EVIDENCE_DOMAIN = "dacs-evidence:v1:"
DELIVERY_EVIDENCE_DOMAIN = "dacs-delivery-evidence:v1:"
ENTITLEMENT_DOMAIN = "dacs-entitlement:v1:"
PAYLOAD_ATTESTATION_DOMAIN = "dacs-payload-attestation:v1:"
POINTER_DOMAINS = {
    "fault": "dacs-fault-bundle-pointer:v1:",
    "evidence-bound": "dacs-evidence-bound-fault-bundle-pointer:v1:",
}
DISCRIMINATORS = {
    "legacy": "bundleVersion",
    "fault": "faultBundleVersion",
    "evidence-bound": "evidenceBoundFaultBundleVersion",
}
EVIDENCE_PHASES = {
    "pay-evm-erc20",
    "pay-solana-spl",
    "pay-cross-chain-htlc",
    "pay-cross-chain-liquidity-tank",
    "pay-ap2",
    "pay-x402",
    "pay-dem",
    "deliver-storage-program",
    "deliver-entitlement",
    "deliver-attested-payload",
}


def canonical(value):
    return jcs.canonicalize(value).encode("utf-8")


def b64u(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def bundle_hash(bundle):
    unsigned = {key: value for key, value in bundle.items() if key not in {"signatures", "anchoredByRole"}}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def listing_hash(listing):
    unsigned = {key: value for key, value in listing.items() if key != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def evidence_hash(record):
    unsigned = {key: value for key, value in record.items() if key != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def sign_artifact(record, signing_key, signer, domain):
    record["signature"] = {
        "signer": signer,
        "algorithm": "ed25519",
        "value": "",
    }
    payload = (domain + evidence_hash(record)).encode("utf-8")
    record["signature"]["value"] = b64u(signing_key.sign(payload))
    return record


def pointer_hash(pointer):
    unsigned = {key: value for key, value in pointer.items() if key != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def keys():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return {
        role: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
        for role, seed in SEEDS.items()
    }


def reference(label):
    return {
        "anchor": {"kind": "storage-program", "locator": f"stor-{hashlib.sha256(label.encode()).hexdigest()}"},
        "contentHash": hashlib.sha256(("content:" + label).encode()).hexdigest(),
    }


def payment_tx_refs(job_id, phase, phase_index):
    label = f"{job_id}:{phase}:{phase_index}"
    tx_hash = "0x" + hashlib.sha256(label.encode()).hexdigest()
    plain_hash = hashlib.sha256(("plain:" + label).encode()).hexdigest()
    by_phase = {
        "pay-evm-erc20": [
            {"kind": "evm-event", "chainId": 1, "txHash": tx_hash, "logIndex": 0},
        ],
        "pay-solana-spl": [
            {"kind": "solana-instruction", "cluster": "mainnet", "signature": plain_hash,
             "instructionIndex": 0},
        ],
        "pay-cross-chain-htlc": [
            {"kind": "htlc-lock", "chainId": 1, "contractAddress": "0xcontract",
             "lockTxHash": tx_hash},
            {"kind": "htlc-reveal", "chainId": 2, "contractAddress": "0xcontract",
             "revealTxHash": tx_hash},
            {"kind": "htlc-claim", "chainId": 1, "contractAddress": "0xcontract",
             "claimTxHash": tx_hash},
        ],
        "pay-cross-chain-liquidity-tank": [
            {"kind": "liquidity-tank", "bridgeId": "demos-tank", "sourceChainId": 1,
             "destChainId": 2, "lockTxHash": tx_hash, "releaseTxHash": tx_hash},
        ],
        "pay-ap2": [
            {"kind": "ap2", "mandateId": plain_hash, "providerRef": "provider-test",
             "protocolVersion": "1", "receiptAttestation": reference("ap2:" + label)},
        ],
        "pay-x402": [
            {"kind": "x402-event", "httpResource": "https://example.invalid/resource",
             "paymentReceiptHash": plain_hash, "settlementTxHash": tx_hash, "chainId": 1,
             "logIndex": 0, "protocolVersion": "1"},
        ],
        "pay-dem": [
            {"kind": "demos", "txHash": plain_hash, "blockNumber": 1},
        ],
    }
    return copy.deepcopy(by_phase[phase])


def settlement_finality(phase, observed_at):
    model = {
        "pay-evm-erc20": "block-depth",
        "pay-solana-spl": "commitment-level",
        "pay-cross-chain-htlc": "htlc-reveal",
        "pay-cross-chain-liquidity-tank": "liquidity-tank",
        "pay-ap2": "provider-receipt",
        "pay-x402": "block-depth",
        "pay-dem": "bft-final",
    }[phase]
    result = {"model": model, "finalityObservedAt": observed_at}
    if model == "block-depth":
        result["finalityBlocks"] = 1
    elif model == "commitment-level":
        result["finalityCommitmentLevel"] = "finalized"
    return result


def make_evidence(job_id, phase, phase_index, signing_keys, *, outcome="success", reason=None,
                  supersedes=None, label_suffix=""):
    delivery = phase.startswith("deliver-")
    record = {
        ("deliveryEvidenceVersion" if delivery else "evidenceVersion"): "1",
        "jobId": job_id,
        **({"phaseIndex": phase_index} if delivery else {}),
        "phase": phase,
        "outcome": outcome,
        "observedAt": 1785772799000 + phase_index,
    }
    if outcome == "failure":
        record["reason"] = reason or "permanent"
    elif phase.startswith("pay-"):
        record["paymentTxRefs"] = payment_tx_refs(job_id, phase, phase_index)
        record["paymentAmount"] = {"amount": "1", "currency": "DEM"}
        record["settlementFinality"] = settlement_finality(phase, record["observedAt"])
    else:
        record["deliverableContentHash"] = hashlib.sha256(
            f"deliverable:{job_id}:{phase_index}".encode()
        ).hexdigest()
        deliverable_address = (
            f"dacs4:entitlement:{job_id}:{phase_index}:0"
            if phase == "deliver-entitlement"
            else f"dacs4:deliverable:{job_id}:{phase_index}"
        )
        record["deliverableAnchor"] = {
            "kind": "storage-program",
            "locator": deliverable_address,
        }
        if phase == "deliver-attested-payload":
            method_hash = hashlib.sha256(
                f"verification-method:{job_id}:{phase_index}".encode()
            ).hexdigest()
            record["attestationRef"] = {
                **reference(f"payload-attestation:{job_id}:{phase_index}"),
                "anchor": {
                    "kind": "storage-program",
                    "locator": (
                        f"dacs4:payload-attestation:{job_id}:{phase_index}:"
                        f"{method_hash}:0"
                    ),
                },
            }
    if supersedes is not None:
        record["supersedesEvidenceRef"] = copy.deepcopy(supersedes)
    domain = DELIVERY_EVIDENCE_DOMAIN if delivery else SETTLEMENT_EVIDENCE_DOMAIN
    payload = (domain + evidence_hash(record)).encode("utf-8")
    record["signature"] = {
        "signer": CLAIMS["seller"],
        "algorithm": "ed25519",
        "value": b64u(signing_keys["seller"].sign(payload)),
    }
    label = f"{job_id}:{phase_index}:{phase}{label_suffix}"
    ref = {
        "anchor": {
            "kind": "storage-program",
            "locator": f"stor-{hashlib.sha256(label.encode()).hexdigest()}",
        },
        "contentHash": evidence_hash(record),
    }
    return record, ref


def make_current_delivery_evidence(job_id, phase, phase_index, signing_keys, *,
                                   outcome="success", reason=None, mutation=None):
    """Create DeliveryEvidence plus the resolved, phase-specific inner closure."""
    if outcome == "failure":
        record, ref = make_evidence(
            job_id, phase, phase_index, signing_keys, outcome=outcome, reason=reason
        )
        return record, ref, None, {}

    artifact_lifecycle = {"state": "finalized", "independentlyResolvable": True}
    closure = {}
    fields = {}
    if phase == "deliver-storage-program":
        cleartext = f"storage delivery:{job_id}:{phase_index}"
        digest = hashlib.sha256(cleartext.encode("utf-8")).hexdigest()
        address = f"dacs4:deliverable:{job_id}:{phase_index}"
        fields = {
            "deliverableContentHash": digest,
            "deliverableAnchor": {"kind": "storage-program", "locator": address},
        }
        closure["deliverable"] = {
            "logicalAddress": address,
            "cleartextUtf8": cleartext,
            "cleartextHash": digest,
            "storedContentHash": digest,
            "available": True,
            "lifecycle": artifact_lifecycle,
        }
    elif phase == "deliver-entitlement":
        renewal_seq = 0
        credential_cleartext = f"credential:{job_id}:{phase_index}:{renewal_seq}"
        credential_cleartext_hash = hashlib.sha256(
            credential_cleartext.encode("utf-8")
        ).hexdigest()
        credential_ref = {
            "ref": {
                "anchor": {
                    "kind": "storage-program",
                    "locator": (
                        f"dacs4:credential:{job_id}:{phase_index}:{renewal_seq}"
                    ),
                },
                "contentHash": credential_cleartext_hash,
                "signer": CLAIMS["seller"],
            },
            "accessModel": "buyer-only",
        }
        entitlement = {
            "entitlementVersion": "1",
            "jobId": job_id,
            "grantee": CLAIMS["buyer"],
            "grantor": CLAIMS["seller"],
            "startsAt": 1785772799000,
            "endsAt": 1785859199000,
            "scope": {"service": "https://service.example.test", "tier": "pro"},
            "serviceEndpoint": "https://service.example.test/access",
            "renewable": True,
            "renewalSeq": renewal_seq,
            "credentialRef": credential_ref,
        }
        if mutation == "entitlement-duration":
            entitlement["endsAt"] = entitlement["startsAt"] + 1
        elif mutation == "entitlement-renewable":
            entitlement["renewable"] = False
        sign_artifact(
            entitlement,
            signing_keys["seller"],
            CLAIMS["seller"],
            ENTITLEMENT_DOMAIN,
        )
        address = f"dacs4:entitlement:{job_id}:{phase_index}:{renewal_seq}"
        fields = {
            "deliverableContentHash": evidence_hash(entitlement),
            "deliverableAnchor": {"kind": "storage-program", "locator": address},
            "credentialDelivery": {
                "credentialRef": copy.deepcopy(credential_ref),
                "credentialCleartextHash": credential_cleartext_hash,
                "renewalSeq": renewal_seq,
            },
        }
        closure["entitlementRecord"] = {
            "logicalAddress": address,
            "artifact": entitlement,
            "available": True,
            "lifecycle": artifact_lifecycle,
        }
        closure["credential"] = {
            "credentialRef": copy.deepcopy(credential_ref),
            "cleartextHash": credential_cleartext_hash,
            "storedContentHash": credential_cleartext_hash,
            "cleartextBytesBase64url": b64u(
                credential_cleartext.encode("utf-8")
            ),
            "available": True,
            "lifecycle": artifact_lifecycle,
        }
    elif phase == "deliver-attested-payload":
        cleartext = f"attested payload:{job_id}:{phase_index}"
        digest = hashlib.sha256(cleartext.encode("utf-8")).hexdigest()
        spec = delivery_spec(job_id, phase, phase_index)
        method = spec["verificationMethod"]
        method_hash = hashlib.sha256(canonical(method)).hexdigest()
        agreement_hash = hashlib.sha256(
            f"agreement:{job_id}".encode("utf-8")
        ).hexdigest()
        transaction_value = hashlib.sha256(
            f"dahr:{job_id}:{phase_index}".encode("utf-8")
        ).hexdigest()
        trusted_transaction_value = transaction_value
        if mutation == "native-transaction":
            transaction_value = "ff" * 32
        transaction_state = "included" if mutation == "native-terminal-included" else "finalized"
        method_evidence = {
            "kind": "demos-web2-request",
            "request": {
                "method": method["endpoint"]["method"],
                "url": method["endpoint"]["urlTemplate"],
            },
            "response": {
                "status": 200,
                "data": cleartext,
                "responseHash": digest,
                "responseHeadersHash": "b2" * 32,
            },
            "transaction": {
                "kind": "demos-web2-request",
                "value": transaction_value,
                "state": transaction_state,
                "authenticated": True,
            },
            "proofValid": True,
        }
        method_address = f"dacs4:method-evidence:{job_id}:{phase_index}"
        method_ref = {
            "anchor": {"kind": "storage-program", "locator": method_address},
            "contentHash": hashlib.sha256(canonical(method_evidence)).hexdigest(),
            "signer": CLAIMS["orchestrator"],
        }
        payload_attestation = {
            "payloadAttestationVersion": "1",
            "jobId": job_id,
            "agreementHash": agreement_hash,
            "deliverableSpecHash": hashlib.sha256(canonical(spec)).hexdigest(),
            "payloadFormat": spec["payloadFormat"],
            "payloadContentHash": digest,
            "verificationMethod": method["kind"],
            "verificationMethodHash": method_hash,
            "attempt": 0,
            "decision": "pass",
            "reason": "deterministic test proof",
            "methodEvidenceRef": method_ref,
            "methodTransactionRef": {
                "kind": "demos-web2-request",
                "value": transaction_value,
            },
            "verifiedAt": 1785772800000 + phase_index,
        }
        sign_artifact(
            payload_attestation,
            signing_keys["orchestrator"],
            CLAIMS["orchestrator"],
            PAYLOAD_ATTESTATION_DOMAIN,
        )
        payload_address = f"dacs4:deliverable:{job_id}:{phase_index}"
        attestation_address = (
            f"dacs4:payload-attestation:{job_id}:{phase_index}:{method_hash}:0"
        )
        attestation_ref = {
            "anchor": {"kind": "storage-program", "locator": attestation_address},
            "contentHash": evidence_hash(payload_attestation),
            "signer": CLAIMS["orchestrator"],
        }
        fields = {
            "deliverableContentHash": digest,
            "deliverableAnchor": {
                "kind": "storage-program",
                "locator": payload_address,
            },
            "attestationRef": attestation_ref,
        }
        closure.update({
            "agreementHash": agreement_hash,
            "deliverable": {
                "logicalAddress": payload_address,
                "cleartextUtf8": cleartext,
                "cleartextHash": digest,
                "available": True,
                "lifecycle": artifact_lifecycle,
            },
            "payloadAttestationRecord": {
                "logicalAddress": attestation_address,
                "artifact": payload_attestation,
                "available": True,
                "lifecycle": artifact_lifecycle,
            },
            "methodEvidence": {
                "logicalAddress": method_address,
                "artifact": method_evidence,
                "available": True,
                "lifecycle": artifact_lifecycle,
            },
        })
        transaction_ref = payload_attestation["methodTransactionRef"]
        trusted_transaction_ref = {
            "kind": "demos-web2-request",
            "value": trusted_transaction_value,
        }
        observed_transaction = copy.deepcopy(method_evidence["transaction"])
        observed_transaction["value"] = trusted_transaction_value
        observed_response = {
            "status": method_evidence["response"]["status"],
            "responseHash": method_evidence["response"]["responseHash"],
            "responseHeadersHash": method_evidence["response"]["responseHeadersHash"],
        }
        if mutation == "native-observation-mismatch":
            observed_response["responseHash"] = "00" * 32
        observation = (
            {"available": False}
            if mutation == "native-observation-unavailable"
            else {
                "available": True,
                "transaction": observed_transaction,
                "verificationMethod": copy.deepcopy(method),
                "request": copy.deepcopy(method_evidence["request"]),
                "response": observed_response,
            }
        )
        trusted_native_observations = {
            canonical(trusted_transaction_ref).decode("utf-8"): observation
        }
    else:
        raise ValueError(f"unsupported delivery phase: {phase}")

    if phase != "deliver-attested-payload":
        trusted_native_observations = {}

    if mutation == "deliverable-locator":
        fields["deliverableAnchor"]["locator"] = (
            f"dacs4:deliverable:ATTACKER-JOB:{phase_index}"
        )
    elif mutation == "attestation-locator":
        fields["attestationRef"]["anchor"]["locator"] = (
            f"dacs4:payload-attestation:ATTACKER-JOB:{phase_index}:deadbeef:0"
        )
    elif mutation == "attestation-content-hash":
        fields["attestationRef"]["contentHash"] = "de" * 32
    elif mutation == "entitlement-locator":
        fields["deliverableAnchor"]["locator"] = (
            f"dacs4:entitlement:ATTACKER-JOB:{phase_index}:777"
        )
    elif mutation == "omit-credential-delivery":
        fields.pop("credentialDelivery", None)
    elif mutation in {
        "entitlement-duration",
        "entitlement-renewable",
        "native-transaction",
        "native-terminal-included",
        "native-observation-mismatch",
        "native-observation-unavailable",
    }:
        pass
    elif mutation is not None:
        raise ValueError(f"unsupported inner-artifact mutation: {mutation}")

    record = {
        "deliveryEvidenceVersion": "1",
        "jobId": job_id,
        "phaseIndex": phase_index,
        "phase": phase,
        "outcome": "success",
        **fields,
        "observedAt": 1785772799000 + phase_index,
    }
    sign_artifact(
        record,
        signing_keys["seller"],
        CLAIMS["seller"],
        DELIVERY_EVIDENCE_DOMAIN,
    )
    label = f"{job_id}:{phase_index}:{phase}"
    ref = {
        "anchor": {
            "kind": "storage-program",
            "locator": f"stor-{hashlib.sha256(label.encode()).hexdigest()}",
        },
        "contentHash": evidence_hash(record),
    }
    return record, ref, closure, trusted_native_observations


def make_legacy_delivery_evidence(
    job_id,
    phase,
    phase_index,
    signing_keys,
    *,
    outcome="success",
    reason=None,
    self_signed=False,
):
    """Create a byte-stable SettlementEvidence delivery with unindexed closure."""
    if outcome == "failure":
        record = {
            "evidenceVersion": "1",
            "jobId": job_id,
            "phase": phase,
            "outcome": "failure",
            "reason": reason or "permanent",
            "observedAt": 1785772799000 + phase_index,
        }
        sign_artifact(
            record,
            signing_keys["seller"],
            CLAIMS["seller"],
            SETTLEMENT_EVIDENCE_DOMAIN,
        )
        label = f"legacy:{job_id}:{phase_index}:{phase}"
        ref = {
            "anchor": {
                "kind": "storage-program",
                "locator": f"stor-{hashlib.sha256(label.encode()).hexdigest()}",
            },
            "contentHash": evidence_hash(record),
        }
        return record, ref, None, {}

    current, _, closure, native_observations = make_current_delivery_evidence(
        job_id, phase, phase_index, signing_keys
    )
    fields = {
        "deliverableContentHash": current["deliverableContentHash"],
    }
    if phase == "deliver-storage-program":
        address = f"dacs4:deliverable:{job_id}"
        closure["deliverable"]["logicalAddress"] = address
        fields["deliverableAnchor"] = {
            "kind": "storage-program",
            "locator": address,
        }
    elif phase == "deliver-entitlement":
        entitlement = closure["entitlementRecord"]["artifact"]
        renewal_seq = entitlement["renewalSeq"]
        credential_ref = entitlement.get("credentialRef")
        if isinstance(credential_ref, dict) and isinstance(
            credential_ref.get("ref"), dict
        ):
            credential_ref["ref"]["anchor"]["locator"] = (
                f"dacs4:credential:{job_id}:{renewal_seq}"
            )
            sign_artifact(
                entitlement,
                signing_keys["seller"],
                CLAIMS["seller"],
                ENTITLEMENT_DOMAIN,
            )
            fields["deliverableContentHash"] = evidence_hash(entitlement)
        address = f"dacs4:entitlement:{job_id}:{renewal_seq}"
        closure["entitlementRecord"]["logicalAddress"] = address
        # The credential may remain referenced by the historical entitlement,
        # but no unsigned closure input can synthesize PDE-5's signed binding.
        closure.pop("credential", None)
        fields["deliverableAnchor"] = {
            "kind": "storage-program",
            "locator": address,
        }
    elif phase == "deliver-attested-payload":
        payload = closure["deliverable"]
        payload_record_entry = closure["payloadAttestationRecord"]
        payload_record = payload_record_entry["artifact"]
        if self_signed:
            method = {"kind": "self-signed"}
            spec = delivery_spec(job_id, phase, phase_index)
            spec["verificationMethod"] = method
            assertion = payload["cleartextUtf8"]
            proof_key = signing_keys["seller"]
            proof = {
                "kind": "self-signed-payload",
                "payloadContentHash": payload["cleartextHash"],
                "methodInput": {
                    "identifier": proof_key.public_key().public_bytes_raw().hex(),
                    "assertion": assertion,
                    "signature": b64u(proof_key.sign(assertion.encode("utf-8"))),
                },
            }
            closure["methodEvidence"]["artifact"] = proof
            payload_record["deliverableSpecHash"] = hashlib.sha256(
                canonical(spec)
            ).hexdigest()
            payload_record["verificationMethod"] = method["kind"]
            payload_record["verificationMethodHash"] = hashlib.sha256(
                canonical(method)
            ).hexdigest()
            payload_record["methodEvidenceRef"]["contentHash"] = hashlib.sha256(
                canonical(proof)
            ).hexdigest()
            payload_record.pop("methodTransactionRef")
            sign_artifact(
                payload_record,
                signing_keys["orchestrator"],
                CLAIMS["orchestrator"],
                PAYLOAD_ATTESTATION_DOMAIN,
            )
            native_observations = {}

        method_address = f"dacs4:method-evidence:{job_id}"
        payload_record["methodEvidenceRef"]["anchor"]["locator"] = method_address
        closure["methodEvidence"]["logicalAddress"] = method_address
        sign_artifact(
            payload_record,
            signing_keys["orchestrator"],
            CLAIMS["orchestrator"],
            PAYLOAD_ATTESTATION_DOMAIN,
        )
        payload_address = f"dacs4:deliverable:{job_id}"
        attestation_address = (
            f"dacs4:payload-attestation:{job_id}:"
            f"{payload_record['verificationMethodHash']}:{payload_record['attempt']}"
        )
        payload["logicalAddress"] = payload_address
        payload_record_entry["logicalAddress"] = attestation_address
        fields.update({
            "deliverableAnchor": {
                "kind": "storage-program",
                "locator": payload_address,
            },
            "attestationRef": {
                "anchor": {
                    "kind": "storage-program",
                    "locator": attestation_address,
                },
                "contentHash": evidence_hash(payload_record),
                "signer": payload_record["signature"]["signer"],
            },
        })
    else:
        raise ValueError(f"unsupported legacy delivery phase: {phase}")

    record = {
        "evidenceVersion": "1",
        "jobId": job_id,
        "phase": phase,
        "outcome": "success",
        **fields,
        "observedAt": 1785772799000 + phase_index,
    }
    sign_artifact(
        record,
        signing_keys["seller"],
        CLAIMS["seller"],
        SETTLEMENT_EVIDENCE_DOMAIN,
    )
    label = f"legacy:{job_id}:{phase_index}:{phase}"
    ref = {
        "anchor": {
            "kind": "storage-program",
            "locator": f"stor-{hashlib.sha256(label.encode()).hexdigest()}",
        },
        "contentHash": evidence_hash(record),
    }
    return record, ref, closure, native_observations


def make_session_execution_authority(job_id, phase, phase_index, *, signer_role="seller",
                                     rail_id="test-rail"):
    signer = CLAIMS[signer_role]
    if phase.startswith("pay-"):
        execution_address = {}
    else:
        execution_address = {"evidenceLogicalAddress": f"dacs4:delivery:{job_id}:{phase_index}"}
    return {
        "jobId": job_id,
        "phaseIndex": phase_index,
        "phaseKind": phase,
        "phaseOrchestrator": signer,
        **({"railId": rail_id} if phase.startswith("pay-") else execution_address),
    }


def make_verified_anchor_receipt(ref, job_id, phase, phase_index, *, signer_role="seller",
                                 resolved=False, rail_id="test-rail"):
    signer = CLAIMS[signer_role]
    logical_address = (
        "dacs4:payment:%s:%s:%d%s" % (
            job_id,
            quote(rail_id, safe="-._~"),
            phase_index,
            ":resolved" if resolved else "",
        )
        if phase.startswith("pay-")
        else f"dacs4:delivery:{job_id}:{phase_index}"
    )
    transaction = "demos-testnet:tx-" + hashlib.sha256(
        f"{job_id}:{phase_index}:{phase}:{'resolved' if resolved else 'ordinary'}".encode()
    ).hexdigest()[:32]
    return {
        "logicalAddress": logical_address,
        "nativeAddress": ref["anchor"]["locator"],
        "contentHash": ref["contentHash"],
        "transaction": transaction,
        "writer": signer,
        "nonce": phase_index,
    }


def delivery_spec(job_id, phase, phase_index):
    if phase == "deliver-attested-payload":
        return {
            "kind": "attested-payload",
            "payloadFormat": "application/octet-stream",
            "verificationMethod": {
                "kind": "consensus-backed-proxy",
                "endpoint": {
                    "method": "GET",
                    "urlTemplate": f"https://api.example.test/delivery/{job_id}/{phase_index}",
                },
            },
        }
    if phase == "deliver-entitlement":
        return {
            "kind": "entitlement",
            "durationSec": 86400,
            "renewable": True,
        }
    return {"kind": "storage-program", "payloadFormat": "application/octet-stream"}


def make_listing(signing_keys, job_id="EBFAB-COMPAT-1", pipeline=None):
    pipeline = list(pipeline or ["pay-dem"])
    listing = {
        "listingId": "listing-ebfab-compat",
        "listingVersion": 1,
        "sellerPrimaryClaim": CLAIMS["seller"],
        "pipeline": [{"kind": phase} for phase in pipeline],
    }
    delivery_steps = [
        (index, phase) for index, phase in enumerate(pipeline)
        if phase.startswith("deliver-")
    ]
    if delivery_steps:
        phase_index, phase = delivery_steps[0]
        listing["offering"] = {
            "deliverable": delivery_spec(job_id, phase, phase_index),
        }
    payload = (LISTING_DOMAIN + listing_hash(listing)).encode("utf-8")
    listing["signature"] = {
        "signer": CLAIMS["seller"],
        "algorithm": "ed25519",
        "value": b64u(signing_keys["seller"].sign(payload)),
    }
    return listing


def sign_bundle(bundle, kind, signing_keys):
    bundle["signatures"] = []
    payload = (DOMAINS[kind] + bundle_hash(bundle)).encode("utf-8")
    bundle["signatures"] = [
        {
            "party": CLAIMS[role],
            "algorithm": "ed25519",
            "value": b64u(signing_keys[role].sign(payload)),
        }
        for role in ("buyer", "seller")
    ]
    return bundle


def make_bundle(kind, anchored_by_role, signing_keys, listing):
    evidence_record, evidence_ref = make_evidence(
        "EBFAB-COMPAT-1", "pay-dem", 0, signing_keys
    )
    bundle = {
        DISCRIMINATORS[kind]: "1",
        "jobId": "EBFAB-COMPAT-1",
        "outcome": "completed",
        "anchoredByRole": anchored_by_role,
        "listingRef": {
            "listingId": listing["listingId"],
            "version": listing["listingVersion"],
            "contentHash": listing_hash(listing),
        },
        "parties": [
            {"role": "buyer", "bundleHash": hashlib.sha256(b"buyer-bundle").hexdigest(), "primaryClaim": CLAIMS["buyer"]},
            {"role": "seller", "bundleHash": hashlib.sha256(b"seller-bundle").hexdigest(), "primaryClaim": CLAIMS["seller"]},
        ],
        "phaseSummary": [
            {"index": 0, "kind": "pay-dem", "outcome": "ok", "attestationRef": evidence_ref}
        ],
        "vetRecords": [],
        "settlementEvidence": [evidence_ref],
        "recipeRegistryVersion": 1,
        "railRegistryVersion": 1,
        "finalisedAt": 1785772800000,
        "signatures": [],
    }
    if kind != "legacy":
        bundle["faultedParty"] = "none"
    return sign_bundle(bundle, kind, signing_keys), evidence_record


def make_pointer(kind, bundle, signing_keys):
    pointer = {
        DISCRIMINATORS[kind]: "1",
        "pointerKind": "extended",
        "fullBundleUrl": f"https://example.invalid/{kind}-bundle.json",
        "fullBundleContentHash": bundle_hash(bundle),
    }
    return sign_pointer(pointer, kind, signing_keys, bundle.get("anchoredByRole", "seller"))


def sign_pointer(pointer, kind, signing_keys, signer_role):
    pointer.pop("signature", None)
    payload = (POINTER_DOMAINS[kind] + pointer_hash(pointer)).encode("utf-8")
    pointer["signature"] = {
        "signer": CLAIMS[signer_role],
        "algorithm": "ed25519",
        "value": b64u(signing_keys[signer_role].sign(payload)),
    }
    return pointer


def generate():
    signing_keys = keys()
    public_keys = {
        CLAIMS[role]: b64u(key.public_key().public_bytes_raw())
        for role, key in signing_keys.items()
    }
    listing = make_listing(signing_keys)
    ebfab_buyer, evidence_record = make_bundle("evidence-bound", "buyer", signing_keys, listing)
    ebfab_seller, _ = make_bundle("evidence-bound", "seller", signing_keys, listing)
    fab_seller, _ = make_bundle("fault", "seller", signing_keys, listing)
    legacy_seller, _ = make_bundle("legacy", "seller", signing_keys, listing)

    signed_missing_member = copy.deepcopy(ebfab_buyer)
    signed_missing_member["settlementEvidence"] = []
    sign_bundle(signed_missing_member, "evidence-bound", signing_keys)
    signed_pointerless = copy.deepcopy(ebfab_buyer)
    signed_pointerless["phaseSummary"][0].pop("attestationRef")
    sign_bundle(signed_pointerless, "evidence-bound", signing_keys)
    alternate_record, alternate_ref = make_evidence(
        "EBFAB-COMPAT-1", "pay-dem", 0, signing_keys, label_suffix=":alternate"
    )
    ebfab_alternate = copy.deepcopy(ebfab_seller)
    ebfab_alternate["phaseSummary"][0]["attestationRef"] = alternate_ref
    ebfab_alternate["settlementEvidence"] = [alternate_ref]
    sign_bundle(ebfab_alternate, "evidence-bound", signing_keys)

    ebfab_pointer = make_pointer("evidence-bound", ebfab_buyer, signing_keys)
    fab_pointer = make_pointer("fault", fab_seller, signing_keys)
    dual_pointer = copy.deepcopy(fab_pointer)
    dual_pointer["bundleVersion"] = "1"
    invalid_extra_pointer = copy.deepcopy(fab_pointer)
    invalid_extra_pointer["evidenceBoundFaultBundleVersion"] = "2"
    missing_url_pointer = copy.deepcopy(ebfab_pointer)
    missing_url_pointer.pop("fullBundleUrl")
    sign_pointer(missing_url_pointer, "evidence-bound", signing_keys, "buyer")
    malformed_segments_pointer = copy.deepcopy(ebfab_pointer)
    malformed_segments_pointer["segmentRefs"] = ["not-an-attestation-ref"]
    sign_pointer(malformed_segments_pointer, "evidence-bound", signing_keys, "buyer")
    unsafe_url_pointer = copy.deepcopy(ebfab_pointer)
    unsafe_url_pointer["fullBundleUrl"] = "file:///etc/passwd"
    sign_pointer(unsafe_url_pointer, "evidence-bound", signing_keys, "buyer")
    unauthorized_pointer = copy.deepcopy(ebfab_pointer)
    sign_pointer(unauthorized_pointer, "evidence-bound", signing_keys, "seller")
    invalid_fault_bundle = copy.deepcopy(ebfab_buyer)
    invalid_fault_bundle["faultedParty"] = "buyer"
    sign_bundle(invalid_fault_bundle, "evidence-bound", signing_keys)
    invalid_fault_pointer = make_pointer("evidence-bound", invalid_fault_bundle, signing_keys)
    seb_invalid_pointer = make_pointer("evidence-bound", signed_missing_member, signing_keys)
    minimal_ebfab = {"evidenceBoundFaultBundleVersion": "1"}
    minimal_ebfab_pointer = make_pointer("evidence-bound", minimal_ebfab, signing_keys)
    incomplete_binding = {"bundleContentHash": bundle_hash(ebfab_buyer)}

    stripped_to_fab = dict(ebfab_buyer)
    stripped_to_fab.pop("evidenceBoundFaultBundleVersion")
    stripped_to_fab["faultBundleVersion"] = "1"
    dual_discriminator = dict(ebfab_buyer)
    dual_discriminator["faultBundleVersion"] = "1"
    unknown_discriminator = dict(ebfab_buyer)
    unknown_discriminator.pop("evidenceBoundFaultBundleVersion")
    unknown_discriminator["futureBundleVersion"] = "1"
    known_plus_unknown = copy.deepcopy(ebfab_buyer)
    known_plus_unknown["futureBundleVersion"] = "1"
    sign_bundle(known_plus_unknown, "evidence-bound", signing_keys)

    completed_lifecycle = {"state": "finalized", "independentlyResolvable": True}

    return {
        "fixture": "evidence-bound-fault-bundle-compatibility-v0.4",
        "tier": "candidate",
        "generator": "scripts/generate_evidence_bound_fault_bundle_fixture.py",
        "seeds": SEEDS,
        "publicKeys": public_keys,
        "domains": DOMAINS,
        "pointerDomains": POINTER_DOMAINS,
        "listingDomain": LISTING_DOMAIN,
        "listing": listing,
        "sessionExecutionAuthorityByPhaseKey": {
            "0:pay-dem": make_session_execution_authority(
                "EBFAB-COMPAT-1", "pay-dem", 0),
        },
        "verifiedReceiptByCanonicalRef": {
            canonical(ebfab_buyer["settlementEvidence"][0]).decode("utf-8"):
                make_verified_anchor_receipt(
                    ebfab_buyer["settlementEvidence"][0], "EBFAB-COMPAT-1", "pay-dem", 0),
            canonical(alternate_ref).decode("utf-8"): make_verified_anchor_receipt(
                alternate_ref, "EBFAB-COMPAT-1", "pay-dem", 0),
        },
        "referenceValidationByCanonicalRef": {
            canonical(ebfab_buyer["settlementEvidence"][0]).decode("utf-8"): {
                "record": evidence_record,
                "lifecycle": {
                    "state": "finalized",
                    "independentlyResolvable": True,
                },
            },
            canonical(alternate_ref).decode("utf-8"): {
                "record": alternate_record,
                "lifecycle": {
                    "state": "finalized",
                    "independentlyResolvable": True,
                },
            }
        },
        "validBundleHash": bundle_hash(ebfab_buyer),
        "bundleLifecycleByHash": {
            bundle_hash(bundle): completed_lifecycle
            for bundle in (
                ebfab_buyer,
                ebfab_seller,
                ebfab_alternate,
                signed_pointerless,
                signed_missing_member,
                known_plus_unknown,
            )
        },
        "cases": [
            {"name": "valid-ebfab", "bundle": ebfab_buyer, "want": {"type": "evidence-bound", "signaturesValid": True, "sebValid": True}},
            {"name": "valid-pointerless-ebfab", "bundle": signed_pointerless, "want": {"type": "evidence-bound", "signaturesValid": True, "sebValid": True}},
            {"name": "signed-seb-missing-member-reject", "bundle": signed_missing_member, "want": {"type": "evidence-bound", "signaturesValid": True, "sebValid": False}},
            {"name": "stripped-to-fab-cross-type-replay", "bundle": stripped_to_fab, "want": {"type": "fault", "signaturesValid": False, "sebValid": False}},
            {"name": "dual-discriminator-reject", "bundle": dual_discriminator, "want": {"type": None, "signaturesValid": False, "sebValid": False}},
            {"name": "unknown-discriminator-reject", "bundle": unknown_discriminator, "want": {"type": None, "signaturesValid": False, "sebValid": False}},
            {"name": "known-plus-unknown-discriminator-reject", "bundle": known_plus_unknown, "want": {"type": None, "signaturesValid": False, "sebValid": False}},
            {"name": "completed-bundle-accepted-lifecycle-reject", "bundle": ebfab_buyer, "bundleLifecycle": {"state": "accepted", "independentlyResolvable": False}, "want": {"type": "evidence-bound", "signaturesValid": True, "sebValid": False}},
        ],
        "pairCases": [
            {
                "name": "ebfab-ebfab",
                "copies": {"buyer": ebfab_buyer, "seller": ebfab_seller},
                "want": {"divergent": False, "authoritativeType": "evidence-bound", "authoritativeBundleHash": bundle_hash(ebfab_buyer), "sebValid": True},
            },
            {
                "name": "ebfab-ebfab-member-skew-diverges",
                "copies": {"buyer": ebfab_buyer, "seller": ebfab_alternate},
                "want": {"divergent": True},
            },
            {
                "name": "ebfab-fab-older-cannot-erase-seb",
                "copies": {"buyer": ebfab_buyer, "seller": fab_seller},
                "want": {"divergent": False, "authoritativeType": "evidence-bound", "authoritativeBundleHash": bundle_hash(ebfab_buyer), "sebValid": True},
            },
            {
                "name": "ebfab-legacy-older-cannot-erase-seb",
                "copies": {"buyer": ebfab_buyer, "seller": legacy_seller},
                "want": {"divergent": False, "authoritativeType": "evidence-bound", "authoritativeBundleHash": bundle_hash(ebfab_buyer), "sebValid": True},
            },
        ],
        "pointerCases": [
            {
                "name": "ebfab-pointer-ebfab-pass",
                "pointer": ebfab_pointer,
                "bundle": ebfab_buyer,
                "useEbfabAuthority": True,
                "want": {"ok": True},
            },
            {
                "name": "fab-pointer-ebfab-reject",
                "pointer": fab_pointer,
                "bundle": ebfab_buyer,
                "want": {"ok": False},
            },
            {
                "name": "ebfab-pointer-fab-reject",
                "pointer": ebfab_pointer,
                "bundle": fab_seller,
                "want": {"ok": False},
            },
            {
                "name": "dual-pointer-discriminator-reject",
                "pointer": dual_pointer,
                "bundle": fab_seller,
                "want": {"ok": False},
            },
            {
                "name": "unsupported-extra-pointer-discriminator-reject",
                "pointer": invalid_extra_pointer,
                "bundle": fab_seller,
                "want": {"ok": False},
            },
            {
                "name": "signed-pointer-missing-url-reject",
                "pointer": missing_url_pointer,
                "bundle": ebfab_buyer,
                "want": {"ok": False},
            },
            {
                "name": "signed-pointer-malformed-segment-ref-reject",
                "pointer": malformed_segments_pointer,
                "bundle": ebfab_buyer,
                "want": {"ok": False},
            },
            {
                "name": "signed-pointer-unsafe-url-reject",
                "pointer": unsafe_url_pointer,
                "bundle": ebfab_buyer,
                "want": {"ok": False},
            },
            {
                "name": "signed-pointer-unauthorized-role-reject",
                "pointer": unauthorized_pointer,
                "bundle": ebfab_buyer,
                "want": {"ok": False},
            },
            {
                "name": "signed-pointer-invalid-fault-attribution-reject",
                "pointer": invalid_fault_pointer,
                "bundle": invalid_fault_bundle,
                "want": {"ok": False},
            },
            {
                "name": "signed-pointer-seb-invalid-bundle-reject",
                "pointer": seb_invalid_pointer,
                "bundle": signed_missing_member,
                "useEbfabAuthority": True,
                "want": {"ok": False},
            },
            {
                "name": "signed-pointer-minimal-bundle-reject",
                "pointer": minimal_ebfab_pointer,
                "bundle": minimal_ebfab,
                "want": {"ok": False},
            },
            {
                "name": "signed-pointer-incomplete-binding-reject",
                "pointer": ebfab_pointer,
                "bundle": ebfab_buyer,
                "binding": incomplete_binding,
                "useEbfabAuthority": True,
                "want": {"ok": False, "reasonContains": "binding invalid"},
            },
        ],
    }


def encoded_fixture():
    return (json.dumps(generate(), indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    generated = encoded_fixture()
    if args.write:
        FIXTURE.write_bytes(generated)
        print(f"wrote {FIXTURE.relative_to(ROOT)}")
        return 0
    if not FIXTURE.exists() or FIXTURE.read_bytes() != generated:
        print(f"{FIXTURE.relative_to(ROOT)} is stale; run this script with --write", file=sys.stderr)
        return 1
    print(f"verified {FIXTURE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
