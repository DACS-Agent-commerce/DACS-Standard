#!/usr/bin/env python3
"""Hydrate SEB candidate vectors with deterministic signed execution authorities."""

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path

import generate_evidence_bound_fault_bundle_fixture as F


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "conformance" / "vectors" / "security" / "bundle-settlement-evidence-bijection-v0.4.json"


def make_listing(name, pipeline, signing_keys, signer_role="seller", job_id=None):
    listing = {
        "listingId": f"listing-seb-{name}",
        "listingVersion": 1,
        "sellerPrimaryClaim": F.CLAIMS["seller"],
        "pipeline": [{"kind": kind} for kind in pipeline],
    }
    delivery_steps = [
        (index, phase) for index, phase in enumerate(pipeline)
        if phase.startswith("deliver-")
    ]
    if delivery_steps:
        phase_index, phase = delivery_steps[0]
        listing["offering"] = {
            "deliverable": F.delivery_spec(job_id, phase, phase_index),
        }
    payload = (F.LISTING_DOMAIN + F.listing_hash(listing)).encode("utf-8")
    listing["signature"] = {
        "signer": F.CLAIMS[signer_role],
        "algorithm": "ed25519",
        "value": F.b64u(signing_keys[signer_role].sign(payload)),
    }
    return listing


def authority_reference(name, phase_key):
    label = f"SEB-AUTHORITY:{name}:{phase_key}"
    return {
        "anchor": {
            "kind": "storage-program",
            "locator": f"stor-{hashlib.sha256(label.encode()).hexdigest()}",
        },
        "contentHash": hashlib.sha256(("content:" + label).encode()).hexdigest(),
    }


def current_agreement_hash(job_id, phase_key):
    return hashlib.sha256(
        ("current-agreement:" + job_id + ":" + phase_key).encode()
    ).hexdigest()


def current_session_id(job_id, phase_key):
    return "session-" + hashlib.sha256(
        (job_id + ":" + phase_key).encode()
    ).hexdigest()


def current_laa_phase_carrier(
    bundle, listing, phase_key, record, ref, receipt, execution
):
    """Build deterministic authenticated current-agreement authority for SEB."""
    agreement_hash = current_agreement_hash(bundle["jobId"], phase_key)
    session_id = current_session_id(bundle["jobId"], phase_key)
    orchestrator = execution["phaseOrchestrator"]
    laa = {
        "operation": "authorize-payment",
        "pipelineHasPayment": True,
        "agreement": {
            "artifact": "payee-bound",
            "shape": "valid",
            "partySignaturesValid": True,
            "contentHash": agreement_hash,
            "jobId": bundle["jobId"],
            "phase": record["phase"],
            "listingRef": copy.deepcopy(bundle["listingRef"]),
            "pbVerified": True,
        },
        "sessionAuthority": {
            "state": "verified",
            "jobId": bundle["jobId"],
            "sessionId": session_id,
            "orchestratorPrimaryClaim": orchestrator,
        },
    }
    binding = {
        "laaContentHash": hashlib.sha256(F.canonical(laa)).hexdigest(),
        "bundleContentHash": F.bundle_hash(bundle),
        "listingRef": copy.deepcopy(bundle["listingRef"]),
        "listingContentHash": F.listing_hash(listing),
        "agreementContentHash": agreement_hash,
        "jobId": bundle["jobId"],
        "sessionId": session_id,
        "phaseKey": phase_key,
        "phaseIndex": execution["phaseIndex"],
        "phase": record["phase"],
        "phaseOrchestrator": orchestrator,
        "evidenceSigner": record["signature"]["signer"],
        "evidenceContentHash": F.evidence_hash(record),
        "evidenceRef": copy.deepcopy(ref),
        "evidenceReceiptHash": hashlib.sha256(F.canonical(receipt)).hexdigest(),
        "receiptWriter": receipt["writer"],
    }
    return {"laa": laa, "binding": binding}


def make_authority(name, definition, signing_keys):
    job_id = f"SEB-AUTHORITY-{name}"
    listing = make_listing(
        name,
        definition["listingPipeline"],
        signing_keys,
        definition.get("listingSignerRole", "seller"),
        job_id,
    )
    legacy_self_signed = definition.get("legacySelfSigned") is True
    if legacy_self_signed:
        listing["offering"]["deliverable"]["verificationMethod"] = {
            "kind": "self-signed"
        }
        payload = (F.LISTING_DOMAIN + F.listing_hash(listing)).encode("utf-8")
        listing["signature"] = {
            "signer": F.CLAIMS[definition.get("listingSignerRole", "seller")],
            "algorithm": "ed25519",
            "value": F.b64u(signing_keys[
                definition.get("listingSignerRole", "seller")
            ].sign(payload)),
        }
    phase_summary = []
    settlement_evidence = []
    reference_validation_by_canonical_ref = {}
    session_execution_authority_by_phase_key = {}
    verified_receipt_by_canonical_ref = {}
    delivery_artifact_authority_by_phase_key = {}
    trusted_native_transaction_observations_by_canonical_ref = {}
    default_lifecycle = definition["defaultReferenceLifecycle"]
    for source in definition["phaseSummary"]:
        entry = copy.deepcopy(source)
        if entry["kind"] in F.EVIDENCE_PHASES:
            supersedes = None
            st8_resolved = False
            if definition.get("st8Resolved") and entry["kind"] in {
                "pay-cross-chain-htlc",
                "pay-cross-chain-liquidity-tank",
            }:
                st8_resolved = True
                interim_record, interim_ref = F.make_evidence(
                    job_id,
                    entry["kind"],
                    entry["index"],
                    signing_keys,
                    outcome="failure",
                    reason=(
                        "dest-revealed-source-unclaimed"
                        if entry["kind"] == "pay-cross-chain-htlc"
                        else "tank-locked-unreleased"
                    ),
                    label_suffix=":interim",
                )
                reference_validation_by_canonical_ref[F.canonical(interim_ref).decode("utf-8")] = {
                    "record": interim_record,
                    "lifecycle": copy.deepcopy(
                        definition.get("st8InterimLifecycle", default_lifecycle)
                    ),
                }
                verified_receipt_by_canonical_ref[F.canonical(interim_ref).decode("utf-8")] = (
                    F.make_verified_anchor_receipt(
                        interim_ref,
                        job_id,
                        entry["kind"],
                        entry["index"],
                        resolved=False,
                        state=definition.get(
                            "st8InterimLifecycle", default_lifecycle
                        )["state"],
                    )
                )
                supersedes = interim_ref
            evidence_reason = entry.get("errorClass")
            if entry.get("errorClass") == "settlement-atomicity":
                evidence_reason = {
                    "pay-cross-chain-htlc": "dest-revealed-source-unclaimed",
                    "pay-cross-chain-liquidity-tank": "tank-locked-unreleased",
                }.get(entry["kind"], evidence_reason)
            if definition.get("evidenceReasonOverride") is not None:
                evidence_reason = definition["evidenceReasonOverride"]
            legacy_delivery = False
            execution_authority_role = "seller"
            evidence_writer_role = "seller"
            if entry["kind"].startswith("deliver-"):
                legacy_delivery = definition.get("legacyDeliveryEvidence") is True
                execution_authority_role = (
                    definition.get("deliveryExecutionAuthorityRole", "orchestrator")
                    if not legacy_delivery
                    else "seller"
                )
                evidence_writer_role = definition.get(
                    "deliveryEvidenceSignerRole", execution_authority_role
                )
                if legacy_delivery:
                    record, ref, delivery_closure, native_observations = (
                        F.make_legacy_delivery_evidence(
                            job_id,
                            entry["kind"],
                            entry["index"],
                            signing_keys,
                            outcome=(
                                "success" if entry["outcome"] == "ok" else "failure"
                            ),
                            reason=evidence_reason,
                            self_signed=legacy_self_signed,
                        )
                    )
                else:
                    record, ref, delivery_closure, native_observations = F.make_current_delivery_evidence(
                        job_id,
                        entry["kind"],
                        entry["index"],
                        signing_keys,
                        outcome="success" if entry["outcome"] == "ok" else "failure",
                        reason=evidence_reason,
                        mutation=definition.get("innerArtifactMutation"),
                        execution_authority_role=evidence_writer_role,
                    )
            else:
                record, ref = F.make_evidence(
                    job_id,
                    entry["kind"],
                    entry["index"],
                    signing_keys,
                    outcome="success" if entry["outcome"] == "ok" else "failure",
                    reason=evidence_reason,
                    supersedes=(
                        None if definition.get("omitSt8Supersedes") else supersedes
                    ),
                    label_suffix=":resolved" if st8_resolved else "",
                )
                delivery_closure = None
            entry["attestationRef"] = ref
            settlement_evidence.append(ref)
            phase_key = f"{entry['index']}:{entry['kind']}"
            execution_authority = F.make_session_execution_authority(
                job_id,
                entry["kind"],
                entry["index"],
                signer_role=execution_authority_role,
            )
            legacy_evidence_address = None
            if entry["kind"].startswith("deliver-") and legacy_delivery:
                legacy_evidence_address = (
                    f"legacy:dacs4:evidence:{job_id}:{entry['kind']}"
                )
                execution_authority["evidenceLogicalAddress"] = legacy_evidence_address
            if isinstance(delivery_closure, dict):
                if "agreementHash" in delivery_closure:
                    execution_authority["agreementHash"] = delivery_closure["agreementHash"]
                delivery_artifact_authority_by_phase_key[phase_key] = delivery_closure
                trusted_native_transaction_observations_by_canonical_ref.update(
                    native_observations
                )
                verified_receipt_by_canonical_ref.update(
                    F.make_delivery_closure_receipts(
                        record,
                        delivery_closure,
                        job_id,
                        entry["kind"],
                        entry["index"],
                    )
                )
            session_execution_authority_by_phase_key[phase_key] = execution_authority
            receipt = F.make_verified_anchor_receipt(
                ref,
                job_id,
                entry["kind"],
                entry["index"],
                resolved=st8_resolved,
                state=default_lifecycle["state"],
                signer_role=execution_authority_role,
            )
            if legacy_evidence_address is not None:
                receipt["logicalAddress"] = legacy_evidence_address
            verified_receipt_by_canonical_ref[F.canonical(ref).decode("utf-8")] = receipt
            record_authority = {
                "record": record,
                "lifecycle": copy.deepcopy(default_lifecycle),
            }
            if entry["kind"].startswith("pay-"):
                record_authority.update({
                    "agreementHash": current_agreement_hash(job_id, phase_key),
                    "sessionId": current_session_id(job_id, phase_key),
                })
            reference_validation_by_canonical_ref[
                F.canonical(ref).decode("utf-8")
            ] = record_authority
        phase_summary.append(entry)

    bundle = {
        "evidenceBoundFaultBundleVersion": "1",
        "jobId": job_id,
        "outcome": definition["bundleOutcome"],
        "faultedParty": {
            "completed": "none",
            "failed-substrate": "none",
            "failed-perm": "seller",
            "aborted-by-self": "seller",
            "failed-counterparty": "buyer",
            "aborted-by-other": "buyer",
        }[definition["bundleOutcome"]],
        "anchoredByRole": "seller",
        "listingRef": {
            "listingId": listing["listingId"],
            "version": listing["listingVersion"],
            "contentHash": F.listing_hash(listing),
        },
        "parties": [
            {"role": "buyer", "bundleHash": hashlib.sha256(b"seb-buyer-bundle").hexdigest(), "primaryClaim": F.CLAIMS["buyer"]},
            {"role": "seller", "bundleHash": hashlib.sha256(b"seb-seller-bundle").hexdigest(), "primaryClaim": F.CLAIMS["seller"]},
        ],
        "phaseSummary": phase_summary,
        "vetRecords": [],
        "settlementEvidence": settlement_evidence,
        "recipeRegistryVersion": 1,
        "railRegistryVersion": 1,
        "finalisedAt": 1785859200000,
        "signatures": [],
    }
    F.sign_bundle(bundle, "evidence-bound", signing_keys)

    if definition.get("corruptListingSignature"):
        value = listing["signature"]["value"]
        listing["signature"]["value"] = ("A" if value[0] != "A" else "B") + value[1:]
    if definition.get("corruptBundleSignature"):
        value = bundle["signatures"][0]["value"]
        bundle["signatures"][0]["value"] = ("A" if value[0] != "A" else "B") + value[1:]

    bundle_lifecycle = copy.deepcopy(definition.get("bundleLifecycle") or (
        {"state": "finalized", "independentlyResolvable": True}
        if definition["bundleOutcome"] == "completed"
        else {"state": "included", "independentlyResolvable": False}
    ))
    authority = {
        "listing": listing,
        "bundle": bundle,
        "defaultReferenceLifecycle": copy.deepcopy(default_lifecycle),
        "referenceValidationByCanonicalRef": reference_validation_by_canonical_ref,
        "sessionExecutionAuthorityByPhaseKey": session_execution_authority_by_phase_key,
        "verifiedReceiptByCanonicalRef": verified_receipt_by_canonical_ref,
        "deliveryArtifactAuthorityByPhaseKey": delivery_artifact_authority_by_phase_key,
        "trustedNativeTransactionObservationsByCanonicalRef": (
            trusted_native_transaction_observations_by_canonical_ref
        ),
        "bundleLifecycle": bundle_lifecycle,
    }
    current_laa_by_phase_key = {}
    for ref in settlement_evidence:
        ref_key = F.canonical(ref).decode("utf-8")
        record = reference_validation_by_canonical_ref[ref_key]["record"]
        if (
            record.get("phase", "").startswith("pay-")
            and record.get("outcome") == "success"
        ):
            phase_key = next(
                key for key, execution in session_execution_authority_by_phase_key.items()
                if execution.get("phaseIndex")
                == next(
                    entry["index"] for entry in phase_summary
                    if entry.get("attestationRef") == ref
                )
                and execution.get("phaseKind") == record.get("phase")
            )
            current_laa_by_phase_key[phase_key] = current_laa_phase_carrier(
                bundle,
                listing,
                phase_key,
                record,
                ref,
                verified_receipt_by_canonical_ref[ref_key],
                session_execution_authority_by_phase_key[phase_key],
            )
    authority["legacyAgreementAuthorityByPhaseKey"] = current_laa_by_phase_key
    cross_phase_reuse = definition.get("crossPhaseDeliveryReuse")
    if cross_phase_reuse is not None:
        apply_cross_phase_delivery_reuse(
            authority, cross_phase_reuse, signing_keys
        )
    return authority


def _delivery_resolution(authority, phase_key):
    phase_index_text, phase = phase_key.split(":", 1)
    phase_index = int(phase_index_text)
    for position, ref in enumerate(authority["bundle"]["settlementEvidence"]):
        key = F.canonical(ref).decode("utf-8")
        resolution = authority["referenceValidationByCanonicalRef"].get(key)
        record = resolution.get("record") if isinstance(resolution, dict) else None
        if (
            isinstance(record, dict)
            and record.get("phaseIndex") == phase_index
            and record.get("phase") == phase
        ):
            return position, ref, resolution, record
    raise ValueError("missing current delivery resolution for " + phase_key)


def _refresh_current_delivery_authority(authority, phase_key, signing_keys):
    position, old_ref, resolution, record = _delivery_resolution(
        authority, phase_key
    )
    old_key = F.canonical(old_ref).decode("utf-8")
    top_receipt = authority["verifiedReceiptByCanonicalRef"].pop(old_key)
    authority["referenceValidationByCanonicalRef"].pop(old_key)
    signer = authority["sessionExecutionAuthorityByPhaseKey"][phase_key][
        "phaseOrchestrator"
    ]
    signer_role = next(
        role for role, claim in F.CLAIMS.items() if claim == signer
    )
    F.sign_artifact(
        record,
        signing_keys[signer_role],
        signer,
        F.DELIVERY_EVIDENCE_DOMAIN,
    )
    new_ref = copy.deepcopy(old_ref)
    new_ref["contentHash"] = F.evidence_hash(record)
    new_key = F.canonical(new_ref).decode("utf-8")
    top_receipt["contentHash"] = new_ref["contentHash"]
    authority["referenceValidationByCanonicalRef"][new_key] = resolution
    authority["verifiedReceiptByCanonicalRef"][new_key] = top_receipt
    authority["bundle"]["settlementEvidence"][position] = new_ref
    authority["bundle"]["phaseSummary"][position]["attestationRef"] = new_ref

    closure = authority["deliveryArtifactAuthorityByPhaseKey"][phase_key]
    authority["verifiedReceiptByCanonicalRef"].update(
        F.make_delivery_closure_receipts(
            record,
            closure,
            record["jobId"],
            record["phase"],
            record["phaseIndex"],
        )
    )


def _apply_repeated_self_signed_proofs(
    authority, phase_keys, signing_keys, *, equivalent_assertion
):
    """Replace two current payload proofs with valid self-signed fixtures."""
    listing = authority["listing"]
    deliverable_spec = listing["offering"]["deliverable"]
    method = {"kind": "self-signed"}
    deliverable_spec["verificationMethod"] = method
    listing_payload = (F.LISTING_DOMAIN + F.listing_hash(listing)).encode("utf-8")
    listing["signature"] = {
        "signer": F.CLAIMS["seller"],
        "algorithm": "ed25519",
        "value": F.b64u(signing_keys["seller"].sign(listing_payload)),
    }
    authority["bundle"]["listingRef"]["contentHash"] = F.listing_hash(listing)

    first_key, second_key = phase_keys
    first = authority["deliveryArtifactAuthorityByPhaseKey"][first_key]
    second = authority["deliveryArtifactAuthorityByPhaseKey"][second_key]
    _, _, _, first_record = _delivery_resolution(authority, first_key)
    _, _, _, second_record = _delivery_resolution(authority, second_key)
    if equivalent_assertion:
        second_address = second_record["deliverableAnchor"]["locator"]
        second["deliverable"] = copy.deepcopy(first["deliverable"])
        second["deliverable"]["logicalAddress"] = second_address
        second["deliverable"]["nativeAddress"] = second_address
        second["deliverable"]["_storageBinding"] = {
            "effectiveAccessMode": "public",
            "storedContentHash": second["deliverable"]["storedContentHash"],
        }
        second_record["deliverableContentHash"] = first_record[
            "deliverableContentHash"
        ]
        second["agreementHash"] = first["agreementHash"]
        authority["sessionExecutionAuthorityByPhaseKey"][second_key][
            "agreementHash"
        ] = first["agreementHash"]

    method_hash = hashlib.sha256(F.canonical(method)).hexdigest()
    deliverable_spec_hash = hashlib.sha256(F.canonical(deliverable_spec)).hexdigest()
    proof_key = signing_keys["seller"]
    proof_identifier = proof_key.public_key().public_bytes_raw().hex()
    for position, phase_key in enumerate(phase_keys):
        closure = authority["deliveryArtifactAuthorityByPhaseKey"][phase_key]
        _, _, _, record = _delivery_resolution(authority, phase_key)
        closure["deliverable"]["_storageBinding"] = {
            "effectiveAccessMode": "public",
            "storedContentHash": closure["deliverable"]["storedContentHash"],
        }
        payload_record_entry = closure["payloadAttestationRecord"]
        payload_record = payload_record_entry["artifact"]
        assertion = closure["deliverable"]["cleartextUtf8"]
        assertion_bytes = assertion.encode("utf-8")
        method_input = {
            "identifier": proof_identifier,
            "signature": F.b64u(proof_key.sign(assertion_bytes)),
        }
        if equivalent_assertion and position == 1:
            method_input["assertionBytesBase64url"] = F.b64u(assertion_bytes)
        else:
            method_input["assertion"] = assertion
        proof = {
            "kind": "self-signed-payload",
            "payloadContentHash": closure["deliverable"]["cleartextHash"],
            "methodInput": method_input,
        }
        closure["methodEvidence"]["artifact"] = proof
        payload_record["deliverableSpecHash"] = deliverable_spec_hash
        payload_record["payloadContentHash"] = closure["deliverable"][
            "cleartextHash"
        ]
        payload_record["verificationMethod"] = "self-signed"
        payload_record["verificationMethodHash"] = method_hash
        payload_record["methodEvidenceRef"]["contentHash"] = hashlib.sha256(
            F.canonical(proof)
        ).hexdigest()
        payload_record.pop("methodTransactionRef", None)
        F.sign_artifact(
            payload_record,
            signing_keys["orchestrator"],
            F.CLAIMS["orchestrator"],
            F.PAYLOAD_ATTESTATION_DOMAIN,
        )
        phase_index = int(phase_key.split(":", 1)[0])
        attestation_address = (
            f"dacs4:payload-attestation:{payload_record['jobId']}:"
            f"{phase_index}:{method_hash}:{payload_record['attempt']}"
        )
        payload_record_entry["logicalAddress"] = attestation_address
        payload_record_entry["nativeAddress"] = attestation_address
        record["attestationRef"] = {
            "anchor": {
                "kind": "storage-program", "locator": attestation_address,
            },
            "contentHash": F.evidence_hash(payload_record),
            "signer": payload_record["signature"]["signer"],
        }

    authority["trustedNativeTransactionObservationsByCanonicalRef"] = {}
    for phase_key in phase_keys:
        _refresh_current_delivery_authority(authority, phase_key, signing_keys)


def apply_cross_phase_delivery_reuse(authority, mode, signing_keys):
    """Create exact negative authorities for bundle-wide PDE-6 ownership."""
    phase_keys = sorted(authority["deliveryArtifactAuthorityByPhaseKey"])
    if len(phase_keys) != 2:
        raise ValueError("cross-phase reuse fixtures require exactly two deliveries")
    first_key, second_key = phase_keys
    first = authority["deliveryArtifactAuthorityByPhaseKey"][first_key]
    second = authority["deliveryArtifactAuthorityByPhaseKey"][second_key]
    _, _, _, first_record = _delivery_resolution(authority, first_key)
    _, _, _, second_record = _delivery_resolution(authority, second_key)

    if mode in {
        "self-signed-alternate-encoding", "self-signed-distinct-proof"
    }:
        _apply_repeated_self_signed_proofs(
            authority,
            phase_keys,
            signing_keys,
            equivalent_assertion=(mode == "self-signed-alternate-encoding"),
        )
    elif mode in {"credential-ref", "semantic-credential"}:
        first_entitlement = first["entitlementRecord"]["artifact"]
        second_entitlement = second["entitlementRecord"]["artifact"]
        if mode == "credential-ref":
            second_entitlement["credentialRef"] = copy.deepcopy(
                first_entitlement["credentialRef"]
            )
            # Keep the signed inner artifacts distinct so this fixture isolates
            # the canonical credential reference ownership rule.
            second_entitlement["phaseDeliveryLabel"] = "second-current-delivery"
            second["credential"] = copy.deepcopy(first["credential"])
        else:
            # Preserve the second phase's independently authenticated anchor, but
            # re-anchor the exact same credential bytes and cleartext identity.
            second_credential_ref = second_entitlement["credentialRef"]
            second_credential_ref["ref"]["contentHash"] = first_entitlement[
                "credentialRef"
            ]["ref"]["contentHash"]
            second["credential"] = copy.deepcopy(first["credential"])
            second["credential"]["credentialRef"] = copy.deepcopy(
                second_credential_ref
            )
        F.sign_artifact(
            second_entitlement,
            signing_keys["seller"],
            F.CLAIMS["seller"],
            F.ENTITLEMENT_DOMAIN,
        )
        credential_hash = second["credential"]["storedContentHash"]
        second["credential"]["_storageBinding"] = {
            "effectiveAccessMode": "buyer-only",
            "storedContentHash": credential_hash,
            "acl": {"mode": "restricted", "allowed": [F.CLAIMS["buyer"]]},
        }
        second_record["credentialDelivery"] = copy.deepcopy(
            (
                first_record["credentialDelivery"]
                if mode == "credential-ref"
                else {
                    **second_record["credentialDelivery"],
                    "credentialRef": copy.deepcopy(
                        second_entitlement["credentialRef"]
                    ),
                    "credentialCleartextHash": second["credential"][
                        "cleartextHash"
                    ],
                }
            )
        )
        second_record["deliverableContentHash"] = F.evidence_hash(
            second_entitlement
        )
    elif mode in {"signed-payload-record", "literal-method-ref", "semantic-method-proof"}:
        first_payload = first["deliverable"]
        second_payload_address = second_record["deliverableAnchor"]["locator"]
        second["deliverable"] = copy.deepcopy(first_payload)
        second["deliverable"]["logicalAddress"] = second_payload_address
        second["deliverable"]["nativeAddress"] = second_payload_address
        second["deliverable"]["_storageBinding"] = {
            "effectiveAccessMode": "public",
            "storedContentHash": second["deliverable"]["storedContentHash"],
        }
        second_record["deliverableContentHash"] = first_record[
            "deliverableContentHash"
        ]
        second["agreementHash"] = first["agreementHash"]
        authority["sessionExecutionAuthorityByPhaseKey"][second_key][
            "agreementHash"
        ] = first["agreementHash"]

        first_payload_record = first["payloadAttestationRecord"]["artifact"]
        payload_record = copy.deepcopy(first_payload_record)
        if mode != "signed-payload-record":
            payload_record["verifiedAt"] += 1
        if mode == "semantic-method-proof":
            second_method_address = second["methodEvidence"]["logicalAddress"]
            payload_record["methodEvidenceRef"] = copy.deepcopy(
                first_payload_record["methodEvidenceRef"]
            )
            payload_record["methodEvidenceRef"]["anchor"][
                "locator"
            ] = second_method_address
            second["methodEvidence"] = copy.deepcopy(first["methodEvidence"])
            second["methodEvidence"]["logicalAddress"] = second_method_address
            second["methodEvidence"]["nativeAddress"] = second_method_address
        else:
            second["methodEvidence"] = copy.deepcopy(first["methodEvidence"])
        if mode != "signed-payload-record":
            F.sign_artifact(
                payload_record,
                signing_keys["orchestrator"],
                F.CLAIMS["orchestrator"],
                F.PAYLOAD_ATTESTATION_DOMAIN,
            )
        second_phase_index = int(second_key.split(":", 1)[0])
        attestation_address = (
            f"dacs4:payload-attestation:{payload_record['jobId']}:"
            f"{second_phase_index}:{payload_record['verificationMethodHash']}:"
            f"{payload_record['attempt']}"
        )
        second["payloadAttestationRecord"] = {
            "logicalAddress": attestation_address,
            "nativeAddress": attestation_address,
            "artifact": payload_record,
            "available": True,
            "independentlyResolvable": True,
        }
        second_record["attestationRef"] = {
            "anchor": {
                "kind": "storage-program", "locator": attestation_address,
            },
            "contentHash": F.evidence_hash(payload_record),
            "signer": payload_record["signature"]["signer"],
        }
    else:
        raise ValueError("unsupported cross-phase reuse fixture: " + str(mode))

    if mode not in {
        "self-signed-alternate-encoding", "self-signed-distinct-proof"
    }:
        _refresh_current_delivery_authority(authority, second_key, signing_keys)
    F.sign_bundle(authority["bundle"], "evidence-bound", signing_keys)


def semantic_definitions(data):
    if "executionAuthorityDefinitions" in data:
        return copy.deepcopy(data["executionAuthorityDefinitions"])
    definitions = copy.deepcopy(data["executionAuthorities"])
    for definition in definitions.values():
        if definition.pop("listingSignatureVerified", True) is False:
            definition["corruptListingSignature"] = True
        definition.pop("bundleDiscriminator", None)
        if definition.pop("bundleSignaturesVerified", True) is False:
            definition["corruptBundleSignature"] = True
    return definitions


def generate(source):
    data = copy.deepcopy(source)
    data["inputModel"] = (
        "executionAuthorityRef selects a domain-verified EBFAB phaseSummary plus its "
        "content-hash-bound, signature-verified DACS-1 listing pipeline; the evaluator "
        "requires an ordered, outcome-consistent execution prefix and derives phase keys "
        "locally. sessionExecutionAuthorityByPhaseKey and verifiedReceiptByCanonicalRef are "
        "independently authenticated SB-1/SR-2 inputs, separate from resolved evidence content. "
        "authenticatedRecordByRef represents independently resolved, job-bound evidence content; "
        "the authenticated phase and uniquely verified signature domain fix its family before the "
        "selector is checked. Payment members are SettlementEvidence, current delivery members are DeliveryEvidence, "
        "and current DeliveryEvidence plus its top-level receipt are controlled by the authenticated "
        "phase orchestrator even when that role is distinct from the seller that writes deliverables, "
        "EntitlementRecords, and credentials; PDE-7 permits only a single unambiguous "
        "delivery-shaped SettlementEvidence. "
        "deliveryArtifactAuthorityByPhaseKey supplies the independently resolved deliverable, "
        "entitlement/credential, or payload-attestation/method-proof closure required "
        "before successful current or legacy delivery evidence can authorize its phase; legacy "
        "closure retains its original unindexed addresses and cannot synthesize credential binding. "
        "Each inner dependency is keyed by its complete canonical reference in the authenticated "
        "receipt map, with exact lifecycle, storage-byte, ACL, or encryption-recipient authority. "
        "trustedNativeTransactionObservationsByCanonicalRef is fixture-only authority keyed by the "
        "complete canonical methodTransactionRef; it is not a portable consensus-proof format. "
        "The record outcome and hashed supersedesEvidenceRef, not "
        "caller-supplied class or edge labels, determine ST-8 terminal selection. Completed "
        "authorities require finalized and independently resolvable evidence; failed or "
        "aborted authorities require included or finalized evidence. Optional pointers never "
        "create phase authority."
    )
    if "execution-authority-indeterminate" not in data["reasonCodes"]:
        data["reasonCodes"].append("execution-authority-indeterminate")
    if "execution-authority-indeterminate" not in data["reasonPrecedence"]:
        data["reasonPrecedence"].insert(1, "execution-authority-indeterminate")
    definitions = semantic_definitions(data)
    definitions["completed-storage-delivery"] = {
        "listingPipeline": ["deliver-storage-program"],
        "bundleOutcome": "completed",
        "phaseSummary": [{
            "index": 0,
            "kind": "deliver-storage-program",
            "outcome": "ok",
        }],
        "defaultReferenceLifecycle": {
            "state": "finalized",
            "independentlyResolvable": True,
        },
    }
    definitions["seller-substituted-current-delivery"] = copy.deepcopy(
        definitions["completed-storage-delivery"]
    )
    definitions["seller-substituted-current-delivery"][
        "deliveryEvidenceSignerRole"
    ] = "seller"
    legacy_completed = {
        "bundleOutcome": "completed",
        "defaultReferenceLifecycle": {
            "state": "finalized",
            "independentlyResolvable": True,
        },
        "legacyDeliveryEvidence": True,
    }
    for name, phase in (
        ("legacy-storage-completed", "deliver-storage-program"),
        ("legacy-entitlement-completed", "deliver-entitlement"),
        ("legacy-attested-completed", "deliver-attested-payload"),
    ):
        definitions[name] = {
            **copy.deepcopy(legacy_completed),
            "listingPipeline": [phase],
            "phaseSummary": [{"index": 0, "kind": phase, "outcome": "ok"}],
        }
    definitions["legacy-self-signed-attested-completed"] = copy.deepcopy(
        definitions["legacy-attested-completed"]
    )
    definitions["legacy-self-signed-attested-completed"]["legacySelfSigned"] = True
    definitions["legacy-repeated-storage-invalid"] = {
        **copy.deepcopy(legacy_completed),
        "listingPipeline": [
            "deliver-storage-program",
            "deliver-storage-program",
        ],
        "phaseSummary": [
            {"index": 0, "kind": "deliver-storage-program", "outcome": "ok"},
            {"index": 1, "kind": "deliver-storage-program", "outcome": "ok"},
        ],
    }
    current_completed = {
        "bundleOutcome": "completed",
        "defaultReferenceLifecycle": {
            "state": "finalized",
            "independentlyResolvable": True,
        },
    }
    cross_phase_delivery_reuse = {
        "cross-phase-credential-ref-reuse": (
            "deliver-entitlement", "credential-ref"
        ),
        "cross-phase-semantic-credential-reuse": (
            "deliver-entitlement", "semantic-credential"
        ),
        "cross-phase-signed-payload-reuse": (
            "deliver-attested-payload", "signed-payload-record"
        ),
        "cross-phase-literal-method-ref-reuse": (
            "deliver-attested-payload", "literal-method-ref"
        ),
        "cross-phase-semantic-method-proof-reuse": (
            "deliver-attested-payload", "semantic-method-proof"
        ),
        "cross-phase-self-signed-alternate-encoding-reuse": (
            "deliver-attested-payload", "self-signed-alternate-encoding"
        ),
    }
    for authority_name, (phase, reuse_mode) in cross_phase_delivery_reuse.items():
        definitions[authority_name] = {
            **copy.deepcopy(current_completed),
            "listingPipeline": [phase, phase],
            "phaseSummary": [
                {"index": 0, "kind": phase, "outcome": "ok"},
                {"index": 1, "kind": phase, "outcome": "ok"},
            ],
            "crossPhaseDeliveryReuse": reuse_mode,
        }
    definitions["repeated-self-signed-distinct-proof-completed"] = {
        **copy.deepcopy(current_completed),
        "listingPipeline": [
            "deliver-attested-payload", "deliver-attested-payload",
        ],
        "phaseSummary": [
            {
                "index": 0,
                "kind": "deliver-attested-payload",
                "outcome": "ok",
            },
            {
                "index": 1,
                "kind": "deliver-attested-payload",
                "outcome": "ok",
            },
        ],
        "crossPhaseDeliveryReuse": "self-signed-distinct-proof",
    }
    if "invalid-bundle-signature" not in definitions:
        definitions["invalid-bundle-signature"] = copy.deepcopy(definitions["standard-completed"])
        definitions["invalid-bundle-signature"]["corruptBundleSignature"] = True
    if "mismatched-listing-signer" not in definitions:
        definitions["mismatched-listing-signer"] = copy.deepcopy(definitions["standard-completed"])
        definitions["mismatched-listing-signer"]["listingSignerRole"] = "buyer"
    if "invalid-completed-bundle-lifecycle" not in definitions:
        definitions["invalid-completed-bundle-lifecycle"] = copy.deepcopy(definitions["standard-completed"])
        definitions["invalid-completed-bundle-lifecycle"]["bundleLifecycle"] = {
            "state": "accepted",
            "independentlyResolvable": False,
        }
    definitions["failed-delivery"]["defaultReferenceLifecycle"]["independentlyResolvable"] = False
    definitions["single-htlc-completed"]["st8Resolved"] = True
    definitions["single-htlc-direct-completed"] = copy.deepcopy(
        definitions["single-htlc-completed"]
    )
    definitions["single-htlc-direct-completed"].pop("st8Resolved", None)
    definitions["single-htlc-expired"] = copy.deepcopy(definitions["single-htlc-completed"])
    definitions["single-htlc-expired"].pop("st8Resolved", None)
    definitions["single-htlc-expired"]["bundleOutcome"] = "failed-counterparty"
    definitions["single-htlc-expired"]["phaseSummary"][-1].update({
        "outcome": "fail",
        "errorClass": "settlement-atomicity",
    })
    definitions["single-htlc-expired"]["defaultReferenceLifecycle"] = {
        "state": "included",
        "independentlyResolvable": False,
    }
    definitions["invalid-completed-incomplete-summary"] = copy.deepcopy(
        definitions["standard-completed"]
    )
    definitions["invalid-completed-incomplete-summary"]["phaseSummary"] = []
    definitions["invalid-failed-gapped-summary"] = copy.deepcopy(definitions["standard-completed"])
    definitions["invalid-failed-gapped-summary"]["bundleOutcome"] = "failed-perm"
    definitions["invalid-failed-gapped-summary"]["phaseSummary"] = [
        copy.deepcopy(definitions["standard-completed"]["phaseSummary"][0]),
        {
            **copy.deepcopy(definitions["standard-completed"]["phaseSummary"][2]),
            "outcome": "fail",
            "errorClass": "permanent",
        },
    ]
    definitions["invalid-aborted-result-summary"] = copy.deepcopy(definitions["aborted-before-result"])
    definitions["invalid-aborted-result-summary"]["phaseSummary"] = [{
        "index": 0,
        "kind": definitions["aborted-before-result"]["listingPipeline"][0],
        "outcome": "fail",
        "errorClass": "counterparty",
    }]
    definitions["invalid-failed-outcome-error-class"] = copy.deepcopy(definitions["failed-delivery"])
    definitions["invalid-failed-outcome-error-class"]["phaseSummary"][-1]["errorClass"] = "substrate"
    definitions["invalid-st8-expired-wrong-reason"] = copy.deepcopy(definitions["single-htlc-expired"])
    definitions["invalid-st8-expired-wrong-reason"]["evidenceReasonOverride"] = "settlement-atomicity"
    definitions["transient-retry-exhausted"] = copy.deepcopy(definitions["failed-delivery"])
    definitions["transient-retry-exhausted"]["phaseSummary"][-1].update({
        "errorClass": "transient",
        "retryExhausted": True,
    })
    definitions["invalid-transient-not-exhausted"] = copy.deepcopy(
        definitions["transient-retry-exhausted"]
    )
    definitions["invalid-transient-not-exhausted"]["phaseSummary"][-1].pop(
        "retryExhausted"
    )
    definitions["invalid-completed-st8-interim-lifecycle"] = copy.deepcopy(
        definitions["single-htlc-completed"]
    )
    definitions["invalid-completed-st8-interim-lifecycle"]["st8InterimLifecycle"] = {
        "state": "included",
        "independentlyResolvable": False,
    }
    definitions["invalid-completed-st8-missing-supersedes"] = copy.deepcopy(
        definitions["single-htlc-completed"]
    )
    definitions["invalid-completed-st8-missing-supersedes"]["omitSt8Supersedes"] = True

    inner_mutations = {
        "invalid-deliverable-locator-closure": (
            "standard-completed", "deliverable-locator"
        ),
        "invalid-attestation-locator-closure": (
            "standard-completed", "attestation-locator"
        ),
        "invalid-attestation-content-hash-closure": (
            "standard-completed", "attestation-content-hash"
        ),
        "invalid-entitlement-locator-closure": (
            "repeated-pay-completed", "entitlement-locator"
        ),
        "invalid-credential-delivery-omitted": (
            "repeated-pay-completed", "omit-credential-delivery"
        ),
        "invalid-entitlement-duration-closure": (
            "repeated-pay-completed", "entitlement-duration"
        ),
        "invalid-entitlement-renewable-closure": (
            "repeated-pay-completed", "entitlement-renewable"
        ),
        "unavailable-native-transaction-observation": (
            "standard-completed", "native-observation-unavailable"
        ),
        "unobserved-resigned-native-transaction": (
            "standard-completed", "native-transaction"
        ),
        "invalid-native-transaction-observation": (
            "standard-completed", "native-observation-mismatch"
        ),
        "invalid-terminal-included-native-transaction": (
            "standard-completed", "native-terminal-included"
        ),
    }
    for authority_name, (source_name, mutation) in inner_mutations.items():
        definitions[authority_name] = copy.deepcopy(definitions[source_name])
        definitions[authority_name]["innerArtifactMutation"] = mutation

    for authority_name in inner_mutations:
        vector_name = f"bundle-settlement-bijection-{authority_name}-reject"
        if any(vector["name"] == vector_name for vector in data["vectors"]):
            continue
        indeterminate = authority_name in {
            "unavailable-native-transaction-observation",
            "unobserved-resigned-native-transaction",
        }
        data["vectors"].append({
            "name": vector_name,
            "expected": "indeterminate" if indeterminate else "fail",
            "input": {
                "executionAuthorityRef": authority_name,
                "topLevelRefs": [],
                "resolvedReferencePhaseKeys": {},
                "pointerMap": {},
                "unrelatedAuthorityDisposition": "verified",
            },
            "want": {
                "disposition": "indeterminate" if indeterminate else "rejected",
                "reasonCode": (
                    "execution-authority-indeterminate"
                    if indeterminate else "execution-authority"
                ),
            },
        })

    seller_substitution_vector = (
        "bundle-settlement-bijection-seller-substituted-current-delivery-reject"
    )
    seller_substitution_case = {
        "name": seller_substitution_vector,
        "expected": "fail",
        "input": {
            "executionAuthorityRef": "seller-substituted-current-delivery",
            "topLevelRefs": [],
            "authenticatedRecordByRef": {},
            "pointerMap": {},
            "unrelatedAuthorityDisposition": "verified",
        },
        "want": {
            "disposition": "rejected",
            "reasonCode": "execution-authority",
        },
    }
    existing_seller_substitution = next((
        vector for vector in data["vectors"]
        if vector["name"] == seller_substitution_vector
    ), None)
    if existing_seller_substitution is None:
        data["vectors"].append(seller_substitution_case)
    else:
        existing_seller_substitution.clear()
        existing_seller_substitution.update(seller_substitution_case)

    for authority_name in cross_phase_delivery_reuse:
        vector_name = f"bundle-settlement-bijection-{authority_name}-reject"
        if any(vector["name"] == vector_name for vector in data["vectors"]):
            continue
        data["vectors"].append({
            "name": vector_name,
            "expected": "fail",
            "input": {
                "executionAuthorityRef": authority_name,
                "topLevelRefs": [],
                "resolvedReferencePhaseKeys": {},
                "pointerMap": {},
                "unrelatedAuthorityDisposition": "verified",
            },
            "want": {
                "disposition": "rejected",
                "reasonCode": "execution-authority",
            },
        })

    distinct_self_signed_vector = (
        "bundle-settlement-bijection-repeated-self-signed-distinct-proof-pass"
    )
    distinct_self_signed_case = {
        "name": distinct_self_signed_vector,
        "expected": "pass",
        "input": {
            "executionAuthorityRef": (
                "repeated-self-signed-distinct-proof-completed"
            ),
            "topLevelRefs": [
                "ref-self-signed-0", "ref-self-signed-1",
            ],
            "resolvedReferencePhaseKeys": {
                "ref-self-signed-0": "0:deliver-attested-payload",
                "ref-self-signed-1": "1:deliver-attested-payload",
            },
            "pointerMap": {},
            "unrelatedAuthorityDisposition": "verified",
        },
        "want": {"disposition": "verified", "reasonCode": "ok"},
    }
    existing_distinct_self_signed = next((
        vector for vector in data["vectors"]
        if vector["name"] == distinct_self_signed_vector
    ), None)
    if existing_distinct_self_signed is None:
        data["vectors"].append(distinct_self_signed_case)
    else:
        existing_distinct_self_signed.clear()
        existing_distinct_self_signed.update(distinct_self_signed_case)

    legacy_vector_definitions = (
        (
            "bundle-settlement-bijection-legacy-storage-closure-pass",
            "legacy-storage-completed",
            "0:deliver-storage-program",
            "ref-legacy-storage",
        ),
        (
            "bundle-settlement-bijection-legacy-entitlement-closure-pass",
            "legacy-entitlement-completed",
            "0:deliver-entitlement",
            "ref-legacy-entitlement",
        ),
        (
            "bundle-settlement-bijection-legacy-attested-closure-pass",
            "legacy-attested-completed",
            "0:deliver-attested-payload",
            "ref-legacy-attested",
        ),
        (
            "bundle-settlement-bijection-legacy-self-signed-closure-pass",
            "legacy-self-signed-attested-completed",
            "0:deliver-attested-payload",
            "ref-legacy-self-signed",
        ),
    )
    for vector_name, authority_name, phase_key, ref_name in legacy_vector_definitions:
        if any(vector["name"] == vector_name for vector in data["vectors"]):
            continue
        data["vectors"].append({
            "name": vector_name,
            "expected": "pass",
            "input": {
                "executionAuthorityRef": authority_name,
                "topLevelRefs": [ref_name],
                "resolvedReferencePhaseKeys": {ref_name: phase_key},
                "pointerMap": {},
                "unrelatedAuthorityDisposition": "verified",
            },
            "want": {"disposition": "verified", "reasonCode": "ok"},
        })

    repeated_legacy_vector = (
        "bundle-settlement-bijection-legacy-repeated-delivery-reject"
    )
    if not any(vector["name"] == repeated_legacy_vector for vector in data["vectors"]):
        data["vectors"].append({
            "name": repeated_legacy_vector,
            "expected": "fail",
            "input": {
                "executionAuthorityRef": "legacy-repeated-storage-invalid",
                "topLevelRefs": [],
                "resolvedReferencePhaseKeys": {},
                "pointerMap": {},
                "unrelatedAuthorityDisposition": "verified",
            },
            "want": {
                "disposition": "rejected",
                "reasonCode": "execution-authority",
            },
        })

    direct_success_name = "bundle-settlement-bijection-cross-chain-direct-success-pass"
    if not any(vector["name"] == direct_success_name for vector in data["vectors"]):
        data["vectors"].append({
            "name": direct_success_name,
            "expected": "pass",
            "input": {
                "executionAuthorityRef": "single-htlc-direct-completed",
                "topLevelRefs": ["ref-direct-success"],
                "resolvedReferencePhaseKeys": {
                    "ref-direct-success": "2:pay-cross-chain-htlc",
                },
                "pointerMap": {},
                "unrelatedAuthorityDisposition": "verified",
            },
            "want": {"disposition": "verified", "reasonCode": "ok"},
        })

    for vector in data["vectors"]:
        if vector["name"] == "bundle-settlement-bijection-st8-expired-interim-pass":
            vector["input"]["executionAuthorityRef"] = "single-htlc-expired"

    vector_name = "bundle-settlement-bijection-invalid-bundle-authority-reject"
    if not any(vector["name"] == vector_name for vector in data["vectors"]):
        data["vectors"].append({
            "name": vector_name,
            "expected": "fail",
            "input": {
                "executionAuthorityRef": "invalid-bundle-signature",
                "topLevelRefs": ["ref-pay", "ref-deliver"],
                "resolvedReferencePhaseKeys": {
                    "ref-pay": "2:pay-dem",
                    "ref-deliver": "3:deliver-attested-payload",
                },
                "pointerMap": {},
                "supersedesEdges": {},
                "unrelatedAuthorityDisposition": "verified",
            },
            "want": {"disposition": "rejected", "reasonCode": "execution-authority"},
        })
    signer_vector_name = "bundle-settlement-bijection-mismatched-listing-signer-reject"
    if not any(vector["name"] == signer_vector_name for vector in data["vectors"]):
        data["vectors"].append({
            "name": signer_vector_name,
            "expected": "fail",
            "input": {
                "executionAuthorityRef": "mismatched-listing-signer",
                "topLevelRefs": ["ref-pay", "ref-deliver"],
                "resolvedReferencePhaseKeys": {
                    "ref-pay": "2:pay-dem",
                    "ref-deliver": "3:deliver-attested-payload",
                },
                "pointerMap": {},
                "supersedesEdges": {},
                "unrelatedAuthorityDisposition": "verified",
            },
            "want": {"disposition": "rejected", "reasonCode": "execution-authority"},
        })
    lifecycle_vector_name = "bundle-settlement-bijection-completed-bundle-not-finalized-reject"
    if not any(vector["name"] == lifecycle_vector_name for vector in data["vectors"]):
        data["vectors"].append({
            "name": lifecycle_vector_name,
            "expected": "fail",
            "input": {
                "executionAuthorityRef": "invalid-completed-bundle-lifecycle",
                "topLevelRefs": ["ref-pay", "ref-deliver"],
                "resolvedReferencePhaseKeys": {
                    "ref-pay": "2:pay-dem",
                    "ref-deliver": "3:deliver-attested-payload",
                },
                "pointerMap": {},
                "supersedesEdges": {},
                "unrelatedAuthorityDisposition": "verified",
            },
            "want": {"disposition": "rejected", "reasonCode": "execution-authority"},
        })
    incomplete_trace_name = "bundle-settlement-bijection-incomplete-completed-summary-reject"
    if not any(vector["name"] == incomplete_trace_name for vector in data["vectors"]):
        data["vectors"].append({
            "name": incomplete_trace_name,
            "expected": "fail",
            "input": {
                "executionAuthorityRef": "invalid-completed-incomplete-summary",
                "topLevelRefs": [],
                "resolvedReferencePhaseKeys": {},
                "pointerMap": {},
                "recordClassByRef": {},
                "supersedesEdges": {},
                "unrelatedAuthorityDisposition": "verified",
            },
            "want": {"disposition": "rejected", "reasonCode": "execution-authority"},
        })
    failed_positive = next(
        vector for vector in data["vectors"]
        if vector["name"] == "bundle-settlement-bijection-failed-phase-included-pass"
    )
    failed_positive["input"]["referenceLifecycleByRef"] = {
        "ref-failed-delivery": {
            "state": "included",
            "independentlyResolvable": False,
        }
    }

    signing_keys = F.keys()
    data["generator"] = "scripts/generate_bundle_settlement_evidence_vectors.py"
    data["seeds"] = F.SEEDS
    data["publicKeys"] = {
        F.CLAIMS[role]: F.b64u(key.public_key().public_bytes_raw())
        for role, key in signing_keys.items()
    }
    data["domains"] = {
        "listing": F.LISTING_DOMAIN,
        "evidenceBoundBundle": F.DOMAINS["evidence-bound"],
    }
    data["executionAuthorityDefinitions"] = definitions
    data["executionAuthorities"] = {
        name: make_authority(name, definition, signing_keys)
        for name, definition in definitions.items()
    }
    for vector in data["vectors"]:
        vector_input = vector["input"]
        authority = data["executionAuthorities"].get(vector_input.get("executionAuthorityRef"))
        job_id = authority["bundle"]["jobId"] if authority else "unresolved-authority"
        outcome_by_key = {
            f"{entry['index']}:{entry['kind']}": (
                "success" if entry["outcome"] == "ok" else "failure"
            )
            for entry in (authority or {}).get("bundle", {}).get("phaseSummary", [])
        }
        if "resolvedReferencePhaseKeys" in vector_input:
            resolved = vector_input.pop("resolvedReferencePhaseKeys")
            record_classes = vector_input.pop("recordClassByRef", {})
            supersedes = vector_input.pop("supersedesEdges", {})
            authenticated_records = {}
            for ref, phase_key in resolved.items():
                record_class = record_classes.get(ref)
                outcome = outcome_by_key.get(phase_key, "success")
                if record_class == "st8-resolved-success":
                    outcome = "success"
                elif record_class == "st8-expired-interim-failure":
                    outcome = "failure"
                record = {
                    "jobId": job_id,
                    "phaseKey": phase_key,
                    "outcome": outcome,
                }
                if ref in supersedes:
                    record["supersedesEvidenceRef"] = supersedes[ref]
                authenticated_records[ref] = record
        else:
            authenticated_records = copy.deepcopy(vector_input.get("authenticatedRecordByRef", {}))

        def st8_reason(phase_key):
            phase = phase_key.split(":", 1)[1] if isinstance(phase_key, str) and ":" in phase_key else None
            return {
                "pay-cross-chain-htlc": "dest-revealed-source-unclaimed",
                "pay-cross-chain-liquidity-tank": "tank-locked-unreleased",
            }.get(phase)

        for ref, record in list(authenticated_records.items()):
            record["jobId"] = job_id
            reason = st8_reason(record.get("phaseKey"))
            if record.get("outcome") == "failure" and reason and "st8" in vector["name"].lower():
                record["reason"] = reason
            interim_ref = record.get("supersedesEvidenceRef")
            if interim_ref is not None and interim_ref not in authenticated_records:
                authenticated_records[interim_ref] = {
                    "jobId": job_id,
                    "phaseKey": record.get("phaseKey"),
                    "outcome": "failure",
                    "reason": reason,
                }
        vector_input["authenticatedRecordByRef"] = authenticated_records
    data["count"] = len(data["vectors"])
    data["hash"] = hashlib.sha256(F.canonical(data["vectors"])).hexdigest()
    return data


def encoded(source):
    return (json.dumps(generate(source), indent=2, ensure_ascii=False) + "\n").encode()


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    source = json.loads(TARGET.read_text(encoding="utf-8"))
    generated = encoded(source)
    if args.write:
        TARGET.write_bytes(generated)
        print(f"wrote {TARGET.relative_to(ROOT)}")
        return 0
    if TARGET.read_bytes() != generated:
        print(f"{TARGET.relative_to(ROOT)} is stale; run this script with --write", file=sys.stderr)
        return 1
    print(f"verified {TARGET.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
