"""Execute the #390 identity-bound agreement conformance corpus."""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_identity_bundle_hash_binding_vectors as generator  # noqa: E402


VECTORS = ROOT / "conformance/vectors/security/identity-bundle-hash-binding-v0.1.json"
PAYEE_VECTORS = ROOT / "conformance/vectors/security/payee-destination-binding-v0.1.json"
HEX = re.compile(r"[0-9a-f]{64}\Z")


def outcome(verdict: str, reason: str) -> tuple[str, dict]:
    return verdict, {
        "verdict": verdict,
        "authorizedAction": verdict == "pass",
        "reason": reason,
    }


def b64url_decode(value: object) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("non-canonical Base64URL")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if generator.b64url(decoded) != value:
        raise ValueError("non-canonical Base64URL")
    return decoded


def key_bytes(claim: object) -> bytes:
    if not isinstance(claim, str) or not claim.startswith("key:"):
        raise ValueError("not a key claim")
    public = claim.removeprefix("key:")
    if not HEX.fullmatch(public):
        raise ValueError("non-canonical key claim")
    return bytes.fromhex(public)


def verify_payload(signature: object, payload: bytes, signer: object) -> bool:
    if not isinstance(signature, dict) or set(signature) != {
        "algorithm", "signer", "value"
    }:
        return False
    if signature.get("algorithm") != "ed25519" or signature.get("signer") != signer:
        return False
    try:
        return generator.verify_ed25519(
            key_bytes(signer), b64url_decode(signature.get("value")), payload
        )
    except (TypeError, ValueError):
        return False


def verify_component(value: object, domain: str, signer: object) -> bool:
    if not isinstance(value, dict):
        return False
    try:
        digest = generator.hash_hex(generator.unsigned(value, "signature"))
    except (TypeError, ValueError):
        return False
    return verify_payload(
        value.get("signature"), (domain + digest).encode("ascii"), signer
    )


def valid_ref(reference: object) -> bool:
    if not isinstance(reference, dict) or set(reference) != {"anchor", "contentHash"}:
        return False
    anchor = reference.get("anchor")
    return (
        isinstance(anchor, dict)
        and set(anchor) == {"kind", "locator"}
        and anchor.get("kind") in {"storage-program", "https", "ipfs"}
        and isinstance(anchor.get("locator"), str)
        and bool(anchor["locator"])
        and isinstance(reference.get("contentHash"), str)
        and bool(HEX.fullmatch(reference["contentHash"]))
    )


def validate_identity_bundle(bundle: object, nonce: object) -> tuple[str, str, str | None]:
    if not isinstance(bundle, dict):
        return "error", "malformed-input", None
    if (
        bundle.get("bundleVersion") != "1"
        or not isinstance(bundle.get("presentedBy"), str)
        or not isinstance(bundle.get("presentedAt"), int)
        or isinstance(bundle.get("presentedAt"), bool)
        or not isinstance(bundle.get("sessionNonce"), str)
        or not isinstance(bundle.get("claims"), list)
        or not bundle["claims"]
    ):
        return "error", "malformed-input", None
    if not isinstance(nonce, str) or bundle["sessionNonce"] != nonce:
        return "fail", "session-nonce-mismatch", None
    claims = bundle["claims"]
    if any(
        not isinstance(claim, dict) or not isinstance(claim.get("ref"), str)
        for claim in claims
    ):
        return "error", "malformed-input", None
    presented_by = bundle["presentedBy"]
    if sum(claim.get("ref") == presented_by for claim in claims) != 1:
        return "fail", "identity-bundle-invalid", None
    presentation = bundle.get("presentation")
    if not isinstance(presentation, dict) or presentation.get("kind") != "per-claim":
        return "error", "malformed-input", None
    signatures = presentation.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        return "error", "malformed-input", None
    signature = signatures[0]
    if not isinstance(signature, dict) or set(signature) != {"ref", "signature"}:
        return "error", "malformed-input", None
    if signature.get("ref") != presented_by:
        return "fail", "identity-bundle-invalid", None
    try:
        digest = generator.hash_hex(generator.unsigned(bundle, "presentation"))
        valid = generator.verify_ed25519(
            key_bytes(presented_by), b64url_decode(signature.get("signature")),
            (generator.BUNDLE_DOMAIN + digest).encode("ascii")
        )
    except (TypeError, ValueError):
        valid = False
    if not valid:
        return "fail", "identity-bundle-invalid", None
    return "pass", "verified", digest


def listing_phase(context: dict) -> tuple[str, str, str | None]:
    listing = context.get("listing")
    if not isinstance(listing, dict):
        return "error", "malformed-input", None
    pipeline = listing.get("pipeline")
    seller = listing.get("seller")
    if (
        listing.get("dacsVersion") != "1"
        or not isinstance(pipeline, list)
        or not pipeline
        or any(
            not isinstance(step, dict) or not isinstance(step.get("kind"), str)
            for step in pipeline
        )
        or not isinstance(seller, dict)
        or not isinstance(seller.get("identity"), dict)
    ):
        return "error", "malformed-input", None
    phases = [
        step["kind"] for step in pipeline
        if step["kind"] in generator.PHASES.values()
    ]
    if len(phases) != 1:
        return "error", "malformed-input", None
    signer = seller["identity"].get("presentedBy")
    if not verify_component(listing, generator.LISTING_DOMAIN, signer):
        return "fail", "listing-signature-invalid", None
    bundle_result, bundle_reason, _ = validate_identity_bundle(
        seller["identity"], context.get("verifierContext", {}).get("sessionNonce")
    )
    if bundle_result != "pass":
        return bundle_result, bundle_reason, None
    return "pass", "verified", phases[0]


def artifact_type(agreement: object) -> tuple[str, str | None]:
    if not isinstance(agreement, dict):
        return "error", None
    present = [
        artifact for artifact, field in generator.DISCRIMINATORS.items()
        if field in agreement
    ]
    if len(present) != 1:
        return "fail", None
    artifact = present[0]
    if agreement.get(generator.DISCRIMINATORS[artifact]) != "1":
        return "fail", None
    return "pass", artifact


def verify_agreement(agreement: object, artifact: str) -> tuple[str, str]:
    if not isinstance(agreement, dict):
        return "error", "malformed-input"
    parties = agreement.get("parties")
    if (
        not isinstance(agreement.get("jobId"), str)
        or not isinstance(agreement.get("listingRef"), dict)
        or not isinstance(agreement.get("terms"), dict)
        or not isinstance(parties, list)
        or len(parties) != 2
    ):
        return "error", "malformed-input"
    for party in parties:
        if (
            not isinstance(party, dict)
            or not isinstance(party.get("role"), str)
            or not isinstance(party.get("primaryClaim"), str)
            or not isinstance(party.get("bundleHash"), str)
            or not valid_ref(party.get("vetRecordRef"))
        ):
            return "error", "malformed-input"
    if sorted(party["role"] for party in parties) != ["buyer", "seller"]:
        return "fail", "agreement-role-invalid"
    expected_signers = {party["primaryClaim"] for party in parties}
    signatures = agreement.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 2:
        return "error", "malformed-input"
    if any(
        not isinstance(signature, dict)
        or set(signature) != {"party", "algorithm", "value"}
        or not isinstance(signature.get("party"), str)
        for signature in signatures
    ):
        return "error", "malformed-input"
    if {signature["party"] for signature in signatures} != expected_signers:
        return "fail", "agreement-signers-invalid"
    try:
        digest = generator.hash_hex(generator.unsigned(agreement, "signatures"))
    except (TypeError, ValueError):
        return "error", "malformed-input"
    for signature in signatures:
        if signature.get("algorithm") != "ed25519":
            return "fail", "agreement-signature-invalid"
        try:
            valid = generator.verify_ed25519(
                key_bytes(signature["party"]), b64url_decode(signature.get("value")),
                (generator.AGREEMENT_DOMAINS[artifact] + digest).encode("ascii")
            )
        except (TypeError, ValueError):
            valid = False
        if not valid:
            return "fail", "agreement-signature-invalid"
    return "pass", "verified"


def agreement_role_claims(agreement: object) -> tuple[str, dict[str, str]]:
    if not isinstance(agreement, dict) or not isinstance(agreement.get("parties"), list):
        return "error", {}
    claims: dict[str, str] = {}
    for party in agreement["parties"]:
        if (
            not isinstance(party, dict)
            or party.get("role") not in {"buyer", "seller"}
            or not isinstance(party.get("primaryClaim"), str)
            or party["role"] in claims
        ):
            return "error", {}
        claims[party["role"]] = party["primaryClaim"]
    if set(claims) != {"buyer", "seller"}:
        return "error", {}
    return "pass", claims


def verify_anchor_receipt(
    wrapped: dict, record: dict, orchestrator: str
) -> tuple[str, str, int | None]:
    receipt = wrapped.get("anchorReceipt")
    if not isinstance(receipt, dict):
        return "error", "malformed-input", None
    transaction_ref = receipt.get("transactionRef")
    block_ref = receipt.get("blockRef")
    evidence = receipt.get("evidence")
    if (
        receipt.get("receiptVersion") != "1"
        or not isinstance(receipt.get("substrate"), str)
        or not isinstance(receipt.get("finalityProfile"), str)
        or not isinstance(receipt.get("logicalAddress"), str)
        or not isinstance(receipt.get("nativeAddress"), str)
        or not isinstance(receipt.get("contentHash"), str)
        or not isinstance(transaction_ref, dict)
        or not isinstance(transaction_ref.get("kind"), str)
        or not isinstance(transaction_ref.get("value"), str)
        or receipt.get("writer") != orchestrator
        or receipt.get("state") != "finalized"
        or receipt.get("observationDisposition") != "established"
        or not isinstance(receipt.get("observedAt"), int)
        or isinstance(receipt.get("observedAt"), bool)
        or not isinstance(block_ref, dict)
        or not isinstance(block_ref.get("id"), str)
        or not isinstance(block_ref.get("height"), str)
        or not isinstance(block_ref.get("timestamp"), int)
        or isinstance(block_ref.get("timestamp"), bool)
        or not isinstance(evidence, dict)
        or evidence.get("kind") != "ed25519"
        or not isinstance(evidence.get("value"), str)
    ):
        return "error", "malformed-input", None
    try:
        content_hash = generator.hash_hex(record)
        evidence_digest = generator.hash_hex(
            generator.unsigned(receipt, "evidence")
        )
        valid = generator.verify_ed25519(
            key_bytes(orchestrator), b64url_decode(evidence["value"]),
            (generator.RECEIPT_EVIDENCE_DOMAIN + evidence_digest).encode("ascii")
        )
    except (TypeError, ValueError):
        valid = False
    if not valid:
        return "fail", "commitment-receipt-invalid", None
    if (
        receipt["contentHash"] != content_hash
        or receipt["logicalAddress"] != f"dacs3:commit:{record.get('jobId')}"
    ):
        return "fail", "commitment-receipt-invalid", None
    return "pass", "verified", block_ref["timestamp"]


def verify_commitment(context: dict) -> tuple[str, str, str | None]:
    wrapped = context.get("commitment")
    agreement = context.get("agreement")
    if not isinstance(wrapped, dict) or not isinstance(agreement, dict):
        return "error", "malformed-input", None
    record = wrapped.get("record")
    if not isinstance(record, dict):
        return "error", "malformed-input", None
    verifier_context = context.get("verifierContext")
    if not isinstance(verifier_context, dict):
        return "error", "malformed-input", None
    orchestrator = verifier_context.get("authenticatedOrchestrator")
    if not isinstance(orchestrator, str):
        return "error", "malformed-input", None
    receipt_status, receipt_reason, anchor_timestamp = verify_anchor_receipt(
        wrapped, record, orchestrator
    )
    if receipt_status != "pass":
        return receipt_status, receipt_reason, None
    has_legacy = (
        record.get("dacsVersion") == "1"
        and "finalityCommitmentVersion" not in record
    )
    has_finality = (
        record.get("finalityCommitmentVersion") == "1"
        and "dacsVersion" not in record
    )
    if has_legacy:
        signature = wrapped.get("externalSignature")
        try:
            payload = (
                generator.COMMITMENT_DOMAIN + generator.hash_hex(record)
            ).encode("ascii")
        except (TypeError, ValueError):
            return "error", "malformed-input", None
        if not verify_payload(signature, payload, orchestrator):
            return "fail", "commitment-signature-invalid", None
        if record.get("committedAt") != anchor_timestamp:
            return "fail", "commitment-time-mismatch", None
        signer = signature.get("signer") if isinstance(signature, dict) else None
    elif has_finality:
        if not verify_component(
            record, generator.FINALITY_COMMITMENT_DOMAIN, orchestrator
        ):
            return "fail", "commitment-signature-invalid", None
        signature = record.get("signature")
        signer = signature.get("signer") if isinstance(signature, dict) else None
    else:
        return "fail", "commitment-discriminator-invalid", None
    try:
        agreement_hash = generator.hash_hex(
            generator.unsigned(agreement, "signatures")
        )
    except (TypeError, ValueError):
        return "error", "malformed-input", None
    if (
        record.get("agreementHash") != agreement_hash
        or record.get("jobId") != agreement.get("jobId")
        or record.get("listingRef") != agreement.get("listingRef")
    ):
        return "fail", "commitment-binding-mismatch", None
    claims_status, role_claims = agreement_role_claims(agreement)
    if (
        claims_status != "pass"
        or record.get("parties") != [role_claims["buyer"], role_claims["seller"]]
    ):
        return "fail", "commitment-binding-mismatch", None
    return "pass", "verified", signer


def dispatch(context: dict) -> tuple[str, str, str | None, str | None]:
    status, reason, phase = listing_phase(context)
    if status != "pass":
        return status, reason, None, None
    status, artifact = artifact_type(context.get("agreement"))
    if status != "pass" or artifact is None:
        return "fail", "agreement-discriminator-invalid", None, None
    if generator.PHASES[artifact] != phase:
        return "fail", "phase-artifact-mismatch", artifact, phase
    status, reason = verify_agreement(context.get("agreement"), artifact)
    if status != "pass":
        return status, reason, artifact, phase
    listing = context["listing"]
    agreement = context["agreement"]
    seller_identity = listing.get("seller", {}).get("identity", {})
    seller = next(
        (
            party for party in agreement["parties"]
            if party.get("role") == "seller"
        ),
        None,
    )
    if (
        not isinstance(seller, dict)
        or seller.get("primaryClaim") != seller_identity.get("presentedBy")
    ):
        return "fail", "agreement-role-invalid", artifact, phase
    try:
        expected_ref = generator.listing_ref(listing)
    except (KeyError, TypeError, ValueError):
        return "error", "malformed-input", artifact, phase
    if agreement.get("listingRef") != expected_ref:
        return "fail", "listing-reference-mismatch", artifact, phase
    status, reason, _ = verify_commitment(context)
    return status, reason, artifact, phase


def companions_for_stage(context: dict, stage: str) -> object:
    if stage == "commit":
        carrier = context.get("commitInput")
    elif stage == "payment":
        carrier = context.get("paymentInput")
    else:
        carrier = context.get("terminalInput")
    return carrier.get("identityBindingCompanions") if isinstance(carrier, dict) else None


def validate_cvr(
    record: object,
    reference: object,
    party: dict,
    digest: str,
    job_id: str,
    orchestrator: str,
) -> tuple[str, str]:
    if not isinstance(record, dict):
        return "error", "malformed-input"
    for field in (
        "recordVersion", "jobId", "evaluatedParty", "bundleHash", "overallDecision"
    ):
        if not isinstance(record.get(field), str):
            return "error", "malformed-input"
    signature = record.get("signature")
    if (
        not isinstance(signature, dict)
        or set(signature) != {"algorithm", "signer", "value"}
        or any(not isinstance(signature.get(field), str) for field in signature)
        or not valid_ref(reference)
    ):
        return "error", "malformed-input"
    try:
        if generator.hash_hex(record) != reference["contentHash"]:
            return "fail", "cvr-reference-mismatch"
    except (TypeError, ValueError):
        return "error", "malformed-input"
    if not verify_component(record, generator.COMPOSITE_DOMAIN, orchestrator):
        return "fail", "cvr-signature-invalid"
    if record.get("jobId") != job_id:
        return "fail", "cvr-job-mismatch"
    if record.get("evaluatedParty") != party.get("primaryClaim"):
        return "fail", "companion-join-contradiction"
    if record.get("bundleHash") != digest:
        return "fail", "cvr-bundle-hash-mismatch"
    if record.get("overallDecision") != "pass":
        return "fail", "cvr-decision-not-pass"
    return "pass", "verified"


def validate_strong_proof(
    context: dict, artifact: str, stage: str, unavailable: set[str]
) -> tuple[str, str, dict[str, str]]:
    agreement = context.get("agreement")
    companions = companions_for_stage(context, stage)
    if not isinstance(agreement, dict) or not isinstance(companions, list):
        return "error", "malformed-input", {}
    if stage == "commit":
        commit_input = context.get("commitInput")
        if not isinstance(commit_input, dict):
            return "error", "malformed-input", {}
        session_status, _ = validated_session_parties(
            commit_input.get("sessionContext"), context
        )
        if session_status != "pass":
            return "error", "malformed-input", {}
        if (
            commit_input.get("jobId") != agreement.get("jobId")
            or commit_input.get("agreement") != agreement
            or commit_input.get("listingRef") != agreement.get("listingRef")
        ):
            return "fail", "commit-input-authority-mismatch", {}
    minimum = 3 if stage == "terminal" else 2
    if len(companions) == 0:
        return "error", "malformed-input", {}
    if len(companions) < minimum:
        reason = (
            "orchestrator-companion-missing"
            if stage == "terminal" and len(companions) == 2
            else "required-companion-missing"
        )
        return "indeterminate", reason, {}
    if len(companions) > minimum:
        return "fail", "companion-cardinality-invalid", {}
    if any(
        not isinstance(companion, dict)
        or not ({"identityBundle", "compositeRecord"} & set(companion))
        for companion in companions
    ):
        return "error", "malformed-input", {}
    parties = agreement.get("parties")
    verifier_context = context.get("verifierContext")
    if not isinstance(parties, list) or not isinstance(verifier_context, dict):
        return "error", "malformed-input", {}
    nonce = verifier_context.get("sessionNonce")
    orchestrator = verifier_context.get("authenticatedOrchestrator")
    if not isinstance(nonce, str) or not isinstance(orchestrator, str):
        return "error", "malformed-input", {}
    digests: dict[str, str] = {}
    used: set[int] = set()
    for party in parties:
        if not isinstance(party, dict):
            return "error", "malformed-input", {}
        claim = party.get("primaryClaim")
        bundle_hash = party.get("bundleHash")
        if not isinstance(claim, str) or not isinstance(bundle_hash, str):
            return "error", "malformed-input", {}
        if artifact in generator.STRONG_ARTIFACTS and not HEX.fullmatch(bundle_hash):
            return "fail", "agreement-bundle-hash-mismatch", {}
        matches = []
        for index, companion in enumerate(companions):
            if not isinstance(companion, dict):
                return "error", "malformed-input", {}
            bundle = companion.get("identityBundle")
            record = companion.get("compositeRecord")
            if (
                isinstance(bundle, dict) and bundle.get("presentedBy") == claim
            ) or (
                isinstance(record, dict) and record.get("evaluatedParty") == claim
            ):
                matches.append((index, companion))
        if len(matches) != 1:
            return "fail", "companion-join-contradiction", {}
        index, companion = matches[0]
        if index in used:
            return "fail", "companion-cardinality-invalid", {}
        used.add(index)
        if f"identity:{claim}" in unavailable:
            return "indeterminate", "identity-bundle-unavailable", {}
        if "identityBundle" not in companion:
            return "indeterminate", "required-companion-missing", {}
        bundle = companion.get("identityBundle")
        if bundle is None:
            return "error", "malformed-input", {}
        status, reason, digest = validate_identity_bundle(bundle, nonce)
        if status != "pass" or digest is None:
            return status, reason, {}
        if bundle_hash != digest:
            return "fail", "agreement-bundle-hash-mismatch", {}
        if f"cvr:{claim}" in unavailable:
            return "indeterminate", "cvr-unavailable", {}
        if "compositeRecord" not in companion:
            return "indeterminate", "required-companion-missing", {}
        record = companion.get("compositeRecord")
        if record is None:
            return "error", "malformed-input", {}
        status, reason = validate_cvr(
            record, party.get("vetRecordRef"), party, digest,
            agreement.get("jobId"), orchestrator,
        )
        if status != "pass":
            return status, reason, {}
        digests[party["role"]] = digest
    if stage == "terminal":
        matches = [
            companion for companion in companions
            if isinstance(companion, dict)
            and isinstance(companion.get("identityBundle"), dict)
            and companion["identityBundle"].get("presentedBy") == orchestrator
        ]
        if len(matches) != 1:
            return "fail", "companion-join-contradiction", {}
        if "compositeRecord" in matches[0]:
            return "fail", "companion-join-contradiction", {}
        if f"identity:{orchestrator}" in unavailable:
            return "indeterminate", "identity-bundle-unavailable", {}
        status, reason, digest = validate_identity_bundle(
            matches[0]["identityBundle"], nonce
        )
        if status != "pass" or digest is None:
            return status, reason, {}
        digests["orchestrator"] = digest
    return "pass", "verified", digests


def carrier_map(value: object) -> tuple[str, dict[str, dict]]:
    if not isinstance(value, list) or not value:
        return "error", {}
    result: dict[str, dict] = {}
    for party in value:
        if (
            not isinstance(party, dict)
            or not isinstance(party.get("role"), str)
            or not isinstance(party.get("primaryClaim"), str)
            or not isinstance(party.get("bundleHash"), str)
            or party["role"] in result
        ):
            return "error", {}
        result[party["role"]] = party
    return "pass", result


def validated_session_parties(
    value: object, context: dict
) -> tuple[str, dict[str, dict]]:
    if not isinstance(value, dict):
        return "error", {}
    signer = value.get("signer")
    agreement = context.get("agreement")
    if (
        not isinstance(agreement, dict)
        or value.get("jobId") != agreement.get("jobId")
        or value.get("listingRef") != agreement.get("listingRef")
        or not isinstance(value.get("recipeRegistryVersion"), int)
        or isinstance(value.get("recipeRegistryVersion"), bool)
        or not isinstance(value.get("railRegistryVersion"), int)
        or isinstance(value.get("railRegistryVersion"), bool)
        or not isinstance(value.get("priorPhaseOutputs"), dict)
        or not isinstance(value.get("startedAt"), int)
        or isinstance(value.get("startedAt"), bool)
        or not isinstance(signer, dict)
        or signer.get("kind") != "deterministic-test-capability"
        or signer.get("claim")
        != context.get("verifierContext", {}).get("authenticatedOrchestrator")
    ):
        return "error", {}
    return carrier_map(value.get("parties"))


def validate_payment_rail(context: dict, payment: dict) -> tuple[str, str]:
    rail = payment.get("rail")
    verifier_context = context.get("verifierContext")
    if not isinstance(rail, dict) or not isinstance(verifier_context, dict):
        return "error", "malformed-input"
    steward = verifier_context.get("authenticatedRailSteward")
    phase_index = verifier_context.get("paymentPhaseIndex")
    accepted_rails = context.get("listing", {}).get("acceptedRails")
    pipeline = context.get("listing", {}).get("pipeline")
    amount = payment.get("amount")
    if (
        not isinstance(steward, str)
        or not isinstance(phase_index, int)
        or isinstance(phase_index, bool)
        or phase_index < 0
        or not isinstance(accepted_rails, list)
        or not isinstance(pipeline, list)
        or not isinstance(amount, dict)
    ):
        return "error", "malformed-input"
    if (
        rail.get("railVersion") != 1
        or rail.get("railId") != generator.RAIL_REF["railId"]
        or rail.get("railType") != "demos-native"
        or rail.get("asset")
        != {"kind": "native-dem", "symbol": "DEM", "decimals": 9}
        or rail.get("network") != {"kind": "demos"}
        or rail.get("phaseHandler") != "pay-dem"
        or not isinstance(rail.get("parameters"), dict)
        or rail.get("availability") != "live"
        or not isinstance(rail.get("governance"), dict)
    ):
        return "fail", "rail-definition-invalid"
    if not verify_component(rail, generator.RAIL_DOMAIN, steward):
        return "fail", "rail-definition-invalid"
    agreement = context["agreement"]
    listing = context["listing"]
    phase = pipeline[phase_index] if phase_index < len(pipeline) else None
    if (
        agreement.get("terms", {}).get("rail") != generator.RAIL_REF
        or payment.get("amount") != agreement.get("terms", {}).get("price")
        or not any(item == generator.RAIL_REF for item in accepted_rails)
        or not isinstance(phase, dict)
        or phase.get("kind") != rail.get("phaseHandler")
        or not isinstance(phase.get("parameters"), dict)
        or phase["parameters"].get("rail")
        != rail.get("railId")
    ):
        return "fail", "rail-binding-mismatch"
    return "pass", "verified"


def validate_replacement(context: dict, unavailable: set[str]) -> tuple[str, str]:
    agreement = context.get("agreement")
    if not isinstance(agreement, dict) or not isinstance(agreement.get("terms"), dict):
        return "error", "malformed-input"
    reference = agreement["terms"].get("priorPaymentDispositionRef")
    if reference is None:
        return "pass", "verified"
    if "prior-disposition" in unavailable:
        return "indeterminate", "prior-disposition-unavailable"
    resolved = context.get("priorPaymentDisposition")
    prior = context.get("priorAgreement")
    if not isinstance(resolved, dict) or not isinstance(prior, dict):
        return "indeterminate", "prior-disposition-unavailable"
    disposition = resolved.get("artifact")
    receipt = resolved.get("receipt")
    if (
        not isinstance(disposition, dict)
        or not isinstance(receipt, dict)
        or not valid_ref(reference)
    ):
        return "error", "malformed-input"
    if generator.hash_hex(disposition) != reference["contentHash"]:
        return "fail", "prior-disposition-reference-mismatch"
    orchestrator = context.get("verifierContext", {}).get("authenticatedOrchestrator")
    if not verify_component(disposition, generator.DISPOSITION_DOMAIN, orchestrator):
        return "fail", "prior-disposition-signature-invalid"
    if (
        receipt.get("state") != "finalized"
        or receipt.get("contentHash") != generator.hash_hex(disposition)
        or receipt.get("writer") != orchestrator
    ):
        return "fail", "prior-disposition-receipt-invalid"
    if disposition.get("replacementJobId") != agreement.get("jobId"):
        return "fail", "replacement-job-mismatch"
    if disposition.get("priorJobId") != prior.get("jobId"):
        return "fail", "prior-job-mismatch"
    if disposition.get("priorAgreementRef") != generator.artifact_ref(
        prior, "prior-agreement"
    ):
        return "fail", "prior-agreement-reference-mismatch"
    prior_status, prior_artifact = artifact_type(prior)
    if (
        prior_status != "pass"
        or prior_artifact is None
        or verify_agreement(prior, prior_artifact)[0] != "pass"
    ):
        return "fail", "prior-agreement-invalid"
    if (
        disposition.get("priorSelection") != prior.get("terms", {}).get("rail")
        or disposition.get("priorPhaseIndex") != 2
    ):
        return "fail", "prior-selection-mismatch"
    if disposition.get("disposition") not in {
        "closed-before-authorization", "closed-cannot-settle"
    }:
        return "fail", "replacement-not-safe"
    return "pass", "verified"


def validate_payment(
    context: dict, artifact: str, unavailable: set[str]
) -> tuple[str, str]:
    status, reason, digests = validate_strong_proof(
        context, artifact, "payment", unavailable
    )
    if status != "pass":
        return status, reason
    payment = context.get("paymentInput")
    if not isinstance(payment, dict):
        return "error", "malformed-input"
    payer = payment.get("payer")
    payee = payment.get("payee")
    if not isinstance(payer, dict) or not isinstance(payee, dict):
        return "error", "malformed-input"
    claims_status, role_claims = agreement_role_claims(context.get("agreement"))
    if claims_status != "pass":
        return "error", "malformed-input"
    for carrier, role, address_field in (
        (payer, "buyer", "payingKey"), (payee, "seller", "payeeAddress")
    ):
        if any(
            not isinstance(carrier.get(field), str)
            for field in ("primaryClaim", "bundleHash", address_field)
        ):
            return "error", "malformed-input"
        if (
            carrier.get("primaryClaim") != role_claims[role]
            or carrier.get("bundleHash") != digests[role]
        ):
            return "fail", "payment-party-mismatch"
    if payment.get("agreement") != context.get("agreement"):
        return "fail", "payment-agreement-mismatch"
    rail_status, rail_reason = validate_payment_rail(context, payment)
    if rail_status != "pass":
        return rail_status, rail_reason
    status, sessions = validated_session_parties(
        payment.get("sessionContext"), context
    )
    if status != "pass":
        return "error", "malformed-input"
    for role in ("buyer", "seller"):
        if (
            role not in sessions
            or sessions[role].get("primaryClaim") != role_claims[role]
            or sessions[role].get("bundleHash") != digests[role]
        ):
            return "fail", "session-party-mismatch"
    agreement = context["agreement"]
    if artifact in generator.PAYEE_ARTIFACTS:
        bindings = agreement.get("terms", {}).get("payoutBindings")
        if (
            not isinstance(bindings, list)
            or len(bindings) != 1
            or not isinstance(bindings[0], dict)
        ):
            return "fail", "payout-binding-invalid"
        binding = bindings[0]
        if (
            binding.get("railId") != generator.RAIL_REF["railId"]
            or binding.get("phaseIndex")
            != context["verifierContext"]["paymentPhaseIndex"]
        ):
            return "fail", "payout-binding-invalid"
        if binding.get("payeeAddress") != payee.get("payeeAddress"):
            return "fail", "payout-destination-mismatch"
    return validate_replacement(context, unavailable)


def verify_terminal_signatures(
    bundle: object, expected_signers: set[str]
) -> tuple[str, str]:
    if not isinstance(bundle, dict):
        return "error", "malformed-input"
    signatures = bundle.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 3:
        return "error", "malformed-input"
    if any(
        not isinstance(signature, dict)
        or set(signature) != {"party", "algorithm", "value"}
        for signature in signatures
    ):
        return "error", "malformed-input"
    try:
        digest = generator.hash_hex({
            key: copy.deepcopy(item)
            for key, item in bundle.items()
            if key not in {"signatures", "anchoredByRole"}
        })
    except (TypeError, ValueError):
        return "error", "malformed-input"
    if {signature.get("party") for signature in signatures} != expected_signers:
        return "fail", "terminal-signers-invalid"
    for signature in signatures:
        if signature.get("algorithm") != "ed25519":
            return "fail", "terminal-signature-invalid"
        try:
            valid = generator.verify_ed25519(
                key_bytes(signature["party"]), b64url_decode(signature.get("value")),
                (generator.TERMINAL_DOMAIN + digest).encode("ascii")
            )
        except (TypeError, ValueError):
            valid = False
        if not valid:
            return "fail", "terminal-signature-invalid"
    return "pass", "verified"


def validate_terminal(
    context: dict, artifact: str, phase: str, unavailable: set[str]
) -> tuple[str, str]:
    terminal_input = context.get("terminalInput")
    if not isinstance(terminal_input, dict):
        return "error", "malformed-input"
    bundle = terminal_input.get("bundle")
    if not isinstance(bundle, dict):
        return "error", "malformed-input"
    if (
        terminal_input.get("listing") != context.get("listing")
        or terminal_input.get("agreement") != context.get("agreement")
        or terminal_input.get("commitment") != context.get("commitment")
    ):
        return "fail", "terminal-authority-mismatch"
    phase_summary = bundle.get("phaseSummary")
    if (
        not isinstance(phase_summary, list)
        or len(phase_summary) <= 1
        or any(not isinstance(entry, dict) for entry in phase_summary)
        or not isinstance(phase_summary[1].get("kind"), str)
        or any(
            not isinstance(entry.get("index"), int)
            or isinstance(entry.get("index"), bool)
            or entry.get("index") != index
            or not isinstance(entry.get("kind"), str)
            for index, entry in enumerate(phase_summary)
        )
    ):
        return "error", "malformed-input"
    if phase_summary[1].get("index") != 1 or phase_summary[1].get("kind") != phase:
        return "fail", "terminal-phase-mismatch"
    agreement = context["agreement"]
    if bundle.get("agreementRef") != generator.artifact_ref(
        agreement, f"{agreement.get('jobId', 'bad')}-agreement"
    ):
        return "fail", "terminal-agreement-reference-mismatch"
    status, terminal_parties = carrier_map(bundle.get("parties"))
    if (
        status != "pass"
        or set(terminal_parties) != {"buyer", "seller", "orchestrator"}
    ):
        return "error", "malformed-input"
    claims_status, role_claims = agreement_role_claims(context.get("agreement"))
    commitment_status, commitment_reason, orchestrator = verify_commitment(context)
    if claims_status != "pass":
        return "error", "malformed-input"
    if commitment_status != "pass" or not isinstance(orchestrator, str):
        return commitment_status, commitment_reason
    expected_claims = {**role_claims, "orchestrator": orchestrator}
    status, reason = verify_terminal_signatures(bundle, set(expected_claims.values()))
    if status != "pass":
        return status, reason
    status, reason, digests = validate_strong_proof(
        context, artifact, "terminal", unavailable
    )
    if status != "pass":
        return status, reason
    status, sessions = validated_session_parties(
        terminal_input.get("sessionContext"), context
    )
    if status != "pass":
        return "error", "malformed-input"
    for role in ("buyer", "seller", "orchestrator"):
        if (
            role not in sessions
            or sessions[role].get("primaryClaim") != expected_claims[role]
            or sessions[role].get("bundleHash") != digests[role]
        ):
            return "fail", "session-party-mismatch"
    status, parties = carrier_map(bundle.get("parties"))
    if status != "pass":
        return "error", "malformed-input"
    for role in ("buyer", "seller", "orchestrator"):
        if (
            role not in parties
            or parties[role].get("primaryClaim") != expected_claims[role]
            or parties[role].get("bundleHash") != digests[role]
        ):
            return "fail", "terminal-party-mismatch"
    return "pass", "verified"


def modeled_old_reader(context: dict) -> tuple[str, str]:
    status, reason, phase = listing_phase(context)
    if status != "pass":
        return status, reason
    status, artifact = artifact_type(context.get("agreement"))
    if status != "pass" or artifact is None:
        return "fail", "agreement-discriminator-invalid"
    old = {"agreement", "payeeBoundAgreement"}
    if artifact not in old or phase not in {generator.PHASES[item] for item in old}:
        return "fail", "unsupported-new-type"
    if generator.PHASES[artifact] != phase:
        return "fail", "phase-artifact-mismatch"
    return verify_agreement(context["agreement"], artifact)


def apply_mutation(context: dict, mutation: dict) -> None:
    path = mutation["path"]
    parent: object = context
    for segment in path[:-1]:
        parent = parent[segment]  # type: ignore[index]
    leaf = path[-1]
    if mutation["op"] == "set":
        parent[leaf] = copy.deepcopy(mutation["value"])  # type: ignore[index]
    elif mutation["op"] == "delete":
        if isinstance(parent, list):
            parent.pop(leaf)
        else:
            parent.pop(leaf, None)  # type: ignore[union-attr]
    elif mutation["op"] == "append-copy":
        target = parent[leaf]  # type: ignore[index]
        target.append(copy.deepcopy(target[mutation["index"]]))
    else:
        raise ValueError("unknown mutation")


def materialize(data: dict, vector: dict) -> dict:
    context = copy.deepcopy(data["scenarios"][vector["scenario"]])
    context["commitment"] = copy.deepcopy(
        context["commitments"][vector["commitment"]]
    )
    generator.synchronize_phase_inputs(context)
    context["terminalInput"]["commitment"] = copy.deepcopy(context["commitment"])
    for mutation in vector.get("mutations", []):
        apply_mutation(context, mutation)
    for action in vector.get("resign", []):
        generator.resign_context(context, action)
        context["commitment"] = copy.deepcopy(
            context["commitments"][vector["commitment"]]
        )
        context["terminalInput"]["commitment"] = copy.deepcopy(
            context["commitment"]
        )
    return context


def evaluate(data: dict, vector: dict) -> tuple[str, dict]:
    try:
        context = materialize(data, vector)
        if vector.get("stage") == "old-reader":
            verdict, reason = modeled_old_reader(context)
            return outcome(verdict, reason)
        verdict, reason, artifact, phase = dispatch(context)
        if verdict != "pass" or artifact is None or phase is None:
            return outcome(verdict, reason)
        if artifact not in generator.STRONG_ARTIFACTS:
            return outcome("pass", "verified")
        unavailable = set(vector.get("unavailable", []))
        stage = vector.get("stage")
        if stage == "commit":
            verdict, reason, _ = validate_strong_proof(
                context, artifact, "commit", unavailable
            )
        elif stage == "payment":
            verdict, reason = validate_payment(context, artifact, unavailable)
        elif stage == "terminal":
            verdict, reason = validate_terminal(context, artifact, phase, unavailable)
        else:
            return outcome("error", "malformed-input")
        return outcome(verdict, reason)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return outcome("error", "malformed-input")


def phase_result(verdict: str) -> dict:
    if verdict == "pass":
        return {"ok": True, "contextDelta": {}}
    if verdict == "indeterminate":
        return {"ok": False, "errorClass": "substrate", "contextDelta": {}}
    return {"ok": False, "errorClass": "permanent", "contextDelta": {}}


class IdentityBundleHashBindingVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {case["name"]: case for case in cls.data["vectors"]}

    def test_committed_file_is_deterministic(self):
        self.assertEqual(VECTORS.read_text(encoding="utf-8"), generator.rendered())

    def test_every_vector_executes_to_pinned_result_without_exception(self):
        for vector in self.data["vectors"]:
            with self.subTest(name=vector["name"]):
                verdict, want = evaluate(self.data, vector)
                self.assertEqual(vector["expected"], verdict)
                self.assertEqual(vector["want"], want)

    def test_four_by_four_dispatch_and_domain_matrices_are_complete(self):
        self.assertEqual(
            len([name for name in self.cases if name.startswith("dispatch-")]), 16
        )
        self.assertEqual(
            len([name for name in self.cases if name.startswith("domain-")]), 16
        )

    def test_historical_signed_bytes_survive_both_commitment_forms(self):
        for artifact in ("agreement", "payeeBoundAgreement"):
            original = generator.canonical_bytes(
                self.data["scenarios"][artifact]["agreement"]
            )
            self.assertIn(b"sha256:", original)
            for commitment in ("legacy", "finality"):
                vector = self.cases[
                    f"historical-{artifact}-prefixed-bytes-{commitment}"
                ]
                self.assertEqual(evaluate(self.data, vector)[0], "pass")
                self.assertEqual(
                    generator.canonical_bytes(
                        self.data["scenarios"][artifact]["agreement"]
                    ),
                    original,
                )

        historical = json.loads(PAYEE_VECTORS.read_text(encoding="utf-8"))
        by_name = {case["name"]: case for case in historical["vectors"]}
        for name in (
            "agreement-legacy-reader-accepts-legacy",
            "agreement-current-reader-accepts-payee-bound",
        ):
            case = by_name[name]
            agreement = case["agreement"]
            original = generator.canonical_bytes(agreement)
            digest = generator.hash_hex(generator.unsigned(agreement, "signatures"))
            self.assertEqual(case["artifactHash"], digest)
            for signature in agreement["signatures"]:
                public = b64url_decode(historical["publicKeys"][signature["party"]])
                self.assertTrue(generator.verify_ed25519(
                    public,
                    b64url_decode(signature["value"]),
                    (case["signatureDomain"] + digest).encode("ascii"),
                ))
            for commitment in generator.commitments(
                agreement, agreement["jobId"]
            ).values():
                context = {
                    "agreement": agreement,
                    "commitment": commitment,
                    "verifierContext": {
                        "authenticatedOrchestrator": generator.CLAIMS["orchestrator"]
                    },
                }
                self.assertEqual(verify_commitment(context)[0], "pass")
                self.assertEqual(generator.canonical_bytes(agreement), original)

    def test_payee_corpus_remains_valid_and_not_superseded(self):
        historical = json.loads(PAYEE_VECTORS.read_text(encoding="utf-8"))
        self.assertNotIn("identityBundleHashProfile", historical)
        self.assertNotIn("supersedesIdentityBundleHashProfiles", self.data)
        self.assertEqual(historical["count"], len(historical["vectors"]))

    def test_missing_proof_keeps_ternary_phase_mapping(self):
        vector = self.cases["buyer-identity-authority-unavailable"]
        verdict, want = evaluate(self.data, vector)
        self.assertEqual((verdict, want["authorizedAction"]), ("indeterminate", False))
        self.assertEqual(
            phase_result(verdict),
            {"ok": False, "errorClass": "substrate", "contextDelta": {}},
        )
        self.assertFalse(phase_result("fail")["ok"])
        self.assertFalse(phase_result("error")["ok"])
        self.assertTrue(phase_result("pass")["ok"])

    def test_modeled_old_reader_provenance_is_explicit(self):
        evidence = self.data["provenance"]["oldReaderEvidence"]
        self.assertEqual(
            evidence["kind"], "modeled-agreement-plus-executable-terminal"
        )
        self.assertEqual(evidence["baseSha"], generator.BASE_SHA)
        self.assertIs(evidence["deployedReaderProof"], False)
        self.assertEqual(
            evidence["terminalReader"]["path"], "tests/dacs5_reference.py"
        )
        self.assertEqual(
            evaluate(self.data, self.cases["modeled-old-reader-agreement"])[0],
            "pass",
        )
        self.assertEqual(
            evaluate(
                self.data, self.cases["modeled-old-reader-identityBoundAgreement"]
            )[0],
            "fail",
        )

    def test_specs_keep_old_carriers_and_name_new_nested_shape(self):
        core = (ROOT / "spec/CORE.md").read_text(encoding="utf-8")
        vet = (ROOT / "spec/DACS-2-VET.md").read_text(encoding="utf-8")
        negotiate = (ROOT / "spec/DACS-3-NEGOTIATE.md").read_text(encoding="utf-8")
        settle = (ROOT / "spec/DACS-4-SETTLE.md").read_text(encoding="utf-8")
        verify = (ROOT / "spec/DACS-5-VERIFY.md").read_text(encoding="utf-8")
        self.assertIn(
            "Identity-bound agreement digest profile (IBH-1..IBH-6)", core
        )
        self.assertIn("type IdentityBoundAgreementParty", negotiate)
        self.assertIn("bundleHash: string", vet)
        self.assertIn("bundleHash: string", settle)
        self.assertIn("bundleHash: string", verify)
        self.assertIn("Commitment kind is not artifact era", negotiate)
        self.assertIn("Agreement dispatch and identity-bound admission", verify)


if __name__ == "__main__":
    unittest.main()
