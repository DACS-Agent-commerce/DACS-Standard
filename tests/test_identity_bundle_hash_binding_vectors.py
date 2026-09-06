"""Execute the #390 identity-bound agreement conformance corpus."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest
from unittest import mock
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import generate_identity_bundle_hash_binding_vectors as generator  # noqa: E402
import test_claim_requirement_qualification_vectors as qualification  # noqa: E402
import dacs5_reference as reputation_reference  # noqa: E402


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


def valid_signed_ref(reference: object) -> bool:
    if not isinstance(reference, dict) or set(reference) != {
        "anchor", "contentHash", "signer"
    }:
        return False
    return (
        valid_ref({
            "anchor": reference.get("anchor"),
            "contentHash": reference.get("contentHash"),
        })
        and isinstance(reference.get("signer"), str)
    )


def valid_verify_result_ref(reference: object) -> bool:
    if not isinstance(reference, dict) or set(reference) != {
        "anchor", "contentHash", "recipeVersion"
    }:
        return False
    if not isinstance(reference.get("recipeVersion"), int) or isinstance(
        reference.get("recipeVersion"), bool
    ):
        return False
    return valid_ref({
        "anchor": reference.get("anchor"),
        "contentHash": reference.get("contentHash"),
    })


def validate_identity_bundle(
    bundle: object, nonce: object, *, session_bound: bool = True
) -> tuple[str, str, str | None]:
    if not isinstance(bundle, dict):
        return "error", "malformed-input", None
    if (
        bundle.get("bundleVersion") != "1"
        or not isinstance(bundle.get("presentedBy"), str)
        or not isinstance(bundle.get("presentedAt"), int)
        or isinstance(bundle.get("presentedAt"), bool)
        or (session_bound and "sessionNonce" not in bundle)
        or ("sessionNonce" in bundle and not isinstance(bundle["sessionNonce"], str))
        or not isinstance(bundle.get("claims"), list)
        or not bundle["claims"]
    ):
        return "error", "malformed-input", None
    if session_bound and (
        not isinstance(nonce, str) or bundle.get("sessionNonce") != nonce
    ):
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


class NonceAdmissionStore:
    """Stateful fixture model for CORE SN-1..SN-4 admission semantics."""

    def __init__(self) -> None:
        self._issued: dict[str, dict] = {}

    def issue(
        self,
        job_id: str,
        presenter: str,
        nonce: str,
        *,
        issued_at: int,
        expires_at: int,
    ) -> bool:
        if (
            not isinstance(job_id, str)
            or not isinstance(presenter, str)
            or not isinstance(nonce, str)
            or nonce in self._issued
            or not isinstance(issued_at, int)
            or isinstance(issued_at, bool)
            or not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
            or expires_at <= issued_at
        ):
            return False
        self._issued[nonce] = {
            "jobId": job_id,
            "presenter": presenter,
            "issuedAt": issued_at,
            "expiresAt": expires_at,
            "consumed": False,
            "accepted": None,
        }
        return True

    def admit(
        self, job_id: str, presenter: str, bundle: object, *, attempted_at: int
    ) -> tuple[str, str]:
        nonce = bundle.get("sessionNonce") if isinstance(bundle, dict) else None
        issued = self._issued.get(nonce) if isinstance(nonce, str) else None
        if not isinstance(issued, dict):
            return "fail", "nonce-not-issued"
        if issued["consumed"]:
            return "fail", "nonce-consumed"
        # SN-4 consumes before every later shape, expiry, or signature decision.
        issued["consumed"] = True
        if (
            issued["jobId"] != job_id
            or issued["presenter"] != presenter
            or not isinstance(bundle, dict)
            or bundle.get("presentedBy") != presenter
        ):
            return "fail", "nonce-binding-mismatch"
        if (
            not isinstance(attempted_at, int)
            or isinstance(attempted_at, bool)
            or attempted_at < issued["issuedAt"]
            or attempted_at > issued["expiresAt"]
        ):
            return "fail", "nonce-expired"
        verdict, reason, digest = validate_identity_bundle(bundle, nonce)
        if verdict == "pass":
            issued["accepted"] = {
                "jobId": job_id,
                "presenter": presenter,
                "bundleBytes": generator.canonical_bytes(bundle),
                "bundleHash": digest,
                "verdict": verdict,
                "reason": reason,
            }
        return verdict, reason


def validate_retained_admission(
    context: dict,
    bundle: object,
    expected_claim: str,
    job_id: str,
) -> tuple[str, str, str | None]:
    verifier_context = context.get("verifierContext")
    authority = (
        verifier_context.get("identityAdmissionAuthority")
        if isinstance(verifier_context, dict)
        else None
    )
    if not isinstance(authority, dict) or authority.get("authorityAuthenticated") is not True:
        return "indeterminate", "identity-admission-authority-unavailable", None
    records = authority.get("records")
    if not isinstance(records, list):
        return "indeterminate", "identity-admission-authority-unavailable", None
    nonces = [record.get("nonce") for record in records if isinstance(record, dict)]
    if (
        len(nonces) != len(records)
        or any(not isinstance(nonce, str) for nonce in nonces)
        or len(nonces) != len(set(nonces))
    ):
        return "fail", "identity-admission-state-invalid", None
    matches = [
        record for record in records
        if isinstance(record, dict)
        and record.get("jobId") == job_id
        and record.get("presenter") == expected_claim
    ]
    if len(matches) == 0:
        return "indeterminate", "identity-admission-state-unavailable", None
    if len(matches) != 1:
        return "fail", "identity-admission-state-invalid", None
    record = matches[0]
    retained_bundle = record.get("bundle")
    accepted = record.get("acceptedResult")
    issued_at = record.get("issuedAt")
    expires_at = record.get("expiresAt")
    attempted_at = record.get("attemptedAt")
    if (
        not isinstance(retained_bundle, dict)
        or not isinstance(accepted, dict)
        or any(
            not isinstance(value, int) or isinstance(value, bool)
            for value in (issued_at, expires_at, attempted_at)
        )
        or not issued_at <= attempted_at <= expires_at
        or record.get("consumed") is not True
        or accepted.get("verdict") != "pass"
        or accepted.get("reason") != "verified"
        or not isinstance(accepted.get("acceptedAt"), int)
        or isinstance(accepted.get("acceptedAt"), bool)
        or accepted["acceptedAt"] < attempted_at
    ):
        return "fail", "identity-admission-state-invalid", None
    presented_verdict, presented_reason, _ = validate_identity_bundle(
        bundle, record.get("nonce")
    )
    if presented_verdict != "pass":
        return presented_verdict, presented_reason, None
    try:
        retained_bytes = generator.canonical_bytes(retained_bundle).decode("utf-8")
        presented_bytes = generator.canonical_bytes(bundle).decode("utf-8")
    except (TypeError, ValueError):
        return "error", "malformed-input", None
    if (
        record.get("bundleBytes") != retained_bytes
        or presented_bytes != retained_bytes
        or retained_bundle.get("presentedBy") != expected_claim
        or retained_bundle.get("sessionNonce") != record.get("nonce")
    ):
        return "fail", "admitted-presentation-mismatch", None
    verdict, reason, digest = validate_identity_bundle(
        retained_bundle, record.get("nonce")
    )
    if verdict != "pass" or digest is None:
        return verdict, reason, None
    if (
        record.get("bundleHash") != digest
        or accepted.get("bundleHash") != digest
    ):
        return "fail", "identity-admission-state-invalid", None
    return "pass", "verified", digest


def listing_phase(
    context: dict,
    supported_phases: frozenset[str] = generator.CURRENT_SUPPORTED_PHASES,
) -> tuple[str, str, str | None]:
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
    if any(step["kind"] not in supported_phases for step in pipeline):
        return "fail", "unsupported-phase", None
    phase_indexes = [
        index for index, step in enumerate(pipeline)
        if step["kind"] in generator.PHASES.values()
    ]
    if not phase_indexes:
        return "error", "malformed-input", None
    if len(phase_indexes) > 1:
        return "fail", "commitment-phase-cardinality-invalid", None
    negotiation_indexes = [
        index for index, step in enumerate(pipeline)
        if step["kind"] in generator.NEGOTIATION_PHASES
    ]
    if len(negotiation_indexes) != 1:
        return "fail", "negotiate-phase-cardinality-invalid", None
    if negotiation_indexes[0] + 1 != phase_indexes[0]:
        return "fail", "negotiate-commit-order-invalid", None
    agreement = context.get("agreement")
    pattern = agreement.get("derivedFromPattern") if isinstance(agreement, dict) else None
    expected_negotiations = {
        "fixed-price": {"negotiate-fixed-price"},
        "rfq": {"negotiate-rfq"},
        "sealed-envelope": {
            "negotiate-sealed-envelope",
            "negotiate-sealed-envelope-procurement",
        },
    }.get(pattern)
    if (
        not isinstance(expected_negotiations, set)
        or pipeline[negotiation_indexes[0]]["kind"] not in expected_negotiations
    ):
        return "fail", "negotiate-pattern-mismatch", None
    signer = seller["identity"].get("presentedBy")
    if not verify_component(listing, generator.LISTING_DOMAIN, signer):
        return "fail", "listing-signature-invalid", None
    bundle_result, bundle_reason, _ = validate_identity_bundle(
        seller["identity"], None, session_bound=False
    )
    if bundle_result != "pass":
        return bundle_result, bundle_reason, None
    return "pass", "verified", pipeline[phase_indexes[0]]["kind"]


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
        or len(parties) < 2
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
    roles = [party["role"] for party in parties]
    claims = [party["primaryClaim"] for party in parties]
    if (
        roles.count("buyer") != 1
        or roles.count("seller") != 1
        or any(role not in {"buyer", "seller", "bidder-non-winning"} for role in roles)
        or len(claims) != len(set(claims))
    ):
        return "fail", "agreement-role-invalid"
    expected_signers = {
        party["primaryClaim"]
        for party in parties
        if party["role"] in {"buyer", "seller"}
    }
    signatures = agreement.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != len(expected_signers):
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
            or party.get("role") not in {"buyer", "seller", "bidder-non-winning"}
            or not isinstance(party.get("primaryClaim"), str)
        ):
            return "error", {}
        if party["role"] in {"buyer", "seller"}:
            if party["role"] in claims:
                return "error", {}
            claims[party["role"]] = party["primaryClaim"]
    if set(claims) != {"buyer", "seller"}:
        return "error", {}
    return "pass", claims


def verify_dependency_receipt(
    receipt: object,
    *,
    logical_address: str,
    native_address: str,
    content_hash: str,
    writer: str,
    nonce: str,
    receipt_authority: str,
    invalid_reason: str,
) -> tuple[str, str, int | None]:
    """Verify the fixture's signed native inclusion/finality observation.

    Expected artifact identity is always supplied by the caller's retained
    authority. Receipt fields and the encoded native envelope never dispatch
    or select the dependency they purport to prove.
    """
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
        or not isinstance(receipt.get("writer"), str)
        or not isinstance(receipt.get("nonce"), str)
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
        or set(evidence) != {"kind", "value"}
        or evidence.get("kind") != "fixture-native-finality-observation"
        or not isinstance(evidence.get("value"), str)
        or not isinstance(receipt_authority, str)
    ):
        return "error", "malformed-input", None
    if receipt_authority == writer:
        return "fail", invalid_reason, None
    try:
        envelope = json.loads(evidence["value"])
        native = envelope["nativeReceipt"]
        signature = envelope["signature"]
        if (
            set(envelope) != {
                "fixtureEvidenceVersion", "scope", "observer",
                "nativeReceipt", "signature",
            }
            or envelope["fixtureEvidenceVersion"] != "1"
            or envelope["scope"] != "offline-conformance-fixture-only"
            or envelope["observer"] != receipt_authority
            or not isinstance(native, dict)
            or not isinstance(signature, str)
        ):
            return "fail", invalid_reason, None
        valid = generator.verify_ed25519(
            key_bytes(receipt_authority),
            b64url_decode(signature),
            generator.FIXTURE_OBSERVATION_PREFIX
            + generator.hash_hex(native).encode("ascii"),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        valid = False
    if not valid:
        return "fail", invalid_reason, None
    binding = native.get("binding")
    inclusion = native.get("inclusion")
    consensus = native.get("consensus")
    if (
        not isinstance(binding, dict)
        or not isinstance(inclusion, dict)
        or not isinstance(consensus, dict)
    ):
        return "fail", invalid_reason, None
    expected_binding = {
        "logicalAddress": logical_address,
        "nativeAddress": native_address,
        "contentHash": content_hash,
        "writer": writer,
        "nonce": nonce,
    }
    expected_transaction = {
        "kind": "fixture",
        "value": generator.hash_hex(expected_binding),
    }
    expected_binding["transactionRef"] = expected_transaction
    ordered_transactions = inclusion.get("orderedTransactions")
    transaction_index = inclusion.get("transactionIndex")
    native_block = inclusion.get("blockRef")
    if (
        native.get("fixtureNativeReceiptVersion") != "1"
        or native.get("substrate") != receipt["substrate"]
        or native.get("finalityProfile") != receipt["finalityProfile"]
        or binding != expected_binding
        or receipt["logicalAddress"] != logical_address
        or receipt["nativeAddress"] != native_address
        or receipt["contentHash"] != content_hash
        or receipt["transactionRef"] != expected_transaction
        or receipt["writer"] != writer
        or receipt["nonce"] != nonce
        or not isinstance(ordered_transactions, list)
        or isinstance(transaction_index, bool)
        or not isinstance(transaction_index, int)
        or transaction_index < 0
        or transaction_index >= len(ordered_transactions)
        or ordered_transactions[transaction_index] != expected_transaction
        or not isinstance(native_block, dict)
        or native_block != block_ref
        or consensus != {"state": "finalized", "inclusionIsFinal": True}
    ):
        return "fail", invalid_reason, None
    block_material = {
        "height": block_ref["height"],
        "timestamp": block_ref["timestamp"],
        "orderedTransactions": ordered_transactions,
    }
    if (
        block_ref["id"] != generator.hash_hex(block_material)
        or receipt["observedAt"] < block_ref["timestamp"]
    ):
        return "fail", invalid_reason, None
    return "pass", "verified", block_ref["timestamp"]


def verify_anchor_receipt(
    wrapped: dict, record: dict, orchestrator: str, receipt_authority: str
) -> tuple[str, str, int | None]:
    receipt = wrapped.get("anchorReceipt")
    job_id = record.get("jobId")
    logical_address = f"dacs3:commit:{job_id}"
    nonce = receipt.get("nonce") if isinstance(receipt, dict) else None
    if not isinstance(nonce, str):
        return "error", "malformed-input", None
    return verify_dependency_receipt(
        receipt,
        logical_address=logical_address,
        native_address=(
            f"fixture:{hashlib.sha256(logical_address.encode()).hexdigest()}"
        ),
        content_hash=generator.commitment_record_hash(record),
        writer=orchestrator,
        nonce=nonce,
        receipt_authority=receipt_authority,
        invalid_reason="commitment-receipt-invalid",
    )


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
    receipt_authority = verifier_context.get("authenticatedReceiptAuthority")
    if not isinstance(orchestrator, str) or not isinstance(receipt_authority, str):
        return "error", "malformed-input", None
    receipt_status, receipt_reason, anchor_timestamp = verify_anchor_receipt(
        wrapped, record, orchestrator, receipt_authority
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
        or record.get("pattern") != agreement.get("derivedFromPattern")
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
    bundle: dict,
    digest: str,
    job_id: str,
    orchestrator: str,
    context: dict,
    stage: str,
) -> tuple[str, str]:
    if not isinstance(record, dict):
        return "error", "malformed-input"
    for field in (
        "recordVersion", "jobId", "evaluatedParty", "bundleHash",
        "requirementHash", "overallDecision"
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
        if generator.artifact_hash(record, "signature") != reference["contentHash"]:
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
    listing = context.get("listing")
    verifier_context = context.get("verifierContext")
    if not isinstance(listing, dict) or not isinstance(verifier_context, dict):
        return "error", "malformed-input"
    requirement = listing.get("buyerRequirement")
    if not isinstance(requirement, dict):
        return "error", "malformed-input"
    if record.get("requirementHash") != generator.hash_hex(requirement):
        return "fail", "cvr-requirement-mismatch"
    authorities = verifier_context.get("authenticatedQualification")
    registries = verifier_context.get("recipeRegistries")
    public_keys = verifier_context.get("qualificationPublicKeys")
    authority = (
        authorities.get(party.get("primaryClaim"))
        if isinstance(authorities, dict)
        else None
    )
    if (
        not isinstance(authority, dict)
        or not isinstance(registries, list)
        or not isinstance(public_keys, dict)
    ):
        return "indeterminate", "cvr-qualification-unavailable"
    materials = authority.get("results")
    freshness = record.get("freshness")
    deal_specific = record.get("dealSpecific")
    if (
        not isinstance(materials, list)
        or not isinstance(freshness, list)
        or not isinstance(deal_specific, list)
    ):
        return "error", "malformed-input"
    committed_refs = freshness + deal_specific
    material_refs = [
        material.get("ref") if isinstance(material, dict) else None
        for material in materials
    ]
    if (
        len(materials) != len(committed_refs)
        or any(not valid_verify_result_ref(item) for item in committed_refs)
        or qualification.canonical_json(material_refs)
        != qualification.canonical_json(committed_refs)
    ):
        return "fail", "cvr-result-set-mismatch"
    resolved_results = []
    for material in materials:
        if not isinstance(material, dict):
            return "error", "malformed-input"
        result_ref = material.get("ref")
        result = material.get("result")
        if (
            not isinstance(result, dict)
            or result.get("resultVersion") != "1"
            or any(
                not isinstance(result.get(field), str)
                for field in ("scheme", "identifier", "method", "decision", "reason")
            )
            or any(
                not isinstance(result.get(field), int)
                or isinstance(result.get(field), bool)
                for field in ("recipeVersion", "fetchedAt", "verifiedAt")
            )
            or not valid_ref(result.get("attestation"))
            or f"{result.get('scheme')}:{result.get('identifier')}"
            != party.get("primaryClaim")
            or not valid_verify_result_ref(result_ref)
            or result_ref.get("recipeVersion") != result.get("recipeVersion")
        ):
            return "fail", "cvr-result-invalid"
        if not qualification.verify_signed_artifact(
            result,
            result_ref,
            generator.VERIFY_RESULT_DOMAIN,
            public_keys,
        ):
            return "fail", "cvr-result-invalid"
        resolved_results.append(copy.deepcopy(result))
    input_data = {
        "recordJobId": job_id,
        "generatedAt": record.get("generatedAt"),
        "requirement": copy.deepcopy(requirement),
        "resolvedResults": resolved_results,
    }
    vector_set = {
        "recipeRegistries": copy.deepcopy(registries),
        "publicKeys": copy.deepcopy(public_keys),
        "authenticatedSessionStarts": {},
        "replayBundles": {},
        "replayRecords": {},
    }
    vet_input = authority.get("vetInput")
    session_start_id = authority.get("sessionStartId")
    authenticated_start = authority.get("authenticatedSessionStart")
    if (
        not isinstance(vet_input, dict)
        or not isinstance(session_start_id, str)
        or not isinstance(authenticated_start, dict)
    ):
        return "indeterminate", "cvr-qualification-unavailable"
    if (
        vet_input.get("actor") != party.get("primaryClaim")
        or qualification.canonical_json(vet_input.get("bundleToVet"))
        != qualification.canonical_json(bundle)
        or qualification.canonical_json(vet_input.get("requirement"))
        != qualification.canonical_json(requirement)
    ):
        return "fail", "cvr-qualification-authority-mismatch"
    vector_set["authenticatedSessionStarts"][session_start_id] = copy.deepcopy(
        authenticated_start
    )
    input_data["aggregationAuthority"] = {
        "kind": "production",
        "sessionStart": session_start_id,
        "vetInput": copy.deepcopy(vet_input),
    }
    replayed = qualification.evaluate(input_data, vector_set)
    if replayed == "error":
        return "fail", "cvr-qualification-invalid"
    if record.get("overallDecision") != replayed:
        return "fail", "cvr-aggregation-mismatch"
    if replayed != "pass":
        return "fail", "cvr-decision-not-pass"
    return "pass", "verified"


def validate_strong_proof(
    context: dict, artifact: str, stage: str, unavailable: set[str]
) -> tuple[str, str, dict[str, str]]:
    agreement = context.get("agreement")
    carrier = context.get({
        "commit": "commitInput",
        "payment": "paymentInput",
        "terminal": "terminalInput",
    }[stage])
    if (
        isinstance(carrier, dict)
        and "identityBindingCompanions" not in carrier
    ):
        return "indeterminate", "required-companion-missing", {}
    companions = companions_for_stage(context, stage)
    if not isinstance(agreement, dict) or not isinstance(companions, list):
        return "error", "malformed-input", {}
    if stage == "commit":
        commit_input = context.get("commitInput")
        if not isinstance(commit_input, dict):
            return "error", "malformed-input", {}
        session_status, session_reason, _ = validated_session_parties(
            commit_input.get("sessionContext"), context
        )
        if session_status != "pass":
            return session_status, session_reason, {}
        if (
            commit_input.get("jobId") != agreement.get("jobId")
            or commit_input.get("agreement") != agreement
            or commit_input.get("listingRef") != agreement.get("listingRef")
        ):
            return "fail", "commit-input-authority-mismatch", {}
    parties = agreement.get("parties")
    verifier_context = context.get("verifierContext")
    if not isinstance(parties, list) or not isinstance(verifier_context, dict):
        return "error", "malformed-input", {}
    orchestrator = verifier_context.get("authenticatedOrchestrator")
    if not isinstance(orchestrator, str):
        return "error", "malformed-input", {}
    agreement_claims = {
        party.get("primaryClaim")
        for party in parties
        if isinstance(party, dict) and isinstance(party.get("primaryClaim"), str)
    }
    if len(agreement_claims) != len(parties):
        return "error", "malformed-input", {}
    needs_orchestrator_companion = stage == "terminal" and orchestrator not in agreement_claims
    minimum = len(parties) + (1 if needs_orchestrator_companion else 0)
    if len(companions) == 0:
        return "error", "malformed-input", {}
    if len(companions) < minimum:
        reason = (
            "orchestrator-companion-missing"
            if needs_orchestrator_companion and len(companions) == len(parties)
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
        status, reason, digest = validate_retained_admission(
            context, bundle, claim, agreement.get("jobId")
        )
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
            record,
            party.get("vetRecordRef"),
            party,
            bundle,
            digest,
            agreement.get("jobId"),
            orchestrator,
            context,
            stage,
        )
        if status != "pass":
            return status, reason, {}
        digests[party["primaryClaim"]] = digest
    if needs_orchestrator_companion:
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
        status, reason, digest = validate_retained_admission(
            context,
            matches[0]["identityBundle"],
            orchestrator,
            agreement.get("jobId"),
        )
        if status != "pass" or digest is None:
            return status, reason, {}
        digests[orchestrator] = digest
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
) -> tuple[str, str, dict[str, dict]]:
    if not isinstance(value, dict):
        return "error", "malformed-input", {}
    signer = value.get("signer")
    agreement = context.get("agreement")
    verifier_context = context.get("verifierContext")
    retained = (
        verifier_context.get("authenticatedSessionContext")
        if isinstance(verifier_context, dict)
        else None
    )
    if not isinstance(retained, dict):
        return "indeterminate", "session-authority-unavailable", {}
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
        return "error", "malformed-input", {}
    status, parties = carrier_map(value.get("parties"))
    if status != "pass":
        return status, "malformed-input", parties
    try:
        if generator.canonical_bytes(value) != generator.canonical_bytes(retained):
            return "fail", "session-authority-mismatch", {}
    except (TypeError, ValueError):
        return "error", "malformed-input", {}
    return "pass", "verified", parties


def rail_ref_shape(value: object) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("railId"), str)
        and bool(value["railId"])
        and (
            "railVersion" not in value
            or (
                isinstance(value["railVersion"], int)
                and not isinstance(value["railVersion"], bool)
                and value["railVersion"] > 0
            )
        )
        and ("parameters" not in value or isinstance(value["parameters"], dict))
    )


def canonical_key(value: object) -> str:
    return generator.canonical_bytes(value).decode("utf-8")


def validate_effective_pipeline(
    context: dict, artifact: str
) -> tuple[str, str, list[dict], dict | None]:
    listing = context.get("listing")
    agreement = context.get("agreement")
    verifier_context = context.get("verifierContext")
    if (
        not isinstance(listing, dict)
        or not isinstance(agreement, dict)
        or not isinstance(verifier_context, dict)
    ):
        return "error", "malformed-input", [], None
    pipeline = listing.get("pipeline")
    accepted = listing.get("acceptedRails")
    if (
        not isinstance(pipeline, list)
        or not isinstance(accepted, list)
        or not accepted
        or any(not rail_ref_shape(reference) for reference in accepted)
    ):
        return "fail", "payment-pipeline-invalid", [], None
    try:
        accepted_keys = [canonical_key(reference) for reference in accepted]
    except (TypeError, ValueError):
        return "error", "malformed-input", [], None
    if len(accepted_keys) != len(set(accepted_keys)):
        return "fail", "payment-pipeline-invalid", [], None
    alternative_indexes = [
        index for index, step in enumerate(pipeline)
        if isinstance(step, dict) and step.get("kind") == "pay-alternative"
    ]
    concrete_indexes = [
        index for index, step in enumerate(pipeline)
        if isinstance(step, dict)
        and step.get("kind") in generator.CONCRETE_PAYMENT_PHASES
    ]
    alternatives = None
    alternative_index = None
    if alternative_indexes:
        if len(alternative_indexes) != 1 or concrete_indexes:
            return "fail", "alternative-payment-shape-invalid", [], None
        alternative_index = alternative_indexes[0]
        parameters = pipeline[alternative_index].get("parameters")
        if not isinstance(parameters, dict) or set(parameters) != {"alternatives"}:
            return "fail", "alternative-payment-shape-invalid", [], None
        alternatives = parameters.get("alternatives")
        if (
            not isinstance(alternatives, list)
            or len(alternatives) < 2
            or any(not rail_ref_shape(reference) for reference in alternatives)
        ):
            return "fail", "alternative-payment-shape-invalid", [], None
        alternative_keys = [canonical_key(reference) for reference in alternatives]
        if (
            len(alternative_keys) != len(set(alternative_keys))
            or any(key not in accepted_keys for key in alternative_keys)
        ):
            return "fail", "alternative-payment-shape-invalid", [], None
    else:
        for index in concrete_indexes:
            parameters = pipeline[index].get("parameters")
            if (
                not isinstance(parameters, dict)
                or set(parameters) != {"rail"}
                or not isinstance(parameters.get("rail"), str)
                or parameters["rail"] not in {
                    reference["railId"] for reference in accepted
                }
            ):
                return "fail", "payment-pipeline-invalid", [], None
    registry = verifier_context.get("railRegistry")
    if not isinstance(registry, dict) or registry.get("authorityAuthenticated") is not True:
        return "indeterminate", "rail-registry-unavailable", [], None
    snapshot = registry.get("snapshotId")
    resolutions = registry.get("resolutions")
    if not isinstance(snapshot, str) or not isinstance(resolutions, list):
        return "indeterminate", "rail-registry-unavailable", [], None
    steward = verifier_context.get("authenticatedRailSteward")
    if not isinstance(steward, str):
        return "indeterminate", "rail-registry-unavailable", [], None
    resolved: dict[str, dict] = {}
    handlers_by_id: dict[str, str] = {}
    for reference, reference_key in zip(accepted, accepted_keys):
        matches = [
            resolution for resolution in resolutions
            if isinstance(resolution, dict)
            and canonical_key(resolution.get("ref")) == reference_key
        ]
        if len(matches) != 1:
            return "fail", "rail-definition-resolution-invalid", [], None
        resolution = matches[0]
        if resolution.get("snapshotId") != snapshot:
            return "fail", "rail-definition-resolution-invalid", [], None
        if resolution.get("status") == "unavailable":
            return "indeterminate", "rail-definition-unavailable", [], None
        definition = resolution.get("definition")
        if (
            resolution.get("status") != "verified"
            or not isinstance(definition, dict)
            or definition.get("railId") != reference["railId"]
            or (
                "railVersion" in reference
                and definition.get("railVersion") != reference["railVersion"]
            )
            or definition.get("phaseHandler")
            not in generator.CONCRETE_PAYMENT_PHASES
            or not verify_component(definition, generator.RAIL_DOMAIN, steward)
        ):
            return "fail", "rail-definition-invalid", [], None
        previous = handlers_by_id.setdefault(
            reference["railId"], definition["phaseHandler"]
        )
        if previous != definition["phaseHandler"]:
            return "fail", "rail-definition-invalid", [], None
        resolved[reference_key] = definition
    selected = agreement.get("terms", {}).get("rail")
    if not rail_ref_shape(selected):
        return "fail", "rail-selection-invalid", [], None
    selected_key = canonical_key(selected)
    candidate_keys = (
        {canonical_key(reference) for reference in alternatives}
        if alternatives is not None else set(accepted_keys)
    )
    if selected_key not in candidate_keys or selected_key not in resolved:
        return "fail", "rail-selection-invalid", [], None
    definition = resolved[selected_key]
    if definition.get("availability") != "live":
        return "fail", "rail-selection-unavailable", [], None
    effective = copy.deepcopy(pipeline)
    if alternative_index is not None:
        effective[alternative_index] = {
            "kind": definition["phaseHandler"],
            "parameters": {"rail": selected["railId"]},
        }
    payment_indexes = [
        index for index, step in enumerate(effective)
        if step.get("kind") in generator.CONCRETE_PAYMENT_PHASES
    ]
    if payment_indexes != [verifier_context.get("paymentPhaseIndex")]:
        return "fail", "payment-phase-index-mismatch", [], None
    claims_status, role_claims = agreement_role_claims(agreement)
    if claims_status != "pass":
        return "error", "malformed-input", [], None
    bindings = agreement.get("terms", {}).get("payoutBindings")
    if artifact in generator.PAYEE_ARTIFACTS:
        expected = [
            (selected["railId"], index, role_claims["seller"])
            for index in payment_indexes
        ]
        if not isinstance(bindings, list) or any(
            not isinstance(binding, dict) for binding in bindings
        ):
            return "fail", "payout-binding-invalid", [], None
        actual = [
            (
                binding.get("railId"),
                binding.get("phaseIndex"),
                binding.get("payeeAddress"),
            )
            for binding in bindings
        ]
        if sorted(actual) != sorted(expected) or len(actual) != len(set(actual)):
            return "fail", "payout-binding-invalid", [], None
    elif bindings is not None:
        return "fail", "non-payee-terms-invalid", [], None
    return "pass", "verified", effective, definition


def validate_session_roster(
    context: dict,
    stage_input: object,
    digests: dict[str, str],
) -> tuple[str, str]:
    if not isinstance(stage_input, dict):
        return "error", "malformed-input"
    status, reason, sessions = validated_session_parties(
        stage_input.get("sessionContext"), context
    )
    if status != "pass":
        return status, reason
    claims_status, role_claims = agreement_role_claims(context.get("agreement"))
    orchestrator = context.get("verifierContext", {}).get("authenticatedOrchestrator")
    if claims_status != "pass" or not isinstance(orchestrator, str):
        return "error", "malformed-input"
    expected_claims = {**role_claims, "orchestrator": orchestrator}
    agreement = context.get("agreement")
    agreement_parties = (
        agreement.get("parties") if isinstance(agreement, dict) else None
    )
    if not isinstance(agreement_parties, list):
        return "error", "malformed-input"
    signed_hashes = {
        party.get("primaryClaim"): party.get("bundleHash")
        for party in agreement_parties
        if isinstance(party, dict)
        and isinstance(party.get("primaryClaim"), str)
        and isinstance(party.get("bundleHash"), str)
    }
    if set(sessions) != set(expected_claims):
        return "fail", "session-roster-mismatch"
    for role, claim in expected_claims.items():
        party = sessions.get(role)
        expected_hash = digests.get(claim)
        if expected_hash is None and claim in signed_hashes:
            historical_hash = signed_hashes[claim]
            expected_hash = (
                historical_hash.removeprefix("sha256:")
                if re.fullmatch(r"sha256:[0-9a-f]{64}", historical_hash)
                else historical_hash
            )
        if (
            not isinstance(party, dict)
            or party.get("primaryClaim") != claim
            or (
                expected_hash is not None
                and party.get("bundleHash") != expected_hash
            )
        ):
            return "fail", "session-party-mismatch"
    return "pass", "verified"


def validate_settlement_observation(
    observation: object,
    *,
    context: dict,
    record: dict,
    execution: dict,
    receipt_authority: str,
) -> tuple[str, str]:
    """Verify fixture-only ledger semantics independently of evidence anchoring."""

    if not isinstance(observation, dict) or set(observation) != {
        "fixtureSettlementObservationVersion", "scope", "observer", "event",
        "signature",
    }:
        return "error", "malformed-input"
    event = observation.get("event")
    if (
        observation.get("fixtureSettlementObservationVersion") != "1"
        or observation.get("scope") != "offline-conformance-fixture-only"
        or observation.get("observer") != receipt_authority
        or not isinstance(event, dict)
        or not isinstance(observation.get("signature"), str)
    ):
        return "fail", "terminal-settlement-observation-invalid"
    try:
        signature_valid = generator.verify_ed25519(
            key_bytes(receipt_authority),
            b64url_decode(observation["signature"]),
            generator.FIXTURE_SETTLEMENT_OBSERVATION_PREFIX
            + generator.hash_hex(event).encode("ascii"),
        )
    except (TypeError, ValueError):
        signature_valid = False
    payment = context.get("paymentInput")
    if not isinstance(payment, dict):
        return "error", "malformed-input"
    payer = payment.get("payer")
    payee = payment.get("payee")
    expected = {
        "jobId": execution.get("jobId"),
        "phaseIndex": execution.get("phaseIndex"),
        "phaseKind": execution.get("phaseKind"),
        "railId": execution.get("railId"),
        "paymentTxRefs": record.get("paymentTxRefs"),
        "payer": payer.get("payingKey") if isinstance(payer, dict) else None,
        "payee": payee.get("payeeAddress") if isinstance(payee, dict) else None,
        "paymentAmount": payment.get("amount"),
    }
    if not signature_valid or event != expected:
        return "fail", "terminal-settlement-observation-invalid"
    return "pass", "verified"


def validate_payment_rail(context: dict, payment: dict) -> tuple[str, str]:
    status, artifact = artifact_type(context.get("agreement"))
    if status != "pass" or artifact is None:
        return "fail", "agreement-discriminator-invalid"
    status, reason, effective, definition = validate_effective_pipeline(
        context, artifact
    )
    if status != "pass":
        return status, reason
    rail = payment.get("rail")
    verifier_context = context.get("verifierContext")
    if not isinstance(rail, dict) or not isinstance(verifier_context, dict):
        return "error", "malformed-input"
    phase_index = verifier_context.get("paymentPhaseIndex")
    if (
        definition is None
        or rail != definition
        or payment.get("amount")
        != context.get("agreement", {}).get("terms", {}).get("price")
        or not isinstance(phase_index, int)
        or isinstance(phase_index, bool)
        or phase_index < 0
        or phase_index >= len(effective)
        or effective[phase_index].get("kind") != rail.get("phaseHandler")
        or effective[phase_index].get("parameters")
        != {"rail": rail.get("railId")}
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
    prior_payment = context.get("priorPaymentInput")
    if not isinstance(resolved, dict) or not isinstance(prior, dict):
        return "indeterminate", "prior-disposition-unavailable"
    disposition = resolved.get("artifact")
    receipt = resolved.get("receipt")
    execution_authority = resolved.get("executionAuthority")
    if (
        not isinstance(disposition, dict)
        or not isinstance(receipt, dict)
        or not valid_signed_ref(reference)
    ):
        return "error", "malformed-input"
    disposition_hash = generator.artifact_hash(disposition, "signature")
    try:
        expected_reference = generator.disposition_reference(disposition)
    except (KeyError, TypeError, ValueError):
        return "error", "malformed-input"
    if reference != expected_reference or disposition_hash != reference["contentHash"]:
        return "fail", "prior-disposition-reference-mismatch"
    orchestrator = context.get("verifierContext", {}).get("authenticatedOrchestrator")
    receipt_authority = context.get("verifierContext", {}).get(
        "authenticatedReceiptAuthority"
    )
    if (
        not isinstance(orchestrator, str)
        or not isinstance(receipt_authority, str)
        or not isinstance(execution_authority, dict)
    ):
        return "indeterminate", "prior-disposition-unavailable"
    if (
        execution_authority.get("status") != "verified"
        or execution_authority.get("phaseOrchestratorClaim") != orchestrator
        or reference.get("signer") != orchestrator
    ):
        return "fail", "prior-disposition-authority-invalid"
    if not verify_component(disposition, generator.DISPOSITION_DOMAIN, orchestrator):
        return "fail", "prior-disposition-signature-invalid"
    expected_nonce = generator.hash_hex({
        "disposition": disposition.get("dispositionId")
    })
    receipt_status, receipt_reason, _ = verify_dependency_receipt(
        receipt,
        logical_address=reference["anchor"]["locator"],
        native_address=reference["anchor"]["locator"],
        content_hash=disposition_hash,
        writer=orchestrator,
        nonce=expected_nonce,
        receipt_authority=receipt_authority,
        invalid_reason="prior-disposition-receipt-invalid",
    )
    if receipt_status != "pass":
        return receipt_status, receipt_reason
    if not any(
        isinstance(step, dict) and step.get("kind") == "pay-alternative"
        for step in context.get("listing", {}).get("pipeline", [])
    ):
        return "fail", "replacement-requires-pay-alternative"
    if disposition.get("replacementJobId") != agreement.get("jobId"):
        return "fail", "replacement-job-mismatch"
    if disposition.get("priorJobId") != prior.get("jobId"):
        return "fail", "prior-job-mismatch"
    if disposition.get("priorAgreementRef") != generator.artifact_ref(
        prior, "prior-agreement", "signatures"
    ):
        return "fail", "prior-agreement-reference-mismatch"
    prior_status, prior_artifact = artifact_type(prior)
    if (
        prior_status != "pass"
        or prior_artifact is None
        or prior_artifact not in generator.PAYEE_ARTIFACTS
        or verify_agreement(prior, prior_artifact)[0] != "pass"
    ):
        return "fail", "prior-agreement-invalid"
    if prior.get("listingRef") != agreement.get("listingRef"):
        return "fail", "prior-agreement-reference-mismatch"
    prior_selection = prior.get("terms", {}).get("rail")
    current_selection = agreement.get("terms", {}).get("rail")
    phase_index = disposition.get("priorPhaseIndex")
    if (
        not rail_ref_shape(prior_selection)
        or not rail_ref_shape(current_selection)
        or disposition.get("priorSelection") != prior_selection
        or prior_selection == current_selection
        or not isinstance(phase_index, int)
        or isinstance(phase_index, bool)
    ):
        return "fail", "prior-selection-mismatch"
    prior_context = {
        "listing": context.get("listing"),
        "agreement": prior,
        "verifierContext": copy.deepcopy(context.get("verifierContext")),
    }
    prior_context["verifierContext"]["paymentPhaseIndex"] = phase_index
    prior_pipeline_status, _, prior_effective, prior_definition = (
        validate_effective_pipeline(prior_context, prior_artifact)
    )
    if prior_pipeline_status == "indeterminate":
        return "indeterminate", "prior-disposition-proof-unavailable"
    if (
        prior_pipeline_status != "pass"
        or not isinstance(prior_definition, dict)
        or phase_index < 0
        or phase_index >= len(prior_effective)
        or prior_effective[phase_index].get("kind")
        != prior_definition.get("phaseHandler")
    ):
        return "fail", "prior-selection-mismatch"
    state = disposition.get("disposition")
    evidence_refs = disposition.get("reconciliationEvidenceRefs")
    if state == "closed-before-authorization":
        if evidence_refs != [] or resolved.get("authorizationJournalClosed") is not True:
            return "fail", "prior-disposition-proof-invalid"
    elif state == "closed-cannot-settle":
        materials = resolved.get("reconciliationEvidence")
        if (
            not isinstance(evidence_refs, list)
            or not evidence_refs
            or any(not valid_ref(item) for item in evidence_refs)
            or resolved.get("reconciliationEvidenceVerified") is not True
            or not isinstance(materials, list)
            or len(materials) != len(evidence_refs)
        ):
            return "fail", "prior-disposition-proof-invalid"
        expected_phase = prior_definition.get("phaseHandler")
        for reference_item in evidence_refs:
            matching_material = [
                material for material in materials
                if isinstance(material, dict) and material.get("ref") == reference_item
            ]
            if len(matching_material) != 1:
                return "fail", "prior-disposition-proof-invalid"
            material = matching_material[0]
            record = material.get("record")
            lifecycle = material.get("lifecycle")
            material_receipt = material.get("receipt")
            material_nonce = material.get("nonce")
            observation = material.get("settlementObservation")
            if (
                not reputation_reference._settlement_evidence_shape_valid(record)
                or record.get("jobId") != prior.get("jobId")
                or record.get("phase") != expected_phase
                or record.get("outcome") != "failure"
                or record.get("reason") != "closed-cannot-settle"
                or reference_item.get("contentHash")
                != reputation_reference.settlement_evidence_hash(record)
                or not verify_component(
                    record, generator.SETTLEMENT_EVIDENCE_DOMAIN, orchestrator
                )
                or lifecycle != {
                    "state": "finalized", "independentlyResolvable": True
                }
                or not isinstance(material_nonce, str)
            ):
                return "fail", "prior-disposition-proof-invalid"
            payer = prior_payment.get("payer") if isinstance(prior_payment, dict) else None
            payee = prior_payment.get("payee") if isinstance(prior_payment, dict) else None
            authorization = {
                "jobId": prior.get("jobId"),
                "phaseIndex": phase_index,
                "phaseKind": expected_phase,
                "railId": prior_selection.get("railId"),
                "resource": prior_selection.get("parameters", {}).get("resource"),
                "payer": payer.get("payingKey") if isinstance(payer, dict) else None,
                "payee": payee.get("payeeAddress") if isinstance(payee, dict) else None,
                "paymentAmount": (
                    prior_payment.get("amount")
                    if isinstance(prior_payment, dict) else None
                ),
            }
            expected_event = {
                **authorization,
                "outcome": "cannot-settle",
                "authorizationRef": generator.hash_hex({
                    "priorPaymentAuthorization": authorization
                }),
            }
            if not isinstance(observation, dict) or set(observation) != {
                "fixtureSettlementObservationVersion", "scope", "observer",
                "event", "signature",
            }:
                return "fail", "prior-disposition-proof-invalid"
            try:
                observation_signature_valid = generator.verify_ed25519(
                    key_bytes(receipt_authority),
                    b64url_decode(observation.get("signature", "")),
                    generator.FIXTURE_SETTLEMENT_OBSERVATION_PREFIX
                    + generator.hash_hex(observation.get("event")).encode("ascii"),
                )
            except (TypeError, ValueError):
                observation_signature_valid = False
            if (
                observation.get("fixtureSettlementObservationVersion") != "1"
                or observation.get("scope") != "offline-conformance-fixture-only"
                or observation.get("observer") != receipt_authority
                or observation.get("event") != expected_event
                or not observation_signature_valid
            ):
                return "fail", "prior-disposition-proof-invalid"
            logical_address = (
                f"dacs4:payment:{prior.get('jobId')}:"
                f"{quote(prior_selection.get('railId'), safe='-._~')}:{phase_index}"
            )
            status, reason, _ = verify_dependency_receipt(
                material_receipt,
                logical_address=logical_address,
                native_address=reference_item["anchor"]["locator"],
                content_hash=reference_item["contentHash"],
                writer=orchestrator,
                nonce=material_nonce,
                receipt_authority=receipt_authority,
                invalid_reason="prior-disposition-proof-invalid",
            )
            if status != "pass":
                return status, reason
    else:
        return "fail", "replacement-not-safe"
    return "pass", "verified"


def pre_action_gate(
    context: dict, artifact: str, stage: str, unavailable: set[str]
) -> tuple[str, str, dict[str, str], list[dict]]:
    stage_input = {
        "commit": context.get("commitInput"),
        "payment": context.get("paymentInput"),
        "terminal": context.get("terminalInput"),
    }.get(stage)
    agreement = context.get("agreement")
    if not isinstance(stage_input, dict) or not isinstance(agreement, dict):
        return "error", "malformed-input", {}, []
    if stage in {"commit", "payment"} and (
        stage_input.get("jobId") != agreement.get("jobId")
        or stage_input.get("agreement") != agreement
    ):
        return "fail", f"{stage}-input-authority-mismatch", {}, []
    if stage == "commit" and stage_input.get("listingRef") != agreement.get("listingRef"):
        return "fail", "commit-input-authority-mismatch", {}, []
    if stage == "terminal" and (
        stage_input.get("listing") != context.get("listing")
        or stage_input.get("agreement") != agreement
        or stage_input.get("commitment") != context.get("commitment")
    ):
        return "fail", "terminal-authority-mismatch", {}, []
    digests: dict[str, str] = {}
    if artifact in generator.STRONG_ARTIFACTS:
        status, reason, digests = validate_strong_proof(
            context, artifact, stage, unavailable
        )
        if status != "pass":
            return status, reason, {}, []
    status, reason = validate_session_roster(context, stage_input, digests)
    if status != "pass":
        return status, reason, {}, []
    status, reason, effective, _ = validate_effective_pipeline(context, artifact)
    if status != "pass":
        return status, reason, {}, []
    status, reason = validate_replacement(context, unavailable)
    if status != "pass":
        return status, reason, {}, []
    return "pass", "verified", digests, effective


def validate_payment(
    context: dict, artifact: str, unavailable: set[str]
) -> tuple[str, str]:
    status, reason, digests, _ = pre_action_gate(
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
            or carrier.get("bundleHash") != digests[role_claims[role]]
        ):
            return "fail", "payment-party-mismatch"
    rail_status, rail_reason = validate_payment_rail(context, payment)
    if rail_status != "pass":
        return rail_status, rail_reason
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
        selected_rail = agreement.get("terms", {}).get("rail")
        if (
            not isinstance(selected_rail, dict)
            or binding.get("railId") != selected_rail.get("railId")
            or binding.get("phaseIndex")
            != context["verifierContext"]["paymentPhaseIndex"]
        ):
            return "fail", "payout-binding-invalid"
        if binding.get("payeeAddress") != payee.get("payeeAddress"):
            return "fail", "payout-destination-mismatch"
    paying_key = payer.get("payingKey")
    buyer_companion = next(
        (
            companion for companion in payment.get("identityBindingCompanions", [])
            if isinstance(companion, dict)
            and isinstance(companion.get("identityBundle"), dict)
            and companion["identityBundle"].get("presentedBy")
            == role_claims["buyer"]
        ),
        None,
    )
    buyer_claims = (
        buyer_companion.get("identityBundle", {}).get("claims")
        if isinstance(buyer_companion, dict)
        else None
    )
    if (
        not isinstance(paying_key, str)
        or not isinstance(buyer_claims, list)
        or not any(
            isinstance(claim, dict)
            and claim.get("ref") == paying_key
            and paying_key.startswith("key:")
            for claim in buyer_claims
        )
    ):
        return "fail", "paying-key-not-authorized"
    return "pass", "verified"


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
                (generator.EVIDENCE_BOUND_TERMINAL_DOMAIN + digest).encode("ascii")
            )
        except (TypeError, ValueError):
            valid = False
        if not valid:
            return "fail", "terminal-signature-invalid"
    return "pass", "verified"


def validate_terminal_authority(
    context: dict,
    bundle: dict,
    phase: str,
    effective: list[dict] | None = None,
) -> tuple[str, str]:
    verifier_context = context.get("verifierContext")
    authority = (
        verifier_context.get("terminalAuthority")
        if isinstance(verifier_context, dict)
        else None
    )
    if not isinstance(authority, dict):
        return "indeterminate", "terminal-authority-unavailable"
    receipt_authority = verifier_context.get("authenticatedReceiptAuthority")
    orchestrator = verifier_context.get("authenticatedOrchestrator")
    if not isinstance(receipt_authority, str) or not isinstance(orchestrator, str):
        return "indeterminate", "terminal-authority-unavailable"
    agreement_authority = authority.get("agreement")
    agreement_ref = bundle.get("agreementRef")
    if not isinstance(agreement_authority, dict) or not valid_ref(agreement_ref):
        return "indeterminate", "terminal-agreement-authority-unavailable"
    agreement_lifecycle = agreement_authority.get("lifecycle")
    if agreement_lifecycle != {
        "state": "finalized", "independentlyResolvable": True
    }:
        return "fail", "terminal-agreement-lifecycle-invalid"
    job_id = bundle.get("jobId")
    status, reason, _ = verify_dependency_receipt(
        agreement_authority.get("receipt"),
        logical_address=f"dacs3:agreement:{job_id}",
        native_address=agreement_ref["anchor"]["locator"],
        content_hash=agreement_ref["contentHash"],
        writer=orchestrator,
        nonce=generator.hash_hex({"agreement": job_id}),
        receipt_authority=receipt_authority,
        invalid_reason="terminal-agreement-receipt-invalid",
    )
    if status != "pass":
        return status, reason

    cvr_authorities = authority.get("compositeRecords")
    vet_records = bundle.get("vetRecords")
    agreement = context.get("agreement")
    parties = agreement.get("parties") if isinstance(agreement, dict) else None
    if (
        not isinstance(cvr_authorities, list)
        or not isinstance(vet_records, list)
        or not isinstance(parties, list)
        or len(cvr_authorities) != len(vet_records)
        or len(vet_records) != len(parties)
    ):
        return "indeterminate", "terminal-cvr-authority-unavailable"
    seen_cvr_refs = set()
    for party, expected_ref in zip(parties, vet_records):
        if not isinstance(party, dict) or not valid_ref(expected_ref):
            return "error", "malformed-input"
        matches = [
            entry for entry in cvr_authorities
            if isinstance(entry, dict) and entry.get("ref") == expected_ref
        ]
        if len(matches) != 1 or canonical_key(expected_ref) in seen_cvr_refs:
            return "fail", "terminal-cvr-authority-invalid"
        seen_cvr_refs.add(canonical_key(expected_ref))
        entry = matches[0]
        if entry.get("lifecycle") != {
            "state": "finalized", "independentlyResolvable": True
        }:
            return "fail", "terminal-cvr-lifecycle-invalid"
        claim = party.get("primaryClaim")
        role = next(
            (role for role, value in generator.CLAIMS.items() if value == claim),
            None,
        )
        if role is None:
            return "fail", "terminal-cvr-authority-invalid"
        logical_address = (
            f"dacs2:composite:{job_id}:{quote(claim, safe='-._~')}"
        )
        status, reason, _ = verify_dependency_receipt(
            entry.get("receipt"),
            logical_address=logical_address,
            native_address=expected_ref["anchor"]["locator"],
            content_hash=expected_ref["contentHash"],
            writer=orchestrator,
            nonce=generator.hash_hex({"cvr": job_id, "role": role}),
            receipt_authority=receipt_authority,
            invalid_reason="terminal-cvr-receipt-invalid",
        )
        if status != "pass":
            return status, reason
    settlement_authorities = authority.get("settlements")
    settlement_refs = bundle.get("settlementEvidence")
    if not isinstance(settlement_authorities, list) or not isinstance(
        settlement_refs, list
    ):
        return "indeterminate", "terminal-settlement-authority-unavailable"
    if len(settlement_authorities) != len(settlement_refs):
        return "fail", "terminal-settlement-authority-invalid"
    reference_validation: dict[str, dict] = {}
    execution_by_phase: dict[str, dict] = {}
    verified_receipts: dict[str, dict] = {}
    for reference in settlement_refs:
        if not valid_ref(reference):
            return "error", "malformed-input"
        matches = [
            entry for entry in settlement_authorities
            if isinstance(entry, dict) and entry.get("ref") == reference
        ]
        if len(matches) != 1:
            return "indeterminate", "terminal-settlement-authority-unavailable"
        entry = matches[0]
        record = entry.get("record")
        execution = entry.get("executionAuthority")
        lifecycle = entry.get("lifecycle")
        if (
            not isinstance(record, dict)
            or not isinstance(execution, dict)
            or lifecycle != {
                "state": "finalized", "independentlyResolvable": True
            }
        ):
            return "fail", "terminal-settlement-authority-invalid"
        phase_index = execution.get("phaseIndex")
        phase_kind = execution.get("phaseKind")
        writer = execution.get("phaseOrchestrator")
        nonce = execution.get("anchorNonce")
        if (
            isinstance(phase_index, bool)
            or not isinstance(phase_index, int)
            or phase_index < 0
            or not isinstance(phase_kind, str)
            or not isinstance(writer, str)
            or not isinstance(nonce, str)
            or execution.get("jobId") != job_id
        ):
            return "fail", "terminal-settlement-authority-invalid"
        if phase_kind.startswith("pay-"):
            rail_id = execution.get("railId")
            if not isinstance(rail_id, str):
                return "fail", "terminal-settlement-authority-invalid"
            logical_address = (
                f"dacs4:payment:{job_id}:{quote(rail_id, safe='-._~')}:{phase_index}"
            )
        else:
            logical_address = execution.get("evidenceLogicalAddress")
            if not isinstance(logical_address, str):
                return "fail", "terminal-settlement-authority-invalid"
        receipt = entry.get("receipt")
        status, reason, _ = verify_dependency_receipt(
            receipt,
            logical_address=logical_address,
            native_address=reference["anchor"]["locator"],
            content_hash=reference["contentHash"],
            writer=writer,
            nonce=nonce,
            receipt_authority=receipt_authority,
            invalid_reason="terminal-settlement-receipt-invalid",
        )
        if status != "pass":
            return status, reason
        if phase_kind.startswith("pay-"):
            status, reason = validate_settlement_observation(
                execution.get("settlementObservation"),
                context=context,
                record=record,
                execution=execution,
                receipt_authority=receipt_authority,
            )
            if status != "pass":
                return status, reason
        reference_key = canonical_key(reference)
        phase_key = f"{phase_index}:{phase_kind}"
        if reference_key in reference_validation or phase_key in execution_by_phase:
            return "fail", "terminal-settlement-authority-invalid"
        reference_validation[reference_key] = {
            "record": record,
            "lifecycle": lifecycle,
        }
        execution_by_phase[phase_key] = execution
        verified_receipts[reference_key] = {
            "logicalAddress": receipt["logicalAddress"],
            "nativeAddress": receipt["nativeAddress"],
            "contentHash": receipt["contentHash"],
            "transaction": receipt["transactionRef"]["value"],
            "writer": receipt["writer"],
            "nonce": receipt["nonce"],
        }

    bundle_authority = authority.get("bundle")
    if not isinstance(bundle_authority, dict):
        return "indeterminate", "terminal-bundle-authority-unavailable"
    bundle_lifecycle = bundle_authority.get("lifecycle")
    if bundle_lifecycle != {
        "state": "finalized", "independentlyResolvable": True
    }:
        return "fail", "terminal-bundle-lifecycle-invalid"
    bundle_address = reputation_reference.logical_address(
        job_id, bundle.get("anchoredByRole")
    )
    status, reason, _ = verify_dependency_receipt(
        bundle_authority.get("receipt"),
        logical_address=bundle_address,
        native_address=bundle_address,
        content_hash=reputation_reference.bundle_hash(bundle),
        writer=orchestrator,
        nonce=generator.hash_hex({"bundle": job_id}),
        receipt_authority=receipt_authority,
        invalid_reason="terminal-bundle-receipt-invalid",
    )
    if status != "pass":
        return status, reason
    public_keys = {}
    try:
        for party in bundle.get("parties", []):
            public_keys[party["primaryClaim"]] = key_bytes(party["primaryClaim"])
    except (KeyError, TypeError, ValueError):
        return "error", "malformed-input"
    ok, seb_reason, _ = reputation_reference.validate_ebfab(
        bundle,
        context.get("listing"),
        public_keys,
        reference_validation,
        bundle_lifecycle,
        execution_by_phase,
        verified_receipts,
        effective_pipeline=(
            effective
            if any(
                isinstance(step, dict) and step.get("kind") == "pay-alternative"
                for step in context.get("listing", {}).get("pipeline", [])
            )
            else None
        ),
        additional_commit_phase=(
            phase if phase != generator.PHASES["agreement"] else None
        ),
    )
    if not ok:
        return "fail", f"terminal-seb-invalid:{seb_reason}"
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
    status, reason, digests, effective = pre_action_gate(
        context, artifact, "terminal", unavailable
    )
    if status != "pass":
        return status, reason
    if any(
        isinstance(step, dict)
        and step.get("kind") in generator.CONCRETE_PAYMENT_PHASES
        for step in effective
    ):
        status, reason = validate_payment(context, artifact, unavailable)
        if status != "pass":
            return status, reason
    phase_summary = bundle.get("phaseSummary")
    if (
        not isinstance(phase_summary, list)
        or len(phase_summary) != len(effective)
        or any(not isinstance(entry, dict) for entry in phase_summary)
        or any(
            not isinstance(entry.get("index"), int)
            or isinstance(entry.get("index"), bool)
            or entry.get("index") != index
            or not isinstance(entry.get("kind"), str)
            or not isinstance(effective[index], dict)
            for index, entry in enumerate(phase_summary)
        )
    ):
        return "error", "malformed-input"
    if (
        any(
            entry.get("kind") != effective[index].get("kind")
            for index, entry in enumerate(phase_summary)
        )
        or sum(entry.get("kind") == phase for entry in phase_summary) != 1
    ):
        return "fail", "terminal-phase-mismatch"
    agreement = context["agreement"]
    if bundle.get("agreementRef") != generator.artifact_ref(
        agreement, f"{agreement.get('jobId', 'bad')}-agreement", "signatures"
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
    status, parties = carrier_map(bundle.get("parties"))
    if status != "pass":
        return "error", "malformed-input"
    for role in ("buyer", "seller", "orchestrator"):
        if (
            role not in parties
            or parties[role].get("primaryClaim") != expected_claims[role]
            or parties[role].get("bundleHash") != digests[expected_claims[role]]
        ):
            return "fail", "terminal-party-mismatch"
    return validate_terminal_authority(context, bundle, phase, effective)


def modeled_old_reader(context: dict) -> tuple[str, str]:
    status, reason, phase = listing_phase(context, generator.BASE_SUPPORTED_PHASES)
    if status != "pass":
        return (
            ("fail", "unsupported-new-type")
            if reason == "unsupported-phase"
            else (status, reason)
        )
    status, artifact = artifact_type(context.get("agreement"))
    if status != "pass" or artifact is None:
        return "fail", "agreement-discriminator-invalid"
    old = {"agreement", "payeeBoundAgreement"}
    if artifact not in old or phase not in {generator.PHASES[item] for item in old}:
        return "fail", "unsupported-new-type"
    if generator.PHASES[artifact] != phase:
        return "fail", "phase-artifact-mismatch"
    return verify_agreement(context["agreement"], artifact)


def validate_historical_stage(
    context: dict, artifact: str, stage: str, unavailable: set[str]
) -> tuple[str, str]:
    status, reason, _, _ = pre_action_gate(
        context, artifact, stage, unavailable
    )
    if status != "pass":
        return status, reason
    if stage == "commit":
        # dispatch() plus the common gate above execute the signed Listing,
        # agreement, commitment, session, pipeline, payout, and APR controls
        # actually modeled in this repository.
        return "pass", "verified"
    if stage == "payment":
        return "indeterminate", "historical-payment-stage-not-modeled"
    if stage == "terminal":
        bundle = context.get("terminalInput", {}).get("bundle")
        claims_status, role_claims = agreement_role_claims(context.get("agreement"))
        orchestrator = context.get("verifierContext", {}).get(
            "authenticatedOrchestrator"
        )
        if claims_status != "pass" or not isinstance(orchestrator, str):
            return "error", "malformed-input"
        status, reason = verify_terminal_signatures(
            bundle, {role_claims["buyer"], role_claims["seller"], orchestrator}
        )
        if status != "pass":
            return status, reason
        status, reason = validate_terminal_authority(
            context, bundle, generator.PHASES[artifact]
        )
        if status != "pass":
            return status, reason
        return "indeterminate", "historical-terminal-stage-not-modeled"
    return "error", "malformed-input"


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
    elif mutation["op"] == "append-value":
        target = parent[leaf]  # type: ignore[index]
        target.append(copy.deepcopy(mutation["value"]))
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
        unavailable = set(vector.get("unavailable", []))
        stage = vector.get("stage")
        if artifact not in generator.STRONG_ARTIFACTS:
            verdict, reason = validate_historical_stage(
                context, artifact, stage, unavailable
            )
            return outcome(verdict, reason)
        if stage == "commit":
            verdict, reason, _, _ = pre_action_gate(
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


def terminal_reputation_authority(context: dict, artifact: str) -> dict:
    bundle = context["terminalInput"]["bundle"]
    authority = context["verifierContext"]["terminalAuthority"]
    reference_validation = {}
    execution_by_phase = {}
    verified_receipts = {}
    for entry in authority["settlements"]:
        reference = entry["ref"]
        key = canonical_key(reference)
        receipt = entry["receipt"]
        execution = entry["executionAuthority"]
        phase_key = f"{execution['phaseIndex']}:{execution['phaseKind']}"
        reference_validation[key] = {
            "record": copy.deepcopy(entry["record"]),
            "lifecycle": copy.deepcopy(entry["lifecycle"]),
        }
        execution_by_phase[phase_key] = copy.deepcopy(execution)
        verified_receipts[key] = {
            "logicalAddress": receipt["logicalAddress"],
            "nativeAddress": receipt["nativeAddress"],
            "contentHash": receipt["contentHash"],
            "transaction": receipt["transactionRef"]["value"],
            "writer": receipt["writer"],
            "nonce": receipt["nonce"],
        }
    public_keys = {
        party["primaryClaim"]: key_bytes(party["primaryClaim"])
        for party in bundle["parties"]
    }
    status, _, effective, _ = validate_effective_pipeline(context, artifact)
    if status != "pass":
        raise ValueError("effective pipeline was not verified")
    result = {
        "listing": copy.deepcopy(context["listing"]),
        "publicKeys": public_keys,
        "referenceValidationByCanonicalRef": reference_validation,
        "bundleLifecycle": copy.deepcopy(authority["bundle"]["lifecycle"]),
        "sessionExecutionAuthorityByPhaseKey": execution_by_phase,
        "verifiedReceiptByCanonicalRef": verified_receipts,
        "additionalCommitPhase": generator.PHASES[artifact],
    }
    if any(
        step.get("kind") == "pay-alternative"
        for step in context["listing"]["pipeline"]
    ):
        result["effectivePipeline"] = effective
    return result


def derive_identity_bound_reputation(
    context: dict,
    unavailable: set[str],
    party: str,
    role_tag: dict,
    window_start: int,
    window_end: int,
) -> tuple[str, str, dict | None]:
    """Execute IBH admission before the existing DACS-5 metric consumer.

    Like dacs5_reference.derive, this reference adapter receives an already
    verified role-resolution tag. It is not a replacement for SR-2/BB-6 role
    resolution or a complete deployed reputation reader. No new derivation
    discriminator or historical metric algorithm is introduced here.
    """
    try:
        verdict, reason, artifact, phase = dispatch(context)
        if verdict != "pass":
            return verdict, reason, None
        if artifact not in generator.STRONG_ARTIFACTS or phase is None:
            return "fail", "stronger-agreement-required", None
        verdict, reason = validate_terminal(context, artifact, phase, unavailable)
        if verdict != "pass":
            return verdict, reason, None
        bundle = context["terminalInput"]["bundle"]
        if not isinstance(role_tag, dict) or role_tag.get("bundle") != bundle:
            return "error", "role-resolution-bundle-mismatch", None
        # Snapshot exactly the verified inputs; do not replace or strip the
        # new phase kinds before the existing metric algorithm consumes them.
        authenticated_tag = copy.deepcopy(role_tag)
        authenticated_tag["ebfabAuthority"] = terminal_reputation_authority(
            context, artifact
        )
        authenticated_tag["selectedByRoleResolution"] = True
        authenticated_tag["resolvedJobId"] = bundle["jobId"]
        derivation = reputation_reference.derive_job_bound(
            party, [authenticated_tag], window_start, window_end
        )
        return "pass", "verified", derivation
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return "error", "malformed-input", None


class IdentityBundleHashBindingVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {case["name"]: case for case in cls.data["vectors"]}

    def test_listing_publication_does_not_require_a_session_nonce(self):
        for artifact in generator.ARTIFACTS:
            context = copy.deepcopy(self.data["scenarios"][artifact])
            publication = context["listing"]["seller"]["identity"]
            publication.pop("sessionNonce", None)
            generator.resign_bundle(publication, "seller")
            generator.resign_context(context, "listing-chain")
            data = {"scenarios": {artifact: context}}
            for stage in ("commit", "payment", "terminal"):
                with self.subTest(artifact=artifact, stage=stage):
                    vector = {
                        "scenario": artifact, "commitment": "finality", "stage": stage,
                    }
                    expected = (
                        "pass"
                        if artifact in generator.STRONG_ARTIFACTS or stage == "commit"
                        else "indeterminate"
                    )
                    self.assertEqual(evaluate(data, vector)[0], expected)
            if artifact in generator.STRONG_ARTIFACTS:
                fresh = context["commitInput"]["identityBindingCompanions"][0]["identityBundle"]
                self.assertEqual(validate_identity_bundle(fresh, "wrong-nonce")[0], "fail")

    def test_nonce_admission_consumes_first_attempt_and_has_bounded_lifetime(self):
        job_id = generator.JOB_IDS["identityBoundAgreement"]
        nonce = "ab" * 32
        store = NonceAdmissionStore()
        self.assertTrue(store.issue(
            job_id, generator.CLAIMS["buyer"], nonce,
            issued_at=generator.NOW, expires_at=generator.NOW + 100,
        ))
        self.assertFalse(store.issue(
            job_id, generator.CLAIMS["seller"], nonce,
            issued_at=generator.NOW, expires_at=generator.NOW + 100,
        ))
        invalid = generator.identity_bundle("buyer", nonce)
        invalid["presentation"]["signatures"][0]["signature"] = "AAAA"
        self.assertEqual(
            store.admit(
                job_id, generator.CLAIMS["buyer"], invalid,
                attempted_at=generator.NOW + 1,
            )[0],
            "fail",
        )
        valid = generator.identity_bundle("buyer", nonce)
        self.assertEqual(
            store.admit(
                job_id, generator.CLAIMS["buyer"], valid,
                attempted_at=generator.NOW + 2,
            ),
            ("fail", "nonce-consumed"),
        )

        expired_nonce = "cd" * 32
        self.assertTrue(store.issue(
            job_id, generator.CLAIMS["seller"], expired_nonce,
            issued_at=generator.NOW, expires_at=generator.NOW + 10,
        ))
        expired = generator.identity_bundle("seller", expired_nonce)
        self.assertEqual(
            store.admit(
                job_id, generator.CLAIMS["seller"], expired,
                attempted_at=generator.NOW + 11,
            ),
            ("fail", "nonce-expired"),
        )

    def test_nonce_admission_binds_the_signed_presenter_before_acceptance(self):
        job_id = generator.JOB_IDS["identityBoundAgreement"]
        buyer = generator.CLAIMS["buyer"]
        store = NonceAdmissionStore()
        nonce = "ef" * 32
        self.assertTrue(store.issue(
            job_id, buyer, nonce,
            issued_at=generator.NOW, expires_at=generator.NOW + 100,
        ))
        self.assertEqual(store.admit(
            job_id, buyer, generator.identity_bundle("seller", nonce),
            attempted_at=generator.NOW + 1,
        ), ("fail", "nonce-binding-mismatch"))
        # A wrong-presenter attempt consumes the challenge too.
        self.assertEqual(store.admit(
            job_id, buyer, generator.identity_bundle("buyer", nonce),
            attempted_at=generator.NOW + 2,
        ), ("fail", "nonce-consumed"))
        fresh_nonce = "ab" * 32
        self.assertTrue(store.issue(
            job_id, buyer, fresh_nonce,
            issued_at=generator.NOW, expires_at=generator.NOW + 100,
        ))
        self.assertEqual(store.admit(
            job_id, buyer, generator.identity_bundle("buyer", fresh_nonce),
            attempted_at=generator.NOW + 1,
        ), ("pass", "verified"))

    def test_retained_admission_is_exact_and_reused_without_readmission(self):
        scenario = self.data["scenarios"]["identityBoundAgreement"]
        records = scenario["verifierContext"]["identityAdmissionAuthority"]["records"]
        self.assertEqual(len(records), len({record["nonce"] for record in records}))
        self.assertTrue(all(record["consumed"] is True for record in records))
        for stage in ("commit", "payment", "terminal"):
            with self.subTest(stage=stage):
                case = self.cases[f"identityBoundAgreement-{stage}-verified"]
                self.assertEqual(evaluate(self.data, case)[0], "pass")
        self.assertEqual(
            evaluate(
                self.data, self.cases["retained-admission-authority-unavailable"]
            )[0],
            "indeterminate",
        )
        self.assertEqual(
            evaluate(
                self.data,
                self.cases[
                    "changed-resigned-presentation-cannot-reuse-admitted-nonce"
                ],
            )[0],
            "fail",
        )

    def test_original_cross_stage_counterexamples_are_non_authorizing(self):
        for name in (
            "payment-job-must-match-agreement-and-session",
            "payment-paying-key-must-be-in-admitted-bundle",
            "commit-session-party-substitution-rejected",
            "payee-payout-coverage-required-before-commit",
            "replacement-disposition-signature-invalid-before-commit",
            "replacement-disposition-native-address-invalid-before-commit",
            "replacement-ordinary-payment-phase-rejected",
            "completed-terminal-empty-settlement-evidence-rejected",
            "historical-payment-destination-substitution-non-authorizing",
        ):
            with self.subTest(name=name):
                verdict, result = evaluate(self.data, self.cases[name])
                self.assertNotEqual(verdict, "pass")
                self.assertIs(result["authorizedAction"], False)

    def test_replacement_uses_apr_projection_and_exact_original_slot(self):
        scenario = self.data["scenarios"]["identityBoundPayeeReplacement"]
        raw = scenario["listing"]["pipeline"]
        self.assertEqual(raw[3]["kind"], "pay-alternative")
        status, reason, effective, definition = validate_effective_pipeline(
            scenario, "identityBoundPayeeAgreement"
        )
        self.assertEqual((status, reason), ("pass", "verified"))
        self.assertEqual(effective[3], {
            "kind": definition["phaseHandler"],
            "parameters": {"rail": scenario["agreement"]["terms"]["rail"]["railId"]},
        })
        self.assertEqual(
            scenario["agreement"]["terms"]["payoutBindings"][0]["phaseIndex"],
            3,
        )
        for stage in ("commit", "payment", "terminal"):
            with self.subTest(stage=stage):
                verdict, _ = evaluate(self.data, {
                    "scenario": "identityBoundPayeeReplacement",
                    "commitment": "finality",
                    "stage": stage,
                })
                self.assertEqual(verdict, "pass")
        self.assertEqual(
            evaluate(
                self.data,
                self.cases[
                    "replacement-prior-selection-cannot-use-synthetic-slot"
                ],
            )[0],
            "fail",
        )

    def test_terminal_uses_complete_seb_and_finalized_dependency_joins(self):
        scenario = self.data["scenarios"]["identityBoundAgreement"]
        bundle = scenario["terminalInput"]["bundle"]
        self.assertEqual(bundle["evidenceBoundFaultBundleVersion"], "1")
        self.assertEqual(
            [
                entry["kind"] for entry in bundle["phaseSummary"]
                if entry["kind"].startswith(("pay-", "deliver-"))
            ],
            ["pay-dem", "deliver-storage-program"],
        )
        self.assertEqual(len(bundle["settlementEvidence"]), 2)
        authority = scenario["verifierContext"]["terminalAuthority"]
        self.assertEqual(len(authority["settlements"]), 2)
        self.assertEqual(len(authority["compositeRecords"]), 2)
        for name in (
            "terminal-settlement-receipt-address-tamper-rejected",
            "terminal-settlement-receipt-finality-tamper-rejected",
            "terminal-bundle-receipt-finality-tamper-rejected",
            "terminal-agreement-receipt-content-tamper-rejected",
            "terminal-bundle-lifecycle-not-finalized-rejected",
            "terminal-outer-signature-cannot-upgrade-missing-proof",
        ):
            with self.subTest(name=name):
                self.assertEqual(evaluate(self.data, self.cases[name])[0], "fail")

    def test_new_authority_helpers_are_total_on_malformed_shapes(self):
        probes = [
            ("commit", ["verifierContext", "identityAdmissionAuthority", "records"]),
            ("commit", ["verifierContext", "railRegistry", "resolutions"]),
            ("terminal", ["verifierContext", "terminalAuthority", "settlements"]),
            ("terminal", ["verifierContext", "terminalAuthority", "agreement", "receipt"]),
            ("terminal", ["verifierContext", "terminalAuthority", "bundle", "receipt"]),
        ]
        for stage, path in probes:
            for malformed in (None, 7, [], {}):
                with self.subTest(stage=stage, path=path, malformed=malformed):
                    context = materialize(self.data, {
                        "scenario": "identityBoundAgreement",
                        "commitment": "finality",
                        "stage": stage,
                    })
                    apply_mutation(context, {
                        "op": "set", "path": path, "value": malformed,
                    })
                    verdict, reason, artifact, phase = dispatch(context)
                    self.assertEqual(verdict, "pass")
                    if stage == "commit":
                        verdict, _, _, _ = pre_action_gate(
                            context, artifact, stage, set()
                        )
                    else:
                        verdict, _ = validate_terminal(
                            context, artifact, phase, set()
                        )
                    self.assertNotEqual(verdict, "pass")

        context = materialize(self.data, {
            "scenario": "identityBoundAgreement",
            "commitment": "finality",
            "stage": "terminal",
        })
        authority = terminal_reputation_authority(
            context, "identityBoundAgreement"
        )
        for malformed in (7, [], {}):
            with self.subTest(additional_commit_phase=malformed):
                malformed_authority = copy.deepcopy(authority)
                malformed_authority["additionalCommitPhase"] = malformed
                self.assertFalse(
                    reputation_reference._tagged_copy_valid_for_derive({
                        "bundle": context["terminalInput"]["bundle"],
                        "ebfabAuthority": malformed_authority,
                    })
                )

    def test_historical_session_hash_must_match_signed_agreement_hash(self):
        for artifact in ("agreement", "payeeBoundAgreement"):
            context = materialize(self.data, {
                "scenario": artifact, "commitment": "legacy", "stage": "commit",
            })
            for role in ("buyer", "seller"):
                with self.subTest(artifact=artifact, role=role):
                    changed = copy.deepcopy(context)
                    for surface in (
                        changed["commitInput"]["sessionContext"],
                        changed["verifierContext"]["authenticatedSessionContext"],
                    ):
                        for party in surface["parties"]:
                            if party["role"] == role:
                                party["bundleHash"] = "0" * 64
                    self.assertEqual(
                        validate_historical_stage(
                            changed, artifact, "commit", set()
                        )[0],
                        "fail",
                    )

    def test_terminal_payment_observation_binds_actual_parties_and_amount(self):
        context = materialize(self.data, {
            "scenario": "identityBoundPayeeAgreement",
            "commitment": "finality",
            "stage": "terminal",
        })
        verdict, _, artifact, phase = dispatch(context)
        self.assertEqual(verdict, "pass")
        self.assertEqual(
            validate_terminal(context, artifact, phase, set())[0], "pass"
        )
        for field, value in (
            ("payer", "key:" + "12" * 32),
            ("payee", "key:" + "34" * 32),
            ("paymentAmount", {"amount": "2", "currency": "DEM"}),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(context)
                execution = changed["verifierContext"]["terminalAuthority"][
                    "settlements"
                ][0]["executionAuthority"]
                event = execution["settlementObservation"]["event"]
                event[field] = value
                execution["settlementObservation"] = (
                    generator.fixture_settlement_observation(event)
                )
                self.assertEqual(
                    validate_terminal(changed, artifact, phase, set())[0],
                    "fail",
                )

        changed = materialize(self.data, {
            "scenario": "identityBoundAgreement",
            "commitment": "finality",
            "stage": "terminal",
        })
        runtime_destination = "demos:runtime-payee-destination"
        changed["paymentInput"]["payer"]["payingKey"] = (
            generator.SECONDARY_PAYER_CLAIM
        )
        changed["paymentInput"]["payee"]["payeeAddress"] = runtime_destination
        execution = changed["verifierContext"]["terminalAuthority"][
            "settlements"
        ][0]["executionAuthority"]
        event = execution["settlementObservation"]["event"]
        event["payer"] = generator.SECONDARY_PAYER_CLAIM
        event["payee"] = runtime_destination
        execution["settlementObservation"] = (
            generator.fixture_settlement_observation(event)
        )
        self.assertEqual(
            validate_terminal(
                changed, "identityBoundAgreement",
                generator.PHASES["identityBoundAgreement"], set()
            )[0],
            "pass",
        )

        for field, value in (
            ("payer", "key:" + "12" * 32),
            ("payee", "key:" + "34" * 32),
            ("paymentAmount", {"amount": "2", "currency": "DEM"}),
        ):
            with self.subTest(field=field, matching_input_tamper=True):
                changed = copy.deepcopy(context)
                execution = changed["verifierContext"]["terminalAuthority"][
                    "settlements"
                ][0]["executionAuthority"]
                event = execution["settlementObservation"]["event"]
                event[field] = value
                if field == "payer":
                    changed["paymentInput"]["payer"]["payingKey"] = value
                elif field == "payee":
                    changed["paymentInput"]["payee"]["payeeAddress"] = value
                else:
                    changed["paymentInput"]["amount"] = value
                execution["settlementObservation"] = (
                    generator.fixture_settlement_observation(event)
                )
                self.assertEqual(
                    validate_terminal(changed, artifact, phase, set())[0],
                    "fail",
                )

    def test_reputation_counting_executes_only_after_identity_admission(self):
        for artifact in generator.STRONG_ARTIFACTS:
            context = materialize(self.data, {
                "scenario": artifact, "commitment": "finality", "stage": "terminal",
            })
            tag = {
                "bundle": context["terminalInput"]["bundle"],
                "resolvedRole": "buyer", "counterpartyDisposition": "absent",
            }
            arguments = (
                generator.CLAIMS["buyer"], tag,
                generator.NOW - 100_000, generator.NOW + 100_000,
            )
            with mock.patch.object(
                reputation_reference,
                "derive_job_bound",
                wraps=reputation_reference.derive_job_bound,
            ) as derive:
                verdict, _, receipt = derive_identity_bound_reputation(
                    context, set(), *arguments
                )
                self.assertEqual(verdict, "pass")
                self.assertEqual(receipt["bundleCount"], 1)
                derive.assert_called_once()
            missing = {f"identity:{generator.CLAIMS['buyer']}"}
            with mock.patch.object(
                reputation_reference, "derive_job_bound"
            ) as derive:
                verdict, _, receipt = derive_identity_bound_reputation(
                    context, missing, *arguments
                )
                self.assertEqual(verdict, "indeterminate")
                self.assertIsNone(receipt)
                derive.assert_not_called()
            invalid = copy.deepcopy(context)
            invalid["terminalInput"]["identityBindingCompanions"][0]["identityBundle"]["presentedAt"] += 1
            with mock.patch.object(
                reputation_reference, "derive_job_bound"
            ) as derive:
                verdict, _, receipt = derive_identity_bound_reputation(
                    invalid, set(), *arguments
                )
                self.assertNotEqual(verdict, "pass")
                self.assertIsNone(receipt)
                derive.assert_not_called()

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

    def test_listing_phase_sets_are_closed_and_versioned(self):
        self.assertEqual(
            generator.CURRENT_SUPPORTED_PHASES - generator.BASE_SUPPORTED_PHASES,
            {
                "commit-identity-bound-agreement",
                "commit-identity-bound-payee-agreement",
            },
        )
        for stage in ("commit", "payment", "terminal"):
            case = self.cases[f"signed-listing-unknown-phase-refused-at-{stage}"]
            self.assertEqual(evaluate(self.data, case)[0], "fail")

    def test_references_use_signature_omitted_artifact_hashes(self):
        scenario = self.data["scenarios"]["identityBoundAgreement"]
        agreement = scenario["agreement"]
        agreement_ref = scenario["terminalInput"]["bundle"]["agreementRef"]
        self.assertEqual(
            agreement_ref["contentHash"],
            generator.artifact_hash(agreement, "signatures"),
        )
        self.assertNotEqual(agreement_ref["contentHash"], generator.hash_hex(agreement))
        for party, companion in zip(
            agreement["parties"], scenario["commitInput"]["identityBindingCompanions"]
        ):
            record = companion["compositeRecord"]
            self.assertEqual(
                party["vetRecordRef"]["contentHash"],
                generator.artifact_hash(record, "signature"),
            )
            self.assertNotEqual(
                party["vetRecordRef"]["contentHash"], generator.hash_hex(record)
            )
            self.assertEqual(
                record["requirementHash"],
                generator.hash_hex(scenario["listing"]["buyerRequirement"]),
            )
        for wrapped in scenario["commitments"].values():
            self.assertEqual(
                wrapped["anchorReceipt"]["contentHash"],
                generator.commitment_record_hash(wrapped["record"]),
            )
        replacement = self.data["scenarios"]["identityBoundPayeeReplacement"]
        disposition = replacement["priorPaymentDisposition"]["artifact"]
        self.assertEqual(
            replacement["agreement"]["terms"]["priorPaymentDispositionRef"]["contentHash"],
            generator.artifact_hash(disposition, "signature"),
        )
        prior = replacement["priorAgreement"]
        self.assertEqual(
            disposition["priorAgreementRef"]["contentHash"],
            generator.artifact_hash(prior, "signatures"),
        )

    def test_cvr_requirement_and_aggregate_are_replayed(self):
        for name, expected in (
            ("identityBoundAgreement-commit-verified", "pass"),
            ("identityBoundAgreement-terminal-verified", "pass"),
            ("signed-listing-requirement-does-not-match-cvr", "fail"),
            ("signed-cvr-overall-decision-disagrees-with-replay", "fail"),
        ):
            with self.subTest(name=name):
                self.assertEqual(evaluate(self.data, self.cases[name])[0], expected)

    def test_sealed_envelope_losing_bidder_compatibility(self):
        historical = self.data["scenarios"]["historicalSealed"]["agreement"]
        self.assertEqual(
            [party["role"] for party in historical["parties"]],
            ["buyer", "seller", "bidder-non-winning"],
        )
        self.assertEqual(len(historical["signatures"]), 2)
        for commitment in ("legacy", "finality"):
            self.assertEqual(
                evaluate(
                    self.data,
                    self.cases[f"historical-sealed-envelope-losing-bidder-{commitment}"],
                )[0],
                "pass",
            )
        self.assertEqual(
            evaluate(
                self.data,
                self.cases[
                    "modeled-old-reader-historical-sealed-envelope-losing-bidder"
                ],
            )[0],
            "pass",
        )
        for stage in ("commit", "payment", "terminal"):
            self.assertEqual(
                evaluate(
                    self.data,
                    self.cases[f"identity-bound-sealed-envelope-losing-bidder-{stage}"],
                )[0],
                "pass",
            )

    def test_fixture_receipt_authority_is_independent_and_tamper_checked(self):
        evidence = self.data["provenance"]["receiptAuthorityEvidence"]
        self.assertEqual(evidence["scope"], "deterministic offline conformance fixture only")
        self.assertIs(evidence["liveSubstrateProof"], False)
        self.assertNotEqual(evidence["observer"], evidence["commitmentProducer"])
        self.assertIn("prior-payment-disposition", evidence["coveredDependencies"])
        self.assertIn("evidence-bound-fault-bundle", evidence["coveredDependencies"])
        names = {
            "commitment-receipt-producer-cannot-self-attest-finality",
            "commitment-receipt-native-content-tamper",
            "commitment-receipt-native-transaction-tamper",
            "commitment-receipt-native-location-tamper",
            "commitment-receipt-native-ordering-tamper",
            "commitment-receipt-native-block-tamper",
            "commitment-receipt-native-finality-tamper",
        }
        for name in names:
            with self.subTest(name=name):
                self.assertEqual(evaluate(self.data, self.cases[name])[0], "fail")

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
                        "authenticatedOrchestrator": generator.CLAIMS["orchestrator"],
                        "authenticatedReceiptAuthority": generator.RECEIPT_AUTHORITY_CLAIM,
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
            evidence["historicalStageAdapter"]["payment"],
            "not-completely-modeled-non-authorizing-indeterminate",
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
        self.assertIn("distinct verifier-issued", core)
        self.assertIn("Retained-authority limitation", core)
        self.assertIn("ordinary common gate independently of IBH", settle)
        self.assertIn("Historical agreement and terminal controls", verify)


if __name__ == "__main__":
    unittest.main()
