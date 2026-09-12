import base64
import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import jcs  # noqa: E402
import dacs5_reference as R  # noqa: E402
import generate_phase_bound_delivery_vectors as G  # noqa: E402
from validate_artifact_shapes import parse_type_fields, check_attestation_ref  # noqa: E402

VECTORS = ROOT / "conformance" / "vectors" / "security" / "phase-bound-delivery-evidence-v0.7.json"
GENERATOR = ROOT / "scripts" / "generate_phase_bound_delivery_vectors.py"
DELIVERY_DOMAIN = "dacs-delivery-evidence:v1:"
LEGACY_DOMAIN = "dacs-evidence:v1:"
ENTITLEMENT_DOMAIN = "dacs-entitlement:v1:"
PAYLOAD_DOMAIN = "dacs-payload-attestation:v1:"
BUNDLE_DOMAIN = "dacs-fault-bundle:v1:"
DELIVERY_KINDS = {"deliver-storage-program", "deliver-entitlement", "deliver-attested-payload"}
DELIVERY_REQUIRED_FIELDS = {
    "deliveryEvidenceVersion", "jobId", "phaseIndex", "phase", "outcome",
    "observedAt", "signature",
}
DELIVERY_OPTIONAL_FIELDS = {
    "reason", "deliverableContentHash", "deliverableAnchor", "attestationRef",
    "credentialDelivery",
}
PAYLOAD_ATTESTATION_REQUIRED_FIELDS = {
    "payloadAttestationVersion", "jobId", "agreementHash", "deliverableSpecHash",
    "payloadFormat", "payloadContentHash", "verificationMethod",
    "verificationMethodHash", "attempt", "decision", "reason", "verifiedAt",
    "signature",
}
PAYLOAD_ATTESTATION_OPTIONAL_FIELDS = {"methodEvidenceRef", "methodTransactionRef"}


def canonical_bytes(value):
    return jcs.canonicalize(value).encode("utf-8")


def hash_hex(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def artifact_hash(artifact):
    return hash_hex({k: v for k, v in artifact.items() if k != "signature"})


def artifact_ref(address, artifact):
    return {
        "anchor": {"kind": "storage-program", "locator": address},
        "contentHash": artifact_hash(artifact),
        "signer": artifact["signature"]["signer"],
    }


def verify_signature(artifact, domain):
    signature = artifact.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519":
        return False
    signer = signature.get("signer")
    if not isinstance(signer, str) or not signer.startswith("cci:"):
        return False
    value = signature.get("value")
    if not isinstance(value, str) or "=" in value:
        return False
    try:
        public = bytes.fromhex(signer.removeprefix("cci:"))
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        payload = domain.encode("ascii") + artifact_hash(artifact).encode("ascii")
        Ed25519PublicKey.from_public_bytes(public).verify(raw, payload)
    except (ValueError, InvalidSignature):
        return False
    return True


def authenticated_evidence_type(artifact):
    """Authenticate the evidence family from its domain before selector parsing."""
    signature = artifact.get("signature") if isinstance(artifact, dict) else None
    signer = signature.get("signer") if isinstance(signature, dict) else None
    if not isinstance(signer, str) or not signer.startswith("cci:"):
        return None
    try:
        pubkeys = {signer: bytes.fromhex(signer.removeprefix("cci:"))}
    except ValueError:
        return None
    return R._authenticated_evidence_wire_type(artifact, pubkeys)


def verify_bundle_signatures(bundle):
    if not isinstance(bundle, dict):
        return False
    if bundle.get("faultBundleVersion") != "1" or "bundleVersion" in bundle:
        return False
    parties = bundle.get("parties")
    signatures = bundle.get("signatures")
    if (
        not isinstance(parties, list)
        or any(
            not isinstance(party, dict)
            or not isinstance(party.get("role"), str)
            or not isinstance(party.get("primaryClaim"), str)
            for party in parties
        )
        or not isinstance(signatures, list)
        or any(not isinstance(signature, dict) for signature in signatures)
    ):
        return False
    unsigned = {k: v for k, v in bundle.items() if k not in {"signatures", "anchoredByRole"}}
    try:
        payload = BUNDLE_DOMAIN.encode("ascii") + hash_hex(unsigned).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        return False
    required = {party.get("primaryClaim") for party in parties}
    observed = set()
    for signature in signatures:
        party = signature.get("party")
        value = signature.get("value")
        if signature.get("algorithm") != "ed25519" or not isinstance(party, str) or not party.startswith("cci:"):
            return False
        try:
            raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(party.removeprefix("cci:"))).verify(raw, payload)
        except (TypeError, ValueError, InvalidSignature):
            return False
        observed.add(party)
    return observed == required


def exact_ref_shape(value):
    errors = []
    check_attestation_ref(value, "vector", errors, "ref")
    return not errors


def find_artifact(case, address, kind=None):
    records = case.get("artifactRecords")
    if records is None:
        return None
    if not isinstance(records, list):
        return []  # Malformed collection sentinel for the shared availability gate.
    if any(not isinstance(entry, dict) for entry in records):
        return []
    found = [entry for entry in records
             if entry.get("logicalAddress") == address and (kind is None or entry.get("kind") == kind)]
    if len(found) != 1:
        return None
    return found[0]


def resolve_evidence(case, supplied_ref):
    if not exact_ref_shape(supplied_ref):
        return "error", None, None
    address = supplied_ref["anchor"]["locator"]
    candidates = [(i, entry) for i, entry in enumerate(case["evidenceRecords"])
                  if entry.get("logicalAddress") == address]
    if len(candidates) != 1:
        return "indeterminate", None, None
    position, entry = candidates[0]
    artifact = entry.get("artifact")
    if not isinstance(artifact, dict):
        return "error", None, None
    if supplied_ref != artifact_ref(address, artifact):
        return "fail", None, None
    return "pass", position, entry


def authenticated_delivery_roles(bundle):
    """Resolve the unique buyer and seller from the already-authenticated bundle."""
    return R.authenticated_delivery_roles(bundle)


def delivery_authority(case, phase_index):
    authorities = case.get("deliveryAuthorities")
    if authorities is None:
        return "indeterminate", None
    if not isinstance(authorities, list) or any(
        not isinstance(item, dict) for item in authorities
    ):
        return "error", None
    matches = [
        item for item in authorities if item.get("phaseIndex") == phase_index
    ]
    if len(matches) != 1:
        return "indeterminate", None
    return "pass", matches[0]


def storage_access_model(case, phase_index):
    status, authority = delivery_authority(case, phase_index)
    if status != "pass":
        return status, None
    deliverable = authority.get("deliverable")
    if not isinstance(deliverable, dict):
        return "error", None
    if deliverable.get("kind") != "storage-program":
        return "fail", None
    access_model = deliverable.get("accessModel", "public")
    if not R._string_member(access_model, {"public", "buyer-only", "encrypt-to-buyer"}):
        return "error", None
    return "pass", access_model


def validate_delivered_cleartext(
    stored, expected_hash, access_model, subject, storage_binding, buyer
):
    return R._validate_resolved_storage(
        stored,
        expected_hash,
        access_model,
        subject,
        authenticated_storage_binding=storage_binding,
        buyer=buyer,
    )[0]


def validate_entitlement_roles(bundle, record):
    role_status, claims_by_role = authenticated_delivery_roles(bundle)
    if role_status != "pass":
        return role_status
    signature = record.get("signature")
    if (
        record.get("grantee") != claims_by_role["buyer"]
        or record.get("grantor") != claims_by_role["seller"]
        or not isinstance(signature, dict)
        or signature.get("signer") != record.get("grantor")
    ):
        return "fail"
    return "pass"


def validate_delivery_artifact(
    case, evidence, *, associated_phase_index=None, legacy=False
):
    job = evidence["jobId"]
    index = associated_phase_index if legacy else evidence["phaseIndex"]
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        return "error"
    phase = evidence["phase"]
    content_hash = evidence.get("deliverableContentHash")
    anchor = evidence.get("deliverableAnchor")
    outcome = evidence.get("outcome")
    role_status, parties = authenticated_delivery_roles(case.get("bundle"))
    if role_status != "pass":
        return role_status
    completed = case.get("bundle", {}).get("outcome") == "completed"
    receipts = case.get("verifiedReceiptByCanonicalRef")
    if outcome not in {"success", "failure"}:
        return "error"
    if outcome == "success":
        if not isinstance(content_hash, str) or not isinstance(anchor, dict):
            return "fail"
    elif content_hash is None and anchor is None:
        return "pass"
    if not isinstance(anchor, dict) or set(anchor) != {"kind", "locator"}:
        return "error"
    address = anchor.get("locator")

    if phase == "deliver-storage-program":
        expected_address = (
            f"dacs4:deliverable:{job}"
            if legacy else f"dacs4:deliverable:{job}:{index}"
        )
        if address != expected_address:
            return "fail"
        stored = find_artifact(case, address, "deliverable")
        dependency, stored, receipt = R._resolved_delivery_dependency(
            stored,
            {"anchor": anchor, "contentHash": content_hash},
            receipts,
            completed,
            "storage deliverable",
            job_id=job,
            phase_index=index,
            phase_kind=phase,
            expected_writer=parties["seller"],
        )
        if dependency[0] != "pass":
            return dependency[0]
        access_status, access_model = storage_access_model(case, index)
        if access_status != "pass":
            return access_status
        storage_status = validate_delivered_cleartext(
            stored,
            content_hash,
            access_model,
            "storage deliverable",
            receipt.get("storageBinding"),
            parties["buyer"],
        )
        if storage_status != "pass":
            return storage_status
        if "attestationRef" in evidence or "credentialDelivery" in evidence:
            return "fail"
        return "pass"

    if phase == "deliver-entitlement":
        prefix = (
            f"dacs4:entitlement:{job}:"
            if legacy else f"dacs4:entitlement:{job}:{index}:"
        )
        if not isinstance(address, str) or not address.startswith(prefix):
            return "fail"
        record_entry = find_artifact(case, address, "EntitlementRecord")
        if record_entry is None:
            artifact_records = case.get("artifactRecords")
            if artifact_records is None:
                return "indeterminate"
            phase_records = [entry for entry in artifact_records
                             if entry.get("kind") == "EntitlementRecord"
                             and str(entry.get("logicalAddress", "")).startswith(prefix)]
            return "fail" if phase_records else "indeterminate"
        dependency, record_entry, _ = R._resolved_delivery_dependency(
            record_entry,
            {"anchor": anchor, "contentHash": content_hash},
            receipts,
            completed,
            "entitlement record",
            job_id=job,
            phase_index=index,
            phase_kind=phase,
            expected_writer=parties["seller"],
        )
        if dependency[0] != "pass":
            return dependency[0]
        record = record_entry.get("artifact")
        if (not isinstance(record, dict)
                or not R._delivery_inner_type_valid(record, "entitlementVersion")
                or not verify_signature(record, ENTITLEMENT_DOMAIN)):
            return "fail"
        role_status = validate_entitlement_roles(case.get("bundle"), record)
        if role_status != "pass":
            return role_status
        renewal = record.get("renewalSeq")
        if isinstance(renewal, bool) or not isinstance(renewal, int) or renewal < 0:
            return "error"
        expected_address = (
            f"dacs4:entitlement:{job}:{renewal}"
            if legacy else f"dacs4:entitlement:{job}:{index}:{renewal}"
        )
        if address != expected_address:
            return "fail"
        if record.get("jobId") != job or content_hash != artifact_hash(record):
            return "fail"
        if "attestationRef" in evidence:
            return "fail"
        authority_status, authority = delivery_authority(case, index)
        if authority_status != "pass":
            return authority_status
        deliverable_spec = authority.get("deliverable")
        duration = (
            deliverable_spec.get("durationSec")
            if isinstance(deliverable_spec, dict) else None
        )
        if (
            not isinstance(deliverable_spec, dict)
            or deliverable_spec.get("kind") != "entitlement"
            or not R._non_boolean_number(duration)
            or not isinstance(deliverable_spec.get("renewable"), bool)
        ):
            return "error"
        if (
            not R._non_boolean_number(record.get("startsAt"))
            or not R._non_boolean_number(record.get("endsAt"))
        ):
            return "error"
        if (
            record["endsAt"] != record["startsAt"] + duration * 1000
            or record.get("renewable") != deliverable_spec["renewable"]
        ):
            return "fail"
        binding = evidence.get("credentialDelivery")
        credential_ref = record.get("credentialRef")
        if legacy:
            # A frozen SettlementEvidence has no signed PDE-5 binding. Resolving
            # credential bytes cannot promote this audit record to DV-5-verified.
            if credential_ref is not None and (
                not isinstance(credential_ref, dict)
                or set(credential_ref) != {"ref", "accessModel"}
                or not exact_ref_shape(credential_ref.get("ref"))
                or credential_ref.get("accessModel")
                not in {"buyer-only", "encrypt-to-buyer"}
            ):
                return "error"
            return "fail" if case.get("requestedGate") == "dv5-verified" else "pass"
        if credential_ref is None:
            return "fail" if binding is not None else "pass"
        if binding is None:
            return "fail"
        if not isinstance(binding, dict):
            return "error"
        permitted = {"credentialRef", "credentialCleartextHash", "renewalSeq"}
        if set(binding) != permitted:
            return "error"
        if binding.get("credentialRef") != credential_ref:
            return "fail"
        if binding.get("renewalSeq") != renewal:
            return "fail"
        ref_value = credential_ref.get("ref") if isinstance(credential_ref, dict) else None
        if not exact_ref_shape(ref_value):
            return "error"
        credentials = case.get("credentials")
        if credentials is None:
            return "indeterminate"
        if not isinstance(credentials, list) or any(
            not isinstance(item, dict) for item in credentials
        ):
            return "error"
        matches = [item for item in credentials
                   if item.get("credentialRef") == credential_ref]
        if not matches and len(credentials) == 1:
            # A sole supplied candidate can be classified directly. Do not guess
            # among multiple unrelated records when the keyed lookup is unresolved.
            matches = credentials
        if len(matches) != 1:
            return "indeterminate"
        credential = matches[0]
        availability, credential, credential_receipt = R._resolved_delivery_dependency(
            credential,
            ref_value,
            receipts,
            completed,
            "entitlement credential",
            job_id=job,
            phase_index=index,
            phase_kind=phase,
            expected_writer=ref_value.get("signer", parties["seller"]),
        )
        if availability[0] != "pass":
            return availability[0]
        return R._validate_resolved_credential(
            credential,
            binding,
            credential_ref,
            authenticated_storage_binding=credential_receipt.get("storageBinding"),
            buyer=parties["buyer"],
        )[0]

    if phase == "deliver-attested-payload":
        payload_address = (
            f"dacs4:deliverable:{job}"
            if legacy else f"dacs4:deliverable:{job}:{index}"
        )
        if address != payload_address:
            return "fail"
        payload = find_artifact(case, payload_address, "deliverable")
        payload_availability, payload, _ = R._resolved_delivery_dependency(
            payload,
            {"anchor": anchor, "contentHash": content_hash},
            receipts,
            completed,
            "attested payload",
            job_id=job,
            phase_index=index,
            phase_kind=phase,
            expected_writer=parties["seller"],
        )
        if payload_availability[0] == "error":
            return "error"
        payload_unavailable = payload_availability[0] == "indeterminate"
        if payload is not None and "storedHash" in payload:
            return "error"
        if payload is not None and content_hash != payload.get("cleartextHash"):
            return "fail"
        supplied = evidence.get("attestationRef")
        if not exact_ref_shape(supplied):
            return "error"
        record_address = supplied["anchor"]["locator"]
        record_entry = find_artifact(case, record_address, "PayloadAttestationRecord")
        if record_entry is None:
            artifact_records = case.get("artifactRecords")
            if artifact_records is None:
                return "indeterminate"
            same_record_elsewhere = any(
                entry.get("kind") == "PayloadAttestationRecord"
                and isinstance(entry.get("artifact"), dict)
                and artifact_hash(entry["artifact"]) == supplied.get("contentHash")
                for entry in artifact_records
            )
            return "fail" if same_record_elsewhere else "indeterminate"
        availability, record_entry, _ = R._resolved_delivery_dependency(
            record_entry,
            supplied,
            receipts,
            completed,
            "payload attestation record",
            job_id=job,
            phase_index=index,
            phase_kind=phase,
            expected_writer=(record_entry.get("artifact", {}).get("signature", {}).get("signer")
                             if isinstance(record_entry.get("artifact"), dict)
                             and isinstance(record_entry["artifact"].get("signature"), dict)
                             else None),
        )
        if availability[0] != "pass":
            return availability[0]
        record = record_entry["artifact"]
        expected_ref = artifact_ref(record_address, record)
        if "signer" not in supplied:
            expected_ref.pop("signer", None)
        if supplied != expected_ref:
            return "fail"
        present = set(record)
        if (
            not PAYLOAD_ATTESTATION_REQUIRED_FIELDS <= present
            or not R._delivery_inner_type_valid(record, "payloadAttestationVersion")
            or not verify_signature(record, PAYLOAD_DOMAIN)
        ):
            return "fail"
        method_hash, attempt = record.get("verificationMethodHash"), record.get("attempt")
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 0:
            return "error"
        expected_record_address = (
            f"dacs4:payload-attestation:{job}:{method_hash}:{attempt}"
            if legacy
            else f"dacs4:payload-attestation:{job}:{index}:{method_hash}:{attempt}"
        )
        if record_address != expected_record_address:
            return "fail"
        if (record.get("jobId") != job or record.get("payloadContentHash") != content_hash
                or record.get("decision") != "pass"):
            return "fail"
        authority_status, authority = delivery_authority(case, index)
        if authority_status != "pass":
            return authority_status
        deliverable = authority.get("deliverable")
        agreement = authority.get("agreement")
        method = deliverable.get("verificationMethod") if isinstance(deliverable, dict) else None
        if (
            not isinstance(deliverable, dict)
            or deliverable.get("kind") != "attested-payload"
            or not isinstance(method, dict)
            or method.get("kind") not in {"consensus-backed-proxy", "self-signed"}
            or not isinstance(agreement, dict)
            or agreement.get("jobId") != job
            or agreement.get("agreementHash") != record.get("agreementHash")
            or agreement.get("deliverable", {}).get("deliverableType") != "attested-payload"
            or agreement.get("deliverable", {}).get("hash") != hash_hex(deliverable)
            or record.get("deliverableSpecHash") != hash_hex(deliverable)
            or record.get("payloadFormat") != deliverable.get("payloadFormat")
            or record.get("verificationMethod") != method.get("kind")
            or record.get("verificationMethodHash") != hash_hex(method)
        ):
            return "fail"
        locator_disposition, _ = R.validate_payload_attestation_locator_context(
            record,
            supplied,
            {"jobId": job, "phaseIndex": index, "phaseKind": phase},
            method,
            legacy=legacy,
        )
        if locator_disposition != "pass":
            return locator_disposition
        if payload_unavailable:
            return "indeterminate"
        cleartext = payload.get("cleartextUtf8")
        cleartext_disposition, cleartext_bytes = R._resolved_exact_bytes(
            payload, "attested payload cleartext"
        )
        if cleartext_disposition[0] != "pass":
            return cleartext_disposition[0]
        if hashlib.sha256(cleartext_bytes).hexdigest() != content_hash:
            return "fail"
        method_ref = record.get("methodEvidenceRef")
        if not exact_ref_shape(method_ref):
            return "error"
        method_entry = find_artifact(
            case, method_ref["anchor"]["locator"], "methodEvidence"
        )
        availability, method_entry, _ = R._resolved_delivery_dependency(
            method_entry,
            method_ref,
            receipts,
            completed,
            "method evidence",
            job_id=job,
            phase_index=index,
            phase_kind=phase,
            expected_writer=method_ref.get("signer"),
        )
        if availability[0] != "pass":
            return availability[0]
        method_evidence = method_entry.get("artifact")
        if (
            not isinstance(method_evidence, dict)
            or method_ref.get("contentHash") != hash_hex(method_evidence)
        ):
            return "fail"
        method_disposition, _ = R.validate_delivery_method_evidence(
            method,
            method_evidence,
            record.get("methodTransactionRef"),
            case.get("trustedNativeTransactionObservationsByCanonicalRef"),
            delivered_cleartext=cleartext,
            delivered_bytes=cleartext_bytes,
            payload_content_hash=content_hash,
            require_finalized=case.get("bundle", {}).get("outcome") == "completed",
        )
        if method_disposition != "pass":
            return method_disposition
        if "credentialDelivery" in evidence:
            return "fail"
        return "pass"
    return "error"


def exact_delivery_evidence_shape(evidence):
    if not isinstance(evidence, dict):
        return False
    present = set(evidence)
    signature = evidence.get("signature")
    index = evidence.get("phaseIndex")
    observed_at = evidence.get("observedAt")
    return (
        DELIVERY_REQUIRED_FIELDS <= present
        and not present - DELIVERY_REQUIRED_FIELDS - DELIVERY_OPTIONAL_FIELDS
        and evidence.get("deliveryEvidenceVersion") == "1"
        and "evidenceVersion" not in evidence
        and isinstance(evidence.get("jobId"), str)
        and bool(evidence["jobId"])
        and isinstance(index, int)
        and not isinstance(index, bool)
        and index >= 0
        and evidence.get("phase") in DELIVERY_KINDS
        and evidence.get("outcome") in {"success", "failure"}
        and isinstance(observed_at, (int, float))
        and not isinstance(observed_at, bool)
        and isinstance(signature, dict)
        and set(signature) == {"algorithm", "signer", "value"}
    )


def evaluate(case):
    if not isinstance(case, dict):
        return "error"
    pipeline = case.get("pipeline")
    bundle = case.get("bundle")
    evidence_records = case.get("evidenceRecords")
    if (
        not isinstance(pipeline, list)
        or any(not isinstance(step, dict) for step in pipeline)
        or not isinstance(bundle, dict)
        or not isinstance(evidence_records, list)
        or any(not isinstance(entry, dict) for entry in evidence_records)
    ):
        return "error"
    if any(
        not isinstance(step.get("kind"), str)
        or isinstance(step.get("index"), bool)
        or not isinstance(step.get("index"), int)
        or step.get("index") < 0
        for step in pipeline
    ):
        return "error"
    parties = bundle.get("parties")
    signatures = bundle.get("signatures")
    if (
        not isinstance(parties, list)
        or any(
            not isinstance(party, dict)
            or not isinstance(party.get("role"), str)
            or not isinstance(party.get("primaryClaim"), str)
            for party in parties
        )
        or not isinstance(signatures, list)
        or any(not isinstance(signature, dict) for signature in signatures)
        or any(not isinstance(entry.get("artifact"), dict) for entry in evidence_records)
    ):
        return "error"
    if case.get("consumerVersion") == "pre-0.7":
        return "error" if any(
            "deliveryEvidenceVersion" in entry.get("artifact", {})
            for entry in evidence_records
            if isinstance(entry.get("artifact"), dict)
        ) else "pass"
    for optional_collection in ("artifactRecords", "credentials", "deliveryAuthorities"):
        value = case.get(optional_collection)
        if value is not None and (
            not isinstance(value, list)
            or any(not isinstance(entry, dict) for entry in value)
        ):
            return "error"
    if not verify_bundle_signatures(bundle):
        return "fail"
    delivery_steps = [step for step in pipeline if step.get("kind") in DELIVERY_KINDS]
    pipeline_delivery_pairs = {
        (step.get("index"), step.get("kind")) for step in delivery_steps
    }
    if len(pipeline_delivery_pairs) != len(delivery_steps):
        return "error"
    summaries = bundle.get("phaseSummary")
    if not isinstance(summaries, list) or any(
        not isinstance(summary, dict) for summary in summaries
    ):
        return "error"
    if any(
        not isinstance(summary.get("kind"), str)
        or isinstance(summary.get("index"), bool)
        or not isinstance(summary.get("index"), int)
        or summary.get("index") < 0
        for summary in summaries
    ):
        return "error"
    delivery_summaries = [s for s in summaries if s.get("kind") in DELIVERY_KINDS]
    summary_pairs = {(s.get("index"), s.get("kind")) for s in delivery_summaries}
    summary_by_pair = {
        (summary.get("index"), summary.get("kind")): summary
        for summary in delivery_summaries
    }
    if (
        len(summary_pairs) != len(delivery_summaries)
        or not summary_pairs.issubset(pipeline_delivery_pairs)
    ):
        return "fail"
    expected = (
        pipeline_delivery_pairs
        if bundle.get("outcome") == "completed"
        else summary_pairs
    )
    refs = bundle.get("settlementEvidence")
    if not isinstance(refs, list):
        return "error"

    mapped = []
    used_entries = set()
    ref_for_mapping = {}
    for supplied_ref in refs:
        status, position, entry = resolve_evidence(case, supplied_ref)
        if status != "pass":
            return status
        if position in used_entries:
            return "fail"
        used_entries.add(position)
        artifact = entry["artifact"]
        evidence_type = authenticated_evidence_type(artifact)
        if evidence_type is None:
            selectors = {
                selector for selector in (
                    "evidenceVersion", "deliveryEvidenceVersion"
                ) if selector in artifact
            }
            # Authentication still precedes family parsing.  An exclusive signed
            # candidate that authenticates under no supported family is a clean
            # integrity failure; an ambiguous selector set is malformed input.
            return "error" if len(selectors) != 1 else "fail"
        if evidence_type == "delivery":
            if not exact_delivery_evidence_shape(artifact):
                return "error"
            index, kind = artifact.get("phaseIndex"), artifact.get("phase")
            if isinstance(index, bool) or not isinstance(index, int) or index < 0:
                return "error"
            if artifact.get("jobId") != bundle.get("jobId"):
                return "fail"
            execution_authority = case.get("executionAuthority")
            if execution_authority is None:
                return "indeterminate"
            if not isinstance(execution_authority, dict):
                return "error"
            authority = execution_authority.get("phaseOrchestrator")
            if authority is None:
                return "indeterminate"
            if not isinstance(authority, str):
                return "error"
            if (artifact.get("signature", {}).get("signer") != authority
                    or entry.get("receiptWriter") != authority):
                return "fail"
            if entry["logicalAddress"] != f"dacs4:delivery:{artifact['jobId']}:{index}":
                return "fail"
            if (index, kind) not in expected:
                return "fail"
            if not verify_signature(artifact, DELIVERY_DOMAIN):
                return "fail"
            status = validate_delivery_artifact(case, artifact)
            if status != "pass":
                return status
            mapping = (index, kind)
        elif evidence_type == "settlement":
            kind = artifact.get("phase")
            if kind not in DELIVERY_KINDS:
                if not verify_signature(artifact, LEGACY_DOMAIN):
                    return "fail"
                continue
            candidates = [pair for pair in expected if pair[1] == kind]
            if len(candidates) != 1:
                return "fail"
            if not R._settlement_evidence_shape_valid(artifact):
                return "error"
            execution_authority = case.get("executionAuthority")
            if execution_authority is None:
                return "indeterminate"
            if not isinstance(execution_authority, dict):
                return "error"
            authority = execution_authority.get("phaseOrchestrator")
            if authority is None:
                return "indeterminate"
            if not isinstance(authority, str):
                return "error"
            if (
                artifact.get("jobId") != bundle.get("jobId")
                or artifact.get("signature", {}).get("signer") != authority
                or entry.get("receiptWriter") != authority
                or not verify_signature(artifact, LEGACY_DOMAIN)
            ):
                return "fail"
            mapping = candidates[0]
            status = validate_delivery_artifact(
                case,
                artifact,
                associated_phase_index=mapping[0],
                legacy=True,
            )
            if status != "pass":
                return status
        else:
            return "error"
        if mapping in mapped:
            return "fail"
        summary = summary_by_pair.get(mapping)
        expected_outcome = (
            "success"
            if isinstance(summary, dict) and summary.get("outcome") == "ok"
            else "failure"
        )
        if not isinstance(summary, dict) or artifact.get("outcome") != expected_outcome:
            return "fail"
        mapped.append(mapping)
        ref_for_mapping[mapping] = supplied_ref

    if set(mapped) != expected or len(mapped) != len(expected):
        return "fail"
    if summary_pairs != expected or len(summary_pairs) != len(delivery_summaries):
        return "fail"
    for summary in delivery_summaries:
        pointer = summary.get("attestationRef")
        pair = (summary.get("index"), summary.get("kind"))
        if pointer is not None and pointer != ref_for_mapping.get(pair):
            return "fail"
    return "pass"


class PhaseBoundDeliveryVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_count_hash_names_and_jcs_recipe(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(self.data["hash"], hash_hex(vectors))
        names = [v["name"] for v in vectors]
        self.assertEqual(len(names), len(set(names)))
        self.assertGreaterEqual(len(vectors), 30)

    def test_every_declared_verdict_is_executed(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(evaluate(vector), vector["expected"])

    def test_generator_is_byte_deterministic(self):
        result = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_positive_current_artifacts_match_spec_top_level_shapes(self):
        spec_text = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "spec").glob("*.md"))
        types = parse_type_fields(spec_text)
        for vector in self.data["vectors"]:
            if vector["expected"] != "pass":
                continue
            for entry in vector["evidenceRecords"]:
                artifact = entry["artifact"]
                typename = "DeliveryEvidence" if "deliveryEvidenceVersion" in artifact else "SettlementEvidence"
                shape = types[typename]
                present = set(artifact)
                with self.subTest(vector=vector["name"], typename=typename):
                    self.assertFalse(shape["required"] - present)
                    self.assertFalse(present - shape["required"] - shape["optional"])
            for entry in vector["artifactRecords"]:
                if entry["kind"] not in {"EntitlementRecord", "PayloadAttestationRecord"}:
                    continue
                shape = types[entry["kind"]]
                present = set(entry["artifact"])
                self.assertFalse(shape["required"] - present)
                self.assertFalse(present - shape["required"] - shape["optional"])
            bundle_shape = types["FaultAttestationBundle"]
            bundle_present = set(vector["bundle"])
            self.assertFalse(bundle_shape["required"] - bundle_present)
            self.assertFalse(bundle_present - bundle_shape["required"] - bundle_shape["optional"])
            self.assertTrue(verify_bundle_signatures(vector["bundle"]))

    def test_fractional_entitlement_endpoint_uses_forward_computation(self):
        case = G.make("fractional-rounding", "pass", "binary64 endpoint", G.entitlement_case)
        self.assertEqual(evaluate(case), "pass")
        case["deliveryAuthorities"][0]["deliverable"]["durationSec"] = 0.0001
        record = case["artifactRecords"][0]["artifact"]
        record["startsAt"] = 0.2
        record["endsAt"] = record["startsAt"] + 0.0001 * 1000
        G.refresh_entitlement_chain(case)
        G.sign_bundle(case["bundle"])
        self.assertEqual(evaluate(case), "pass")
        record["endsAt"] += 0.01
        G.refresh_entitlement_chain(case)
        G.sign_bundle(case["bundle"])
        self.assertEqual(evaluate(case), "fail")

    def test_signed_inner_extensions_and_version_refusal(self):
        for factory, kind, refresh, discriminator in (
            (G.entitlement_case, "EntitlementRecord", G.refresh_entitlement_chain, "entitlementVersion"),
            (G.attested_case, "PayloadAttestationRecord", G.refresh_payload_chain, "payloadAttestationVersion"),
        ):
            case = G.make("extension", "pass", "signed optional extension", factory)
            record = next(entry["artifact"] for entry in case["artifactRecords"] if entry["kind"] == kind)
            record["laterMinorAuditLabel"] = "preserve-me"
            record["auditVersion"] = "2026-09"
            record["recipeVersion"] = 7
            refresh(case)
            G.sign_bundle(case["bundle"])
            with self.subTest(kind=kind):
                self.assertEqual(evaluate(case), "pass")
                record[discriminator] = "99"
                refresh(case)
                G.sign_bundle(case["bundle"])
                self.assertNotEqual(evaluate(case), "pass")

    def test_shared_delivery_classifier_is_syntactic_after_family_context(self):
        contextual_versions = {
            "recipeVersion": 3,
            "railVersion": 4,
            "listingVersion": 5,
            "recipeRegistryVersion": 6,
            "railRegistryVersion": 7,
            "protocolVersion": "2",
            "auditVersion": "inert-extension",
        }
        entitlement = {"entitlementVersion": "1", **contextual_versions}
        self.assertEqual(R._delivery_artifact_type(entitlement), "entitlement")
        self.assertTrue(R._delivery_inner_type_valid(entitlement, "entitlementVersion"))

        for discriminator, artifact_type in R._DELIVERY_ARTIFACT_TYPE_BY_DISCRIMINATOR.items():
            with self.subTest(discriminator=discriminator):
                self.assertEqual(
                    R._delivery_artifact_type({discriminator: "1"}), artifact_type
                )
                for expected in ("entitlementVersion", "payloadAttestationVersion"):
                    self.assertEqual(
                        R._delivery_inner_type_valid({expected: "1", discriminator: "1"}, expected),
                        discriminator == expected,
                    )

        self.assertIsNone(R._delivery_artifact_type({
            "entitlementVersion": "1", "agreementVersion": "1"
        }))
        self.assertEqual(
            R._delivery_artifact_type({
                "entitlementVersion": "1", "futureEntitlementVersion": "1"
            }),
            "entitlement",
        )

    def test_storage_delivery_hashes_exact_utf8_in_current_and_legacy_arms(self):
        for factory in (G.storage_case, G.legacy_case):
            case = G.make("storage-contract", "pass", "exact UTF-8", factory)
            stored = case["artifactRecords"][0]
            with self.subTest(factory=factory.__name__, condition="valid"):
                self.assertEqual(evaluate(case), "pass")
                self.assertEqual(
                    stored["storedContentHash"], stored["cleartextHash"]
                )
                self.assertNotIn("storedHash", stored)

            for access_model in ("buyer-only", "encrypt-to-buyer"):
                private = G.make(
                    "storage-" + access_model,
                    "pass",
                    "legitimate private storage",
                    factory,
                )
                for authority in private["deliveryAuthorities"]:
                    authority["deliverable"]["accessModel"] = access_model
                for position, resolved in enumerate(private["artifactRecords"]):
                    phase_index = private["deliveryAuthorities"][position]["phaseIndex"]
                    evidence = private["evidenceRecords"][position]["artifact"]
                    if access_model == "encrypt-to-buyer":
                        stored_bytes = f"ciphertext:{position}".encode("ascii")
                        resolved["storedContentHash"] = hashlib.sha256(
                            stored_bytes
                        ).hexdigest()
                        resolved["storedBytesBase64url"] = G.b64url(stored_bytes)
                        storage_binding = {
                            "effectiveAccessMode": access_model,
                            "storedContentHash": resolved["storedContentHash"],
                            "encryption": {
                                "recipient": G.BUYER,
                                "ciphertextContentHash": resolved["storedContentHash"],
                            },
                        }
                    else:
                        storage_binding = {
                            "effectiveAccessMode": access_model,
                            "storedContentHash": resolved["storedContentHash"],
                            "acl": {"mode": "restricted", "allowed": [G.BUYER]},
                        }
                    G.replace_dependency_receipt(
                        private,
                        resolved,
                        {
                            "anchor": copy.deepcopy(evidence["deliverableAnchor"]),
                            "contentHash": evidence["deliverableContentHash"],
                        },
                        phase_index,
                        "deliver-storage-program",
                        G.SELLER,
                        storage_binding=storage_binding,
                    )
                with self.subTest(
                    factory=factory.__name__, access_model=access_model
                ):
                    self.assertEqual(evaluate(private), "pass")

            unavailable = G.make(
                "storage-unavailable", "indeterminate", "unavailable", factory
            )
            unavailable["artifactRecords"][0]["available"] = False
            with self.subTest(factory=factory.__name__, condition="unavailable"):
                self.assertEqual(evaluate(unavailable), "indeterminate")

            malformed = G.make(
                "storage-malformed", "error", "malformed UTF-8", factory
            )
            malformed["artifactRecords"][0]["cleartextUtf8"] = chr(0xD800)
            with self.subTest(factory=factory.__name__, condition="malformed-utf8"):
                self.assertEqual(evaluate(malformed), "error")

            obsolete = G.make(
                "storage-obsolete-alias", "error", "obsolete resolver alias", factory
            )
            obsolete["artifactRecords"][0]["storedHash"] = (
                obsolete["artifactRecords"][0]["storedContentHash"]
            )
            with self.subTest(factory=factory.__name__, condition="obsolete-alias"):
                self.assertEqual(evaluate(obsolete), "error")

            mismatched = G.make(
                "storage-commitment-mismatch", "fail", "stored bytes differ", factory
            )
            mismatched["artifactRecords"][0]["storedContentHash"] = "00" * 32
            with self.subTest(factory=factory.__name__, condition="stored-mismatch"):
                self.assertEqual(evaluate(mismatched), "fail")

            malformed_commitment = G.make(
                "storage-commitment-malformed",
                "error",
                "stored digest malformed",
                factory,
            )
            malformed_commitment["artifactRecords"][0].pop("storedContentHash")
            with self.subTest(
                factory=factory.__name__, condition="stored-malformed"
            ):
                self.assertEqual(evaluate(malformed_commitment), "error")

    def test_exact_credential_bytes_and_storage_modes_execute(self):
        for access_model in ("buyer-only", "encrypt-to-buyer"):
            case = G.make(
                "credential-" + access_model,
                "pass",
                "legitimate exact credential bytes",
                lambda access_model=access_model: G.credential_case(access_model),
            )
            credential = case["credentials"][0]
            result, exact_bytes = R._exact_base64url_bytes(
                credential["cleartextBytesBase64url"], "credential"
            )
            cleartext_hash = hashlib.sha256(exact_bytes).hexdigest()
            with self.subTest(access_model=access_model):
                self.assertEqual(result[0], "pass")
                self.assertEqual(evaluate(case), "pass")
                self.assertEqual(credential["cleartextHash"], cleartext_hash)
                self.assertEqual(
                    credential["storedContentHash"],
                    credential["credentialRef"]["ref"]["contentHash"],
                )
                self.assertNotIn("storedHash", credential)
                if access_model == "buyer-only":
                    self.assertEqual(credential["storedContentHash"], cleartext_hash)
                else:
                    self.assertNotEqual(credential["storedContentHash"], cleartext_hash)

        arbitrary = b"\x00\xff\x80credential\x00"
        encoded = base64.urlsafe_b64encode(arbitrary).rstrip(b"=").decode("ascii")
        result, decoded = R._exact_base64url_bytes(encoded, "arbitrary bytes")
        self.assertEqual(result[0], "pass")
        self.assertEqual(decoded, arbitrary)
        self.assertEqual(R._exact_base64url_bytes("", "empty bytes"), (("pass", "ok"), b""))

        self.assertEqual(R._exact_base64url_bytes(None, "missing bytes")[0][0], "indeterminate")
        for malformed in (b"AA", "AA==", "AA+", "AA/", " AA", "A", 1):
            with self.subTest(malformed=malformed):
                self.assertEqual(
                    R._exact_base64url_bytes(malformed, "credential")[0][0],
                    "error",
                )

        for mutation in ("missing", None, "AA==", 1):
            case = G.make(
                "credential-byte-guard", "pass", "resolver byte guard", G.credential_case
            )
            if mutation == "missing":
                case["credentials"][0].pop("cleartextBytesBase64url")
                expected = "indeterminate"
            else:
                case["credentials"][0]["cleartextBytesBase64url"] = mutation
                expected = "indeterminate" if mutation is None else "error"
            with self.subTest(actual_consumer=mutation):
                self.assertEqual(evaluate(case), expected)

        for field in ("cleartextHash", "storedContentHash"):
            case = G.make(
                "credential-digest-guard", "pass", "resolver digest guard", G.credential_case
            )
            case["credentials"][0][field] = "not-a-digest"
            with self.subTest(resolver_digest=field):
                self.assertEqual(evaluate(case), "error")

    def test_resolver_schema_and_access_model_guards(self):
        credential_case = G.make(
            "credential-schema", "pass", "single byte representation", G.credential_case
        )
        for field in ("cleartextUtf8", "storedBytes", "ciphertextHash", "storedHash", "extraBytes"):
            case = copy.deepcopy(credential_case)
            case["credentials"][0][field] = None
            with self.subTest(unsupported_field=field):
                self.assertEqual(evaluate(case), "error")

        storage_case = G.make("storage-mode", "pass", "mode shape guard", G.storage_case)
        stored = storage_case["artifactRecords"][0]
        for malformed in ([], {}, None, 1, "unknown"):
            case = copy.deepcopy(storage_case)
            case["deliveryAuthorities"][0]["deliverable"]["accessModel"] = malformed
            with self.subTest(access_model=malformed):
                self.assertEqual(evaluate(case), "error")
                self.assertEqual(R._validate_resolved_storage(
                    stored,
                    stored["cleartextHash"],
                    malformed,
                    "storage",
                    authenticated_storage_binding={
                        "effectiveAccessMode": "public",
                        "storedContentHash": stored["storedContentHash"],
                    },
                    buyer=G.BUYER,
                )[0], "error")
        self.assertEqual(R._validate_resolved_storage([], "", "public", "storage")[0], "error")
        self.assertEqual(R._validate_resolved_credential([], {}, {})[0], "error")

    def test_resolver_collections_and_unique_credential_candidate(self):
        for factory, field in ((G.storage_case, "artifactRecords"), (G.credential_case, "credentials")):
            for missing in (False, True):
                case = G.make("missing-collection", "pass", "unavailable resolver", factory)
                if missing:
                    case.pop(field)
                else:
                    case[field] = None
                with self.subTest(field=field, missing=missing):
                    self.assertEqual(evaluate(case), "indeterminate")
            for malformed in ({}, {"available": False}, {"available": True}, "records", 1, [None]):
                case = G.make("collection-shape", "pass", "resolver shape guard", factory)
                case[field] = malformed
                with self.subTest(field=field, malformed=malformed):
                    self.assertEqual(evaluate(case), "error")

        for malformed_ref in (None, {}, [], "ref"):
            case = G.make("credential-ref-shape", "pass", "resolver ref guard", G.credential_case)
            case["credentials"][0]["credentialRef"] = malformed_ref
            with self.subTest(credential_ref=malformed_ref):
                self.assertEqual(evaluate(case), "error")

        case = G.make("credential-ref-binding", "pass", "resolver ref binding", G.credential_case)
        case["credentials"][0]["credentialRef"]["ref"]["contentHash"] = "11" * 32
        self.assertEqual(evaluate(case), "fail")
        case["credentials"].append(copy.deepcopy(case["credentials"][0]))
        self.assertEqual(evaluate(case), "indeterminate")

    def test_shared_availability_contract_reaches_every_alternate_dependency_arm(self):
        for entry, expected in (
            (None, "indeterminate"),
            ([], "error"),
            ({}, "error"),
            ({"available": None}, "error"),
            ({"available": "true"}, "error"),
            ({"available": 1}, "error"),
            ({"available": 0}, "error"),
            ({"available": False}, "indeterminate"),
            ({"available": True}, "pass"),
        ):
            with self.subTest(helper_entry=entry):
                self.assertEqual(R._resolved_availability(entry, "dependency")[0][0], expected)

        dependencies = (
            ("storage", G.storage_case, lambda case: case["artifactRecords"][0]),
            ("entitlement", G.entitlement_case, lambda case: next(
                entry for entry in case["artifactRecords"]
                if entry.get("kind") == "EntitlementRecord"
            )),
            ("credential", G.credential_case, lambda case: case["credentials"][0]),
            ("payload", G.attested_case, lambda case: next(
                entry for entry in case["artifactRecords"]
                if entry.get("kind") == "deliverable"
            )),
            ("payload-attestation", G.attested_case, lambda case: next(
                entry for entry in case["artifactRecords"]
                if entry.get("kind") == "PayloadAttestationRecord"
            )),
            ("method-evidence", G.attested_case, lambda case: next(
                entry for entry in case["artifactRecords"]
                if entry.get("kind") == "methodEvidence"
            )),
        )
        for name, factory, select in dependencies:
            unavailable = G.make(
                "availability-" + name, "pass", "resolver unavailable", factory
            )
            select(unavailable)["available"] = False
            with self.subTest(dependency=name, availability=False):
                self.assertEqual(evaluate(unavailable), "indeterminate")
            for malformed in (None, "true", 1, 0):
                case = G.make(
                    "availability-" + name, "pass", "resolver malformed", factory
                )
                select(case)["available"] = malformed
                with self.subTest(dependency=name, availability=malformed):
                    self.assertEqual(evaluate(case), "error")

    def test_legacy_consumers_close_every_delivery_kind_at_frozen_addresses(self):
        cases = {
            "storage": G.legacy_case(),
            "entitlement": G.legacy_entitlement_case(),
            "attested": G.legacy_attested_case(),
            "self-signed": G.legacy_attested_case(self_signed=True),
        }
        for name, case in cases.items():
            evidence = case["evidenceRecords"][0]["artifact"]
            with self.subTest(kind=name):
                self.assertEqual(evaluate(G.make(
                    "legacy-" + name,
                    "pass",
                    "historical compatibility",
                    lambda case=case: copy.deepcopy(case),
                )), "pass")
                self.assertEqual(evidence.get("evidenceVersion"), "1")
                self.assertNotIn("deliveryEvidenceVersion", evidence)
                self.assertNotIn("phaseIndex", evidence)
                self.assertNotIn("credentialDelivery", evidence)
                self.assertTrue(verify_signature(evidence, LEGACY_DOMAIN))

        self.assertEqual(
            cases["storage"]["evidenceRecords"][0]["artifact"][
                "deliverableAnchor"
            ]["locator"],
            f"dacs4:deliverable:{G.JOB}",
        )
        entitlement = cases["entitlement"]
        entitlement_record = entitlement["artifactRecords"][0]["artifact"]
        self.assertEqual(
            entitlement["evidenceRecords"][0]["artifact"]["deliverableAnchor"][
                "locator"
            ],
            f"dacs4:entitlement:{G.JOB}:{entitlement_record['renewalSeq']}",
        )
        legacy_credential = G.make(
            "legacy-credential-audit",
            "pass",
            "credential reference remains audit-only",
            G.legacy_credential_case,
        )
        credential_record = legacy_credential["artifactRecords"][0]["artifact"]
        self.assertEqual(evaluate(legacy_credential), "pass")
        self.assertEqual(
            credential_record["credentialRef"]["ref"]["anchor"]["locator"],
            f"dacs4:credential:{G.JOB}:0",
        )
        self.assertNotIn(
            "credentialDelivery",
            legacy_credential["evidenceRecords"][0]["artifact"],
        )
        for name in ("attested", "self-signed"):
            case = cases[name]
            evidence = case["evidenceRecords"][0]["artifact"]
            payload_record = next(
                entry["artifact"] for entry in case["artifactRecords"]
                if entry.get("kind") == "PayloadAttestationRecord"
            )
            expected = (
                f"dacs4:payload-attestation:{G.JOB}:"
                f"{payload_record['verificationMethodHash']}:"
                f"{payload_record['attempt']}"
            )
            self.assertEqual(evidence["attestationRef"]["anchor"]["locator"], expected)
            self.assertEqual(
                payload_record["methodEvidenceRef"]["anchor"]["locator"],
                f"dacs4:method-evidence:{G.JOB}",
            )

        self_signed_record = next(
            entry["artifact"] for entry in cases["self-signed"]["artifactRecords"]
            if entry.get("kind") == "PayloadAttestationRecord"
        )
        self.assertNotIn("methodTransactionRef", self_signed_record)
        self.assertEqual(
            cases["self-signed"][
                "trustedNativeTransactionObservationsByCanonicalRef"
            ],
            {},
        )

    def test_legacy_missing_dependencies_keep_their_contract_dispositions(self):
        for factory, kind in (
            (G.legacy_case, "deliverable"),
            (G.legacy_entitlement_case, "EntitlementRecord"),
            (G.legacy_attested_case, "methodEvidence"),
        ):
            case = G.make(
                "legacy-missing-dependency",
                "indeterminate",
                "required historical dependency unavailable",
                factory,
            )
            next(
                entry for entry in case["artifactRecords"]
                if entry.get("kind") == kind
            )["available"] = False
            with self.subTest(factory=factory.__name__, dependency=kind):
                self.assertEqual(evaluate(case), "indeterminate")

        malformed = G.make(
            "legacy-malformed-dependency",
            "error",
            "resolved historical payload is malformed",
            G.legacy_case,
        )
        malformed["artifactRecords"][0]["cleartextUtf8"] = chr(0xD800)
        self.assertEqual(evaluate(malformed), "error")

        for factory in (G.legacy_entitlement_case, G.legacy_attested_case):
            authority_missing = G.make(
                "legacy-authority-missing",
                "indeterminate",
                "authenticated commerce authority unavailable",
                factory,
            )
            authority_missing["deliveryAuthorities"] = []
            with self.subTest(factory=factory.__name__, dependency="authority"):
                self.assertEqual(evaluate(authority_missing), "indeterminate")

    def test_entitlement_roles_come_from_the_authenticated_bundle(self):
        current = G.make(
            "entitlement-role-contract", "pass", "authenticated roles", G.entitlement_case
        )
        self.assertEqual(evaluate(current), "pass")
        record = current["artifactRecords"][0]["artifact"]
        self.assertEqual(record["grantee"], G.BUYER)
        self.assertEqual(record["grantor"], G.SELLER)
        self.assertEqual(record["signature"]["signer"], record["grantor"])

        legacy = G.make(
            "legacy-entitlement-role-contract",
            "pass",
            "authenticated legacy roles",
            G.legacy_credential_case,
        )
        self.assertEqual(evaluate(legacy), "pass")

        missing_role = {"parties": [{"role": "buyer", "primaryClaim": G.BUYER}]}
        self.assertEqual(authenticated_delivery_roles(missing_role)[0], "error")
        ambiguous_role = {
            "parties": [
                {"role": "buyer", "primaryClaim": G.BUYER},
                {"role": "buyer", "primaryClaim": G.BUYER},
                {"role": "seller", "primaryClaim": G.SELLER},
            ]
        }
        self.assertEqual(authenticated_delivery_roles(ambiguous_role)[0], "error")

        mismatched = copy.deepcopy(record)
        mismatched["grantee"] = G.SELLER
        self.assertEqual(validate_entitlement_roles(current["bundle"], mismatched), "fail")

    def test_credential_binding_members_are_all_signed(self):
        vector = next(v for v in self.data["vectors"] if v["name"] == "credential-buyer-only-exact-binding")
        original = vector["evidenceRecords"][0]["artifact"]
        self.assertTrue(verify_signature(original, DELIVERY_DOMAIN))
        mutations = [
            ("phaseIndex", lambda a: a.update({"phaseIndex": a["phaseIndex"] + 1})),
            ("credentialRef", lambda a: a["credentialDelivery"]["credentialRef"].update({"accessModel": "encrypt-to-buyer"})),
            ("credentialCleartextHash", lambda a: a["credentialDelivery"].update({"credentialCleartextHash": "00" * 32})),
            ("renewalSeq", lambda a: a["credentialDelivery"].update({"renewalSeq": 1})),
        ]
        for name, mutate in mutations:
            artifact = copy.deepcopy(original)
            mutate(artifact)
            with self.subTest(field=name):
                self.assertFalse(verify_signature(artifact, DELIVERY_DOMAIN))

    def test_attested_delivery_executes_the_resolved_dpa_chain(self):
        vector = next(
            item for item in self.data["vectors"]
            if item["name"] == "repeated-attested-payload-each-attempt-zero"
        )
        self.assertEqual(evaluate(vector), "pass")
        for entry in vector["evidenceRecords"]:
            evidence = entry["artifact"]
            supplied = evidence["attestationRef"]
            payload_record_entry = find_artifact(
                vector, supplied["anchor"]["locator"], "PayloadAttestationRecord"
            )
            self.assertIsNotNone(payload_record_entry)
            payload_record = payload_record_entry["artifact"]
            method_ref = payload_record["methodEvidenceRef"]
            method_entry = find_artifact(
                vector, method_ref["anchor"]["locator"], "methodEvidence"
            )
            self.assertIsNotNone(method_entry)
            self.assertEqual(method_ref["contentHash"], hash_hex(method_entry["artifact"]))
            self.assertTrue(method_entry["artifact"]["transaction"]["authenticated"])
            self.assertEqual(
                method_entry["artifact"]["response"]["responseHash"],
                evidence["deliverableContentHash"],
            )

    def test_malformed_and_empty_utf8_take_closed_actual_consumer_paths(self):
        vector = copy.deepcopy(next(
            item for item in self.data["vectors"]
            if item["name"] == "repeated-attested-payload-each-attempt-zero"
        ))
        payload = next(
            entry for entry in vector["artifactRecords"]
            if entry.get("kind") == "deliverable"
        )
        payload["cleartextUtf8"] = chr(0xD800)
        self.assertEqual(evaluate(vector), "error")

        def empty_payload(case):
            evidence = case["evidenceRecords"][0]["artifact"]
            payload_entry = next(
                entry for entry in case["artifactRecords"]
                if entry.get("kind") == "deliverable"
                and entry.get("logicalAddress") == evidence["deliverableAnchor"]["locator"]
            )
            payload_record = next(
                entry["artifact"] for entry in case["artifactRecords"]
                if entry.get("kind") == "PayloadAttestationRecord"
                and entry.get("logicalAddress") == evidence["attestationRef"]["anchor"]["locator"]
            )
            method_evidence = next(
                entry["artifact"] for entry in case["artifactRecords"]
                if entry.get("kind") == "methodEvidence"
                and entry.get("logicalAddress")
                == payload_record["methodEvidenceRef"]["anchor"]["locator"]
            )
            empty_hash = hashlib.sha256(b"").hexdigest()
            payload_entry["cleartextUtf8"] = ""
            payload_entry["cleartextBytesBase64url"] = ""
            payload_entry["storedBytesBase64url"] = ""
            payload_entry["cleartextHash"] = empty_hash
            payload_entry["storedContentHash"] = empty_hash
            evidence["deliverableContentHash"] = empty_hash
            payload_record["payloadContentHash"] = empty_hash
            method_evidence["response"]["data"] = ""
            method_evidence["response"]["dataBytesBase64url"] = ""
            method_evidence["response"]["responseHash"] = empty_hash
            key = canonical_bytes(payload_record["methodTransactionRef"]).decode("utf-8")
            case["trustedNativeTransactionObservationsByCanonicalRef"][key]["response"][
                "responseHash"
            ] = empty_hash
            G.refresh_payload_chain(case)

        empty = G.make(
            "empty-utf8-control",
            "pass",
            "empty UTF-8 remains a valid exact payload",
            G.attested_case,
            empty_payload,
        )
        self.assertEqual(evaluate(empty), "pass")

    def test_spec_registers_type_domain_addresses_rules_and_versions(self):
        core = (ROOT / "spec" / "CORE.md").read_text(encoding="utf-8")
        dacs4 = (ROOT / "spec" / "DACS-4-SETTLE.md").read_text(encoding="utf-8")
        dacs5 = (ROOT / "spec" / "DACS-5-VERIFY.md").read_text(encoding="utf-8")
        self.assertIn('"dacs-delivery-evidence:v1:"', core)
        self.assertIn("type DeliveryEvidence = {", dacs4)
        self.assertIn("DACS-4 v0.7", dacs4)
        self.assertIn("DACS-5 v0.5", dacs5)
        for rule in range(1, 9):
            self.assertIn(f"(PDE-{rule})", dacs4)
        for address in [
            "dacs4:delivery:{jobId}:{phaseIndex}",
            "dacs4:deliverable:{jobId}:{phaseIndex}",
            "dacs4:entitlement:{jobId}:{phaseIndex}:{renewalSeq}",
            "dacs4:payload-attestation:{jobId}:{phaseIndex}:{verificationMethodHash}:{attempt}",
        ]:
            self.assertIn(address, core)
        self.assertIn("Exact current delivery mapping (PDE-8)", dacs5)


if __name__ == "__main__":
    unittest.main()
