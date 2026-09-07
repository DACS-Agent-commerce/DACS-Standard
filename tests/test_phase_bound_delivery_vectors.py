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


def verify_bundle_signatures(bundle):
    if bundle.get("faultBundleVersion") != "1" or "bundleVersion" in bundle:
        return False
    unsigned = {k: v for k, v in bundle.items() if k not in {"signatures", "anchoredByRole"}}
    payload = BUNDLE_DOMAIN.encode("ascii") + hash_hex(unsigned).encode("ascii")
    required = {party.get("primaryClaim") for party in bundle.get("parties", [])}
    observed = set()
    for signature in bundle.get("signatures", []):
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
    found = [entry for entry in case["artifactRecords"]
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
    if supplied_ref != artifact_ref(address, entry["artifact"]):
        return "fail", None, None
    return "pass", position, entry


def authenticated_delivery_roles(bundle):
    """Resolve the unique buyer and seller from the already-authenticated bundle."""
    return R.authenticated_delivery_roles(bundle)


def validate_delivered_cleartext(stored, expected_hash, subject):
    cleartext_status, cleartext_bytes = R._utf8_bytes(
        stored.get("cleartextUtf8"), subject
    )
    if cleartext_status[0] != "pass":
        return cleartext_status[0]
    actual_hash = hashlib.sha256(cleartext_bytes).hexdigest()
    if expected_hash != stored.get("cleartextHash") or actual_hash != expected_hash:
        return "fail"
    return "pass"


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


def validate_delivery_artifact(case, evidence):
    job = evidence["jobId"]
    index = evidence["phaseIndex"]
    phase = evidence["phase"]
    content_hash = evidence.get("deliverableContentHash")
    anchor = evidence.get("deliverableAnchor")
    outcome = evidence.get("outcome")
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
        if address != f"dacs4:deliverable:{job}:{index}":
            return "fail"
        stored = find_artifact(case, address, "deliverable")
        if stored is None or stored.get("available") is False:
            return "indeterminate"
        storage_status = validate_delivered_cleartext(
            stored, content_hash, "storage deliverable cleartext"
        )
        if storage_status != "pass":
            return storage_status
        if "attestationRef" in evidence or "credentialDelivery" in evidence:
            return "fail"
        return "pass"

    if phase == "deliver-entitlement":
        prefix = f"dacs4:entitlement:{job}:{index}:"
        if not isinstance(address, str) or not address.startswith(prefix):
            return "fail"
        record_entry = find_artifact(case, address, "EntitlementRecord")
        if record_entry is None:
            phase_records = [entry for entry in case["artifactRecords"]
                             if entry.get("kind") == "EntitlementRecord"
                             and str(entry.get("logicalAddress", "")).startswith(prefix)]
            return "fail" if phase_records else "indeterminate"
        if record_entry.get("available") is False:
            return "indeterminate"
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
        if address != f"dacs4:entitlement:{job}:{index}:{renewal}":
            return "fail"
        if record.get("jobId") != job or content_hash != artifact_hash(record):
            return "fail"
        if "attestationRef" in evidence:
            return "fail"
        authorities = [
            item for item in case.get("deliveryAuthorities", [])
            if item.get("phaseIndex") == index
        ]
        if len(authorities) != 1:
            return "indeterminate"
        deliverable_spec = authorities[0].get("deliverable")
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
        matches = [item for item in case.get("credentials", [])
                   if item.get("credentialRef") == credential_ref]
        if len(matches) != 1:
            return "indeterminate"
        credential = matches[0]
        if credential.get("available") is False:
            return "indeterminate"
        if binding.get("credentialCleartextHash") != credential.get("cleartextHash"):
            return "fail"
        return "pass"

    if phase == "deliver-attested-payload":
        payload_address = f"dacs4:deliverable:{job}:{index}"
        if address != payload_address:
            return "fail"
        payload = find_artifact(case, payload_address, "deliverable")
        payload_unavailable = payload is None or payload.get("available") is False
        if not payload_unavailable and content_hash != payload.get("cleartextHash"):
            return "fail"
        supplied = evidence.get("attestationRef")
        if not exact_ref_shape(supplied):
            return "error"
        record_address = supplied["anchor"]["locator"]
        record_entry = find_artifact(case, record_address, "PayloadAttestationRecord")
        if record_entry is None:
            same_record_elsewhere = any(
                entry.get("kind") == "PayloadAttestationRecord"
                and isinstance(entry.get("artifact"), dict)
                and artifact_hash(entry["artifact"]) == supplied.get("contentHash")
                for entry in case["artifactRecords"]
            )
            return "fail" if same_record_elsewhere else "indeterminate"
        if record_entry.get("available") is False:
            return "indeterminate"
        record = record_entry["artifact"]
        if supplied != artifact_ref(record_address, record):
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
        if record_address != f"dacs4:payload-attestation:{job}:{index}:{method_hash}:{attempt}":
            return "fail"
        if (record.get("jobId") != job or record.get("payloadContentHash") != content_hash
                or record.get("decision") != "pass"):
            return "fail"
        authorities = [
            item for item in case.get("deliveryAuthorities", [])
            if item.get("phaseIndex") == index
        ]
        if len(authorities) != 1:
            return "indeterminate"
        authority = authorities[0]
        deliverable = authority.get("deliverable")
        agreement = authority.get("agreement")
        method = deliverable.get("verificationMethod") if isinstance(deliverable, dict) else None
        if (
            not isinstance(deliverable, dict)
            or deliverable.get("kind") != "attested-payload"
            or not isinstance(method, dict)
            or method.get("kind") != "consensus-backed-proxy"
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
        if payload_unavailable:
            return "indeterminate"
        cleartext = payload.get("cleartextUtf8")
        cleartext_disposition, cleartext_bytes = R._utf8_bytes(
            cleartext, "attested payload cleartext"
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
        if method_entry is None or method_entry.get("available") is False:
            return "indeterminate"
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
    if case.get("consumerVersion") == "pre-0.7":
        return "error" if any("deliveryEvidenceVersion" in e.get("artifact", {}) for e in case["evidenceRecords"]) else "pass"
    pipeline = case.get("pipeline")
    bundle = case.get("bundle")
    if not isinstance(pipeline, list) or not isinstance(bundle, dict):
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
    if not isinstance(summaries, list):
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
        evidence_type = R._delivery_artifact_type(artifact)
        if evidence_type == "delivery":
            if not exact_delivery_evidence_shape(artifact):
                return "error"
            index, kind = artifact.get("phaseIndex"), artifact.get("phase")
            if isinstance(index, bool) or not isinstance(index, int) or index < 0:
                return "error"
            if artifact.get("jobId") != bundle.get("jobId"):
                return "fail"
            authority = case.get("executionAuthority", {}).get("phaseOrchestrator")
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
            if artifact.get("jobId") != bundle.get("jobId") or not verify_signature(artifact, LEGACY_DOMAIN):
                return "fail"
            anchor = artifact.get("deliverableAnchor")
            if not isinstance(anchor, dict):
                return "fail"
            if kind == "deliver-entitlement":
                delivered = find_artifact(case, anchor.get("locator"), "EntitlementRecord")
                if delivered is None or delivered.get("available") is False:
                    return "indeterminate"
                record = delivered.get("artifact")
                if (
                    not isinstance(record, dict)
                    or not R._delivery_inner_type_valid(record, "entitlementVersion")
                    or not verify_signature(record, ENTITLEMENT_DOMAIN)
                ):
                    return "fail"
                role_status = validate_entitlement_roles(bundle, record)
                if role_status != "pass":
                    return role_status
                if artifact.get("deliverableContentHash") != artifact_hash(record):
                    return "fail"
                if record.get("credentialRef") is not None and case.get("requestedGate") == "dv5-verified":
                    return "fail"
            else:
                delivered = find_artifact(case, anchor.get("locator"), "deliverable")
                if delivered is None or delivered.get("available") is False:
                    return "indeterminate"
                storage_status = validate_delivered_cleartext(
                    delivered,
                    artifact.get("deliverableContentHash"),
                    "legacy storage deliverable cleartext",
                )
                if storage_status != "pass":
                    return storage_status
            mapping = candidates[0]
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

    def test_shared_delivery_classifier_uses_registered_type_signals_only(self):
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
        self.assertIsNone(R._delivery_artifact_type({
            "entitlementVersion": "1", "futureEntitlementVersion": "1"
        }))

    def test_storage_delivery_hashes_exact_utf8_in_current_and_legacy_arms(self):
        for factory in (G.storage_case, G.legacy_case):
            case = G.make("storage-contract", "pass", "exact UTF-8", factory)
            with self.subTest(factory=factory.__name__, condition="valid"):
                self.assertEqual(evaluate(case), "pass")

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
            payload_entry["cleartextHash"] = empty_hash
            evidence["deliverableContentHash"] = empty_hash
            payload_record["payloadContentHash"] = empty_hash
            method_evidence["response"]["data"] = ""
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
