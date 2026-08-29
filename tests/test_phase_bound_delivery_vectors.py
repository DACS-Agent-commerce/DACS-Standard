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
from validate_artifact_shapes import parse_type_fields, check_attestation_ref  # noqa: E402

VECTORS = ROOT / "conformance" / "vectors" / "security" / "phase-bound-delivery-evidence-v0.7.json"
GENERATOR = ROOT / "scripts" / "generate_phase_bound_delivery_vectors.py"
DELIVERY_DOMAIN = "dacs-delivery-evidence:v1:"
LEGACY_DOMAIN = "dacs-evidence:v1:"
ENTITLEMENT_DOMAIN = "dacs-entitlement:v1:"
PAYLOAD_DOMAIN = "dacs-payload-attestation:v1:"
BUNDLE_DOMAIN = "dacs-fault-bundle:v1:"
DELIVERY_KINDS = {"deliver-storage-program", "deliver-entitlement", "deliver-attested-payload"}


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
        if content_hash != stored.get("cleartextHash"):
            return "fail"
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
        if not isinstance(record, dict) or not verify_signature(record, ENTITLEMENT_DOMAIN):
            return "fail"
        renewal = record.get("renewalSeq")
        if isinstance(renewal, bool) or not isinstance(renewal, int) or renewal < 0:
            return "error"
        if address != f"dacs4:entitlement:{job}:{index}:{renewal}":
            return "fail"
        if record.get("jobId") != job or content_hash != artifact_hash(record):
            return "fail"
        if "attestationRef" in evidence:
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
        if payload is None or payload.get("available") is False:
            return "indeterminate"
        if content_hash != payload.get("cleartextHash"):
            return "fail"
        supplied = evidence.get("attestationRef")
        if not exact_ref_shape(supplied):
            return "error"
        record_address = supplied["anchor"]["locator"]
        record_entry = find_artifact(case, record_address, "PayloadAttestationRecord")
        if record_entry is None or record_entry.get("available") is False:
            return "indeterminate"
        record = record_entry["artifact"]
        if supplied != artifact_ref(record_address, record):
            return "fail"
        if not verify_signature(record, PAYLOAD_DOMAIN):
            return "fail"
        method_hash, attempt = record.get("verificationMethodHash"), record.get("attempt")
        if record_address != f"dacs4:payload-attestation:{job}:{index}:{method_hash}:{attempt}":
            return "fail"
        if (record.get("jobId") != job or record.get("payloadContentHash") != content_hash
                or record.get("decision") != "pass"):
            return "fail"
        if "credentialDelivery" in evidence:
            return "fail"
        return "pass"
    return "error"


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
        current = artifact.get("deliveryEvidenceVersion") == "1"
        legacy = artifact.get("evidenceVersion") == "1"
        if current and legacy:
            return "error"
        if current:
            if set(artifact).intersection({"evidenceVersion"}):
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
        elif legacy:
            if "deliveryEvidenceVersion" in artifact:
                return "error"
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
                if not isinstance(record, dict) or not verify_signature(record, ENTITLEMENT_DOMAIN):
                    return "fail"
                if artifact.get("deliverableContentHash") != artifact_hash(record):
                    return "fail"
                if record.get("credentialRef") is not None and case.get("requestedGate") == "dv5-verified":
                    return "fail"
            else:
                delivered = find_artifact(case, anchor.get("locator"), "deliverable")
                if delivered is None or delivered.get("available") is False:
                    return "indeterminate"
                if artifact.get("deliverableContentHash") != delivered.get("cleartextHash"):
                    return "fail"
            mapping = candidates[0]
        else:
            return "error"
        if mapping in mapped:
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
            ["python3", str(GENERATOR), "--check"], cwd=ROOT, text=True,
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
