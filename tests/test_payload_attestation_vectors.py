import base64
import hashlib
import json
import subprocess
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "payload-attestation-binding-v0.1.json"
)
GENERATOR = ROOT / "scripts" / "generate_payload_attestation_vectors.py"
HAPPY_PATH = ROOT / "conformance" / "vectors" / "dacs-v0.1-happy-path.json"
PAYLOAD_DOMAIN = "dacs-payload-attestation:v1:"
EVIDENCE_DOMAIN = "dacs-evidence:v1:"


def canonical_bytes(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def hash_hex(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def verify_signature(artifact, seed_hex, domain):
    signature = artifact.get("signature")
    if not isinstance(signature, dict):
        return False
    encoded = signature.get("value")
    if not isinstance(encoded, str) or "=" in encoded:
        return False
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        public = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(seed_hex)
        ).public_key()
        unsigned = {k: v for k, v in artifact.items() if k != "signature"}
        public.verify(
            raw,
            domain.encode("utf-8") + hash_hex(unsigned).encode("ascii"),
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def evaluate(vector, seeds):
    listing = vector["listing"]
    agreement = vector["agreement"]
    record = vector["payloadAttestationRecord"]
    record_ref = vector["payloadAttestationRef"]
    evidence = vector["settlementEvidence"]

    pipeline = listing.get("pipeline")
    if not isinstance(pipeline, list) or not any(
        isinstance(step, dict) and step.get("kind") == "deliver-attested-payload"
        for step in pipeline
    ):
        return "fail"
    deliverable = listing.get("offering", {}).get("deliverable")
    if not isinstance(deliverable, dict) or deliverable.get("kind") != "attested-payload":
        return "fail"
    method = deliverable.get("verificationMethod")
    if not isinstance(method, dict) or not isinstance(method.get("kind"), str):
        return "fail"

    spec_hash = hash_hex(deliverable)
    if agreement.get("deliverable", {}).get("deliverableType") != "attested-payload":
        return "fail"
    if agreement.get("deliverable", {}).get("hash") != spec_hash:
        return "fail"

    if record.get("payloadAttestationVersion") != "1":
        return "fail"
    if "resultVersion" in record or "evidenceVersion" in record:
        return "fail"
    if not verify_signature(record, seeds["verifierEd25519"], PAYLOAD_DOMAIN):
        return "fail"

    record_unsigned = {k: v for k, v in record.items() if k != "signature"}
    record_hash = hash_hex(record_unsigned)
    if record_ref.get("contentHash") != record_hash:
        return "fail"
    if record_ref.get("signer") != record.get("signature", {}).get("signer"):
        return "fail"

    payload = vector["payloadUtf8"].encode("utf-8")
    payload_hash = hashlib.sha256(payload).hexdigest()
    expected_fields = {
        "jobId": agreement.get("jobId"),
        "agreementHash": agreement.get("agreementHash"),
        "deliverableSpecHash": spec_hash,
        "payloadFormat": deliverable.get("payloadFormat"),
        "payloadContentHash": payload_hash,
        "verificationMethod": method.get("kind"),
        "verificationMethodHash": hash_hex(method),
    }
    for field, expected in expected_fields.items():
        if record.get(field) != expected:
            return "fail"
    if evidence.get("jobId") != agreement.get("jobId"):
        return "fail"
    attempt = record.get("attempt")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 0:
        return "fail"
    if record.get("decision") != "pass":
        return "fail"

    method_ref = record.get("methodEvidenceRef")
    if not isinstance(method_ref, dict):
        return "fail"
    method_evidence = vector["methodEvidence"]
    if method_evidence.get("disposition") == "unavailable":
        return "indeterminate"
    if method_ref.get("contentHash") != hash_hex(method_evidence):
        return "fail"
    if not method_evidence.get("proofValid", method_evidence.get("signatureValid", False)):
        return "fail"

    if method["kind"] == "consensus-backed-proxy":
        endpoint = method.get("endpoint", {})
        request = method_evidence.get("request", {})
        if request.get("method") != endpoint.get("method"):
            return "fail"
        if request.get("url") != endpoint.get("urlTemplate"):
            return "fail"
        response = method_evidence.get("response", {})
        if not isinstance(response.get("status"), int) or not (200 <= response["status"] < 300):
            return "fail"
        response_data = response.get("data")
        if not isinstance(response_data, str):
            return "fail"
        response_hash = hashlib.sha256(response_data.encode("utf-8")).hexdigest()
        if response.get("responseHash") != response_hash:
            return "fail"
        if response_hash != record["payloadContentHash"]:
            return "fail"
        transaction = method_evidence.get("transaction", {})
        method_tx = record.get("methodTransactionRef")
        if not isinstance(method_tx, dict):
            return "fail"
        if (
            transaction.get("kind") != method_tx.get("kind")
            or transaction.get("value") != method_tx.get("value")
            or transaction.get("state") not in {"included", "finalized"}
            or transaction.get("authenticated") is not True
        ):
            return "fail"
    elif method["kind"] == "self-signed":
        if method_evidence.get("kind") != "self-signed-payload":
            return "fail"
        if method_evidence.get("payloadContentHash") != record["payloadContentHash"]:
            return "fail"
        if method_evidence.get("signatureValid") is not True:
            return "fail"
    else:
        return "fail"

    if not verify_signature(evidence, seeds["orchestratorEd25519"], EVIDENCE_DOMAIN):
        return "fail"
    if evidence.get("phase") != "deliver-attested-payload":
        return "fail"
    if evidence.get("outcome") != "success":
        return "fail"
    if evidence.get("deliverableContentHash") != record["payloadContentHash"]:
        return "fail"
    if not isinstance(evidence.get("deliverableAnchor"), dict):
        return "fail"
    if evidence.get("attestationRef") != record_ref:
        return "fail"
    return "pass"


class PayloadAttestationVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_vector_hash_count_and_unique_names(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(
            self.data["hash"],
            hashlib.sha256(canonical_bytes(vectors)).hexdigest(),
        )
        names = [vector["name"] for vector in vectors]
        self.assertEqual(len(names), len(set(names)))

    def test_every_dpa_case_executes_to_its_declared_verdict(self):
        seeds = self.data["publicTestSeeds"]
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(evaluate(vector, seeds), vector["expected"])

    def test_generator_is_byte_deterministic(self):
        result = subprocess.run(
            ["python3", str(GENERATOR), "--check"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_happy_path_is_dpa1_coherent_and_transitively_resigned(self):
        data = json.loads(HAPPY_PATH.read_text(encoding="utf-8"))
        artifacts = {item["kind"]: item for item in data["artifacts"]}
        listing_item = artifacts["Listing"]
        listing = listing_item["artifact"]
        deliverable = listing["offering"]["deliverable"]
        self.assertEqual(deliverable["verificationMethod"], {"kind": "self-signed"})

        listing_hash = listing_item["contentHash"].removeprefix("sha256:")
        agreement_item = artifacts["AgreementDocument"]
        agreement = agreement_item["artifact"]
        self.assertEqual(agreement["listingRef"]["contentHash"], listing_hash)
        self.assertEqual(agreement["terms"]["deliverable"]["hash"], hash_hex(deliverable))

        bundle_item = artifacts["AttestationBundle"]
        bundle = bundle_item["artifact"]
        self.assertEqual(bundle["listingRef"]["contentHash"], listing_hash)

        for item, omitted in [
            (listing_item, {"signature"}),
            (agreement_item, {"signatures"}),
            (bundle_item, {"signatures", "anchoredByRole"}),
        ]:
            artifact = item["artifact"]
            unsigned = {key: value for key, value in artifact.items() if key not in omitted}
            payload = item["domainSeparator"].encode("utf-8") + hash_hex(unsigned).encode("ascii")
            signatures = artifact.get("signatures", [artifact.get("signature")])
            for signature in signatures:
                signer = signature.get("signer") or signature.get("party")
                with self.subTest(kind=item["kind"], signer=signer):
                    public = bytes.fromhex(signer.removeprefix("cci:"))
                    raw = base64.b64decode(signature["value"], validate=True)
                    Ed25519PublicKey.from_public_bytes(public).verify(raw, payload)

    def test_spec_registers_distinct_type_domain_and_rules(self):
        core = (ROOT / "spec" / "CORE.md").read_text(encoding="utf-8")
        dacs4 = (ROOT / "spec" / "DACS-4-SETTLE.md").read_text(encoding="utf-8")
        demos = (ROOT / "spec" / "DEMOS-MAPPING.md").read_text(encoding="utf-8")
        self.assertIn('"dacs-payload-attestation:v1:"', core)
        self.assertIn("type PayloadAttestationRecord = {", dacs4)
        for rule in range(1, 10):
            self.assertIn(f"(DPA-{rule})", dacs4)
        self.assertIn("behavioural", dacs4)
        self.assertIn("reject-timing change", dacs4)
        self.assertNotIn("already-unfulfillable", dacs4)
        self.assertNotIn("internally unfulfillable", dacs4)
        self.assertIn("IWeb2Result.txHash", demos)
        self.assertIn("sha256(UTF8(data)) == responseHash", demos)

    def test_positive_records_have_genuine_domain_separated_signatures(self):
        seeds = self.data["publicTestSeeds"]
        for name in [
            "dahr-payload-bound-success",
            "explicit-self-signed-tier-still-carries-proof",
        ]:
            vector = next(v for v in self.data["vectors"] if v["name"] == name)
            self.assertTrue(
                verify_signature(
                    vector["payloadAttestationRecord"],
                    seeds["verifierEd25519"],
                    PAYLOAD_DOMAIN,
                )
            )
            self.assertTrue(
                verify_signature(
                    vector["settlementEvidence"],
                    seeds["orchestratorEd25519"],
                    EVIDENCE_DOMAIN,
                )
            )


if __name__ == "__main__":
    unittest.main()
