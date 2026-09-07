import base64
import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import dacs5_reference as R


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
# Reuse the validator's canonical primitives rather than hand-rolling them:
#  - decode_signature_value decodes canonical SIG-6 (unpadded Base64URL) and, only under
#    an explicit permit, legacy padded standard Base64 (called legacy_allowed=False here).
#  - canonical_json is the §B.2 RFC 8785 (JCS) serializer used for every hash the corpus
#    commits to, so this test hashes under the SAME canonicalizer the generator signs with.
from validate_conformance_vectors import canonical_json, decode_signature_value  # noqa: E402
VECTORS = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "payload-attestation-binding-v0.1.json"
)
GENERATOR = ROOT / "scripts" / "generate_payload_attestation_vectors.py"
HAPPY_PATH = ROOT / "conformance" / "vectors" / "dacs-v0.1-happy-path.json"
NEGATIVE_PATH = ROOT / "conformance" / "vectors" / "dacs-v0.1-negative-paths.json"
PAYLOAD_DOMAIN = "dacs-payload-attestation:v1:"
EVIDENCE_DOMAIN = "dacs-evidence:v1:"


def canonical_bytes(value):
    # §B.2 canonical bytes via the validator's RFC 8785 (JCS) primitive — the single
    # canonicalizer the whole corpus commits to. NOT json.dumps, which merely coincides
    # with JCS on ASCII/float-free input.
    return canonical_json(value)


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

    if not R._delivery_inner_type_valid(record, "payloadAttestationVersion"):
        return "fail"
    if not verify_signature(record, seeds["verifierEd25519"], PAYLOAD_DOMAIN):
        return "fail"

    record_unsigned = {k: v for k, v in record.items() if k != "signature"}
    record_hash = hash_hex(record_unsigned)
    if record_ref.get("contentHash") != record_hash:
        return "fail"
    if record_ref.get("signer") != record.get("signature", {}).get("signer"):
        return "fail"

    payload_disposition, payload = R._utf8_bytes(
        vector.get("payloadUtf8"), "delivered payload"
    )
    if payload_disposition[0] != "pass":
        return payload_disposition[0]
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
    method_disposition, _ = R.validate_delivery_method_evidence(
        method,
        method_evidence,
        record.get("methodTransactionRef"),
        vector.get("trustedNativeTransactionObservationsByCanonicalRef"),
        delivered_cleartext=vector["payloadUtf8"],
        delivered_bytes=payload,
        payload_content_hash=record["payloadContentHash"],
        require_finalized=False,
    )
    if method_disposition != "pass":
        return method_disposition

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
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_signed_optional_endpoint_and_record_fields_remain_bound(self):
        import generate_payload_attestation_vectors as G

        case = G.base_case()
        seeds = self.data["publicTestSeeds"]
        self.assertEqual(evaluate(case, seeds), "pass")
        deliverable = case["listing"]["offering"]["deliverable"]
        method = deliverable["verificationMethod"]
        method["endpoint"]["laterMinorAuditLabel"] = "preserve-me"
        method["signature"] = {"purpose": "inert-method-extension"}
        deliverable["signature"] = {"purpose": "inert-deliverable-extension"}
        record = case["payloadAttestationRecord"]
        record["laterMinorAuditLabel"] = "preserve-me"
        case["agreement"]["deliverable"]["hash"] = G.hash_hex(deliverable)
        record["deliverableSpecHash"] = G.hash_hex(deliverable)
        record["verificationMethodHash"] = G.hash_hex(method)
        key = G.canonical_bytes(record["methodTransactionRef"]).decode("utf-8")
        case["trustedNativeTransactionObservationsByCanonicalRef"][key] = (
            G.trusted_native_observation(method, case["methodEvidence"])
        )
        G.refresh_record_and_evidence(case)
        self.assertEqual(record["deliverableSpecHash"], R._complete_object_hash(deliverable))
        self.assertEqual(record["verificationMethodHash"], R._complete_object_hash(method))
        self.assertEqual(evaluate(case, seeds), "pass")
        record["laterMinorAuditLabel"] = "unsigned-tampering"
        self.assertNotEqual(evaluate(case, seeds), "pass")

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

        # Review item 6: the Agreement's Vet-record references must also resolve — both
        # parties' vetRecordRef must equal the CompositeVerificationRecord's stored §B.2
        # envelope contentHash, not the legacy whole-artifact hash. Compares two stored
        # file values (agreement ref vs composite envelope), so it is not a re-derivation.
        composite_item = artifacts["CompositeVerificationRecord"]
        composite_hash = composite_item["contentHash"].removeprefix("sha256:")
        for party in agreement["parties"]:
            self.assertEqual(party["vetRecordRef"]["contentHash"], composite_hash)

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
                    raw = decode_signature_value(signature["value"], legacy_allowed=False)
                    Ed25519PublicKey.from_public_bytes(public).verify(raw, payload)

    def test_negative_chain_is_internally_coherent(self):
        """The negative chain's DECLARED defects are the tampered bundle signature and
        the tampered HTLC preimage — reference staleness is NOT one of them. A negative
        vector must fail only for the reason it declares, so its cross-references must
        still resolve to the §B.2 envelope hashes of their referents.

        This asserts the same coherence family as the happy-path test, over stored file
        values only (no signature verification — the tampered bundle signature is
        SUPPOSED to fail and is never touched here). It is EXPECTED to fail until the
        negative chain is regenerated (Step 5); the failure precisely localises the
        remaining incoherence."""
        data = json.loads(NEGATIVE_PATH.read_text(encoding="utf-8"))
        artifacts = {item["kind"]: item for item in data["artifacts"]}

        listing_item = artifacts["Listing"]
        listing_hash = listing_item["contentHash"].removeprefix("sha256:")
        composite_hash = artifacts["CompositeVerificationRecord"]["contentHash"].removeprefix("sha256:")
        deliverable = listing_item["artifact"]["offering"]["deliverable"]

        agreement = artifacts["AgreementDocument"]["artifact"]
        bundle = artifacts["AttestationBundle"]["artifact"]
        self.assertEqual(agreement["listingRef"]["contentHash"], listing_hash)
        self.assertEqual(bundle["listingRef"]["contentHash"], listing_hash)
        for party in agreement["parties"]:
            self.assertEqual(party["vetRecordRef"]["contentHash"], composite_hash)
        self.assertEqual(agreement["terms"]["deliverable"]["hash"], hash_hex(deliverable))

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

    def test_native_observations_and_self_signed_method_input_are_load_bearing(self):
        seeds = self.data["publicTestSeeds"]
        by_name = {vector["name"]: vector for vector in self.data["vectors"]}
        for name, expected in (
            ("resigned-arbitrary-native-transaction-unobserved", "indeterminate"),
            ("native-transaction-observation-contradicts-envelope", "fail"),
            ("native-transaction-observation-unavailable", "indeterminate"),
            ("standalone-included-native-observation", "pass"),
            ("self-signed-method-input-signature-invalid", "fail"),
        ):
            with self.subTest(vector=name):
                self.assertEqual(evaluate(by_name[name], seeds), expected)

        malformed = copy.deepcopy(by_name["dahr-payload-bound-success"])
        malformed["payloadUtf8"] = chr(0xD800)
        self.assertEqual(evaluate(malformed, seeds), "error")


if __name__ == "__main__":
    unittest.main()
