import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - optional local dependency
    HAVE_CRYPTO = False


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "vectors" / "security" / "commitment-anchor-authority-v0.3.json"
SPEC = ROOT / "spec" / "DACS-3-NEGOTIATE.md"
PLAN = ROOT / "spec" / "CONFORMANCE-PLAN.md"


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def content_hash(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


def unsigned_agreement(agreement):
    return {key: value for key, value in agreement.items() if key != "signatures"}


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class CommitmentAnchorAuthorityVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))

    def evaluate(self, vector):
        orchestrator = next(
            party["primaryClaim"] for party in self.data["sessionParties"]
            if party["role"] == "orchestrator"
        )
        signer = self.data["commitmentSignature"]["signer"]
        if vector["signatureMode"] == "buyer-substitution":
            signer = next(
                party["primaryClaim"] for party in self.data["sessionParties"]
                if party["role"] == "buyer"
            )
        if signer != orchestrator:
            return "fail", "unauthorized-commitment-signer"

        agreement = copy.deepcopy(self.data["agreement"])
        mutation = vector["agreementMutation"]
        if mutation:
            target = agreement
            parts = mutation["path"].split(".")
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = mutation["value"]

        if content_hash(unsigned_agreement(agreement)) != self.data["commitmentRecord"]["agreementHash"]:
            return "fail", "agreement-hash-mismatch"
        return "pass", None

    def test_vector_hash_count_and_names(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(len({vector["name"] for vector in vectors}), len(vectors))
        self.assertEqual(self.data["hash"], content_hash(vectors))

    def test_fixture_hashes_are_byte_exact(self):
        self.assertEqual(content_hash(unsigned_agreement(self.data["agreement"])), self.data["agreementHash"])
        self.assertEqual(content_hash(self.data["commitmentRecord"]), self.data["commitmentRecordHash"])
        self.assertEqual(self.data["commitmentRecord"]["agreementHash"], self.data["agreementHash"])

    def test_executed_authority_decisions_match_want(self):
        for vector in self.data["vectors"]:
            verdict, reason = self.evaluate(vector)
            with self.subTest(vector=vector["name"]):
                self.assertEqual(verdict, vector["expected"])
                self.assertFalse(vector["want"]["physicalOwnerAuthoritative"])
                if verdict == "fail":
                    self.assertEqual(reason, vector["want"]["rejection"])

    def test_buyer_and_seller_deployers_have_identical_protocol_authority(self):
        buyer_case, seller_case = self.data["vectors"][:2]
        self.assertNotEqual(buyer_case["commitmentAnchor"]["owner"], seller_case["commitmentAnchor"]["owner"])
        self.assertNotEqual(
            buyer_case["commitmentAnchor"]["nativeAddress"],
            seller_case["commitmentAnchor"]["nativeAddress"],
        )
        self.assertEqual(self.evaluate(buyer_case), ("pass", None))
        self.assertEqual(self.evaluate(seller_case), ("pass", None))
        self.assertEqual(buyer_case["want"]["commitmentAuthority"], seller_case["want"]["commitmentAuthority"])
        self.assertEqual(buyer_case["want"]["agreementAuthors"], seller_case["want"]["agreementAuthors"])

    def test_spec_and_plan_pin_commitment_authority_and_compatibility(self):
        spec = SPEC.read_text(encoding="utf-8")
        plan = PLAN.read_text(encoding="utf-8")
        self.assertIn("(CA-6) **Commitment authority.**", spec)
        self.assertIn("(CA-7) **Agreement binding.**", spec)
        self.assertIn("transaction submitter, deployer, owner, and native address MUST NOT", spec)
        self.assertIn("CA-1..CA-9", plan)
        self.assertIn(VECTORS.name, plan)

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography package not installed")
    def test_fixture_signatures_verify(self):
        agreement_payload = ("dacs-agreement:v1:" + self.data["agreementHash"]).encode("utf-8")
        for signature in self.data["agreement"]["signatures"]:
            public_key = Ed25519PublicKey.from_public_bytes(b64url_decode(self.data["publicKeys"][signature["party"]]))
            with self.subTest(party=signature["party"]):
                try:
                    public_key.verify(b64url_decode(signature["value"]), agreement_payload)
                except InvalidSignature:
                    self.fail("agreement signature must verify")

        commitment_payload = ("dacs-commitment:v1:" + self.data["commitmentRecordHash"]).encode("utf-8")
        signature = self.data["commitmentSignature"]
        public_key = Ed25519PublicKey.from_public_bytes(b64url_decode(self.data["publicKeys"][signature["signer"]]))
        try:
            public_key.verify(b64url_decode(signature["value"]), commitment_payload)
        except InvalidSignature:
            self.fail("commitment signature must verify")


if __name__ == "__main__":
    unittest.main()
