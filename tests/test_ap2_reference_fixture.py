import base64
import copy
import hashlib
import json
import sys
import unittest
from decimal import Decimal
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import jcs  # noqa: E402


FIXTURE = (
    ROOT
    / "conformance"
    / "fixtures"
    / "settlement"
    / "settlement-ap2-reference.json"
)
OFFICIAL_AP2_COMMIT = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43"


def b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class Ap2ReferenceFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_fixture_pins_public_official_ap2_output(self):
        fixture = self.fixture
        self.assertEqual(fixture["fixtureVersion"], "1")
        self.assertEqual(fixture["provenance"]["officialAp2Commit"], OFFICIAL_AP2_COMMIT)
        self.assertEqual(fixture["officialAp2"]["officialAp2Commit"], OFFICIAL_AP2_COMMIT)
        self.assertIn("no private key", fixture["provenance"]["note"])
        self.assertEqual(
            fixture["officialAp2"]["request"]["merchantSignatureGeneration"],
            "non-deterministic",
        )
        self.assertEqual(fixture["expected"]["officialMandatesVerify"], True)

    def test_checkout_jws_signature_and_transaction_id_are_byte_exact(self):
        fixture = self.fixture
        verified = fixture["officialAp2"]["verified"]
        checkout_jws = verified["checkout"]["checkoutJwt"]
        header_segment, payload_segment, signature_segment = checkout_jws.split(".")
        transaction_id = base64.urlsafe_b64encode(
            hashlib.sha256(checkout_jws.encode("utf-8")).digest()
        ).rstrip(b"=").decode("ascii")
        self.assertEqual(transaction_id, verified["checkout"]["checkoutHash"])
        self.assertEqual(transaction_id, verified["payment"]["transactionId"])

        header = json.loads(b64url(header_segment))
        payload = json.loads(b64url(payload_segment))
        self.assertEqual(header, {
            "alg": "ES256",
            "kid": "dacs-ap2-merchant-v1",
            "typ": "JWT",
        })
        self.assertEqual(payload["merchant"]["id"], fixture["agreement"]["payeeId"])
        self.assertEqual(payload["currency"], fixture["agreement"]["currency"])
        self.assertEqual(payload["totals"][-1]["amount"], 50)

        jwk = fixture["officialAp2"]["request"]["trust"]["merchantPublicJwk"]
        public_key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64url(jwk["x"]), "big"),
            int.from_bytes(b64url(jwk["y"]), "big"),
            ec.SECP256R1(),
        ).public_key()
        raw_signature = b64url(signature_segment)
        self.assertEqual(len(raw_signature), 64)
        der_signature = encode_dss_signature(
            int.from_bytes(raw_signature[:32], "big"),
            int.from_bytes(raw_signature[32:], "big"),
        )
        public_key.verify(
            der_signature,
            f"{header_segment}.{payload_segment}".encode("ascii"),
            ec.ECDSA(SHA256()),
        )

    def test_attested_provider_status_binds_the_dacs_session(self):
        fixture = self.fixture
        agreement = fixture["agreement"]
        provider = fixture["provider"]
        body = provider["statusResponseBody"]
        self.assertEqual(hashlib.sha256(body.encode("utf-8")).hexdigest(), provider["statusResponseHash"])
        status = json.loads(body)
        self.assertEqual(status["status"], "succeeded")
        self.assertEqual(status["metadata"]["dacs_job_id"], agreement["jobId"])
        self.assertEqual(
            status["metadata"]["dacs_agreement_hash"],
            agreement["agreementHash"],
        )
        self.assertEqual(status["id"], fixture["evidence"]["paymentTxRefs"][0]["providerRef"])
        self.assertEqual(status["currency"].upper(), agreement["currency"])
        minor = Decimal(agreement["amount"]) * (Decimal(10) ** agreement["currencyMinorUnits"])
        self.assertEqual(status["amount_received"], int(minor))
        self.assertEqual(
            fixture["evidence"]["paymentTxRefs"][0]["receiptAttestation"]["contentHash"],
            provider["statusResponseHash"],
        )
        tx_ref = fixture["evidence"]["paymentTxRefs"][0]
        self.assertEqual(tx_ref["receiptAttestation"]["anchor"], {
            "kind": "https",
            "locator": (
                "https://api.stripe.com/v1/payment_intents/"
                "pi_dacs_ap2_reference_0001"
            ),
        })
        self.assertEqual(tx_ref["receiptTransactionRef"], {
            "kind": "demos-web2-request",
            "value": provider["attestedAnchorTxRef"],
        })

    def test_signed_settlement_evidence_and_result_are_exact(self):
        fixture = self.fixture
        evidence = fixture["evidence"]
        unsigned = copy.deepcopy(evidence)
        signature = unsigned.pop("signature")
        evidence_hash = hashlib.sha256(
            jcs.canonicalize(unsigned).encode("utf-8")
        ).hexdigest()
        self.assertEqual(evidence_hash, fixture["evidenceHash"])
        self.assertEqual(
            fixture["result"]["attestationRef"]["contentHash"],
            evidence_hash,
        )
        self.assertEqual(fixture["result"]["txRefs"], evidence["paymentTxRefs"])
        self.assertEqual(evidence["phase"], "pay-ap2")
        self.assertEqual(evidence["settlementFinality"]["model"], "provider-receipt")
        self.assertEqual(evidence["outcome"], "success")

        public = ed25519.Ed25519PublicKey.from_public_bytes(
            b64url(fixture["publicKeys"][signature["signer"]])
        )
        public.verify(
            b64url(signature["value"]),
            b"dacs-evidence:v1:" + evidence_hash.encode("ascii"),
        )

    def test_expected_assertions_are_all_positive(self):
        expected = self.fixture["expected"]
        self.assertEqual(expected["verdict"], "pass")
        self.assertTrue(all(value is True for key, value in expected.items() if key != "verdict"))


if __name__ == "__main__":
    unittest.main()
