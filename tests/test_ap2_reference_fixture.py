import base64
import copy
import hashlib
import json
import re
import sys
import tempfile
import unittest
from contextlib import contextmanager
from decimal import Decimal
from importlib.metadata import version as package_version
from pathlib import Path
from urllib.parse import quote

import ap2.sdk.mandate as ap2_mandate
from ap2.sdk.checkout_mandate_chain import CheckoutMandateChain
from ap2.sdk.generated.checkout_mandate import CheckoutMandate
from ap2.sdk.generated.open_checkout_mandate import OpenCheckoutMandate
from ap2.sdk.generated.open_payment_mandate import OpenPaymentMandate
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.mandate import MandateClient
from ap2.sdk.payment_mandate_chain import PaymentMandateChain
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256
from jwcrypto.jwk import JWK

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
DACS4 = ROOT / "spec" / "DACS-4-SETTLE.md"
DEMOS_MAPPING = ROOT / "spec" / "DEMOS-MAPPING.md"
AP2_REQUIREMENTS = ROOT / "requirements-ap2-reference.txt"
VALIDATE_WORKFLOW = ROOT / ".github" / "workflows" / "validate.yml"
OFFICIAL_AP2_COMMIT = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43"
OFFICIAL_AP2_VERSION = "0.1"
PINNED_AP2_PROTOCOL_VERSION = "0.2"
PINNED_EXPECTED_AUDIENCE = "dacs-ap2-merchant"
PINNED_EXPECTED_NONCE = "dacs-ap2-reference-nonce-v1"
PINNED_USER_PUBLIC_JWK = {
    "crv": "P-256",
    "kid": "dacs-ap2-user-v1",
    "kty": "EC",
    "x": "GvAJOD5a9RZ3q3hEnMp-CrLebge_jy4I4ZCixoxzgZo",
    "y": "NgU6E3ysQemB42Ez64ROG1Kw3yuG_D_XdtHLX-JCi-w",
}
PINNED_MERCHANT_PUBLIC_JWK = {
    "crv": "P-256",
    "kid": "dacs-ap2-merchant-v1",
    "kty": "EC",
    "x": "Zy8NP2pjEk4zW5nYZFtFh-gyU7San2SPvDAdvYaZfko",
    "y": "JA9OCSU12De59y6F_oCW6vOvUeyi7PDN0_wqXcj3R-g",
}
PINNED_ORCHESTRATOR = "did:demos:orchestrator"
PINNED_ORCHESTRATOR_PUBLIC_KEY = (
    "maekceCtXQ62avDhCrkykrlD64Bd6XkRY320vgwHLkI"
)
ULID_RE = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}\Z")
BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]+\Z")
PINNED_DAHR_TX_HASH = "75a2ac2e8cf8baf514b8a0e2b0c7caef36f330f3488d3a011f85400a968ae010"
PINNED_DAHR_BLOCK = {
    "number": 213605,
    "hash": "fd0977fba4ef15128801401c30648b643f67b3e638df1cf27aa5f6ed9134ddc0",
}
PINNED_DAHR_VALIDATORS = frozenset(
    {
        "0x41e8fde132ad670e534cd8b275d2cd7eec77733c66f8db48a1cada7fabfc4555",
        "0xb4740ba4e0f7e0576f11e8149dbbb2529c212213db679831fb5d1b221e84552d",
        "0xed3234b276d4ceda57d59bad14fbaf5a773c0f318c999de3a60d53c5a5b34c05",
    }
)


def b64url(value: str) -> bytes:
    if not isinstance(value, str) or not BASE64URL_RE.fullmatch(value):
        raise ValueError("non-canonical base64url value")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError("non-canonical base64url value")
    return decoded


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def parse_json_without_duplicate_keys(value: str):
    def reject_duplicates(pairs):
        parsed = {}
        for key, item in pairs:
            if key in parsed:
                raise ValueError("duplicate JSON member")
            parsed[key] = item
        return parsed

    return json.loads(value, object_pairs_hook=reject_duplicates)


def parse_jwt_json_segment(segment: str) -> dict:
    parsed = parse_json_without_duplicate_keys(b64url(segment).decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("JWT segment MUST decode to a JSON object")
    return parsed


@contextmanager
def ap2_log_in_private_test_temp():
    """Keep the official SDK's audit logging inside the assigned worktree."""
    original = ap2_mandate.LOG_FILE_PATH
    with tempfile.TemporaryDirectory(prefix=".ap2-verifier-", dir=ROOT) as tmp:
        ap2_mandate.LOG_FILE_PATH = str(Path(tmp) / "mandate.log")
        try:
            yield
        finally:
            ap2_mandate.LOG_FILE_PATH = original


def pinned_user_key_provider(token) -> JWK:
    if token.header != {
        "alg": "ES256",
        "typ": "example+sd-jwt",
        "kid": PINNED_USER_PUBLIC_JWK["kid"],
    }:
        raise ValueError("AP2 root header violates the pinned trust policy")
    return JWK(**PINNED_USER_PUBLIC_JWK)


def verified_mandate_chains(fixture: dict):
    """Verify both exact presentations with official AP2 and pinned authority."""
    presentations = fixture["officialAp2"]["request"]["presentation"]
    evaluation_time = (
        fixture["dahr"]["signedTransaction"]["content"]["timestamp"] // 1000
    )
    with ap2_log_in_private_test_temp():
        client = MandateClient()
        checkout_payloads = client.verify(
            token=presentations["checkoutPresentation"],
            key_or_provider=pinned_user_key_provider,
            expected_aud=PINNED_EXPECTED_AUDIENCE,
            expected_nonce=PINNED_EXPECTED_NONCE,
            clock_skew_seconds=300,
            current_time=evaluation_time,
        )
        payment_payloads = client.verify(
            token=presentations["paymentPresentation"],
            key_or_provider=pinned_user_key_provider,
            expected_aud=PINNED_EXPECTED_AUDIENCE,
            expected_nonce=PINNED_EXPECTED_NONCE,
            clock_skew_seconds=300,
            current_time=evaluation_time,
        )
    return (
        CheckoutMandateChain.parse(checkout_payloads),
        PaymentMandateChain.parse(payment_payloads),
    )


def checkout_transaction_id(checkout_presentation: str, checkout_jws: str) -> str:
    closed_jwt = MandateClient().get_closed_mandate_jwt(checkout_presentation)
    parts = closed_jwt.split(".")
    if len(parts) != 3:
        raise ValueError("malformed closed CheckoutMandate JWT")
    sd_payload = parse_jwt_json_segment(parts[1])
    digest_name = sd_payload.get("_sd_alg", "sha-256")
    if digest_name != "sha-256":
        raise ValueError(f"unsupported CheckoutMandate _sd_alg: {digest_name!r}")
    return b64url_encode(hashlib.sha256(checkout_jws.encode("utf-8")).digest())


def verified_merchant_checkout(checkout_jws: str) -> dict:
    parts = checkout_jws.split(".")
    if len(parts) != 3:
        raise ValueError("malformed merchant checkout JWS")
    header_segment, payload_segment, signature_segment = parts
    header = parse_jwt_json_segment(header_segment)
    if header != {
        "alg": "ES256",
        "kid": PINNED_MERCHANT_PUBLIC_JWK["kid"],
        "typ": "JWT",
    }:
        raise ValueError("merchant checkout JWS violates the strict DACS profile")
    payload = parse_jwt_json_segment(payload_segment)
    jwk = PINNED_MERCHANT_PUBLIC_JWK
    public_key = ec.EllipticCurvePublicNumbers(
        int.from_bytes(b64url(jwk["x"]), "big"),
        int.from_bytes(b64url(jwk["y"]), "big"),
        ec.SECP256R1(),
    ).public_key()
    raw_signature = b64url(signature_segment)
    if len(raw_signature) != 64:
        raise ValueError("ES256 signature MUST be 64 raw bytes")
    public_key.verify(
        encode_dss_signature(
            int.from_bytes(raw_signature[:32], "big"),
            int.from_bytes(raw_signature[32:], "big"),
        ),
        f"{header_segment}.{payload_segment}".encode("ascii"),
        ec.ECDSA(SHA256()),
    )
    return payload


def signed_settlement_evidence_valid(fixture: dict) -> bool:
    try:
        evidence = fixture["evidence"]
        unsigned = copy.deepcopy(evidence)
        signature = unsigned.pop("signature")
        if signature != {
            "algorithm": "ed25519",
            "signer": PINNED_ORCHESTRATOR,
            "value": signature["value"],
        }:
            return False
        if fixture["publicKeys"] != {
            PINNED_ORCHESTRATOR: PINNED_ORCHESTRATOR_PUBLIC_KEY
        }:
            return False
        evidence_hash = hashlib.sha256(
            jcs.canonicalize(unsigned).encode("utf-8")
        ).hexdigest()
        if not (
            evidence_hash == fixture["evidenceHash"]
            and fixture["result"]["attestationRef"]["contentHash"]
            == evidence_hash
            and fixture["result"]["txRefs"] == evidence["paymentTxRefs"]
        ):
            return False
        public = ed25519.Ed25519PublicKey.from_public_bytes(
            b64url(PINNED_ORCHESTRATOR_PUBLIC_KEY)
        )
        public.verify(
            b64url(signature["value"]),
            b"dacs-evidence:v1:" + evidence_hash.encode("ascii"),
        )
        return True
    except Exception:
        return False


def dahr_snapshot_valid(fixture: dict) -> bool:
    """Authenticate the pinned DAHR transaction, block, and AP2 commitment."""
    try:
        agreement = fixture["agreement"]
        provider = fixture["provider"]
        payment_ref = fixture["evidence"]["paymentTxRefs"][0]
        dahr = fixture["dahr"]
        signed = dahr["signedTransaction"]
        content = signed["content"]
        tx_hash = hashlib.sha256(
            json.dumps(
                content, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        if tx_hash != signed["hash"] or tx_hash != PINNED_DAHR_TX_HASH:
            return False

        writer = content["from"]
        if not re.fullmatch(r"0x[0-9a-f]{64}", writer):
            return False
        if content["to"] != writer or content["from_ed25519_address"] != writer:
            return False
        public = ed25519.Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(writer[2:])
        )
        public.verify(
            bytes.fromhex(signed["signature"]["data"][2:]),
            tx_hash.encode("ascii"),
        )

        message = content["data"][1]["message"]
        request = message["web2Request"]["raw"]
        response = message["web2Request"]["result"]
        response_bytes = provider["statusResponseBytes"]
        if not isinstance(response_bytes, str):
            return False
        if (
            hashlib.sha256(response_bytes.encode("utf-8")).hexdigest()
            != response["responseHash"]
        ):
            return False
        status_projection = parse_json_without_duplicate_keys(response_bytes)
        if status_projection != provider["statusProjection"]:
            return False
        expected_minor = Decimal(agreement["amount"]) * (
            Decimal(10) ** agreement["currencyMinorUnits"]
        )
        if expected_minor != expected_minor.to_integral_value():
            return False
        if not (
            status_projection["object"] == "payment_intent"
            and status_projection["status"] == "succeeded"
            and status_projection["id"] == payment_ref["providerRef"]
            and status_projection["amount"] == int(expected_minor)
            and status_projection["amount_received"] == int(expected_minor)
            and status_projection["currency"].upper() == agreement["currency"]
            and status_projection["metadata"]["dacs_job_id"] == agreement["jobId"]
            and status_projection["metadata"]["dacs_agreement_hash"]
            == agreement["agreementHash"]
        ):
            return False
        if not (
            content["type"] == "web2Request"
            and content["data"][0] == "web2Request"
            and message["authorization"] == ""
            and request["action"] == "startProxy"
            and request["parameters"] == []
            and request["method"] == "GET"
            and request["headers"] == {}
            and request["url"] == provider["statusResource"]
            and response["targetUrl"] == provider["statusResource"]
            and response["sessionId"] == message["sessionId"]
            and response["status"] == 200
            and response["responseHash"] == provider["statusResponseHash"]
            and response["responseHeadersHash"]
            == provider["statusResponseHeadersHash"]
            and payment_ref["kind"] == "ap2-sr3"
            and payment_ref["providerRef"]
            == provider["statusProjection"]["id"]
            and payment_ref["receiptAttestation"]["anchor"]
            == {"kind": "https", "locator": provider["statusResource"]}
            and payment_ref["receiptAttestation"]["contentHash"]
            == response["responseHash"]
            and payment_ref["receiptTransactionRef"]
            == {"kind": "demos-web2-request", "value": tx_hash}
        ):
            return False

        canonical = dahr["canonicalTransaction"]
        block = dahr["block"]
        block_hash = hashlib.sha256(
            json.dumps(
                block["content"], separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        if not (
            canonical
            == {"hash": tx_hash, "status": "confirmed", "blockNumber": block["number"]}
            and block["status"] == "confirmed"
            and block_hash == block["hash"]
            and {"number": block["number"], "hash": block_hash}
            == PINNED_DAHR_BLOCK
            and tx_hash in block["content"]["ordered_transactions"]
        ):
            return False

        peers = set(block["content"]["peerlist"])
        validator_signatures = block["validationData"]["signatures"]
        if (
            peers != PINNED_DAHR_VALIDATORS
            or set(validator_signatures) != PINNED_DAHR_VALIDATORS
        ):
            return False
        for signer, signature in validator_signatures.items():
            if not re.fullmatch(r"0x[0-9a-f]{64}", signer):
                return False
            if not re.fullmatch(r"0x[0-9a-f]{128}", signature):
                return False
            validator = ed25519.Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(signer[2:])
            )
            validator.verify(bytes.fromhex(signature[2:]), block_hash.encode("ascii"))
        return True
    except (KeyError, TypeError, ValueError):
        return False
    except Exception:
        return False


def authenticated_ap2_settlement_valid(fixture: dict) -> bool:
    """Fail closed unless mandate, agreement, evidence, and DAHR receipt all join."""
    try:
        official = fixture["officialAp2"]
        request = official["request"]
        if not (
            fixture["provenance"]["officialAp2Commit"] == OFFICIAL_AP2_COMMIT
            and official["officialAp2Commit"] == OFFICIAL_AP2_COMMIT
            and request["expectedAudience"] == PINNED_EXPECTED_AUDIENCE
            and request["expectedNonce"] == PINNED_EXPECTED_NONCE
            and request["trust"]
            == {
                "userPublicJwk": PINNED_USER_PUBLIC_JWK,
                "merchantPublicJwk": PINNED_MERCHANT_PUBLIC_JWK,
            }
            and request["merchantSignatureGeneration"] == "non-deterministic"
        ):
            return False

        # This check authenticates the timestamp used for deterministic mandate
        # expiry/iat evaluation as well as the exact provider response bytes.
        if not dahr_snapshot_valid(fixture):
            return False
        if not signed_settlement_evidence_valid(fixture):
            return False

        checkout_chain, payment_chain = verified_mandate_chains(fixture)
        if not (
            type(checkout_chain.open_mandate) is OpenCheckoutMandate
            and type(checkout_chain.closed_mandate) is CheckoutMandate
            and type(payment_chain.open_mandate) is OpenPaymentMandate
            and type(payment_chain.closed_mandate) is PaymentMandate
        ):
            return False

        checkout_mandate = checkout_chain.closed_mandate
        payment_mandate = payment_chain.closed_mandate
        checkout_jws = checkout_mandate.checkout_jwt
        checkout = verified_merchant_checkout(checkout_jws)
        transaction_id = checkout_transaction_id(
            request["presentation"]["checkoutPresentation"], checkout_jws
        )
        with ap2_log_in_private_test_temp():
            checkout_violations = checkout_chain.verify(
                expected_checkout_hash=transaction_id,
                checkout_jwt=checkout_jws,
            )
            payment_violations = payment_chain.verify(
                expected_transaction_id=transaction_id
            )
        if checkout_violations or payment_violations:
            return False

        payment_closed_jwt = MandateClient().get_closed_mandate_jwt(
            request["presentation"]["paymentPresentation"]
        )
        mandate_id = b64url_encode(
            hashlib.sha256(payment_closed_jwt.encode("utf-8")).digest()
        )
        agreement = fixture["agreement"]
        minor_units = agreement["currencyMinorUnits"]
        if type(minor_units) is not int or minor_units < 0:
            return False
        expected_minor = Decimal(agreement["amount"]) * (
            Decimal(10) ** minor_units
        )
        if expected_minor != expected_minor.to_integral_value():
            return False
        expected_minor_int = int(expected_minor)

        # dahr_snapshot_valid authenticated the response hash before this parse.
        status = parse_json_without_duplicate_keys(
            fixture["provider"]["statusResponseBytes"]
        )
        evidence = fixture["evidence"]
        tx_refs = evidence["paymentTxRefs"]
        if len(tx_refs) != 1:
            return False
        tx_ref = tx_refs[0]
        expected_evidence_anchor = (
            "dacs4:payment:"
            f"{agreement['jobId']}:"
            f"{quote(agreement['railId'], safe='')}:"
            f"{agreement['phaseIndex']}"
        )

        return (
            payment_mandate.transaction_id == transaction_id
            and checkout_mandate.checkout_hash == transaction_id
            and payment_mandate.payee.id == agreement["payeeId"]
            and payment_mandate.payment_amount.amount == expected_minor_int
            and payment_mandate.payment_amount.currency == agreement["currency"]
            and checkout["merchant"]["id"] == payment_mandate.payee.id
            and checkout["currency"] == payment_mandate.payment_amount.currency
            and checkout["totals"][-1]
            == {"type": "total", "amount": expected_minor_int}
            and evidence["jobId"] == agreement["jobId"]
            and evidence["phase"] == "pay-ap2"
            and evidence["outcome"] == "success"
            and evidence["paymentAmount"]
            == {"amount": agreement["amount"], "currency": agreement["currency"]}
            and evidence["settlementFinality"]["model"] == "provider-receipt"
            and tx_ref["kind"] == "ap2-sr3"
            and tx_ref["mandateId"] == mandate_id
            and tx_ref["protocolVersion"] == PINNED_AP2_PROTOCOL_VERSION
            and tx_ref["providerRef"] == status["id"]
            and status["status"] == "succeeded"
            and status["amount"] == expected_minor_int
            and status["amount_received"] == expected_minor_int
            and status["currency"].upper() == agreement["currency"]
            and status["metadata"]["dacs_job_id"] == agreement["jobId"]
            and status["metadata"]["dacs_agreement_hash"]
            == agreement["agreementHash"]
            and fixture["result"]["ok"] is True
            and fixture["result"]["attestationRef"]["anchor"]
            == {"kind": "storage-program", "locator": expected_evidence_anchor}
        )
    except Exception:
        return False


def resign_settlement_evidence(fixture: dict) -> None:
    """Re-sign a mutation with the fixture's explicitly public test key."""
    evidence = fixture["evidence"]
    unsigned = copy.deepcopy(evidence)
    unsigned.pop("signature")
    evidence_hash = hashlib.sha256(
        jcs.canonicalize(unsigned).encode("utf-8")
    ).hexdigest()
    private = ed25519.Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(fixture["seeds"]["orchestrator"])
    )
    evidence["signature"] = {
        "algorithm": "ed25519",
        "signer": PINNED_ORCHESTRATOR,
        "value": b64url_encode(
            private.sign(b"dacs-evidence:v1:" + evidence_hash.encode("ascii"))
        ),
    }
    fixture["evidenceHash"] = evidence_hash
    fixture["result"]["attestationRef"]["contentHash"] = evidence_hash
    fixture["result"]["txRefs"] = copy.deepcopy(evidence["paymentTxRefs"])


def omit_last_leaf_disclosure(presentation: str) -> str:
    root, leaf = presentation.split("~~")
    parts = leaf.split("~")
    if len(parts) < 3 or parts[-1] != "":
        raise ValueError("unexpected AP2 fixture presentation shape")
    del parts[-2]
    return root + "~~" + "~".join(parts)


def rewrite_leaf_jwt_payload(presentation: str, key: str, value) -> str:
    root, leaf = presentation.split("~~")
    parts = leaf.split("~")
    jwt_parts = parts[0].split(".")
    payload = parse_jwt_json_segment(jwt_parts[1])
    payload[key] = value
    jwt_parts[1] = b64url_encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    parts[0] = ".".join(jwt_parts)
    return root + "~~" + "~".join(parts)


def rewrite_leaf_delegate_field(presentation: str, key: str, value) -> str:
    root, leaf = presentation.split("~~")
    parts = leaf.split("~")
    disclosure = json.loads(b64url(parts[-2]))
    if len(disclosure) != 2 or not isinstance(disclosure[1], dict):
        raise ValueError("unexpected terminal delegate disclosure")
    disclosure[1][key] = value
    parts[-2] = b64url_encode(
        json.dumps(disclosure, separators=(",", ":")).encode("utf-8")
    )
    return root + "~~" + "~".join(parts)


def rewrite_leaf_disclosed_property(presentation: str, key: str, value) -> str:
    root, leaf = presentation.split("~~")
    parts = leaf.split("~")
    for index in range(1, len(parts) - 1):
        disclosure = json.loads(b64url(parts[index]))
        if len(disclosure) == 3 and disclosure[1] == key:
            disclosure[2] = value
            parts[index] = b64url_encode(
                json.dumps(disclosure, separators=(",", ":")).encode("utf-8")
            )
            return root + "~~" + "~".join(parts)
    raise ValueError(f"missing disclosed property: {key}")


class Ap2ReferenceFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def assert_rejected_before_effects(self, fixture):
        effects = []
        if authenticated_ap2_settlement_valid(fixture):
            effects.append("reserved-ap2-7-and-submitted-provider-payment")
        self.assertEqual(effects, [])

    def test_fixture_pins_public_official_ap2_output(self):
        fixture = self.fixture
        request = fixture["officialAp2"]["request"]
        self.assertEqual(fixture["fixtureVersion"], "1")
        self.assertEqual(fixture["provenance"]["officialAp2Commit"], OFFICIAL_AP2_COMMIT)
        self.assertEqual(fixture["officialAp2"]["officialAp2Commit"], OFFICIAL_AP2_COMMIT)
        self.assertIn(
            "not a live-network or production-provider receipt",
            fixture["provenance"]["note"],
        )
        self.assertEqual(
            request["merchantSignatureGeneration"],
            "non-deterministic",
        )
        self.assertEqual(request["expectedAudience"], PINNED_EXPECTED_AUDIENCE)
        self.assertEqual(request["expectedNonce"], PINNED_EXPECTED_NONCE)
        self.assertEqual(
            request["trust"],
            {
                "userPublicJwk": PINNED_USER_PUBLIC_JWK,
                "merchantPublicJwk": PINNED_MERCHANT_PUBLIC_JWK,
            },
        )

    def test_ci_requires_the_immutable_official_ap2_source(self):
        requirements = AP2_REQUIREMENTS.read_text(encoding="utf-8")
        workflow = VALIDATE_WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(package_version("ap2"), OFFICIAL_AP2_VERSION)
        self.assertIn(
            "ap2 @ git+https://github.com/google-agentic-commerce/AP2.git@"
            + OFFICIAL_AP2_COMMIT,
            requirements,
        )
        self.assertIn("requirements-ap2-reference.txt", workflow)
        self.assertIn(OFFICIAL_AP2_COMMIT, workflow)
        self.assertIn('distribution("ap2")', workflow)

    def test_official_ap2_verifies_both_presentations_as_expected_types(self):
        fixture = self.fixture
        checkout_chain, payment_chain = verified_mandate_chains(fixture)
        self.assertIs(type(checkout_chain.open_mandate), OpenCheckoutMandate)
        self.assertIs(type(checkout_chain.closed_mandate), CheckoutMandate)
        self.assertIs(type(payment_chain.open_mandate), OpenPaymentMandate)
        self.assertIs(type(payment_chain.closed_mandate), PaymentMandate)
        checkout = checkout_chain.closed_mandate
        payment = payment_chain.closed_mandate
        with ap2_log_in_private_test_temp():
            checkout_violations = checkout_chain.verify(
                expected_checkout_hash=checkout.checkout_hash,
                checkout_jwt=checkout.checkout_jwt,
            )
            payment_violations = payment_chain.verify(
                expected_transaction_id=checkout.checkout_hash
            )
        self.assertEqual(checkout_violations, [])
        self.assertEqual(payment_violations, [])
        payment_closed_jwt = MandateClient().get_closed_mandate_jwt(
            fixture["officialAp2"]["request"]["presentation"][
                "paymentPresentation"
            ]
        )
        verified = fixture["officialAp2"]["verified"]
        self.assertEqual(
            verified["checkout"],
            {
                "vct": checkout.vct,
                "checkoutJwt": checkout.checkout_jwt,
                "checkoutHash": checkout.checkout_hash,
            },
        )
        self.assertEqual(
            verified["payment"],
            {
                "vct": payment.vct,
                "mandateId": b64url_encode(
                    hashlib.sha256(
                        payment_closed_jwt.encode("utf-8")
                    ).digest()
                ),
                "protocolVersion": PINNED_AP2_PROTOCOL_VERSION,
                "transactionId": payment.transaction_id,
                "payee": {
                    "id": payment.payee.id,
                    "name": payment.payee.name,
                },
                "paymentAmount": {
                    "amount": payment.payment_amount.amount,
                    "currency": payment.payment_amount.currency,
                },
                "paymentInstrument": {
                    "id": payment.payment_instrument.id,
                    "type": payment.payment_instrument.type,
                },
            },
        )
        self.assertEqual(
            verified["merchantSignature"],
            {"algorithm": "ES256", "generation": "non-deterministic"},
        )

    def test_checkout_jws_signature_and_transaction_id_are_byte_exact(self):
        fixture = self.fixture
        checkout_chain, payment_chain = verified_mandate_chains(fixture)
        checkout_mandate = checkout_chain.closed_mandate
        payment_mandate = payment_chain.closed_mandate
        checkout_jws = checkout_mandate.checkout_jwt
        transaction_id = checkout_transaction_id(
            fixture["officialAp2"]["request"]["presentation"][
                "checkoutPresentation"
            ],
            checkout_jws,
        )
        self.assertEqual(transaction_id, checkout_mandate.checkout_hash)
        self.assertEqual(transaction_id, payment_mandate.transaction_id)

        payload = verified_merchant_checkout(checkout_jws)
        self.assertEqual(payload["merchant"]["id"], fixture["agreement"]["payeeId"])
        self.assertEqual(payload["currency"], fixture["agreement"]["currency"])
        self.assertEqual(payload["totals"][-1]["amount"], 50)

    def test_authenticated_cross_artifact_settlement_join_passes(self):
        self.assertTrue(authenticated_ap2_settlement_valid(self.fixture))

    def test_official_verifier_rejects_wrong_trust_audience_and_nonce(self):
        fixture = self.fixture
        token = fixture["officialAp2"]["request"]["presentation"][
            "checkoutPresentation"
        ]
        evaluation_time = (
            fixture["dahr"]["signedTransaction"]["content"]["timestamp"]
            // 1000
        )

        def accepts(key_provider, audience, nonce):
            try:
                with ap2_log_in_private_test_temp():
                    MandateClient().verify(
                        token=token,
                        key_or_provider=key_provider,
                        expected_aud=audience,
                        expected_nonce=nonce,
                        clock_skew_seconds=300,
                        current_time=evaluation_time,
                    )
                return True
            except Exception:
                return False

        self.assertTrue(
            accepts(
                pinned_user_key_provider,
                PINNED_EXPECTED_AUDIENCE,
                PINNED_EXPECTED_NONCE,
            )
        )
        self.assertFalse(
            accepts(
                lambda _token: JWK(**PINNED_MERCHANT_PUBLIC_JWK),
                PINNED_EXPECTED_AUDIENCE,
                PINNED_EXPECTED_NONCE,
            )
        )
        self.assertFalse(
            accepts(
                pinned_user_key_provider,
                "attacker-audience",
                PINNED_EXPECTED_NONCE,
            )
        )
        self.assertFalse(
            accepts(
                pinned_user_key_provider,
                PINNED_EXPECTED_AUDIENCE,
                "attacker-nonce",
            )
        )

    def test_candidate_authority_fields_never_become_verifier_authority(self):
        mutations = [
            lambda f: f["officialAp2"]["request"].__setitem__(
                "expectedAudience", "attacker-audience"
            ),
            lambda f: f["officialAp2"]["request"].__setitem__(
                "expectedNonce", "attacker-nonce"
            ),
            lambda f: f["officialAp2"]["request"]["trust"].__setitem__(
                "userPublicJwk", PINNED_MERCHANT_PUBLIC_JWK
            ),
            lambda f: f["officialAp2"]["request"]["trust"].__setitem__(
                "merchantPublicJwk", PINNED_USER_PUBLIC_JWK
            ),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                fixture = copy.deepcopy(self.fixture)
                mutate(fixture)
                self.assert_rejected_before_effects(fixture)

    def test_presentation_and_required_disclosure_mutations_fail_before_effects(self):
        presentation = self.fixture["officialAp2"]["request"]["presentation"]
        fixtures = []
        for name in ("checkoutPresentation", "paymentPresentation"):
            corrupted = copy.deepcopy(self.fixture)
            token = corrupted["officialAp2"]["request"]["presentation"][name]
            corrupted["officialAp2"]["request"]["presentation"][name] = (
                ("A" if token[0] != "A" else "B") + token[1:]
            )
            fixtures.append((f"corrupt-{name}", corrupted))

            omitted = copy.deepcopy(self.fixture)
            omitted["officialAp2"]["request"]["presentation"][name] = (
                omit_last_leaf_disclosure(presentation[name])
            )
            fixtures.append((f"omit-disclosure-{name}", omitted))

        swapped = copy.deepcopy(self.fixture)
        swapped_presentations = swapped["officialAp2"]["request"]["presentation"]
        (
            swapped_presentations["checkoutPresentation"],
            swapped_presentations["paymentPresentation"],
        ) = (
            swapped_presentations["paymentPresentation"],
            swapped_presentations["checkoutPresentation"],
        )
        fixtures.append(("swap-authenticated-types", swapped))

        for name, fixture in fixtures:
            with self.subTest(name=name):
                # The stored oracle remains positive and cannot authorize effects.
                self.assertIs(fixture["expected"]["officialMandatesVerify"], True)
                self.assert_rejected_before_effects(fixture)

    def test_digest_merchant_policy_and_transaction_id_mutations_fail_closed(self):
        request = self.fixture["officialAp2"]["request"]
        checkout_presentation = request["presentation"]["checkoutPresentation"]
        payment_presentation = request["presentation"]["paymentPresentation"]
        checkout_jws = self.fixture["officialAp2"]["verified"]["checkout"][
            "checkoutJwt"
        ]

        bad_digest = copy.deepcopy(self.fixture)
        bad_digest_presentation = rewrite_leaf_jwt_payload(
            checkout_presentation, "_sd_alg", "sha-512"
        )
        bad_digest["officialAp2"]["request"]["presentation"][
            "checkoutPresentation"
        ] = bad_digest_presentation
        with self.assertRaisesRegex(ValueError, "unsupported CheckoutMandate"):
            checkout_transaction_id(bad_digest_presentation, checkout_jws)

        jws_parts = checkout_jws.split(".")
        bad_header = {
            "alg": "none",
            "kid": PINNED_MERCHANT_PUBLIC_JWK["kid"],
            "typ": "JWT",
        }
        jws_parts[0] = b64url_encode(
            json.dumps(bad_header, separators=(",", ":")).encode("utf-8")
        )
        bad_merchant_jws = ".".join(jws_parts)
        with self.assertRaisesRegex(ValueError, "strict DACS profile"):
            verified_merchant_checkout(bad_merchant_jws)
        bad_merchant = copy.deepcopy(self.fixture)
        bad_merchant["officialAp2"]["request"]["presentation"][
            "checkoutPresentation"
        ] = rewrite_leaf_disclosed_property(
            checkout_presentation, "checkout_jwt", bad_merchant_jws
        )

        bad_transaction = copy.deepcopy(self.fixture)
        bad_transaction["officialAp2"]["request"]["presentation"][
            "paymentPresentation"
        ] = rewrite_leaf_delegate_field(
            payment_presentation,
            "transaction_id",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )

        for name, fixture in (
            ("unsupported-digest", bad_digest),
            ("merchant-policy", bad_merchant),
            ("transaction-id", bad_transaction),
        ):
            with self.subTest(name=name):
                self.assert_rejected_before_effects(fixture)

    def test_attested_provider_status_binds_the_dacs_session(self):
        fixture = self.fixture
        agreement = fixture["agreement"]
        provider = fixture["provider"]
        status = provider["statusProjection"]
        response_bytes = provider["statusResponseBytes"]
        self.assertEqual(parse_json_without_duplicate_keys(response_bytes), status)
        self.assertEqual(
            hashlib.sha256(response_bytes.encode("utf-8")).hexdigest(),
            provider["statusResponseHash"],
        )
        self.assertTrue(fixture["expected"]["providerResponseBytesBindProjection"])
        self.assertRegex(agreement["jobId"], ULID_RE)
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
        self.assertEqual(tx_ref["kind"], "ap2-sr3")
        self.assertEqual(tx_ref["receiptAttestation"]["anchor"], {
            "kind": "https",
            "locator": provider["statusResource"],
        })
        self.assertEqual(tx_ref["receiptTransactionRef"], {
            "kind": "demos-web2-request",
            "value": provider["attestedAnchorTxRef"],
        })

    def test_normative_rules_forbid_detached_provider_projection(self):
        dacs4 = DACS4.read_text(encoding="utf-8")
        demos = DEMOS_MAPPING.read_text(encoding="utf-8")
        self.assertIn("parse the provider-reported status", dacs4)
        self.assertIn("from those same bytes", dacs4)
        self.assertIn("separately stored field projection MUST NOT substitute", dacs4)
        self.assertIn("derive the provider status", demos)
        self.assertIn("A detached or caller-supplied projection", demos)

    def test_dahr_transaction_and_finality_are_cryptographically_bound(self):
        self.assertTrue(dahr_snapshot_valid(self.fixture))

    def test_public_seeds_reproduce_the_fixture_trust_keys(self):
        fixture = self.fixture
        writer = ed25519.Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(fixture["seeds"]["dahrWriter"])
        )
        writer_id = "0x" + writer.public_key().public_bytes_raw().hex()
        self.assertEqual(
            writer_id,
            fixture["dahr"]["signedTransaction"]["content"]["from"],
        )

        validators = {
            "0x"
            + ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
            .public_key()
            .public_bytes_raw()
            .hex()
            for seed in fixture["seeds"]["dahrValidators"]
        }
        self.assertEqual(validators, PINNED_DAHR_VALIDATORS)

    def test_dahr_binding_mutations_are_rejected(self):
        def request(fixture):
            return fixture["dahr"]["signedTransaction"]["content"]["data"][1]["message"]["web2Request"]["raw"]

        def response(fixture):
            return fixture["dahr"]["signedTransaction"]["content"]["data"][1]["message"]["web2Request"]["result"]

        mutations = [
            lambda f: request(f).__setitem__("url", "https://attacker.invalid/status"),
            lambda f: request(f).__setitem__("method", "POST"),
            lambda f: response(f).__setitem__("status", 202),
            lambda f: response(f).__setitem__("responseHash", "00" * 32),
            lambda f: response(f).__setitem__("responseHeadersHash", "00" * 32),
            lambda f: f["provider"].__setitem__("statusResponseBytes", "{}"),
            lambda f: f["provider"]["statusProjection"].__setitem__(
                "status", "failed"
            ),
            lambda f: f["provider"]["statusProjection"]["metadata"].__setitem__(
                "dacs_job_id", "01K4AP2PAY0000000000000005"
            ),
            lambda f: f["provider"]["statusProjection"].__setitem__(
                "amount", 49
            ),
            lambda f: f["provider"]["statusProjection"].__setitem__(
                "amount_received", 49
            ),
            lambda f: f["provider"]["statusProjection"].__setitem__(
                "currency", "eur"
            ),
            lambda f: f["dahr"]["signedTransaction"]["signature"].__setitem__("data", "0x" + "00" * 64),
            lambda f: f["dahr"]["canonicalTransaction"].__setitem__("status", "pending"),
            lambda f: f["dahr"]["block"].__setitem__("status", "pending"),
            lambda f: f["dahr"]["block"]["content"].__setitem__("ordered_transactions", []),
            lambda f: f["dahr"]["block"]["validationData"].__setitem__("signatures", {}),
            lambda f: f["evidence"]["paymentTxRefs"][0]["receiptAttestation"].__setitem__("contentHash", "00" * 32),
            lambda f: f["evidence"]["paymentTxRefs"][0]["receiptTransactionRef"].__setitem__("value", "00" * 32),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                fixture = copy.deepcopy(self.fixture)
                mutate(fixture)
                self.assertFalse(dahr_snapshot_valid(fixture))
                self.assert_rejected_before_effects(fixture)

    def test_self_certified_validator_set_is_not_a_trust_anchor(self):
        fixture = copy.deepcopy(self.fixture)
        block = fixture["dahr"]["block"]
        attacker_keys = [
            ed25519.Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
            for seed in (1, 2, 3)
        ]
        attacker_signers = [
            "0x"
            + key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            .hex()
            for key in attacker_keys
        ]
        block["content"]["peerlist"] = attacker_signers
        block_hash = hashlib.sha256(
            json.dumps(
                block["content"], separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        block["hash"] = block_hash
        block["validationData"]["signatures"] = {
            signer: "0x" + key.sign(block_hash.encode("ascii")).hex()
            for signer, key in zip(attacker_signers, attacker_keys)
        }
        self.assertFalse(dahr_snapshot_valid(fixture))
        self.assert_rejected_before_effects(fixture)

    def test_resigned_cross_artifact_mismatches_fail_the_authenticated_join(self):
        mutations = [
            (
                "job",
                lambda f: f["evidence"].__setitem__(
                    "jobId", "01K4AP2PAY0000000000000005"
                ),
            ),
            (
                "phase",
                lambda f: f["evidence"].__setitem__("phase", "pay-x402"),
            ),
            (
                "outcome",
                lambda f: f["evidence"].__setitem__("outcome", "failure"),
            ),
            (
                "amount",
                lambda f: f["evidence"]["paymentAmount"].__setitem__(
                    "amount", "0.6"
                ),
            ),
            (
                "currency",
                lambda f: f["evidence"]["paymentAmount"].__setitem__(
                    "currency", "EUR"
                ),
            ),
            (
                "mandate",
                lambda f: f["evidence"]["paymentTxRefs"][0].__setitem__(
                    "mandateId", "A" * 43
                ),
            ),
            (
                "protocol",
                lambda f: f["evidence"]["paymentTxRefs"][0].__setitem__(
                    "protocolVersion", "0.3"
                ),
            ),
            (
                "provider-reference",
                lambda f: f["evidence"]["paymentTxRefs"][0].__setitem__(
                    "providerRef", "pi_other"
                ),
            ),
        ]
        for name, mutate in mutations:
            with self.subTest(name=name):
                fixture = copy.deepcopy(self.fixture)
                mutate(fixture)
                resign_settlement_evidence(fixture)
                self.assertTrue(
                    signed_settlement_evidence_valid(fixture),
                    "mutation must have a current valid signature and hash",
                )
                self.assert_rejected_before_effects(fixture)

    def test_authenticated_agreement_mismatches_fail_before_effects(self):
        mutations = [
            lambda f: f["agreement"].__setitem__("payeeId", "acct_other"),
            lambda f: f["agreement"].__setitem__("amount", "0.6"),
            lambda f: f["agreement"].__setitem__("currency", "EUR"),
            lambda f: f["agreement"].__setitem__("agreementHash", "00" * 32),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                fixture = copy.deepcopy(self.fixture)
                mutate(fixture)
                self.assertTrue(signed_settlement_evidence_valid(fixture))
                self.assert_rejected_before_effects(fixture)

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
        self.assertEqual(signature["signer"], PINNED_ORCHESTRATOR)
        self.assertTrue(signed_settlement_evidence_valid(fixture))

    def test_expected_assertions_are_all_positive(self):
        expected = self.fixture["expected"]
        self.assertEqual(expected["verdict"], "pass")
        self.assertTrue(all(value is True for key, value in expected.items() if key != "verdict"))


if __name__ == "__main__":
    unittest.main()
