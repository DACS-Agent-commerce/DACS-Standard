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
PINNED_PRESENTATION_SHA256 = {
    "checkoutPresentation": "f2201c046ff35aac543135a32afaffad96575c3a0c3b34ae1ecb6f21734df53b",
    "paymentPresentation": "b8c8508da7744db1782f0baffd3361324b660e855e610cb476954812836c836a",
}
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
PINNED_CURRENCY_MINOR_UNITS = {"USD": 2}
PINNED_BUYER = (
    "key:ae092bdbc6ab347a6399e210c2eb6114a1d1088478098504b66ed57326d603b7"
)
PINNED_BUYER_PUBLIC_KEY = "rgkr28arNHpjmeIQwuthFKHRCIR4CYUEtm7VcybWA7c"
PINNED_SELLER = (
    "key:acbc3dd927d43e48ad57d2a05638985261baf5cdf8d3f3b30f3284663d3fc52c"
)
PINNED_SELLER_PUBLIC_KEY = "rLw92SfUPkitV9KgVjiYUmG69c340_OzDzKEZj0_xSw"
PINNED_PUBLIC_KEYS = {
    PINNED_ORCHESTRATOR: PINNED_ORCHESTRATOR_PUBLIC_KEY,
    PINNED_BUYER: PINNED_BUYER_PUBLIC_KEY,
    PINNED_SELLER: PINNED_SELLER_PUBLIC_KEY,
}
ULID_RE = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}\Z")
BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]+\Z")
PINNED_DAHR_WRITER = (
    "0x6ee091fd280a9b68554fa73c588125d47d3425c68a26ba236b4dad90f90a8f92"
)
PINNED_DAHR_TX_HASH = "a1f54b3cf02b088104499e9a729f637bba0086737e0c6324a10151f97c761bfd"
PINNED_DAHR_BLOCK = {
    "number": 213605,
    "hash": "2e0d7991276b4451def4178e261e38a473011d49a3b15650d6c2582c8efc6ed6",
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


def canonical_hash(value) -> str:
    return hashlib.sha256(jcs.canonicalize(value).encode("utf-8")).hexdigest()


def without_field(value: dict, field: str) -> dict:
    unsigned = copy.deepcopy(value)
    unsigned.pop(field)
    return unsigned


def ed25519_signature_valid(public_key: str, signature: str, payload: bytes) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(b64url(public_key)).verify(
            b64url(signature), payload
        )
        return True
    except Exception:
        return False


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


def authenticated_payment_authority(fixture: dict):
    """Verify the signed Listing/PBAD chain and return its sole payment tuple."""
    try:
        if fixture["publicKeys"] != PINNED_PUBLIC_KEYS:
            return None

        listing = fixture["listing"]
        if not (listing.get("dacsVersion") == "1"
                and type(listing.get("listingVersion")) is int
                and listing["listingVersion"] == 1):
            return None
        listing_signature = listing["signature"]
        if (
            listing_signature.get("algorithm") != "ed25519"
            or listing_signature.get("signer") != PINNED_SELLER
            or set(listing_signature) != {"algorithm", "signer", "value"}
        ):
            return None
        listing_unsigned = without_field(listing, "signature")
        listing_hash = canonical_hash(listing_unsigned)
        if not ed25519_signature_valid(
            PINNED_SELLER_PUBLIC_KEY,
            listing_signature["value"],
            b"dacs-listing:v1:" + listing_hash.encode("ascii"),
        ):
            return None

        seller_identity = listing["seller"]["identity"]
        seller_claims = seller_identity["claims"]
        presentation = seller_identity["presentation"]
        if not (
            seller_identity.get("bundleVersion") == "1"
            and type(seller_identity.get("presentedAt")) is int
            and seller_identity["presentedAt"] > 0
            and seller_identity["presentedBy"] == PINNED_SELLER
            and seller_claims == [{"ref": PINNED_SELLER}]
            and presentation.get("kind") == "per-claim"
            and presentation.get("signatures")
            == [{"ref": PINNED_SELLER, "signature": presentation["signatures"][0]["signature"]}]
            and listing_signature["signer"]
            in {claim.get("ref") for claim in seller_claims}
        ):
            return None
        identity_hash = canonical_hash(without_field(seller_identity, "presentation"))
        if not ed25519_signature_valid(
            PINNED_SELLER_PUBLIC_KEY,
            presentation["signatures"][0]["signature"],
            b"dacs-bundle-presentation:v1:" + identity_hash.encode("ascii"),
        ):
            return None

        agreement = fixture["agreement"]
        if not (
            agreement.get("payeeBoundAgreementVersion") == "1"
            and "agreementVersion" not in agreement
            and ULID_RE.fullmatch(agreement["jobId"])
            and agreement.get("derivedFromPattern") == "fixed-price"
        ):
            return None
        agreement_unsigned = without_field(agreement, "signatures")
        agreement_hash = canonical_hash(agreement_unsigned)

        parties = agreement["parties"]
        party_claims = {
            party["role"]: party["primaryClaim"]
            for party in parties
            if isinstance(party, dict)
            and party.get("role") in {"buyer", "seller"}
        }
        if len(parties) != 2 or party_claims != {
            "buyer": PINNED_BUYER,
            "seller": PINNED_SELLER,
        }:
            return None
        for party in parties:
            vet_ref = party.get("vetRecordRef", {})
            anchor = vet_ref.get("anchor", {})
            if not (
                re.fullmatch(r"[0-9a-f]{64}", party.get("bundleHash", ""))
                and re.fullmatch(r"[0-9a-f]{64}", vet_ref.get("contentHash", ""))
                and anchor.get("kind") == "storage-program"
                and isinstance(anchor.get("locator"), str)
                and anchor["locator"]
            ):
                return None
            if party["role"] == "seller" and party["bundleHash"] != identity_hash:
                return None
        signatures = agreement["signatures"]
        if not isinstance(signatures, list) or len(signatures) != 2:
            return None
        signature_by_party = {}
        for signature in signatures:
            if (
                not isinstance(signature, dict)
                or set(signature) != {"party", "algorithm", "value"}
                or signature.get("algorithm") != "ed25519"
                or signature.get("party") in signature_by_party
            ):
                return None
            signature_by_party[signature["party"]] = signature["value"]
        if set(signature_by_party) != {PINNED_BUYER, PINNED_SELLER}:
            return None
        agreement_payload = (
            b"dacs-payee-bound-agreement:v1:" + agreement_hash.encode("ascii")
        )
        if not all(
            ed25519_signature_valid(
                PINNED_PUBLIC_KEYS[party], signature_by_party[party], agreement_payload
            )
            for party in (PINNED_BUYER, PINNED_SELLER)
        ):
            return None

        listing_ref = agreement["listingRef"]
        if listing_ref != {
            "listingId": listing["listingId"],
            "version": listing["listingVersion"],
            "contentHash": listing_hash,
        }:
            return None
        # This retrospective fixture has one exact ordinary payment pipeline.
        # Restricting its shape avoids presenting this helper as a generic validator.
        pipeline = listing["pipeline"]
        if pipeline != [
            {"kind": "vet-credentials"},
            {"kind": "negotiate-fixed-price"},
            {"kind": "commit-payee-bound-agreement"},
            {"kind": "pay-ap2", "parameters": {"rail": pipeline[3]["parameters"]["rail"]}},
            {"kind": "deliver-storage-program"},
        ]:
            return None
        phase_index, payment_phase = 3, pipeline[3]
        payment_phases = [(phase_index, payment_phase)]
        rail_id = payment_phase.get("parameters", {}).get("rail")
        if not isinstance(rail_id, str) or not rail_id:
            return None
        terms = agreement["terms"]
        selected_rail = terms["rail"]
        if not (
            selected_rail.get("railId") == rail_id
            and selected_rail in listing["acceptedRails"]
            and terms["price"] == listing["pricing"]["price"]
        ):
            return None
        deliverable = listing["offering"]["deliverable"]
        expected_deliverable_ref = {
            "deliverableType": deliverable["kind"],
            "hash": canonical_hash(deliverable),
        }
        if "schemaUrl" in deliverable:
            expected_deliverable_ref["schemaUrl"] = deliverable["schemaUrl"]
        if terms["deliverable"] != expected_deliverable_ref:
            return None

        payouts = terms["payoutBindings"]
        if not isinstance(payouts, list) or len(payouts) != len(payment_phases):
            return None
        payout_by_tuple = {}
        for payout in payouts:
            if (
                not isinstance(payout, dict)
                or set(payout) != {"railId", "phaseIndex", "payeeAddress"}
                or type(payout.get("phaseIndex")) is not int
                or not isinstance(payout.get("railId"), str)
                or not isinstance(payout.get("payeeAddress"), str)
                or not payout["payeeAddress"]
            ):
                return None
            key = (payout["railId"], payout["phaseIndex"])
            if key in payout_by_tuple:
                return None
            payout_by_tuple[key] = payout["payeeAddress"]
        expected_keys = {
            (phase["parameters"]["rail"], index)
            for index, phase in payment_phases
        }
        if set(payout_by_tuple) != expected_keys:
            return None

        price = terms["price"]
        currency = price["currency"]
        if currency not in PINNED_CURRENCY_MINOR_UNITS:
            return None
        return {
            "agreementHash": agreement_hash,
            "amount": price["amount"],
            "currency": currency,
            "currencyMinorUnits": PINNED_CURRENCY_MINOR_UNITS[currency],
            "jobId": agreement["jobId"],
            "payeeAddress": payout_by_tuple[(rail_id, phase_index)],
            "phaseIndex": phase_index,
            "railId": rail_id,
        }
    except Exception:
        return None


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
        if fixture["publicKeys"] != PINNED_PUBLIC_KEYS:
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
        authority = authenticated_payment_authority(fixture)
        if authority is None:
            return False
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
        if writer != PINNED_DAHR_WRITER:
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
        expected_minor = Decimal(authority["amount"]) * (
            Decimal(10) ** authority["currencyMinorUnits"]
        )
        if expected_minor != expected_minor.to_integral_value():
            return False
        if not (
            status_projection["object"] == "payment_intent"
            and status_projection["status"] == "succeeded"
            and status_projection["id"] == payment_ref["providerRef"]
            and status_projection["amount"] == int(expected_minor)
            and status_projection["amount_received"] == int(expected_minor)
            and status_projection["currency"].upper() == authority["currency"]
            and status_projection["metadata"]["dacs_job_id"] == authority["jobId"]
            and status_projection["metadata"]["dacs_agreement_hash"]
            == authority["agreementHash"]
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

        presentation = request["presentation"]
        if {
            name: hashlib.sha256(value.encode("utf-8")).hexdigest()
            for name, value in presentation.items()
        } != PINNED_PRESENTATION_SHA256:
            return False

        authority = authenticated_payment_authority(fixture)
        if authority is None:
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
        minor_units = authority["currencyMinorUnits"]
        if type(minor_units) is not int or minor_units < 0:
            return False
        expected_minor = Decimal(authority["amount"]) * (
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
            f"{authority['jobId']}:"
            f"{quote(authority['railId'], safe='')}:"
            f"{authority['phaseIndex']}"
        )

        return (
            payment_mandate.transaction_id == transaction_id
            and checkout_mandate.checkout_hash == transaction_id
            and payment_mandate.payee.id == authority["payeeAddress"]
            and payment_mandate.payment_amount.amount == expected_minor_int
            and payment_mandate.payment_amount.currency == authority["currency"]
            and checkout["merchant"]["id"] == payment_mandate.payee.id
            and checkout["currency"] == payment_mandate.payment_amount.currency
            and checkout["totals"][-1]
            == {"type": "total", "amount": expected_minor_int}
            and evidence["jobId"] == authority["jobId"]
            and evidence["phase"] == "pay-ap2"
            and evidence["outcome"] == "success"
            and evidence["paymentAmount"]
            == {"amount": authority["amount"], "currency": authority["currency"]}
            and evidence["settlementFinality"]["model"] == "provider-receipt"
            and tx_ref["kind"] == "ap2-sr3"
            and tx_ref["mandateId"] == mandate_id
            and tx_ref["protocolVersion"] == PINNED_AP2_PROTOCOL_VERSION
            and tx_ref["providerRef"] == status["id"]
            and status["status"] == "succeeded"
            and status["amount"] == expected_minor_int
            and status["amount_received"] == expected_minor_int
            and status["currency"].upper() == authority["currency"]
            and status["metadata"]["dacs_job_id"] == authority["jobId"]
            and status["metadata"]["dacs_agreement_hash"]
            == authority["agreementHash"]
            and fixture["result"]["ok"] is True
            and fixture["result"]["attestationRef"]["anchor"]
            == {"kind": "storage-program", "locator": expected_evidence_anchor}
        )
    except Exception:
        return False


def derived_agreement_private_key(fixture: dict, role: str):
    """Derive fixture-only party keys from the already-published synthetic seeds."""
    source, label = {
        "buyer": ("orchestrator", b"dacs-ap2-reference:v2:agreement-buyer"),
        "seller": ("dahrWriter", b"dacs-ap2-reference:v2:agreement-seller"),
    }[role]
    seed = bytes.fromhex(fixture["seeds"][source])
    derived_seed = hashlib.sha256(label + b":" + seed).digest()
    return ed25519.Ed25519PrivateKey.from_private_bytes(derived_seed)


def sign_canonical_hash(private_key, domain: bytes, unsigned) -> str:
    digest = canonical_hash(unsigned)
    return b64url_encode(private_key.sign(domain + digest.encode("ascii")))


def regenerate_synthetic_fixture_authority(fixture: dict) -> None:
    """Refresh only the synthetic DACS/provider/DAHR side of the public fixture."""
    buyer_private = derived_agreement_private_key(fixture, "buyer")
    seller_private = derived_agreement_private_key(fixture, "seller")
    orchestrator_private = ed25519.Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(fixture["seeds"]["orchestrator"])
    )
    if {
        "buyer": b64url_encode(buyer_private.public_key().public_bytes_raw()),
        "seller": b64url_encode(seller_private.public_key().public_bytes_raw()),
        "orchestrator": b64url_encode(
            orchestrator_private.public_key().public_bytes_raw()
        ),
    } != {
        "buyer": PINNED_BUYER_PUBLIC_KEY,
        "seller": PINNED_SELLER_PUBLIC_KEY,
        "orchestrator": PINNED_ORCHESTRATOR_PUBLIC_KEY,
    }:
        raise ValueError("public fixture seeds do not reproduce pinned authority keys")

    fixture["fixtureVersion"] = "2"
    fixture["provenance"] = {
        "officialAp2Repository": "https://github.com/google-agentic-commerce/AP2",
        "officialAp2Commit": OFFICIAL_AP2_COMMIT,
        "generator": (
            "official AP2 Python SDK MandateClient + deterministic DACS "
            "signed-authority refresh"
        ),
        "fixtureGeneratedAt": "2026-09-02T09:10:38Z",
        "syntheticAuthorityRefreshedAt": "2026-09-07T00:00:00Z",
        "officialPresentationSha256": copy.deepcopy(PINNED_PRESENTATION_SHA256),
        "note": (
            "The original official AP2 presentations and JWKs are retained "
            "byte-for-byte. The signed Listing, co-signed PayeeBoundAgreementDocument, "
            "provider response, Demos wire evidence, and SettlementEvidence are "
            "deterministic public conformance replay data regenerated from the "
            "published fixture seeds; this is not a live-network or production-provider "
            "receipt, and no production secret is included."
        ),
    }
    fixture["publicKeys"] = copy.deepcopy(PINNED_PUBLIC_KEYS)

    seller_identity_unsigned = {
        "bundleVersion": "1",
        "presentedBy": PINNED_SELLER,
        "presentedAt": 1788340200000,
        "claims": [{"ref": PINNED_SELLER}],
    }
    seller_identity = copy.deepcopy(seller_identity_unsigned)
    seller_identity["presentation"] = {
        "kind": "per-claim",
        "signatures": [
            {
                "ref": PINNED_SELLER,
                "signature": sign_canonical_hash(
                    seller_private,
                    b"dacs-bundle-presentation:v1:",
                    seller_identity_unsigned,
                ),
            }
        ],
    }
    deliverable = {
        "kind": "storage-program",
        "schemaUrl": "https://example.invalid/dacs/ap2-reference-result.schema.json",
        "expectedSizeBytes": 50,
        "accessModel": "public",
    }
    rail_ref = {
        "railId": "ap2:stripe-paymentintents",
        "railVersion": 1,
    }
    listing_unsigned = {
        "dacsVersion": "1",
        "listingVersion": 1,
        "listingId": "dacs-ap2-reference-settlement",
        "seller": {
            "identity": seller_identity,
            "displayName": "DACS AP2 Reference Seller",
        },
        "offering": {
            "title": "DACS AP2 reference settlement",
            "description": "Deterministic public AP2 settlement replay fixture.",
            "category": "reference.conformance.settlement",
            "tags": ["ap2", "conformance"],
            "deliverable": deliverable,
        },
        "buyerRequirement": {
            "requirementVersion": "1",
            "required": [{"scheme": "key", "verificationRequired": False}],
        },
        "pipeline": [
            {"kind": "vet-credentials"},
            {"kind": "negotiate-fixed-price"},
            {"kind": "commit-payee-bound-agreement"},
            {
                "kind": "pay-ap2",
                "parameters": {"rail": rail_ref["railId"]},
            },
            {"kind": "deliver-storage-program"},
        ],
        "pricing": {
            "kind": "fixed",
            "price": {"amount": "0.5", "currency": "USD"},
        },
        "acceptedRails": [copy.deepcopy(rail_ref)],
        "terms": {
            "deadlineSecAfterCommit": 3600,
            "cancellationPolicy": "pre-commit",
        },
        "validity": {
            "notBefore": 1788336600000,
            "notAfter": 1788426600000,
        },
    }
    listing = copy.deepcopy(listing_unsigned)
    listing["signature"] = {
        "algorithm": "ed25519",
        "signer": PINNED_SELLER,
        "value": sign_canonical_hash(
            seller_private, b"dacs-listing:v1:", listing_unsigned
        ),
    }
    fixture["listing"] = listing
    listing_hash = canonical_hash(listing_unsigned)

    buyer_bundle_hash = canonical_hash(
        {
            "bundleVersion": "1",
            "presentedBy": PINNED_BUYER,
            "presentedAt": 1788340200000,
            "claims": [{"ref": PINNED_BUYER}],
        }
    )
    seller_bundle_hash = canonical_hash(seller_identity_unsigned)
    agreement_unsigned = {
        "payeeBoundAgreementVersion": "1",
        "jobId": "01K4AP2PAY0000000000000004",
        "listingRef": {
            "listingId": listing["listingId"],
            "version": listing["listingVersion"],
            "contentHash": listing_hash,
        },
        "parties": [
            {
                "role": "buyer",
                "bundleHash": buyer_bundle_hash,
                "primaryClaim": PINNED_BUYER,
                "vetRecordRef": {
                    "anchor": {
                        "kind": "storage-program",
                        "locator": "dacs2:composite:ap2-reference:buyer",
                    },
                    "contentHash": hashlib.sha256(
                        b"dacs-ap2-reference:v2:buyer-vet"
                    ).hexdigest(),
                },
            },
            {
                "role": "seller",
                "bundleHash": seller_bundle_hash,
                "primaryClaim": PINNED_SELLER,
                "vetRecordRef": {
                    "anchor": {
                        "kind": "storage-program",
                        "locator": "dacs2:composite:ap2-reference:seller",
                    },
                    "contentHash": hashlib.sha256(
                        b"dacs-ap2-reference:v2:seller-vet"
                    ).hexdigest(),
                },
            },
        ],
        "terms": {
            "deliverable": {
                "deliverableType": deliverable["kind"],
                "hash": canonical_hash(deliverable),
                "schemaUrl": deliverable["schemaUrl"],
            },
            "price": copy.deepcopy(listing["pricing"]["price"]),
            "rail": copy.deepcopy(rail_ref),
            "deadline": 1788343838797,
            "payoutBindings": [
                {
                    "railId": rail_ref["railId"],
                    "phaseIndex": 3,
                    "payeeAddress": "acct_dacs_reference",
                }
            ],
        },
        "derivedFromPattern": "fixed-price",
        "generatedAt": 1788340228797,
    }
    agreement_hash = canonical_hash(agreement_unsigned)
    agreement_payload = (
        b"dacs-payee-bound-agreement:v1:" + agreement_hash.encode("ascii")
    )
    agreement = copy.deepcopy(agreement_unsigned)
    agreement["signatures"] = [
        {
            "party": claim,
            "algorithm": "ed25519",
            "value": b64url_encode(private.sign(agreement_payload)),
        }
        for claim, private in (
            (PINNED_BUYER, buyer_private),
            (PINNED_SELLER, seller_private),
        )
    ]
    fixture["agreement"] = agreement

    provider_ref = "pi_dacs_reference"
    status_projection = {
        "amount": 50,
        "amount_received": 50,
        "currency": "usd",
        "id": provider_ref,
        "metadata": {
            "dacs_agreement_hash": agreement_hash,
            "dacs_job_id": agreement["jobId"],
        },
        "object": "payment_intent",
        "status": "succeeded",
    }
    response_bytes = jcs.canonicalize(status_projection)
    response_hash = hashlib.sha256(response_bytes.encode("utf-8")).hexdigest()
    provider = {
        "statusResource": (
            "https://provider.example/dacs/ap2/payment-status/" + provider_ref
        ),
        "statusProjection": status_projection,
        "statusResponseBytes": response_bytes,
        "projectionNote": (
            "statusResponseBytes is the exact replayable UTF-8 body committed by "
            "the DAHR responseHash. statusProjection MUST be parsed from those bytes "
            "without reserialisation and cannot be supplied independently."
        ),
        "statusResponseHash": response_hash,
        "statusResponseHeadersHash": fixture["provider"][
            "statusResponseHeadersHash"
        ],
        "attestedAnchorTxRef": "",
    }
    fixture["provider"] = provider

    dahr = fixture["dahr"]
    signed_transaction = dahr["signedTransaction"]
    content = signed_transaction["content"]
    content["from"] = PINNED_DAHR_WRITER
    content["to"] = PINNED_DAHR_WRITER
    content["from_ed25519_address"] = PINNED_DAHR_WRITER
    message = content["data"][1]["message"]
    raw_request = message["web2Request"]["raw"]
    response = message["web2Request"]["result"]
    raw_request["url"] = provider["statusResource"]
    response["targetUrl"] = provider["statusResource"]
    response["responseHash"] = response_hash
    response["responseHeadersHash"] = provider["statusResponseHeadersHash"]
    tx_hash = hashlib.sha256(
        json.dumps(content, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    writer_private = ed25519.Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(fixture["seeds"]["dahrWriter"])
    )
    if "0x" + writer_private.public_key().public_bytes_raw().hex() != PINNED_DAHR_WRITER:
        raise ValueError("public dahrWriter seed does not reproduce the pinned writer")
    signed_transaction["hash"] = tx_hash
    signed_transaction["signature"] = {
        "type": "ed25519",
        "data": "0x" + writer_private.sign(tx_hash.encode("ascii")).hex(),
    }
    dahr["canonicalTransaction"] = {
        "hash": tx_hash,
        "status": "confirmed",
        "blockNumber": dahr["block"]["number"],
    }
    block = dahr["block"]
    block["content"]["ordered_transactions"] = [tx_hash]
    validator_keys = [
        ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
        for seed in fixture["seeds"]["dahrValidators"]
    ]
    validator_ids = [
        "0x" + private.public_key().public_bytes_raw().hex()
        for private in validator_keys
    ]
    if set(validator_ids) != PINNED_DAHR_VALIDATORS:
        raise ValueError("public validator seeds do not reproduce the pinned roster")
    block["content"]["peerlist"] = validator_ids
    block_hash = hashlib.sha256(
        json.dumps(
            block["content"], separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()
    block["hash"] = block_hash
    block["status"] = "confirmed"
    block["validationData"] = {
        "signatures": {
            validator: "0x" + private.sign(block_hash.encode("ascii")).hex()
            for validator, private in zip(validator_ids, validator_keys)
        }
    }
    provider["attestedAnchorTxRef"] = tx_hash

    payment = fixture["officialAp2"]["verified"]["payment"]
    receipt_ref = {
        "kind": "ap2-sr3",
        "mandateId": payment["mandateId"],
        "protocolVersion": payment["protocolVersion"],
        "providerRef": provider_ref,
        "receiptAttestation": {
            "anchor": {
                "kind": "https",
                "locator": provider["statusResource"],
            },
            "contentHash": response_hash,
        },
        "receiptTransactionRef": {
            "kind": "demos-web2-request",
            "value": tx_hash,
        },
    }
    fixture["evidence"] = {
        "evidenceVersion": "1",
        "jobId": agreement["jobId"],
        "observedAt": 1788340250184,
        "outcome": "success",
        "paymentAmount": copy.deepcopy(agreement["terms"]["price"]),
        "paymentTxRefs": [receipt_ref],
        "phase": "pay-ap2",
        "settlementFinality": {
            "finalityObservedAt": 1788340250184,
            "model": "provider-receipt",
        },
        "signature": {
            "algorithm": "ed25519",
            "signer": PINNED_ORCHESTRATOR,
            "value": "",
        },
    }
    fixture["result"] = {
        "ok": True,
        "txRefs": [copy.deepcopy(receipt_ref)],
        "attestationRef": {
            "anchor": {
                "kind": "storage-program",
                "locator": (
                    "dacs4:payment:"
                    f"{agreement['jobId']}:"
                    f"{quote(rail_ref['railId'], safe='')}:3"
                ),
            },
            "contentHash": "",
        },
    }
    resign_settlement_evidence(fixture)
    fixture["expected"] = {
        "officialMandatesVerify": True,
        "transactionIdMatchesCheckoutJws": True,
        "merchantCheckoutSignatureVerifies": True,
        "listingSignatureVerifies": True,
        "agreementSignaturesVerify": True,
        "agreementHashMatchesCanonicalArtifact": True,
        "paymentTupleMatchesSignedAuthority": True,
        "providerStatusBindsSession": True,
        "providerStatusBindsAgreement": True,
        "providerStatusMatchesAmountCurrency": True,
        "providerResponseBytesBindProjection": True,
        "jobIdIsCanonicalUlid": True,
        "receiptAttestationMatchesDahrCommitment": True,
        "dahrTransactionHashVerifies": True,
        "dahrTransactionSignatureVerifies": True,
        "dahrRequestResponseBindingVerifies": True,
        "dahrTransactionIncluded": True,
        "dahrBlockConfirmed": True,
        "dahrValidatorSetUsesIndependentTrustAnchor": True,
        "dahrSelfCertifiedValidatorSetRejected": True,
        "settlementEvidenceVerifies": True,
        "verdict": "pass",
    }


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
        self.assertEqual(fixture["fixtureVersion"], "2")
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
        presentation_hashes = {
            name: hashlib.sha256(value.encode("utf-8")).hexdigest()
            for name, value in request["presentation"].items()
        }
        self.assertEqual(presentation_hashes, PINNED_PRESENTATION_SHA256)
        self.assertEqual(
            fixture["provenance"]["officialPresentationSha256"],
            PINNED_PRESENTATION_SHA256,
        )
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
        authority = authenticated_payment_authority(fixture)
        self.assertIsNotNone(authority)
        self.assertEqual(payload["merchant"]["id"], authority["payeeAddress"])
        self.assertEqual(payload["currency"], authority["currency"])
        self.assertEqual(payload["totals"][-1]["amount"], 50)

    def test_signed_listing_and_agreement_authenticate_the_complete_payment_tuple(self):
        authority = authenticated_payment_authority(self.fixture)
        self.assertIsNotNone(authority)
        self.assertEqual(
            authority,
            {
                "agreementHash": canonical_hash(
                    without_field(self.fixture["agreement"], "signatures")
                ),
                "amount": "0.5",
                "currency": "USD",
                "currencyMinorUnits": 2,
                "jobId": "01K4AP2PAY0000000000000004",
                "payeeAddress": "acct_dacs_reference",
                "phaseIndex": 3,
                "railId": "ap2:stripe-paymentintents",
            },
        )
        self.assertEqual(
            self.fixture["provider"]["statusProjection"]["metadata"][
                "dacs_agreement_hash"
            ],
            authority["agreementHash"],
        )

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
        authority = authenticated_payment_authority(fixture)
        self.assertIsNotNone(authority)
        provider = fixture["provider"]
        status = provider["statusProjection"]
        response_bytes = provider["statusResponseBytes"]
        self.assertEqual(parse_json_without_duplicate_keys(response_bytes), status)
        self.assertEqual(
            hashlib.sha256(response_bytes.encode("utf-8")).hexdigest(),
            provider["statusResponseHash"],
        )
        self.assertTrue(fixture["expected"]["providerResponseBytesBindProjection"])
        self.assertRegex(authority["jobId"], ULID_RE)
        self.assertEqual(status["status"], "succeeded")
        self.assertEqual(status["metadata"]["dacs_job_id"], authority["jobId"])
        self.assertEqual(
            status["metadata"]["dacs_agreement_hash"],
            authority["agreementHash"],
        )
        self.assertEqual(status["id"], fixture["evidence"]["paymentTxRefs"][0]["providerRef"])
        self.assertEqual(status["currency"].upper(), authority["currency"])
        minor = Decimal(authority["amount"]) * (
            Decimal(10) ** authority["currencyMinorUnits"]
        )
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
        self.assertEqual(writer_id, PINNED_DAHR_WRITER)

        self.assertEqual(
            b64url_encode(
                derived_agreement_private_key(fixture, "buyer")
                .public_key()
                .public_bytes_raw()
            ),
            PINNED_BUYER_PUBLIC_KEY,
        )
        self.assertEqual(
            b64url_encode(
                derived_agreement_private_key(fixture, "seller")
                .public_key()
                .public_bytes_raw()
            ),
            PINNED_SELLER_PUBLIC_KEY,
        )
        self.assertEqual(fixture["publicKeys"], PINNED_PUBLIC_KEYS)

        validators = {
            "0x"
            + ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
            .public_key()
            .public_bytes_raw()
            .hex()
            for seed in fixture["seeds"]["dahrValidators"]
        }
        self.assertEqual(validators, PINNED_DAHR_VALIDATORS)

    def test_synthetic_authority_regeneration_is_byte_stable(self):
        regenerated = copy.deepcopy(self.fixture)
        presentations = copy.deepcopy(
            regenerated["officialAp2"]["request"]["presentation"]
        )
        regenerate_synthetic_fixture_authority(regenerated)
        self.assertEqual(
            regenerated["officialAp2"]["request"]["presentation"],
            presentations,
        )
        self.assertEqual(regenerated, self.fixture)

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
            lambda f: f["agreement"]["terms"]["payoutBindings"][0].__setitem__(
                "payeeAddress", "acct_other"
            ),
            lambda f: f["agreement"]["terms"]["price"].__setitem__(
                "amount", "0.6"
            ),
            lambda f: f["agreement"]["terms"]["price"].__setitem__(
                "currency", "EUR"
            ),
            lambda f: f["agreement"]["listingRef"].__setitem__(
                "contentHash", "00" * 32
            ),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                fixture = copy.deepcopy(self.fixture)
                mutate(fixture)
                self.assertTrue(signed_settlement_evidence_valid(fixture))
                self.assert_rejected_before_effects(fixture)

    def test_resigned_nonconforming_authority_is_rejected(self):
        mutations = [
            lambda f: f["listing"]["pipeline"].pop(),
            lambda f: f["listing"]["pipeline"].append({"kind": "pay-alternative"}),
            lambda f: f["listing"]["pipeline"].insert(2, {"kind": "negotiate-fixed-price"}),
            lambda f: f["listing"]["pipeline"].insert(2, {"kind": "commit-agreement"}),
            lambda f: f["listing"].__setitem__("dacsVersion", "2"),
            lambda f: f["listing"].__setitem__("listingVersion", True),
            lambda f: f["listing"]["seller"]["identity"].__setitem__("bundleVersion", "2"),
            lambda f: f["listing"]["seller"]["identity"].pop("presentedAt"),
            lambda f: f["agreement"]["parties"][1].__setitem__("bundleHash", "00" * 32),
            lambda f: f["agreement"]["parties"][0].pop("vetRecordRef"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                fixture = copy.deepcopy(self.fixture)
                mutate(fixture)
                seller_key = derived_agreement_private_key(fixture, "seller")
                identity = fixture["listing"]["seller"]["identity"]
                identity["presentation"]["signatures"][0]["signature"] = sign_canonical_hash(
                    seller_key, b"dacs-bundle-presentation:v1:",
                    without_field(identity, "presentation"),
                )
                listing = fixture["listing"]
                unsigned_listing = without_field(listing, "signature")
                listing["signature"]["value"] = sign_canonical_hash(
                    seller_key, b"dacs-listing:v1:", unsigned_listing,
                )
                agreement = fixture["agreement"]
                agreement["listingRef"]["contentHash"] = canonical_hash(unsigned_listing)
                agreement["listingRef"]["version"] = listing["listingVersion"]
                for role, signature in zip(("buyer", "seller"), agreement["signatures"]):
                    signature["value"] = sign_canonical_hash(
                        derived_agreement_private_key(fixture, role),
                        b"dacs-payee-bound-agreement:v1:",
                        without_field(agreement, "signatures"),
                    )
                self.assertIsNone(authenticated_payment_authority(fixture))
                self.assert_rejected_before_effects(fixture)

    def test_coordinated_rail_and_result_locator_mutation_fails_before_effects(self):
        fixture = copy.deepcopy(self.fixture)
        payout = fixture["agreement"]["terms"]["payoutBindings"][0]
        payout["railId"] = "ap2:visa-direct"
        fixture["result"]["attestationRef"]["anchor"]["locator"] = (
            "dacs4:payment:01K4AP2PAY0000000000000004:ap2%3Avisa-direct:3"
        )
        self.assertTrue(signed_settlement_evidence_valid(fixture))
        self.assertIsNone(authenticated_payment_authority(fixture))
        self.assert_rejected_before_effects(fixture)

    def test_coordinated_phase_and_result_locator_mutation_fails_before_effects(self):
        fixture = copy.deepcopy(self.fixture)
        payout = fixture["agreement"]["terms"]["payoutBindings"][0]
        payout["phaseIndex"] = 4
        fixture["result"]["attestationRef"]["anchor"]["locator"] = (
            "dacs4:payment:01K4AP2PAY0000000000000004:"
            "ap2%3Astripe-paymentintents:4"
        )
        self.assertTrue(signed_settlement_evidence_valid(fixture))
        self.assertIsNone(authenticated_payment_authority(fixture))
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
