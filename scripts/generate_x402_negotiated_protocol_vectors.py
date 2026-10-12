#!/usr/bin/env python3
"""Generate deterministic DACS-3/DACS-4 negotiated-x402 security vectors."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize as jcs_canonicalize
from evm_crypto import (
    deterministic_ecdsa_sha256,
    evm_address,
    keccak256,
    uncompressed_public_key,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance/vectors/security/x402-negotiated-protocol-v0.8.json"
SAFE_TX = "ab" * 32
# Upstream x402 EVM responses spell the transaction hash with 0x; settlementEvent
# keys use the canonical SB-1 form (SAFE_TX).
RESPONSE_TX = "0x" + SAFE_TX
URL = "https://seller.example/dacs/resource?job=274"
ASSET = "0x" + "33" * 20
EVM_BUYER_PRIVATE_SCALAR = 1
EVM_BUYER_PUBLIC_KEY = uncompressed_public_key(EVM_BUYER_PRIVATE_SCALAR)
BUYER_ADDRESS = evm_address(EVM_BUYER_PUBLIC_KEY)
SELLER_ADDRESS = "0x" + "22" * 20
# XN-5 address-case vectors need hex letters, which SELLER_ADDRESS lacks. These
# are EIP-55's first two examples, so their checksum spellings can be checked
# against the EIP.
LETTERED_SELLER = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
OTHER_LETTERED_ADDRESS = "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359"
SOLANA_NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
SOLANA_ASSET = "3" * 44
SOLANA_SELLER = "5" * 44
SOLANA_TX = "1" * 64
BUYER_CLAIM = "did:demos:agent:" + "11" * 32
SELLER_CLAIM = "did:demos:agent:" + "22" * 32
STEWARD_CLAIM = "did:demos:agent:" + "44" * 32
ORCHESTRATOR_CLAIM = "did:demos:agent:" + "55" * 32
BUYER_SESSION_NONCE = hashlib.sha256(
    b"01M0NVBGYEANE562QQXD33C7WX:buyer:x402"
).hexdigest()[:32]
SEEDS = {
    "buyer": hashlib.sha256(b"DACS #274 buyer").digest(),
    "seller": hashlib.sha256(b"DACS #274 seller").digest(),
    "steward": hashlib.sha256(b"DACS #274 steward").digest(),
    "orchestrator": hashlib.sha256(b"DACS #274 orchestrator").digest(),
}
SOLANA_BUYER_SEED = hashlib.sha256(b"DACS #274 buyer Solana payment key").digest()
CLAIMS = {
    "buyer": BUYER_CLAIM,
    "seller": SELLER_CLAIM,
    "steward": STEWARD_CLAIM,
    "orchestrator": ORCHESTRATOR_CLAIM,
}
CASE_META_FIELDS = {
    "name", "expected", "expectedReason", "rule", "operation", "note", "base",
}


def key(role: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(SEEDS[role])


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def base58(raw: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded
    zeroes = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * zeroes + (encoded or "1")


def solana_payment_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(SOLANA_BUYER_SEED)


def solana_public_key_bytes() -> bytes:
    return solana_payment_key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


SOLANA_BUYER = base58(solana_public_key_bytes())
# XN-5 Solana case vectors need a seller with letters, which SOLANA_SELLER lacks.
LETTERED_SOLANA_SELLER = base58(hashlib.sha256(b"DACS #274 lettered Solana seller").digest())


def public_key(role: str) -> str:
    return b64u(key(role).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ))


def digest(value: object) -> str:
    return hashlib.sha256(jcs_canonicalize(value).encode("utf-8")).hexdigest()


def sign(role: str, domain: str, unsigned: object) -> str:
    return b64u(key(role).sign((domain + digest(unsigned)).encode("ascii")))


def unsigned(value: dict, signature_field: str) -> dict:
    return {k: v for k, v in value.items() if k != signature_field}


def eip55(address: str) -> str:
    """The EIP-55 mixed-case checksum spelling of a 0x-prefixed EVM address."""
    digits = address[2:].lower()
    hashed = keccak256(digits.encode("ascii")).hex()
    return "0x" + "".join(
        char.upper() if int(nibble, 16) >= 8 else char
        for char, nibble in zip(digits, hashed)
    )


def payment_claim(network: str, address: str) -> str:
    family, subchain = network.split(":", 1)
    return f"cci-xm:{'evm' if family == 'eip155' else family}:{subchain}:{address}"


def buyer_bundle(network: str, address: str) -> dict:
    claim = payment_claim(network, address)
    if network.startswith("eip155:"):
        payment_metadata = {
            "algorithm": "ecdsa-secp256k1",
            "publicKey": EVM_BUYER_PUBLIC_KEY.hex(),
        }
    elif network.startswith("solana:"):
        payment_metadata = {
            "algorithm": "ed25519",
            "publicKey": b64u(solana_public_key_bytes()),
        }
    else:
        raise ValueError(f"no payment-key fixture for {network}")
    body = {
        "bundleVersion": "1",
        "presentedBy": BUYER_CLAIM,
        "presentedAt": 1787443199000,
        "sessionNonce": BUYER_SESSION_NONCE,
        "claims": [
            {"ref": BUYER_CLAIM, "metadata": {"testRole": "buyer"}},
            {"ref": claim, "metadata": payment_metadata},
        ],
    }
    payload = ("dacs-bundle-presentation:v1:" + digest(body)).encode("ascii")
    if network.startswith("eip155:"):
        payment_signature = deterministic_ecdsa_sha256(
            EVM_BUYER_PRIVATE_SCALAR, payload
        )
    else:
        payment_signature = solana_payment_key().sign(payload)
    return {
        **body,
        "presentation": {
            "kind": "per-claim",
            "signatures": [
                {
                    "ref": BUYER_CLAIM,
                    "signature": b64u(key("buyer").sign(payload)),
                },
                {"ref": claim, "signature": b64u(payment_signature)},
            ],
        },
    }


def payment_ref(version: int = 2) -> dict:
    ref = {
        "railId": "x402:protocol",
        "railVersion": 1,
        "parameters": {
            "request": {"method": "GET", "url": URL},
            "selection": {
                "x402Version": version,
                "scheme": "exact",
                "network": "eip155:8453",
                "asset": ASSET,
                "assetDecimals": 6,
                "currency": "USDC",
                "maxTimeoutSeconds": 60,
                "extra": {
                    "name": "USDC",
                    "version": "2",
                    "verifyingContract": "0x" + "66" * 20,
                },
            },
        },
    }
    if version == 2:
        ref["parameters"]["paymentRequiredExtensions"] = {
            "payment-identifier": {"required": True}
        }
    return ref


def requirement(version: int = 2) -> dict:
    common = {
        "scheme": "exact",
        "network": "eip155:8453",
        "payTo": SELLER_ADDRESS,
        "maxTimeoutSeconds": 60,
        "asset": ASSET,
        "extra": {
            "name": "USDC",
            "version": "2",
            "verifyingContract": "0x" + "66" * 20,
        },
    }
    if version == 1:
        return {
            **common,
            "maxAmountRequired": "1250000",
            "resource": URL,
            "description": "DACS #274 resource",
            "mimeType": "application/json",
            "outputSchema": {},
        }
    return {**common, "amount": "1250000"}


def payment_required(version: int = 2) -> dict:
    if version == 1:
        return {"x402Version": 1, "accepts": [requirement(1)]}
    return {
        "x402Version": 2,
        "resource": {
            "url": URL,
            "description": "DACS #274 resource",
            "mimeType": "application/json",
        },
        "accepts": [requirement(2)],
        "extensions": {"payment-identifier": {"required": True}},
    }


def settlement_response(version: int = 2) -> dict:
    response = {
        "success": True,
        "payer": BUYER_ADDRESS,
        "transaction": RESPONSE_TX,
        "network": "eip155:8453",
    }
    if version == 2:
        response["extensions"] = {"payment-identifier": "payment-274"}
    return response


def encoded_header(response: dict, version: int) -> dict:
    raw = json.dumps(response, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {
        "name": "X-PAYMENT-RESPONSE" if version == 1 else "PAYMENT-RESPONSE",
        "value": base64.b64encode(raw).decode("ascii"),
    }


def protocol_rail() -> dict:
    return {
        "railVersion": 1,
        "railId": "x402:protocol",
        "railType": "x402",
        "phaseHandler": "pay-x402",
        "resolution": {"kind": "x402-payment-required"},
        "availability": "live",
        "governance": {
            "proposedBy": STEWARD_CLAIM,
            "acceptedAt": 1787443200000,
            "anchoring": "single-signer",
        },
    }


def legacy_rail() -> dict:
    rail = legacy_live_rail()
    rail.update({
        "railVersion": 2,
        "availability": "disabled",
        "governance": {
            "proposedBy": STEWARD_CLAIM,
            "acceptedAt": 1787443200000,
            "supersedes": 1,
            "anchoring": "single-signer",
            "deprecated": True,
            "deprecationReason": "Use x402:protocol for new sessions",
        },
    })
    return rail


def legacy_live_rail() -> dict:
    return {
        "railVersion": 1,
        "railId": "x402:default",
        "railType": "x402",
        "asset": {
            "kind": "erc20",
            "chainId": 8453,
            "contract": ASSET,
            "symbol": "USDC",
            "decimals": 6,
        },
        "network": {"kind": "x402-resource", "resourceBaseUrl": URL},
        "phaseHandler": "pay-x402",
        "parameters": {"authorization": "eip-3009"},
        "availability": "live",
        "governance": {
            "proposedBy": STEWARD_CLAIM,
            "acceptedAt": 1787356800000,
            "anchoring": "single-signer",
        },
    }


def make_base(version: int = 2) -> dict:
    ref = payment_ref(version)
    response = settlement_response(version)
    event = f"evm:8453:{SAFE_TX}:7"
    bundle = buyer_bundle("eip155:8453", BUYER_ADDRESS)
    bundle_hash = digest(unsigned(bundle, "presentation"))
    value = {
        "railDefinition": protocol_rail(),
        "buyerBundle": bundle,
        "listing": {
            "dacsVersion": "1",
            "listingVersion": 1,
            "listingId": "x402-274",
            "acceptedRails": [copy.deepcopy(ref)],
        },
        "agreement": {
            "payeeBoundAgreementVersion": "1",
            "jobId": "01M0NVBGYEANE562QQXD33C7WX",
            "parties": [
                {"role": "buyer", "bundleHash": bundle_hash, "primaryClaim": BUYER_CLAIM},
                {"role": "seller", "bundleHash": "bb" * 32, "primaryClaim": SELLER_CLAIM},
            ],
            "terms": {
                "price": {"amount": "1.25", "currency": "USDC"},
                "rail": copy.deepcopy(ref),
                "payoutBindings": [{
                    "railId": "x402:protocol",
                    "phaseIndex": 3,
                    "payeeAddress": SELLER_ADDRESS,
                }],
            },
        },
        "runtime": {
            "phaseIndex": 3,
            "issuedBuyerSessionNonce": BUYER_SESSION_NONCE,
            "selectedRailRef": copy.deepcopy(ref),
            "payer": {
                "bundleHash": bundle_hash,
                "primaryClaim": BUYER_CLAIM,
                "payingKey": payment_claim("eip155:8453", BUYER_ADDRESS),
                "paymentAddress": BUYER_ADDRESS,
            },
            "payee": {"primaryClaim": SELLER_CLAIM, "payeeAddress": SELLER_ADDRESS},
            "requestBodyBase64": "",
            "effectiveUrl": URL,
            "redirected": False,
            "operatorConfigSource": "local-operator-policy",
            "authorizationSubmitted": False,
            "retryWouldAuthorize": False,
            "reconciliationState": {
                "jobId": "01M0NVBGYEANE562QQXD33C7WX",
                "phaseIndex": 3,
                "requirementHash": digest(ref),
                "authorizationIdentity": BUYER_ADDRESS,
                "settlementTransaction": RESPONSE_TX,
            },
        },
        "capability": {
            "supportedTuples": [[version, "exact", "eip155:8453"]],
            "bindingProfiles": ["dacs-x402-exact:v1"],
            "understoodActionExtensions": ["payment-identifier"],
            "assetMetadata": {
                "network": "eip155:8453",
                "asset": ASSET,
                "decimals": 6,
            },
        },
        "http": {
            "status": 402,
            "paymentRequired": payment_required(version),
            "responseHeader": encoded_header(response, version),
            "actionBearingExtensions": ["payment-identifier"] if version == 2 else [],
        },
        "ledger": {
            "available": True,
            "network": "eip155:8453",
            "transaction": RESPONSE_TX,
            "settlementEvent": event,
            "scheme": "exact",
            "asset": ASSET,
            "assetDecimals": 6,
            "amount": "1250000",
            "payer": BUYER_ADDRESS,
            "payTo": SELLER_ADDRESS,
            "authorization": "eip-3009",
            "sessionBound": True,
            "finalized": True,
        },
        "evidence": {
            "evidenceVersion": "1",
            "jobId": "01M0NVBGYEANE562QQXD33C7WX",
            "phase": "pay-x402",
            "outcome": "success",
            "paymentTxRefs": [{
                "kind": "x402-protocol",
                "httpResource": URL,
                "paymentRequiredHash": "",
                "paymentReceiptHash": "",
                "x402Version": version,
                "settlementNetwork": "eip155:8453",
                "settlementTransaction": RESPONSE_TX,
                "settlementEvent": event,
            }],
            "paymentAmount": {"amount": "1.25", "currency": "USDC"},
            "settlementFinality": {
                "model": "scheme-network-finality",
                "schemeNetworkFinality": {
                    "scheme": "exact",
                    "network": "eip155:8453",
                    "bindingProfile": "dacs-x402-exact:v1",
                },
                "finalityObservedAt": 1787443201000,
            },
            "observedAt": 1787443201000,
        },
        "keys": {role: public_key(role) for role in SEEDS},
    }
    refresh_received_hashes(value)
    sign_all(value)
    return value


def refresh_received_hashes(value: dict) -> None:
    required = value.get("http", {}).get("paymentRequired")
    header = value.get("http", {}).get("responseHeader")
    evidence = value.get("evidence", {})
    refs = evidence.get("paymentTxRefs", [])
    if isinstance(required, dict) and refs and refs[0].get("kind") == "x402-protocol":
        refs[0]["paymentRequiredHash"] = digest(required)
    if isinstance(header, dict) and refs and refs[0].get("kind") == "x402-protocol":
        try:
            response = json.loads(base64.b64decode(header["value"], validate=True))
        except Exception:
            return
        refs[0]["paymentReceiptHash"] = digest(response)


def sign_all(value: dict) -> None:
    rail = value.get("railDefinition")
    if isinstance(rail, dict):
        rail.pop("signature", None)
        rail["signature"] = {
            "algorithm": "ed25519",
            "signer": STEWARD_CLAIM,
            "value": sign("steward", "dacs-rail:v1:", rail),
        }
    listing = value.get("listing")
    if isinstance(listing, dict):
        listing.pop("signature", None)
        listing["signature"] = {
            "algorithm": "ed25519",
            "signer": SELLER_CLAIM,
            "value": sign("seller", "dacs-listing:v1:", listing),
        }
    agreement = value.get("agreement")
    if isinstance(agreement, dict):
        agreement.pop("signatures", None)
        payload = unsigned(agreement, "signatures")
        agreement["signatures"] = [
            {
                "party": CLAIMS[role],
                "algorithm": "ed25519",
                "value": sign(role, "dacs-payee-bound-agreement:v1:", payload),
            }
            for role in ("buyer", "seller")
        ]
    evidence = value.get("evidence")
    if isinstance(evidence, dict):
        evidence.pop("signature", None)
        evidence["signature"] = {
            "algorithm": "ed25519",
            "signer": ORCHESTRATOR_CLAIM,
            "value": sign("orchestrator", "dacs-evidence:v1:", evidence),
        }


def add_case(vectors: list, name: str, expected: str, rule: str, note: str,
             mutate=None, *, version: int = 2, operation: str = "execute",
             refresh: bool = False, reason: str | None = None,
             authorization_submitted: bool | None = None) -> None:
    value = make_base(version)
    if mutate:
        mutate(value)
    value["runtime"]["authorizationSubmitted"] = (
        operation == "execute" and expected == "pass"
        if authorization_submitted is None
        else authorization_submitted
    )
    if refresh:
        refresh_received_hashes(value)
    sign_all(value)
    case = {
        "name": name,
        "expected": expected,
        "rule": rule,
        "operation": operation,
        "note": note,
        "base": f"v{version}",
        **value,
    }
    if reason:
        case["expectedReason"] = reason
    vectors.append(case)


def build_vectors() -> list[dict]:
    vectors: list[dict] = []
    add_case(vectors, "protocol-v2-exact-success", "pass", "XN-1..XN-9",
             "provider-neutral v2 exact selection reaches independently verified finality")
    add_case(vectors, "protocol-v1-exact-success", "pass", "XN-4/XN-7",
             "numeric version 1 maps legacy PaymentRequired fields without rewriting the hash preimage",
             version=1)

    def second_provider(v):
        other_url = "https://independent-seller.example/pay/274"
        for ref in (
            v["listing"]["acceptedRails"][0],
            v["agreement"]["terms"]["rail"],
            v["runtime"]["selectedRailRef"],
        ):
            ref["parameters"]["request"]["url"] = other_url
        v["runtime"]["effectiveUrl"] = other_url
        v["http"]["paymentRequired"]["resource"]["url"] = other_url
        v["evidence"]["paymentTxRefs"][0]["httpResource"] = other_url
    add_case(vectors, "independent-provider-same-protocol-rules", "pass", "XN-1..XN-4",
             "a second seller endpoint needs no provider-specific global rail entry",
             second_provider, refresh=True)

    def solana_exact(v, network=SOLANA_NETWORK, cluster="devnet"):
        extra = {"feePayer": "seller", "mint": SOLANA_ASSET}
        for ref in (
            v["listing"]["acceptedRails"][0],
            v["agreement"]["terms"]["rail"],
            v["runtime"]["selectedRailRef"],
        ):
            selection = ref["parameters"]["selection"]
            selection.update({
                "network": network,
                "asset": SOLANA_ASSET,
                "extra": copy.deepcopy(extra),
            })
        binding = v["agreement"]["terms"]["payoutBindings"][0]
        binding["payeeAddress"] = SOLANA_SELLER
        bundle = buyer_bundle(network, SOLANA_BUYER)
        bundle_hash = digest(unsigned(bundle, "presentation"))
        v["buyerBundle"] = bundle
        v["agreement"]["parties"][0]["bundleHash"] = bundle_hash
        v["runtime"]["payer"].update({
            "bundleHash": bundle_hash,
            "payingKey": payment_claim(network, SOLANA_BUYER),
            "paymentAddress": SOLANA_BUYER,
        })
        v["runtime"]["payee"]["payeeAddress"] = SOLANA_SELLER
        requirement_value = v["http"]["paymentRequired"]["accepts"][0]
        requirement_value.update({
            "network": network,
            "asset": SOLANA_ASSET,
            "payTo": SOLANA_SELLER,
            "extra": copy.deepcopy(extra),
        })
        response = settlement_response(2)
        response.update({
            "payer": SOLANA_BUYER,
            "transaction": SOLANA_TX,
            "network": network,
        })
        v["http"]["responseHeader"] = encoded_header(response, 2)
        v["capability"]["supportedTuples"] = [[2, "exact", network]]
        v["capability"]["assetMetadata"] = {
            "network": network,
            "asset": SOLANA_ASSET,
            "decimals": 6,
        }
        event = f"solana:{cluster}:{SOLANA_TX}:4"
        v["ledger"].update({
            "network": network,
            "transaction": SOLANA_TX,
            "settlementEvent": event,
            "asset": SOLANA_ASSET,
            "payer": SOLANA_BUYER,
            "payTo": SOLANA_SELLER,
            "authorization": "solana-transfer",
            "sessionBound": False,
        })
        evidence_ref = v["evidence"]["paymentTxRefs"][0]
        evidence_ref.update({
            "settlementNetwork": network,
            "settlementTransaction": SOLANA_TX,
            "settlementEvent": event,
        })
        v["evidence"]["settlementFinality"]["schemeNetworkFinality"]["network"] = network
    add_case(vectors, "protocol-v2-solana-exact-success", "pass", "XN-3/XN-8/XN-9/SB-1",
             "a non-EVM CAIP-2 network succeeds through its local exact adapter without a registry addition",
             solana_exact, refresh=True)
    add_case(vectors, "protocol-v2-solana-mainnet-exact-success", "pass", "XN-3/XN-8/XN-9/SB-1",
             "Solana mainnet-beta's CAIP-2 genesis reference maps to the mainnet event-key cluster",
             lambda v: solana_exact(v, "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "mainnet"),
             refresh=True)

    add_case(vectors, "definition-hybrid-static-asset", "error", "XN-1",
             "protocol arm cannot carry a static asset",
             lambda v: v["railDefinition"].update({"asset": {"kind": "erc20"}}),
             operation="validate-definition")
    add_case(vectors, "definition-global-resource-url", "error", "XN-1",
             "global protocol definition cannot pin one seller resource",
             lambda v: v["railDefinition"].update({"resourceBaseUrl": URL}),
             operation="validate-definition")
    add_case(vectors, "definition-global-provider-allowlist", "error", "XN-1",
             "global protocol definition cannot approve providers",
             lambda v: v["railDefinition"].update({"providers": ["facilitator.example"]}),
             operation="validate-definition")
    add_case(vectors, "definition-global-operator-credential", "error", "XN-1/XN-3",
             "operator secrets cannot enter the signed protocol definition",
             lambda v: v["railDefinition"].update({"apiKey": "secret"}),
             operation="validate-definition")

    def consumer_finality_profile(v):
        v["railDefinition"]["consumerFinalityProfile"] = {
            "finalityProfileVersion": "1",
            "model": "block-depth",
            "settlement": {
                "kind": "block-depth",
                "networkId": "eip155:8453",
                "genesisHash": "0x" + "77" * 32,
                "requiredDepth": 12,
                "observation": {},
            },
        }
    add_case(vectors, "definition-with-consumer-finality-profile", "error", "RD-7/XN-1",
             "the closed protocol arm has no consumerFinalityProfile member, so it cannot "
             "produce FinalityBoundSettlementEvidence",
             consumer_finality_profile, operation="validate-definition")

    def duplicate_ref(v):
        v["listing"]["acceptedRails"].append(copy.deepcopy(v["listing"]["acceptedRails"][0]))
    add_case(vectors, "listing-duplicate-canonical-ref", "fail", "XN-2/LRR-1",
             "duplicate full-canonical refs reject", duplicate_ref)

    def multi_accepts_right_selection(v):
        wrong = copy.deepcopy(v["agreement"]["terms"]["rail"])
        wrong["parameters"]["selection"]["network"] = "eip155:1"
        v["listing"]["acceptedRails"] = [wrong, copy.deepcopy(v["agreement"]["terms"]["rail"])]
    add_case(vectors, "listing-same-id-selects-complete-second-ref", "pass", "XN-2",
             "the complete agreed ref is selected even when it is not the first matching railId",
             multi_accepts_right_selection)

    def first_id_runtime(v):
        multi_accepts_right_selection(v)
        v["runtime"]["selectedRailRef"] = copy.deepcopy(v["listing"]["acceptedRails"][0])
    add_case(vectors, "runtime-first-matching-railid", "fail", "XN-2",
             "runtime selection of the first same-ID ref is non-conforming", first_id_runtime)

    def agreement_ref_not_listed(v):
        v["agreement"]["terms"]["rail"]["parameters"]["selection"]["maxTimeoutSeconds"] = 61
        v["runtime"]["selectedRailRef"] = copy.deepcopy(v["agreement"]["terms"]["rail"])
    add_case(vectors, "agreement-ref-not-full-jcs-member", "fail", "XN-2",
             "a co-signed partial/changed ref not in the Listing rejects", agreement_ref_not_listed)

    def legacy_agreement(v):
        v["agreement"].pop("payeeBoundAgreementVersion")
        v["agreement"]["agreementVersion"] = "1"
    add_case(vectors, "protocol-legacy-agreement-artifact", "fail", "XN-2",
             "x402:protocol requires PayeeBoundAgreementDocument", legacy_agreement)

    # XN-2 listing admission. The signed Listing's commitment phase fixes the
    # agreement type (DACS-3 §8.5.2 check 9), so an x402:protocol offer beside
    # any phase other than commit-payee-bound-agreement is rejected at listing
    # time instead of being admitted and then never committing.
    sealed_complete_negotiation = {
        "kind": "negotiate-sealed-envelope-complete",
        "parameters": {
            "commitDeadline": 2000000000000,
            "revealWindow": 120,
            "selectionRule": "lowest-price",
            "candidateSetBinding": {
                "bindingId": "x402-274-complete-log",
                "bindingVersion": "1",
                "definitionRef": {
                    "anchor": {"kind": "storage-program", "locator": "stor-x402-274-binding"},
                    "contentHash": "77" * 32,
                    "signer": SELLER_CLAIM,
                },
            },
        },
    }

    def listing_pipeline(negotiate, commit, *, alternative=False):
        def mutate(v):
            listing = v["listing"]
            protocol_ref = copy.deepcopy(listing["acceptedRails"][0])
            if alternative:
                dem_ref = {"railId": "demos-native:DEM", "railVersion": 1}
                listing["acceptedRails"] = [protocol_ref, dem_ref]
                pay = {"kind": "pay-alternative", "parameters": {
                    "alternatives": [copy.deepcopy(protocol_ref), copy.deepcopy(dem_ref)],
                }}
            else:
                pay = {"kind": "pay-x402", "parameters": {"rail": "x402:protocol"}}
            listing["pipeline"] = [
                copy.deepcopy(negotiate), {"kind": commit}, pay,
                {"kind": "deliver-storage-program"},
            ]
        return mutate
    fixed_price = {"kind": "negotiate-fixed-price"}
    add_case(vectors, "listing-protocol-with-payee-bound-commit-admitted", "pass", "XN-2",
             "a Listing offering x402:protocol with commit-payee-bound-agreement is admissible",
             listing_pipeline(fixed_price, "commit-payee-bound-agreement"),
             operation="admit-listing")
    add_case(vectors, "listing-protocol-with-identity-bound-payee-commit-rejected", "fail",
             "XN-2",
             "an x402:protocol offer cannot be paired with IdentityBoundPayeeAgreementDocument in this candidate",
             listing_pipeline(fixed_price, "commit-identity-bound-payee-agreement"),
             operation="admit-listing", reason="x402-protocol-agreement-type")
    add_case(vectors, "listing-protocol-with-selection-bound-commit-rejected", "fail",
             "XN-2",
             "an x402:protocol offer cannot be paired with SealedSelectionAgreementDocument in this candidate",
             listing_pipeline(sealed_complete_negotiation, "commit-selection-bound-agreement"),
             operation="admit-listing", reason="x402-protocol-agreement-type")
    add_case(vectors, "listing-protocol-alternative-with-payee-bound-commit-admitted", "pass",
             "XN-2/APR-1",
             "a pay-alternative slot may offer x402:protocol under commit-payee-bound-agreement",
             listing_pipeline(fixed_price, "commit-payee-bound-agreement", alternative=True),
             operation="admit-listing")
    add_case(vectors, "listing-protocol-alternative-with-identity-bound-payee-commit-rejected",
             "fail", "XN-2/APR-1",
             "APR-1 rejects an x402:protocol alternative under an identity-bound commitment phase",
             listing_pipeline(fixed_price, "commit-identity-bound-payee-agreement", alternative=True),
             operation="admit-listing", reason="x402-protocol-agreement-type")
    add_case(vectors, "listing-protocol-alternative-with-selection-bound-commit-rejected",
             "fail", "XN-2/APR-1",
             "APR-1 rejects an x402:protocol alternative under the selection-bound commitment phase",
             listing_pipeline(sealed_complete_negotiation, "commit-selection-bound-agreement",
                              alternative=True),
             operation="admit-listing", reason="x402-protocol-agreement-type")

    # A signed pay-alternative slot whose parameters or alternatives are absent,
    # have the wrong JSON type, or offer fewer than two objects is a malformed
    # Listing before the offered set is built. APR-1 returns `rejected`, which
    # this corpus scores as `fail`; DACS-1 has no `error` listing disposition.
    absent = object()

    def malformed_alternative_slot(path, value):
        def mutate(v):
            listing_pipeline(fixed_price, "commit-payee-bound-agreement", alternative=True)(v)
            slot = next(step for step in v["listing"]["pipeline"]
                        if step["kind"] == "pay-alternative")
            if path == "member":
                slot["parameters"]["alternatives"].append(value)
                return
            target = slot if path == "parameters" else slot["parameters"]
            if value is absent:
                del target[path]
            else:
                target[path] = value
        return mutate
    for name, path, value, note in (
        ("parameters-null", "parameters", None, "pay-alternative parameters must be an object"),
        ("parameters-array", "parameters", [], "pay-alternative parameters must be an object"),
        ("parameters-absent", "parameters", absent, "APR-1 rejects absent pay-alternative parameters"),
        ("alternatives-null", "alternatives", None, "pay-alternative alternatives must be an array"),
        ("alternatives-object", "alternatives", {},
         "pay-alternative alternatives must be an array, not an object"),
        ("alternatives-absent", "alternatives", absent,
         "APR-1 rejects a pay-alternative slot without alternatives"),
        ("alternatives-empty", "alternatives", [],
         "APR-1 requires at least two alternatives, so an empty array is malformed"),
        ("alternatives-non-object-member", "member", "x402:protocol",
         "every pay-alternative member must be a complete PaymentRailRef object"),
    ):
        add_case(vectors, f"listing-pay-alternative-{name}", "fail", "XN-2/APR-1", note,
                 malformed_alternative_slot(path, value), operation="admit-listing",
                 reason="listing-shape")
    add_case(vectors, "unsigned-runtime-url-override", "fail", "XN-2/XN-6",
             "a runtime URL beside the signed rail ref cannot override it",
             lambda v: v["runtime"].update({"effectiveUrl": "https://attacker.example/pay"}))
    add_case(vectors, "lowercase-request-method", "error", "XN-2",
             "method must be the canonical uppercase token",
             lambda v: v["agreement"]["terms"]["rail"]["parameters"]["request"].update({"method": "get"}))
    add_case(vectors, "non-https-request-url", "error", "XN-2",
             "payable target must be absolute HTTPS",
             lambda v: v["agreement"]["terms"]["rail"]["parameters"]["request"].update({"url": "http://seller.example/pay"}))
    # NB the address-class rule cited here lives in DACS-1 §6.3.6 on the `next` branch, which
    # is this PR's base; it is not yet present on `main`. Anyone checking the citation against
    # `main` will not find it — that is a branch difference, not a bad citation.
    #
    # At least one representative for each address class DACS-1 §6.3.6 names —
    # representative samples, not exhaustive coverage of each class's address space.
    # The multicast rows are the ones an `is_global` gate lets through; ipv4-mapped-*
    # pin the "equivalent IPv4-mapped IPv6 spellings" clause.
    #
    # Every row refreshes the received-object hashes and pins the reason, so an
    # evaluator without the address-class gate reaches "pass" and fails the vector
    # instead of failing later on a stale challenge hash.
    #
    # NB these vectors assert REJECTION of each class, not which branch rejected it.
    # They are not deletion-sensitive on their own: 127.0.0.1, 169.254.1.1, 0.0.0.0 and 240.0.0.1 are all is_private in CPython,
    # so removing the loopback, link-local, unspecified or reserved branch still rejects
    # them through the is_private fallback and leaves these green. The class-name unit
    # test is what makes a deleted branch fail.
    for name, unsafe_url in (
        ("localhost", "https://localhost/pay"),
        ("ipv4-loopback", "https://127.0.0.1/pay"),
        ("ipv4-private", "https://10.0.0.1/pay"),
        # 169.254.169.254 is BOTH link-local and a metadata address, and _non_public_class
        # checks metadata first — so this case exercises the metadata branch, not link-local.
        # The pure link-local case below executes the link-local branch, but note what it does
        # NOT do: deleting that branch still rejects 169.254.1.1 through the is_private
        # fallback, so these vectors stay green. Only the class-name unit test detects the
        # deletion. Vectors prove rejection; the unit test proves which rule did the rejecting.
        ("ipv4-link-local-metadata", "https://169.254.169.254/latest/meta-data/"),
        ("ipv4-link-local-only", "https://169.254.1.1/pay"),
        ("ipv6-loopback", "https://[::1]/pay"),
        ("ipv4-multicast", "https://224.0.0.1/pay"),
        ("ipv4-multicast-ssdp", "https://239.255.255.250/pay"),
        ("ipv6-multicast", "https://[ff02::1]/pay"),
        ("ipv4-shared-address", "https://100.64.0.1/pay"),
        ("ipv4-unspecified", "https://0.0.0.0/pay"),
        ("ipv4-reserved", "https://240.0.0.1/pay"),
        ("ipv4-broadcast", "https://255.255.255.255/pay"),
        # Metadata endpoints whose rejection §6.3.6 compels directly. Azure's WireServer
        # (168.63.129.16) is deliberately NOT asserted here: Microsoft documents it as a
        # platform endpoint distinct from IMDS, so requiring its rejection would impose a
        # conformance obligation the spec does not clearly state on every implementer.
        # The evaluator still rejects it as defence-in-depth — see _METADATA_ADDRESSES —
        # but that is our hardening choice and does not belong in a normative vector set.
        ("ipv6-aws-imds-metadata", "https://[fd00:ec2::254]/latest/meta-data/"),
        ("ipv6-unique-local", "https://[fc00::1]/pay"),
        ("ipv4-mapped-loopback", "https://[::ffff:127.0.0.1]/pay"),
        ("ipv4-mapped-metadata", "https://[::ffff:169.254.169.254]/pay"),
        ("ipv4-mapped-multicast", "https://[::ffff:224.0.0.1]/pay"),
    ):
        def unsafe_public_target(v, target=unsafe_url):
            request = v["agreement"]["terms"]["rail"]["parameters"]["request"]
            request["url"] = target
            v["listing"]["acceptedRails"][0] = copy.deepcopy(
                v["agreement"]["terms"]["rail"])
            v["runtime"]["selectedRailRef"] = copy.deepcopy(
                v["agreement"]["terms"]["rail"])
            v["runtime"]["effectiveUrl"] = target
            v["http"]["paymentRequired"]["resource"]["url"] = target
            v["evidence"]["paymentTxRefs"][0]["httpResource"] = target
        add_case(
            vectors,
            f"bounded-fetch-{name}-target",
            "fail",
            "XN-2/DACS-1-6.3.6",
            "a counterparty-selected non-public payable target is rejected",
            unsafe_public_target,
            refresh=True,
            reason="non-public-request-target",
        )
    # Legacy IPv4 host spellings. A fetch-style (WHATWG) URL parser treats a host
    # whose last label is a number as an IPv4 literal, so these denote the same
    # destinations as their dotted forms; a numeric host that is not a valid IPv4
    # literal is not a valid host at all. Like the rows above, these refresh the
    # received-object hashes and pin the reason, so an evaluator that treats the
    # host as a DNS name reaches "pass" and fails the vector.
    for name, unsafe_url in (
        ("ipv4-shorthand-loopback", "https://127.1/pay"),
        ("ipv4-integer-loopback", "https://2130706433/pay"),
        ("ipv4-hex-loopback", "https://0x7f.0.0.1/pay"),
        ("ipv4-octal-loopback", "https://0177.0.0.1/pay"),
        ("ipv4-trailing-dot-loopback", "https://127.0.0.1./pay"),
        ("ipv4-shorthand-metadata", "https://169.254.43518/latest/meta-data/"),
        ("ipv4-invalid-numeric-host", "https://256.0.0.1/pay"),
        # 0x0x08 is not a WHATWG IPv4 number, so the host is invalid, not 8.8.8.8.
        ("ipv4-double-hex-prefix-invalid-host", "https://0x0x08.8.8.8/pay"),
    ):
        def legacy_ipv4_target(v, target=unsafe_url):
            request = v["agreement"]["terms"]["rail"]["parameters"]["request"]
            request["url"] = target
            v["listing"]["acceptedRails"][0] = copy.deepcopy(
                v["agreement"]["terms"]["rail"])
            v["runtime"]["selectedRailRef"] = copy.deepcopy(
                v["agreement"]["terms"]["rail"])
            v["runtime"]["effectiveUrl"] = target
            v["http"]["paymentRequired"]["resource"]["url"] = target
            v["evidence"]["paymentTxRefs"][0]["httpResource"] = target
        add_case(
            vectors,
            f"bounded-fetch-{name}-target",
            "fail",
            "XN-2/DACS-1-6.3.6",
            "a legacy numeric IPv4 host spelling is classified as its literal address, never as a DNS name",
            legacy_ipv4_target,
            refresh=True,
            reason="non-public-request-target",
        )
    # XN-2 URL syntax: printable ASCII only, no `\`, no `%` in the host, no
    # userinfo or fragment even when empty, a decimal port of at most 65535, and an
    # internationalized host in A-label form. Outside it, parsers disagree on the
    # host: UTS-46 drops default-ignorable code points, WHATWG ends an https
    # authority at `\` and percent-decodes the host. Each error row would reach a
    # fetch client as loopback, metadata or localhost although `urlsplit` sees a
    # DNS name. Like the bounded-fetch rows, every row refreshes the received-object
    # hashes, so an evaluator without the syntax rule (and with the address gate
    # open) reaches "pass" and fails the vector.
    for name, expected, request_url, note in (
        ("host-soft-hyphen-loopback", "error", "https://127.0.0.1­/pay",
         "U+00AD after an IPv4 loopback host is not printable ASCII"),
        ("host-zero-width-space-loopback", "error", "https://127.0.0.1​/pay",
         "U+200B after an IPv4 loopback host is not printable ASCII"),
        ("host-encoded-soft-hyphen-loopback", "error", "https://127.0.0.1%C2%AD/pay",
         "a percent-encoded U+00AD puts % in the host"),
        ("host-soft-hyphen-metadata", "error",
         "https://169.254.169.254­/latest/meta-data/",
         "U+00AD after the metadata address is not printable ASCII"),
        ("backslash-authority-loopback", "error", "https://127.0.0.1\\.seller.example/pay",
         "a backslash ends a WHATWG https authority, so the host would be 127.0.0.1"),
        ("backslash-authority-metadata", "error",
         "https://169.254.169.254\\.seller.example/latest/meta-data/",
         "a backslash ends a WHATWG https authority, so the host would be the metadata address"),
        ("percent-encoded-localhost", "error", "https://%6c%6fcalhost/pay",
         "a percent-encoded host is malformed even when it decodes to localhost"),
        ("full-width-localhost", "error",
         "https://ｌｏｃａｌｈｏｓｔ/pay",
         "a full-width host is not printable ASCII"),
        ("idn-u-label-host", "error", "https://bücher.example/pay",
         "an internationalized host must be signed in A-label form"),
        ("percent-encoded-ipv4-loopback", "error", "https://%31%32%37.0.0.1/pay",
         "a percent-encoded IPv4 host puts % in the host"),
        ("empty-userinfo", "error", "https://@seller.example/pay",
         "an @ in the authority is userinfo even when the userinfo is empty"),
        ("empty-userinfo-password", "error", "https://:@seller.example/pay",
         "an empty user and password are still userinfo"),
        ("empty-fragment", "error", "https://seller.example/pay#",
         "a # starts a fragment even when nothing follows it"),
        ("port-not-decimal", "error", "https://seller.example:abc/pay",
         "a port must be decimal digits"),
        ("port-out-of-range", "error", "https://seller.example:99999/pay",
         "a port must be at most 65535"),
        ("empty-a-label", "error", "https://xn--.example/pay",
         "an xn-- label with no Punycode content is not an RFC 5890 A-label"),
        ("fake-a-label-localhost", "error", "https://xn--localhost-/pay",
         "xn--localhost- decodes to the ASCII label localhost, so it is not an A-label"),
        ("fake-a-label-upper-case", "error", "https://XN--LOCALHOST-.example/pay",
         "the ACE prefix is case-insensitive, so XN--LOCALHOST- must also be a real A-label"),
        ("over-long-a-label", "error",
         f"https://xn--{('ü' * 60).encode('punycode').decode('ascii')}.example/pay",
         "a 66-character xn-- label exceeds the 63-octet DNS limit, so it is not an A-label"),
        ("a-label-tangut-joiner", "error", "https://xn--ukba655qaaaa14431eeaaba.c/pay",
         "a ZWNJ between Tangut ideographs fails CONTEXTJ, so this is not an A-label; "
         "idna 3.6 raises ValueError instead of IDNAError on it"),
        ("backslash-in-path", "error", "https://seller.example/pay\\x",
         "a backslash is malformed anywhere in the URL, not only in the authority"),
        ("non-ascii-path", "error", "https://seller.example/pé",
         "a non-ASCII code point is malformed anywhere in the URL, not only in the host"),
        ("del", "error", "https://seller.example/pay\x7f",
         "U+007F is outside printable ASCII"),
        ("idn-a-label-host", "pass", "https://xn--bcher-kva.example/pay",
         "the A-label form of an internationalized host is admitted"),
        ("percent-in-path", "pass", "https://seller.example/p%C3%A9",
         "percent-encoding outside the host is admitted"),
        ("explicit-port", "pass", "https://seller.example:8443/pay",
         "a decimal port of at most 65535 is admitted"),
    ):
        def request_url_spelling(v, target=request_url):
            request = v["agreement"]["terms"]["rail"]["parameters"]["request"]
            request["url"] = target
            v["listing"]["acceptedRails"][0] = copy.deepcopy(
                v["agreement"]["terms"]["rail"])
            v["runtime"]["selectedRailRef"] = copy.deepcopy(
                v["agreement"]["terms"]["rail"])
            v["runtime"]["effectiveUrl"] = target
            v["http"]["paymentRequired"]["resource"]["url"] = target
            v["evidence"]["paymentTxRefs"][0]["httpResource"] = target
        add_case(
            vectors,
            f"request-url-{name}",
            expected,
            "XN-2",
            note,
            request_url_spelling,
            refresh=True,
            reason="rail-ref-shape" if expected == "error" else None,
        )
    add_case(vectors, "bare-network-label", "error", "XN-2/XN-4",
             "a bare network label is not CAIP-2",
             lambda v: v["agreement"]["terms"]["rail"]["parameters"]["selection"].update({"network": "base"}))
    add_case(vectors, "numeric-version-replaced-by-string", "error", "XN-2/XN-7",
             "new evidence and selection use a number, never protocolVersion-style text",
             lambda v: v["agreement"]["terms"]["rail"]["parameters"]["selection"].update({"x402Version": "2"}))
    add_case(vectors, "negative-asset-decimals", "error", "XN-2/XN-5",
             "assetDecimals is a non-negative safe integer",
             lambda v: v["agreement"]["terms"]["rail"]["parameters"]["selection"].update({"assetDecimals": -1}))

    def unsupported_tuple(v):
        v["capability"]["supportedTuples"] = []
    add_case(vectors, "unsupported-local-capability", "fail", "XN-3",
             "unsupported tuple fails locally before authorization", unsupported_tuple,
             reason="x402-capability-unsupported")
    add_case(vectors, "counterparty-operator-config", "error", "XN-3",
             "operator configuration must come from trusted local policy",
             lambda v: v["runtime"].update({"operatorConfigSource": "payment-required-extension"}))
    add_case(vectors, "operator-routing-change-preserves-rail-identity", "pass", "XN-3",
             "changing local facilitator/RPC routing does not change the signed rail identity",
             lambda v: v["runtime"].update({"facilitator": "https://facilitator-b.example", "rpc": "https://rpc-b.example"}))

    add_case(vectors, "non-402-response-before-authorization", "fail", "XN-4",
             "a normal 200 response is not an x402 challenge",
             lambda v: v["http"].update({"status": 200}))
    add_case(vectors, "challenge-resource-substitution", "fail", "XN-4",
             "resource URL substitution rejects before signing",
             lambda v: v["http"]["paymentRequired"]["resource"].update({"url": "https://attacker.example/pay"}))

    def first_accept_wrong_then_exact(v):
        wrong = copy.deepcopy(v["http"]["paymentRequired"]["accepts"][0])
        wrong["network"] = "eip155:1"
        v["http"]["paymentRequired"]["accepts"] = [wrong, v["http"]["paymentRequired"]["accepts"][0]]
    add_case(vectors, "challenge-selects-exact-not-first-accept", "pass", "XN-4",
             "the one exact requirement is selected even when accepts[0] is different",
             first_accept_wrong_then_exact, refresh=True)

    def duplicate_accept(v):
        v["http"]["paymentRequired"]["accepts"].append(
            copy.deepcopy(v["http"]["paymentRequired"]["accepts"][0]))
    add_case(vectors, "challenge-duplicate-exact-accepts", "fail", "XN-4",
             "multiple exact matches are ambiguous", duplicate_accept, refresh=True)
    for name, field, replacement in (
        ("challenge-network-substitution", "network", "eip155:1"),
        ("challenge-asset-substitution", "asset", "0x" + "99" * 20),
        ("challenge-timeout-substitution", "maxTimeoutSeconds", 61),
        ("challenge-amount-substitution", "amount", "1250001"),
        ("challenge-payto-substitution", "payTo", "0x" + "99" * 20),
    ):
        add_case(vectors, name, "fail", "XN-4/XN-5",
                 f"{field} substitution rejects before authorization",
                 lambda v, f=field, r=replacement: v["http"]["paymentRequired"]["accepts"][0].update({f: r}))
    add_case(vectors, "challenge-extra-substitution", "fail", "XN-4/XN-6",
             "the complete PaymentRequirements.extra object is bound",
             lambda v: v["http"]["paymentRequired"]["accepts"][0]["extra"].update({"spender": "attacker"}))
    add_case(vectors, "challenge-extension-substitution", "fail", "XN-4/XN-6",
             "the complete top-level extensions object is bound",
             lambda v: v["http"]["paymentRequired"]["extensions"]["payment-identifier"].update({"required": False}))
    add_case(vectors, "challenge-extension-absent-vs-empty", "fail", "XN-4/XN-6",
             "omitted and empty extensions are distinct",
             lambda v: v["http"]["paymentRequired"].update({"extensions": {}}))
    add_case(vectors, "payment-required-unknown-member-preserved", "pass", "XN-6/XN-7",
             "an unrecognised descriptive member remains in the complete challenge commitment",
             lambda v: v["http"]["paymentRequired"].update({"futureDescription": {"label": "v3-readable"}}),
             refresh=True)

    def non_nfc_received_objects(v):
        # Decomposed (non-NFC) descriptive strings in both received objects. XN-7
        # hashes them after the recursive CF-1 NFC pass, so an implementation
        # that hashes the raw strings computes different commitments.
        v["http"]["paymentRequired"]["resource"]["description"] = "Café résumé"
        response = settlement_response(2)
        response["note"] = "Café résumé"
        v["http"]["responseHeader"] = encoded_header(response, 2)
    add_case(vectors, "received-objects-non-nfc-strings-hash-after-cf1", "pass", "XN-7",
             "challenge and receipt hashes apply the recursive CF-1 NFC pass to decomposed strings",
             non_nfc_received_objects, refresh=True)
    add_case(vectors, "unsupported-action-bearing-extension", "fail", "XN-6",
             "an action-bearing extension the adapter cannot validate rejects before signing",
             lambda v: v["capability"].update({"understoodActionExtensions": []}))
    add_case(vectors, "redirected-payable-resource", "fail", "XN-6",
             "redirect following cannot change the signed payable target",
             lambda v: v["runtime"].update({"redirected": True, "effectiveUrl": "https://cdn.example/pay"}))

    def add_body_without_hash(v):
        v["runtime"]["requestBodyBase64"] = base64.b64encode(b"{} ").decode("ascii")
    add_case(vectors, "body-sent-without-signed-hash", "fail", "XN-6",
             "an absent bodyHash requires no request body", add_body_without_hash)

    def valid_body(v):
        body = b'{"job":"274"}'
        v["runtime"]["requestBodyBase64"] = base64.b64encode(body).decode("ascii")
        v["agreement"]["terms"]["rail"]["parameters"]["request"]["bodyHash"] = hashlib.sha256(body).hexdigest()
        v["listing"]["acceptedRails"][0] = copy.deepcopy(v["agreement"]["terms"]["rail"])
        v["runtime"]["selectedRailRef"] = copy.deepcopy(v["agreement"]["terms"]["rail"])
    add_case(vectors, "signed-request-body-hash", "pass", "XN-6",
             "exact body bytes match the signed sha256", valid_body)

    def wrong_decimals(v):
        v["capability"]["assetMetadata"]["decimals"] = 18
    add_case(vectors, "asset-decimals-adapter-mismatch", "fail", "XN-5",
             "signed decimals must match independent asset metadata", wrong_decimals)
    add_case(vectors, "agreement-price-excess-precision", "fail", "XN-5",
             "exact conversion never rounds excess fractional precision",
             lambda v: v["agreement"]["terms"]["price"].update({"amount": "1.0000001"}))

    # Exact shifting must not depend on an arithmetic context: a 28-digit
    # decimal context would round both prices below and accept the second.
    def price_and_atomic(price, atomic):
        def mutate(v):
            v["agreement"]["terms"]["price"]["amount"] = price
            v["evidence"]["paymentAmount"]["amount"] = price
            v["http"]["paymentRequired"]["accepts"][0]["amount"] = atomic
            v["ledger"]["amount"] = atomic
        return mutate
    add_case(vectors, "agreement-price-large-exact-amount", "pass", "XN-5",
             "a price with more significant digits than a default decimal context converts exactly",
             price_and_atomic("123456789012345678901234567.25",
                              "123456789012345678901234567250000"),
             refresh=True)
    add_case(vectors, "agreement-price-rounded-by-decimal-context", "fail", "XN-5",
             "excess precision rejects even when the challenge carries the context-rounded amount",
             price_and_atomic("1000000000000000000000000.0000001",
                              "1000000000000000000000000000000"),
             refresh=True, reason="exact-amount")

    # XN-5 overflow is the binding's native amount type: EIP-3009 value is
    # uint256 on EIP-155 and SPL Token amounts are u64 on Solana. Prices use
    # the fixture's 6 decimals, so atomic = price * 10**6 exactly.
    def at_atomic(atomic):
        digits = str(atomic)
        whole, fraction = digits[:-6], digits[-6:].rstrip("0")
        return price_and_atomic(whole + ("." + fraction if fraction else ""), digits)
    add_case(vectors, "exact-amount-at-uint256-limit", "pass", "XN-5",
             "the largest EIP-3009 uint256 value converts exactly and settles",
             at_atomic(2**256 - 1), refresh=True)
    add_case(vectors, "exact-amount-above-uint256-limit", "fail", "XN-5",
             "an atomic amount of 2**256 overflows EIP-3009 value and rejects before authorization",
             at_atomic(2**256), refresh=True, reason="exact-amount")

    def solana_at_atomic(atomic):
        def mutate(v):
            solana_exact(v)
            at_atomic(atomic)(v)
        return mutate
    add_case(vectors, "solana-exact-amount-at-u64-limit", "pass", "XN-5",
             "the largest SPL Token u64 amount converts exactly and settles",
             solana_at_atomic(2**64 - 1), refresh=True)
    add_case(vectors, "solana-exact-amount-above-u64-limit", "fail", "XN-5",
             "an atomic amount of 2**64 overflows the SPL Token u64 and rejects before authorization",
             solana_at_atomic(2**64), refresh=True, reason="exact-amount")

    def with_decimals(decimals, price, atomic):
        def mutate(v):
            for ref in (
                v["listing"]["acceptedRails"][0],
                v["agreement"]["terms"]["rail"],
                v["runtime"]["selectedRailRef"],
            ):
                ref["parameters"]["selection"]["assetDecimals"] = decimals
            v["capability"]["assetMetadata"]["decimals"] = decimals
            v["ledger"]["assetDecimals"] = decimals
            price_and_atomic(price, atomic)(v)
        return mutate
    add_case(vectors, "asset-decimals-at-uint8-limit", "pass", "XN-2/XN-5",
             "assetDecimals 255 is the uint8 maximum and converts exactly",
             with_decimals(255, "0." + "0" * 254 + "1", "1"), refresh=True)
    add_case(vectors, "asset-decimals-above-uint8-limit", "error", "XN-2/XN-5",
             "assetDecimals 256 exceeds uint8 and is malformed before any power of ten",
             with_decimals(256, "0." + "0" * 255 + "1", "1"), refresh=True,
             reason="rail-ref-shape")
    add_case(vectors, "runtime-payer-not-agreement-buyer", "fail", "XN-5",
             "runtime payer must resolve to the signed buyer",
             lambda v: v["runtime"]["payer"].update({"primaryClaim": "did:demos:agent:" + "99" * 32}))
    add_case(vectors, "runtime-paying-key-not-buyer-controlled", "fail", "XN-5",
             "the payment authorization key must be controlled by the signed buyer",
             lambda v: v["runtime"]["payer"].update({"payingKey": "did:demos:agent:" + "99" * 32}))
    add_case(vectors, "runtime-payer-address-not-derived-from-paying-key", "fail", "XN-5",
             "an attacker address cannot replace the address independently derived from the signed bundle payment key",
             lambda v: v["runtime"]["payer"].update({"paymentAddress": "0x" + "99" * 20}))
    add_case(vectors, "runtime-payee-not-signed-destination", "fail", "XN-5",
             "an unsigned runtime payee cannot replace the payout binding",
             lambda v: v["runtime"]["payee"].update({"payeeAddress": "0x" + "99" * 20}))
    add_case(vectors, "ledger-payer-substitution", "fail", "XN-5/XN-8",
             "authenticated event payer must be the buyer-controlled authorization payer",
             lambda v: v["ledger"].update({"payer": "0x" + "99" * 20}),
             authorization_submitted=True)
    add_case(vectors, "ledger-payee-substitution", "fail", "XN-5/XN-8",
             "authenticated event destination must be the signed payout binding",
             lambda v: v["ledger"].update({"payTo": "0x" + "99" * 20}),
             authorization_submitted=True)

    # XN-5: an EIP-155 address compares as a 20-byte value, letter case ignored;
    # the EIP-55 checksum is neither required nor checked. The seller here is
    # LETTERED_SELLER, signed in lower case in the payout binding.
    def lettered_seller(pay_to, ledger_pay_to=LETTERED_SELLER):
        def mutate(v):
            v["agreement"]["terms"]["payoutBindings"][0]["payeeAddress"] = LETTERED_SELLER
            v["runtime"]["payee"]["payeeAddress"] = LETTERED_SELLER
            v["http"]["paymentRequired"]["accepts"][0]["payTo"] = pay_to
            v["ledger"]["payTo"] = ledger_pay_to
        return mutate
    add_case(vectors, "challenge-payto-eip55-checksum-binding-lower-case", "pass", "XN-5",
             "an EIP-55 checksummed payTo matches the lower-case payout binding",
             lettered_seller(eip55(LETTERED_SELLER)), refresh=True)
    add_case(vectors, "challenge-payto-wrong-eip55-checksum-binding-lower-case", "pass", "XN-5",
             "a mixed-case payTo whose every letter has the wrong EIP-55 case still matches, "
             "since the adapter must not check the checksum",
             lettered_seller("0x" + eip55(LETTERED_SELLER)[2:].swapcase()), refresh=True)
    add_case(vectors, "ledger-payto-upper-case", "pass", "XN-5/XN-8",
             "an upper-case authenticated ledger payTo is the same 20-byte destination",
             lettered_seller(LETTERED_SELLER, "0x" + LETTERED_SELLER[2:].upper()), refresh=True)
    add_case(vectors, "challenge-payto-substitution-mixed-case", "fail", "XN-4/XN-5",
             "a different address stays a mismatch in EIP-55 mixed case",
             lettered_seller(eip55(OTHER_LETTERED_ADDRESS)), refresh=True,
             reason="challenge-match")
    add_case(vectors, "challenge-payto-not-20-bytes", "error", "XN-5",
             "an EIP-155 payTo that is not 0x plus 40 hex digits is malformed before authorization",
             lettered_seller(LETTERED_SELLER[:-2]), refresh=True, reason="address-form")

    def malformed_payout_binding(v):
        lettered_seller(LETTERED_SELLER)(v)
        v["agreement"]["terms"]["payoutBindings"][0]["payeeAddress"] = LETTERED_SELLER[:-2]
        v["runtime"]["payee"]["payeeAddress"] = LETTERED_SELLER[:-2]
    add_case(vectors, "payout-binding-not-20-bytes", "error", "XN-5/PB-1",
             "a signed EIP-155 payout binding that is not 0x plus 40 hex digits is malformed "
             "before authorization, even beside a well-formed payTo",
             malformed_payout_binding, refresh=True, reason="address-form")

    # The two earlier XN-5 gates: payer control and the PB-1 runtime payee.
    def eip55_paying_key_claim(v):
        bundle = buyer_bundle("eip155:8453", eip55(BUYER_ADDRESS))
        bundle_hash = digest(unsigned(bundle, "presentation"))
        v["buyerBundle"] = bundle
        v["agreement"]["parties"][0]["bundleHash"] = bundle_hash
        v["runtime"]["payer"].update({
            "bundleHash": bundle_hash,
            "payingKey": payment_claim("eip155:8453", eip55(BUYER_ADDRESS)),
        })
    add_case(vectors, "paying-key-claim-eip55-derived-payer-lower-case", "pass", "XN-5",
             "an EIP-55 paying-key claim address is the same 20-byte payer as the lower-case "
             "address derived from its key and the authorization payer",
             eip55_paying_key_claim)
    def eip55_runtime_payee(v):
        lettered_seller(LETTERED_SELLER)(v)
        v["runtime"]["payee"]["payeeAddress"] = eip55(LETTERED_SELLER)
    add_case(vectors, "runtime-payee-eip55-binding-lower-case", "pass", "XN-5/PB-1",
             "an EIP-55 runtime payee is the same 20-byte destination as the lower-case "
             "signed payout binding",
             eip55_runtime_payee, refresh=True)

    def malformed_binding_runtime_payee_valid(v):
        lettered_seller(LETTERED_SELLER)(v)
        v["agreement"]["terms"]["payoutBindings"][0]["payeeAddress"] = LETTERED_SELLER[:-2]
    add_case(vectors, "payout-binding-not-20-bytes-runtime-payee-valid", "error", "XN-5/PB-1",
             "a malformed signed EIP-155 payout binding is malformed before authorization "
             "even when the runtime payee is well formed",
             malformed_binding_runtime_payee_valid, refresh=True, reason="address-form")
    # The unsigned runtime copies at the same two gates.
    add_case(vectors, "runtime-payer-eip55-derived-payer-lower-case", "pass", "XN-5",
             "an EIP-55 runtime authorization payer is the same 20-byte payer as the "
             "lower-case paying-key claim and derived payer",
             lambda v: v["runtime"]["payer"].update({"paymentAddress": eip55(BUYER_ADDRESS)}))
    add_case(vectors, "runtime-payer-not-20-bytes", "error", "XN-5",
             "a runtime authorization payer that is not 0x plus 40 hex digits is malformed "
             "before authorization, even beside a well-formed claim and derived payer",
             lambda v: v["runtime"]["payer"].update({"paymentAddress": BUYER_ADDRESS[:-2]}),
             reason="address-form")
    add_case(vectors, "runtime-payee-not-20-bytes-binding-valid", "error", "XN-5/PB-1",
             "a runtime payee that is not 0x plus 40 hex digits is malformed before "
             "authorization, even beside a well-formed signed payout binding",
             lambda v: v["runtime"]["payee"].update({"payeeAddress": SELLER_ADDRESS[:-2]}),
             reason="address-form")
    add_case(vectors, "ledger-payer-mixed-case", "pass", "XN-5/XN-8",
             "an EIP-55 mixed-case authenticated ledger payer is the same 20-byte payer",
             lambda v: v["ledger"].update({"payer": eip55(BUYER_ADDRESS)}))

    def solana_ledger_payer_case_changed(v):
        solana_exact(v)
        v["ledger"]["payer"] = SOLANA_BUYER.replace("k", "K", 1)
    add_case(vectors, "solana-ledger-payer-case-changed", "fail", "XN-5/XN-8",
             "base58 is case-sensitive, so one changed letter case names a different Solana payer",
             solana_ledger_payer_case_changed, refresh=True, authorization_submitted=True,
             reason="ledger-event")

    # The other Solana address sites stay exact too. The payTo cases use
    # LETTERED_SOLANA_SELLER, whose unchanged spelling passes first.
    def solana_lettered_seller(pay_to=LETTERED_SOLANA_SELLER, ledger_pay_to=LETTERED_SOLANA_SELLER):
        def mutate(v):
            solana_exact(v)
            v["agreement"]["terms"]["payoutBindings"][0]["payeeAddress"] = LETTERED_SOLANA_SELLER
            v["runtime"]["payee"]["payeeAddress"] = LETTERED_SOLANA_SELLER
            v["http"]["paymentRequired"]["accepts"][0]["payTo"] = pay_to
            v["ledger"]["payTo"] = ledger_pay_to
        return mutate
    add_case(vectors, "solana-lettered-seller-exact-success", "pass", "XN-5/XN-8",
             "a letter-bearing Solana payTo that matches exactly settles",
             solana_lettered_seller(), refresh=True)
    add_case(vectors, "solana-challenge-payto-case-changed", "fail", "XN-4/XN-5",
             "one changed letter case in the Solana challenge payTo names a different destination",
             solana_lettered_seller(pay_to=LETTERED_SOLANA_SELLER.replace("E", "e", 1)),
             refresh=True, reason="challenge-match")
    add_case(vectors, "solana-ledger-payto-case-changed", "fail", "XN-5/XN-8",
             "one changed letter case in the Solana ledger payTo names a different payee",
             solana_lettered_seller(ledger_pay_to=LETTERED_SOLANA_SELLER.replace("E", "e", 1)),
             refresh=True, authorization_submitted=True, reason="ledger-event")

    def solana_response_payer_case_changed(v):
        solana_exact(v)
        response = settlement_response(2)
        response.update({
            "payer": SOLANA_BUYER.replace("k", "K", 1),
            "transaction": SOLANA_TX,
            "network": SOLANA_NETWORK,
        })
        v["http"]["responseHeader"] = encoded_header(response, 2)
    add_case(vectors, "solana-response-payer-case-changed", "fail", "XN-5/XN-7",
             "one changed letter case in the Solana response payer names a different payer",
             solana_response_payer_case_changed, refresh=True, authorization_submitted=True,
             reason="response-payer")

    def response_payer(payer):
        def mutate(v):
            response = settlement_response(2)
            response["payer"] = payer
            v["http"]["responseHeader"] = encoded_header(response, 2)
        return mutate
    add_case(vectors, "response-payer-mixed-case", "pass", "XN-5/XN-7",
             "an EIP-55 mixed-case response payer is the same 20-byte payer",
             response_payer(eip55(BUYER_ADDRESS)), refresh=True)
    add_case(vectors, "response-payer-not-20-bytes", "error", "XN-5/XN-7",
             "an EIP-155 response payer that is not 0x plus 40 hex digits is malformed",
             response_payer(BUYER_ADDRESS + "00"), refresh=True,
             authorization_submitted=True, reason="address-form")

    add_case(vectors, "payment-required-hash-substitution", "fail", "XN-7",
             "stored challenge hash must recompute from the complete object",
             lambda v: v["evidence"]["paymentTxRefs"][0].update({"paymentRequiredHash": "00" * 32}),
             authorization_submitted=True)
    add_case(vectors, "payment-receipt-hash-substitution", "fail", "XN-7",
             "stored receipt hash must recompute from the complete response",
             lambda v: v["evidence"]["paymentTxRefs"][0].update({"paymentReceiptHash": "00" * 32}),
             authorization_submitted=True)
    add_case(vectors, "wrong-version-response-header", "error", "XN-7",
             "numeric version selects one exact response header",
             lambda v: v["http"]["responseHeader"].update({"name": "X-PAYMENT-RESPONSE"}),
             authorization_submitted=True)

    def response_network_mismatch(v):
        response = settlement_response(2)
        response["network"] = "eip155:1"
        v["http"]["responseHeader"] = encoded_header(response, 2)
    add_case(vectors, "response-network-substitution", "fail", "XN-7",
             "a fully rehashed response still cannot change the signed network",
             response_network_mismatch, refresh=True, authorization_submitted=True)

    def response_transaction_mismatch(v):
        response = settlement_response(2)
        response["transaction"] = "0x" + "cd" * 32
        v["http"]["responseHeader"] = encoded_header(response, 2)
    add_case(vectors, "response-transaction-substitution", "fail", "XN-7",
             "a fully rehashed response cannot change the signed settlement transaction",
             response_transaction_mismatch, refresh=True, authorization_submitted=True)

    # XN-7 keeps the response transaction verbatim in settlementTransaction; the
    # EIP-155 adapter compares it with settlementEvent, and with the ledger
    # transaction in the same form, after the SB-1 collapse: at most one 0x/0X,
    # hex in either case, exactly 32 bytes. The base fixture already carries the
    # upstream 0x lower-case spelling in the response and the ledger.
    def response_transaction_spelling(spelling, ledger_spelling=None):
        def mutate(v):
            response = settlement_response(2)
            response["transaction"] = spelling
            v["http"]["responseHeader"] = encoded_header(response, 2)
            v["evidence"]["paymentTxRefs"][0]["settlementTransaction"] = spelling
            if ledger_spelling is not None:
                v["ledger"]["transaction"] = ledger_spelling
        return mutate
    add_case(vectors, "response-transaction-0x-ledger-unprefixed", "pass", "XN-7/XN-8/SB-1",
             "a 0x response matches an unprefixed authenticated ledger transaction in the collapsed form",
             response_transaction_spelling("0x" + SAFE_TX, SAFE_TX), refresh=True,
             authorization_submitted=True)
    for name, expected, spelling, note in (
        ("response-transaction-unprefixed", "pass", SAFE_TX,
         "a hash without a prefix is already the canonical form"),
        ("response-transaction-0x-mixed-case", "pass", "0x" + "Ab" * 32,
         "hex digits compare case-insensitively"),
        ("response-transaction-0X-uppercase", "pass", "0X" + SAFE_TX.upper(),
         "an upper-case 0X prefix is one allowed prefix"),
        ("response-transaction-63-hex-digits", "error", "0x" + SAFE_TX[:63],
         "a hash that is not exactly 32 bytes has no canonical form"),
        ("response-transaction-double-0x-prefix", "error", "0x0x" + SAFE_TX,
         "at most one prefix is removed, so a second 0x is malformed"),
    ):
        add_case(vectors, name, expected, "XN-7/XN-8/SB-1", note,
                 response_transaction_spelling(spelling), refresh=True,
                 authorization_submitted=True,
                 reason=None if expected == "pass" else "settlement-transaction-form")

    def response_payer_mismatch(v):
        response = settlement_response(2)
        response["payer"] = "0x" + "99" * 20
        v["http"]["responseHeader"] = encoded_header(response, 2)
    add_case(vectors, "response-payer-substitution", "fail", "XN-5/XN-7",
             "the settlement response payer must be the buyer-controlled payer",
             response_payer_mismatch, refresh=True, authorization_submitted=True)

    def protocol_version_field(v):
        ref = v["evidence"]["paymentTxRefs"][0]
        ref["protocolVersion"] = str(ref.pop("x402Version"))
    add_case(vectors, "new-evidence-uses-legacy-protocolversion", "error", "XN-7/XN-10",
             "x402-protocol evidence cannot emit legacy protocolVersion", protocol_version_field,
             authorization_submitted=True)
    add_case(vectors, "ledger-unavailable-after-submission", "indeterminate", "XN-8/XN-11",
             "receipt acknowledgement without authenticated ledger data is not success",
             lambda v: v["ledger"].update({"available": False}),
             authorization_submitted=True)
    add_case(vectors, "acknowledgement-only-no-transaction", "indeterminate", "XN-8",
             "a signed/hashed server acknowledgement alone cannot produce success",
             lambda v: v.pop("ledger"), authorization_submitted=True)
    add_case(vectors, "ledger-event-amount-mismatch", "fail", "XN-5/XN-8",
             "the authenticated event amount must be exact",
             lambda v: v["ledger"].update({"amount": "1249999"}),
             authorization_submitted=True)
    add_case(vectors, "ledger-not-final", "indeterminate", "XN-8",
             "included but non-final settlement is not success",
             lambda v: v["ledger"].update({"finalized": False}),
             authorization_submitted=True)

    def noncanonical_event(v):
        value = f"evm:8453:0x{SAFE_TX}:7"
        v["ledger"]["settlementEvent"] = value
        v["evidence"]["paymentTxRefs"][0]["settlementEvent"] = value
    add_case(vectors, "noncanonical-native-event-key", "error", "XN-8/SB-1",
             "a noncanonical event spelling cannot mint another SB-1 identity",
             noncanonical_event, authorization_submitted=True, reason="native-event-key")

    def uppercase_event(v):
        value = f"evm:8453:{SAFE_TX.upper()}:7"
        v["ledger"]["settlementEvent"] = value
        v["evidence"]["paymentTxRefs"][0]["settlementEvent"] = value
    add_case(vectors, "noncanonical-native-event-key-uppercase", "error", "XN-8/SB-1",
             "an upper-case EVM hash cannot mint another SB-1 identity",
             uppercase_event, authorization_submitted=True, reason="native-event-key")
    add_case(vectors, "native-event-coordinate-substitution", "fail", "XN-8/SB-1",
             "a different signed event coordinate cannot match authenticated ledger data",
             lambda v: v["evidence"]["paymentTxRefs"][0].update({
                 "settlementEvent": f"evm:8453:{SAFE_TX}:8"
             }), authorization_submitted=True)
    add_case(vectors, "finality-profile-network-substitution", "fail", "XN-8",
             "the signed finality profile must repeat the selected scheme and network",
             lambda v: v["evidence"]["settlementFinality"]["schemeNetworkFinality"].update({
                 "network": "eip155:1"
             }), authorization_submitted=True)
    add_case(vectors, "finality-binding-profile-substitution", "fail", "XN-8",
             "the finality binding profile must name the exact v0.8 DACS semantics",
             lambda v: v["evidence"]["settlementFinality"]["schemeNetworkFinality"].update({
                 "bindingProfile": "counterparty-profile:v1"
             }), authorization_submitted=True)
    add_case(vectors, "event-key-cross-rail-alias", "pass", "XN-8/SB-1",
             "EIP-155 x402 evidence emits the same evm event key as the direct rail")

    def upto_scheme(v):
        for ref in (v["listing"]["acceptedRails"][0], v["agreement"]["terms"]["rail"], v["runtime"]["selectedRailRef"]):
            ref["parameters"]["selection"]["scheme"] = "upto"
        v["http"]["paymentRequired"]["accepts"][0]["scheme"] = "upto"
        v["capability"]["supportedTuples"] = [[2, "upto", "eip155:8453"]]
    add_case(vectors, "upto-has-no-dacs-success-profile", "fail", "XN-9",
             "upto is protocol-valid but cannot use exact success semantics", upto_scheme,
             reason="x402-capability-unsupported")

    def batch_ack(v):
        for ref in (v["listing"]["acceptedRails"][0], v["agreement"]["terms"]["rail"], v["runtime"]["selectedRailRef"]):
            ref["parameters"]["selection"]["scheme"] = "batch-settlement"
        v["http"]["paymentRequired"]["accepts"][0]["scheme"] = "batch-settlement"
        v["capability"]["supportedTuples"] = [[2, "batch-settlement", "eip155:8453"]]
        v.pop("ledger")
    add_case(vectors, "batch-commitment-is-not-financial-settlement", "indeterminate", "XN-8/XN-9",
             "batch commitment acknowledgement stays distinct from eventual settlement", batch_ack,
             authorization_submitted=True)

    def disabled_default(v):
        v["railDefinition"] = legacy_rail()
        v["runtime"]["sessionState"] = "new"
    add_case(vectors, "legacy-default-new-session-disabled", "fail", "XN-10/RAV-R2",
             "x402:default cannot start a new session", disabled_default,
             operation="new-session")

    def pinned_live_default(v):
        v["railDefinition"] = legacy_live_rail()
        v["runtime"]["sessionState"] = "new"
    add_case(vectors, "legacy-default-pinned-live-new-session", "fail", "XN-10",
             "pinning the historical live revision cannot bypass the new-session prohibition",
             pinned_live_default, operation="new-session")

    def legacy_replay(v):
        v["railDefinition"] = legacy_live_rail()
        v["evidence"]["paymentTxRefs"] = [{
            "kind": "x402-event",
            "httpResource": URL,
            "paymentReceiptHash": digest({**settlement_response(2), "transaction": SAFE_TX}),
            "settlementTxHash": SAFE_TX,
            "chainId": 8453,
            "logIndex": 7,
            "protocolVersion": "2",
        }]
    add_case(vectors, "legacy-default-string-version-replay", "pass", "XN-10/X402-1",
             "historical bytes keep protocolVersion string and legacy discriminator",
             legacy_replay, operation="legacy-replay", authorization_submitted=True)

    def legacy_continuation(v):
        legacy_replay(v)
        v["runtime"]["sessionState"] = "in-flight"
    add_case(vectors, "legacy-default-pinned-in-flight-continuation", "pass", "XN-10",
             "an already-pinned historical session may finish without rewriting its evidence",
             legacy_continuation, operation="legacy-continuation",
             authorization_submitted=True)

    def retry_pending(v):
        v["ledger"]["available"] = False
        v["runtime"]["retryWouldAuthorize"] = False
    add_case(vectors, "retry-indeterminate-remains-pending", "pass", "XN-11",
             "indeterminate observation reconciles without a second authorization",
             retry_pending, operation="retry", authorization_submitted=True)

    def retry_hostile_reauthorization_request(v):
        v["ledger"]["available"] = False
        v["runtime"]["retryWouldAuthorize"] = True
    add_case(vectors, "retry-caller-reauthorization-request-is-ignored", "pass", "XN-11",
             "a caller request cannot make reconciliation authorize another payment",
             retry_hostile_reauthorization_request, operation="retry",
             authorization_submitted=True, reason="reconciliation-pending")

    def retry_job_mismatch(v):
        v["agreement"]["jobId"] = "01M0NVBGYEANE562QQXD33C7WY"
    add_case(vectors, "retry-job-binding-mismatch", "fail", "XN-11",
             "reconciliation is bound to the original signed jobId",
             retry_job_mismatch, operation="retry", authorization_submitted=True,
             reason="reconciliation-binding")

    def retry_phase_mismatch(v):
        v["runtime"]["phaseIndex"] = 4
    add_case(vectors, "retry-phase-binding-mismatch", "fail", "XN-11",
             "reconciliation is bound to the original phase index",
             retry_phase_mismatch, operation="retry", authorization_submitted=True,
             reason="reconciliation-binding")

    def retry_requirement_mismatch(v):
        v["agreement"]["terms"]["rail"]["parameters"]["selection"]["asset"] = "0x" + "99" * 20
    add_case(vectors, "retry-requirement-binding-mismatch", "fail", "XN-11",
             "reconciliation is bound to the original complete selected requirement",
             retry_requirement_mismatch, operation="retry", authorization_submitted=True,
             reason="reconciliation-binding")

    def retry_authorization_mismatch(v):
        v["runtime"]["payer"]["paymentAddress"] = "0x" + "99" * 20
    add_case(vectors, "retry-authorization-binding-mismatch", "fail", "XN-11",
             "reconciliation is bound to the original authorization identity",
             retry_authorization_mismatch, operation="retry", authorization_submitted=True,
             reason="reconciliation-binding")

    def retry_transaction_mismatch(v):
        v["evidence"]["paymentTxRefs"][0]["settlementTransaction"] = "cd" * 32
    add_case(vectors, "retry-transaction-binding-mismatch", "fail", "XN-11",
             "reconciliation is bound to the retained transaction identity",
             retry_transaction_mismatch, operation="retry", authorization_submitted=True,
             reason="reconciliation-binding")

    def retry_retained_transaction_spelling(v):
        v["ledger"]["available"] = False
        v["runtime"]["reconciliationState"]["settlementTransaction"] = SAFE_TX.upper()
    add_case(vectors, "retry-retained-transaction-spelling-reconciles", "pass", "XN-11/XN-7",
             "a retained transaction that differs from the record only by prefix and case "
             "reconciles in the XN-7 adapter form",
             retry_retained_transaction_spelling, operation="retry",
             authorization_submitted=True, reason="reconciliation-pending")

    def retry_identical_malformed_transaction(v):
        v["ledger"]["available"] = False
        v["evidence"]["paymentTxRefs"][0]["settlementTransaction"] = "not-a-hash"
        v["runtime"]["reconciliationState"]["settlementTransaction"] = "not-a-hash"
    add_case(vectors, "retry-identical-malformed-transaction-is-error", "error", "XN-11/XN-7",
             "identical retained and recorded spellings still need an XN-7 adapter form; "
             "a value with none is a malformed coordinate",
             retry_identical_malformed_transaction, operation="retry",
             authorization_submitted=True, reason="settlement-transaction-form")

    def retry_recorded_malformed_transaction(v):
        v["ledger"]["available"] = False
        v["evidence"]["paymentTxRefs"][0]["settlementTransaction"] = "not-a-hash"
    add_case(vectors, "retry-recorded-malformed-transaction-is-error", "error", "XN-11/XN-7",
             "a recorded transaction with no XN-7 adapter form is malformed even beside a "
             "well-formed retained value",
             retry_recorded_malformed_transaction, operation="retry",
             authorization_submitted=True, reason="settlement-transaction-form")

    # The authorization identity is the authorization payer, an XN-5 address.
    # Neither side is in the lower-case form, so the adapter must convert both.
    def retry_authorization_identity_spelling(v):
        v["ledger"]["available"] = False
        v["runtime"]["payer"]["paymentAddress"] = "0x" + BUYER_ADDRESS[2:].upper()
        v["runtime"]["reconciliationState"]["authorizationIdentity"] = eip55(BUYER_ADDRESS)
    add_case(vectors, "retry-authorization-identity-eip55-reconciles", "pass", "XN-11/XN-5",
             "a retained EIP-55 authorization identity reconciles with the same payer in "
             "upper-case hex, since both compare as 20-byte values",
             retry_authorization_identity_spelling, operation="retry",
             authorization_submitted=True, reason="reconciliation-pending")

    def retry_identical_malformed_authorization_identity(v):
        v["ledger"]["available"] = False
        v["runtime"]["payer"]["paymentAddress"] = BUYER_ADDRESS[:-2]
        v["runtime"]["reconciliationState"]["authorizationIdentity"] = BUYER_ADDRESS[:-2]
    add_case(vectors, "retry-authorization-identity-not-20-bytes", "error", "XN-11/XN-5",
             "identical retained and session authorization identities that are not 0x plus "
             "40 hex digits are a malformed coordinate",
             retry_identical_malformed_authorization_identity, operation="retry",
             authorization_submitted=True, reason="address-form")

    # XN-5 leaves Solana exact at the retry site too: the unchanged retained
    # state reconciles, so one changed letter case is the only difference.
    def retry_solana_authorization_identity_case_changed(v):
        solana_exact(v)
        v["ledger"]["available"] = False
        v["runtime"]["reconciliationState"].update({
            "requirementHash": digest(v["agreement"]["terms"]["rail"]),
            "authorizationIdentity": SOLANA_BUYER.replace("k", "K", 1),
            "settlementTransaction": SOLANA_TX,
        })
    add_case(vectors, "retry-solana-authorization-identity-case-changed", "fail", "XN-11/XN-5",
             "base58 is case-sensitive, so a retained Solana authorization identity with one "
             "changed letter case names a different payer",
             retry_solana_authorization_identity_case_changed, operation="retry",
             authorization_submitted=True, reason="reconciliation-binding")

    return vectors


def diff_ops(base: object, target: object, path: tuple = ()) -> list[dict]:
    """Return deterministic, path-array JSON patch operations.

    Arrays of equal length are compared element-by-element; a length change
    replaces the complete array. This keeps the committed vector set compact
    without making a runner interpret signatures or regenerate artifact bytes.
    """
    if type(base) is not type(target):
        return [{"op": "replace", "path": list(path), "value": target}]
    if isinstance(base, dict):
        ops: list[dict] = []
        for name in sorted(set(base) - set(target)):
            ops.append({"op": "remove", "path": list(path + (name,))})
        for name in sorted(set(target) - set(base)):
            ops.append({
                "op": "add",
                "path": list(path + (name,)),
                "value": target[name],
            })
        for name in sorted(set(base) & set(target)):
            ops.extend(diff_ops(base[name], target[name], path + (name,)))
        return ops
    if isinstance(base, list):
        if len(base) != len(target):
            return [{"op": "replace", "path": list(path), "value": target}]
        ops: list[dict] = []
        for index, (left, right) in enumerate(zip(base, target)):
            ops.extend(diff_ops(left, right, path + (index,)))
        return ops
    if base != target:
        return [{"op": "replace", "path": list(path), "value": target}]
    return []


def compact_case(case: dict, fixtures: dict[str, dict]) -> dict:
    base_name = case["base"]
    material = {
        name: value for name, value in case.items() if name not in CASE_META_FIELDS
    }
    compact = {
        "name": case["name"],
        "expected": case["expected"],
        "rule": case["rule"],
        "operation": case["operation"],
        "note": case["note"],
        "base": base_name,
        "patch": diff_ops(fixtures[base_name], material),
    }
    if "expectedReason" in case:
        compact["expectedReason"] = case["expectedReason"]
    return compact


def build() -> dict:
    fixtures = {"v1": make_base(1), "v2": make_base(2)}
    vectors = [compact_case(case, fixtures) for case in build_vectors()]
    return {
        "set": "x402-negotiated-protocol-v0.8",
        "spec": "§8.5.2 / §9.3 / §9.4.3 XN-1 / §9.5.1 PB-2 / §9.5.7 XN-2..XN-11 / §9.5.8 SB-1",
        "upstream": {
            "repository": "x402-foundation/x402",
            "commit": "230e6a9a7eebce22c911a0687d6f4e6d1ac019f7",
            "v2Types": "typescript/packages/core/src/types/payments.ts",
            "v1Types": "typescript/packages/core/src/types/v1/index.ts",
        },
        "fixtureModel": {
            "materialization": "deep-copy fixtures[vector.base], then apply vector.patch in order",
            "path": "array of object member names or zero-based array indexes",
            "operations": ["add", "remove", "replace"],
            "signatureRule": "patches include every changed deterministic signature; runners do not re-sign",
        },
        "fixtures": fixtures,
        "count": len(vectors),
        "hash": hashlib.sha256(json.dumps(
            vectors, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")).hexdigest(),
        "vectors": vectors,
    }


def encoded(value: object) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    wanted = encoded(build())
    current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
    if args.write:
        OUTPUT.write_text(wanted, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    if current != wanted:
        print("negotiated x402 vectors are stale; run generator with --write")
        return 1
    print("negotiated x402 vectors OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
