#!/usr/bin/env python3
"""Generate deterministic DACS-3/DACS-4 negotiated-x402 security vectors."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import unicodedata
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize as jcs_canonicalize
from raw_json_profile import loads as admit_raw_json
from solana_authorization import (
    COMPUTE_BUDGET_PROGRAM,
    MEMO_PROGRAM,
    TRANSFER_CHECKED,
    associated_token_account,
    authorization_identity as solana_identity,
    base58,
    public_key_bytes,
)
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
# Private scalar 1 (public key = the secp256k1 generator) is publicly known:
# a conformance-fixture key only, never for real funds.
EVM_BUYER_PRIVATE_SCALAR = 1
EVM_BUYER_PUBLIC_KEY = uncompressed_public_key(EVM_BUYER_PRIVATE_SCALAR)
BUYER_ADDRESS = evm_address(EVM_BUYER_PUBLIC_KEY)
SELLER_ADDRESS = "0x" + "22" * 20
# XN-5 address-case vectors need hex letters, which SELLER_ADDRESS lacks. These
# are EIP-55's first two examples, so their checksum spellings can be checked
# against the EIP.
LETTERED_SELLER = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
OTHER_LETTERED_ADDRESS = "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359"
# The asset and verifyingContract case vectors use EIP-55's next two examples.
LETTERED_ASSET = "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb"
LETTERED_VERIFYING_CONTRACT = "0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb"
# XN-6: an `extra` as the pinned upstream exact scheme definitions give it
# (x402-foundation/x402@230e6a9a, specs/schemes/exact/scheme_exact_evm.md and
# scheme_exact_svm.md). The EIP-155 one is upstream's EIP-3009 example; the
# EIP-712 domain's verifying contract is the asset, so `extra` names none.
EIP3009_EXTRA = {"assetTransferMethod": "eip3009", "name": "USDC", "version": "2"}
# The `payment-identifier` advertisement exactly as the pinned upstream extension
# gives it (specs/extensions/payment_identifier.md): optional, so it is
# descriptive and v0.8 supports it with no local capability.
PAYMENT_IDENTIFIER_EXTENSIONS = {
    "payment-identifier": {
        "info": {"required": False},
        "schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "required": {"type": "boolean"},
                "id": {"type": "string", "minLength": 16, "maxLength": 128},
            },
            "required": ["required"],
        },
    },
}
# The schema the pinned reference SDKs' declarePaymentIdentifierExtension()
# emits (typescript/packages/extensions/src/payment-identifier/schema.ts and its
# Python and Go twins): the markdown example plus the `id` character pattern.
PAYMENT_IDENTIFIER_SDK_SCHEMA = copy.deepcopy(PAYMENT_IDENTIFIER_EXTENSIONS["payment-identifier"]["schema"])
PAYMENT_IDENTIFIER_SDK_SCHEMA["properties"]["id"]["pattern"] = "^[a-zA-Z0-9_-]+$"
# DACS-4 §9.5.7 failure modes (`x402:protocol`): the PC-4 errorClass of each
# handler result the list names. Unsupported or undefined members, like
# unsupported capability, are `permanent`, never the seller's fault.
FAILURE_MODE_ERROR_CLASSES = {
    "unpaid-request-transient": "transient",
    **{reason: "counterparty" for reason in (
        "not-payment-required", "payment-required-header", "payment-required-json",
        "payment-required-version", "payment-required-shape", "accepts-shape",
        "extension-presence", "extensions", "challenge-match", "extra-member-value",
        "extension-value",
    )},
    **{reason: "permanent" for reason in (
        "x402-capability-unsupported", "unsupported-transfer-method", "unsupported-payment-flow",
        "unsupported-action-extension", "unclassified-extra-member", "unclassified-extension",
        "terminal-non-settlement", "ledger-event", "currency", "asset-currency", "paid-request-payload",
    )},
    # §9.5.1 PB failure modes, with the static PB corpus's classes.
    "payee-destination": "counterparty",
    "payee-linkage-unresolved": "substrate",
    "payee-linkage-error": "permanent",
    "payee-bundle": "permanent",
    "payee-bundle-shape": "permanent",
}
REQUEST_HEADERS = {"Accept": "application/json"}
# XN-6: a fixed 65-byte EIP-712 signature placeholder for the paid payload.
# The corpus binds the authorization's fields; the token contract and the
# facilitator verify the signature itself.
EIP712_SIGNATURE = "0x" + hashlib.sha256(b"DACS #274 EIP-712 r").hexdigest() + hashlib.sha256(
    b"DACS #274 EIP-712 s").hexdigest() + "1b"
FACILITATOR = "https://facilitator-a.example"
# X402-1: the v1 SettlementResponse of the x402-receipt-hash corpus's
# `v1-success-x-payment-response` case (its `canonicalReceipt`).
V1_RECEIPT = {
    "network": "base-sepolia",
    "payer": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
    "success": True,
    "transaction": "0x1fb8611c1aef418f2714dc5ec04f6856c3c2a6f64bf458462ee46329306c14de",
}
# The EIP-3009 authorization's validBefore, in seconds, as the handler retains it.
VALID_BEFORE = 1787443260
SOLANA_NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
SOLANA_ASSET = "3" * 44
SOLANA_SELLER = "5" * 44
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
    "name", "expected", "expectedReason", "expectedErrorClass", "rule", "operation", "note", "base",
}


def key(role: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(SEEDS[role])


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unused_bits_set(signature: str) -> str:
    """The same signature bytes, with the last base64url character's unused bits set (SIG-6)."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    assert len(signature) % 4 == 2  # 64 bytes: the last character carries 4 unused bits
    return signature[:-1] + alphabet[alphabet.index(signature[-1]) | 1]


def flip_first(signature: str) -> str:
    """The same base64url signature with its first character changed."""
    return ("A" if signature[0] != "A" else "B") + signature[1:]


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
# A Solana `extra` names the fee payer's key; the mint is the `asset`.
SOLANA_SPONSOR_KEY = Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(b"DACS #274 Solana fee payer").digest())
SOLANA_SPONSOR_PUBLIC = SOLANA_SPONSOR_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
SOLANA_FEE_PAYER = base58(SOLANA_SPONSOR_PUBLIC)


SOLANA_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
SOLANA_TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
SOLANA_AMOUNT = 1250000  # the base price, 1.25 USDC, at 6 decimals
# Upstream's client puts a random nonce in the Memo instruction when `extra`
# names no memo; the fixtures use a fixed one.
SOLANA_MEMO_NONCE = hashlib.sha256(b"DACS #274 Solana memo nonce").hexdigest()[:32]
# Another key, for substituted sponsors, payers, destinations and authorities.
SOLANA_OTHER_KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"DACS #274 Solana other key").digest())
SOLANA_OTHER = base58(SOLANA_OTHER_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))


def compact_u16(number: int) -> bytes:
    encoded = b""
    while number >= 128:
        encoded += bytes([number & 127 | 128])
        number >>= 7
    return encoded + bytes([number])


def solana_payment_instructions(*, amount=SOLANA_AMOUNT, pay_to=SOLANA_SELLER, memo=None, payer=None,
                                mint=SOLANA_ASSET, token_program=SOLANA_TOKEN_PROGRAM, decimals=6):
    """§9.5.7.1: the instructions of one payment, each (program, [(account, writable)], data)."""
    payer = payer or SOLANA_BUYER
    return [
        (COMPUTE_BUDGET_PROGRAM, [], b"\x02" + (20_000).to_bytes(4, "little")),
        (COMPUTE_BUDGET_PROGRAM, [], b"\x03" + (1).to_bytes(8, "little")),
        (token_program, [(associated_token_account(payer, mint, token_program), True), (mint, False),
                         (associated_token_account(pay_to, mint, token_program), True), (payer, False)],
         bytes([TRANSFER_CHECKED]) + amount.to_bytes(8, "little") + bytes([decimals])),
        (MEMO_PROGRAM, [], (SOLANA_MEMO_NONCE if memo is None else memo).encode("utf-8")),
    ]


def solana_transactions(blockhash=b"DACS #274 Solana blockhash", *, edit=None, extra_signers=(),
                        sponsor_key=None, payer_key=None, lookups=(), **terms):
    """Wire-valid v0 fixtures of one payment: (partial, full, transaction ID).

    The message is compiled from `solana_payment_instructions(**terms)`, which
    `edit` may replace. Accounts follow the wire order: signers (the sponsor
    first), then writable, then read-only. These offline fixture keys and
    synthetic accounts never hold real funds. The ledger fixture supplies the
    independently verified execution outcome.
    """
    def public(private):
        return base58(private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))

    signing = [sponsor_key or SOLANA_SPONSOR_KEY, payer_key or solana_payment_key(), *extra_signers]
    signers = [public(private) for private in signing]
    terms.setdefault("payer", signers[1])
    instructions = solana_payment_instructions(**terms)
    instructions = edit(instructions) if edit else instructions
    order, writable = list(signers), {signers[0]}
    for program, accounts, _ in instructions:
        for account, is_writable in accounts:
            writable |= {account} if is_writable else set()
            order += [] if account in order else [account]
        order += [] if program in order else [program]
    keys = sorted(order, key=lambda name: (name not in signers, name not in writable, order.index(name)))
    message = (bytes([128, len(signers), sum(name not in writable for name in signers),
                      sum(name not in writable for name in keys[len(signers):])])
               + compact_u16(len(keys)) + b"".join(public_key_bytes(name) for name in keys)
               + hashlib.sha256(blockhash).digest() + compact_u16(len(instructions)))
    for program, accounts, data in instructions:
        message += (bytes([keys.index(program)]) + compact_u16(len(accounts))
                    + bytes(keys.index(account) for account, _ in accounts)
                    + compact_u16(len(data)) + data)
    message += compact_u16(len(lookups)) + b"".join(
        public_key_bytes(table) + compact_u16(len(loaded)) + bytes(loaded) + compact_u16(0)
        for table, loaded in lookups)
    signatures = [private.sign(message) for private in signing]
    partial = base64.b64encode(compact_u16(len(signing)) + bytes(64) + b"".join(signatures[1:])
                               + message).decode("ascii")
    full = base64.b64encode(compact_u16(len(signing)) + b"".join(signatures) + message).decode("ascii")
    return partial, full, base58(signatures[0])


SOLANA_PAYMENT_TRANSACTION, SOLANA_FINAL_TRANSACTION, SOLANA_TX = solana_transactions()


def rebind_solana_authorization(value: dict) -> None:
    """§9.5.7.1: a Solana case signs a message encoding its own signed terms.

    The base fixture encodes the base terms. A case that changes the amount,
    payout address, memo or token program gets a transaction for its terms, and
    its other copies of the base transaction follow. A case that sets its own
    transaction, or whose terms have no transaction, keeps what it has.
    """
    try:
        terms = value["agreement"]["terms"]
        selection = terms["rail"]["parameters"]["selection"]
        if (not selection["network"].startswith("solana:")
                or value["runtime"].get("solanaAuthorization") != SOLANA_PAYMENT_TRANSACTION
                or selection["extra"].get("feePayer") != SOLANA_FEE_PAYER):
            return
        whole, _, fraction = terms["price"]["amount"].partition(".")
        memo = selection["extra"].get("memo")
        partial, full, transaction = solana_transactions(
            amount=int(whole + fraction) * 10 ** (selection["assetDecimals"] - len(fraction)),
            pay_to=terms["payoutBindings"][0]["payeeAddress"],
            memo=memo if isinstance(memo, str) else None,
            token_program=value["capability"]["assetMetadata"]["tokenProgram"],
            decimals=selection["assetDecimals"])
    except (AttributeError, KeyError, OverflowError, TypeError, ValueError):
        return
    if transaction == SOLANA_TX:
        return
    old = solana_identity(SOLANA_PAYMENT_TRANSACTION, SOLANA_BUYER, SOLANA_FEE_PAYER)[0]
    new = solana_identity(partial, SOLANA_BUYER, SOLANA_FEE_PAYER)[0]
    pairs = ((SOLANA_FINAL_TRANSACTION, full), (SOLANA_PAYMENT_TRANSACTION, partial),
             (SOLANA_TX, transaction), (old["messageHash"], new["messageHash"]),
             (old["clientSignatures"][0]["signature"], new["clientSignatures"][0]["signature"]))

    def replaced(node):
        if isinstance(node, dict):
            return {name: replaced(item) for name, item in node.items()}
        if isinstance(node, list):
            return [replaced(item) for item in node]
        if isinstance(node, str):
            for before, after in pairs:
                node = node.replace(before, after)
        return node

    for part in ("runtime", "ledger", "evidence"):
        if part in value:
            value[part] = replaced(value[part])
    response = received_response(value)
    if response is not None and replaced(response) != response:
        refs = value.get("evidence", {}).get("paymentTxRefs", [])
        consistent = bool(refs) and refs[0].get("paymentReceiptHash") == digest(response)
        value["http"]["responseHeader"] = encoded_header(replaced(response), 2)
        if consistent:
            refs[0]["paymentReceiptHash"] = digest(received_response(value))


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


def buyer_bundle(network: str, address: str, *, presented_by_payment_key: bool = False,
                 duplicate_payment_claim: bool = False) -> dict:
    """The buyer's presented DACS-1 bundle with one payment claim for `address`.

    The keyword variants stay correctly signed: one is presented by the payment
    claim instead of the buyer's primary claim (the buyer's Ed25519 key signs
    both entries), the other lists the payment claim twice.
    """
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
    buyer_metadata = {"testRole": "buyer"}
    if presented_by_payment_key:
        buyer_metadata = {"algorithm": "ed25519", "publicKey": public_key("buyer")}
    claims = [
        {"ref": BUYER_CLAIM, "metadata": buyer_metadata},
        {"ref": claim, "metadata": payment_metadata},
    ]
    if duplicate_payment_claim:
        claims.append(copy.deepcopy(claims[1]))
    body = {
        "bundleVersion": "1",
        "presentedBy": claim if presented_by_payment_key else BUYER_CLAIM,
        "presentedAt": 1787443199000,
        "sessionNonce": BUYER_SESSION_NONCE,
        "claims": claims,
    }
    payload = ("dacs-bundle-presentation:v1:" + digest(body)).encode("ascii")
    if presented_by_payment_key:
        payment_signature = key("buyer").sign(payload)
    elif network.startswith("eip155:"):
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


def payee_bundle(*claims: str, presented_by: str = SELLER_CLAIM,
                 primary: tuple = (SELLER_CLAIM,), presented_at=1787443199000) -> dict:
    """The seller's presented DACS-1 bundle (PB-2): its `primary` claims, then `claims`.

    A complete `IdentityBundle`: the seller's key signs the per-claim
    presentation over the bundle without `presentation`, the scope its
    `bundleHash` covers (DACS-1 §6.3.2).
    """
    body = {
        "bundleVersion": "1",
        "presentedBy": presented_by,
        "presentedAt": presented_at,
        "claims": [{"ref": claim} for claim in (*primary, *claims)],
    }
    payload = ("dacs-bundle-presentation:v1:" + digest(body)).encode("ascii")
    return {
        **body,
        "presentation": {
            "kind": "per-claim",
            "signatures": [{"ref": SELLER_CLAIM, "signature": b64u(key("seller").sign(payload))}],
        },
    }


def evm_presentation_envelopes(body: dict, claim: str) -> list[dict]:
    """Per-claim presentation signatures over `body`: the buyer's key, then the EVM payment key."""
    payload = ("dacs-bundle-presentation:v1:" + digest(body)).encode("ascii")
    return [
        {"ref": BUYER_CLAIM, "signature": b64u(key("buyer").sign(payload))},
        {"ref": claim, "signature": b64u(deterministic_ecdsa_sha256(EVM_BUYER_PRIVATE_SCALAR, payload))},
    ]


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
                "extra": copy.deepcopy(EIP3009_EXTRA),
            },
        },
    }
    ref["parameters"]["paymentRequiredExtensions"] = copy.deepcopy(PAYMENT_IDENTIFIER_EXTENSIONS)
    return ref


def requirement(version: int = 2) -> dict:
    return {
        "scheme": "exact",
        "network": "eip155:8453",
        "amount": "1250000",
        "payTo": SELLER_ADDRESS,
        "maxTimeoutSeconds": 60,
        "asset": ASSET,
        "extra": copy.deepcopy(EIP3009_EXTRA),
    }


def payment_required(version: int = 2) -> dict:
    return {
        "x402Version": 2,
        "resource": {
            "url": URL,
            "description": "DACS #274 resource",
            "mimeType": "application/json",
        },
        "accepts": [requirement(2)],
        "extensions": copy.deepcopy(PAYMENT_IDENTIFIER_EXTENSIONS),
    }


def settlement_response(version: int = 2) -> dict:
    return {
        "success": True,
        "payer": BUYER_ADDRESS,
        "transaction": RESPONSE_TX,
        "network": "eip155:8453",
    }


def encoded_header(response: dict, version: int) -> dict:
    raw = json.dumps(response, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {
        "name": "PAYMENT-RESPONSE",
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
    seller_bundle = payee_bundle()
    seller_bundle_hash = digest(unsigned(seller_bundle, "presentation"))
    value = {
        "railDefinition": protocol_rail(),
        "buyerBundle": bundle,
        # PB-2: the seller's DACS-1 bundle, pinned by the agreement's and the
        # runtime payee's bundleHash, which leave out its presentation like the
        # buyer's. The base one carries no EVM settlement-chain
        # claim, so tier 2 is not applicable and the co-signed payout binding
        # (tier 3) binds the destination.
        "payeeBundle": seller_bundle,
        # PB-2: the SR-1 linkage decision the adapter's resolver returns for
        # each payee claim; a claim with no entry is unresolved.
        "payeeLinkage": {},
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
                {"role": "seller", "bundleHash": seller_bundle_hash, "primaryClaim": SELLER_CLAIM},
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
            "payee": {
                "bundleHash": seller_bundle_hash,
                "primaryClaim": SELLER_CLAIM,
                "payeeAddress": SELLER_ADDRESS,
            },
            # XN-6: the request derived from the agreement, then the unpaid and
            # the paid request as sent.
            "effectiveMethod": "GET",
            "unpaidMethod": "GET",
            "paidMethod": "GET",
            "requestBodyBase64": "",
            "unpaidBodyBase64": "",
            "paidBodyBase64": "",
            "effectiveUrl": URL,
            "unpaidUrl": URL,
            "paidUrl": URL,
            # XN-2/XN-6: the header fields of each request as sent; the paid
            # request adds only the v2 payment header.
            "unpaidHeaders": dict(REQUEST_HEADERS),
            "paidHeaders": dict(REQUEST_HEADERS),
            "redirected": False,
            "operatorConfigSource": "local-operator-policy",
            # XN-3: trusted local routing, retained for the session (XN-11).
            "facilitator": FACILITATOR,
            "authorizationSubmitted": False,
            "retryWouldAuthorize": False,
            "reconciliationState": {
                "jobId": "01M0NVBGYEANE562QQXD33C7WX",
                "phaseIndex": 3,
                "requirementHash": digest(ref),
                "authorizationIdentity": BUYER_ADDRESS,
                "facilitator": FACILITATOR,
                "settlementTransaction": RESPONSE_TX,
                "validBefore": VALID_BEFORE,
            },
        },
        "capability": {
            "supportedTuples": [[version, "exact", "eip155:8453"]],
            "bindingProfiles": ["dacs-x402-exact:v1"],
            # XN-5: the adapter's trusted metadata, including the currency the
            # asset denominates.
            "assetMetadata": {
                "network": "eip155:8453",
                "asset": ASSET,
                "decimals": 6,
                "currency": "USDC",
            },
        },
        "http": {
            "status": 402,
            "paymentRequired": payment_required(version),
            "responseHeader": encoded_header(response, version),
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
            # The observed form is informational: the SB-3 policy comes from the
            # pinned definition and the signed selection (XN-9).
            "authorization": "eip-3009",
            "sessionBinding": {"state": "match"},
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
    value["runtime"]["paidHeaders"]["PAYMENT-SIGNATURE"] = payment_signature(value)
    refresh_received_hashes(value)
    sign_all(value)
    return value


def sb3_nonce(job_id: str, phase_index: int) -> str:
    """SB-3: the EIP-3009 nonce derived from (jobId, phaseIndex), as `0x` plus lower-case hex."""
    preimage = (b"dacs-sb3:v1:" + unicodedata.normalize("NFC", job_id).encode("utf-8")
                + b":" + str(phase_index).encode("ascii"))
    return "0x" + hashlib.sha256(preimage).hexdigest()


def matched_requirement(value: dict) -> object:
    """The received requirement the signed selection matches (XN-4), else the first one."""
    required = received_challenge(value)
    accepts = required.get("accepts") if isinstance(required, dict) else None
    if not isinstance(accepts, list) or not accepts:
        return None
    try:
        selection = value["agreement"]["terms"]["rail"]["parameters"]["selection"]
        whole, _, fraction = value["agreement"]["terms"]["price"]["amount"].partition(".")
        amount = str(int(whole + fraction) * 10 ** (selection["assetDecimals"] - len(fraction)))
        pay_to = value["agreement"]["terms"]["payoutBindings"][0]["payeeAddress"]
        evm = selection["network"].startswith("eip155:")
    except Exception:
        return accepts[0]

    def folded(address: object) -> object:
        return address.lower() if evm and isinstance(address, str) else address

    def comparable(extra: object) -> object:
        hints = {"recentBlockhash", "lastValidBlockHeight"}
        if not isinstance(extra, dict):
            return extra
        return {name: item for name, item in extra.items() if name not in hints}
    for candidate in accepts:
        if isinstance(candidate, dict) and all((
            candidate.get("scheme") == selection.get("scheme"),
            candidate.get("network") == selection.get("network"),
            candidate.get("amount") == amount,
            candidate.get("maxTimeoutSeconds") == selection.get("maxTimeoutSeconds"),
            folded(candidate.get("asset")) == folded(selection.get("asset")),
            folded(candidate.get("payTo")) == folded(pay_to),
            comparable(candidate.get("extra")) == comparable(selection.get("extra")),
        )):
            return candidate
    return accepts[0]


def payment_payload(value: dict) -> dict:
    """XN-6: the v2 PaymentPayload the paid request's PAYMENT-SIGNATURE carries (x402 v2 §5.2).

    `accepted` is the matched requirement as received, and `resource` and
    `extensions` are the challenge's own. The EIP-155 payload is the EIP-3009
    authorization of the payer to `payTo` for the exact amount, with the
    retained `validBefore` and the SB-3 derived nonce; the Solana one is the
    base64 transaction.
    """
    required = received_challenge(value)
    required = required if isinstance(required, dict) else {}
    accepted = matched_requirement(value)
    payload = {"x402Version": 2}
    if "resource" in required:
        payload["resource"] = copy.deepcopy(required["resource"])
    payload["accepted"] = copy.deepcopy(accepted)
    network = value["agreement"]["terms"]["rail"]["parameters"]["selection"].get("network")
    if isinstance(network, str) and network.startswith("solana:"):
        payload["payload"] = {"transaction": value["runtime"].get("solanaAuthorization", SOLANA_PAYMENT_TRANSACTION)}
    else:
        retained = value["runtime"].get("reconciliationState")
        valid_before = retained.get("validBefore") if isinstance(retained, dict) else None
        valid_before = valid_before if type(valid_before) is int and valid_before > 0 else VALID_BEFORE
        accepted = accepted if isinstance(accepted, dict) else {}
        payload["payload"] = {
            "signature": EIP712_SIGNATURE,
            "authorization": {
                "from": value["runtime"]["payer"].get("paymentAddress"),
                "to": accepted.get("payTo"),
                "value": accepted.get("amount"),
                "validAfter": str(max(valid_before - 660, 0)),
                "validBefore": str(valid_before),
                "nonce": sb3_nonce(value["agreement"]["jobId"], value["runtime"]["phaseIndex"]),
            },
        }
    if "extensions" in required:
        payload["extensions"] = copy.deepcopy(required["extensions"])
    return payload


def payment_signature(value: dict, payload: object = None) -> str:
    """The PAYMENT-SIGNATURE value: base64 of the payload's JSON bytes."""
    payload = payment_payload(value) if payload is None else payload
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def paid_signature_name(value: dict) -> str | None:
    headers = value.get("runtime", {}).get("paidHeaders")
    if not isinstance(headers, dict):
        return None
    return next((name for name in headers if name.lower() == "payment-signature"), None)


def received_response(value: dict) -> dict | None:
    """The version-selected settlement response object, or None if none decodes.

    XN-7 hashes the response as received, defective or not; with no decoded
    object the receipt preimage is JSON null.
    """
    header = value.get("http", {}).get("responseHeader")
    try:
        version = value["agreement"]["terms"]["rail"]["parameters"]["selection"]["x402Version"]
    except (KeyError, TypeError):
        return None
    wanted = "PAYMENT-RESPONSE" if type(version) is int and version == 2 else None
    if not isinstance(header, dict) or wanted is None or header.get("name") != wanted:
        return None
    try:
        # CORE CF-5 admission: bytes it refuses decode to no object.
        response = admit_raw_json(base64.b64decode(header["value"], validate=True))
    except Exception:
        return None
    return response if isinstance(response, dict) else None


def received_challenge(value: dict) -> object:
    """The received PaymentRequired: the raw form after CF-5 admission, else the object."""
    http = value.get("http", {})
    if "paymentRequiredRaw" not in http:
        return http.get("paymentRequired")
    try:
        return admit_raw_json(base64.b64decode(http["paymentRequiredRaw"], validate=True))
    except Exception:
        return None


def refresh_received_hashes(value: dict) -> None:
    required = received_challenge(value)
    evidence = value.get("evidence", {})
    refs = evidence.get("paymentTxRefs", [])
    if not refs or refs[0].get("kind") != "x402-protocol":
        return
    if isinstance(required, dict):
        refs[0]["paymentRequiredHash"] = digest(required)
    refs[0]["paymentReceiptHash"] = digest(received_response(value))


def send_requests_to(value: dict, url: str) -> None:
    """The derived, unpaid and paid requests of the runtime trace all go to `url`."""
    value["runtime"].update({"effectiveUrl": url, "unpaidUrl": url, "paidUrl": url})


def send_body(value: dict, body: bytes) -> None:
    """The derived, unpaid and paid requests of the runtime trace all carry `body`."""
    encoded = base64.b64encode(body).decode("ascii")
    value["runtime"].update({
        "requestBodyBase64": encoded, "unpaidBodyBase64": encoded, "paidBodyBase64": encoded,
    })


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
             authorization_submitted: bool | None = None, tamper=None) -> None:
    value = make_base(version)
    sent = value["runtime"]["paidHeaders"]["PAYMENT-SIGNATURE"]
    if mutate:
        mutate(value)
    rebind_solana_authorization(value)
    # XN-6: the paid payload follows the case's challenge and authorization,
    # unless the case itself changes the header's value. A case whose signed
    # material has no payload form keeps the base one; it fails before then.
    header = paid_signature_name(value)
    if header is not None and value["runtime"]["paidHeaders"][header] == sent:
        try:
            value["runtime"]["paidHeaders"][header] = payment_signature(value)
        except (AttributeError, KeyError, TypeError, ValueError):
            pass
    # A verifier judges a stored success record, which exists only after a
    # submission; it never authorizes itself.
    value["runtime"]["authorizationSubmitted"] = (
        operation == "verify-evidence" or (operation == "execute" and expected == "pass")
        if authorization_submitted is None
        else authorization_submitted
    )
    if refresh:
        refresh_received_hashes(value)
    sign_all(value)
    if tamper:
        # Changes signed bytes after signing, so a signature no longer verifies.
        tamper(value)
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
    elif expected == "pass":
        # A clean pass records no defect: `null` pins that, so a recorded
        # reason (such as booking a sound response as the seller's fault) fails.
        case["expectedReason"] = None
    if operation == "execute" and expected != "pass" and reason in FAILURE_MODE_ERROR_CLASSES:
        case["expectedErrorClass"] = FAILURE_MODE_ERROR_CLASSES[reason]
    vectors.append(case)


def build_vectors() -> list[dict]:
    vectors: list[dict] = []
    add_case(vectors, "protocol-v2-exact-success", "pass", "XN-1..XN-9",
             "provider-neutral v2 exact selection reaches independently verified finality")

    def signed_version(version):
        def mutate(v):
            for ref in (
                v["listing"]["acceptedRails"][0],
                v["agreement"]["terms"]["rail"],
                v["runtime"]["selectedRailRef"],
            ):
                ref["parameters"]["selection"]["x402Version"] = version
                ref["parameters"].pop("paymentRequiredExtensions", None)
            v["capability"]["supportedTuples"] = [[version, "exact", "eip155:8453"]]
        return mutate
    add_case(vectors, "v1-selection-outside-v08-profile", "error", "XN-2",
             "v0.8 binds only x402 version 2: a signed version-1 selection is malformed, so it "
             "rejects before the unpaid request and no v1 challenge is ever read",
             signed_version(1), reason="rail-ref-shape")

    def second_provider(v):
        other_url = "https://independent-seller.example/pay/274"
        for ref in (
            v["listing"]["acceptedRails"][0],
            v["agreement"]["terms"]["rail"],
            v["runtime"]["selectedRailRef"],
        ):
            ref["parameters"]["request"]["url"] = other_url
        send_requests_to(v, other_url)
        v["http"]["paymentRequired"]["resource"]["url"] = other_url
        v["evidence"]["paymentTxRefs"][0]["httpResource"] = other_url
    add_case(vectors, "independent-provider-same-protocol-rules", "pass", "XN-1..XN-4",
             "a second seller endpoint needs no provider-specific global rail entry",
             second_provider, refresh=True)

    def solana_exact(v, network=SOLANA_NETWORK, cluster="devnet", extra=None):
        extra = extra or {"feePayer": SOLANA_FEE_PAYER}
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
            "currency": "USDC",
            "tokenProgram": SOLANA_TOKEN_PROGRAM,
        }
        v["runtime"]["solanaAuthorization"] = SOLANA_PAYMENT_TRANSACTION
        v["runtime"]["reconciliationState"] = {
            "jobId": v["agreement"]["jobId"],
            "phaseIndex": v["runtime"]["phaseIndex"],
            "requirementHash": digest(v["agreement"]["terms"]["rail"]),
            "authorizationIdentity": solana_identity(
                SOLANA_PAYMENT_TRANSACTION, SOLANA_BUYER, SOLANA_FEE_PAYER)[0],
            "facilitator": v["runtime"]["facilitator"],
            "settlementTransaction": SOLANA_TX,
        }
        event = f"solana:{cluster}:{SOLANA_TX}:4"
        v["ledger"].update({
            "transactionBase64": SOLANA_FINAL_TRANSACTION,
            "network": network,
            "transaction": SOLANA_TX,
            "settlementEvent": event,
            "asset": SOLANA_ASSET,
            "payer": SOLANA_BUYER,
            "payTo": SOLANA_SELLER,
            "authorization": "solana-transfer",
            "sessionBinding": {"state": "absent"},
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

    # The duplicated ref is not the selected one, so the selected ref still
    # occurs once and only the duplicate check can reject the Listing.
    def duplicate_ref(v):
        other = copy.deepcopy(v["listing"]["acceptedRails"][0])
        other["parameters"]["selection"]["network"] = "eip155:1"
        v["listing"]["acceptedRails"] += [other, copy.deepcopy(other)]
    add_case(vectors, "listing-duplicate-canonical-ref", "fail", "XN-2/LRR-1",
             "duplicate full-canonical refs reject even when neither is the selected ref",
             duplicate_ref, reason="duplicate-listing-ref")

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
             "runtime selection of the first same-ID ref is non-conforming", first_id_runtime,
             reason="runtime-selection")

    def agreement_ref_not_listed(v):
        v["agreement"]["terms"]["rail"]["parameters"]["selection"]["maxTimeoutSeconds"] = 61
        v["runtime"]["selectedRailRef"] = copy.deepcopy(v["agreement"]["terms"]["rail"])
    add_case(vectors, "agreement-ref-not-full-jcs-member", "fail", "XN-2",
             "a co-signed partial/changed ref not in the Listing rejects", agreement_ref_not_listed,
             reason="listing-membership")

    def legacy_agreement(v):
        v["agreement"].pop("payeeBoundAgreementVersion")
        v["agreement"]["agreementVersion"] = "1"
    add_case(vectors, "protocol-legacy-agreement-artifact", "fail", "XN-2",
             "x402:protocol requires PayeeBoundAgreementDocument", legacy_agreement,
             reason="signature")

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
             lambda v: v["runtime"].update({"effectiveUrl": "https://attacker.example/pay"}),
             reason="effective-request")
    add_case(vectors, "lowercase-request-method", "error", "XN-2",
             "method must be the canonical uppercase token",
             lambda v: v["agreement"]["terms"]["rail"]["parameters"]["request"].update({"method": "get"}),
             reason="rail-ref-shape")
    add_case(vectors, "non-https-request-url", "error", "XN-2",
             "payable target must be absolute HTTPS",
             lambda v: v["agreement"]["terms"]["rail"]["parameters"]["request"].update({"url": "http://seller.example/pay"}),
             reason="rail-ref-shape")
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
            send_requests_to(v, target)
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
            send_requests_to(v, target)
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
            send_requests_to(v, target)
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
             lambda v: v["agreement"]["terms"]["rail"]["parameters"]["selection"].update({"network": "base"}),
             reason="rail-ref-shape")
    add_case(vectors, "numeric-version-replaced-by-string", "error", "XN-2/XN-7",
             "new evidence and selection use a number, never protocolVersion-style text",
             lambda v: v["agreement"]["terms"]["rail"]["parameters"]["selection"].update({"x402Version": "2"}),
             reason="rail-ref-shape")
    add_case(vectors, "negative-asset-decimals", "error", "XN-2/XN-5",
             "assetDecimals is a non-negative safe integer",
             lambda v: v["agreement"]["terms"]["rail"]["parameters"]["selection"].update({"assetDecimals": -1}),
             reason="rail-ref-shape")

    def unsupported_tuple(v):
        v["capability"]["supportedTuples"] = []
    add_case(vectors, "unsupported-local-capability", "fail", "XN-3",
             "unsupported tuple fails locally before authorization", unsupported_tuple,
             reason="x402-capability-unsupported")
    add_case(vectors, "counterparty-operator-config", "error", "XN-3",
             "operator configuration must come from trusted local policy",
             lambda v: v["runtime"].update({"operatorConfigSource": "payment-required-extension"}),
             reason="operator-config-source")
    add_case(vectors, "operator-routing-change-preserves-rail-identity", "pass", "XN-3",
             "changing local facilitator/RPC routing does not change the signed rail identity",
             lambda v: v["runtime"].update({"facilitator": "https://facilitator-b.example", "rpc": "https://rpc-b.example"}))

    add_case(vectors, "non-402-response-before-authorization", "fail", "XN-4",
             "a normal 200 response is not an x402 challenge",
             lambda v: v["http"].update({"status": 200}),
             reason="not-payment-required")
    # XN-4: only a definite non-payment answer fails. No answer, a server error,
    # a timeout or a rate limit is transient: nothing was authorized, so the
    # unpaid request is retried and no party is at fault.
    for name, expected, status, note in (
        ("unpaid-request-not-found-404", "fail", 404,
         "a 404 is a definite non-payment answer, not an x402 challenge"),
        ("unpaid-request-server-error-500", "indeterminate", 500,
         "a 500 to the unpaid request is transient and retryable"),
        ("unpaid-request-service-unavailable-503", "indeterminate", 503,
         "a 503 to the unpaid request is transient and retryable"),
        ("unpaid-request-gateway-timeout-504", "indeterminate", 504,
         "a 504 to the unpaid request is transient and retryable"),
        ("unpaid-request-timeout-408", "indeterminate", 408,
         "a 408 request timeout is transient and retryable"),
        ("unpaid-request-rate-limited-429", "indeterminate", 429,
         "a 429 rate limit is transient and retryable"),
        ("unpaid-request-no-answer", "indeterminate", None,
         "no answer to the unpaid request (a timeout) is transient and retryable"),
    ):
        add_case(vectors, name, expected, "XN-4", note,
                 lambda v, s=status: v["http"].update({"status": s}),
                 reason="not-payment-required" if expected == "fail" else "unpaid-request-transient")
    add_case(vectors, "challenge-resource-substitution", "fail", "XN-4",
             "resource URL substitution rejects before signing",
             lambda v: v["http"]["paymentRequired"]["resource"].update({"url": "https://attacker.example/pay"}),
             refresh=True, reason="challenge-match")

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
             "multiple exact matches are ambiguous", duplicate_accept, refresh=True,
             reason="challenge-match")
    for name, field, replacement in (
        ("challenge-network-substitution", "network", "eip155:1"),
        ("challenge-asset-substitution", "asset", "0x" + "99" * 20),
        ("challenge-timeout-substitution", "maxTimeoutSeconds", 61),
        ("challenge-amount-substitution", "amount", "1250001"),
        ("challenge-payto-substitution", "payTo", "0x" + "99" * 20),
    ):
        add_case(vectors, name, "fail", "XN-4/XN-5",
                 f"{field} substitution rejects before authorization",
                 lambda v, f=field, r=replacement: v["http"]["paymentRequired"]["accepts"][0].update({f: r}),
                 refresh=True, reason="challenge-match")
    add_case(vectors, "challenge-extra-substitution", "fail", "XN-4/XN-6",
             "the complete PaymentRequirements.extra object is bound",
             lambda v: v["http"]["paymentRequired"]["accepts"][0]["extra"].update({"spender": "attacker"}),
             refresh=True, reason="challenge-match")
    add_case(vectors, "challenge-extension-substitution", "fail", "XN-4/XN-6",
             "the complete top-level extensions object is bound",
             lambda v: v["http"]["paymentRequired"]["extensions"]["payment-identifier"]["schema"].update(
                 {"type": "string"}),
             refresh=True, reason="extensions")
    # XN-4: omitted and `{}` are distinct, in both directions.
    def signed_extensions(value):
        def mutate(v, value=value):
            for ref in (v["listing"]["acceptedRails"][0], v["agreement"]["terms"]["rail"],
                        v["runtime"]["selectedRailRef"]):
                if value is absent:
                    ref["parameters"].pop("paymentRequiredExtensions")
                else:
                    ref["parameters"]["paymentRequiredExtensions"] = value
            if value is absent:
                v["http"]["paymentRequired"]["extensions"] = {}
            else:
                v["http"]["paymentRequired"].pop("extensions")
        return mutate
    add_case(vectors, "challenge-extension-absent-vs-empty", "fail", "XN-4/XN-6",
             "a challenge that omits extensions does not match a signed empty object",
             signed_extensions({}), refresh=True, reason="extension-presence")
    add_case(vectors, "challenge-extension-empty-vs-absent", "fail", "XN-4/XN-6",
             "a challenge with empty extensions does not match a selection that omits them",
             signed_extensions(absent), refresh=True, reason="extension-presence")
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
    add_case(vectors, "optional-payment-identifier-needs-no-capability", "pass", "XN-6/§9.5.7.1",
             "the optional payment-identifier is descriptive, so a local capability that lists "
             "no extension still pays; only the required form is an unsupported action",
             lambda v: v["capability"].update({"understoodActionExtensions": []}))
    add_case(vectors, "redirected-payable-resource", "fail", "XN-6",
             "redirect following cannot change the signed payable target",
             lambda v: v["runtime"].update({"redirected": True, "effectiveUrl": "https://cdn.example/pay"}),
             reason="effective-request")

    def add_body_without_hash(v):
        send_body(v, b"{} ")
    add_case(vectors, "body-sent-without-signed-hash", "fail", "XN-6",
             "an absent bodyHash requires no request body", add_body_without_hash,
             reason="unsigned-request-body")

    def valid_body(v):
        body = b'{"job":"274"}'
        send_body(v, body)
        v["agreement"]["terms"]["rail"]["parameters"]["request"]["bodyHash"] = hashlib.sha256(body).hexdigest()
        v["listing"]["acceptedRails"][0] = copy.deepcopy(v["agreement"]["terms"]["rail"])
        v["runtime"]["selectedRailRef"] = copy.deepcopy(v["agreement"]["terms"]["rail"])
    add_case(vectors, "signed-request-body-hash", "pass", "XN-6",
             "exact body bytes match the signed sha256", valid_body)

    def wrong_decimals(v):
        v["capability"]["assetMetadata"]["decimals"] = 18
    add_case(vectors, "asset-decimals-adapter-mismatch", "fail", "XN-5",
             "signed decimals must match independent asset metadata", wrong_decimals,
             reason="asset-metadata")
    add_case(vectors, "agreement-price-excess-precision", "fail", "XN-5",
             "exact conversion never rounds excess fractional precision",
             lambda v: v["agreement"]["terms"]["price"].update({"amount": "1.0000001"}),
             reason="exact-amount")

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
             lambda v: v["runtime"]["payer"].update({"primaryClaim": "did:demos:agent:" + "99" * 32}),
             reason="payer-party")
    add_case(vectors, "runtime-paying-key-not-buyer-controlled", "fail", "XN-5",
             "the payment authorization key must be controlled by the signed buyer",
             lambda v: v["runtime"]["payer"].update({"payingKey": "did:demos:agent:" + "99" * 32}),
             reason="payer-control")
    add_case(vectors, "runtime-payer-address-not-derived-from-paying-key", "fail", "XN-5",
             "an attacker address cannot replace the address independently derived from the signed bundle payment key",
             lambda v: v["runtime"]["payer"].update({"paymentAddress": "0x" + "99" * 20}),
             reason="payer-control")
    add_case(vectors, "runtime-payee-not-signed-destination", "fail", "XN-5",
             "an unsigned runtime payee cannot replace the payout binding",
             lambda v: v["runtime"]["payee"].update({"payeeAddress": "0x" + "99" * 20}),
             reason="payout-binding")
    add_case(vectors, "ledger-payer-substitution", "fail", "XN-5/XN-8",
             "authenticated event payer must be the buyer-controlled authorization payer",
             lambda v: v["ledger"].update({"payer": "0x" + "99" * 20}),
             authorization_submitted=True,
             reason="ledger-event")
    add_case(vectors, "ledger-payee-substitution", "fail", "XN-5/XN-8",
             "authenticated event destination must be the signed payout binding",
             lambda v: v["ledger"].update({"payTo": "0x" + "99" * 20}),
             authorization_submitted=True,
             reason="ledger-event")

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
    add_case(vectors, "solana-response-payer-case-changed", "pass", "XN-5/XN-11",
             "one changed letter case in the Solana response payer names a different payer, "
             "a response defect; the exact finalized settlement stands",
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
    add_case(vectors, "response-payer-not-20-bytes", "pass", "XN-5/XN-11",
             "an EIP-155 response payer that is not 0x plus 40 hex digits is a response "
             "defect, not a malformed coordinate; the exact finalized settlement stands",
             response_payer(BUYER_ADDRESS + "00"), refresh=True,
             authorization_submitted=True, reason="response-payer")

    # A stored success record is judged by `verify-evidence`, the XN-7/XN-8
    # verifier: its verdict is on the record. The handler's payment disposition
    # never comes from it (XN-11; see the stored-record execute cases below).
    add_case(vectors, "payment-required-hash-substitution", "fail", "XN-7",
             "stored challenge hash must recompute from the complete object",
             lambda v: v["evidence"]["paymentTxRefs"][0].update({"paymentRequiredHash": "00" * 32}),
             operation="verify-evidence", reason="payment-required-hash")
    add_case(vectors, "payment-receipt-hash-substitution", "fail", "XN-7",
             "stored receipt hash must recompute from the complete response",
             lambda v: v["evidence"]["paymentTxRefs"][0].update({"paymentReceiptHash": "00" * 32}),
             operation="verify-evidence", reason="payment-receipt-hash")
    # XN-11: after authorization only the authenticated ledger decides. Each
    # response defect below sits over the base ledger, an exact finalized
    # settlement, so the payment settled and the defect is the reason: the
    # seller's recorded protocol fault. Its -no-settlement twin has no ledger
    # data, so reconciliation stays pending instead of failing on the response.
    def response_defect(name, note, mutate, fault):
        add_case(vectors, name, "pass", "XN-7/XN-11",
                 f"{note}; the exact finalized settlement stands and the defect is the "
                 "seller's recorded protocol fault",
                 mutate, refresh=True, authorization_submitted=True, reason=fault)

        def no_settlement(v):
            mutate(v)
            v.pop("ledger")
        add_case(vectors, f"{name}-no-settlement", "indeterminate", "XN-7/XN-11",
                 f"{note}; with no matching settlement reconciliation stays pending, "
                 "never a permanent failure from the response alone",
                 no_settlement, refresh=True, authorization_submitted=True,
                 reason="independent-settlement-unavailable")

    response_defect("wrong-version-response-header",
                    "a v2 session reads only PAYMENT-RESPONSE, so a response under the v1 "
                    "header is not received and the receipt preimage is JSON null",
                    lambda v: v["http"]["responseHeader"].update({"name": "X-PAYMENT-RESPONSE"}),
                    "response-header")

    def response_not_success(v):
        response = settlement_response(2)
        response.update({"success": False, "errorReason": "unexpected_settle_error",
                         "transaction": ""})
        v["http"]["responseHeader"] = encoded_header(response, 2)
    response_defect("response-not-success",
                    "a response reporting success false cannot undo a settlement the "
                    "ledger proves", response_not_success, "response-not-success")

    def response_network_mismatch(v):
        response = settlement_response(2)
        response["network"] = "eip155:1"
        v["http"]["responseHeader"] = encoded_header(response, 2)
    response_defect("response-network-substitution",
                    "a fully rehashed response naming another network is a response defect",
                    response_network_mismatch, "response-network")

    def response_transaction_mismatch(v):
        response = settlement_response(2)
        response["transaction"] = "0x" + "cd" * 32
        v["http"]["responseHeader"] = encoded_header(response, 2)
    response_defect("response-transaction-substitution",
                    "a fully rehashed response naming another transaction than the one the "
                    "ledger establishes is a response defect",
                    response_transaction_mismatch, "response-transaction")

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
    for name, spelling, note in (
        ("response-transaction-unprefixed", SAFE_TX,
         "a hash without a prefix is already the canonical form"),
        ("response-transaction-0x-mixed-case", "0x" + "Ab" * 32,
         "hex digits compare case-insensitively"),
        ("response-transaction-0X-uppercase", "0X" + SAFE_TX.upper(),
         "an upper-case 0X prefix is one allowed prefix"),
    ):
        add_case(vectors, name, "pass", "XN-7/XN-8/SB-1", note,
                 response_transaction_spelling(spelling), refresh=True,
                 authorization_submitted=True)
    # A malformed hash in the signed settlementTransaction is a malformed
    # coordinate of the record; the response stays sound.
    for name, spelling, note in (
        ("evidence-transaction-63-hex-digits", "0x" + SAFE_TX[:63],
         "a recorded hash that is not exactly 32 bytes has no canonical form"),
        ("evidence-transaction-double-0x-prefix", "0x0x" + SAFE_TX,
         "at most one prefix is removed, so a second 0x in the record is malformed"),
    ):
        add_case(vectors, name, "error", "XN-7/XN-8/SB-1", note,
                 lambda v, s=spelling: v["evidence"]["paymentTxRefs"][0].update(
                     {"settlementTransaction": s}),
                 operation="verify-evidence", reason="settlement-transaction-form")

    # The same malformed hash in the response alone is a response defect: the
    # record names the reconciled transaction and the ledger decides (XN-11).
    def malformed_response_transaction(v):
        response = settlement_response(2)
        response["transaction"] = "0x" + SAFE_TX[:63]
        v["http"]["responseHeader"] = encoded_header(response, 2)
    response_defect("response-transaction-not-32-bytes",
                    "a response transaction of 63 hexadecimal digits has no XN-7 adapter form",
                    malformed_response_transaction, "response-transaction")

    def response_payer_mismatch(v):
        response = settlement_response(2)
        response["payer"] = "0x" + "99" * 20
        v["http"]["responseHeader"] = encoded_header(response, 2)
    response_defect("response-payer-substitution",
                    "a response payer other than the buyer-controlled payer is a response defect",
                    response_payer_mismatch, "response-payer")

    def protocol_version_field(v):
        ref = v["evidence"]["paymentTxRefs"][0]
        ref["protocolVersion"] = str(ref.pop("x402Version"))
    add_case(vectors, "new-evidence-uses-legacy-protocolversion", "error", "XN-7/XN-10",
             "x402-protocol evidence cannot emit legacy protocolVersion", protocol_version_field,
             operation="verify-evidence", reason="evidence-ref-shape")
    add_case(vectors, "ledger-unavailable-after-submission", "indeterminate", "XN-8/XN-11",
             "receipt acknowledgement without authenticated ledger data is not success",
             lambda v: v["ledger"].update({"available": False}),
             authorization_submitted=True,
             reason="independent-settlement-unavailable")
    add_case(vectors, "acknowledgement-only-no-transaction", "indeterminate", "XN-8",
             "a signed/hashed server acknowledgement alone cannot produce success",
             lambda v: v.pop("ledger"), authorization_submitted=True,
             reason="independent-settlement-unavailable")
    add_case(vectors, "ledger-event-amount-mismatch", "fail", "XN-5/XN-8",
             "the authenticated event amount must be exact",
             lambda v: v["ledger"].update({"amount": "1249999"}),
             authorization_submitted=True,
             reason="ledger-event")
    add_case(vectors, "ledger-not-final", "indeterminate", "XN-8",
             "included but non-final settlement is not success",
             lambda v: v["ledger"].update({"finalized": False}),
             authorization_submitted=True,
             reason="settlement-not-final")

    # The record's key alone is malformed: the ledger keeps its canonical key,
    # since a malformed ledger coordinate is an error of the reconciliation.
    def noncanonical_event(v):
        v["evidence"]["paymentTxRefs"][0]["settlementEvent"] = f"evm:8453:0x{SAFE_TX}:7"
    add_case(vectors, "noncanonical-native-event-key", "error", "XN-8/SB-1",
             "a noncanonical event spelling cannot mint another SB-1 identity",
             noncanonical_event, operation="verify-evidence", reason="native-event-key")

    def uppercase_event(v):
        v["evidence"]["paymentTxRefs"][0]["settlementEvent"] = f"evm:8453:{SAFE_TX.upper()}:7"
    add_case(vectors, "noncanonical-native-event-key-uppercase", "error", "XN-8/SB-1",
             "an upper-case EVM hash cannot mint another SB-1 identity",
             uppercase_event, operation="verify-evidence", reason="native-event-key")
    add_case(vectors, "native-event-coordinate-substitution", "fail", "XN-8/SB-1",
             "a different signed event coordinate cannot match authenticated ledger data",
             lambda v: v["evidence"]["paymentTxRefs"][0].update({
                 "settlementEvent": f"evm:8453:{SAFE_TX}:8"
             }), operation="verify-evidence",
             reason="ledger-event")
    add_case(vectors, "finality-profile-network-substitution", "fail", "XN-8",
             "the signed finality profile must repeat the selected scheme and network",
             lambda v: v["evidence"]["settlementFinality"]["schemeNetworkFinality"].update({
                 "network": "eip155:1"
             }), operation="verify-evidence",
             reason="finality-profile")
    add_case(vectors, "finality-binding-profile-substitution", "fail", "XN-8",
             "the finality binding profile must name the exact v0.8 DACS semantics",
             lambda v: v["evidence"]["settlementFinality"]["schemeNetworkFinality"].update({
                 "bindingProfile": "counterparty-profile:v1"
             }), operation="verify-evidence",
             reason="finality-profile")
    add_case(vectors, "event-key-cross-rail-alias", "pass", "XN-8/SB-1",
             "EIP-155 x402 evidence emits the same evm event key as the direct rail")

    # XN-9/SB-3: the EIP-155 exact binding always requires the SB-3 job
    # binding, so its four branches apply whatever form the event shows. The
    # ledger matches the evidence in every case; only the binding differs. The
    # evidence uses the sb3-binding-required set's closed `{"state"}` model and
    # state list, so every `unavailable-*` state is unresolved, never malformed.
    def session_binding(binding, authorization="eip-3009"):
        def mutate(v):
            v["ledger"]["authorization"] = authorization
            if binding is absent:
                v["ledger"].pop("sessionBinding")
            else:
                v["ledger"]["sessionBinding"] = binding
        return mutate
    for name, expected, binding, note in (
        ("sb3-binding-mismatch", "fail", {"state": "mismatch"},
         "a verified EIP-3009 nonce derived for another job or phase rejects the evidence"),
        ("sb3-binding-absent", "indeterminate", {"state": "absent"},
         "an EIP-3009 transfer without the derived job nonce is non-countable, never unbound success"),
        ("sb3-binding-unverifiable", "indeterminate", {"state": "unavailable-rpc"},
         "binding evidence that the RPC cannot serve now keeps the settlement non-countable"),
        ("sb3-binding-unavailable-pruned-history", "indeterminate",
         {"state": "unavailable-pruned-history"},
         "pruned history leaves the binding unverifiable, so the settlement stays non-countable"),
        ("sb3-binding-unavailable-signature-authority", "indeterminate",
         {"state": "unavailable-signature-authority"},
         "an unresolved ERC-1271 isValidSignature leaves the binding unverifiable"),
        ("sb3-binding-unavailable-reorged", "indeterminate", {"state": "unavailable-reorged"},
         "a reorganisation that removed the binding observation is unresolved, never malformed"),
        ("sb3-binding-evidence-missing", "error", absent,
         "a missing binding-evidence value is malformed, not unavailable"),
        ("sb3-binding-evidence-null", "error", None,
         "a non-object binding-evidence value is malformed"),
        ("sb3-binding-unknown-state", "error", {"state": "future-state"},
         "an unknown binding state is malformed"),
        ("sb3-binding-bare-unavailable-state", "error", {"state": "unavailable"},
         "a bare unavailable state is not one of the sb3-binding-required states, so it is malformed"),
        ("sb3-binding-malformed-state", "error", {"state": "malformed"},
         "the malformed state is SB-3's malformed branch"),
        ("sb3-binding-extra-member", "error", {"state": "match", "observedAt": 1787443201000},
         "binding evidence is the closed {state} object, so an extra member is malformed"),
    ):
        add_case(vectors, name, expected, "XN-9/SB-3", note, session_binding(binding),
                 authorization_submitted=True, reason="sb3")
    add_case(vectors, "sb3-earlier-plain-transfer-cannot-replace-binding", "indeterminate",
             "XN-9/SB-3",
             "an earlier plain ERC-20 transfer from the buyer to the seller for the same amount "
             "carries no job binding; the policy comes from the pinned definition, not from the "
             "observed transfer form, so the payment stays non-countable",
             session_binding({"state": "absent"}, authorization="erc20-transfer"),
             authorization_submitted=True, reason="sb3")

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
    add_case(vectors, "batch-commitment-is-not-financial-settlement", "fail", "XN-9",
             "batch commitment acceptance is never eventual settlement and v0.8 has no "
             "binding for it, so a supported batch-settlement tuple is refused before "
             "authorization with no wallet call", batch_ack,
             reason="x402-capability-unsupported")

    def disabled_default(v):
        v["railDefinition"] = legacy_rail()
        v["runtime"]["sessionState"] = "new"
    add_case(vectors, "legacy-default-new-session-disabled", "fail", "XN-10/RAV-R2",
             "x402:default cannot start a new session", disabled_default,
             operation="new-session",
             reason="legacy-default-new-session")

    def pinned_live_default(v):
        v["railDefinition"] = legacy_live_rail()
        v["runtime"]["sessionState"] = "new"
    add_case(vectors, "legacy-default-pinned-live-new-session", "fail", "XN-10",
             "pinning the historical live revision cannot bypass the new-session prohibition",
             pinned_live_default, operation="new-session",
             reason="legacy-default-new-session")

    legacy_response = {**settlement_response(2), "transaction": SAFE_TX}

    def legacy_replay(v):
        v["railDefinition"] = legacy_live_rail()
        v["evidence"]["paymentTxRefs"] = [{
            "kind": "x402-event",
            "httpResource": URL,
            "paymentReceiptHash": digest(legacy_response),
            "settlementTxHash": SAFE_TX,
            "chainId": 8453,
            "logIndex": 7,
            "protocolVersion": "2",
        }]
        # X402-1: the version-selected response the record was hashed over.
        v["http"]["responseHeader"] = encoded_header(legacy_response, 2)
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
    # X402-1..X402-4: the negotiated XN-11 policy never reaches the legacy
    # path, so a finalized ledger settlement cannot replace the response.
    for name, change in (
        ("missing", lambda http: http.pop("responseHeader")),
        ("malformed", lambda http: http["responseHeader"].update({"value": "not base64!"})),
        ("non-success", lambda http: http.update({"responseHeader": encoded_header(
            {**settlement_response(2), "success": False}, 2)})),
    ):
        def legacy_bad_response(v, change=change):
            legacy_continuation(v)
            change(v["http"])
        add_case(vectors, f"legacy-continuation-response-{name}-ledger-settled", "fail",
                 "X402-1/X402-4/XN-10",
                 "the ledger shows the exact finalized settlement, but a legacy session needs the "
                 "complete successful response, so it cannot become legacy success",
                 legacy_bad_response, operation="legacy-continuation",
                 authorization_submitted=True, reason="legacy-response")
    # X402-1..X402-4: a successful response must still verify against the
    # record: its schema, the recomputed receipt hash, and the recorded
    # transaction and chain. `rehash` re-commits the record to the changed
    # response, so only X402-3 can reject it.
    for name, change, rehash, reason, note in (
        ("other-transaction", {"transaction": "cd" * 32}, False, "legacy-receipt-hash",
         "another transaction does not recompute the stored receipt hash"),
        ("other-transaction-rehashed", {"transaction": "cd" * 32}, True,
         "legacy-receipt-transaction", "the transaction equals the recorded settlementTxHash"),
        ("other-network-rehashed", {"network": "eip155:1"}, True, "legacy-receipt-network",
         "the network maps to the recorded chainId"),
        ("without-transaction-rehashed", {"transaction": None}, True, "legacy-response",
         "a SettlementResponse names its transaction"),
        ("without-network-rehashed", {"network": None}, True, "legacy-response",
         "a SettlementResponse names its network"),
        ("other-header-name", "X-PAYMENT-RESPONSE", False, "legacy-response",
         "protocolVersion \"2\" selects PAYMENT-RESPONSE"),
    ):
        def legacy_mismatch(v, change=change, rehash=rehash):
            legacy_continuation(v)
            if isinstance(change, str):
                v["http"]["responseHeader"]["name"] = change
                return
            response = {key: item for key, item in {**legacy_response, **change}.items()
                        if item is not None}
            v["http"]["responseHeader"] = encoded_header(response, 2)
            if rehash:
                v["evidence"]["paymentTxRefs"][0]["paymentReceiptHash"] = digest(response)
        add_case(vectors, f"legacy-continuation-response-{name}", "fail", "X402-1..X402-4/XN-10",
                 note, legacy_mismatch, operation="legacy-continuation",
                 authorization_submitted=True, reason=reason)
    add_case(vectors, "legacy-continuation-stored-hash-upper-case", "fail", "X402-2/X402-4",
             "a non-canonical stored receipt hash is rejected, never repaired",
             lambda v: (legacy_continuation(v), v["evidence"]["paymentTxRefs"][0].update(
                 {"paymentReceiptHash": digest(legacy_response).upper()})),
             operation="legacy-continuation", authorization_submitted=True,
             reason="legacy-receipt-hash")
    add_case(vectors, "legacy-replay-presented-response-other-transaction", "fail", "X402-4",
             "a replay verifier presented with the response applies X402-1..X402-3",
             lambda v: (legacy_replay(v), v["http"].update({"responseHeader": encoded_header(
                 {**legacy_response, "transaction": "cd" * 32}, 2)}),
                 v["evidence"]["paymentTxRefs"][0].update({"paymentReceiptHash": digest(
                     {**legacy_response, "transaction": "cd" * 32})})),
             operation="legacy-replay", authorization_submitted=True,
             reason="legacy-receipt-transaction")
    # X402-1/X402-3: a v1 record selects X-PAYMENT-RESPONSE, and its v1 network
    # maps to the recorded chainId through the registered v1 mapping. The
    # receipt is the x402-receipt-hash corpus's v1 `pass` case.
    def legacy_v1(network="base-sepolia", chain_id=84532):
        def mutate(v):
            legacy_replay(v)
            response = {**V1_RECEIPT, "network": network}
            raw = json.dumps(response, separators=(",", ":")).encode("utf-8")
            v["http"]["responseHeader"] = {
                "name": "X-PAYMENT-RESPONSE", "value": base64.b64encode(raw).decode("ascii"),
            }
            v["evidence"]["paymentTxRefs"][0].update({
                "paymentReceiptHash": digest(response),
                "settlementTxHash": V1_RECEIPT["transaction"],
                "chainId": chain_id,
                "protocolVersion": "1",
            })
            v["runtime"]["sessionState"] = "in-flight"
        return mutate
    add_case(vectors, "legacy-v1-continuation-registered-network", "pass", "X402-1..X402-4/XN-10",
             "a v1 receipt's base-sepolia maps to the recorded chainId 84532 through the "
             "registered v1 mapping", legacy_v1(), operation="legacy-continuation",
             authorization_submitted=True)
    add_case(vectors, "legacy-v1-replay-presented-response", "pass", "X402-4",
             "a replay verifier presented with the v1 response maps its network the same way",
             legacy_v1(), operation="legacy-replay", authorization_submitted=True)
    for name, network, chain_id, note in (
        ("other-chain", "base-sepolia", 8453, "base-sepolia maps to 84532, not the recorded 8453"),
        ("unregistered-network", "iotex", 84532,
         "a v1 network the registered mapping does not name maps to no chain"),
    ):
        add_case(vectors, f"legacy-v1-continuation-{name}", "fail", "X402-3", note,
                 legacy_v1(network, chain_id), operation="legacy-continuation",
                 authorization_submitted=True, reason="legacy-receipt-network")

    # XN-11 retry: the retained identity must be this session's, and then the
    # payment disposition is the ledger reconciliation's, as after the execute
    # path's wallet call. Unavailable ledger data keeps the session pending.
    pending = "independent-settlement-unavailable"

    def retry_pending(v):
        v["ledger"]["available"] = False
        v["runtime"]["retryWouldAuthorize"] = False
    add_case(vectors, "retry-indeterminate-remains-pending", "indeterminate", "XN-11",
             "indeterminate observation reconciles without a second authorization and stays pending",
             retry_pending, operation="retry", authorization_submitted=True, reason=pending)

    def retry_hostile_reauthorization_request(v):
        v["ledger"]["available"] = False
        v["runtime"]["retryWouldAuthorize"] = True
    add_case(vectors, "retry-caller-reauthorization-request-is-ignored", "indeterminate", "XN-11",
             "a caller request cannot make reconciliation authorize another payment",
             retry_hostile_reauthorization_request, operation="retry",
             authorization_submitted=True, reason=pending)

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

    # A stored record is never part of the retained identity: on retry, as
    # after the wallet call, it is judged only once the ledger has decided, and
    # its defect is the recorded reason (XN-11).
    def retry_transaction_mismatch(v):
        v["evidence"]["paymentTxRefs"][0]["settlementTransaction"] = "cd" * 32
    add_case(vectors, "retry-record-transaction-substitution-settled", "pass", "XN-11/XN-8",
             "a re-signed record naming another transaction, while its event key still names "
             "the reconciled one, does not verify; the retry rebuilds it and the ledger decides",
             retry_transaction_mismatch, operation="retry", authorization_submitted=True,
             reason="native-event-key")

    def retry_retained_transaction_spelling(v):
        v["runtime"]["reconciliationState"]["settlementTransaction"] = SAFE_TX.upper()
    add_case(vectors, "retry-retained-transaction-spelling-reconciles", "pass",
             "XN-11/XN-7",
             "a retained transaction that differs from the reconciled one only by prefix and "
             "case names it in the XN-7 adapter form, so it is no response defect",
             retry_retained_transaction_spelling, operation="retry",
             authorization_submitted=True)

    def retry_identical_malformed_transaction(v):
        v["evidence"]["paymentTxRefs"][0]["settlementTransaction"] = "not-a-hash"
        v["runtime"]["reconciliationState"]["settlementTransaction"] = "not-a-hash"
    add_case(vectors, "retry-identical-malformed-transaction-settled", "pass", "XN-11/XN-7",
             "identical retained and recorded transactions with no XN-7 adapter form never "
             "decide; the retained one is the response's, so it is the recorded defect",
             retry_identical_malformed_transaction, operation="retry",
             authorization_submitted=True, reason="response-transaction")

    def retry_recorded_malformed_transaction(v):
        v["ledger"]["available"] = False
        v["evidence"]["paymentTxRefs"][0]["settlementTransaction"] = "not-a-hash"
    add_case(vectors, "retry-record-malformed-transaction-ledger-unavailable", "indeterminate",
             "XN-11/XN-7",
             "a recorded transaction with no XN-7 adapter form is a verifier's error, but it "
             "never decides the retry: the unavailable ledger keeps it pending",
             retry_recorded_malformed_transaction, operation="retry",
             authorization_submitted=True, reason=pending)

    # The authorization identity is the authorization payer, an XN-5 address.
    # Neither side is in the lower-case form, so the adapter must convert both.
    def retry_authorization_identity_spelling(v):
        v["ledger"]["available"] = False
        v["runtime"]["payer"]["paymentAddress"] = "0x" + BUYER_ADDRESS[2:].upper()
        v["runtime"]["reconciliationState"]["authorizationIdentity"] = eip55(BUYER_ADDRESS)
    add_case(vectors, "retry-authorization-identity-eip55-reconciles", "indeterminate",
             "XN-11/XN-5",
             "a retained EIP-55 authorization identity reconciles with the same payer in "
             "upper-case hex, since both compare as 20-byte values; the unavailable ledger "
             "keeps it pending",
             retry_authorization_identity_spelling, operation="retry",
             authorization_submitted=True, reason=pending)

    def retry_identical_malformed_authorization_identity(v):
        v["ledger"]["available"] = False
        v["runtime"]["payer"]["paymentAddress"] = BUYER_ADDRESS[:-2]
        v["runtime"]["reconciliationState"]["authorizationIdentity"] = BUYER_ADDRESS[:-2]
    add_case(vectors, "retry-authorization-identity-not-20-bytes", "error", "XN-11/XN-5",
             "identical retained and session authorization identities that are not 0x plus "
             "40 hex digits are a malformed coordinate",
             retry_identical_malformed_authorization_identity, operation="retry",
             authorization_submitted=True, reason="address-form")

    # XN-11 response loss: the wallet authorized, the response was lost, and no
    # transaction is known. Nothing signed records one yet, so there is no
    # evidence, and the retained state has no transaction (absent or null). The
    # ledger reconciliation of the authorization identity still decides.
    def retry_response_lost(keep_null, ledger=None):
        def mutate(v):
            if ledger is None:
                v["ledger"]["available"] = False
            else:
                ledger(v)
            v.pop("evidence")
            state = v["runtime"]["reconciliationState"]
            if keep_null:
                state["settlementTransaction"] = None
            else:
                del state["settlementTransaction"]
        return mutate
    add_case(vectors, "retry-response-lost-no-transaction-known", "indeterminate", "XN-11",
             "after a lost response no transaction is known and no evidence exists; the "
             "identity reconciles on its other values and the unavailable ledger keeps it pending",
             retry_response_lost(False), operation="retry",
             authorization_submitted=True, reason=pending)
    add_case(vectors, "retry-response-lost-transaction-null", "indeterminate", "XN-11",
             "a retained null settlementTransaction means none is known, not a malformed one; "
             "reconciliation stays pending",
             retry_response_lost(True), operation="retry",
             authorization_submitted=True, reason=pending)
    add_case(vectors, "retry-response-lost-ledger-settled", "pass", "XN-11",
             "after a lost response, with no evidence and no known transaction, an exact "
             "finalized settlement of the authorization identity is success; the evidence is "
             "built from the retained material",
             retry_response_lost(False, ledger=lambda v: None), operation="retry",
             authorization_submitted=True)

    def authorization_state(state, timestamp=None):
        # The finalized ledger's EIP-3009 nonce state for the identity, at a
        # finalized block whose authenticated timestamp is given when known.
        def mutate(v):
            v["ledger"] = {"available": True, "finalized": True, "nonceState": state}
            if timestamp is not None:
                v["ledger"]["finalizedBlockTimestamp"] = timestamp
        return mutate
    add_case(vectors, "retry-response-lost-authorization-cancelled", "fail", "XN-11/SB-3",
             "after a lost response the ledger proves the authorization was cancelled with no "
             "transfer: a terminal non-settlement",
             retry_response_lost(False, ledger=authorization_state("cancelled")),
             operation="retry", authorization_submitted=True, reason="terminal-non-settlement")
    # XN-11: EIP-3009 requires block.timestamp < validBefore, so only a
    # finalized block at or after validBefore, with the nonce still unused,
    # proves the authorization can never settle. No local clock decides.
    for name, timestamp, verdict, reason, note in (
        ("before", VALID_BEFORE - 1, "indeterminate", "authorization-unsettled",
         "one second before validBefore the authorization can still be submitted"),
        ("equal", VALID_BEFORE, "fail", "terminal-non-settlement",
         "at validBefore EIP-3009 already refuses the authorization"),
        ("after", VALID_BEFORE + 1, "fail", "terminal-non-settlement",
         "after validBefore with the nonce unused the authorization can never settle"),
        ("unavailable", None, "indeterminate", "authorization-unsettled",
         "without an authenticated finalized block timestamp nothing proves expiry"),
        ("malformed", "1787443260", "error", "ledger-block-timestamp",
         "a block timestamp that is not a safe integer is a malformed ledger value"),
    ):
        add_case(vectors, f"retry-eip3009-expiry-block-{name}", verdict, "XN-11",
                 f"the nonce is unused at a finalized block: {note}",
                 retry_response_lost(False, ledger=authorization_state("unused", timestamp)),
                 operation="retry", authorization_submitted=True, reason=reason)

    def expiry_without_retained_valid_before(v):
        retry_response_lost(False, ledger=authorization_state("unused", VALID_BEFORE + 1))(v)
        del v["runtime"]["reconciliationState"]["validBefore"]
    add_case(vectors, "retry-eip3009-expiry-without-retained-valid-before", "indeterminate", "XN-11",
             "a handler that kept no validBefore cannot prove expiry from the ledger's clock alone",
             expiry_without_retained_valid_before, operation="retry",
             authorization_submitted=True, reason="authorization-unsettled")
    for name, retained in (("decimal-string", str(VALID_BEFORE)), ("unsafe", 2**53), ("boolean", True)):
        def malformed_retained(v, retained=retained):
            retry_response_lost(False, ledger=authorization_state("unused", VALID_BEFORE + 1))(v)
            v["runtime"]["reconciliationState"]["validBefore"] = retained
        add_case(vectors, f"retry-eip3009-retained-valid-before-{name}", "error", "XN-11",
                 "the retained validBefore is integer seconds, a safe integer; another form is "
                 "malformed retained state, never an expiry proof",
                 malformed_retained, operation="retry", authorization_submitted=True,
                 reason="authorization-valid-before")
    add_case(vectors, "retry-eip3009-nonce-state-unknown", "error", "XN-11",
             "a nonce state outside unused, used and cancelled is malformed ledger data",
             retry_response_lost(False, ledger=authorization_state("expired", VALID_BEFORE + 1)),
             operation="retry", authorization_submitted=True, reason="ledger-nonce-state")
    add_case(vectors, "retry-eip3009-expiry-not-final", "indeterminate", "XN-11",
             "a block past validBefore that is not yet final proves nothing: a reorganisation "
             "could still include the authorization",
             retry_response_lost(False, ledger=lambda v: v["ledger"].clear() or v["ledger"].update({
                 "available": True, "finalized": False, "nonceState": "unused",
                 "finalizedBlockTimestamp": VALID_BEFORE + 1})),
             operation="retry", authorization_submitted=True, reason="settlement-not-final")
    add_case(vectors, "retry-ledger-event-contradicts-authorization", "fail", "XN-11/XN-8",
             "the event the authorization identity resolves to moves another amount: a resolved "
             "contradiction, so the retry fails from the ledger",
             lambda v: v["ledger"].update({"amount": "1249999"}), operation="retry",
             authorization_submitted=True, reason="ledger-event")

    # XN-5 leaves Solana exact at the retry site too: the unchanged retained
    # state reconciles, so one changed letter case is the only difference.
    def retry_solana_authorization_identity_case_changed(v):
        solana_exact(v)
        v["ledger"]["available"] = False
        v["runtime"]["reconciliationState"].update({
            "requirementHash": digest(v["agreement"]["terms"]["rail"]),
            "authorizationIdentity": {
                **v["runtime"]["reconciliationState"]["authorizationIdentity"],
                "payer": SOLANA_BUYER.replace("k", "K", 1),
            },
            "settlementTransaction": SOLANA_TX,
        })
    add_case(vectors, "retry-solana-authorization-identity-case-changed", "fail", "XN-11/XN-5",
             "base58 is case-sensitive, so a retained Solana authorization identity with one "
             "changed letter case differs from the retained signed authorization",
             retry_solana_authorization_identity_case_changed, operation="retry",
             authorization_submitted=True, reason="reconciliation-binding")

    # Every evaluator check has a case that reaches it alone: each input differs
    # from a passing fixture only in what that check reads, and the reason is
    # pinned, so deleting the check changes the verdict or the reason.
    def signed_selection_refs(v):
        return (v["listing"]["acceptedRails"][0], v["agreement"]["terms"]["rail"],
                v["runtime"]["selectedRailRef"])

    # Before authorization: definition, listing, parties and payer control.
    add_case(vectors, "execute-with-hybrid-definition", "error", "XN-1",
             "the execute path re-validates the pinned protocol definition",
             lambda v: v["railDefinition"].update({"asset": {"kind": "erc20"}}),
             reason="definition")
    add_case(vectors, "listing-accepted-rails-empty", "fail", "XN-2",
             "a Listing with no accepted rails cannot contain the selected ref",
             lambda v: v["listing"].update({"acceptedRails": []}), reason="listing-membership")
    add_case(vectors, "listing-accepted-rails-absent", "fail", "XN-2",
             "a Listing without acceptedRails cannot contain the selected ref",
             lambda v: v["listing"].pop("acceptedRails"), reason="listing-membership")
    add_case(vectors, "runtime-selected-ref-out-of-profile-number", "fail", "XN-2",
             "an unsigned runtime ref whose railVersion is outside the CORE number profile "
             "is not the selected ref, never an exception",
             lambda v: v["runtime"]["selectedRailRef"].update({"railVersion": 2**53}),
             reason="runtime-selection")
    add_case(vectors, "rail-ref-extra-member", "error", "XN-2",
             "a selected ref with a member outside railId, railVersion and parameters is malformed",
             lambda v: v["agreement"]["terms"]["rail"].update({"provider": "facilitator.example"}),
             reason="rail-ref-shape")

    def body_hash_upper_case(v):
        valid_body(v)
        for ref in signed_selection_refs(v):
            request = ref["parameters"]["request"]
            request["bodyHash"] = request["bodyHash"].upper()
    add_case(vectors, "request-body-hash-upper-case", "error", "XN-2",
             "a signed bodyHash is exactly 64 lower-case hexadecimal digits",
             body_hash_upper_case, reason="rail-ref-shape")
    add_case(vectors, "payout-binding-duplicated", "fail", "XN-5/PB-1",
             "exactly one payout binding may name (x402:protocol, phaseIndex)",
             lambda v: v["agreement"]["terms"]["payoutBindings"].append(
                 copy.deepcopy(v["agreement"]["terms"]["payoutBindings"][0])),
             reason="payout-binding")
    add_case(vectors, "challenge-scheme-substitution", "fail", "XN-4",
             "scheme substitution rejects before authorization",
             lambda v: v["http"]["paymentRequired"]["accepts"][0].update({"scheme": "upto"}),
             reason="challenge-match")

    # Artifact signatures: each case changes signed bytes after signing.
    for name, tamper, note, operation in (
        ("definition-signature-invalid",
         lambda v: v["railDefinition"].update({"railVersion": 2}),
         "the pinned protocol definition must carry the steward's valid signature", "execute"),
        ("listing-signature-invalid",
         lambda v: v["listing"].update({"listingVersion": 2}),
         "the Listing must carry the seller's valid signature", "execute"),
        ("agreement-signature-invalid",
         lambda v: v["agreement"]["terms"]["price"].update({"amount": "1.26"}),
         "the agreement must carry both parties' valid signatures", "execute"),
        ("buyer-bundle-presentation-signature-invalid",
         lambda v: v["buyerBundle"]["presentation"]["signatures"][1].update(
             {"signature": flip_first(v["buyerBundle"]["presentation"]["signatures"][1]["signature"])}),
         "the buyer bundle's per-claim presentation signatures must verify", "execute"),
        ("evidence-signature-invalid",
         lambda v: v["evidence"].update({"observedAt": 1787443202000}),
         "settlement evidence must carry the orchestrator's valid signature", "verify-evidence"),
    ):
        add_case(vectors, name, "fail", "SIG-2", note, tamper=tamper, operation=operation,
                 reason="signature")

    # Payer control over the presented bundle.
    def presented_bundle(**variant):
        def mutate(v):
            bundle = buyer_bundle("eip155:8453", BUYER_ADDRESS, **variant)
            bundle_hash = digest(unsigned(bundle, "presentation"))
            v["buyerBundle"] = bundle
            v["agreement"]["parties"][0]["bundleHash"] = bundle_hash
            v["runtime"]["payer"]["bundleHash"] = bundle_hash
        return mutate
    add_case(vectors, "buyer-bundle-presented-by-paying-key", "fail", "XN-5",
             "a validly signed bundle presented by its payment claim is not the buyer's "
             "presentation, which the agreement's buyer primary claim makes",
             presented_bundle(presented_by_payment_key=True), reason="payer-control")
    add_case(vectors, "buyer-bundle-duplicate-paying-key-claim", "fail", "XN-5",
             "payingKey must identify exactly one claim in the bundle",
             presented_bundle(duplicate_payment_claim=True), reason="payer-control")

    def claim_address_not_derived(v):
        attacker = "0x" + "99" * 20
        bundle = buyer_bundle("eip155:8453", attacker)
        bundle_hash = digest(unsigned(bundle, "presentation"))
        v["buyerBundle"] = bundle
        v["agreement"]["parties"][0]["bundleHash"] = bundle_hash
        v["runtime"]["payer"].update({
            "bundleHash": bundle_hash,
            "payingKey": payment_claim("eip155:8453", attacker),
        })
    add_case(vectors, "paying-key-claim-address-not-derived-from-key", "fail", "XN-5",
             "a signed paying-key claim naming an address its key does not derive proves no "
             "payer, even though the authorization payer is the derived address",
             claim_address_not_derived, reason="payer-control")

    # XN-7: a sound response's transaction is kept verbatim in the evidence.
    add_case(vectors, "evidence-transaction-respelled", "fail", "XN-7",
             "evidence that respells the sound response's transaction contradicts it, "
             "though both name the same transaction",
             lambda v: v["evidence"]["paymentTxRefs"][0].update({"settlementTransaction": SAFE_TX}),
             operation="verify-evidence", reason="evidence-response-binding")
    for role in ("buyer", "seller"):
        add_case(vectors, f"agreement-{role}-listed-twice", "fail", "XN-2",
                 f"the agreement {role} must occur exactly once in parties",
                 lambda v, r=role: v["agreement"]["parties"].append(copy.deepcopy(next(
                     party for party in v["agreement"]["parties"] if party["role"] == r))),
                 reason="party-cardinality")
    add_case(vectors, "runtime-payee-not-agreement-seller", "fail", "XN-5",
             "the runtime payee must resolve to the signed seller",
             lambda v: v["runtime"]["payee"].update({"primaryClaim": "did:demos:agent:" + "99" * 32}),
             reason="payee-party")
    add_case(vectors, "agreement-buyer-bundle-hash-not-presented-bundle", "fail", "XN-5",
             "the signed buyer bundleHash must pin the presented bundle",
             lambda v: v["agreement"]["parties"][0].update({"bundleHash": "cc" * 32}),
             reason="payer-control")
    add_case(vectors, "runtime-payer-bundle-hash-not-presented-bundle", "fail", "XN-5",
             "the runtime payer's bundleHash must pin the presented bundle",
             lambda v: v["runtime"]["payer"].update({"bundleHash": "cc" * 32}),
             reason="payer-control")
    add_case(vectors, "buyer-bundle-session-nonce-not-issued", "fail", "XN-5",
             "the presented bundle must carry the session nonce issued for this session",
             lambda v: v["runtime"].update({"issuedBuyerSessionNonce": "00" * 16}),
             reason="payer-control")
    add_case(vectors, "runtime-paying-key-is-identity-claim", "fail", "XN-5",
             "a paying key that is the buyer's identity claim, not a payment claim, proves no payer",
             lambda v: v["runtime"]["payer"].update({"payingKey": BUYER_CLAIM}),
             reason="payer-control")

    # Before authorization: capability, currency, request and challenge.
    add_case(vectors, "exact-binding-profile-unsupported-locally", "fail", "XN-3",
             "a supported exact tuple without the local dacs-x402-exact:v1 binding is refused",
             lambda v: v["capability"].update({"bindingProfiles": []}),
             reason="x402-capability-unsupported")
    add_case(vectors, "price-currency-not-selection-currency", "fail", "PC-5/XN-5",
             "the agreement price currency must equal the signed selection currency",
             lambda v: v["agreement"]["terms"]["price"].update({"currency": "USDT"}),
             reason="currency")
    add_case(vectors, "asset-metadata-network-mismatch", "fail", "XN-5",
             "independent asset metadata must be for the signed network",
             lambda v: v["capability"]["assetMetadata"].update({"network": "eip155:1"}),
             reason="asset-metadata")
    add_case(vectors, "asset-metadata-asset-mismatch", "fail", "XN-5",
             "independent asset metadata must be for the signed asset",
             lambda v: v["capability"]["assetMetadata"].update({"asset": "0x" + "99" * 20}),
             reason="asset-metadata")
    add_case(vectors, "redirect-followed-to-same-url", "fail", "XN-6",
             "a followed redirect rejects even when it lands on the signed URL",
             lambda v: v["runtime"].update({"redirected": True}), reason="effective-request")
    add_case(vectors, "request-body-not-base64", "error", "XN-6",
             "a request body that is not base64 is malformed",
             lambda v: v["runtime"].update({"requestBodyBase64": "%%%"}), reason="request-body")

    def body_not_signed(v):
        valid_body(v)
        send_body(v, b'{"job":"275"}')
    add_case(vectors, "request-body-not-signed-body-hash", "fail", "XN-6",
             "request body bytes must hash to the signed bodyHash",
             body_not_signed, reason="request-body-hash")
    add_case(vectors, "payment-required-not-object", "error", "XN-4",
             "a PaymentRequired that is not an object is malformed",
             lambda v: v["http"].update({"paymentRequired": []}), reason="payment-required-version")
    add_case(vectors, "challenge-version-not-selection", "error", "XN-4",
             "PaymentRequired.x402Version must equal the signed selection",
             lambda v: v["http"]["paymentRequired"].update({"x402Version": 1}),
             reason="payment-required-version")
    add_case(vectors, "challenge-accepts-not-array", "error", "XN-4",
             "accepts must be an array",
             lambda v: v["http"]["paymentRequired"].update({"accepts": {}}),
             reason="payment-required-shape")
    add_case(vectors, "challenge-resource-not-object", "error", "XN-4",
             "a v2 resource must be an object",
             lambda v: v["http"]["paymentRequired"].update({"resource": URL}),
             reason="payment-required-shape")
    add_case(vectors, "challenge-accepts-member-not-object", "error", "XN-4",
             "every accepts member must be an object",
             lambda v: v["http"]["paymentRequired"]["accepts"].append("exact"),
             reason="accepts-shape")
    add_case(vectors, "challenge-accepts-extra-absent", "fail", "XN-4/XN-6",
             "an accepts member without extra cannot match the signed extra object",
             lambda v: v["http"]["paymentRequired"]["accepts"][0].pop("extra"),
             refresh=True, reason="challenge-match")

    def version_three(v):
        for ref in signed_selection_refs(v):
            ref["parameters"]["selection"]["x402Version"] = 3
        v["http"]["paymentRequired"]["x402Version"] = 3
        v["capability"]["supportedTuples"] = [[3, "exact", "eip155:8453"]]
    add_case(vectors, "x402-version-without-known-shapes", "error", "XN-2/XN-4",
             "v0.8 binds only x402 version 2, so a later version is malformed even when the "
             "challenge and the local capability name it, and is refused before the unpaid request",
             version_three, reason="rail-ref-shape")

    # After authorization: evidence and ledger.
    for name, change, note, verdict, reason in (
        ("evidence-two-references", lambda ref, refs: refs.append(copy.deepcopy(ref)),
         "success evidence carries exactly one x402-protocol reference", "error",
         "evidence-ref-count"),
        ("evidence-kind-not-protocol", lambda ref, _: ref.update({"kind": "x402-event"}),
         "x402:protocol evidence uses the x402-protocol arm", "error", "evidence-version"),
        ("evidence-x402-version-string", lambda ref, _: ref.update({"x402Version": "2"}),
         "the evidence x402Version is a number", "error", "evidence-version"),
        ("evidence-x402-version-substitution", lambda ref, _: ref.update({"x402Version": 1}),
         "the evidence x402Version must equal the signed selection", "fail", "evidence-version"),
        ("evidence-receipt-hash-upper-case",
         lambda ref, _: ref.update({"paymentReceiptHash": ref["paymentReceiptHash"].upper()}),
         "a stored hash is exactly 64 lower-case hex digits", "error", "evidence-hash-shape"),
        ("evidence-http-resource-substitution",
         lambda ref, _: ref.update({"httpResource": "https://other-seller.example/pay"}),
         "httpResource must equal the signed URL", "fail", "evidence-binding"),
        ("evidence-settlement-network-substitution",
         lambda ref, _: ref.update({"settlementNetwork": "eip155:1"}),
         "settlementNetwork must equal the signed network", "fail", "evidence-binding"),
    ):
        add_case(vectors, name, verdict, "XN-7/XN-8", note,
                 lambda v, c=change: c(v["evidence"]["paymentTxRefs"][0],
                                       v["evidence"]["paymentTxRefs"]),
                 operation="verify-evidence", reason=reason)
    add_case(vectors, "finality-model-substitution", "fail", "XN-8",
             "the finality record must use the scheme-network-finality model",
             lambda v: v["evidence"]["settlementFinality"].update({"model": "block-depth"}),
             operation="verify-evidence", reason="finality-profile")
    # The event the authorization identity resolves to contradicts the
    # authorization: a resolved contradiction, `fail` from the ledger (XN-8).
    for name, field, value, note in (
        ("ledger-asset-substitution", "asset", "0x" + "99" * 20,
         "the authenticated event must move the signed asset, not another token for the same amount"),
        ("ledger-network-substitution", "network", "eip155:1",
         "the authenticated event must be on the signed network"),
        ("ledger-scheme-substitution", "scheme", "upto",
         "the authenticated event must settle the exact scheme"),
        ("ledger-asset-decimals-substitution", "assetDecimals", 18,
         "the authenticated asset decimals must equal the signed decimals"),
    ):
        add_case(vectors, name, "fail", "XN-5/XN-8", note,
                 lambda v, f=field, x=value: v["ledger"].update({f: x}),
                 authorization_submitted=True, reason="ledger-event")
    # A record naming another transaction than the reconciled event's is a
    # record defect: the verifier rejects that record. The ledger's event is
    # consistent, its key naming its own transaction.
    add_case(vectors, "ledger-transaction-substitution", "fail", "XN-7/XN-8",
             "the authenticated event must belong to the recorded transaction",
             lambda v: v["ledger"].update({"transaction": "0x" + "cd" * 32,
                                           "settlementEvent": "evm:8453:" + "cd" * 32 + ":7"}),
             operation="verify-evidence", reason="ledger-event")

    # Legacy x402:default replay and continuation boundaries.
    def legacy_variant(change):
        def mutate(v):
            legacy_replay(v)
            change(v)
        return mutate
    add_case(vectors, "legacy-default-continuation-not-in-flight", "fail", "XN-10",
             "only an already pinned in-flight session may continue on x402:default",
             legacy_variant(lambda v: v["runtime"].update({"sessionState": "new"})),
             operation="legacy-continuation", authorization_submitted=True,
             reason="not-in-flight")
    for name, change, note, reason in (
        ("legacy-replay-two-references",
         lambda v: v["evidence"]["paymentTxRefs"].append(copy.deepcopy(v["evidence"]["paymentTxRefs"][0])),
         "legacy replay evidence carries exactly one reference", "shape"),
        ("legacy-replay-protocol-rail", lambda v: v.update({"railDefinition": protocol_rail()}),
         "legacy replay is only for the x402:default rail", "legacy-boundary"),
        ("legacy-replay-protocol-arm",
         lambda v: v["evidence"]["paymentTxRefs"][0].update({"kind": "x402-protocol"}),
         "legacy replay keeps the frozen x402-event arm", "legacy-boundary"),
        ("legacy-replay-numeric-protocol-version",
         lambda v: v["evidence"]["paymentTxRefs"][0].update({"protocolVersion": 2}),
         "legacy protocolVersion stays a string", "legacy-boundary"),
        ("legacy-replay-ref-carries-x402-version",
         lambda v: v["evidence"]["paymentTxRefs"][0].update({"x402Version": 2}),
         "a legacy reference never acquires the numeric x402Version", "legacy-boundary"),
    ):
        add_case(vectors, name, "error", "XN-10", note, legacy_variant(change),
                 operation="legacy-replay", authorization_submitted=True, reason=reason)

    # Retry: the retained state's shape.
    def retained_state(value):
        def mutate(v):
            v["ledger"]["available"] = False
            v["runtime"]["reconciliationState"] = value(v["runtime"]["reconciliationState"])
        return mutate
    add_case(vectors, "retry-retained-state-not-object", "fail", "XN-11",
             "a retained state that is not an object names no identity",
             retained_state(lambda _: None), operation="retry", authorization_submitted=True,
             reason="reconciliation-binding")
    add_case(vectors, "retry-retained-state-extra-field", "fail", "XN-11",
             "a retained state with a field outside the identity is not this session's",
             retained_state(lambda state: {**state, "nonce": "fresh"}), operation="retry",
             authorization_submitted=True, reason="reconciliation-binding")

    # XN-2: RFC 6761 localhost names are never public, and an IPv6 form that
    # embeds an IPv4 address is judged by the address it carries, explicitly
    # rather than through the host language's address tables. Like the
    # bounded-fetch rows above, each refreshes the received-object hashes.
    def literal_target(target):
        def mutate(v):
            request = v["agreement"]["terms"]["rail"]["parameters"]["request"]
            request["url"] = target
            v["listing"]["acceptedRails"][0] = copy.deepcopy(v["agreement"]["terms"]["rail"])
            v["runtime"]["selectedRailRef"] = copy.deepcopy(v["agreement"]["terms"]["rail"])
            send_requests_to(v, target)
            v["http"]["paymentRequired"]["resource"]["url"] = target
            v["evidence"]["paymentTxRefs"][0]["httpResource"] = target
        return mutate
    for name, unsafe_url, note in (
        ("localhost-subdomain", "https://api.localhost/pay",
         "a name under .localhost is a loopback name (RFC 6761)"),
        ("localhost-subdomain-upper-case-root-dot", "https://API.LOCALHOST./pay",
         "a .localhost name in any letter case and with a root dot is a loopback name"),
        ("localhost-localdomain", "https://localhost.localdomain/pay",
         "localhost.localdomain is a loopback name"),
        ("ipv4-compatible-loopback", "https://[::127.0.0.1]/pay",
         "an IPv4-compatible address carrying 127.0.0.1 is loopback"),
        ("nat64-metadata", "https://[64:ff9b::a9fe:a9fe]/latest/meta-data/",
         "a NAT64 address carrying 169.254.169.254 reaches the metadata endpoint"),
        ("nat64-local-use", "https://[64:ff9b:1::808:808]/pay",
         "the local-use NAT64 prefix does not fix where the IPv4 address sits"),
        ("6to4-loopback", "https://[2002:7f00:1::1]/pay",
         "a 6to4 address carrying 127.0.0.1 is loopback"),
        ("teredo-server-loopback", "https://[2001:0:7f00:1::f7f7:f7f7]/pay",
         "a Teredo address whose server is 127.0.0.1 is loopback"),
        ("teredo-client-private", "https://[2001:0:808:808::f5ff:fffe]/pay",
         "a Teredo address whose inverted client is 10.0.0.1 is private"),
    ):
        add_case(vectors, f"bounded-fetch-{name}-target", "fail", "XN-2/DACS-1-6.3.6", note,
                 literal_target(unsafe_url), refresh=True, reason="non-public-request-target")
    add_case(vectors, "request-target-ipv4-mapped-public-address", "pass", "XN-2/DACS-1-6.3.6",
             "an IPv4-mapped spelling of a public address reaches the IPv4 verdict",
             literal_target("https://[::ffff:8.8.8.8]/pay"), refresh=True)

    # XN-8/SB-1: the signed event key's form needs no ledger data, so the
    # verifier's verdict on a record with a malformed key is `error` even while
    # the ledger is unavailable or not final.
    for name, ledger_state, note in (
        ("noncanonical-native-event-key-ledger-unavailable", {"available": False},
         "a malformed signed event key is error even while the ledger is unavailable"),
        ("noncanonical-native-event-key-ledger-not-final", {"finalized": False},
         "a malformed signed event key is error even while the settlement is not final"),
    ):
        def malformed_event_key(v, state=ledger_state):
            noncanonical_event(v)
            v["ledger"].update(state)
        add_case(vectors, name, "error", "XN-8/SB-1", note, malformed_event_key,
                 operation="verify-evidence", reason="native-event-key")

    # XN-7 / CORE CF-5: received x402 objects are admitted from their exact
    # bytes. NaN, a number outside binary64, a lone surrogate and a duplicate
    # member are refused, never an exception or a last-wins reading. A refused
    # settlement response is a response defect, so the ledger still decides.
    def compact(value):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    response_text = compact(settlement_response(2))
    challenge_text = compact(payment_required(2))
    refused = (
        ("nan", "NaN is not a JSON number", ',"fee":NaN}'),
        ("number-overflow", "1e400 is outside binary64", ',"fee":1e400}'),
        ("lone-surrogate", "a lone UTF-16 surrogate is not Unicode text", ',"memo":"\\ud800"}'),
    )
    for suffix, why, member in refused:
        def raw_response(v, text=response_text[:-1] + member):
            v["http"]["responseHeader"]["value"] = base64.b64encode(
                text.encode("utf-8")).decode("ascii")
        response_defect(f"response-raw-json-{suffix}",
                        f"a settlement response whose bytes CF-5 refuses ({why}) decodes to "
                        "no object", raw_response, "response-json")

    # {"success":false,"success":true,...}: a last-wins parser reads success.
    def duplicate_success(v):
        text = '{"success":false,' + response_text[1:]
        v["http"]["responseHeader"]["value"] = base64.b64encode(
            text.encode("utf-8")).decode("ascii")
    response_defect("response-raw-json-duplicate-success",
                    "a settlement response that repeats success is refused by CF-5, "
                    "not read as its last value", duplicate_success, "response-json")

    def raw_challenge(text):
        def mutate(v):
            v["http"].pop("paymentRequired")
            v["http"]["paymentRequiredRaw"] = base64.b64encode(text.encode("utf-8")).decode("ascii")
        return mutate
    add_case(vectors, "challenge-raw-json-admitted", "pass", "XN-4/XN-7/CF-5",
             "a challenge received as raw bytes is admitted under CF-5 and hashed as decoded",
             raw_challenge(challenge_text), refresh=True)
    for suffix, why, member in refused:
        add_case(vectors, f"challenge-raw-json-{suffix}", "error", "XN-4/XN-7/CF-5",
                 f"a challenge whose bytes CF-5 refuses ({why}) is malformed before authorization",
                 raw_challenge(challenge_text[:-1] + member), refresh=True,
                 reason="payment-required-json")
    duplicate_amount = challenge_text.replace('"amount":"1250000"',
                                              '"amount":"9999999","amount":"1250000"')
    assert duplicate_amount != challenge_text
    add_case(vectors, "challenge-raw-json-duplicate-amount", "error", "XN-4/XN-7/CF-5",
             "a challenge that repeats amount is refused by CF-5, not matched on its last value",
             raw_challenge(duplicate_amount), refresh=True, reason="payment-required-json")

    def raw_and_object_challenge(v):
        raw_challenge(challenge_text)(v)
        v["http"]["paymentRequired"] = payment_required(2)
    add_case(vectors, "challenge-raw-json-and-object-both-received", "error", "XN-4/XN-7/CF-5",
             "a challenge received both as raw bytes and as an object is ambiguous",
             raw_and_object_challenge, reason="payment-required-json")

    # XN-2: the RFC 2765 IPv4-translated form embeds an IPv4 address too.
    add_case(vectors, "bounded-fetch-ipv4-translated-loopback-target", "fail", "XN-2/DACS-1-6.3.6",
             "an IPv4-translated address carrying 127.0.0.1 is loopback",
             literal_target("https://[::ffff:0:7f00:1]/pay"), refresh=True,
             reason="non-public-request-target")

    # XN-11: after the wallet call the payment disposition comes only from the
    # ledger reconciliation of the authorization identity. A lost response
    # leaves no evidence, and none has to exist before reconciling.
    def response_lost(ledger=None):
        def mutate(v):
            v["http"].pop("responseHeader")
            v.pop("evidence")
            if ledger is not None:
                ledger(v)
        return mutate
    add_case(vectors, "response-lost-no-evidence-settled", "pass", "XN-11",
             "the response was lost and no evidence exists, but the ledger proves an exact "
             "finalized settlement: success, with the missing response as the recorded defect",
             response_lost(), authorization_submitted=True, reason="response-header")
    add_case(vectors, "response-lost-no-evidence-ledger-unavailable", "indeterminate", "XN-11",
             "the response was lost, no evidence exists and the ledger is unavailable: "
             "reconciliation-pending",
             response_lost(lambda v: v["ledger"].update({"available": False})),
             authorization_submitted=True, reason="independent-settlement-unavailable")
    add_case(vectors, "response-lost-no-evidence-authorization-expired", "fail", "XN-11/SB-3",
             "the response was lost and the nonce is unused at a finalized block whose "
             "timestamp passed the retained validBefore: a terminal non-settlement",
             response_lost(authorization_state("unused", VALID_BEFORE + 60)),
             authorization_submitted=True, reason="terminal-non-settlement")
    add_case(vectors, "response-lost-no-evidence-authorization-unused", "indeterminate", "XN-11",
             "the response was lost and the authorization is unused but can still settle: "
             "reconciliation-pending, never a failure",
             response_lost(authorization_state("unused")), authorization_submitted=True,
             reason="authorization-unsettled")

    # A stored record that does not verify is rejected and rebuilt from the
    # retained material; it never ends the payment phase.
    def response_changed_after_record(v):
        # The record committed to the response first received; the retained
        # response differs, though it is sound.
        response = settlement_response(2)
        response["extensions"] = {"receipt": "resent"}
        v["http"]["responseHeader"] = encoded_header(response, 2)
    add_case(vectors, "response-changed-after-record-settled", "pass", "XN-7/XN-11",
             "the response changed after the record was built, so the stored receipt hash no "
             "longer recomputes; the ledger proves the settlement, and the record is rebuilt",
             response_changed_after_record, authorization_submitted=True,
             reason="payment-receipt-hash")
    add_case(vectors, "stored-challenge-hash-not-recomputing-settled", "pass", "XN-7/XN-11",
             "a stored challenge hash that does not recompute rejects the record, which is "
             "rebuilt; the ledger proves the settlement",
             lambda v: v["evidence"]["paymentTxRefs"][0].update({"paymentRequiredHash": "00" * 32}),
             authorization_submitted=True, reason="payment-required-hash")

    def stored_record_malformed_key_ledger_unavailable(v):
        noncanonical_event(v)
        v["ledger"]["available"] = False
    add_case(vectors, "stored-record-noncanonical-event-key-ledger-unavailable", "indeterminate",
             "XN-8/XN-11",
             "a stored record with a malformed event key is the verifier's error, but the "
             "payment stays reconciliation-pending while the ledger is unavailable",
             stored_record_malformed_key_ledger_unavailable, authorization_submitted=True,
             reason="independent-settlement-unavailable")

    # XN-8/XN-11: a resolved contradiction is an event the authorization
    # identity resolves to; a transaction only the response names is a defect.
    def other_transaction_contradicting_event(v):
        response_transaction_mismatch(v)
        v["ledger"]["amount"] = "1249999"
    add_case(vectors, "response-transaction-substitution-ledger-event-contradicts", "fail",
             "XN-8/XN-11",
             "the response names another transaction, and the event the authorization "
             "identity resolves to moves another amount: fail from the ledger",
             other_transaction_contradicting_event, refresh=True,
             authorization_submitted=True, reason="ledger-event")

    def other_transaction_no_event(v):
        response_transaction_mismatch(v)
        authorization_state("unused")(v)
    add_case(vectors, "response-transaction-substitution-no-ledger-event", "indeterminate",
             "XN-8/XN-11",
             "the response names another transaction, but no event is resolved for the "
             "authorization identity: reconciliation-pending, never a failure",
             other_transaction_no_event, refresh=True, authorization_submitted=True,
             reason="authorization-unsettled")

    # XN-5: on EIP-155 the asset and extra.verifyingContract compare as 20-byte
    # values wherever they are compared. Each case changes one spelling.
    def lettered_asset(signed=LETTERED_ASSET, metadata=LETTERED_ASSET,
                       challenge=LETTERED_ASSET, ledger=LETTERED_ASSET):
        def mutate(v):
            for ref in signed_selection_refs(v):
                ref["parameters"]["selection"]["asset"] = signed
            v["capability"]["assetMetadata"]["asset"] = metadata
            v["http"]["paymentRequired"]["accepts"][0]["asset"] = challenge
            v["ledger"]["asset"] = ledger
        return mutate
    upper = "0x" + LETTERED_ASSET[2:].upper()
    short = LETTERED_ASSET[:-2]
    for name, expected, mutate, note in (
        ("challenge-asset-eip55-selection-lower-case", "pass",
         lettered_asset(challenge=eip55(LETTERED_ASSET)),
         "an EIP-55 challenge asset is the same 20-byte asset as the lower-case selection"),
        ("selection-asset-eip55-challenge-lower-case", "pass",
         lettered_asset(signed=eip55(LETTERED_ASSET)),
         "an EIP-55 signed asset is the same 20-byte asset as the lower-case challenge, "
         "metadata and ledger"),
        ("asset-metadata-asset-eip55", "pass", lettered_asset(metadata=eip55(LETTERED_ASSET)),
         "EIP-55 adapter metadata names the same 20-byte asset"),
        ("ledger-asset-upper-case", "pass", lettered_asset(ledger=upper),
         "an upper-case authenticated ledger asset is the same 20-byte asset"),
        ("selection-asset-not-20-bytes", "error",
         lettered_asset(signed=short, metadata=short, challenge=short, ledger=short),
         "a signed EIP-155 asset that is not 0x plus 40 hex digits is malformed before "
         "authorization, even where every copy agrees"),
        ("asset-metadata-asset-not-20-bytes", "error", lettered_asset(metadata=short),
         "adapter metadata naming an asset that is not 0x plus 40 hex digits is malformed"),
        ("challenge-asset-not-20-bytes", "error", lettered_asset(challenge=short),
         "a challenge asset that is not 0x plus 40 hex digits is malformed before authorization"),
    ):
        add_case(vectors, name, expected, "XN-4/XN-5", note, mutate, refresh=True,
                 reason="address-form" if expected == "error" else None)
    add_case(vectors, "ledger-asset-not-20-bytes", "error", "XN-5/XN-8",
             "an authenticated ledger asset that is not 0x plus 40 hex digits is a malformed "
             "coordinate after authorization",
             lettered_asset(ledger=short), refresh=True, authorization_submitted=True,
             reason="address-form")

    # XN-4/XN-6: the pinned EIP-155 exact definition has no
    # extra.verifyingContract (the EIP-712 domain's is the asset), so the
    # member has no address form: its spellings compare as JCS bytes, and an
    # agreeing copy is unclassified.
    def lettered_verifying_contract(signed=LETTERED_VERIFYING_CONTRACT,
                                    challenge=LETTERED_VERIFYING_CONTRACT):
        def mutate(v):
            for ref in signed_selection_refs(v):
                ref["parameters"]["selection"]["extra"]["verifyingContract"] = signed
            v["http"]["paymentRequired"]["accepts"][0]["extra"]["verifyingContract"] = challenge
        return mutate
    for name, reason, mutate, note in (
        ("challenge-verifying-contract-eip55-selection-lower-case", "challenge-match",
         lettered_verifying_contract(challenge=eip55(LETTERED_VERIFYING_CONTRACT)),
         "an EIP-55 extra.verifyingContract in the challenge is other bytes than the lower-case "
         "signed one: the EIP-155 adapter defines no such member, so nothing compares it as "
         "an address"),
        ("selection-verifying-contract-eip55-challenge-lower-case", "challenge-match",
         lettered_verifying_contract(signed=eip55(LETTERED_VERIFYING_CONTRACT)),
         "an EIP-55 signed extra.verifyingContract does not match the lower-case challenge "
         "extra, since the member has no address form"),
        ("challenge-verifying-contract-not-20-bytes", "challenge-match",
         lettered_verifying_contract(challenge=LETTERED_VERIFYING_CONTRACT[:-2]),
         "a challenge extra.verifyingContract that differs from the signed one is a mismatch"),
        ("selection-verifying-contract-not-20-bytes", "unclassified-extra-member",
         lettered_verifying_contract(signed=LETTERED_VERIFYING_CONTRACT[:-2],
                                     challenge=LETTERED_VERIFYING_CONTRACT[:-2]),
         "a signed and received extra.verifyingContract, here agreeing, is a member the "
         "EIP-155 exact adapter does not define, so it is unclassified"),
    ):
        add_case(vectors, name, "fail", "XN-4/XN-6", note, mutate, refresh=True, reason=reason)

    # XN-7: a response header whose value is not a string decodes to nothing.
    response_defect("response-header-value-not-string",
                    "a settlement-response header whose value is not a string decodes to no "
                    "object, so the receipt preimage is JSON null",
                    lambda v: v["http"]["responseHeader"].update({"value": None}),
                    "response-header")

    # XN-2: ISATAP (RFC 5214) carries an IPv4 address in the interface
    # identifier after any prefix; the prefix here is public.
    for name, unsafe_url, note in (
        ("isatap-loopback", "https://[2606:4700::5efe:7f00:1]/pay",
         "an ISATAP interface identifier carrying 127.0.0.1 is loopback, whatever its prefix"),
        ("isatap-universal-bit-metadata", "https://[2606:4700::200:5efe:a9fe:a9fe]/latest/meta-data/",
         "an ISATAP identifier with the universal bit carrying 169.254.169.254 reaches the "
         "metadata endpoint"),
    ):
        add_case(vectors, f"bounded-fetch-{name}-target", "fail", "XN-2/DACS-1-6.3.6", note,
                 literal_target(unsafe_url), refresh=True, reason="non-public-request-target")

    # XN-7: a record built over a response that was never received commits to
    # JSON null, and the verifier accepts that preimage.
    add_case(vectors, "record-over-unreceived-response-verifies", "pass", "XN-7/XN-8",
             "a stored record whose receipt hash commits to JSON null, because no "
             "version-selected response decoded, verifies; the response defect is recorded",
             lambda v: v["http"]["responseHeader"].update({"name": "X-PAYMENT-RESPONSE"}),
             operation="verify-evidence", refresh=True, reason="response-header")

    # XN-8/XN-11: the reconciled event's own coordinates are judged before it
    # can be success: a missing transaction or settlementEvent is missing data,
    # one with no adapter-canonical form is malformed. Each mutation runs with
    # no response or evidence (execute and retry) and over a full success.
    def ledger_coordinate(field, value=absent):
        def mutate(v):
            if value is absent:
                v["ledger"].pop(field)
            else:
                v["ledger"][field] = value
        return mutate
    for suffix, expected, reason, mutate, note in (
        ("ledger-transaction-missing", "indeterminate", "ledger-coordinate-missing",
         ledger_coordinate("transaction"),
         "an event whose transaction is missing cannot be identified yet"),
        ("ledger-transaction-null", "error", "ledger-transaction-form",
         ledger_coordinate("transaction", None),
         "a null event transaction has no XN-7 adapter form"),
        ("ledger-transaction-not-32-bytes", "error", "ledger-transaction-form",
         ledger_coordinate("transaction", "0x" + SAFE_TX[:63]),
         "an event transaction of 63 hexadecimal digits has no XN-7 adapter form"),
        ("ledger-transaction-double-0x-prefix", "error", "ledger-transaction-form",
         ledger_coordinate("transaction", "0x0x" + SAFE_TX),
         "a second 0x prefix is a spelling the SB-1 collapse does not admit"),
        ("ledger-event-key-missing", "indeterminate", "ledger-coordinate-missing",
         ledger_coordinate("settlementEvent"),
         "an event whose settlementEvent is missing cannot be identified yet"),
        ("ledger-event-key-garbled", "error", "ledger-event-key",
         ledger_coordinate("settlementEvent", "not-an-event"),
         "an event key that is not adapter-canonical is malformed"),
    ):
        add_case(vectors, suffix, expected, "XN-8/XN-11", f"{note}, whatever the response and "
                 "the stored record say", mutate, authorization_submitted=True, reason=reason)
        add_case(vectors, f"response-lost-no-evidence-{suffix}", expected, "XN-8/XN-11",
                 f"with the response lost and no evidence, {note}", response_lost(mutate),
                 authorization_submitted=True, reason=reason)
        add_case(vectors, f"retry-response-lost-{suffix}", expected, "XN-8/XN-11",
                 f"on retry after a lost response, {note}",
                 retry_response_lost(False, ledger=mutate), operation="retry",
                 authorization_submitted=True, reason=reason)
    for suffix, key, note in (
        ("noncanonical", f"evm:8453:0x{SAFE_TX}:7",
         "an event key spelling its hash with 0x is not adapter-canonical"),
        ("names-another-transaction", "evm:8453:" + "cd" * 32 + ":7",
         "an event key naming another transaction than the event's own does not identify it"),
        ("names-another-network", f"evm:1:{SAFE_TX}:7",
         "an event key on another chain than the selected network does not identify the event"),
    ):
        add_case(vectors, f"ledger-event-key-{suffix}", "error", "XN-8/SB-1", note,
                 ledger_coordinate("settlementEvent", key), authorization_submitted=True,
                 reason="ledger-event-key")

    # XN-11: a retry takes its disposition from the ledger as execute does. A
    # stored record that does not verify is rejected and rebuilt from the
    # reconciled event; its defect is the reason beside the ledger's verdict.
    def record_signature_broken(v):
        v["evidence"]["signature"]["value"] = flip_first(v["evidence"]["signature"]["value"])
    add_case(vectors, "retry-record-signature-invalid-settled", "pass", "XN-11/XN-7",
             "a stored record whose signature does not verify is rebuilt; the ledger proves the "
             "settlement, so the retry succeeds with the record's defect as the reason",
             operation="retry", authorization_submitted=True, tamper=record_signature_broken,
             reason="signature")
    add_case(vectors, "retry-record-signature-invalid-ledger-unavailable", "indeterminate",
             "XN-11/XN-7",
             "the same record over an unavailable ledger leaves the session reconciliation-pending",
             lambda v: v["ledger"].update({"available": False}), operation="retry",
             authorization_submitted=True, tamper=record_signature_broken, reason=pending)
    for name, refs, note in (
        ("retry-record-two-references-settled", lambda ref: [ref, copy.deepcopy(ref)],
         "a re-signed record with two references is rebuilt; the ledger decides"),
        ("retry-record-no-reference-settled", lambda ref: [],
         "a re-signed record with no reference is rebuilt; the ledger decides"),
    ):
        add_case(vectors, name, "pass", "XN-11/XN-8", note,
                 lambda v, r=refs: v["evidence"].update(
                     {"paymentTxRefs": r(v["evidence"]["paymentTxRefs"][0])}),
                 operation="retry", authorization_submitted=True, reason="evidence-ref-count")

    def record_names_other_transaction(v):
        v["evidence"]["paymentTxRefs"][0].update({
            "settlementTransaction": "0x" + "cd" * 32,
            "settlementEvent": "evm:8453:" + "cd" * 32 + ":7",
        })
    add_case(vectors, "retry-record-names-another-transaction-settled", "pass", "XN-11/XN-8",
             "a re-signed record naming another transaction and event than the one the "
             "authorization identity resolves to is rebuilt from that event",
             record_names_other_transaction, operation="retry", authorization_submitted=True,
             reason="ledger-event")
    add_case(vectors, "retry-record-transaction-not-32-bytes-settled", "pass", "XN-11/XN-7",
             "a re-signed record whose transaction has 63 hexadecimal digits is a verifier's "
             "error, but the retry rebuilds it and the ledger decides",
             lambda v: v["evidence"]["paymentTxRefs"][0].update(
                 {"settlementTransaction": "0x" + SAFE_TX[:63]}),
             operation="retry", authorization_submitted=True, reason="settlement-transaction-form")
    add_case(vectors, "retry-record-receipt-hash-not-recomputing-settled", "pass", "XN-11/XN-7",
             "a re-signed record whose receipt hash does not recompute over the retained "
             "response is rebuilt, as after the wallet call",
             lambda v: v["evidence"]["paymentTxRefs"][0].update({"paymentReceiptHash": "00" * 32}),
             operation="retry", authorization_submitted=True, reason="payment-receipt-hash")
    add_case(vectors, "retry-retained-transaction-not-reconciled-settled", "pass", "XN-11/XN-7",
             "the retained transaction is the response's and names another transaction than "
             "the event the identity resolves to, which the record names: the ledger decides, "
             "and the response's transaction is the recorded defect",
             lambda v: v["runtime"]["reconciliationState"].update(
                 {"settlementTransaction": "0x" + "cd" * 32}),
             operation="retry", authorization_submitted=True, reason="response-transaction")

    # The execute twin: a sound response names the resolved event, and the
    # record names another; the record is the defect, not the seller's response.
    add_case(vectors, "stored-record-names-another-transaction-settled", "pass", "XN-7/XN-11",
             "the response is sound and names the event the authorization identity resolves "
             "to, but the stored record names another transaction: the record is the defect "
             "and is rebuilt, and the response is not blamed",
             record_names_other_transaction, authorization_submitted=True, reason="ledger-event")

    # XN-4/XN-5: no extra member compares as an address.
    add_case(vectors, "challenge-extra-name-case-changed", "fail", "XN-4/XN-5",
             "the EIP-712 domain name is case-sensitive, so a challenge extra.name in another "
             "letter case does not match the signed extra",
             lambda v: v["http"]["paymentRequired"]["accepts"][0]["extra"].update({"name": "usdc"}),
             refresh=True, reason="challenge-match")

    # XN-6: the runtime trace names the request derived from the agreement and
    # the unpaid and paid requests as sent. Each case changes one of them, or
    # the whole exchange, and rejects before authorization.
    add_case(vectors, "request-method-substitution", "fail", "XN-6",
             "the derived, unpaid and paid requests all use another method than the signed one",
             lambda v: v["runtime"].update(
                 {"effectiveMethod": "DELETE", "unpaidMethod": "DELETE", "paidMethod": "DELETE"}),
             reason="effective-request-method")
    add_case(vectors, "unsigned-runtime-method-override", "fail", "XN-6",
             "a runtime method beside the signed rail ref cannot override it",
             lambda v: v["runtime"].update({"effectiveMethod": "POST"}),
             reason="effective-request-method")
    add_case(vectors, "unpaid-request-method-substitution", "fail", "XN-6",
             "the unpaid request uses the signed method",
             lambda v: v["runtime"].update({"unpaidMethod": "DELETE"}),
             reason="effective-request-method")
    add_case(vectors, "paid-request-method-substitution", "fail", "XN-6",
             "the paid request repeats the method of the validated unpaid request",
             lambda v: v["runtime"].update({"paidMethod": "PATCH"}),
             reason="effective-request-method")
    add_case(vectors, "unpaid-request-url-substitution", "fail", "XN-6",
             "the unpaid request goes to the signed URL",
             lambda v: v["runtime"].update({"unpaidUrl": "https://other.example/pay"}),
             reason="effective-request")
    add_case(vectors, "paid-request-url-substitution", "fail", "XN-6",
             "the paid request goes to the signed URL",
             lambda v: v["runtime"].update({"paidUrl": "https://other.example/pay"}),
             reason="effective-request")
    add_case(vectors, "unsigned-runtime-body-override", "fail", "XN-6",
             "a runtime body beside the signed rail ref is not the body the requests carry",
             lambda v: v["runtime"].update(
                 {"requestBodyBase64": base64.b64encode(b"{}").decode("ascii")}),
             reason="effective-request-body")
    add_case(vectors, "unpaid-request-body-substitution", "fail", "XN-6",
             "with no bodyHash, the unpaid request carries a body that the derived request does not",
             lambda v: v["runtime"].update(
                 {"unpaidBodyBase64": base64.b64encode(b"{}").decode("ascii")}),
             reason="effective-request-body")

    def paid_body_changed(v):
        valid_body(v)
        v["runtime"]["paidBodyBase64"] = base64.b64encode(b'{"job":"275"}').decode("ascii")
    add_case(vectors, "paid-request-body-substitution", "fail", "XN-6",
             "the paid request repeats the signed body bytes of the unpaid request",
             paid_body_changed, reason="effective-request-body")

    # XN-6: the selected adapter classifies every member of the matched `extra`
    # and of `extensions` itself. Each member below is signed and received, so
    # only that classification rejects it; a list supplied beside the
    # challenge classifies nothing.
    def omitted_from_claim(v):
        v["http"]["actionBearingExtensions"] = []
    add_case(vectors, "descriptive-extension-omitted-from-claim", "pass", "XN-6/§9.5.7.1",
             "a supplied list that omits the received payment-identifier classifies nothing: "
             "the adapter's own table defines it, and its optional form is descriptive",
             omitted_from_claim)

    def signed_and_received(extra=None, extensions=None):
        def mutate(v):
            required = v["http"]["paymentRequired"]
            for ref in signed_selection_refs(v):
                ref["parameters"]["selection"]["extra"].update(copy.deepcopy(extra or {}))
                if extensions:
                    ref["parameters"]["paymentRequiredExtensions"].update(copy.deepcopy(extensions))
            required["accepts"][0]["extra"].update(copy.deepcopy(extra or {}))
            if extensions:
                required["extensions"].update(copy.deepcopy(extensions))
        return mutate
    future_extra = {"future-action": {"spender": "0x" + "99" * 20}}
    future_extension = {"future-action": {"target": "https://other.example/next"}}
    add_case(vectors, "unclassified-payment-requirements-extra", "fail", "XN-6",
             "a signed and received extra member that the EIP-155 exact adapter does not define "
             "is unclassified",
             signed_and_received(extra=future_extra), refresh=True,
             reason="unclassified-extra-member")
    add_case(vectors, "unclassified-top-level-extension", "fail", "XN-6",
             "a signed and received extension that the adapter does not define is unclassified",
             signed_and_received(extensions=future_extension), refresh=True,
             reason="unclassified-extension")

    def listed_as_understood(v):
        signed_and_received(extensions=future_extension)(v)
        v["capability"]["understoodActionExtensions"] = ["future-action"]
    add_case(vectors, "unclassified-extension-listed-as-understood", "fail", "XN-6",
             "a local capability that lists an undefined extension does not classify it",
             listed_as_understood, refresh=True, reason="unclassified-extension")

    def solana_extra_with_evm_member(v):
        solana_exact(v)
        signed_and_received(extra={"verifyingContract": "0x" + "66" * 20})(v)
    add_case(vectors, "solana-extra-carries-verifying-contract", "fail", "XN-6",
             "the members are the selected adapter's: the Solana exact adapter does not define "
             "verifyingContract",
             solana_extra_with_evm_member, refresh=True, reason="unclassified-extra-member")

    # XN-6: each `extra` member of the pinned upstream exact definitions
    # (scheme_exact_evm.md, scheme_exact_svm.md at 230e6a9a) is classified, in
    # the form upstream gives it; a member of another adapter, or one upstream
    # does not define, is not. The base fixtures carry upstream's EIP-3009
    # example and a Solana extra naming only the fee payer.
    def extra_is(extra, *, solana=False):
        def mutate(v):
            if solana:
                solana_exact(v, extra=copy.deepcopy(extra))
                return
            for ref in signed_selection_refs(v):
                ref["parameters"]["selection"]["extra"] = copy.deepcopy(extra)
            v["http"]["paymentRequired"]["accepts"][0]["extra"] = copy.deepcopy(extra)
        return mutate

    def permit2(v):
        extra_is({"assetTransferMethod": "permit2", "name": "USDC", "version": "2"})(v)
        v["ledger"]["authorization"] = "permit2"
    add_case(vectors, "eip3009-extra-without-transfer-method", "pass", "XN-6",
             "assetTransferMethod is optional for EIP-3009: an extra naming only the token's "
             "EIP-712 name and version selects it",
             extra_is({"name": "USDC", "version": "2"}), refresh=True)
    add_case(vectors, "permit2-transfer-method", "fail", "XN-6/XN-9/SB-3",
             "upstream's Permit2 witness is Witness(address to,uint256 validAfter), which cannot "
             "carry the mandatory SB-3 job binding, so its example rejects before signing",
             permit2, refresh=True, reason="unsupported-transfer-method")
    add_case(vectors, "erc7710-transfer-method-has-no-v08-binding", "fail", "XN-6/XN-9",
             "the v0.8 EIP-155 exact binding authorizes only through EIP-3009, so upstream's "
             "ERC-7710 example rejects before signing",
             extra_is({"assetTransferMethod": "erc7710", "name": "USDC", "version": "2"}),
             refresh=True, reason="unsupported-transfer-method")
    # §9.5.7.1: EIP-3009 requires the token's EIP-712 domain name and version.
    for name, extra, note in (
        ("eip3009-extra-empty", {}, "an empty extra names no EIP-712 domain"),
        ("eip3009-extra-name-absent", {"version": "2"}, "the domain name is absent"),
        ("eip3009-extra-version-absent", {"name": "USDC"}, "the domain version is absent"),
        ("eip3009-extra-name-empty", {"name": "", "version": "2"}, "the domain name is empty"),
        ("eip3009-extra-version-not-string", {"name": "USDC", "version": 2},
         "the domain version is a number"),
        ("eip3009-extra-name-object", {"name": {}, "version": "2"}, "the domain name is an object"),
    ):
        add_case(vectors, name, "fail", "XN-6/§9.5.7.1",
                 f"EIP-3009 requires string extra.name and extra.version: {note}, so it rejects "
                 "before signing", extra_is(extra), refresh=True, reason="extra-member-value")
    # x402 v2 §6.1: paymentFlow is protocol-reserved; `authorization` may be explicit.
    add_case(vectors, "eip155-extra-explicit-authorization-flow", "pass", "XN-6/§9.5.7.1",
             "the protocol-reserved paymentFlow may name the default authorization flow explicitly",
             extra_is({**EIP3009_EXTRA, "paymentFlow": "authorization"}), refresh=True)
    for flow in ("upfront", "escrow", 1):
        add_case(vectors, f"eip155-extra-payment-flow-{flow}", "fail", "XN-6/§9.5.7.1",
                 "exact has no v0.8 binding for a payment flow other than authorization, so it "
                 "rejects before signing",
                 extra_is({**EIP3009_EXTRA, "paymentFlow": flow}), refresh=True,
                 reason="unsupported-payment-flow")
    blockhash = base58(hashlib.sha256(b"DACS #274 recent blockhash").digest())
    add_case(vectors, "solana-extra-memo", "pass", "XN-6",
             "upstream's optional memo fixes the Memo instruction's data; the Solana adapter "
             "defines it", extra_is({"feePayer": SOLANA_FEE_PAYER, "memo": "dacs-274"}, solana=True),
             refresh=True)

    def solana_hints(hints):
        # The signed selection omits the per-challenge hints; the challenge
        # carries fresh ones, as upstream's example does.
        def mutate(v):
            solana_exact(v, extra={"feePayer": SOLANA_FEE_PAYER, "memo": "dacs-274"})
            v["http"]["paymentRequired"]["accepts"][0]["extra"].update(copy.deepcopy(hints))
        return mutate
    add_case(vectors, "solana-extra-recent-blockhash", "pass", "XN-4/XN-6/§9.5.7.1",
             "upstream's PaymentRequirements example: fresh recentBlockhash and "
             "lastValidBlockHeight hints beside the signed feePayer and memo; the hints do not "
             "bind the transaction, so XN-4 compares extra without them",
             solana_hints({"recentBlockhash": blockhash, "lastValidBlockHeight": "280000000"}),
             refresh=True)
    add_case(vectors, "solana-extra-malformed-blockhash-hint", "pass", "XN-6/§9.5.7.1",
             "a malformed recentBlockhash is ignored and the client fetches its own; it never "
             "rejects", solana_hints({"recentBlockhash": "not base58 0OIl"}), refresh=True)
    add_case(vectors, "solana-extra-non-decimal-height-hint", "pass", "XN-6/§9.5.7.1",
             "lastValidBlockHeight is an informational hint that may be ignored, so a value that "
             "is not a decimal string does not reject",
             solana_hints({"recentBlockhash": blockhash, "lastValidBlockHeight": 280000000}),
             refresh=True)
    add_case(vectors, "solana-extra-fee-payer-absent", "fail", "XN-6/§9.5.7.1",
             "upstream requires feePayer for Solana exact, so an extra without it rejects "
             "before signing", extra_is({"memo": "dacs-274"}, solana=True), refresh=True,
             reason="extra-member-value")
    for name, fee_payer in (("object", {}), ("not-base58", "0" * 44),
                            ("short", base58(b"\x01" * 31))):
        add_case(vectors, f"solana-extra-fee-payer-{name}", "fail", "XN-6/§9.5.7.1",
                 "feePayer must be a base58 32-byte Solana public key",
                 extra_is({"feePayer": fee_payer}, solana=True), refresh=True,
                 reason="extra-member-value")
    add_case(vectors, "solana-extra-memo-256-bytes", "pass", "XN-6/§9.5.7.1",
             "a memo of exactly 256 UTF-8 bytes is within upstream's limit",
             extra_is({"feePayer": SOLANA_FEE_PAYER, "memo": "é" * 128}, solana=True),
             refresh=True)
    add_case(vectors, "solana-extra-memo-257-bytes", "fail", "XN-6/§9.5.7.1",
             "the limit counts UTF-8 bytes, not characters: 129 two-byte characters exceed 256",
             extra_is({"feePayer": SOLANA_FEE_PAYER, "memo": "é" * 128 + "a"}, solana=True),
             refresh=True, reason="extra-member-value")
    add_case(vectors, "solana-extra-memo-object", "fail", "XN-6/§9.5.7.1",
             "the memo is a UTF-8 string",
             extra_is({"feePayer": SOLANA_FEE_PAYER, "memo": {}}, solana=True), refresh=True,
             reason="extra-member-value")
    add_case(vectors, "solana-extra-carries-mint", "fail", "XN-6",
             "the mint is the asset: the pinned Solana exact definition has no extra.mint, so a "
             "signed and received one is unclassified",
             extra_is({"feePayer": SOLANA_FEE_PAYER, "mint": SOLANA_ASSET}, solana=True),
             refresh=True, reason="unclassified-extra-member")
    add_case(vectors, "solana-extra-carries-eip155-transfer-method", "fail", "XN-6",
             "assetTransferMethod is protocol-reserved, but the pinned Solana exact definition "
             "defines no transfer method, so naming one is unsupported",
             extra_is({"feePayer": SOLANA_FEE_PAYER, "assetTransferMethod": "eip3009"}, solana=True),
             refresh=True, reason="unsupported-transfer-method")

    # §9.5.7.1: the payment-identifier advertisement is upstream's
    # {info: {required}, schema}; v0.8 supports only the optional form.
    def payment_identifier(value):
        def mutate(v):
            for ref in signed_selection_refs(v):
                ref["parameters"]["paymentRequiredExtensions"]["payment-identifier"] = copy.deepcopy(value)
            v["http"]["paymentRequired"]["extensions"]["payment-identifier"] = copy.deepcopy(value)
        return mutate
    advertised = PAYMENT_IDENTIFIER_EXTENSIONS["payment-identifier"]
    add_case(vectors, "payment-identifier-required", "fail", "XN-6/§9.5.7.1",
             "a required payment identifier asks for an id v0.8 does not define, so it is an "
             "unsupported action and rejects before signing",
             payment_identifier({**advertised, "info": {"required": True}}), refresh=True,
             reason="unsupported-action-extension")
    for name, value in (
        ("null", None),
        ("legacy-flat-shape", {"required": False}),
        ("info-absent", {"schema": advertised["schema"]}),
        ("schema-absent", {"info": {"required": False}}),
        ("required-absent", {**advertised, "info": {}}),
        ("required-not-boolean", {**advertised, "info": {"required": "false"}}),
        ("schema-not-object", {**advertised, "schema": "draft 2020-12"}),
        ("schema-not-pinned", {**advertised, "schema": {"type": "array"}}),
        ("schema-without-id-bounds", {**advertised, "schema": {
            **advertised["schema"], "properties": {"required": {"type": "boolean"},
                                                   "id": {"type": "string"}}}}),
        ("info-id-below-schema-minimum", {**advertised, "info": {"required": False, "id": "short"}}),
        ("info-id-not-string", {**advertised, "info": {"required": False, "id": 2**52}}),
        ("info-id-outside-character-set", {**advertised, "info": {
            "required": False, "id": "pay." + "7" * 16}}),
        ("schema-other-id-pattern", {**advertised, "schema": {
            **PAYMENT_IDENTIFIER_SDK_SCHEMA, "properties": {
                "required": {"type": "boolean"},
                "id": {**PAYMENT_IDENTIFIER_SDK_SCHEMA["properties"]["id"], "pattern": "^.+$"}}}}),
    ):
        add_case(vectors, f"payment-identifier-{name}", "fail", "XN-6/§9.5.7.1",
                 "the advertisement must have upstream's {info: {required: boolean}, schema} "
                 "shape, with the pinned schema and an info that satisfies it, before it can be "
                 "judged optional",
                 payment_identifier(value), refresh=True, reason="extension-value")
    # The pinned reference SDKs advertise the schema with the `id` pattern;
    # that default optional advertisement is upstream's own, so it pays.
    sdk_advertised = {"info": {"required": False}, "schema": PAYMENT_IDENTIFIER_SDK_SCHEMA}
    add_case(vectors, "payment-identifier-sdk-schema", "pass", "XN-6/§9.5.7.1",
             "the optional advertisement the pinned reference SDKs emit, whose schema adds the "
             "id character pattern, is the other pinned schema",
             payment_identifier(sdk_advertised), refresh=True)
    add_case(vectors, "payment-identifier-sdk-schema-with-id", "pass", "XN-6/§9.5.7.1",
             "an id of 16 to 128 alphanumerics, hyphens or underscores satisfies either schema",
             payment_identifier({**sdk_advertised, "info": {"required": False, "id": "pay_" + "7" * 16}}),
             refresh=True)
    add_case(vectors, "payment-identifier-sdk-schema-required", "fail", "XN-6/§9.5.7.1",
             "the required form stays an unsupported action under the SDK schema too",
             payment_identifier({**sdk_advertised, "info": {"required": True}}), refresh=True,
             reason="unsupported-action-extension")
    add_case(vectors, "eip155-extra-carries-solana-fee-payer", "fail", "XN-6",
             "feePayer is the Solana adapter's member, not the EIP-155 adapter's",
             signed_and_received(extra={"feePayer": SELLER_ADDRESS}), refresh=True,
             reason="unclassified-extra-member")

    # XN-1: the definition applied is the revision the signed reference pins.
    def definition_version(version):
        def mutate(v):
            v["railDefinition"]["railVersion"] = version
            v["railDefinition"]["governance"]["supersedes"] = version - 1
        return mutate

    def reference_pins(version):
        def mutate(v):
            for ref in signed_selection_refs(v):
                ref["railVersion"] = version
        return mutate
    add_case(vectors, "definition-railversion-2-ref-pins-1", "fail", "XN-1",
             "a validly signed, well-formed definition at railVersion 2 is not the revision 1 "
             "that the signed reference pins", definition_version(2), reason="rail-version")
    add_case(vectors, "definition-railversion-1-ref-pins-2", "fail", "XN-1",
             "the signed reference pins railVersion 2, so the revision 1 definition is not the "
             "one the session applies", reference_pins(2), reason="rail-version")
    add_case(vectors, "definition-and-ref-railversion-2", "pass", "XN-1",
             "the comparison is with the pinned revision, not with revision 1: a definition at "
             "railVersion 2 under a reference pinning 2 pays",
             lambda v: (definition_version(2)(v), reference_pins(2)(v)))
    add_case(vectors, "verify-evidence-definition-railversion-2-ref-pins-1", "fail", "XN-1/XN-8",
             "a verifier judges a record only against the revision the reference pins",
             definition_version(2), operation="verify-evidence", reason="rail-version")

    # Every MUST-backed check has a vector that reaches it alone, on each
    # operation that applies it.

    def zero_timeout(v):
        for ref in signed_selection_refs(v):
            ref["parameters"]["selection"]["maxTimeoutSeconds"] = 0
        v["http"]["paymentRequired"]["accepts"][0]["maxTimeoutSeconds"] = 0
    add_case(vectors, "selection-max-timeout-seconds-zero", "error", "XN-2",
             "maxTimeoutSeconds is a positive safe integer, so 0 is malformed even where the "
             "challenge agrees", zero_timeout, refresh=True, reason="rail-ref-shape")

    def array_extensions(v):
        for ref in signed_selection_refs(v):
            ref["parameters"]["paymentRequiredExtensions"] = []
        v["http"]["paymentRequired"]["extensions"] = []
    add_case(vectors, "payment-required-extensions-array", "error", "XN-2",
             "paymentRequiredExtensions is a JSON object, so an array is malformed even where the "
             "challenge's extensions is the same array", array_extensions, refresh=True,
             reason="rail-ref-shape")
    for name, member, value, rule in (
        ("rail-id-substituted", "railId", "x402:default", "XN-1/RD-5"),
        ("rail-type-substituted", "railType", "evm-erc20", "XN-1/RD-5"),
        ("phase-handler-substituted", "phaseHandler", "pay-evm-erc20", "XN-1/RD-5"),
        ("resolution-substituted", "resolution", {"kind": "static"}, "XN-1/RD-5"),
        ("rail-version-zero", "railVersion", 0, "XN-1/RD-3"),
    ):
        add_case(vectors, f"execute-definition-{name}", "error", rule,
                 f"a re-signed definition whose {member} is {json.dumps(value)} is not the "
                 "complete protocol arm; it adds no member",
                 lambda v, m=member, x=value: v["railDefinition"].update({m: copy.deepcopy(x)}),
                 reason="definition")
    add_case(vectors, "agreement-signature-unused-bits-set", "fail", "SIG-6",
             "an agreement signature whose last base64url character sets unused bits decodes to "
             "the same bytes but is not the canonical encoding",
             tamper=lambda v: v["agreement"]["signatures"][0].update(
                 {"value": unused_bits_set(v["agreement"]["signatures"][0]["value"])}),
             reason="signature")

    def broken_signature(artifact):
        def tamper(v):
            target = v["agreement"]["signatures"][0] if artifact == "agreement" else v[artifact]["signature"]
            target["value"] = flip_first(target["value"])
        return tamper
    add_case(vectors, "definition-protocol-arm-validates", "pass", "XN-1",
             "the complete, steward-signed protocol arm validates", operation="validate-definition")
    add_case(vectors, "definition-signature-invalid-at-validation", "fail", "SIG-2/XN-1",
             "definition validation verifies the steward's signature first",
             operation="validate-definition", tamper=broken_signature("railDefinition"),
             reason="signature")
    add_case(vectors, "listing-signature-invalid-at-admission", "fail", "SIG-2/XN-2",
             "listing admission verifies the seller's signature before the commitment phase",
             listing_pipeline(fixed_price, "commit-payee-bound-agreement"),
             operation="admit-listing", tamper=broken_signature("listing"), reason="signature")
    add_case(vectors, "new-session-definition-signature-invalid", "fail", "SIG-2/XN-1",
             "a new session starts only under the steward-signed definition",
             lambda v: v["runtime"].update({"sessionState": "new"}), operation="new-session",
             tamper=broken_signature("railDefinition"), reason="signature")
    add_case(vectors, "legacy-replay-definition-signature-invalid", "fail", "SIG-2/XN-10",
             "historical replay verifies the pinned legacy definition's signature",
             legacy_replay, operation="legacy-replay", authorization_submitted=True,
             tamper=broken_signature("railDefinition"), reason="signature")
    add_case(vectors, "legacy-continuation-listing-signature-invalid", "fail", "SIG-2/XN-10",
             "an in-flight legacy session continues only under the seller's valid signature",
             legacy_continuation, operation="legacy-continuation", authorization_submitted=True,
             tamper=broken_signature("listing"), reason="signature")
    add_case(vectors, "retry-agreement-signature-invalid", "fail", "SIG-2/XN-11",
             "a retry reconciles only under both parties' valid agreement signatures, though the "
             "ledger shows the settlement", operation="retry", authorization_submitted=True,
             tamper=broken_signature("agreement"), reason="signature")
    add_case(vectors, "verify-evidence-ledger-unavailable", "indeterminate", "XN-8",
             "a sound record over unavailable authenticated ledger data cannot be verified yet",
             lambda v: v["ledger"].update({"available": False}), operation="verify-evidence",
             reason="independent-settlement-unavailable")
    add_case(vectors, "rail-ref-legacy-default-id", "error", "XN-2/XN-10",
             "a negotiated-shape ref whose railId is x402:default is not an "
             "X402ProtocolPaymentRailRef",
             lambda v: [ref.update({"railId": "x402:default"}) for ref in signed_selection_refs(v)],
             reason="rail-ref-shape")

    def currency_number(v):
        for ref in signed_selection_refs(v):
            ref["parameters"]["selection"]["currency"] = 840
        v["agreement"]["terms"]["price"]["currency"] = 840
    add_case(vectors, "selection-currency-not-a-string", "error", "XN-2",
             "the selection currency is a non-empty string, even where the price names the same "
             "number", currency_number, reason="rail-ref-shape")
    add_case(vectors, "agreement-price-not-canonical-decimal", "fail", "XN-5/CD-1",
             "1.250 is not the CD-1 spelling of 1.25, so no exact atomic amount is derived",
             lambda v: v["agreement"]["terms"]["price"].update({"amount": "1.250"}),
             reason="exact-amount")
    add_case(vectors, "response-header-json-array", "pass", "XN-7/XN-11",
             "a settlement response whose JSON is an array is not the version's object: a "
             "response defect, and the ledger decides",
             lambda v: v["http"]["responseHeader"].update(
                 {"value": base64.b64encode(b"[1]").decode("ascii")}),
             refresh=True, authorization_submitted=True, reason="response-header")

    def no_protocol_offer(v):
        v["listing"]["acceptedRails"] = [{"railId": "demos-native:DEM", "railVersion": 1}]
        v["listing"]["pipeline"] = [
            copy.deepcopy(fixed_price), {"kind": "commit-identity-bound-payee-agreement"},
            {"kind": "pay-dem", "parameters": {"rail": "demos-native:DEM"}},
            {"kind": "deliver-storage-program"},
        ]
    add_case(vectors, "listing-without-protocol-offer-admitted", "pass", "XN-2",
             "the commitment-phase rule binds only a Listing that offers x402:protocol",
             no_protocol_offer, operation="admit-listing")

    # XN-5: the buyer bundle's presentation, re-signed by each claim's own key
    # after one change, so only the presentation check can reject it.
    def resigned_bundle(body_change=None, envelopes_change=None, kind="per-claim", paying_ref=None):
        def mutate(v):
            body = unsigned(buyer_bundle("eip155:8453", BUYER_ADDRESS), "presentation")
            claim = payment_claim("eip155:8453", BUYER_ADDRESS)
            if paying_ref:
                body["claims"][1]["ref"] = claim = paying_ref
            if body_change:
                body_change(body)
            envelopes = evm_presentation_envelopes(body, claim)
            if envelopes_change:
                envelopes = envelopes_change(envelopes)
            v["buyerBundle"] = {**body, "presentation": {"kind": kind, "signatures": envelopes}}
            bundle_hash = digest(body)
            v["agreement"]["parties"][0]["bundleHash"] = bundle_hash
            v["runtime"]["payer"].update({"bundleHash": bundle_hash, "payingKey": claim})
        return mutate

    def presenter_not_a_claim(body):
        body["claims"] = body["claims"][1:]
    for name, mutate, note, reason in (
        ("buyer-bundle-version-unknown", resigned_bundle(lambda b: b.update({"bundleVersion": "2"})),
         "a bundle whose bundleVersion is not 1 is not a presentation this verifier reads",
         "signature"),
        ("buyer-bundle-presenter-not-a-claim",
         resigned_bundle(presenter_not_a_claim, lambda e: e[1:]),
         "a bundle presented by the buyer's primary claim must carry that claim and its "
         "signature, not only the payment claim's", "signature"),
        ("buyer-bundle-presentation-kind-unknown", resigned_bundle(kind="aggregate"),
         "only a per-claim presentation is verified per claim", "signature"),
        ("buyer-bundle-envelope-duplicated", resigned_bundle(envelopes_change=lambda e: e + e[1:]),
         "each claim has exactly one presentation signature", "signature"),
        ("buyer-bundle-envelope-for-no-claim", resigned_bundle(envelopes_change=lambda e: e + [
            {"ref": "cci-xm:evm:8453:0x" + "99" * 20, "signature": e[1]["signature"]}]),
         "a presentation signature names a claim of the bundle", "signature"),
        ("buyer-bundle-paying-claim-not-cci-xm",
         resigned_bundle(paying_ref="cci-xx:evm:8453:" + BUYER_ADDRESS),
         "the paying key is a cci-xm payment claim; another claim scheme is no native payment "
         "key, even when its key derives the payer", "payer-control"),
    ):
        add_case(vectors, name, "fail", "XN-5", note, mutate, reason=reason)
    add_case(vectors, "stored-record-not-an-object-settled", "pass", "XN-11/XN-7",
             "a stored record that is not an object does not verify; it is rebuilt, and the "
             "ledger's settlement is the disposition", lambda v: v.update({"evidence": None}),
             authorization_submitted=True, reason="signature")

    def array_extra(v):
        for ref in signed_selection_refs(v):
            ref["parameters"]["selection"]["extra"] = []
        v["http"]["paymentRequired"]["accepts"][0]["extra"] = []
    add_case(vectors, "selection-extra-array", "error", "XN-2",
             "the selection's extra is a JSON object, so an array is malformed even where the "
             "challenge's extra is the same array", array_extra, refresh=True,
             reason="rail-ref-shape")

    def url_in_array(v):
        for ref in signed_selection_refs(v):
            request = ref["parameters"]["request"]
            request["url"] = [request["url"]]
    add_case(vectors, "signed-request-url-not-a-string", "error", "XN-2",
             "the signed request URL is a string; an array holding the same URL is malformed",
             url_in_array, reason="rail-ref-shape")

    # DACS-1 listing validation: a Listing that fails schema conformance is
    # `rejected`, which this corpus scores as `fail`, before any phase rule.
    def listing_shape(change):
        def mutate(v):
            listing_pipeline(fixed_price, "commit-payee-bound-agreement")(v)
            change(v["listing"])
        return mutate

    def step_not_an_object(listing):
        listing["pipeline"][1] = listing["pipeline"][1]["kind"]
    for name, change, note in (
        ("pipeline-absent", lambda listing: listing.pop("pipeline"),
         "a Listing without a pipeline fails schema conformance"),
        ("accepted-rails-null", lambda listing: listing.update({"acceptedRails": None}),
         "a Listing with a pay phase carries acceptedRails as an array, not null"),
        ("pipeline-step-not-an-object", step_not_an_object,
         "each pipeline step is an object; a bare phase kind is not one"),
    ):
        add_case(vectors, f"listing-{name}", "fail", "XN-2/LR-2", note, listing_shape(change),
                 operation="admit-listing", reason="listing-shape")

    add_solana_identity_cases(vectors, solana_exact)
    add_solana_instruction_cases(vectors, solana_exact)
    add_payee_destination_cases(vectors, solana_exact)
    add_round_twelve_cases(vectors, signed_selection_refs, solana_exact, response_lost,
                           listing_pipeline(fixed_price, "commit-payee-bound-agreement"),
                           listing_pipeline(fixed_price, "commit-identity-bound-payee-agreement"))
    # N-P3-4: XN-2's signed request names both method and url.
    for member in ("method", "url"):
        def request_without(v, member=member):
            for ref in signed_selection_refs(v):
                ref["parameters"]["request"].pop(member)
        add_case(vectors, f"signed-request-without-{member}", "error", "XN-2",
                 f"the signed request names its {member}, so a reference without one is malformed",
                 request_without, reason="rail-ref-shape")

    # FR-2: an x402:protocol rateBps fee item resolves at the signed selection's
    # assetDecimals, half-up, once the adapter has established that precision.
    def fee_rate(rate_bps, amount, price=None, decimals=None, metadata_decimals=None):
        def mutate(v):
            if price is not None:
                v["agreement"]["terms"]["price"]["amount"] = price
                v["evidence"]["paymentAmount"]["amount"] = price
            if decimals is not None:
                for ref in signed_selection_refs(v):
                    ref["parameters"]["selection"]["assetDecimals"] = decimals
                v["capability"]["assetMetadata"]["decimals"] = decimals
            if metadata_decimals is not None:
                v["capability"]["assetMetadata"]["decimals"] = metadata_decimals
            v["feeDerivation"] = {"rateBps": rate_bps, "amount": amount}
        return mutate
    for name, mutate, verdict, reason, note in (
        ("exact-at-6", fee_rate(33, "0.004125"), "pass", None,
         "1.25 x 33 bps is exact at 6 decimals"),
        ("half-up-at-6", fee_rate(5000, "0.000001", price="0.000001"), "pass", None,
         "an exact half of the last unit at 6 decimals rounds up"),
        ("below-half-at-6", fee_rate(4999, "0", price="0.000001"), "pass", None,
         "just below half of the last unit rounds down, to the CD-1 zero"),
        ("half-up-not-half-even-at-6", fee_rate(5000, "0.000003", price="0.000005"), "pass", None,
         "2.5 units rounds half-up to 3, where half-even would give 2"),
        ("half-even-at-6", fee_rate(5000, "0.000002", price="0.000005"), "fail", "fee-amount",
         "half-even rounding is not FR-2's half-up"),
        ("exact-at-18", fee_rate(33, "0.004125", decimals=18), "pass", None,
         "the precision is the signed selection's assetDecimals, here 18"),
        ("half-up-at-18", fee_rate(5000, "0.000000000000000003", price="0.000000000000000005",
                                   decimals=18), "pass", None,
         "an exact half of the last unit at 18 decimals rounds up"),
        ("rounded-at-6-for-18-decimal-asset", fee_rate(
            5000, "0", price="0.000000000000000005", decimals=18), "fail", "fee-amount",
         "rounding at another precision than the selection's assetDecimals is not FR-2"),
        ("metadata-decimals-differ", fee_rate(33, "0.004125", metadata_decimals=18), "fail",
         "asset-metadata", "the precision is used only once the adapter's metadata establishes it"),
        ("amount-not-canonical", fee_rate(33, "0.0041250"), "error", "fee-amount",
         "the derived amount is a CD-1 canonical decimal"),
        ("rate-not-integer", fee_rate("33", "0.004125"), "error", "fee-rate",
         "rateBps is a non-negative integer"),
    ):
        add_case(vectors, f"fee-rate-{name}", verdict, "FR-2", note, mutate,
                 operation="fee-rate-amount", reason=reason)
    # FR-2 resolves only signed terms under the pinned definition, with the
    # adapter's metadata for the selected asset on the selected network. Each
    # derived amount is right for the inputs as given, so only the gate rejects.
    def fee_rate_where(member, changes):
        def mutate(v):
            fee_rate(33, "0.004125")(v)
            target = v["railDefinition"] if member == "definition" else v["capability"]["assetMetadata"]
            target.update(changes)
        return mutate
    for name, mutate, tamper, verdict, reason, note in (
        ("agreement-signature-invalid", fee_rate(33, "0.00825"),
         lambda v: v["agreement"]["terms"]["price"].update({"amount": "2.5"}), "fail", "signature",
         "a price changed after signing is not a signed term, though its fee is derived right"),
        ("definition-malformed", fee_rate_where("definition", {"providers": ["facilitator.example"]}),
         None, "error", "definition",
         "the rate resolves under the pinned protocol definition, re-validated even when signed"),
        ("definition-other-revision", fee_rate_where("definition", {"railVersion": 2}),
         None, "fail", "rail-version", "the rate resolves under the revision the signed reference pins"),
        ("metadata-other-asset", fee_rate_where("metadata", {"asset": "0x" + "99" * 20}),
         None, "fail", "asset-metadata",
         "metadata for another asset with equal decimals does not establish the precision"),
        ("metadata-other-network", fee_rate_where("metadata", {"network": "eip155:1"}),
         None, "fail", "asset-metadata",
         "metadata for the asset on another network does not establish the precision"),
        ("metadata-asset-not-20-bytes", fee_rate_where("metadata", {"asset": "0x1234"}),
         None, "error", "address-form", "an EIP-155 metadata asset is an XN-5 address"),
    ):
        add_case(vectors, f"fee-rate-{name}", verdict, "FR-2/XN-1/XN-5", note, mutate,
                 operation="fee-rate-amount", reason=reason, tamper=tamper)
    return vectors


def add_solana_identity_cases(vectors, solana_exact):
    def lost(v):
        solana_exact(v)
        v.pop("evidence", None)
        v["http"].pop("responseHeader", None)
        v["runtime"]["reconciliationState"]["settlementTransaction"] = None

    add_case(vectors, "solana-response-lost-settled", "pass", "XN-11",
             "the retained client-signed message resolves after response loss without evidence",
             lost, reason="response-header", authorization_submitted=True)
    add_case(vectors, "retry-solana-response-lost-settled", "pass", "XN-11",
             "a retry resolves the retained client signatures without knowing the sponsor transaction ID",
             lost, operation="retry", authorization_submitted=True)

    for operation in ("execute", "retry", "verify-evidence"):
        def substituted(v):
            solana_exact(v)
            _, full, transaction = solana_transactions(b"different valid blockhash")
            v["ledger"].update({"transaction": transaction, "transactionBase64": full,
                                 "settlementEvent": f"solana:devnet:{transaction}:4"})
        add_case(vectors, f"{operation}-solana-substituted-transaction", "indeterminate", "XN-8/XN-11",
                 "a genuinely signed different message with identical transfer terms cannot settle this authorization",
                 substituted, operation=operation, refresh=True,
                 authorization_submitted=True, reason="authorization-identity-mismatch")

    for operation in ("execute", "retry", "verify-evidence"):
        def unknown(v):
            solana_exact(v)
            v["ledger"].pop("transactionBase64")
        add_case(vectors, f"{operation}-solana-identity-lookup-unavailable", "indeterminate", "XN-8/XN-11",
                 "matching transfer metadata without authenticated transaction bytes leaves identity unresolved",
                 unknown, operation=operation, refresh=True, authorization_submitted=True,
                 reason="authorization-identity-unavailable")

    for operation in ("execute", "retry"):
        def pending(v):
            lost(v)
            v["ledger"] = {"available": True, "finalized": True}
        add_case(vectors, f"{operation}-solana-response-lost-unsettled", "indeterminate", "XN-11",
                 "no resolved transaction after response loss stays pending without a new authorization",
                 pending, operation=operation, authorization_submitted=True,
                 reason="authorization-unsettled")

    def mismatched_coordinate(v):
        solana_exact(v)
        _, _, transaction = solana_transactions(b"another transaction coordinate")
        v["ledger"].update({"transaction": transaction,
                             "settlementEvent": f"solana:devnet:{transaction}:4"})
    add_case(vectors, "solana-transaction-id-not-sponsor-signature", "indeterminate", "XN-8/XN-11",
             "the ledger coordinate must equal the authenticated full transaction's sponsor signature",
             mismatched_coordinate, refresh=True, authorization_submitted=True,
             reason="authorization-identity-mismatch")


def add_solana_instruction_cases(vectors, solana_exact):
    """§9.5.7.1/XN-6: the payer signs only a message that is exactly the payment.

    Each message below is the retained message and the paid payload alike, and
    each is refused before the wallet signs it.
    """
    source = associated_token_account(SOLANA_BUYER, SOLANA_ASSET, SOLANA_TOKEN_PROGRAM)
    token, system = SOLANA_TOKEN_PROGRAM, "1" * 32
    unknown = base58(hashlib.sha256(b"DACS #274 unknown Solana program").digest())
    table = base58(hashlib.sha256(b"DACS #274 Solana lookup table").digest())
    memo_extra = {"feePayer": SOLANA_FEE_PAYER, "memo": "dacs-274"}

    def added(instruction):
        return lambda instructions: instructions[:3] + [instruction] + instructions[3:]

    def replaced(index, instruction):
        return lambda instructions: instructions[:index] + [instruction] + instructions[index + 1:]

    def transfer_accounts(index, account):
        def edit(instructions):
            program, accounts, data = instructions[2]
            accounts = accounts[:index] + [(account, accounts[index][1])] + accounts[index + 1:]
            return replaced(2, (program, accounts, data))(instructions)
        return edit

    for name, note, extra, options in (
        ("amount-plus-one", "a transfer of one more atomic unit than the signed amount", None,
         {"amount": SOLANA_AMOUNT + 1}),
        ("amount-minus-one", "a transfer of one atomic unit less than the signed amount", None,
         {"amount": SOLANA_AMOUNT - 1}),
        ("amount-tenfold", "an overpayment, which upstream tolerates but the signed terms do not", None,
         {"amount": SOLANA_AMOUNT * 10}),
        ("other-mint", "a transfer of another mint", None, {"mint": SOLANA_OTHER}),
        ("other-destination", "a transfer to another owner's associated token account", None,
         {"pay_to": LETTERED_SOLANA_SELLER}),
        ("destination-not-associated", "a transfer to the payTo wallet itself, not its associated "
         "token account", None, {"edit": transfer_accounts(2, SOLANA_SELLER)}),
        ("source-not-associated", "a transfer from another token account of the payer", None,
         {"edit": transfer_accounts(0, SOLANA_OTHER)}),
        ("authority-not-payer", "a transfer whose authority is not the payer", None,
         {"edit": transfer_accounts(3, SOLANA_OTHER)}),
        ("other-token-program", "a Token-2022 transfer of a mint the adapter's metadata assigns to "
         "SPL Token", None, {"token_program": SOLANA_TOKEN_2022_PROGRAM}),
        ("wrong-decimals", "a TransferChecked naming other decimals", None, {"decimals": 9}),
        ("extra-approve", "an added Approve of the payer's token account to another delegate", None,
         {"edit": added((token, [(source, True), (SOLANA_OTHER, False), (SOLANA_BUYER, False)],
                         b"\x04" + SOLANA_AMOUNT.to_bytes(8, "little")))}),
        ("extra-set-authority", "an added SetAuthority handing the payer's token account to another "
         "owner", None, {"edit": added((token, [(source, True), (SOLANA_BUYER, False)],
                                        b"\x06\x02\x01" + public_key_bytes(SOLANA_OTHER)))}),
        ("extra-close-account", "an added CloseAccount of the payer's token account", None,
         {"edit": added((token, [(source, True), (SOLANA_OTHER, True), (SOLANA_BUYER, False)], b"\x09"))}),
        ("extra-system-transfer", "an added System transfer of the payer's lamports", None,
         {"edit": added((system, [(SOLANA_BUYER, True), (SOLANA_OTHER, True)],
                         (2).to_bytes(4, "little") + (10**6).to_bytes(8, "little")))}),
        ("extra-unknown-program", "an added instruction of a program the profile does not name", None,
         {"edit": added((unknown, [], b"x"))}),
        ("second-transfer", "a second TransferChecked", None,
         {"edit": lambda instructions: instructions[:3] + instructions[2:]}),
        ("memo-missing", "no Memo instruction, which upstream's client always adds", None,
         {"edit": lambda instructions: instructions[:3]}),
        ("memo-second", "a second Memo instruction", None,
         {"edit": lambda instructions: instructions + instructions[3:]}),
        ("memo-not-nonce", "without extra.memo the Memo carries upstream's hex nonce of at least "
         "16 bytes", None, {"memo": "not a hex nonce"}),
        ("memo-with-signer", "a Memo instruction that also names a signer account", None,
         {"edit": replaced(3, (MEMO_PROGRAM, [(SOLANA_BUYER, False)], SOLANA_MEMO_NONCE.encode()))}),
        ("extra-memo-other", "a Memo instruction whose data is not the signed extra.memo", memo_extra,
         {"memo": "dacs-275"}),
        ("extra-memo-missing", "no Memo instruction although extra.memo names one", memo_extra,
         {"memo": "dacs-274", "edit": lambda instructions: instructions[:3]}),
        ("compute-heap-frame", "a compute-budget instruction other than the unit limit and price", None,
         {"edit": added((COMPUTE_BUDGET_PROGRAM, [], b"\x01" + (32768).to_bytes(4, "little")))}),
        ("compute-limit-above-bound", "a compute-unit limit above the pinned 400,000", None,
         {"edit": replaced(0, (COMPUTE_BUDGET_PROGRAM, [], b"\x02" + (400_001).to_bytes(4, "little")))}),
        ("compute-price-above-bound", "a compute-unit price above the pinned 5 lamports per unit", None,
         {"edit": replaced(1, (COMPUTE_BUDGET_PROGRAM, [], b"\x03" + (5_000_001).to_bytes(8, "little")))}),
        ("lookup-table", "an address lookup table, which hides the accounts it loads", None,
         {"lookups": [(table, [0])]}),
        ("extra-signer", "a third required signer besides the sponsor and the payer", None,
         {"extra_signers": [SOLANA_OTHER_KEY]}),
    ):
        def signed_message(v, extra=extra, options=options):
            solana_exact(v, extra=copy.deepcopy(extra))
            partial = solana_transactions(**options)[0]
            v["runtime"]["solanaAuthorization"] = partial
            v["runtime"]["reconciliationState"]["authorizationIdentity"] = solana_identity(
                partial, SOLANA_BUYER, SOLANA_FEE_PAYER)[0]
        add_case(vectors, f"solana-signed-message-{name}", "fail", "XN-6/§9.5.7.1",
                 f"{note}: the payer signs only a message that is exactly the signed payment",
                 signed_message, refresh=True, reason="paid-request-payload")

    def token_2022(v):
        solana_exact(v)
        v["capability"]["assetMetadata"]["tokenProgram"] = SOLANA_TOKEN_2022_PROGRAM
    add_case(vectors, "solana-token-2022-exact-success", "pass", "XN-5/§9.5.7.1",
             "a mint the adapter's metadata assigns to Token-2022 is paid by a Token-2022 TransferChecked",
             token_2022, refresh=True)
    for name, value in (("absent", None), ("unknown", SOLANA_OTHER), ("array", [SOLANA_TOKEN_PROGRAM])):
        def metadata_program(v, value=value):
            solana_exact(v)
            if value is None:
                v["capability"]["assetMetadata"].pop("tokenProgram")
            else:
                v["capability"]["assetMetadata"]["tokenProgram"] = value
        add_case(vectors, f"solana-asset-metadata-token-program-{name}", "fail", "XN-5/§9.5.7.1",
                 "the Solana adapter's trusted metadata names the token program that owns the mint",
                 metadata_program, refresh=True, reason="asset-metadata")

    # XN-11: a validly signed resolved transaction of other signers is another
    # transaction, so the original authorization stays pending.
    for operation in ("execute", "retry", "verify-evidence"):
        for who in ("sponsor", "payer"):
            def other_signer(v, who=who):
                solana_exact(v)
                _, full, transaction = solana_transactions(**{f"{who}_key": SOLANA_OTHER_KEY})
                v["ledger"].update({"transaction": transaction, "transactionBase64": full,
                                     "settlementEvent": f"solana:devnet:{transaction}:4"})
            add_case(vectors, f"{operation}-solana-resolved-other-{who}", "indeterminate", "XN-8/XN-11",
                     f"a validly signed finalized transaction of another {who} does not resolve this "
                     "authorization", other_signer, operation=operation, refresh=True,
                     authorization_submitted=True, reason="authorization-identity-mismatch")


def add_payee_destination_cases(vectors, solana_exact):
    """PB-2 for the negotiated arm: step 1(b) takes the EVM chain from the
    agreement-signed selection, and an applicable controlled claim in the pinned
    payee bundle is checked before the wallet is called."""

    def pin_payee_bundle(v, bundle_hash=None):
        """The seller's signed and the runtime payee's bundleHash pin the presented bundle."""
        if bundle_hash is None:
            bundle_hash = digest(unsigned(v["payeeBundle"], "presentation"))
        v["agreement"]["parties"][1]["bundleHash"] = bundle_hash
        v["runtime"]["payee"]["bundleHash"] = bundle_hash

    def payee_claims(*claims, linkage=None, rebind=True, **bundle):
        def mutate(v):
            v["payeeBundle"] = payee_bundle(*claims, **bundle)
            v["payeeLinkage"] = dict(linkage or {})
            if rebind:
                pin_payee_bundle(v)
        return mutate

    def reshape_payee_bundle(change):
        """A pinned payee bundle that is not a DACS-1 IdentityBundle."""
        def mutate(v):
            change(v["payeeBundle"])
            pin_payee_bundle(v)
        return mutate

    def then(*changes):
        def mutate(v):
            for change in changes:
                change(v)
        return mutate

    payout_claim = "cci-xm:evm:8453:" + SELLER_ADDRESS
    other_claim = "cci-xm:evm:8453:0x" + "99" * 20
    add_case(vectors, "pb2-negotiated-chain-controlled-claim-binds-payout", "pass", "PB-2",
             "the signed eip155:8453 selection makes the payee's cci-xm:evm:8453 claim applicable "
             "(step 1(b)); its linkage resolves control-proven to the payout address, so tier 2 binds it",
             payee_claims(payout_claim, linkage={payout_claim: "pass"}))
    add_case(vectors, "pb2-negotiated-chain-claim-controls-other-address", "fail", "PB-2",
             "the applicable claim proves control of another address than the signed payout: tier 2 "
             "is applicable, so the co-signed payout binding (tier 3) is not legal and nothing is paid",
             payee_claims(other_claim, linkage={other_claim: "pass"}), reason="payee-destination")
    add_case(vectors, "pb2-negotiated-chain-linkage-unresolved-pauses", "indeterminate", "PB-2",
             "the applicable claim names the payout but its linkage cannot be resolved: an ST-7 pause "
             "with no wallet call, never a fall-through to the payout binding's tier 3",
             payee_claims(payout_claim, linkage={payout_claim: "indeterminate"}),
             reason="payee-linkage-unresolved")
    add_case(vectors, "pb2-negotiated-chain-linkage-absent-pauses", "indeterminate", "PB-2",
             "no linkage decision for the applicable claim is unresolved, not tier 3",
             payee_claims(payout_claim), reason="payee-linkage-unresolved")
    add_case(vectors, "pb2-negotiated-chain-linkage-error-stays-error", "error", "PB-2",
             "a resolver error for the applicable claim stays error (§7.3.2), never a silent downgrade",
             payee_claims(payout_claim, linkage={payout_claim: "error"}), reason="payee-linkage-error")
    for name, claim, note in (
        ("pb2-other-chain-claim-leaves-tier3", "cci-xm:evm:1:" + SELLER_ADDRESS,
         "a claim for eip155:1 is not applicable under an eip155:8453 selection"),
        ("pb2-name-style-subchain-claim-leaves-tier3", "cci-xm:evm:base:" + SELLER_ADDRESS,
         "a name-style subchain is not the DACS-1 EVM profile and is never aliased to a chain ID"),
        ("pb2-leading-zero-chain-claim-leaves-tier3", "cci-xm:evm:08453:" + SELLER_ADDRESS,
         "a non-minimal chain ID is not the DACS-1 EVM profile"),
    ):
        add_case(vectors, name, "pass", "PB-2", note + ", so its unresolved linkage is never consulted "
                 "and the co-signed payout binding (tier 3) binds the destination",
                 payee_claims(claim, linkage={claim: "indeterminate"}))
    add_case(vectors, "pb2-solana-selection-evm-claim-leaves-tier3", "pass", "PB-2",
             "a Solana selection exposes no EIP-155 chain, so an EVM claim cannot make tier 2 applicable",
             then(solana_exact, payee_claims(payout_claim, linkage={payout_claim: "indeterminate"})),
             refresh=True)

    def challenge_offers_evm(v):
        v["http"]["paymentRequired"]["accepts"].insert(0, requirement(2))
    add_case(vectors, "pb2-challenge-chain-cannot-make-tier2-applicable", "pass", "PB-2",
             "the challenge also offers eip155:8453, but only the agreement-signed selection derives "
             "the chain: under the Solana selection the EVM claim stays inapplicable",
             then(solana_exact, challenge_offers_evm,
                  payee_claims(payout_claim, linkage={payout_claim: "indeterminate"})), refresh=True)
    add_case(vectors, "pb2-payee-bundle-not-pinned", "fail", "PB-2",
             "the presented payee bundle must be the one the agreement's and the runtime payee's "
             "bundleHash pin; dropping or adding a claim cannot change the applicable tier",
             payee_claims(payout_claim, linkage={payout_claim: "pass"}, rebind=False),
             reason="payee-bundle")
    add_case(vectors, "pb2-runtime-payee-bundle-hash-not-signed", "fail", "PB-2",
             "the runtime payee's bundleHash must equal the seller party's signed bundleHash",
             lambda v: v["runtime"]["payee"].update({"bundleHash": "cc" * 32}), reason="payee-bundle")

    def strip_signed_claim(v):
        payee_claims(other_claim, linkage={other_claim: "pass"})(v)
        v["payeeBundle"] = payee_bundle()
        v["runtime"]["payee"]["bundleHash"] = digest(unsigned(v["payeeBundle"], "presentation"))
    add_case(vectors, "pb2-runtime-pin-matches-unsigned-bundle", "fail", "PB-2",
             "the seller signs a bundle whose applicable claim names another address; the runtime "
             "presents it without that claim, with an unsigned runtime bundleHash that pins what it "
             "presents: only the seller's signed bundleHash refuses it, so it never takes tier 3",
             strip_signed_claim, reason="payee-bundle")
    add_case(vectors, "pb2-payee-bundle-hash-over-presentation", "fail", "PB-2",
             "bundleHash covers the bundle without its presentation (DACS-1 §6.3.2), so a pin "
             "over the whole bundle, presentation included, does not pin it",
             then(payee_claims(payout_claim, linkage={payout_claim: "pass"}),
                  lambda v: pin_payee_bundle(v, digest(v["payeeBundle"]))), reason="payee-bundle")
    add_case(vectors, "pb2-payee-bundle-presented-by-other-claim", "fail", "PB-2",
             "the pinned bundle is presented by the payout claim, not the seller party's primary "
             "claim, so it is not the seller's bundle",
             payee_claims(payout_claim, linkage={payout_claim: "pass"}, presented_by=payout_claim),
             reason="payee-bundle")
    for name, change, note in (
        ("pb2-payee-claim-not-object", lambda b: b["claims"].append(payout_claim),
         "a bare-string claim is a malformed claim container, a structural error, never "
         "skipped so that the payment takes tier 3"),
        ("pb2-payee-claim-ref-not-string", lambda b: b["claims"].append({"ref": 8453}),
         "a claim whose ref is not a string is a malformed claim reference"),
        ("pb2-payee-bundle-presentation-absent", lambda b: b.pop("presentation"),
         "an IdentityBundle has a presentation; it is outside bundleHash, so only the bundle's "
         "shape refuses a bundle without one"),
        ("pb2-payee-bundle-presented-at-absent", lambda b: b.pop("presentedAt"),
         "an IdentityBundle always carries presentedAt"),
    ):
        add_case(vectors, name, "error", "PB-2", note, reshape_payee_bundle(change),
                 reason="payee-bundle-shape")
    add_case(vectors, "pb2-negotiated-chain-linkage-fail-refuses", "fail", "PB-2",
             "the applicable claim's linkage resolves not controlled: no tier binds the payout, so "
             "nothing is paid and the co-signed payout binding (tier 3) is not legal",
             payee_claims(payout_claim, linkage={payout_claim: "fail"}), reason="payee-destination")
    add_case(vectors, "pb2-negotiated-chain-linkage-malformed-is-error", "error", "PB-2",
             "a linkage decision that is not a VerifyResult decision is a malformed resolver answer",
             payee_claims(payout_claim, linkage={payout_claim: {"decision": "pass"}}),
             reason="payee-linkage-error")
    add_case(vectors, "pb2-payee-linkage-not-object", "error", "PB-2",
             "linkage decisions that are not an object keyed by claim are a malformed resolver answer",
             then(payee_claims(payout_claim), lambda v: v.update({"payeeLinkage": [payout_claim]})),
             reason="payee-linkage-error")
    oversized_claim = "cci-xm:evm:" + "9" * 4301 + ":" + SELLER_ADDRESS
    add_case(vectors, "pb2-oversized-chain-claim-leaves-tier3", "pass", "PB-2",
             "a chain ID above 9007199254740991, here 4301 digits, establishes no EIP-155 chain and "
             "cannot make tier 2 applicable, so the co-signed payout binding (tier 3) binds the "
             "destination",
             payee_claims(oversized_claim, linkage={oversized_claim: "indeterminate"}))
    add_case(vectors, "pb2-verify-evidence-controlled-claim-binds-payout", "pass", "PB-2",
             "a verifier admits a stored success record whose payout the applicable claim binds",
             payee_claims(payout_claim, linkage={payout_claim: "pass"}), operation="verify-evidence")
    add_case(vectors, "pb2-verify-evidence-claim-controls-other-address", "fail", "PB-2",
             "a verifier applies the same PB-2 gate to a stored success record",
             payee_claims(other_claim, linkage={other_claim: "pass"}), operation="verify-evidence",
             reason="payee-destination")

    def linkage_unanswered(v):
        v.pop("payeeLinkage")
    add_case(vectors, "pb2-payee-linkage-map-absent-pauses", "indeterminate", "PB-2",
             "the adapter has no linkage answer yet, so the applicable claim is unresolved: an ST-7 "
             "pause (substrate), not a resolver error",
             then(payee_claims(payout_claim), linkage_unanswered), reason="payee-linkage-unresolved")
    add_case(vectors, "pb2-verify-evidence-linkage-map-absent-is-indeterminate", "indeterminate",
             "PB-2/XN-8", "a verifier with no linkage answer yet cannot establish the tier-2 binding, "
             "which is temporarily unavailable data, so the record is indeterminate",
             then(payee_claims(payout_claim), linkage_unanswered), operation="verify-evidence",
             reason="payee-linkage-unresolved")
    add_case(vectors, "pb2-payee-bundle-presenter-not-in-claims", "fail", "PB-2",
             "the seller signs and both pins name a bundle whose claims omit its presentedBy, so "
             "presentedBy resolves to no claim (DACS-1 §6.3.2) and it is not the seller's bundle",
             payee_claims("cci-xm:evm:1:" + SELLER_ADDRESS, primary=()), reason="payee-bundle")
    seller_qualified = SELLER_CLAIM + "?role=payee"
    add_case(vectors, "pb2-payee-bundle-presenter-cf3-match-binds-payout", "pass", "PB-2",
             "presentedBy resolves by CF-3 (Scheme, Identifier) identity, so a claim that differs "
             "only in parameters is the presented claim",
             payee_claims(payout_claim, linkage={payout_claim: "pass"}, primary=(seller_qualified,)))
    add_case(vectors, "pb2-payee-bundle-presenter-ambiguous", "fail", "PB-2",
             "two canonical-distinct claims share presentedBy's CF-3 identity, so it resolves no "
             "presented claim (DACS-1 §6.3.2) and array order does not pick one",
             payee_claims(payout_claim, linkage={payout_claim: "pass"},
                          primary=(SELLER_CLAIM, seller_qualified)), reason="payee-bundle")
    add_case(vectors, "pb2-payee-presentation-signatures-absent", "error", "PB-2",
             "a per-claim presentation has signatures (DACS-1 §6.3.2); the presentation is outside "
             "bundleHash, so only the bundle's shape refuses one without them",
             reshape_payee_bundle(lambda b: b["presentation"].pop("signatures")),
             reason="payee-bundle-shape")
    add_case(vectors, "pb2-payee-bundle-presented-at-fractional", "pass", "PB-2",
             "presentedAt is a diagnostic CORE number (DACS-1 §6.3.2): a fractional value is "
             "admitted and gates nothing",
             payee_claims(payout_claim, linkage={payout_claim: "pass"}, presented_at=1787443199000.5))
    add_case(vectors, "pb2-negotiated-chain-claim-naming-payout-passes-beside-unresolved", "pass",
             "PB-2", "of two applicable claims, the one naming the payout resolves control-proven, "
             "so tier 2 binds it; the other claim, unresolved, names no payout and decides nothing",
             payee_claims(payout_claim, other_claim, linkage={payout_claim: "pass"}))


def add_round_twelve_cases(vectors, signed_selection_refs, solana_exact, response_lost,
                           admissible_listing, violating_listing) -> None:
    """Cases for the stored record's own fields, the static arm, the challenge
    location, response semantics, event-key bounds, closed shapes, request
    headers, currency binding, retry gates, Solana clusters and anchoring."""

    # §9.7/SB-1/XN-8: the stored record's own version, outcome, phase, job and
    # amount. A verifier judges them; execute and retry record the defect and
    # rebuild the record from the reconciled event.
    for name, change, verdict, reason in (
        ("evidence-version-2", lambda e: e.update({"evidenceVersion": "2"}),
         "error", "evidence-record-version"),
        ("evidence-version-absent", lambda e: e.pop("evidenceVersion"),
         "error", "evidence-record-version"),
        ("outcome-failure", lambda e: e.update({"outcome": "failure"}),
         "fail", "evidence-record-binding"),
        ("outcome-absent", lambda e: e.pop("outcome"), "error", "evidence-record-shape"),
        ("phase-other-rail", lambda e: e.update({"phase": "pay-evm-erc20"}),
         "fail", "evidence-record-binding"),
        ("job-other", lambda e: e.update({"jobId": "01M0NVBGYEANE562QQXD33C7WY"}),
         "fail", "evidence-record-binding"),
        ("payment-amount-inflated", lambda e: e["paymentAmount"].update({"amount": "999"}),
         "fail", "evidence-payment-amount"),
        ("payment-amount-other-currency", lambda e: e["paymentAmount"].update({"currency": "EURC"}),
         "fail", "evidence-payment-amount"),
        ("payment-amount-absent", lambda e: e.pop("paymentAmount"),
         "error", "evidence-payment-amount"),
        ("payment-amount-not-canonical", lambda e: e["paymentAmount"].update({"amount": "1.250"}),
         "error", "evidence-payment-amount"),
        ("payment-amount-extra-member", lambda e: e["paymentAmount"].update({"decimals": 6}),
         "error", "evidence-payment-amount"),
    ):
        add_case(vectors, f"verify-evidence-record-{name}", verdict, "XN-8/SB-1/§9.7",
                 "a verifier compares the stored record's own fields with the agreement before "
                 "it counts the record as this payment's success",
                 lambda v, change=change: change(v["evidence"]), operation="verify-evidence",
                 reason=reason)
    # XN-8: exactly `amount` and `currency`; and the finality record's scheme,
    # network and bindingProfile, each different, missing or malformed.
    record_defects = (
        ("payment-amount-extra-member", lambda e: e["paymentAmount"].update({"decimals": 6}),
         "evidence-payment-amount"),
        ("finality-scheme-other",
         lambda e: e["settlementFinality"]["schemeNetworkFinality"].update({"scheme": "upto"}),
         "finality-profile"),
        ("finality-binding-profile-absent",
         lambda e: e["settlementFinality"]["schemeNetworkFinality"].pop("bindingProfile"),
         "finality-profile"),
        ("finality-binding-profile-not-string",
         lambda e: e["settlementFinality"]["schemeNetworkFinality"].update({"bindingProfile": 1}),
         "finality-profile"),
        ("finality-profile-absent", lambda e: e["settlementFinality"].pop("schemeNetworkFinality"),
         "finality-profile"),
    )
    for name, change, reason in record_defects[1:]:
        add_case(vectors, f"verify-evidence-record-{name}", "fail", "XN-8",
                 "the scheme-network-finality record repeats the signed selection's scheme and "
                 "network and the literal dacs-x402-exact:v1; a different, missing or malformed "
                 "member is a resolved evidence contradiction",
                 lambda v, change=change: change(v["evidence"]), operation="verify-evidence",
                 reason=reason)
    for name, change, reason in record_defects:
        add_case(vectors, f"execute-record-{name}-rebuilt", "pass", "XN-11/XN-8",
                 "the stored record's defect is the recorded reason; the ledger decides and the "
                 "record is rebuilt",
                 lambda v, change=change: change(v["evidence"]), authorization_submitted=True,
                 reason=reason)
        add_case(vectors, f"retry-record-{name}-rebuilt", "pass", "XN-11/XN-8",
                 "a retry judges the stored record like execute and rebuilds it",
                 lambda v, change=change: change(v["evidence"]), operation="retry",
                 authorization_submitted=True, reason=reason)
    add_case(vectors, "execute-record-job-other-rebuilt", "pass", "XN-11/SB-1",
             "a stored record naming another job never decides the payment: the settlement stands "
             "and the record is rebuilt",
             lambda v: v["evidence"].update({"jobId": "01M0NVBGYEANE562QQXD33C7WY"}),
             authorization_submitted=True, reason="evidence-record-binding")
    add_case(vectors, "retry-record-payment-amount-inflated-rebuilt", "pass", "XN-11/SB-1",
             "a retry judges the stored record's amount like execute: the inflated record is "
             "the recorded reason and is rebuilt",
             lambda v: v["evidence"]["paymentAmount"].update({"amount": "999"}),
             operation="retry", authorization_submitted=True, reason="evidence-payment-amount")

    # XN-11/PC-7: an anchored record cannot be overwritten, so it is not rebuilt.
    def anchored(change):
        def mutate(v):
            change(v)
            v["runtime"]["storedRecordAnchored"] = True
        return mutate
    add_case(vectors, "execute-anchored-record-defect-manual-recovery", "pass", "XN-11/PC-7",
             "the stored record is already anchored at the write-once PC-2 address: the ledger "
             "still decides success, but nothing is rebuilt and the phase enters manual recovery",
             anchored(lambda v: v["evidence"].update({"jobId": "01M0NVBGYEANE562QQXD33C7WY"})),
             authorization_submitted=True, reason="evidence-record-binding")
    add_case(vectors, "retry-anchored-record-defect-manual-recovery", "pass", "XN-11/PC-7",
             "a retry never re-anchors over an anchored record that does not verify",
             anchored(lambda v: v["evidence"]["paymentAmount"].update({"amount": "999"})),
             operation="retry", authorization_submitted=True, reason="evidence-payment-amount")
    add_case(vectors, "execute-anchored-record-verifies", "pass", "XN-11/PC-7",
             "an anchored record that verifies is the phase's evidence; re-anchoring the same "
             "record is idempotent", anchored(lambda v: None), authorization_submitted=True)

    # XN-2: the static arm cannot carry x402:protocol.
    for name, parameters in (
        ("no-parameters", None),
        ("static-resource-parameter", {"resource": URL}),
        ("parameters-without-selection", {"request": {"method": "GET", "url": URL}}),
    ):
        def static_shape(v, parameters=parameters):
            for ref in signed_selection_refs(v):
                if parameters is None:
                    ref.pop("parameters")
                else:
                    ref["parameters"] = copy.deepcopy(parameters)
        add_case(vectors, f"static-arm-ref-{name}", "error", "XN-2",
                 "a StaticPaymentRailRef whose railId is x402:protocol is malformed; it is never "
                 "routed to static handling", static_shape, reason="rail-ref-shape")

    # XN-2: the negotiated ref and its parameters, request and selection are
    # closed objects.
    for name, change in (
        ("ref-unknown-member", lambda ref: ref.update({"facilitator": "https://f.example"})),
        ("parameters-unknown-member", lambda ref: ref["parameters"].update(
            {"facilitator": "https://f.example"})),
        ("request-headers-member", lambda ref: ref["parameters"]["request"].update(
            {"headers": {"Accept": "application/json"}})),
        ("selection-pay-to-member", lambda ref: ref["parameters"]["selection"].update(
            {"payTo": SELLER_ADDRESS})),
    ):
        def closed(v, change=change):
            for ref in signed_selection_refs(v):
                change(ref)
        add_case(vectors, f"closed-shape-{name}", "error", "XN-2",
                 "the negotiated ref, parameters, request and selection are closed: an unknown "
                 "member is malformed, never ignored or merged", closed, reason="rail-ref-shape")

    # XN-2 structural MUSTs that previously reached their verdict untested.
    for name, change in (
        ("request-url-empty-host", lambda ref: ref["parameters"]["request"].update(
            {"url": "https:///dacs/resource"})),
        ("rail-version-zero", lambda ref: ref.update({"railVersion": 0})),
        ("rail-version-string", lambda ref: ref.update({"railVersion": "1"})),
        ("request-method-number", lambda ref: ref["parameters"]["request"].update({"method": 1})),
        ("selection-scheme-empty", lambda ref: ref["parameters"]["selection"].update({"scheme": ""})),
        ("selection-asset-empty", lambda ref: ref["parameters"]["selection"].update({"asset": ""})),
        ("selection-currency-empty", lambda ref: ref["parameters"]["selection"].update(
            {"currency": ""})),
    ):
        def structural(v, change=change):
            for ref in signed_selection_refs(v):
                change(ref)
        add_case(vectors, f"structural-{name}", "error", "XN-2",
                 "a malformed signed reference is an error before any request", structural,
                 reason="rail-ref-shape")
    add_case(vectors, "evidence-payment-required-hash-upper-case", "error", "XN-7",
             "the challenge hash is 64 lower-case hex digits",
             lambda v: v["evidence"]["paymentTxRefs"][0].update(
                 {"paymentRequiredHash": v["evidence"]["paymentTxRefs"][0]["paymentRequiredHash"].upper()}),
             operation="verify-evidence", reason="evidence-hash-shape")
    for member in ("paymentRequiredHash", "paymentReceiptHash"):
        for shape, value in (("number", 123), ("null", None), ("list", ["a"]), ("object", {"x": 1})):
            for operation in ("verify-evidence", "execute", "retry"):
                add_case(vectors, f"{operation}-record-{member}-not-string-{shape}",
                         "error" if operation == "verify-evidence" else "pass", "XN-7/XN-8/XN-11",
                         "a re-signed non-string record hash is a verifier error; execute and retry "
                         "rebuild the unanchored record while the ledger decides the payment",
                         lambda v, member=member, value=value: v["evidence"]["paymentTxRefs"][0].update(
                             {member: value}), operation=operation, authorization_submitted=True,
                         reason="evidence-hash-shape")
    add_case(vectors, "definition-rail-type-value-mismatch", "error", "XN-1/RD-5",
             "the protocol arm must match its discriminated values exactly",
             lambda v: v["railDefinition"].update({"railType": "evm-erc20"}),
             operation="validate-definition")

    # XN-4: the v2 challenge is the PAYMENT-REQUIRED header; the body is never read.
    def body(raw):
        return base64.b64encode(raw).decode("ascii")
    add_case(vectors, "challenge-header-with-html-body", "pass", "XN-4",
             "the PAYMENT-REQUIRED header carries the challenge; an HTML 402 body is ignored",
             lambda v: v["http"].update({"bodyBase64": body(b"<html><body>Pay</body></html>")}),
             authorization_submitted=True)
    add_case(vectors, "challenge-header-and-body-disagree", "pass", "XN-4",
             "the header governs: a body carrying another challenge is never read or hashed",
             lambda v: v["http"].update({"bodyBase64": body(json.dumps(
                 {**payment_required(2), "accepts": [{**requirement(2), "amount": "1"}]},
                 separators=(",", ":")).encode("utf-8"))}),
             authorization_submitted=True)

    def body_only(v):
        v["http"]["bodyBase64"] = body(json.dumps(
            v["http"].pop("paymentRequired"), separators=(",", ":")).encode("utf-8"))
    add_case(vectors, "challenge-in-body-only", "error", "XN-4",
             "a v2 challenge only in the 402 body is no PAYMENT-REQUIRED challenge, so nothing "
             "is authorized", body_only, reason="payment-required-header")

    # XN-7: upstream's payer is optional, and settlement_pending is non-terminal.
    def response_is(change):
        def mutate(v):
            response = settlement_response(2)
            change(response)
            v["http"]["responseHeader"] = encoded_header(response, 2)
        return mutate
    add_case(vectors, "response-without-payer", "pass", "XN-7",
             "upstream's SettleResponse.payer is optional, so a response without it is sound",
             response_is(lambda r: r.pop("payer")), refresh=True, authorization_submitted=True)
    add_case(vectors, "response-settlement-pending", "pass", "XN-7/XN-11",
             "upstream's non-terminal settlement_pending names the broadcast transaction; it is "
             "no fault, and the finalized ledger decides",
             response_is(lambda r: r.update({"success": False, "errorReason": "settlement_pending"})),
             refresh=True, authorization_submitted=True)
    add_case(vectors, "response-settlement-pending-without-transaction", "pass", "XN-7/XN-11",
             "settlement_pending must carry the broadcast transaction; without one it is a "
             "non-success response defect",
             response_is(lambda r: r.update(
                 {"success": False, "errorReason": "settlement_pending", "transaction": ""})),
             refresh=True, authorization_submitted=True, reason="response-not-success")
    add_case(vectors, "verify-evidence-response-without-payer", "pass", "XN-7/XN-8",
             "a verifier also reads an absent payer as sound",
             response_is(lambda r: r.pop("payer")), refresh=True, operation="verify-evidence")

    # SB-1: event-key integers are safe and a Solana signature is 64 bytes.
    unsafe = str(2**53 + 1)
    add_case(vectors, "ledger-event-log-index-unsafe", "error", "SB-1/XN-11",
             "a logIndex above 2^53-1 renders differently across readers, so it is malformed",
             lambda v: v["ledger"].update({"settlementEvent": f"evm:8453:{SAFE_TX}:{unsafe}"}),
             authorization_submitted=True, reason="ledger-event-key")
    add_case(vectors, "evidence-event-log-index-unsafe", "error", "SB-1/XN-8",
             "a signed event key with an unsafe logIndex is malformed for a verifier too",
             lambda v: (v["ledger"].update({"settlementEvent": f"evm:8453:{SAFE_TX}:{unsafe}"}),
                        v["evidence"]["paymentTxRefs"][0].update(
                            {"settlementEvent": f"evm:8453:{SAFE_TX}:{unsafe}"})),
             operation="verify-evidence", reason="native-event-key")

    def short_solana_signature(v):
        solana_exact(v)
        v["ledger"].update({"transaction": "1" * 10, "settlementEvent": f"solana:devnet:{'1' * 10}:4"})
    add_case(vectors, "ledger-solana-signature-not-64-bytes", "error", "SB-1/XN-11",
             "a Solana signature must decode to exactly 64 bytes; a 10-byte one is malformed",
             short_solana_signature, refresh=True, authorization_submitted=True,
             reason="ledger-event-key")

    # XN-4/XN-5: a v2 success with no extensions on either side, the common case.
    def no_extensions(v):
        for ref in signed_selection_refs(v):
            ref["parameters"].pop("paymentRequiredExtensions")
        v["http"]["paymentRequired"].pop("extensions")
    add_case(vectors, "protocol-v2-exact-success-without-extensions", "pass", "XN-4",
             "absent extensions on both sides are equal; upstream's common challenge succeeds",
             no_extensions, refresh=True)
    add_case(vectors, "verify-evidence-without-extensions", "pass", "XN-4/XN-8",
             "a verifier accepts the same record with no extensions on either side",
             no_extensions, refresh=True, operation="verify-evidence")

    # LRR-5: the commitment-phase rule rejects even without registry authority.
    def registry_unauthenticated(listing):
        def mutate(v):
            listing(v)
            v["registry"] = {"authenticated": False}
        return mutate
    add_case(vectors, "listing-violation-registry-unauthenticated", "fail", "XN-2/LRR-5",
             "the commitment-phase rule needs no registry, so a violating Listing is rejected "
             "even when registry authority cannot be authenticated",
             registry_unauthenticated(violating_listing), operation="admit-listing",
             reason="x402-protocol-agreement-type")
    add_case(vectors, "listing-compliant-registry-unauthenticated", "indeterminate", "XN-2/LRR-5",
             "a compliant Listing still waits on registry-dependent checks",
             registry_unauthenticated(admissible_listing), operation="admit-listing",
             reason="registry-unauthenticated")

    # XN-2/XN-6: request headers. The paid request adds only PAYMENT-SIGNATURE,
    # and neither request carries an ambient credential.
    for name, change, verdict, reason in (
        ("paid-adds-cookie", lambda r: r["paidHeaders"].update({"Cookie": "session=1"}),
         "fail", "ambient-credential"),
        ("paid-adds-authorization", lambda r: r["paidHeaders"].update({"Authorization": "Bearer x"}),
         "fail", "ambient-credential"),
        ("both-carry-proxy-authorization", lambda r: (
            r["unpaidHeaders"].update({"Proxy-Authorization": "Basic eA=="}),
            r["paidHeaders"].update({"Proxy-Authorization": "Basic eA=="})),
         "fail", "ambient-credential"),
        ("paid-adds-other-header", lambda r: r["paidHeaders"].update({"X-Trace": "1"}),
         "fail", "paid-request-headers"),
        ("paid-name-not-token", lambda r: r["paidHeaders"].update({"X Trace": "1"}),
         "error", "request-headers"),
        ("both-value-not-string", lambda r: (
            r["unpaidHeaders"].update({"Accept": 1}), r["paidHeaders"].update({"Accept": 1})),
         "error", "request-headers"),
        ("paid-without-payment-signature", lambda r: r["paidHeaders"].pop("PAYMENT-SIGNATURE"),
         "fail", "paid-request-headers"),
        ("unpaid-carries-payment-signature", lambda r: r["unpaidHeaders"].update(
            {"PAYMENT-SIGNATURE": r["paidHeaders"]["PAYMENT-SIGNATURE"]}), "fail",
         "paid-request-headers"),
        ("paid-changes-accept", lambda r: r["paidHeaders"].update({"Accept": "*/*"}),
         "fail", "paid-request-headers"),
        ("paid-not-object", lambda r: r.update({"paidHeaders": [["Accept", "application/json"]]}),
         "error", "request-headers"),
        ("unpaid-duplicate-name", lambda r: r["unpaidHeaders"].update({"accept": "application/json"}),
         "error", "request-headers"),
    ):
        add_case(vectors, f"request-headers-{name}", verdict, "XN-2/XN-6",
                 "the paid request differs from the unpaid one only by the v2 payment header, "
                 "and neither carries ambient credentials; checked before the challenge",
                 lambda v, change=change: change(v["runtime"]), reason=reason)

    def lower_case_payment_header(v):
        signature = v["runtime"]["paidHeaders"].pop("PAYMENT-SIGNATURE")
        v["runtime"]["paidHeaders"]["payment-signature"] = signature
    add_case(vectors, "request-headers-payment-signature-lower-case", "pass", "XN-6",
             "header names compare case-insensitively", lower_case_payment_header)

    # XN-6/§9.5.7.1: the PAYMENT-SIGNATURE value is the v2 PaymentPayload of
    # this authorization for the matched requirement. Envelope and unsigned
    # field defects fail before signing. Signature-form defects are recorded
    # after signing, with the payment disposition taken only from the ledger.
    def paid_value(value):
        def mutate(v):
            v["runtime"]["paidHeaders"]["PAYMENT-SIGNATURE"] = value
        return mutate

    def paid_payload(change, network=None):
        def mutate(v):
            if network == "solana":
                solana_exact(v)
            payload = payment_payload(v)
            change(payload)
            v["runtime"]["paidHeaders"]["PAYMENT-SIGNATURE"] = payment_signature(v, payload)
        return mutate

    def authorization(**members):
        return lambda payload: payload["payload"]["authorization"].update(members)
    for name, mutate, note in (
        ("not-base64", paid_value("garbage"), "the header value is not base64"),
        ("empty", paid_value(""), "an empty header value carries no payload"),
        ("empty-object", paid_value(base64.b64encode(b"{}").decode("ascii")),
         "an empty object is not a PaymentPayload"),
        ("version-only", paid_value(base64.b64encode(b'{"x402Version":2}').decode("ascii")),
         "a payload with no accepted requirement and no authorization is not the payment"),
        ("version-1", paid_payload(lambda payload: payload.update({"x402Version": 1})),
         "the paid payload names the selected version 2"),
        ("unknown-member", paid_payload(lambda payload: payload.update({"memo": "x"})),
         "the PaymentPayload is closed"),
        ("accepted-other-amount", paid_payload(
            lambda payload: payload["accepted"].update({"amount": "1250001"})),
         "accepted is the matched requirement as received"),
        ("resource-changed", paid_payload(
            lambda payload: payload["resource"].update({"url": "https://other.example/pay"})),
         "an echoed resource is the challenge's own"),
        ("extensions-carry-identifier", paid_payload(
            lambda payload: payload["extensions"]["payment-identifier"]["info"].update(
                {"id": "pay_" + "7" * 16})),
         "v0.8 defines no payment identifier, so the echoed extensions add none"),
        ("authorization-absent", paid_payload(lambda payload: payload["payload"].pop("authorization")),
         "the EIP-155 payload carries the EIP-3009 authorization"),
        ("signature-absent", paid_payload(lambda payload: payload["payload"].pop("signature")),
         "the EIP-155 payload carries the EIP-712 signature"),
        ("signature-short", paid_payload(lambda payload: payload["payload"].update(
            {"signature": EIP712_SIGNATURE[:-2]})),
         "an EIP-712 signature is 65 bytes"),
        ("other-recipient", paid_payload(authorization(to=OTHER_LETTERED_ADDRESS)),
         "the authorization pays the signed payTo"),
        ("other-payer", paid_payload(authorization(**{"from": OTHER_LETTERED_ADDRESS})),
         "the authorization is the derived payer's"),
        ("other-value", paid_payload(authorization(value="1250001")),
         "the authorization is for the exact amount"),
        ("value-not-decimal", paid_payload(authorization(value="0x1312d0")),
         "EIP-3009 values travel as decimal strings"),
        ("valid-before-not-retained", paid_payload(authorization(validBefore=str(VALID_BEFORE + 1))),
         "validBefore is the one the handler retains for XN-11"),
        ("valid-after-not-before", paid_payload(authorization(validAfter=str(VALID_BEFORE))),
         "the authorization's validity window is not empty"),
        ("nonce-not-derived", paid_payload(authorization(nonce="0x" + "ab" * 32)),
         "the EIP-3009 nonce is the SB-3 one derived from (jobId, phaseIndex)"),
        ("nonce-upper-case", paid_payload(lambda payload: payload["payload"]["authorization"].update(
            {"nonce": payload["payload"]["authorization"]["nonce"].upper().replace("0X", "0x")})),
         "DACS serialises the derived nonce as 0x plus lower-case hex"),
        ("solana-transaction-absent", paid_payload(
            lambda payload: payload["payload"].pop("transaction"), network="solana"),
         "the Solana payload carries the transaction"),
        ("solana-carries-evm-authorization", paid_payload(
            lambda payload: payload["payload"].update({"authorization": {}}), network="solana"),
         "the Solana payload is only the transaction"),
        ("solana-transaction-not-base64", paid_payload(
            lambda payload: payload["payload"].update({"transaction": "not base64!"}), network="solana"),
         "the Solana transaction is base64"),
        ("solana-transaction-empty", paid_payload(
            lambda payload: payload["payload"].update({"transaction": ""}), network="solana"),
         "the Solana transaction is a non-empty base64 string"),
        ("version-string", paid_payload(lambda payload: payload.update({"x402Version": "2"})),
         "x402Version is the integer 2, not a string"),
        ("payload-not-object", paid_payload(lambda payload: payload.update({"payload": EIP712_SIGNATURE})),
         "the binding's payload is an object"),
        ("from-not-20-bytes", paid_payload(authorization(**{"from": "0x1234"})),
         "the authorization's from is an XN-5 address, 0x plus 40 hex digits"),
        ("authorization-unknown-member", paid_payload(authorization(memo="x")),
         "the EIP-3009 authorization has exactly its six members"),
        ("authorization-without-nonce", paid_payload(
            lambda payload: payload["payload"]["authorization"].pop("nonce")),
         "the EIP-3009 authorization carries its nonce"),
        ("valid-after-not-decimal", paid_payload(authorization(validAfter="0x10")),
         "EIP-3009 times travel as unsigned decimal strings"),
        ("valid-before-not-decimal", paid_payload(authorization(validBefore=str(VALID_BEFORE) + ".0")),
         "EIP-3009 times travel as unsigned decimal strings"),
    ):
        after_signing = name in {"signature-absent", "signature-short"}
        add_case(vectors, f"paid-request-payload-{name}", "pass" if after_signing else "fail",
                 "XN-6/§9.5.7.1/XN-11", note, mutate, refresh=True,
                 authorization_submitted=after_signing, reason="paid-request-payload")
    for name, ledger, expected, reason in (
        ("ledger-unavailable", {"available": False}, "indeterminate", "independent-settlement-unavailable"),
        ("authorization-pending", {"available": True, "finalized": True, "nonceState": "unused"},
         "indeterminate", "authorization-unsettled"),
        ("authorization-cancelled", {"available": True, "finalized": True, "nonceState": "cancelled"},
         "fail", "terminal-non-settlement"),
    ):
        def signature_and_ledger(v, ledger=ledger):
            paid_payload(lambda payload: payload["payload"].update({"signature": EIP712_SIGNATURE[:-2]}))(v)
            v["ledger"] = copy.deepcopy(ledger)
        add_case(vectors, f"paid-request-signature-short-{name}", expected, "XN-6/XN-11",
                 "the handler records the post-signing signature defect and takes the payment "
                 "disposition only from reconciliation", signature_and_ledger, refresh=True,
                 authorization_submitted=True, reason=reason)
    add_case(vectors, "paid-request-payload-payer-upper-case", "pass", "XN-5/XN-6",
             "the authorization's addresses compare as 20-byte values",
             paid_payload(authorization(**{"from": "0x" + BUYER_ADDRESS[2:].upper()})), refresh=True)
    add_case(vectors, "paid-request-payload-without-optional-members", "pass", "XN-6",
             "resource and extensions are optional in the v2 PaymentPayload",
             paid_payload(lambda payload: (payload.pop("resource"), payload.pop("extensions"))),
             refresh=True)
    add_case(vectors, "verify-evidence-ignores-paid-request-payload", "pass", "XN-8",
             "a verifier judges the stored record, not the PAYMENT-SIGNATURE value the "
             "handler sent",
             paid_value("garbage"), refresh=True, operation="verify-evidence")
    add_case(vectors, "verify-evidence-judges-paid-request-headers", "fail", "XN-2/XN-6",
             "a verifier still applies the paid request's other gates: an ambient credential "
             "on it fails",
             lambda v: v["runtime"]["paidHeaders"].update({"Cookie": "session=1"}),
             operation="verify-evidence", reason="ambient-credential")
    # XN-4/XN-6: `accepted` is the matched requirement even when it is not the
    # first, matched with its addresses compared as XN-5 values and its
    # `extra` without the Solana hints.
    def matched_second(change, network=None):
        def mutate(v):
            if network == "solana":
                solana_exact(v)
            matched = v["http"]["paymentRequired"]["accepts"][0]
            change(v, matched)
            decoy = {**copy.deepcopy(matched), "amount": "1250001"}
            v["http"]["paymentRequired"]["accepts"] = [decoy, matched]
        return mutate

    def checksummed_pay_to(v, matched):
        v["agreement"]["terms"]["payoutBindings"][0]["payeeAddress"] = LETTERED_SELLER
        v["runtime"]["payee"]["payeeAddress"] = LETTERED_SELLER
        v["ledger"]["payTo"] = LETTERED_SELLER
        matched["payTo"] = eip55(LETTERED_SELLER)

    def blockhash_hint(v, matched):
        matched["extra"]["recentBlockhash"] = base58(hashlib.sha256(b"DACS #274 recent blockhash").digest())
    add_case(vectors, "paid-request-payload-accepted-second-checksummed-payto", "pass", "XN-4/XN-5/XN-6",
             "accepted is the second requirement, whose EIP-55 payTo matches the lower-case "
             "binding; the first differs in amount", matched_second(checksummed_pay_to), refresh=True)
    add_case(vectors, "paid-request-payload-accepted-second-solana-hint", "pass", "XN-4/XN-6",
             "accepted is the second requirement, which carries a recentBlockhash hint the signed "
             "extra omits; the first differs in amount",
             matched_second(blockhash_hint, network="solana"), refresh=True)

    # XN-11/§9.5.7.1: the EIP-3009 validBefore is retained as a safe integer
    # before the wallet signs, so a handler without one makes no wallet call,
    # with or without a later response.
    def retain_valid_before(value, *changes):
        def mutate(v):
            for change in changes:
                change(v)
            if value is None:
                del v["runtime"]["reconciliationState"]["validBefore"]
            else:
                v["runtime"]["reconciliationState"]["validBefore"] = value
        return mutate
    for name, mutate, note in (
        ("absent", retain_valid_before(None),
         "without a retained validBefore no later reconciliation can prove the expiry"),
        ("decimal-string", retain_valid_before(str(VALID_BEFORE)),
         "the retained validBefore is integer seconds, not the payload's decimal string"),
        ("above-safe-integer", retain_valid_before(2**53),
         "the retained validBefore is a safe integer"),
        ("absent-response-lost", retain_valid_before(None, response_lost()),
         "the response-loss path reconciles on the retained validBefore, so it is needed "
         "before signing"),
    ):
        add_case(vectors, f"execute-retained-valid-before-{name}", "error", "XN-11/§9.5.7.1", note,
                 mutate, refresh=True, reason="authorization-valid-before")

    # XN-5: the adapter's metadata binds the currency to the asset.
    def relabel_currency(v):
        for ref in signed_selection_refs(v):
            ref["parameters"]["selection"]["currency"] = "BTC"
        v["agreement"]["terms"]["price"]["currency"] = "BTC"
        v["evidence"]["paymentAmount"]["currency"] = "BTC"
    add_case(vectors, "currency-relabelled-over-same-asset", "fail", "XN-5/PC-5",
             "price and selection relabelled BTC over the unchanged USDC asset: the adapter's "
             "trusted metadata names USDC, so it rejects before authorization",
             relabel_currency, reason="asset-currency")
    add_case(vectors, "asset-metadata-without-currency", "fail", "XN-5",
             "an adapter that cannot name the asset's currency cannot bind it",
             lambda v: v["capability"]["assetMetadata"].pop("currency"), reason="asset-currency")

    # XN-1/XN-11: retry runs the same definition and reference gates and keeps
    # the session's routing.
    retry = {"operation": "retry", "authorization_submitted": True}
    add_case(vectors, "retry-definition-other-revision", "fail", "XN-1/XN-11",
             "a retry applies the revision the signed reference pins; revision 2 is not it",
             lambda v: v["railDefinition"].update({"railVersion": 2}), reason="rail-version", **retry)
    add_case(vectors, "retry-definition-legacy-arm", "error", "XN-1/XN-10/XN-11",
             "a retry cannot reconcile under the legacy x402:default definition",
             lambda v: v.update({"railDefinition": legacy_rail()}), reason="definition", **retry)
    add_case(vectors, "retry-definition-malformed", "error", "XN-1/XN-11",
             "a retry re-validates the pinned protocol definition",
             lambda v: v["railDefinition"].update({"providers": ["facilitator.example"]}),
             reason="definition", **retry)
    add_case(vectors, "retry-facilitator-switched", "fail", "XN-3/XN-11",
             "the facilitator is retained local routing; a retry cannot switch it",
             lambda v: v["runtime"].update({"facilitator": "https://facilitator-b.example"}),
             reason="routing-switch", **retry)
    add_case(vectors, "retry-retained-facilitator-absent", "fail", "XN-11",
             "a retained state without the session's facilitator cannot show the routing is "
             "unchanged", lambda v: v["runtime"]["reconciliationState"].pop("facilitator"),
             reason="routing-switch", **retry)
    add_case(vectors, "retry-static-arm-ref", "error", "XN-2/XN-11",
             "a retry refuses a malformed reference before reconciling",
             lambda v: [ref.pop("parameters") for ref in signed_selection_refs(v)],
             reason="rail-ref-shape", **retry)

    # §9.5.7.1: only the three mapped Solana clusters and EIP-155 have an
    # event-key form, whatever the local capability claims.
    private_cluster = "solana:8E9rvCKLFQia2Y35HXjjpWzj8weVo44K"
    add_case(vectors, "solana-unmapped-cluster-unsupported", "fail", "XN-3/XN-9/SB-1",
             "a Solana CAIP-2 reference outside the pinned mapping has no event-key form, so it "
             "is unsupported before authorization even when the local capability names it",
             lambda v: solana_exact(v, private_cluster, "devnet"), refresh=True,
             reason="x402-capability-unsupported")

    # XN-5: the paying claim names the selected network, even when the same
    # key derives the same address on another chain.
    def other_chain_claim(v):
        bundle = buyer_bundle("eip155:1", BUYER_ADDRESS)
        bundle_hash = digest(unsigned(bundle, "presentation"))
        v["buyerBundle"] = bundle
        v["agreement"]["parties"][0]["bundleHash"] = bundle_hash
        v["runtime"]["payer"].update({
            "bundleHash": bundle_hash, "payingKey": payment_claim("eip155:1", BUYER_ADDRESS),
        })
    add_case(vectors, "paying-claim-names-another-chain", "fail", "XN-5",
             "a cci-xm:evm:1 claim does not control the payment on eip155:8453, though its key "
             "derives the same address", other_chain_claim, reason="payer-control")

    # A new session may start on the protocol rail (XN-10's positive twin).
    add_case(vectors, "new-session-on-protocol-rail", "pass", "XN-10",
             "a v0.8 orchestrator may start a new session on x402:protocol",
             operation="new-session")
    for availability in ("disabled", "failed"):
        add_case(vectors, f"new-session-on-{availability}-protocol-rail", "fail", "RAV-R2",
                 f"no new session starts on an x402:protocol definition that is {availability}",
                 lambda v, availability=availability: v["railDefinition"].update(
                     {"availability": availability}),
                 operation="new-session", reason="rail-availability")
    # §9.3: availability is one of RailAvailability's seven values, checked
    # with the rest of the signed definition before RAV-R2 reads it.
    for name, availability in (("outside-union", "unknown"), ("not-string", ["disabled"])):
        add_case(vectors, f"new-session-availability-{name}", "error", "XN-1/RAV-R2",
                 "a signed definition whose availability is not a RailAvailability value is "
                 "malformed, so no session starts on it",
                 lambda v, availability=availability: v["railDefinition"].update(
                     {"availability": availability}),
                 operation="new-session", reason="definition")


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
    if "expectedErrorClass" in case:
        compact["expectedErrorClass"] = case["expectedErrorClass"]
    return compact


def build() -> dict:
    fixtures = {"v2": make_base(2)}
    vectors = [compact_case(case, fixtures) for case in build_vectors()]
    return {
        "set": "x402-negotiated-protocol-v0.8",
        "spec": "§8.5.2 / §9.3 / §9.4.3 XN-1 / §9.5.1 PB-1, PB-2 / §9.5.7 XN-2..XN-11, X402-1..X402-4, §9.5.7.1 / §9.5.8 SB-1 / §9.7.2 FR-2",
        "upstream": {
            "repository": "x402-foundation/x402",
            "commit": "230e6a9a7eebce22c911a0687d6f4e6d1ac019f7",
            "v2Types": "typescript/packages/core/src/types/payments.ts",
            "v2Protocol": "specs/x402-specification-v2.md",
            "v2HttpTransport": "specs/transports-v2/http.md",
            "exactEvmScheme": "specs/schemes/exact/scheme_exact_evm.md",
            "exactSvmScheme": "specs/schemes/exact/scheme_exact_svm.md",
            "paymentIdentifierExtension": "specs/extensions/payment_identifier.md",
            # The second pinned `payment-identifier` schema (§9.5.7.1).
            "paymentIdentifierSdkSchemas": [
                "typescript/packages/extensions/src/payment-identifier/schema.ts",
                "python/x402/extensions/payment_identifier/schema.py",
                "go/extensions/paymentidentifier/schema.go",
            ],
            # X402-3's v1 network table is §11.1 of the v1 specification, pinned
            # at the x402-receipt-hash corpus's own upstream commit.
            "v1Protocol": {
                "commit": "22a7677f829584073638d2e5b9898e1f19089b61",
                "path": "specs/x402-specification-v1.md",
            },
        },
        "bindingProfile": "dacs-x402-exact:v1 (DACS-4 §9.5.7.1)",
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
