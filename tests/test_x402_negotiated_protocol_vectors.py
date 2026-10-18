import base64
import copy
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import quote, unquote, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import idna
from scripts.evm_crypto import evm_address
from scripts.jcs import canonicalize as jcs_canonicalize
from scripts.raw_json_profile import RawJsonProfileError, loads as admit_raw_json
from scripts.sb3_binding import binding_branch
from scripts.solana_authorization import TOKEN_PROGRAMS, SignerMismatch, payment_instruction_defect
from scripts.solana_authorization import authorization_identity as solana_identity


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance/vectors/security/x402-negotiated-protocol-v0.8.json"
GENERATOR = ROOT / "scripts/generate_x402_negotiated_protocol_vectors.py"
SAFE_INT = 2**53 - 1
HEX_32 = re.compile(r"^[0-9a-f]{64}$")
HTTP_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Z-]+$")
CAIP2 = re.compile(r"^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$")
CD1 = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$")
# SB-1: `chainId` > 0 and `logIndex` are also safe integers (checked after the
# match); the hash is exactly 64 lower-case hex digits.
EVM_EVENT = re.compile(r"^evm:([1-9][0-9]*):([0-9a-f]{64}):(0|[1-9][0-9]*)$")
# A received EIP-155 response transaction: at most one 0x/0X prefix, then
# exactly 32 bytes of hex in either case (the SB-1 legacy-spelling collapse).
EVM_RESPONSE_TRANSACTION = re.compile(r"^(?:0[xX])?([0-9a-fA-F]{64})$")
# XN-5: an EIP-155 address is `0x` plus 20 bytes of hex in either letter case.
EVM_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
# XN-2: ERC-20 decimals() and an SPL mint's decimals are both uint8.
ASSET_DECIMALS_MAX = 255
# XN-5 overflow ceiling per exact binding, keyed by CAIP-2 namespace: EIP-3009
# value and ERC-20 amounts are uint256; SPL Token amounts are u64. These are the
# only namespaces `dacs-x402-exact:v1` binds (§9.5.7.1).
ATOMIC_AMOUNT_MAX = {"eip155": 2**256 - 1, "solana": 2**64 - 1}
# XN-6 and §9.5.7.1: the `extra` members `dacs-x402-exact:v1` defines, from the
# pinned upstream exact scheme definitions (x402-foundation/x402@230e6a9a,
# specs/schemes/exact/scheme_exact_evm.md and scheme_exact_svm.md) and the two
# protocol-reserved keys of specs/x402-specification-v2.md §6.1, keyed like the
# ceiling. On EIP-155, `assetTransferMethod` selects the authorization form, and
# `name` and `version` are the EIP-712 domain of the token, whose verifying
# contract is the `asset` itself. On Solana, `feePayer` pays the transaction
# fee and `memo` fixes the Memo instruction's data; the mint is the `asset`.
# `recentBlockhash` and `lastValidBlockHeight` are per-challenge construction
# hints that do not bind the transaction. A received member these tables do
# not name is unclassified.
ADAPTER_EXTRA_MEMBERS = {
    "eip155": frozenset({"assetTransferMethod", "paymentFlow", "name", "version"}),
    "solana": frozenset({
        "assetTransferMethod", "paymentFlow", "feePayer", "memo",
        "recentBlockhash", "lastValidBlockHeight",
    }),
}
# §9.5.7.1: XN-4 and XN-6 ignore the Solana hints; the XN-7 challenge hash
# still covers them.
SOLANA_HINT_MEMBERS = frozenset({"recentBlockhash", "lastValidBlockHeight"})
SOLANA_MEMO_MAX_BYTES = 256
# The v2 `payment-identifier` extension asks the payer to identify the payment
# in the paid request. v0.8 defines no identifier, so only its optional form is
# supported, and that form is descriptive (§9.5.7.1).
DEFINED_EXTENSIONS = frozenset({"payment-identifier"})
# §9.5.7.1: the advertisement's `schema` is one of the two pinned upstream
# forms, and `info` satisfies it: the example of
# specs/extensions/payment_identifier.md, or the schema the pinned reference
# SDKs emit (typescript/packages/extensions/src/payment-identifier/schema.ts,
# python/x402/extensions/payment_identifier/schema.py and
# go/extensions/paymentidentifier/schema.go), which adds the `id` pattern.
PAYMENT_IDENTIFIER_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "required": {"type": "boolean"},
        "id": {"type": "string", "minLength": 16, "maxLength": 128},
    },
    "required": ["required"],
}
PAYMENT_IDENTIFIER_SDK_SCHEMA = copy.deepcopy(PAYMENT_IDENTIFIER_SCHEMA)
PAYMENT_IDENTIFIER_SDK_SCHEMA["properties"]["id"]["pattern"] = "^[a-zA-Z0-9_-]+$"
PAYMENT_IDENTIFIER_SCHEMAS = frozenset(
    jcs_canonicalize(schema) for schema in (PAYMENT_IDENTIFIER_SCHEMA, PAYMENT_IDENTIFIER_SDK_SCHEMA)
)
# payment_identifier.md's `id` format: 16 to 128 alphanumerics, hyphens or
# underscores, the rule the SDK pattern states.
PAYMENT_IDENTIFIER_ID = re.compile(r"[A-Za-z0-9_-]{16,128}")
# XN-6/§9.5.7.1: the v2 PaymentPayload the paid request's PAYMENT-SIGNATURE
# carries (x402 v2 §5.2), and the EIP-3009 authorization of the EIP-155 payload.
PAYMENT_PAYLOAD_REQUIRED = frozenset({"x402Version", "accepted", "payload"})
PAYMENT_PAYLOAD_FIELDS = PAYMENT_PAYLOAD_REQUIRED | {"resource", "extensions"}
EIP3009_AUTHORIZATION_FIELDS = frozenset({"from", "to", "value", "validAfter", "validBefore", "nonce"})
EVM_SIGNATURE = re.compile(r"^0x[0-9a-fA-F]{130}$")
UINT_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)$")
# XN-9: the v0.8 EIP-155 `exact` binding authorizes only through EIP-3009, the
# form an absent `assetTransferMethod` selects. Upstream's Permit2 witness
# cannot carry the SB-3 job binding, and `erc7710` has no v0.8 binding.
EIP155_TRANSFER_METHODS = frozenset({"eip3009"})
# x402 v2 §6.1: `authorization` is the only flow `exact` defines here; it may
# be omitted or explicit.
PAYMENT_FLOWS = frozenset({"authorization"})
SOLANA_EVENT = re.compile(
    r"^solana:(mainnet|devnet|testnet):([1-9A-HJ-NP-Za-km-z]+):(0|[1-9][0-9]*)$"
)
# §9.5.7.1: the closed mapping from a CAIP-2 Solana reference (the cluster's
# genesis-hash prefix) to DACS-4 §9.3's `mainnet | devnet | testnet`. Any other
# Solana reference has no v0.8 event-key form, so no adapter supports it.
SOLANA_NETWORK_CLUSTERS = {
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": "mainnet",
    "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": "devnet",
    "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z": "testnet",
}
# XN-9/SB-3: the pinned x402:protocol definition's `dacs-x402-exact:v1` binding
# authorizes an EIP-155 payment only through EIP-3009, which declares an SB-3
# job binding, so it is mandatory on those networks whatever the observed
# event's `authorization` says. Binding evidence uses the sb3-binding-required
# set's closed model and classifier (scripts/sb3_binding).
SB3_BINDING_NAMESPACES = frozenset({"eip155"})
# XN-11: with no payment event for the authorization identity, the finalized
# ledger proves an EIP-3009 non-settlement only by a cancelled nonce, or by an
# unused nonce at a finalized block whose timestamp is at least the retained
# `validBefore` (EIP-3009 requires `block.timestamp < validBefore`).
EIP3009_NONCE_STATES = frozenset({"unused", "used", "cancelled"})
# DACS-4 §9.5.7 failure modes (`x402:protocol`): the handler's PC-4 errorClass
# for each result reason the list names. An unsupported or undefined member is
# `permanent` like unsupported capability, never the seller's fault.
FAILURE_MODE_ERROR_CLASSES = {
    "unpaid-request-transient": "transient",
    "not-payment-required": "counterparty",
    "payment-required-header": "counterparty",
    "payment-required-json": "counterparty",
    "payment-required-version": "counterparty",
    "payment-required-shape": "counterparty",
    "accepts-shape": "counterparty",
    "extension-presence": "counterparty",
    "extensions": "counterparty",
    "challenge-match": "counterparty",
    "extra-member-value": "counterparty",
    "extension-value": "counterparty",
    "x402-capability-unsupported": "permanent",
    "unsupported-transfer-method": "permanent",
    "unsupported-payment-flow": "permanent",
    "unsupported-action-extension": "permanent",
    "unclassified-extra-member": "permanent",
    "unclassified-extension": "permanent",
    "terminal-non-settlement": "permanent",
    "ledger-event": "permanent",
    # PC-5: a price currency that does not resolve to the selected asset.
    "currency": "permanent",
    "asset-currency": "permanent",
    "paid-request-payload": "permanent",
}
# X402-3: the registered v1 legacy-network mapping, the supported-network table
# of the pinned v1 specification (x402-foundation/x402@22a7677f,
# specs/x402-specification-v1.md §11.1, the x402-receipt-hash corpus's pin).
X402_V1_NETWORK_CHAIN_IDS = {
    "base-sepolia": 84532,
    "base": 8453,
    "avalanche-fuji": 43113,
    "avalanche": 43114,
}
# XN-6: the one header the paid request adds, and the ambient credentials
# neither request carries (XN-2). Header names compare case-insensitively.
PAYMENT_SIGNATURE_HEADER = "payment-signature"
AMBIENT_CREDENTIAL_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization"})
PROTOCOL_REQUIRED = {
    "railVersion", "railId", "railType", "phaseHandler", "resolution",
    "availability", "governance", "signature",
}
PROTOCOL_FORBIDDEN = {
    "asset", "network", "parameters", "resourceBaseUrl", "provider",
    "providers", "facilitator", "facilitatorEndpoint", "apiKey", "wallet", "rpc",
}
# DACS-4 §9.3: the closed `RailAvailability` union (§9.4.4).
RAIL_AVAILABILITY = frozenset({
    "live", "operator_gated", "closed_data", "bilateral", "mocked", "disabled", "failed",
})
REF_FIELDS = {"railId", "railVersion", "parameters"}
PARAM_FIELDS = {"request", "selection", "paymentRequiredExtensions"}
REQUEST_FIELDS = {"method", "url", "bodyHash"}
SELECTION_FIELDS = {
    "x402Version", "scheme", "network", "asset", "assetDecimals",
    "currency", "maxTimeoutSeconds", "extra",
}
EVIDENCE_REF_FIELDS = {
    "kind", "httpResource", "paymentRequiredHash", "paymentReceiptHash",
    "x402Version", "settlementNetwork", "settlementTransaction", "settlementEvent",
}


def digest(value):
    return hashlib.sha256(jcs_canonicalize(value).encode("utf-8")).hexdigest()


def b64u_decode(value):
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("non-canonical base64url")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ValueError("non-canonical base64url")
    return raw


def verify_signature(public, domain, body, value):
    try:
        Ed25519PublicKey.from_public_bytes(b64u_decode(public)).verify(
            b64u_decode(value), (domain + digest(body)).encode("ascii")
        )
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False


def base58(raw):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded
    zeroes = len(raw) - len(raw.lstrip(b"\x00"))
    # Each leading zero byte is one "1"; an all-zero input is nothing else.
    return "1" * zeroes + encoded


def base58_decoded_length(value):
    """The byte length a base58 string decodes to, or None if it is not base58."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    if not isinstance(value, str) or not value or any(char not in alphabet for char in value):
        return None
    number = 0
    for char in value:
        number = number * 58 + alphabet.index(char)
    zeroes = len(value) - len(value.lstrip("1"))
    return zeroes + (number.bit_length() + 7) // 8


def buyer_bundle_scope(bundle):
    if not isinstance(bundle, dict):
        return None
    return {name: value for name, value in bundle.items() if name != "presentation"}


def payment_claim_parts(claim):
    if not isinstance(claim, str):
        return None
    bare = claim.split("?", 1)[0]
    parts = bare.split(":", 3)
    if len(parts) != 4 or parts[0] != "cci-xm" or not parts[3]:
        return None
    return parts[1], parts[2], parts[3]


def verify_buyer_bundle_presentation(v):
    bundle = v.get("buyerBundle")
    scope = buyer_bundle_scope(bundle)
    if not isinstance(scope, dict) or bundle.get("bundleVersion") != "1":
        return False
    claims = bundle.get("claims")
    presentation = bundle.get("presentation")
    if not isinstance(claims, list) or not claims or not isinstance(presentation, dict):
        return False
    refs = [claim.get("ref") for claim in claims if isinstance(claim, dict)]
    if len(refs) != len(claims) or bundle.get("presentedBy") not in refs:
        return False
    signatures = presentation.get("signatures")
    if presentation.get("kind") != "per-claim" or not isinstance(signatures, list):
        return False
    by_ref = {}
    for envelope in signatures:
        if not isinstance(envelope, dict) or set(envelope) != {"ref", "signature"}:
            return False
        if envelope["ref"] in by_ref:
            return False
        by_ref[envelope["ref"]] = envelope["signature"]
    if set(by_ref) != set(refs):
        return False
    payload = ("dacs-bundle-presentation:v1:" + digest(scope)).encode("ascii")
    keys = v.get("keys", {})
    for claim in claims:
        ref = claim["ref"]
        metadata = claim.get("metadata", {})
        try:
            signature = b64u_decode(by_ref[ref])
            if ref == bundle.get("presentedBy"):
                Ed25519PublicKey.from_public_bytes(b64u_decode(keys.get("buyer"))).verify(
                    signature, payload
                )
            elif metadata.get("algorithm") == "ecdsa-secp256k1":
                public = bytes.fromhex(metadata.get("publicKey"))
                ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256K1(), public
                ).verify(signature, payload, ec.ECDSA(hashes.SHA256()))
            elif metadata.get("algorithm") == "ed25519":
                public = b64u_decode(metadata.get("publicKey"))
                Ed25519PublicKey.from_public_bytes(public).verify(signature, payload)
            else:
                return False
        except (InvalidSignature, TypeError, ValueError):
            return False
    return True


def buyer_payment_control(v, buyer, selection):
    bundle = v.get("buyerBundle", {})
    runtime = v.get("runtime", {})
    payer = runtime.get("payer", {})
    scope = buyer_bundle_scope(bundle)
    if not isinstance(scope, dict):
        return False
    bundle_hash = digest(scope)
    if (
        buyer.get("bundleHash") != bundle_hash
        or payer.get("bundleHash") != bundle_hash
        or bundle.get("presentedBy") != buyer.get("primaryClaim")
        or bundle.get("sessionNonce") != runtime.get("issuedBuyerSessionNonce")
    ):
        return False
    claims = [
        claim for claim in bundle.get("claims", [])
        if isinstance(claim, dict) and claim.get("ref") == payer.get("payingKey")
    ]
    if len(claims) != 1:
        return False
    parts = payment_claim_parts(payer.get("payingKey"))
    if parts is None:
        return False
    family, subchain, claimed_address = parts
    metadata = claims[0].get("metadata", {})
    network = selection.get("network")
    try:
        if network == f"eip155:{subchain}" and family == "evm":
            public = bytes.fromhex(metadata.get("publicKey"))
            derived_address = evm_address(public)
            if metadata.get("algorithm") != "ecdsa-secp256k1":
                return False
        elif network == f"solana:{subchain}" and family == "solana":
            public = b64u_decode(metadata.get("publicKey"))
            derived_address = base58(public)
            if metadata.get("algorithm") != "ed25519":
                return False
        else:
            return False
    except (TypeError, ValueError):
        return False
    # XN-5: the claimed, derived and authorization payer compare in the adapter
    # form. All three are taken to it first, so a malformed one raises
    # ValueError (the caller's `error`) whatever the others hold.
    claimed, derived, authorization = (
        adapter_address(network, address)
        for address in (claimed_address, derived_address, payer.get("paymentAddress"))
    )
    return claimed == derived == authorization


def verify_record_signature(v):
    """The stored x402-protocol success record carries the orchestrator's signature."""
    evidence = v.get("evidence")
    if not isinstance(evidence, dict):
        return False
    signature = evidence.get("signature", {})
    return verify_signature(
        v.get("keys", {}).get("orchestrator"), "dacs-evidence:v1:",
        {k: value for k, value in evidence.items() if k != "signature"},
        signature.get("value"),
    )


def verify_artifact_signatures(v):
    if not verify_buyer_bundle_presentation(v):
        return False
    keys = v.get("keys", {})
    rail = v.get("railDefinition", {})
    signature = rail.get("signature", {})
    if not verify_signature(
        keys.get("steward"), "dacs-rail:v1:",
        {k: value for k, value in rail.items() if k != "signature"},
        signature.get("value"),
    ):
        return False

    listing = v.get("listing", {})
    signature = listing.get("signature", {})
    if not verify_signature(
        keys.get("seller"), "dacs-listing:v1:",
        {k: value for k, value in listing.items() if k != "signature"},
        signature.get("value"),
    ):
        return False

    agreement = v.get("agreement", {})
    if agreement.get("payeeBoundAgreementVersion") != "1":
        return False
    body = {k: value for k, value in agreement.items() if k != "signatures"}
    signatures = {s.get("party"): s for s in agreement.get("signatures", [])}
    roles = {party.get("role"): party.get("primaryClaim") for party in agreement.get("parties", [])}
    for role in ("buyer", "seller"):
        signature = signatures.get(roles.get(role), {})
        if not verify_signature(
            keys.get(role), "dacs-payee-bound-agreement:v1:", body,
            signature.get("value"),
        ):
            return False

    # Evidence may not exist yet (XN-11 response loss); when present it is signed.
    if "evidence" not in v:
        return True
    return verify_record_signature(v)


def is_safe_positive(value):
    return type(value) is int and 0 < value <= SAFE_INT


def is_safe_nonnegative(value):
    return type(value) is int and 0 <= value <= SAFE_INT


def validate_protocol_definition(rail):
    if not isinstance(rail, dict):
        return "error"
    if not PROTOCOL_REQUIRED.issubset(rail) or PROTOCOL_FORBIDDEN.intersection(rail):
        return "error"
    if set(rail) != PROTOCOL_REQUIRED:
        return "error"
    if (
        rail.get("railId") != "x402:protocol"
        or rail.get("railType") != "x402"
        or rail.get("phaseHandler") != "pay-x402"
        or rail.get("resolution") != {"kind": "x402-payment-required"}
        or not is_safe_positive(rail.get("railVersion"))
        or not (isinstance(rail.get("availability"), str) and rail["availability"] in RAIL_AVAILABILITY)
    ):
        return "error"
    return "pass"


def validate_ref(ref):
    if not isinstance(ref, dict) or set(ref) != REF_FIELDS:
        return "error"
    if ref.get("railId") != "x402:protocol" or not is_safe_positive(ref.get("railVersion")):
        return "error"
    parameters = ref.get("parameters")
    if not isinstance(parameters, dict) or not set(parameters).issubset(PARAM_FIELDS):
        return "error"
    if not {"request", "selection"}.issubset(parameters):
        return "error"
    request = parameters.get("request")
    if not isinstance(request, dict) or not set(request).issubset(REQUEST_FIELDS):
        return "error"
    if not {"method", "url"}.issubset(request):
        return "error"
    method = request.get("method")
    if not isinstance(method, str) or not HTTP_TOKEN.fullmatch(method):
        return "error"
    if not request_url_syntax_ok(request.get("url")):
        return "error"
    try:
        parsed = urlsplit(request.get("url"))
    except (TypeError, ValueError):
        return "error"
    if parsed.scheme != "https" or not parsed.hostname:
        return "error"
    if "bodyHash" in request and not (
        isinstance(request["bodyHash"], str) and HEX_32.fullmatch(request["bodyHash"])
    ):
        return "error"

    selection = parameters.get("selection")
    if not isinstance(selection, dict) or set(selection) != SELECTION_FIELDS:
        return "error"
    # XN-2: v0.8 binds only x402 version 2; another positive version is a
    # well-typed value outside this profile, so it is malformed here too.
    if not is_safe_positive(selection.get("x402Version")) or selection["x402Version"] != 2:
        return "error"
    if not is_safe_positive(selection.get("maxTimeoutSeconds")):
        return "error"
    if not is_safe_nonnegative(selection.get("assetDecimals")) or (
        selection["assetDecimals"] > ASSET_DECIMALS_MAX
    ):
        return "error"
    for field in ("scheme", "network", "asset", "currency"):
        if not isinstance(selection.get(field), str) or not selection[field]:
            return "error"
    if not CAIP2.fullmatch(selection["network"]):
        return "error"
    if not isinstance(selection.get("extra"), dict):
        return "error"
    if "paymentRequiredExtensions" in parameters and not isinstance(
        parameters["paymentRequiredExtensions"], dict
    ):
        return "error"
    try:
        jcs_canonicalize(selection["extra"])
        if "paymentRequiredExtensions" in parameters:
            jcs_canonicalize(parameters["paymentRequiredExtensions"])
    except (TypeError, ValueError):
        return "error"
    return "pass"


# DACS-1 §6.3.6 names the classes a server-side probe MUST reject:
#   "loopback, private, link-local, shared-address, unspecified, multicast,
#    reserved, and cloud-provider metadata destinations, including equivalent
#    IPv4-mapped IPv6 spellings"
# One branch per named class, so the gate can be read against that sentence.
#
# Why not ``is_global``: it is well-defined — CPython derives it from IANA's
# global-reachability registries — but it answers a different question than §6.3.6 asks.
# It admits multicast (``224.0.0.1``, ``239.255.255.250`` and ``ff02::1`` are all
# ``is_global == True``), because globally-reachable and safe-to-fetch are not the same
# property. An aggregate predicate could in principle implement the union of these classes;
# ``is_global`` is simply not that predicate, so the evaluator tracks the spec's sentence
# instead of borrowing a near-neighbour.
_SHARED_ADDRESS_V4 = ipaddress.ip_network("100.64.0.0/10")   # RFC 6598 CGNAT

# "cloud-provider metadata destinations" is an independently named required class in §6.3.6.
# The spec names the CLASS; it lists no example addresses, so the endpoints below are ones we
# selected. Stated without inference, because the distinction is easy to overclaim:
#
#   - §6.3.6 names metadata as a required class, and this branch implements it as a distinct
#     rule rather than leaving it to be caught by accident.
#   - Of the addresses listed here for conformance, EVERY one also falls in another rejected
#     class (169.254.169.254 link-local, 100.100.100.200 shared-address, fd00:ec2::254
#     private). So no conformance rejection currently depends on this branch alone, and this
#     branch's presence is not what makes those particular addresses reject.
#   - It would be the only thing rejecting a metadata endpoint that falls outside every
#     generic range. 168.63.129.16 is exactly such an address — and it is excluded from
#     conformance below as hardening, so that case is not claimed either.
#
# 168.63.129.16 (Azure WireServer) is included as defence-in-depth, not as conformance:
# Microsoft documents it as a platform endpoint distinct from IMDS, so §6.3.6 does not clearly
# compel its rejection. It is deliberately kept out of the normative named-class table and out
# of the conformance vectors; see the hardening test instead.
#
# On 168.63.129.16 specifically: CPython reports is_global == True for it, because is_global
# follows IANA's global-reachability registries and that address sits in a globally-allocated
# block. Microsoft nonetheless documents it as an Azure-internal platform endpoint, distinct
# from IMDS. The property that matters here is simply that no generic predicate rejects it.
# Rejecting it is defence-in-depth beyond what §6.3.6 plainly compels — same trust boundary
# and SSRF exposure — and it is deliberately NOT asserted as a conformance vector: an
# evaluator that rejects more than the standard requires is security-conservative but can
# refuse inputs the standard permits, which is an interoperability cost, not a free win.
#
# 169.254.169.253 is deliberately NOT listed: it is AWS's Route 53 VPC DNS resolver, not a
# metadata service (AWS IMDS is .254). It is link-local and rejected by that branch.
_METADATA_ADDRESSES = frozenset(
    ipaddress.ip_address(a) for a in (
        "169.254.169.254",   # AWS / GCP / Azure IMDS / Oracle / OpenStack / DigitalOcean
        "168.63.129.16",     # Azure WireServer — no generic predicate matches it
        "100.100.100.200",   # Alibaba Cloud metadata
        "fd00:ec2::254",     # AWS IPv6 IMDS
    )
)


def _non_public_class(address):
    """Name of the §6.3.6 class this address falls in, or None if it is public.

    Order matters: metadata is tested before the generic classes it partially overlaps, so a
    metadata address is reported as metadata rather than as whatever else it happens to be.
    """
    if address in _METADATA_ADDRESSES:
        return "cloud-metadata"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_multicast:
        return "multicast"
    if address.is_unspecified:
        return "unspecified"
    if address.is_reserved:
        return "reserved"            # includes 240/4 and 255.255.255.255
    if address.version == 4 and address in _SHARED_ADDRESS_V4:
        return "shared-address"
    if address.is_private:
        return "private"             # includes IPv6 unique-local fc00::/7
    return None


# XN-2: IPv6 forms that embed an IPv4 address, by explicit prefix. CPython's
# is_private / is_reserved tables cover some of these prefixes and differ
# between releases, so each form is unwrapped here and judged by the IPv4
# address it carries. Teredo carries two: the server, and the client with
# every bit inverted.
_IPV4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
_IPV4_TRANSLATED = ipaddress.ip_network("::ffff:0:0:0/96")   # RFC 2765 SIIT
_IPV4_COMPATIBLE = ipaddress.ip_network("::/96")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL_USE = ipaddress.ip_network("64:ff9b:1::/48")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")
_TEREDO = ipaddress.ip_network("2001::/32")
# ISATAP (RFC 5214) carries an IPv4 address in the interface identifier, after
# any /64 prefix: 0000:5efe, or 0200:5efe with the universal bit set.
_ISATAP_IDENTIFIERS = frozenset({0x00005EFE, 0x02005EFE})


def _embedded_ipv4(address):
    """The form name and IPv4 addresses an IPv6 address embeds, or None."""
    if address.version != 6:
        return None
    value = int(address)
    low = ipaddress.IPv4Address(value & 0xFFFFFFFF)
    if address in _IPV4_MAPPED:
        return "ipv4-mapped", (low,)
    if address in _IPV4_TRANSLATED:
        return "ipv4-translated", (low,)
    if address in _NAT64:
        return "nat64", (low,)
    # :: and ::1 are the unspecified and loopback addresses, not IPv4-compatible.
    if address in _IPV4_COMPATIBLE and value > 1:
        return "ipv4-compatible", (low,)
    if address in _SIX_TO_FOUR:
        return "6to4", (ipaddress.IPv4Address((value >> 80) & 0xFFFFFFFF),)
    if address in _TEREDO:
        server = ipaddress.IPv4Address((value >> 64) & 0xFFFFFFFF)
        return "teredo", (server, ipaddress.IPv4Address(~value & 0xFFFFFFFF))
    return None


def _isatap_ipv4(address):
    """("isatap", (IPv4,)) when the interface identifier is an ISATAP one, or None."""
    if address.version != 6 or (int(address) >> 32) & 0xFFFFFFFF not in _ISATAP_IDENTIFIERS:
        return None
    return "isatap", (ipaddress.IPv4Address(int(address) & 0xFFFFFFFF),)


def _target_class(address):
    """Name of the non-public class of a literal target, or None if it is public.

    An embedded-IPv4 form is not public when any IPv4 address it carries is
    not, and is reported as `<form>:<class>`. The local-use NAT64 prefix does
    not fix where the IPv4 address sits, and it is never public. An address in
    no prefix form is judged as itself; an ISATAP interface identifier, which
    can follow any prefix, adds the IPv4 address it carries.
    """
    if address.version == 6 and address in _NAT64_LOCAL_USE:
        return "nat64-local-use"
    embedded = _embedded_ipv4(address)
    if embedded is None:
        named = _non_public_class(address)
        if named is not None:
            return named
        forms = []
    else:
        forms = [embedded]
    isatap = _isatap_ipv4(address)
    if isatap is not None:
        forms.append(isatap)
    for form, carried in forms:
        for ipv4 in carried:
            named = _non_public_class(ipv4)
            if named is not None:
                return f"{form}:{named}"
    return None


def _is_localhost_name(hostname):
    """`localhost`, any name under `.localhost` (RFC 6761), or `localhost.localdomain`."""
    name = hostname.lower().rstrip(".")
    return name in ("localhost", "localhost.localdomain") or name.endswith(".localhost")


# At least one representative for every named class — representative samples, not exhaustive
# coverage of each class's address space. Asserted on the CLASS NAME rather than on the
# rejection boolean, because rejection alone is not deletion-sensitive: 127.0.0.1,
# 169.254.1.1, 0.0.0.0 and 240.0.0.1 are all is_private in CPython, so deleting the loopback,
# link-local, unspecified or reserved branch would still reject them via the final is_private
# fallback and every vector would stay green. §6.3.6 requires REJECTION; asserting the class
# name is an internal deletion-sensitivity technique for this suite, not a protocol
# requirement. Precisely what it catches: a deleted branch, or a reorder that changes
# PRECEDENCE between overlapping branches. It does not catch a reorder between branches
# whose inputs never overlap, since that cannot change any verdict.
NON_PUBLIC_CLASS_CASES = (
    ("169.254.169.254", "cloud-metadata"),
    ("100.100.100.200", "cloud-metadata"),
    ("fd00:ec2::254", "cloud-metadata"),
    ("127.0.0.1", "loopback"),
    ("::1", "loopback"),
    ("169.254.1.1", "link-local"),
    ("224.0.0.1", "multicast"),
    ("239.255.255.250", "multicast"),
    ("ff02::1", "multicast"),
    ("0.0.0.0", "unspecified"),
    ("240.0.0.1", "reserved"),
    ("255.255.255.255", "reserved"),
    ("100.64.0.1", "shared-address"),
    ("10.0.0.1", "private"),
    ("fc00::1", "private"),
    ("8.8.8.8", None),
    ("2606:4700::1111", None),
)

# Every embedded-IPv4 form with a non-public and a public carried address. The
# public rows are what make each unwrapping branch deletion-sensitive: without
# it, CPython 3.12 calls all of these prefixes private or reserved.
EMBEDDED_IPV4_CASES = (
    ("::ffff:127.0.0.1", "ipv4-mapped:loopback"),
    ("::ffff:8.8.8.8", None),
    ("::ffff:0:7f00:1", "ipv4-translated:loopback"),
    ("::ffff:0:808:808", None),
    ("::127.0.0.1", "ipv4-compatible:loopback"),
    ("::8.8.8.8", None),
    ("::", "unspecified"),
    ("::1", "loopback"),
    ("64:ff9b::a9fe:a9fe", "nat64:cloud-metadata"),
    ("64:ff9b::808:808", None),
    ("64:ff9b:1::808:808", "nat64-local-use"),
    ("2002:7f00:1::1", "6to4:loopback"),
    ("2002:808:808::1", None),
    ("2001:0:7f00:1::f7f7:f7f7", "teredo:loopback"),
    ("2001:0:808:808::f5ff:fffe", "teredo:private"),
    ("2001:0:808:808::f7f7:f7f7", None),
    # ISATAP is an interface identifier after any prefix, in both u-bit forms.
    ("2606:4700::5efe:7f00:1", "isatap:loopback"),
    ("2606:4700::200:5efe:a9fe:a9fe", "isatap:cloud-metadata"),
    ("2606:4700::200:5efe:808:808", None),
    ("2002:808:808::5efe:7f00:1", "isatap:loopback"),
    ("fe80::5efe:808:808", "link-local"),
)


_IDEOGRAPHIC_DOTS = str.maketrans({"。": ".", "．": ".", "｡": "."})
_IPV4_DIGITS = {16: frozenset("0123456789abcdefABCDEF"), 8: frozenset("01234567"),
                10: frozenset("0123456789")}


def _ipv4_number(part):
    """WHATWG URL IPv4 number parser: decimal, 0x-hex, or leading-0 octal."""
    if part[:2] in ("0x", "0X"):
        digits, radix = part[2:], 16
    elif len(part) > 1 and part[0] == "0":
        digits, radix = part[1:], 8
    else:
        digits, radix = part, 10
    if digits == "":
        return 0
    # Only the radix's own digits: int() would also accept a second 0x prefix,
    # signs, underscores and surrounding whitespace, which WHATWG rejects.
    if not set(digits) <= _IPV4_DIGITS[radix]:
        raise ValueError("invalid IPv4 number")
    return int(digits, radix)


def _is_a_label(label):
    """RFC 5890: an `xn--` label is an A-label only if it decodes to a U-label.

    The U-label must contain a non-ASCII code point and encode back to the same
    label, so `xn--`, `xn--localhost-` and other non-canonical Punycode are not
    A-labels. Those structural checks (round trip, non-ASCII decoding, length)
    do not depend on the `idna` release. Which code points are allowed does: it
    follows the installed IDNA2008 tables and their Unicode version, so CI pins
    `idna`. Any conversion failure means "not an A-label". `idna` 3.6 raises a
    bare ValueError from `unicodedata.name` for an unassigned code point after
    a joiner, and `IDNAError` is a `UnicodeError`, which is a `ValueError`.
    """
    try:
        decoded = idna.ulabel(label)
        return not decoded.isascii() and idna.alabel(decoded).decode("ascii") == label
    except (idna.IDNAError, UnicodeError, ValueError):
        return False


def request_url_syntax_ok(url):
    """XN-2 signed URL syntax: printable ASCII only, no `\\`, no `%` in the host.

    URL parsers disagree outside this syntax: UTS-46 drops default-ignorable code
    points, WHATWG ends an https authority at `\\`, and WHATWG percent-decodes the
    host, so `urlsplit` can see a DNS name where a fetch client connects to
    127.0.0.1. An internationalized host passes only in A-label form, and every
    `xn--` label must be a real one. `%` is checked over the whole netloc, since a
    port has none. Userinfo and a fragment are refused by presence (`@` in the
    netloc, any `#`), so an empty one is malformed too; a port must be decimal
    and at most 65535.
    """
    if not isinstance(url, str) or not url:
        return False
    if any(not "\x21" <= char <= "\x7e" for char in url) or "\\" in url:
        return False
    if "#" in url:
        return False
    try:
        parsed = urlsplit(url)
        parsed.port
    except ValueError:
        return False
    if "%" in parsed.netloc or "@" in parsed.netloc:
        return False
    labels = (parsed.hostname or "").split(".")
    return all(_is_a_label(label) for label in labels if label.startswith("xn--"))


def _host_literal(hostname):
    """Return the IP address an XN-2-admitted ASCII host denotes, or None for a DNS name.

    Classifies the host as the WHATWG IPv4 parser does: a host whose last label is
    a number is an IPv4 literal (shorthand, 32-bit, hex and octal spellings),
    never a DNS name, and a numeric-ending host that is not a valid IPv4 literal
    raises. It is not a full WHATWG host parser: it applies no UTS-46 mapping and
    relies on `urlsplit`, which does not end the authority at `\\`. Those
    spellings never reach it, because public_http_target applies the XN-2 syntax
    rule first. The percent-decoding and NFKC steps only keep a direct caller
    with a non-XN-2 host on the literal reading.
    """
    host = unquote(hostname, errors="strict")
    if not host.isascii():
        host = unicodedata.normalize("NFKC", host.translate(_IDEOGRAPHIC_DOTS))
    host = host.lower()
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    last = parts[-1]
    try:
        ends_in_number = last != "" and (last.isascii() and last.isdigit() or _ipv4_number(last) >= 0)
    except ValueError:
        ends_in_number = False
    if not ends_in_number:
        return None
    if len(parts) > 4 or "" in parts:
        raise ValueError("invalid IPv4 host")
    numbers = [_ipv4_number(part) for part in parts]
    if any(number > 255 for number in numbers[:-1]) or numbers[-1] >= 256 ** (5 - len(numbers)):
        raise ValueError("IPv4 host out of range")
    value = numbers[-1]
    for index, number in enumerate(numbers[:-1]):
        value += number * 256 ** (3 - index)
    return ipaddress.IPv4Address(value)


def public_http_target(url):
    """Reject directly encoded non-public targets before a network adapter runs.

    Hostname DNS, mixed-answer, and rebinding enforcement remains an executable
    adapter obligation under DACS-1 §6.3.6; URL-only conformance cannot prove it.
    validate_ref already returns `error` for a URL outside the XN-2 syntax; the
    gate refuses it again first, as defence in depth for direct callers.
    """
    if not request_url_syntax_ok(url):
        return False
    try:
        hostname = urlsplit(url).hostname
        if hostname is None or _is_localhost_name(hostname):
            return False
        address = _host_literal(hostname)
    except (UnicodeError, ValueError):
        return False
    if address is None:
        return True
    # An IPv4-mapped spelling reaches the same verdict as its IPv4 form; every
    # other embedded-IPv4 form is judged by what it carries, too.
    return _target_class(address) is None


def request_trace_defect(runtime, request):
    """XN-6: the reason the runtime's requests are not the signed request, if any.

    The trace names the request the handler derives from the agreement, then
    the unpaid and the paid request as sent. Each uses the exact signed method
    and URL, with no redirect followed. All three carry the same body bytes:
    those the signed `bodyHash` covers, or none without one.
    """
    if any(runtime.get(name) != request["method"]
           for name in ("effectiveMethod", "unpaidMethod", "paidMethod")):
        return "fail", "effective-request-method"
    if runtime.get("redirected") or any(runtime.get(name) != request["url"]
                                        for name in ("effectiveUrl", "unpaidUrl", "paidUrl")):
        return "fail", "effective-request"
    try:
        bodies = [base64.b64decode(runtime.get(name), validate=True)
                  for name in ("requestBodyBase64", "unpaidBodyBase64", "paidBodyBase64")]
    except Exception:
        return "error", "request-body"
    if bodies.count(bodies[0]) != len(bodies):
        return "fail", "effective-request-body"
    if "bodyHash" in request:
        if hashlib.sha256(bodies[0]).hexdigest() != request["bodyHash"]:
            return "fail", "request-body-hash"
    elif bodies[0]:
        return "fail", "unsigned-request-body"
    # XN-2/XN-6: neither request carries an ambient credential, and the paid
    # request adds exactly the v2 payment header to the unpaid request's set.
    headers = [request_headers(runtime.get(name)) for name in ("unpaidHeaders", "paidHeaders")]
    if None in headers:
        return "error", "request-headers"
    unpaid, paid = headers
    if AMBIENT_CREDENTIAL_HEADERS.intersection(unpaid) or AMBIENT_CREDENTIAL_HEADERS.intersection(paid):
        return "fail", "ambient-credential"
    if PAYMENT_SIGNATURE_HEADER in unpaid or PAYMENT_SIGNATURE_HEADER not in paid or {
        name: value for name, value in paid.items() if name != PAYMENT_SIGNATURE_HEADER
    } != unpaid:
        return "fail", "paid-request-headers"
    return None


def request_headers(headers):
    """A request's header fields keyed by lower-case name, or None if malformed."""
    if not isinstance(headers, dict):
        return None
    folded = {}
    for name, value in headers.items():
        if not HTTP_TOKEN.fullmatch(name.upper()) or not isinstance(value, str):
            return None
        if name.lower() in folded:
            return None
        folded[name.lower()] = value
    return folded


def record_wallet_authorization(effects):
    if effects is not None:
        effects["walletAuthorizationCalls"] = effects.get("walletAuthorizationCalls", 0) + 1


def retained_solana_identity(v):
    """Derive the identity from the durably retained client-signed transaction."""
    try:
        runtime = v["runtime"]
        selection = v["agreement"]["terms"]["rail"]["parameters"]["selection"]
        return solana_identity(runtime.get("solanaAuthorization"),
                               runtime["payer"]["paymentAddress"],
                               selection["extra"]["feePayer"])[0]
    except (KeyError, TypeError, ValueError):
        return None


def reconciliation_identity(v):
    """XN-11: this session's identity, from the signed agreement and the runtime.

    A stored record is never part of it: the record is judged only after the
    ledger reconciliation, and only for the recorded reason. The facilitator is
    trusted local routing (XN-3), retained so that a retry cannot switch it.
    """
    agreement = v.get("agreement", {})
    runtime = v.get("runtime", {})
    selected = agreement.get("terms", {}).get("rail")
    if not isinstance(selected, dict):
        return None
    return {
        "jobId": agreement.get("jobId"),
        "phaseIndex": runtime.get("phaseIndex"),
        "requirementHash": digest(selected),
        "authorizationIdentity": (
            retained_solana_identity(v)
            if selected.get("parameters", {}).get("selection", {}).get("network", "").startswith("solana:")
            else runtime.get("payer", {}).get("paymentAddress")
        ),
        "facilitator": runtime.get("facilitator"),
    }


def reconciliation_matches(retained, v):
    """XN-11: the retained state names this session's identity and routing.

    The retained state may also hold the known settlementTransaction (absent or
    null after response loss) and the authorization's EIP-3009 `validBefore`.
    The transaction is the response's, so it is compared with the reconciled
    one only after the ledger decides, as a recorded defect. An EIP-155
    authorization identity is the payer in XN-5 adapter form. Solana compares
    the message/client-signature identity derived from the durably retained
    client transaction instead.
    """
    identity = reconciliation_identity(v)
    if identity is None or not isinstance(retained, dict):
        return False
    if set(retained) - {"settlementTransaction", "validBefore"} != set(identity):
        return False
    parameters = v["agreement"]["terms"]["rail"].get("parameters")
    selection = parameters.get("selection") if isinstance(parameters, dict) else None
    network = selection.get("network") if isinstance(selection, dict) else None
    if network.startswith("solana:"):
        return identity["authorizationIdentity"] is not None and all(
            retained[field] == value for field, value in identity.items())
    try:
        payers = [adapter_address(network, payer) for payer in (
            retained["authorizationIdentity"], identity["authorizationIdentity"])]
    except (AttributeError, ValueError) as malformed:
        raise AddressFormError("authorizationIdentity has no XN-5 adapter form") from malformed
    if any(retained[field] != value for field, value in identity.items()
           if field != "authorizationIdentity"):
        return False
    return payers[0] == payers[1]


def exact_atomic(amount, decimals, ceiling):
    if not isinstance(amount, str) or not CD1.fullmatch(amount):
        raise ValueError("non-canonical decimal")
    # Bound decimals before any power of ten is computed.
    if not is_safe_nonnegative(decimals) or decimals > ASSET_DECIMALS_MAX:
        raise ValueError("invalid decimals")
    if type(ceiling) is not int:
        raise ValueError("no binding amount ceiling")
    # Exact decimal shifting on the canonical digits: no arithmetic context,
    # so there is no precision limit and nothing can round.
    whole, _, fraction = amount.partition(".")
    if len(fraction) > decimals:
        raise ValueError("not exactly representable")
    atomic = int(whole + fraction) * 10 ** (decimals - len(fraction))
    if atomic <= 0:
        raise ValueError("not exactly representable")
    if atomic > ceiling:
        raise ValueError("overflows the binding amount type")
    # A positive int, so its decimal string is already canonical.
    return str(atomic)


def fr2_rate_amount(amount, rate_bps, decimals):
    """FR-2: `amount × rateBps ÷ 10000`, rounded half-up to `decimals`, as a CD-1 decimal.

    Exact integer arithmetic on the canonical digits, so nothing rounds but
    the one half-up step at the asset's precision.
    """
    if not isinstance(amount, str) or not CD1.fullmatch(amount):
        raise ValueError("non-canonical decimal")
    if not is_safe_nonnegative(rate_bps):
        raise ValueError("invalid rateBps")
    if not is_safe_nonnegative(decimals) or decimals > ASSET_DECIMALS_MAX:
        raise ValueError("invalid decimals")
    whole, _, fraction = amount.partition(".")
    denominator = 10 ** len(fraction) * 10000
    units, remainder = divmod(int(whole + fraction) * rate_bps * 10 ** decimals, denominator)
    if 2 * remainder >= denominator:
        units += 1
    digits = str(units).rjust(decimals + 1, "0")
    integer, fraction = digits[:len(digits) - decimals], digits[len(digits) - decimals:].rstrip("0")
    return integer + ("." + fraction if fraction else "")


def decode_response_header(header, version):
    # XN-7: v0.8 binds version 2, whose settlement response is PAYMENT-RESPONSE.
    if version != 2 or not isinstance(header, dict) or header.get("name") != "PAYMENT-RESPONSE":
        raise ValueError("wrong response header")
    if not isinstance(header.get("value"), str):
        raise ValueError("response header has no value")
    raw = base64.b64decode(header["value"], validate=True)
    # CORE CF-5: the exact received bytes are admitted before any use, so NaN,
    # an out-of-profile number, a lone surrogate or a duplicate member is
    # refused, never an exception or a last-wins reading (RawJsonProfileError).
    response = admit_raw_json(raw)
    if not isinstance(response, dict):
        raise ValueError("response is not object")
    return response


def read_settlement_response(header, version, network, payer):
    """XN-7/XN-11: the received settlement response and its first defect, if any.

    The response is the payee's unsigned acknowledgement, so a defect here is
    the seller's protocol fault and never the outcome. Returns the complete
    decoded object (None when no version-selected object decodes) and None or
    the defect: `response-json` (refused by CORE CF-5), `response-header`,
    `response-not-success`, `response-network` or `response-payer`. Its
    transaction is compared later, with the one the reconciliation establishes
    (`response-transaction`). Upstream's `payer` is optional, so an absent one
    is sound. Upstream's non-terminal `settlement_pending` names the broadcast
    transaction; it is sound too, and the ledger decides as always.
    """
    try:
        response = decode_response_header(header, version)
    except RawJsonProfileError:
        return None, "response-json"
    except ValueError:
        return None, "response-header"
    pending = (
        response.get("success") is False
        and response.get("errorReason") == "settlement_pending"
        and isinstance(response.get("transaction"), str)
        and response["transaction"] != ""
    )
    if response.get("success") is not True and not pending:
        return response, "response-not-success"
    if response.get("network") != network:
        return response, "response-network"
    if "payer" in response:
        try:
            if adapter_address(network, response["payer"]) != payer:
                return response, "response-payer"
        except ValueError:
            return response, "response-payer"
    return response, None


def adapter_canonical_transaction(network, transaction):
    """The adapter's comparison form of a received response `transaction`.

    settlementTransaction keeps the response spelling verbatim (XN-7). Only the
    comparison with settlementEvent and ledger data uses this form, so None (no
    canonical form) is a malformed coordinate. DACS-produced settlementEvent
    keys get no such collapse: EVM_EVENT accepts only the canonical spelling.
    """
    if not isinstance(transaction, str):
        return None
    if network.startswith("eip155:"):
        match = EVM_RESPONSE_TRANSACTION.fullmatch(transaction)
        return match.group(1).lower() if match else None
    if network.startswith("solana:"):
        return transaction
    return None


def adapter_address(network, address):
    """XN-5: the comparison form of an address on the selected network.

    An EIP-155 address compares as a 20-byte value: `0x` plus 40 hex digits,
    letter case ignored. The EIP-55 checksum is neither required nor checked;
    case carries no account identity. Anything else is a malformed coordinate
    (ValueError). Other networks compare the exact string, since Solana's
    base58 is case-sensitive.
    """
    if network.startswith("eip155:"):
        if not (isinstance(address, str) and EVM_ADDRESS.fullmatch(address)):
            raise ValueError("EVM address is not 0x plus 40 hexadecimal digits")
        return address.lower()
    return address


class AddressFormError(ValueError):
    """XN-5: an address with no adapter form, where ValueError would name another coordinate."""


def challenge_member_defect(network, extra, extensions):
    """XN-6: the reason a member of the matched `extra` or of `extensions` rejects, if any.

    Each received member is classified from the selected adapter's own tables,
    never from a list supplied beside the challenge or a local capability. A
    member they do not name is unclassified and rejects like an unsupported
    action-bearing member. A defined member is then validated by the §9.5.7.1
    value rules: an EIP-155 transfer method other than EIP-3009 is unsupported
    (XN-9), as is any payment flow but `authorization`, and a required member
    that is absent or malformed rejects (`extra-member-value`).
    """
    namespace = network.split(":", 1)[0]
    if not set(extra) <= ADAPTER_EXTRA_MEMBERS.get(namespace, frozenset()):
        return "fail", "unclassified-extra-member"
    if "paymentFlow" in extra and not (
        isinstance(extra["paymentFlow"], str) and extra["paymentFlow"] in PAYMENT_FLOWS
    ):
        return "fail", "unsupported-payment-flow"
    if namespace == "eip155":
        method = extra.get("assetTransferMethod", "eip3009")
        if not (isinstance(method, str) and method in EIP155_TRANSFER_METHODS):
            return "fail", "unsupported-transfer-method"
        # EIP-3009: the token's EIP-712 domain name and version are required.
        if not all(isinstance(extra.get(name), str) and extra[name] for name in ("name", "version")):
            return "fail", "extra-member-value"
    elif namespace == "solana":
        # The pinned Solana exact definition defines no transfer method.
        if "assetTransferMethod" in extra:
            return "fail", "unsupported-transfer-method"
        if base58_decoded_length(extra.get("feePayer")) != 32:
            return "fail", "extra-member-value"
        if "memo" in extra:
            memo = extra["memo"]
            try:
                if not isinstance(memo, str) or len(memo.encode("utf-8")) > SOLANA_MEMO_MAX_BYTES:
                    return "fail", "extra-member-value"
            except UnicodeEncodeError:
                return "fail", "extra-member-value"
        # recentBlockhash and lastValidBlockHeight are hints: a malformed one is
        # ignored (the client fetches its own blockhash), never a rejection.
    if not set(extensions) <= DEFINED_EXTENSIONS:
        return "fail", "unclassified-extension"
    if "payment-identifier" in extensions:
        # Upstream's advertisement is {info: {required}, schema}, with a
        # pinned schema, and `info` satisfies it. v0.8 defines no identifier,
        # so a required one is an unsupported action; the optional one is
        # descriptive and needs no local capability.
        advertised = extensions["payment-identifier"]
        if (
            not isinstance(advertised, dict)
            or set(advertised) != {"info", "schema"}
            or not isinstance(advertised["info"], dict)
            or not isinstance(advertised["schema"], dict)
            or jcs_canonicalize(advertised["schema"]) not in PAYMENT_IDENTIFIER_SCHEMAS
            or type(advertised["info"].get("required")) is not bool
            or "id" in advertised["info"] and not (
                isinstance(advertised["info"]["id"], str)
                and PAYMENT_IDENTIFIER_ID.fullmatch(advertised["info"]["id"])
            )
        ):
            return "fail", "extension-value"
        if advertised["info"]["required"]:
            return "fail", "unsupported-action-extension"
    return None


def sb3_eip3009_nonce(job_id, phase_index):
    """SB-3: the EIP-3009 `bytes32 nonce` derived from (jobId, phaseIndex), as DACS serialises it."""
    preimage = (b"dacs-sb3:v1:" + unicodedata.normalize("NFC", job_id).encode("utf-8")
                + b":" + str(phase_index).encode("ascii"))
    return "0x" + hashlib.sha256(preimage).hexdigest()


def payment_payload_defect(v, required, matched, network, payer, pay_to, *, before_signing=False):
    """XN-6/§9.5.7.1: whether the paid request's PAYMENT-SIGNATURE fails to carry this payment.

    Its value is the base64 of a v2 PaymentPayload (x402 v2 §5.2) that CF-5
    admits: `x402Version` 2, `accepted` the matched requirement as received,
    `resource` and `extensions` (both optional) the challenge's own, and the
    binding's payload. On EIP-155 that is an EIP-712 signature and the EIP-3009
    authorization of the payer to `payTo` for the exact amount, whose
    `validBefore` is the retained one and whose nonce is the SB-3 derived one.
    On Solana it is the base64 transaction. The paid request carries no
    payment identifier, since v0.8 defines none.

    Before signing, judge the envelope and to-be-signed fields, allowing the
    EIP-712 signature to be absent. Its form is judged after the wallet call.
    """
    paid = request_headers(v.get("runtime", {}).get("paidHeaders")) or {}
    try:
        payload = admit_raw_json(base64.b64decode(paid.get(PAYMENT_SIGNATURE_HEADER), validate=True))
    except (TypeError, ValueError):
        return True
    if (
        not isinstance(payload, dict)
        or not PAYMENT_PAYLOAD_REQUIRED <= set(payload) <= PAYMENT_PAYLOAD_FIELDS
        or type(payload["x402Version"]) is not int or payload["x402Version"] != 2
        or jcs_canonicalize(payload["accepted"]) != jcs_canonicalize(matched)
        or any(name in payload and jcs_canonicalize(payload[name]) != jcs_canonicalize(required.get(name))
               for name in ("resource", "extensions"))
        or not isinstance(payload["payload"], dict)
    ):
        return True
    body = payload["payload"]
    if network.startswith("solana:"):
        transaction = body.get("transaction")
        try:
            if set(body) != {"transaction"}:
                return True
            identity, _ = solana_identity(transaction, payer, matched["extra"]["feePayer"],
                                          before_signing=before_signing)
            # §9.5.7.1: the message is exactly this payment, before the payer
            # signs it and again before the signed transaction can be sent.
            if payment_instruction_defect(
                    transaction, payer=payer, fee_payer=matched["extra"]["feePayer"], pay_to=pay_to,
                    mint=matched["asset"], amount=int(matched["amount"]),
                    decimals=v["agreement"]["terms"]["rail"]["parameters"]["selection"]["assetDecimals"],
                    token_program=v["capability"]["assetMetadata"].get("tokenProgram"),
                    memo=matched["extra"].get("memo")) is not None:
                return True
            retained = retained_solana_identity(v)
            if before_signing:
                return retained is None or identity["messageHash"] != retained["messageHash"]
            return identity != retained
        except (KeyError, TypeError, ValueError):
            return True
    authorization = body.get("authorization")
    if (
        set(body) - {"signature"} != {"authorization"}
        or (not before_signing and not (
            isinstance(body.get("signature"), str) and EVM_SIGNATURE.fullmatch(body["signature"])))
        or not isinstance(authorization, dict)
        or set(authorization) != EIP3009_AUTHORIZATION_FIELDS
        # EIP-3009's value and times are uint256, so at most 78 decimal digits
        # are converted. Each is then bounded by value: `value` equals the
        # XN-5 amount, `validBefore` the retained safe integer, and
        # `validAfter` is below it.
        or not all(isinstance(authorization[name], str) and UINT_DECIMAL.fullmatch(authorization[name])
                   and len(authorization[name]) <= 78
                   for name in ("value", "validAfter", "validBefore"))
        or authorization["value"] != matched["amount"]
        or int(authorization["validAfter"]) >= int(authorization["validBefore"])
    ):
        return True
    # Execute already required a retained safe integer before inspecting the
    # to-be-signed fields, so retained_valid_before yields one here.
    if authorization["validBefore"] != str(retained_valid_before(v)):
        return True
    try:
        if (adapter_address(network, authorization["from"]) != payer
                or adapter_address(network, authorization["to"]) != pay_to):
            return True
        nonce = sb3_eip3009_nonce(v["agreement"]["jobId"], v["runtime"]["phaseIndex"])
    except (AttributeError, KeyError, TypeError, ValueError):
        return True
    return authorization["nonce"] != nonce


def comparable_extra(network, extra):
    """XN-4: the `extra` object compared by JCS, without the Solana hints."""
    if network.startswith("solana:"):
        return {name: value for name, value in extra.items() if name not in SOLANA_HINT_MEMBERS}
    return extra


def payout_bindings(agreement, phase_index):
    """PB-1: the agreement's payout bindings for (x402:protocol, phaseIndex)."""
    return [item for item in agreement.get("terms", {}).get("payoutBindings", []) if (
        item.get("railId") == "x402:protocol" and item.get("phaseIndex") == phase_index
    )]


def selection_eip155_chain(network):
    """PB-2 step 1(b): the agreement-signed selection's canonical EIP-155 chain, or None."""
    match = re.fullmatch(r"eip155:([1-9][0-9]*)", network)
    if match is None or int(match.group(1)) > SAFE_INT:
        return None
    return network


def claim_eip155_chain(claim):
    """PB-2 step 2: a cci-xm claim's canonical EIP-155 chain under the DACS-1 EVM profile, or None."""
    if not isinstance(claim, str):
        return None
    parts = claim.split(":", 3)
    if len(parts) != 4 or parts[0].lower() != "cci-xm" or parts[1] != "evm":
        return None
    if re.fullmatch(r"[1-9][0-9]*", parts[2]) is None or int(parts[2]) > SAFE_INT:
        return None
    if not parts[3].split("?", 1)[0]:
        return None
    return f"eip155:{parts[2]}"


def payee_destination_defect(v, seller, network, pay_to):
    """PB-2: the (verdict, reason) when the payout is not bound to the payee, else None.

    Tier applicability comes from the pinned payee bundle and the signed
    selection's chain, never from whether linkage resolution succeeds. With
    no applicable claim the co-signed payout binding (tier 3, PB-1) binds the
    destination. With one, only a claim naming the payout whose linkage
    resolves control-proven binds it; an unresolved one pauses and a resolver
    error stays `error`, never falling through to tier 3.
    """
    bundle = v.get("payeeBundle")
    if not isinstance(bundle, dict) or not isinstance(bundle.get("claims"), list):
        return "fail", "payee-bundle"
    bundle_hash = digest(bundle)
    if (
        seller.get("bundleHash") != bundle_hash
        or v.get("runtime", {}).get("payee", {}).get("bundleHash") != bundle_hash
        or bundle.get("presentedBy") != seller.get("primaryClaim")
    ):
        return "fail", "payee-bundle"
    chain = selection_eip155_chain(network)
    applicable = [
        claim["ref"] for claim in bundle["claims"]
        if chain is not None and isinstance(claim, dict) and claim_eip155_chain(claim.get("ref")) == chain
    ]
    if not applicable:
        return None
    naming = []
    for ref in applicable:
        try:
            if adapter_address(network, ref.split("?", 1)[0].split(":", 3)[3]) == pay_to:
                naming.append(ref)
        except ValueError:
            # A claim address with no adapter form cannot name the payout.
            continue
    if not naming:
        return "fail", "payee-destination"
    decisions = {v.get("payeeLinkage", {}).get(ref) for ref in naming}
    if "pass" in decisions:
        return None
    if "error" in decisions:
        return "error", "payee-linkage-error"
    return "indeterminate", "payee-linkage-unresolved"


def selection_amount(price, selection):
    """XN-5: the signed price in the selected asset's atomic units (ValueError if inexact)."""
    return exact_atomic(
        price.get("amount"), selection["assetDecimals"],
        ATOMIC_AMOUNT_MAX.get(selection["network"].split(":", 1)[0]),
    )


def listing_agreement_type_violation(listing):
    """XN-2 listing admission: an offered x402:protocol ref needs the payee-bound phase.

    A malformed Listing is DACS-1 `rejected`, which this corpus scores as `fail`;
    ListingValidationDisposition has no `error`.
    """
    if not isinstance(listing, dict):
        return "fail", "listing-shape"
    pipeline = listing.get("pipeline")
    accepted = listing.get("acceptedRails")
    if not isinstance(pipeline, list) or not isinstance(accepted, list):
        return "fail", "listing-shape"
    if not all(isinstance(step, dict) for step in pipeline):
        return "fail", "listing-shape"
    offered = list(accepted)
    for step in pipeline:
        if step.get("kind") == "pay-alternative":
            # Shape before use: a signed but malformed slot is APR-1 `rejected`,
            # not an exception. APR-1 requires at least two alternatives.
            parameters = step.get("parameters")
            if not isinstance(parameters, dict):
                return "fail", "listing-shape"
            alternatives = parameters.get("alternatives")
            if not isinstance(alternatives, list) or len(alternatives) < 2 or not all(
                isinstance(alternative, dict) for alternative in alternatives
            ):
                return "fail", "listing-shape"
            offered.extend(alternatives)
    if not any(isinstance(ref, dict) and ref.get("railId") == "x402:protocol" for ref in offered):
        return None
    commits = [step.get("kind") for step in pipeline
               if isinstance(step.get("kind"), str) and step["kind"].startswith("commit-")]
    if commits != ["commit-payee-bound-agreement"]:
        return "fail", "x402-protocol-agreement-type"
    return None


def native_event_matches(event, network, transaction):
    if not isinstance(event, str):
        return False
    evm = EVM_EVENT.fullmatch(event)
    if evm:
        # SB-1: chainId and logIndex are safe integers, so every reader renders
        # the same key.
        return (
            int(evm.group(1)) <= SAFE_INT and int(evm.group(3)) <= SAFE_INT
            and network == f"eip155:{evm.group(1)}" and transaction == evm.group(2)
        )
    solana = SOLANA_EVENT.fullmatch(event)
    if solana:
        # SB-1: the signature decodes to exactly 64 bytes.
        return (
            int(solana.group(3)) <= SAFE_INT
            and base58_decoded_length(solana.group(2)) == 64
            and SOLANA_NETWORK_CLUSTERS.get(network) == solana.group(1)
            and transaction == solana.group(2)
        )
    return False


def reconcile_settlement(ledger, selection, amount, payer, pay_to, valid_before=None,
                         authorization_identity=None):
    """XN-11/XN-8: the payment disposition, from authenticated ledger data alone.

    `ledger` is what the adapter resolves for the retained authorization
    identity: the payment event that consumed it or, naming neither event
    coordinate, the identity's state. No settlement response and no stored
    record is read, so neither can replace this disposition. Unavailable or
    unreadable data, a non-final observation and a missing coordinate are
    `indeterminate`. A terminal state proven for the identity, or a resolved
    event that contradicts the authorization, is `fail`. A malformed coordinate
    is `error`. Returns (verdict, reason, event): on `pass`, event holds the
    validated adapter-form `transaction` and canonical `settlementEvent` that
    the success evidence is built or rebuilt from; otherwise it is None.
    `valid_before` is the retained EIP-3009 authorization's `validBefore`.
    """
    network = selection["network"]
    if not isinstance(ledger, dict) or ledger.get("available") is not True:
        return "indeterminate", "independent-settlement-unavailable", None
    if ledger.get("finalized") is not True:
        return "indeterminate", "settlement-not-final", None
    if "transaction" not in ledger and "settlementEvent" not in ledger:
        # No event: only a terminal state the finalized ledger proves ends the
        # phase; otherwise the authorization can still settle and the session
        # stays pending. No local clock decides an EIP-3009 expiry: a finalized
        # block whose timestamp is at least `validBefore`, with the nonce still
        # unused at that block, does.
        if network.startswith("eip155:"):
            state = ledger.get("nonceState")
            if state is not None and state not in EIP3009_NONCE_STATES:
                return "error", "ledger-nonce-state", None
            if state == "cancelled":
                return "fail", "terminal-non-settlement", None
            timestamp = ledger.get("finalizedBlockTimestamp")
            if timestamp is not None and not is_safe_nonnegative(timestamp):
                return "error", "ledger-block-timestamp", None
            if valid_before is not None and not is_safe_nonnegative(valid_before):
                return "error", "authorization-valid-before", None
            if (
                state == "unused" and timestamp is not None and valid_before is not None
                and timestamp >= valid_before
            ):
                return "fail", "terminal-non-settlement", None
        return "indeterminate", "authorization-unsettled", None
    # XN-7/XN-8: the event's transaction and settlementEvent identify it, so
    # they are judged before anything about the transfer. A missing one is
    # missing data. A transaction with no adapter form, or a key that is not
    # adapter-canonical or does not name that transaction on the selected
    # network, is malformed.
    if "transaction" not in ledger or "settlementEvent" not in ledger:
        return "indeterminate", "ledger-coordinate-missing", None
    transaction = adapter_canonical_transaction(network, ledger["transaction"])
    if transaction is None:
        return "error", "ledger-transaction-form", None
    if not native_event_matches(ledger["settlementEvent"], network, transaction):
        return "error", "ledger-event-key", None
    if network.startswith("solana:"):
        # A response transaction or matching transfer terms cannot identify a
        # client authorization. Resolve its exact message/signatures from the
        # authenticated transaction bytes, including the sponsor's signature.
        if authorization_identity is None or ledger.get("transactionBase64") is None:
            return "indeterminate", "authorization-identity-unavailable", None
        try:
            resolved, transaction_id = solana_identity(
                ledger["transactionBase64"], payer, selection["extra"]["feePayer"], finalized=True)
        except SignerMismatch:
            # A validly signed transaction of other signers is a different
            # transaction, not a malformed one: the original stays pending.
            return "indeterminate", "authorization-identity-mismatch", None
        except (KeyError, TypeError, ValueError):
            return "error", "ledger-authorization-form", None
        if transaction_id != transaction or resolved != authorization_identity:
            return "indeterminate", "authorization-identity-mismatch", None
    try:
        ledger_payer = adapter_address(network, ledger.get("payer"))
        ledger_pay_to = adapter_address(network, ledger.get("payTo"))
        ledger_asset = adapter_address(network, ledger.get("asset"))
        asset = adapter_address(network, selection["asset"])
    except ValueError:
        return "error", "address-form", None
    # SB-3: a mandatory binding is resolved before the transfer checks.
    if network.split(":", 1)[0] in SB3_BINDING_NAMESPACES:
        branch = binding_branch(ledger.get("sessionBinding"))
        if branch == "mismatch":
            return "fail", "sb3", None
        if branch in ("absent", "unavailable"):
            return "indeterminate", "sb3", None
        if branch != "match":
            return "error", "sb3", None
    if (
        ledger.get("network") != network
        or ledger.get("scheme") != "exact"
        or ledger_asset != asset
        or ledger.get("assetDecimals") != selection["assetDecimals"]
        or ledger.get("amount") != amount
        or ledger_payer != payer
        or ledger_pay_to != pay_to
    ):
        return "fail", "ledger-event", None
    return "pass", None, {"transaction": transaction, "settlementEvent": ledger["settlementEvent"]}


def reconciliation_terms(v):
    """XN-11: the signed terms a retry reconciles ledger data against.

    The agreement passed every execute gate before the authorization this
    retry reconciles, so a term it cannot yield is malformed (ValueError).
    """
    agreement = v.get("agreement", {})
    runtime = v.get("runtime", {})
    ref = agreement.get("terms", {}).get("rail")
    if validate_ref(ref) != "pass":
        raise ValueError("selected ref is malformed")
    selection = ref["parameters"]["selection"]
    network = selection["network"]
    binding = payout_bindings(agreement, runtime.get("phaseIndex"))
    if len(binding) != 1:
        raise ValueError("no single payout binding")
    return (
        selection,
        selection_amount(agreement["terms"].get("price", {}), selection),
        adapter_address(network, runtime.get("payer", {}).get("paymentAddress")),
        adapter_address(network, binding[0].get("payeeAddress")),
    )


def check_record(v, required, response, response_fault, selection, request):
    """XN-7/XN-8: the stored success record's first defect that needs no ledger data.

    Returns (defect, record). defect is None or the (verdict, reason) a verifier
    gives the record. record holds its adapter-form `transaction`, its
    `event` key, and `responseFault`: the response defect, judged against the
    record when the response is otherwise sound.
    """
    network = selection["network"]
    if "evidence" in v and not verify_record_signature(v):
        return ("fail", "signature"), None
    evidence = v.get("evidence", {})
    # §9.7/SB-1: the record's own version, outcome, phase, job and amount. A
    # missing or mistyped one is malformed; another value is not this payment.
    agreement = v.get("agreement", {})
    if evidence.get("evidenceVersion") != "1":
        return ("error", "evidence-record-version"), None
    if not all(isinstance(evidence.get(name), str) for name in ("outcome", "phase", "jobId")):
        return ("error", "evidence-record-shape"), None
    if (
        evidence["outcome"] != "success"
        or evidence["phase"] != "pay-x402"
        or evidence["jobId"] != agreement.get("jobId")
    ):
        return ("fail", "evidence-record-binding"), None
    paid = evidence.get("paymentAmount")
    if (
        not isinstance(paid, dict)
        or set(paid) != {"amount", "currency"}
        or not isinstance(paid["amount"], str)
        or not CD1.fullmatch(paid["amount"])
        or not isinstance(paid["currency"], str)
    ):
        return ("error", "evidence-payment-amount"), None
    # CD-1 forms are canonical, so equal amounts are equal strings.
    price = agreement.get("terms", {}).get("price", {})
    if paid != {"amount": price.get("amount"), "currency": price.get("currency")}:
        return ("fail", "evidence-payment-amount"), None
    refs = evidence.get("paymentTxRefs")
    if not isinstance(refs, list) or len(refs) != 1:
        return ("error", "evidence-ref-count"), None
    evidence_ref = refs[0]
    if not isinstance(evidence_ref, dict) or set(evidence_ref) != EVIDENCE_REF_FIELDS:
        return ("error", "evidence-ref-shape"), None
    if evidence_ref.get("kind") != "x402-protocol" or type(evidence_ref.get("x402Version")) is not int:
        return ("error", "evidence-version"), None
    if evidence_ref["x402Version"] != selection["x402Version"]:
        return ("fail", "evidence-version"), None
    if not all(isinstance(evidence_ref.get(name), str) and HEX_32.fullmatch(evidence_ref[name])
               for name in ("paymentRequiredHash", "paymentReceiptHash")):
        return ("error", "evidence-hash-shape"), None
    if evidence_ref["paymentRequiredHash"] != digest(required):
        return ("fail", "payment-required-hash"), None
    # The receipt commitment covers the response as received, defective or
    # not; with no decoded object its preimage is JSON null (XN-7).
    if evidence_ref["paymentReceiptHash"] != digest(response):
        return ("fail", "payment-receipt-hash"), None
    if (
        evidence_ref.get("httpResource") != request["url"]
        or evidence_ref.get("settlementNetwork") != network
    ):
        return ("fail", "evidence-binding"), None
    # settlementTransaction is the transaction the reconciliation establishes.
    transaction = adapter_canonical_transaction(network, evidence_ref.get("settlementTransaction"))
    if transaction is None:
        return ("error", "settlement-transaction-form"), None
    if response_fault is None and evidence_ref["settlementTransaction"] != response.get("transaction"):
        # A sound response's own transaction spelling is kept verbatim; one that
        # names another transaction, or none, is a response defect.
        if adapter_canonical_transaction(network, response.get("transaction")) == transaction:
            return ("fail", "evidence-response-binding"), None
        response_fault = "response-transaction"
    finality = evidence.get("settlementFinality", {})
    profile = finality.get("schemeNetworkFinality", {})
    if (
        finality.get("model") != "scheme-network-finality"
        or profile != {
            "scheme": selection["scheme"],
            "network": network,
            "bindingProfile": "dacs-x402-exact:v1",
        }
    ):
        return ("fail", "finality-profile"), None
    # The signed event key's form needs no ledger data, so a malformed key is
    # `error` for the record even while the ledger is unavailable or not final.
    event = evidence_ref.get("settlementEvent")
    if not native_event_matches(event, network, transaction):
        return ("error", "native-event-key"), None
    return None, {"transaction": transaction, "event": event, "responseFault": response_fault}


def record_ledger_defect(record, event):
    """XN-8: the record must name the reconciled event's transaction and event key."""
    if (
        event["transaction"] != record["transaction"]
        or event["settlementEvent"] != record["event"]
    ):
        return "fail", "ledger-event"
    return None


def stored_record_defect(v, required, response, response_fault, selection, request, event):
    """XN-7/XN-11: the verdict a verifier gives a stored record, or None.

    The handler rejects such a record and rebuilds it from the retained
    challenge and response and the reconciled event; the defect is at most the
    recorded reason, after the ledger has decided.
    """
    defect, record = check_record(v, required, response, response_fault, selection, request)
    return defect or record_ledger_defect(record, event)


def build_evidence(effects, event, transaction):
    """XN-7/XN-11: the success record is built, or rebuilt, from the reconciled event.

    `transaction` is the verbatim spelling of a known transaction that names
    the reconciled one (a sound response's), or None for the adapter form.
    """
    if effects is not None:
        effects["builtEvidence"] = {
            "settlementTransaction": event["transaction"] if transaction is None else transaction,
            "settlementEvent": event["settlementEvent"],
        }


def keep_anchored_record(v, effects, defect):
    """XN-11/PC-7: a stored record already anchored at the write-once address.

    An unanchored record is local material: one a verifier rejects is
    discarded and the record built from the reconciled event replaces it. An
    anchored record is never replaced. One that verifies stays the phase's
    evidence, so re-anchoring it is idempotent; one that does not verify
    leaves nothing to build, and the phase enters manual recovery. The
    ledger's disposition stands either way.
    """
    if effects is None or v.get("runtime", {}).get("storedRecordAnchored") is not True:
        return
    if defect is not None:
        effects.pop("builtEvidence", None)
        effects["manualRecovery"] = defect[1]
        return
    ref = v["evidence"]["paymentTxRefs"][0]
    effects["builtEvidence"] = {
        "settlementTransaction": ref["settlementTransaction"],
        "settlementEvent": ref["settlementEvent"],
    }


def received_challenge(http):
    """CORE CF-5: the received PaymentRequired, with raw bytes admitted before any use.

    Both forms model the v2 `PAYMENT-REQUIRED` header (XN-4): the raw form is
    its base64 value and the object form its decoded object. The 402 body is
    never read. An object challenge is checked against the same profile by
    hashing it. TypeError or ValueError means it is not admissible, as is a
    challenge received both as raw bytes and as an object.
    """
    if "paymentRequiredRaw" in http:
        if "paymentRequired" in http:
            raise ValueError("two received challenges")
        required = admit_raw_json(base64.b64decode(http["paymentRequiredRaw"], validate=True))
    else:
        required = http.get("paymentRequired")
    digest(required)
    return required


def materialize_vector(data, vector):
    value = copy.deepcopy(data["fixtures"][vector["base"]])
    for patch in vector.get("patch", []):
        path = patch.get("path")
        if not isinstance(path, list) or not path:
            raise ValueError("patch path must be a non-empty array")
        target = value
        for segment in path[:-1]:
            target = target[segment]
        leaf = path[-1]
        operation = patch.get("op")
        if operation in {"add", "replace"}:
            target[leaf] = copy.deepcopy(patch["value"])
        elif operation == "remove":
            del target[leaf]
        else:
            raise ValueError(f"unsupported patch operation: {operation!r}")
    return {
        **{name: copy.deepcopy(item) for name, item in vector.items()
           if name not in {"base", "patch"}},
        **value,
    }


def protocol_preflight(v):
    """XN-1/XN-2: the definition and reference gates every protocol operation runs.

    Execute, retry and verify-evidence all apply them, so a retry cannot
    reconcile under a malformed or other-revision definition, a legacy arm, or
    a malformed reference.
    """
    rail = v.get("railDefinition")
    if validate_protocol_definition(rail) != "pass":
        return "error", "definition"
    ref = v.get("agreement", {}).get("terms", {}).get("rail")
    ref_result = validate_ref(ref)
    if ref_result != "pass":
        return ref_result, "rail-ref-shape"
    # XN-1: the definition applied is the revision the signed reference pins;
    # another one, even validly signed and well formed, is not it.
    if rail["railVersion"] != ref["railVersion"]:
        return "fail", "rail-version"
    return None


def evaluate(v, effects=None):
    operation = v.get("operation")
    rail = v.get("railDefinition")

    if operation == "validate-definition":
        if not verify_artifact_signatures(v):
            return "fail", "signature"
        return validate_protocol_definition(rail), None

    if operation == "admit-listing":
        if not verify_artifact_signatures(v):
            return "fail", "signature"
        # LRR-5: the commitment-phase rule needs no registry, so it rejects
        # even when registry authority cannot be authenticated.
        violation = listing_agreement_type_violation(v.get("listing"))
        if violation is not None:
            return violation
        if v.get("registry", {}).get("authenticated") is False:
            return "indeterminate", "registry-unauthenticated"
        return "pass", None

    if operation == "new-session":
        if not verify_artifact_signatures(v):
            return "fail", "signature"
        if rail.get("railId") == "x402:default":
            return "fail", "legacy-default-new-session"
        # XN-1: the protocol definition is well formed, its availability one
        # of the union's values, before that value is read.
        if validate_protocol_definition(rail) != "pass":
            return "error", "definition"
        # RAV-R2: no new session on a disabled or failed rail. The production
        # `mocked` arm needs the operator's mode, which this corpus does not model.
        if rail["availability"] in {"disabled", "failed"}:
            return "fail", "rail-availability"
        return "pass", None

    if operation in {"legacy-replay", "legacy-continuation"}:
        if not verify_artifact_signatures(v):
            return "fail", "signature"
        if (
            operation == "legacy-continuation"
            and v.get("runtime", {}).get("sessionState") != "in-flight"
        ):
            return "fail", "not-in-flight"
        refs = v.get("evidence", {}).get("paymentTxRefs", [])
        if len(refs) != 1:
            return "error", "shape"
        ref = refs[0]
        if not (
            rail.get("railId") == "x402:default"
            and ref.get("kind") == "x402-event"
            and isinstance(ref.get("protocolVersion"), str)
            and "x402Version" not in ref
        ):
            return "error", "legacy-boundary"
        # X402-1..X402-4: finishing a legacy session needs the complete
        # successful response, and it must verify against the record. A
        # finalized ledger settlement never stands in for a missing, malformed,
        # non-success or mismatched one; the negotiated XN-11 policy does not
        # apply here. A replay verifier presented with the response applies
        # the same checks (X402-4).
        http = v.get("http", {})
        if operation == "legacy-continuation" or "responseHeader" in http:
            defect = legacy_receipt_defect(http.get("responseHeader"), ref)
            if defect is not None:
                return "fail", defect
        return "pass", None

    if operation == "retry":
        # As in execute, a stored record is judged only after the ledger has
        # decided, so its own signature is not a gate here.
        if not verify_artifact_signatures({name: item for name, item in v.items() if name != "evidence"}):
            return "fail", "signature"
        # XN-1/XN-2: the same definition and reference gates as execute.
        defect = protocol_preflight(v)
        if defect is not None:
            return defect
        retained = v.get("runtime", {}).get("reconciliationState")
        # XN-11: no provider or facilitator switch inside the session.
        if isinstance(retained, dict) and retained.get("facilitator") != v.get("runtime", {}).get("facilitator"):
            return "fail", "routing-switch"
        try:
            matches = reconciliation_matches(retained, v)
        except AddressFormError:
            return "error", "address-form"
        if not matches:
            return "fail", "reconciliation-binding"
        # XN-11: the retained identity is this session's. The payment
        # disposition comes from the same ledger reconciliation as after the
        # execute path's wallet call; no settlement evidence is needed.
        try:
            selection, amount, payer, pay_to = reconciliation_terms(v)
        except (AttributeError, KeyError, TypeError, ValueError):
            return "error", "reconciliation-terms"
        verdict, reason, event = reconcile_settlement(
            v.get("ledger"), selection, amount, payer, pay_to, retained.get("validBefore"),
            retained_solana_identity(v)
        )
        if verdict != "pass":
            return verdict, reason
        network = selection["network"]
        # The retained transaction is the response's, kept verbatim (XN-7). One
        # with no adapter form, or naming another transaction than the
        # reconciled one, is a recorded response defect.
        known = retained.get("settlementTransaction")
        retained_fault = known is not None and adapter_canonical_transaction(
            network, known) != event["transaction"]
        build_evidence(effects, event, None if retained_fault else known)
        # A stored record is checked as in execute, against the retained
        # challenge and response and the reconciled event; its defect is the
        # recorded reason, never the outcome.
        defect = None
        if "evidence" in v:
            http = v.get("http", {})
            try:
                required = received_challenge(http)
            except (TypeError, ValueError):
                required = None
            response, response_fault = read_settlement_response(
                http.get("responseHeader"), selection["x402Version"], network, payer
            )
            request = v["agreement"]["terms"]["rail"]["parameters"]["request"]
            defect = stored_record_defect(v, required, response, response_fault, selection, request, event)
            keep_anchored_record(v, effects, defect)
        if retained_fault:
            return "pass", "response-transaction"
        return "pass", defect and defect[1]

    if operation == "fee-rate-amount":
        # FR-2: an `x402:protocol` rateBps item resolves at the signed
        # selection's assetDecimals, once the adapter's metadata has
        # independently established that precision (XN-5).
        if not verify_artifact_signatures({name: item for name, item in v.items() if name != "evidence"}):
            return "fail", "signature"
        defect = protocol_preflight(v)
        if defect is not None:
            return defect
        selection = v["agreement"]["terms"]["rail"]["parameters"]["selection"]
        # The same XN-5 metadata gate as execute: the metadata is the selected
        # asset's on the selected network, not just one with equal decimals.
        metadata = v.get("capability", {}).get("assetMetadata", {})
        try:
            same_asset = (adapter_address(selection["network"], metadata.get("asset"))
                          == adapter_address(selection["network"], selection["asset"]))
        except ValueError:
            return "error", "address-form"
        if (
            metadata.get("network") != selection["network"]
            or not same_asset
            or metadata.get("decimals") != selection["assetDecimals"]
        ):
            return "fail", "asset-metadata"
        derivation = v.get("feeDerivation")
        if not isinstance(derivation, dict) or not (
                isinstance(derivation.get("amount"), str) and CD1.fullmatch(derivation["amount"])):
            return "error", "fee-amount"
        try:
            want = fr2_rate_amount(v["agreement"]["terms"]["price"].get("amount"),
                                   derivation.get("rateBps"), selection["assetDecimals"])
        except (AttributeError, TypeError, ValueError):
            return "error", "fee-rate"
        return ("pass", None) if derivation["amount"] == want else ("fail", "fee-amount")

    # `execute` runs the handler; `verify-evidence` is a verifier judging a
    # stored success record (XN-7/XN-8) and never authorizes. Both apply the
    # same gates, except that only `execute` checks the retained `validBefore`,
    # calls the wallet and judges the `PAYMENT-SIGNATURE` value. A stored
    # record is judged apart from the payment.
    if operation not in {"execute", "verify-evidence"}:
        return "error", "operation"
    # The stored record's own signature is judged in check_record.
    if not verify_artifact_signatures({name: item for name, item in v.items() if name != "evidence"}):
        return "fail", "signature"
    defect = protocol_preflight(v)
    if defect is not None:
        return defect

    agreement = v.get("agreement", {})
    ref = agreement["terms"]["rail"]
    canonical_ref = jcs_canonicalize(ref)
    listed = v.get("listing", {}).get("acceptedRails")
    if not isinstance(listed, list):
        return "fail", "listing-membership"
    # The Listing signature verified, so every listed ref canonicalizes.
    canonical_listed = [jcs_canonicalize(item) for item in listed]
    if len(canonical_listed) != len(set(canonical_listed)):
        return "fail", "duplicate-listing-ref"
    if canonical_listed.count(canonical_ref) != 1:
        return "fail", "listing-membership"
    # The runtime copy is unsigned: one that cannot canonicalize is not the ref.
    try:
        runtime_ref = jcs_canonicalize(v.get("runtime", {}).get("selectedRailRef"))
    except (TypeError, ValueError):
        runtime_ref = None
    if runtime_ref != canonical_ref:
        return "fail", "runtime-selection"

    parties = agreement.get("parties", [])
    buyer = [p for p in parties if p.get("role") == "buyer"]
    seller = [p for p in parties if p.get("role") == "seller"]
    if len(buyer) != 1 or len(seller) != 1:
        return "fail", "party-cardinality"
    runtime = v.get("runtime", {})
    if runtime.get("payer", {}).get("primaryClaim") != buyer[0].get("primaryClaim"):
        return "fail", "payer-party"
    try:
        controlled = buyer_payment_control(v, buyer[0], ref["parameters"]["selection"])
    except ValueError:
        return "error", "address-form"
    if not controlled:
        return "fail", "payer-control"
    if runtime.get("payee", {}).get("primaryClaim") != seller[0].get("primaryClaim"):
        return "fail", "payee-party"
    binding = payout_bindings(agreement, runtime.get("phaseIndex"))
    if len(binding) != 1:
        return "fail", "payout-binding"
    # XN-5/PB-1: the signed binding and the runtime payee compare in the adapter
    # form; a malformed form on either side is `error`, not a mismatch.
    network = ref["parameters"]["selection"]["network"]
    try:
        pay_to = adapter_address(network, binding[0].get("payeeAddress"))
        runtime_pay_to = adapter_address(network, runtime.get("payee", {}).get("payeeAddress"))
    except ValueError:
        return "error", "address-form"
    if runtime_pay_to != pay_to:
        return "fail", "payout-binding"
    # PB-2: the strongest applicable tier binds the payout before any wallet call.
    defect = payee_destination_defect(v, seller[0], network, pay_to)
    if defect is not None:
        return defect

    if runtime.get("operatorConfigSource") != "local-operator-policy":
        return "error", "operator-config-source"
    selection = ref["parameters"]["selection"]
    capability = v.get("capability", {})
    tuple_value = [selection["x402Version"], selection["scheme"], selection["network"]]
    if tuple_value not in capability.get("supportedTuples", []):
        return "fail", "x402-capability-unsupported"
    if selection["scheme"] != "exact" or "dacs-x402-exact:v1" not in capability.get("bindingProfiles", []):
        # XN-9: other schemes, batch-settlement included, are protocol-valid but
        # have no v0.8 DACS success binding, so they end here, unauthorized.
        return "fail", "x402-capability-unsupported"
    chain = selection["network"].split(":", 1)[-1]
    if selection["network"].split(":", 1)[0] not in ATOMIC_AMOUNT_MAX or (
        selection["network"].startswith("solana:")
        and selection["network"] not in SOLANA_NETWORK_CLUSTERS
    ) or (
        selection["network"].startswith("eip155:")
        and not (re.fullmatch(r"[1-9][0-9]{0,15}", chain) and int(chain) <= SAFE_INT)
    ):
        # §9.5.7.1: `dacs-x402-exact:v1` binds only EIP-155 chain IDs with an
        # SB-1 key form and the three mapped Solana clusters; no local claim
        # adds a network it cannot key.
        return "fail", "x402-capability-unsupported"

    request = ref["parameters"]["request"]
    if not public_http_target(request["url"]):
        return "fail", "non-public-request-target"
    defect = request_trace_defect(runtime, request)
    if defect is not None:
        return defect

    http = v.get("http", {})
    status = http.get("status")
    # XN-4: no answer, a server error, a timeout or a rate limit is transient.
    # Nothing is authorized yet, so the unpaid request can simply be retried.
    if status is None or type(status) is int and (500 <= status <= 599 or status in (408, 429)):
        return "indeterminate", "unpaid-request-transient"
    if status != 402:
        return "fail", "not-payment-required"
    # XN-4: the v2 challenge is the `PAYMENT-REQUIRED` header; the 402 body is
    # never read, so a challenge only in the body is no challenge.
    if "paymentRequired" not in http and "paymentRequiredRaw" not in http:
        return "error", "payment-required-header"
    # CORE CF-5: a challenge received as raw bytes is admitted before any use,
    # and an object one is checked against the same profile, so neither a
    # non-finite or out-of-profile number nor a lone surrogate can raise later.
    try:
        required = received_challenge(http)
    except (TypeError, ValueError):
        return "error", "payment-required-json"
    if not isinstance(required, dict) or required.get("x402Version") != selection["x402Version"]:
        return "error", "payment-required-version"
    version = selection["x402Version"]
    accepts = required.get("accepts")
    if not isinstance(accepts, list):
        return "error", "payment-required-shape"
    resource = required.get("resource")
    if not isinstance(resource, dict):
        return "error", "payment-required-shape"
    resource_url = resource.get("url")
    actual_extensions_present = "extensions" in required
    signed_extensions_present = "paymentRequiredExtensions" in ref["parameters"]
    if actual_extensions_present != signed_extensions_present:
        return "fail", "extension-presence"
    if actual_extensions_present and jcs_canonicalize(required["extensions"]) != jcs_canonicalize(
        ref["parameters"]["paymentRequiredExtensions"]
    ):
        return "fail", "extensions"

    price = agreement.get("terms", {}).get("price", {})
    if selection["currency"] != price.get("currency"):
        return "fail", "currency"
    # XN-5: on EIP-155 the asset compares as a 20-byte value, like payTo, in
    # the metadata, the challenge and the ledger. `extra` compares by JCS.
    metadata = capability.get("assetMetadata", {})
    try:
        asset = adapter_address(network, selection["asset"])
        metadata_asset = adapter_address(network, metadata.get("asset"))
    except ValueError:
        return "error", "address-form"
    signed_extra = jcs_canonicalize(comparable_extra(network, selection["extra"]))
    if (
        metadata.get("network") != selection["network"]
        or metadata_asset != asset
        or metadata.get("decimals") != selection["assetDecimals"]
        # §9.5.7.1: a Solana adapter names the token program owning the mint.
        or network.startswith("solana:") and not (
            isinstance(metadata.get("tokenProgram"), str) and metadata["tokenProgram"] in TOKEN_PROGRAMS)
    ):
        return "fail", "asset-metadata"
    # XN-5: the adapter's trusted metadata names the currency the asset
    # denominates, so a relabelled price and selection cannot pass.
    if metadata.get("currency") != selection["currency"]:
        return "fail", "asset-currency"
    try:
        amount = selection_amount(price, selection)
    except (TypeError, ValueError):
        return "fail", "exact-amount"
    matches = []
    for candidate in accepts:
        if not isinstance(candidate, dict):
            return "error", "accepts-shape"
        if (
            resource_url == request["url"]
            and candidate.get("scheme") == selection["scheme"]
            and candidate.get("network") == selection["network"]
            and candidate.get("maxTimeoutSeconds") == selection["maxTimeoutSeconds"]
            and isinstance(candidate.get("extra"), dict)
            and candidate.get("amount") == amount
        ):
            try:
                if (
                    adapter_address(network, candidate.get("asset")) == asset
                    and jcs_canonicalize(comparable_extra(network, candidate["extra"])) == signed_extra
                    and adapter_address(network, candidate.get("payTo")) == pay_to
                ):
                    matches.append(candidate)
            except ValueError:
                return "error", "address-form"
    if len(matches) != 1:
        return "fail", "challenge-match"
    # XN-6: every member of the matched `extra` and of `extensions` is
    # classified before signing. The complete `extensions` object itself is
    # bound above by JCS equality with the signed `paymentRequiredExtensions`.
    defect = challenge_member_defect(network, matches[0]["extra"], required.get("extensions", {}))
    if defect is not None:
        return defect

    # XN-11/§9.5.7.1: an EIP-3009 authorization is signed only once its
    # `validBefore` is retained as a safe integer, so a later reconciliation
    # can prove its expiry. A handler without one makes no wallet call.
    if (
        operation == "execute"
        and network.startswith("eip155:")
        and not is_safe_nonnegative(retained_valid_before(v))
    ):
        return "error", "authorization-valid-before"

    # XN-6: validate the envelope and every to-be-signed authorization field
    # before asking the wallet. The payer-control gate already validated payer.
    payer = adapter_address(network, runtime["payer"]["paymentAddress"])
    if operation == "execute" and payment_payload_defect(
        v, required, matches[0], network, payer, pay_to, before_signing=True
    ):
        return "fail", "paid-request-payload"

    # This is the sole authorization site in the executable reference path.
    # Every gate above is therefore mechanically pre-authorization; retry
    # returns through the reconciliation branch and a verifier never gets here.
    if operation == "execute":
        record_wallet_authorization(effects)

    # A defect only observable after signing (including the signature's form)
    # is the handler's fault, recorded separately from the ledger disposition.
    # A verifier judges the stored record, not the `PAYMENT-SIGNATURE` value, so
    # it skips this; the paid request's other gates above still apply to it.
    payload_fault = operation == "execute" and payment_payload_defect(
        v, required, matches[0], network, payer, pay_to)
    if payload_fault and effects is not None:
        effects["handlerFault"] = "paid-request-payload"
        effects["handlerErrorClass"] = FAILURE_MODE_ERROR_CLASSES["paid-request-payload"]
    # A response defect is the seller's protocol fault: it is returned as the
    # reason beside the verdict and never replaces it.
    response, response_fault = read_settlement_response(
        http.get("responseHeader"), version, network, payer
    )
    ledger = v.get("ledger")

    if operation == "verify-evidence":
        # XN-8: the verdict on the stored record. Its own defects need no
        # ledger data; then the ledger must prove the event the record names.
        defect, record = check_record(v, required, response, response_fault, selection, request)
        if defect is not None:
            return defect
        verdict, reason, event = reconcile_settlement(
            ledger, selection, amount, payer, pay_to, authorization_identity=retained_solana_identity(v))
        if verdict != "pass":
            return verdict, reason
        return record_ledger_defect(record, event) or ("pass", record["responseFault"])

    # XN-11: the payment disposition comes only from reconciling the
    # authorization identity against authenticated ledger data. It needs no
    # success record, and no response material or stored record can replace it.
    verdict, reason, event = reconcile_settlement(
        ledger, selection, amount, payer, pay_to, retained_valid_before(v), retained_solana_identity(v)
    )
    if verdict != "pass":
        return verdict, reason
    # The exact finalized settlement stands. A response naming another
    # transaction than the reconciled one is a response defect (XN-7).
    if response_fault is None and adapter_canonical_transaction(
        network, response.get("transaction")
    ) != event["transaction"]:
        response_fault = "response-transaction"
    # The evidence is built from the reconciled event, keeping a sound
    # response's transaction spelling.
    build_evidence(effects, event, response["transaction"] if response_fault is None else None)
    # A stored record that a verifier would reject is rebuilt from the
    # retained challenge, response and reconciled event, unless it is already
    # anchored; its defect is the recorded reason, never the outcome.
    defect = None
    if "evidence" in v:
        defect = stored_record_defect(v, required, response, response_fault, selection, request, event)
        keep_anchored_record(v, effects, defect)
    if payload_fault:
        return "pass", "paid-request-payload"
    if response_fault is not None:
        return "pass", response_fault
    return "pass", defect and defect[1]


def legacy_receipt_defect(header, ref):
    """X402-1..X402-4: the reason a legacy response does not verify against its record, if any.

    X402-1: the version-selected header decodes to that version's successful
    SettlementResponse, which names its `transaction` and `network`
    (`legacy-response`). X402-2/X402-4: the stored `paymentReceiptHash` is
    canonical and equals the recomputed NFC/JCS hash (`legacy-receipt-hash`).
    X402-3: the `transaction` equals a recorded `settlementTxHash`
    (`legacy-receipt-transaction`), and the `network` maps to a recorded
    `chainId` (`legacy-receipt-network`): v2 by `eip155:{chainId}`, v1 through
    the registered v1 mapping, under which a network it does not name maps to
    no chain.
    """
    version = ref["protocolVersion"]
    wanted = {"1": "X-PAYMENT-RESPONSE", "2": "PAYMENT-RESPONSE"}.get(version)
    if wanted is None or not isinstance(header, dict) or header.get("name") != wanted:
        return "legacy-response"
    try:
        response = admit_raw_json(base64.b64decode(header.get("value"), validate=True))
    except (TypeError, ValueError):
        return "legacy-response"
    if not (
        isinstance(response, dict)
        and response.get("success") is True
        and isinstance(response.get("transaction"), str)
        and isinstance(response.get("network"), str)
    ):
        return "legacy-response"
    stored = ref.get("paymentReceiptHash")
    if not (isinstance(stored, str) and HEX_32.fullmatch(stored)) or digest(response) != stored:
        return "legacy-receipt-hash"
    if "settlementTxHash" in ref and response["transaction"] != ref["settlementTxHash"]:
        return "legacy-receipt-transaction"
    if "chainId" in ref:
        if version == "2":
            mapped = response["network"] == f"eip155:{ref['chainId']}"
        else:
            mapped = X402_V1_NETWORK_CHAIN_IDS.get(response["network"]) == ref["chainId"]
        if not mapped:
            return "legacy-receipt-network"
    return None


def retained_valid_before(v):
    """XN-11: the retained EIP-3009 `validBefore`, or None if none is retained."""
    retained = v.get("runtime", {}).get("reconciliationState")
    return retained.get("validBefore") if isinstance(retained, dict) else None


class X402NegotiatedProtocolVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.raw_vectors = cls.data["vectors"]
        cls.vectors = [materialize_vector(cls.data, item) for item in cls.raw_vectors]
        cls.by_name = {item["name"]: item for item in cls.vectors}

    def test_generated_file_is_current(self):
        result = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"], cwd=ROOT,
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_hash_count_and_names_are_exact(self):
        vectors = self.raw_vectors
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(len(vectors), len(self.by_name))
        encoded = json.dumps(
            vectors, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        self.assertEqual(self.data["hash"], hashlib.sha256(encoded).hexdigest())

    def test_set_identifier_names_the_dacs4_module_version(self):
        """The unreleased corpus carries the DACS-4 version whose XN rules it pins."""
        spec = (ROOT / "spec/DACS-4-SETTLE.md").read_text(encoding="utf-8")
        version = re.search(r"\*\*Status:\*\* Draft — \*\*DACS-4 (v0\.\d+)\*\*", spec).group(1)
        self.assertEqual(self.data["set"], f"x402-negotiated-protocol-{version}")
        self.assertEqual(VECTORS.stem, self.data["set"])

    def test_buyer_bundle_and_native_payment_key_proofs_are_cryptographic(self):
        generator_public_key = bytes.fromhex(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        )
        self.assertEqual(
            evm_address(generator_public_key),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
        )
        for name in ("protocol-v2-exact-success", "protocol-v2-solana-exact-success"):
            with self.subTest(vector=name):
                vector = self.by_name[name]
                self.assertTrue(verify_buyer_bundle_presentation(vector))
                buyer = next(
                    party for party in vector["agreement"]["parties"]
                    if party["role"] == "buyer"
                )
                selection = vector["agreement"]["terms"]["rail"]["parameters"]["selection"]
                self.assertTrue(buyer_payment_control(vector, buyer, selection))
                self.assertEqual(
                    buyer["bundleHash"],
                    digest(buyer_bundle_scope(vector["buyerBundle"])),
                )

        tampered = copy.deepcopy(self.by_name["protocol-v2-exact-success"])
        signature = tampered["buyerBundle"]["presentation"]["signatures"][1]["signature"]
        tampered["buyerBundle"]["presentation"]["signatures"][1]["signature"] = (
            ("A" if signature[0] != "A" else "B") + signature[1:]
        )
        self.assertEqual(evaluate(tampered), ("fail", "signature"))

    def test_every_vector_executes_to_pinned_verdict(self):
        for vector in self.vectors:
            with self.subTest(vector=vector["name"]):
                actual, reason = evaluate(vector)
                self.assertEqual(actual, vector["expected"])
                if "expectedReason" in vector:
                    self.assertEqual(reason, vector["expectedReason"])
                if "expectedErrorClass" in vector:
                    self.assertEqual(FAILURE_MODE_ERROR_CLASSES.get(reason), vector["expectedErrorClass"])

    def test_published_legacy_replacement_has_the_xn10_values(self):
        """XN-10: the superseding x402:default revision the corpus refuses is the steward's
        signed disabled, deprecated definition pointing new sessions at x402:protocol."""
        vector = self.by_name["legacy-default-new-session-disabled"]
        rail = vector["railDefinition"]
        self.assertTrue(verify_signature(
            vector["keys"]["steward"], "dacs-rail:v1:",
            {name: value for name, value in rail.items() if name != "signature"},
            rail["signature"]["value"]))
        self.assertEqual((rail["railId"], rail["railVersion"], rail["availability"]),
                         ("x402:default", 2, "disabled"))
        governance = rail["governance"]
        self.assertEqual((governance["supersedes"], governance["deprecated"]), (1, True))
        self.assertIn("x402:protocol", governance["deprecationReason"])
        self.assertEqual(evaluate(copy.deepcopy(vector)), ("fail", "legacy-default-new-session"))

    def test_generator_check_fails_on_a_stale_file(self):
        """CI's determinism gate: --check exits 1 when the committed file differs."""
        sys.path.insert(0, str(ROOT / "scripts"))
        try:
            import generate_x402_negotiated_protocol_vectors as generator
        finally:
            sys.path.remove(str(ROOT / "scripts"))
        stale = VECTORS.read_text(encoding="utf-8").replace('"count": ', '"count": 1', 1)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / VECTORS.name
            output.write_text(stale, encoding="utf-8")
            with mock.patch.object(generator, "OUTPUT", output), \
                    mock.patch.object(sys, "argv", ["generator", "--check"]), \
                    mock.patch("builtins.print"):
                self.assertEqual(generator.main(), 1)
            # The committed file itself is current.
            output.write_text(VECTORS.read_text(encoding="utf-8"), encoding="utf-8")
            with mock.patch.object(generator, "OUTPUT", output), \
                    mock.patch.object(sys, "argv", ["generator", "--check"]), \
                    mock.patch("builtins.print"):
                self.assertEqual(generator.main(), 0)

    def test_failure_mode_error_classes_are_pinned(self):
        """§9.5.7 failure modes: each execute result the list names carries its errorClass.

        So booking an unsupported capability or member as the seller's
        `counterparty` fault, or a malformed challenge as `permanent`, fails.
        """
        pinned = 0
        for vector in self.vectors:
            if vector["operation"] != "execute" or vector["expected"] == "pass":
                continue
            reason = vector.get("expectedReason")
            with self.subTest(vector=vector["name"]):
                if reason in FAILURE_MODE_ERROR_CLASSES:
                    pinned += 1
                    self.assertEqual(vector.get("expectedErrorClass"), FAILURE_MODE_ERROR_CLASSES[reason])
                else:
                    self.assertNotIn("expectedErrorClass", vector)
        by_reason = {}
        for vector in self.vectors:
            if "expectedErrorClass" in vector:
                by_reason.setdefault(vector["expectedReason"], set()).add(vector["expectedErrorClass"])
        self.assertEqual(by_reason["x402-capability-unsupported"], {"permanent"})
        self.assertEqual(by_reason["unclassified-extra-member"], {"permanent"})
        self.assertEqual(by_reason["challenge-match"], {"counterparty"})
        self.assertEqual(by_reason["unpaid-request-transient"], {"transient"})
        self.assertEqual(by_reason["paid-request-payload"], {"permanent"})
        self.assertEqual(pinned, 154)

    def test_resolution_inputs_are_inside_real_agreement_signatures(self):
        original = self.by_name["protocol-v2-exact-success"]
        self.assertEqual(evaluate(original)[0], "pass")
        mutations = (
            (("terms", "rail", "parameters", "request", "url"), "https://attacker.example/pay"),
            (("terms", "rail", "parameters", "request", "method"), "POST"),
            (("terms", "rail", "parameters", "request", "bodyHash"), "00" * 32),
            (("terms", "rail", "parameters", "selection", "x402Version"), 1),
            (("terms", "rail", "parameters", "selection", "scheme"), "upto"),
            (("terms", "rail", "parameters", "selection", "network"), "eip155:1"),
            (("terms", "rail", "parameters", "selection", "asset"), "0x" + "99" * 20),
            (("terms", "rail", "parameters", "selection", "assetDecimals"), 18),
            (("terms", "rail", "parameters", "selection", "currency"), "USDT"),
            (("terms", "rail", "parameters", "selection", "maxTimeoutSeconds"), 61),
            (("terms", "rail", "parameters", "selection", "extra"), {"spender": "attacker"}),
            (("terms", "rail", "parameters", "paymentRequiredExtensions", "payment-identifier", "required"), False),
            (("terms", "price", "amount"), "1.26"),
            (("terms", "payoutBindings", 0, "payeeAddress"), "0x" + "99" * 20),
        )
        for path, value in mutations:
            mutated = copy.deepcopy(original)
            target = mutated["agreement"]
            for segment in path[:-1]:
                target = target[segment]
            target[path[-1]] = value
            with self.subTest(path=path):
                self.assertEqual(evaluate(mutated), ("fail", "signature"))

    def test_pre_authorization_failures_never_reach_wallet_use(self):
        pre_authorization = (
            "definition-hybrid-static-asset",
            "definition-global-resource-url",
            "definition-global-provider-allowlist",
            "definition-global-operator-credential",
            "listing-duplicate-canonical-ref",
            "runtime-first-matching-railid",
            "agreement-ref-not-full-jcs-member",
            "protocol-legacy-agreement-artifact",
            "unsigned-runtime-url-override",
            "lowercase-request-method",
            "non-https-request-url",
            "bounded-fetch-localhost-target",
            "bounded-fetch-ipv4-loopback-target",
            "bounded-fetch-ipv4-private-target",
            "bounded-fetch-ipv4-link-local-metadata-target",
            "bounded-fetch-ipv4-link-local-only-target",
            "bounded-fetch-ipv6-loopback-target",
            "bounded-fetch-ipv4-multicast-target",
            "bounded-fetch-ipv4-multicast-ssdp-target",
            "bounded-fetch-ipv6-multicast-target",
            "bounded-fetch-ipv4-shared-address-target",
            "bounded-fetch-ipv4-unspecified-target",
            "bounded-fetch-ipv4-reserved-target",
            "bounded-fetch-ipv4-broadcast-target",
            "bounded-fetch-ipv6-aws-imds-metadata-target",
            "bounded-fetch-ipv6-unique-local-target",
            "bounded-fetch-ipv4-mapped-loopback-target",
            "bounded-fetch-ipv4-mapped-metadata-target",
            "bounded-fetch-ipv4-mapped-multicast-target",
            "bounded-fetch-ipv4-shorthand-loopback-target",
            "bounded-fetch-ipv4-integer-loopback-target",
            "bounded-fetch-ipv4-hex-loopback-target",
            "bounded-fetch-ipv4-octal-loopback-target",
            "bounded-fetch-ipv4-trailing-dot-loopback-target",
            "bounded-fetch-ipv4-shorthand-metadata-target",
            "bounded-fetch-ipv4-invalid-numeric-host-target",
            "bounded-fetch-ipv4-double-hex-prefix-invalid-host-target",
            "request-url-host-soft-hyphen-loopback",
            "request-url-host-zero-width-space-loopback",
            "request-url-host-encoded-soft-hyphen-loopback",
            "request-url-host-soft-hyphen-metadata",
            "request-url-backslash-authority-loopback",
            "request-url-backslash-authority-metadata",
            "request-url-percent-encoded-localhost",
            "request-url-full-width-localhost",
            "request-url-idn-u-label-host",
            "request-url-percent-encoded-ipv4-loopback",
            "request-url-empty-userinfo",
            "request-url-empty-userinfo-password",
            "request-url-empty-fragment",
            "request-url-port-not-decimal",
            "request-url-port-out-of-range",
            "request-url-empty-a-label",
            "request-url-fake-a-label-localhost",
            "request-url-fake-a-label-upper-case",
            "request-url-over-long-a-label",
            "request-url-a-label-tangut-joiner",
            "request-url-backslash-in-path",
            "request-url-non-ascii-path",
            "request-url-del",
            "bare-network-label",
            "numeric-version-replaced-by-string",
            "negative-asset-decimals",
            "unsupported-local-capability",
            "counterparty-operator-config",
            "non-402-response-before-authorization",
            "unpaid-request-not-found-404",
            "unpaid-request-server-error-500",
            "unpaid-request-service-unavailable-503",
            "unpaid-request-gateway-timeout-504",
            "unpaid-request-timeout-408",
            "unpaid-request-rate-limited-429",
            "unpaid-request-no-answer",
            "challenge-resource-substitution",
            "challenge-duplicate-exact-accepts",
            "challenge-network-substitution",
            "challenge-asset-substitution",
            "challenge-timeout-substitution",
            "challenge-amount-substitution",
            "challenge-payto-substitution",
            "challenge-extra-substitution",
            "challenge-extension-substitution",
            "challenge-extension-absent-vs-empty",
            "payment-identifier-required",
            "redirected-payable-resource",
            "body-sent-without-signed-hash",
            "asset-decimals-adapter-mismatch",
            "agreement-price-excess-precision",
            "agreement-price-rounded-by-decimal-context",
            "exact-amount-above-uint256-limit",
            "solana-exact-amount-above-u64-limit",
            "asset-decimals-above-uint8-limit",
            "runtime-payer-not-agreement-buyer",
            "runtime-paying-key-not-buyer-controlled",
            "runtime-payer-address-not-derived-from-paying-key",
            "runtime-payee-not-signed-destination",
            "challenge-payto-substitution-mixed-case",
            "challenge-payto-not-20-bytes",
            "payout-binding-not-20-bytes",
            "payout-binding-not-20-bytes-runtime-payee-valid",
            "runtime-payer-not-20-bytes",
            "runtime-payee-not-20-bytes-binding-valid",
            "solana-challenge-payto-case-changed",
            "upto-has-no-dacs-success-profile",
            "batch-commitment-is-not-financial-settlement",
            "legacy-default-new-session-disabled",
            "legacy-default-pinned-live-new-session",
            "selection-asset-not-20-bytes",
            "asset-metadata-asset-not-20-bytes",
            "challenge-asset-not-20-bytes",
            "challenge-verifying-contract-not-20-bytes",
            "selection-verifying-contract-not-20-bytes",
            "bounded-fetch-isatap-loopback-target",
            "bounded-fetch-isatap-universal-bit-metadata-target",
            "request-method-substitution",
            "unsigned-runtime-method-override",
            "unpaid-request-method-substitution",
            "paid-request-method-substitution",
            "unpaid-request-url-substitution",
            "paid-request-url-substitution",
            "unsigned-runtime-body-override",
            "unpaid-request-body-substitution",
            "paid-request-body-substitution",
            "payment-identifier-schema-not-pinned",
            "unclassified-payment-requirements-extra",
            "unclassified-top-level-extension",
            "unclassified-extension-listed-as-understood",
            "solana-extra-carries-verifying-contract",
            "challenge-verifying-contract-eip55-selection-lower-case",
            "selection-verifying-contract-eip55-challenge-lower-case",
            "erc7710-transfer-method-has-no-v08-binding",
            "solana-extra-carries-mint",
            "solana-extra-carries-eip155-transfer-method",
            "eip155-extra-carries-solana-fee-payer",
            "definition-railversion-2-ref-pins-1",
            "definition-railversion-1-ref-pins-2",
            "v1-selection-outside-v08-profile",
            "selection-max-timeout-seconds-zero",
            "payment-required-extensions-array",
            "execute-definition-rail-id-substituted",
            "execute-definition-rail-type-substituted",
            "execute-definition-phase-handler-substituted",
            "execute-definition-resolution-substituted",
            "execute-definition-rail-version-zero",
            "agreement-signature-unused-bits-set",
            "selection-extra-array",
            "signed-request-url-not-a-string",
        )
        for name in pre_authorization:
            with self.subTest(vector=name):
                effects = {"walletAuthorizationCalls": 0}
                evaluate(self.by_name[name], effects)
                self.assertEqual(effects["walletAuthorizationCalls"], 0)

    def test_every_execute_vector_calls_the_wallet_only_past_the_gates(self):
        """Every execute vector, including ones added later, makes exactly the calls it declares.

        `authorizationSubmitted` is the generator's declaration; the count comes
        from the evaluator's one instrumented wallet-call site.
        """
        for vector in self.vectors:
            if vector["operation"] != "execute":
                continue
            with self.subTest(vector=vector["name"]):
                effects = {}
                evaluate(copy.deepcopy(vector), effects)
                want = 1 if vector["runtime"]["authorizationSubmitted"] else 0
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), want)

    def test_paying_key_proof_uses_the_network_native_algorithm(self):
        """XN-5: an EVM payer is proven by secp256k1 and a Solana payer by Ed25519.

        The presentation check already ties each claim to its declared algorithm,
        so this calls buyer_payment_control directly with a claim that names the
        other algorithm over the right key bytes.
        """
        for name, wrong in (("protocol-v2-exact-success", "ed25519"),
                            ("protocol-v2-solana-exact-success", "ecdsa-secp256k1")):
            with self.subTest(vector=name):
                vector = copy.deepcopy(self.by_name[name])
                buyer = next(p for p in vector["agreement"]["parties"] if p["role"] == "buyer")
                selection = vector["agreement"]["terms"]["rail"]["parameters"]["selection"]
                self.assertTrue(buyer_payment_control(vector, buyer, selection))
                vector["buyerBundle"]["claims"][1]["metadata"]["algorithm"] = wrong
                bundle_hash = digest(buyer_bundle_scope(vector["buyerBundle"]))
                buyer["bundleHash"] = vector["runtime"]["payer"]["bundleHash"] = bundle_hash
                self.assertFalse(buyer_payment_control(vector, buyer, selection))

    def test_received_challenge_objects_follow_the_cf5_profile(self):
        """XN-7/CF-5: a challenge passed as an object is held to the same profile.

        Values JSON text cannot carry (NaN, infinity, an integer beyond 2^53-1, a
        lone surrogate) are `error` before authorization, never an exception from
        a later hash; so are a raw and an object challenge received together.
        """
        base = self.by_name["protocol-v2-exact-success"]
        for label, place in (
            ("nan in extra", lambda r: r["accepts"][0]["extra"].update({"fee": float("nan")})),
            ("infinity in extensions", lambda r: r["extensions"].update({"fee": float("inf")})),
            ("2^53 in extra", lambda r: r["accepts"][0]["extra"].update({"fee": 2**53})),
            ("lone surrogate in extensions", lambda r: r["extensions"].update({"memo": "\ud800"})),
            ("lone surrogate in a member name", lambda r: r["extensions"].update({"\udfff": 1})),
        ):
            with self.subTest(case=label):
                vector = copy.deepcopy(base)
                place(vector["http"]["paymentRequired"])
                effects = {}
                self.assertEqual(evaluate(vector, effects), ("error", "payment-required-json"))
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)
        both = copy.deepcopy(self.by_name["challenge-raw-json-admitted"])
        self.assertEqual(evaluate(copy.deepcopy(both)), ("pass", None))
        both["http"]["paymentRequired"] = copy.deepcopy(base["http"]["paymentRequired"])
        self.assertEqual(evaluate(both), ("error", "payment-required-json"))

    def test_authorization_counter_distinguishes_pre_and_post_authorization(self):
        for name, want in (
            ("protocol-v2-exact-success", 1),
            ("ledger-unavailable-after-submission", 1),
            ("challenge-resource-substitution", 0),
        ):
            with self.subTest(vector=name):
                effects = {"walletAuthorizationCalls": 0}
                evaluate(self.by_name[name], effects)
                self.assertEqual(effects["walletAuthorizationCalls"], want)

    def test_retry_reconciliation_never_calls_wallet(self):
        names = (
            "retry-indeterminate-remains-pending",
            "retry-caller-reauthorization-request-is-ignored",
            "retry-job-binding-mismatch",
            "retry-phase-binding-mismatch",
            "retry-requirement-binding-mismatch",
            "retry-authorization-binding-mismatch",
            "retry-record-transaction-substitution-settled",
            "retry-retained-transaction-spelling-reconciles",
            "retry-identical-malformed-transaction-settled",
            "retry-record-malformed-transaction-ledger-unavailable",
            "retry-authorization-identity-eip55-reconciles",
            "retry-authorization-identity-not-20-bytes",
            "retry-solana-authorization-identity-case-changed",
            "retry-response-lost-no-transaction-known",
            "retry-response-lost-transaction-null",
            "retry-response-lost-ledger-settled",
            "retry-response-lost-authorization-cancelled",
            "retry-ledger-event-contradicts-authorization",
            "retry-retained-state-not-object",
            "retry-retained-state-extra-field",
            "retry-record-signature-invalid-settled",
            "retry-record-signature-invalid-ledger-unavailable",
            "retry-record-two-references-settled",
            "retry-record-no-reference-settled",
            "retry-record-names-another-transaction-settled",
            "retry-record-transaction-not-32-bytes-settled",
            "retry-record-receipt-hash-not-recomputing-settled",
            "retry-retained-transaction-not-reconciled-settled",
            "retry-response-lost-ledger-transaction-missing",
            "retry-response-lost-ledger-transaction-null",
            "retry-response-lost-ledger-transaction-not-32-bytes",
            "retry-response-lost-ledger-transaction-double-0x-prefix",
            "retry-response-lost-ledger-event-key-missing",
            "retry-response-lost-ledger-event-key-garbled",
            "retry-agreement-signature-invalid",
            "retry-eip3009-expiry-block-before",
            "retry-eip3009-expiry-block-equal",
            "retry-eip3009-expiry-block-after",
            "retry-eip3009-expiry-block-unavailable",
            "retry-eip3009-expiry-block-malformed",
            "retry-eip3009-expiry-without-retained-valid-before",
            "retry-eip3009-nonce-state-unknown",
            "retry-eip3009-retained-valid-before-decimal-string",
            "retry-eip3009-retained-valid-before-unsafe",
            "retry-eip3009-retained-valid-before-boolean",
            "retry-eip3009-expiry-not-final",
            "retry-record-payment-amount-inflated-rebuilt",
            "retry-anchored-record-defect-manual-recovery",
            "retry-definition-other-revision",
            "retry-definition-legacy-arm",
            "retry-definition-malformed",
            "retry-facilitator-switched",
            "retry-retained-facilitator-absent",
            "retry-static-arm-ref",
            "retry-solana-response-lost-settled",
            "retry-solana-substituted-transaction",
            "retry-solana-identity-lookup-unavailable",
            "retry-solana-response-lost-unsettled",
            "retry-solana-resolved-other-sponsor",
            "retry-solana-resolved-other-payer",
        )
        names += tuple(f"retry-record-{member}-not-string-{shape}"
                       for member in ("paymentRequiredHash", "paymentReceiptHash")
                       for shape in ("number", "null", "list", "object"))
        names += tuple(f"retry-record-{defect}-rebuilt" for defect in (
            "payment-amount-extra-member", "finality-scheme-other", "finality-binding-profile-absent",
            "finality-binding-profile-not-string", "finality-profile-absent"))
        self.assertEqual(set(names),{v["name"] for v in self.vectors if v["operation"] == "retry"})
        for name in names:
            with self.subTest(vector=name):
                effects = {"walletAuthorizationCalls": 0}
                evaluate(self.by_name[name], effects)
                self.assertEqual(effects["walletAuthorizationCalls"], 0)

    def test_retry_after_response_loss_needs_no_known_transaction(self):
        """XN-11: "any known" transaction; an unknown one (absent or null) still reconciles."""
        pending = ("indeterminate", "independent-settlement-unavailable")
        for name in ("retry-response-lost-no-transaction-known",
                     "retry-response-lost-transaction-null"):
            with self.subTest(vector=name):
                vector = self.by_name[name]
                self.assertNotIn("evidence", vector)
                self.assertIsNone(vector["runtime"]["reconciliationState"].get("settlementTransaction"))
                self.assertEqual(evaluate(copy.deepcopy(vector)), pending)
        base = self.by_name["retry-indeterminate-remains-pending"]
        lost = self.by_name["retry-response-lost-no-transaction-known"]
        defect = ("pass", "response-transaction")
        for label, source, retained_tx, want, settled in (
            # Evidence records a transaction; the retained state knows none.
            ("recorded only", base, "<absent>", pending, ("pass", None)),
            ("recorded only, retained null", base, None, pending, ("pass", None)),
            # The retained state knows one; nothing is recorded yet.
            ("retained only", lost, "0x" + "ab" * 32, pending, ("pass", None)),
            ("retained only, other spelling", lost, "AB" * 32, pending, ("pass", None)),
            # A known value is the response's: with no adapter form, or naming
            # another transaction, it is a recorded defect and never decides.
            ("retained only, malformed", lost, "not-a-hash", pending, defect),
            ("retained empty string", lost, "", pending, defect),
            ("retained not a string", lost, 7, pending, defect),
            ("retained other transaction", lost, "0x" + "cd" * 32, pending, defect),
        ):
            for available, expected in ((False, want), (True, settled)):
                with self.subTest(case=label, ledger_available=available):
                    vector = copy.deepcopy(source)
                    vector["ledger"]["available"] = available
                    state = vector["runtime"]["reconciliationState"]
                    if retained_tx == "<absent>":
                        state.pop("settlementTransaction", None)
                    else:
                        state["settlementTransaction"] = retained_tx
                    effects = {}
                    self.assertEqual(evaluate(vector, effects), expected)
                    self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)
        self.assertEqual(evaluate(copy.deepcopy(
            self.by_name["retry-retained-transaction-spelling-reconciles"])), ("pass", None))
        # Another identity value still has to match without a transaction.
        vector = copy.deepcopy(lost)
        vector["runtime"]["reconciliationState"]["phaseIndex"] = 4
        self.assertEqual(evaluate(vector), ("fail", "reconciliation-binding"))

    def test_response_defects_never_decide_the_outcome(self):
        """XN-11: after authorization the ledger decides; a response defect is the recorded fault."""
        success_ledger = self.by_name["protocol-v2-exact-success"]["ledger"]
        for name, fault in (
            ("wrong-version-response-header", "response-header"),
            ("response-header-value-not-string", "response-header"),
            ("response-not-success", "response-not-success"),
            ("response-network-substitution", "response-network"),
            ("response-transaction-substitution", "response-transaction"),
            ("response-transaction-not-32-bytes", "response-transaction"),
            ("response-payer-substitution", "response-payer"),
        ):
            with self.subTest(vector=name):
                vector = self.by_name[name]
                self.assertEqual(vector["ledger"], success_ledger)
                effects = {}
                self.assertEqual(evaluate(copy.deepcopy(vector), effects), ("pass", fault))
                self.assertEqual(effects["walletAuthorizationCalls"], 1)
                twin = self.by_name[f"{name}-no-settlement"]
                self.assertNotIn("ledger", twin)
                effects = {}
                self.assertEqual(evaluate(copy.deepcopy(twin), effects),
                                 ("indeterminate", "independent-settlement-unavailable"))
                self.assertEqual(effects["walletAuthorizationCalls"], 1)
                # A contradiction the ledger itself resolves is still `fail`.
                contradicted = copy.deepcopy(vector)
                contradicted["ledger"]["amount"] = "1249999"
                self.assertEqual(evaluate(contradicted), ("fail", "ledger-event"))
        # With no decoded response the receipt commits to JSON null (XN-7).
        for name in ("wrong-version-response-header", "response-header-value-not-string"):
            ref = self.by_name[name]["evidence"]["paymentTxRefs"][0]
            self.assertEqual(ref["paymentReceiptHash"], digest(None))
        # XN-8: only an event resolved for the authorization identity can
        # contradict it; a transaction that only the response names cannot.
        for name, want in (
            ("response-transaction-substitution-ledger-event-contradicts", ("fail", "ledger-event")),
            ("response-transaction-substitution-no-ledger-event",
             ("indeterminate", "authorization-unsettled")),
        ):
            with self.subTest(vector=name):
                vector = self.by_name[name]
                response = decode_response_header(vector["http"]["responseHeader"], 2)
                self.assertEqual(response["transaction"], "0x" + "cd" * 32)
                effects = {}
                self.assertEqual(evaluate(copy.deepcopy(vector), effects), want)
                self.assertEqual(effects["walletAuthorizationCalls"], 1)

    def test_sb3_policy_comes_from_the_pinned_definition_not_the_observed_event(self):
        """XN-9/SB-3: EIP-155 exact always needs the job binding; the event's form cannot waive it."""
        base = self.by_name["protocol-v2-exact-success"]
        self.assertEqual(base["ledger"]["sessionBinding"], {"state": "match"})
        for authorization in ("eip-3009", "permit2", "erc20-transfer", "something-else", None):
            for binding, want in (
                ({"state": "match"}, ("pass", None)),
                ({"state": "mismatch"}, ("fail", "sb3")),
                ({"state": "absent"}, ("indeterminate", "sb3")),
                ({"state": "unavailable-rpc"}, ("indeterminate", "sb3")),
                ({"state": "unavailable-pruned-history"}, ("indeterminate", "sb3")),
                ({"state": "unavailable-signature-authority"}, ("indeterminate", "sb3")),
                ({"state": "unavailable-reorged"}, ("indeterminate", "sb3")),
                ({"state": "unavailable"}, ("error", "sb3")),
                ({"state": "malformed"}, ("error", "sb3")),
                ({"state": "match", "observedAt": 1}, ("error", "sb3")),
                ({"state": 7}, ("error", "sb3")),
                ({}, ("error", "sb3")),
                ("match", ("error", "sb3")),
            ):
                with self.subTest(authorization=authorization, binding=binding):
                    vector = copy.deepcopy(base)
                    vector["ledger"]["authorization"] = authorization
                    vector["ledger"]["sessionBinding"] = binding
                    self.assertEqual(evaluate(vector), want)
        # Solana's exact binding declares no job binding, so nothing is consulted.
        vector = copy.deepcopy(self.by_name["protocol-v2-solana-exact-success"])
        vector["ledger"].pop("sessionBinding")
        self.assertEqual(evaluate(vector), ("pass", None))

    def test_sb3_states_follow_the_binding_required_set(self):
        """Every required-binding evidence value of the SB-3 set reaches the same branch here."""
        corpus = json.loads((ROOT / "conformance/vectors/security/sb3-binding-required-v0.8.json")
                            .read_text(encoding="utf-8"))
        base = self.by_name["protocol-v2-exact-success"]
        checked = 0
        for case in corpus["vectors"]:
            inputs = case["protocolInput"]
            if (case["trustedContext"].get("resolvedRailProfile") != "x402-eip3009-binding-v0.8"
                    or inputs.get("unboundTransferChecks") != "match"
                    or case["want"]["usedUnboundPosture"]):
                continue
            with self.subTest(sb3_vector=case["name"]):
                vector = copy.deepcopy(base)
                if "bindingEvidence" in inputs:
                    vector["ledger"]["sessionBinding"] = copy.deepcopy(inputs["bindingEvidence"])
                else:
                    vector["ledger"].pop("sessionBinding")
                effects = {}
                verdict, reason = evaluate(vector, effects)
                self.assertEqual(verdict, case["expected"])
                self.assertEqual(reason, None if verdict == "pass" else "sb3")
                self.assertEqual(effects["walletAuthorizationCalls"], 1)
                checked += 1
        self.assertGreaterEqual(checked, 12)

    def test_payment_disposition_never_comes_from_a_record_or_the_response(self):
        """XN-11: after the wallet call the verdict is the ledger reconciliation's alone.

        Every execute vector that reaches the wallet call has exactly the
        reconciliation verdict. Removing the record or response changes at
        most the reason.
        """
        reached = 0
        for vector in self.vectors:
            if vector["operation"] != "execute":
                continue
            effects = {}
            verdict = evaluate(copy.deepcopy(vector), effects)[0]
            if not effects.get("walletAuthorizationCalls"):
                continue
            reached += 1
            selection, amount, payer, pay_to = reconciliation_terms(vector)
            with self.subTest(vector=vector["name"], change="ledger disposition"):
                self.assertEqual(verdict, reconcile_settlement(
                    vector.get("ledger"), selection, amount, payer, pay_to,
                    retained_valid_before(vector), retained_solana_identity(vector))[0])
            for label, strip in (("no record", ("evidence",)), ("no response", ("http", "responseHeader"))):
                with self.subTest(vector=vector["name"], change=label):
                    changed = copy.deepcopy(vector)
                    target = changed
                    for segment in strip[:-1]:
                        target = target[segment]
                    target.pop(strip[-1], None)
                    effects = {}
                    self.assertEqual(evaluate(changed, effects)[0], verdict)
                    self.assertEqual(effects["walletAuthorizationCalls"], 1)
        self.assertGreaterEqual(reached, 75)
        # A retry is judged the same way: neither the stored record, nor the
        # retained response, nor the retained transaction changes its verdict.
        retries = [v for v in self.vectors if v["operation"] == "retry"]
        self.assertGreaterEqual(len(retries), 34)
        for vector in retries:
            verdict = evaluate(copy.deepcopy(vector))[0]
            for label, strip in (("no record", ("evidence",)),
                                 ("no response", ("http", "responseHeader")),
                                 ("no retained transaction",
                                  ("runtime", "reconciliationState", "settlementTransaction"))):
                with self.subTest(vector=vector["name"], change=label):
                    changed = copy.deepcopy(vector)
                    target = changed
                    for segment in strip[:-1]:
                        target = target[segment] if isinstance(target, dict) else {}
                    if isinstance(target, dict):
                        target.pop(strip[-1], None)
                    effects = {}
                    self.assertEqual(evaluate(changed, effects)[0], verdict)
                    self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)
        # Every stored-record verdict a verifier gives leaves the payment to the
        # ledger, after the wallet call and on retry alike.
        records = [v for v in self.vectors if v["operation"] == "verify-evidence"]
        self.assertEqual(len(records), 60)
        for vector in records:
            for operation in ("execute", "retry"):
                with self.subTest(record=vector["name"], operation=operation):
                    judged = copy.deepcopy(vector)
                    judged["operation"] = operation
                    bare = copy.deepcopy(judged)
                    bare.pop("evidence")
                    self.assertEqual(evaluate(judged)[0], evaluate(bare)[0])

    def test_response_loss_reconciles_against_the_ledger(self):
        """XN-11: with no response and no evidence, execute and retry both read the ledger."""
        for name, want in (
            ("response-lost-no-evidence-settled", ("pass", "response-header")),
            ("response-lost-no-evidence-ledger-unavailable",
             ("indeterminate", "independent-settlement-unavailable")),
            ("response-lost-no-evidence-authorization-expired", ("fail", "terminal-non-settlement")),
            ("response-lost-no-evidence-authorization-unused",
             ("indeterminate", "authorization-unsettled")),
            ("retry-response-lost-ledger-settled", ("pass", None)),
            ("retry-response-lost-no-transaction-known",
             ("indeterminate", "independent-settlement-unavailable")),
            ("retry-response-lost-authorization-cancelled", ("fail", "terminal-non-settlement")),
        ):
            with self.subTest(vector=name):
                vector = self.by_name[name]
                self.assertNotIn("evidence", vector)
                effects = {}
                self.assertEqual(evaluate(copy.deepcopy(vector), effects), want)
                calls = 1 if vector["operation"] == "execute" else 0
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), calls)
        # Flipping only the ledger's availability flips the retry's disposition.
        vector = copy.deepcopy(self.by_name["retry-response-lost-no-transaction-known"])
        vector["ledger"]["available"] = True
        self.assertEqual(evaluate(vector), ("pass", None))
        # Only the finalized ledger's nonce state and block clock prove a
        # terminal EIP-3009 non-settlement; validBefore is the retained one.
        terminal, pending = ("fail", "terminal-non-settlement"), ("indeterminate", "authorization-unsettled")
        for name in ("response-lost-no-evidence-authorization-expired",
                     "retry-response-lost-authorization-cancelled"):
            valid_before = self.by_name[name]["runtime"]["reconciliationState"]["validBefore"]
            for state, offset, want in (("unused", 1, terminal), ("unused", 0, terminal),
                                        ("unused", -1, pending), ("unused", None, pending),
                                        ("cancelled", None, terminal), ("used", 1, pending),
                                        (None, 1, pending)):
                with self.subTest(vector=name, state=state, offset=offset):
                    vector = copy.deepcopy(self.by_name[name])
                    vector["ledger"] = {"available": True, "finalized": True}
                    if state is not None:
                        vector["ledger"]["nonceState"] = state
                    if offset is not None:
                        vector["ledger"]["finalizedBlockTimestamp"] = valid_before + offset
                    self.assertEqual(evaluate(vector), want)
                    vector["ledger"]["finalized"] = False
                    self.assertEqual(evaluate(vector), ("indeterminate", "settlement-not-final"))

    def test_stored_record_defects_are_rebuilt_not_decisive(self):
        """XN-7: a record that does not verify is rejected and rebuilt; the ledger decides."""
        for name, want in (
            ("response-changed-after-record-settled", ("pass", "payment-receipt-hash")),
            ("stored-challenge-hash-not-recomputing-settled", ("pass", "payment-required-hash")),
            ("stored-record-noncanonical-event-key-ledger-unavailable",
             ("indeterminate", "independent-settlement-unavailable")),
        ):
            with self.subTest(vector=name):
                effects = {}
                self.assertEqual(evaluate(copy.deepcopy(self.by_name[name]), effects), want)
                self.assertEqual(effects["walletAuthorizationCalls"], 1)
                # The verifier still rejects that record.
                record = copy.deepcopy(self.by_name[name])
                record["operation"] = "verify-evidence"
                self.assertIn(evaluate(record)[0], ("fail", "error"))
        changed = self.by_name["response-changed-after-record-settled"]
        ref = changed["evidence"]["paymentTxRefs"][0]
        response = decode_response_header(changed["http"]["responseHeader"], 2)
        self.assertNotEqual(ref["paymentReceiptHash"], digest(response))
        self.assertEqual(changed["ledger"], self.by_name["protocol-v2-exact-success"]["ledger"])

    def test_retry_judges_a_stored_record_like_execute(self):
        """XN-11: on retry a record that does not verify is the reason, never the disposition."""
        for name, want in (
            ("retry-record-signature-invalid-settled", ("pass", "signature")),
            ("retry-record-signature-invalid-ledger-unavailable",
             ("indeterminate", "independent-settlement-unavailable")),
            ("retry-record-two-references-settled", ("pass", "evidence-ref-count")),
            ("retry-record-no-reference-settled", ("pass", "evidence-ref-count")),
            ("retry-record-names-another-transaction-settled", ("pass", "ledger-event")),
            ("retry-record-transaction-substitution-settled", ("pass", "native-event-key")),
            ("retry-record-transaction-not-32-bytes-settled", ("pass", "settlement-transaction-form")),
            ("retry-record-receipt-hash-not-recomputing-settled", ("pass", "payment-receipt-hash")),
            ("retry-record-malformed-transaction-ledger-unavailable",
             ("indeterminate", "independent-settlement-unavailable")),
        ):
            with self.subTest(vector=name):
                vector = self.by_name[name]
                self.assertIn("evidence", vector)
                effects = {}
                self.assertEqual(evaluate(copy.deepcopy(vector), effects), want)
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)
                # After the wallet call the same record gets the same result,
                as_execute = copy.deepcopy(vector)
                as_execute["operation"] = "execute"
                self.assertEqual(evaluate(as_execute), want)
                # and a verifier still rejects it.
                as_verifier = copy.deepcopy(vector)
                as_verifier["operation"] = "verify-evidence"
                self.assertIn(evaluate(as_verifier)[0], ("fail", "error"))
        # A record that names the reconciled event is no defect on retry.
        sound = copy.deepcopy(self.by_name["retry-indeterminate-remains-pending"])
        sound["ledger"]["available"] = True
        self.assertEqual(evaluate(sound), ("pass", None))

    def test_ledger_coordinates_are_judged_before_success(self):
        """XN-8/XN-11: the resolved event's transaction and key must identify it before `pass`."""
        tx = "ab" * 32
        cases = (
            ("transaction", "<absent>", ("indeterminate", "ledger-coordinate-missing")),
            ("settlementEvent", "<absent>", ("indeterminate", "ledger-coordinate-missing")),
            ("transaction", None, ("error", "ledger-transaction-form")),
            ("transaction", 7, ("error", "ledger-transaction-form")),
            ("transaction", "", ("error", "ledger-transaction-form")),
            ("transaction", "not-a-transaction", ("error", "ledger-transaction-form")),
            ("transaction", "0x" + tx[:63], ("error", "ledger-transaction-form")),
            ("transaction", "0x0x" + tx, ("error", "ledger-transaction-form")),
            ("transaction", "0x" + "cd" * 32, ("error", "ledger-event-key")),
            ("settlementEvent", None, ("error", "ledger-event-key")),
            ("settlementEvent", "not-an-event", ("error", "ledger-event-key")),
            ("settlementEvent", f"evm:8453:0x{tx}:7", ("error", "ledger-event-key")),
            ("settlementEvent", f"evm:8453:{tx.upper()}:7", ("error", "ledger-event-key")),
            ("settlementEvent", f"evm:8453:{tx}:07", ("error", "ledger-event-key")),
            ("settlementEvent", f"evm:1:{tx}:7", ("error", "ledger-event-key")),
            ("settlementEvent", "evm:8453:" + "cd" * 32 + ":7", ("error", "ledger-event-key")),
            # Every spelling the SB-1 collapse admits names the same event.
            ("transaction", tx.upper(), None),
            ("transaction", "0X" + tx.upper(), None),
        )
        for name in ("protocol-v2-exact-success", "response-lost-no-evidence-settled",
                     "retry-response-lost-ledger-settled"):
            base = self.by_name[name]
            self.assertEqual(base["ledger"]["settlementEvent"], f"evm:8453:{tx}:7")
            baseline = evaluate(copy.deepcopy(base))
            self.assertEqual(baseline[0], "pass")
            calls = 1 if base["operation"] == "execute" else 0
            for field, value, want in cases:
                with self.subTest(vector=name, field=field, value=value):
                    vector = copy.deepcopy(base)
                    if value == "<absent>":
                        vector["ledger"].pop(field)
                    else:
                        vector["ledger"][field] = value
                    effects = {}
                    self.assertEqual(evaluate(vector, effects), want or baseline)
                    self.assertEqual(effects.get("walletAuthorizationCalls", 0), calls)
                    # A non-final observation stays pending whatever its coordinates.
                    vector["ledger"]["finalized"] = False
                    self.assertEqual(evaluate(vector), ("indeterminate", "settlement-not-final"))
            # With neither coordinate no event is resolved: the identity's state decides.
            valid_before = base["runtime"]["reconciliationState"]["validBefore"]
            for timestamp, want in ((valid_before, ("fail", "terminal-non-settlement")),
                                    (valid_before - 1, ("indeterminate", "authorization-unsettled"))):
                with self.subTest(vector=name, no_event=timestamp):
                    vector = copy.deepcopy(base)
                    del vector["ledger"]["transaction"], vector["ledger"]["settlementEvent"]
                    vector["ledger"].update({"nonceState": "unused", "finalizedBlockTimestamp": timestamp})
                    self.assertEqual(evaluate(vector), want)
        # Solana: the key names the selected network's cluster and the exact signature.
        base = self.by_name["protocol-v2-solana-exact-success"]
        signature = base["ledger"]["transaction"]
        self.assertEqual(base["ledger"]["settlementEvent"], f"solana:devnet:{signature}:4")
        self.assertEqual(evaluate(copy.deepcopy(base)), ("pass", None))
        for field, value in (("settlementEvent", f"solana:mainnet:{signature}:4"),
                             ("settlementEvent", f"solana:devnet:{'2' * 64}:4"),
                             ("transaction", "2" * 64)):
            with self.subTest(solana=field, value=value):
                vector = copy.deepcopy(base)
                vector["ledger"][field] = value
                self.assertEqual(evaluate(vector), ("error", "ledger-event-key"))

    def test_record_names_the_reconciled_transaction_and_key_each(self):
        """XN-7/XN-8: a record is compared with both the reconciled transaction and its key.

        A record whose key names its own transaction, beside a ledger key that
        names the ledger's, already differs in the key when the transactions
        differ; this pins each comparison on its own, as XN-7 states them.
        """
        tx, other = "ab" * 32, "cd" * 32
        event = {"transaction": tx, "settlementEvent": f"evm:8453:{tx}:7"}
        for record, want in (
            ({"transaction": tx, "event": f"evm:8453:{tx}:7"}, None),
            ({"transaction": other, "event": f"evm:8453:{tx}:7"}, ("fail", "ledger-event")),
            ({"transaction": tx, "event": f"evm:8453:{tx}:8"}, ("fail", "ledger-event")),
        ):
            with self.subTest(record=record):
                self.assertEqual(record_ledger_defect(record, event), want)

    def test_success_evidence_is_built_from_the_reconciled_event(self):
        """XN-7/XN-11: success evidence names the ledger's event, never a defective record's."""
        built = 0
        for vector in self.vectors:
            if vector["operation"] not in ("execute", "retry"):
                continue
            effects = {}
            verdict, reason = evaluate(copy.deepcopy(vector), effects)
            with self.subTest(vector=vector["name"]):
                if verdict != "pass":
                    self.assertNotIn("builtEvidence", effects)
                    continue
                if vector["runtime"].get("storedRecordAnchored") is True and reason is not None:
                    # PC-7: an anchored record that does not verify cannot be
                    # replaced at its write-once address; nothing is rebuilt.
                    self.assertNotIn("builtEvidence", effects)
                    self.assertEqual(effects["manualRecovery"], reason)
                    continue
                built += 1
                network = vector["agreement"]["terms"]["rail"]["parameters"]["selection"]["network"]
                evidence = effects["builtEvidence"]
                self.assertEqual(evidence["settlementEvent"], vector["ledger"]["settlementEvent"])
                self.assertEqual(
                    adapter_canonical_transaction(network, evidence["settlementTransaction"]),
                    adapter_canonical_transaction(network, vector["ledger"]["transaction"]),
                )
        self.assertGreaterEqual(built, 57)
        # A sound response keeps its spelling; a record naming another
        # transaction is rebuilt from the ledger's event.
        for name, transaction in (
            ("response-transaction-0X-uppercase", "0X" + "AB" * 32),
            ("response-transaction-substitution", "ab" * 32),
            ("stored-record-names-another-transaction-settled", "0x" + "ab" * 32),
            ("retry-record-names-another-transaction-settled", "0x" + "ab" * 32),
            ("retry-retained-transaction-spelling-reconciles", "AB" * 32),
            ("retry-retained-transaction-not-reconciled-settled", "ab" * 32),
            ("retry-response-lost-ledger-settled", "ab" * 32),
        ):
            with self.subTest(rebuilt=name):
                effects = {}
                self.assertEqual(evaluate(copy.deepcopy(self.by_name[name]), effects)[0], "pass")
                self.assertEqual(effects["builtEvidence"], {
                    "settlementTransaction": transaction,
                    "settlementEvent": "evm:8453:" + "ab" * 32 + ":7",
                })

    def test_verify_evidence_never_calls_the_wallet(self):
        """A verifier judges a stored record; it never reaches the authorization site."""
        for vector in self.vectors:
            if vector["operation"] != "verify-evidence":
                continue
            with self.subTest(vector=vector["name"]):
                effects = {}
                verdict, _ = evaluate(copy.deepcopy(vector), effects)
                # Every record case is a rejection except the JSON-null
                # preimage, the two sound-shape successes and the record
                # judged apart from the paid request.
                self.assertEqual(verdict == "pass", vector["name"] in {
                    "record-over-unreceived-response-verifies",
                    "verify-evidence-response-without-payer",
                    "verify-evidence-without-extensions",
                    "verify-evidence-ignores-paid-request-payload",
                })
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)
        for name, want in (("protocol-v2-exact-success", ("pass", None)),
                           ("response-not-success", ("pass", "response-not-success")),
                           # The record names the ledger's transaction; the sound
                           # response names another, so the response is defective.
                           ("response-transaction-substitution", ("pass", "response-transaction")),
                           # A verifier with no record has nothing well formed to judge.
                           ("response-lost-no-evidence-settled", ("error", "evidence-record-version"))):
            with self.subTest(record_over=name):
                vector = copy.deepcopy(self.by_name[name])
                vector["operation"] = "verify-evidence"
                effects = {}
                self.assertEqual(evaluate(vector, effects), want)
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)

    def test_retry_terms_that_cannot_be_derived_are_malformed(self):
        """XN-11: a retry reconciles the signed terms; one it cannot derive is `error`."""
        base = self.by_name["retry-response-lost-ledger-settled"]
        self.assertEqual(evaluate(copy.deepcopy(base)), ("pass", None))
        # A malformed reference is refused by the preflight retry shares with
        # execute, before any reconciliation (XN-2).
        with mock.patch(f"{__name__}.verify_artifact_signatures", return_value=True):
            vector = copy.deepcopy(base)
            vector["agreement"]["terms"]["rail"]["provider"] = "x"
            self.assertEqual(evaluate(vector), ("error", "rail-ref-shape"))
        for label, change in (
            ("price not exact", lambda a: a["terms"]["price"].update({"amount": "1.0000001"})),
            ("price not an object", lambda a: a["terms"].update({"price": "1.25"})),
            ("binding duplicated", lambda a: a["terms"]["payoutBindings"].append(
                copy.deepcopy(a["terms"]["payoutBindings"][0]))),
            ("binding not 20 bytes", lambda a: a["terms"]["payoutBindings"][0].update(
                {"payeeAddress": "0x22"})),
        ):
            with self.subTest(case=label), mock.patch(
                    f"{__name__}.reconciliation_matches", return_value=True), mock.patch(
                    f"{__name__}.verify_artifact_signatures", return_value=True):
                vector = copy.deepcopy(base)
                change(vector["agreement"])
                effects = {}
                self.assertEqual(evaluate(vector, effects), ("error", "reconciliation-terms"))
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)

    def test_unpaid_request_answers_split_transient_from_definite(self):
        """XN-4: no answer, 5xx, 408 and 429 are transient; other non-402 answers fail."""
        base = self.by_name["protocol-v2-exact-success"]
        for status in (None, 408, 429, 500, 502, 503, 504, 599):
            with self.subTest(status=status):
                vector = copy.deepcopy(base)
                vector["http"]["status"] = status
                effects = {}
                self.assertEqual(evaluate(vector, effects),
                                 ("indeterminate", "unpaid-request-transient"))
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)
        for status in (200, 204, 301, 302, 400, 401, 403, 404, 410, 499):
            with self.subTest(status=status):
                vector = copy.deepcopy(base)
                vector["http"]["status"] = status
                effects = {}
                self.assertEqual(evaluate(vector, effects), ("fail", "not-payment-required"))
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)

    def test_retry_authorization_identity_compares_as_an_xn5_address(self):
        """XN-11/XN-5: both sides of the authorization identity take the adapter form first."""
        payer = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        checksum = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        pending = ("indeterminate", "independent-settlement-unavailable")
        for runtime_payer, retained, want in (
            (checksum, payer, pending),
            (payer, "0x" + payer[2:].upper(), pending),
            ("0x" + "99" * 20, payer, ("fail", "reconciliation-binding")),
            (payer[:-2], payer, ("error", "address-form")),
            (payer, payer[:-2], ("error", "address-form")),
            ("0X" + payer[2:], "0X" + payer[2:], ("error", "address-form")),
        ):
            with self.subTest(runtime_payer=runtime_payer, retained=retained):
                vector = copy.deepcopy(self.by_name["retry-indeterminate-remains-pending"])
                vector["runtime"]["payer"]["paymentAddress"] = runtime_payer
                vector["runtime"]["reconciliationState"]["authorizationIdentity"] = retained
                effects = {}
                self.assertEqual(evaluate(vector, effects), want)
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)
        # Solana retains a signed-message/client-signature identity, separate
        # from the sponsor signature that later becomes the transaction ID.
        vector = copy.deepcopy(self.by_name["protocol-v2-solana-exact-success"])
        vector["operation"] = "retry"
        vector["runtime"]["reconciliationState"] = reconciliation_identity(vector)
        self.assertEqual(evaluate(copy.deepcopy(vector)), ("pass", None))
        state = vector["runtime"]["reconciliationState"]
        state["authorizationIdentity"]["payer"] = state["authorizationIdentity"]["payer"].swapcase()
        self.assertEqual(evaluate(vector), ("fail", "reconciliation-binding"))

    def test_solana_reconciliation_rejects_substituted_transaction_coordinates(self):
        """Changing only valid ledger coordinates cannot credit another payment."""
        base = self.by_name["protocol-v2-solana-exact-success"]
        selection = base["agreement"]["terms"]["rail"]["parameters"]["selection"]
        for operation in ("execute", "retry", "verify-evidence"):
            for transaction in (base58(bytes([2]) * 64), base58(bytes([3]) * 64)):
                with self.subTest(operation=operation, transaction=transaction):
                    vector = copy.deepcopy(base)
                    vector["operation"] = operation
                    self.assertIsNotNone(adapter_canonical_transaction(selection["network"], transaction))
                    vector["ledger"].update({"transaction": transaction,
                                             "settlementEvent": f"solana:devnet:{transaction}:4"})
                    effects = {}
                    self.assertEqual(evaluate(vector, effects),
                                     ("indeterminate", "authorization-identity-mismatch"))
                    self.assertEqual(effects.get("walletAuthorizationCalls", 0),
                                     int(operation == "execute"))
                    self.assertNotIn("builtEvidence", effects)
        # Also reject another genuinely signed, finalized transaction rather
        # than just mismatched coordinates beside the original wire bytes.
        for operation in ("execute", "retry", "verify-evidence"):
            with self.subTest(genuine_substitution=operation):
                vector = copy.deepcopy(self.by_name[f"{operation}-solana-substituted-transaction"])
                for field in ("network", "scheme", "asset", "assetDecimals", "amount", "payer", "payTo"):
                    self.assertEqual(vector["ledger"][field], base["ledger"][field])
                self.assertEqual(vector["runtime"]["paidHeaders"], base["runtime"]["paidHeaders"])
                self.assertNotEqual(vector["ledger"]["transactionBase64"], base["ledger"]["transactionBase64"])
                effects = {}
                self.assertEqual(evaluate(vector, effects), ("indeterminate", "authorization-identity-mismatch"))
                self.assertNotIn("builtEvidence", effects)

    def test_solana_retry_uses_the_retained_authorization_after_response_loss(self):
        """No paid header, response, record or sponsor transaction ID is needed on retry."""
        vector = copy.deepcopy(self.by_name["retry-solana-response-lost-settled"])
        vector["runtime"].pop("paidHeaders")
        state = vector["runtime"]["reconciliationState"]
        state.pop("settlementTransaction")
        effects = {}
        self.assertEqual(evaluate(vector, effects), ("pass", None))
        self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)
        self.assertEqual(effects["builtEvidence"]["settlementTransaction"], vector["ledger"]["transaction"])
        for field, value in (("transactionBase64", None), ("available", False), ("finalized", False)):
            with self.subTest(unavailable=field):
                pending = copy.deepcopy(vector)
                pending["ledger"][field] = value
                effects = {}
                self.assertEqual(evaluate(pending, effects)[0], "indeterminate")
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)
                self.assertNotIn("builtEvidence", effects)
        # Retained bytes are immutable: changing the message invalidates its
        # client signature and cannot turn another message into this identity.
        raw = bytearray(base64.b64decode(vector["runtime"]["solanaAuthorization"]))
        raw[-2] ^= 1
        vector["runtime"]["solanaAuthorization"] = base64.b64encode(raw).decode()
        self.assertEqual(evaluate(vector), ("fail", "reconciliation-binding"))

    def test_solana_wallet_is_after_message_validation_and_signature_faults_reconcile(self):
        base = self.by_name["protocol-v2-solana-exact-success"]
        for transaction in (base64.b64encode(b"opaque transaction").decode(),
                            base64.b64encode(base64.b64decode(base["runtime"]["solanaAuthorization"])[:-1]).decode()):
            with self.subTest(malformed=transaction):
                vector = copy.deepcopy(base)
                payload = admit_raw_json(base64.b64decode(vector["runtime"]["paidHeaders"]["PAYMENT-SIGNATURE"]))
                payload["payload"]["transaction"] = transaction
                vector["runtime"]["paidHeaders"]["PAYMENT-SIGNATURE"] = base64.b64encode(
                    json.dumps(payload).encode()).decode()
                effects = {}
                self.assertEqual(evaluate(vector, effects), ("fail", "paid-request-payload"))
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)
        vector = copy.deepcopy(base)
        payload = admit_raw_json(base64.b64decode(vector["runtime"]["paidHeaders"]["PAYMENT-SIGNATURE"]))
        raw = bytearray(base64.b64decode(payload["payload"]["transaction"]))
        raw[65] ^= 1  # the first client-signature byte, without changing its message
        payload["payload"]["transaction"] = base64.b64encode(raw).decode()
        vector["runtime"]["paidHeaders"]["PAYMENT-SIGNATURE"] = base64.b64encode(json.dumps(payload).encode()).decode()
        for available in (False, True):
            vector["ledger"]["available"] = available
            effects = {}
            want = ("pass", "paid-request-payload") if available else (
                "indeterminate", "independent-settlement-unavailable")
            self.assertEqual(evaluate(vector, effects), want)
            self.assertEqual(effects.get("walletAuthorizationCalls", 0), 1)
            self.assertEqual(effects["handlerFault"], "paid-request-payload")
            self.assertEqual("builtEvidence" in effects, available)

    def test_solana_malformed_resolved_transaction_never_builds_success_evidence(self):
        base = self.by_name["protocol-v2-solana-exact-success"]
        wire = base64.b64decode(base["ledger"]["transactionBase64"])
        malformed = [wire + b"trailing"]
        for signature_offset in (1, 65):
            corrupted = bytearray(wire)
            corrupted[signature_offset] ^= 1
            malformed.append(bytes(corrupted))
        for operation in ("execute", "retry", "verify-evidence"):
            for raw in malformed:
                with self.subTest(operation=operation, malformed=raw[:3]):
                    vector = copy.deepcopy(base)
                    vector["operation"] = operation
                    vector["ledger"]["transactionBase64"] = base64.b64encode(raw).decode()
                    effects = {}
                    self.assertEqual(evaluate(vector, effects), ("error", "ledger-authorization-form"))
                    self.assertEqual(effects.get("walletAuthorizationCalls", 0), int(operation == "execute"))
                    self.assertNotIn("builtEvidence", effects)

    def solana_message_defect(self, vector):
        selection = vector["agreement"]["terms"]["rail"]["parameters"]["selection"]
        return payment_instruction_defect(
            vector["runtime"]["solanaAuthorization"], payer=vector["runtime"]["payer"]["paymentAddress"],
            fee_payer=selection["extra"]["feePayer"],
            pay_to=vector["agreement"]["terms"]["payoutBindings"][0]["payeeAddress"],
            mint=selection["asset"], amount=int(selection_amount(vector["agreement"]["terms"]["price"], selection)),
            decimals=selection["assetDecimals"],
            token_program=vector["capability"]["assetMetadata"]["tokenProgram"],
            memo=selection["extra"].get("memo"))

    def test_solana_payer_signs_only_the_exact_payment_message(self):
        """§9.5.7.1/XN-6: each deviation from the signed payment is refused before signing.

        The reason names the first deviation the instruction check finds. With
        that check removed, the same message reaches the wallet, as an
        overpayment or a granted account authority did before.
        """
        global payment_instruction_defect
        wanted = {
            **dict.fromkeys(("amount-plus-one", "amount-minus-one", "amount-tenfold", "other-mint",
                             "other-destination", "destination-not-associated", "source-not-associated",
                             "authority-not-payer", "wrong-decimals"), "transfer"),
            **dict.fromkeys(("other-token-program", "extra-approve", "extra-set-authority",
                             "extra-close-account", "extra-system-transfer", "extra-unknown-program"),
                            "instruction"),
            "second-transfer": "transfer-count",
            **dict.fromkeys(("memo-missing", "memo-second", "memo-not-nonce", "memo-with-signer",
                             "extra-memo-other", "extra-memo-missing"), "memo"),
            **dict.fromkeys(("compute-heap-frame", "compute-limit-above-bound", "compute-price-above-bound"),
                            "compute-budget"),
            "lookup-table": "lookup-table",
            "extra-signer": "signers",
        }
        names = sorted(name for name in self.by_name if name.startswith("solana-signed-message-"))
        self.assertEqual(names, sorted(f"solana-signed-message-{suffix}" for suffix in wanted))
        for suffix, reason in wanted.items():
            vector = self.by_name[f"solana-signed-message-{suffix}"]
            with self.subTest(vector=suffix):
                self.assertEqual(self.solana_message_defect(vector), reason)
                effects = {}
                self.assertEqual(evaluate(copy.deepcopy(vector), effects), ("fail", "paid-request-payload"))
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)
        check = payment_instruction_defect
        payment_instruction_defect = lambda *_args, **_kwargs: None  # noqa: E731
        try:
            for suffix in wanted:
                with self.subTest(vector=suffix, mutant="instruction check removed"):
                    effects = {}
                    evaluate(copy.deepcopy(self.by_name[f"solana-signed-message-{suffix}"]), effects)
                    self.assertEqual(effects.get("walletAuthorizationCalls", 0), 1)
        finally:
            payment_instruction_defect = check

    def test_every_solana_fixture_signs_its_own_terms(self):
        """§9.5.7.1: a passing Solana vector's message is exactly its own payment.

        This covers the u64-limit amount, the lettered payee, the memos and the
        Token-2022 mint, not only the base terms.
        """
        passing = [vector for vector in self.vectors if vector["expected"] == "pass"
                   and "solanaAuthorization" in vector["runtime"]]
        self.assertGreaterEqual(len(passing), 12)
        for vector in passing:
            with self.subTest(vector=vector["name"]):
                self.assertIsNone(self.solana_message_defect(vector))
        amounts = {vector["name"]: int(selection_amount(
            vector["agreement"]["terms"]["price"], vector["agreement"]["terms"]["rail"]["parameters"]["selection"]))
            for vector in passing}
        self.assertEqual(amounts["solana-exact-amount-at-u64-limit"], 2**64 - 1)

    def test_solana_resolved_transaction_of_other_signers_stays_pending(self):
        """XN-11: a validly signed different transaction is indeterminate; bad signatures are error."""
        for operation in ("execute", "retry", "verify-evidence"):
            for who in ("sponsor", "payer"):
                vector = self.by_name[f"{operation}-solana-resolved-other-{who}"]
                with self.subTest(operation=operation, who=who):
                    effects = {}
                    self.assertEqual(evaluate(copy.deepcopy(vector), effects),
                                     ("indeterminate", "authorization-identity-mismatch"))
                    self.assertNotIn("builtEvidence", effects)
                    corrupted = copy.deepcopy(vector)
                    raw = bytearray(base64.b64decode(corrupted["ledger"]["transactionBase64"]))
                    raw[1] ^= 1
                    corrupted["ledger"]["transactionBase64"] = base64.b64encode(raw).decode()
                    self.assertEqual(evaluate(corrupted), ("error", "ledger-authorization-form"))

    def test_solana_verifier_uses_disclosed_authorization_not_paid_header(self):
        vector = copy.deepcopy(self.by_name["protocol-v2-solana-exact-success"])
        vector["operation"] = "verify-evidence"
        vector["runtime"]["paidHeaders"]["PAYMENT-SIGNATURE"] = "unreadable"
        self.assertEqual(evaluate(vector), ("pass", None))
        vector["runtime"].pop("solanaAuthorization")
        self.assertEqual(evaluate(vector), ("indeterminate", "authorization-identity-unavailable"))

    def test_literal_public_target_classes_are_explicit(self):
        rejected = (
            "https://127.0.0.1/",
            "https://10.0.0.1/",
            "https://169.254.169.254/",
            "https://100.64.0.1/",
            "https://224.0.0.1/",
            "https://240.0.0.1/",
            "https://[::1]/",
            "https://[::ffff:127.0.0.1]/",
        )
        for url in rejected:
            with self.subTest(url=url):
                self.assertFalse(public_http_target(url))
        self.assertTrue(public_http_target("https://seller.example/pay"))

    def test_new_and_legacy_version_fields_are_not_interchangeable(self):
        new_ref = self.by_name["protocol-v2-exact-success"]["evidence"]["paymentTxRefs"][0]
        legacy_ref = self.by_name["legacy-default-string-version-replay"]["evidence"]["paymentTxRefs"][0]
        self.assertEqual(type(new_ref["x402Version"]), int)
        self.assertNotIn("protocolVersion", new_ref)
        self.assertEqual(type(legacy_ref["protocolVersion"]), str)
        self.assertNotIn("x402Version", legacy_ref)

    def test_cross_rail_identity_uses_native_evm_key(self):
        vector = self.by_name["event-key-cross-rail-alias"]
        event = vector["evidence"]["paymentTxRefs"][0]["settlementEvent"]
        self.assertRegex(event, EVM_EVENT)
        self.assertEqual(event, vector["ledger"]["settlementEvent"])

    def test_non_evm_success_uses_native_solana_key(self):
        vector = self.by_name["protocol-v2-solana-exact-success"]
        ref = vector["evidence"]["paymentTxRefs"][0]
        self.assertRegex(ref["settlementEvent"], SOLANA_EVENT)
        self.assertEqual(ref["settlementEvent"], vector["ledger"]["settlementEvent"])
        self.assertEqual(evaluate(vector), ("pass", None))

    def test_solana_event_key_names_the_cluster_of_each_caip2_network(self):
        """The reference evaluator maps every DACS-4 Solana cluster, not only devnet."""
        signature = "1" * 64
        clusters = {
            "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": "mainnet",
            "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": "devnet",
            "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z": "testnet",
        }
        self.assertEqual(SOLANA_NETWORK_CLUSTERS, clusters)
        for network, cluster in clusters.items():
            for other in ("mainnet", "devnet", "testnet"):
                with self.subTest(network=network, event_cluster=other):
                    self.assertEqual(
                        native_event_matches(f"solana:{other}:{signature}:4", network, signature),
                        other == cluster,
                    )
        self.assertFalse(native_event_matches(
            f"solana:mainnet:{signature}:4", "solana:" + "1" * 32, signature))
        vector = self.by_name["protocol-v2-solana-mainnet-exact-success"]
        ref = vector["evidence"]["paymentTxRefs"][0]
        self.assertEqual(ref["settlementNetwork"], "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
        self.assertTrue(ref["settlementEvent"].startswith("solana:mainnet:"))
        self.assertEqual(evaluate(vector), ("pass", None))
        # The mapping is the spec's closed §9.5.7.1 table, so the spec and the
        # evaluator name the same three references.
        spec = (ROOT / "spec/DACS-4-SETTLE.md").read_text(encoding="utf-8")
        for network, cluster in clusters.items():
            self.assertIn(f"| `{network}` | `{cluster}` |", spec)

    def test_event_key_integers_are_safe_and_signatures_are_64_bytes(self):
        """SB-1: chainId > 0 and logIndex are safe integers; a Solana signature is 64 bytes."""
        tx = "ab" * 32
        unsafe = 2**53 + 1
        self.assertTrue(native_event_matches(f"evm:8453:{tx}:{SAFE_INT}", "eip155:8453", tx))
        self.assertFalse(native_event_matches(f"evm:8453:{tx}:{unsafe}", "eip155:8453", tx))
        self.assertTrue(native_event_matches(f"evm:{SAFE_INT}:{tx}:0", f"eip155:{SAFE_INT}", tx))
        self.assertFalse(native_event_matches(f"evm:{unsafe}:{tx}:0", f"eip155:{unsafe}", tx))
        self.assertFalse(native_event_matches(f"evm:0:{tx}:0", "eip155:0", tx))
        devnet = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
        for raw, want in ((b"\x05" * 64, True), (b"\x05" * 63, False), (b"\x05" * 65, False),
                          (b"\x00" * 64, True), (b"\x00" * 10, False)):
            signature = base58(raw)
            with self.subTest(length=len(raw), leading_zero=raw[0] == 0):
                self.assertEqual(base58_decoded_length(signature), len(raw))
                self.assertEqual(
                    native_event_matches(f"solana:devnet:{signature}:4", devnet, signature), want)
        self.assertFalse(native_event_matches(
            f"solana:devnet:{base58(b'\x05' * 64)}:{unsafe}", devnet, base58(b"\x05" * 64)))

    def test_unbound_namespace_or_unmapped_cluster_is_unsupported_before_authorization(self):
        """§9.5.7.1: the binding names EIP-155 and three Solana clusters, whatever is claimed.

        An EIP-155 reference with no SB-1 `evm:` key form (zero, a leading
        zero, or above 2^53-1) is unsupported too, before the wallet signs.
        """
        base = self.by_name["protocol-v2-exact-success"]
        for network in ("cosmos:cosmoshub-4", "solana:8E9rvCKLFQia2Y35HXjjpWzj8weVo44K",
                        "eip155:0", "eip155:08453", f"eip155:{SAFE_INT + 1}"):
            with self.subTest(network=network), mock.patch(
                    f"{__name__}.verify_artifact_signatures", return_value=True), mock.patch(
                    f"{__name__}.buyer_payment_control", return_value=True), mock.patch(
                    f"{__name__}.adapter_address", side_effect=lambda _network, address: address):
                vector = copy.deepcopy(base)
                for ref in (vector["listing"]["acceptedRails"][0], vector["agreement"]["terms"]["rail"],
                            vector["runtime"]["selectedRailRef"]):
                    ref["parameters"]["selection"]["network"] = network
                vector["capability"]["supportedTuples"] = [[2, "exact", network]]
                effects = {}
                self.assertEqual(evaluate(vector, effects), ("fail", "x402-capability-unsupported"))
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)

    def test_an_anchored_record_is_never_overwritten(self):
        """PC-7(b)/XN-11: replay every execute and retry against a write-once anchor store.

        The address already holds the stored record when the runtime says it
        is anchored. Writing different bytes to an occupied address is refused,
        so a handler that rebuilt over an anchored record would raise here.
        """
        class WriteOnceStore:
            def __init__(self):
                self.slots = {}

            def write(self, address, record):
                if address in self.slots and self.slots[address] != record:
                    raise AssertionError(f"write-once address {address} already anchored")
                self.slots[address] = record

        def address(v):
            return f"dacs4:payment:{v['agreement']['jobId']}:x402:protocol:{v['runtime']['phaseIndex']}"

        def as_anchored(evidence):
            # The anchored bytes as the coordinates a rebuilt record carries;
            # a record with no such coordinates is kept as it is, so any
            # write over it is refused.
            try:
                ref = evidence["paymentTxRefs"][0]
                return {"settlementTransaction": ref["settlementTransaction"],
                        "settlementEvent": ref["settlementEvent"]}
            except (IndexError, KeyError, TypeError):
                return evidence

        manual = 0
        for vector in self.vectors:
            if vector["operation"] not in ("execute", "retry") or "evidence" not in vector:
                continue
            for anchored_flag in (False, True):
                with self.subTest(vector=vector["name"], anchored=anchored_flag):
                    changed = copy.deepcopy(vector)
                    changed["runtime"]["storedRecordAnchored"] = anchored_flag
                    store = WriteOnceStore()
                    if anchored_flag:
                        store.write(address(changed), as_anchored(changed["evidence"]))
                    effects = {}
                    verdict, reason = evaluate(changed, effects)
                    if "builtEvidence" in effects:
                        store.write(address(changed), effects["builtEvidence"])
                    if anchored_flag and "manualRecovery" in effects:
                        manual += 1
                        self.assertEqual(verdict, "pass")
                        self.assertIsNotNone(reason)
        self.assertGreaterEqual(manual, 16)

    def test_each_named_class_is_reported_by_its_own_branch(self):
        """Every §6.3.6 named class has at least one representative that reports that class.

        §6.3.6 requires these targets to be REJECTED; reporting a class name is this suite's
        own device, not a protocol requirement. Asserting the class rather than the rejection
        boolean is what catches a deleted branch or a precedence-changing reorder between
        overlapping branches — a reorder between non-overlapping branches changes no verdict
        and is not detected, nor does it need to be. Several of these addresses are ALSO is_private in CPython, so a
        test that only checked "was it rejected" would stay green with the loopback,
        link-local, unspecified or reserved branch deleted — the is_private fallback would
        absorb them and the loss of a named rule would be invisible.
        """
        for literal, expected in NON_PUBLIC_CLASS_CASES:
            with self.subTest(address=literal):
                address = ipaddress.ip_address(literal)
                self.assertEqual(_non_public_class(address), expected)

    def test_embedded_ipv4_forms_are_judged_by_the_address_they_carry(self):
        """XN-2: each embedded-IPv4 IPv6 form is unwrapped explicitly, not by CPython's tables.

        The class names show which branch decided, and the unwrapped addresses
        agree with CPython's own ipv4_mapped, sixtofour and teredo readings.
        """
        for literal, expected in EMBEDDED_IPV4_CASES:
            with self.subTest(address=literal):
                address = ipaddress.ip_address(literal)
                self.assertEqual(_target_class(address), expected)
                self.assertEqual(public_http_target(f"https://[{literal}]/pay"), expected is None)
                embedded = _embedded_ipv4(address)
                if address.ipv4_mapped is not None:
                    self.assertEqual(embedded, ("ipv4-mapped", (address.ipv4_mapped,)))
                if address.sixtofour is not None:
                    self.assertEqual(embedded, ("6to4", (address.sixtofour,)))
                if address.teredo is not None:
                    self.assertEqual(embedded, ("teredo", address.teredo))
        for literal, expected in NON_PUBLIC_CLASS_CASES:
            with self.subTest(address=literal, form="not embedded"):
                self.assertEqual(_target_class(ipaddress.ip_address(literal)), expected)

    def test_localhost_names_are_never_public(self):
        """XN-2: `localhost`, every `.localhost` name (RFC 6761) and `localhost.localdomain`."""
        for host in ("localhost", "LOCALHOST.", "api.localhost", "a.b.localhost.",
                     "localhost.localdomain", "LOCALHOST.LOCALDOMAIN."):
            with self.subTest(host=host):
                self.assertFalse(public_http_target(f"https://{host}/pay"))
        for host in ("localhost.example", "notlocalhost", "localhost-api.example",
                     "localdomain", "api.localhost.example"):
            with self.subTest(host=host):
                self.assertTrue(public_http_target(f"https://{host}/pay"))

    def test_wireserver_is_rejected_as_hardening_not_conformance(self):
        """Azure WireServer is rejected, but that is our choice — not a §6.3.6 obligation.

        Kept separate from the named-class table on purpose. Microsoft documents 168.63.129.16
        as a platform endpoint distinct from IMDS, so asserting it under "cloud-provider
        metadata destinations" would claim a conformance requirement the spec does not clearly
        state, and would push that requirement onto every other implementer. It is also the one
        address here that no generic predicate rejects, which is why the evaluator carries it at
        all. Asserted on REJECTION only — deliberately not on class name.
        """
        self.assertFalse(public_http_target("https://168.63.129.16/machine/"))
        self.assertFalse(public_http_target("https://[::ffff:168.63.129.16]/machine/"))

    def test_legacy_ipv4_host_spellings_are_classified_as_literals(self):
        """WHATWG URL hosts that end in a number are IPv4 literals, not DNS names.

        Fetch-style URL parsers and resolvers map these spellings to the dotted
        address, so the literal gate must classify them the same way; a
        numeric-ending host that is not a valid IPv4 literal fails closed.
        """
        rejected = (
            "https://127.1/pay",                 # shorthand loopback
            "https://2130706433/pay",            # one 32-bit number
            "https://0x7f.0.0.1/pay",            # hexadecimal part
            "https://0x7f000001/pay",            # hexadecimal 32-bit number
            "https://0177.0.0.1/pay",            # octal part
            "https://127.0.0.1./pay",            # trailing root dot
            "https://%31%32%37.0.0.1/pay",       # percent-encoded digits
            "https://１２７．０．０．１/pay",  # full-width
            "https://10.1/pay",                  # shorthand private
            "https://169.254.43518/pay",         # shorthand metadata (169.254.169.254)
            "https://localhost./pay",
            "https://1.2.3.4.5/pay",             # too many parts: not a valid host
            "https://1.2.3.4.0/pay",             # too many parts, even ending in 0: not 1.2.3.4
            "https://1..1/pay",                  # an empty part: not a valid host
            "https://256.0.0.1/pay",             # part out of range: not a valid host
            "https://127.16777216/pay",          # last part past 24 bits: not a valid host
            "https://0x7g.0.0.1/pay",            # bad hex part in a numeric host
            "https://0x0x08.8.8.8/",             # second 0x prefix: not a valid host
            "https://08.8.8.8/pay",              # 8 is not an octal digit
            "https://0x/pay",                    # a bare 0x prefix is the number 0: 0.0.0.0
        )
        for url in rejected:
            with self.subTest(url=url):
                self.assertFalse(public_http_target(url))
        for url in (
            "https://8.8.8.8/pay",
            "https://134744072/pay",             # 8.8.8.8 as one number
            "https://seller.example/pay",
            "https://1.2.3.example/pay",         # ends in a label, not a number
            "https://0x.example/pay",
        ):
            with self.subTest(url=url):
                self.assertTrue(public_http_target(url))

    def test_every_bounded_fetch_vector_depends_on_the_public_target_gate(self):
        """Each literal-target vector fails at the gate and would otherwise pass.

        The received-object hashes are refreshed and the reason pinned, so a stale
        challenge hash cannot keep a vector green for an evaluator without the gate.
        """
        global public_http_target
        names = [name for name in self.by_name if name.startswith("bounded-fetch-")]
        self.assertGreaterEqual(len(names), 26)
        gate = public_http_target
        public_http_target = lambda _url: True  # noqa: E731
        try:
            for name in names:
                with self.subTest(vector=name):
                    vector = self.by_name[name]
                    self.assertEqual(vector.get("expectedReason"), "non-public-request-target")
                    self.assertEqual(evaluate(copy.deepcopy(vector)), ("pass", None))
        finally:
            public_http_target = gate

    def test_every_request_url_error_vector_depends_on_the_syntax_rule(self):
        """Each request-url-* error vector fails on the XN-2 syntax rule and would otherwise pass.

        With the syntax rule removed and the address gate forced open, every one
        reaches `pass`, so neither a stale hash nor a later check keeps it green.
        """
        global request_url_syntax_ok, public_http_target
        names = [name for name, vector in self.by_name.items()
                 if name.startswith("request-url-") and vector["expected"] == "error"]
        self.assertEqual(len(names), 23)
        for name in names:
            with self.subTest(vector=name):
                self.assertEqual(self.by_name[name].get("expectedReason"), "rail-ref-shape")
        syntax, gate = request_url_syntax_ok, public_http_target
        request_url_syntax_ok = lambda _url: True  # noqa: E731
        public_http_target = lambda _url: True  # noqa: E731
        try:
            for name in names:
                with self.subTest(vector=name, mutant="syntax rule removed, gate open"):
                    self.assertEqual(evaluate(copy.deepcopy(self.by_name[name])), ("pass", None))
        finally:
            request_url_syntax_ok, public_http_target = syntax, gate

    def test_every_request_trace_vector_depends_on_its_check(self):
        """Each vector the XN-6 request-trace check rejects would otherwise pass.

        With the check removed, every vector pinned to one of its reasons
        reaches `pass`, so neither a stale hash nor another gate keeps it red.
        """
        global request_trace_defect
        reasons = {
            "effective-request-method", "effective-request", "effective-request-body",
            "request-body", "request-body-hash", "unsigned-request-body",
        }
        names = [name for name, vector in self.by_name.items()
                 if vector.get("expectedReason") in reasons]
        self.assertEqual(len(names), 15)
        check = request_trace_defect
        request_trace_defect = lambda _runtime, _request: None  # noqa: E731
        try:
            for name in names:
                with self.subTest(vector=name, mutant="request-trace check removed"):
                    self.assertEqual(evaluate(copy.deepcopy(self.by_name[name])), ("pass", None))
        finally:
            request_trace_defect = check

    def test_request_trace_carries_the_signed_method_url_and_body_in_each_request(self):
        """XN-6: the derived, unpaid and paid requests each use the signed method, URL and body.

        Changing one field of one request alone rejects before the wallet call.
        A method is the exact case-sensitive token, and a trace that omits a
        field does not name the signed request.
        """
        base = self.by_name["protocol-v2-exact-success"]
        self.assertEqual(evaluate(copy.deepcopy(base)), ("pass", None))
        url = base["agreement"]["terms"]["rail"]["parameters"]["request"]["url"]
        method = ("fail", "effective-request-method")
        target = ("fail", "effective-request")
        body = ("fail", "effective-request-body")
        malformed = ("error", "request-body")
        for field, value, want in (
            ("effectiveMethod", "POST", method),
            ("unpaidMethod", "get", method),
            ("paidMethod", None, method),
            ("effectiveUrl", url + "&", target),
            ("unpaidUrl", url.upper(), target),
            ("paidUrl", None, target),
            ("requestBodyBase64", base64.b64encode(b"{}").decode("ascii"), body),
            ("unpaidBodyBase64", "%%%", malformed),
            ("paidBodyBase64", None, malformed),
        ):
            with self.subTest(field=field, value=value):
                vector = copy.deepcopy(base)
                if value is None:
                    del vector["runtime"][field]
                else:
                    vector["runtime"][field] = value
                effects = {}
                self.assertEqual(evaluate(vector, effects), want)
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)

    def test_every_member_classification_vector_depends_on_its_check(self):
        """Member classification precedes the independent authorization checks.

        Most classified members are rejected only by this gate. A malformed
        Solana sponsor also fails the independent transaction-identity gate,
        and a memo that is not a string the independent instruction gate.
        """
        global challenge_member_defect
        reasons = {
            "unclassified-extra-member", "unclassified-extension", "unsupported-action-extension",
            "unsupported-transfer-method", "unsupported-payment-flow", "extra-member-value",
            "extension-value",
        }
        names = [name for name, vector in self.by_name.items()
                 if vector.get("expectedReason") in reasons]
        self.assertEqual(len(names), 40)
        check = challenge_member_defect
        challenge_member_defect = lambda *_args: None  # noqa: E731
        try:
            for name in names:
                with self.subTest(vector=name, mutant="member check removed"):
                    # The transaction identity check independently requires a
                    # real sponsor key, and the instruction check a Memo whose
                    # data is the memo; removing classification cannot make a
                    # malformed Solana fee payer or memo usable.
                    redundant = name in {
                        "solana-extra-fee-payer-absent", "solana-extra-fee-payer-object",
                        "solana-extra-fee-payer-not-base58", "solana-extra-fee-payer-short",
                        "solana-extra-memo-object",
                    }
                    want = ("fail", "paid-request-payload") if redundant else ("pass", None)
                    self.assertEqual(evaluate(copy.deepcopy(self.by_name[name])), want)
        finally:
            challenge_member_defect = check

    def test_challenge_members_are_classified_by_the_selected_adapter(self):
        """XN-6: each received member is classified from the selected adapter's own table.

        The tables are keyed by CAIP-2 namespace, so one adapter's member is
        unclassified under another, and a namespace without a table defines
        none, whatever a local capability lists.
        """
        schema = copy.deepcopy(PAYMENT_IDENTIFIER_SCHEMA)
        extension = {"payment-identifier": {"info": {"required": False}, "schema": schema}}
        # Every member the pinned upstream exact definitions and the v2
        # protocol-reserved keys define, and nothing else.
        defined = {
            "eip155:8453": {"assetTransferMethod": "eip3009", "paymentFlow": "authorization",
                            "name": "USDC", "version": "2"},
            "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": {
                "paymentFlow": "authorization", "feePayer": "4" * 44, "memo": "dacs-274",
                "recentBlockhash": "6" * 44, "lastValidBlockHeight": "280000000"},
        }
        minimal = {"eip155:8453": {"name": "USDC", "version": "2"},
                   "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": {"feePayer": "4" * 44}}
        self.assertEqual({key: set(value) for key, value in ADAPTER_EXTRA_MEMBERS.items()},
                         {network.split(":")[0]: set(extra) | {"assetTransferMethod"}
                          for network, extra in defined.items()})
        self.assertEqual((self.data["upstream"]["commit"], self.data["upstream"]["exactEvmScheme"],
                          self.data["upstream"]["exactSvmScheme"]),
                         ("230e6a9a7eebce22c911a0687d6f4e6d1ac019f7",
                          "specs/schemes/exact/scheme_exact_evm.md",
                          "specs/schemes/exact/scheme_exact_svm.md"))
        for network, extra in defined.items():
            with self.subTest(network=network):
                self.assertIsNone(challenge_member_defect(network, extra, extension))
                self.assertIsNone(challenge_member_defect(network, minimal[network], {}))
                # A required member is required: an empty extra rejects.
                self.assertEqual(challenge_member_defect(network, {}, {}),
                                 ("fail", "extra-member-value"))
                # The two members the pinned definitions do not have: the asset
                # is the EIP-712 verifying contract and the mint.
                for member in ("verifyingContract", "mint"):
                    self.assertEqual(
                        challenge_member_defect(network, {**extra, member: "x"}, extension),
                        ("fail", "unclassified-extra-member"))
                for other in defined.values():
                    # assetTransferMethod is protocol-reserved on both; it is
                    # judged as a transfer method below.
                    for member in set(other) - set(extra) - {"assetTransferMethod"}:
                        self.assertEqual(
                            challenge_member_defect(
                                network, {**extra, member: other[member]}, extension),
                            ("fail", "unclassified-extra-member"))
                for flow in ("upfront", "escrow", "", None, ["authorization"]):
                    self.assertEqual(
                        challenge_member_defect(network, {**extra, "paymentFlow": flow}, {}),
                        ("fail", "unsupported-payment-flow"))
        # XN-9: only EIP-3009 (also when the member is absent) is a v0.8
        # EIP-155 form; the value is an exact token. Solana defines none.
        domain = minimal["eip155:8453"]
        for method, want in (("eip3009", None), ("permit2", "unsupported"), ("erc7710", "unsupported"),
                             ("EIP3009", "unsupported"), ("", "unsupported"), (None, "unsupported"),
                             (3009, "unsupported"), (["permit2"], "unsupported"),
                             ({"permit2": True}, "unsupported")):
            with self.subTest(assetTransferMethod=method):
                self.assertEqual(
                    challenge_member_defect(
                        "eip155:8453", {**domain, "assetTransferMethod": method}, {}),
                    want and ("fail", "unsupported-transfer-method"))
        self.assertEqual(
            challenge_member_defect("solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                                    {**minimal["solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"],
                                     "assetTransferMethod": "eip3009"}, {}),
            ("fail", "unsupported-transfer-method"))
        # §9.5.7.1 value rules: the EIP-3009 domain, the Solana fee payer and
        # memo; the Solana hints are never judged.
        solana = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
        for network, extra, want in (
            ("eip155:8453", {"name": "USDC"}, "extra-member-value"),
            ("eip155:8453", {"name": "", "version": "2"}, "extra-member-value"),
            ("eip155:8453", {"name": "USDC", "version": 2}, "extra-member-value"),
            (solana, {"feePayer": "4" * 43 + "0"}, "extra-member-value"),
            (solana, {"feePayer": base58(b"\x07" * 33)}, "extra-member-value"),
            (solana, {"feePayer": base58(b"\x07" * 32), "memo": "x" * 256}, None),
            (solana, {"feePayer": base58(b"\x07" * 32), "memo": "x" * 257}, "extra-member-value"),
            (solana, {"feePayer": base58(b"\x07" * 32), "memo": "é" * 129}, "extra-member-value"),
            (solana, {"feePayer": base58(b"\x07" * 32), "recentBlockhash": [],
                      "lastValidBlockHeight": {}}, None),
        ):
            with self.subTest(network=network, extra=extra):
                self.assertEqual(challenge_member_defect(network, extra, {}),
                                 want and ("fail", want))
        self.assertEqual(
            challenge_member_defect("cosmos:cosmoshub-4", {"name": "USDC"}, {}),
            ("fail", "unclassified-extra-member"))
        self.assertEqual(
            challenge_member_defect("eip155:8453", domain, {"future-action": {}}),
            ("fail", "unclassified-extension"))
        # payment-identifier: upstream's {info: {required}, schema} with the
        # pinned schema, and `info` satisfying it; only the optional form is
        # supported, and it is descriptive, so no capability gates it.
        other_schema = {**schema, "properties": {**schema["properties"], "id": {"type": "string"}}}
        sdk_schema = copy.deepcopy(PAYMENT_IDENTIFIER_SDK_SCHEMA)
        for advertised, want in (
            ({"info": {"required": False}, "schema": schema}, None),
            ({"info": {"required": False, "id": "i" * 16}, "schema": schema}, None),
            # The schema the pinned reference SDKs emit is the other pinned form.
            ({"info": {"required": False}, "schema": sdk_schema}, None),
            ({"info": {"required": False, "id": "pay_A-z0" + "9" * 120}, "schema": sdk_schema}, None),
            ({"info": {"required": True}, "schema": sdk_schema}, "unsupported-action-extension"),
            # payment_identifier.md's id characters, under either schema: a
            # trailing newline or a non-ASCII letter is outside them.
            ({"info": {"required": False, "id": "pay." + "7" * 16}, "schema": schema}, "extension-value"),
            ({"info": {"required": False, "id": "i" * 16 + "\n"}, "schema": sdk_schema}, "extension-value"),
            ({"info": {"required": False, "id": "é" * 16}, "schema": sdk_schema}, "extension-value"),
            ({"info": {"required": True}, "schema": schema}, "unsupported-action-extension"),
            (None, "extension-value"), ({"required": True}, "extension-value"),
            ({"info": {}, "schema": schema}, "extension-value"),
            ({"info": {"required": 0}, "schema": schema}, "extension-value"),
            ({"info": {"required": False}, "schema": schema, "id": "x"}, "extension-value"),
            ({"info": {"required": False}, "schema": []}, "extension-value"),
            ({"info": {"required": False}, "schema": {"type": "array"}}, "extension-value"),
            ({"info": {"required": False}, "schema": {"type": "object"}}, "extension-value"),
            ({"info": {"required": False}, "schema": other_schema}, "extension-value"),
            ({"info": {"required": False, "id": "i" * 15}, "schema": schema}, "extension-value"),
            ({"info": {"required": False, "id": "i" * 129}, "schema": schema}, "extension-value"),
            ({"info": {"required": False, "id": 1234567890123456}, "schema": schema}, "extension-value"),
        ):
            with self.subTest(advertised=advertised):
                self.assertEqual(
                    challenge_member_defect(
                        "eip155:8453", domain, {"payment-identifier": advertised}),
                    want and ("fail", want))

    def test_a_supplied_classification_list_never_changes_a_result(self):
        """XN-6: a list of action-bearing members beside the challenge is not a classification.

        Adding one that omits, names or invents members leaves every execute
        and verify-evidence result unchanged.
        """
        for vector in self.vectors:
            if vector["operation"] not in {"execute", "verify-evidence"}:
                continue
            want = evaluate(copy.deepcopy(vector))
            for supplied in ([], ["payment-identifier"], ["future-action"]):
                with self.subTest(vector=vector["name"], supplied=supplied):
                    changed = copy.deepcopy(vector)
                    changed["http"]["actionBearingExtensions"] = supplied
                    self.assertEqual(evaluate(changed), want)

    def test_definition_is_the_revision_the_reference_pins(self):
        """XN-1: the definition's railVersion equals the one the signed reference pins.

        Signatures are taken as verified, so only the two versions vary: any
        unequal pair rejects before the wallet call, on execute and for a
        verifier, and any equal pair is the success it was.
        """
        for operation in ("execute", "verify-evidence"):
            base = copy.deepcopy(self.by_name["protocol-v2-exact-success"])
            base["operation"] = operation
            for definition, pinned in ((1, 1), (2, 2), (7, 7), (1, 2), (2, 1), (2, 3), (3, 2)):
                with self.subTest(operation=operation, definition=definition, pinned=pinned), \
                        mock.patch(f"{__name__}.verify_artifact_signatures", return_value=True):
                    vector = copy.deepcopy(base)
                    vector["railDefinition"]["railVersion"] = definition
                    for ref in (vector["listing"]["acceptedRails"][0],
                                vector["agreement"]["terms"]["rail"],
                                vector["runtime"]["selectedRailRef"]):
                        ref["railVersion"] = pinned
                    effects = {}
                    self.assertEqual(evaluate(vector, effects), ("pass", None) if definition == pinned
                                     else ("fail", "rail-version"))
                    calls = 1 if operation == "execute" and definition == pinned else 0
                    self.assertEqual(effects.get("walletAuthorizationCalls", 0), calls)
        for name in ("definition-railversion-2-ref-pins-1", "definition-railversion-1-ref-pins-2",
                     "verify-evidence-definition-railversion-2-ref-pins-1"):
            with self.subTest(vector=name):
                vector = self.by_name[name]
                self.assertNotEqual(vector["railDefinition"]["railVersion"],
                                    vector["agreement"]["terms"]["rail"]["railVersion"])
                self.assertEqual(evaluate(copy.deepcopy(vector)), ("fail", "rail-version"))

    def test_parser_dependent_url_spellings_are_malformed_and_not_public(self):
        """Spellings that WHATWG/UTS-46 parsers resolve to a non-public host are XN-2 `error`.

        Sweeps the default-ignorable code points, raw and percent-encoded, over
        loopback, metadata, private and shared-address hosts, plus the `\\`
        authority and encoded or mapped `localhost` forms. Each is malformed under
        validate_ref, and public_http_target refuses it too for direct callers.
        """
        ignorables = ("­", "​", "⁠", "﻿", "͏", "᠋", "️")
        urls = []
        for host in ("127.0.0.1", "169.254.169.254", "10.0.0.1", "100.100.100.200"):
            head, _, tail = host.rpartition(".")
            for char in ignorables:
                for spelling in (char, quote(char)):
                    urls.append(f"https://{host}{spelling}/pay")
                    urls.append(f"https://{head}.{spelling}{tail}/pay")
            urls.append(f"https://{host}\\.seller.example/pay")
            urls.append(f"https://{host}\\@seller.example/pay")
        urls += [
            "https://%6c%6fcalhost/pay",
            "https://localhost%2e/pay",
            "https://local­host/pay",
            "https://ｌｏｃａｌｈｏｓｔ/pay",
            "https://127.0.0\t.1/pay",
            "https://seller.example /pay",
            "https://127.0.0.xn--1-/pay",
            "https://169.254.169.xn--254-/pay",
            "https://XN--LOCALHOST-/pay",
            "https://@127.0.0.1/pay",
            "https://seller.example/pay?q=#",
        ]
        self.assertEqual(len(urls), 4 * (7 * 2 * 2 + 2) + 11)
        base = self.by_name["protocol-v2-exact-success"]["agreement"]["terms"]["rail"]
        self.assertEqual(validate_ref(base), "pass")
        for url in urls:
            with self.subTest(url=url):
                ref = copy.deepcopy(base)
                ref["parameters"]["request"]["url"] = url
                self.assertEqual(validate_ref(ref), "error")
                self.assertFalse(public_http_target(url))
        for url in ("https://xn--bcher-kva.example/pay", "https://seller.example/p%C3%A9",
                    "https://seller.example/pay?q=%5C", "https://XN--BCHER-KVA.example/pay",
                    "https://xn--bcher-kva.example./pay", "https://seller.example:443/pay",
                    "https://seller.example:8443/pay", "https://seller.example/a@b"):
            with self.subTest(url=url):
                ref = copy.deepcopy(base)
                ref["parameters"]["request"]["url"] = url
                self.assertEqual(validate_ref(ref), "pass")
                self.assertTrue(public_http_target(url))

    def test_a_label_conversion_failure_is_malformed_not_an_exception(self):
        """XN-2: every `idna` conversion failure means "not an A-label", never an exception.

        `idna` 3.6 raises a bare ValueError on the Tangut/ZWNJ label; other
        releases raise IDNAError. Force each exception class from both conversion
        stages so this failure handling does not depend on the installed release.
        """
        url = "https://xn--ukba655qaaaa14431eeaaba.c/pay"
        self.assertFalse(_is_a_label("xn--ukba655qaaaa14431eeaaba"))
        self.assertFalse(request_url_syntax_ok(url))
        vector = self.by_name["request-url-a-label-tangut-joiner"]
        self.assertEqual(vector["agreement"]["terms"]["rail"]["parameters"]["request"]["url"], url)
        effects = {}
        self.assertEqual(evaluate(copy.deepcopy(vector), effects), ("error", "rail-ref-shape"))
        self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)
        for stage in ("ulabel", "alabel"):
            for exc in (idna.IDNAError("x"), UnicodeError("x"), ValueError("no such name")):
                with self.subTest(stage=stage, raised=type(exc).__name__), \
                        mock.patch.object(idna, stage, side_effect=exc) as conversion:
                    self.assertFalse(_is_a_label("xn--bcher-kva"))
                    self.assertFalse(request_url_syntax_ok("https://xn--bcher-kva.example/pay"))
                    self.assertEqual(conversion.call_count, 2)

    def test_ipv4_mapped_spellings_match_their_ipv4_verdict(self):
        """§6.3.6 requires equivalent IPv4-mapped IPv6 spellings to reach the same verdict."""
        for literal, _ in NON_PUBLIC_CLASS_CASES:
            address = ipaddress.ip_address(literal)
            if address.version != 4:
                continue
            with self.subTest(address=literal):
                self.assertEqual(public_http_target(f"https://{literal}/pay"),
                                 public_http_target(f"https://[::ffff:{literal}]/pay"))

    def test_pb2_tier_comes_from_the_signed_selection_before_the_wallet(self):
        """PB-2 step 1(b): an applicable claim gates the wallet and never falls through to tier 3."""
        refused = {
            "pb2-negotiated-chain-claim-controls-other-address": ("fail", "payee-destination"),
            "pb2-negotiated-chain-linkage-unresolved-pauses": ("indeterminate", "payee-linkage-unresolved"),
            "pb2-negotiated-chain-linkage-absent-pauses": ("indeterminate", "payee-linkage-unresolved"),
            "pb2-negotiated-chain-linkage-error-stays-error": ("error", "payee-linkage-error"),
            "pb2-payee-bundle-not-pinned": ("fail", "payee-bundle"),
            "pb2-runtime-payee-bundle-hash-not-signed": ("fail", "payee-bundle"),
        }
        for name, want in refused.items():
            with self.subTest(vector=name):
                vector = self.by_name[name]
                # The co-signed payout binding (tier 3) is present and matches.
                self.assertEqual(vector["runtime"]["payee"]["payeeAddress"],
                                 payout_bindings(vector["agreement"], 3)[0]["payeeAddress"])
                effects = {"walletAuthorizationCalls": 0}
                self.assertEqual(evaluate(copy.deepcopy(vector), effects), want)
                self.assertEqual(effects["walletAuthorizationCalls"], 0)
        # Each refusal depends on the gate: the same vector with the claim's
        # chain taken from nowhere (an implementation ignoring step 1(b)) pays.
        for name in ("pb2-negotiated-chain-claim-controls-other-address",
                     "pb2-negotiated-chain-linkage-unresolved-pauses",
                     "pb2-negotiated-chain-linkage-error-stays-error"):
            with self.subTest(without_step_1b=name):
                with mock.patch(f"{__name__}.selection_eip155_chain", return_value=None):
                    self.assertEqual(evaluate(copy.deepcopy(self.by_name[name])), ("pass", None))
        for name in ("pb2-negotiated-chain-controlled-claim-binds-payout",
                     "pb2-other-chain-claim-leaves-tier3",
                     "pb2-name-style-subchain-claim-leaves-tier3",
                     "pb2-leading-zero-chain-claim-leaves-tier3",
                     "pb2-solana-selection-evm-claim-leaves-tier3",
                     "pb2-challenge-chain-cannot-make-tier2-applicable"):
            with self.subTest(vector=name):
                effects = {}
                self.assertEqual(evaluate(copy.deepcopy(self.by_name[name]), effects), ("pass", None))
                self.assertEqual(effects["walletAuthorizationCalls"], 1)

    def test_pb2_claim_profile_matches_the_static_rail_corpus(self):
        """The negotiated arm reads a cci-xm claim's chain exactly as the static-rail PB-2 corpus does."""
        sys.path.insert(0, str(ROOT / "tests"))
        from test_cci_xm_rail_chain_applicability_vectors import (
            VECTORS as STATIC_VECTORS,
            claim_eip155_chain as static_claim_chain,
        )
        claims = {vector["claim"] for vector in json.loads(
            STATIC_VECTORS.read_text(encoding="utf-8"))["vectors"]}
        claims |= {claim["ref"] for vector in self.vectors
                   for claim in vector["payeeBundle"]["claims"]}
        claims |= {f"cci-xm:evm:{2**53 - 1}:0xab", f"cci-xm:evm:{2**53}:0xab", "cci-xm:evm:1:",
                   "cci-xm:evm:1:?p=1", "CCI-XM:evm:1:0xab", "cci-xm:EVM:1:0xab", 7}
        for claim in claims:
            with self.subTest(claim=claim):
                self.assertEqual(claim_eip155_chain(claim), static_claim_chain(claim))
        for network, want in (("eip155:8453", "eip155:8453"), ("eip155:08453", None),
                              ("eip155:0", None), (f"eip155:{2**53}", None),
                              (f"eip155:{2**53 - 1}", f"eip155:{2**53 - 1}"),
                              ("solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", None)):
            with self.subTest(network=network):
                self.assertEqual(selection_eip155_chain(network), want)

    def test_a_paid_protocol_job_is_held_out_of_current_use(self):
        """RD-7/CUR-4/CUR-5: a pay-x402 success outside a finality-bound copy holds current use.

        `x402:protocol` cannot produce FinalityBoundSettlementEvidence, so its
        success can appear only in a weaker copy, which the DACS-5 reference
        consumer holds as `indeterminate` (no derivation under CUR-2).
        """
        sys.path.insert(0, str(ROOT / "tests"))
        import dacs5_reference
        self.assertIn("pay-x402", dacs5_reference.PAYMENT_PHASES)
        self.assertTrue(dacs5_reference._job_successful_payment_without_strong_finality(
            {"phaseSummary": [{"kind": "pay-x402", "outcome": "ok"}]}, {}))
        self.assertFalse(dacs5_reference._job_successful_payment_without_strong_finality(
            {"phaseSummary": [{"kind": "pay-x402", "outcome": "failed"}]}, {}))
        self.assertEqual(self.by_name["definition-with-consumer-finality-profile"]["expected"], "error")

    def test_spec_contains_load_bearing_guards(self):
        spec = (ROOT / "spec/DACS-4-SETTLE.md").read_text(encoding="utf-8")
        for text in (
            'railId: "x402:protocol"',
            'resolution: { kind: "x402-payment-required" }',
            "the first matching `railId`",
            "No wallet or signing operation may occur before all of those gates pass",
            "paymentRequiredHash = lowerhex(SHA-256(UTF8(JCS(nfcPaymentRequired))))",
            'MUST NOT produce `SettlementEvidence.outcome: "success"`',
            '`availability: "disabled"`',
            "MUST NOT rewrite",
            "Its host MUST NOT contain `%`.",
            "every name under `.localhost` are never public.",
            "An IPv6 address that embeds an IPv4 address is not public when an address it carries is not.",
            "The local-use NAT64 prefix `64:ff9b:1::/48` is never public.",
            "Each received object MUST first pass CORE §B.2 CF-5 raw JSON admission over its exact received bytes",
            "A challenge that CF-5 refuses is malformed and yields `error` before authorization.",
            "needs no ledger data, so it is `error` even while that data is unavailable or not final.",
            "No answer, a 5xx, 408, or 429 is transient: nothing is authorized, the result is "
            "`indeterminate`, and the unpaid request may be retried.",
            "internationalized host MUST be signed in A-label form",
            "every host label that begins with `xn--` in any letter case MUST be an RFC 5890 A-label",
            "no userinfo or fragment, even an empty one.",
            "A non-empty port MUST be decimal digits with a value of at most 65535.",
            "It MUST also compare it with the authenticated ledger",
            "The retained state then records `settlementTransaction` as absent or `null`, and the "
            "identity reconciles without it.",
            "The handler MUST compare it with the reconciled transaction in the XN-7 adapter form, "
            "so the same transaction in another prefix or hexadecimal case matches.",
            "A retained value with no such form, or one that names another transaction, is a "
            "recorded response defect.",
            "A retry takes it the same way as the first attempt; a stored record is never part of "
            "the retained identity.",
            "The event that the authorization identity resolves to is identified by its transaction "
            "and its `settlementEvent`, and a missing one is `indeterminate`.",
            "A transaction with no XN-7 adapter form, or a `settlementEvent` that is not "
            "adapter-canonical or does not name that transaction on the selected network, is a "
            "malformed coordinate and yields `error`.",
            "That holds whatever the record's defect, such as an invalid signature, another "
            "reference count, or another or a malformed transaction.",
            "A transaction that only the settlement response, its retained copy, or a stored record "
            "names is not resolved by that identity.",
            "An address in the authorization identity compares under XN-5, so a malformed one "
            "yields `error` even when both spellings are identical.",
            "the adapter MUST compare the following addresses as 20-byte values.",
            "They are `payTo`, the PB-1 payout binding and `PaymentPhaseInput.payee.payeeAddress`; "
            "the `payingKey` address component, the derived payer and the authorization payer; "
            "the response `payer`; and the authenticated event's payer and payee.",
            "So is the selection `asset`, against the adapter's asset metadata, the challenge, "
            "and the authenticated event.",
            "On an EIP-155 network the `asset` compares as an XN-5 address, so letter case alone "
            "is not a mismatch.",
            "A challenge whose `extra.assetTransferMethod` names another form, such as `permit2` "
            "or `erc7710`, therefore MUST reject before signing; an absent member selects EIP-3009.",
            "The challenge is read only from the `PAYMENT-REQUIRED` response header",
            "For version 2 that is exactly one added `PAYMENT-SIGNATURE` header field",
            "The selection's `x402Version` MUST be the integer `2`",
            "That identifier MUST equal `selection.currency`",
            "closed §9.5.7.1 table names for the selected CAIP-2 network.",
            "or a nonce still unused at a finalized block whose authenticated timestamp is greater "
            "than or equal to the retained authorization's `validBefore`",
            "A record already anchored at the write-once PC-2 address MUST NOT be overwritten",
            "A retry MUST first apply the same XN-1 definition and XN-2 reference-shape gates as "
            "the first attempt",
            "The handler retains `validBefore` as integer seconds, a safe integer",
            "The field's value MUST be the x402 v2 `PaymentPayload` of this authorization for the "
            "matched requirement",
            "With `required: false` the extension is descriptive. It needs no local capability",
            "`schema` MUST equal one of two pinned schemas under JCS.",
            "which adds `\"pattern\": \"^[a-zA-Z0-9_-]+$\"` to `id`",
            "each an ASCII letter, digit, hyphen, or underscore",
            "`nonce` MUST be the SB-3 derived nonce.",
            "The handler MUST retain that `validBefore` in the XN-11 form before the wallet signs.",
            "The message and client signatures MUST equal the durably retained XN-11 authorization identity.",
            "verify all required signatures including the sponsor signature",
            "If the adapter cannot resolve the transaction or obtain the authenticated message/signatures",
            "`base-sepolia` 84532, `base` 8453, `avalanche-fuji` 43113, and `avalanche` 43114. Any "
            "other v1 network maps to no `chainId`.",
            "**Failure modes (`x402:protocol` only).**",
            "**Failure modes (legacy `x402:default`).**",
            "`x402:protocol` is an optional rail and does not gate v0.8\nconformance.",
            "Each MUST be `0x` followed by 40 hexadecimal digits in either letter case.",
            "An adapter MUST accept such an address whatever its EIP-55 checksum.",
            "Any other value is a malformed coordinate and yields `error`.",
            "A response `payer` in any other form is instead a response defect under XN-11.",
            "Other networks compare these addresses as exact strings.",
            "When no version-selected object decodes, that preimage is the JSON value `null`.",
            "After authorization the handler MUST take the payment disposition only from this "
            "reconciliation of the retained identity against authenticated ledger data (XN-8), "
            "and MUST NOT require a success evidence record to reach it.",
            "Ledger data that is unavailable, unreadable, or not yet final is `indeterminate`.",
            "A finalized event that the authorization identity resolves to and that contradicts "
            "the authorization is `fail`.",
            "With no event for the identity, a terminal non-settlement that the scheme profile "
            "proves from finalized ledger data is `fail`.",
            "Response material that is missing, changed, malformed, or does not recompute, and a "
            "stored record that does not verify, never replace this disposition.",
            "These are verdicts on a success record; the handler's payment disposition never "
            "comes from a record (XN-11).",
            "Such a record never decides the payment disposition, and XN-11 states whether it is "
            "rebuilt.",
            "- unanchored stored record whose challenge or receipt hash does not recompute → the "
            "record is discarded and rebuilt from the retained challenge and response; it never "
            "ends the payment phase",
            "- such a response defect without any ledger event resolved for the authorization "
            "identity → reconciliation-pending / `indeterminate`, never `permanent`",
            "- finalized ledger event resolved for the authorization identity that contradicts the "
            "authorization (another amount, payee, or asset) → `permanent` from the ledger (XN-8)",
            "| `counterparty` | AP2 mandate revoked, x402 server refused before authorization |",
            "The ISATAP interface identifier `0:5efe` or `200:5efe` carries an IPv4 address after "
            "any prefix.",
            "The handler MUST treat each NAT64 prefix its own network uses, whether discovered "
            "under RFC 7050 or configured locally, like `64:ff9b::/96`.",
            "The v0.8 EIP-155 `exact` binding authorizes only through EIP-3009, whose SB-3 nonce "
            "binding is therefore always mandatory there.",
            "so v0.8 defines no Permit2 binding for `x402:protocol`.",
            "A verifier MUST take this binding policy from the pinned definition and the signed "
            "selection, never from the observed ledger event,",
            "The handler MUST itself classify each member of the matched requirement's `extra` "
            "and of `PaymentRequired.extensions` from the selected adapter's definition of that "
            "member.",
            "A list of action-bearing members supplied beside the challenge is not that "
            "classification.",
            "A member that the selected adapter does not define is unclassified and MUST reject "
            "before signing, like an unsupported action-bearing member.",
            "The unpaid and the paid request MUST each use the signed `request.method` and "
            "`request.url` exactly.",
        ):
            self.assertIn(text, spec)
        # Notes are hard-wrapped blockquotes: compare without wrapping or markers.
        flat = " ".join(spec.split()).replace(" > ", " ")
        self.assertIn("Which code points an A-label may contain follows the implementer's "
                      "IDNA2008 tables and their Unicode version.", flat)
        # XN-1 is hard-wrapped too.
        self.assertIn("The definition that a handler or verifier applies MUST be the revision "
                      "whose `railVersion` equals the selected reference's `railVersion`. Another "
                      "revision, even one validly signed and well formed, MUST be rejected: by the "
                      "handler before the unpaid request, and by a verifier before it judges a "
                      "record.", flat)
        # RD-7 states the current-use consequence of having no finality profile.
        self.assertIn("A job paid through `x402:protocol` therefore cannot be represented by the "
                      "finality-bound bundle that DACS-5 CUR-4 requires for a current successful "
                      "payment, and under CUR-2 a current-use request that includes that job "
                      "emits no derivation.", flat)

    def test_listing_admission_rule_precedes_registry_checks_and_is_cross_referenced(self):
        """XN-2's listing rule needs no registry: APR-1 carries it, not APR-2, and LRR-4 points to it."""
        spec = (ROOT / "spec/DACS-4-SETTLE.md").read_text(encoding="utf-8")

        def block(start, end):
            begin = spec.index(start)
            return " ".join(spec[begin:spec.index(end, begin)].split())

        apr1 = block("- (APR-1) ", "- (APR-2) ")
        apr2 = block("- (APR-2) ", "- (APR-3) ")
        xn2 = block("- **(XN-2) ", "- **(XN-3) ")
        self.assertIn("An `x402:protocol` alternative MUST NOT appear unless "
                      "`commit-payee-bound-agreement` is the Listing's only agreement "
                      "commitment phase (XN-2).", apr1)
        self.assertNotIn("x402:protocol", apr2)
        self.assertIn("before registry-dependent checks", xn2)
        rule_text, _, notes = xn2.partition("> **Note (non-normative).**")
        self.assertNotIn("later compatible extension", rule_text)
        self.assertIn("later compatible extension", notes)
        lrr = (ROOT / "spec/DACS-1-IDENTIFY.md").read_text(encoding="utf-8")
        lrr4 = next(line for line in lrr.splitlines() if line.startswith("- (LRR-4) "))
        self.assertIn("DACS-4 XN-2 commitment-phase rule", lrr4)
        # LRR-5 must agree with LRR-4 when the registry is unavailable.
        lrr5 = next(line for line in lrr.splitlines() if line.startswith("- (LRR-5) "))
        pre_registry, _, rest = lrr5.partition("Otherwise, failure to authenticate")
        self.assertIn("DACS-4 APR-1 malformation and an LRR-4 `x402:protocol` "
                      "commitment-phase violation need no registry", pre_registry)
        self.assertIn("even when registry authority cannot be authenticated", pre_registry)
        self.assertIn("returns `indeterminate`", rest)

    def test_pay_alternative_members_must_be_objects(self):
        """A non-object alternative, or fewer than two, is APR-1 `rejected` (`fail`), not offered."""
        base = self.by_name["listing-protocol-alternative-with-payee-bound-commit-admitted"]["listing"]
        self.assertIsNone(listing_agreement_type_violation(base))
        for member in (1, "x402:protocol", None, []):
            with self.subTest(member=member):
                listing = copy.deepcopy(base)
                slot = next(step for step in listing["pipeline"] if step["kind"] == "pay-alternative")
                slot["parameters"]["alternatives"].append(member)
                self.assertEqual(listing_agreement_type_violation(listing), ("fail", "listing-shape"))
        for count in (0, 1):
            with self.subTest(alternatives=count):
                listing = copy.deepcopy(base)
                slot = next(step for step in listing["pipeline"] if step["kind"] == "pay-alternative")
                del slot["parameters"]["alternatives"][count:]
                self.assertEqual(listing_agreement_type_violation(listing), ("fail", "listing-shape"))

    def test_listing_shape_is_a_rejection_not_an_error(self):
        """DACS-1 ListingValidationDisposition has no `error`; APR-1 calls these Listings `rejected`."""
        names = [name for name, vector in self.by_name.items()
                 if vector.get("expectedReason") == "listing-shape"]
        self.assertEqual(len(names), 11)
        for name in names:
            with self.subTest(vector=name):
                self.assertEqual(self.by_name[name]["operation"], "admit-listing")
                self.assertEqual(evaluate(self.by_name[name]), ("fail", "listing-shape"))

    def test_legacy_procedure_keeps_single_event_success_guard(self):
        """The condensed legacy x402:default procedure keeps its success MUST NOT."""
        spec = (ROOT / "spec/DACS-4-SETTLE.md").read_text(encoding="utf-8")
        start = spec.index("**Legacy static procedure and receipt rules.**")
        procedure = " ".join(spec[start:spec.index("- **(X402-1)", start)].split())
        self.assertIn(
            "A handler that cannot identify one settling event MUST NOT emit success evidence",
            procedure,
        )

    def test_received_object_hashes_apply_cf1_nfc_pass(self):
        """XN-7 hashes NFC(JCS) of both received objects; raw-string hashing fails."""
        vector = self.by_name["received-objects-non-nfc-strings-hash-after-cf1"]
        self.assertEqual(evaluate(vector), ("pass", None))
        required = vector["http"]["paymentRequired"]
        response = decode_response_header(vector["http"]["responseHeader"], 2)
        ref = vector["evidence"]["paymentTxRefs"][0]

        def without_nfc(value):
            # RFC 8785 bytes for these integer/string-only objects, minus CF-1.
            return hashlib.sha256(json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")).hexdigest()

        for name, received, committed in (
            ("PaymentRequired", required, ref["paymentRequiredHash"]),
            ("settlement response", response, ref["paymentReceiptHash"]),
        ):
            with self.subTest(object=name):
                raw = json.dumps(received, ensure_ascii=False)
                self.assertNotEqual(raw, unicodedata.normalize("NFC", raw))
                self.assertEqual(committed, digest(received))
                self.assertNotEqual(committed, without_nfc(received))

    def test_fr2_rate_amount_rounds_half_up_at_the_selection_precision(self):
        """FR-2: price × rateBps ÷ 10000 rounds half-up once, at assetDecimals, to CD-1."""
        for amount, rate_bps, decimals, want in (
            ("1.25", 33, 6, "0.004125"),
            ("0.000001", 5000, 6, "0.000001"),
            ("0.000001", 4999, 6, "0"),
            ("0.000005", 5000, 6, "0.000003"),
            ("0.000000000000000005", 5000, 18, "0.000000000000000003"),
            ("0.000000000000000005", 5000, 6, "0"),
            ("10", 10000, 0, "10"),
            ("1.5", 3333, 0, "0"),
            ("1.5", 3334, 0, "1"),
            ("123456789012345678901234567.25", 1, 2, "12345678901234567890123.46"),
        ):
            with self.subTest(amount=amount, rate_bps=rate_bps, decimals=decimals):
                self.assertEqual(fr2_rate_amount(amount, rate_bps, decimals), want)
        for amount, rate_bps, decimals in (("1.250", 1, 6), ("1", True, 6), ("1", -1, 6),
                                           ("1", 1, 256), ("1", 1, 2.0)):
            with self.subTest(amount=amount, rate_bps=rate_bps, decimals=decimals):
                with self.assertRaises(ValueError):
                    fr2_rate_amount(amount, rate_bps, decimals)

    def test_paid_payload_carries_the_authorization_for_the_matched_requirement(self):
        """XN-6/§9.5.7.1: the paid PAYMENT-SIGNATURE is upstream's v2 PaymentPayload.

        Its `accepted` is the matched requirement, and its EIP-3009
        authorization is the payer's, to payTo, for the exact amount, with the
        retained validBefore and the SB-3 nonce. The pre-fix `{"x402Version":2}`
        header is not a paid request.
        """
        vector = self.by_name["protocol-v2-exact-success"]
        header = vector["runtime"]["paidHeaders"]["PAYMENT-SIGNATURE"]
        payload = json.loads(base64.b64decode(header))
        required = vector["http"]["paymentRequired"]
        self.assertEqual(set(payload), {"x402Version", "resource", "accepted", "payload", "extensions"})
        self.assertEqual(payload["accepted"], required["accepts"][0])
        authorization = payload["payload"]["authorization"]
        self.assertEqual(
            (authorization["from"], authorization["to"], authorization["value"], authorization["validBefore"]),
            (vector["runtime"]["payer"]["paymentAddress"], required["accepts"][0]["payTo"], "1250000",
             str(vector["runtime"]["reconciliationState"]["validBefore"])))
        self.assertEqual(authorization["nonce"], "0x" + hashlib.sha256(
            b"dacs-sb3:v1:01M0NVBGYEANE562QQXD33C7WX:3").hexdigest())
        for value in ("garbage", "", base64.b64encode(b"{}").decode("ascii"),
                      base64.b64encode(b'{"x402Version":2}').decode("ascii")):
            with self.subTest(value=value):
                changed = copy.deepcopy(vector)
                changed["runtime"]["paidHeaders"]["PAYMENT-SIGNATURE"] = value
                self.assertEqual(evaluate(changed), ("fail", "paid-request-payload"))
        # A time beyond uint256's 78 digits is refused, never an int() overflow.
        long_time = copy.deepcopy(payload)
        long_time["payload"]["authorization"]["validBefore"] = "9" * 5000
        changed = copy.deepcopy(vector)
        changed["runtime"]["paidHeaders"]["PAYMENT-SIGNATURE"] = base64.b64encode(
            json.dumps(long_time).encode("utf-8")).decode("ascii")
        self.assertEqual(evaluate(changed), ("fail", "paid-request-payload"))

    def test_unsigned_payload_defects_never_reach_the_wallet(self):
        cases = [v for v in self.vectors if v["name"].startswith("paid-request-payload-")
                 and v.get("expectedReason") == "paid-request-payload"]
        self.assertEqual(len(cases), 31)
        for vector in cases:
            with self.subTest(vector=vector["name"]):
                effects = {}
                result = evaluate(copy.deepcopy(vector), effects)
                signed = vector["name"] in {"paid-request-payload-signature-absent",
                                            "paid-request-payload-signature-short"}
                self.assertEqual(result, ("pass" if signed else "fail", "paid-request-payload"))
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), int(signed))
                if signed:
                    self.assertEqual(effects["handlerFault"], "paid-request-payload")
                    self.assertEqual(effects["handlerErrorClass"], "permanent")
                    self.assertIn("builtEvidence", effects)
                else:
                    self.assertEqual(vector["expectedErrorClass"], "permanent")
                    self.assertNotIn("builtEvidence", effects)

    def test_payload_defects_discovered_after_signing_only_record_a_handler_fault(self):
        """Even a changed envelope after the wallet call cannot replace reconciliation."""
        cases = [v for v in self.vectors if v["name"].startswith("paid-request-payload-")
                 and v.get("expectedReason") == "paid-request-payload"]
        wallet = record_wallet_authorization
        for bad in cases:
            is_solana = bad["agreement"]["terms"]["rail"]["parameters"]["selection"]["network"].startswith(
                "solana:")
            base = self.by_name["protocol-v2-solana-exact-success" if is_solana
                                else "protocol-v2-exact-success"]
            for state, ledger, verdict, reason in (
                ("settled", base["ledger"], "pass", "paid-request-payload"),
                ("unavailable", {"available": False}, "indeterminate", "independent-settlement-unavailable"),
                ("pending", {"available": True, "finalized": True}, "indeterminate", "authorization-unsettled"),
                ("contradictory", {**base["ledger"], "amount": "1"}, "fail", "ledger-event"),
                ("malformed", {**base["ledger"], "transaction": None}, "error", "ledger-transaction-form"),
            ):
                with self.subTest(payload=bad["name"], ledger=state):
                    changed = copy.deepcopy(base)
                    changed["ledger"] = copy.deepcopy(ledger)

                    def sign_then_observe_defect(effects):
                        wallet(effects)
                        changed["runtime"]["paidHeaders"] = copy.deepcopy(bad["runtime"]["paidHeaders"])

                    effects = {}
                    with mock.patch(__name__ + ".record_wallet_authorization", sign_then_observe_defect):
                        self.assertEqual(evaluate(changed, effects), (verdict, reason))
                    self.assertEqual(effects["walletAuthorizationCalls"], 1)
                    self.assertEqual(effects["handlerFault"], "paid-request-payload")
                    self.assertEqual(effects["handlerErrorClass"], "permanent")
                    self.assertEqual("builtEvidence" in effects, verdict == "pass")

    def test_non_string_record_hashes_are_verifier_errors_and_rebuilt_by_handlers(self):
        for member in ("paymentRequiredHash", "paymentReceiptHash"):
            for shape in ("number", "null", "list", "object"):
                for operation in ("verify-evidence", "execute", "retry"):
                    name = f"{operation}-record-{member}-not-string-{shape}"
                    with self.subTest(vector=name):
                        vector = self.by_name[name]
                        self.assertTrue(verify_record_signature(vector))
                        effects = {}
                        self.assertEqual(evaluate(copy.deepcopy(vector), effects),
                                         ("error" if operation == "verify-evidence" else "pass",
                                          "evidence-hash-shape"))
                        self.assertEqual(effects.get("walletAuthorizationCalls", 0), int(operation == "execute"))
                        if operation != "verify-evidence":
                            self.assertIn("builtEvidence", effects)
                            unavailable = copy.deepcopy(vector)
                            unavailable["ledger"] = {"available": False}
                            effects = {}
                            self.assertEqual(evaluate(unavailable, effects),
                                             ("indeterminate", "independent-settlement-unavailable"))
                            self.assertNotIn("builtEvidence", effects)

    def test_paid_payload_accepts_the_matched_requirement_when_it_is_not_first(self):
        """XN-4/XN-6: `accepted` is the one matched requirement, here the second.

        The first differs only in amount. The second matches the signed
        selection only with its payTo compared as an XN-5 value, or its
        `extra` compared without the Solana hints, so a payload built from the
        first requirement, or from a match that skips either rule, is refused.
        """
        for name in ("paid-request-payload-accepted-second-checksummed-payto",
                     "paid-request-payload-accepted-second-solana-hint"):
            with self.subTest(vector=name):
                vector = self.by_name[name]
                accepts = vector["http"]["paymentRequired"]["accepts"]
                payload = json.loads(base64.b64decode(vector["runtime"]["paidHeaders"]["PAYMENT-SIGNATURE"]))
                self.assertEqual(payload["accepted"], accepts[1])
                self.assertNotEqual(accepts[0], accepts[1])
                effects = {}
                self.assertEqual(evaluate(copy.deepcopy(vector), effects), ("pass", None))
                self.assertEqual(effects.get("walletAuthorizationCalls"), 1)
                first = copy.deepcopy(vector)
                first["runtime"]["paidHeaders"]["PAYMENT-SIGNATURE"] = base64.b64encode(json.dumps(
                    {**payload, "accepted": accepts[0]}).encode("utf-8")).decode("ascii")
                self.assertEqual(evaluate(first), ("fail", "paid-request-payload"))
        self.assertNotEqual(self.by_name["paid-request-payload-accepted-second-checksummed-payto"][
            "http"]["paymentRequired"]["accepts"][1]["payTo"], self.by_name[
            "paid-request-payload-accepted-second-checksummed-payto"]["agreement"]["terms"][
            "payoutBindings"][0]["payeeAddress"])
        self.assertIn("recentBlockhash", self.by_name["paid-request-payload-accepted-second-solana-hint"][
            "http"]["paymentRequired"]["accepts"][1]["extra"])

    def test_legacy_v1_continuation_carries_the_receipt_hash_corpus_v1_receipt(self):
        """X402-1..X402-3: the v1 vectors mirror x402-receipt-hash's v1 `pass` case.

        Its receipt, hash, transaction and chain are that case's, so the two
        corpora cannot disagree on a valid v1 receipt with a recorded chain.
        """
        receipts = json.loads((ROOT / "conformance/vectors/security/x402-receipt-hash-v0.1.json").read_text(
            encoding="utf-8"))
        v1 = next(item for item in receipts["vectors"] if item["name"] == "v1-success-x-payment-response")
        self.assertEqual(v1["expected"], "pass")
        for name in ("legacy-v1-continuation-registered-network", "legacy-v1-replay-presented-response"):
            with self.subTest(vector=name):
                vector = self.by_name[name]
                ref = vector["evidence"]["paymentTxRefs"][0]
                header = vector["http"]["responseHeader"]
                self.assertEqual(header["name"], v1["responseHeader"]["name"])
                self.assertEqual(json.loads(base64.b64decode(header["value"])),
                                 json.loads(base64.b64decode(v1["responseHeader"]["value"])))
                self.assertEqual(
                    (ref["protocolVersion"], ref["paymentReceiptHash"], ref["settlementTxHash"], ref["chainId"]),
                    ("1", v1["evidence"]["paymentReceiptHash"], v1["evidence"]["settlementTxHash"],
                     v1["evidence"]["chainId"]))
                self.assertIsNone(legacy_receipt_defect(header, ref))
        self.assertEqual(X402_V1_NETWORK_CHAIN_IDS, {
            "base-sepolia": 84532, "base": 8453, "avalanche-fuji": 43113, "avalanche": 43114})

    def test_upstream_block_names_every_mirrored_source(self):
        """§9.5.7.1 and X402-3: the corpus pins the SDK schema files and the v1 table's source.

        The second `payment-identifier` schema comes from the SDK files, and
        X402-3's v1 table from the v1 specification at the receipt-hash pin.
        """
        spec = (ROOT / "spec/DACS-4-SETTLE.md").read_text(encoding="utf-8")
        upstream = self.data["upstream"]
        self.assertEqual(upstream["paymentIdentifierSdkSchemas"], [
            "typescript/packages/extensions/src/payment-identifier/schema.ts",
            "python/x402/extensions/payment_identifier/schema.py",
            "go/extensions/paymentidentifier/schema.go",
        ])
        for path in upstream["paymentIdentifierSdkSchemas"]:
            with self.subTest(path=path):
                self.assertIn(f"`{path}`", spec)
        receipts = json.loads((ROOT / "conformance/vectors/security/x402-receipt-hash-v0.1.json").read_text(
            encoding="utf-8"))
        v1 = upstream["v1Protocol"]
        self.assertEqual(f"{upstream['repository']}@{v1['commit']}", receipts["source"])
        self.assertEqual(v1["path"], "specs/x402-specification-v1.md")
        self.assertIn(f"at `{receipts['source']}` (`{v1['path']}` §11.1)", spec)

    def test_plan_lists_the_witnesses_this_corpus_cannot_give(self):
        """The plan names each MUST this corpus cannot witness and the suite that owes it."""
        plan = (ROOT / "spec/CONFORMANCE-PLAN.md").read_text(encoding="utf-8")
        row = next(line for line in plan.splitlines()
                   if line.startswith("| XN-2 / XN-10 / RD-7 witnesses owed outside the x402 corpus"))
        self.assertTrue(row.endswith("| none yet (open) |"))
        for owed in ("DACS-1 §6.3.6 checks on each connection", "DNS rebinding",
                     "decoded-response-size bounds", "owed by an adapter suite",
                     "XN-10 superseding disabled `x402:default` revision",
                     "owed by the registry-resolution and RAV corpora",
                     "RD-7 consequence", "owed by the DACS-5 current-use corpus"):
            with self.subTest(owed=owed):
                self.assertIn(owed, row)
        self.assertIn("definition-with-consumer-finality-profile", self.by_name)
        self.assertTrue(any(name.startswith("bounded-fetch-") for name in self.by_name))

    def test_generator_cli_check_exits_nonzero_on_a_stale_file(self):
        """CI runs the generator's CLI: `--check` against a stale file exits 1.

        The script runs as `__main__` from a scratch root, whose committed
        corpus is stale, so the exit status comes from its own entrypoint.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "scripts" / GENERATOR.name
            output = root / VECTORS.relative_to(ROOT)
            script.parent.mkdir()
            output.parent.mkdir(parents=True)
            script.write_bytes(GENERATOR.read_bytes())
            environment = {**os.environ, "PYTHONPATH": str(ROOT / "scripts")}
            for text, code, message in (
                (VECTORS.read_text(encoding="utf-8").replace('"count": ', '"count": 1', 1), 1, "stale"),
                (VECTORS.read_text(encoding="utf-8"), 0, "OK"),
            ):
                output.write_text(text, encoding="utf-8")
                with self.subTest(code=code):
                    result = subprocess.run([sys.executable, str(script), "--check"], cwd=root,
                                            capture_output=True, text=True, env=environment)
                    self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                    self.assertIn(message, result.stdout)

    def test_exact_atomic_never_rounds_beyond_decimal_context_precision(self):
        """XN-5 exact shifting has no 28-digit precision limit and never rounds."""
        for amount, decimals, want in (
            ("1.25", 6, "1250000"),
            ("123456789012345678901234567.25", 6, "123456789012345678901234567250000"),
            ("1234567890123456789012345678901234", 0, "1234567890123456789012345678901234"),
            ("0.000001", 6, "1"),
        ):
            with self.subTest(amount=amount, decimals=decimals):
                self.assertEqual(exact_atomic(amount, decimals, ATOMIC_AMOUNT_MAX["eip155"]), want)
        for amount, decimals in (
            ("1000000000000000000000000.0000001", 6),
            ("1234567890123456789012345678.9", 0),
            ("1.0000001", 6),
            ("0", 6),
            ("0.0000001", 6),
        ):
            with self.subTest(amount=amount, decimals=decimals):
                with self.assertRaises(ValueError):
                    exact_atomic(amount, decimals, ATOMIC_AMOUNT_MAX["eip155"])

    def test_exact_atomic_enforces_the_binding_amount_type_and_decimals_bound(self):
        """XN-5 overflow is the binding's native amount type; XN-2 bounds decimals to uint8."""
        for namespace, ceiling in (("eip155", 2**256 - 1), ("solana", 2**64 - 1)):
            with self.subTest(namespace=namespace):
                self.assertEqual(ATOMIC_AMOUNT_MAX[namespace], ceiling)
                self.assertEqual(exact_atomic(str(ceiling), 0, ceiling), str(ceiling))
                with self.assertRaises(ValueError):
                    exact_atomic(str(ceiling + 1), 0, ceiling)
        uint256 = ATOMIC_AMOUNT_MAX["eip155"]
        self.assertEqual(exact_atomic("0." + "0" * 254 + "1", 255, uint256), "1")
        # Only a cheap out-of-range value here; huge ones run in a bounded child
        # process (test_huge_asset_decimals_are_rejected_before_exponentiation).
        with self.assertRaises(ValueError):
            exact_atomic("1", 256, uint256)
        with self.assertRaises(ValueError):
            exact_atomic("1", 6, None)  # a network with no exact binding has no ceiling

    def test_huge_asset_decimals_are_rejected_before_exponentiation(self):
        """A safe-integer assetDecimals of 10**9 must not reach 10 ** decimals.

        Runs in a child process with a 256 MiB address-space limit and a timeout,
        so an unbounded power of ten fails the test instead of stalling the suite.
        """
        script = (
            "import copy, json, sys\n"
            "import tests.test_x402_negotiated_protocol_vectors as m\n"
            "data = json.loads(m.VECTORS.read_text(encoding='utf-8'))\n"
            "raw = next(x for x in data['vectors'] if x['name'] == 'protocol-v2-exact-success')\n"
            "v = m.materialize_vector(data, raw)\n"
            "huge = 1_000_000_000\n"
            "for ref in (v['listing']['acceptedRails'][0], v['agreement']['terms']['rail'],\n"
            "            v['runtime']['selectedRailRef']):\n"
            "    ref['parameters']['selection']['assetDecimals'] = huge\n"
            "v['capability']['assetMetadata']['decimals'] = huge\n"
            "m.verify_artifact_signatures = lambda _v: True\n"
            "print(json.dumps(m.evaluate(v)))\n"
            "try:\n"
            "    m.exact_atomic('1', huge, m.ATOMIC_AMOUNT_MAX['eip155'])\n"
            "except ValueError:\n"
            "    print('rejected')\n"
        )
        limit = (
            "import resource; resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", limit + script], cwd=ROOT,
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        self.assertEqual(result.stdout.split(), ['["error",', '"rail-ref-shape"]', "rejected"])

    def test_noncanonical_event_vectors_change_only_the_dacs_side_key(self):
        """The SB-1 error vectors test the produced settlementEvent, not the response spelling."""
        base = self.by_name["protocol-v2-exact-success"]
        base_response = decode_response_header(base["http"]["responseHeader"], 2)
        for name in ("noncanonical-native-event-key", "noncanonical-native-event-key-uppercase"):
            with self.subTest(vector=name):
                vector = self.by_name[name]
                self.assertEqual(vector["expectedReason"], "native-event-key")
                self.assertEqual(vector["http"], base["http"])
                self.assertEqual(
                    decode_response_header(vector["http"]["responseHeader"], 2), base_response
                )
                event = vector["evidence"]["paymentTxRefs"][0]["settlementEvent"]
                self.assertNotRegex(event, EVM_EVENT)
                # The same hash spelled as a response transaction would be accepted.
                hash_text = event.split(":")[2]
                self.assertIsNotNone(adapter_canonical_transaction("eip155:8453", hash_text))

    def test_response_transaction_canonical_form_is_the_eip155_adapter_rule(self):
        """At most one 0x/0X, hex in either case, exactly 32 bytes; nothing else."""
        tx = "ab" * 32
        for spelling in (tx, "0x" + tx, "0X" + tx.upper(), "0x" + "Ab" * 32):
            with self.subTest(spelling=spelling):
                self.assertEqual(adapter_canonical_transaction("eip155:8453", spelling), tx)
        for spelling in ("0x" + tx[:63], "0x0x" + tx, "0x" + tx + "0", "0x" + "g" * 64,
                         " 0x" + tx, "0x", "", None, 1):
            with self.subTest(spelling=spelling):
                self.assertIsNone(adapter_canonical_transaction("eip155:8453", spelling))

    def test_evm_addresses_compare_as_20_byte_values(self):
        """XN-5: EIP-155 addresses ignore letter case and the EIP-55 checksum; Solana is exact."""
        lower = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
        for spelling in (
            lower,
            "0x" + lower[2:].upper(),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",   # EIP-55's own spelling
            "0x5AAEB6053f3e94c9b9a09f33669435e7ef1beaed",   # a wrong checksum is not checked
        ):
            with self.subTest(spelling=spelling):
                self.assertEqual(adapter_address("eip155:8453", spelling), lower)
        for spelling in ("0X" + lower[2:], lower[2:], lower[:-1], lower + "0", "0x" + "g" * 40,
                         " " + lower, lower + "\n", "0x", "", None, 1):
            with self.subTest(spelling=spelling), self.assertRaises(ValueError):
                adapter_address("eip155:8453", spelling)
        solana = "53kyv2biTMZBy8g2cxhPpSKVHYzqjVer8mGPuqiE3k6Z"
        network = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
        self.assertEqual(adapter_address(network, solana), solana)
        self.assertNotEqual(adapter_address(network, solana.swapcase()), solana)

        for name, want, calls in (
            ("challenge-payto-eip55-checksum-binding-lower-case", ("pass", None), 1),
            ("challenge-payto-wrong-eip55-checksum-binding-lower-case", ("pass", None), 1),
            ("ledger-payto-upper-case", ("pass", None), 1),
            ("response-payer-mixed-case", ("pass", None), 1),
            ("challenge-payto-substitution-mixed-case", ("fail", "challenge-match"), 0),
            ("challenge-payto-not-20-bytes", ("error", "address-form"), 0),
            ("response-payer-not-20-bytes", ("pass", "response-payer"), 1),
            ("payout-binding-not-20-bytes", ("error", "address-form"), 0),
            ("paying-key-claim-eip55-derived-payer-lower-case", ("pass", None), 1),
            ("runtime-payee-eip55-binding-lower-case", ("pass", None), 1),
            ("payout-binding-not-20-bytes-runtime-payee-valid", ("error", "address-form"), 0),
            ("runtime-payer-eip55-derived-payer-lower-case", ("pass", None), 1),
            ("runtime-payer-not-20-bytes", ("error", "address-form"), 0),
            ("runtime-payee-not-20-bytes-binding-valid", ("error", "address-form"), 0),
            ("ledger-payer-mixed-case", ("pass", None), 1),
            ("solana-ledger-payer-case-changed", ("fail", "ledger-event"), 1),
            ("solana-lettered-seller-exact-success", ("pass", None), 1),
            ("solana-challenge-payto-case-changed", ("fail", "challenge-match"), 0),
            ("solana-response-payer-case-changed", ("pass", "response-payer"), 1),
            ("solana-ledger-payto-case-changed", ("fail", "ledger-event"), 1),
            # The asset is a 20-byte value too.
            ("challenge-asset-eip55-selection-lower-case", ("pass", None), 1),
            ("selection-asset-eip55-challenge-lower-case", ("pass", None), 1),
            ("asset-metadata-asset-eip55", ("pass", None), 1),
            ("ledger-asset-upper-case", ("pass", None), 1),
            ("selection-asset-not-20-bytes", ("error", "address-form"), 0),
            ("asset-metadata-asset-not-20-bytes", ("error", "address-form"), 0),
            ("challenge-asset-not-20-bytes", ("error", "address-form"), 0),
            ("ledger-asset-not-20-bytes", ("error", "address-form"), 1),
            # The pinned EIP-155 definition has no extra.verifyingContract, so
            # its spellings compare as JCS bytes and an agreeing one is unclassified.
            ("challenge-verifying-contract-eip55-selection-lower-case", ("fail", "challenge-match"), 0),
            ("selection-verifying-contract-eip55-challenge-lower-case", ("fail", "challenge-match"), 0),
            ("challenge-verifying-contract-not-20-bytes", ("fail", "challenge-match"), 0),
            ("selection-verifying-contract-not-20-bytes", ("fail", "unclassified-extra-member"), 0),
        ):
            with self.subTest(vector=name):
                effects = {}
                self.assertEqual(evaluate(copy.deepcopy(self.by_name[name]), effects), want)
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), calls)
        binding = self.by_name["challenge-payto-eip55-checksum-binding-lower-case"]
        self.assertEqual(binding["agreement"]["terms"]["payoutBindings"][0]["payeeAddress"], lower)
        self.assertEqual(binding["http"]["paymentRequired"]["accepts"][0]["payTo"],
                         "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")

        # Base58 is case-sensitive: a case change in the Solana ledger payer is a different payer.
        vector = copy.deepcopy(self.by_name["protocol-v2-solana-exact-success"])
        self.assertEqual(vector["ledger"]["payer"], solana)
        vector["ledger"]["payer"] = solana.swapcase()
        self.assertEqual(evaluate(vector), ("fail", "ledger-event"))
        # An EIP-155 ledger address that is not 0x plus 40 hex digits is malformed.
        vector = copy.deepcopy(self.by_name["protocol-v2-exact-success"])
        vector["ledger"]["payer"] = vector["ledger"]["payer"][2:]
        self.assertEqual(evaluate(vector), ("error", "address-form"))

        # The unsigned runtime copies at the payer-control and PB-1 gates: a
        # checksum spelling matches, and a malformed copy is `error` beside a
        # well-formed signed value, before any wallet call.
        payer = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        self.assertEqual(
            self.by_name["protocol-v2-exact-success"]["runtime"]["payer"]["paymentAddress"], payer
        )
        for path, spelling, want, calls in (
            (("payer", "paymentAddress"), "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", ("pass", None), 1),
            (("payer", "paymentAddress"), payer[:-2], ("error", "address-form"), 0),
            (("payee", "payeeAddress"), lower[:-2], ("error", "address-form"), 0),
        ):
            with self.subTest(runtime=path, spelling=spelling):
                vector = copy.deepcopy(self.by_name["runtime-payee-eip55-binding-lower-case"])
                vector["runtime"][path[0]][path[1]] = spelling
                effects = {}
                self.assertEqual(evaluate(vector, effects), want)
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), calls)

    def test_ledger_transaction_is_compared_in_the_collapsed_form(self):
        """XN-7: the ledger side is collapsed too, in both spelling directions."""
        for name, response_tx, ledger_tx in (
            ("protocol-v2-exact-success", "0x" + "ab" * 32, "0x" + "ab" * 32),
            ("response-transaction-unprefixed", "ab" * 32, "0x" + "ab" * 32),
            ("response-transaction-0x-ledger-unprefixed", "0x" + "ab" * 32, "ab" * 32),
        ):
            with self.subTest(vector=name):
                vector = self.by_name[name]
                response = decode_response_header(vector["http"]["responseHeader"], 2)
                self.assertEqual(response["transaction"], response_tx)
                self.assertEqual(
                    vector["evidence"]["paymentTxRefs"][0]["settlementTransaction"], response_tx
                )
                self.assertEqual(vector["ledger"]["transaction"], ledger_tx)
                self.assertEqual(evaluate(vector), ("pass", None))

    def test_threat_model_summary_matches_xn9_dispositions(self):
        """The §12.4 index row states XN-9's one disposition: refused before authorization."""
        threat_model = (ROOT / "spec/THREAT-MODEL.md").read_text(encoding="utf-8")
        rows = [
            line for line in threat_model.splitlines()
            if line.startswith("| x402 server acknowledgement presented as independent")
        ]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertNotIn("indeterminate", row)
        self.assertIn("including `upto` and `batch-settlement`, is a pre-authorization fail "
                      "with no wallet call", row)
        for name in ("batch-commitment-is-not-financial-settlement",
                     "upto-has-no-dacs-success-profile"):
            with self.subTest(vector=name):
                effects = {}
                self.assertEqual(evaluate(self.by_name[name], effects),
                                 ("fail", "x402-capability-unsupported"))
                self.assertEqual(effects.get("walletAuthorizationCalls", 0), 0)
                self.assertIs(self.by_name[name]["runtime"]["authorizationSubmitted"], False)


if __name__ == "__main__":
    unittest.main()
