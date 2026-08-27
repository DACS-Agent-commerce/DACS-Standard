import base64
import copy
import hashlib
import ipaddress
import json
import re
import subprocess
import sys
import unittest
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from scripts.evm_crypto import evm_address
from scripts.jcs import canonicalize as jcs_canonicalize


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance/vectors/security/x402-negotiated-protocol-v0.7.json"
GENERATOR = ROOT / "scripts/generate_x402_negotiated_protocol_vectors.py"
SAFE_INT = 2**53 - 1
HEX_32 = re.compile(r"^[0-9a-f]{64}$")
HTTP_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Z-]+$")
CAIP2 = re.compile(r"^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$")
CD1 = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$")
EVM_EVENT = re.compile(r"^evm:([1-9][0-9]*):([0-9a-f]{64}):(0|[1-9][0-9]*)$")
SOLANA_EVENT = re.compile(
    r"^solana:(mainnet|devnet|testnet):([1-9A-HJ-NP-Za-km-z]+):(0|[1-9][0-9]*)$"
)
SOLANA_NETWORK_CLUSTERS = {
    "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": "devnet",
}
PROTOCOL_REQUIRED = {
    "railVersion", "railId", "railType", "phaseHandler", "resolution",
    "availability", "governance", "signature",
}
PROTOCOL_FORBIDDEN = {
    "asset", "network", "parameters", "resourceBaseUrl", "provider",
    "providers", "facilitator", "facilitatorEndpoint", "apiKey", "wallet", "rpc",
}
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
    return "1" * zeroes + (encoded or "1")


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
    return claimed_address == derived_address == payer.get("paymentAddress")


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

    evidence = v.get("evidence", {})
    signature = evidence.get("signature", {})
    if not verify_signature(
        keys.get("orchestrator"), "dacs-evidence:v1:",
        {k: value for k, value in evidence.items() if k != "signature"},
        signature.get("value"),
    ):
        return False
    return True


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
    try:
        parsed = urlsplit(request.get("url"))
    except (TypeError, ValueError):
        return "error"
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        return "error"
    if "bodyHash" in request and not (
        isinstance(request["bodyHash"], str) and HEX_32.fullmatch(request["bodyHash"])
    ):
        return "error"

    selection = parameters.get("selection")
    if not isinstance(selection, dict) or set(selection) != SELECTION_FIELDS:
        return "error"
    if not is_safe_positive(selection.get("x402Version")):
        return "error"
    if not is_safe_positive(selection.get("maxTimeoutSeconds")):
        return "error"
    if not is_safe_nonnegative(selection.get("assetDecimals")):
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
    if selection["x402Version"] == 1 and "paymentRequiredExtensions" in parameters:
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


def public_http_target(url):
    """Reject directly encoded non-public targets before a network adapter runs.

    Hostname DNS, mixed-answer, and rebinding enforcement remains an executable
    adapter obligation under DACS-1 §6.3.6; URL-only conformance cannot prove it.
    """
    try:
        hostname = urlsplit(url).hostname
        if hostname is None or hostname.lower() == "localhost":
            return False
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return True
    # An IPv4-mapped IPv6 spelling must reach the same verdict as its IPv4 form.
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    return _non_public_class(address) is None


def record_wallet_authorization(effects):
    if effects is not None:
        effects["walletAuthorizationCalls"] = effects.get("walletAuthorizationCalls", 0) + 1


def reconciliation_identity(v):
    agreement = v.get("agreement", {})
    runtime = v.get("runtime", {})
    refs = v.get("evidence", {}).get("paymentTxRefs", [])
    selected = agreement.get("terms", {}).get("rail")
    if not isinstance(selected, dict) or len(refs) != 1 or not isinstance(refs[0], dict):
        return None
    return {
        "jobId": agreement.get("jobId"),
        "phaseIndex": runtime.get("phaseIndex"),
        "requirementHash": digest(selected),
        "authorizationIdentity": runtime.get("payer", {}).get("paymentAddress"),
        "settlementTransaction": refs[0].get("settlementTransaction"),
    }


def exact_atomic(amount, decimals):
    if not isinstance(amount, str) or not CD1.fullmatch(amount):
        raise ValueError("non-canonical decimal")
    try:
        atomic = Decimal(amount) * (Decimal(10) ** decimals)
    except InvalidOperation as exc:
        raise ValueError("invalid decimal") from exc
    if atomic != atomic.to_integral_value() or atomic <= 0:
        raise ValueError("not exactly representable")
    value = str(int(atomic))
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise ValueError("non-canonical atomic amount")
    return value


def decode_response_header(header, version):
    wanted = "X-PAYMENT-RESPONSE" if version == 1 else "PAYMENT-RESPONSE" if version == 2 else None
    if wanted is None or not isinstance(header, dict) or header.get("name") != wanted:
        raise ValueError("wrong response header")
    raw = base64.b64decode(header.get("value"), validate=True)
    response = json.loads(raw.decode("utf-8"))
    if not isinstance(response, dict):
        raise ValueError("response is not object")
    return response


def native_event_matches(event, network, transaction):
    if not isinstance(event, str):
        return False
    evm = EVM_EVENT.fullmatch(event)
    if evm:
        return network == f"eip155:{evm.group(1)}" and transaction == evm.group(2)
    solana = SOLANA_EVENT.fullmatch(event)
    if solana:
        return (
            SOLANA_NETWORK_CLUSTERS.get(network) == solana.group(1)
            and transaction == solana.group(2)
        )
    return False


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


def evaluate(v, effects=None):
    operation = v.get("operation")
    rail = v.get("railDefinition")

    if operation == "validate-definition":
        if not verify_artifact_signatures(v):
            return "fail", "signature"
        return validate_protocol_definition(rail), None

    if operation == "new-session":
        if not verify_artifact_signatures(v):
            return "fail", "signature"
        if rail.get("railId") == "x402:default":
            return "fail", "legacy-default-new-session"
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
        if (
            rail.get("railId") == "x402:default"
            and ref.get("kind") == "x402-event"
            and isinstance(ref.get("protocolVersion"), str)
            and "x402Version" not in ref
        ):
            return "pass", None
        return "error", "legacy-boundary"

    if operation == "retry":
        if not verify_artifact_signatures(v):
            return "fail", "signature"
        if v.get("runtime", {}).get("reconciliationState") != reconciliation_identity(v):
            return "fail", "reconciliation-binding"
        return "pass", "reconciliation-pending"

    if operation != "execute":
        return "error", "operation"
    if not verify_artifact_signatures(v):
        return "fail", "signature"
    if validate_protocol_definition(rail) != "pass":
        return "error", "definition"

    agreement = v.get("agreement", {})
    ref = agreement.get("terms", {}).get("rail")
    ref_result = validate_ref(ref)
    if ref_result != "pass":
        return ref_result, "rail-ref-shape"
    canonical_ref = jcs_canonicalize(ref)
    listed = v.get("listing", {}).get("acceptedRails")
    if not isinstance(listed, list) or not listed:
        return "fail", "listing-membership"
    try:
        canonical_listed = [jcs_canonicalize(item) for item in listed]
    except (TypeError, ValueError):
        return "error", "listing-ref-shape"
    if len(canonical_listed) != len(set(canonical_listed)):
        return "fail", "duplicate-listing-ref"
    if canonical_listed.count(canonical_ref) != 1:
        return "fail", "listing-membership"
    if jcs_canonicalize(v.get("runtime", {}).get("selectedRailRef")) != canonical_ref:
        return "fail", "runtime-selection"

    parties = agreement.get("parties", [])
    buyer = [p for p in parties if p.get("role") == "buyer"]
    seller = [p for p in parties if p.get("role") == "seller"]
    if len(buyer) != 1 or len(seller) != 1:
        return "fail", "party-cardinality"
    runtime = v.get("runtime", {})
    if runtime.get("payer", {}).get("primaryClaim") != buyer[0].get("primaryClaim"):
        return "fail", "payer-party"
    if not buyer_payment_control(v, buyer[0], ref["parameters"]["selection"]):
        return "fail", "payer-control"
    if runtime.get("payee", {}).get("primaryClaim") != seller[0].get("primaryClaim"):
        return "fail", "payee-party"
    bindings = agreement.get("terms", {}).get("payoutBindings", [])
    binding = [item for item in bindings if (
        item.get("railId") == "x402:protocol"
        and item.get("phaseIndex") == runtime.get("phaseIndex")
    )]
    if len(binding) != 1 or binding[0].get("payeeAddress") != runtime.get("payee", {}).get("payeeAddress"):
        return "fail", "payout-binding"

    if runtime.get("operatorConfigSource") != "local-operator-policy":
        return "error", "operator-config-source"
    selection = ref["parameters"]["selection"]
    capability = v.get("capability", {})
    tuple_value = [selection["x402Version"], selection["scheme"], selection["network"]]
    if tuple_value not in capability.get("supportedTuples", []):
        return "fail", "x402-capability-unsupported"
    if selection["scheme"] != "exact" or "dacs-x402-exact:v1" not in capability.get("bindingProfiles", []):
        # Other schemes are protocol-valid but have no v0.7 DACS success profile.
        return ("indeterminate" if selection["scheme"] == "batch-settlement" else "fail"), "x402-capability-unsupported"

    request = ref["parameters"]["request"]
    if not public_http_target(request["url"]):
        return "fail", "non-public-request-target"
    if runtime.get("redirected") or runtime.get("effectiveUrl") != request["url"]:
        return "fail", "effective-request"
    try:
        body = base64.b64decode(runtime.get("requestBodyBase64"), validate=True)
    except Exception:
        return "error", "request-body"
    if "bodyHash" in request:
        if hashlib.sha256(body).hexdigest() != request["bodyHash"]:
            return "fail", "request-body-hash"
    elif body:
        return "fail", "unsigned-request-body"

    http = v.get("http", {})
    if http.get("status") != 402:
        return "fail", "not-payment-required"
    required = http.get("paymentRequired")
    if not isinstance(required, dict) or required.get("x402Version") != selection["x402Version"]:
        return "error", "payment-required-version"
    version = selection["x402Version"]
    accepts = required.get("accepts")
    if not isinstance(accepts, list):
        return "error", "payment-required-shape"
    if version == 2:
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
    elif version == 1:
        resource_url = None
        if "extensions" in required or "paymentRequiredExtensions" in ref["parameters"]:
            return "fail", "legacy-extension-boundary"
    else:
        return "error", "unsupported-version"

    price = agreement.get("terms", {}).get("price", {})
    if selection["currency"] != price.get("currency"):
        return "fail", "currency"
    metadata = capability.get("assetMetadata", {})
    if (
        metadata.get("network") != selection["network"]
        or metadata.get("asset") != selection["asset"]
        or metadata.get("decimals") != selection["assetDecimals"]
    ):
        return "fail", "asset-metadata"
    try:
        amount = exact_atomic(price.get("amount"), selection["assetDecimals"])
    except (TypeError, ValueError):
        return "fail", "exact-amount"
    pay_to = binding[0]["payeeAddress"]
    matches = []
    for candidate in accepts:
        if not isinstance(candidate, dict):
            return "error", "accepts-shape"
        candidate_amount = candidate.get("amount") if version == 2 else candidate.get("maxAmountRequired")
        candidate_url = resource_url if version == 2 else candidate.get("resource")
        if (
            candidate_url == request["url"]
            and candidate.get("scheme") == selection["scheme"]
            and candidate.get("network") == selection["network"]
            and candidate.get("asset") == selection["asset"]
            and candidate.get("maxTimeoutSeconds") == selection["maxTimeoutSeconds"]
            and isinstance(candidate.get("extra"), dict)
            and jcs_canonicalize(candidate["extra"]) == jcs_canonicalize(selection["extra"])
            and candidate_amount == amount
            and candidate.get("payTo") == pay_to
        ):
            matches.append(candidate)
    if len(matches) != 1:
        return "fail", "challenge-match"
    action_bearing = set(http.get("actionBearingExtensions", []))
    understood = set(capability.get("understoodActionExtensions", []))
    if not action_bearing.issubset(understood):
        return "fail", "unsupported-action-extension"

    # This is the sole authorization site in the executable reference path.
    # Every gate above is therefore mechanically pre-authorization, and retry
    # returns through the reconciliation branch without reaching this call.
    record_wallet_authorization(effects)

    try:
        response = decode_response_header(http.get("responseHeader"), version)
    except Exception:
        return "error", "response-header"
    if response.get("success") is not True:
        return "fail", "response-not-success"
    if response.get("network") != selection["network"]:
        return "fail", "response-network"
    if response.get("payer") != runtime.get("payer", {}).get("paymentAddress"):
        return "fail", "response-payer"

    evidence = v.get("evidence", {})
    refs = evidence.get("paymentTxRefs")
    if not isinstance(refs, list) or len(refs) != 1:
        return "error", "evidence-ref-count"
    evidence_ref = refs[0]
    if not isinstance(evidence_ref, dict) or set(evidence_ref) != EVIDENCE_REF_FIELDS:
        return "error", "evidence-ref-shape"
    if evidence_ref.get("kind") != "x402-protocol" or type(evidence_ref.get("x402Version")) is not int:
        return "error", "evidence-version"
    if evidence_ref["x402Version"] != version:
        return "fail", "evidence-version"
    if not HEX_32.fullmatch(evidence_ref.get("paymentRequiredHash", "")) or not HEX_32.fullmatch(
        evidence_ref.get("paymentReceiptHash", "")
    ):
        return "error", "evidence-hash-shape"
    if evidence_ref["paymentRequiredHash"] != digest(required):
        return "fail", "payment-required-hash"
    if evidence_ref["paymentReceiptHash"] != digest(response):
        return "fail", "payment-receipt-hash"
    if (
        evidence_ref.get("httpResource") != request["url"]
        or evidence_ref.get("settlementNetwork") != selection["network"]
        or evidence_ref.get("settlementTransaction") != response.get("transaction")
    ):
        return "fail", "evidence-response-binding"
    finality = evidence.get("settlementFinality", {})
    profile = finality.get("schemeNetworkFinality", {})
    if (
        finality.get("model") != "scheme-network-finality"
        or profile != {
            "scheme": selection["scheme"],
            "network": selection["network"],
            "bindingProfile": "dacs-x402-exact:v1",
        }
    ):
        return "fail", "finality-profile"

    ledger = v.get("ledger")
    if not isinstance(ledger, dict) or ledger.get("available") is not True:
        return "indeterminate", "independent-settlement-unavailable"
    if ledger.get("finalized") is not True:
        return "indeterminate", "settlement-not-final"
    event = evidence_ref.get("settlementEvent")
    if not native_event_matches(
        event, selection["network"], evidence_ref.get("settlementTransaction")
    ):
        return "error", "native-event-key"
    if (
        ledger.get("network") != selection["network"]
        or ledger.get("transaction") != response.get("transaction")
        or ledger.get("settlementEvent") != event
        or ledger.get("scheme") != "exact"
        or ledger.get("asset") != selection["asset"]
        or ledger.get("assetDecimals") != selection["assetDecimals"]
        or ledger.get("amount") != amount
        or ledger.get("payer") != runtime.get("payer", {}).get("paymentAddress")
        or ledger.get("payTo") != pay_to
    ):
        return "fail", "ledger-event"
    if ledger.get("authorization") in {"eip-3009", "permit2"} and ledger.get("sessionBound") is not True:
        return "fail", "sb3"
    return "pass", None


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
            "bare-network-label",
            "numeric-version-replaced-by-string",
            "negative-asset-decimals",
            "unsupported-local-capability",
            "counterparty-operator-config",
            "non-402-response-before-authorization",
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
            "unsupported-action-bearing-extension",
            "redirected-payable-resource",
            "body-sent-without-signed-hash",
            "asset-decimals-adapter-mismatch",
            "agreement-price-excess-precision",
            "runtime-payer-not-agreement-buyer",
            "runtime-paying-key-not-buyer-controlled",
            "runtime-payer-address-not-derived-from-paying-key",
            "runtime-payee-not-signed-destination",
            "upto-has-no-dacs-success-profile",
            "legacy-default-new-session-disabled",
            "legacy-default-pinned-live-new-session",
        )
        for name in pre_authorization:
            with self.subTest(vector=name):
                effects = {"walletAuthorizationCalls": 0}
                evaluate(self.by_name[name], effects)
                self.assertEqual(effects["walletAuthorizationCalls"], 0)

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
            "retry-transaction-binding-mismatch",
        )
        for name in names:
            with self.subTest(vector=name):
                effects = {"walletAuthorizationCalls": 0}
                evaluate(self.by_name[name], effects)
                self.assertEqual(effects["walletAuthorizationCalls"], 0)

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

    def test_ipv4_mapped_spellings_match_their_ipv4_verdict(self):
        """§6.3.6 requires equivalent IPv4-mapped IPv6 spellings to reach the same verdict."""
        for literal, _ in NON_PUBLIC_CLASS_CASES:
            address = ipaddress.ip_address(literal)
            if address.version != 4:
                continue
            with self.subTest(address=literal):
                self.assertEqual(public_http_target(f"https://{literal}/pay"),
                                 public_http_target(f"https://[::ffff:{literal}]/pay"))

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
        ):
            self.assertIn(text, spec)


if __name__ == "__main__":
    unittest.main()
