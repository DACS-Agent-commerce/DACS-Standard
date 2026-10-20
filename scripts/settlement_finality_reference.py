#!/usr/bin/env python3
"""Fixture-only executable reference for DACS-4 FV-1..FV-10.

This module deliberately does not claim a native production proof codec.  It
verifies the deterministic ``dacs-finality-synthetic-fixture-v1`` codec used by
the conformance corpus.  Candidate artifacts never carry trust keys or the
verification clock: callers supply both through a separately pinned policy.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import utils as asymmetric_utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    from scripts.jcs import canonicalize
except ImportError:  # executed as a script dependency
    from jcs import canonicalize


FIXTURE_POLICY = "dacs-finality-synthetic-fixture-v1"
RESOLUTION_CONTEXT_CAPABILITY = "finality-resolution-context-v1"
EVIDENCE_DOMAIN = "dacs-finality-bound-evidence:v1:"
LEGACY_EVIDENCE_DOMAIN = "dacs-evidence:v1:"
RAIL_DOMAIN = "dacs-rail:v1:"
AGREEMENT_DOMAIN = "dacs-agreement:v1:"
CHAIN_AUTHORITY_DOMAIN = "dacs-finality-fixture-chain-observation:v1:"
BFT_CERTIFICATE_DOMAIN = "dacs-finality-fixture-bft-certificate:v1:"
PROVIDER_ATTESTATION_DOMAIN = "dacs-finality-fixture-provider-response:v1:"

POSITION_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
DECIMAL_RE = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?\Z")
SIG_RE = re.compile(r"[A-Za-z0-9_-]+\Z")
MAX_SAFE_INTEGER = 9_007_199_254_740_991
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
COMMITMENT_RANK = {"processed": 0, "confirmed": 1, "finalized": 2}
PAYMENT_PHASE_BY_MODEL = {
    "block-depth": {"pay-evm-erc20", "pay-x402"},
    "commitment-level": {"pay-solana-spl"},
    "bft-final": {"pay-dem"},
    "provider-receipt": {"pay-ap2"},
    "htlc-reveal": {"pay-cross-chain-htlc"},
    "liquidity-tank": {"pay-cross-chain-liquidity-tank"},
}
KNOWN_MODELS = frozenset(PAYMENT_PHASE_BY_MODEL)
# AP2 wire versions whose rules this reference implements (DACS-4 §9.5.6
# step 6); equals tests/test_ap2_reference_fixture.py's pinned version.
AP2_PROTOCOL_VERSIONS = frozenset({"0.2"})
# CORE §B.7 SIG-7 step 1 sets. ``ComponentSignature`` (evidence, rail) and
# ``AgreementSignature`` admit all three registered names; the fixture
# authority, certificate and provider attestation types admit ``ed25519``.
COMPONENT_SIGNATURE_ALGORITHMS = frozenset({"ed25519", "ecdsa-secp256k1", "sr1-aggregate"})
ED25519_ONLY = frozenset({"ed25519"})
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def canonical_bytes(value: Any) -> bytes:
    return canonicalize(value).encode("utf-8")


def hash_value(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def artifact_hash(value: dict, omitted: str | tuple[str, ...]) -> str:
    omitted_fields = {omitted} if isinstance(omitted, str) else set(omitted)
    return hash_value({key: item for key, item in value.items() if key not in omitted_fields})


def b64url_decode(value: Any) -> bytes:
    if not isinstance(value, str) or not SIG_RE.fullmatch(value):
        raise ValueError("non-canonical Base64URL")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ValueError("non-minimal Base64URL")
    return raw


def base58_decode(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("invalid base58")
    number = 0
    for char in value:
        if char not in BASE58_ALPHABET:
            raise ValueError("invalid base58")
        number = number * 58 + BASE58_ALPHABET.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + raw


def decode_json_bytes(value: Any) -> tuple[bytes, Any]:
    raw = b64url_decode(value)
    duplicates = []

    def object_pairs(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                duplicates.append(key)
            result[key] = item
        return result

    decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs)
    if duplicates or raw != canonical_bytes(decoded):
        raise ValueError("raw JSON is not duplicate-free canonical JCS")
    return raw, decoded


def _result(decision: str, reason: str, finality_class: str | None = None) -> dict:
    result = {"decision": decision, "reason": reason}
    if decision == "pass":
        result["finalityClass"] = finality_class or "profile-final"
    return result


def _exact_object(value: Any, required: set[str], optional: set[str] = frozenset()) -> bool:
    return isinstance(value, dict) and required <= set(value) <= required | set(optional)


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _safe_integer(value: Any, *, positive: bool = False) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and (value > 0 if positive else value >= 0)
        and value <= MAX_SAFE_INTEGER
    )


def _finite_time(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and 0 <= value <= MAX_SAFE_INTEGER
    )


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _attestation_ref(value: Any, *, extended: bool = False) -> bool:
    required = {"anchor", "contentHash"}
    if extended:
        required |= {"railId", "railVersion"}
    if not _exact_object(value, required, {"signer"}):
        return False
    anchor = value.get("anchor")
    if (
        not _exact_object(anchor, {"kind", "locator"})
        or anchor.get("kind") not in {"storage-program", "ipfs", "https"}
        or not _nonempty_string(anchor.get("locator"))
        or not _sha256(value.get("contentHash"))
    ):
        return False
    return (
        not extended
        or (
            _nonempty_string(value.get("railId"))
            and _safe_integer(value.get("railVersion"), positive=True)
        )
    )


FIXTURE_HEADER_MEMBERS = frozenset({"networkId", "genesisHash", "position", "parentId", "transactionsRoot"})


def _fixture_header_shape(header: Any) -> bool:
    """The fixture block-header codec. ``commitment`` is optional, and so is
    ``timestamp``: the block's time as integer Unix milliseconds (DACS-4
    HTLC-8 reads a lock's mined instant from it)."""
    return (
        _exact_object(header, FIXTURE_HEADER_MEMBERS, {"commitment", "timestamp"})
        and ("timestamp" not in header or _safe_integer(header["timestamp"]))
    )


def _public_key(keys: Any, signer: Any) -> bytes | None:
    if not isinstance(keys, dict) or not isinstance(signer, str):
        return None
    encoded = keys.get(signer)
    try:
        raw = b64url_decode(encoded)
    except (ValueError, TypeError, binascii.Error):
        return None
    return raw if len(raw) == 32 else None


def _trusted_key_map(trusted: dict, name: str) -> tuple[str, str] | None:
    """Classify one verifier-local key map: missing or empty is
    ``indeterminate`` and malformed is ``error`` (FV entry); a usable map
    returns ``None``. Callers treat an absent entry for a signer that trusted
    authority names (session orchestrator or party, profile authority or
    provider) as missing authority, not as a bad signature (``_key_absent``)."""
    keys = trusted.get(name)
    if keys is None or keys == {}:
        return "indeterminate", f"trusted {name} unavailable"
    if not isinstance(keys, dict) or any(
        _public_key(keys, signer) is None for signer in keys
    ):
        return "error", f"malformed trusted {name}"
    return None


def _key_absent(decision: str, reason: str) -> bool:
    """An ``indeterminate`` caused only by absent verifier-local key material.
    Its caller defers it and keeps checking every later signature with an
    available key and every deterministic fact, so an absent key cannot hide
    a ``fail`` or ``error`` (FV entry, FV-10)."""
    reasons = {
        "trusted partyKeys unavailable", "trusted stewardKeys unavailable",
        "trusted observationAuthorityKeys unavailable", "trusted providerAuthorityKeys unavailable",
        "trusted key for the authenticated phase orchestrator unavailable",
        "trusted key for an authenticated session party unavailable",
        "trusted key for a profile-pinned observation authority unavailable",
        "trusted key for the profile provider unavailable",
    }
    return decision == "indeterminate" and reason in reasons


def _settle(deferred: dict | None, result: dict) -> dict:
    """Report a deferred ``indeterminate`` unless the later checks
    established ``error`` or ``fail``."""
    if deferred is None or result["decision"] in {"error", "fail"}:
        return result
    return deferred


def _signature_wire(value: Any) -> bool:
    """CORE §B.7 SIG-6 wire stage: exact unpadded Base64URL. Failing it is
    malformed encoding, ``error`` under SIG-7, so the envelope shape checks
    apply it before any key is consulted."""
    try:
        b64url_decode(value)
    except (ValueError, TypeError, binascii.Error):
        return False
    return True


def _signature_encoding(value: Any, algorithm: str = "ed25519") -> bool:
    """SIG-7 step 4, which needs no key: the decoded value has its
    algorithm's format. ``ed25519`` is exactly 64 bytes; ``ecdsa-secp256k1``
    is strict DER with ``1 <= r < n`` and low S, never normalised. CORE §B.7
    defines no decoded format for ``sr1-aggregate``, so it has no step-4
    check. A signature skipped for lack of a key still gets this check, so an
    invalid format is ``fail`` whether or not the verifier holds the key."""
    try:
        raw = b64url_decode(value)
    except (ValueError, TypeError, binascii.Error):
        return False
    if algorithm == "ed25519":
        return len(raw) == 64
    if algorithm == "ecdsa-secp256k1":
        try:
            r, s = asymmetric_utils.decode_dss_signature(raw)
        except ValueError:
            return False
        return (
            asymmetric_utils.encode_dss_signature(r, s) == raw
            and 1 <= r < SECP256K1_ORDER
            and 1 <= s <= SECP256K1_ORDER // 2
        )
    return algorithm == "sr1-aggregate"


def _envelope_verdict(envelope: dict, signer: str, keys: dict | None, domain: str, digest: str) -> str:
    """CORE §B.7 SIG-7 steps 3-6 for an envelope that passed
    ``_signature_shape`` (steps 1-2). ``keys`` is the verifier's usable key
    map, or ``None`` when the map itself is missing or empty. The fixture's
    trusted keys are raw Ed25519 public keys, so they authenticate
    ``ed25519`` for their signers: another registered name for a keyed
    signer is a metadata mismatch (step 3). Returns ``pass``, ``fail``, or
    ``unavailable`` (step 5: the signer's key is absent or this reference
    does not implement the registered algorithm), which the caller defers."""
    algorithm = envelope["algorithm"]
    keyed = keys is not None and signer in keys
    if keyed and algorithm != "ed25519":
        return "fail"
    if not _signature_encoding(envelope["value"], algorithm):
        return "fail"
    if not keyed:
        return "unavailable"
    return "pass" if _verify_ed25519(keys, signer, domain, digest, envelope["value"]) else "fail"


def _verify_ed25519(keys: Any, signer: Any, domain: str, digest: str, value: Any) -> bool:
    key = _public_key(keys, signer)
    if key is None or not _sha256(digest):
        return False
    try:
        signature = b64url_decode(value)
        if len(signature) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(key).verify(
            signature, (domain + digest).encode("ascii")
        )
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False


def _signature_shape(value: Any, signer_field: str, algorithms: frozenset = ED25519_ONLY) -> bool:
    """SIG-7 steps 1-2 (``error``): the closed envelope, an algorithm in its
    type's set, and the SIG-6 wire encoding."""
    return (
        _exact_object(value, {signer_field, "algorithm", "value"})
        and value.get("algorithm") in algorithms
        and _nonempty_string(value.get(signer_field))
        and _signature_wire(value.get("value"))
    )


def _price(value: Any) -> bool:
    return (
        _exact_object(value, {"amount", "currency"})
        and isinstance(value.get("amount"), str)
        and DECIMAL_RE.fullmatch(value["amount"]) is not None
        and value["amount"] != "0"
        and _nonempty_string(value.get("currency"))
    )


def _https_origin(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and parsed.path == ""
        and parsed.query == ""
        and parsed.fragment == ""
    )


def _verify_agreement(agreement: Any, trusted: dict, session: dict) -> tuple[str, str, dict | None]:
    required = {
        "agreementVersion", "jobId", "listingRef", "parties", "terms",
        "derivedFromPattern", "generatedAt", "signatures",
    }
    if not _exact_object(agreement, required):
        return "error", "malformed AgreementDocument", None
    if (
        agreement.get("agreementVersion") != "1"
        or agreement.get("jobId") != session.get("jobId")
        or agreement.get("derivedFromPattern") not in {"fixed-price", "rfq", "sealed-envelope"}
        or not _finite_time(agreement.get("generatedAt"))
    ):
        return "fail", "agreement identity or discriminator mismatch", None
    listing_ref = agreement.get("listingRef")
    if not (
        _exact_object(listing_ref, {"listingId", "version", "contentHash"})
        and _nonempty_string(listing_ref.get("listingId"))
        and _safe_integer(listing_ref.get("version"), positive=True)
        and _sha256(listing_ref.get("contentHash"))
    ):
        return "error", "malformed agreement listingRef", None
    parties = agreement.get("parties")
    if not isinstance(parties, list) or len(parties) != 2:
        return "error", "agreement requires the fixture buyer and seller", None
    party_claims = {}
    for party in parties:
        if not _exact_object(party, {"role", "bundleHash", "primaryClaim", "vetRecordRef"}):
            return "error", "malformed agreement party", None
        if (
            party.get("role") not in {"buyer", "seller"}
            or party.get("role") in party_claims
            or not _sha256(party.get("bundleHash"))
            or not _nonempty_string(party.get("primaryClaim"))
            or not _attestation_ref(party.get("vetRecordRef"))
        ):
            return "error", "malformed or duplicate agreement role", None
        party_claims[party["role"]] = party["primaryClaim"]
    if party_claims != session.get("partyClaims"):
        return "fail", "agreement parties differ from authenticated session authority", None
    terms = agreement.get("terms")
    if not _exact_object(terms, {"deliverable", "price", "rail", "deadline"}):
        return "error", "malformed agreement terms", None
    deliverable = terms.get("deliverable")
    rail_ref = terms.get("rail")
    if not (
        _exact_object(deliverable, {"deliverableType", "hash"})
        and _nonempty_string(deliverable.get("deliverableType"))
        and _sha256(deliverable.get("hash"))
        and _price(terms.get("price"))
        and _exact_object(rail_ref, {"railId", "railVersion"})
        and _nonempty_string(rail_ref.get("railId"))
        and _safe_integer(rail_ref.get("railVersion"), positive=True)
        and _finite_time(terms.get("deadline"))
    ):
        return "error", "malformed agreement economics or rail selection", None
    if (
        rail_ref.get("railId") != session.get("railId")
        or rail_ref.get("railVersion") != session.get("railVersion")
    ):
        return "fail", "agreement rail differs from authenticated session authority", None
    digest = artifact_hash(agreement, "signatures")
    if digest != session.get("agreementHash"):
        return "fail", "agreement hash differs from authenticated commitment", None
    signatures = agreement.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 2:
        return "error", "agreement signatures malformed", None
    if any(
        not _signature_shape(signature, "party", COMPONENT_SIGNATURE_ALGORITHMS)
        for signature in signatures
    ):
        return "error", "malformed agreement signature", None
    key_state = _trusted_key_map(trusted, "partyKeys")
    if key_state is not None and key_state[0] == "error":
        return key_state[0], key_state[1], None
    keys = trusted["partyKeys"] if key_state is None else {}
    signed = set()
    for signature in signatures:
        signer = signature["party"]
        if signer in signed or signer not in party_claims.values():
            return "fail", "agreement signer is duplicate or not a session party", None
        signed.add(signer)
    if signed != set(party_claims.values()):
        return "fail", "agreement lacks a required party signature", None
    # Check every signature a trusted key covers before reporting a session
    # party's absent key, so a bad signature is not hidden (FV-10).
    unavailable = False
    for signature in signatures:
        verdict = _envelope_verdict(signature, signature["party"], keys, AGREEMENT_DOMAIN, digest)
        if verdict == "fail":
            return "fail", "agreement signature does not verify", None
        unavailable = unavailable or verdict == "unavailable"
    if key_state is not None:
        return key_state[0], key_state[1], terms
    if unavailable:
        return "indeterminate", "trusted key for an authenticated session party unavailable", terms
    return "pass", "agreement authenticated", terms


def _chain_profile_shape(profile: Any, expected_kind: str | None = None) -> bool:
    if not isinstance(profile, dict):
        return False
    kind = profile.get("kind")
    if kind not in {"block-depth", "commitment-level", "bft-final"}:
        return False
    if expected_kind is not None and kind != expected_kind:
        return False
    required = {"kind", "networkId", "genesisHash", "observation"}
    conditional = {
        "block-depth": {"requiredDepth"},
        "commitment-level": {"requiredCommitment"},
        "bft-final": {"validatorSetRef", "quorumNumerator", "quorumDenominator"},
    }[kind]
    if set(profile) != required | conditional:
        return False
    observation = profile.get("observation")
    if not (
        _nonempty_string(profile.get("networkId"))
        and _nonempty_string(profile.get("genesisHash"))
        and _exact_object(observation, {"method", "authorityRefs", "threshold", "maxHeadAgeSec"})
        and observation.get("method") in {"light-client", "consensus-backed-proxy", "rpc-quorum"}
        and isinstance(observation.get("authorityRefs"), list)
        and bool(observation["authorityRefs"])
        and all(_nonempty_string(item) for item in observation["authorityRefs"])
        and len(observation["authorityRefs"]) == len(set(observation["authorityRefs"]))
        and _safe_integer(observation.get("threshold"), positive=True)
        and observation["threshold"] <= len(observation["authorityRefs"])
        and _safe_integer(observation.get("maxHeadAgeSec"), positive=True)
    ):
        return False
    if kind == "block-depth":
        return _safe_integer(profile.get("requiredDepth"), positive=True)
    if kind == "commitment-level":
        return profile.get("requiredCommitment") in COMMITMENT_RANK
    return (
        _attestation_ref(profile.get("validatorSetRef"))
        and _safe_integer(profile.get("quorumNumerator"), positive=True)
        and _safe_integer(profile.get("quorumDenominator"), positive=True)
        and profile["quorumNumerator"] <= profile["quorumDenominator"]
    )


def _finality_profile_shape(profile: Any) -> bool:
    if not isinstance(profile, dict) or profile.get("finalityProfileVersion") != "1":
        return False
    model = profile.get("model")
    capability = profile.get("finalityResolutionCapability")
    if capability not in {None, RESOLUTION_CONTEXT_CAPABILITY}:
        return False
    optional = {"finalityResolutionCapability"} if capability is not None else set()
    if model in {"block-depth", "commitment-level", "bft-final"}:
        return set(profile) == {"finalityProfileVersion", "model", "settlement"} | optional and _chain_profile_shape(
            profile.get("settlement"), model
        )
    if model == "provider-receipt":
        return (
            set(profile) == {
                "finalityProfileVersion", "model", "providerId", "statusEndpointOrigin",
                "captureStatuses", "sr3Binding", "maxObservationAgeSec", "reversibility",
            } | optional
            and _nonempty_string(profile.get("providerId"))
            and _https_origin(profile.get("statusEndpointOrigin"))
            and isinstance(profile.get("captureStatuses"), list)
            and bool(profile["captureStatuses"])
            and all(_nonempty_string(item) for item in profile["captureStatuses"])
            and len(profile["captureStatuses"]) == len(set(profile["captureStatuses"]))
            and _nonempty_string(profile.get("sr3Binding"))
            and _safe_integer(profile.get("maxObservationAgeSec"), positive=True)
            and profile.get("reversibility") == "provisional-provider-capture"
        )
    if model == "htlc-reveal":
        return (
            set(profile) == {"finalityProfileVersion", "model", "source", "destination"} | optional
            and _chain_profile_shape(profile.get("source"))
            and _chain_profile_shape(profile.get("destination"))
        )
    if model == "liquidity-tank":
        return (
            set(profile) == {
                "finalityProfileVersion", "model", "bridgeId", "coordinator", "source", "destination",
            } | optional
            and _nonempty_string(profile.get("bridgeId"))
            and all(_chain_profile_shape(profile.get(name)) for name in ("coordinator", "source", "destination"))
        )
    return False


def _rail_profile_consistency(rail: dict, profile: dict) -> tuple[str, str]:
    """Check RD-5 typed joins under this reference's pinned fixture codec.

    This does not authenticate a production registry/network mapping or resolve
    conflicting observations; those require their own evidence contract.
    """
    asset, network = rail["asset"], rail["network"]
    rail_type = rail["railType"]
    kinds = {
        "evm-erc20": ({"erc20", "native-evm"}, {"evm"}, "block-depth"),
        "solana-spl": ({"spl", "native-solana"}, {"solana"}, "commitment-level"),
        "demos-native": ({"native-dem"}, {"demos"}, "bft-final"),
        "ap2": ({"fiat-via-ap2"}, {"ap2-provider"}, "provider-receipt"),
        "cross-chain-htlc": ({"stablecoin-cross-chain"}, {"cross-chain"}, "htlc-reveal"),
        "cross-chain-liquidity-tank": ({"stablecoin-cross-chain"}, {"cross-chain"}, "liquidity-tank"),
        "x402": ({"erc20", "native-evm"}, {"evm", "x402-resource"}, "block-depth"),
    }
    if rail_type not in kinds:
        return "error", "unsupported railType"
    asset_kinds, network_kinds, model = kinds[rail_type]
    if (
        asset.get("kind") not in asset_kinds
        or network.get("kind") not in network_kinds
        or profile["model"] != model
    ):
        return "fail", "rail type, asset, network and finality model disagree"
    if asset.get("kind") in {"erc20", "native-evm"}:
        chain_id = asset.get("chainId")
        if not _safe_integer(chain_id, positive=True):
            return "error", "malformed asset chainId"
        if network.get("kind") == "evm":
            if not _safe_integer(network.get("chainId"), positive=True):
                return "error", "malformed network chainId"
            if network["chainId"] != chain_id:
                return "fail", "asset and network chainId differ"
        if profile["settlement"]["networkId"] != "eip155:" + str(chain_id):
            return "fail", "fixture profile network differs from rail asset chainId"
    elif network.get("kind") == "solana":
        cluster = asset.get("cluster")
        if cluster not in {"mainnet", "devnet", "testnet"}:
            return "error", "malformed asset cluster"
        if network.get("cluster") != cluster:
            return "fail", "asset and network cluster differ"
        if profile["settlement"]["networkId"] != "solana:" + cluster:
            return "fail", "fixture profile network differs from rail cluster"
    elif rail_type == "ap2":
        if asset.get("provider") != profile["providerId"]:
            return "fail", "asset provider differs from finality provider"
        endpoint = network.get("providerEndpoint")
        if not isinstance(endpoint, str):
            return "error", "malformed provider endpoint"
        parsed = urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            return "error", "malformed provider endpoint"
        # Payment and status endpoints can legitimately have different origins.
        # A production provider mapping is outside this fixture codec.
    elif network.get("kind") == "cross-chain":
        expected = "htlc" if rail_type == "cross-chain-htlc" else "liquidity-tank"
        if network.get("mechanism") != expected:
            return "fail", "cross-chain mechanism differs from rail type"
    return "pass", "typed rail/profile joins verified"


def _verify_rail(rail: Any, evidence: dict, agreement_terms: dict, trusted: dict) -> tuple[str, str, dict | None]:
    required = {
        "railVersion", "railId", "railType", "asset", "network", "phaseHandler",
        "parameters", "consumerFinalityProfile", "availability", "governance", "signature",
    }
    if not _exact_object(rail, required):
        return "error", "malformed RailDefinition", None
    signature = rail.get("signature")
    if not _signature_shape(signature, "signer", COMPONENT_SIGNATURE_ALGORITHMS):
        return "error", "malformed rail signature", None
    digest = artifact_hash(rail, "signature")
    signer = signature["signer"]
    key_state = _trusted_key_map(trusted, "stewardKeys")
    if key_state is not None and key_state[0] == "error":
        return key_state[0], key_state[1], None
    # A signer outside a configured steward map is not a trusted steward
    # (FV entry); only a missing or empty map defers.
    keys = trusted["stewardKeys"] if key_state is None else None
    if keys is not None and signer not in keys:
        return "fail", "rail steward signature does not verify", None
    if _envelope_verdict(signature, signer, keys, RAIL_DOMAIN, digest) == "fail":
        return "fail", "rail steward signature does not verify", None
    reference = evidence.get("railDefinitionRef")
    agreement_rail = agreement_terms.get("rail")
    if not _attestation_ref(reference, extended=True):
        return "error", "malformed railDefinitionRef", None
    if (
        reference.get("contentHash") != digest
        or reference.get("railId") != rail.get("railId")
        or reference.get("railVersion") != rail.get("railVersion")
        or agreement_rail.get("railId") != rail.get("railId")
        or agreement_rail.get("railVersion") != rail.get("railVersion")
        or evidence.get("phase") != rail.get("phaseHandler")
    ):
        return "fail", "rail reference, agreement selection, or phase does not match", None
    governance = rail.get("governance")
    if not (
        _exact_object(governance, {"proposedBy", "acceptedAt", "anchoring"})
        and governance.get("proposedBy") == signer
        and _finite_time(governance.get("acceptedAt"))
        and governance.get("anchoring") in {"in-code", "single-signer", "multisig"}
        and _safe_integer(rail.get("railVersion"), positive=True)
        and _nonempty_string(rail.get("railId"))
        and _nonempty_string(rail.get("railType"))
        and _nonempty_string(rail.get("phaseHandler"))
        and isinstance(rail.get("asset"), dict)
        and isinstance(rail.get("network"), dict)
        and isinstance(rail.get("parameters"), dict)
        and rail.get("availability") in {"live", "operator_gated", "closed_data", "bilateral", "mocked", "disabled", "failed"}
    ):
        return "error", "malformed rail authority or common fields", None
    profile = rail.get("consumerFinalityProfile")
    if not _finality_profile_shape(profile):
        return "error", "malformed consumerFinalityProfile", None
    consistency, reason = _rail_profile_consistency(rail, profile)
    if consistency != "pass":
        return consistency, reason, None
    model = profile["model"]
    if evidence.get("phase") not in PAYMENT_PHASE_BY_MODEL.get(model, set()):
        return "fail", "rail phaseHandler cannot select this finality model", None
    asset = rail["asset"]
    if "symbol" in asset:
        rail_currency = asset.get("symbol")
    elif "isoCurrency" in asset:
        rail_currency = asset.get("isoCurrency")
    else:
        rail_currency = asset.get("canonicalSymbol")
    signed_currency = agreement_terms.get("price", {}).get("currency")
    parameter_asset = rail["parameters"].get("assetId")
    if not _nonempty_string(rail_currency):
        return "error", "rail asset does not declare a canonical currency", None
    if rail_currency != signed_currency or (
        parameter_asset is not None and parameter_asset != signed_currency
    ):
        return "fail", "rail asset differs from the signed settlement currency", None
    if key_state is not None:
        return key_state[0], key_state[1], profile
    return "pass", "rail authenticated", profile


def _report_shape(report: Any, profile: dict) -> tuple[str, str]:
    if not isinstance(report, dict):
        return "error", "settlementFinality is not an object"
    model = profile["model"]
    required = {"model", "finalityObservedAt"}
    if model == "block-depth":
        required.add("finalityBlocks")
    elif model == "commitment-level":
        required.add("finalityCommitmentLevel")
    if set(report) != required or not _finite_time(report.get("finalityObservedAt")):
        return "error", "malformed settlementFinality producer report"
    # FV-2: malformed or unknown echo values are error before any comparison.
    if (
        report.get("model") not in KNOWN_MODELS
        or "finalityBlocks" in required and not _safe_integer(report.get("finalityBlocks"), positive=True)
        or "finalityCommitmentLevel" in required and report.get("finalityCommitmentLevel") not in COMMITMENT_RANK
    ):
        return "error", "unknown or malformed settlementFinality producer report value"
    if report.get("model") != model:
        return "fail", "producer report model differs from signed rail profile"
    if model == "block-depth" and report.get("finalityBlocks") != profile["settlement"]["requiredDepth"]:
        return "fail", "producer report depth differs from signed rail profile"
    if model == "commitment-level" and report.get("finalityCommitmentLevel") != profile["settlement"]["requiredCommitment"]:
        return "fail", "producer report commitment differs from signed rail profile"
    return "pass", "producer report echo is consistent"


def _transaction_ref_shape(reference: Any) -> bool:
    if not isinstance(reference, dict):
        return False
    kind = reference.get("kind")
    shapes = {
        "evm-event": ({"kind", "chainId", "txHash", "logIndex"}, {"chainId", "logIndex"}),
        "x402-event": (
            {"kind", "httpResource", "paymentReceiptHash", "settlementTxHash", "chainId", "logIndex", "protocolVersion"},
            {"chainId", "logIndex"},
        ),
        "solana-instruction": ({"kind", "cluster", "signature", "instructionIndex"}, {"instructionIndex"}),
        "demos": ({"kind", "txHash", "blockNumber"}, {"blockNumber"}),
        "htlc-lock": ({"kind", "chainId", "contractAddress", "lockTxHash"}, {"chainId"}),
        "htlc-reveal": ({"kind", "chainId", "contractAddress", "revealTxHash"}, {"chainId"}),
        "htlc-claim": ({"kind", "chainId", "contractAddress", "claimTxHash"}, {"chainId"}),
        "liquidity-tank": (
            {"kind", "bridgeId", "sourceChainId", "destChainId", "lockTxHash", "releaseTxHash"},
            {"sourceChainId", "destChainId"},
        ),
        "ap2": ({"kind", "mandateId", "providerRef", "protocolVersion", "receiptAttestation"}, set()),
        "ap2-sr3": (
            {"kind", "mandateId", "providerRef", "protocolVersion", "receiptAttestation", "receiptTransactionRef"},
            set(),
        ),
    }
    selected = shapes.get(kind)
    if selected is None or set(reference) != selected[0]:
        return False
    if any(not _safe_integer(reference.get(field)) for field in selected[1]):
        return False
    for field, value in reference.items():
        if field in {"kind", *selected[1], "receiptAttestation", "receiptTransactionRef"}:
            continue
        if not _nonempty_string(value):
            return False
    if kind == "solana-instruction":
        try:
            if len(base58_decode(reference["signature"])) != 64:
                return False
        except ValueError:
            return False
    if kind == "ap2-sr3":
        tx_ref = reference.get("receiptTransactionRef")
        if not (
            isinstance(tx_ref, dict)
            and set(tx_ref) == {"kind", "value"}
            and _nonempty_string(tx_ref.get("kind"))
            and _nonempty_string(tx_ref.get("value"))
        ):
            return False
    return "receiptAttestation" not in reference or _attestation_ref(reference["receiptAttestation"])


def _evidence_shape(evidence: Any) -> bool:
    required = {
        "finalityBoundEvidenceVersion", "jobId", "phase", "outcome", "paymentTxRefs",
        "paymentAmount", "settlementFinality", "railDefinitionRef", "observedAt", "signature",
    }
    if not _exact_object(evidence, required, {"paymentFee", "amendmentRefs", "supersedesEvidenceRef"}):
        return False
    unknown_discriminators = {
        key for key in evidence
        if isinstance(key, str) and key.endswith("EvidenceVersion")
        and key != "finalityBoundEvidenceVersion"
    }
    signature = evidence.get("signature")
    return (
        not unknown_discriminators
        and "evidenceVersion" not in evidence
        and evidence.get("finalityBoundEvidenceVersion") == "1"
        and _nonempty_string(evidence.get("jobId"))
        and evidence.get("outcome") == "success"
        and _nonempty_string(evidence.get("phase"))
        and isinstance(evidence.get("paymentTxRefs"), list)
        and bool(evidence["paymentTxRefs"])
        and all(_transaction_ref_shape(reference) for reference in evidence["paymentTxRefs"])
        and _price(evidence.get("paymentAmount"))
        and ("paymentFee" not in evidence or _price(evidence["paymentFee"]))
        and (
            "amendmentRefs" not in evidence
            or isinstance(evidence["amendmentRefs"], list)
            and all(_attestation_ref(ref) for ref in evidence["amendmentRefs"])
        )
        and (
            "supersedesEvidenceRef" not in evidence
            or _attestation_ref(evidence["supersedesEvidenceRef"])
        )
        and _finite_time(evidence.get("observedAt"))
        and _attestation_ref(evidence.get("railDefinitionRef"), extended=True)
        and _signature_shape(signature, "signer", COMPONENT_SIGNATURE_ALGORITHMS)
    )


def _verify_evidence(evidence: Any, trusted: dict) -> tuple[str, str, dict | None]:
    if not _evidence_shape(evidence):
        return "error", "malformed or non-exclusive FinalityBoundSettlementEvidence", None
    session = (trusted.get("sessionAuthorityByJob") or {}).get(evidence["jobId"])
    if not isinstance(session, dict):
        return "indeterminate", "authenticated session authority unavailable", None
    expected_session_fields = {
        "jobId", "phaseIndex", "phaseKind", "phaseOrchestrator", "railId", "railVersion",
        "agreementHash", "partyClaims", "payer", "payee", "asset",
    }
    if set(session) != expected_session_fields:
        return "error", "malformed trusted session authority", None
    if (
        session.get("jobId") != evidence.get("jobId")
        or session.get("phaseKind") != evidence.get("phase")
        or not _safe_integer(session.get("phaseIndex"))
        or not _nonempty_string(session.get("phaseOrchestrator"))
    ):
        return "fail", "evidence differs from authenticated phase authority", None
    signature = evidence["signature"]
    if signature.get("signer") != session.get("phaseOrchestrator"):
        return "fail", "evidence signer is not the authenticated phase orchestrator", None
    key_state = _trusted_key_map(trusted, "partyKeys")
    if key_state is not None and key_state[0] == "error":
        return key_state[0], key_state[1], session
    keys = trusted["partyKeys"] if key_state is None else None
    digest = artifact_hash(evidence, "signature")
    verdict = _envelope_verdict(signature, signature["signer"], keys, EVIDENCE_DOMAIN, digest)
    if verdict == "fail":
        return "fail", "finality-bound evidence signature does not verify", None
    if verdict == "unavailable":
        if key_state is None:
            key_state = "indeterminate", "trusted key for the authenticated phase orchestrator unavailable"
        return key_state[0], key_state[1], session
    return "pass", "evidence authenticated", session


def _merkle_root(leaf_hash: str, sibling_hash: str, leaf_index: int) -> str:
    leaf = bytes.fromhex(leaf_hash)
    sibling = bytes.fromhex(sibling_hash)
    left, right = (leaf, sibling) if leaf_index == 0 else (sibling, leaf)
    return hashlib.sha256(b"\x01" + left + right).hexdigest()


def _verify_merkle_proof(proof: Any, *, kind: str, bytes_field: str) -> tuple[str, str, Any | None]:
    required = {"kind", bytes_field, "leafHash", "siblingHash", "leafIndex", "root"}
    if proof is None:
        return "indeterminate", f"{kind} proof unavailable", None
    if not _exact_object(proof, required):
        return "error", f"malformed {kind} proof", None
    if proof.get("kind") != kind:
        return "error", f"unsupported {kind} proof codec", None
    if (
        not _sha256(proof.get("leafHash"))
        or not _sha256(proof.get("siblingHash"))
        or not _sha256(proof.get("root"))
        or proof.get("leafIndex") not in {0, 1}
        or isinstance(proof.get("leafIndex"), bool)
    ):
        return "error", f"malformed {kind} Merkle relation", None
    try:
        raw, decoded = decode_json_bytes(proof[bytes_field])
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError, binascii.Error):
        return "error", f"malformed {kind} raw bytes", None
    leaf_hash = hashlib.sha256(b"\x00" + raw).hexdigest()
    if proof["leafHash"] != leaf_hash:
        return "fail", f"{kind} leaf does not bind raw bytes", None
    if _merkle_root(leaf_hash, proof["siblingHash"], proof["leafIndex"]) != proof["root"]:
        return "fail", f"{kind} Merkle root does not verify", None
    return "pass", f"{kind} proof verified", decoded


def _chain_ref_matches_profile(reference: Any, profile: dict) -> bool:
    if not isinstance(reference, dict):
        return False
    network = profile["networkId"]
    if reference.get("kind") in {"evm-event", "x402-event"}:
        expected = network.split(":", 1)[1] if network.startswith("eip155:") else None
        return expected is not None and str(reference.get("chainId")) == expected
    if reference.get("kind") == "solana-instruction":
        expected = network.split(":", 1)[1] if network.startswith("solana:") else None
        return reference.get("cluster") == expected
    if reference.get("kind") in {"demos", "demos-web2-request"}:
        return network.startswith("demos:")
    if reference.get("kind") in {"htlc-lock", "htlc-reveal", "htlc-claim"}:
        expected = network.split(":", 1)[1] if network.startswith("eip155:") else None
        return expected is not None and str(reference.get("chainId")) == expected
    return False


def _event_index(reference: dict) -> int:
    if reference.get("kind") in {"evm-event", "x402-event"}:
        return reference.get("logIndex")
    if reference.get("kind") == "solana-instruction":
        return reference.get("instructionIndex")
    return 0


def _expected_tx_id(reference: dict) -> Any:
    return {
        "evm-event": reference.get("txHash"),
        "x402-event": reference.get("settlementTxHash"),
        "solana-instruction": reference.get("signature"),
        "demos": reference.get("txHash"),
        "htlc-lock": reference.get("lockTxHash"),
        "htlc-reveal": reference.get("revealTxHash"),
        "htlc-claim": reference.get("claimTxHash"),
    }.get(reference.get("kind"))


def _verify_event_economics(event: Any, reference: dict, expected: dict) -> tuple[str, str]:
    common = {
        "eventType", "jobId", "phaseIndex", "transactionRef", "transactionId", "eventIndex",
        "asset", "amount", "currency", "payer", "payee", "status",
    }
    event_type = event.get("eventType") if isinstance(event, dict) else None
    conditional = {
        "transfer": set(),
        "htlc-lock": {"contractAddress", "hashAlgorithm", "hashlock", "expiry", "minedAt"},
        "htlc-claim": {"contractAddress", "hashAlgorithm", "hashlock", "preimage"},
        "htlc-reveal": {"contractAddress", "hashAlgorithm", "hashlock", "preimage"},
        "tank-source-lock": {"bridgeId", "transferId"},
        "tank-destination-release": {"bridgeId", "transferId"},
        "tank-completed": {"bridgeId", "transferId", "sourceEventHash", "destinationEventHash"},
    }.get(event_type)
    if conditional is None or not _exact_object(event, common | conditional):
        return "error", "malformed selected event body"
    if (
        not _transaction_ref_shape(event.get("transactionRef"))
        or not _safe_integer(event.get("phaseIndex"))
        or not _safe_integer(event.get("eventIndex"))
        or any(
            not _nonempty_string(event.get(field))
            for field in {
                "eventType", "jobId", "transactionId", "asset", "amount", "currency",
                "payer", "payee", "status",
            }
        )
        or any(
            not _nonempty_string(event.get(field))
            for field in conditional - {"expiry", "minedAt"}
        )
        # HTLC-8 compares lock times as integer Unix milliseconds.
        or any(not _safe_integer(event.get(field)) for field in conditional & {"expiry", "minedAt"})
        or any(
            not _sha256(event.get(field))
            for field in conditional & {"hashlock", "sourceEventHash", "destinationEventHash"}
        )
    ):
        return "error", "malformed selected event member"
    if (
        canonical_bytes(event.get("transactionRef")) != canonical_bytes(reference)
        or event.get("transactionId") != _expected_tx_id(reference)
        or event.get("eventIndex") != _event_index(reference)
        or event.get("jobId") != expected.get("jobId")
        or event.get("phaseIndex") != expected.get("phaseIndex")
        or event.get("asset") != expected.get("asset")
        or event.get("amount") != expected.get("amount")
        or event.get("currency") != expected.get("currency")
        or event.get("payer") != expected.get("payer")
        or event.get("payee") != expected.get("payee")
        or event.get("status") != "success"
    ):
        return "fail", "selected event does not bind the signed reference and authenticated economics"
    return "pass", "selected event economics verified"


def _authority_payload(observation: dict, path_ids: list[str]) -> dict:
    head = observation["authenticatedHead"]
    return {
        "networkId": observation["networkId"],
        "genesisHash": observation["genesisHash"],
        "headId": head["id"],
        "headPosition": head["position"],
        "observedAt": head["observedAt"],
        "pathDigest": hash_value(path_ids),
    }


def _verify_authority(observation: dict, profile: dict, path_ids: list[str], trusted: dict) -> tuple[str, str]:
    authority = observation.get("authorityEvidence")
    if authority is None:
        return "indeterminate", "authenticated head authority unavailable"
    if not _exact_object(authority, {"kind", "sourceRefs", "attestations"}):
        return "error", "malformed chain authority evidence"
    policy = profile["observation"]
    if authority.get("kind") != "fixture-threshold-signature-v1":
        return "error", "unsupported fixture chain authority codec"
    if authority.get("sourceRefs") != policy.get("authorityRefs"):
        return "fail", "authority sources differ from the signed rail profile"
    attestations = authority.get("attestations")
    if not isinstance(attestations, list):
        return "error", "authority attestations are not an array"
    payload_hash = hash_value(_authority_payload(observation, path_ids))
    # SIG-7: an algorithm outside the ed25519-only attestation set, or a
    # value that fails the SIG-6 wire stage, is malformed (error).
    if any(
        not _exact_object(attestation, {"authorityRef", "algorithm", "value"})
        or attestation.get("algorithm") != "ed25519"
        or not _signature_wire(attestation.get("value"))
        for attestation in attestations
    ):
        return "error", "malformed authority attestation"
    key_state = _trusted_key_map(trusted, "observationAuthorityKeys")
    if key_state is not None and key_state[0] == "error":
        return key_state
    keys = trusted["observationAuthorityKeys"] if key_state is None else {}
    seen = set()
    valid = set()
    for attestation in attestations:
        authority_ref = attestation.get("authorityRef")
        if (
            authority_ref in seen
            or authority_ref not in policy["authorityRefs"]
        ):
            return "fail", "duplicate or substituted observation authority"
        seen.add(authority_ref)
        # A profile-pinned authority without a trusted key cannot count
        # toward the quorum; it is missing authority, not a bad signature.
        # Its presented value still gets the keyed path's encoding check.
        if authority_ref not in keys:
            valid_value = _signature_encoding(attestation.get("value"))
        else:
            valid_value = _verify_ed25519(
                keys, authority_ref,
                CHAIN_AUTHORITY_DOMAIN, payload_hash, attestation.get("value"),
            )
        if not valid_value:
            return "fail", "observation authority signature does not verify"
        if authority_ref in keys:
            valid.add(authority_ref)
    if len(valid) < policy["threshold"]:
        if key_state is not None:
            return key_state
        if seen - valid:
            return "indeterminate", "trusted key for a profile-pinned observation authority unavailable"
        return "indeterminate", "authenticated observation quorum is incomplete"
    return "pass", "authenticated observation quorum verified"


def _verify_bft_certificate(observation: dict, profile: dict, trusted: dict) -> tuple[str, str]:
    certificate = observation.get("finalityCertificate")
    if certificate is None:
        return "indeterminate", "BFT finality certificate unavailable"
    if not _exact_object(certificate, {"kind", "validatorSetHash", "blockId", "signatures"}):
        return "error", "malformed BFT certificate"
    if certificate.get("kind") != "fixture-bft-certificate-v1":
        return "error", "unsupported BFT certificate codec"
    set_hash = profile["validatorSetRef"]["contentHash"]
    if certificate.get("validatorSetHash") != set_hash or certificate.get("blockId") != observation["inclusionBlock"]["id"]:
        return "fail", "BFT certificate binds the wrong block or validator set"
    signatures = certificate.get("signatures")
    if not isinstance(signatures, list):
        return "error", "BFT signatures are not an array"
    for signature in signatures:
        # SIG-7: the certificate's algorithm set is ed25519 alone; another
        # name or a value failing the SIG-6 wire stage is malformed (error).
        if not (
            _exact_object(signature, {"validatorId", "algorithm", "value"})
            and _nonempty_string(signature.get("validatorId"))
            and signature.get("algorithm") == "ed25519"
            and _signature_wire(signature.get("value"))
        ):
            return "error", "malformed BFT signature"
    validator_sets = trusted.get("validatorSets")
    if validator_sets is not None and not isinstance(validator_sets, dict):
        return "error", "malformed trusted validator-set map"
    validator_set = (validator_sets or {}).get(set_hash)
    if validator_set is None:
        # FV-10: a missing checkpoint defers only after every check the
        # certificate supports alone. A pinned set is non-empty with positive
        # weights and the quorum numerator is positive, so an empty signature
        # list can never meet it.
        seen = set()
        for signature in signatures:
            if signature["validatorId"] in seen:
                return "fail", "BFT signer is substituted or duplicate"
            if not _signature_encoding(signature.get("value")):
                return "fail", "BFT certificate signature does not verify"
            seen.add(signature["validatorId"])
        if not signatures:
            return "fail", "BFT signed weight is below the pinned quorum"
        return "indeterminate", "trusted validator set unavailable"
    if not isinstance(validator_set, dict) or hash_value(validator_set) != set_hash:
        return "error", "malformed trusted validator-set checkpoint"
    validators = validator_set.get("validators")
    if not isinstance(validators, list) or not validators:
        return "error", "trusted validator set is empty"
    by_id = {}
    total = 0
    for validator in validators:
        if not (
            _exact_object(validator, {"validatorId", "weight", "publicKey"})
            and _nonempty_string(validator.get("validatorId"))
            and _safe_integer(validator.get("weight"), positive=True)
            and validator["validatorId"] not in by_id
            and _public_key({validator["validatorId"]: validator.get("publicKey")}, validator["validatorId"]) is not None
        ):
            return "error", "malformed trusted validator set member"
        by_id[validator["validatorId"]] = validator
        total += validator["weight"]
    signed = 0
    seen = set()
    for signature in signatures:
        validator_id = signature.get("validatorId")
        validator = by_id.get(validator_id)
        if validator is None or validator_id in seen:
            return "fail", "BFT signer is substituted or duplicate"
        if not _verify_ed25519(
            {validator_id: validator["publicKey"]}, validator_id,
            BFT_CERTIFICATE_DOMAIN, certificate["blockId"], signature.get("value"),
        ):
            return "fail", "BFT certificate signature does not verify"
        signed += validator["weight"]
        seen.add(validator_id)
    if signed * profile["quorumDenominator"] < total * profile["quorumNumerator"]:
        return "fail", "BFT signed weight is below the pinned quorum"
    return "pass", "BFT certificate and weighted quorum verified"


def _verify_chain_observation(
    observation: Any,
    profile: dict,
    reference: dict,
    expected: dict,
    trusted: dict,
) -> tuple[dict, dict | None]:
    if observation is None:
        return _result("indeterminate", "required chain observation unavailable"), None
    required = {
        "networkId", "genesisHash", "transactionRef", "transactionInclusionProof",
        "selectedEventProof", "inclusionBlock", "authenticatedHead", "ancestryProof",
        "authorityEvidence",
    }
    optional = {"finalityCertificate"}
    if not _exact_object(observation, required, optional):
        return _result("error", "malformed AuthenticatedChainObservation"), None
    if not _chain_profile_shape(profile):
        return _result("error", "malformed chain finality profile"), None
    if observation.get("networkId") != profile.get("networkId") or observation.get("genesisHash") != profile.get("genesisHash"):
        return _result("fail", "chain network or genesis differs from signed rail profile"), None
    # FRC-8 closure below the arm: a malformed member is error before it is
    # compared with the signed value.
    if not _transaction_ref_shape(observation.get("transactionRef")):
        return _result("error", "malformed observation transaction reference"), None
    if canonical_bytes(observation.get("transactionRef")) != canonical_bytes(reference):
        return _result("fail", "observation transaction reference differs from signed evidence"), None
    if not _chain_ref_matches_profile(reference, profile):
        return _result("fail", "signed transaction reference is on the wrong profile network"), None

    event_decision, event_reason, event = _verify_merkle_proof(
        observation.get("selectedEventProof"), kind="fixture-event-merkle-v1", bytes_field="eventBytes"
    )
    transaction_decision, transaction_reason, transaction = _verify_merkle_proof(
        observation.get("transactionInclusionProof"), kind="fixture-transaction-merkle-v1", bytes_field="transactionBytes"
    )
    if event_decision != "pass":
        return _result(event_decision, event_reason), None
    if transaction_decision != "pass":
        return _result(transaction_decision, transaction_reason), None
    if not _exact_object(transaction, {"networkId", "genesisHash", "transactionRef", "eventsRoot", "status"}):
        return _result("error", "malformed raw transaction body"), None
    if (
        transaction.get("networkId") != profile["networkId"]
        or transaction.get("genesisHash") != profile["genesisHash"]
        or canonical_bytes(transaction.get("transactionRef")) != canonical_bytes(reference)
        or transaction.get("eventsRoot") != observation["selectedEventProof"]["root"]
        or transaction.get("status") != "success"
    ):
        return _result("fail", "raw transaction does not bind selected event, network, or reference"), None
    economics_decision, economics_reason = _verify_event_economics(event, reference, expected)
    if economics_decision != "pass":
        return _result(economics_decision, economics_reason), None

    inclusion = observation.get("inclusionBlock")
    head = observation.get("authenticatedHead")
    if not (
        _exact_object(inclusion, {"id", "parentId", "position", "header"})
        and _exact_object(head, {"id", "position", "observedAt", "header"})
        and _sha256(inclusion.get("id"))
        and _sha256(inclusion.get("parentId"))
        and _sha256(head.get("id"))
        and isinstance(inclusion.get("position"), str)
        and POSITION_RE.fullmatch(inclusion["position"])
        and isinstance(head.get("position"), str)
        and POSITION_RE.fullmatch(head["position"])
        and _finite_time(head.get("observedAt"))
    ):
        return _result("error", "malformed inclusion block or authenticated head"), None
    try:
        _inclusion_raw, inclusion_header = decode_json_bytes(inclusion["header"])
        _head_raw, head_header = decode_json_bytes(head["header"])
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError, binascii.Error):
        return _result("error", "malformed raw block header bytes"), None
    if not _fixture_header_shape(inclusion_header) or not _fixture_header_shape(head_header):
        return _result("error", "malformed fixture block header"), None
    if (
        hash_value(inclusion_header) != inclusion["id"]
        or inclusion_header.get("parentId") != inclusion["parentId"]
        or inclusion_header.get("position") != inclusion["position"]
        or inclusion_header.get("transactionsRoot") != observation["transactionInclusionProof"]["root"]
        or inclusion_header.get("networkId") != profile["networkId"]
        or inclusion_header.get("genesisHash") != profile["genesisHash"]
        or hash_value(head_header) != head["id"]
        or head_header.get("position") != head["position"]
        or head_header.get("networkId") != profile["networkId"]
        or head_header.get("genesisHash") != profile["genesisHash"]
    ):
        return _result("fail", "block header identity or transaction root does not verify"), None

    ancestry = observation.get("ancestryProof")
    if not isinstance(ancestry, list):
        return _result("error", "ancestryProof is not an array"), None
    inclusion_position = int(inclusion["position"])
    head_position = int(head["position"])
    if head_position < inclusion_position:
        return _result("fail", "authenticated head precedes inclusion block"), None
    if len(ancestry) != head_position - inclusion_position:
        return _result("fail", "ancestry proof is incomplete or contains an extra link"), None
    previous_id = inclusion["id"]
    path_ids = [previous_id]
    previous_position = inclusion_position
    for link in ancestry:
        if not _exact_object(link, {"childId", "parentId", "position", "header"}):
            return _result("error", "malformed ancestry link"), None
        if (
            not _sha256(link.get("childId"))
            or not _sha256(link.get("parentId"))
            or not isinstance(link.get("position"), str)
            or POSITION_RE.fullmatch(link["position"]) is None
        ):
            return _result("error", "malformed ancestry identity or position"), None
        try:
            _raw, header = decode_json_bytes(link["header"])
        except (ValueError, TypeError, UnicodeError, json.JSONDecodeError, binascii.Error):
            return _result("error", "malformed ancestry header bytes"), None
        position = int(link["position"])
        if not _fixture_header_shape(header):
            return _result("error", "malformed ancestry header body"), None
        if (
            position != previous_position + 1
            or link["parentId"] != previous_id
            or link["childId"] != hash_value(header)
            or header.get("parentId") != previous_id
            or header.get("position") != link["position"]
            or header.get("networkId") != profile["networkId"]
            or header.get("genesisHash") != profile["genesisHash"]
        ):
            return _result("fail", "ancestry link does not extend the authenticated path"), None
        previous_id = link["childId"]
        previous_position = position
        path_ids.append(previous_id)
    if previous_id != head["id"] or canonical_bytes(head_header) != canonical_bytes(
        inclusion_header if not ancestry else header
    ):
        return _result("fail", "ancestry terminus differs from authenticated head"), None

    authority_decision, authority_reason = _verify_authority(observation, profile, path_ids, trusted)
    deferred = None
    if authority_decision != "pass":
        if authority_decision != "indeterminate":
            return _result(authority_decision, authority_reason), None
        deferred = _result(authority_decision, authority_reason)
    verification_time = trusted.get("verificationTimeMs")
    if not _finite_time(verification_time):
        return _result("error", "trusted verifier-local clock is malformed"), None
    if head["observedAt"] > verification_time:
        return _result("fail", "authenticated head observation is from the future"), None
    age_ms = verification_time - head["observedAt"]
    if age_ms > profile["observation"]["maxHeadAgeSec"] * 1000:
        deferred = deferred or _result("indeterminate", "authenticated head observation is stale")

    kind = profile["kind"]
    if kind == "block-depth":
        depth = head_position - inclusion_position + 1
        if depth < profile["requiredDepth"]:
            return _result("fail", "authenticated canonical depth is insufficient"), None
    elif kind == "commitment-level":
        observed = head_header.get("commitment")
        if observed not in COMMITMENT_RANK:
            return _result("error", "authenticated commitment is missing or unknown"), None
        if COMMITMENT_RANK[observed] < COMMITMENT_RANK[profile["requiredCommitment"]]:
            return _result("fail", "authenticated commitment is below the signed requirement"), None
    else:
        bft_decision, bft_reason = _verify_bft_certificate(observation, profile, trusted)
        if bft_decision in {"error", "fail"}:
            return _result(bft_decision, bft_reason), None
        if bft_decision == "indeterminate":
            deferred = deferred or _result(bft_decision, bft_reason)
    # Uncertainty still returns the structurally verified event, so the
    # caller can reject deterministic event and cross-arm relation defects.
    return _settle(deferred, _result("pass", "chain observation verified")), event


def _verify_web2_request_event(event: Any, reference: dict, response_hash: str, status_resource: str) -> tuple[str, str]:
    required = {
        "eventType", "transactionRef", "transactionId", "requestUrl",
        "requestMethod", "responseStatus", "responseHash",
    }
    if not _exact_object(event, required) or event.get("eventType") != "web2-request":
        return "error", "malformed web2-request event body"
    if (
        not _nonempty_string(event.get("transactionId"))
        or not _nonempty_string(event.get("requestUrl"))
        or not _nonempty_string(event.get("requestMethod"))
        or not _safe_integer(event.get("responseStatus"), positive=True)
        or not _sha256(event.get("responseHash"))
    ):
        return "error", "malformed web2-request event member"
    if (
        canonical_bytes(event.get("transactionRef")) != canonical_bytes(reference)
        or event.get("transactionId") != reference.get("value")
        or event.get("responseHash") != response_hash
        or event.get("requestUrl") != status_resource
        or event.get("requestMethod") != "GET"
    ):
        return "fail", "web2-request event does not bind the signed native transaction, request, and response commitment"
    return "pass", "web2-request event verified"


def _verify_sr3_native_transaction(
    observation: Any,
    reference: dict,
    response_hash: str,
    receipt_attestation: dict,
    sr3_binding: str,
    trusted: dict,
) -> tuple[str, str]:
    """Authenticate the SR-3 native ``web2Request`` transaction inclusion at
    Demos BFT finality and its commitment to the exact provider response hash.

    The DAHR binding (DEMOS-MAPPING §A.3) exposes a consensus-anchored hash
    commitment, so the reference authenticates the on-chain transaction and the
    response commitment it carries; it does not claim multi-validator body
    observation.  The candidate observation shape is checked before the
    verifier-local trusted finality authority so a malformed observation is
    ``error`` even when the trusted authority is also missing (FV-10).
    """
    required = {
        "networkId", "genesisHash", "transactionRef", "transactionInclusionProof",
        "selectedEventProof", "inclusionBlock", "authenticatedHead", "ancestryProof",
        "authorityEvidence",
    }
    optional = {"finalityCertificate"}
    if observation is None:
        return "indeterminate", "authenticated SR-3 native transaction observation unavailable"
    if not _exact_object(observation, required, optional):
        return "error", "malformed SR-3 native transaction observation"
    authority = trusted.get("sr3TransactionFinalityProfile")
    if authority is None:
        return "indeterminate", "authenticated SR-3 native transaction finality profile unavailable"
    if not _exact_object(authority, {"sr3Binding", "settlement"}):
        return "error", "malformed trusted SR-3 native transaction finality authority"
    if authority.get("sr3Binding") != sr3_binding:
        return "indeterminate", "authenticated SR-3 native transaction finality profile is bound to a different SR-3 binding"
    profile = authority.get("settlement")
    if not _chain_profile_shape(profile, "bft-final"):
        return "error", "malformed trusted SR-3 native transaction finality profile"
    if observation.get("networkId") != profile.get("networkId") or observation.get("genesisHash") != profile.get("genesisHash"):
        return "fail", "SR-3 native transaction network or genesis differs from signed profile"
    native_ref = observation.get("transactionRef")
    if not (
        _exact_object(native_ref, {"kind", "value"})
        and _nonempty_string(native_ref.get("kind"))
        and _nonempty_string(native_ref.get("value"))
    ):
        return "error", "malformed SR-3 native transaction reference"
    if canonical_bytes(native_ref) != canonical_bytes(reference):
        return "fail", "SR-3 native transaction reference differs from signed evidence"
    if not _chain_ref_matches_profile(reference, profile):
        return "fail", "signed SR-3 native transaction reference is on the wrong profile network"
    anchor = receipt_attestation.get("anchor") if isinstance(receipt_attestation, dict) else None
    status_resource = anchor.get("locator") if isinstance(anchor, dict) else None
    if not isinstance(anchor, dict) or anchor.get("kind") != "https" or not _nonempty_string(status_resource):
        return "error", "malformed SR-3 receipt attestation locator"

    event_decision, event_reason, event = _verify_merkle_proof(
        observation.get("selectedEventProof"), kind="fixture-event-merkle-v1", bytes_field="eventBytes"
    )
    transaction_decision, transaction_reason, transaction = _verify_merkle_proof(
        observation.get("transactionInclusionProof"), kind="fixture-transaction-merkle-v1", bytes_field="transactionBytes"
    )
    if event_decision != "pass":
        return event_decision, event_reason
    if transaction_decision != "pass":
        return transaction_decision, transaction_reason
    if not _exact_object(transaction, {"networkId", "genesisHash", "transactionRef", "eventsRoot", "status"}):
        return "error", "malformed raw SR-3 native transaction body"
    if (
        transaction.get("networkId") != profile["networkId"]
        or transaction.get("genesisHash") != profile["genesisHash"]
        or canonical_bytes(transaction.get("transactionRef")) != canonical_bytes(reference)
        or transaction.get("eventsRoot") != observation["selectedEventProof"]["root"]
        or transaction.get("status") != "success"
    ):
        return "fail", "raw SR-3 native transaction does not bind selected event, network, or reference"
    web2_decision, web2_reason = _verify_web2_request_event(event, reference, response_hash, status_resource)
    if web2_decision != "pass":
        return web2_decision, web2_reason

    inclusion = observation.get("inclusionBlock")
    head = observation.get("authenticatedHead")
    if not (
        _exact_object(inclusion, {"id", "parentId", "position", "header"})
        and _exact_object(head, {"id", "position", "observedAt", "header"})
        and _sha256(inclusion.get("id"))
        and _sha256(inclusion.get("parentId"))
        and _sha256(head.get("id"))
        and isinstance(inclusion.get("position"), str)
        and POSITION_RE.fullmatch(inclusion["position"])
        and isinstance(head.get("position"), str)
        and POSITION_RE.fullmatch(head["position"])
        and _finite_time(head.get("observedAt"))
    ):
        return "error", "malformed SR-3 inclusion block or authenticated head"
    try:
        _inclusion_raw, inclusion_header = decode_json_bytes(inclusion["header"])
        _head_raw, head_header = decode_json_bytes(head["header"])
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError, binascii.Error):
        return "error", "malformed SR-3 raw block header bytes"
    if not _fixture_header_shape(inclusion_header) or not _fixture_header_shape(head_header):
        return "error", "malformed SR-3 fixture block header"
    if (
        hash_value(inclusion_header) != inclusion["id"]
        or inclusion_header.get("parentId") != inclusion["parentId"]
        or inclusion_header.get("position") != inclusion["position"]
        or inclusion_header.get("transactionsRoot") != observation["transactionInclusionProof"]["root"]
        or inclusion_header.get("networkId") != profile["networkId"]
        or inclusion_header.get("genesisHash") != profile["genesisHash"]
        or hash_value(head_header) != head["id"]
        or head_header.get("position") != head["position"]
        or head_header.get("networkId") != profile["networkId"]
        or head_header.get("genesisHash") != profile["genesisHash"]
    ):
        return "fail", "SR-3 block header identity or transaction root does not verify"

    ancestry = observation.get("ancestryProof")
    if not isinstance(ancestry, list):
        return "error", "SR-3 ancestryProof is not an array"
    inclusion_position = int(inclusion["position"])
    head_position = int(head["position"])
    if head_position < inclusion_position:
        return "fail", "SR-3 authenticated head precedes inclusion block"
    if len(ancestry) != head_position - inclusion_position:
        return "fail", "SR-3 ancestry proof is incomplete or contains an extra link"
    previous_id = inclusion["id"]
    path_ids = [previous_id]
    previous_position = inclusion_position
    for link in ancestry:
        if not _exact_object(link, {"childId", "parentId", "position", "header"}):
            return "error", "malformed SR-3 ancestry link"
        if (
            not _sha256(link.get("childId"))
            or not _sha256(link.get("parentId"))
            or not isinstance(link.get("position"), str)
            or POSITION_RE.fullmatch(link["position"]) is None
        ):
            return "error", "malformed SR-3 ancestry identity or position"
        try:
            _raw, header = decode_json_bytes(link["header"])
        except (ValueError, TypeError, UnicodeError, json.JSONDecodeError, binascii.Error):
            return "error", "malformed SR-3 ancestry header bytes"
        position = int(link["position"])
        if not _fixture_header_shape(header):
            return "error", "malformed SR-3 ancestry header body"
        if (
            position != previous_position + 1
            or link["parentId"] != previous_id
            or link["childId"] != hash_value(header)
            or header.get("parentId") != previous_id
            or header.get("position") != link["position"]
            or header.get("networkId") != profile["networkId"]
            or header.get("genesisHash") != profile["genesisHash"]
        ):
            return "fail", "SR-3 ancestry link does not extend the authenticated path"
        previous_id = link["childId"]
        previous_position = position
        path_ids.append(previous_id)
    if previous_id != head["id"] or canonical_bytes(head_header) != canonical_bytes(
        inclusion_header if not ancestry else header
    ):
        return "fail", "SR-3 ancestry terminus differs from authenticated head"

    authority_decision, authority_reason = _verify_authority(observation, profile, path_ids, trusted)
    deferred = None
    if authority_decision != "pass":
        if authority_decision != "indeterminate":
            return authority_decision, authority_reason
        deferred = authority_decision, authority_reason
    verification_time = trusted.get("verificationTimeMs")
    if not _finite_time(verification_time):
        return "error", "trusted verifier-local clock is malformed"
    if head["observedAt"] > verification_time:
        return "fail", "SR-3 authenticated head observation is from the future"
    age_ms = verification_time - head["observedAt"]
    if age_ms > profile["observation"]["maxHeadAgeSec"] * 1000:
        deferred = deferred or ("indeterminate", "SR-3 authenticated head observation is stale")

    bft_decision, bft_reason = _verify_bft_certificate(observation, profile, trusted)
    if bft_decision in {"error", "fail"}:
        return bft_decision, bft_reason
    if deferred is not None:
        return deferred
    if bft_decision != "pass":
        return bft_decision, bft_reason
    return "pass", "authenticated SR-3 native transaction inclusion and response commitment verified"


def _combine(results: list[dict]) -> dict | None:
    for decision in ("error", "fail", "indeterminate"):
        for result in results:
            if result["decision"] == decision:
                return result
    return None


def _combine_arms(results: list[dict], events: dict) -> tuple[dict | None, dict | None]:
    """Combine composite arm results into ``(stop, deferred)``. When every arm
    passed or is indeterminate and still produced its event, the
    uncertainty is deferred so the cross-arm relations are checked first
    (FV-10); otherwise ``stop`` is the combined result to return now."""
    combined = _combine(results)
    if combined is not None and len(events) == len(results) and all(
        result["decision"] in {"pass", "indeterminate"}
        for result in results
    ):
        return None, combined
    return combined, None


def _expected_economics(session: dict, agreement_terms: dict) -> dict:
    return {
        "jobId": session["jobId"],
        "phaseIndex": session["phaseIndex"],
        "asset": session["asset"],
        "amount": agreement_terms["price"]["amount"],
        "currency": agreement_terms["price"]["currency"],
        "payer": session["payer"],
        "payee": session["payee"],
    }


HTLC_PARAMETERS = {
    "sourceContract", "destinationContract", "sourceHashAlgorithm", "destinationHashAlgorithm",
    "timelockSourceSec", "timelockDestSec", "sourceFinalitySec", "safetyWindowSec",
}


def _evm_chain(network_id: str) -> str | None:
    """The registered HTLC txRef kinds name a numeric EVM chainId."""
    return network_id.split(":", 1)[1] if network_id.startswith("eip155:") else None


def _find_htlc_refs(refs: list, rail: dict) -> dict | None:
    parameters = rail.get("parameters")
    if not _exact_object(parameters, HTLC_PARAMETERS):
        return None
    source_chain = _evm_chain(rail.get("consumerFinalityProfile", {}).get("source", {}).get("networkId", ""))
    destination_chain = _evm_chain(rail.get("consumerFinalityProfile", {}).get("destination", {}).get("networkId", ""))
    if source_chain is None or destination_chain is None:
        return None
    result = {}
    for ref in refs:
        if not isinstance(ref, dict):
            return None
        chain = str(ref.get("chainId"))
        if ref.get("kind") == "htlc-lock" and chain == source_chain and ref.get("contractAddress") == parameters["sourceContract"]:
            key = "sourceLock"
        elif ref.get("kind") == "htlc-claim" and chain == source_chain and ref.get("contractAddress") == parameters["sourceContract"]:
            key = "sourceClaim"
        elif ref.get("kind") == "htlc-lock" and chain == destination_chain and ref.get("contractAddress") == parameters["destinationContract"]:
            key = "destinationLock"
        elif ref.get("kind") == "htlc-reveal" and chain == destination_chain and ref.get("contractAddress") == parameters["destinationContract"]:
            key = "destinationReveal"
        else:
            return None
        if key in result:
            return None
        result[key] = ref
    return result if set(result) == {"sourceLock", "sourceClaim", "destinationLock", "destinationReveal"} else None


_KECCAK_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_KECCAK_ROTATIONS = (
    (0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56), (27, 20, 39, 8, 14),
)
_LANE_MASK = (1 << 64) - 1


def _keccak_f1600(lanes: list[list[int]]) -> list[list[int]]:
    def rotate(value: int, shift: int) -> int:
        return ((value << shift) | (value >> (64 - shift))) & _LANE_MASK if shift else value

    for constant in _KECCAK_ROUND_CONSTANTS:
        parity = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
        lanes = [
            [lanes[x][y] ^ parity[(x - 1) % 5] ^ rotate(parity[(x + 1) % 5], 1) for y in range(5)]
            for x in range(5)
        ]
        moved = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                moved[y][(2 * x + 3 * y) % 5] = rotate(lanes[x][y], _KECCAK_ROTATIONS[x][y])
        lanes = [
            [moved[x][y] ^ (~moved[(x + 1) % 5][y] & moved[(x + 2) % 5][y]) for y in range(5)]
            for x in range(5)
        ]
        lanes[0][0] ^= constant
    return lanes


def keccak256(data: bytes, *, domain_padding: int = 0x01) -> bytes:
    """Keccak-256 with the original 0x01 padding used by Ethereum.

    ``hashlib.sha3_256`` is FIPS 202 SHA3-256 (padding 0x06) and yields a
    different digest; ``domain_padding=0x06`` reproduces it as a self-check.
    """
    rate = 136
    padded = bytearray(data) + bytes([domain_padding])
    padded += b"\x00" * (-len(padded) % rate)
    padded[-1] |= 0x80
    lanes = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), rate):
        for index in range(rate // 8):
            word = padded[offset + 8 * index:offset + 8 * index + 8]
            lanes[index % 5][index // 5] ^= int.from_bytes(word, "little")
        lanes = _keccak_f1600(lanes)
    return b"".join(lanes[index % 5][index // 5].to_bytes(8, "little") for index in range(4))


# DACS-4 §9.14 HTLC hash identifiers (HTLC-6); any other value is error.
HTLC_HASH_ALGORITHMS = {
    "sha256": lambda preimage: hashlib.sha256(preimage).hexdigest(),
    "keccak256": lambda preimage: keccak256(preimage).hex(),
}


def _hash_preimage(algorithm: str, preimage: bytes) -> str | None:
    function = HTLC_HASH_ALGORITHMS.get(algorithm)
    return None if function is None else function(preimage)


# HTLC-6: the registered identifiers each leg chain computes natively. EVM
# has the KECCAK256 opcode and the SHA-256 precompile (0x02); Solana the
# sol_keccak256 and sol_sha256 syscalls; Bitcoin script OP_SHA256.
HTLC_CHAIN_NATIVE_HASHES = {
    "eip155": frozenset({"keccak256", "sha256"}),
    "solana": frozenset({"keccak256", "sha256"}),
    "bip122": frozenset({"sha256"}),
}


def _chain_native_hashes(network_id: str) -> frozenset | None:
    return HTLC_CHAIN_NATIVE_HASHES.get(network_id.split(":", 1)[0])


def _inclusion_timestamp(observation: dict) -> int | None:
    """The ``timestamp`` of an observation's inclusion header. Called only
    after ``_verify_chain_observation`` returned the observation's event,
    so the header bytes are already decoded, shape-checked and hashed to the
    authenticated block id."""
    _raw, header = decode_json_bytes(observation["inclusionBlock"]["header"])
    timestamp = header.get("timestamp")
    return timestamp if _safe_integer(timestamp) else None


def _htlc_hash_selection(profile: dict, parameters: dict) -> dict | None:
    """HTLC-6 on the signed rail alone. A selection the leg chain cannot
    compute is a structural impossibility (error), never a mismatch."""
    for leg, field in (("source", "sourceHashAlgorithm"), ("destination", "destinationHashAlgorithm")):
        algorithm = parameters[field]
        if algorithm not in HTLC_HASH_ALGORITHMS:
            return _result("error", "HTLC rail selects an unsupported hash algorithm")
        native = _chain_native_hashes(profile[leg]["networkId"])
        if native is None:
            return _result("error", "HTLC leg chain has no registered native hash")
        if algorithm not in native:
            return _result("error", "HTLC rail hash algorithm is not native to its leg chain")
    return None


def _verify_htlc(input_value: dict, profile: dict, rail: dict, expected: dict, trusted: dict) -> dict:
    context = input_value.get("context")
    if not _exact_object(context, {"kind", "sourceLock", "sourceClaim", "destinationLock", "destinationReveal"}) or context.get("kind") != "htlc":
        return _result("error", "malformed HTLC finality context")
    if not _exact_object(rail.get("parameters"), HTLC_PARAMETERS):
        return _result("error", "malformed signed HTLC parameters")
    selection = _htlc_hash_selection(profile, rail["parameters"])
    if selection is not None:
        return selection
    refs = _find_htlc_refs(input_value["evidence"]["paymentTxRefs"], rail)
    if refs is None:
        return _result("error", "HTLC signed evidence lacks four unambiguous transaction references")
    results = []
    events = {}
    for name in ("sourceLock", "sourceClaim", "destinationLock", "destinationReveal"):
        chain_profile = profile["source"] if name.startswith("source") else profile["destination"]
        result, event = _verify_chain_observation(context.get(name), chain_profile, refs[name], expected, trusted)
        results.append(result)
        if event is not None:
            events[name] = event
    stop, deferred = _combine_arms(results, events)
    if stop is not None:
        return stop
    parameters = rail["parameters"]
    event_types = {
        "sourceLock": "htlc-lock", "sourceClaim": "htlc-claim",
        "destinationLock": "htlc-lock", "destinationReveal": "htlc-reveal",
    }
    for name, event_type in event_types.items():
        if events[name].get("eventType") != event_type:
            return _result("fail", f"{name} proves the wrong HTLC event type")
    if (
        events["sourceLock"].get("contractAddress") != parameters["sourceContract"]
        or events["sourceClaim"].get("contractAddress") != parameters["sourceContract"]
        or events["destinationLock"].get("contractAddress") != parameters["destinationContract"]
        or events["destinationReveal"].get("contractAddress") != parameters["destinationContract"]
    ):
        return _result("fail", "HTLC contract relation differs from the signed rail")
    try:
        source_preimage = b64url_decode(events["sourceClaim"].get("preimage"))
        destination_preimage = b64url_decode(events["destinationReveal"].get("preimage"))
    except (ValueError, TypeError, binascii.Error):
        return _result("error", "HTLC revealed preimage encoding is malformed")
    if source_preimage != destination_preimage:
        return _result("fail", "HTLC claim and reveal use different preimages")
    source_hash = _hash_preimage(parameters["sourceHashAlgorithm"], source_preimage)
    destination_hash = _hash_preimage(parameters["destinationHashAlgorithm"], source_preimage)
    if (
        events["sourceLock"].get("hashAlgorithm") != parameters["sourceHashAlgorithm"]
        or events["sourceClaim"].get("hashAlgorithm") != parameters["sourceHashAlgorithm"]
        or events["sourceLock"].get("hashlock") != source_hash
        or events["sourceClaim"].get("hashlock") != source_hash
        or events["destinationLock"].get("hashAlgorithm") != parameters["destinationHashAlgorithm"]
        or events["destinationReveal"].get("hashAlgorithm") != parameters["destinationHashAlgorithm"]
        or events["destinationLock"].get("hashlock") != destination_hash
        or events["destinationReveal"].get("hashlock") != destination_hash
    ):
        return _result("fail", "HTLC hashlocks do not recompute from the authenticated preimage")
    integer_fields = ("timelockSourceSec", "timelockDestSec", "sourceFinalitySec", "safetyWindowSec")
    if any(not _safe_integer(parameters.get(field), positive=True) for field in integer_fields):
        return _result("error", "HTLC signed timing parameters are malformed")
    source_expiry = events["sourceLock"].get("expiry")
    destination_expiry = events["destinationLock"].get("expiry")
    # HTLC-8 timing inputs: a lock's mined instant is its authenticated
    # inclusion block's timestamp, decoded from the exact header bytes the
    # chain observation hashed to the block id. The lock event's minedAt
    # must agree with it; it is never the source of the instant.
    source_mined = _inclusion_timestamp(context["sourceLock"])
    destination_mined = _inclusion_timestamp(context["destinationLock"])
    if source_mined is None or destination_mined is None:
        return _result("error", "HTLC lock inclusion block yields no authenticated mined instant")
    if any(not _safe_integer(value) for value in (source_expiry, destination_expiry)):
        return _result("error", "HTLC authenticated timing fields are malformed")
    if (
        events["sourceLock"].get("minedAt") != source_mined
        or events["destinationLock"].get("minedAt") != destination_mined
    ):
        return _result("fail", "HTLC lock event minedAt differs from its inclusion block timestamp")
    if (
        source_expiry != source_mined + parameters["timelockSourceSec"] * 1000
        or destination_expiry != destination_mined + parameters["timelockDestSec"] * 1000
        or source_expiry <= destination_expiry + (parameters["sourceFinalitySec"] + parameters["safetyWindowSec"]) * 1000
    ):
        return _result("fail", "HTLC timelock relation does not satisfy the signed route")
    # HTLC-8 verifier schedule bound: the pinned source-finality bound (the
    # HTLC-7 `source_finality`), not a proof of when the source finalized.
    # Waiting for actual source-lock finality is the payee's obligation.
    if destination_mined < source_mined + parameters["sourceFinalitySec"] * 1000:
        return _result("fail", "HTLC destination lock was mined before pinned source-lock finality")
    return _settle(deferred, _result("pass", "all four HTLC observations and recomputed relations verified"))


def _tank_refs(evidence: dict, profile: dict) -> dict | None:
    refs = evidence.get("paymentTxRefs")
    if not isinstance(refs, list) or len(refs) != 1:
        return None
    composite = refs[0]
    if not _exact_object(composite, {"kind", "bridgeId", "sourceChainId", "destChainId", "lockTxHash", "releaseTxHash"}) or composite.get("kind") != "liquidity-tank":
        return None
    source_network = profile["source"]["networkId"]
    destination_network = profile["destination"]["networkId"]
    source_chain = source_network.split(":", 1)[1] if source_network.startswith("eip155:") else None
    destination_chain = destination_network.split(":", 1)[1] if destination_network.startswith("eip155:") else None
    if str(composite.get("sourceChainId")) != source_chain or str(composite.get("destChainId")) != destination_chain:
        return None
    return {
        "source": {"kind": "evm-event", "chainId": composite["sourceChainId"], "txHash": composite["lockTxHash"], "logIndex": 0},
        "destination": {"kind": "evm-event", "chainId": composite["destChainId"], "txHash": composite["releaseTxHash"], "logIndex": 0},
        "coordinator": {"kind": "demos", "txHash": hashlib.sha256(("coordinator:" + composite["bridgeId"]).encode()).hexdigest(), "blockNumber": 100},
        "composite": composite,
    }


def _verify_tank(input_value: dict, profile: dict, rail: dict, expected: dict, trusted: dict) -> dict:
    context = input_value.get("context")
    if not _exact_object(context, {"kind", "coordinator", "source", "destination"}) or context.get("kind") != "liquidity-tank":
        return _result("error", "malformed liquidity-tank finality context")
    refs = _tank_refs(input_value["evidence"], profile)
    if refs is None:
        return _result("error", "malformed liquidity-tank signed transaction reference")
    results = []
    events = {}
    for name in ("coordinator", "source", "destination"):
        result, event = _verify_chain_observation(context.get(name), profile[name], refs[name], expected, trusted)
        results.append(result)
        if event is not None:
            events[name] = event
    stop, deferred = _combine_arms(results, events)
    if stop is not None:
        return stop
    parameters = rail.get("parameters")
    if not _exact_object(parameters, {"bridgeId", "transferId"}):
        return _result("error", "malformed signed liquidity-tank parameters")
    composite = refs["composite"]
    source_hash = hash_value(events["source"])
    destination_hash = hash_value(events["destination"])
    if (
        profile.get("bridgeId") != parameters.get("bridgeId")
        or composite.get("bridgeId") != parameters.get("bridgeId")
        or any(event.get("bridgeId") != parameters.get("bridgeId") for event in events.values())
        or any(event.get("transferId") != parameters.get("transferId") for event in events.values())
        or events["source"].get("eventType") != "tank-source-lock"
        or events["destination"].get("eventType") != "tank-destination-release"
        or events["coordinator"].get("eventType") != "tank-completed"
        or events["coordinator"].get("sourceEventHash") != source_hash
        or events["coordinator"].get("destinationEventHash") != destination_hash
    ):
        return _result("fail", "liquidity-tank arms do not bind one completed bridge transfer")
    return _settle(deferred, _result("pass", "coordinator, source, and destination tank observations verified"))


def _verify_provider(input_value: dict, profile: dict, expected: dict, trusted: dict) -> dict:
    context = input_value.get("context")
    required = {"kind", "providerId", "endpointOrigin", "providerRef", "responseBytes", "responseAttestation"}
    optional = {"receiptTransactionObservation"}
    if not _exact_object(context, required, optional) or context.get("kind") != "provider":
        return _result("error", "malformed provider finality context")
    if (
        context.get("providerId") != profile.get("providerId")
        or context.get("endpointOrigin") != profile.get("statusEndpointOrigin")
    ):
        return _result("fail", "provider identity or endpoint differs from signed rail profile")
    refs = input_value["evidence"].get("paymentTxRefs")
    if not isinstance(refs, list) or len(refs) != 1:
        return _result("error", "provider evidence requires one signed AP2 reference")
    ref = refs[0]
    if not _transaction_ref_shape(ref) or ref.get("kind") not in {"ap2", "ap2-sr3"}:
        return _result("error", "malformed signed AP2 reference")
    if ref.get("protocolVersion") not in AP2_PROTOCOL_VERSIONS:
        return _result("error", "unsupported AP2 protocolVersion")
    sr3 = ref.get("kind") == "ap2-sr3"
    if not sr3 and "receiptTransactionObservation" in context:
        return _result("error", "frozen AP2 reference must not carry SR-3 native transaction authority")
    if not _attestation_ref(context.get("responseAttestation")):
        return _result("error", "malformed provider response attestation reference")
    if context.get("providerRef") != ref.get("providerRef") or canonical_bytes(context.get("responseAttestation")) != canonical_bytes(ref.get("receiptAttestation")):
        return _result("fail", "provider context differs from signed provider reference")
    try:
        response_raw, response = decode_json_bytes(context.get("responseBytes"))
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError, binascii.Error):
        return _result("error", "provider response bytes are malformed")
    response_hash = hashlib.sha256(response_raw).hexdigest()
    if context["responseAttestation"].get("contentHash") != response_hash:
        return _result("fail", "provider response hash differs from signed attestation reference")
    expected_response = {
        "providerRef": ref["providerRef"],
        "endpointOrigin": profile["statusEndpointOrigin"],
        "jobId": expected["jobId"],
        "phaseIndex": expected["phaseIndex"],
        "status": response.get("status") if isinstance(response, dict) else None,
        "amount": expected["amount"],
        "currency": expected["currency"],
        "payer": expected["payer"],
        "payee": expected["payee"],
    }
    if not isinstance(response, dict) or response != expected_response:
        return _result("fail", "provider response bytes do not bind exact payment economics")
    if response["status"] not in profile["captureStatuses"]:
        return _result("fail", "authenticated provider status is not captured")
    deferred = None
    if sr3:
        sr3_decision, sr3_reason = _verify_sr3_native_transaction(
            context.get("receiptTransactionObservation"),
            ref.get("receiptTransactionRef"),
            response_hash,
            ref.get("receiptAttestation"),
            profile.get("sr3Binding"),
            trusted,
        )
        if sr3_decision != "pass":
            if sr3_decision != "indeterminate":
                return _result(sr3_decision, sr3_reason)
            deferred = _result(sr3_decision, sr3_reason)
    attestation_map = trusted.get("providerAttestations")
    if attestation_map is None:
        return _settle(deferred, _result("indeterminate", "authenticated SR-3 provider attestation unavailable"))
    if not isinstance(attestation_map, dict):
        return _result("error", "malformed trusted provider attestation map")
    attestation = attestation_map.get(response_hash)
    if attestation is None:
        return _settle(deferred, _result("indeterminate", "authenticated SR-3 provider attestation unavailable"))
    required_attestation = {
        "responseAttestationVersion", "providerId", "sr3Binding", "endpointOrigin",
        "providerRef", "responseHash", "observedAt", "signature",
    }
    if not _exact_object(attestation, required_attestation) or attestation.get("responseAttestationVersion") != "1":
        return _result("error", "malformed SR-3 provider response attestation")
    signature = attestation.get("signature")
    if not _signature_shape(signature, "signer"):
        return _result("error", "malformed provider response signature")
    key_state = _trusted_key_map(trusted, "providerAuthorityKeys")
    if key_state is not None and key_state[0] == "error":
        return _result(*key_state)
    if key_state is None and (
        signature["signer"] == profile.get("providerId")
        and signature["signer"] not in trusted["providerAuthorityKeys"]
    ):
        key_state = "indeterminate", "trusted key for the profile provider unavailable"
    if key_state is not None:
        valid = _signature_encoding(signature["value"])
        deferred = deferred or _result(*key_state)
    else:
        valid = _verify_ed25519(
            trusted.get("providerAuthorityKeys"), signature["signer"],
            PROVIDER_ATTESTATION_DOMAIN, artifact_hash(attestation, "signature"), signature["value"],
        )
    if not valid:
        return _result("fail", "provider response attestation signature does not verify")
    if (
        attestation.get("providerId") != profile.get("providerId")
        or signature.get("signer") != profile.get("providerId")
        or attestation.get("sr3Binding") != profile.get("sr3Binding")
        or attestation.get("endpointOrigin") != profile.get("statusEndpointOrigin")
        or attestation.get("providerRef") != ref.get("providerRef")
        or attestation.get("responseHash") != response_hash
        or not _finite_time(attestation.get("observedAt"))
    ):
        return _result("fail", "provider attestation does not bind the signed profile and response")
    verification_time = trusted.get("verificationTimeMs")
    if not _finite_time(verification_time):
        return _result("error", "trusted verifier-local clock is malformed")
    if attestation["observedAt"] > verification_time:
        return _result("fail", "provider observation is from the future")
    if verification_time - attestation["observedAt"] > profile["maxObservationAgeSec"] * 1000:
        return _settle(deferred, _result("indeterminate", "authenticated provider observation is stale"))
    return _settle(
        deferred,
        _result("pass", "authenticated provider capture verified", "provisional-provider-capture"),
    )


def _verify(value: Any, trusted: Any) -> dict:
    if not isinstance(trusted, dict) or trusted.get("policy") != FIXTURE_POLICY:
        return _result("indeterminate", "native production proof codec is unavailable; fixture policy not pinned")
    if not _exact_object(value, {"evidence", "rail", "agreement", "context"}):
        return _result("error", "malformed FV consumer input")
    # An absent trusted key in one stage is deferred: the later stages still
    # check every signature with an available key and every deterministic
    # fact, and their ``error`` or ``fail`` wins (FV entry, FV-10).
    deferred = None
    evidence_decision, evidence_reason, session = _verify_evidence(value.get("evidence"), trusted)
    if evidence_decision != "pass":
        if not _key_absent(evidence_decision, evidence_reason):
            return _result(evidence_decision, evidence_reason)
        deferred = _result(evidence_decision, evidence_reason)
    agreement_decision, agreement_reason, agreement_terms = _verify_agreement(value.get("agreement"), trusted, session)
    if agreement_decision != "pass":
        if not _key_absent(agreement_decision, agreement_reason):
            return _result(agreement_decision, agreement_reason)
        deferred = deferred or _result(agreement_decision, agreement_reason)
    rail_decision, rail_reason, profile = _verify_rail(value.get("rail"), value["evidence"], agreement_terms, trusted)
    if rail_decision != "pass":
        if not _key_absent(rail_decision, rail_reason):
            return _result(rail_decision, rail_reason)
        deferred = deferred or _result(rail_decision, rail_reason)
    return _settle(deferred, _verify_context(value, trusted, session, agreement_terms, profile))


def _verify_context(value: dict, trusted: dict, session: dict, agreement_terms: dict, profile: dict) -> dict:
    report_decision, report_reason = _report_shape(value["evidence"].get("settlementFinality"), profile)
    if report_decision != "pass":
        return _result(report_decision, report_reason)
    if value["evidence"].get("paymentAmount") != agreement_terms.get("price"):
        return _result("fail", "signed evidence payment amount differs from signed agreement")
    expected = _expected_economics(session, agreement_terms)
    model = profile["model"]
    if model in {"block-depth", "commitment-level", "bft-final"}:
        context = value.get("context")
        if not _exact_object(context, {"kind", "observation"}) or context.get("kind") != "chain":
            return _result("error", "malformed chain finality context")
        refs = value["evidence"].get("paymentTxRefs")
        if not isinstance(refs, list) or len(refs) != 1:
            return _result("error", "single-chain evidence requires exactly one transaction reference")
        result, event = _verify_chain_observation(
            context.get("observation"), profile["settlement"], refs[0], expected, trusted
        )
        if event is not None and event.get("eventType") != "transfer":
            return _result("fail", "single-chain finality selected a non-transfer event")
        return result
    if model == "provider-receipt":
        return _verify_provider(value, profile, expected, trusted)
    if model == "htlc-reveal":
        return _verify_htlc(value, profile, value["rail"], expected, trusted)
    if model == "liquidity-tank":
        return _verify_tank(value, profile, value["rail"], expected, trusted)
    return _result("error", "unsupported finality model")


def _verify_single_view_finality(value: Any, trusted: Any) -> dict:
    """Execute the historical single-view fixture contract byte-for-byte."""
    try:
        return _verify(value, trusted)
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError, json.JSONDecodeError, binascii.Error, RecursionError):
        return _result("error", "malformed nested FV input")


def verify_finality(value: Any, trusted: Any) -> dict:
    """Dispatch an explicit context capability without legacy fallback."""
    context = value.get("context") if isinstance(value, dict) else None
    if isinstance(context, dict) and (
        "finalityResolutionContextVersion" in context
        or context.get("capability") == "finality-resolution-context-v1"
    ):
        try:
            from finality_resolution_context_reference import (
                verify_finality_resolution_context,
            )
        except ImportError:
            from scripts.finality_resolution_context_reference import (
                verify_finality_resolution_context,
            )
        authority = (
            trusted.get("finalityResolutionAuthority")
            if isinstance(trusted, dict)
            else None
        )
        return verify_finality_resolution_context(
            value,
            authority,
            legacy_verifier=_verify_single_view_finality,
        )
    profile = (
        value.get("rail", {}).get("consumerFinalityProfile")
        if isinstance(value, dict) and isinstance(value.get("rail"), dict)
        else None
    )
    if (
        isinstance(profile, dict)
        and profile.get("finalityResolutionCapability")
            == RESOLUTION_CONTEXT_CAPABILITY
    ):
        return _result(
            "error",
            "finality-resolution-context-v1 cannot fall back to a single-view context",
        )
    return _verify_single_view_finality(value, trusted)
