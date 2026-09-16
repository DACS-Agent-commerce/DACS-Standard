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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    from scripts.jcs import canonicalize
except ImportError:  # executed as a script dependency
    from jcs import canonicalize


FIXTURE_POLICY = "dacs-finality-synthetic-fixture-v1"
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


def _public_key(keys: Any, signer: Any) -> bytes | None:
    if not isinstance(keys, dict) or not isinstance(signer, str):
        return None
    encoded = keys.get(signer)
    try:
        raw = b64url_decode(encoded)
    except (ValueError, TypeError, binascii.Error):
        return None
    return raw if len(raw) == 32 else None


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


def _signature_shape(value: Any, signer_field: str) -> bool:
    return (
        _exact_object(value, {signer_field, "algorithm", "value"})
        and value.get("algorithm") == "ed25519"
        and _nonempty_string(value.get(signer_field))
        and isinstance(value.get("value"), str)
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
    signed = set()
    for signature in signatures:
        if not _signature_shape(signature, "party"):
            return "error", "malformed agreement signature", None
        signer = signature["party"]
        if signer in signed or signer not in party_claims.values():
            return "fail", "agreement signer is duplicate or not a session party", None
        if not _verify_ed25519(
            trusted.get("partyKeys"), signer, AGREEMENT_DOMAIN, digest, signature["value"]
        ):
            return "fail", "agreement signature does not verify", None
        signed.add(signer)
    if signed != set(party_claims.values()):
        return "fail", "agreement lacks a required party signature", None
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
    if model in {"block-depth", "commitment-level", "bft-final"}:
        return set(profile) == {"finalityProfileVersion", "model", "settlement"} and _chain_profile_shape(
            profile.get("settlement"), model
        )
    if model == "provider-receipt":
        return (
            set(profile) == {
                "finalityProfileVersion", "model", "providerId", "statusEndpointOrigin",
                "captureStatuses", "sr3Binding", "maxObservationAgeSec", "reversibility",
            }
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
            set(profile) == {"finalityProfileVersion", "model", "source", "destination"}
            and _chain_profile_shape(profile.get("source"))
            and _chain_profile_shape(profile.get("destination"))
        )
    if model == "liquidity-tank":
        return (
            set(profile) == {
                "finalityProfileVersion", "model", "bridgeId", "coordinator", "source", "destination",
            }
            and _nonempty_string(profile.get("bridgeId"))
            and all(_chain_profile_shape(profile.get(name)) for name in ("coordinator", "source", "destination"))
        )
    return False


def _verify_rail(rail: Any, evidence: dict, agreement_terms: dict, trusted: dict) -> tuple[str, str, dict | None]:
    required = {
        "railVersion", "railId", "railType", "asset", "network", "phaseHandler",
        "parameters", "consumerFinalityProfile", "availability", "governance", "signature",
    }
    if not _exact_object(rail, required):
        return "error", "malformed RailDefinition", None
    signature = rail.get("signature")
    if not _signature_shape(signature, "signer"):
        return "error", "malformed rail signature", None
    digest = artifact_hash(rail, "signature")
    signer = signature["signer"]
    if not _verify_ed25519(
        trusted.get("stewardKeys"), signer, RAIL_DOMAIN, digest, signature["value"]
    ):
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
    }
    selected = shapes.get(kind)
    if selected is None or set(reference) != selected[0]:
        return False
    if any(not _safe_integer(reference.get(field)) for field in selected[1]):
        return False
    for field, value in reference.items():
        if field in {"kind", *selected[1], "receiptAttestation"}:
            continue
        if not _nonempty_string(value):
            return False
    if kind == "solana-instruction":
        try:
            if len(base58_decode(reference["signature"])) != 64:
                return False
        except ValueError:
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
        and _signature_shape(signature, "signer")
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
    digest = artifact_hash(evidence, "signature")
    if not _verify_ed25519(
        trusted.get("partyKeys"), signature["signer"], EVIDENCE_DOMAIN, digest, signature["value"]
    ):
        return "fail", "finality-bound evidence signature does not verify", None
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
    if reference.get("kind") == "demos":
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
        or any(not _finite_time(event.get(field)) for field in conditional & {"expiry", "minedAt"})
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
    valid = set()
    for attestation in attestations:
        if not _exact_object(attestation, {"authorityRef", "algorithm", "value"}):
            return "error", "malformed authority attestation"
        authority_ref = attestation.get("authorityRef")
        if (
            authority_ref in valid
            or authority_ref not in policy["authorityRefs"]
            or attestation.get("algorithm") != "ed25519"
        ):
            return "fail", "duplicate, substituted, or unsupported observation authority"
        if not _verify_ed25519(
            trusted.get("observationAuthorityKeys"), authority_ref,
            CHAIN_AUTHORITY_DOMAIN, payload_hash, attestation.get("value"),
        ):
            return "fail", "observation authority signature does not verify"
        valid.add(authority_ref)
    if len(valid) < policy["threshold"]:
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
    validator_set = (trusted.get("validatorSets") or {}).get(set_hash)
    if validator_set is None:
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
    signatures = certificate.get("signatures")
    if not isinstance(signatures, list):
        return "error", "BFT signatures are not an array"
    signed = 0
    seen = set()
    for signature in signatures:
        if not _exact_object(signature, {"validatorId", "algorithm", "value"}):
            return "error", "malformed BFT signature"
        validator_id = signature.get("validatorId")
        validator = by_id.get(validator_id)
        if validator is None or validator_id in seen or signature.get("algorithm") != "ed25519":
            return "fail", "BFT signer is substituted, duplicate, or unsupported"
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
    required_header = {"networkId", "genesisHash", "position", "parentId", "transactionsRoot"}
    if not _exact_object(inclusion_header, required_header, {"commitment"}) or not _exact_object(head_header, required_header, {"commitment"}):
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
        if not _exact_object(header, required_header, {"commitment"}):
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
    if authority_decision != "pass":
        return _result(authority_decision, authority_reason), None
    verification_time = trusted.get("verificationTimeMs")
    if not _finite_time(verification_time):
        return _result("error", "trusted verifier-local clock is malformed"), None
    if head["observedAt"] > verification_time:
        return _result("fail", "authenticated head observation is from the future"), None
    age_ms = verification_time - head["observedAt"]
    if age_ms > profile["observation"]["maxHeadAgeSec"] * 1000:
        return _result("indeterminate", "authenticated head observation is stale"), None

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
        if bft_decision != "pass":
            return _result(bft_decision, bft_reason), None
    return _result("pass", "chain observation verified"), event


def _combine(results: list[dict]) -> dict | None:
    for decision in ("error", "fail", "indeterminate"):
        for result in results:
            if result["decision"] == decision:
                return result
    return None


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


def _find_htlc_refs(refs: list, rail: dict) -> dict | None:
    parameters = rail.get("parameters")
    if not _exact_object(parameters, {
        "sourceContract", "destinationContract", "sourceHashAlgorithm", "destinationHashAlgorithm",
        "timelockSourceSec", "timelockDestSec", "sourceFinalitySec", "safetyWindowSec",
    }):
        return None
    source_chain = rail.get("consumerFinalityProfile", {}).get("source", {}).get("networkId", "").split(":")[-1]
    destination_chain = rail.get("consumerFinalityProfile", {}).get("destination", {}).get("networkId", "").split(":")[-1]
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


def _hash_preimage(algorithm: str, preimage: bytes) -> str | None:
    if algorithm == "sha256":
        return hashlib.sha256(preimage).hexdigest()
    if algorithm == "sha3-256":
        return hashlib.sha3_256(preimage).hexdigest()
    return None


def _verify_htlc(input_value: dict, profile: dict, rail: dict, expected: dict, trusted: dict) -> dict:
    context = input_value.get("context")
    if not _exact_object(context, {"kind", "sourceLock", "sourceClaim", "destinationLock", "destinationReveal"}) or context.get("kind") != "htlc":
        return _result("error", "malformed HTLC finality context")
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
    combined = _combine(results)
    if combined is not None:
        return combined
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
    if source_hash is None or destination_hash is None:
        return _result("error", "HTLC rail selects an unsupported hash algorithm")
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
    source_mined = events["sourceLock"].get("minedAt")
    destination_mined = events["destinationLock"].get("minedAt")
    if any(not _finite_time(value) for value in (source_expiry, destination_expiry, source_mined, destination_mined)):
        return _result("error", "HTLC authenticated timing fields are malformed")
    if (
        source_expiry != source_mined + parameters["timelockSourceSec"] * 1000
        or destination_expiry != destination_mined + parameters["timelockDestSec"] * 1000
        or source_expiry <= destination_expiry + (parameters["sourceFinalitySec"] + parameters["safetyWindowSec"]) * 1000
        or destination_mined < events["sourceLock"].get("minedAt")
    ):
        return _result("fail", "HTLC timelock relation does not satisfy the signed route")
    return _result("pass", "all four HTLC observations and recomputed relations verified")


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
    combined = _combine(results)
    if combined is not None:
        return combined
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
    return _result("pass", "coordinator, source, and destination tank observations verified")


def _verify_provider(input_value: dict, profile: dict, expected: dict, trusted: dict) -> dict:
    context = input_value.get("context")
    required = {"kind", "providerId", "endpointOrigin", "providerRef", "responseBytes", "responseAttestation"}
    if not _exact_object(context, required) or context.get("kind") != "provider":
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
    if not (
        _exact_object(ref, {"kind", "mandateId", "providerRef", "protocolVersion", "receiptAttestation"})
        and ref.get("kind") == "ap2"
        and _attestation_ref(ref.get("receiptAttestation"))
    ):
        return _result("error", "malformed signed AP2 reference")
    if context.get("providerRef") != ref.get("providerRef") or canonical_bytes(context.get("responseAttestation")) != canonical_bytes(ref.get("receiptAttestation")):
        return _result("fail", "provider context differs from signed provider reference")
    try:
        response_raw, response = decode_json_bytes(context.get("responseBytes"))
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError, binascii.Error):
        return _result("error", "provider response bytes are malformed")
    response_hash = hashlib.sha256(response_raw).hexdigest()
    if context["responseAttestation"].get("contentHash") != response_hash:
        return _result("fail", "provider response hash differs from signed attestation reference")
    attestation_map = trusted.get("providerAttestations")
    if attestation_map is None:
        return _result("indeterminate", "authenticated SR-3 provider attestation unavailable")
    if not isinstance(attestation_map, dict):
        return _result("error", "malformed trusted provider attestation map")
    attestation = attestation_map.get(response_hash)
    if attestation is None:
        return _result("indeterminate", "authenticated SR-3 provider attestation unavailable")
    required_attestation = {
        "responseAttestationVersion", "providerId", "sr3Binding", "endpointOrigin",
        "providerRef", "responseHash", "observedAt", "signature",
    }
    if not _exact_object(attestation, required_attestation) or attestation.get("responseAttestationVersion") != "1":
        return _result("error", "malformed SR-3 provider response attestation")
    signature = attestation.get("signature")
    if not _signature_shape(signature, "signer"):
        return _result("error", "malformed provider response signature")
    digest = artifact_hash(attestation, "signature")
    if not _verify_ed25519(
        trusted.get("providerAuthorityKeys"), signature["signer"],
        PROVIDER_ATTESTATION_DOMAIN, digest, signature["value"],
    ):
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
    verification_time = trusted.get("verificationTimeMs")
    if not _finite_time(verification_time):
        return _result("error", "trusted verifier-local clock is malformed")
    if attestation["observedAt"] > verification_time:
        return _result("fail", "provider observation is from the future")
    if verification_time - attestation["observedAt"] > profile["maxObservationAgeSec"] * 1000:
        return _result("indeterminate", "authenticated provider observation is stale")
    return _result("pass", "authenticated provider capture verified", "provisional-provider-capture")


def _verify(value: Any, trusted: Any) -> dict:
    if not isinstance(trusted, dict) or trusted.get("policy") != FIXTURE_POLICY:
        return _result("indeterminate", "native production proof codec is unavailable; fixture policy not pinned")
    if not _exact_object(value, {"evidence", "rail", "agreement", "context"}):
        return _result("error", "malformed FV consumer input")
    evidence_decision, evidence_reason, session = _verify_evidence(value.get("evidence"), trusted)
    if evidence_decision != "pass":
        return _result(evidence_decision, evidence_reason)
    agreement_decision, agreement_reason, agreement_terms = _verify_agreement(value.get("agreement"), trusted, session)
    if agreement_decision != "pass":
        return _result(agreement_decision, agreement_reason)
    rail_decision, rail_reason, profile = _verify_rail(value.get("rail"), value["evidence"], agreement_terms, trusted)
    if rail_decision != "pass":
        return _result(rail_decision, rail_reason)
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
        if result["decision"] == "pass" and event.get("eventType") != "transfer":
            return _result("fail", "single-chain finality selected a non-transfer event")
        return result
    if model == "provider-receipt":
        return _verify_provider(value, profile, expected, trusted)
    if model == "htlc-reveal":
        return _verify_htlc(value, profile, value["rail"], expected, trusted)
    if model == "liquidity-tank":
        return _verify_tank(value, profile, value["rail"], expected, trusted)
    return _result("error", "unsupported finality model")


def verify_finality(value: Any, trusted: Any) -> dict:
    """Return a deterministic four-value FV result; malformed input never raises."""
    try:
        return _verify(value, trusted)
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError, json.JSONDecodeError, binascii.Error, RecursionError):
        return _result("error", "malformed nested FV input")
