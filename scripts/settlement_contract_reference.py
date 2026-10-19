"""Non-normative PC-1 input gate, AMEND-1 target consumer and RTB-1 rail check.

Bindings, the session orchestrator, the session's `startedAt` and pinned
rail-registry version, the amendment's anchored address, the rail steward and
the resolver/network pins are verifier-owned arguments, never selected from
phase input, target members or receipts. Finality uses a synthetic test proof
profile (`settlement-vector-anchor-finality:`), not a production Demos proof.
This module makes no live rail calls and implements no refund ledger. A
`valid` result admits the target under AMEND-1 only. AMEND-2/3, amendment
writer authorization, and a transition or finality-bound target's §9.7
reservation or FV-1..FV-10 authority remain the enclosing consumer's
responsibility. PhaseBinding does not carry the signed Listing's agreement-kind
selection; the enclosing verifier must enforce that selection and
require/verify the identityBindingCompanions for either identity-bound
agreement kind.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from dacs_reference import cf4_encode  # noqa: E402
from jcs import canonicalize  # noqa: E402


PAYMENT_PHASES = frozenset({
    "pay-dem", "pay-evm-erc20", "pay-solana-spl", "pay-cross-chain-htlc",
    "pay-cross-chain-liquidity-tank", "pay-ap2", "pay-x402",
})
ORDINARY_INPUT_MEMBERS = frozenset({
    "jobId", "rail", "agreement", "payer", "payee", "amount", "sessionContext",
})
_AMENDMENT_ADDRESS = re.compile(
    r"dacs4:amendment:([^:]+):([0-9a-f]{64}):(0|[1-9][0-9]*)\Z"
)
# DACS-3 AgreementArtifact discriminators; the last three carry payout bindings.
_AGREEMENT_SELECTORS = {
    "agreementVersion": False, "identityBoundAgreementVersion": False,
    "payeeBoundAgreementVersion": True, "identityBoundPayeeAgreementVersion": True,
    "sealedSelectionAgreementVersion": True,
}
_AGREEMENT_MEMBERS = frozenset({
    "jobId", "listingRef", "parties", "terms", "derivedFromPattern", "generatedAt",
    "signatures",
})
_RAIL_MEMBERS = frozenset({
    "railVersion", "railId", "railType", "asset", "network", "phaseHandler",
    "parameters", "availability", "governance", "signature",
})
# DACS-4 9.4.1 closed enumerations.
_RAIL_TYPES = frozenset({
    "evm-erc20", "solana-spl", "cross-chain-htlc", "cross-chain-liquidity-tank",
    "ap2", "x402", "demos-native",
})
_SOLANA_CLUSTERS = frozenset({"mainnet", "devnet", "testnet"})
_RAIL_AVAILABILITY = frozenset({
    "live", "operator_gated", "closed_data", "bilateral", "mocked", "disabled", "failed",
})
# Canonical railId: ASCII without whitespace, at most 64 characters. The
# registry's own ids carry uppercase asset symbols, so case is not checked.
_RAIL_ID = re.compile(r"[\x21-\x7e]{1,64}\Z")
_CHAIN_FINALITY_KINDS = frozenset({"block-depth", "commitment-level", "bft-final"})
# DACS-3 MTR-4 canonical unsigned decimal quantity.
_METERED_QUANTITY = re.compile(r"(0|[1-9][0-9]*)\Z")

# Every recognized DACS-4 evidence selector, and the AMEND-1 target arms among
# them: (signature domain, complete closed arm shape predicate name).
EVIDENCE_SELECTORS = (
    "evidenceVersion", "legacyTransitionEvidenceVersion",
    "deliveryEvidenceVersion", "finalityBoundEvidenceVersion",
)
_TARGET_ARMS = {
    "evidenceVersion": (b"dacs-evidence:v1:", "_settlement_evidence_shape_valid"),
    "legacyTransitionEvidenceVersion": (
        b"dacs-legacy-transition-evidence:v1:",
        "_legacy_transition_settlement_evidence_shape_valid"),
    "finalityBoundEvidenceVersion": (
        b"dacs-finality-bound-evidence:v1:",
        "_finality_bound_settlement_evidence_shape_valid"),
}
AMENDMENT_DOMAIN = b"dacs-amendment:v1:"
RAIL_DOMAIN = b"dacs-rail:v1:"
REGISTRY_INDEX_ADDRESS = "dacs4:registry:v0.1"
# Test-only domain and evidence kind of the synthetic finality proof that
# authenticates an AnchorReceipt's own fields. Not a DACS wire domain.
ANCHOR_TEST_DOMAIN = b"settlement-vector-anchor-finality:"
ANCHOR_TEST_KIND = "test-anchor-finality"
SAFE_INT_MAX = 2**53 - 1
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")


def _shapes():
    for path in (ROOT, ROOT / "tests"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    import dacs5_reference
    return dacs5_reference


@dataclass(frozen=True)
class PhaseBinding:
    """Authenticated invocation metadata supplied by the enclosing verifier."""
    phase: str


class InputArmError(ValueError):
    pass


def _party_valid(shape, value, key_member: str, *, closed: bool) -> bool:
    members = {"bundleHash", "primaryClaim", key_member}
    if (not isinstance(value, dict) or not members <= set(value)
            or (closed and set(value) != members)
            or not shape._sha256_hex(value["bundleHash"])
            or not shape._claim_reference_shape_valid(value["primaryClaim"])):
        return False
    if key_member == "payingKey":
        return shape._claim_reference_shape_valid(value["payingKey"])
    return shape._nonempty_jcs_string(value["payeeAddress"])


def _listing_ref_valid(shape, value, *, closed: bool) -> bool:
    members = {"listingId", "version", "contentHash"}
    return (isinstance(value, dict) and members <= set(value)
            and (not closed or set(value) == members)
            and shape._nonempty_jcs_string(value["listingId"])
            and shape._safe_nonnegative_integer(value["version"], positive=True)
            and shape._sha256_hex(value["contentHash"]))


def _agreement_valid(shape, value) -> bool:
    """DACS-3 AgreementArtifact: one supported discriminator and its typed members.

    A pay-* input's agreement carries `terms.rail` (DACS-3 8.5.2 rule 3). Every
    present optional member is typed except the informational `priceAnchor`
    and disclosure-only `feeSchedule`, which no consumer may gate settlement on
    (DACS-3 8.5.2 priceAnchor tolerance, FS-3).
    """
    selectors = [key for key in _AGREEMENT_SELECTORS if isinstance(value, dict) and key in value]
    if (len(selectors) != 1 or value[selectors[0]] != "1"
            or not _AGREEMENT_MEMBERS <= set(value)):
        return False
    selector = selectors[0]
    sealed = selector == "sealedSelectionAgreementVersion"
    payout = _AGREEMENT_SELECTORS[selector]
    identity_bound = selector in {"identityBoundAgreementVersion", "identityBoundPayeeAgreementVersion"}
    terms = value["terms"]
    channel = value.get("derivedFromChannel")
    metered = terms.get("meteredQuantity") if isinstance(terms, dict) else None
    return (shape._nonempty_jcs_string(value["jobId"])
            and _listing_ref_valid(shape, value["listingRef"], closed=False)
            and isinstance(value["parties"], list) and bool(value["parties"])
            and all(isinstance(party, dict)
                    and shape._string_member(party.get("role"),
                                             {"buyer", "seller", "bidder-non-winning"})
                    and (shape._sha256_hex(party.get("bundleHash")) if identity_bound
                         else shape._nonempty_jcs_string(party.get("bundleHash")))
                    and shape._claim_reference_shape_valid(party.get("primaryClaim"))
                    and shape._attestation_ref_shape_valid(party.get("vetRecordRef"))
                    and ("encryptionKey" not in party
                         or shape._nonempty_jcs_string(party["encryptionKey"]))
                    for party in value["parties"])
            and isinstance(terms, dict) and {"deliverable", "price", "deadline", "rail"} <= set(terms)
            and _agreement_deliverable_valid(shape, terms["deliverable"])
            and shape._price_term_shape_valid(terms["price"])
            and shape._safe_nonnegative_integer(terms["deadline"])
            and _payment_rail_ref_valid(shape, terms["rail"])
            and ("meteredQuantity" not in terms
                 or (isinstance(metered, dict)
                     and isinstance(metered.get("quantity"), str)
                     and _METERED_QUANTITY.fullmatch(metered["quantity"]) is not None
                     and shape._nonempty_jcs_string(metered.get("unit"))))
            and ("additionalTerms" not in terms or isinstance(terms["additionalTerms"], dict))
            and ("derivedFromChannel" not in value
                 or (isinstance(channel, dict)
                     and all(shape._nonempty_jcs_string(channel.get(key))
                             for key in ("subnet", "lastMessageHash"))))
            and (isinstance(terms.get("payoutBindings"), list)
                 and all(_payout_binding_valid(shape, entry) for entry in terms["payoutBindings"])
                 if payout else "payoutBindings" not in terms and "priorPaymentDispositionRef" not in terms)
            and ("priorPaymentDispositionRef" not in terms
                 or shape._attestation_ref_shape_valid(terms["priorPaymentDispositionRef"]))
            and (sealed or "selectionReceiptRef" not in value)
            and shape._string_member(value["derivedFromPattern"], {"sealed-envelope"} if sealed
                                     else {"fixed-price", "rfq", "sealed-envelope"})
            and (not sealed or shape._attestation_ref_shape_valid(value.get("selectionReceiptRef")))
            and shape._safe_nonnegative_integer(value["generatedAt"])
            and isinstance(value["signatures"], list) and bool(value["signatures"])
            and all(isinstance(signature, dict)
                    and shape._claim_reference_shape_valid(signature.get("party"))
                    and shape._string_member(signature.get("algorithm"),
                                             {"ed25519", "ecdsa-secp256k1", "sr1-aggregate"})
                    and shape._nonempty_jcs_string(signature.get("value"))
                    for signature in value["signatures"]))


def _agreement_deliverable_valid(shape, value) -> bool:
    return (isinstance(value, dict)
            and shape._string_member(value.get("deliverableType"),
                                     {"storage-program", "entitlement", "attested-payload", "external"})
            and shape._sha256_hex(value.get("hash"))
            and ("schemaUrl" not in value or shape._nonempty_jcs_string(value["schemaUrl"])))


def _payment_rail_ref_valid(shape, value) -> bool:
    return (isinstance(value, dict) and shape._nonempty_jcs_string(value.get("railId"))
            and ("railVersion" not in value
                 or shape._safe_nonnegative_integer(value["railVersion"], positive=True))
            and ("parameters" not in value or isinstance(value["parameters"], dict)))


def _payout_binding_valid(shape, value) -> bool:
    return (isinstance(value, dict) and shape._nonempty_jcs_string(value.get("railId"))
            and shape._nonempty_jcs_string(value.get("payeeAddress"))
            and shape._safe_nonnegative_integer(value.get("phaseIndex")))


def _cross_chain_route_valid(shape, value) -> bool:
    def chain_id(member):
        return (shape._nonempty_jcs_string(member)
                or shape._safe_nonnegative_integer(member))
    if not isinstance(value, dict):
        return False
    contracts = value.get("htlcContracts")
    return (chain_id(value.get("sourceChainId")) and chain_id(value.get("destChainId"))
            and ("htlcContracts" not in value
                 or (isinstance(contracts, dict)
                     and all(shape._nonempty_jcs_string(contracts.get(key)) for key in ("source", "dest"))))
            and ("liquidityTankIds" not in value
                 or (isinstance(value["liquidityTankIds"], list)
                     and all(shape._nonempty_jcs_string(item) for item in value["liquidityTankIds"]))))


def _asset_valid(shape, value) -> bool:
    if not isinstance(value, dict):
        return False
    kind = value.get("kind")
    if kind == "fiat-via-ap2":
        return all(shape._nonempty_jcs_string(value.get(key)) for key in ("isoCurrency", "provider"))
    if kind == "stablecoin-cross-chain":
        return (shape._nonempty_jcs_string(value.get("canonicalSymbol"))
                and isinstance(value.get("routes"), list)
                and all(_cross_chain_route_valid(shape, route) for route in value["routes"]))
    if not shape._string_member(kind, {"erc20", "spl", "native-evm", "native-solana", "native-dem"}):
        return False
    if not (shape._nonempty_jcs_string(value.get("symbol"))
            and shape._safe_nonnegative_integer(value.get("decimals"))):
        return False
    if kind in {"erc20", "native-evm"}:
        return (shape._safe_nonnegative_integer(value.get("chainId"), positive=True)
                and (kind != "erc20" or shape._nonempty_jcs_string(value.get("contract"))))
    if kind in {"spl", "native-solana"}:
        return (shape._string_member(value.get("cluster"), _SOLANA_CLUSTERS)
                and (shape._nonempty_jcs_string(value.get("mint")) if kind == "spl"
                     else value["symbol"] == "SOL" and value["decimals"] == 9))
    return value["symbol"] == "DEM" and value["decimals"] == 9


def _network_valid(shape, value) -> bool:
    if not isinstance(value, dict):
        return False
    kind = value.get("kind")
    if kind == "evm":
        return (shape._safe_nonnegative_integer(value.get("chainId"), positive=True)
                and shape._string_member(value.get("rpcAttestation"), {"consensus-backed-proxy", "evm-rpc"}))
    if kind == "solana":
        return shape._string_member(value.get("cluster"), _SOLANA_CLUSTERS)
    if kind == "ap2-provider":
        return shape._nonempty_jcs_string(value.get("providerEndpoint"))
    if kind == "x402-resource":
        return shape._nonempty_jcs_string(value.get("resourceBaseUrl"))
    if kind == "cross-chain":
        return shape._string_member(value.get("mechanism"), {"htlc", "liquidity-tank", "substrate-native"})
    return kind == "demos"


def _governance_valid(shape, value) -> bool:
    if not isinstance(value, dict):
        return False
    emergency = value.get("emergency")
    return (shape._claim_reference_shape_valid(value.get("proposedBy"))
            and shape._safe_nonnegative_integer(value.get("acceptedAt"))
            and shape._string_member(value.get("anchoring"), {"in-code", "single-signer", "multisig"})
            and ("supersedes" not in value or shape._safe_nonnegative_integer(value["supersedes"]))
            and ("deprecated" not in value or isinstance(value["deprecated"], bool))
            and (value.get("deprecated") is not True or "deprecationReason" in value)
            and ("deprecationReason" not in value or shape._nonempty_jcs_string(value["deprecationReason"]))
            and ("emergency" not in value
                 or (isinstance(emergency, dict) and emergency.get("isEmergency") is True
                     and shape._nonempty_jcs_string(emergency.get("failureObservation")))))


def _chain_finality_valid(shape, value, kind: str | None = None) -> bool:
    """DACS-4 9.4.1 ChainFinalityProfile with its ChainObservationPolicy."""
    if not isinstance(value, dict) or not shape._string_member(value.get("kind"), _CHAIN_FINALITY_KINDS):
        return False
    observation = value.get("observation")
    refs = observation.get("authorityRefs") if isinstance(observation, dict) else None
    if not ((kind is None or value["kind"] == kind)
            and shape._nonempty_jcs_string(value.get("networkId"))
            and shape._nonempty_jcs_string(value.get("genesisHash"))
            and isinstance(observation, dict)
            and shape._string_member(observation.get("method"),
                                     {"light-client", "consensus-backed-proxy", "rpc-quorum"})
            and isinstance(refs, list) and bool(refs)
            and all(shape._nonempty_jcs_string(item) for item in refs)
            # threshold is required for rpc-quorum and bounded by the authority set.
            and (("threshold" not in observation and observation["method"] != "rpc-quorum")
                 or (shape._safe_nonnegative_integer(observation.get("threshold"), positive=True)
                     and observation["threshold"] <= len(refs)))
            and shape._safe_nonnegative_integer(observation.get("maxHeadAgeSec"), positive=True)):
        return False
    if value["kind"] == "block-depth":
        return shape._safe_nonnegative_integer(value.get("requiredDepth"), positive=True)
    if value["kind"] == "commitment-level":
        return shape._string_member(value.get("requiredCommitment"), {"processed", "confirmed", "finalized"})
    return (shape._attestation_ref_shape_valid(value.get("validatorSetRef"))
            and all(shape._safe_nonnegative_integer(value.get(key), positive=True)
                    for key in ("quorumNumerator", "quorumDenominator")))


def _finality_profile_valid(shape, value) -> bool:
    """DACS-4 9.4.1 ConsumerFinalityProfile: one model arm and its typed members."""
    capability = "finality-resolution-context-v1"
    if not (isinstance(value, dict) and value.get("finalityProfileVersion") == "1"
            and value.get("finalityResolutionCapability", capability) == capability):
        return False
    model = value.get("model")
    if shape._string_member(model, _CHAIN_FINALITY_KINDS):
        return _chain_finality_valid(shape, value.get("settlement"), model)
    if model == "provider-receipt":
        statuses = value.get("captureStatuses")
        return (all(shape._nonempty_jcs_string(value.get(key))
                    for key in ("providerId", "statusEndpointOrigin", "sr3Binding"))
                and isinstance(statuses, list) and bool(statuses)
                and all(shape._nonempty_jcs_string(item) for item in statuses)
                and shape._safe_nonnegative_integer(value.get("maxObservationAgeSec"), positive=True)
                and value.get("reversibility") == "provisional-provider-capture")
    if model == "htlc-reveal":
        return all(_chain_finality_valid(shape, value.get(key)) for key in ("source", "destination"))
    if model == "liquidity-tank":
        return (shape._nonempty_jcs_string(value.get("bridgeId"))
                and all(_chain_finality_valid(shape, value.get(key))
                        for key in ("coordinator", "source", "destination")))
    return False


def _rail_valid(shape, value) -> bool:
    """DACS-4 9.4.1 RailDefinition: required members, closed enumerations, typed optionals."""
    if not isinstance(value, dict) or not _RAIL_MEMBERS <= set(value):
        return False
    return (shape._safe_nonnegative_integer(value["railVersion"], positive=True)
            and isinstance(value["railId"], str) and _RAIL_ID.fullmatch(value["railId"]) is not None
            and shape._string_member(value["railType"], _RAIL_TYPES)
            and _asset_valid(shape, value["asset"])
            and _network_valid(shape, value["network"])
            # A concrete executable handler; pay-alternative is not one.
            and shape._string_member(value["phaseHandler"], PAYMENT_PHASES)
            and isinstance(value["parameters"], dict)
            and ("consumerFinalityProfile" not in value
                 or _finality_profile_valid(shape, value["consumerFinalityProfile"]))
            and shape._string_member(value["availability"], _RAIL_AVAILABILITY)
            and _governance_valid(shape, value["governance"])
            and isinstance(value["signature"], dict)
            and shape._nonempty_jcs_string(value["signature"].get("algorithm"))
            and shape._nonempty_jcs_string(value["signature"].get("value")))


def _session_context_valid(shape, value) -> bool:
    # The runtime SubstrateSigner is not serializable, so `signer` may be absent.
    return (isinstance(value, dict)
            and {"jobId", "listingRef", "recipeRegistryVersion", "railRegistryVersion",
                 "parties", "priorPhaseOutputs", "startedAt"} <= set(value)
            and shape._nonempty_jcs_string(value["jobId"])
            and _listing_ref_valid(shape, value["listingRef"], closed=False)
            and shape._safe_nonnegative_integer(value["recipeRegistryVersion"])
            and shape._safe_nonnegative_integer(value["railRegistryVersion"])
            and isinstance(value["parties"], list) and bool(value["parties"])
            and all(isinstance(party, dict)
                    and shape._string_member(party.get("role"), {"buyer", "seller", "orchestrator"})
                    and shape._sha256_hex(party.get("bundleHash"))
                    and shape._claim_reference_shape_valid(party.get("primaryClaim"))
                    and ("vetRecordRef" not in party
                         or shape._attestation_ref_shape_valid(party["vetRecordRef"]))
                    for party in value["parties"])
            and isinstance(value["priorPhaseOutputs"], dict)
            and shape._safe_nonnegative_integer(value["startedAt"]))


def check_payment_input(binding: PhaseBinding, phase_input: Any) -> None:
    if binding.phase not in PAYMENT_PHASES:
        raise InputArmError("binding is not a payment phase")
    if not isinstance(phase_input, dict):
        raise InputArmError("payment input is not an object")
    if "sessionContext" not in phase_input:
        raise InputArmError("payment input lacks sessionContext")
    shape = _shapes()
    # Unknown members stay open under CORE SIG-5.
    if not ORDINARY_INPUT_MEMBERS <= set(phase_input):
        raise InputArmError("payment input lacks a required member")
    if not (shape._nonempty_jcs_string(phase_input["jobId"])
            and _agreement_valid(shape, phase_input["agreement"])
            and _rail_valid(shape, phase_input["rail"])
            and _party_valid(shape, phase_input["payer"], "payingKey", closed=False)
            and _party_valid(shape, phase_input["payee"], "payeeAddress", closed=False)
            and shape._price_term_shape_valid(phase_input["amount"])):
        raise InputArmError("payment input member is not its declared type")
    if not _session_context_valid(shape, phase_input["sessionContext"]):
        raise InputArmError("sessionContext is not SessionContext")
    if ("identityBindingCompanions" in phase_input
            and not isinstance(phase_input["identityBindingCompanions"], list)):
        raise InputArmError("identityBindingCompanions is not an array")


def dispatch_payment(binding: PhaseBinding, phase_input: Any, handler: Callable) -> dict:
    """Run the PC-1 input gate before the enclosing handler can call a rail."""
    try:
        check_payment_input(binding, phase_input)
    except InputArmError as exc:
        return {"status": "rejected", "ok": False, "errorClass": "permanent",
                "reason": str(exc)}
    return handler(phase_input)


# ---- signatures, hashes and authenticated receipts --------------------------

class Invalid(ValueError):
    """Authenticated material contradicts the rule: a violation."""


class Unknown(RuntimeError):
    """The authority the rule needs is unavailable: indeterminate."""


def jcs_bytes(value: Any) -> bytes:
    return canonicalize(value).encode("utf-8")


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def content_hash(value: dict) -> str:
    """CORE B.2 content hash: JCS of the object without its signature."""
    return sha256_hex(jcs_bytes({k: v for k, v in value.items() if k != "signature"}))


def b64u_decode(value: Any) -> bytes:
    """Strict unpadded base64url: re-encoding must give back the same text."""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise Invalid("base64url value must be an unpadded string")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise Invalid("invalid base64url value") from exc
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise Invalid("non-canonical base64url encoding")
    return raw


def is_pure_json(value: Any) -> bool:
    """NFC strings and safe integers only (CORE CF-1, §B.2)."""
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value) == value
    if isinstance(value, int):
        return abs(value) <= SAFE_INT_MAX
    if isinstance(value, list):
        return all(is_pure_json(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and unicodedata.normalize("NFC", key) == key
                   and is_pure_json(item) for key, item in value.items())
    return False


def claim_identity(claim: Any) -> str:
    """CF-3 identity of a CF-2 ClaimReference: advisory parameters drop out."""
    if not _shapes()._claim_reference_shape_valid(claim):
        raise Invalid("signer is not a canonical ClaimReference string")
    return claim.split("?", 1)[0]


def require_signer(value: dict, expected: str) -> None:
    signature = value.get("signature")
    signer = signature.get("signer") if isinstance(signature, dict) else None
    if claim_identity(signer) != claim_identity(expected):
        raise Invalid("signature signer is not the authenticated authority")


def _public_key(public_keys: dict, claim: str) -> str | None:
    if claim in public_keys:
        return public_keys[claim]
    identity = claim_identity(claim)
    matches = [key for candidate, key in public_keys.items()
               if claim_identity(candidate) == identity]
    if len(matches) > 1:
        raise Invalid("multiple authenticated keys resolve to one ClaimReference identity")
    return matches[0] if matches else None


def verify_embedded(value: dict, public_keys: dict, domain: bytes) -> None:
    """Verify `signature` over domain || content hash (CORE §B.7)."""
    signature = value.get("signature")
    if not isinstance(signature, dict):
        raise Unknown("missing signature")
    if signature.get("algorithm") != "ed25519":
        raise Invalid("unsupported signature algorithm")
    encoded_key = _public_key(public_keys, signature.get("signer"))
    if encoded_key is None:
        raise Unknown(f"no authenticated key for {signature.get('signer')}")
    if not is_pure_json(value):
        raise Invalid("signed value is not NFC-normalized safe-integer JSON")
    key, raw = b64u_decode(encoded_key), b64u_decode(signature.get("value"))
    if len(key) != 32 or len(raw) != 64:
        raise Invalid("Ed25519 key or signature has the wrong length")
    message = domain + content_hash(value).encode("ascii")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(raw, message)
    except InvalidSignature as exc:
        raise Invalid("invalid signature") from exc


def _verify_finality_proof(receipt: dict, *, public_keys: dict, network_authority: str,
                           network_id: str, proof_profile: str, validator_set_id: str) -> None:
    """Authenticate an AnchorReceipt's own fields (CORE SR2-4) before use.

    The synthetic proof is a network-authority-signed copy of the receipt's
    binding tuple. Every failure here means the receipt is not authentic.
    """
    if receipt.get("substrate") != network_id or receipt.get("finalityProfile") != proof_profile:
        raise Invalid("AnchorReceipt network or finality profile is not pinned")
    for key in ("logicalAddress", "nativeAddress", "contentHash", "writer", "nonce"):
        if not isinstance(receipt.get(key), str) or not receipt[key]:
            raise Invalid(f"AnchorReceipt {key} is malformed")
    transaction = receipt.get("transactionRef")
    if (not isinstance(transaction, dict) or set(transaction) != {"kind", "value"}
            or not all(isinstance(item, str) and item for item in transaction.values())):
        raise Invalid("AnchorReceipt transactionRef is malformed")
    if type(receipt.get("observedAt")) is not int or not 0 <= receipt["observedAt"] <= SAFE_INT_MAX:
        raise Invalid("AnchorReceipt observedAt is malformed")
    block = receipt.get("blockRef")
    if (not isinstance(block, dict) or not isinstance(block.get("id"), str) or not block["id"]
            or type(block.get("timestamp")) is not int
            or not 0 <= block["timestamp"] <= SAFE_INT_MAX):
        raise Invalid("AnchorReceipt blockRef is malformed")
    evidence = receipt.get("evidence")
    if not isinstance(evidence, dict):
        raise Invalid("AnchorReceipt carries no finality proof")
    if evidence.get("kind") != ANCHOR_TEST_KIND:
        raise Invalid("AnchorReceipt finality proof kind is not the pinned profile's")
    try:
        proof = json.loads(b64u_decode(evidence.get("value")).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Invalid("AnchorReceipt finality proof is not encoded JSON") from exc
    if not isinstance(proof, dict):
        raise Invalid("AnchorReceipt finality proof is not an object")
    try:
        verify_embedded(proof, public_keys, ANCHOR_TEST_DOMAIN)
    except Unknown as exc:
        raise Invalid(f"AnchorReceipt finality proof is unverifiable: {exc}") from exc
    require_signer(proof, network_authority)
    expected = {
        "logicalAddress": receipt["logicalAddress"],
        "nativeAddress": receipt["nativeAddress"],
        "contentHash": receipt["contentHash"],
        "transactionRef": transaction,
        "writer": receipt["writer"],
        "nonce": receipt["nonce"],
        "state": receipt.get("state"),
        "blockRef": block,
        "networkId": network_id,
        "proofProfile": proof_profile,
        "validatorSetId": validator_set_id,
    }
    if set(proof) != set(expected) | {"signature"} or any(
            proof[key] != value for key, value in expected.items()):
        raise Invalid("AnchorReceipt finality proof does not bind the receipt's fields")


def _established_finalized(receipt: Any) -> bool:
    return (isinstance(receipt, dict) and receipt.get("receiptVersion") == "1"
            and receipt.get("state") == "finalized"
            and receipt.get("observationDisposition") == "established")


# ---- AMEND-1 ------------------------------------------------------------------

def consume_amendment_target(
    amendment: dict, resolve: Callable[[dict], dict | None], *,
    amendment_address: str, orchestrator: str,
    public_keys: dict, network_authority: str, network_id: str,
    proof_profile: str, validator_set_id: str,
) -> tuple[str, str]:
    """Resolve, establish finality, hash, then select/verify the AMEND-1 arm.

    The resolver returns {artifact, anchorReceipt}; absent, unfinalized or
    inauthentic receipts, or bytes that differ from an authentic anchor binding
    the reference's hash, leave the target pending. Contradictory established
    proofs are violations.
    `orchestrator` is the authenticated session phase orchestrator and
    `amendment_address` the amendment's own anchored logical address.
    No AMEND-4 reject-versus-flag policy is selected here.
    """
    shape = _shapes()
    try:
        verify_embedded(amendment, public_keys, AMENDMENT_DOMAIN)
        target_ref = amendment.get("amendsEvidenceRef")
        if not shape._attestation_ref_shape_valid(target_ref):
            raise Invalid("amendment target reference malformed")
        try:
            resolved = resolve(target_ref)
        except OSError as exc:
            raise Unknown("amendment target unavailable") from exc
        if not isinstance(resolved, dict):
            raise Unknown("amendment target unavailable")
        target = resolved.get("artifact")
        anchor = resolved.get("anchorReceipt")
        if not isinstance(target, dict) or not _established_finalized(anchor):
            raise Unknown("amendment target not anchored and finalized")
        # CORE SR2-4/SR2-12: receipt fields are assertions until its proof binds
        # them, so authenticate the receipt's own tuple first. A forged or
        # mismatched receipt is discarded, leaving the target pending.
        try:
            if anchor.get("logicalAddress") != target_ref["anchor"]["locator"]:
                raise Invalid("AnchorReceipt is for another address")
            _verify_finality_proof(
                anchor, public_keys=public_keys, network_authority=network_authority,
                network_id=network_id, proof_profile=proof_profile,
                validator_set_id=validator_set_id,
            )
        except (Invalid, ValueError, TypeError, KeyError) as exc:
            raise Unknown(f"amendment target anchor is not authentic: {exc}") from exc
        # PC-2's payment address is single-write, so an authentic anchor binding
        # another hash means the reference names other content.
        if anchor["contentHash"] != target_ref["contentHash"]:
            raise Invalid("authentic amendment target anchor binds another content hash")
        # CORE B.2 / DACS-4 9.7: content hashes omit only signature. No target
        # discriminator, job or phase is read before this recomputation. Bytes
        # differing from the anchored hash are a substituted resolution.
        digest = content_hash(target)
        if digest != target_ref["contentHash"]:
            raise Unknown("amendment target content differs from its finalized anchor")
        selectors = [key for key in EVIDENCE_SELECTORS if key in target]
        if len(selectors) != 1 or selectors[0] not in _TARGET_ARMS:
            raise Invalid("amendment target discriminator unsupported or ambiguous")
        selector = selectors[0]
        if target[selector] != "1":
            raise Invalid("amendment target version unsupported")
        domain, shape_name = _TARGET_ARMS[selector]
        if not isinstance(target.get("signature"), dict):
            raise Invalid("amendment target signature missing")
        # Every evidence arm is signed by the session's phase orchestrator.
        require_signer(target, orchestrator)
        verify_embedded(target, public_keys, domain)
        if not getattr(shape, shape_name)(target):
            raise Invalid(f"amendment target is not its {selector} arm")
        if "signer" in target_ref:
            require_signer(target, target_ref["signer"])
        if target.get("jobId") != amendment.get("jobId"):
            raise Invalid("amendment target job mismatch")
        if target.get("phase") not in PAYMENT_PHASES:
            raise Invalid("amendment target is not a payment phase")
        # Every arm's {evidenceHash} is its signature-omitting content hash.
        address = (_AMENDMENT_ADDRESS.fullmatch(amendment_address)
                   if isinstance(amendment_address, str) else None)
        if (address is None or address.group(1) != amendment.get("jobId")
                or address.group(2) != digest):
            raise Invalid("amendment address does not bind the target evidence hash")
        return "valid", "AMEND-1 target verified"
    except Unknown as exc:
        return "indeterminate", str(exc)
    except (Invalid, ValueError, TypeError, KeyError) as exc:
        return "violation", str(exc)


# ---- RTB-1 --------------------------------------------------------------------

def rail_address(rail: dict) -> str:
    return f"dacs4:rail:{cf4_encode(rail['railId'])}:{rail['railVersion']}"


def resolve_session_rail(
    session: dict, rail_ref: dict, rail: dict, authority: dict, *,
    public_keys: dict, steward: str, network_authority: str, network_id: str,
    proof_profile: str, validator_set_id: str,
) -> tuple[str, str]:
    """Resolve an existing session's PA-2/PA-3 rail under DACS-4 §9.4.3 RTB-1.

    `session` carries the authenticated `startedAt` and pinned
    `railRegistryVersion`; `authority` carries the registry index snapshot and
    the finalized index and definition AnchorReceipts. A missing index,
    receipt or finalized binding does not resolve the rail (`indeterminate`);
    an authenticated contradiction, including authority later than the
    session start, is `rejected`.
    """
    try:
        started_at = session["startedAt"]
        registry_version = session["railRegistryVersion"]
        if type(started_at) is not int or type(registry_version) is not int:
            raise TypeError("session pins are not integers")
        index = authority.get("railRegistryIndex") if isinstance(authority, dict) else None
        index_receipt = authority.get("railRegistryIndexReceipt") if isinstance(authority, dict) else None
        rail_receipt = authority.get("railDefinitionReceipt") if isinstance(authority, dict) else None
        if not all(isinstance(value, dict) for value in (index, index_receipt, rail_receipt)):
            raise Unknown("pinned registry index or a finalized anchor binding is unavailable")
        # RD-1: the definition is the steward's, under the rail domain.
        verify_embedded(rail, public_keys, RAIL_DOMAIN)
        require_signer(rail, steward)
        # The index must be the session's own pinned snapshot: a later index
        # can inform a new session but not rewrite this one's rail authority.
        if (set(index) != {"registryVersion", "logicalAddress", "entries"}
                or index["logicalAddress"] != REGISTRY_INDEX_ADDRESS
                or not isinstance(index["entries"], list)):
            raise Invalid("rail-registry index snapshot is malformed")
        if type(index["registryVersion"]) is not int or index["registryVersion"] != registry_version:
            raise Invalid("index is not the session's pinned registry snapshot")
        entries = [entry for entry in index["entries"]
                   if isinstance(entry, dict) and entry.get("railId") == rail["railId"]]
        if len(entries) != 1 or not isinstance(entries[0].get("versions"), list):
            raise Invalid("pinned index does not list this rail exactly once")
        entry = entries[0]
        selected = rail_ref.get("railVersion", entry.get("latestVersion"))
        if rail_ref.get("railId") != rail["railId"] or type(selected) is not int \
                or rail["railVersion"] != selected:
            raise Invalid("definition is not the version the agreement selects")
        versions = [item for item in entry["versions"]
                    if isinstance(item, dict) and item.get("railVersion") == selected]
        if (len(versions) != 1 or versions[0].get("logicalAddress") != rail_address(rail)
                or versions[0].get("contentHash") != content_hash(rail)):
            raise Invalid("pinned index does not select this definition")
        # Both bindings must be finalized and authentic before any field,
        # including the timestamp, is read from them.
        for receipt, logical, digest in (
            (index_receipt, REGISTRY_INDEX_ADDRESS, sha256_hex(jcs_bytes(index))),
            (rail_receipt, rail_address(rail), content_hash(rail)),
        ):
            if not _established_finalized(receipt):
                raise Unknown(f"{logical} has no finalized anchor binding")
            try:
                _verify_finality_proof(
                    receipt, public_keys=public_keys, network_authority=network_authority,
                    network_id=network_id, proof_profile=proof_profile,
                    validator_set_id=validator_set_id,
                )
            except (Invalid, ValueError, TypeError, KeyError) as exc:
                raise Unknown(f"{logical} anchor is not authentic: {exc}") from exc
            if receipt["logicalAddress"] != logical or receipt["contentHash"] != digest:
                raise Invalid(f"authentic {logical} anchor binds other content")
        accepted_at = rail["governance"]["acceptedAt"]
        if (type(accepted_at) is not int or accepted_at > started_at
                or index_receipt["blockRef"]["timestamp"] > started_at
                or rail_receipt["blockRef"]["timestamp"] > started_at):
            raise Invalid("rail authority postdates the session start")
        return "verified", "rail authority was pinned and finalized by session start"
    except Unknown as exc:
        return "indeterminate", str(exc)
    except (Invalid, ValueError, TypeError, KeyError) as exc:
        return "rejected", str(exc)
