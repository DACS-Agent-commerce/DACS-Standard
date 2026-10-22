"""Non-normative PC-1 input gate, AMEND-1 target consumer and RTB-1 rail check.

Bindings (including the signed Listing's identity-bound agreement selection),
the session orchestrator and its native receipt writer, the session's
`startedAt` and pinned rail-registry version, the amendment's anchored
address, the rail steward and registry writer, and the resolver/network pins
are verifier-owned arguments, never selected from phase input, target members
or receipts. Session and registry pins are cross-checked against exact retained
bytes authenticated by a separately pinned fixture root under
`settlement-vector-retained-state:`. This test profile models an immutable
authenticated session store; it does not define a production session envelope.
Finality uses a synthetic test proof profile
(`settlement-vector-anchor-finality:`), not a production Demos proof; its
`blockRef.timestamp` is CORE SR2-6 consensus time in unix milliseconds.
AMEND-1 admits the amendment and the resolved target from their exact
received bytes under CORE CF-5 (`raw_json_profile.loads`), as it admits the
embedded finality proof. Resolvers return every carrier they found for an
address. Observations of each SR2-5 tuple are reconciled through authenticated
binding order before incompatible authorized bindings count as equivocation
(CORE §5). Only `ed25519` signatures are
implemented; another registered `ComponentSignature` algorithm leaves the
decision `indeterminate`. This module makes no live rail calls and implements
no refund ledger. A `valid` result admits the target under AMEND-1 only.
AMEND-2/3, amendment writer authorization, and a transition or finality-bound
target's §9.7 reservation or FV-1..FV-10 authority remain the enclosing
consumer's responsibility. PC-1 types the identity-binding companions; the
IBH-1..IBH-5 rerun over their contents is the verifier-owned
`PhaseBinding.identity_binding`, and without it an identity-bound payment is
`indeterminate`. RTB-1 here verifies PA-2 single-signer rails; a PA-1 in-code
or PA-3 multisig rail is left `indeterminate`, not verified.

The synthetic finality proof may carry a signed `observationSequence`, a
canonical unsigned-decimal string ordering finalized observations of one
SR2-5 tuple. Such observations may differ in `observedAt` only; all anchor
facts, including blockRef consensus time, remain fixed. Without that native
order, unequal snapshots of one tuple are unorderable (SR2-7).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from dacs_reference import cf4_encode  # noqa: E402
from jcs import canonicalize  # noqa: E402
import raw_json_profile  # noqa: E402


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
_JOB_ID = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}\Z")
_PAYMENT_ADDRESS = re.compile(
    r"dacs4:payment:([^:]+):([^:]+):(0|[1-9][0-9]*)(:resolved)?\Z"
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
# them: (signature domain, complete arm shape predicate name).
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
# Fixture-only authentication of independently retained session/registry state.
# This is not a new DACS artifact or a production session-signature codec.
RETAINED_STATE_DOMAIN = b"settlement-vector-retained-state:"
# Bound on decoded proof bytes, checked before JSON admission.
MAX_PROOF_BYTES = 64 * 1024
# Bounds on what a resolver hands back: received artifact bytes, checked
# before CF-5 admission, and the carriers listed for one address.
MAX_ARTIFACT_BYTES = 256 * 1024
MAX_CARRIERS = 16
SAFE_INT_MAX = 2**53 - 1
# ComponentSignature algorithms (DACS-4 §9.7); only ed25519 is implemented.
REGISTERED_ALGORITHMS = frozenset({"ed25519", "ecdsa-secp256k1", "sr1-aggregate"})
_IDENTITY_BOUND_SELECTORS = frozenset({
    "identityBoundAgreementVersion", "identityBoundPayeeAgreementVersion",
})
# DACS-4 §9.7 ordinary SettlementEvidence members. The ordinary arm keeps
# unknown optional members under CORE SIG-5 (older-reads-newer); the
# transition and finality-bound arms are closed.
_SETTLEMENT_EVIDENCE_MEMBERS = frozenset({
    "evidenceVersion", "jobId", "phase", "outcome", "observedAt", "signature",
    "reason", "paymentTxRefs", "paymentAmount", "paymentFee",
    "deliverableContentHash", "deliverableAnchor", "attestationRef",
    "settlementFinality", "amendmentRefs", "supersedesEvidenceRef",
})
# CORE §5.1 AnchorReceipt v1 members; binding metadata belongs in `evidence`.
_RECEIPT_MEMBERS = frozenset({
    "receiptVersion", "substrate", "finalityProfile", "logicalAddress", "nativeAddress",
    "contentHash", "transactionRef", "writer", "nonce", "state", "observationDisposition",
    "preservedReceiptHash", "observedAt", "blockRef", "replacementTransactionRef", "evidence",
})
_HEIGHT = re.compile(r"(0|[1-9][0-9]*)\Z")


def _shapes():
    for path in (ROOT, ROOT / "tests"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    import dacs5_reference
    return dacs5_reference


@dataclass(frozen=True)
class PhaseBinding:
    """Authenticated invocation metadata supplied by the enclosing verifier.

    `identity_bound` is the signed Listing phase's selection of either
    identity-bound agreement kind (DACS-4 §9.5.1); it alone selects the
    IdentityBoundPaymentPhaseInput path. `identity_binding` is the verifier's
    IBH-1..IBH-5 rerun against the retained Identify/Vet admission: given the
    phase input it returns "verified", "rejected" or "indeterminate".
    `signer` is the enclosing runtime's capability, attached only after wire
    admission and the IBH rerun, never obtained from a serialized member.
    """
    phase: str
    identity_bound: bool = False
    identity_binding: Callable[[dict], str] | None = None
    signer: Any = None


class InputArmError(ValueError):
    pass


class InputAuthorityUnavailable(RuntimeError):
    """§9.5.1: required identity-binding authority is missing: indeterminate."""


def _party_valid(shape, value, key_member: str, *, identity_bound=False) -> bool:
    if (not isinstance(value, dict) or not {"bundleHash", "primaryClaim", key_member} <= set(value)
            or not (shape._sha256_hex(value["bundleHash"]) if identity_bound
                    else shape._nonempty_jcs_string(value["bundleHash"]))
            or not shape._claim_reference_shape_valid(value["primaryClaim"])):
        return False
    if key_member == "payingKey":
        return shape._claim_reference_shape_valid(value["payingKey"])
    return shape._nonempty_jcs_string(value["payeeAddress"])


def _listing_ref_valid(shape, value) -> bool:
    return (isinstance(value, dict) and {"listingId", "version", "contentHash"} <= set(value)
            and shape._nonempty_jcs_string(value["listingId"])
            and shape._safe_nonnegative_integer(value["version"], positive=True)
            and shape._sha256_hex(value["contentHash"]))


def _price_term_valid(shape, value) -> bool:
    """PriceTerm's declared members typed; unknown members stay open (SIG-5)."""
    return (isinstance(value, dict) and shape._price_term_shape_valid(
        {key: item for key, item in value.items() if key in {"amount", "currency", "unit"}})
            and ("unit" not in value or shape._nonempty_jcs_string(value["unit"])))


def _attestation_ref_valid(shape, value) -> bool:
    """AttestationRef's declared members typed; unknown members stay open (SIG-5)."""
    if not isinstance(value, dict) or not isinstance(value.get("anchor"), dict):
        return False
    projected = {key: item for key, item in value.items()
                 if key in {"anchor", "contentHash", "signer"}}
    projected["anchor"] = {key: item for key, item in value["anchor"].items()
                           if key in {"kind", "locator"}}
    return shape._attestation_ref_shape_valid(projected)


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
            and _listing_ref_valid(shape, value["listingRef"])
            and isinstance(value["parties"], list) and bool(value["parties"])
            and all(isinstance(party, dict)
                    and shape._string_member(party.get("role"),
                                             {"buyer", "seller", "bidder-non-winning"})
                    and (shape._sha256_hex(party.get("bundleHash")) if identity_bound
                         else shape._nonempty_jcs_string(party.get("bundleHash")))
                    and shape._claim_reference_shape_valid(party.get("primaryClaim"))
                    and _attestation_ref_valid(shape, party.get("vetRecordRef"))
                    and ("encryptionKey" not in party
                         or shape._nonempty_jcs_string(party["encryptionKey"]))
                    for party in value["parties"])
            and isinstance(terms, dict) and {"deliverable", "price", "deadline", "rail"} <= set(terms)
            and _agreement_deliverable_valid(shape, terms["deliverable"])
            and _price_term_valid(shape, terms["price"])
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
                 or _attestation_ref_valid(shape, terms["priorPaymentDispositionRef"]))
            and (sealed or "selectionReceiptRef" not in value)
            and shape._string_member(value["derivedFromPattern"], {"sealed-envelope"} if sealed
                                     else {"fixed-price", "rfq", "sealed-envelope"})
            and (not sealed or _attestation_ref_valid(shape, value.get("selectionReceiptRef")))
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
    return (_attestation_ref_valid(shape, value.get("validatorSetRef"))
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


def _session_context_valid(shape, value, *, identity_bound=False) -> bool:
    # This is SerializedSessionContext, never the runtime capability carrier.
    return (isinstance(value, dict)
            and "signer" not in value
            and {"jobId", "listingRef", "recipeRegistryVersion", "railRegistryVersion",
                 "parties", "priorPhaseOutputs", "startedAt"} <= set(value)
            and shape._nonempty_jcs_string(value["jobId"])
            and _listing_ref_valid(shape, value["listingRef"])
            and shape._safe_nonnegative_integer(value["recipeRegistryVersion"])
            and shape._safe_nonnegative_integer(value["railRegistryVersion"])
            and isinstance(value["parties"], list) and bool(value["parties"])
            and all(isinstance(party, dict)
                    and shape._string_member(party.get("role"), {"buyer", "seller", "orchestrator"})
                    and (shape._sha256_hex(party.get("bundleHash")) if identity_bound
                         else shape._nonempty_jcs_string(party.get("bundleHash")))
                    and shape._claim_reference_shape_valid(party.get("primaryClaim"))
                    and ("vetRecordRef" not in party
                         or _attestation_ref_valid(shape, party["vetRecordRef"]))
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
            and _party_valid(shape, phase_input["payer"], "payingKey", identity_bound=binding.identity_bound)
            and _party_valid(shape, phase_input["payee"], "payeeAddress", identity_bound=binding.identity_bound)
            and _price_term_valid(shape, phase_input["amount"])):
        raise InputArmError("payment input member is not its declared type")
    if not _session_context_valid(shape, phase_input["sessionContext"], identity_bound=binding.identity_bound):
        raise InputArmError("sessionContext is not SessionContext")
    # §9.5.1: the signed Listing's selection alone selects the path; an
    # agreement of the other kind contradicts it in either direction.
    identity_bound = any(key in phase_input["agreement"] for key in _IDENTITY_BOUND_SELECTORS)
    if binding.identity_bound != identity_bound:
        raise InputArmError("agreement is not the agreement kind the Listing selects")
    # A present companion member is typed on either path exactly where IBH
    # makes it `error`: not an array, empty, or an entry that is not an
    # object carrying `identityBundle` or `compositeRecord`. Only an absent
    # member on the identity-bound path is missing authority
    # (`indeterminate`); IBH-1..IBH-5 decides each companion's members.
    if "identityBindingCompanions" in phase_input:
        companions = phase_input["identityBindingCompanions"]
        if not isinstance(companions, list):
            raise InputArmError("identityBindingCompanions is not an array")
        if not companions:
            raise InputArmError("identityBindingCompanions is empty")
        if not all(isinstance(item, dict) and {"identityBundle", "compositeRecord"} & set(item)
                   for item in companions):
            raise InputArmError("identityBindingCompanions entry is not an IdentityBoundAgreementCompanion")
    elif identity_bound:
        raise InputAuthorityUnavailable("identity-bound payment input lacks identityBindingCompanions")


def _require_identity_binding(binding: PhaseBinding, phase_input: dict) -> None:
    """§9.5.1: the verifier's IBH-1..IBH-5 rerun must verify before any rail call."""
    if binding.identity_binding is None:
        raise InputAuthorityUnavailable("no IBH-1..IBH-5 rerun authority for the identity-bound path")
    try:
        verdict = binding.identity_binding(phase_input)
    except Exception as exc:  # noqa: BLE001 - an unavailable rerun is missing authority
        raise InputAuthorityUnavailable(
            f"IBH-1..IBH-5 rerun unavailable ({type(exc).__name__}: {exc})") from exc
    if verdict == "rejected":
        raise InputArmError("IBH-1..IBH-5 rerun rejected the identity binding")
    if verdict != "verified":
        raise InputAuthorityUnavailable(f"IBH-1..IBH-5 rerun did not verify ({verdict!r})")


def dispatch_payment(binding: PhaseBinding, phase_input: Any, handler: Callable) -> dict:
    """Run the PC-1 input gate and, on the identity-bound path, the verifier's
    IBH-1..IBH-5 rerun before the enclosing handler can call a rail."""
    try:
        check_payment_input(binding, phase_input)
        if binding.identity_bound:
            _require_identity_binding(binding, phase_input)
        if binding.signer is None:
            raise InputAuthorityUnavailable("runtime SubstrateSigner unavailable")
    except InputArmError as exc:
        return {"status": "rejected", "ok": False, "errorClass": "permanent",
                "reason": str(exc)}
    except InputAuthorityUnavailable as exc:
        return {"status": "indeterminate", "ok": False, "errorClass": "substrate",
                "reason": str(exc)}
    runtime_input = {**phase_input, "sessionContext": {
        **phase_input["sessionContext"], "signer": binding.signer}}
    return handler(runtime_input)


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


def _well_formed(text: str) -> bool:
    return not any(0xD800 <= ord(character) <= 0xDFFF for character in text)


def in_number_profile(value: Any) -> bool:
    """CORE §B.2 value model: finite numbers, integral or fractional, of
    magnitude at most 2**53 - 1, and well-formed strings and member names.

    Values need not already be NFC: CF-1 normalizes string values (never
    member names) while hashing, which `jcs.canonicalize` does.
    """
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, str):
        return _well_formed(value)
    if isinstance(value, int):
        return abs(value) <= SAFE_INT_MAX
    if isinstance(value, float):
        return math.isfinite(value) and abs(value) <= SAFE_INT_MAX
    if isinstance(value, list):
        return all(in_number_profile(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _well_formed(key) and in_number_profile(item)
                   for key, item in value.items())
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
    # Every spelling with the same CF-3 identity counts, the exact one too:
    # an exact match must not hide a conflicting parameterized entry.
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
        raise Invalid("missing signature")
    algorithm = signature.get("algorithm")
    if not isinstance(algorithm, str) or algorithm not in REGISTERED_ALGORITHMS:
        raise Invalid("unregistered signature algorithm")
    claim_identity(signature.get("signer"))
    raw = b64u_decode(signature.get("value"))
    if not raw:
        raise Invalid("signature value must be non-empty")
    if not in_number_profile(value):
        raise Invalid("signed value is outside the CORE §B.2 value model")
    if algorithm == "ed25519" and len(raw) != 64:
        raise Invalid("Ed25519 key or signature has the wrong length")
    if algorithm != "ed25519":
        # Registered but not implemented here: another verifier may decide it.
        raise Unknown(f"signature algorithm {algorithm} is not implemented by this verifier")
    encoded_key = _public_key(public_keys, signature.get("signer"))
    if encoded_key is None:
        raise Unknown(f"no authenticated key for {signature.get('signer')}")
    key = b64u_decode(encoded_key)
    if len(key) != 32 or len(raw) != 64:
        raise Invalid("Ed25519 key or signature has the wrong length")
    message = domain + content_hash(value).encode("ascii")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(raw, message)
    except InvalidSignature as exc:
        raise Invalid("invalid signature") from exc


def _verify_finality_proof(receipt: dict, *, writer: str, public_keys: dict,
                           network_authority: str, network_id: str, proof_profile: str,
                           validator_set_id: str) -> int | None:
    """Authenticate an AnchorReceipt's own fields (CORE SR2-4) and its writer.

    The synthetic proof is a network-authority-signed copy of every receipt
    member except `evidence`, so `state`, `observationDisposition`,
    `substrate` and `finalityProfile` are bound too. A receipt from a writer
    other than the verifier-owned `writer` proves publication, not authority
    (CORE SR2-11). Every failure here discards the receipt.
    """
    if not set(receipt) <= _RECEIPT_MEMBERS:
        raise Invalid("AnchorReceipt carries a member outside AnchorReceipt v1")
    if receipt.get("substrate") != network_id or receipt.get("finalityProfile") != proof_profile:
        raise Invalid("AnchorReceipt network or finality profile is not pinned")
    for key in ("logicalAddress", "nativeAddress", "contentHash", "writer"):
        if not isinstance(receipt.get(key), str) or not receipt[key]:
            raise Invalid(f"AnchorReceipt {key} is malformed")
    if not _shapes()._sha256_hex(receipt["contentHash"]):
        raise Invalid("AnchorReceipt contentHash is malformed")
    # CORE §5.1: nonce is required only where the substrate uses one.
    if "nonce" in receipt and (not isinstance(receipt["nonce"], str) or not receipt["nonce"]):
        raise Invalid("AnchorReceipt nonce is malformed")
    transaction = receipt.get("transactionRef")
    if (not isinstance(transaction, dict) or set(transaction) != {"kind", "value"}
            or not all(isinstance(item, str) and item for item in transaction.values())):
        raise Invalid("AnchorReceipt transactionRef is malformed")
    if type(receipt.get("observedAt")) is not int or not 0 <= receipt["observedAt"] <= SAFE_INT_MAX:
        raise Invalid("AnchorReceipt observedAt is malformed")
    # SR2-6: consensus time is blockRef.timestamp in unix ms; a finalized
    # receipt carries it, and a present height is canonical decimal.
    block = receipt.get("blockRef")
    if (not isinstance(block, dict) or not isinstance(block.get("id"), str) or not block["id"]
            or type(block.get("timestamp")) is not int
            or not 0 <= block["timestamp"] <= SAFE_INT_MAX
            or ("height" in block and (not isinstance(block["height"], str)
                                       or _HEIGHT.fullmatch(block["height"]) is None))):
        raise Invalid("AnchorReceipt blockRef is malformed")
    evidence = receipt.get("evidence")
    if not isinstance(evidence, dict):
        raise Invalid("AnchorReceipt carries no finality proof")
    if evidence.get("kind") != ANCHOR_TEST_KIND:
        raise Invalid("AnchorReceipt finality proof kind is not the pinned profile's")
    raw = b64u_decode(evidence.get("value"))
    if len(raw) > MAX_PROOF_BYTES:
        raise Invalid("AnchorReceipt finality proof exceeds the byte limit")
    try:
        # CORE CF-5: admit the proof from its exact bytes.
        proof = raw_json_profile.loads(raw)
    except raw_json_profile.RawJsonProfileError as exc:
        raise Invalid(f"AnchorReceipt finality proof is not admitted JSON: {exc}") from exc
    if not isinstance(proof, dict):
        raise Invalid("AnchorReceipt finality proof is not an object")
    try:
        verify_embedded(proof, public_keys, ANCHOR_TEST_DOMAIN)
    except Unknown as exc:
        raise Invalid(f"AnchorReceipt finality proof is unverifiable: {exc}") from exc
    require_signer(proof, network_authority)
    expected = {
        "receipt": {key: value for key, value in receipt.items() if key != "evidence"},
        "networkId": network_id,
        "proofProfile": proof_profile,
        "validatorSetId": validator_set_id,
    }
    if not (set(expected) | {"signature"}) <= set(proof) or set(proof) - set(expected) - {
            "signature", "observationSequence"} or any(
            canonicalize(proof[key]) != canonicalize(value) for key, value in expected.items()):
        raise Invalid("AnchorReceipt finality proof does not bind the receipt's fields")
    if receipt["writer"] != writer:
        raise Invalid("AnchorReceipt writer is not the authorized writer")
    # Test-profile SR2-7 order lives inside the signed evidence, never in
    # observedAt or an unverified sidecar. Finalized re-observations preserve
    # every receipt field except observer time, including anchor consensus time.
    sequence = proof.get("observationSequence")
    if "observationSequence" in proof:
        if not isinstance(sequence, str) or _HEIGHT.fullmatch(sequence) is None:
            raise Invalid("AnchorReceipt observation sequence is malformed")
        return int(sequence)
    return None


def _established_finalized(receipt: Any) -> bool:
    return (isinstance(receipt, dict) and receipt.get("receiptVersion") == "1"
            and receipt.get("state") == "finalized"
            and receipt.get("observationDisposition") == "established")


def admit(raw: Any, error: type[Exception], label: str) -> Any:
    """CORE CF-5: admit an external document from its exact received bytes."""
    if not isinstance(raw, bytes):
        raise error(f"{label} is not received bytes")
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise error(f"{label} exceeds the byte limit")
    try:
        return raw_json_profile.loads(raw)
    except raw_json_profile.RawJsonProfileError as exc:
        raise error(f"{label} is not admitted JSON: {exc}") from exc


def _sole_carrier(receipts: Any, label: str, for_address: Callable[[dict], None],
                  **pins) -> dict:
    """The one authorized finalized carrier for an immutable address (CORE §5).

    Every candidate that is not an established finalized receipt for this
    address, whose proof does not authenticate its fields, or whose writer
    is not the authorized one is discarded (SR2-4, SR2-11, SR2-12).
    Observations of the same tuple are reconciled by this test profile's
    signed observationSequence. Distinct bindings are equivocation; neither
    fetch order nor observer time can choose a winner.
    """
    if not isinstance(receipts, list) or not receipts:
        raise Unknown(f"{label} has no finalized anchor binding")
    if len(receipts) > MAX_CARRIERS:
        raise Unknown(f"{label} lists more carriers than this verifier admits")
    groups, causes = {}, []
    for receipt in receipts:
        try:
            if not _established_finalized(receipt):
                raise Invalid("receipt is not an established finalized receipt")
            for_address(receipt)
            sequence = _verify_finality_proof(receipt, **pins)
        except (Invalid, ValueError, TypeError, KeyError) as exc:
            causes.append(str(exc))
            continue
        binding = canonicalize({key: receipt.get(key) for key in (
            "substrate", "logicalAddress", "nativeAddress", "contentHash",
            "transactionRef", "writer", "nonce")})
        groups.setdefault(binding, []).append((receipt, sequence))
    survivors = {}
    for binding, observations in groups.items():
        bodies = {canonicalize({k: v for k, v in r.items() if k != "evidence"})
                  for r, _ in observations}
        if len(bodies) == 1:
            survivors[binding] = observations[0][0]
            continue
        fixed = {canonicalize({k: v for k, v in r.items() if k not in {"evidence", "observedAt"}})
                 for r, _ in observations}
        ordered = {}
        for receipt, sequence in observations:
            body = canonicalize({k: v for k, v in receipt.items() if k != "evidence"})
            if (sequence is None or len(fixed) != 1
                    or (sequence in ordered and ordered[sequence][0] != body)):
                raise Unknown(f"{label} has unorderable observations of one transaction (SR2-7)")
            ordered[sequence] = (body, receipt)
        survivors[binding] = ordered[max(ordered)][1]
    if len(survivors) > 1:
        raise Unknown(f"{label} has {len(survivors)} canonically unequal authorized carriers (equivocation)")
    if not survivors:
        raise Unknown(f"{label} anchor is not authentic: {'; '.join(causes)}")
    return next(iter(survivors.values()))


# ---- AMEND-1 ------------------------------------------------------------------

def _ordinary_target_shape(record: dict) -> dict:
    """Declared members of open ordinary types, only for shape checking.

    Hashing and signature verification always use the complete received object.
    ChainTxRef remains its explicitly closed discriminated union (§9.3).
    """
    checked = {k: v for k, v in record.items() if k in _SETTLEMENT_EVIDENCE_MEMBERS}

    def project(value, members):
        return {k: v for k, v in value.items() if k in members} if isinstance(value, dict) else value

    def attestation(value):
        value = project(value, {"anchor", "contentHash", "signer"})
        if isinstance(value, dict) and "anchor" in value:
            value["anchor"] = project(value["anchor"], {"kind", "locator"})
        return value

    for key, members in (
            ("paymentAmount", {"amount", "currency", "unit"}),
            ("paymentFee", {"amount", "currency", "unit"}),
            ("signature", {"algorithm", "signer", "value"}),
            ("settlementFinality", {"model", "finalityBlocks", "finalityCommitmentLevel", "finalityObservedAt"}),
            ("deliverableAnchor", {"kind", "locator"})):
        if key in checked:
            checked[key] = project(checked[key], members)
    for key in ("attestationRef", "supersedesEvidenceRef"):
        if key in checked:
            checked[key] = attestation(checked[key])
    if isinstance(checked.get("amendmentRefs"), list):
        checked["amendmentRefs"] = [attestation(value) for value in checked["amendmentRefs"]]
    if isinstance(checked.get("paymentTxRefs"), list):
        refs = []
        for value in checked["paymentTxRefs"]:
            if isinstance(value, dict) and value.get("kind") in ("ap2", "ap2-sr3"):
                # The union arm stays closed; its embedded reference types
                # retain their own open-member policy.
                value = dict(value)
                if "receiptAttestation" in value:
                    value["receiptAttestation"] = attestation(value["receiptAttestation"])
                if "receiptTransactionRef" in value:
                    value["receiptTransactionRef"] = project(value["receiptTransactionRef"], {"kind", "value"})
            refs.append(value)
        checked["paymentTxRefs"] = refs
    return checked


def _payment_address_valid(address: Any, job_id: str) -> bool:
    match = _PAYMENT_ADDRESS.fullmatch(address) if isinstance(address, str) else None
    if match is None or match[1] != job_id:
        return False
    rail = unquote(match[2], errors="strict")
    return _RAIL_ID.fullmatch(rail) is not None and cf4_encode(rail) == match[2]

def consume_amendment_target(
    amendment: bytes, resolve: Callable[[dict], dict | None], *,
    amendment_address: str, orchestrator: str, writer: str,
    public_keys: dict, network_authority: str, network_id: str,
    proof_profile: str, validator_set_id: str,
    retained_state: bytes | None = None,
) -> tuple[str, str]:
    """Admit, resolve, establish finality, hash, then select/verify the AMEND-1 arm.

    `amendment` and the resolved `artifact` are exact received bytes, each
    admitted under CORE CF-5 before any hash or signature check: refused
    amendment bytes violate, refused target bytes are a substituted
    resolution. The resolver returns {artifact, anchorReceipts} with every
    carrier it found for the reference's locator. No surviving carrier
    (absent, unfinalized, inauthentic or another writer's), an equivocation,
    or bytes that differ from the authentic anchor binding the reference's
    hash leave the target pending. Contradictory established proofs are
    violations. `orchestrator` is the authenticated session phase
    orchestrator, `writer` its verifier-owned native receipt writer, and
    `amendment_address` the amendment's own anchored logical address. The
    reference's locator may be the receipt's logical PC-2 payment address or
    its native address. No AMEND-4 reject-versus-flag policy is selected here.
    """
    shape = _shapes()
    try:
        amendment = admit(amendment, Invalid, "amendment")
        if not isinstance(amendment, dict):
            raise Invalid("amendment is not an object")
        if not isinstance(amendment.get("jobId"), str) or _JOB_ID.fullmatch(amendment["jobId"]) is None:
            raise Invalid("amendment jobId malformed")
        state = authenticate_retained_state(retained_state, public_keys, network_authority)
        if (state["jobId"] != amendment["jobId"]
                or claim_identity(state["orchestrator"]) != claim_identity(orchestrator)
                or state["writer"] != writer):
            raise Invalid("amendment authority differs from retained session state")
        orchestrator, writer = state["orchestrator"], state["writer"]
        target_ref = amendment.get("amendsEvidenceRef")
        # Declared members typed; unknown signed members stay open (SIG-5).
        if not _attestation_ref_valid(shape, target_ref):
            raise Invalid("amendment target reference malformed")
        verify_embedded(amendment, public_keys, AMENDMENT_DOMAIN)
        try:
            resolved = resolve(target_ref)
        except Exception as exc:  # noqa: BLE001 - any resolver failure is unavailability
            # Keep the cause: a timeout, a not-found, a refusal or a bad reply differ.
            raise Unknown(f"amendment target unavailable ({type(exc).__name__}: {exc})") from exc
        if not isinstance(resolved, dict):
            raise Unknown("amendment target unavailable")
        locator = target_ref["anchor"]["locator"]

        def for_payment_address(receipt):
            if locator not in (receipt.get("logicalAddress"), receipt.get("nativeAddress")):
                raise Invalid("AnchorReceipt is for another address")
            if not _payment_address_valid(receipt.get("logicalAddress"), amendment["jobId"]):
                raise Invalid("AnchorReceipt is not for a PC-2 payment address of this job")
        # CORE SR2-4/SR2-11/SR2-12: receipt fields are assertions until its
        # proof binds them, and only the orchestrator's writer has authority
        # over the payment address.
        anchor = _sole_carrier(
            resolved.get("anchorReceipts"), "amendment target", for_payment_address,
            writer=writer, public_keys=public_keys, network_authority=network_authority,
            network_id=network_id, proof_profile=proof_profile, validator_set_id=validator_set_id)
        # PC-2's payment address is single-write, so an authentic anchor by
        # the authorized writer binding another hash means the reference
        # names other content.
        if anchor["contentHash"] != target_ref["contentHash"]:
            raise Invalid("authentic amendment target anchor binds another content hash")
        target = admit(resolved.get("artifact"), Unknown, "amendment target")
        if not isinstance(target, dict):
            raise Unknown("amendment target is not an object")
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
        if not isinstance(target.get("jobId"), str) or _JOB_ID.fullmatch(target["jobId"]) is None:
            raise Invalid("amendment target jobId malformed")
        # Every evidence arm is signed by the session's phase orchestrator.
        require_signer(target, orchestrator)
        # The ordinary arm keeps unknown optional members (CORE SIG-5); the
        # transition and finality-bound arms are closed.
        checked = (_ordinary_target_shape(target)
                   if selector == "evidenceVersion" else target)
        if not getattr(shape, shape_name)(checked):
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
        verify_embedded(target, public_keys, domain)
        return "valid", "AMEND-1 target verified"
    except Unknown as exc:
        return "indeterminate", str(exc)
    except (Invalid, ValueError, TypeError, KeyError) as exc:
        return "violation", str(exc)


# ---- RTB-1 --------------------------------------------------------------------

_REGISTRY_ANCHOR_KINDS = frozenset({"storage-program", "ipfs", "https"})


def _nfc(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _positive_safe(value: Any) -> bool:
    return type(value) is int and 0 < value <= SAFE_INT_MAX


def _index_entry_valid(shape, entry) -> bool:
    """CORE RegistryIndexEntry (closed): id, exact version, native anchor, content hash."""
    anchor = entry.get("anchor") if isinstance(entry, dict) else None
    return (isinstance(entry, dict) and set(entry) == {"id", "version", "anchor", "contentHash"}
            and isinstance(entry["id"], str) and bool(entry["id"]) and _well_formed(entry["id"])
            and shape._safe_nonnegative_integer(entry["version"], positive=True)
            and isinstance(anchor, dict) and set(anchor) == {"kind", "locator"}
            and anchor["kind"] in _REGISTRY_ANCHOR_KINDS
            and isinstance(anchor["locator"], str) and bool(anchor["locator"])
            and shape._sha256_hex(entry["contentHash"]))


def authenticate_retained_state(raw, public_keys, network_authority):
    """Reauthenticate an immutable received snapshot against the fixture root.

    No caller boolean or mutable projection establishes authority. Production
    bindings obtain equivalent state from their authenticated session store.
    """
    if raw is None:
        raise Unknown("authenticated retained session state unavailable")
    if not isinstance(public_keys, dict):
        raise Unknown("retained session trust keys unavailable")
    state = admit(raw, Invalid, "retained session state")
    if not isinstance(state, dict):
        raise Invalid("retained session state is not an object")
    verify_embedded(state, public_keys, RETAINED_STATE_DOMAIN)
    if claim_identity(state["signature"]["signer"]) != claim_identity(network_authority):
        raise Unknown("retained session state has no proof from the pinned authority")
    if not {"jobId", "session", "orchestrator", "writer", "steward", "registryWriter"} <= set(state):
        raise Invalid("retained session state lacks authority pins")
    if not isinstance(state["session"], dict):
        raise Invalid("retained session pins malformed")
    return state


def resolve_session_rail(
    session: dict, rail_ref: dict, rail: dict, authority: dict, *,
    public_keys: dict, steward: str, registry_writer: str, network_authority: str,
    network_id: str, proof_profile: str, validator_set_id: str,
    retained_state: bytes | None = None, job_id: str | None = None,
) -> tuple[str, str]:
    """Check an existing session's PA-2 rail authority: §9.4.3 steps 1-2 and RTB-1.

    `retained_state` supplies the authenticated immutable session/registry
    snapshot. Bare caller pins cannot resolve anything: `session`, `steward`,
    `registry_writer` and `job_id` must match that snapshot.
    `session` carries the authenticated `startedAt` and pinned
    `railRegistryVersion`; `authority` carries the registry index snapshot
    (CORE `RegistryIndexSnapshot` shape, `revision` = the pinned version) and
    every finalized index and definition AnchorReceipt found for those
    bindings, written by the verifier-owned `registry_writer`. The agreement's
    exact `railVersion` pin, otherwise the unique greatest version listed for
    the rail ID, selects the entry; the definition receipt is matched by its
    native address to that entry's anchor locator (SR2-10). A missing,
    unfinalized, inauthentic or outsider binding, an equivocation, an
    internally inconsistent index, or a PA-1 in-code or PA-3 multisig rail
    (not modelled here) does not resolve the rail (`indeterminate`); an
    authenticated contradiction, including authority later than the session
    start, is `rejected`. `verified` means only that this rail authority was
    pinned and finalized by the session start: step 3 (availability,
    governance and RD-1..RD-6) stays with the caller.
    """
    shape = _shapes()
    try:
        state = authenticate_retained_state(retained_state, public_keys, network_authority)
        if (state["jobId"] != job_id or state["session"] != session
                or claim_identity(state["steward"]) != claim_identity(steward)
                or state["registryWriter"] != registry_writer):
            raise Invalid("rail authority differs from retained session/registry state")
        session = state["session"]
        steward, registry_writer = state["steward"], state["registryWriter"]
        if not all(isinstance(value, dict) for value in (session, rail_ref, rail)):
            raise Invalid("session pins, rail reference and rail definition must be objects")
        started_at = session["startedAt"]
        registry_version = session["railRegistryVersion"]
        if type(started_at) is not int or not _positive_safe(registry_version):
            raise TypeError("session pins are not an integer start and a positive registry version")
        index = authority.get("railRegistryIndex") if isinstance(authority, dict) else None
        index_receipts = authority.get("railRegistryIndexReceipts") if isinstance(authority, dict) else None
        rail_receipts = authority.get("railDefinitionReceipts") if isinstance(authority, dict) else None
        if not isinstance(index, dict) or not all(
                isinstance(value, list) and value for value in (index_receipts, rail_receipts)):
            raise Unknown("pinned registry index or a finalized anchor binding is unavailable")
        # RTB-1 covers PA-2 and PA-3; this verifier implements only the PA-2
        # single-signer steward signature, so another anchoring stays pending.
        anchoring = rail["governance"]["anchoring"]
        if anchoring in ("multisig", "in-code"):
            raise Unknown(f"{anchoring} rail authority is not implemented by this verifier")
        if anchoring != "single-signer":
            raise Invalid("rail governance anchoring is not a declared value")
        # RD-1: the definition is the steward's, under the rail domain.
        verify_embedded(rail, public_keys, RAIL_DOMAIN)
        require_signer(rail, steward)
        pins = {"writer": registry_writer, "public_keys": public_keys,
                "network_authority": network_authority, "network_id": network_id,
                "proof_profile": proof_profile, "validator_set_id": validator_set_id}

        def for_index_address(receipt):
            if receipt.get("logicalAddress") != REGISTRY_INDEX_ADDRESS:
                raise Invalid("index receipt is for another address")
        # The index is read only after its finalized binding authenticates it.
        index_receipt = _sole_carrier(index_receipts, REGISTRY_INDEX_ADDRESS, for_index_address, **pins)
        if index_receipt["contentHash"] != sha256_hex(jcs_bytes(index)):
            raise Invalid(f"authentic {REGISTRY_INDEX_ADDRESS} anchor binds other content")
        # The index must be the session's own pinned snapshot: a later index
        # can inform a new session but not rewrite this one's rail authority.
        if (index.get("registryIndexVersion") != "1" or index.get("registryKind") != "rail"
                or not _positive_safe(index.get("revision"))
                or not isinstance(index.get("entries"), list)
                or not all(_index_entry_valid(shape, entry) for entry in index["entries"])):
            raise Invalid("rail-registry index snapshot is malformed")
        if index["revision"] != registry_version:
            raise Invalid("index is not the session's pinned registry snapshot")
        keys = [(_nfc(entry["id"]), entry["version"]) for entry in index["entries"]]
        if len(keys) != len(set(keys)):
            raise Unknown("pinned index lists one rail version more than once")
        # §9.4.3 step 2: NFC comparison keys; an exact pin, else the unique
        # greatest numeric version. No hint member selects a version.
        rail_id = rail_ref.get("railId")
        if not isinstance(rail_id, str) or not isinstance(rail["railId"], str) \
                or _nfc(rail_id) != _nfc(rail["railId"]):
            raise Invalid("definition is not the rail the agreement names")
        listed = [entry for entry in index["entries"] if _nfc(entry["id"]) == _nfc(rail_id)]
        if not listed:
            raise Invalid("pinned index does not list this rail")
        if "railVersion" in rail_ref:
            if not shape._safe_nonnegative_integer(rail_ref["railVersion"], positive=True):
                raise Invalid("agreement railVersion pin is malformed")
            listed = [entry for entry in listed if entry["version"] == rail_ref["railVersion"]]
            if not listed:
                raise Invalid("pinned index does not list the agreement's rail version")
        entry = max(listed, key=lambda item: item["version"])
        if rail["railVersion"] != entry["version"] or type(rail["railVersion"]) is not int:
            raise Invalid("definition is not the version the agreement selects")
        if content_hash(rail) != entry["contentHash"]:
            raise Invalid("pinned index does not select this definition")
        # The definition binding must be finalized and authentic before any
        # field, including the timestamp, is read from it.
        def for_entry_address(receipt):
            if receipt.get("nativeAddress") != entry["anchor"]["locator"]:
                raise Invalid("definition receipt is for another native address")
        rail_receipt = _sole_carrier(rail_receipts, "rail definition", for_entry_address, **pins)
        if rail_receipt["contentHash"] != entry["contentHash"]:
            raise Invalid("authentic rail definition anchor binds other content")
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


@dataclass(frozen=True)
class ResolvedSessionRail:
    """Immutable exact resolution retained by the enclosing session store."""
    snapshot_hash: str
    definition_hash: str
    binding_bytes: bytes

    def fixture_projection(self):
        # A new copy for persistence; callers cannot mutate the retained bytes.
        return {**json.loads(self.binding_bytes), "snapshotHash": self.snapshot_hash,
                "definitionHash": self.definition_hash}


def resolve_session_rail_state(session, rail_ref, rail, authority, **pins):
    """Resolve first, then retain the exact authenticated snapshot and rail.

    No unresolved result produces session authority. Later consumers rerun the
    original proofs instead of trusting a saved status.
    """
    status, reason = resolve_session_rail(session, rail_ref, rail, authority, **pins)
    if status != "verified":
        return status, reason, None
    binding = {"retainedStateText": pins["retained_state"].decode("utf-8"),
               "railRef": rail_ref, "rail": rail, "authority": authority}
    retained = ResolvedSessionRail(
        sha256_hex(jcs_bytes(authority["railRegistryIndex"])), content_hash(rail),
        jcs_bytes(binding))
    return status, reason, retained


def verify_retained_rail(binding, candidate, reference, job_id, policy):
    """FV/DACS-5 reuses exact session rail authority, rechecking its proofs.

    The retained bundle includes the authenticated numeric snapshot, selected
    definition and both receipt histories. A saved success flag is never used.
    """
    if not isinstance(binding, dict) or not isinstance(policy, dict):
        return "indeterminate", "retained session rail authority unavailable"
    try:
        if not all(isinstance(binding.get(member), dict) for member in ("rail", "railRef", "authority")):
            raise Invalid("retained rail binding is malformed")
        text = binding["retainedStateText"]
        if not isinstance(text, str) or len(text) > MAX_ARTIFACT_BYTES:
            raise Invalid("retained session state text malformed or oversized")
        raw = text.encode("utf-8")
        state = authenticate_retained_state(raw, policy["public_keys"], policy["network_authority"])
        if (binding["snapshotHash"] != sha256_hex(jcs_bytes(binding["authority"]["railRegistryIndex"]))
                or binding["definitionHash"] != content_hash(binding["rail"])):
            raise Invalid("retained snapshot or definition differs from the original resolution")
        status, reason = resolve_session_rail(
            state["session"], binding["railRef"], binding["rail"], binding["authority"],
            retained_state=raw, job_id=job_id, steward=state["steward"],
            registry_writer=state["registryWriter"], **policy)
        if status != "verified":
            return status, reason
        if content_hash(candidate) != content_hash(binding["rail"]):
            raise Invalid("caller rail differs from the retained session definition")
        index = binding["authority"]["railRegistryIndex"]
        entry = next(entry for entry in index["entries"]
                     if entry["contentHash"] == content_hash(candidate)
                     and entry["version"] == candidate["railVersion"]
                     and _nfc(entry["id"]) == _nfc(candidate["railId"]))
        if reference["anchor"] != entry["anchor"]:
            raise Invalid("rail reference differs from the retained snapshot locator")
        return "verified", "exact session rail reauthenticated"
    except Unknown as exc:
        return "indeterminate", str(exc)
    except (Invalid, ValueError, TypeError, KeyError, StopIteration, UnicodeError) as exc:
        return "rejected", str(exc)
