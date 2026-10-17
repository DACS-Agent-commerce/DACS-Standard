"""Non-normative PC-1 dispatch and AMEND-1 target consumer.

Bindings, the session orchestrator, the amendment's anchored address and
resolver/network pins are verifier-owned arguments, never selected from phase
input or target members. Finality uses the existing synthetic proof profile;
this module makes no live rail calls and implements no refund ledger. A `valid`
result admits the target under AMEND-1 only. AMEND-2/3, amendment writer
authorization, and a transition or finality-bound target's §9.7 reservation or
FV-1..FV-10 authority remain the enclosing consumer's responsibility.
PhaseBinding does not carry the signed Listing's agreement-kind selection;
the enclosing verifier must enforce that selection and require/verify the
identityBindingCompanions for either identity-bound agreement kind.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]


PAYMENT_PHASES = frozenset({
    "pay-dem", "pay-evm-erc20", "pay-solana-spl", "pay-cross-chain-htlc",
    "pay-cross-chain-liquidity-tank", "pay-ap2", "pay-x402",
})
ATOMIC_INPUT_MEMBERS = frozenset({
    "jobId", "rail", "agreement", "payer", "payee", "amount",
    "atomicSessionContext",
})
ORDINARY_INPUT_MEMBERS = ATOMIC_INPUT_MEMBERS - {"atomicSessionContext"} | {"sessionContext"}
_ATOMIC_CONTEXT_MEMBERS = frozenset({
    "contextVersion", "jobId", "listingRef", "recipeRegistryVersion",
    "railRegistryVersion", "parties", "priorPhaseOutputsHash", "startedAt",
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
    work_profile: str | None = None
    capability_gated: bool = False

    @property
    def atomic(self) -> bool:
        return (self.phase == "pay-dem" and self.capability_gated
                and self.work_profile == "dacs-purchase-v1")


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


def _atomic_session_context_valid(shape, value) -> bool:
    return (isinstance(value, dict) and set(value) == _ATOMIC_CONTEXT_MEMBERS
            and value["contextVersion"] == "1"
            and shape._nonempty_jcs_string(value["jobId"])
            and _listing_ref_valid(shape, value["listingRef"], closed=True)
            and shape._safe_nonnegative_integer(value["recipeRegistryVersion"])
            and shape._safe_nonnegative_integer(value["railRegistryVersion"])
            and isinstance(value["parties"], list)
            and [party.get("role") if isinstance(party, dict) else None
                 for party in value["parties"]] == ["buyer", "seller", "orchestrator"]
            and all(set(party) == {"role", "primaryClaim"}
                    and shape._claim_reference_shape_valid(party["primaryClaim"])
                    for party in value["parties"])
            and shape._sha256_hex(value["priorPhaseOutputsHash"])
            and shape._safe_nonnegative_integer(value["startedAt"]))


def check_payment_input(binding: PhaseBinding, phase_input: Any) -> None:
    # Select the arm before accessing even a single input member.
    atomic = binding.atomic
    if binding.phase not in PAYMENT_PHASES:
        raise InputArmError("binding is not a payment phase")
    if not isinstance(phase_input, dict):
        raise InputArmError("payment input is not an object")
    if atomic:
        if set(phase_input) != ATOMIC_INPUT_MEMBERS:
            raise InputArmError("Atomic payment input is not its closed arm")
    elif "sessionContext" not in phase_input or "atomicSessionContext" in phase_input:
        raise InputArmError("ordinary payment input requires only its session arm")
    shape = _shapes()
    # Ordinary members stay open under CORE SIG-5; the Atomic arm is closed.
    closed = atomic
    if not (ORDINARY_INPUT_MEMBERS - {"sessionContext"}) <= set(phase_input):
        raise InputArmError("payment input lacks a required member")
    if not (shape._nonempty_jcs_string(phase_input["jobId"])
            and _agreement_valid(shape, phase_input["agreement"])
            and _rail_valid(shape, phase_input["rail"])
            and _party_valid(shape, phase_input["payer"], "payingKey", closed=closed)
            and _party_valid(shape, phase_input["payee"], "payeeAddress", closed=closed)
            and shape._price_term_shape_valid(phase_input["amount"])):
        raise InputArmError("payment input member is not its declared type")
    if atomic:
        if not _atomic_session_context_valid(shape, phase_input["atomicSessionContext"]):
            raise InputArmError("atomicSessionContext is not AtomicPaymentSessionContextV1")
    elif not _session_context_valid(shape, phase_input["sessionContext"]):
        raise InputArmError("sessionContext is not SessionContext")
    elif ("identityBindingCompanions" in phase_input
          and not isinstance(phase_input["identityBindingCompanions"], list)):
        raise InputArmError("identityBindingCompanions is not an array")


def dispatch_payment(binding: PhaseBinding, phase_input: Any, handler: Callable) -> dict:
    """Run the input-arm gate before the enclosing handler can call a rail."""
    try:
        check_payment_input(binding, phase_input)
    except InputArmError as exc:
        return {"status": "rejected", "ok": False, "errorClass": "permanent",
                "reason": str(exc)}
    return handler(phase_input)


def _target_arms(ref, shape) -> dict:
    """AMEND-1 selector -> (signature domain, complete arm shape check).

    The three DACS-4 v0.x shapes are closed; Atomic uses its open schema.
    """
    def atomic_shape(target):
        ref.validate_schema(target, "atomic-settlement-evidence-v1.schema.json")
        return True
    return {
        "evidenceVersion": (b"dacs-evidence:v1:", shape._settlement_evidence_shape_valid),
        "legacyTransitionEvidenceVersion": (
            b"dacs-legacy-transition-evidence:v1:",
            shape._legacy_transition_settlement_evidence_shape_valid),
        "finalityBoundEvidenceVersion": (
            b"dacs-finality-bound-evidence:v1:",
            shape._finality_bound_settlement_evidence_shape_valid),
        "atomicEvidenceVersion": (ref.EVIDENCE_DOMAIN, atomic_shape),
    }


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
    import atomic_work_reference as ref
    shape = _shapes()

    try:
        ref.verify_embedded(amendment, public_keys, ref._AMENDMENT_DOMAIN)
        target_ref = amendment.get("amendsEvidenceRef")
        if not ref._valid_attestation_ref(target_ref):
            raise ref.Invalid("amendment target reference malformed")
        try:
            resolved = resolve(target_ref)
        except OSError as exc:
            raise ref.Unknown("amendment target unavailable") from exc
        if not isinstance(resolved, dict):
            raise ref.Unknown("amendment target unavailable")
        target = resolved.get("artifact")
        anchor = resolved.get("anchorReceipt")
        if (not isinstance(target, dict) or not isinstance(anchor, dict)
                or anchor.get("state") != "finalized"
                or anchor.get("observationDisposition") != "established"):
            raise ref.Unknown("amendment target not anchored and finalized")
        # CORE SR2-4/SR2-12: receipt fields are assertions until its proof binds
        # them, so authenticate the receipt's own tuple first. A forged or
        # mismatched receipt is discarded, leaving the target pending.
        try:
            ref._verify_anchor_receipt(
                anchor, logical=target_ref["anchor"]["locator"],
                content_hash=anchor.get("contentHash"),
                public_keys=public_keys, network_authority=network_authority,
                network_id=network_id, proof_profile=proof_profile,
                validator_set_id=validator_set_id,
            )
        except (ref.Invalid, ref.Malformed, ValueError, TypeError, KeyError) as exc:
            raise ref.Unknown(f"amendment target anchor is not authentic: {exc}") from exc
        # PC-2's payment address is single-write, so an authentic anchor binding
        # another hash means the reference names other content.
        if anchor["contentHash"] != target_ref["contentHash"]:
            raise ref.Invalid("authentic amendment target anchor binds another content hash")
        # CORE B.2 / DACS-4 9.7: content hashes omit only signature. No target
        # discriminator, job or phase is read before this recomputation. Bytes
        # differing from the anchored hash are a substituted resolution.
        digest = ref.sha256_hex(ref.jcs_bytes({
            key: value for key, value in target.items() if key != "signature"
        }))
        if digest != target_ref["contentHash"]:
            raise ref.Unknown("amendment target content differs from its finalized anchor")
        arms = _target_arms(ref, shape)
        selectors = [key for key in ref.EVIDENCE_SELECTORS if key in target]
        if len(selectors) != 1 or selectors[0] not in arms:
            raise ref.Invalid("amendment target discriminator unsupported or ambiguous")
        selector = selectors[0]
        if target[selector] != "1":
            raise ref.Invalid("amendment target version unsupported")
        domain, arm_shape_valid = arms[selector]
        if not isinstance(target.get("signature"), dict):
            raise ref.Invalid("amendment target signature missing")
        # Every evidence arm is signed by the session's phase orchestrator.
        ref.require_signer(target, orchestrator)
        ref.verify_embedded(target, public_keys, domain)
        if not ref._is_pure_json(target):
            raise ref.Invalid("amendment target is not NFC-normalized safe-integer JSON")
        if not arm_shape_valid(target):
            raise ref.Invalid(f"amendment target is not its {selector} arm")
        if "signer" in target_ref:
            ref.require_signer(target, target_ref["signer"])
        if target.get("jobId") != amendment.get("jobId"):
            raise ref.Invalid("amendment target job mismatch")
        if target.get("phase") not in PAYMENT_PHASES:
            raise ref.Invalid("amendment target is not a payment phase")
        # Every arm's {evidenceHash} is its signature-omitting content hash
        # (atomic_evidence_hash for an Atomic target).
        address = (_AMENDMENT_ADDRESS.fullmatch(amendment_address)
                   if isinstance(amendment_address, str) else None)
        if (address is None or address.group(1) != amendment.get("jobId")
                or address.group(2) != digest):
            raise ref.Invalid("amendment address does not bind the target evidence hash")
        return "valid", "AMEND-1 target verified"
    except ref.Unknown as exc:
        return "indeterminate", str(exc)
    except (ref.Invalid, ref.Malformed, ValueError, TypeError, KeyError) as exc:
        return "violation", str(exc)
