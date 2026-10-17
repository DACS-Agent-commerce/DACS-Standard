"""Non-normative PC-1 dispatch and AMEND-1 target consumer.

Bindings, the session orchestrator, the amendment's anchored address and
resolver/network pins are verifier-owned arguments, never selected from phase
input or target members. Finality uses the existing synthetic proof profile;
this module makes no live rail calls and implements no refund ledger. A `valid`
result admits the target under AMEND-1 only. AMEND-2/3, amendment writer
authorization, and a transition or finality-bound target's §9.7 reservation or
FV-1..FV-10 authority remain the enclosing consumer's responsibility.
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
                    and shape._nonempty_jcs_string(party.get("role"))
                    and shape._claim_reference_shape_valid(party.get("primaryClaim"))
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
            and isinstance(phase_input["agreement"], dict)
            and isinstance(phase_input["rail"], dict)
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
    """AMEND-1 selector -> (signature domain, complete closed-arm shape check)."""
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

    The resolver returns {artifact, anchorReceipt}; absent/unfinalized receipts,
    or bytes that differ from an authentic anchor binding the reference's hash,
    leave the target pending. Contradictory established proofs are violations.
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
        # The authentic anchor must bind the reference's own hash; one binding
        # another hash means the reference names other content.
        ref._verify_anchor_receipt(
            anchor, logical=target_ref["anchor"]["locator"],
            content_hash=target_ref["contentHash"],
            public_keys=public_keys, network_authority=network_authority,
            network_id=network_id, proof_profile=proof_profile,
            validator_set_id=validator_set_id,
        )
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
