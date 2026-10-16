"""Non-normative PC-1 dispatch and AMEND-1 target consumer.

Bindings and resolver/network pins are verifier-owned arguments, never selected
from phase input or target members. Finality uses the existing synthetic proof
profile; this module makes no live rail calls and implements no refund ledger.
A `valid` result admits the target under AMEND-1 only. AMEND-2/3 and amendment
writer authorization remain the enclosing consumer's responsibility.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


PAYMENT_PHASES = frozenset({
    "pay-dem", "pay-evm-erc20", "pay-solana-spl", "pay-cross-chain-htlc",
    "pay-cross-chain-liquidity-tank", "pay-ap2", "pay-x402",
})


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


def check_payment_input(binding: PhaseBinding, phase_input: Any) -> None:
    # Select the arm before accessing even a single input member.
    atomic = binding.atomic
    if binding.phase not in PAYMENT_PHASES:
        raise InputArmError("binding is not a payment phase")
    if not isinstance(phase_input, dict):
        raise InputArmError("payment input is not an object")
    if atomic:
        if set(phase_input) != {
            "jobId", "rail", "agreement", "payer", "payee", "amount",
            "atomicSessionContext",
        }:
            raise InputArmError("Atomic payment input is not its closed arm")
    elif "sessionContext" not in phase_input or "atomicSessionContext" in phase_input:
        raise InputArmError("ordinary payment input requires only its session arm")


def dispatch_payment(binding: PhaseBinding, phase_input: Any, handler: Callable) -> dict:
    """Run the input-arm gate before the enclosing handler can call a rail."""
    try:
        check_payment_input(binding, phase_input)
    except InputArmError as exc:
        return {"status": "rejected", "ok": False, "errorClass": "permanent",
                "reason": str(exc)}
    return handler(phase_input)


def consume_amendment_target(
    amendment: dict, resolve: Callable[[dict], dict | None], *,
    public_keys: dict, network_authority: str, network_id: str,
    proof_profile: str, validator_set_id: str,
) -> tuple[str, str]:
    """Resolve, hash, establish finality, then select/verify the AMEND-1 arm.

    The resolver returns {artifact, anchorReceipt}; absent/unfinalized receipts
    leave the target pending. Contradictory established proofs are violations.
    No AMEND-4 reject-versus-flag policy is selected here.
    """
    import atomic_work_reference as ref

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
        # CORE B.2 / DACS-4 9.7: content hashes omit only signature. No target
        # discriminator, job or phase is read before this recomputation.
        digest = ref.sha256_hex(ref.jcs_bytes({
            key: value for key, value in target.items() if key != "signature"
        }))
        if digest != target_ref["contentHash"]:
            raise ref.Invalid("amendment target content hash mismatch")
        ref._verify_anchor_receipt(
            anchor, logical=target_ref["anchor"]["locator"], content_hash=digest,
            public_keys=public_keys, network_authority=network_authority,
            network_id=network_id, proof_profile=proof_profile,
            validator_set_id=validator_set_id,
        )
        selectors = [key for key in ref.EVIDENCE_SELECTORS if key in target]
        if len(selectors) != 1 or selectors[0] not in {
            "evidenceVersion", "atomicEvidenceVersion",
        }:
            raise ref.Invalid("amendment target discriminator unsupported or ambiguous")
        selector = selectors[0]
        if target[selector] != "1":
            raise ref.Invalid("amendment target version unsupported")
        domain = (b"dacs-evidence:v1:" if selector == "evidenceVersion"
                  else ref.EVIDENCE_DOMAIN)
        if not isinstance(target.get("signature"), dict):
            raise ref.Invalid("amendment target signature missing")
        ref.verify_embedded(target, public_keys, domain)
        if not ref._is_pure_json(target):
            raise ref.Invalid("amendment target is not NFC-normalized safe-integer JSON")
        if selector == "atomicEvidenceVersion":
            ref.validate_schema(target, "atomic-settlement-evidence-v1.schema.json")
        elif (not {"evidenceVersion", "jobId", "phase", "outcome", "observedAt", "signature"} <= set(target)
              or target.get("outcome") not in {"success", "failure"}
              or type(target.get("observedAt")) is not int
              or not 0 <= target["observedAt"] <= ref.SAFE_INT_MAX):
            raise ref.Invalid("amendment target is not SettlementEvidence v1")
        if "signer" in target_ref:
            ref.require_signer(target, target_ref["signer"])
        if target.get("jobId") != amendment.get("jobId"):
            raise ref.Invalid("amendment target job mismatch")
        if target.get("phase") not in PAYMENT_PHASES:
            raise ref.Invalid("amendment target is not a payment phase")
        return "valid", "AMEND-1 target verified"
    except ref.Unknown as exc:
        return "indeterminate", str(exc)
    except (ref.Invalid, ref.Malformed, ValueError, TypeError, KeyError) as exc:
        return "violation", str(exc)
