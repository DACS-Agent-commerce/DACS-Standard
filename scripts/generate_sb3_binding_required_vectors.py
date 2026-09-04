#!/usr/bin/env python3
"""Generate DACS-4 v0.8 SB-3 binding-required disposition vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance/vectors/security/sb3-binding-required-v0.8.json"
_USE_STATE = object()


def rail(binding: str = "required") -> dict[str, str]:
    profile = (
        "x402-eip3009-binding-v0.8"
        if binding == "required"
        else "evm-erc20-unbound-v0.8"
    )
    return {
        "authority": "authenticated-agreement-pinned-rail",
        "resolvedRailProfile": profile,
    }


def want(
    expected: str,
    disposition: str,
    reason: str,
    *,
    unbound_posture: bool = False,
) -> dict[str, Any]:
    return {
        "bindingDisposition": disposition,
        "reason": reason,
        "usedUnboundPosture": unbound_posture,
        "countable": expected == "pass",
        "finalVerificationSatisfied": expected == "pass",
        "reputationEligible": expected == "pass",
        "partyFaultCreatedByThisGate": False,
    }


def case(
    name: str,
    state: str,
    expected: str,
    disposition: str,
    reason: str,
    note: str,
    *,
    authenticated_rail: dict[str, str] | None = None,
    transfer: str = "match",
    caller_hint: str | None = None,
    unbound_posture: bool = False,
    binding_evidence: Any = _USE_STATE,
    omit_binding_evidence: bool = False,
) -> dict[str, Any]:
    protocol_input: dict[str, Any] = {"unboundTransferChecks": transfer}
    if not omit_binding_evidence:
        protocol_input["bindingEvidence"] = (
            {"state": state}
            if binding_evidence is _USE_STATE
            else binding_evidence
        )
    if caller_hint is not None:
        protocol_input["callerProfileHint"] = caller_hint
    vector: dict[str, Any] = {
        "name": name,
        "operation": "verify-sb3-binding-required",
        "trustedContext": (
            rail() if authenticated_rail is None else authenticated_rail
        ),
        "protocolInput": protocol_input,
        "expected": expected,
        "want": want(
            expected, disposition, reason, unbound_posture=unbound_posture
        ),
        "rule": "DACS-4 §9.5.8 SB-3",
        "note": note,
    }
    return vector


def build_vectors() -> list[dict[str, Any]]:
    return [
        case(
            "required-binding-match-pass",
            "match",
            "pass",
            "satisfied",
            "verified-binding-and-transfer",
            "A verified exact job/phase binding permits the remaining settlement checks.",
        ),
        case(
            "required-binding-mismatch-fail",
            "mismatch",
            "fail",
            "rejected",
            "binding-mismatch",
            "A well-formed verified binding to another job cannot settle this one.",
        ),
        case(
            "required-binding-absent-indeterminate",
            "absent",
            "indeterminate",
            "unresolved",
            "required-binding-absent",
            "Missing required binding is non-countable, not unbound acceptance.",
        ),
        case(
            "required-binding-rpc-unavailable-indeterminate",
            "unavailable-rpc",
            "indeterminate",
            "unresolved",
            "binding-authority-unavailable",
            "An RPC outage cannot become acceptance or party fault.",
        ),
        case(
            "required-binding-pruned-history-indeterminate",
            "unavailable-pruned-history",
            "indeterminate",
            "unresolved",
            "binding-authority-unavailable",
            "Pruned binding history remains non-countable.",
        ),
        case(
            "required-binding-smart-account-check-unavailable",
            "unavailable-signature-authority",
            "indeterminate",
            "unresolved",
            "binding-authority-unavailable",
            "An unavailable ERC-1271 check does not downgrade to transfer-only proof.",
        ),
        case(
            "required-binding-reorged-indeterminate",
            "unavailable-reorged",
            "indeterminate",
            "unresolved",
            "binding-authority-unavailable",
            "A reorganisation that removes binding evidence suspends acceptance.",
        ),
        case(
            "required-binding-malformed-error",
            "malformed",
            "error",
            "malformed",
            "malformed-binding-evidence",
            "Malformed binding evidence is an error before transfer interpretation.",
        ),
        case(
            "required-binding-unknown-state-error",
            "future-state",
            "error",
            "malformed",
            "malformed-binding-evidence",
            "An unsupported state is malformed, not unavailable authority.",
        ),
        case(
            "required-binding-missing-evidence-error",
            "unused",
            "error",
            "malformed",
            "malformed-binding-evidence",
            "A missing binding-evidence member is a deterministic error.",
            omit_binding_evidence=True,
        ),
        case(
            "required-binding-null-evidence-error",
            "unused",
            "error",
            "malformed",
            "malformed-binding-evidence",
            "A non-object binding-evidence value is a deterministic error.",
            binding_evidence=None,
        ),
        case(
            "required-binding-missing-state-error",
            "unused",
            "error",
            "malformed",
            "malformed-binding-evidence",
            "A binding-evidence object without a state is malformed.",
            binding_evidence={},
        ),
        case(
            "required-binding-non-string-state-error",
            "unused",
            "error",
            "malformed",
            "malformed-binding-evidence",
            "A non-string binding-evidence state is malformed.",
            binding_evidence={"state": 7},
        ),
        case(
            "unrelated-exact-transfer-cannot-replace-binding",
            "absent",
            "indeterminate",
            "unresolved",
            "required-binding-absent",
            "Even an exact asset/amount/payer/payee transfer does not prove job authorization.",
            transfer="match",
        ),
        case(
            "caller-unbound-downgrade-ignored",
            "absent",
            "indeterminate",
            "unresolved",
            "required-binding-absent",
            "Caller policy cannot override the authenticated required-binding rail.",
            caller_hint="binding-none",
        ),
        case(
            "unproven-legacy-downgrade-ignored",
            "absent",
            "indeterminate",
            "unresolved",
            "required-binding-absent",
            "A legacy label without an authenticated compatibility profile grants no fallback.",
            caller_hint="legacy-pre-v0.8",
        ),
        case(
            "binding-match-but-transfer-mismatch-fail",
            "match",
            "fail",
            "satisfied",
            "unbound-transfer-mismatch",
            "SB-3 satisfaction does not bypass SB-1/amount/payee verification.",
            transfer="mismatch",
        ),
        case(
            "binding-match-but-transfer-unavailable-indeterminate",
            "match",
            "indeterminate",
            "satisfied",
            "unbound-transfer-unavailable",
            "Binding success does not turn unavailable ledger checks into pass.",
            transfer="unavailable",
        ),
        case(
            "authenticated-unbound-rail-exact-transfer-pass",
            "absent",
            "pass",
            "not-required",
            "verified-unbound-transfer",
            "A rail that authentically declares no binding retains the weaker posture.",
            authenticated_rail=rail("none"),
            unbound_posture=True,
        ),
        case(
            "authenticated-unbound-rail-transfer-mismatch-fail",
            "absent",
            "fail",
            "not-required",
            "unbound-transfer-mismatch",
            "The weaker posture still requires exact transfer checks.",
            authenticated_rail=rail("none"),
            transfer="mismatch",
            unbound_posture=True,
        ),
        case(
            "authenticated-unbound-rail-ledger-unavailable",
            "absent",
            "indeterminate",
            "not-required",
            "unbound-transfer-unavailable",
            "An unbound rail also remains indeterminate when its ledger evidence is unavailable.",
            authenticated_rail=rail("none"),
            transfer="unavailable",
            unbound_posture=True,
        ),
        case(
            "rail-binding-policy-unavailable-indeterminate",
            "match",
            "indeterminate",
            "policy-unresolved",
            "authenticated-rail-policy-unavailable",
            "A caller cannot select a policy when the signed pinned rail cannot be resolved.",
            authenticated_rail={},
            caller_hint="binding-none",
        ),
    ]


def document() -> dict[str, Any]:
    vectors = build_vectors()
    encoded = json.dumps(
        vectors, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "set": "sb3-binding-required-v0.8",
        "spec": "DACS-4 §9.5.8 SB-3 required-binding four-value gate",
        "tier": "candidate",
        "description": (
            "A rail-declared settlement-side binding cannot downgrade to unbound "
            "transfer evidence when missing, unavailable, pruned, reorged, or malformed."
        ),
        "count": len(vectors),
        "hash": hashlib.sha256(encoded).hexdigest(),
        "vectors": vectors,
    }


def rendered() -> str:
    return json.dumps(document(), ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = rendered()
    if args.write:
        OUTPUT.write_text(expected, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)} ({document()['count']} vectors)")
        return 0
    try:
        actual = OUTPUT.read_text(encoding="utf-8")
    except FileNotFoundError:
        actual = ""
    if actual != expected:
        print("SB-3 binding-required vectors are stale; run with --write")
        return 1
    print(f"SB-3 binding-required vectors OK ({document()['count']} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
