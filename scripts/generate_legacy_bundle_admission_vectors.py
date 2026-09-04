#!/usr/bin/env python3
"""Generate deterministic DACS-5 LAB-1..LAB-7 conformance vectors."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "vectors" / "security"
    / "legacy-bundle-admission-v0.6.json"
)
CHECKPOINT_ORDER = 100
LEGACY_HASH = hashlib.sha256(b"dacs-lab-legacy-bundle").hexdigest()


def checkpoint(**overrides: object) -> dict:
    value = {
        "state": "finalized",
        "unique": True,
        "ordered": True,
        "stewardAuthorized": True,
        "signatureValid": True,
        "addressBound": True,
        "substrate": "demos-mainnet",
        "order": CHECKPOINT_ORDER,
    }
    value.update(overrides)
    return value


def anchor(**overrides: object) -> dict:
    value = {
        "state": "finalized",
        "ordered": True,
        "substrate": "demos-mainnet",
        "role": "buyer",
        "contentHash": LEGACY_HASH,
        "order": CHECKPOINT_ORDER - 1,
    }
    value.update(overrides)
    return value


def case(
    name: str,
    expected: str,
    note: str,
    *,
    bundle_type: str = "legacy",
    resolved_role: str = "buyer",
    checkpoint_value: dict | None = None,
    anchor_value: dict | None = None,
    presentation_order: int = CHECKPOINT_ORDER + 50,
    finalised_at: int = CHECKPOINT_ORDER - 10,
) -> dict:
    disposition = {
        "pass": "eligible",
        "fail": "ineligible",
        "indeterminate": "indeterminate",
    }[expected]
    return {
        "name": name,
        "expected": expected,
        "note": note,
        "input": {
            "bundle": {
                "type": bundle_type,
                "contentHash": LEGACY_HASH,
                "anchoredByRole": resolved_role,
                "finalisedAt": finalised_at,
            },
            "resolvedRole": resolved_role,
            "presentedAtOrder": presentation_order,
            "checkpoint": checkpoint_value,
            "historicalAnchor": anchor_value,
        },
        "want": {
            "admissionDisposition": disposition,
            "reputationEffect": "include" if expected == "pass" else "exclude",
            "auditInspectable": True,
            "authoritativeAbsence": False,
            "partyFaultCreatedByGate": False,
        },
    }


def vectors() -> list[dict]:
    return [
        case(
            "lab-modern-fab-checkpoint-unavailable",
            "pass",
            "LAB applies only to legacy AttestationBundle; a valid FAB does not need era proof",
            bundle_type="fault",
            checkpoint_value={"state": "unavailable"},
            anchor_value=None,
        ),
        case(
            "lab-modern-ebfab-no-era-proof",
            "pass",
            "EBFAB admission follows its normal type/SEB gates, not legacy-era proof",
            bundle_type="evidence-bound-fault",
            checkpoint_value=None,
            anchor_value=None,
        ),
        case(
            "lab-authentic-historical-buyer",
            "pass",
            "exact-hash buyer-role anchor finalized strictly before the governed checkpoint",
            checkpoint_value=checkpoint(),
            anchor_value=anchor(),
        ),
        case(
            "lab-authentic-historical-seller",
            "pass",
            "each role qualifies independently; exact seller-role history is eligible",
            resolved_role="seller",
            checkpoint_value=checkpoint(),
            anchor_value=anchor(role="seller"),
        ),
        case(
            "lab-historical-replay-after-checkpoint",
            "pass",
            "later presentation does not erase the original qualifying pre-checkpoint anchor",
            checkpoint_value=checkpoint(),
            anchor_value=anchor(),
            presentation_order=250,
        ),
        case(
            "lab-same-role-reanchor-keeps-original-proof",
            "pass",
            "a same-role re-anchor after activation remains eligible only through its original receipt",
            checkpoint_value=checkpoint(),
            anchor_value=anchor(),
            presentation_order=180,
        ),
        case(
            "lab-cross-role-rebind-rejected",
            "fail",
            "buyer-role history cannot qualify the same bytes resolved under seller role",
            resolved_role="seller",
            checkpoint_value=checkpoint(),
            anchor_value=anchor(role="buyer"),
        ),
        case(
            "lab-fresh-legacy-post-checkpoint",
            "fail",
            "a first legacy anchor after activation is audit-only and non-countable",
            checkpoint_value=checkpoint(),
            anchor_value=anchor(order=101),
        ),
        case(
            "lab-same-order-not-strictly-before",
            "fail",
            "checkpoint equality does not satisfy the strict-before relation",
            checkpoint_value=checkpoint(),
            anchor_value=anchor(order=100),
        ),
        case(
            "lab-backdated-fresh-legacy",
            "fail",
            "producer finalisedAt cannot backdate a post-checkpoint anchor",
            checkpoint_value=checkpoint(),
            anchor_value=anchor(order=130),
            finalised_at=1,
        ),
        case(
            "lab-content-hash-mismatch",
            "fail",
            "historical proof for different bytes does not qualify the returned bundle",
            checkpoint_value=checkpoint(),
            anchor_value=anchor(contentHash="0" * 64),
        ),
        case(
            "lab-anchor-substrate-mismatch",
            "fail",
            "history on another substrate cannot satisfy this checkpoint/anchor relation",
            checkpoint_value=checkpoint(),
            anchor_value=anchor(substrate="other-mainnet"),
        ),
        case(
            "lab-checkpoint-signature-invalid",
            "fail",
            "an invalid steward signature is deterministic invalidity, not activation authority",
            checkpoint_value=checkpoint(signatureValid=False),
            anchor_value=anchor(),
        ),
        case(
            "lab-checkpoint-signer-unauthorized",
            "fail",
            "a valid signature by a non-steward signer cannot activate the legacy boundary",
            checkpoint_value=checkpoint(stewardAuthorized=False),
            anchor_value=anchor(),
        ),
        case(
            "lab-checkpoint-address-mismatch",
            "fail",
            "a checkpoint not bound to the derived substrate address is invalid",
            checkpoint_value=checkpoint(addressBound=False),
            anchor_value=anchor(),
        ),
        case(
            "lab-checkpoint-unavailable",
            "indeterminate",
            "unavailable governed checkpoint proof cannot admit or fault a legacy copy",
            checkpoint_value={"state": "unavailable"},
            anchor_value=anchor(),
        ),
        case(
            "lab-checkpoint-conflicting",
            "indeterminate",
            "multiple conflicting authorized checkpoint candidates fail closed",
            checkpoint_value=checkpoint(unique=False),
            anchor_value=anchor(),
        ),
        case(
            "lab-checkpoint-reorged",
            "indeterminate",
            "an unresolved checkpoint reorganization has no stable activation position",
            checkpoint_value=checkpoint(state="reorged"),
            anchor_value=anchor(),
        ),
        case(
            "lab-checkpoint-order-unavailable",
            "indeterminate",
            "a finalized checkpoint without authenticated total order cannot activate LAB",
            checkpoint_value=checkpoint(ordered=False),
            anchor_value=anchor(),
        ),
        case(
            "lab-anchor-history-missing",
            "indeterminate",
            "missing earliest/exact historical receipt cannot establish creation era",
            checkpoint_value=checkpoint(),
            anchor_value=None,
        ),
        case(
            "lab-anchor-history-pruned",
            "indeterminate",
            "pruned role-anchor history is not converted into ineligibility or fault",
            checkpoint_value=checkpoint(),
            anchor_value={"state": "pruned"},
        ),
        case(
            "lab-anchor-history-reorged",
            "indeterminate",
            "reorged historical anchor evidence fails closed pending stable proof",
            checkpoint_value=checkpoint(),
            anchor_value=anchor(state="reorged"),
        ),
        case(
            "lab-anchor-order-unavailable",
            "indeterminate",
            "same-block evidence without authenticated strict ordering cannot qualify",
            checkpoint_value=checkpoint(),
            anchor_value=anchor(ordered=False, order=100),
        ),
    ]


def document() -> dict:
    values = vectors()
    encoded = json.dumps(
        values, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return {
        "set": OUTPUT.stem,
        "spec": "DACS-5 v0.6 §10.4.1/§10.5.1 LAB-1..LAB-7",
        "tier": "candidate",
        "description": (
            "Legacy AttestationBundle authenticated-era admission, role binding, "
            "and fail-closed reputation effects."
        ),
        "provenance": {
            "issue": "DACS-Agent-commerce/DACS-Standard#381",
            "generator": "scripts/generate_legacy_bundle_admission_vectors.py",
        },
        "count": len(values),
        "hash": hashlib.sha256(encoded).hexdigest(),
        "vectors": values,
    }


def render() -> bytes:
    return (json.dumps(document(), indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.write:
        OUTPUT.write_bytes(expected)
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    if not OUTPUT.exists() or OUTPUT.read_bytes() != expected:
        print(f"ERROR: {OUTPUT.relative_to(ROOT)} is not deterministic/in sync")
        return 1
    print(f"verified {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
