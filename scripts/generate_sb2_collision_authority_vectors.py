#!/usr/bin/env python3
"""Generate DACS-4 v0.8 SB-2 collision-authority vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance/vectors/security/sb2-collision-authority-v0.8.json"

TX = "evm:1:" + "ab" * 32 + ":7"
TX_OTHER_EVENT = "evm:1:" + "ab" * 32 + ":8"
TX_SECOND_GROUP = "evm:1:" + "cd" * 32 + ":9"
JOB_A = "01KTY8ZJ00CW7KSECW3FS6PQPK"
JOB_B = "01KTY8ZJ01CW7KSECW3FS6PQPK"
JOB_C = "01KTY8ZJ02CW7KSECW3FS6PQPK"
HASH_A = "11" * 32
HASH_B = "22" * 32
HASH_C = "33" * 32
HASH_D = "44" * 32
HASH_E = "55" * 32

RAIL_X402 = "base-usdc-x402"
RAIL_AP2 = "usd-ap2"
PROFILE_EIP3009 = "pay-x402/eip-3009:dacs-sb3-v1"
PROFILE_PERMIT2 = "pay-x402/permit2:witness-job-v1"
PROFILE_AP2 = "pay-ap2/provider-metadata:dacs-job-id-v1"


def record(
    content_hash: str,
    job_id: str,
    phase_index: int,
    *,
    observed_at: int,
    anchor_order: int,
    tx_id: str = TX,
) -> dict[str, Any]:
    return {
        "contentHash": content_hash,
        "jobId": job_id,
        "phaseIndex": phase_index,
        "settlementTxId": tx_id,
        "observedAt": observed_at,
        "sr2AnchorOrder": anchor_order,
    }


A = record(HASH_A, JOB_A, 1, observed_at=2_000, anchor_order=2)
B = record(HASH_B, JOB_B, 1, observed_at=1_000, anchor_order=1)
C_PHASE = record(HASH_C, JOB_A, 2, observed_at=500, anchor_order=1)
C_EVENT = record(
    HASH_C,
    JOB_C,
    1,
    observed_at=500,
    anchor_order=1,
    tx_id=TX_OTHER_EVENT,
)
D = record(
    HASH_D,
    JOB_A,
    1,
    observed_at=700,
    anchor_order=2,
    tx_id=TX_SECOND_GROUP,
)
E = record(
    HASH_E,
    JOB_B,
    1,
    observed_at=600,
    anchor_order=1,
    tx_id=TX_SECOND_GROUP,
)


def authority(
    state: str,
    *,
    settlement_tx_id: str | None = TX,
    rail_id: str | None = RAIL_X402,
    rail_profile: str | None = PROFILE_EIP3009,
    job_id: str | None = None,
    phase_index: int | None = None,
    source: str = "independently-verified-settlement",
) -> dict[str, Any]:
    result: dict[str, Any] = {"source": source, "state": state}
    if settlement_tx_id is not None:
        result["settlementTxId"] = settlement_tx_id
    if rail_id is not None:
        result["railId"] = rail_id
    if rail_profile is not None:
        result["railProfile"] = rail_profile
    if job_id is not None:
        result["jobId"] = job_id
    if phase_index is not None:
        result["phaseIndex"] = phase_index
    return result


def verified_rail_contexts(
    records: list[dict[str, Any]],
    *,
    rail_id: str = RAIL_X402,
    rail_profile: str = PROFILE_EIP3009,
) -> list[dict[str, Any]]:
    """Build trusted rail pins independently of claimant-controlled records."""
    contexts: dict[str, dict[str, Any]] = {}
    for item in records:
        contexts[item["contentHash"]] = {
            "contentHash": item["contentHash"],
            "settlementTxId": item["settlementTxId"],
            "railId": rail_id,
            "railProfile": rail_profile,
        }
    return [contexts[key] for key in sorted(contexts)]


def case(
    name: str,
    records: list[dict[str, Any]],
    trusted_authorities: list[dict[str, Any]],
    expected: str,
    counted: list[str],
    rejected: list[str],
    indeterminate: list[str],
    reason: str,
    note: str,
    *,
    protocol_hints: dict[str, Any] | None = None,
    selected_by: str | None = None,
    rail_id: str = RAIL_X402,
    rail_profile: str = PROFILE_EIP3009,
    rail_contexts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "operation": "resolve-sb2-collision-group",
        "trustedContext": {
            "verifiedRailContexts": (
                rail_contexts
                if rail_contexts is not None
                else verified_rail_contexts(
                    records, rail_id=rail_id, rail_profile=rail_profile
                )
            ),
            "settlementAuthorities": trusted_authorities,
        },
        "protocolInput": {
            "records": records,
            "hints": protocol_hints or {},
        },
        "expected": expected,
        "want": {
            "countedEvidenceHashes": sorted(counted),
            "rejectedEvidenceHashes": sorted(rejected),
            "indeterminateEvidenceHashes": sorted(indeterminate),
            "reason": reason,
            "selectedBy": selected_by,
            "partyFaultCreatedByThisGate": False,
        },
        "rule": "DACS-4 §9.5.8 SB-2",
        "note": note,
    }


def build_vectors() -> list[dict[str, Any]]:
    finalized_a = [authority("finalized", job_id=JOB_A, phase_index=1)]
    unresolved = [authority("unavailable")]
    return [
        case(
            "single-record-no-collision-counts",
            [A],
            [],
            "pass",
            [HASH_A],
            [],
            [],
            "no-collision",
            "SB-2 does not require settlement-side authority until a collision appears.",
            selected_by="no-collision",
        ),
        case(
            "idempotent-identical-record-counts-once",
            [A, A],
            [],
            "pass",
            [HASH_A],
            [],
            [],
            "idempotent-same-tuple",
            "Repeated presentation of the same evidence hash is idempotent.",
            selected_by="no-collision",
        ),
        case(
            "cross-job-finalized-binding-selects-a",
            [A, B],
            finalized_a,
            "pass",
            [HASH_A],
            [HASH_B],
            [],
            "authenticated-settlement-binding",
            "The settlement's finalized job binding selects A and rejects B.",
            selected_by="settlement-authority",
        ),
        case(
            "backdated-attacker-does-not-win",
            [A, B],
            finalized_a,
            "pass",
            [HASH_A],
            [HASH_B],
            [],
            "authenticated-settlement-binding",
            "B has earlier observedAt but cannot override the binding to A.",
            selected_by="settlement-authority",
        ),
        case(
            "equal-producer-timestamps-do-not-tie-break",
            [A, {**B, "observedAt": A["observedAt"]}],
            finalized_a,
            "pass",
            [HASH_A],
            [HASH_B],
            [],
            "authenticated-settlement-binding",
            "Equal timestamps and hash order are irrelevant when authority binds A.",
            selected_by="settlement-authority",
        ),
        case(
            "reverse-arrival-order-same-authority",
            [B, A],
            finalized_a,
            "pass",
            [HASH_A],
            [HASH_B],
            [],
            "authenticated-settlement-binding",
            "Input and arrival order cannot change the selected tuple.",
            selected_by="settlement-authority",
        ),
        case(
            "cross-phase-eip3009-exact-binding-selects-phase-one",
            [A, C_PHASE],
            finalized_a,
            "pass",
            [HASH_A],
            [HASH_C],
            [],
            "authenticated-settlement-binding",
            "The EIP-3009 nonce authenticates both jobId and phaseIndex.",
            selected_by="settlement-authority",
        ),
        case(
            "no-binding-collision-voids-both",
            [A, B],
            [],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_B],
            "collision-without-authority",
            "An unbound rail collision suspends both claims.",
        ),
        case(
            "attacker-anchors-stolen-claim-first",
            [A, B],
            [],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_B],
            "collision-without-authority",
            "B's earlier SR-2 anchor and timestamp do not grant commercial authority.",
            protocol_hints={"firstSr2Claim": HASH_B},
        ),
        case(
            "authority-unavailable-voids-both",
            [A, B],
            unresolved,
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_B],
            "collision-authority-unavailable",
            "Unavailable authority is non-countable, not first-observed wins.",
        ),
        case(
            "authority-not-final-voids-both",
            [A, B],
            [authority("included", job_id=JOB_A, phase_index=1)],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_B],
            "collision-authority-not-final",
            "A non-final binding cannot choose a durable winner.",
        ),
        case(
            "authority-pruned-voids-both",
            [A, B],
            [authority("pruned")],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_B],
            "collision-authority-unavailable",
            "Pruned authority does not fall back to timestamps.",
        ),
        case(
            "authority-reorged-before-finality-voids-both",
            [A, B],
            [authority("reorged")],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_B],
            "collision-authority-not-final",
            "A pre-finality reorganisation suspends the whole collision group.",
        ),
        case(
            "conflicting-finalized-authority-voids-both",
            [A, B],
            [authority("conflicting-finalized")],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_B],
            "collision-authority-conflicting",
            "Conflicting purported finality cannot silently transfer credit.",
        ),
        case(
            "malformed-authority-errors",
            [A, B],
            [authority("malformed")],
            "error",
            [],
            [],
            [],
            "malformed-collision-authority",
            "Malformed authority is an error, not an ordering fallback.",
        ),
        case(
            "binding-to-unpresented-tuple-rejects-both",
            [A, B],
            [authority("finalized", job_id=JOB_C, phase_index=1)],
            "fail",
            [],
            [HASH_A, HASH_B],
            [],
            "binding-matches-no-claim",
            "Neither claim matches the settlement's authenticated tuple.",
            selected_by="settlement-authority",
        ),
        case(
            "later-anchor-hint-cannot-replace-finalized-binding",
            [A, B],
            finalized_a,
            "pass",
            [HASH_A],
            [HASH_B],
            [],
            "authenticated-settlement-binding",
            "A later outer anchor claiming B cannot replace finalized binding to A.",
            protocol_hints={"replacementAnchorClaims": {"jobId": JOB_B, "phaseIndex": 1}},
            selected_by="settlement-authority",
        ),
        case(
            "unsupported-atomic-first-claim-hint-is-inert",
            [A, B],
            [],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_B],
            "collision-without-authority",
            "No atomic first-claim mechanism is registered in this revision.",
            protocol_hints={"atomicFirstClaim": HASH_B},
        ),
        case(
            "two-groups-one-authority-does-not-substitute",
            [A, B, D, E],
            finalized_a,
            "indeterminate",
            [HASH_A],
            [HASH_B],
            [HASH_D, HASH_E],
            "collision-authority-settlement-mismatch",
            "Authority for the first canonical settlement cannot select the same tuple in the second group.",
        ),
        case(
            "two-groups-each-exact-authority-selects-independently",
            [A, B, D, E],
            [
                *finalized_a,
                authority(
                    "finalized",
                    settlement_tx_id=TX_SECOND_GROUP,
                    job_id=JOB_B,
                    phase_index=1,
                ),
            ],
            "pass",
            [HASH_A, HASH_E],
            [HASH_B, HASH_D],
            [],
            "authenticated-settlement-binding",
            "Each collision group is selected only by its own exact settlement relation.",
            selected_by="settlement-authority",
        ),
        case(
            "authority-missing-settlement-id-does-not-select",
            [A, B],
            [
                authority(
                    "finalized",
                    settlement_tx_id=None,
                    job_id=JOB_A,
                    phase_index=1,
                )
            ],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_B],
            "collision-authority-settlement-mismatch",
            "A relation without the canonical settlement identifier proves no authority for this group.",
        ),
        case(
            "authority-mismatched-settlement-id-does-not-select",
            [A, B],
            [
                authority(
                    "finalized",
                    settlement_tx_id=TX_SECOND_GROUP,
                    job_id=JOB_A,
                    phase_index=1,
                )
            ],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_B],
            "collision-authority-settlement-mismatch",
            "Authority authenticated for another settlement cannot be substituted into this group.",
        ),
        case(
            "authority-missing-rail-profile-does-not-select",
            [A, B],
            [
                authority(
                    "finalized",
                    rail_profile=None,
                    job_id=JOB_A,
                    phase_index=1,
                )
            ],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_B],
            "collision-authority-profile-mismatch",
            "A relation without the authenticated pinned profile proves no authority for this group.",
        ),
        case(
            "authority-mismatched-rail-id-does-not-select",
            [A, B],
            [
                authority(
                    "finalized",
                    rail_id="wrong-x402-rail",
                    job_id=JOB_A,
                    phase_index=1,
                )
            ],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_B],
            "collision-authority-profile-mismatch",
            "Authority under another pinned rail cannot select this group's record.",
        ),
        case(
            "authority-mismatched-profile-does-not-select",
            [A, B],
            [
                authority(
                    "finalized",
                    rail_profile=PROFILE_PERMIT2,
                    job_id=JOB_A,
                )
            ],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_B],
            "collision-authority-profile-mismatch",
            "A Permit2 proof cannot substitute for the pinned EIP-3009 profile.",
        ),
        case(
            "eip3009-missing-phase-proof-is-indeterminate",
            [A, C_PHASE],
            [authority("finalized", job_id=JOB_A)],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_C],
            "collision-authority-phase-unproven",
            "An incomplete EIP-3009 relation cannot select a phase.",
        ),
        case(
            "permit2-job-only-cross-phase-is-indeterminate",
            [A, C_PHASE],
            [
                authority(
                    "finalized",
                    rail_profile=PROFILE_PERMIT2,
                    job_id=JOB_A,
                )
            ],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_C],
            "collision-authority-phase-unproven",
            "The existing Permit2 witness authenticates jobId but not phaseIndex.",
            rail_profile=PROFILE_PERMIT2,
        ),
        case(
            "ap2-job-only-cross-phase-is-indeterminate",
            [A, C_PHASE],
            [
                authority(
                    "finalized",
                    rail_id=RAIL_AP2,
                    rail_profile=PROFILE_AP2,
                    job_id=JOB_A,
                )
            ],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_C],
            "collision-authority-phase-unproven",
            "The existing AP2 provider metadata authenticates jobId but not phaseIndex.",
            rail_id=RAIL_AP2,
            rail_profile=PROFILE_AP2,
        ),
        case(
            "permit2-caller-phase-claim-adds-no-authority",
            [A, C_PHASE],
            [
                authority(
                    "finalized",
                    rail_profile=PROFILE_PERMIT2,
                    job_id=JOB_A,
                    phase_index=1,
                )
            ],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_C],
            "collision-authority-phase-unproven",
            "A phase field cannot add an authentication dimension that Permit2 does not sign.",
            rail_profile=PROFILE_PERMIT2,
        ),
        case(
            "unproven-authority-source-does-not-select",
            [A, B],
            [
                authority(
                    "finalized",
                    job_id=JOB_A,
                    phase_index=1,
                    source="producer-report",
                )
            ],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_B],
            "collision-authority-unproven",
            "A producer report is not independently authenticated settlement authority.",
        ),
        case(
            "protocol-input-authority-claim-is-inert",
            [A, B],
            [],
            "indeterminate",
            [],
            [],
            [HASH_A, HASH_B],
            "collision-without-authority",
            "Claimant-controlled protocol input cannot manufacture trusted authority.",
            protocol_hints={
                "settlementAuthority": authority(
                    "finalized", job_id=JOB_A, phase_index=1
                )
            },
        ),
        case(
            "distinct-event-identifiers-both-count",
            [A, C_EVENT],
            [],
            "pass",
            [HASH_A, HASH_C],
            [],
            [],
            "no-collision",
            "Different log indices are different canonical settlement identifiers.",
            selected_by="no-collision",
        ),
    ]


def document() -> dict[str, Any]:
    vectors = build_vectors()
    encoded = json.dumps(
        vectors, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "set": "sb2-collision-authority-v0.8",
        "spec": "DACS-4 §9.5.8 SB-2 authenticated collision authority",
        "tier": "candidate",
        "supersedes": ["sb2-settlement-uniqueness-v0.1"],
        "authorityRelation": {
            "scope": "per-canonical-settlement-and-pinned-rail-profile",
            "requiredDimensions": [
                "settlementTxId",
                "railId",
                "railProfile",
                "jobId",
                "phaseIndex",
            ],
            "currentProfileDimensions": {
                PROFILE_EIP3009: ["jobId", "phaseIndex"],
                PROFILE_PERMIT2: ["jobId"],
                PROFILE_AP2: ["jobId"],
            },
        },
        "description": (
            "Each cross-job/phase collision group requires finalized authority bound "
            "to its exact canonical settlement, pinned rail/profile, job, and phase; "
            "without that complete relation every competitor is indeterminate."
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
        print("SB-2 collision-authority vectors are stale; run with --write")
        return 1
    print(f"SB-2 collision-authority vectors OK ({document()['count']} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
