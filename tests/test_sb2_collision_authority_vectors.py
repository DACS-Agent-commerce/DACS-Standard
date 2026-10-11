"""Execute the DACS-4 v0.8 SB-2 collision-authority corpus."""

from __future__ import annotations

from collections import defaultdict
import copy
from decimal import Decimal
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_sb2_collision_authority_vectors as generator  # noqa: E402


VECTORS = ROOT / "conformance/vectors/security/sb2-collision-authority-v0.8.json"
HISTORICAL_VECTORS = (
    ROOT / "conformance/vectors/security/sb2-settlement-uniqueness-v0.1.json"
)

# These capabilities come from DACS-4 SB-3, not from a fixture boolean. The
# EIP-3009 nonce authenticates job+phase; the current Permit2 witness and AP2
# provider metadata authenticate job only.
PROFILE_BINDING_DIMENSIONS = {
    "pay-x402/eip-3009:dacs-sb3-v1": frozenset({"jobId", "phaseIndex"}),
    "pay-x402/permit2:witness-job-v1": frozenset({"jobId"}),
    "pay-ap2/provider-metadata:dacs-job-id-v1": frozenset({"jobId"}),
}


def outcome(
    expected: str,
    counted: list[str],
    rejected: list[str],
    indeterminate: list[str],
    reason: str,
    selected_by: str | None = None,
) -> tuple[str, dict]:
    return expected, {
        "countedEvidenceHashes": sorted(counted),
        "rejectedEvidenceHashes": sorted(rejected),
        "indeterminateEvidenceHashes": sorted(indeterminate),
        "reason": reason,
        "selectedBy": selected_by,
        "partyFaultCreatedByThisGate": False,
    }


def _malformed(reason: str) -> tuple[str, dict]:
    return outcome("error", [], [], [], reason)


def _unmatched_authority_reason(
    authorities: list[dict], settlement_tx_id: str, rail_id: str, rail_profile: str
) -> str:
    if not authorities:
        return "collision-without-authority"
    if any(item.get("settlementTxId") == settlement_tx_id for item in authorities):
        return "collision-authority-profile-mismatch"
    if any(
        item.get("railId") == rail_id and item.get("railProfile") == rail_profile
        for item in authorities
    ):
        return "collision-authority-settlement-mismatch"
    return "collision-authority-relation-mismatch"


def resolve_collision_groups(
    records: list[dict], trusted_context: dict
) -> tuple[str, dict]:
    """Resolve records from trusted rail pins and per-settlement authority."""
    if not isinstance(records, list) or not isinstance(trusted_context, dict):
        return _malformed("malformed-collision-input")

    groups: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("contentHash"), str)
            or not isinstance(record.get("settlementTxId"), str)
            or not isinstance(record.get("jobId"), str)
            or not isinstance(record.get("phaseIndex"), int)
            or isinstance(record.get("phaseIndex"), bool)
            or record["phaseIndex"] < 0
        ):
            return _malformed("malformed-collision-record")
        groups[record["settlementTxId"]].append(record)

    rail_contexts = trusted_context.get("verifiedRailContexts", [])
    authorities = trusted_context.get("settlementAuthorities", [])
    if not isinstance(rail_contexts, list) or not isinstance(authorities, list):
        return _malformed("malformed-trusted-collision-context")
    if any(not isinstance(item, dict) for item in rail_contexts + authorities):
        return _malformed("malformed-trusted-collision-context")

    results: list[dict] = []
    for settlement_tx_id in sorted(groups):
        group = groups[settlement_tx_id]
        distinct_by_hash: dict[str, dict] = {}
        for record in group:
            prior = distinct_by_hash.get(record["contentHash"])
            if prior is not None and prior != record:
                return _malformed("content-hash-record-mismatch")
            distinct_by_hash[record["contentHash"]] = record
        unique = list(distinct_by_hash.values())
        tuples = {(record["jobId"], record["phaseIndex"]) for record in unique}
        if len(tuples) == 1:
            results.append(
                {
                    "status": "pass",
                    "counted": [sorted(distinct_by_hash)[0]],
                    "rejected": [],
                    "unresolved": [],
                    "reason": (
                        "idempotent-same-tuple"
                        if len(group) != len(unique)
                        else "no-collision"
                    ),
                    "selectedBy": "no-collision",
                }
            )
            continue

        group_contexts: list[dict] = []
        for record in unique:
            matching_contexts = [
                item
                for item in rail_contexts
                if item.get("contentHash") == record["contentHash"]
            ]
            if len(matching_contexts) != 1:
                group_contexts = []
                break
            group_contexts.append(matching_contexts[0])
        profile_tuples = {
            (
                item.get("settlementTxId"),
                item.get("railId"),
                item.get("railProfile"),
            )
            for item in group_contexts
        }
        if (
            len(group_contexts) != len(unique)
            or len(profile_tuples) != 1
            or next(iter(profile_tuples))[0] != settlement_tx_id
            or not all(isinstance(value, str) and value for value in next(iter(profile_tuples)))
        ):
            results.append(
                {
                    "status": "indeterminate",
                    "counted": [],
                    "rejected": [],
                    "unresolved": [record["contentHash"] for record in unique],
                    "reason": "collision-rail-profile-unproven",
                    "selectedBy": None,
                }
            )
            continue
        _, rail_id, rail_profile = next(iter(profile_tuples))

        exact_authorities = [
            item
            for item in authorities
            if item.get("settlementTxId") == settlement_tx_id
            and item.get("railId") == rail_id
            and item.get("railProfile") == rail_profile
        ]
        if not exact_authorities:
            results.append(
                {
                    "status": "indeterminate",
                    "counted": [],
                    "rejected": [],
                    "unresolved": [record["contentHash"] for record in unique],
                    "reason": _unmatched_authority_reason(
                        authorities, settlement_tx_id, rail_id, rail_profile
                    ),
                    "selectedBy": None,
                }
            )
            continue
        if len({json.dumps(item, sort_keys=True) for item in exact_authorities}) != 1:
            results.append(
                {
                    "status": "indeterminate",
                    "counted": [],
                    "rejected": [],
                    "unresolved": [record["contentHash"] for record in unique],
                    "reason": "collision-authority-conflicting",
                    "selectedBy": None,
                }
            )
            continue

        authority = exact_authorities[0]
        state = authority.get("state")
        if state == "malformed":
            return _malformed("malformed-collision-authority")
        if authority.get("source") != "independently-verified-settlement":
            reason = "collision-authority-unproven"
        elif state in {"unavailable", "pruned"}:
            reason = "collision-authority-unavailable"
        elif state in {"included", "reorged"}:
            reason = "collision-authority-not-final"
        elif state == "conflicting-finalized":
            reason = "collision-authority-conflicting"
        elif state != "finalized":
            return _malformed("malformed-collision-authority")
        else:
            dimensions = PROFILE_BINDING_DIMENSIONS.get(rail_profile)
            if dimensions is None:
                reason = "collision-authority-profile-unproven"
            elif "phaseIndex" not in dimensions or not isinstance(
                authority.get("phaseIndex"), int
            ) or isinstance(authority.get("phaseIndex"), bool):
                reason = "collision-authority-phase-unproven"
            elif not isinstance(authority.get("jobId"), str):
                reason = "collision-authority-job-unproven"
            else:
                bound = (authority["jobId"], authority["phaseIndex"])
                matching = [
                    record
                    for record in unique
                    if (record["jobId"], record["phaseIndex"]) == bound
                ]
                nonmatching = [
                    record
                    for record in unique
                    if (record["jobId"], record["phaseIndex"]) != bound
                ]
                results.append(
                    {
                        "status": "pass" if matching else "fail",
                        "counted": (
                            [sorted(record["contentHash"] for record in matching)[0]]
                            if matching
                            else []
                        ),
                        "rejected": [record["contentHash"] for record in nonmatching]
                        if matching
                        else [record["contentHash"] for record in unique],
                        "unresolved": [],
                        "reason": (
                            "authenticated-settlement-binding"
                            if matching
                            else "binding-matches-no-claim"
                        ),
                        "selectedBy": "settlement-authority",
                    }
                )
                continue
        results.append(
            {
                "status": "indeterminate",
                "counted": [],
                "rejected": [],
                "unresolved": [record["contentHash"] for record in unique],
                "reason": reason,
                "selectedBy": None,
            }
        )

    statuses = {item["status"] for item in results}
    overall = next(
        status
        for status in ("error", "indeterminate", "fail", "pass")
        if status in statuses
    )
    decisive = [item for item in results if item["status"] != "pass"] or results
    reasons = {item["reason"] for item in decisive}
    reason = next(iter(reasons)) if len(reasons) == 1 else "mixed-group-results"
    selectors = {item["selectedBy"] for item in results}
    selected_by = next(iter(selectors)) if len(selectors) == 1 else None
    return outcome(
        overall,
        [value for item in results for value in item["counted"]],
        [value for item in results for value in item["rejected"]],
        [value for item in results for value in item["unresolved"]],
        reason,
        selected_by,
    )


def evaluate(vector: dict) -> tuple[str, dict]:
    return resolve_collision_groups(
        vector["protocolInput"]["records"], vector["trustedContext"]
    )


def derive_settlement_verified_metrics(
    records: list[dict], trusted_context: dict, bundles: list[dict]
) -> dict:
    """Minimal executable DACS-5 consumer for the SB-2/RSV-3 boundary."""
    _, disposition = resolve_collision_groups(records, trusted_context)
    counted = set(disposition["countedEvidenceHashes"])
    excluded = set(disposition["rejectedEvidenceHashes"]) | set(
        disposition["indeterminateEvidenceHashes"]
    )
    reconciled = []
    for bundle in bundles:
        evidence_hashes = bundle["settlementEvidenceHashes"]
        if any(item in excluded or item not in counted for item in evidence_hashes):
            continue
        reconciled.append(bundle)

    completed = [item for item in reconciled if item["outcome"] == "completed"]
    neutral = [item for item in reconciled if item["outcome"] == "failed-substrate"]
    counterparty_fault = [
        item
        for item in reconciled
        if item["outcome"] in {"failed-counterparty", "aborted-by-other"}
    ]
    party_fault_denominator = len(reconciled) - len(neutral)
    party_blame_denominator = party_fault_denominator - len(counterparty_fault)

    volume: dict[str, Decimal] = defaultdict(Decimal)
    counts: dict[str, int] = defaultdict(int)
    for bundle in completed:
        if not bundle["settlementEvidenceHashes"]:
            continue
        price = bundle["agreementPrice"]
        volume[price["currency"]] += Decimal(price["amount"])
        counts[price["currency"]] += 1

    return {
        "bundleCount": len(reconciled),
        "completedCount": len(completed),
        "partyFaultDenominator": party_fault_denominator,
        "partyBlameDenominator": party_blame_denominator,
        "completionRate": (
            len(completed) / party_fault_denominator
            if party_fault_denominator
            else None
        ),
        "counterpartyAdjustedCompletionRate": (
            len(completed) / party_blame_denominator
            if party_blame_denominator
            else None
        ),
        "observedTransactionalVolume": [
            {"currency": currency, "amount": format(amount, "f")}
            for currency, amount in sorted(volume.items())
        ],
        "transactionCountByCurrency": [
            {"currency": currency, "count": count}
            for currency, count in sorted(counts.items())
        ],
    }


class Sb2CollisionAuthorityVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {vector["name"]: vector for vector in cls.data["vectors"]}

    def test_committed_file_is_deterministic(self):
        self.assertEqual(VECTORS.read_text(encoding="utf-8"), generator.rendered())

    def test_historical_winner_corpus_is_machine_readably_superseded(self):
        historical = json.loads(HISTORICAL_VECTORS.read_text(encoding="utf-8"))
        self.assertEqual(historical["tier"], "historical")
        self.assertEqual(
            historical["conformanceProfile"],
            {
                "status": "superseded",
                "currentCollisionAuthority": False,
                "normativeScope": (
                    "settlement-tx-id-canonicalisation-and-same-tuple-idempotency-only"
                ),
                "supersededBy": "sb2-collision-authority-v0.8",
            },
        )
        self.assertEqual(
            self.data["supersedes"], ["sb2-settlement-uniqueness-v0.1"]
        )

    def test_every_vector_executes_to_pinned_group_result(self):
        for vector in self.data["vectors"]:
            with self.subTest(name=vector["name"]):
                expected, want = evaluate(vector)
                self.assertEqual(vector["expected"], expected)
                self.assertEqual(vector["want"], want)

    def test_producer_and_anchor_order_never_select_a_winner(self):
        vector = copy.deepcopy(self.cases["cross-job-finalized-binding-selects-a"])
        baseline = evaluate(vector)
        for index, record in enumerate(vector["protocolInput"]["records"]):
            record["observedAt"] = 9_999_999 - index
            record["sr2AnchorOrder"] = 100 - index
        vector["protocolInput"]["records"].reverse()
        vector["protocolInput"]["hints"] = {
            "firstSr2Claim": generator.HASH_B,
            "lowerEvidenceHash": generator.HASH_B,
        }
        self.assertEqual(evaluate(vector), baseline)

    def test_late_collision_revokes_a_provisional_count(self):
        single = self.cases["single-record-no-collision-counts"]
        collision = self.cases["no-binding-collision-voids-both"]
        self.assertEqual(evaluate(single)[1]["countedEvidenceHashes"], [generator.HASH_A])
        expected, want = evaluate(collision)
        self.assertEqual(expected, "indeterminate")
        self.assertEqual(want["countedEvidenceHashes"], [])
        self.assertEqual(
            want["indeterminateEvidenceHashes"],
            sorted([generator.HASH_A, generator.HASH_B]),
        )

    def test_late_collision_removes_dacs5_count_denominators_and_volume(self):
        control = copy.deepcopy(generator.C_EVENT)
        before_records = [copy.deepcopy(generator.A), control]
        after_records = [
            copy.deepcopy(generator.A),
            copy.deepcopy(generator.B),
            control,
        ]
        bundles = [
            {
                "jobId": generator.JOB_A,
                "outcome": "completed",
                "settlementEvidenceHashes": [generator.HASH_A],
                "agreementPrice": {"amount": "5", "currency": "USDC"},
            },
            {
                "jobId": generator.JOB_C,
                "outcome": "completed",
                "settlementEvidenceHashes": [generator.HASH_C],
                "agreementPrice": {"amount": "7", "currency": "USDC"},
            },
        ]
        before = derive_settlement_verified_metrics(
            before_records,
            {
                "verifiedRailContexts": generator.verified_rail_contexts(
                    before_records
                ),
                "settlementAuthorities": [],
            },
            bundles,
        )
        after_context = {
            "verifiedRailContexts": generator.verified_rail_contexts(after_records),
            "settlementAuthorities": [],
        }
        after = derive_settlement_verified_metrics(
            after_records, after_context, bundles
        )

        self.assertEqual(
            {
                key: before[key]
                for key in (
                    "bundleCount",
                    "completedCount",
                    "partyFaultDenominator",
                    "partyBlameDenominator",
                    "observedTransactionalVolume",
                    "transactionCountByCurrency",
                )
            },
            {
                "bundleCount": 2,
                "completedCount": 2,
                "partyFaultDenominator": 2,
                "partyBlameDenominator": 2,
                "observedTransactionalVolume": [
                    {"currency": "USDC", "amount": "12"}
                ],
                "transactionCountByCurrency": [
                    {"currency": "USDC", "count": 2}
                ],
            },
        )
        self.assertEqual(
            {
                key: after[key]
                for key in (
                    "bundleCount",
                    "completedCount",
                    "partyFaultDenominator",
                    "partyBlameDenominator",
                    "observedTransactionalVolume",
                    "transactionCountByCurrency",
                )
            },
            {
                "bundleCount": 1,
                "completedCount": 1,
                "partyFaultDenominator": 1,
                "partyBlameDenominator": 1,
                "observedTransactionalVolume": [
                    {"currency": "USDC", "amount": "7"}
                ],
                "transactionCountByCurrency": [
                    {"currency": "USDC", "count": 1}
                ],
            },
        )
        verdict, disposition = resolve_collision_groups(
            after_records, after_context
        )
        self.assertEqual(verdict, "indeterminate")
        self.assertEqual(
            disposition["indeterminateEvidenceHashes"],
            sorted([generator.HASH_A, generator.HASH_B]),
        )
        self.assertFalse(disposition["partyFaultCreatedByThisGate"])
        self.assertEqual(before["completionRate"], after["completionRate"])

    def test_no_binding_or_unavailable_authority_voids_every_competitor(self):
        names = {
            "no-binding-collision-voids-both",
            "attacker-anchors-stolen-claim-first",
            "authority-unavailable-voids-both",
            "authority-pruned-voids-both",
            "authority-reorged-before-finality-voids-both",
            "unsupported-atomic-first-claim-hint-is-inert",
        }
        for name in names:
            with self.subTest(name=name):
                expected, want = evaluate(self.cases[name])
                self.assertEqual(expected, "indeterminate")
                self.assertEqual(want["countedEvidenceHashes"], [])
                self.assertFalse(want["partyFaultCreatedByThisGate"])

    def test_finalized_binding_and_phase_are_authoritative(self):
        cross_job = evaluate(self.cases["cross-job-finalized-binding-selects-a"])
        cross_phase = evaluate(
            self.cases["cross-phase-eip3009-exact-binding-selects-phase-one"]
        )
        for expected, want in (cross_job, cross_phase):
            self.assertEqual(expected, "pass")
            self.assertEqual(want["countedEvidenceHashes"], [generator.HASH_A])
            self.assertEqual(want["selectedBy"], "settlement-authority")

    def test_authority_relation_is_scoped_to_exact_settlement_and_profile(self):
        one = evaluate(self.cases["two-groups-one-authority-does-not-substitute"])
        self.assertEqual(one[0], "indeterminate")
        self.assertEqual(one[1]["countedEvidenceHashes"], [generator.HASH_A])
        self.assertEqual(one[1]["rejectedEvidenceHashes"], [generator.HASH_B])
        self.assertEqual(
            one[1]["indeterminateEvidenceHashes"],
            sorted([generator.HASH_D, generator.HASH_E]),
        )

        both = evaluate(
            self.cases["two-groups-each-exact-authority-selects-independently"]
        )
        self.assertEqual(both[0], "pass")
        self.assertEqual(
            both[1]["countedEvidenceHashes"],
            sorted([generator.HASH_A, generator.HASH_E]),
        )
        self.assertEqual(
            both[1]["rejectedEvidenceHashes"],
            sorted([generator.HASH_B, generator.HASH_D]),
        )

    def test_missing_or_mismatched_relation_never_selects(self):
        names = {
            "authority-missing-settlement-id-does-not-select",
            "authority-mismatched-settlement-id-does-not-select",
            "authority-missing-rail-profile-does-not-select",
            "authority-mismatched-rail-id-does-not-select",
            "authority-mismatched-profile-does-not-select",
            "unproven-authority-source-does-not-select",
            "protocol-input-authority-claim-is-inert",
        }
        for name in names:
            with self.subTest(name=name):
                expected, want = evaluate(self.cases[name])
                self.assertEqual(expected, "indeterminate")
                self.assertEqual(want["countedEvidenceHashes"], [])
                self.assertEqual(
                    want["indeterminateEvidenceHashes"],
                    sorted([generator.HASH_A, generator.HASH_B]),
                )

    def test_profile_dimensions_come_from_sb3_not_fixture_fields(self):
        exact = evaluate(
            self.cases["cross-phase-eip3009-exact-binding-selects-phase-one"]
        )
        self.assertEqual(exact[0], "pass")
        for name in (
            "eip3009-missing-phase-proof-is-indeterminate",
            "permit2-job-only-cross-phase-is-indeterminate",
            "ap2-job-only-cross-phase-is-indeterminate",
            "permit2-caller-phase-claim-adds-no-authority",
        ):
            with self.subTest(name=name):
                expected, want = evaluate(self.cases[name])
                self.assertEqual(expected, "indeterminate")
                self.assertEqual(want["countedEvidenceHashes"], [])
                self.assertEqual(
                    want["reason"], "collision-authority-phase-unproven"
                )

    def test_trusted_context_pins_relation_outside_protocol_input(self):
        dimensions = self.data["authorityRelation"]
        self.assertEqual(
            dimensions["requiredDimensions"],
            ["settlementTxId", "railId", "railProfile", "jobId", "phaseIndex"],
        )
        self.assertEqual(
            {
                profile: frozenset(fields)
                for profile, fields in dimensions[
                    "currentProfileDimensions"
                ].items()
            },
            PROFILE_BINDING_DIMENSIONS,
        )
        for vector in self.data["vectors"]:
            with self.subTest(name=vector["name"]):
                self.assertNotIn("trustedContext", vector["protocolInput"])
                self.assertIn("verifiedRailContexts", vector["trustedContext"])
                self.assertIn("settlementAuthorities", vector["trustedContext"])

    def test_later_outer_anchor_cannot_replace_finalized_authority(self):
        vector = self.cases["later-anchor-hint-cannot-replace-finalized-binding"]
        self.assertEqual(
            vector["protocolInput"]["hints"]["replacementAnchorClaims"]["jobId"],
            generator.JOB_B,
        )
        expected, want = evaluate(vector)
        self.assertEqual(expected, "pass")
        self.assertEqual(want["countedEvidenceHashes"], [generator.HASH_A])
        self.assertEqual(want["rejectedEvidenceHashes"], [generator.HASH_B])

    def test_required_issue_380_cases_are_present(self):
        self.assertTrue(
            {
                "backdated-attacker-does-not-win",
                "equal-producer-timestamps-do-not-tie-break",
                "binding-to-unpresented-tuple-rejects-both",
                "no-binding-collision-voids-both",
                "attacker-anchors-stolen-claim-first",
                "authority-unavailable-voids-both",
                "authority-reorged-before-finality-voids-both",
                "conflicting-finalized-authority-voids-both",
                "unsupported-atomic-first-claim-hint-is-inert",
            }.issubset(self.cases)
        )

    def test_required_private_issue_389_cases_are_present(self):
        self.assertTrue(
            {
                "two-groups-one-authority-does-not-substitute",
                "two-groups-each-exact-authority-selects-independently",
                "authority-missing-settlement-id-does-not-select",
                "authority-mismatched-settlement-id-does-not-select",
                "authority-missing-rail-profile-does-not-select",
                "authority-mismatched-profile-does-not-select",
                "permit2-job-only-cross-phase-is-indeterminate",
                "ap2-job-only-cross-phase-is-indeterminate",
                "cross-phase-eip3009-exact-binding-selects-phase-one",
                "protocol-input-authority-claim-is-inert",
            }.issubset(self.cases)
        )

    def test_spec_and_dacs5_remove_timestamp_authority(self):
        settle = (ROOT / "spec/DACS-4-SETTLE.md").read_text(encoding="utf-8")
        verify = (ROOT / "spec/DACS-5-VERIFY.md").read_text(encoding="utf-8")
        self.assertIn("authority — not ordering — decides", settle)
        self.assertIn("MUST remove any member it provisionally counted", settle)
        self.assertIn("No such mechanism is registered", settle)
        self.assertIn("per-canonical-settlement authenticated relation", settle)
        self.assertIn("authenticate `jobId` only", settle)
        self.assertNotIn("earlier `observedAt` wins", settle)
        self.assertIn("observedAt", verify)
        self.assertIn("never choose a winner", verify)
        self.assertIn("exact settlement, rail/profile, job, and phase", verify)


if __name__ == "__main__":
    unittest.main()
