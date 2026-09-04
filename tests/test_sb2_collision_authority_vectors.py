"""Execute the DACS-4 v0.8 SB-2 collision-authority corpus."""

from __future__ import annotations

from collections import defaultdict
import copy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_sb2_collision_authority_vectors as generator  # noqa: E402


VECTORS = ROOT / "conformance/vectors/security/sb2-collision-authority-v0.8.json"


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


def evaluate(vector: dict) -> tuple[str, dict]:
    records = vector["protocolInput"]["records"]
    groups: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        groups[record["settlementTxId"]].append(record)

    counted: list[str] = []
    rejected: list[str] = []
    unresolved: list[str] = []
    collision_reason: str | None = None
    selected_by: str | None = "no-collision"
    overall = "pass"

    for group in groups.values():
        distinct_by_hash = {record["contentHash"]: record for record in group}
        unique = list(distinct_by_hash.values())
        tuples = {(record["jobId"], record["phaseIndex"]) for record in unique}
        if len(tuples) == 1:
            counted.append(sorted(distinct_by_hash)[0])
            continue

        authority = vector["trustedContext"].get("settlementAuthority", {})
        state = authority.get("state")
        selected_by = None
        if state == "malformed":
            return outcome("error", [], [], [], "malformed-collision-authority")
        if state == "finalized" and authority.get("source") == "independently-verified-settlement":
            bound = (authority.get("jobId"), authority.get("phaseIndex"))
            matching = [record for record in unique if (record["jobId"], record["phaseIndex"]) == bound]
            nonmatching = [record for record in unique if (record["jobId"], record["phaseIndex"]) != bound]
            selected_by = "settlement-authority"
            if not matching:
                rejected.extend(record["contentHash"] for record in unique)
                overall = "fail"
                collision_reason = "binding-matches-no-claim"
            else:
                counted.append(sorted(record["contentHash"] for record in matching)[0])
                rejected.extend(record["contentHash"] for record in nonmatching)
                collision_reason = "authenticated-settlement-binding"
            continue

        unresolved.extend(record["contentHash"] for record in unique)
        if state in {"unavailable", "pruned"}:
            collision_reason = "collision-authority-unavailable"
        elif state in {"included", "reorged"}:
            collision_reason = "collision-authority-not-final"
        elif state == "conflicting-finalized":
            collision_reason = "collision-authority-conflicting"
        else:
            collision_reason = "collision-without-authority"
        overall = "indeterminate"

    if collision_reason is None:
        collision_reason = (
            "idempotent-same-tuple"
            if len(records) != len({record["contentHash"] for record in records})
            else "no-collision"
        )
    return outcome(
        overall,
        counted,
        rejected,
        unresolved,
        collision_reason,
        selected_by,
    )


class Sb2CollisionAuthorityVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {vector["name"]: vector for vector in cls.data["vectors"]}

    def test_committed_file_is_deterministic(self):
        self.assertEqual(VECTORS.read_text(encoding="utf-8"), generator.rendered())

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
            self.cases["cross-phase-finalized-binding-selects-phase-one"]
        )
        for expected, want in (cross_job, cross_phase):
            self.assertEqual(expected, "pass")
            self.assertEqual(want["countedEvidenceHashes"], [generator.HASH_A])
            self.assertEqual(want["selectedBy"], "settlement-authority")

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

    def test_spec_and_dacs5_remove_timestamp_authority(self):
        settle = (ROOT / "spec/DACS-4-SETTLE.md").read_text(encoding="utf-8")
        verify = (ROOT / "spec/DACS-5-VERIFY.md").read_text(encoding="utf-8")
        self.assertIn("authority — not ordering — decides", settle)
        self.assertIn("MUST remove any member it provisionally counted", settle)
        self.assertIn("No such mechanism is registered", settle)
        self.assertNotIn("earlier `observedAt` wins", settle)
        self.assertIn("observedAt", verify)
        self.assertIn("never choose a winner", verify)


if __name__ == "__main__":
    unittest.main()
