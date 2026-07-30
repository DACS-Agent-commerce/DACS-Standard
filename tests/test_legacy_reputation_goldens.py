import hashlib
import json
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "conformance" / "fixtures" / "session-bundles-reputation.json"
GOLDEN = ROOT / "conformance" / "vectors" / "golden.json"
MANIFEST = ROOT / "conformance" / "MANIFEST.json"

LEGACY_CANDIDATES = {
    "verify-reputation-denominator",
    "verify-reputation-determinism-receipt",
    "verify-reputation-mixed-role-window",
    "verify-reputation-no-double-count",
    "verify-reputation-null-not-zero",
    "verify-reputation-orchestrator-ignored",
    "verify-reputation-perspective-flip",
    "verify-reputation-rating-dedup",
    "verify-reputation-ratings-volume-l3-null",
    "verify-reputation-reconcile-withdrawer",
    "verify-reputation-seller-perspective-flip",
    "verify-reputation-volume-grouped",
    "verify-reputation-window",
    "verify-reputation-window-boundary-inclusive",
}
NEGATIVE_GOLDENS = {
    "verify-reputation-divergence-excluded",
    "verify-reputation-relabel-attack-defeated",
    "verify-reputation-single-signed-non-abort-dropped",
}


def canonical_hash(bundle):
    unsigned = {
        key: value
        for key, value in bundle.items()
        if key not in {"anchoredByRole", "signatures"}
    }
    encoded = json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def derive_with_guard_iv(fixture, resolution_context=None):
    context = resolution_context or {}
    scoped = [
        bundle
        for bundle in fixture["bundles"]
        if fixture["windowStart"] <= bundle["finalisedAt"] <= fixture["windowEnd"]
        and fixture["partyPrimaryClaim"]
        in {party["primaryClaim"] for party in bundle["parties"]}
    ]
    selected = []
    for bundle in scoped:
        other_role = "seller" if bundle["anchoredByRole"] == "buyer" else "buyer"
        dispositions = context.get(bundle["jobId"], {})
        if dispositions.get(other_role) != "absent":
            continue
        selected.append(bundle)

    outcomes = [bundle["outcome"] for bundle in selected]
    completed = outcomes.count("completed")
    failed_substrate = outcomes.count("failed-substrate")
    counterparty_fault = outcomes.count("failed-counterparty") + outcomes.count("aborted-by-other")
    party_fault_denom = len(outcomes) - failed_substrate
    party_blame_denom = party_fault_denom - counterparty_fault

    def ratio(numerator, denominator):
        return numerator / denominator if denominator else None

    refs = sorted(
        (
            {
                "anchor": {
                    "kind": "storage-program",
                    "locator": bundle["jobId"],
                },
                "contentHash": canonical_hash(bundle),
            }
            for bundle in selected
        ),
        key=lambda ref: ref["contentHash"],
    )
    return {
        "bundleCount": len(selected),
        "metrics": {
            "completionRate": ratio(completed, party_fault_denom),
            "counterpartyAdjustedCompletionRate": ratio(completed, party_blame_denom),
            "counterpartyFaultRate": ratio(counterparty_fault, party_fault_denom),
            "averageBuyerRating": None,
            "averageSellerRating": None,
            "observedTransactionalVolume": [],
            "transactionCountByCurrency": [],
        },
        "bundleRefs": refs,
    }


class LegacyReputationGoldenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.golden = json.loads(GOLDEN.read_text(encoding="utf-8"))["verify"]
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        cls.cases = {case["id"]: case for case in manifest["cases"]}

    def test_fixture_is_explicitly_legacy_and_has_no_resolution_context(self):
        self.assertEqual(self.fixture["status"], "legacy-candidate-pre-guard-iv")
        self.assertNotIn("resolutionContext", self.fixture)
        self.assertEqual(len(self.fixture["bundles"]), 6)
        self.assertEqual(
            Counter(bundle["anchoredByRole"] for bundle in self.fixture["bundles"]),
            {"buyer": 6},
        )
        self.assertEqual(len({bundle["jobId"] for bundle in self.fixture["bundles"]}), 6)

    def test_current_guard_iv_excludes_every_unqualified_in_window_job(self):
        produced = derive_with_guard_iv(self.fixture)
        expected = self.golden["reputation"]
        self.assertEqual(produced["bundleCount"], expected["bundleCount"])
        self.assertEqual(produced["metrics"], expected["metrics"])
        self.assertEqual(produced["bundleRefs"], expected["bundleRefs"])
        self.assertEqual(produced["bundleCount"], 0)

    def test_historical_metrics_are_retained_only_as_candidates(self):
        self.assertIn("guard (iv) excludes", self.golden["reputationDisposition"]["current"])
        self.assertIn("candidate", self.golden["reputationDisposition"]["legacy"])
        legacy = self.golden["legacyReputationCandidate"]
        self.assertEqual(legacy["bundleCount"], 5)
        self.assertEqual(legacy["metrics"]["completionRate"], 0.25)
        self.assertEqual(legacy["metrics"]["counterpartyAdjustedCompletionRate"], 0.5)
        self.assertEqual(legacy["metrics"]["counterpartyFaultRate"], 0.5)
        for ref in legacy["bundleRefs"]:
            bundle = next(
                item
                for item in self.fixture["bundles"]
                if item["jobId"] == ref["anchor"]["locator"]
            )
            self.assertEqual(ref["contentHash"], canonical_hash(bundle))

    def test_manifest_demotes_only_the_affected_positive_cases(self):
        actual_candidates = {
            case_id
            for case_id, case in self.cases.items()
            if case_id.startswith("verify-reputation-") and case["status"] == "candidate"
        }
        self.assertEqual(actual_candidates, LEGACY_CANDIDATES)
        for case_id in NEGATIVE_GOLDENS:
            self.assertEqual(self.cases[case_id]["status"], "golden")
        current = self.cases["verify-reputation-unqualified-one-copy-excluded"]
        self.assertEqual(current["status"], "golden")
        self.assertEqual(current["want"]["bundleCount"], 0)

    def test_normative_guard_is_the_reason_for_the_disposition(self):
        spec = (ROOT / "spec" / "DACS-5-VERIFY.md").read_text(encoding="utf-8")
        self.assertIn("**authoritative absence before one-copy attribution**", spec)
        self.assertIn("A caller that supplies one raw copy without that context", spec)


if __name__ == "__main__":
    unittest.main()
