import hashlib
import json
import unicodedata
import unittest
from collections import Counter
from pathlib import Path

import dacs5_reference as R


ROOT = Path(__file__).resolve().parents[1]
SECURITY = ROOT / "conformance" / "vectors" / "security"
REFERENCE_VECTORS = SECURITY / "reputation-settlement-reference-divergence-v0.4.json"
SEMANTIC_VECTORS = SECURITY / "reputation-settlement-semantics-v0.4.json"
SPEC = ROOT / "spec" / "DACS-5-VERIFY.md"
PAYMENT_PHASE_TYPES = frozenset({
    "pay-evm-erc20",
    "pay-solana-spl",
    "pay-cross-chain-htlc",
    "pay-cross-chain-liquidity-tank",
    "pay-ap2",
    "pay-x402",
    "pay-dem",
})


def canonical_json(value):
    def normalize(item):
        if isinstance(item, str):
            return unicodedata.normalize("NFC", item)
        if isinstance(item, list):
            return [normalize(value) for value in item]
        if isinstance(item, dict):
            return {key: normalize(value) for key, value in item.items()}
        return item

    return json.dumps(normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def vector_set_bytes(vectors):
    return json.dumps(vectors, separators=(",", ":"), ensure_ascii=False).encode()


def evaluate_reference(vector):
    left = Counter(canonical_json(reference) for reference in vector["input"]["selfRefs"])
    right = Counter(canonical_json(reference) for reference in vector["input"]["counterpartyRefs"])
    unified = left == right
    return {
        "expected": "pass" if unified else "fail",
        "want": {"lookupDisposition": "unified" if unified else "divergent", "bundleIncluded": unified},
    }


def evaluate_semantic(vector):
    input_data = vector["input"]
    authority = input_data["authorityDisposition"]
    legacy = input_data.get("legacyAgreement") is True

    historical_only = False
    if legacy:
        # Run the actual LAA oracle over the embedded admission input; a legacy
        # payment never trusts a precomputed disposition. Missing, unknown, or
        # malformed LAA input is non-authorizing (rejected).
        admission = R.laa_want(input_data.get("laa"))["dacs5Admission"]
        if admission == "historical-only":
            expected = "accept"
            historical_only = True
        elif admission == "indeterminate":
            expected = "indeterminate"
        else:
            expected = "reject"
    elif authority == "indeterminate":
        expected = "indeterminate"
    elif authority == "rejected" or input_data.get("mismatch") is not None:
        expected = "reject"
    else:
        expected = "accept"

    included = expected == "accept" and not historical_only
    completed = included and input_data["outcome"] == "completed"
    payment = (
        input_data["presentedEvidenceCount"] > 0
        and input_data.get("evidencePhase", "pay-dem") in PAYMENT_PHASE_TYPES
        and input_data.get("evidenceOutcome", "success") == "success"
    )
    volume = completed and payment
    if historical_only:
        disposition = "historical-only"
    else:
        disposition = (
            "eligible"
            if volume
            else ("eligible-non-volume" if included else "excluded-without-fault")
        )
    want = {
        "bundleIncluded": included,
        "completionNumerator": 1 if completed else 0,
        "partyFaultDenominator": 1 if included else 0,
        "counterpartyAdjustedDenominator": 1 if included else 0,
        "volumeByCurrency": ["5 DEM"] if volume else [],
        "transactionCountByCurrency": [{"currency": "DEM", "count": 1}] if volume else [],
        "disposition": disposition,
    }
    return {"expected": expected, "want": want}


class SettlementVerifiedReputationVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = json.loads(REFERENCE_VECTORS.read_text(encoding="utf-8"))
        cls.semantic = json.loads(SEMANTIC_VECTORS.read_text(encoding="utf-8"))

    def test_vector_metadata(self):
        for data in (self.reference, self.semantic):
            with self.subTest(vector_set=data["set"]):
                vectors = data["vectors"]
                self.assertEqual(data["count"], len(vectors))
                self.assertEqual(data["hash"], hashlib.sha256(vector_set_bytes(vectors)).hexdigest())
                names = [vector["name"] for vector in vectors]
                self.assertEqual(len(names), len(set(names)))

    def test_reference_multiset_semantics(self):
        for vector in self.reference["vectors"]:
            with self.subTest(vector=vector["name"]):
                result = evaluate_reference(vector)
                self.assertEqual(result["expected"], vector["expected"])
                self.assertEqual(result["want"], vector["want"])

    def test_full_reference_arm_uses_attestationref_shape(self):
        vector = next(
            vector
            for vector in self.reference["vectors"]
            if vector["name"]
            == "reputation-settlement-reference-same-content-different-anchor-divergent"
        )
        for side in ("selfRefs", "counterpartyRefs"):
            reference = vector["input"][side][0]
            self.assertEqual(set(reference), {"anchor", "contentHash"})
            self.assertEqual(set(reference["anchor"]), {"kind", "locator"})
            self.assertIn(reference["anchor"]["kind"], {"storage-program", "ipfs", "https"})
            self.assertEqual(len(reference["contentHash"]), 64)

    def test_settlement_admission_and_volume_semantics(self):
        for vector in self.semantic["vectors"]:
            with self.subTest(vector=vector["name"]):
                result = evaluate_semantic(vector)
                self.assertEqual(result["expected"], vector["expected"])
                self.assertEqual(result["want"], vector["want"])

    def test_historical_legacy_pass_is_excluded_from_every_current_metric(self):
        case = next(
            c for c in self.semantic["vectors"]
            if c["name"] == "reputation-settlement-semantic-legacy-historical-pass-excluded"
        )
        result = evaluate_semantic(case)
        self.assertEqual(result["expected"], "accept")
        want = result["want"]
        self.assertFalse(want["bundleIncluded"])
        self.assertEqual(want["completionNumerator"], 0)
        self.assertEqual(want["partyFaultDenominator"], 0)
        self.assertEqual(want["counterpartyAdjustedDenominator"], 0)
        self.assertEqual(want["volumeByCurrency"], [])
        self.assertEqual(want["transactionCountByCurrency"], [])
        self.assertEqual(want["disposition"], "historical-only")

    def test_legacy_omission_and_tamper_are_non_authorizing(self):
        """A legacy payment is never default-accepted: an omitted, unknown, or
        malformed LAA admission input rejects the bundle member."""
        base = next(
            c for c in self.semantic["vectors"]
            if c["name"] == "reputation-settlement-semantic-legacy-historical-pass-excluded"
        )
        # Omitted LAA input -> rejected, not accepted.
        omitted = {"input": {k: v for k, v in base["input"].items() if k != "laa"}}
        self.assertEqual(evaluate_semantic(omitted)["expected"], "reject")
        self.assertFalse(evaluate_semantic(omitted)["want"]["bundleIncluded"])
        # Unknown/malformed LAA input -> rejected, never accepted.
        for bad in (None, "historical-pass", [], {"operation": ["historical-audit"]}):
            with self.subTest(bad=repr(bad)[:40]):
                tampered = {"input": {**base["input"], "laa": bad}}
                self.assertEqual(evaluate_semantic(tampered)["expected"], "reject")
                self.assertFalse(evaluate_semantic(tampered)["want"]["bundleIncluded"])

    def test_volume_uses_closed_payment_phase_type_membership(self):
        expected_payment_phases = (
            "pay-evm-erc20",
            "pay-solana-spl",
            "pay-cross-chain-htlc",
            "pay-cross-chain-liquidity-tank",
            "pay-ap2",
            "pay-x402",
            "pay-dem",
        )
        self.assertEqual(PAYMENT_PHASE_TYPES, frozenset(expected_payment_phases))
        base = {
            "name": "phase-membership-control",
            "input": {
                "outcome": "completed",
                "presentedEvidenceCount": 1,
                "evidenceOutcome": "success",
                "authorityDisposition": "verified",
                "mismatch": None,
            },
        }
        for phase in expected_payment_phases:
            with self.subTest(phase=phase):
                vector = {**base, "input": {**base["input"], "evidencePhase": phase}}
                self.assertEqual(evaluate_semantic(vector)["want"]["volumeByCurrency"], ["5 DEM"])

        for phase in ("pay-not-a-dacs4-phase", "deliver-entitlement"):
            with self.subTest(phase=phase):
                vector = {**base, "input": {**base["input"], "evidencePhase": phase}}
                result = evaluate_semantic(vector)
                self.assertEqual(result["expected"], "accept")
                self.assertEqual(result["want"]["volumeByCurrency"], [])
                self.assertEqual(result["want"]["transactionCountByCurrency"], [])
                self.assertEqual(result["want"]["disposition"], "eligible-non-volume")

    def test_new_discriminators_preserve_released_v1_meaning(self):
        text = SPEC.read_text(encoding="utf-8")
        self.assertRegex(text, r"\*\*DACS-5 v0\.(?:[5-9]|[1-9][0-9]+)\*\*")
        self.assertIn("makes APR-7 effective-pipeline recomputation mandatory", text)
        self.assertIn('settlementVerifiedDerivationVersion: "1"', text)
        self.assertIn('replayableSettlementVerifiedDerivationVersion: "1"', text)
        self.assertIn("Existing discriminators retain their released meaning.", text)
        self.assertIn("without repository-revision knowledge", text)


if __name__ == "__main__":
    unittest.main()
