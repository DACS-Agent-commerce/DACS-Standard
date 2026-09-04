"""Independent executable adapter for DACS-5 LAB-1..LAB-7 vectors."""
from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTOR_PATH = (
    ROOT / "conformance" / "vectors" / "security"
    / "legacy-bundle-admission-v0.6.json"
)
SPEC = ROOT / "spec" / "DACS-5-VERIFY.md"


def canonical_vectors(vectors: list[dict]) -> bytes:
    return json.dumps(
        vectors, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def result(verdict: str) -> dict:
    disposition = {
        "pass": "eligible",
        "fail": "ineligible",
        "indeterminate": "indeterminate",
    }[verdict]
    return {
        "expected": verdict,
        "want": {
            "admissionDisposition": disposition,
            "reputationEffect": "include" if verdict == "pass" else "exclude",
            "auditInspectable": True,
            "authoritativeAbsence": False,
            "partyFaultCreatedByGate": False,
        },
    }


def evaluate(vector: dict) -> dict:
    value = vector["input"]
    bundle = value["bundle"]
    if bundle["type"] != "legacy":
        return result("pass")

    checkpoint = value.get("checkpoint")
    if not checkpoint or checkpoint.get("state") != "finalized":
        return result("indeterminate")
    if not checkpoint.get("unique", False) or not checkpoint.get("ordered", False):
        return result("indeterminate")
    if not all(
        checkpoint.get(field, False)
        for field in ("stewardAuthorized", "signatureValid", "addressBound")
    ):
        return result("fail")

    history = value.get("historicalAnchor")
    if not history or history.get("state") != "finalized":
        return result("indeterminate")
    if not history.get("ordered", False):
        return result("indeterminate")
    if checkpoint.get("substrate") != history.get("substrate"):
        return result("fail")
    if history.get("role") != value.get("resolvedRole"):
        return result("fail")
    if history.get("contentHash") != bundle.get("contentHash"):
        return result("fail")
    if history.get("order") >= checkpoint.get("order"):
        return result("fail")
    return result("pass")


class LegacyBundleAdmissionVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        cls.vectors = cls.data["vectors"]
        cls.by_name = {item["name"]: item for item in cls.vectors}

    def test_metadata_and_hash(self):
        self.assertEqual(self.data["set"], VECTOR_PATH.stem)
        self.assertEqual(self.data["count"], len(self.vectors))
        self.assertEqual(len(self.by_name), len(self.vectors))
        self.assertEqual(
            self.data["hash"],
            hashlib.sha256(canonical_vectors(self.vectors)).hexdigest(),
        )

    def test_independent_adapter_matches_every_vector(self):
        for vector in self.vectors:
            with self.subTest(vector=vector["name"]):
                actual = evaluate(vector)
                self.assertEqual(actual["expected"], vector["expected"])
                self.assertEqual(actual["want"], vector["want"])

    def test_adversarial_acceptance_criteria_are_present(self):
        required = {
            "lab-cross-role-rebind-rejected",
            "lab-fresh-legacy-post-checkpoint",
            "lab-backdated-fresh-legacy",
            "lab-historical-replay-after-checkpoint",
            "lab-anchor-history-missing",
        }
        self.assertTrue(required.issubset(self.by_name))

    def test_timestamps_do_not_override_receipt_order(self):
        vector = self.by_name["lab-backdated-fresh-legacy"]
        self.assertLess(vector["input"]["bundle"]["finalisedAt"], 100)
        self.assertGreater(vector["input"]["historicalAnchor"]["order"], 100)
        self.assertEqual(evaluate(vector)["expected"], "fail")

    def test_role_history_is_not_transferable(self):
        vector = self.by_name["lab-cross-role-rebind-rejected"]
        self.assertNotEqual(
            vector["input"]["resolvedRole"],
            vector["input"]["historicalAnchor"]["role"],
        )
        self.assertFalse(vector["want"]["authoritativeAbsence"])

    def test_spec_defines_complete_lab_family_and_replay_context(self):
        text = SPEC.read_text(encoding="utf-8")
        for number in range(1, 8):
            self.assertIn(f"(LAB-{number})", text)
        self.assertIn("LegacyBundleActivationCheckpoint", text)
        self.assertIn("dacs-legacy-bundle-checkpoint:v1:", text)
        self.assertIn("LegacyBundleEraEvidence", text)
        self.assertIn("strictly before the checkpoint", text)


if __name__ == "__main__":
    unittest.main()
