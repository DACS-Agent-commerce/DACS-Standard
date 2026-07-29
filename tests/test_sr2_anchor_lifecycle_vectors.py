import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "sr2-anchor-lifecycle-v0.1.json"
)


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def receipt_is_final(receipt):
    if not receipt or not receipt.get("authenticatedEvidence"):
        return False
    if receipt.get("observationDisposition") != "established":
        return False
    if not receipt.get("blockRef"):
        return False
    if receipt.get("bindingsMatch", True) is not True:
        return False
    return receipt.get("state") == "finalized" or (
        receipt.get("state") == "included"
        and receipt.get("inclusionIsFinal") is True
    )


def evaluate(vector):
    gate = vector["gate"]
    receipt = vector.get("receipt", {})

    if receipt.get("state") == "replaced":
        receipt = vector.get("replacementReceipt", {})

    if gate == "vet-reversible":
        return (
            receipt.get("state") in {"accepted", "included", "finalized"}
            and receipt.get("observationDisposition") == "established"
            and receipt.get("authenticatedEvidence") is True
        )
    if gate == "irreversible-effect":
        return receipt_is_final(receipt)
    if gate == "payment-result":
        return vector.get("railFinal") is True
    if gate == "payment-recovery":
        return not (
            vector.get("railFinal") is True
            and vector.get("recoveryAction") == "resubmit-payment"
        )
    if gate == "completed-bundle":
        return all(
            vector.get(field) is True
            for field in (
                "allDependenciesFinalized",
                "allDependenciesResolvable",
                "bundleFinalized",
                "bundleResolvable",
            )
        )
    if gate == "lifecycle-transition":
        allowed_reentry = {
            "dropped": {"accepted", "included", "replaced"},
            "expired": {"accepted", "included", "replaced"},
            "reorged": {"accepted", "included", "replaced"},
        }
        return (
            vector.get("observationDisposition") == "established"
            and vector.get("authenticatedEvidence") is True
            and vector.get("toState") in allowed_reentry.get(vector.get("fromState"), set())
        )
    if gate == "observation-disposition":
        return all(
            (
                vector.get("observationDisposition") == "indeterminate",
                vector.get("preservedReceiptHashPresent") is True,
                vector.get("preservedReceiptVerified") is True,
                vector.get("reportedState") == vector.get("priorState"),
                vector.get("recoveryAction") == "observe-same-transaction",
            )
        )
    if gate == "vet-recovery":
        return all(
            (
                vector.get("observationDisposition") == "established",
                vector.get("fromState") in {"dropped", "expired", "reorged"},
                vector.get("authenticatedEvidence") is True,
                vector.get("recoveryAction") == "resubmit-identical",
                vector.get("identicalLogicalAddressAndContent") is True,
            )
        )
    if gate == "session-transition":
        transition = (vector.get("fromState"), vector.get("toState"))
        if transition == ("audit-pending", "substrate-failure-paused"):
            return True
        if vector.get("toState") in {"aborted-by-self", "aborted-by-other"}:
            if vector.get("fromState") in {"rate-pending", "audit-pending"}:
                return False
            if vector.get("fromState") == "settle-pending":
                return vector.get("irreversibleEffect") is not True
        return False
    raise AssertionError(f"unknown gate: {gate}")


class Sr2AnchorLifecycleVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_vector_hash_count_and_unique_names(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(
            self.data["hash"],
            hashlib.sha256(canonical_json(vectors)).hexdigest(),
        )
        names = [vector["name"] for vector in vectors]
        self.assertEqual(len(names), len(set(names)))

    def test_every_gate_case_matches_expected_verdict(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                actual = "pass" if evaluate(vector) else "fail"
                self.assertEqual(actual, vector["expected"])

    def test_index_visibility_is_never_an_evaluator_input(self):
        for vector in self.data["vectors"]:
            mutated = dict(vector)
            mutated["indexed"] = not vector.get("indexed", False)
            with self.subTest(vector=vector["name"]):
                self.assertEqual(evaluate(vector), evaluate(mutated))

    def test_final_receipt_requires_evidence_block_and_matching_bindings(self):
        valid = {
            "state": "finalized",
            "observationDisposition": "established",
            "authenticatedEvidence": True,
            "blockRef": True,
            "bindingsMatch": True,
        }
        self.assertTrue(receipt_is_final(valid))
        for field in ("authenticatedEvidence", "blockRef", "bindingsMatch"):
            mutated = dict(valid)
            mutated[field] = False
            with self.subTest(field=field):
                self.assertFalse(receipt_is_final(mutated))

    def test_normative_rules_and_stage_hooks_are_present(self):
        core = (ROOT / "spec" / "CORE.md").read_text(encoding="utf-8")
        for rule in range(1, 10):
            self.assertIn(f"(SR2-{rule})", core)
        self.assertIn("Indexer visibility is orthogonal", core)
        self.assertIn('observationDisposition: "established" | "indeterminate"', core)
        self.assertIn("preservedReceiptHash?: string", core)
        self.assertNotIn("submitted → accepted | rejected | indeterminate", core)
        self.assertNotIn('| "reorged" | "indeterminate"', core)
        self.assertIn('"audit-pending"', (ROOT / "spec" / "DACS-5-VERIFY.md").read_text())
        self.assertIn("(CA-8)", (ROOT / "spec" / "DACS-3-NEGOTIATE.md").read_text())
        self.assertIn("(CA-9)", (ROOT / "spec" / "DACS-3-NEGOTIATE.md").read_text())
        self.assertIn("(PIPE-6)", (ROOT / "spec" / "DACS-4-SETTLE.md").read_text())


if __name__ == "__main__":
    unittest.main()
