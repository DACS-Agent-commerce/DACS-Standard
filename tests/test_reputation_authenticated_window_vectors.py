import hashlib
import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "reputation-authenticated-window-v0.6.json"
)
GENERATOR = ROOT / "scripts" / "generate_reputation_authenticated_window_vectors.py"
SPEC = ROOT / "spec" / "DACS-5-VERIFY.md"
CURRENT = {"authenticatedWindowDerivationVersion": "1"}
LEGACY_DISCRIMINATORS = {
    "derivationVersion",
    "replayableDerivationVersion",
    "jobBoundReplayableDerivationVersion",
    "settlementVerifiedDerivationVersion",
    "replayableSettlementVerifiedDerivationVersion",
}
BINDING_FIELDS = (
    "substrate", "logicalAddress", "nativeAddress", "contentHash", "writer", "nonce",
)


def vector_hash(vectors):
    encoded = json.dumps(vectors, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def indeterminate_want(*, current=True):
    return {
        "currentProfile": current,
        "historicalEligible": False,
        "timeDisposition": "indeterminate",
        "countable": False,
        "windowMember": False,
        "windowTimestamp": None,
        "clockSource": None,
    }


def evaluate(vector):
    data = vector["input"]
    discriminators = data.get("derivationDiscriminators")
    if not isinstance(discriminators, dict) or len(discriminators) != 1:
        return {"expected": "error", "want": indeterminate_want()}

    if discriminators != CURRENT:
        name, version = next(iter(discriminators.items()))
        historical = (
            name in LEGACY_DISCRIMINATORS
            and version == "1"
            and data.get("historicalPolicy") is True
            and isinstance(data.get("eraEvidence"), dict)
            and data["eraEvidence"].get("kind") == "authenticated-profile-commit"
            and data["eraEvidence"].get("authenticated") is True
            and isinstance(data["eraEvidence"].get("commit"), str)
            and len(data["eraEvidence"]["commit"]) == 40
        )
        result = indeterminate_want(current=False)
        result["historicalEligible"] = historical
        return {"expected": "pass" if historical else "fail", "want": result}

    if data.get("windowingBasis") != "sr2-finalized-inclusion-timestamp":
        return {"expected": "error", "want": indeterminate_want()}

    if data.get("replayMutation") is not None:
        return {"expected": "fail", "want": indeterminate_want()}

    bundle = data.get("bundle")
    receipts = data.get("knownReceipts")
    if not isinstance(bundle, dict) or not isinstance(receipts, list):
        return {"expected": "error", "want": indeterminate_want()}

    exact = []
    for receipt in receipts:
        if not isinstance(receipt, dict) or receipt.get("evidenceValid") is not True:
            continue
        if any(receipt.get(field) != bundle.get(field) for field in BINDING_FIELDS):
            continue
        exact.append(receipt)

    if any(item.get("historyDisposition") == "unorderable" for item in exact):
        return {"expected": "indeterminate", "want": indeterminate_want()}

    finalized = [
        item for item in exact
        if item.get("state") == "finalized"
        and item.get("observationDisposition") == "established"
        and isinstance(item.get("blockRef"), dict)
        and isinstance(item["blockRef"].get("timestamp"), int)
        and not isinstance(item["blockRef"].get("timestamp"), bool)
        and item.get("historyDisposition") == "canonical"
    ]

    # Finality is terminal. A later authenticated reorg claim for that same
    # transaction is an unorderable conflict, not a new clock.
    for removed in (
        item for item in exact if item.get("historyDisposition") == "reorged"
    ):
        removed_tx = removed.get("transactionRef")
        removed_order = removed.get("nativeOrder")
        if any(
            final.get("transactionRef") == removed_tx
            and isinstance(removed_order, int)
            and isinstance(final.get("nativeOrder"), int)
            and final["nativeOrder"] < removed_order
            for final in finalized
        ):
            return {"expected": "indeterminate", "want": indeterminate_want()}

    unique = {
        (
            item.get("transactionRef", {}).get("kind"),
            item.get("transactionRef", {}).get("value"),
            item["blockRef"].get("id"),
            item["blockRef"].get("timestamp"),
            item.get("nativeOrder"),
        )
        for item in finalized
    }
    if len(unique) != 1:
        return {"expected": "indeterminate", "want": indeterminate_want()}

    timestamp = next(iter(unique))[3]
    member = data["windowStart"] <= timestamp <= data["windowEnd"]
    return {
        "expected": "pass",
        "want": {
            "currentProfile": True,
            "historicalEligible": False,
            "timeDisposition": "verified",
            "countable": True,
            "windowMember": member,
            "windowTimestamp": timestamp,
            "clockSource": "windowReceipt.blockRef.timestamp",
        },
    }


class AuthenticatedWindowVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_vector_metadata(self):
        vectors = self.document["vectors"]
        self.assertEqual(self.document["count"], len(vectors))
        self.assertEqual(self.document["hash"], vector_hash(vectors))
        names = [vector["name"] for vector in vectors]
        self.assertEqual(len(names), len(set(names)))

    def test_independent_reference_evaluator(self):
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(
                    evaluate(vector),
                    {"expected": vector["expected"], "want": vector["want"]},
                )

    def test_generator_is_deterministic(self):
        completed = subprocess.run(
            ["python3", str(GENERATOR), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_spec_pins_current_profile_and_legacy_boundary(self):
        text = SPEC.read_text(encoding="utf-8")
        self.assertIn("**DACS-5 v0.7**", text)
        self.assertIn('authenticatedWindowDerivationVersion: "1"', text)
        self.assertIn('windowingBasis: "sr2-finalized-inclusion-timestamp"', text)
        self.assertIn("(AWT-1)", text)
        self.assertIn("(AWT-8)", text)
        self.assertIn("historical/partial", text)
        self.assertIn("both boundaries are inclusive", text)
        self.assertIn("windowReceiptHistory", text)


if __name__ == "__main__":
    unittest.main()
