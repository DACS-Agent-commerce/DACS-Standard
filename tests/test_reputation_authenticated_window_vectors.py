import copy
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
MAX_SAFE_INTEGER = 2**53 - 1
TRUSTED_ERA_POLICY = {
    "policyId": "dacs-test-era-policy-v1",
    "adapter": "conformance-harness-profile-era-v1",
    "authority": "did:demos:steward",
    "producer": "did:demos:legacy-reputation-producer",
    "sessionId": "01K4AWT0000000000000000001",
    "profile": "dacs-next-dacs-5-v0.5",
    "commit": "3426faaebc09948d57a3a6d30fd6795df579b68f",
    "currentProfile": "dacs-next-dacs-5-v0.6",
    "revisionRelation": "predates-current",
}
TRUSTED_ERA_POLICY_FIELDS = tuple(TRUSTED_ERA_POLICY)


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


def safe_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_SAFE_INTEGER
    )


def valid_transaction_ref(value):
    return (
        isinstance(value, dict)
        and set(value) == {"kind", "value"}
        and isinstance(value.get("kind"), str)
        and bool(value["kind"])
        and isinstance(value.get("value"), str)
        and bool(value["value"])
    )


def transaction_key(value):
    return (value["kind"], value["value"])


def receipt_hash(value):
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def receipt_is_verified_for_bundle(item, bundle):
    if not isinstance(item, dict) or item.get("evidenceValid") is not True:
        return False
    if (
        item.get("receiptVersion") != "1"
        or item.get("finalityProfile") != "demos-bft-final"
    ):
        return False
    if any(item.get(field) != bundle.get(field) for field in BINDING_FIELDS):
        return False
    if not valid_transaction_ref(item.get("transactionRef")):
        return False
    if not isinstance(item.get("state"), str) or item["state"] not in {
        "accepted", "included", "finalized"
    }:
        return False
    if not isinstance(item.get("observationDisposition"), str) or item[
        "observationDisposition"
    ] not in {"established", "indeterminate"}:
        return False
    if not isinstance(item.get("historyDisposition"), str) or item[
        "historyDisposition"
    ] not in {
        "canonical", "replaced", "reorged", "unorderable"
    }:
        return False
    if not safe_integer(item.get("observedAt")) or not safe_integer(item.get("nativeOrder")):
        return False
    evidence = item.get("evidence")
    if not (
        isinstance(evidence, dict)
        and isinstance(evidence.get("kind"), str)
        and bool(evidence["kind"])
        and isinstance(evidence.get("value"), str)
        and bool(evidence["value"])
    ):
        return False
    if item["state"] in {"included", "finalized"}:
        block = item.get("blockRef")
        if not (
            isinstance(block, dict)
            and isinstance(block.get("id"), str)
            and bool(block["id"])
            and isinstance(block.get("height"), str)
            and bool(block["height"])
        ):
            return False
        if "timestamp" in block and not safe_integer(block["timestamp"]):
            return False
    relation = item.get("replacementRelation")
    if relation is not None:
        if not (
            isinstance(relation, dict)
            and relation.get("kind") == "demos-authenticated-replacement"
            and isinstance(relation.get("evidenceValid"), bool)
            and valid_transaction_ref(relation.get("predecessor"))
            and valid_transaction_ref(relation.get("replacement"))
            and valid_transaction_ref(item.get("replacementTransactionRef"))
            and relation["predecessor"] == item["transactionRef"]
            and relation["replacement"] == item["replacementTransactionRef"]
        ):
            return False
    elif "replacementTransactionRef" in item:
        return False
    return True


def authorized_transaction_keys(exact, bundle):
    expected = bundle.get("transactionRef")
    if not valid_transaction_ref(expected):
        return set()
    authorized = {transaction_key(expected)}
    changed = True
    while changed:
        changed = False
        for item in exact:
            relation = item.get("replacementRelation")
            if not (
                item.get("historyDisposition") == "replaced"
                and isinstance(relation, dict)
                and relation.get("evidenceValid") is True
                and transaction_key(item["transactionRef"]) in authorized
            ):
                continue
            successor = transaction_key(relation["replacement"])
            if successor not in authorized:
                authorized.add(successor)
                changed = True
    return authorized


def canonical_receipt_history(exact):
    unique = {receipt_hash(item): item for item in exact}
    return [
        copy.deepcopy(item)
        for _, item in sorted(
            unique.items(), key=lambda pair: (pair[1]["nativeOrder"], pair[0])
        )
    ]


def resolve_current(data, receipts):
    bundle = data.get("bundle")
    if not isinstance(bundle, dict) or not isinstance(receipts, list):
        return "error", indeterminate_want(), None, []
    if not valid_transaction_ref(bundle.get("transactionRef")):
        return "error", indeterminate_want(), None, []
    if not safe_integer(data.get("windowStart")) or not safe_integer(data.get("windowEnd")):
        return "error", indeterminate_want(), None, []
    if data["windowStart"] > data["windowEnd"]:
        return "error", indeterminate_want(), None, []

    exact = [
        item for item in receipts if receipt_is_verified_for_bundle(item, bundle)
    ]
    history = canonical_receipt_history(exact)
    if any(item["historyDisposition"] == "unorderable" for item in exact):
        return "indeterminate", indeterminate_want(), None, history

    authorized = authorized_transaction_keys(exact, bundle)
    finalized = [
        item for item in exact
        if transaction_key(item["transactionRef"]) in authorized
        and item["state"] == "finalized"
        and item["observationDisposition"] == "established"
        and isinstance(item.get("blockRef"), dict)
        and safe_integer(item["blockRef"].get("timestamp"))
        and item["historyDisposition"] == "canonical"
    ]

    # Finality is terminal. A later authenticated reorg claim for that same
    # transaction is an unorderable conflict, not a new clock.
    for removed in (item for item in exact if item["historyDisposition"] == "reorged"):
        if any(
            final["transactionRef"] == removed["transactionRef"]
            and final["nativeOrder"] < removed["nativeOrder"]
            for final in finalized
        ):
            return "indeterminate", indeterminate_want(), None, history

    unique = {}
    for item in finalized:
        key = (
            *transaction_key(item["transactionRef"]),
            item["blockRef"]["id"],
            item["blockRef"]["timestamp"],
            item["nativeOrder"],
        )
        unique.setdefault(key, item)
    if len(unique) != 1:
        return "indeterminate", indeterminate_want(), None, history

    key, selected = next(iter(unique.items()))
    timestamp = key[3]
    member = data["windowStart"] <= timestamp <= data["windowEnd"]
    return (
        "pass",
        {
            "currentProfile": True,
            "historicalEligible": False,
            "timeDisposition": "verified",
            "countable": True,
            "windowMember": member,
            "windowTimestamp": timestamp,
            "clockSource": "windowReceipt.blockRef.timestamp",
        },
        copy.deepcopy(selected),
        history,
    )


def verified_historical_era(data):
    policy = data.get("trustedEraPolicy")
    evidence = data.get("eraEvidence")
    if not isinstance(policy, dict) or not isinstance(evidence, dict):
        return False
    if policy != TRUSTED_ERA_POLICY:
        return False
    if evidence.get("kind") != "verified-profile-era-projection":
        return False
    if evidence.get("verificationDisposition") != "verified":
        return False
    if any(evidence.get(field) != policy.get(field) for field in TRUSTED_ERA_POLICY_FIELDS):
        return False
    return (
        isinstance(policy.get("commit"), str)
        and len(policy["commit"]) == 40
        and policy.get("profile") != policy.get("currentProfile")
        and policy.get("revisionRelation") == "predates-current"
    )


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
            and verified_historical_era(data)
        )
        result = indeterminate_want(current=False)
        result["historicalEligible"] = historical
        return {"expected": "pass" if historical else "fail", "want": result}

    if data.get("windowingBasis") != "sr2-finalized-inclusion-timestamp":
        return {"expected": "error", "want": indeterminate_want()}

    expected, want, selected, history = resolve_current(data, data.get("knownReceipts"))
    replay = data.get("replayContext")
    if replay is not None:
        if expected != "pass":
            return {"expected": "fail", "want": indeterminate_want()}
        if not isinstance(replay, dict) or set(replay) != {
            "windowReceipt", "windowReceiptHistory"
        }:
            return {"expected": "fail", "want": indeterminate_want()}
        replay_history = replay.get("windowReceiptHistory")
        if not isinstance(replay_history, list):
            return {"expected": "fail", "want": indeterminate_want()}
        replay_expected, replay_want, replay_selected, canonical_history = resolve_current(
            data, replay_history
        )
        if not (
            replay_expected == "pass"
            and replay_want == want
            and replay.get("windowReceipt") == selected == replay_selected
            and replay_history == history == canonical_history
        ):
            return {"expected": "fail", "want": indeterminate_want()}

    return {"expected": expected, "want": want}


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

    def test_review_closure_vectors_are_concrete_and_complete(self):
        vectors = {item["name"]: item for item in self.document["vectors"]}
        required = {
            "awt-wrong-sole-transaction-indeterminate",
            "awt-finalized-replacement-without-authenticated-relation",
            "awt-finalized-exact-replacement-pass",
            "awt-replay-concrete-history-pass",
            "awt-replay-substituted-transaction",
            "awt-replay-substituted-native-proof",
            "awt-replay-misordered-history",
            "awt-malformed-transaction-ref-array-indeterminate",
            "awt-malformed-block-ref-array-indeterminate",
            "awt-malformed-timestamp-container-indeterminate",
            "awt-malformed-native-order-container-indeterminate",
            "awt-era-trust-policy-mismatch-rejected",
            "awt-era-coordinated-policy-and-evidence-tampering-rejected",
        }
        self.assertLessEqual(required, set(vectors))
        self.assertNotIn("replayMutation", json.dumps(self.document))

        replay = vectors["awt-replay-concrete-history-pass"]["input"][
            "replayContext"
        ]
        self.assertGreater(len(replay["windowReceiptHistory"]), 1)
        self.assertEqual(
            replay["windowReceipt"], replay["windowReceiptHistory"][-1]
        )

        names = set(vectors)
        slugs = {
            "derivation",
            "replayable-derivation",
            "job-bound-replayable-derivation",
            "settlement-verified-derivation",
            "replayable-settlement-verified-derivation",
        }
        for slug in slugs:
            self.assertIn(f"awt-{slug}-cannot-claim-current", names)
            self.assertIn(f"awt-{slug}-verified-era-is-historical-only", names)

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
