import hashlib
import json
import unicodedata
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "settlement-finalization-propagation-v0.3.json"
)
SPEC = ROOT / "spec" / "DACS-4-SETTLE.md"
PLAN = ROOT / "spec" / "CONFORMANCE-PLAN.md"


def nfc_deep(value):
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [nfc_deep(item) for item in value]
    if isinstance(value, dict):
        return {key: nfc_deep(item) for key, item in value.items()}
    return value


def canonical_json(value):
    return json.dumps(
        nfc_deep(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def content_hash(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


def diff_paths(left, right, prefix=""):
    if type(left) is not type(right):
        return {prefix}
    if isinstance(left, dict):
        paths = set()
        for key in set(left) | set(right):
            path = f"{prefix}.{key}" if prefix else key
            if key not in left or key not in right:
                paths.add(path)
            else:
                paths.update(diff_paths(left[key], right[key], path))
        return paths
    if isinstance(left, list):
        if len(left) != len(right):
            return {prefix}
        paths = set()
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            paths.update(diff_paths(left_item, right_item, f"{prefix}[{index}]"))
        return paths
    return set() if left == right else {prefix}


def evaluate_vector(vector, required_paths, allowed_paths):
    changed = set(vector["changedPaths"])
    errors = []
    if vector["draftDisposition"] != "in-memory-only":
        errors.append("placeholder draft was signed or anchored")
    missing = sorted(required_paths - changed)
    if missing:
        errors.append(f"stale propagation: {', '.join(missing)}")
    extra = sorted(changed - allowed_paths)
    if extra:
        errors.append(f"outside propagation closure: {', '.join(extra)}")
    return "pass" if not errors else "fail", errors


class SettlementFinalizationPropagationVectorTests(unittest.TestCase):
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

    def test_fixture_recomputes_both_transitive_hash_changes(self):
        fixture = self.data["fixture"]
        draft_evidence_hash = content_hash(fixture["draftEvidence"])
        final_evidence_hash = content_hash(fixture["finalEvidence"])
        self.assertEqual(draft_evidence_hash, fixture["draftEvidenceHash"])
        self.assertEqual(final_evidence_hash, fixture["finalEvidenceHash"])
        self.assertNotEqual(draft_evidence_hash, final_evidence_hash)

        self.assertEqual(content_hash(fixture["draftBundle"]), fixture["draftBundleHash"])
        self.assertEqual(content_hash(fixture["finalBundle"]), fixture["finalBundleHash"])
        self.assertNotEqual(fixture["draftBundleHash"], fixture["finalBundleHash"])

        draft_bundle = fixture["draftBundle"]
        final_bundle = fixture["finalBundle"]
        self.assertEqual(
            draft_bundle["settlementEvidence"][0]["contentHash"],
            draft_evidence_hash,
        )
        self.assertEqual(
            final_bundle["settlementEvidence"][0]["contentHash"],
            final_evidence_hash,
        )
        self.assertEqual(
            final_bundle["phaseSummary"][0]["attestationRef"]["contentHash"],
            final_evidence_hash,
        )

    def test_unsigned_artifact_semantics_change_only_at_the_source_and_propagation_sites(self):
        fixture = self.data["fixture"]
        self.assertEqual(
            diff_paths(fixture["draftEvidence"], fixture["finalEvidence"]),
            {"paymentTxRefs[0].txHash"},
        )
        self.assertEqual(
            diff_paths(fixture["draftBundle"], fixture["finalBundle"]),
            {
                "phaseSummary[0].attestationRef.contentHash",
                "phaseSummary[0].txRefs[0].txHash",
                "settlementEvidence[0].contentHash",
            },
        )
        self.assertEqual(
            fixture["draftBundle"]["agreementRef"],
            fixture["finalBundle"]["agreementRef"],
        )
        self.assertEqual(
            [party["bundleHash"] for party in fixture["draftBundle"]["parties"]],
            [party["bundleHash"] for party in fixture["finalBundle"]["parties"]],
        )

    def test_all_acceptance_and_rejection_paths_are_executed(self):
        required = set(self.data["requiredChangedPaths"])
        allowed = set(self.data["allowedChangedPaths"])
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                verdict, errors = evaluate_vector(vector, required, allowed)
                self.assertEqual(verdict, vector["expected"])
                if verdict == "pass":
                    self.assertEqual(errors, [])
                else:
                    self.assertTrue(errors)

    def test_normative_rules_and_conformance_hook_are_present(self):
        spec = SPEC.read_text(encoding="utf-8")
        for rule in ("FP-1", "FP-2", "FP-3", "FP-4"):
            self.assertIn(f"({rule})", spec)
        self.assertIn("It MUST NOT require that only the bytes of `SettlementEvidence` differ.", spec)
        self.assertIn("settlement-finalization-propagation-v0.3.json", PLAN.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
