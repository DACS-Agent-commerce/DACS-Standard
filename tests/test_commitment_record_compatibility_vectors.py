import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "commitment-record-compatibility-v0.1.json"
)


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def materialize_record(data, kind):
    legacy = deepcopy(data["fixture"]["legacyRecord"])
    finality = deepcopy(data["fixture"]["finalityRecord"])
    if kind == "legacy":
        return legacy
    if kind == "finality":
        return finality
    if kind == "both-discriminators":
        finality["dacsVersion"] = "1"
        return finality
    if kind == "neither-discriminator":
        finality.pop("finalityCommitmentVersion")
        return finality
    if kind == "finality-no-signature":
        finality.pop("signature")
        return finality
    if kind == "unsupported-finality-version":
        finality["finalityCommitmentVersion"] = "2"
        return finality
    raise AssertionError(f"unknown record fixture: {kind}")


def evaluate(data, vector):
    record = materialize_record(data, vector["record"])
    has_legacy = record.get("dacsVersion") == "1"
    has_finality = record.get("finalityCommitmentVersion") == "1"
    if has_legacy == has_finality:
        return False

    receipt = data["fixture"]["finalizedReceipt"]
    if vector["receipt"] != "finalized":
        return False
    if (
        receipt.get("observationDisposition") != "established"
        or not receipt["authenticatedEvidence"]
        or receipt["state"] != "finalized"
    ):
        return False

    if has_legacy:
        if vector["signatureDomain"] != "dacs-commitment:v1:":
            return False
        if "committedAt" not in record or "createdAt" in record or "signature" in record:
            return False
        return (
            record["committedAt"]
            == vector["usedCommittedAt"]
            == receipt["blockTimestamp"]
        )

    if vector["signatureDomain"] != "dacs-finality-commitment:v1:":
        return False
    if "createdAt" not in record or "signature" not in record or "committedAt" in record:
        return False
    return vector["usedCommittedAt"] == receipt["blockTimestamp"]


class CommitmentRecordCompatibilityVectorTests(unittest.TestCase):
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

    def test_every_compatibility_case_executes(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                actual = "pass" if evaluate(self.data, vector) else "fail"
                self.assertEqual(actual, vector["expected"])

    def test_the_two_shapes_are_structurally_disjoint(self):
        legacy = self.data["fixture"]["legacyRecord"]
        finality = self.data["fixture"]["finalityRecord"]
        self.assertIn("dacsVersion", legacy)
        self.assertNotIn("finalityCommitmentVersion", legacy)
        self.assertIn("committedAt", legacy)
        self.assertNotIn("createdAt", legacy)
        self.assertNotIn("signature", legacy)
        self.assertIn("finalityCommitmentVersion", finality)
        self.assertNotIn("dacsVersion", finality)
        self.assertIn("createdAt", finality)
        self.assertIn("signature", finality)
        self.assertNotIn("committedAt", finality)

    def test_spec_pins_both_domains_and_the_anti_coercion_rule(self):
        core = (ROOT / "spec" / "CORE.md").read_text(encoding="utf-8")
        dacs3 = (ROOT / "spec" / "DACS-3-NEGOTIATE.md").read_text(encoding="utf-8")
        self.assertIn('"dacs-commitment:v1:"', core)
        self.assertIn('"dacs-finality-commitment:v1:"', core)
        self.assertIn("(CA-9) **Minor-safe type distinction.**", dacs3)
        self.assertIn("type FinalityCommitmentRecord = {", dacs3)
        self.assertIn("New producers MUST NOT emit it.", dacs3)


if __name__ == "__main__":
    unittest.main()
