import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from sr2_resolution_reference import descriptor_hash, evaluate_vector, hash_hex  # noqa: E402


RESOLUTION = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "sr2-logical-native-resolution-v0.1.json"
)
BOOTSTRAP = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "registry-bootstrap-v0.1.json"
)
GENERATOR = ROOT / "scripts" / "generate_sr2_resolution_vectors.py"


def canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


class SR2ResolutionVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.documents = [
            json.loads(RESOLUTION.read_text(encoding="utf-8")),
            json.loads(BOOTSTRAP.read_text(encoding="utf-8")),
        ]
        cls.vectors = {
            vector["name"]: vector
            for document in cls.documents
            for vector in document["vectors"]
        }

    def test_hash_count_and_names(self):
        all_names = []
        for document in self.documents:
            vectors = document["vectors"]
            self.assertEqual(document["count"], len(vectors))
            self.assertEqual(
                document["hash"],
                hashlib.sha256(canonical_bytes(vectors)).hexdigest(),
            )
            all_names.extend(vector["name"] for vector in vectors)
        self.assertEqual(len(all_names), len(set(all_names)))

    def test_every_declared_outcome_executes(self):
        for document in self.documents:
            for vector in document["vectors"]:
                with self.subTest(vector=vector["name"]):
                    self.assertEqual(evaluate_vector(vector), vector["expected"])

    def test_generator_is_byte_deterministic(self):
        result = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_receipt_authority_is_decision_bearing(self):
        vector = copy.deepcopy(self.vectors["direct-finalized-receipt-resolves"])
        vector["input"]["carriers"][0]["authorityVerified"] = False
        self.assertEqual(evaluate_vector(vector), "indeterminate")

    def test_descriptor_signature_is_decision_bearing(self):
        vector = copy.deepcopy(self.vectors["valid-recipe-registry-root"])
        signature = vector["input"]["descriptors"][0]["authorizationSignature"]
        signature["value"] = "AA"
        self.assertEqual(evaluate_vector(vector), "fail")

    def test_unknown_member_is_hashed_not_stripped(self):
        vector = copy.deepcopy(self.vectors["signed-unknown-member-is-preserved"])
        descriptor = vector["input"]["descriptors"][0]
        descriptor["futurePolicyHint"]["mode"] = "replace"
        vector["input"]["trustPin"]["descriptorHash"] = descriptor_hash(descriptor)
        self.assertEqual(evaluate_vector(vector), "fail")

    def test_transport_order_cannot_choose_first_contact_fork(self):
        vector = copy.deepcopy(self.vectors["key-only-sequence-one-fork"])
        vector["input"]["descriptors"].reverse()
        self.assertEqual(evaluate_vector(vector), "indeterminate")

    def test_historical_replay_uses_exact_accepted_descriptor_identity(self):
        self.assertEqual(
            evaluate_vector(self.vectors["historical-replay-uses-recorded-sequence"]),
            "pass",
        )
        self.assertEqual(
            evaluate_vector(self.vectors["historical-replay-refuses-unrelated-descriptor"]),
            "indeterminate",
        )
        self.assertEqual(
            evaluate_vector(self.vectors["historical-replay-requires-descriptor-hash"]),
            "fail",
        )

    def test_candidate_classification_precedes_chain_advance(self):
        self.assertEqual(
            evaluate_vector(self.vectors["valid-and-unavailable-successors-remain-unresolved"]),
            "indeterminate",
        )
        self.assertEqual(
            evaluate_vector(self.vectors["invalid-successor-is-discarded"]),
            "pass",
        )

    def test_presence_absence_and_equivalent_carriers_are_unambiguous(self):
        self.assertEqual(
            evaluate_vector(self.vectors["authenticated-presence-and-absence-conflict"]),
            "indeterminate",
        )
        self.assertEqual(
            evaluate_vector(self.vectors["equivalent-reference-and-receipt-collapse"]),
            "pass",
        )

    def test_jcs_nfc_known_answers_are_independent_of_generator_metadata(self):
        self.assertEqual(
            hash_hex({"z": 1, "a": "e\u0301"}),
            "fb64e573f7cde5b7efeda52ffc4bdd57572055b0b7e64a70172606c82c6c7eac",
        )
        vector = copy.deepcopy(self.vectors["signed-unknown-member-is-nfc-canonical"])
        descriptor = vector["input"]["descriptors"][0]
        self.assertEqual(
            descriptor_hash(descriptor),
            "3a06d68ee4fbc7ace3c67e8c7e0a0fa1f7e05a838a16e76fd3c26c829845e882",
        )
        descriptor["futurePolicyHint"]["label"] = "é"
        self.assertEqual(evaluate_vector(vector), "pass")
        with self.assertRaises(ValueError):
            hash_hex({"unsafe": 9007199254740992})
        with self.assertRaises(ValueError):
            hash_hex({"unsafe": 1.5})


if __name__ == "__main__":
    unittest.main()
