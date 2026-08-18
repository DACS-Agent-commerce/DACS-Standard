import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from sr2_resolution_reference import descriptor_hash, evaluate_vector  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
