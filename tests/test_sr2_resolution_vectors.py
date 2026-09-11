import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from sr2_resolution_reference import (  # noqa: E402
    _basic_descriptor,
    _valid_index_snapshot,
    _verify_snapshot,
    descriptor_hash,
    evaluate_vector,
    hash_hex,
)


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
DACS2 = ROOT / "spec" / "DACS-2-VET.md"


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

    def test_invalid_root_is_discarded_before_first_contact_cardinality(self):
        self.assertEqual(
            evaluate_vector(
                self.vectors["invalid-key-pinned-root-sibling-is-discarded"]
            ),
            "pass",
        )

    def test_transport_copy_permutations_preserve_classified_identity(self):
        expected = {
            "invalid-first-root-copy-cannot-suppress-valid-identity": "pass",
            "invalid-first-root-copy-cannot-suppress-unresolved-identity": "indeterminate",
            "invalid-first-successor-copy-cannot-suppress-valid-identity": "pass",
            "invalid-first-successor-copy-cannot-suppress-unresolved-identity": "indeterminate",
        }
        for name, verdict in expected.items():
            with self.subTest(vector=name, order="invalid-first"):
                self.assertEqual(evaluate_vector(self.vectors[name]), verdict)
            reversed_vector = copy.deepcopy(self.vectors[name])
            reversed_vector["input"]["descriptors"].reverse()
            with self.subTest(vector=name, order="reversed"):
                self.assertEqual(evaluate_vector(reversed_vector), verdict)

    def test_receipt_copy_identity_and_delivery_are_order_independent(self):
        expected = {
            "timely-identical-receipt-survives-late-redelivery": "pass",
            "all-identical-receipt-copies-arrive-late": "fail",
            "unequal-lifecycle-snapshots-remain-unordered": "indeterminate",
        }
        for name, verdict in expected.items():
            with self.subTest(vector=name, order="generated"):
                self.assertEqual(evaluate_vector(self.vectors[name]), verdict)
            reversed_vector = copy.deepcopy(self.vectors[name])
            reversed_vector["input"]["carriers"].reverse()
            with self.subTest(vector=name, order="reversed"):
                self.assertEqual(evaluate_vector(reversed_vector), verdict)

    def test_invalid_receipt_copy_is_discarded_before_snapshot_identity(self):
        vector = copy.deepcopy(self.vectors["direct-finalized-receipt-resolves"])
        invalid = copy.deepcopy(vector["input"]["carriers"][0])
        invalid["receipt"]["state"] = []
        vector["input"]["carriers"].insert(0, invalid)
        self.assertEqual(evaluate_vector(vector), "pass")

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
        self.assertEqual(
            evaluate_vector(
                self.vectors[
                    "historical-mode-validates-but-does-not-apply-stored-latest"
                ]
            ),
            "pass",
        )
        self.assertEqual(
            evaluate_vector(
                self.vectors["historical-mode-rejects-malformed-stored-latest"]
            ),
            "fail",
        )

    def test_expected_registry_tuple_is_independent_closed_configuration(self):
        valid = copy.deepcopy(self.vectors["valid-recipe-registry-root"])
        expected = valid["input"]["expectedRegistryTuple"]
        self.assertEqual(
            set(expected),
            {
                "registryKind",
                "registryLogicalAddress",
                "substrate",
                "registryBootstrapVersion",
            },
        )
        self.assertNotIn("expectedRegistryTuple", valid["input"]["descriptors"][0])
        for name in (
            "missing-expected-registry-tuple-is-rejected",
            "expected-registry-tuple-is-closed",
            "expected-registry-tuple-substrate-is-nonempty",
            "expected-registry-tuple-must-match-root",
        ):
            with self.subTest(vector=name):
                self.assertEqual(evaluate_vector(self.vectors[name]), "fail")

    def test_mode_and_context_containers_fail_closed_without_exceptions(self):
        for name in (
            "explicit-null-mode-is-rejected",
            "unsupported-mode-is-rejected",
            "malformed-verified-evidence-context-is-rejected",
        ):
            with self.subTest(vector=name):
                self.assertEqual(evaluate_vector(self.vectors[name]), "fail")

        resolution_mutations = {
            "carrier kind": lambda c: c["carriers"][0].update({"kind": []}),
            "receipt state": lambda c: c["carriers"][0]["receipt"].update(
                {"state": []}
            ),
            "minimum state": lambda c: c.update({"minimumState": []}),
            "storage": lambda c: c.update({"storage": []}),
        }
        for label, mutate in resolution_mutations.items():
            vector = copy.deepcopy(self.vectors["direct-finalized-receipt-resolves"])
            mutate(vector["input"])
            with self.subTest(context=label):
                self.assertEqual(evaluate_vector(vector), "indeterminate")

        reference = copy.deepcopy(
            self.vectors["authenticated-registry-index-reference-dereferences"]
        )
        reference["input"]["carriers"][0]["surface"] = []
        self.assertEqual(evaluate_vector(reference), "indeterminate")

        bootstrap = copy.deepcopy(self.vectors["valid-recipe-registry-root"])
        bootstrap["input"]["storedLatest"] = None
        self.assertEqual(evaluate_vector(bootstrap), "fail")

        bootstrap = copy.deepcopy(self.vectors["valid-recipe-registry-root"])
        bootstrap["input"]["indexStorage"] = []
        self.assertEqual(evaluate_vector(bootstrap), "fail")

        definition = copy.deepcopy(
            self.vectors["authenticated-index-definition-reference"]
        )
        definition["input"]["definitionChecks"] = []
        self.assertEqual(evaluate_vector(definition), "fail")

    def test_bootstrap_receipt_completeness_precedes_nested_access(self):
        vector = copy.deepcopy(self.vectors["valid-recipe-registry-root"])
        case = vector["input"]
        descriptor = case["descriptors"][0]
        malformed = {
            "transactionRef": 1.5,
            "writer": [],
            "state": [],
            "evidence": [],
            "blockRef": {"height": "42000"},
            "finalityProfile": "",
        }
        for field, value in malformed.items():
            candidate = copy.deepcopy(descriptor)
            candidate["indexAnchorReceipt"][field] = value
            with self.subTest(field=field):
                self.assertEqual(_verify_snapshot(candidate, case), "fail")

    def test_independent_receipt_verifier_results_are_exactly_bound(self):
        vector = copy.deepcopy(self.vectors["valid-recipe-registry-root"])
        case = vector["input"]
        receipt = case["descriptors"][0]["indexAnchorReceipt"]
        self.assertEqual(case["verifiedReceiptEvidence"], [{
            "evidence": receipt["evidence"], "receiptHash": hash_hex(receipt)
        }])
        self.assertEqual(evaluate_vector(vector), "pass")
        for field, value in (
            ("receiptHash", "cd" * 32),
            ("evidence", {"kind": "other-proof", "value": receipt["evidence"]["value"]}),
        ):
            candidate = copy.deepcopy(vector)
            candidate["input"]["verifiedReceiptEvidence"][0][field] = value
            with self.subTest(field=field):
                self.assertEqual(evaluate_vector(candidate), "indeterminate")
        malformed = copy.deepcopy(vector)
        malformed["input"]["verifiedReceiptEvidence"][0]["receiptHash"] = []
        self.assertEqual(evaluate_vector(malformed), "fail")

    def test_descriptor_and_index_scalar_guards_are_total(self):
        vector = copy.deepcopy(self.vectors["valid-recipe-registry-root"])
        descriptor = vector["input"]["descriptors"][0]
        for field, value in (
            ("registryKind", []),
            ("indexContentHash", []),
            ("authorityKeyId", []),
            ("revokedAuthorityKeyIds", [["key"]]),
        ):
            candidate = copy.deepcopy(descriptor)
            candidate[field] = value
            with self.subTest(descriptor_field=field):
                self.assertFalse(_basic_descriptor(candidate))

        snapshot = copy.deepcopy(
            vector["input"]["indexStorage"][descriptor["nativeIndexAddress"]]
        )
        snapshot["entries"] = [
            {
                "id": "sample",
                "version": 1,
                "anchor": {"kind": [], "locator": "demos:storage:sample"},
                "contentHash": "ab" * 32,
            }
        ]
        self.assertFalse(_valid_index_snapshot(snapshot, descriptor))

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

    def test_malformed_receipt_and_unsafe_definition_return_dispositions(self):
        for name in (
            "malformed-number-transaction-ref-is-discarded",
            "unhashable-native-address-is-discarded",
            "non-numeric-delivery-time-is-discarded",
        ):
            with self.subTest(vector=name):
                self.assertEqual(evaluate_vector(self.vectors[name]), "indeterminate")
        oversized_time = copy.deepcopy(
            self.vectors["direct-finalized-receipt-resolves"]
        )
        oversized_time["input"]["carriers"][0]["deliveredAt"] = 10**1000
        self.assertEqual(evaluate_vector(oversized_time), "indeterminate")
        self.assertEqual(
            evaluate_vector(self.vectors["unsafe-integer-in-definition-is-rejected"]),
            "fail",
        )

    def test_only_normative_authenticated_reference_surfaces_are_admitted(self):
        self.assertEqual(
            evaluate_vector(
                self.vectors[
                    "unrecognized-authenticated-reference-surface-is-discarded"
                ]
            ),
            "indeterminate",
        )

    def test_finite_fraction_is_valid_only_when_authenticated(self):
        self.assertEqual(
            evaluate_vector(self.vectors["unsigned-fraction-member-invalidates-root"]),
            "fail",
        )
        self.assertEqual(
            evaluate_vector(
                self.vectors["signed-fraction-in-unknown-member-is-canonical"]
            ),
            "pass",
        )

    def test_crq1_replay_names_the_complete_pa2_pin(self):
        text = DACS2.read_text(encoding="utf-8")
        self.assertIn(
            "exact `(recipeRegistryVersion, recipeRegistryDescriptorHash)` pair",
            text,
        )
        self.assertIn("numeric version alone is the PA-1 form", text)

    def test_reference_surface_authority_is_closed_and_class_specific(self):
        expected = {
            "finalized-bundle-reference-dereferences": "pass",
            "authenticated-registry-index-reference-dereferences": "pass",
            "unrecognized-authenticated-reference-surface-is-discarded": "indeterminate",
            "finalized-bundle-reference-requires-class-checks": "indeterminate",
            "registry-reference-requires-class-checks": "indeterminate",
        }
        for name, verdict in expected.items():
            with self.subTest(vector=name):
                self.assertEqual(evaluate_vector(self.vectors[name]), verdict)

    def test_persisted_branch_snapshot_shape_and_root_classification(self):
        expected = {
            "persisted-branch-must-be-ancestor-of-latest": "indeterminate",
            "snapshot-version-is-bound": "fail",
            "snapshot-kind-is-bound": "fail",
            "snapshot-revision-is-bound-to-sequence": "fail",
            "snapshot-entry-schema-is-validated": "fail",
            "snapshot-envelope-is-closed": "fail",
            "snapshot-entry-is-closed": "fail",
            "snapshot-entry-anchor-is-closed": "fail",
            "invalid-same-key-root-cannot-suppress-valid-root": "pass",
            "duplicate-root-transport-copy-collapses": "pass",
            "duplicate-successor-transport-copy-collapses": "pass",
        }
        for name, verdict in expected.items():
            with self.subTest(vector=name):
                self.assertEqual(evaluate_vector(self.vectors[name]), verdict)

    def test_canonicalization_failures_never_escape_the_evaluator(self):
        expected = {
            "fractional-unknown-in-transaction-ref-is-canonical": "pass",
            "unsafe-number-in-transaction-ref-is-discarded": "indeterminate",
            "fractional-unknown-in-definition-is-canonical": "pass",
            "unsafe-integer-in-definition-is-rejected": "fail",
            "signed-fraction-in-unknown-member-is-canonical": "pass",
            "unsafe-integer-in-unknown-member-is-rejected": "fail",
        }
        for name, verdict in expected.items():
            with self.subTest(vector=name):
                self.assertEqual(evaluate_vector(self.vectors[name]), verdict)

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
        self.assertEqual(
            hash_hex({"safe": 0.5}),
            "3fe4ea34236b064b37a43082de46db8c7ccb0076b96916a74b0dc6cc48320506",
        )
        self.assertEqual(
            hash_hex({"unsafe": 1.5}),
            "3390e768e77aa39ea7a95540e416758b209f6b61f057257be66b9c073296533d",
        )


if __name__ == "__main__":
    unittest.main()
