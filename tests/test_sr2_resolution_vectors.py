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
    evaluate_bootstrap,
    evaluate_resolution,
    evaluate_vector,
    hash_hex,
)
from generate_sr2_resolution_vectors import (  # noqa: E402
    OLD_SEED,
    BOOTSTRAP_DOMAIN,
    sign_descriptor,
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
CORE = ROOT / "spec" / "CORE.md"
DACS1 = ROOT / "spec" / "DACS-1-IDENTIFY.md"
DACS2 = ROOT / "spec" / "DACS-2-VET.md"
DACS4 = ROOT / "spec" / "DACS-4-SETTLE.md"
DACS5 = ROOT / "spec" / "DACS-5-VERIFY.md"
PROFILE = ROOT / "spec" / "PROFILE.md"


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

    def test_candidate_profile_metadata_is_explicit_and_consistent(self):
        expected_versions = {
            "core": "0.3",
            "dacs1": "0.8",
            "dacs2": "0.6",
            "dacs3": "0.6",
            "dacs4": "0.8",
            "dacs5": "0.6",
        }
        for document in self.documents:
            fixture = document["syntheticProfileAdmissionFixture"]
            self.assertEqual(fixture["moduleVersions"], expected_versions)
            self.assertEqual(
                fixture["implementationOwnedReleasePin"],
                "0000000000000000000000000000000000000001",
            )
            self.assertIn("candidate conformance fixture only", fixture["scope"])

        manifest = json.loads((ROOT / "conformance" / "MANIFEST.json").read_text(encoding="utf-8"))
        manifest_fixture = manifest["syntheticProfileAdmissionFixture"]
        self.assertEqual(manifest_fixture["moduleVersions"], expected_versions)
        self.assertEqual(
            manifest_fixture["implementationOwnedReleasePin"],
            "0000000000000000000000000000000000000001",
        )

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

    def test_optional_evidence_extension_is_forward_readable(self):
        # mj-deving/cX3po finding 1: an additive future member in
        # AnchorReceipt.evidence must not fail closed when the independent
        # verifier result repeats the complete extended record and the
        # descriptor is re-signed and re-pinned.
        vector = copy.deepcopy(self.vectors["valid-recipe-registry-root"])
        case = vector["input"]
        receipt = case["descriptors"][0]["indexAnchorReceipt"]
        pre_extension_hash = hash_hex(receipt)
        receipt["evidence"]["futureHint"] = "forward-compatible"
        case["verifiedReceiptEvidence"] = [{
            "evidence": copy.deepcopy(receipt["evidence"]),
            "receiptHash": hash_hex(receipt),
        }]
        sign_descriptor(case["descriptors"][0], OLD_SEED, domain=BOOTSTRAP_DOMAIN)
        case["trustPin"]["descriptorHash"] = descriptor_hash(case["descriptors"][0])
        self.assertEqual(evaluate_vector(vector), "pass")

        # The optional member must be bound by complete equality on both
        # sides: a sidecar that disagrees on the extension cannot authorize.
        mismatch = copy.deepcopy(vector)
        mismatch["input"]["verifiedReceiptEvidence"][0]["evidence"]["futureHint"] = "attacker-different"
        self.assertEqual(evaluate_vector(mismatch), "indeterminate")

        # The receipt hash binds the complete extended receipt snapshot: a
        # sidecar still naming the pre-extension receipt hash cannot
        # authorize the extended receipt.
        stale_hash = copy.deepcopy(vector)
        stale_hash["input"]["verifiedReceiptEvidence"][0]["receiptHash"] = pre_extension_hash
        self.assertEqual(evaluate_vector(stale_hash), "indeterminate")

        # Required members stay required: the extension cannot replace kind/value.
        required = copy.deepcopy(vector)
        del required["input"]["descriptors"][0]["indexAnchorReceipt"]["evidence"]["kind"]
        self.assertEqual(evaluate_vector(required), "fail")

    def test_deep_runtime_input_never_leaks_host_recursion_errors(self):
        # mj-deving/cX3po finding 2: deeply nested runtime-controlled
        # descriptor/storage input must normalize RecursionError/OverflowError
        # into deterministic dispositions at the deepcopy, canonicalization,
        # and hashing boundaries. Neither entry point may raise; the wrapper's
        # guarded deepcopy makes malformed bootstrap input fail and malformed
        # resolution input indeterminate, while direct evaluation of a deep
        # snapshot keeps the unavailable-proof result indeterminate.
        def nested(depth=1200):
            value = {}
            for _ in range(depth):
                value = {"child": value}
            return value

        bootstrap = self.vectors["valid-recipe-registry-root"]
        deep_descriptor = {
            "name": "deep-descriptor-member",
            "family": "bootstrap",
            "input": {
                **copy.deepcopy(bootstrap["input"]),
                "descriptors": [
                    {**copy.deepcopy(bootstrap["input"]["descriptors"][0]),
                     "futureDeep": nested()}
                ],
            },
        }
        self.assertEqual(evaluate_vector(deep_descriptor), "fail")

        deep_storage = copy.deepcopy(bootstrap)
        native = deep_storage["input"]["descriptors"][0]["nativeIndexAddress"]
        deep_storage["input"]["indexStorage"][native] = nested()
        self.assertEqual(evaluate_vector(deep_storage), "fail")
        self.assertEqual(
            evaluate_bootstrap(deep_storage["input"]), "indeterminate"
        )

        deep_evidence = copy.deepcopy(bootstrap)
        receipt = deep_evidence["input"]["descriptors"][0]["indexAnchorReceipt"]
        receipt["evidence"]["futureDeep"] = nested()
        self.assertEqual(evaluate_vector(deep_evidence), "fail")

        resolution = self.vectors["direct-finalized-receipt-resolves"]
        deep_receipt = copy.deepcopy(resolution)
        deep_receipt["input"]["carriers"][0]["receipt"]["futureDeep"] = nested()
        self.assertEqual(evaluate_vector(deep_receipt), "indeterminate")
        # Direct evaluation of the same deep input must not raise either: the
        # iterative JCS traversal canonicalizes it and the carrier is judged
        # on its content. The wrapper's guarded deepcopy is the boundary that
        # normalizes the same depth to a fail-closed disposition.
        self.assertIn(
            evaluate_resolution(deep_receipt["input"]), {"pass", "indeterminate"}
        )

        deep_artifact = copy.deepcopy(resolution)
        deep_artifact["input"]["storage"] = {
            deep_artifact["input"]["carriers"][0]["receipt"]["nativeAddress"]: nested()
        }
        self.assertEqual(evaluate_vector(deep_artifact), "indeterminate")

    def test_extended_evidence_vectors_execute(self):
        expected = {
            "extended-evidence-optional-member-is-forward-readable": "pass",
            "extended-evidence-sidecar-must-equal-complete-record": "indeterminate",
            "extended-evidence-required-members-stay-required": "fail",
        }
        for name, verdict in expected.items():
            with self.subTest(vector=name):
                self.assertEqual(evaluate_vector(self.vectors[name]), verdict)

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

    def test_descriptor_hash_activation_is_deferred_from_existing_types(self):
        core = CORE.read_text(encoding="utf-8")
        dacs1 = DACS1.read_text(encoding="utf-8")
        dacs2 = DACS2.read_text(encoding="utf-8")
        dacs4 = DACS4.read_text(encoding="utf-8")
        dacs5 = DACS5.read_text(encoding="utf-8")
        profile = PROFILE.read_text(encoding="utf-8")

        for text in (core, dacs1, dacs2, dacs4, dacs5):
            self.assertNotIn("recipeRegistryDescriptorHash", text)
            self.assertNotIn("railRegistryDescriptorHash", text)

        for text in (dacs1, dacs2, dacs4):
            self.assertNotIn("`RegistryBootstrapDescriptor`", text)

        self.assertIn("**Activation boundary.**", core)
        self.assertIn(
            "MUST NOT claim descriptor-authenticated production or replay",
            core,
        )
        self.assertIn(
            "distinct versioned signed bundle contract",
            dacs5,
        )
        self.assertIn(
            "**not** activate its descriptor hash",
            profile,
        )
        self.assertIn(
            "authenticated snapshot's numeric version in\n"
            "   `SessionContext.railRegistryVersion`",
            dacs4,
        )
        self.assertIn("Keep `RailDefinition.railVersion`\n   distinct", dacs4)
        self.assertNotIn(
            "numeric definition version at session start under the existing\n"
            "   `railRegistryVersion` contract",
            dacs4,
        )

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
