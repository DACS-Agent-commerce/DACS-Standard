"""Standalone positive composition coverage for #391 with current admission."""

import copy
import hashlib
import unittest

import dacs5_reference as R
from scripts import generate_current_use_reputation_vectors as fixture_support


JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
WINDOW_START = 0
WINDOW_END = 2_000_000_000_000


class _DependencyBomb(dict):
    def get(self, *_args, **_kwargs):  # pragma: no cover - called only on regression
        raise AssertionError("dependency resolved before current JID admission")


class Pr391CurrentUseIntegrationTests(unittest.TestCase):
    def _binding(self, factory, bundle, role, logical_address, label):
        binding = {
            "bindingVersion": "1",
            "jobId": JOB_ID,
            "role": role,
            "logicalAddress": logical_address,
            "nativeAddress": "native-" + hashlib.sha256(label.encode("ascii")).hexdigest(),
            "bundleContentHash": R.bundle_hash(bundle),
            "signer": fixture_support.CLAIMS[role],
            "signature": {},
        }
        factory.sign_bundle_binding(binding, role)
        return binding

    def _fixture(self):
        factory = fixture_support.CurrentUseFixtureFactory()
        checkpoint = factory.checkpoint(
            fixture_support.WRITE_SUBSTRATE, write_input=True)
        listing = factory._historical_listing()
        role_map = {
            "buyer": fixture_support.CLAIMS["buyer"],
            "seller": fixture_support.CLAIMS["seller"],
        }
        factory.config["partyRolesByJob"][JOB_ID] = copy.deepcopy(role_map)

        trusted_context = R.trusted_current_context(
            [
                R.trusted_role_authority(JOB_ID, role, identity)
                for role, identity in role_map.items()
            ],
            query=R.trusted_query_authority(
                role_map["buyer"], WINDOW_START, WINDOW_END, "finalisedAt"),
        )
        current_keys = R.trusted_verification_keys(
            copy.deepcopy(factory.config["publicKeys"]))
        # Current key capability is supplied separately; this raw compatibility
        # field must not be capable of authorizing the operation by itself.
        factory.config["publicKeys"] = {}

        roles = {}
        for role_index, role in enumerate(("buyer", "seller")):
            bundle = factory._legacy_bundle(JOB_ID, role, listing)
            digest = R.bundle_hash(bundle)
            factory.dependencies["bundleAuthorityByContentHash"][digest] = {
                "listing": copy.deepcopy(listing),
            }

            legacy_logical = R.legacy_logical_address(JOB_ID, role)
            legacy_binding = self._binding(
                factory, bundle, role, legacy_logical,
                "canonical-historical:" + role)
            factory.dependencies["bundlesByNativeAddress"][
                legacy_binding["nativeAddress"]] = bundle
            historical_receipt = factory.anchor_proof(
                purpose="historical-bundle",
                substrate=fixture_support.WRITE_SUBSTRATE,
                subject_id=JOB_ID,
                subject_role=role,
                logical=legacy_logical,
                native=legacy_binding["nativeAddress"],
                content_hash=digest,
                transaction="fixture-canonical-historical-" + role,
                writer=role_map[role],
                nonce=10 + role_index,
                height=90,
                index=role_index,
            )
            era = {
                "bundleContentHash": digest,
                "resolvedJobId": JOB_ID,
                "resolvedRole": role,
                "substrate": fixture_support.WRITE_SUBSTRATE,
                "checkpointCandidates": copy.deepcopy(checkpoint["candidates"]),
                "checkpointReceipt": copy.deepcopy(checkpoint["receipt"]),
                "historicalAnchorReceipt": historical_receipt,
                "originalMapping": {
                    "kind": "binding",
                    "binding": copy.deepcopy(legacy_binding),
                    "selectionContext": {
                        "candidateBindings": [copy.deepcopy(legacy_binding)],
                        "partyMap": {
                            identity: mapped_role
                            for mapped_role, identity in role_map.items()
                        },
                        "budget": 8,
                    },
                    "anchorTransaction": historical_receipt["transactionRef"],
                    "writer": historical_receipt["writer"],
                    "nonce": historical_receipt["nonce"],
                },
            }

            current_logical = R.logical_address(
                JOB_ID, role, trusted_contexts=trusted_context)
            current_binding = self._binding(
                factory, bundle, role, current_logical,
                "canonical-current:" + role)
            self.assertNotEqual(
                legacy_binding["nativeAddress"], current_binding["nativeAddress"])
            factory.dependencies["bundlesByNativeAddress"][
                current_binding["nativeAddress"]] = bundle
            current_receipt = factory.anchor_proof(
                purpose="current-bundle",
                substrate=fixture_support.WRITE_SUBSTRATE,
                subject_id=JOB_ID,
                subject_role=role,
                logical=current_logical,
                native=current_binding["nativeAddress"],
                content_hash=digest,
                transaction="fixture-canonical-current-" + role,
                writer=role_map[role],
                nonce=30 + role_index,
                height=110,
                index=role_index,
            )
            roles[role] = {
                "disposition": "present",
                "mappingKind": "binding",
                "selectionContext": {
                    "candidateBindings": [current_binding],
                    "partyMap": {
                        identity: mapped_role
                        for mapped_role, identity in role_map.items()
                    },
                    "budget": 8,
                },
                "anchorReceiptsByNativeAddress": {
                    current_binding["nativeAddress"]: current_receipt,
                },
                "legacyEraEvidenceByNativeAddress": {
                    current_binding["nativeAddress"]: era,
                },
            }

        request = {
            "jobId": JOB_ID,
            "substrate": fixture_support.WRITE_SUBSTRATE,
            "roles": roles,
        }
        return factory, request, current_keys, trusted_context

    def test_current_use_fixture_source_constructs_canonical_independent_jobs(self):
        factory = fixture_support.CurrentUseFixtureFactory()
        historical = factory.historical_job(
            fixture_support.HISTORICAL_BINDING_JOB_ID, pure=False
        )
        finality, _expectation = factory.current_finality_job("block-depth", 0)
        trusted_context = factory.current_authority(
            fixture_support.CLAIMS["buyer"], (WINDOW_START, WINDOW_END)
        )

        for request in (historical, finality):
            self.assertEqual(
                request["jobId"], R.validate_current_job_id(request["jobId"])
            )
        self.assertEqual(
            fixture_support.CURRENT_FINALITY_JOB_IDS["block-depth"],
            finality["jobId"],
        )

        role_request = historical["roles"]["buyer"]
        current_binding = role_request["selectionContext"][
            "candidateBindings"
        ][0]
        current_native = current_binding["nativeAddress"]
        era = role_request["legacyEraEvidenceByNativeAddress"][current_native]
        historical_binding = era["originalMapping"]["binding"]
        self.assertNotEqual(
            historical_binding["nativeAddress"], current_native
        )
        self.assertEqual(
            R.legacy_logical_address(historical["jobId"], "buyer"),
            historical_binding["logicalAddress"],
        )
        self.assertEqual(
            R.logical_address(
                historical["jobId"],
                "buyer",
                trusted_contexts=trusted_context,
            ),
            current_binding["logicalAddress"],
        )

        result = R.derive_current_use_replayable(
            fixture_support.CLAIMS["buyer"],
            [historical, finality],
            WINDOW_START,
            WINDOW_END,
            factory.dependencies,
            factory.config,
            pubkeys=factory.current_keys,
            trusted_contexts=trusted_context,
        )
        self.assertEqual("pass", result["decision"], result["reason"])
        replay = R.replay_current_use_derivation(
            result["derivation"],
            factory.dependencies,
            factory.config,
            pubkeys=factory.current_keys,
            trusted_contexts=trusted_context,
        )
        self.assertTrue(replay["ok"], replay["reason"])

        finality_factory = fixture_support.FixtureFactory()
        archival = finality_factory.strong_bundle_case("block-depth")
        explicit = finality_factory.strong_bundle_case(
            "block-depth",
            job_id=fixture_support.CURRENT_FINALITY_JOB_IDS["block-depth"],
        )
        archival_again = finality_factory.strong_bundle_case("block-depth")
        self.assertEqual(
            "FV-392-block-depth", archival["bundle"]["jobId"]
        )
        self.assertEqual(archival, archival_again)
        self.assertEqual(
            fixture_support.CURRENT_FINALITY_JOB_IDS["block-depth"],
            explicit["bundle"]["jobId"],
        )

    def test_canonical_historical_type_uses_separate_current_and_legacy_gates(self):
        factory, request, current_keys, trusted_context = self._fixture()
        result = R.derive_current_use_replayable(
            fixture_support.CLAIMS["buyer"],
            [request],
            WINDOW_START,
            WINDOW_END,
            factory.dependencies,
            factory.config,
            pubkeys=current_keys,
            trusted_contexts=trusted_context,
        )
        self.assertEqual("pass", result["decision"], result["reason"])
        self.assertEqual(1, result["derivation"]["bundleCount"])
        self.assertEqual(
            "legacy", result["derivation"]["resolutionContext"][0]["bundleType"])

        replay = R.replay_current_use_derivation(
            result["derivation"],
            factory.dependencies,
            factory.config,
            pubkeys=current_keys,
            trusted_contexts=trusted_context,
        )
        self.assertTrue(replay["ok"], replay["reason"])
        self.assertEqual(result["derivation"], replay["replayed"])

    def test_current_pointer_composes_profile_gate_with_finality_authority(self):
        factory, request, current_keys, trusted_context = self._fixture()
        role = "buyer"
        current_binding = request["roles"][role]["selectionContext"][
            "candidateBindings"][0]
        bundle = copy.deepcopy(factory.dependencies["bundlesByNativeAddress"][
            current_binding["nativeAddress"]])
        bundle.pop("bundleVersion")
        bundle["finalityBoundEvidenceFaultBundleVersion"] = "1"
        bundle["outcome"] = "aborted-by-self"
        bundle["faultedParty"] = role
        bundle["signatures"] = []
        factory.finality.sign_bundle(
            bundle, fixture_support.FINALITY_BUNDLE_DOMAIN)
        digest = R.bundle_hash(bundle)
        pointer = {
            "finalityBoundEvidenceFaultBundleVersion": "1",
            "pointerKind": "extended",
            "fullBundleUrl": "https://fixtures.example/canonical-finality-bundle",
            "fullBundleContentHash": digest,
            "signature": {},
        }
        pointer["signature"] = {
            "signer": fixture_support.CLAIMS[role],
            "algorithm": "ed25519",
            "value": factory._sign(
                factory.finality.keys[role],
                R.FINALITY_BOUND_EVIDENCE_FAULT_POINTER_DOMAIN,
                R.pointer_hash(pointer),
            ),
        }
        listing = next(iter(
            factory.dependencies["bundleAuthorityByContentHash"].values()
        ))["listing"]
        authority = {
            "listing": listing,
            "referenceValidationByCanonicalRef": {},
            "bundleLifecycle": {"state": "included"},
            "sessionExecutionAuthorityByPhaseKey": {},
            "verifiedReceiptByCanonicalRef": {},
            "finalityVerificationByCanonicalRef": {},
            "finalityTrust": {},
        }
        result = R.resolve_absolute_fault_pointer(
            pointer,
            bundle,
            pubkeys=current_keys,
            finality_bound_authority=authority,
            trusted_contexts=trusted_context,
            expected_jobid=JOB_ID,
            expected_role=role,
        )
        self.assertTrue(result["ok"], result["reason"])

    def test_canonical_finality_type_enters_current_use_consumer(self):
        factory, request, current_keys, trusted_context = self._fixture()
        listing = next(iter(
            factory.dependencies["bundleAuthorityByContentHash"].values()
        ))["listing"]
        role_map = factory.config["partyRolesByJob"][JOB_ID]
        roles = {}
        for role_index, role in enumerate(("buyer", "seller")):
            bundle = factory._legacy_bundle(JOB_ID, role, listing)
            bundle.pop("bundleVersion")
            bundle["finalityBoundEvidenceFaultBundleVersion"] = "1"
            bundle["faultedParty"] = "seller"
            bundle["signatures"] = []
            factory.finality.sign_bundle(
                bundle, fixture_support.FINALITY_BUNDLE_DOMAIN)
            digest = R.bundle_hash(bundle)
            factory.dependencies["bundleAuthorityByContentHash"][digest] = {
                "listing": copy.deepcopy(listing),
                "referenceValidationByCanonicalRef": {},
                "bundleLifecycle": {"state": "included"},
                "sessionExecutionAuthorityByPhaseKey": {},
                "verifiedReceiptByCanonicalRef": {},
                "finalityVerificationByCanonicalRef": {},
            }
            logical = R.logical_address(
                JOB_ID, role, trusted_contexts=trusted_context)
            binding = self._binding(
                factory, bundle, role, logical,
                "canonical-finality-current:" + role)
            factory.dependencies["bundlesByNativeAddress"][
                binding["nativeAddress"]] = bundle
            receipt = factory.anchor_proof(
                purpose="current-bundle",
                substrate=fixture_support.WRITE_SUBSTRATE,
                subject_id=JOB_ID,
                subject_role=role,
                logical=logical,
                native=binding["nativeAddress"],
                content_hash=digest,
                transaction="fixture-canonical-finality-current-" + role,
                writer=role_map[role],
                nonce=50 + role_index,
                height=120,
                index=role_index,
            )
            roles[role] = {
                "disposition": "present",
                "mappingKind": "binding",
                "selectionContext": {
                    "candidateBindings": [binding],
                    "partyMap": {
                        identity: mapped_role
                        for mapped_role, identity in role_map.items()
                    },
                    "budget": 8,
                },
                "anchorReceiptsByNativeAddress": {
                    binding["nativeAddress"]: receipt,
                },
                "legacyEraEvidenceByNativeAddress": {},
            }
        request["roles"] = roles

        result = R.derive_current_use_replayable(
            role_map["buyer"], [request], WINDOW_START, WINDOW_END,
            factory.dependencies, factory.config, pubkeys=current_keys,
            trusted_contexts=trusted_context,
        )
        self.assertEqual("pass", result["decision"], result["reason"])
        self.assertEqual(
            "finality-bound",
            result["derivation"]["resolutionContext"][0]["bundleType"],
        )
        replay = R.replay_current_use_derivation(
            result["derivation"], factory.dependencies, factory.config,
            pubkeys=current_keys, trusted_contexts=trusted_context,
        )
        self.assertTrue(replay["ok"], replay["reason"])

    def test_noncanonical_archival_label_is_not_a_current_job(self):
        context = R.trusted_current_context(
            [
                R.trusted_role_authority(
                    "CUR-HIST-BINDING", role, fixture_support.CLAIMS[role])
                for role in ("buyer", "seller")
            ],
            query=R.trusted_query_authority(
                fixture_support.CLAIMS["buyer"], 0, 1, "finalisedAt"),
        )
        keys = R.trusted_verification_keys({
            identity: b"\x01" * 32
            for identity in (
                fixture_support.CLAIMS["buyer"],
                fixture_support.CLAIMS["seller"],
            )
        })
        result = R.derive_current_use_replayable(
            fixture_support.CLAIMS["buyer"],
            [{"jobId": "CUR-HIST-BINDING", "substrate": "archive", "roles": {}}],
            0,
            1,
            _DependencyBomb(),
            {"partyRolesByJob": {}},
            pubkeys=keys,
            trusted_contexts=context,
        )
        self.assertEqual("error", result["decision"])
        self.assertIn("job-id-validation", result["reason"])
        self.assertIsNone(result["derivation"])

    def test_party_roles_cannot_mint_current_profile_authority(self):
        role_map = {
            "buyer": fixture_support.CLAIMS["buyer"],
            "seller": fixture_support.CLAIMS["seller"],
        }
        context = R.trusted_current_context(
            [
                R.trusted_role_authority(JOB_ID, role, identity)
                for role, identity in role_map.items()
            ],
            query=R.trusted_query_authority(
                role_map["buyer"], 0, 1, "finalisedAt"),
        )
        keys = R.trusted_verification_keys({
            identity: b"\x02" * 32 for identity in role_map.values()
        })
        request = {
            "jobId": JOB_ID,
            "substrate": "fixture",
            "roles": {"buyer": {}, "seller": {}},
        }
        reversed_roles = {
            "buyer": role_map["seller"],
            "seller": role_map["buyer"],
        }
        mismatch = R.derive_current_use_replayable(
            role_map["buyer"], [request], 0, 1, _DependencyBomb(),
            {"partyRolesByJob": {JOB_ID: reversed_roles}},
            pubkeys=keys, trusted_contexts=context,
        )
        self.assertEqual("fail", mismatch["decision"])
        self.assertIn("differs from authenticated role authority", mismatch["reason"])

        untrusted = R.derive_current_use_replayable(
            role_map["buyer"], [request], 0, 1, _DependencyBomb(),
            {"partyRolesByJob": {JOB_ID: role_map}},
            pubkeys=keys, trusted_contexts=None,
        )
        self.assertEqual("indeterminate", untrusted["decision"])
        self.assertIn("current-profile-admission", untrusted["reason"])


if __name__ == "__main__":
    unittest.main()
