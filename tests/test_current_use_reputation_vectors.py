from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
for path in (str(ROOT), str(ROOT / "tests"), str(ROOT / "scripts")):
    if path not in sys.path:
        sys.path.insert(0, path)

import generate_current_use_reputation_vectors as generator  # noqa: E402
from dacs5_reference import (  # noqa: E402
    BUNDLE_DOMAIN,
    CURRENT_USE_SYNTHETIC_ANCHOR_PROOF_DOMAIN,
    CURRENT_USE_SYNTHETIC_SETTLEMENT_BINDING_PROOF_DOMAIN,
    LEGACY_BUNDLE_CHECKPOINT_BINDING_DOMAIN,
    _current_use_roster_matches_role_map,
    _current_use_sb2_conflict,
    _current_use_settlement_tx_ids,
    _validate_current_use_historical_nonpayment,
    bundle_hash,
    current_use_synthetic_proof_hash,
    derive,
    derive_current_use_replayable,
    derive_job_bound,
    legacy_checkpoint_binding_hash,
    legacy_logical_address,
    logical_address,
    replay_current_use_derivation,
    replay_receipt,
    require_current_use_replayable_derivation,
    require_replayable_derivation,
    validate_legacy_bundle_admission,
)


VECTORS = ROOT / "conformance/vectors/security/current-use-reputation-v1.json"
GENERATOR = ROOT / "scripts/generate_current_use_reputation_vectors.py"


class _Bomb(dict):
    def get(self, *_args, **_kwargs):  # pragma: no cover - called only on a gate regression
        raise AssertionError("dependency dereferenced before discriminator refusal")


class CurrentUseReputationVectorTests(unittest.TestCase):
    def setUp(self):
        self.factory = generator.CurrentUseFixtureFactory()
        self.party = generator.CLAIMS["buyer"]
        self.window = generator.FIXTURE_QUERY_WINDOW
        self.current_keys = self.factory.current_keys
        self.current_context = self.factory.current_authority(
            self.party, self.window
        )
        self.fixture = self.factory.build()

    def derive(self, requests):
        return derive_current_use_replayable(
            self.party,
            requests,
            *self.window,
            self.fixture["dependencies"],
            self.fixture["verifierConfig"],
            pubkeys=self.current_keys,
            trusted_contexts=self.current_context,
        )

    def _resign_anchor(self, proof, *, repin=True):
        proof["signature"] = {
            "signer": generator.NATIVE_AUTHORITY,
            "algorithm": "ed25519",
            "value": self.factory._sign(
                self.factory.native_key,
                CURRENT_USE_SYNTHETIC_ANCHOR_PROOF_DOMAIN,
                current_use_synthetic_proof_hash(proof),
            ),
        }
        if repin:
            key = ":".join((
                proof["substrate"], proof["purpose"], proof["subjectId"],
                proof["subjectRole"], proof["nativeAddress"],
            ))
            self.fixture["verifierConfig"]["pinnedSyntheticAnchorProofHashBySubject"][key] = (
                current_use_synthetic_proof_hash(proof)
            )

    def _resign_checkpoint_binding(self, binding):
        binding["signature"] = {
            "signer": generator.CLAIMS["steward"],
            "algorithm": "ed25519",
            "value": self.factory._sign(
                self.factory.finality.keys["steward"],
                LEGACY_BUNDLE_CHECKPOINT_BINDING_DOMAIN,
                legacy_checkpoint_binding_hash(binding),
            ),
        }

    def _resign_settlement_binding(self, proof):
        proof["signature"] = {
            "signer": generator.NATIVE_AUTHORITY,
            "algorithm": "ed25519",
            "value": self.factory._sign(
                self.factory.native_key,
                CURRENT_USE_SYNTHETIC_SETTLEMENT_BINDING_PROOF_DOMAIN,
                current_use_synthetic_proof_hash(proof),
            ),
        }

    @staticmethod
    def _binding_era(request, role="buyer"):
        role_request = request["roles"][role]
        native = role_request["selectionContext"]["candidateBindings"][0]["nativeAddress"]
        return role_request, native, role_request["legacyEraEvidenceByNativeAddress"][native]

    def _make_legacy_era(self, job_id, role, bundle):
        checkpoint = self.factory.checkpoints[generator.WRITE_SUBSTRATE]
        digest = bundle_hash(bundle)
        binding = self.factory.legacy_bundle_binding(
            bundle, role, "alternate-historical:" + job_id + ":" + role + ":" + digest
        )
        self.fixture["dependencies"]["bundlesByNativeAddress"][
            binding["nativeAddress"]
        ] = bundle
        historical = self.factory.anchor_proof(
            purpose="historical-bundle",
            substrate=generator.WRITE_SUBSTRATE,
            subject_id=job_id,
            subject_role=role,
            logical=binding["logicalAddress"],
            native=binding["nativeAddress"],
            content_hash=digest,
            transaction="fixture-alt-history-" + digest,
            writer=generator.CLAIMS[role],
            nonce=77,
            height=89,
            index=1,
        )
        return {
            "bundleContentHash": digest,
            "resolvedJobId": job_id,
            "resolvedRole": role,
            "substrate": generator.WRITE_SUBSTRATE,
            "checkpointCandidates": copy.deepcopy(checkpoint["candidates"]),
            "checkpointReceipt": copy.deepcopy(checkpoint["receipt"]),
            "historicalAnchorReceipt": historical,
            "originalMapping": {
                "kind": "binding",
                "binding": copy.deepcopy(binding),
                "anchorTransaction": historical["transactionRef"],
                "writer": historical["writer"],
                "nonce": historical["nonce"],
                "selectionContext": {
                    "candidateBindings": [copy.deepcopy(binding)],
                    "partyMap": {
                        generator.CLAIMS["buyer"]: "buyer",
                        generator.CLAIMS["seller"]: "seller",
                    },
                    "budget": 8,
                },
            },
        }

    def _add_alternate_legacy_candidate(self, *, full_standing, include_era=True):
        request = self.fixture["historicalRequests"][0]
        role_request, _native, _era = self._binding_era(request)
        base_binding = role_request["selectionContext"]["candidateBindings"][0]
        base_bundle = self.fixture["dependencies"]["bundlesByNativeAddress"][base_binding["nativeAddress"]]
        alternate = copy.deepcopy(base_bundle)
        alternate["outcome"] = "aborted-by-self"
        alternate["finalisedAt"] += 1
        self.factory.finality.sign_bundle(alternate, BUNDLE_DOMAIN)
        if not full_standing:
            alternate["signatures"] = [
                signature for signature in alternate["signatures"]
                if signature["party"] == generator.CLAIMS["buyer"]
            ]
        binding = self.factory.bundle_binding(
            alternate,
            "buyer",
            "alternate:" + ("full" if full_standing else "lesser"),
            trusted_contexts=self.current_context,
        )
        native = binding["nativeAddress"]
        self.fixture["dependencies"]["bundlesByNativeAddress"][native] = alternate
        receipt = self.factory.anchor_proof(
            purpose="current-bundle",
            substrate=generator.WRITE_SUBSTRATE,
            subject_id=request["jobId"],
            subject_role="buyer",
            logical=binding["logicalAddress"],
            native=native,
            content_hash=binding["bundleContentHash"],
            transaction="fixture-alt-current-" + binding["bundleContentHash"],
            writer=generator.CLAIMS["buyer"],
            nonce=88,
            height=111,
            index=1,
        )
        role_request["selectionContext"]["candidateBindings"].append(binding)
        role_request["anchorReceiptsByNativeAddress"][native] = receipt
        if include_era:
            role_request["legacyEraEvidenceByNativeAddress"][native] = self._make_legacy_era(
                request["jobId"], "buyer", alternate
            )
        return request, base_binding, binding

    def _replace_role_with_older_copy(self, kind):
        request = self.fixture["currentRequestsByModel"]["block-depth"]
        buyer_binding = request["roles"]["buyer"]["selectionContext"]["candidateBindings"][0]
        strong = self.fixture["dependencies"]["bundlesByNativeAddress"][buyer_binding["nativeAddress"]]
        authority = self.fixture["dependencies"]["bundleAuthorityByContentHash"][bundle_hash(strong)]
        compatibility = self.factory.finality.compatibility_copies({
            "bundle": strong,
            "authority": authority,
        })
        older = compatibility["copies"][kind]
        digest = bundle_hash(older)
        if kind == "evidence-bound":
            self.fixture["dependencies"]["bundleAuthorityByContentHash"][digest] = (
                compatibility["evidenceBoundAuthority"]
            )
        binding = self.factory.bundle_binding(
            older,
            "seller",
            "older:" + kind,
            trusted_contexts=self.current_context,
        )
        native = binding["nativeAddress"]
        self.fixture["dependencies"]["bundlesByNativeAddress"][native] = older
        receipt = self.factory.anchor_proof(
            purpose="current-bundle",
            substrate=generator.WRITE_SUBSTRATE,
            subject_id=request["jobId"],
            subject_role="seller",
            logical=binding["logicalAddress"],
            native=native,
            content_hash=digest,
            transaction="fixture-current-older-" + kind,
            writer=generator.CLAIMS["seller"],
            nonce=91,
            height=205,
            index=1,
        )
        era_by_address = {}
        if kind == "legacy":
            era_by_address[native] = self._make_legacy_era(
                request["jobId"], "seller", older
            )
        request["roles"]["seller"] = {
            "disposition": "present",
            "mappingKind": "binding",
            "selectionContext": {
                "candidateBindings": [binding],
                "partyMap": {
                    generator.CLAIMS["buyer"]: "buyer",
                    generator.CLAIMS["seller"]: "seller",
                },
                "budget": 8,
            },
            "anchorReceiptsByNativeAddress": {native: receipt},
            "legacyEraEvidenceByNativeAddress": era_by_address,
        }
        return request

    def _authenticate_absence(self, request, role):
        role_request = request["roles"][role]
        binding = copy.deepcopy(role_request["selectionContext"]["candidateBindings"][0])
        self.fixture["dependencies"]["bundlesByNativeAddress"].pop(binding["nativeAddress"])
        evidence = {
            "kind": "synthetic-finalized-non-membership",
            "nativeAddress": binding["nativeAddress"],
            "finalizedStateRef": "fixture-finalized-state:" + request["jobId"],
        }
        digest = generator.old_hash(evidence, "__no_omitted_member__")
        ref = {
            "kind": evidence["kind"],
            "locator": "fixture-absence:" + request["jobId"] + ":" + role,
            "contentHash": digest,
        }
        self.fixture["dependencies"]["absenceEvidenceByCanonicalRef"][digest] = evidence
        self.fixture["verifierConfig"]["authenticatedAbsenceByJobRole"][
            request["jobId"] + ":" + role
        ] = {
            "disposition": "absent",
            "absenceEvidenceRef": ref,
            "absenceBinding": binding,
        }

    def test_generator_is_deterministic_and_corpus_is_hash_bound(self):
        subprocess.run(
            [sys.executable, "-B", str(GENERATOR), "--check"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        data = json.loads(VECTORS.read_text(encoding="utf-8"))
        self.assertEqual(8, data["count"])
        self.assertEqual(data["count"], len(data["vectors"]))
        self.assertEqual(generator.document()["hash"], data["hash"])
        self.assertIn("Synthetic", data["fixturePolicy"])
        self.assertIn("no production Demos", data["fixturePolicy"])

    def test_historical_binding_and_pure_mapping_arms_execute(self):
        result = self.derive(self.fixture["historicalRequests"])
        self.assertEqual("pass", result["decision"], result["reason"])
        receipt = result["derivation"]
        self.assertEqual(2, receipt["bundleCount"])
        self.assertEqual(0.0, receipt["metrics"]["completionRate"])
        self.assertIsNone(receipt["metrics"]["counterpartyAdjustedCompletionRate"])
        self.assertEqual(1.0, receipt["metrics"]["counterpartyFaultRate"])
        kinds = {
            request["roles"]["buyer"]["mappingKind"]
            for request in receipt["requestContext"]
        }
        self.assertEqual({"binding", "pure"}, kinds)

        binding_request = self.fixture["historicalRequests"][0]
        role_request, current_native, era = self._binding_era(binding_request)
        current_binding = role_request["selectionContext"]["candidateBindings"][0]
        historical_binding = era["originalMapping"]["binding"]
        self.assertNotEqual(
            historical_binding["nativeAddress"], current_native
        )
        self.assertEqual(
            legacy_logical_address(binding_request["jobId"], "buyer"),
            historical_binding["logicalAddress"],
        )
        self.assertEqual(
            logical_address(
                binding_request["jobId"],
                "buyer",
                trusted_contexts=self.current_context,
            ),
            current_binding["logicalAddress"],
        )

    def test_anchor_receipt_purposes_are_bound_to_each_call_site(self):
        cases = (
            ("checkpoint", "historical-bundle"),
            ("historical", "current-bundle"),
            ("current", "historical-bundle"),
        )
        for receipt_kind, wrong_purpose in cases:
            with self.subTest(receipt=receipt_kind):
                self.setUp()
                if receipt_kind == "current":
                    request = self.fixture["currentRequestsByModel"]["block-depth"]
                    role_request = request["roles"]["buyer"]
                    native = role_request["selectionContext"]["candidateBindings"][0]["nativeAddress"]
                    proof = role_request["anchorReceiptsByNativeAddress"][native]
                else:
                    request = self.fixture["historicalRequests"][0]
                    _, _, era = self._binding_era(request)
                    proof = era[
                        "checkpointReceipt" if receipt_kind == "checkpoint"
                        else "historicalAnchorReceipt"
                    ]
                proof["purpose"] = wrong_purpose
                self._resign_anchor(proof, repin=True)
                result = self.derive([request])
                self.assertNotEqual("pass", result["decision"])
                self.assertIsNone(result["derivation"])

    def test_legacy_era_substrate_must_equal_the_requested_substrate_on_both_mapping_arms(self):
        for index, other_substrate in (
            (0, generator.PURE_SUBSTRATE),
            (1, generator.WRITE_SUBSTRATE),
        ):
            with self.subTest(mapping=self.fixture["historicalRequests"][index]["roles"]["buyer"]["mappingKind"]):
                self.setUp()
                request = self.fixture["historicalRequests"][index]
                role_request = request["roles"]["buyer"]
                if role_request["mappingKind"] == "binding":
                    _, _, era = self._binding_era(request)
                else:
                    era = role_request["legacyEraEvidence"]
                era["substrate"] = other_substrate
                result = self.derive([request])
                self.assertEqual("fail", result["decision"])
                self.assertIn("differs from requested substrate", result["reason"])
                self.assertIsNone(result["derivation"])

    def test_historical_nonpayment_requires_authenticated_complete_execution_evidence(self):
        request = self.fixture["historicalRequests"][0]
        binding = request["roles"]["buyer"]["selectionContext"]["candidateBindings"][0]
        bundle = self.fixture["dependencies"]["bundlesByNativeAddress"][binding["nativeAddress"]]
        decision, reason = _validate_current_use_historical_nonpayment(
            bundle, self.fixture["dependencies"], self.fixture["verifierConfig"]
        )
        self.assertEqual("pass", decision, reason)

        for mutation in ("empty-failed-summary", "partial-completed-summary", "omitted-evidence"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(bundle)
                if mutation == "empty-failed-summary":
                    changed["outcome"] = "failed-counterparty"
                elif mutation == "partial-completed-summary":
                    changed["outcome"] = "completed"
                else:
                    changed.pop("settlementEvidence")
                changed_dependencies = copy.deepcopy(self.fixture["dependencies"])
                changed_dependencies["bundleAuthorityByContentHash"][bundle_hash(changed)] = (
                    copy.deepcopy(
                        self.fixture["dependencies"]["bundleAuthorityByContentHash"][
                            bundle_hash(bundle)
                        ]
                    )
                )
                decision, _ = _validate_current_use_historical_nonpayment(
                    changed, changed_dependencies, self.fixture["verifierConfig"]
                )
                self.assertNotEqual("pass", decision)

        for role_request in request["roles"].values():
            role_binding = role_request["selectionContext"]["candidateBindings"][0]
            role_bundle = self.fixture["dependencies"]["bundlesByNativeAddress"][
                role_binding["nativeAddress"]
            ]
            self.fixture["dependencies"]["bundleAuthorityByContentHash"][
                bundle_hash(role_bundle)
            ].pop("listing")
        result = self.derive([request])
        self.assertEqual("indeterminate", result["decision"])
        self.assertIsNone(result["derivation"])

    def test_present_copy_rosters_match_verifier_owned_job_roles(self):
        role_map = {
            "buyer": generator.CLAIMS["buyer"],
            "seller": generator.CLAIMS["seller"],
        }
        request = self.fixture["historicalRequests"][1]
        native = request["roles"]["buyer"]["resolvedAddress"]
        bundle = self.fixture["dependencies"]["bundlesByNativeAddress"][native]
        self.assertTrue(_current_use_roster_matches_role_map(bundle, role_map))
        for mutation in ("missing", "duplicate", "reversed", "inconsistent"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(bundle)
                if mutation == "missing":
                    changed["parties"] = [
                        party for party in changed["parties"] if party["role"] != "buyer"
                    ]
                elif mutation == "duplicate":
                    changed["parties"].append(copy.deepcopy(changed["parties"][0]))
                elif mutation == "reversed":
                    changed["parties"][0]["primaryClaim"], changed["parties"][1]["primaryClaim"] = (
                        changed["parties"][1]["primaryClaim"], changed["parties"][0]["primaryClaim"]
                    )
                else:
                    changed["parties"][0]["primaryClaim"] = "did:fixture:untrusted-buyer"
                self.assertFalse(_current_use_roster_matches_role_map(changed, role_map))

        changed = copy.deepcopy(bundle)
        changed["parties"][0]["primaryClaim"], changed["parties"][1]["primaryClaim"] = (
            changed["parties"][1]["primaryClaim"], changed["parties"][0]["primaryClaim"]
        )
        self.factory.finality.sign_bundle(changed, BUNDLE_DOMAIN)
        self.fixture["dependencies"]["bundlesByNativeAddress"][native] = changed
        result = self.derive([request])
        self.assertEqual("fail", result["decision"])
        # Pure-mapping admission authenticates the requested role holder before
        # the whole-roster check. The current-copy case below reaches that gate.
        self.assertEqual(
            f'{request["jobId"]}: pure-mapping check: role holder != authenticated participant',
            result["reason"],
        )

        self.setUp()
        request = self.fixture["currentRequestsByModel"]["block-depth"]
        old_binding = request["roles"]["buyer"]["selectionContext"]["candidateBindings"][0]
        current = copy.deepcopy(
            self.fixture["dependencies"]["bundlesByNativeAddress"][old_binding["nativeAddress"]]
        )
        current["parties"].append(copy.deepcopy(current["parties"][0]))
        self.factory.finality.sign_bundle(current, generator.FINALITY_BUNDLE_DOMAIN)
        binding = self.factory.bundle_binding(
            current,
            "buyer",
            "current-roster-mismatch",
            trusted_contexts=self.current_context,
        )
        native = binding["nativeAddress"]
        self.fixture["dependencies"]["bundlesByNativeAddress"][native] = current
        receipt = self.factory.anchor_proof(
            purpose="current-bundle", substrate=generator.WRITE_SUBSTRATE,
            subject_id=request["jobId"], subject_role="buyer",
            logical=binding["logicalAddress"], native=native,
            content_hash=binding["bundleContentHash"], transaction="fixture-current-roster-mismatch",
            writer=generator.CLAIMS["buyer"], nonce=313, height=205, index=0,
        )
        request["roles"]["buyer"] = {
            "disposition": "present", "mappingKind": "binding",
            "selectionContext": {
                "candidateBindings": [binding],
                "partyMap": {
                    generator.CLAIMS["buyer"]: "buyer",
                    generator.CLAIMS["seller"]: "seller",
                },
                "budget": 8,
            },
            "anchorReceiptsByNativeAddress": {native: receipt},
            "legacyEraEvidenceByNativeAddress": {},
        }
        result = self.derive([request])
        self.assertEqual("fail", result["decision"])
        self.assertIn("roster differs", result["reason"])

    def test_every_historical_exact_join_rejects_mutation(self):
        evidence_fields = ("bundleContentHash", "resolvedJobId", "resolvedRole", "substrate")
        for field in evidence_fields:
            with self.subTest(scope="era", field=field):
                self.setUp()
                request = self.fixture["historicalRequests"][0]
                _, _, era = self._binding_era(request)
                era[field] = "seller" if field == "resolvedRole" else "mutated"
                result = self.derive([request])
                self.assertNotEqual("pass", result["decision"])
                self.assertIsNone(result["derivation"])

        receipt_fields = (
            "logicalAddress", "nativeAddress", "contentHash", "transactionRef", "writer",
            "subjectId", "subjectRole",
        )
        for receipt_name in ("checkpointReceipt", "historicalAnchorReceipt"):
            for field in receipt_fields:
                with self.subTest(scope=receipt_name, field=field):
                    self.setUp()
                    request = self.fixture["historicalRequests"][0]
                    _, _, era = self._binding_era(request)
                    proof = era[receipt_name]
                    proof[field] = "seller" if field == "subjectRole" else "mutated"
                    self._resign_anchor(proof, repin=True)
                    result = self.derive([request])
                    self.assertNotEqual("pass", result["decision"])
                    self.assertIsNone(result["derivation"])

        for field in ("nonce", "position"):
            with self.subTest(scope="pinned-receipt", field=field):
                self.setUp()
                request = self.fixture["historicalRequests"][0]
                _, _, era = self._binding_era(request)
                proof = era["historicalAnchorReceipt"]
                if field == "nonce":
                    proof[field] += 1
                else:
                    proof[field]["index"] += 1
                self._resign_anchor(proof, repin=False)
                result = self.derive([request])
                self.assertNotEqual("pass", result["decision"])

    def test_original_bundle_binding_and_selection_context_are_exact(self):
        for field in ("jobId", "role", "logicalAddress", "nativeAddress", "bundleContentHash", "signer"):
            with self.subTest(field=field):
                self.setUp()
                request = self.fixture["historicalRequests"][0]
                _, _, era = self._binding_era(request)
                binding = era["originalMapping"]["binding"]
                binding[field] = "seller" if field == "role" else "mutated"
                result = self.derive([request])
                self.assertNotEqual("pass", result["decision"])
                self.assertIsNone(result["derivation"])
        for mutation in ("party-map", "budget", "selected-binding-missing"):
            with self.subTest(mutation=mutation):
                self.setUp()
                request = self.fixture["historicalRequests"][0]
                _, _, era = self._binding_era(request)
                context = era["originalMapping"]["selectionContext"]
                if mutation == "party-map":
                    context["partyMap"] = {generator.CLAIMS["buyer"]: "seller"}
                elif mutation == "budget":
                    context["budget"] = 7
                else:
                    context["candidateBindings"] = []
                result = self.derive([request])
                self.assertNotEqual("pass", result["decision"])

    def test_checkpoint_binding_and_pure_mapping_joins_are_exact(self):
        for field in (
            "legacyBundleCheckpointBindingVersion", "substrate", "logicalAddress",
            "nativeAddress", "checkpointContentHash", "anchorTx", "signer",
        ):
            with self.subTest(scope="checkpoint-binding", field=field):
                self.setUp()
                request = self.fixture["historicalRequests"][0]
                _, _, era = self._binding_era(request)
                binding = era["checkpointCandidates"][0]
                binding[field] = (
                    "2" if field == "legacyBundleCheckpointBindingVersion" else "mutated"
                )
                self._resign_checkpoint_binding(binding)
                result = self.derive([request])
                self.assertNotEqual("pass", result["decision"])
                self.assertIsNone(result["derivation"])

        for field in (
            "logicalAddress", "nativeAddress", "anchorTransaction", "writer", "nonce",
        ):
            with self.subTest(scope="pure-mapping", field=field):
                self.setUp()
                request = self.fixture["historicalRequests"][1]
                era = request["roles"]["buyer"]["legacyEraEvidence"]
                original = era["originalMapping"]
                original[field] = original[field] + 1 if field == "nonce" else "mutated"
                result = self.derive([request])
                self.assertNotEqual("pass", result["decision"])
                self.assertIsNone(result["derivation"])

        self.setUp()
        request = self.fixture["historicalRequests"][0]
        _, _, era = self._binding_era(request)
        proof = era["historicalAnchorReceipt"]
        proof["nonce"] += 1
        self._resign_anchor(proof, repin=True)
        self.assertEqual("fail", self.derive([request])["decision"])

    def test_checkpoint_discovery_discards_junk_and_deduplicates_before_multiplicity(self):
        request = self.fixture["historicalRequests"][0]
        _, _, era = self._binding_era(request)
        control = self.derive([request])
        self.assertEqual("pass", control["decision"], control["reason"])
        era["checkpointCandidates"].extend([
            None,
            {"authorizedStewards": ["did:attacker:self"], "producerVerified": True},
            copy.deepcopy(era["checkpointCandidates"][0]),
        ])
        result = self.derive([request])
        self.assertEqual("pass", result["decision"], result["reason"])

    def test_conflicting_authorized_checkpoint_survivors_are_indeterminate(self):
        request = self.fixture["historicalRequests"][0]
        _, _, era = self._binding_era(request)
        conflict = copy.deepcopy(era["checkpointCandidates"][0])
        conflict["nativeAddress"] = "native-conflicting-checkpoint"
        conflict["anchorTx"] = "fixture-conflicting-checkpoint-tx"
        self._resign_checkpoint_binding(conflict)
        era["checkpointCandidates"].append(conflict)
        result = self.derive([request])
        self.assertEqual("indeterminate", result["decision"])
        self.assertIsNone(result["derivation"])

    def test_candidate_cannot_self_authorize_checkpoint_or_native_proof(self):
        request = self.fixture["historicalRequests"][0]
        _, _, era = self._binding_era(request)
        era["checkpointCandidates"][0]["authorizedStewards"] = [generator.CLAIMS["steward"]]
        self.fixture["verifierConfig"]["authorizedStewardBySubstrate"] = {}
        result = self.derive([request])
        self.assertEqual("indeterminate", result["decision"])
        self.assertIsNone(result["derivation"])

    def test_pruned_reorganized_unorderable_and_post_checkpoint_history_never_pass(self):
        for disposition in ("pruned", "reorganized", "unorderable"):
            with self.subTest(disposition=disposition):
                self.setUp()
                request = self.fixture["historicalRequests"][0]
                _, _, era = self._binding_era(request)
                proof = era["historicalAnchorReceipt"]
                proof["observationDisposition"] = disposition
                self._resign_anchor(proof, repin=True)
                self.assertEqual("indeterminate", self.derive([request])["decision"])
        self.setUp()
        request = self.fixture["historicalRequests"][0]
        _, _, era = self._binding_era(request)
        proof = era["historicalAnchorReceipt"]
        proof["position"] = copy.deepcopy(era["checkpointReceipt"]["position"])
        self._resign_anchor(proof, repin=True)
        self.assertEqual("fail", self.derive([request])["decision"])
        self.setUp()
        request = self.fixture["historicalRequests"][0]
        _, _, era = self._binding_era(request)
        proof = era["historicalAnchorReceipt"]
        proof["position"]["orderDomain"] = "unrelated-ledger"
        self._resign_anchor(proof, repin=True)
        self.assertEqual("indeterminate", self.derive([request])["decision"])

    def test_bb6_standing_budget_and_admission_order(self):
        request, base, alternate = self._add_alternate_legacy_candidate(full_standing=False)
        result = self.derive([request])
        self.assertEqual("pass", result["decision"], result["reason"])
        context = result["derivation"]["resolutionContext"][0]
        admitted_hashes = {
            result["derivation"]["bundleRefs"][0]["contentHash"],
            context["counterpartyRef"]["contentHash"],
        }
        self.assertIn(base["bundleContentHash"], admitted_hashes)
        self.assertNotIn(alternate["bundleContentHash"], admitted_hashes)

        self.setUp()
        request, _base, _alternate = self._add_alternate_legacy_candidate(full_standing=True)
        self.assertEqual("indeterminate", self.derive([request])["decision"])

        self.setUp()
        request, _base, _alternate = self._add_alternate_legacy_candidate(
            full_standing=False, include_era=False
        )
        self.assertEqual("indeterminate", self.derive([request])["decision"])

        self.setUp()
        request = self.fixture["historicalRequests"][0]
        role_request, _, _ = self._binding_era(request)
        candidate = role_request["selectionContext"]["candidateBindings"][0]
        role_request["selectionContext"]["candidateBindings"] = [copy.deepcopy(candidate) for _ in range(9)]
        self.assertEqual("indeterminate", self.derive([request])["decision"])

    def test_outsider_binding_junk_is_pruned_before_validation(self):
        request = self.fixture["historicalRequests"][0]
        role_request, _, _ = self._binding_era(request)
        role_request["selectionContext"]["candidateBindings"].insert(0, {
            "signer": "did:attacker:outsider",
            "role": ["malformed"],
            "nativeAddress": None,
        })
        result = self.derive([request])
        self.assertEqual("pass", result["decision"], result["reason"])

    def test_all_six_finality_models_execute_with_volume_and_rating_metrics(self):
        expected_models = set(generator.MODELS)
        observed = set()
        for model, request in self.fixture["currentRequestsByModel"].items():
            with self.subTest(model=model):
                result = self.derive([request])
                self.assertEqual("pass", result["decision"], result["reason"])
                metrics = result["derivation"]["metrics"]
                self.assertEqual(1, result["derivation"]["bundleCount"])
                self.assertEqual(1.0, metrics["completionRate"])
                self.assertEqual(1.0, metrics["counterpartyAdjustedCompletionRate"])
                self.assertEqual(0.0, metrics["counterpartyFaultRate"])
                self.assertEqual(1, metrics["transactionCountByCurrency"][0]["count"])
                if model == "block-depth":
                    self.assertEqual(5.0, metrics["averageBuyerRating"])
                if model == "provider-receipt":
                    self.assertEqual([], metrics["finalityClassifiedVolume"]["profileFinal"]["observedTransactionalVolume"])
                    self.assertEqual("USD", metrics["finalityClassifiedVolume"]["provisionalProviderCapture"]["observedTransactionalVolume"][0]["currency"])
                else:
                    self.assertEqual([], metrics["finalityClassifiedVolume"]["provisionalProviderCapture"]["observedTransactionalVolume"])
                observed.add(model)
        self.assertEqual(expected_models, observed)

    def test_sb2_projection_and_cross_job_rebinding_are_fail_closed(self):
        expected_prefixes = {
            "block-depth": "evm:1:",
            "commitment-level": "solana:mainnet:",
            "bft-final": "demos:",
        }
        records = {}
        for model, prefix in expected_prefixes.items():
            request = self.fixture["currentRequestsByModel"][model]
            binding = request["roles"]["buyer"]["selectionContext"]["candidateBindings"][0]
            bundle = self.fixture["dependencies"]["bundlesByNativeAddress"][binding["nativeAddress"]]
            authority = self.fixture["dependencies"]["bundleAuthorityByContentHash"][bundle_hash(bundle)]
            record = next(iter(authority["referenceValidationByCanonicalRef"].values()))["record"]
            projected = _current_use_settlement_tx_ids(record)
            self.assertEqual(1, len(projected))
            self.assertTrue(projected[0].startswith(prefix))
            records[model] = record

        duplicate = copy.deepcopy(records["block-depth"])
        duplicate["jobId"] = "SB2-DIFFERENT-REQUESTED-JOB"
        first = {
            "selected": {"settlement": {"successfulPayments": [{
                "record": records["block-depth"], "phaseIndex": 0,
            }]}}
        }
        second = {
            "selected": {"settlement": {"successfulPayments": [{
                "record": duplicate, "phaseIndex": 0,
            }]}}
        }
        self.assertIn("rebound", _current_use_sb2_conflict([first, second]))

    def test_solana_projection_rejects_malformed_alphabet_and_width(self):
        request = self.fixture["currentRequestsByModel"]["commitment-level"]
        binding = request["roles"]["buyer"]["selectionContext"]["candidateBindings"][0]
        bundle = self.fixture["dependencies"]["bundlesByNativeAddress"][binding["nativeAddress"]]
        authority = self.fixture["dependencies"]["bundleAuthorityByContentHash"][bundle_hash(bundle)]
        record = next(iter(authority["referenceValidationByCanonicalRef"].values()))["record"]
        self.assertIsNotNone(_current_use_settlement_tx_ids(record))
        for signature in ("not-base58-0OIl", generator.FixtureFactory.base58(b"\x05" * 63)):
            malformed = copy.deepcopy(record)
            malformed["paymentTxRefs"][0]["signature"] = signature
            with self.subTest(signature=signature):
                self.assertIsNone(_current_use_settlement_tx_ids(malformed))

    def test_new_new_and_each_new_older_pair_selects_authenticated_new_copy(self):
        new_new = self.derive([self.fixture["currentRequestsByModel"]["block-depth"]])
        self.assertEqual("pass", new_new["decision"], new_new["reason"])
        for kind in ("evidence-bound", "fault", "legacy"):
            with self.subTest(kind=kind):
                self.setUp()
                request = self._replace_role_with_older_copy(kind)
                result = self.derive([request])
                self.assertEqual("pass", result["decision"], result["reason"])
                self.assertEqual("finality-bound", result["derivation"]["resolutionContext"][0]["bundleType"])

    def test_invalid_new_copy_never_falls_back_to_older_copy(self):
        request = self._replace_role_with_older_copy("legacy")
        buyer_binding = request["roles"]["buyer"]["selectionContext"]["candidateBindings"][0]
        strong = self.fixture["dependencies"]["bundlesByNativeAddress"][buyer_binding["nativeAddress"]]
        authority = self.fixture["dependencies"]["bundleAuthorityByContentHash"][bundle_hash(strong)]
        candidate = next(iter(authority["finalityVerificationByCanonicalRef"].values()))
        candidate["context"]["observation"]["transactionRef"]["txHash"] = "ff" * 32
        result = self.derive([request])
        self.assertEqual("fail", result["decision"])
        self.assertIsNone(result["derivation"])

    def test_absent_and_indeterminate_role_dispositions_are_not_conflated(self):
        request = self.fixture["currentRequestsByModel"]["block-depth"]
        self._authenticate_absence(request, "seller")
        request["roles"]["seller"] = {"disposition": "absent"}
        result = self.derive([request])
        self.assertEqual("pass", result["decision"], result["reason"])
        context = result["derivation"]["resolutionContext"][0]
        self.assertEqual("absent", context["counterpartyDisposition"])
        self.assertIn("absenceEvidenceRef", context)
        self.assertIn("absenceBinding", context)

        self.setUp()
        request = self.fixture["currentRequestsByModel"]["block-depth"]
        request["roles"]["seller"] = {"disposition": "absent"}
        self.assertEqual("indeterminate", self.derive([request])["decision"])

        self.setUp()
        request = self.fixture["currentRequestsByModel"]["block-depth"]
        request["roles"]["seller"] = {"disposition": "indeterminate"}
        self.assertEqual("indeterminate", self.derive([request])["decision"])

        for disposition in ("absent", "indeterminate"):
            with self.subTest(disposition=disposition, malformed="unknown-member"):
                self.setUp()
                request = self.fixture["currentRequestsByModel"]["block-depth"]
                request["roles"]["seller"] = {
                    "disposition": disposition,
                    "producerVerified": True,
                }
                self.assertEqual("error", self.derive([request])["decision"])

    def test_historical_success_without_exact_stronger_finality_is_indeterminate(self):
        request = self._replace_role_with_older_copy("evidence-bound")
        request["roles"]["buyer"] = copy.deepcopy(request["roles"]["seller"])
        buyer_binding = request["roles"]["buyer"]["selectionContext"]["candidateBindings"][0]
        buyer_bundle = copy.deepcopy(
            self.fixture["dependencies"]["bundlesByNativeAddress"][buyer_binding["nativeAddress"]]
        )
        buyer_bundle["anchoredByRole"] = "buyer"
        buyer_binding = self.factory.bundle_binding(
            buyer_bundle,
            "buyer",
            "older:evidence-bound:buyer",
            trusted_contexts=self.current_context,
        )
        native = buyer_binding["nativeAddress"]
        self.fixture["dependencies"]["bundlesByNativeAddress"][native] = buyer_bundle
        receipt = self.factory.anchor_proof(
            purpose="current-bundle", substrate=generator.WRITE_SUBSTRATE,
            subject_id=request["jobId"], subject_role="buyer",
            logical=buyer_binding["logicalAddress"], native=native,
            content_hash=bundle_hash(buyer_bundle), transaction="fixture-old-success-buyer",
            writer=generator.CLAIMS["buyer"], nonce=92, height=205, index=0,
        )
        request["roles"]["buyer"] = {
            "disposition": "present", "mappingKind": "binding",
            "selectionContext": {
                "candidateBindings": [buyer_binding],
                "partyMap": {generator.CLAIMS["buyer"]: "buyer", generator.CLAIMS["seller"]: "seller"},
                "budget": 8,
            },
            "anchorReceiptsByNativeAddress": {native: receipt},
            "legacyEraEvidenceByNativeAddress": {},
        }
        result = self.derive([request])
        self.assertEqual("indeterminate", result["decision"])
        self.assertIsNone(result["derivation"])

    def test_required_sb3_binding_has_no_boolean_or_unbound_downgrade(self):
        request = self.fixture["currentRequestsByModel"]["provider-receipt"]
        control = self.derive([request])
        self.assertEqual("pass", control["decision"], control["reason"])
        proof_map = self.fixture["dependencies"]["settlementBindingProofByCanonicalRef"]
        key = next(iter(proof_map))
        del proof_map[key]
        result = self.derive([request])
        self.assertEqual("indeterminate", result["decision"])
        self.assertIsNone(result["derivation"])

        for state, expected in (("mismatch", "fail"), ("unavailable", "indeterminate")):
            with self.subTest(state=state):
                self.setUp()
                request = self.fixture["currentRequestsByModel"]["provider-receipt"]
                proof = next(iter(self.fixture["dependencies"]["settlementBindingProofByCanonicalRef"].values()))
                proof["state"] = state
                proof["allowUnboundFallback"] = True
                self._resign_settlement_binding(proof)
                result = self.derive([request])
                self.assertEqual("error", result["decision"])
                del proof["allowUnboundFallback"]
                self._resign_settlement_binding(proof)
                self.assertEqual(expected, self.derive([request])["decision"])

    def test_multi_job_request_never_emits_partial_metrics(self):
        requests = [
            self.fixture["currentRequestsByModel"]["block-depth"],
            self.fixture["currentRequestsByModel"]["provider-receipt"],
        ]
        self.assertEqual("pass", self.derive(requests)["decision"])
        proof_map = self.fixture["dependencies"]["settlementBindingProofByCanonicalRef"]
        proof_map.clear()
        result = self.derive(requests)
        self.assertEqual("indeterminate", result["decision"])
        self.assertIsNone(result["derivation"])

    def test_complete_replay_and_dependency_mutations(self):
        requests = list(self.fixture["currentRequestsByModel"].values()) + self.fixture["historicalRequests"]
        result = self.derive(requests)
        self.assertEqual("pass", result["decision"], result["reason"])
        receipt = result["derivation"]
        replay = replay_current_use_derivation(
            receipt,
            self.fixture["dependencies"],
            self.fixture["verifierConfig"],
            pubkeys=self.current_keys,
            trusted_contexts=self.current_context,
        )
        self.assertTrue(replay["ok"], replay["reason"])
        self.assertEqual(receipt, replay["replayed"])

        changed = copy.deepcopy(receipt)
        changed["metrics"]["completionRate"] = 0
        self.assertFalse(replay_current_use_derivation(
            changed,
            self.fixture["dependencies"],
            self.fixture["verifierConfig"],
            pubkeys=self.current_keys,
            trusted_contexts=self.current_context,
        )["ok"])

        provider = self.fixture["currentRequestsByModel"]["provider-receipt"]
        key = next(iter(self.fixture["dependencies"]["settlementBindingProofByCanonicalRef"]))
        self.fixture["dependencies"]["settlementBindingProofByCanonicalRef"].pop(key)
        replay = replay_current_use_derivation(
            receipt,
            self.fixture["dependencies"],
            self.fixture["verifierConfig"],
            pubkeys=self.current_keys,
            trusted_contexts=self.current_context,
        )
        self.assertFalse(replay["ok"])
        self.assertIsNone(replay["replayed"])
        self.assertIn(provider["jobId"], replay["reason"])

    def test_exclusive_discriminator_old_reader_refusal_and_stripping_resistance(self):
        result = self.derive([self.fixture["currentRequestsByModel"]["block-depth"]])
        self.assertEqual("pass", result["decision"], result["reason"])
        receipt = result["derivation"]
        discriminator_keys = {key for key in receipt if key.endswith("DerivationVersion")}
        self.assertEqual({"currentUseReplayableDerivationVersion"}, discriminator_keys)
        self.assertFalse(require_replayable_derivation(receipt)["ok"])
        self.assertEqual((False, None), replay_receipt(
            receipt, _Bomb(), self.party, 0, 2_000_000_000_000
        ))

        for name, mutate in (
            ("missing", lambda value: value.pop("currentUseReplayableDerivationVersion")),
            ("unknown", lambda value: value.__setitem__("futureDerivationVersion", "1")),
            ("dual", lambda value: value.__setitem__("replayableDerivationVersion", "1")),
            ("dual-released", lambda value: value.__setitem__("derivationVersion", "1")),
            ("wrong-version", lambda value: value.__setitem__("currentUseReplayableDerivationVersion", "2")),
        ):
            with self.subTest(name=name):
                changed = copy.deepcopy(receipt)
                mutate(changed)
                self.assertFalse(require_current_use_replayable_derivation(changed)["ok"])
                self.assertFalse(replay_current_use_derivation(changed, _Bomb(), _Bomb())["ok"])

        relabelled = copy.deepcopy(receipt)
        relabelled.pop("currentUseReplayableDerivationVersion")
        relabelled["replayableDerivationVersion"] = "1"
        self.assertFalse(replay_current_use_derivation(
            relabelled, self.fixture["dependencies"], self.fixture["verifierConfig"]
        )["ok"])

    def test_existing_derive_and_job_bound_algorithms_remain_historical(self):
        request = self.fixture["historicalRequests"][0]
        binding = request["roles"]["buyer"]["selectionContext"]["candidateBindings"][0]
        bundle = self.fixture["dependencies"]["bundlesByNativeAddress"][binding["nativeAddress"]]
        tag = {
            "bundle": bundle,
            "resolvedRole": "buyer",
            "counterpartyDisposition": "present",
            "resolvedJobId": bundle["jobId"],
            "selectedByRoleResolution": True,
        }
        old = derive(self.party, [tag], 0, 2_000_000_000_000)
        job_bound = derive_job_bound(self.party, [tag], 0, 2_000_000_000_000)
        self.assertEqual("1", old["replayableDerivationVersion"])
        self.assertEqual("1", job_bound["jobBoundReplayableDerivationVersion"])
        self.assertEqual(
            {"completionRate", "counterpartyAdjustedCompletionRate", "counterpartyFaultRate"},
            set(old["metrics"]),
        )
        self.assertNotIn("currentUseReplayableDerivationVersion", old)
        self.assertNotIn("currentUseReplayableDerivationVersion", job_bound)

    def test_malformed_nested_containers_are_total_nonpasses(self):
        mutations = (
            lambda request: request.__setitem__("roles", []),
            lambda request: request["roles"].__setitem__("buyer", None),
            lambda request: request["roles"]["buyer"].__setitem__("selectionContext", []),
            lambda request: request["roles"]["buyer"]["selectionContext"].__setitem__("candidateBindings", {}),
            lambda request: request["roles"]["buyer"]["selectionContext"].__setitem__("partyMap", []),
            lambda request: request["roles"]["buyer"].__setitem__("anchorReceiptsByNativeAddress", []),
            lambda request: request["roles"]["buyer"].__setitem__("legacyEraEvidenceByNativeAddress", []),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.setUp()
                request = self.fixture["historicalRequests"][0]
                mutate(request)
                result = self.derive([request])
                self.assertIn(result["decision"], {"error", "fail", "indeterminate"})
                self.assertIsNone(result["derivation"])

        for malformed in (None, True, 7, "request", {}, [None]):
            with self.subTest(top=malformed):
                result = derive_current_use_replayable(
                    self.party, malformed, 0, 1, {}, self.fixture["verifierConfig"]
                )
                self.assertIn(result["decision"], {"error", "fail", "indeterminate"})
                self.assertIsNone(result["derivation"])


if __name__ == "__main__":
    unittest.main()
