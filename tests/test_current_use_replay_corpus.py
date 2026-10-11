"""JSON-only replay of the committed current-use corpus.

Every vector in ``current-use-reputation-v1.json`` embeds the complete
executable replay input: the exact request, the full authenticated
dependency closure, the verifier configuration with public keys, the trusted
query context, and the expected outcome.  These tests reconstitute nothing
from the generator: they execute the committed bytes alone, proving the
corpus is independently executable, that the set hash binds the complete
replay inputs, that mutating any bound authority, receipt, finality, or
historical-evidence member of a passing case changes the payload and yields a
non-pass, and that each LAB negative is rejected only by its named guard.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for path in (str(ROOT), str(ROOT / "tests")):
    if path not in sys.path:
        sys.path.insert(0, path)

import dacs5_reference as D5  # noqa: E402
from dacs5_reference import derive_current_use_replayable  # noqa: E402


VECTORS = ROOT / "conformance" / "vectors" / "security" / "current-use-reputation-v1.json"


def decode_keys(encoded):
    """Reconstitute raw Ed25519 verification keys from committed Base64URL."""
    return {
        identity: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        for identity, value in encoded["keys"].items()
    }


def decode_key_map(value):
    """Reconstitute one committed Base64URL key map to raw Ed25519 bytes."""
    return {
        identity: base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
        for identity, key in value.items()
    }


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def execute(replay):
    request = copy.deepcopy(replay["request"])
    dependencies = copy.deepcopy(replay["dependencies"])
    verifier_config = copy.deepcopy(replay["verifierConfig"])
    keys = decode_keys(replay["verificationKeys"])
    for identity, key in keys.items():
        verifier_config["publicKeys"][identity] = key
    verifier_config["nativeAuthorityKeys"] = decode_key_map(
        verifier_config["nativeAuthorityKeys"]
    )
    verifier_config["settlementBindingAuthorityKeys"] = decode_key_map(
        verifier_config["settlementBindingAuthorityKeys"]
    )
    pubkeys = {
        "authenticated": replay["verificationKeys"]["authenticated"],
        "keys": keys,
    }
    return derive_current_use_replayable(
        replay["query"]["party"],
        [request],
        replay["query"]["windowStart"],
        replay["query"]["windowEnd"],
        dependencies,
        verifier_config,
        basis=replay["query"]["windowingBasis"],
        pubkeys=pubkeys,
        trusted_contexts=copy.deepcopy(replay["trustedContext"]),
    )


class CurrentUseReplayCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {vector["name"]: vector for vector in cls.data["vectors"]}

    def test_set_hash_binds_the_complete_replay_inputs(self):
        self.assertEqual(13, self.data["count"])
        self.assertEqual(self.data["count"], len(self.data["vectors"]))
        encoded = canonical(self.data["vectors"])
        self.assertEqual(
            hashlib.sha256(encoded).hexdigest(), self.data["hash"]
        )
        every_field = True
        for vector in self.data["vectors"]:
            replay = vector.get("replay")
            complete = (
                isinstance(replay, dict)
                and set(replay) == {
                    "request", "dependencies", "verifierConfig",
                    "trustedContext", "verificationKeys", "query",
                }
                and isinstance(replay["request"], dict)
                and isinstance(replay["dependencies"], dict)
                and isinstance(replay["verifierConfig"], dict)
                and isinstance(replay["trustedContext"], dict)
                and isinstance(replay["verificationKeys"], dict)
                and isinstance(replay["query"], dict)
            )
            every_field &= complete
            if not complete:
                self.fail("%s does not embed the complete replay input" % vector["name"])
            self.assertIn(
                "pinnedSyntheticAnchorProofHashBySubject",
                replay["verifierConfig"],
            )
            self.assertIn(
                "finalityTrust", replay["verifierConfig"],
            )
            self.assertIn("publicKeys", replay["verifierConfig"])
            self.assertTrue(replay["verificationKeys"]["keys"])
        self.assertTrue(every_field)
        for vector in self.data["vectors"]:
            without_replay = copy.deepcopy(vector)
            without_replay.pop("replay")
            different = copy.deepcopy(self.data["vectors"])
            different[different.index(vector)] = without_replay
            self.assertNotEqual(
                hashlib.sha256(canonical(different)).hexdigest(),
                self.data["hash"],
            )

    def test_every_committed_case_is_independently_executable_and_passes(self):
        for vector in self.data["vectors"]:
            with self.subTest(case=vector["name"]):
                self.assertIn("replay", vector)
                result = execute(vector["replay"])
                self.assertEqual(
                    vector["expected"], result["decision"], result["reason"]
                )

    def _mutated_nonpass(self, vector, mutate, *, scope):
        original = copy.deepcopy(vector["replay"])
        mutated = copy.deepcopy(original)
        mutate(mutated)
        self.assertNotEqual(
            canonical(mutated), canonical(original),
            "mutation must change the committed bound payload",
        )
        changed_vectors = copy.deepcopy(self.data["vectors"])
        changed_vectors[self.data["vectors"].index(vector)]["replay"] = mutated
        self.assertNotEqual(
            hashlib.sha256(canonical(changed_vectors)).hexdigest(),
            self.data["hash"],
            "%s mutation must change the committed set hash" % scope,
        )
        result = execute(mutated)
        self.assertNotEqual(
            "pass", result["decision"],
            "%s mutation must yield a non-pass decision" % scope,
        )

    def test_every_case_rejects_authority_receipt_and_finality_or_historical_mutations(self):
        """Every positive case: each mutation family changes the payload and fails."""
        for vector in self.data["vectors"]:
            if vector["expected"] != "pass":
                continue
            with self.subTest(case=vector["name"]):
                # Authority: the verifier-owned role authority for this job.
                def mutate_authority(replay, vector=vector):
                    for record in replay["trustedContext"]["roleMap"]:
                        if record["sessionId"] == replay["request"]["jobId"]:
                            record["participantIdentity"] = "did:fixture:untrusted"
                            return
                    raise AssertionError("role authority record not found")

                self._mutated_nonpass(
                    vector, mutate_authority, scope="role-authority"
                )

                # Receipt: the first pinned anchor receipt reachable from the roles.
                def mutate_receipt(replay, vector=vector):
                    receipt = self._first_receipt(replay)
                    receipt["transactionRef"] = "fixture-tx-mutated"

                self._mutated_nonpass(vector, mutate_receipt, scope="receipt")

                # Finality or historical evidence, per case kind.
                if vector["name"].startswith("current-use-"):
                    def mutate_evidence(replay, vector=vector):
                        authority = next(iter(
                            replay["dependencies"]["bundleAuthorityByContentHash"].values()
                        ))
                        candidate = next(iter(
                            authority["finalityVerificationByCanonicalRef"].values()
                        ))
                        context = candidate["context"]
                        if "observation" in context:
                            context["observation"]["inclusionBlock"]["id"] = "ff" * 32
                        elif any(
                            isinstance(context[key], dict) and "inclusionBlock" in context[key]
                            for key in context
                        ):
                            arm = next(
                                key for key in sorted(context)
                                if isinstance(context[key], dict)
                                and "inclusionBlock" in context[key]
                            )
                            context[arm]["inclusionBlock"]["id"] = "ff" * 32
                        else:
                            context["providerRef"] = "mutated-provider-ref"
                else:
                    def mutate_evidence(replay, vector=vector):
                        role_request = replay["request"]["roles"]["buyer"]
                        if "legacyEraEvidence" in role_request:
                            era = role_request["legacyEraEvidence"]
                        else:
                            native = role_request["selectionContext"][
                                "candidateBindings"
                            ][0]["nativeAddress"]
                            era = role_request["legacyEraEvidenceByNativeAddress"][native]
                        era["historicalAnchorReceipt"]["observationDisposition"] = "pruned"

                self._mutated_nonpass(
                    vector, mutate_evidence, scope="finality-or-historical"
                )

    def _first_receipt(self, replay):
        for role_request in replay["request"]["roles"].values():
            for receipt in (role_request.get("anchorReceiptsByNativeAddress") or {}).values():
                return receipt
            if "anchorReceipt" in role_request:
                return role_request["anchorReceipt"]
            for era in (
                role_request.get("legacyEraEvidenceByNativeAddress") or {}
            ).values():
                if era:
                    return era["checkpointReceipt"]
            if "legacyEraEvidence" in role_request:
                return role_request["legacyEraEvidence"]["checkpointReceipt"]
        raise AssertionError("no anchor receipt found")

    def test_authority_mutations_change_the_bound_payload_and_never_pass(self):
        case = self.cases["historical-original-bundle-binding"]

        def mutate_role_authority(replay):
            replay["trustedContext"]["roleMap"][0]["participantIdentity"] = (
                "did:fixture:untrusted-buyer"
            )

        self._mutated_nonpass(case, mutate_role_authority, scope="role-authority")

        def mutate_party_roles(replay):
            replay["verifierConfig"]["partyRolesByJob"] = {}

        self._mutated_nonpass(case, mutate_party_roles, scope="partyRolesByJob")

        def mutate_query_authority(replay):
            replay["trustedContext"]["query"]["authenticated"] = False

        self._mutated_nonpass(case, mutate_query_authority, scope="query-authority")

        def mutate_verification_keys(replay):
            replay["verificationKeys"]["keys"][next(iter(
                replay["verificationKeys"]["keys"]
            ))] = "A" * 43

        self._mutated_nonpass(case, mutate_verification_keys, scope="verification-keys")

        def mutate_steward_authority(replay):
            replay["verifierConfig"]["authorizedStewardBySubstrate"] = {}

        self._mutated_nonpass(
            case, mutate_steward_authority, scope="authorized-steward"
        )

        def mutate_pinned_anchor_hash(replay):
            pins = replay["verifierConfig"]["pinnedSyntheticAnchorProofHashBySubject"]
            pins[next(iter(pins))] = "00" * 32

        self._mutated_nonpass(case, mutate_pinned_anchor_hash, scope="pinned-hash")

    def test_receipt_mutations_change_the_bound_payload_and_never_pass(self):
        case = self.cases["historical-original-bundle-binding"]
        role_request = case["replay"]["request"]["roles"]["buyer"]
        native = role_request["selectionContext"]["candidateBindings"][0]["nativeAddress"]
        era = role_request["legacyEraEvidenceByNativeAddress"][native]
        receipts = (
            ("current", role_request["anchorReceiptsByNativeAddress"][native]),
            ("checkpoint", era["checkpointReceipt"]),
            ("historical", era["historicalAnchorReceipt"]),
        )
        for scope, receipt in receipts:
            for field in ("transactionRef", "writer"):
                with self.subTest(receipt=scope, field=field):
                    def mutate(replay, receipt=scope, field=field):
                        target = self._receipt(replay, receipt)
                        target[field] = "mutated"
                    self._mutated_nonpass(case, mutate, scope="%s.%s" % (scope, field))
            for field in ("nonce", "height", "index"):
                with self.subTest(receipt=scope, field=field):
                    def mutate(replay, receipt=scope, field=field):
                        target = self._receipt(replay, receipt)
                        if field == "nonce":
                            target["nonce"] += 1
                        else:
                            target["position"][field] += 1
                    self._mutated_nonpass(case, mutate, scope="%s.%s" % (scope, field))

    def _receipt(self, replay, scope):
        role_request = replay["request"]["roles"]["buyer"]
        if scope == "current":
            native = role_request["selectionContext"]["candidateBindings"][0]["nativeAddress"]
            return role_request["anchorReceiptsByNativeAddress"][native]
        if scope == "pure-current":
            return role_request["anchorReceipt"]
        native = role_request["selectionContext"]["candidateBindings"][0]["nativeAddress"]
        era = role_request["legacyEraEvidenceByNativeAddress"][native]
        return era["checkpointReceipt" if scope == "checkpoint" else "historicalAnchorReceipt"]

    def test_finality_and_historical_evidence_mutations_never_pass(self):
        finality_case = self.cases["current-use-block-depth"]

        def mutate_finality_candidate(replay):
            authority = next(iter(replay["dependencies"]["bundleAuthorityByContentHash"].values()))
            candidate = next(iter(authority["finalityVerificationByCanonicalRef"].values()))
            candidate["context"]["observation"]["transactionRef"]["txHash"] = "ff" * 32

        self._mutated_nonpass(
            finality_case, mutate_finality_candidate, scope="finality-candidate"
        )

        def mutate_finality_trust(replay):
            replay["verifierConfig"]["finalityTrust"]["sessionAuthorityByJob"] = {}

        self._mutated_nonpass(
            finality_case, mutate_finality_trust, scope="finality-trust"
        )

        def mutate_provider_attestations(replay):
            replay["verifierConfig"]["finalityTrust"]["providerAttestations"] = {}

        provider_case = self.cases["current-use-provider-receipt"]
        self._mutated_nonpass(
            provider_case, mutate_provider_attestations, scope="provider-attestations"
        )

        historical_case = self.cases["historical-original-bundle-binding"]

        def mutate_historical_evidence(replay):
            role_request = replay["request"]["roles"]["buyer"]
            native = role_request["selectionContext"]["candidateBindings"][0]["nativeAddress"]
            era = role_request["legacyEraEvidenceByNativeAddress"][native]
            era["historicalAnchorReceipt"]["observationDisposition"] = "pruned"

        self._mutated_nonpass(
            historical_case, mutate_historical_evidence, scope="historical-evidence"
        )

        def mutate_original_mapping(replay):
            role_request = replay["request"]["roles"]["buyer"]
            native = role_request["selectionContext"]["candidateBindings"][0]["nativeAddress"]
            era = role_request["legacyEraEvidenceByNativeAddress"][native]
            era["originalMapping"]["binding"]["bundleContentHash"] = "00" * 32

        self._mutated_nonpass(
            historical_case, mutate_original_mapping, scope="original-mapping"
        )

        def mutate_checkpoint_candidate(replay):
            role_request = replay["request"]["roles"]["buyer"]
            native = role_request["selectionContext"]["candidateBindings"][0]["nativeAddress"]
            era = role_request["legacyEraEvidenceByNativeAddress"][native]
            era["checkpointCandidates"][0]["nativeAddress"] = "native-mutated-checkpoint"

        self._mutated_nonpass(
            historical_case, mutate_checkpoint_candidate, scope="checkpoint-candidate"
        )

        def mutate_dependency_bundle(replay):
            address = next(iter(replay["dependencies"]["bundlesByNativeAddress"]))
            bundle = replay["dependencies"]["bundlesByNativeAddress"][address]
            bundle["outcome"] = "completed"

        self._mutated_nonpass(
            historical_case, mutate_dependency_bundle, scope="dependency-bundle"
        )

    def test_pure_mapping_case_receipt_and_era_mutations_never_pass(self):
        case = self.cases["historical-original-pure-mapping"]

        def mutate_current_receipt(replay):
            self._receipt(replay, "pure-current")["nativeAddress"] = "pure-mutated"

        self._mutated_nonpass(case, mutate_current_receipt, scope="pure-current-receipt")

        def mutate_era_mapping(replay):
            era = replay["request"]["roles"]["buyer"]["legacyEraEvidence"]
            era["originalMapping"]["nonce"] += 1

        self._mutated_nonpass(case, mutate_era_mapping, scope="pure-era-mapping")

        def mutate_resolved_address(replay):
            role_request = replay["request"]["roles"]["buyer"]
            role_request["resolvedAddress"] = "pure-mutated-current-address"

        self._mutated_nonpass(case, mutate_resolved_address, scope="pure-resolved-address")

    def test_all_six_finality_models_and_both_historical_arms_replay(self):
        for vector in self.data["vectors"]:
            if vector["expected"] != "pass":
                continue
            with self.subTest(case=vector["name"]):
                result = execute(vector["replay"])
                self.assertEqual("pass", result["decision"], result["reason"])
                derivation = result["derivation"]
                self.assertEqual(1, derivation["bundleCount"])
                metrics = derivation["metrics"]
                if vector["name"].startswith("current-use-"):
                    self.assertEqual(1.0, metrics["completionRate"])
                    self.assertEqual(1.0, metrics["counterpartyAdjustedCompletionRate"])
                    self.assertEqual(0.0, metrics["counterpartyFaultRate"])
                    observed = metrics["finalityClassifiedVolume"]
                    expected_key = (
                        "provisionalProviderCapture"
                        if vector["finalityClass"] == "provisional-provider-capture"
                        else "profileFinal"
                    )
                    other_key = (
                        "profileFinal"
                        if expected_key == "provisionalProviderCapture"
                        else "provisionalProviderCapture"
                    )
                    self.assertEqual(
                        [], observed[other_key]["observedTransactionalVolume"]
                    )
                    self.assertEqual(
                        1,
                        observed[expected_key]["transactionCountByCurrency"][0]["count"],
                    )
                    self.assertEqual(
                        vector["currency"],
                        observed[expected_key]["observedTransactionalVolume"][0]["currency"],
                    )
                else:
                    self.assertEqual(0.0, metrics["completionRate"])
                    self.assertIsNone(metrics["counterpartyAdjustedCompletionRate"])
                    self.assertEqual(1.0, metrics["counterpartyFaultRate"])

    def test_legacy_negative_cases_reach_the_named_lab_guard(self):
        expected_reasons = {
            "buyer-seller-role-rebinding": ("fail", "historical receipt does not join the exact job, role, and content hash"),
            "seller-buyer-role-rebinding": ("fail", "historical receipt does not join the exact job, role, and content hash"),
            "fresh-post-checkpoint-legacy-creation": ("fail", "legacy bundle anchor is not strictly before the checkpoint"),
            "post-checkpoint-anchor-without-pre-checkpoint-proof": ("fail", "legacy bundle anchor is not strictly before the checkpoint"),
            "missing-era-proof": ("indeterminate", "legacy era evidence is unavailable"),
        }
        for name, (decision, reason) in expected_reasons.items():
            with self.subTest(case=name):
                vector = self.cases[name]
                lab_results = []
                original_guard = D5.validate_legacy_bundle_admission

                def trace_lab(*args):
                    outcome = original_guard(*args)
                    lab_results.append(outcome)
                    return outcome

                with mock.patch.object(
                    D5, "validate_legacy_bundle_admission",
                    side_effect=trace_lab,
                ) as lab_guard:
                    result = execute(vector["replay"])
                self.assertGreater(lab_guard.call_count, 0, "earlier admission gate blocked LAB")
                self.assertIn((decision, reason), lab_results)
                self.assertEqual(decision, result["decision"], result["reason"])
                self.assertTrue(result["reason"].endswith(reason), result["reason"])
                self.assertIsNone(result["derivation"])

    def test_legacy_negative_cases_pass_a_verifier_missing_only_their_guard(self):
        """Bounded wrong implementations: drop one LAB guard and the case passes.

        Each negative is otherwise admitted, so a decision-only runner cannot
        satisfy it through an earlier gate (LAB-2 included) or later divergence.
        """
        original_guard = D5.validate_legacy_bundle_admission
        original_mapping = D5._verify_original_binding_mapping

        class RoleBlindReceipt(dict):
            """Signed receipt bytes unchanged; the LAB-3 role read is skipped."""

            def get(self, key, default=None):
                if key == "subjectRole":
                    return self.claimed_role
                return dict.get(self, key, default)

        def mapping_without_tuple_join(*args):
            outcome = original_mapping(*args)
            if outcome == ("fail", "historical receipt does not join the original BundleBinding tuple"):
                return ("pass", "LAB-3 tuple join omitted")
            return outcome

        def without_lab3(bundle, evidence, dependencies, verifier_config):
            evidence = dict(evidence)
            receipt = RoleBlindReceipt(evidence["historicalAnchorReceipt"])
            receipt.claimed_role = evidence["resolvedRole"]
            evidence["historicalAnchorReceipt"] = receipt
            with mock.patch.object(D5, "_verify_original_binding_mapping", mapping_without_tuple_join):
                return original_guard(bundle, evidence, dependencies, verifier_config)

        def without_lab6(bundle, evidence, dependencies, verifier_config):
            if evidence is None:
                return ("pass", "missing era evidence treated as historical")
            return original_guard(bundle, evidence, dependencies, verifier_config)

        lab3 = mock.patch.object(D5, "validate_legacy_bundle_admission", side_effect=without_lab3)
        lab4 = mock.patch.object(D5, "_strictly_before", return_value=True)
        lab6 = mock.patch.object(D5, "validate_legacy_bundle_admission", side_effect=without_lab6)
        mutants = {
            "buyer-seller-role-rebinding": lab3,
            "seller-buyer-role-rebinding": lab3,
            "fresh-post-checkpoint-legacy-creation": lab4,
            "post-checkpoint-anchor-without-pre-checkpoint-proof": lab4,
            "missing-era-proof": lab6,
        }
        self.assertEqual(
            set(mutants),
            {vector["name"] for vector in self.data["vectors"] if vector["expected"] != "pass"},
        )
        authentic = execute(self.cases["historical-original-bundle-binding"]["replay"])
        self.assertEqual(1.0, authentic["derivation"]["metrics"]["counterpartyFaultRate"])
        for name, mutant in mutants.items():
            with self.subTest(case=name):
                with mutant:
                    result = execute(self.cases[name]["replay"])
                self.assertEqual("pass", result["decision"], result["reason"])
                self.assertIsNotNone(result["derivation"])
                if name.endswith("role-rebinding"):
                    # Without LAB-3 the rebound abort reverses the authentic blame.
                    metrics = result["derivation"]["metrics"]
                    self.assertEqual(0.0, metrics["counterpartyFaultRate"])
                    self.assertEqual(0.0, metrics["counterpartyAdjustedCompletionRate"])


if __name__ == "__main__":
    unittest.main()
