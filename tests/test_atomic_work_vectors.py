"""Determinism and semantic conformance tests for Atomic DACS Work vectors."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import atomic_work_reference as ref  # noqa: E402
import generate_atomic_work_vectors as generator  # noqa: E402
import validate_atomic_work_vectors as validator  # noqa: E402


class AtomicWorkVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = [
            ROOT / "conformance" / "vectors" / "security" / f"{name}.json"
            for name in generator.SET_SPECS
        ]
        cls.sets = [json.loads(path.read_text(encoding="utf-8")) for path in cls.paths]

    def test_strict_validator_accepts_corpus(self):
        errors, set_count, vector_count = validator.validate_all()
        self.assertEqual(errors, [])
        self.assertEqual(set_count, 6)
        self.assertEqual(vector_count, 297)

    def test_proof_byte_limit_uses_canonical_material_size(self):
        execution = next(
            data for data in self.sets
            if data["set"] == "atomic-work-execution-recovery-v0.1"
        )
        by_name = {vector["name"]: vector for vector in execution["vectors"]}
        at_limit = by_name["aw-proof-byte-limit-equality"]
        over_limit = by_name["aw-proof-byte-limit-one-over"]
        limit = at_limit["input"]["capability"]["limits"]["maxProofBytes"]
        self.assertEqual(
            len(ref.proof_package_bytes(
                at_limit["input"]["proofMaterial"],
                at_limit["input"]["proofReservationEvidence"],
            )),
            limit,
        )
        self.assertEqual(
            len(ref.proof_package_bytes(
                over_limit["input"]["proofMaterial"],
                over_limit["input"]["proofReservationEvidence"],
            )),
            limit + 1,
        )
        self.assertEqual(ref.evaluate_vector(at_limit)[0], "pass")
        self.assertEqual(ref.evaluate_vector(over_limit)[0], "fail")

    def test_receipt_storage_and_signed_slot_payload_are_exact(self):
        execution = next(
            data for data in self.sets
            if data["set"] == "atomic-work-execution-recovery-v0.1"
        )
        by_name = {vector["name"]: vector for vector in execution["vectors"]}
        accepted = by_name["aw-receipt-complete-and-final"]
        intent = accepted["input"]["intent"]
        receipt = accepted["input"]["receipt"]
        signed_slot = intent["operations"][4]["payload"]
        self.assertEqual(receipt["paymentSlot"]["before"], signed_slot["expected"])
        self.assertEqual(
            receipt["paymentSlot"]["after"]["conflictDigest"],
            signed_slot["conflictDigest"],
        )
        for name in (
            "aw-receipt-storage-output-missing",
            "aw-receipt-slot-before-generation-mismatch",
            "aw-receipt-slot-after-generation-mismatch",
            "aw-receipt-slot-after-digest-mismatch",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(by_name[name])[0], "fail")

    def test_slot_authority_derives_accounts_and_exact_commitment(self):
        settlement = next(
            data for data in self.sets
            if data["set"] == "atomic-work-settlement-slot-v0.1"
        )
        by_name = {vector["name"]: vector for vector in settlement["vectors"]}
        accepted = by_name["aws-structured-network-slot-cas"]
        payer = accepted["input"]["slotAuthority"]["paymentPhaseInput"]["payer"]
        self.assertNotIn("nativeAccount", payer)
        self.assertEqual(ref.evaluate_vector(accepted)[0], "pass")
        for name in (
            "aws-commitment-other-job-substitution",
            "aws-arbitrary-payer-account",
            "aws-arbitrary-payee-account",
            "aws-arbitrary-roster-native-account",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(by_name[name])[0], "fail")
        profiles = next(
            data for data in self.sets
            if data["set"] == "atomic-work-purchase-completion-v0.1"
        )
        profiles_by_name = {
            vector["name"]: vector for vector in profiles["vectors"]
        }
        for name in (
            "awp-commitment-job-binding",
            "awp-commitment-listing-binding",
        ):
            with self.subTest(name=name):
                self.assertEqual(
                    ref.evaluate_vector(profiles_by_name[name])[0], "fail"
                )

    def test_projected_anchor_uses_complete_core_shape(self):
        execution = next(
            data for data in self.sets
            if data["set"] == "atomic-work-execution-recovery-v0.1"
        )
        by_name = {vector["name"]: vector for vector in execution["vectors"]}
        accepted = by_name["aw-anchor-projection"]
        anchor = accepted["input"]["anchorReceipt"]
        self.assertEqual(
            set(anchor),
            {
                "receiptVersion", "substrate", "finalityProfile",
                "logicalAddress", "nativeAddress", "contentHash",
                "transactionRef", "writer", "nonce", "state",
                "observationDisposition", "observedAt", "blockRef", "evidence",
            },
        )
        self.assertNotIn("networkId", anchor)
        self.assertEqual(ref.evaluate_vector(accepted)[0], "pass")
        for name in (
            "aw-anchor-finality-field-missing",
            "aw-anchor-nonce-mutated",
            "aw-anchor-networkid-shortcut-rejected",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(by_name[name])[0], "fail")

    def test_base64url_is_canonical_and_ed25519_lengths_are_exact(self):
        self.assertEqual(ref.b64u_decode("_w"), b"\xff")
        with self.assertRaisesRegex(ref.Invalid, "non-canonical"):
            ref.b64u_decode("_x")
        with self.assertRaisesRegex(ref.Invalid, "unpadded"):
            ref.b64u_decode("A")

        authorization = next(
            data for data in self.sets
            if data["set"] == "atomic-work-authorization-v0.1"
        )
        by_name = {vector["name"]: vector for vector in authorization["vectors"]}
        for name in (
            "aw-auth-signature-base64url-alias",
            "aw-auth-signature-wrong-length",
            "aw-auth-public-key-wrong-length",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(by_name[name])[0], "fail")

    def test_capability_scope_is_consumed_by_authorization_and_receipts(self):
        authorization = next(
            data for data in self.sets
            if data["set"] == "atomic-work-authorization-v0.1"
        )
        execution = next(
            data for data in self.sets
            if data["set"] == "atomic-work-execution-recovery-v0.1"
        )
        auth_by_name = {vector["name"]: vector for vector in authorization["vectors"]}
        receipt_by_name = {vector["name"]: vector for vector in execution["vectors"]}
        for name in (
            "aw-auth-capability-network-substitution",
            "aw-auth-capability-execution-substitution",
            "aw-auth-capability-profile-substitution",
            "aw-auth-capability-schema-substitution",
            "aw-auth-capability-operation-kind-duplicate",
            "aw-auth-capability-proof-profile-substitution",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(auth_by_name[name])[0], "fail")
        for name in (
            "aw-receipt-capability-proof-profile-substitution",
            "aw-receipt-capability-schema-substitution",
            "aw-receipt-malformed-operation-payload",
            "aw-completion-storage-bytes-content-hash-mismatch",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(receipt_by_name[name])[0], "fail")

    def test_lifecycle_evidence_binds_exact_native_transaction_ref(self):
        execution = next(
            data for data in self.sets
            if data["set"] == "atomic-work-execution-recovery-v0.1"
        )
        by_name = {vector["name"]: vector for vector in execution["vectors"]}
        accepted = by_name["aw-lifecycle-noninclusion-proof"]
        self.assertEqual(
            accepted["input"]["evidence"]["nativeTransactionRef"],
            accepted["input"]["nativeTransactionRef"],
        )
        self.assertEqual(ref.evaluate_vector(accepted)[0], "pass")
        for name in (
            "aw-attempt-evidence-native-ref-mismatch",
            "aw-lifecycle-native-ref-mismatch",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(by_name[name])[0], "fail")

    def test_all_normative_rules_have_vector_coverage(self):
        covered = {
            rule
            for data in self.sets
            for vector in data["vectors"]
            for rule in vector["ruleRefs"]
        }
        self.assertEqual(covered, validator.EXPECTED_RULES)

    def test_applicable_polarity_coverage_is_complete_and_honest(self):
        report = validator.coverage_report()
        self.assertEqual(
            report["classification"],
            "candidate-complete-applicable-polarity",
        )
        self.assertTrue(report["completeApplicablePolarity"])
        self.assertFalse(report["nonGatingPolarityGaps"])
        self.assertEqual(set(report["byRule"]), validator.EXPECTED_RULES)
        self.assertEqual(report["missing"], {"P": [], "N": [], "B": []})
        self.assertEqual(
            report["applicabilityConflicts"],
            {"P": [], "N": [], "B": []},
        )
        self.assertTrue(report["notApplicable"]["P"])
        self.assertTrue(report["notApplicable"]["N"])
        self.assertTrue(report["notApplicable"]["B"])
        self.assertIn("X", "".join(report["byRule"].values()))

    def test_boundary_attribution_is_rule_specific(self):
        for data in self.sets:
            for vector in data["vectors"]:
                boundary_rules = vector.get("boundaryRuleRefs")
                if vector.get("boundary") is True:
                    self.assertTrue(boundary_rules)
                    self.assertLessEqual(
                        set(boundary_rules), set(vector["ruleRefs"])
                    )
                    self.assertLessEqual(
                        set(boundary_rules), generator.BOUNDARY_APPLICABLE_RULES
                    )
                else:
                    self.assertNotIn("boundaryRuleRefs", vector)

    def test_job_ids_and_signers_use_normative_wire_shapes(self):
        def walk(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key == "jobId":
                        self.assertIsInstance(child, str)
                        self.assertRegex(child, ref.JOB_ID)
                    if key == "signer":
                        self.assertIsInstance(child, str)
                        self.assertRegex(child, ref.CLAIM_REFERENCE)
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        for data in self.sets:
            walk(data["vectors"])

        malformed = generator.purchase_intent()
        malformed["roleRoster"][0]["signer"] = {
            "kind": "did", "value": generator.CLAIMS["buyer"]
        }
        with self.assertRaisesRegex(ref.Invalid, "signer|ClaimReference"):
            ref.validate_intent(malformed)

    def test_atomic_settlement_evidence_uses_normative_shape(self):
        settlement = next(
            data for data in self.sets
            if data["set"] == "atomic-work-settlement-slot-v0.1"
        )
        accepted = next(
            vector for vector in settlement["vectors"]
            if vector["name"] == "aws-final-work-receipt-bound"
        )["input"]["evidence"]
        self.assertNotIn("kind", accepted)
        self.assertNotIn("workReceiptHash", accepted)
        self.assertNotIn("settlementPayload", accepted)
        self.assertIn("workReceiptRef", accepted)
        self.assertEqual(
            set(accepted["workReceiptRef"]),
            {"refVersion", "networkId", "workId", "receiptCommitment", "contentHash", "locator"},
        )
        self.assertEqual(
            set(accepted["operationRef"]),
            {"kind", "networkId", "workId", "operationIndex", "operationId", "operationKind"},
        )
        self.assertEqual(
            set(accepted["operationProof"]["subject"]),
            {
                "networkId", "workId", "winningAttemptId", "operationReceiptRoot",
                "operationIndex", "operationId", "operationKind", "receiptContentHash",
            },
        )
        self.assertEqual(accepted["paymentAmount"], {"amount": "10", "currency": "DEM"})
        self.assertEqual(accepted["settlementFinality"]["model"], "bft-final")
        self.assertEqual(accepted["signature"]["signer"], generator.CLAIMS["orchestrator"])
        self.assertEqual(
            ref.settlement_id(accepted["operationRef"]),
            ref.settlement_id({**accepted["operationRef"], "extra": True}),
        )

    def test_expiry_boundary_is_strict(self):
        identity = next(
            data for data in self.sets if data["set"] == "atomic-work-identity-v0.1"
        )
        by_name = {vector["name"]: vector for vector in identity["vectors"]}
        self.assertEqual(
            ref.evaluate_vector(by_name["aw-expiry-last-valid-millisecond"])[0], "pass"
        )
        self.assertEqual(
            ref.evaluate_vector(by_name["aw-expiry-equality-rejected-before-op"])[0], "fail"
        )

    def test_payload_schemas_are_complete_authenticated_and_closed(self):
        identity = next(
            data for data in self.sets if data["set"] == "atomic-work-identity-v0.1"
        )
        by_name = {vector["name"]: vector for vector in identity["vectors"]}
        exact = by_name["aw-payload-schema-exact-profile"]
        self.assertEqual(
            exact["input"]["capability"]["payloadSchemas"], ref.PAYLOAD_SCHEMAS
        )
        self.assertEqual(ref.evaluate_vector(exact)[0], "pass")
        self.assertEqual(
            ref.evaluate_vector(by_name["aw-payload-schema-kind-missing"])[0], "fail"
        )
        self.assertEqual(
            ref.evaluate_vector(by_name["aw-payload-schema-version-unsupported"])[0], "fail"
        )
        self.assertEqual(
            ref.evaluate_vector(by_name["aw-payload-schema-no-caller-inference"])[0], "fail"
        )

    def test_role_anchor_uses_external_party_maps_and_both_works(self):
        role_set = next(
            data for data in self.sets if data["set"] == "atomic-work-audit-role-v0.1"
        )
        by_name = {vector["name"]: vector for vector in role_set["vectors"]}
        self.assertEqual(ref.evaluate_vector(by_name["awb-completion-receipt-not-final"])[0], "fail")
        self.assertEqual(ref.evaluate_vector(by_name["awb-receipt-dependent-bundle-in-completion"])[0], "fail")
        self.assertEqual(ref.evaluate_vector(by_name["awb-work-carried-bundle-profile-deferred"])[0], "indeterminate")
        self.assertEqual(ref.evaluate_vector(by_name["awb-purchase-evidence-required"])[0], "indeterminate")
        self.assertEqual(ref.evaluate_vector(by_name["awb-purchase-completion-mismatch"])[0], "indeterminate")
        self.assertEqual(ref.evaluate_vector(by_name["awb-self-consistent-forged-roster"])[0], "indeterminate")

    def test_receipt_slot_transition_and_retry_intent_are_bound(self):
        execution = next(
            data for data in self.sets
            if data["set"] == "atomic-work-execution-recovery-v0.1"
        )
        receipt_input = next(
            vector["input"] for vector in execution["vectors"]
            if vector["name"] == "aw-receipt-complete-and-final"
        )
        intent, receipt = receipt_input["intent"], receipt_input["receipt"]
        self.assertEqual(
            receipt["paymentSlot"]["key"],
            {
                "networkId": intent["networkId"], "railId": intent["railId"],
                "jobId": intent["jobId"], "phaseIndex": intent["phaseIndex"],
            },
        )
        self.assertEqual(receipt["paymentSlot"]["before"]["state"], "vacant")
        self.assertEqual(receipt["paymentSlot"]["after"]["state"], "settled")
        self.assertEqual(receipt["receiptCommitment"], ref._receipt_commitment(receipt))
        self.assertEqual(ref.receipt_hash(receipt), ref.sha256_hex(ref.jcs_bytes(receipt)))

        slot_set = next(
            data for data in self.sets
            if data["set"] == "atomic-work-settlement-slot-v0.1"
        )
        retry = next(
            vector["input"] for vector in slot_set["vectors"]
            if vector["name"] == "aws-retry-after-rollback"
        )
        retry_intent = retry["work"]["intent"]
        self.assertEqual(
            retry_intent["priorFailureReceiptCommitment"],
            retry["ledgerProof"]["state"]["failureReceiptCommitment"],
        )
        self.assertEqual(retry["work"]["workId"], ref.work_id(retry_intent))
        self.assertEqual(
            retry_intent["operations"][4]["payload"]["expected"],
            {
                "state": "rolled-back",
                "generation": retry["ledgerProof"]["state"]["generation"],
            },
        )
        self.assertEqual(
            retry["newState"]["generation"],
            retry["ledgerProof"]["state"]["generation"] + 1,
        )

        by_name = {vector["name"]: vector for vector in slot_set["vectors"]}
        for name in (
            "aws-retry-committed-receipt-generation",
            "aws-retry-rollback-receipt-generation",
        ):
            with self.subTest(name=name):
                candidate = by_name[name]
                self.assertEqual(ref.evaluate_vector(candidate)[0], "pass")
                before = candidate["input"]["receipt"]["paymentSlot"]["before"]
                after = candidate["input"]["receipt"]["paymentSlot"]["after"]
                self.assertEqual(after["generation"], before["generation"] + 1)

    def test_composed_admission_is_the_whole_profile_verdict(self):
        profiles = next(
            data for data in self.sets
            if data["set"] == "atomic-work-purchase-completion-v0.1"
        )
        by_name = {vector["name"]: vector for vector in profiles["vectors"]}
        self.assertEqual(
            ref.evaluate_vector(by_name["awp-purchase-composed-admission"])[0],
            "pass",
        )
        self.assertEqual(
            ref.evaluate_vector(by_name["awp-completion-composed-admission"])[0],
            "pass",
        )
        self.assertEqual(
            ref.evaluate_vector(
                by_name["awp-purchase-composed-retry-admission"]
            )[0],
            "pass",
        )
        self.assertNotIn(
            "commitmentReceipt",
            by_name["awp-purchase-composed-admission"]["input"]["authority"],
        )
        for name, verdict in (
            ("awp-composed-profile-empty-required-roles", "fail"),
            ("awp-composed-common-receipt-missing", "indeterminate"),
            ("awp-composed-winner-receipt-mismatch", "fail"),
            ("awp-purchase-composed-retry-generation-skip", "fail"),
            ("awp-composed-slot-cross-work-substitution", "fail"),
            ("awp-composed-capability-limit-enforced", "fail"),
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(by_name[name])[0], verdict)

    def test_closed_capability_and_algorithm_confusion_are_rejected(self):
        identity = next(
            data for data in self.sets
            if data["set"] == "atomic-work-identity-v0.1"
        )
        authorization = next(
            data for data in self.sets
            if data["set"] == "atomic-work-authorization-v0.1"
        )
        identity_by_name = {
            vector["name"]: vector for vector in identity["vectors"]
        }
        auth_by_name = {
            vector["name"]: vector for vector in authorization["vectors"]
        }
        for name in (
            "aw-capability-validator-set-empty",
            "aw-capability-fee-rule-unsupported",
            "aw-capability-authorization-algorithm-duplicate",
            "aw-capability-closed-extension",
            "aw-capability-boolean-limit",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(identity_by_name[name])[0], "fail")
        for name in (
            "aw-auth-ecdsa-label-confusion",
            "aw-auth-sr1-label-confusion",
            "aw-auth-boolean-phase-index",
            "aw-auth-boolean-operation-index",
            "aw-auth-rail-phase-handler-mismatch",
            "aw-auth-self-consistent-session-orchestrator-rekey",
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(auth_by_name[name])[0], "fail")
        self.assertEqual(
            ref.evaluate_vector(auth_by_name["aw-auth-cf3-parameter-identity"])[0],
            "pass",
        )

    def test_publication_proof_authenticates_create_only_prior_state(self):
        settlement = next(
            data for data in self.sets
            if data["set"] == "atomic-work-settlement-slot-v0.1"
        )
        by_name = {vector["name"]: vector for vector in settlement["vectors"]}
        self.assertEqual(
            ref.evaluate_vector(by_name["aws-atomic-publication-exact-replay"])[0],
            "pass",
        )
        for name, verdict in (
            ("aws-atomic-publication-write-condition-missing", "indeterminate"),
            ("aws-atomic-publication-prior-state-contradiction", "fail"),
            ("aws-atomic-publication-unsigned-mode-flip", "fail"),
        ):
            with self.subTest(name=name):
                self.assertEqual(ref.evaluate_vector(by_name[name])[0], verdict)

    def test_receipt_witnesses_are_encoded_in_declared_evidence_fields(self):
        execution = next(
            data for data in self.sets
            if data["set"] == "atomic-work-execution-recovery-v0.1"
        )
        receipt = next(
            vector["input"]["receipt"] for vector in execution["vectors"]
            if vector["name"] == "aw-receipt-complete-and-final"
        )
        self.assertNotIn("stateWitness", receipt)
        self.assertEqual(
            set(receipt["businessState"]["evidence"]), {"kind", "value"}
        )
        self.assertEqual(set(receipt["finalityEvidence"]), {"kind", "value"})
        self.assertEqual(set(receipt["slotStateEvidence"]), {"kind", "value"})
        state_witness = json.loads(
            ref.b64u_decode(receipt["businessState"]["evidence"]["value"]).decode()
        )
        checkpoint = json.loads(
            ref.b64u_decode(receipt["finalityEvidence"]["value"]).decode()
        )
        self.assertEqual(
            receipt["businessState"]["preRoot"],
            ref.state_root(state_witness["preState"]),
        )
        ref.verify_embedded(
            state_witness, execution["publicKeys"], ref._STATE_TEST_DOMAIN
        )
        ref.verify_embedded(
            checkpoint, execution["publicKeys"], ref._CHECKPOINT_TEST_DOMAIN
        )

    def test_jcs_vector_hashes_recompute_exactly(self):
        for path, data in zip(self.paths, self.sets):
            with self.subTest(path=path.name):
                self.assertEqual(data["count"], len(data["vectors"]))
                self.assertEqual(data["hash"], ref.vector_hash(data["vectors"]))

    def test_every_expected_verdict_is_computed(self):
        verdict_counts = {verdict: 0 for verdict in ref.VERDICTS}
        for data in self.sets:
            for vector in data["vectors"]:
                actual, diagnostic = ref.evaluate_vector(vector)
                with self.subTest(set=data["set"], vector=vector["name"]):
                    self.assertEqual(actual, vector["expected"], diagnostic)
                verdict_counts[actual] += 1
        self.assertGreater(verdict_counts["pass"], 0)
        self.assertGreater(verdict_counts["fail"], 0)
        self.assertGreater(verdict_counts["indeterminate"], 0)
        # DACS uses ``error`` for a malformed/non-canonical address, distinct
        # from a well-formed semantic mismatch (``fail``).
        self.assertGreater(verdict_counts["error"], 0)

    def test_fixed_seed_signatures_without_optional_crypto(self):
        seed = bytes.fromhex("9d" * 32)
        message = b"Atomic DACS Work deterministic signature self-test"
        public = ref.ed25519_public_key(seed)
        signature = ref.ed25519_sign(seed, message)
        self.assertTrue(ref.ed25519_verify(public, message, signature))
        self.assertFalse(ref.ed25519_verify(public, message + b"!", signature))

    def test_rfc6962_tree_does_not_duplicate_odd_leaf(self):
        leaves = [
            {
                "operationId": f"op-{i}",
                "operationIndex": i,
                "operationKind": "assert-artifact",
                "inputHash": f"{i:064x}",
                "status": "committed",
            }
            for i in range(3)
        ]
        root = ref.operation_receipt_root(leaves)
        for index, leaf in enumerate(leaves):
            path = ref.inclusion_path(leaves, index)
            self.assertTrue(ref.verify_inclusion(leaf, path, root))
        duplicated = ref.operation_receipt_root(leaves + [leaves[-1]])
        self.assertNotEqual(root, duplicated)

    def test_generator_check_is_byte_exact(self):
        run = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "generate_atomic_work_vectors.py"), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("6 byte-identical sets", run.stdout)


if __name__ == "__main__":
    unittest.main()
