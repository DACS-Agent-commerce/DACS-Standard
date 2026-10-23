"""Payment authority, durable retention and finality contracts."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts import generate_settlement_finality_verification_vectors as fv
from scripts.demos_identity import demos_key_claim
from scripts.settlement_finality_reference import artifact_hash, verify_finality
from tests import pay_dem_reference_handler as handler
from tests import test_pay_dem_execution_vectors as pay

ROOT = Path(__file__).resolve().parents[1]


class PayDemPaymentAuthorityTests(unittest.TestCase):
    def test_verified_result_does_not_require_plain_rpc_agreement(self):
        record = pay.generator.record("confirmed")
        for state in ("confirmed", "pending", "failed", "wrong-hash", "not-found", "unavailable"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as scratch:
                read = pay.generator.found(record, authenticated=True)
                read["record"] = copy.deepcopy(record)
                if state in ("pending", "failed"):
                    read["record"]["status"] = state
                elif state == "wrong-hash":
                    read["record"]["hash"] = pay.generator.OTHER_TX_HASH
                elif state in ("not-found", "unavailable"):
                    read["state"] = state
                    read.pop("record")
                work = Path(scratch)
                payee = handler.Payee(handler.Store(work / "store"), work, "review")
                payee.provision()
                self.assertEqual("pass", payee.deliver(pay.generator.JOB_ID, read=read))
                self.assertEqual(1, len(payee.delivered()))
                # The plain read cannot rescue an unauthenticated result.
                read["executionResult"]["attestations"] = []
                self.assertEqual("indeterminate", payee.deliver(pay.generator.JOB_ID, read=read))

    def test_claim_grammar_precedes_non_demos_filtering(self):
        factory = fv.FixtureFactory()
        value = factory.model_input("bft-final")
        payer = factory.trusted["sessionAuthorityByJob"][value["agreement"]["jobId"]]["payer"]
        original = copy.deepcopy(factory.trusted["demosPayerKeyClaims"][payer])
        for claim in ("key:", "key:not-hex", "did:demos:agent:", "bad_scheme:abc", "KEY:" + "ab" * 32, "lei:"):
            with self.subTest(claim=claim):
                factory.trusted["demosPayerKeyClaims"][payer] = original + [fv.controlled_claim(claim)]
                self.assertEqual("error", verify_finality(value, factory.trusted)["decision"])
        for claim in ("lei:5493001KJTIIGC8Y1R12", "future-scheme:opaque?z=1&a=2", "did:example:123"):
            with self.subTest(claim=claim):
                self.assertIsNone(demos_key_claim(claim))
                factory.trusted["demosPayerKeyClaims"][payer] = [fv.controlled_claim(claim)] + original
                self.assertEqual("pass", verify_finality(value, factory.trusted)["decision"])

    def test_payee_bound_agreement_requires_a_destination_capable_codec(self):
        for model in fv.MODEL_PHASE:
            factory = fv.FixtureFactory()
            value = factory.model_input(model)
            self.assertEqual("pass", verify_finality(value, factory.trusted)["decision"])
            agreement = value["agreement"]
            agreement.pop("agreementVersion")
            agreement["payeeBoundAgreementVersion"] = "1"
            session = factory.trusted["sessionAuthorityByJob"][agreement["jobId"]]
            for destination in (factory.demos_key("seller"), factory.demos_key("orchestrator")):
                with self.subTest(model=model, destination=destination):
                    agreement["terms"]["payoutBindings"] = [{
                        "railId": session["railId"], "phaseIndex": session["phaseIndex"],
                        "payeeAddress": destination,
                    }]
                    digest = artifact_hash(agreement, "signatures")
                    for signature, role in zip(agreement["signatures"], ("buyer", "seller")):
                        signature["value"] = factory.sign_digest(role, "dacs-payee-bound-agreement:v1:", digest)
                    session["agreementHash"] = digest
                    decision = verify_finality(value, factory.trusted)["decision"]
                    expected = ("pass" if destination == factory.demos_key("seller") else "fail") if model == "bft-final" else "indeterminate"
                    self.assertEqual(expected, decision)

    def test_nondefault_nonce_is_retained_and_submitted_after_restart(self):
        for nonce in (pay.generator.NONCE, pay.generator.NONCE + 1):
            with self.subTest(nonce=nonce), tempfile.TemporaryDirectory() as scratch:
                work = Path(scratch)
                transaction = pay.generator.signed(pay.generator.send_content(nonce=nonce, amount=pay.generator.AMOUNT_OS))
                store = handler.Store(work / "store")
                first = handler.PayerHandler(store, handler.Node(work, "first"), "first", crash_at="after-retain")
                with self.assertRaises(handler.Crashed):
                    first.pay(transaction)
                retained = store.read(first.journal)["retainedTransfer"]
                self.assertEqual(str(nonce), str(retained["nonce"]))
                projection = pay.decode(transaction, frozenset(), executed=False)
                for field in ("txHash", "nonce", "sender", "recipient", "amountOs"):
                    self.assertEqual(str(projection[field]), str(retained[field]))
                later = handler.PayerHandler(store, handler.Node(work, "later"), "later",
                    recovery=handler.RecoveryAuthority(pay.generator.NETWORK))
                later.recover()
                calls = handler.read_lines(work / "egress.jsonl")
                self.assertEqual(["confirm", "broadcast"], [call["call"] for call in calls])
                self.assertTrue(all(handler.same_signed_bytes(transaction, call["transaction"]) for call in calls))

    def test_open_payment_rules_resume_on_verified_success(self):
        settle = (ROOT / "spec/DACS-4-SETTLE.md").read_text()
        verify = (ROOT / "spec/DACS-5-VERIFY.md").read_text()
        self.assertNotIn("until DEM-3 success is anchored", settle + verify)
        self.assertIn("until DEM-3 success verifies or DEM-4 proves failure", settle)
        self.assertIn("MUST NOT delay resuming the remaining pipeline", verify)
        self.assertIn("separately under PC-7", settle)

    def test_finality_rule_distinguishes_checkpoint_absence(self):
        settle = (ROOT / "spec/DACS-4-SETTLE.md").read_text()
        paragraph = next(line for line in settle.splitlines() if line.startswith("**Finality.** Demos"))
        self.assertIn("nonce-exhaustion terminal", paragraph)
        self.assertIn("finalized checkpoint block and cumulative retained-hash absence", paragraph)

    def test_consistent_uppercase_vector_and_lowercase_control(self):
        data = json.loads((ROOT / "conformance/vectors/security/settlement-finality-verification.json").read_text())
        cases = {case["name"]: case for case in data["vectors"]}
        value = cases["fv-bft-final-consistently-uppercase-hash"]["input"]
        reference = value["evidence"]["paymentTxRefs"][0]
        observation = value["context"]["observation"]
        proof = observation["transactionInclusionProof"]
        encoded = proof["transactionBytes"]
        body = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertNotEqual(reference["txHash"].lower(), reference["txHash"])
        self.assertEqual(reference, body["transactionRef"])
        self.assertEqual(reference["txHash"], body["txHash"])
        self.assertEqual(reference, observation["executionResult"]["transactionRef"])
        self.assertEqual(reference["txHash"], observation["executionResult"]["record"]["hash"])
        self.assertEqual("error", verify_finality(value, data["trustedFixturePolicy"])["decision"])
        control = cases["fv-bft-final-canonical-success"]["input"]
        self.assertEqual("pass", verify_finality(control, data["trustedFixturePolicy"])["decision"])

    def test_summary_rules_match_guarded_recovery_and_pb_tiers(self):
        settle = (ROOT / "spec/DACS-4-SETTLE.md").read_text()
        plan = (ROOT / "spec/CONFORMANCE-PLAN.md").read_text()
        readme = (ROOT / "conformance/vectors/security/README.md").read_text()
        changelog = (ROOT / "CHANGELOG.md").read_text()
        self.assertNotIn("forbids a second broadcast", settle)
        self.assertNotIn("Submit it once", settle)
        self.assertNotIn("tier-1 intrinsic and tier-2 controlled-claim positive cases", plan)
        self.assertNotIn("`pay-dem` intrinsic addressing binds at tier 1", readme)
        self.assertIn("`identity-bundle-hash-binding-v0.1` corpus is regenerated", changelog)
        self.assertIn("provisioned effective-fork attestation", settle)
        mapping = (ROOT / "spec/DEMOS-MAPPING.md").read_text()
        self.assertNotIn("independently authenticated active nonce enforcement", mapping + changelog)


if __name__ == "__main__":
    unittest.main()
