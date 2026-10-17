"""PC-1 and AMEND-1 references with independently finalized target fixtures."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import atomic_work_reference as atomic
import generate_settlement_contract_vectors as generator
import settlement_contract_reference as ref

# Enclosing handler metadata is fixed outside the phase input. The fixtures
# cannot choose a profile by adding or removing an input member.
BINDINGS = {
    "ordinary": ref.PhaseBinding("pay-dem"),
    "atomic": ref.PhaseBinding("pay-dem", "dacs-purchase-v1", True),
    "ungated-purchase": ref.PhaseBinding("pay-dem", "dacs-purchase-v1", False),
    "completion": ref.PhaseBinding("pay-dem", "dacs-completion-v1", True),
    "other-payment": ref.PhaseBinding("pay-evm-erc20", "dacs-purchase-v1", True),
}


class SettlementContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(generator.OUTPUT.read_text())

    def consume(self, vector, resolver=None, *, orchestrator=None):
        return ref.consume_amendment_target(
            vector["amendment"], resolver or (lambda _: vector["resolved"]),
            amendment_address=vector["amendmentAddress"],
            orchestrator=orchestrator or self.data["orchestrator"],
            public_keys=self.data["publicKeys"], network_authority="did:dacs:test:network",
            network_id="demos:testnet-atomic", proof_profile="demos-bft-proof/test-1",
            validator_set_id="test-validator-set-1",
        )

    def test_payment_arm_vectors_reject_before_handler_and_preserve_input(self):
        for vector in self.data["phaseInputs"]:
            with self.subTest(vector=vector["name"]):
                value = copy.deepcopy(vector["input"])
                before = copy.deepcopy(value)
                rail = mock.Mock(return_value={"status": "accepted", "ok": True})
                result = ref.dispatch_payment(BINDINGS[vector["binding"]], value, rail)
                self.assertEqual(result["status"], vector["expected"])
                self.assertEqual(value, before)
                if vector["expected"] == "rejected":
                    rail.assert_not_called()
                    self.assertIs(result["ok"], False)
                    self.assertEqual(result["errorClass"], "permanent")
                else:
                    rail.assert_called_once_with(value)
                    self.assertIs(rail.call_args.args[0], value)

    def test_identity_binding_payment_authorization_members_keep_their_arm(self):
        corpus = json.loads((ROOT / "conformance/vectors/security/identity-bundle-hash-binding-v0.1.json").read_text())
        checked = 0
        for name, scenario in corpus["scenarios"].items():
            value = scenario.get("paymentInput")
            if isinstance(value, dict) and "paymentAuthorization" in value:
                with self.subTest(scenario=name):
                    ref.check_payment_input(BINDINGS["ordinary"], value)
                    checked += 1
        self.assertGreater(checked, 0)

    def test_binding_is_selected_before_reading_input(self):
        events = []
        class Binding:
            phase = "pay-dem"
            @property
            def atomic(self):
                events.append("binding")
                return False
        class Input(dict):
            def __contains__(self, key):
                events.append("input")
                return super().__contains__(key)
        with self.assertRaises(ref.InputArmError):
            ref.check_payment_input(Binding(), Input(sessionContext={}))
        self.assertEqual(events[0], "binding")
        self.assertIn("input", events)

    def test_typed_arm_shape_is_checked_before_handler(self):
        # PC-1 accepts the typed arm, not any object carrying its session key.
        names = {v["name"]: v for v in self.data["phaseInputs"]}
        for name in ("ordinary-empty-session-context", "ordinary-null-payer",
                     "atomic-null-payer", "atomic-context-parties-reordered"):
            with self.subTest(vector=name):
                rail = mock.Mock()
                result = ref.dispatch_payment(BINDINGS[names[name]["binding"]],
                                              copy.deepcopy(names[name]["input"]), rail)
                self.assertEqual((result["status"], result["errorClass"]), ("rejected", "permanent"))
                rail.assert_not_called()

    def test_amendment_targets_resolve_hash_select_and_verify(self):
        for vector in self.data["amendmentTargets"]:
            with self.subTest(vector=vector["name"]):
                resolver = mock.Mock(return_value=vector["resolved"])
                result, reason = self.consume(vector, resolver)
                self.assertEqual(result, vector["expected"], reason)
                resolver.assert_called_once_with(vector["amendment"]["amendsEvidenceRef"])
                if result == "valid":
                    record = vector["resolved"]["artifact"]
                    digest = atomic.sha256_hex(atomic.jcs_bytes({
                        k: v for k, v in record.items() if k != "signature"
                    }))
                    self.assertRegex(vector["amendmentAddress"],
                        rf"\Adacs4:amendment:{record['jobId']}:{digest}:(0|[1-9][0-9]*)\Z")

    def test_target_hash_precedes_discriminator_interpretation(self):
        vector = copy.deepcopy(next(v for v in self.data["amendmentTargets"]
                                   if v["name"] == "atomic-target"))
        vector["resolved"]["artifact"]["evidenceVersion"] = "1"
        self.assertEqual(self.consume(vector), (
            "indeterminate", "amendment target content differs from its finalized anchor"))

    def test_every_payment_evidence_arm_is_an_amendment_target(self):
        # AMEND-2 refunds successful transition and finality-bound records too.
        names = {v["name"]: v for v in self.data["amendmentTargets"]}
        for label, selector in (("legacy-transition", "legacyTransitionEvidenceVersion"),
                                ("finality-bound", "finalityBoundEvidenceVersion")):
            with self.subTest(arm=label):
                vector = names[label + "-target"]
                self.assertIn(selector, vector["resolved"]["artifact"])
                self.assertEqual(self.consume(vector), ("valid", "AMEND-1 target verified"))
                for case in ("wrong-domain", "wrong-job", "unsupported-version"):
                    self.assertEqual(self.consume(names[f"{label}-{case}"])[0], "violation")

    def test_target_signer_is_the_verifier_owned_orchestrator(self):
        names = {v["name"]: v for v in self.data["amendmentTargets"]}
        for label in ("ordinary", "atomic", "legacy-transition", "finality-bound"):
            with self.subTest(arm=label):
                self.assertEqual(self.consume(names[label + "-seller-signed"]), (
                    "violation", "signature signer is not the authenticated authority"))
                # The same valid target fails when the verifier pins another orchestrator.
                self.assertEqual(self.consume(names[label + "-target"],
                                              orchestrator="did:dacs:test:seller")[0], "violation")

    def test_success_target_requires_its_complete_arm(self):
        names = {v["name"]: v for v in self.data["amendmentTargets"]}
        for label in ("ordinary", "atomic", "legacy-transition", "finality-bound"):
            for member in ("paymentAmount", "settlementFinality"):
                with self.subTest(arm=label, member=member):
                    vector = names[f"{label}-success-without-{member}"]
                    self.assertNotIn(member, vector["resolved"]["artifact"])
                    self.assertEqual(self.consume(vector)[0], "violation")

    def test_amendment_address_binds_target_hash(self):
        vector = next(v for v in self.data["amendmentTargets"] if v["name"] == "atomic-target")
        good = vector["amendmentAddress"]
        prefix, digest, index = good.rsplit(":", 2)
        for address in (f"{prefix}:{'0' * 64}:{index}", good + ":0", good.upper(), None):
            with self.subTest(address=address):
                self.assertEqual(self.consume({**vector, "amendmentAddress": address}), (
                    "violation", "amendment address does not bind the target evidence hash"))

    def test_unavailable_resolver_does_not_record_a_violation(self):
        vector = next(v for v in self.data["amendmentTargets"] if v["name"] == "atomic-target")
        for exception in (TimeoutError("timeout"), FileNotFoundError("not found")):
            with self.subTest(exception=type(exception).__name__):
                resolver = mock.Mock(side_effect=exception)
                self.assertEqual(self.consume(vector, resolver)[0], "indeterminate")

    def test_fixture_is_reproducible(self):
        self.assertEqual(self.data, generator.build_fixture())


if __name__ == "__main__":
    unittest.main()
