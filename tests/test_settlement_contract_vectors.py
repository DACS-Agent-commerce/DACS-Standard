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

    def consume(self, vector, resolver=None):
        return ref.consume_amendment_target(
            vector["amendment"], resolver or (lambda _: vector["resolved"]),
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
        ref.check_payment_input(Binding(), Input(sessionContext={}))
        self.assertEqual(events[0], "binding")
        self.assertIn("input", events)

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
                    self.assertEqual(vector["amendmentAddress"],
                        f"dacs4:amendment:{record['jobId']}:{digest}:0")

    def test_target_hash_precedes_discriminator_interpretation(self):
        vector = copy.deepcopy(next(v for v in self.data["amendmentTargets"]
                                   if v["name"] == "atomic-target"))
        vector["resolved"]["artifact"]["evidenceVersion"] = "1"
        self.assertEqual(self.consume(vector), ("violation", "amendment target content hash mismatch"))

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
