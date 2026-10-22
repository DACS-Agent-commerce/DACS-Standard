"""Settlement admission boundaries, using signed artifacts and receipt proofs."""
from __future__ import annotations

import copy
import json
import unittest
from unittest import mock

import test_settlement_contract_vectors as vectors

ref = vectors.ref
gen = vectors.generator


class SettlementAdmissionRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        vectors.SettlementContractTests.setUpClass()
        cls.fixture = vectors.SettlementContractTests()
        cls.targets = {v["name"]: v for v in cls.fixture.data["amendmentTargets"]}

    def rebuild(self, record, name="ordinary-target", algorithm="ed25519"):
        vector = copy.deepcopy(self.targets[name])
        selector = next(key for key in ref.EVIDENCE_SELECTORS if key in record)
        domain = ref._TARGET_ARMS[selector][0]
        record = (gen.sign_ecdsa(record, domain) if algorithm == "ecdsa-secp256k1"
                  else gen.sign(record, "orchestrator", domain))
        digest = ref.content_hash(record)
        vector["resolved"]["artifact"] = record
        receipt = vector["resolved"]["anchorReceipts"][0]
        vector["resolved"]["anchorReceipts"] = [self.fixture.resign_receipt(receipt, contentHash=digest)]
        vector["amendment"]["amendsEvidenceRef"]["contentHash"] = digest
        vector["amendment"] = gen.sign(vector["amendment"], "seller", ref.AMENDMENT_DOMAIN)
        vector["amendmentAddress"] = f"dacs4:amendment:{gen.JOB_ID}:{digest}:0"
        return vector

    def ordered(self, receipt, sequence, **change):
        receipt = self.fixture.resign_receipt(receipt, **change)
        proof = json.loads(ref.b64u_decode(receipt["evidence"]["value"]))
        proof["observationSequence"] = sequence
        proof = gen.sign(proof, "network", ref.ANCHOR_TEST_DOMAIN)
        receipt["evidence"]["value"] = gen.b64u(ref.jcs_bytes(proof))
        return receipt

    def test_ordered_receipt_history_resolves_payment_and_both_rail_bindings(self):
        # CORE §5.1/SR2-7: order is authenticated inside evidence.value. A
        # decreasing observer clock has no influence on native precedence.
        vector = copy.deepcopy(self.targets["ordinary-target"])
        old = vector["resolved"]["anchorReceipts"][0]
        receipts = [self.ordered(old, "8"), self.ordered(old, "9", observedAt=old["observedAt"] - 1000)]
        for history in (receipts, list(reversed(receipts))):
            vector["resolved"]["anchorReceipts"] = history
            self.assertEqual(self.fixture.consume(vector)[0], "valid")
            selected = ref._sole_carrier(history, "test", lambda _: None,
                                         writer=self.fixture.data["orchestratorWriter"],
                                         public_keys=self.fixture.data["publicKeys"], **vectors.TRUST)
            self.assertEqual(selected["observedAt"], old["observedAt"] - 1000)
        base = next(c for c in self.fixture.rails["cases"] if c["expected"] == "verified")
        for key in ("railRegistryIndexReceipts", "railDefinitionReceipts"):
            for reverse in (False, True):
                with self.subTest(binding=key, reverse=reverse):
                    case = copy.deepcopy(base)
                    old = case["authority"][key][0]
                    history = [self.ordered(old, "1"), self.ordered(old, "2", observedAt=old["observedAt"] + 1000)]
                    case["authority"][key] = list(reversed(history)) if reverse else history
                    self.assertEqual(self.fixture.resolve_rail(case)[0], "verified")

    def test_unordered_or_conflicting_observations_do_not_choose_a_winner(self):
        vector = copy.deepcopy(self.targets["ordinary-target"])
        old = vector["resolved"]["anchorReceipts"][0]
        newer = self.fixture.resign_receipt(old, observedAt=old["observedAt"] + 1000)
        for index, history in enumerate((
                [old, newer],
                [self.ordered(old, "1"), newer],
                [self.ordered(old, "1"), self.ordered(newer, "1")],
                [self.ordered(old, "1"), self.ordered(newer, "2", blockRef={**old["blockRef"], "timestamp": 0})])):
            with self.subTest(history=index):
                vector["resolved"]["anchorReceipts"] = history
                status, reason = self.fixture.consume(vector)
                self.assertEqual(status, "indeterminate")
                self.assertIn("SR2-7", reason)
        # Ordering cannot collapse different native transactions/bindings.
        for name in ("anchor-equivocation", "anchor-equivocation-other-content"):
            vector = copy.deepcopy(self.targets[name])
            vector["resolved"]["anchorReceipts"] = [self.ordered(r, str(i)) for i, r in
                                                     enumerate(vector["resolved"]["anchorReceipts"])]
            self.assertIn("equivocation", self.fixture.consume(vector)[1])

    def test_historical_hash_carriers_keep_the_agreement_string_contract(self):
        base = next(v["input"] for v in self.fixture.data["phaseInputs"] if v["name"] == "ordinary-input")
        for value in ("sha256:" + "AB" * 32, "AB" * 32, "ab" * 32):
            phase_input = copy.deepcopy(base)
            for party in phase_input["agreement"]["parties"]:
                party["bundleHash"] = value
            for key in ("payer", "payee"):
                phase_input[key]["bundleHash"] = value
            for party in phase_input["sessionContext"]["parties"]:
                party["bundleHash"] = value
            before = copy.deepcopy(phase_input)
            handler = mock.Mock(return_value={"status": "accepted", "ok": True})
            self.assertEqual(ref.dispatch_payment(vectors.BINDINGS["ordinary"], phase_input, handler)["status"], "accepted")
            handler.assert_called_once_with(before)
            self.assertEqual(phase_input, before)
        for key in ("payer", "payee"):
            phase_input = copy.deepcopy(base)
            phase_input[key]["bundleHash"] = ""
            handler = mock.Mock()
            self.assertEqual(ref.dispatch_payment(vectors.BINDINGS["ordinary"], phase_input, handler)["status"], "rejected")
            handler.assert_not_called()

    def test_malformed_signatures_are_decidable_without_algorithm_or_key_support(self):
        # CORE §B.7 SIG-6: encoding is checked even without a usable key.
        for name in ("ordinary-target", "legacy-transition-target", "finality-bound-target"):
            for algorithm in ("ed25519", "ecdsa-secp256k1", "sr1-aggregate"):
                for value in ("", "abc=", "abc+", "%%%%", "a", "Zh", None):
                    with self.subTest(arm=name, algorithm=algorithm, value=value):
                        vector = copy.deepcopy(self.targets[name])
                        vector["resolved"]["artifact"]["signature"].update(algorithm=algorithm, value=value)
                        self.assertEqual(self.fixture.consume(vector)[0], "violation")
                        signed = copy.deepcopy(vector["resolved"]["artifact"])
                        with self.assertRaises(ref.Invalid):
                            ref.verify_embedded(signed, {}, ref._TARGET_ARMS[next(
                                key for key in ref.EVIDENCE_SELECTORS if key in signed)][0])
        # Well-formed registered algorithms stay pending on every arm. Missing
        # outcome-required fields remain violations even for genuine ECDSA.
        for name in ("ordinary-target", "legacy-transition-target", "finality-bound-target"):
            record = self.targets[name]["resolved"]["artifact"]
            self.assertEqual(self.fixture.consume(self.rebuild(record, name, "ecdsa-secp256k1"))[0], "indeterminate")
            for member in ("paymentAmount", "settlementFinality", "paymentTxRefs"):
                malformed = {k: v for k, v in record.items() if k != member}
                self.assertEqual(self.fixture.consume(self.rebuild(malformed, name, "ecdsa-secp256k1"))[0], "violation")

    def test_full_payment_address_grammar_for_logical_and_native_locators(self):
        invalid = ("", "garbage", "r:-1", "r:01", "r:2:bogus", "r:2:resolved:extra",
                   "a%3ab:2", "a%41:2", "a%:2", "a?b:2", "r:２", "r:2\n", "r" * 65 + ":2")
        valid = ("r:0", "r:2", "r:2:resolved", "evm-erc20%3A8453%3AUSDC:2", "a%25%3F%26%3D:2")
        for native in (False, True):
            for suffix in (*invalid, *valid):
                with self.subTest(native=native, suffix=suffix):
                    vector = copy.deepcopy(self.targets["ordinary-target"])
                    old = vector["resolved"]["anchorReceipts"][0]
                    address = f"dacs4:payment:{gen.JOB_ID}:{suffix}"
                    receipt = self.fixture.resign_receipt(old, logicalAddress=address)
                    vector["resolved"]["anchorReceipts"] = [receipt]
                    vector["amendment"]["amendsEvidenceRef"]["anchor"]["locator"] = receipt["nativeAddress"] if native else address
                    vector["amendment"] = gen.sign(vector["amendment"], "seller", ref.AMENDMENT_DOMAIN)
                    self.assertEqual(self.fixture.consume(vector)[0], "valid" if suffix in valid else "indeterminate")

    def test_open_nested_members_are_hashed_without_opening_closed_unions(self):
        base = self.targets["ordinary-target"]["resolved"]["artifact"]
        for member in ("paymentAmount", "settlementFinality", "signature"):
            record = copy.deepcopy(base)
            record[member]["futureNote"] = "additive"
            vector = self.rebuild(record)
            if member == "signature":
                vector["resolved"]["artifact"][member]["futureNote"] = "additive"
            before = copy.deepcopy(vector)
            self.assertEqual(self.fixture.consume(vector)[0], "valid")
            self.assertEqual(vector, before)
            if member != "signature":
                # Changing an unknown signed member without refreshing bindings
                # must still fail the content hash, despite the open shape.
                vector["resolved"]["artifact"][member]["futureNote"] = "changed"
                self.assertEqual(self.fixture.consume(vector)[0], "indeterminate")
        record = copy.deepcopy(base)
        record["paymentTxRefs"][0]["futureNote"] = "closed union"
        self.assertEqual(self.fixture.consume(self.rebuild(record))[0], "violation")

        future_ref = {"anchor": {"kind": "https", "locator": "https://example.test/evidence", "futureNote": "x"},
                      "contentHash": "ab" * 32, "futureNote": "x"}
        record = copy.deepcopy(base)
        record.update(paymentFee={"amount": "1", "currency": "DEM", "futureNote": "x"},
                      amendmentRefs=[future_ref], supersedesEvidenceRef=future_ref)
        self.assertEqual(self.fixture.consume(self.rebuild(record))[0], "valid")
        for kind in ("ap2", "ap2-sr3"):
            record = copy.deepcopy(base)
            record["phase"] = "pay-ap2"
            record["settlementFinality"]["model"] = "provider-receipt"
            tx_ref = {"kind": kind, "mandateId": "mandate", "providerRef": "provider",
                      "protocolVersion": "1", "receiptAttestation": future_ref}
            if kind == "ap2-sr3":
                tx_ref["receiptTransactionRef"] = {"kind": "provider", "value": "capture", "futureNote": "x"}
            record["paymentTxRefs"] = [tx_ref]
            self.assertEqual(self.fixture.consume(self.rebuild(record))[0], "valid")
            tx_ref["futureNote"] = "closed union arm"
            self.assertEqual(self.fixture.consume(self.rebuild(record))[0], "violation")

    def test_equivalent_raw_json_integer_spellings_keep_hashes_and_admission(self):
        for name, old, new in (
                ("legacy-transition-target", b'"phaseIndex": 2', b'"phaseIndex": 2.0'),
                ("legacy-transition-target", b'"phaseIndex": 2', b'"phaseIndex": 2e0'),
                ("ordinary-target", b'"blockNumber": 750', b'"blockNumber": 750e0'),
                ("finality-bound-target", b'"railVersion": 1', b'"railVersion": 1.0')):
            vector = copy.deepcopy(self.targets[name])
            raw = vectors.received(vector["resolved"]["artifact"])
            changed = raw.replace(old, new)
            self.assertNotEqual(raw, changed)
            self.assertEqual(ref.content_hash(json.loads(raw)), ref.content_hash(json.loads(changed)))
            vector["resolved"]["artifactText"] = changed.decode()
            self.assertEqual(self.fixture.consume(vector)[0], "valid")
        shape = ref._shapes()
        for value in (0, -0.0, 2.0, 750e0, float(2**53 - 1)):
            self.assertTrue(shape._safe_nonnegative_integer(value))
        for value in (True, False, 0.5, -1.0, float("nan"), float("inf"), 2**53):
            self.assertFalse(shape._safe_nonnegative_integer(value))

    def test_job_id_validation_precedes_lookup_and_target_comparison(self):
        self.assertEqual(self.fixture.consume(self.targets["ordinary-target"])[0], "valid")
        for job in ("not-a-ulid", gen.JOB_ID.lower(), "8" + gen.JOB_ID[1:], gen.JOB_ID + "\n", "%30" + gen.JOB_ID[1:]):
            vector = copy.deepcopy(self.targets["ordinary-target"])
            vector["amendment"]["jobId"] = job
            vector["amendment"] = gen.sign(vector["amendment"], "seller", ref.AMENDMENT_DOMAIN)
            resolver = mock.Mock()
            self.assertEqual(self.fixture.consume(vector, resolver)[0], "violation")
            resolver.assert_not_called()
            record = {**self.targets["ordinary-target"]["resolved"]["artifact"], "jobId": job}
            status, reason = self.fixture.consume(self.rebuild(record))
            self.assertEqual(status, "violation")
            self.assertIn("target jobId malformed", reason)

    def test_failure_reason_is_optional_but_present_values_are_typed(self):
        base = self.targets["ordinary-failure-target"]["resolved"]["artifact"]
        record = {k: v for k, v in base.items() if k != "reason"}
        self.assertEqual(self.fixture.consume(self.rebuild(record))[0], "valid")
        for value in ("rail refused the transfer", ""):
            self.assertEqual(self.fixture.consume(self.rebuild({**record, "reason": value}))[0],
                             "valid" if value else "violation")
        for value in (None, 1, [], {}):
            self.assertEqual(self.fixture.consume(self.rebuild({**record, "reason": value}))[0], "violation")

    def test_malformed_receipt_digest_is_discarded_before_hash_comparison(self):
        vector = copy.deepcopy(self.targets["ordinary-target"])
        old = vector["resolved"]["anchorReceipts"][0]
        for digest in ("g" * 64, "AB" * 32, "sha256:" + "ab" * 32, "x"):
            bad = self.fixture.resign_receipt(old, contentHash=digest)
            vector["resolved"]["anchorReceipts"] = [bad]
            self.assertEqual(self.fixture.consume(vector)[0], "indeterminate")
            vector["resolved"]["anchorReceipts"] = [bad, old]
            self.assertEqual(self.fixture.consume(vector)[0], "valid")
        vector["resolved"]["anchorReceipts"] = [self.fixture.resign_receipt(old, contentHash="00" * 32)]
        self.assertEqual(self.fixture.consume(vector)[0], "violation")


if __name__ == "__main__":
    unittest.main()
