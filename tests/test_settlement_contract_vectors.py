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

# Complete DACS-4 §9.4.1 examples, independent of the reference predicates.
ASSETS = [
    {"kind": "erc20", "chainId": 1, "contract": "0x1234", "symbol": "USDC", "decimals": 6},
    {"kind": "spl", "cluster": "mainnet", "mint": "mint-key", "symbol": "USDC", "decimals": 6},
    {"kind": "native-evm", "chainId": 1, "symbol": "ETH", "decimals": 18},
    {"kind": "native-solana", "cluster": "mainnet", "symbol": "SOL", "decimals": 9},
    {"kind": "native-dem", "symbol": "DEM", "decimals": 9},
    {"kind": "fiat-via-ap2", "isoCurrency": "USD", "provider": "provider-1"},
    {"kind": "stablecoin-cross-chain", "canonicalSymbol": "USDC", "routes": [{
        "sourceChainId": 1, "destChainId": "solana",
        "htlcContracts": {"source": "0x1234", "dest": "contract-key"}, "liquidityTankIds": ["tank-1"]}]},
]
NETWORKS = [
    {"kind": "evm", "chainId": 1, "rpcAttestation": "consensus-backed-proxy"},
    {"kind": "solana", "cluster": "mainnet"}, {"kind": "demos"},
    {"kind": "ap2-provider", "providerEndpoint": "https://provider.example"},
    {"kind": "x402-resource", "resourceBaseUrl": "https://resource.example"},
    {"kind": "cross-chain", "mechanism": "htlc"},
]


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
                     "atomic-null-payer", "atomic-context-parties-reordered",
                     "ordinary-empty-agreement", "atomic-empty-agreement",
                     "ordinary-empty-rail", "atomic-empty-rail"):
            with self.subTest(vector=name):
                rail = mock.Mock()
                result = ref.dispatch_payment(BINDINGS[names[name]["binding"]],
                                              copy.deepcopy(names[name]["input"]), rail)
                self.assertEqual((result["status"], result["errorClass"]), ("rejected", "permanent"))
                rail.assert_not_called()

    def test_single_member_edit_fails_on_that_members_type(self):
        # A one-member edit of an accepted input is rejected by that member's
        # own check, so no case passes by tripping an earlier, unrelated one.
        reasons = {"sessionContext": "sessionContext is not SessionContext",
                   "atomicSessionContext": "atomicSessionContext is not AtomicPaymentSessionContextV1",
                   "identityBindingCompanions": "identityBindingCompanions is not an array"}
        names = {v["name"]: v for v in self.data["phaseInputs"]}
        bases = {"ordinary": names["ordinary-input"]["input"], "atomic": names["atomic-input"]["input"]}
        absent, checked = object(), set()
        for vector in self.data["phaseInputs"]:
            base, value = bases.get(vector["binding"]), vector["input"]
            if vector["expected"] != "rejected" or base is None:
                continue
            changed = [key for key in set(value) | set(base)
                       if value.get(key, absent) != base.get(key, absent)]
            # Skip removals and additions other than the optional companions:
            # they fail on the member set.
            if (len(changed) != 1 or changed[0] not in value
                    or (changed[0] not in base and changed[0] != "identityBindingCompanions")):
                continue
            with self.subTest(vector=vector["name"]):
                result = ref.dispatch_payment(BINDINGS[vector["binding"]], copy.deepcopy(value), mock.Mock())
                self.assertEqual(result["reason"], reasons.get(
                    changed[0], "payment input member is not its declared type"))
                checked.add(changed[0])
        self.assertTrue({"agreement", "rail", "payer", "payee", "amount", "jobId",
                         "sessionContext", "atomicSessionContext"} <= checked, checked)

    def test_agreement_and_rail_accept_every_declared_enumeration_value(self):
        # DACS-3 AgreementArtifact and DACS-4 9.4.1 RailDefinition closed unions.
        names = {v["name"]: v for v in self.data["phaseInputs"]}
        accepted = names["ordinary-input"]["input"]
        agreement, rail = accepted["agreement"], accepted["rail"]
        variants = [("railType", value) for value in (
            "evm-erc20", "solana-spl", "cross-chain-htlc", "cross-chain-liquidity-tank",
            "ap2", "x402", "demos-native")]
        variants += [("phaseHandler", value) for value in (
            "pay-evm-erc20", "pay-solana-spl", "pay-cross-chain-htlc",
            "pay-cross-chain-liquidity-tank", "pay-ap2", "pay-x402", "pay-dem")]
        variants += [("availability", value) for value in (
            "live", "operator_gated", "closed_data", "bilateral", "mocked", "disabled", "failed")]
        variants += [("asset", value) for value in ASSETS]
        variants += [("network", value) for value in NETWORKS]
        variants += [("asset", {**value, "cluster": cluster}) for value in ASSETS
                     if "cluster" in value for cluster in ("devnet", "testnet")]
        variants += [("network", {**NETWORKS[1], "cluster": cluster}) for cluster in ("devnet", "testnet")]
        variants += [("network", {**NETWORKS[0], "rpcAttestation": "evm-rpc"})]
        variants += [("network", {**NETWORKS[-1], "mechanism": value})
                     for value in ("liquidity-tank", "substrate-native")]
        variants += [("governance", {**rail["governance"], "anchoring": value})
                     for value in ("in-code", "single-signer", "multisig")]
        variants.append(("railId", "r" * 64))  # the longest canonical railId
        variants += [("governance", {**rail["governance"], **change}) for change in (
            {"supersedes": 0}, {"deprecated": False}, {"deprecated": True, "deprecationReason": "retired"},
            {"emergency": {"isEmergency": True, "failureObservation": "unavailable"}})]
        inputs = [{**accepted, "rail": {**rail, key: value}} for key, value in variants]
        for change in ([{"derivedFromPattern": value} for value in ("fixed-price", "rfq", "sealed-envelope")]
                       + [{"parties": [{**agreement["parties"][0], "role": "bidder-non-winning"},
                                       *agreement["parties"][1:]]}]
                       + [{"signatures": [{**agreement["signatures"][0], "algorithm": value}]}
                          for value in ("ed25519", "ecdsa-secp256k1", "sr1-aggregate")]):
            inputs.append({**accepted, "agreement": {**agreement, **change}})
        for selector in ("identityBoundAgreementVersion", "agreementVersion"):
            inputs.append({**accepted, "agreement": {selector: "1", **{
                k: v for k, v in agreement.items() if k != "agreementVersion"}}})
        payout = {**agreement["terms"], "payoutBindings": [{
            "railId": rail["railId"], "phaseIndex": 0, "payeeAddress": "seller-address"}]}
        for selector in ("payeeBoundAgreementVersion", "identityBoundPayeeAgreementVersion"):
            inputs.append({**accepted, "agreement": {selector: "1", **{
                k: v for k, v in agreement.items() if k != "agreementVersion"}, "terms": payout}})
        for party in ("buyer", "seller", "orchestrator"):
            session = accepted["sessionContext"]
            inputs.append({**accepted, "sessionContext": {**session, "parties": [
                {**session["parties"][0], "role": party}, *session["parties"][1:]]}})
        for value in inputs:
            with self.subTest(input=json.dumps({k: value[k] for k in ("agreement", "rail")})[:120]):
                ref.check_payment_input(BINDINGS["ordinary"], value)

    def test_nested_rail_required_members_and_types_reject_before_handler(self):
        names = {v["name"]: v for v in self.data["phaseInputs"]}
        for binding in ("ordinary", "atomic"):
            base = names[binding + "-input"]["input"]
            for member, examples in (("asset", ASSETS), ("network", NETWORKS)):
                for example in examples:
                    for key in example:
                        # Each required union member independently refuses omission
                        # and a value of another type; routes get their own tests.
                        for replacement in (None, {}):
                            value = {k: v for k, v in example.items() if k != key}
                            if replacement is not None:
                                value[key] = replacement
                            with self.subTest(binding=binding, kind=example["kind"], key=key, replacement=replacement):
                                handler = mock.Mock(return_value={"status": "accepted", "ok": True})
                                result = ref.dispatch_payment(BINDINGS[binding], {
                                    **base, "rail": {**base["rail"], member: value}}, handler)
                                self.assertEqual(result["status"], "rejected")
                                self.assertEqual(result["errorClass"], "permanent")
                                self.assertIs(result["ok"], False)
                                handler.assert_not_called()

    def test_nested_optional_rail_members_are_typed(self):
        base = next(v["input"] for v in self.data["phaseInputs"] if v["name"] == "ordinary-input")
        route = ASSETS[-1]["routes"][0]
        changes = [("asset", {**ASSETS[-1], "routes": [{**route, **change}]}) for change in (
            {"sourceChainId": True}, {"destChainId": 2**53}, {"htlcContracts": {}},
            {"htlcContracts": []}, {"htlcContracts": {"source": "a", "dest": 1}},
            {"liquidityTankIds": "tank"}, {"liquidityTankIds": [1]})]
        changes += [("governance", {**base["rail"]["governance"], **change}) for change in (
            {"supersedes": True}, {"deprecated": 1}, {"deprecationReason": 1},
            {"emergency": True}, {"emergency": {"isEmergency": 1, "failureObservation": "outage"}},
            {"emergency": {"isEmergency": False, "failureObservation": "outage"}},
            {"emergency": {"isEmergency": True, "failureObservation": 1}})]
        changes += [("asset", {**ASSETS[0], key: value}) for key, value in (
            ("chainId", 0), ("chainId", 2**53), ("decimals", True), ("decimals", -1), ("decimals", 2**53))]
        changes += [("asset", {**ASSETS[3], key: value}) for key, value in (("symbol", "ETH"), ("decimals", 18))]
        for member, value in changes:
            with self.subTest(member=member, value=value):
                handler = mock.Mock(return_value={"status": "accepted", "ok": True})
                result = ref.dispatch_payment(BINDINGS["ordinary"], {**base, "rail": {**base["rail"], member: value}}, handler)
                self.assertEqual(result["status"], "rejected")
                handler.assert_not_called()

    def test_complete_nested_shapes_preserve_unknown_members_and_boundaries(self):
        names = {v["name"]: v for v in self.data["phaseInputs"]}
        for binding in ("ordinary", "atomic"):
            for asset in ASSETS:
                value = copy.deepcopy(names[binding + "-input"]["input"])
                value["rail"]["asset"] = {**asset, "future": "preserved"}
                value["rail"]["network"]["future"] = "preserved"
                value["rail"]["governance"]["future"] = "preserved"
                value["agreement"]["listingRef"]["future"] = "preserved"
                value["agreement"]["terms"]["deliverable"]["future"] = "preserved"
                value["agreement"]["terms"]["rail"].update(railVersion=1, parameters={"future": True})
                before = copy.deepcopy(value)
                handler = mock.Mock(return_value={"status": "accepted", "ok": True})
                with self.subTest(binding=binding, asset=asset["kind"]):
                    self.assertEqual(ref.dispatch_payment(BINDINGS[binding], value, handler)["status"], "accepted")
                    handler.assert_called_once_with(value)
                    self.assertEqual(value, before)
        ordinary = names["ordinary-input"]["input"]
        for asset in ({**ASSETS[0], "chainId": 2**53 - 1, "decimals": 0},
                      {**ASSETS[-1], "routes": []},
                      {**ASSETS[-1], "routes": [{"sourceChainId": 0, "destChainId": 1}]},
                      {**ASSETS[-1], "routes": [{"sourceChainId": "evm:1", "destChainId": 1}]}):
            ref.check_payment_input(BINDINGS["ordinary"], {**ordinary, "rail": {**ordinary["rail"], "asset": asset}})
        for kind in ("storage-program", "entitlement", "attested-payload", "external"):
            ref.check_payment_input(BINDINGS["ordinary"], {**ordinary, "agreement": {
                **ordinary["agreement"], "terms": {**ordinary["agreement"]["terms"], "deliverable": {
                    "deliverableType": kind, "hash": "ab" * 32}}}})
        # Historical AgreementParty hashes keep their declared string contract.
        legacy = copy.deepcopy(ordinary)
        legacy["agreement"]["parties"][0]["bundleHash"] = "sha256:" + "AB" * 32
        ref.check_payment_input(BINDINGS["ordinary"], legacy)

    def test_agreement_nested_members_and_arm_exclusions(self):
        base = next(v["input"] for v in self.data["phaseInputs"] if v["name"] == "ordinary-input")
        agreement = base["agreement"]
        for selector in ("agreementVersion", "identityBoundAgreementVersion", "payeeBoundAgreementVersion",
                         "identityBoundPayeeAgreementVersion", "sealedSelectionAgreementVersion"):
            source = copy.deepcopy(agreement)
            source.pop("agreementVersion")
            source[selector] = "1"
            payout = selector not in ("agreementVersion", "identityBoundAgreementVersion")
            if payout:
                source["terms"]["payoutBindings"] = [{"railId": "rail", "phaseIndex": 0, "payeeAddress": "seller"}]
            if selector == "sealedSelectionAgreementVersion":
                source.update(derivedFromPattern="sealed-envelope", selectionReceiptRef=agreement["parties"][0]["vetRecordRef"])
            # A complete minimal arm is accepted; no optional member is required.
            source["terms"] = {k: v for k, v in source["terms"].items() if k in ("deliverable", "price", "deadline", "payoutBindings")}
            source["terms"]["deliverable"].pop("schemaUrl", None)
            ref.check_payment_input(BINDINGS["ordinary"], {**base, "agreement": source})
            bad = []
            for member, value in (("deliverable", {"deliverableType": "external"}),
                                  ("rail", {}), ("rail", {"railId": "rail", "parameters": []}),
                                  ("deliverable", {"deliverableType": "external", "hash": "ab" * 32, "schemaUrl": 1})):
                bad.append({**source, "terms": {**source["terms"], member: value}})
            if not payout:
                for key, value in (("payoutBindings", []), ("priorPaymentDispositionRef", agreement["parties"][0]["vetRecordRef"])):
                    bad.append({**source, "terms": {**source["terms"], key: value}})
            else:
                for key, value in (("railId", ""), ("payeeAddress", ""), ("phaseIndex", True), ("phaseIndex", -1), ("phaseIndex", 2**53)):
                    bad.append({**source, "terms": {**source["terms"], "payoutBindings": [{
                        **source["terms"]["payoutBindings"][0], key: value}]}})
                bad.append({**source, "terms": {**source["terms"], "priorPaymentDispositionRef": {}}})
            if selector != "sealedSelectionAgreementVersion":
                bad.append({**source, "selectionReceiptRef": agreement["parties"][0]["vetRecordRef"]})
            if selector.startswith("identityBound"):
                for bundle_hash in ("sha256:" + "ab" * 32, "AB" * 32):
                    bad.append({**source, "parties": [{**source["parties"][0], "bundleHash": bundle_hash}, *source["parties"][1:]]})
            for candidate in bad:
                with self.subTest(selector=selector, agreement=candidate):
                    handler = mock.Mock(return_value={"status": "accepted", "ok": True})
                    result = ref.dispatch_payment(BINDINGS["ordinary"], {**base, "agreement": candidate}, handler)
                    self.assertEqual(result["status"], "rejected")
                    handler.assert_not_called()

    def test_unknown_target_members_follow_each_arms_schema(self):
        names = {v["name"]: v for v in self.data["amendmentTargets"]}
        for label in ("ordinary", "legacy-transition", "finality-bound", "atomic"):
            with self.subTest(arm=label):
                vector = names[label + "-unknown-member"]
                self.assertIn("futureMember", vector["resolved"]["artifact"])
                self.assertEqual(self.consume(vector)[0], "valid" if label == "atomic" else "violation")
        changelog = (ROOT / "CHANGELOG.md").read_text()
        heading = "### Changed — general normative changes in candidate DACS-4 v0.8 (every profile)"
        changed = " ".join(changelog.split(heading, 1)[1].split("\n### ", 1)[0].split())
        for phrase in ("complete AssetSpec and NetworkSpec arms",
                       "DeliverableRef, PaymentRailRef, payout binding entries",
                       "three DACS-4 v0.x target arms use closed shapes and reject unknown members",
                       "Atomic targets use the open normative schema (§9.7.3)"):
            self.assertIn(phrase, changed)
        spec = " ".join((ROOT / "spec/DACS-4-SETTLE.md").read_text().split())
        self.assertIn("the Atomic arm uses the normative schema in §9.7.3, which admits unknown members", spec)

    def test_inauthentic_target_anchor_leaves_the_amendment_pending(self):
        # CORE SR2-4/SR2-12: an inauthentic receipt is discarded, not a violation.
        names = {v["name"]: v for v in self.data["amendmentTargets"]}
        for name in ("anchor-content-mismatch", "anchor-proof-signature-invalid",
                     "anchor-without-evidence"):
            with self.subTest(vector=name):
                result, reason = self.consume(names[name])
                self.assertEqual(result, "indeterminate")
                self.assertTrue(reason.startswith("amendment target anchor is not authentic"), reason)
        self.assertEqual(self.consume(names["anchor-binds-other-content"]), (
            "violation", "authentic amendment target anchor binds another content hash"))

    def test_delivery_target_fails_the_payment_phase_rule(self):
        # A complete delivery record passes its arm and fails only the pay-* rule.
        names = {v["name"]: v for v in self.data["amendmentTargets"]}
        for name in ("ordinary-delivery-target", "atomic-delivery-target"):
            with self.subTest(vector=name):
                self.assertEqual(self.consume(names[name]),
                                 ("violation", "amendment target is not a payment phase"))

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
