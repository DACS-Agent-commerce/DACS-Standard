"""PC-1, AMEND-1 and RTB-1 references with independently finalized fixtures."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import generate_settlement_contract_vectors as generator
import settlement_contract_reference as ref
from jcs import canonicalize

def ibh(verdict):
    """A verifier-owned IBH-1..IBH-5 rerun that returns a fixed outcome."""
    return lambda _phase_input: verdict


# Enclosing handler metadata is fixed outside the phase input.
BINDINGS = {
    "ordinary": ref.PhaseBinding("pay-dem"),
    # The signed Listing phase selected an identity-bound agreement (§9.5.1)
    # and the verifier's IBH rerun verified the companions.
    "identity-bound": ref.PhaseBinding("pay-dem", identity_bound=True, identity_binding=ibh("verified")),
}


def binding_for(vector):
    """The vector's binding, with its declared IBH rerun outcome (none: no authority)."""
    if vector["binding"] == "ordinary":
        return BINDINGS["ordinary"]
    verdict = vector.get("identityBinding")
    return ref.PhaseBinding("pay-dem", identity_bound=True,
                            identity_binding=ibh(verdict) if verdict else None)


def received(value):
    """The received bytes of a fixture artifact: its UTF-8 JSON text."""
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


def received_resolution(resolved):
    """A resolver reply carrying the artifact's exact received bytes."""
    if not isinstance(resolved, dict) or "artifact" not in resolved:
        return resolved
    text = resolved.get("artifactText")
    return {**resolved, "artifact": text.encode("utf-8") if text else received(resolved["artifact"])}
# PC-1 input arms and AMEND-1 target arms the fixture exercises.
ARMS = ("ordinary",)
TARGET_ARMS = ("ordinary", "legacy-transition", "finality-bound")
# Target arms whose shape is open (keeps unknown members under CORE SIG-5):
# ordinary SettlementEvidence. The transition and finality-bound arms are closed.
OPEN_TARGET_ARMS: dict[str, str] = {"ordinary": "valid"}
# IdentityBoundAgreementCompanion placeholders: PC-1 types the objects and the
# binding's IBH-1..IBH-5 rerun stub decides their contents.
COMPANIONS = [{"identityBundle": {}, "compositeRecord": {}}]
# Complete delivery records that pass their arm and fail only the pay-* rule.
DELIVERY_TARGETS = ("ordinary-delivery-target",)
# Verifier-owned trust pins for the synthetic finality proofs. They are
# fixture configuration, never read from the material under test.
TRUST = {
    "network_authority": "did:dacs:test:network",
    "network_id": "demos:testnet",
    "proof_profile": "demos-bft-proof/test-1",
    "validator_set_id": "test-validator-set-1",
}


def content_hash(record):
    """CORE B.2 signature-omitting content hash, computed independently."""
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    return hashlib.sha256(canonicalize(unsigned).encode("utf-8")).hexdigest()

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


def edits(before, after, path=""):
    """Each member path where after differs from before, for a subtest label."""
    if isinstance(before, dict) and isinstance(after, dict):
        return [change for key in sorted(set(before) | set(after))
                for change in edits(before.get(key, ...), after.get(key, ...), f"{path}.{key}")]
    if isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
        return [change for index, pair in enumerate(zip(before, after))
                for change in edits(*pair, f"{path}[{index}]")]
    if before == after and type(before) is type(after):
        return []
    return [f"{path}=" + ("<missing>" if after is ... else json.dumps(after)[:60])]


class SettlementContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(generator.OUTPUT.read_text())
        cls.rails = json.loads(generator.RAIL_OUTPUT.read_text())

    def consume(self, vector, resolver=None, *, orchestrator=None, writer=None, keys=None):
        text = vector.get("amendmentText")
        return ref.consume_amendment_target(
            text.encode("utf-8") if text else received(vector["amendment"]),
            resolver or (lambda _: received_resolution(vector["resolved"])),
            amendment_address=vector["amendmentAddress"],
            orchestrator=orchestrator or self.data["orchestrator"],
            writer=writer or self.data["orchestratorWriter"],
            public_keys=keys or self.data["publicKeys"], **TRUST,
        )

    def resolve_rail(self, case, **change):
        pins = {"public_keys": self.rails["publicKeys"], "steward": self.rails["steward"],
                "registry_writer": self.rails["registryWriter"], **TRUST, **change}
        return ref.resolve_session_rail(
            case["session"], case["railRef"], case["rail"], case["authority"], **pins)

    def test_payment_arm_vectors_reject_before_handler_and_preserve_input(self):
        dispositions = {"rejected": "permanent", "indeterminate": "substrate"}
        for vector in self.data["phaseInputs"]:
            with self.subTest(vector=vector["name"]):
                value = copy.deepcopy(vector["input"])
                before = copy.deepcopy(value)
                rail = mock.Mock(return_value={"status": "accepted", "ok": True})
                result = ref.dispatch_payment(binding_for(vector), value, rail)
                self.assertEqual(result["status"], vector["expected"])
                self.assertEqual(value, before)
                if vector["expected"] in dispositions:
                    rail.assert_not_called()
                    self.assertIs(result["ok"], False)
                    self.assertEqual(result["errorClass"], dispositions[vector["expected"]])
                else:
                    rail.assert_called_once_with(value)
                    self.assertIs(rail.call_args.args[0], value)

    def test_identity_binding_companions_keep_the_ibh_dispositions(self):
        # §9.5.1 and the IBH corpus: an absent companion member is
        # `indeterminate` (no rail call, errorClass substrate); an empty or
        # malformed one is IBH `error`, a PC-1 rejection before any rail call.
        corpus = json.loads((ROOT / "conformance/vectors/security/identity-bundle-hash-binding-v0.1.json").read_text())
        base = corpus["scenarios"]["identityBoundAgreement"]["paymentInput"]
        vectors = {v["name"]: v for v in corpus["vectors"]}
        for name, expected, companions in (
                ("malformed-payment-07-missing", "indeterminate", ...),
                ("malformed-payment-07-list", "error", []),
                ("malformed-supplied-companion-is-not-missing-authority", "error", [{}])):
            mutation = vectors[name]["mutations"][0]
            self.assertEqual((vectors[name]["expected"], mutation["path"]),
                             (expected, ["paymentInput", "identityBindingCompanions"]))
            self.assertEqual(mutation.get("value", ...), companions)
        missing = {k: v for k, v in base.items() if k != "identityBindingCompanions"}
        binding = BINDINGS["identity-bound"]
        for value, status, error_class in (
                (missing, "indeterminate", "substrate"),
                ({**base, "identityBindingCompanions": []}, "rejected", "permanent"),
                ({**base, "identityBindingCompanions": [{}]}, "rejected", "permanent")):
            with self.subTest(companions=value.get("identityBindingCompanions", "<missing>")):
                handler = mock.Mock(return_value={"status": "accepted", "ok": True})
                result = ref.dispatch_payment(binding, copy.deepcopy(value), handler)
                self.assertEqual((result["status"], result["ok"], result["errorClass"]),
                                 (status, False, error_class))
                handler.assert_not_called()
        handler = mock.Mock(return_value={"status": "accepted", "ok": True})
        self.assertEqual(ref.dispatch_payment(binding, copy.deepcopy(base), handler)["status"], "accepted")
        handler.assert_called_once()
        # PC-1 rejects exactly IBH's structural `error`: an entry carrying
        # neither member. A companion lacking only one member is the rerun's
        # (IBH `indeterminate` without the bundle), never a PC-1 rejection.
        first, *rest = base["identityBindingCompanions"]
        for kept in ("identityBundle", "compositeRecord"):
            with self.subTest(kept=kept):
                ref.check_payment_input(binding, {**base, "identityBindingCompanions": [
                    {kept: first[kept]}, *rest]})
        with self.assertRaisesRegex(ref.InputArmError, "not an IdentityBoundAgreementCompanion"):
            ref.check_payment_input(binding, {**base, "identityBindingCompanions": [{"note": 1}, *rest]})
        spec = " ".join((ROOT / "spec/DACS-4-SETTLE.md").read_text().split())
        self.assertIn("an absent `identityBindingCompanions` member is missing authority", spec)
        self.assertIn("A present `identityBindingCompanions` that is not a non-empty array", spec)

    def test_identity_bound_path_needs_the_listing_kind_and_a_verified_ibh_rerun(self):
        # §9.5.1: the authenticated Listing alone selects the path, and only a
        # verified IBH-1..IBH-5 rerun reaches the rail.
        corpus = json.loads((ROOT / "conformance/vectors/security/identity-bundle-hash-binding-v0.1.json").read_text())
        base = corpus["scenarios"]["identityBoundAgreement"]["paymentInput"]
        failing = mock.Mock(side_effect=TimeoutError("admission store timed out"))
        for binding, status, error_class, reason in (
                (BINDINGS["ordinary"], "rejected", "permanent", "agreement is not the agreement kind the Listing selects"),
                (ref.PhaseBinding("pay-dem", identity_bound=True), "indeterminate", "substrate",
                 "no IBH-1..IBH-5 rerun authority for the identity-bound path"),
                (ref.PhaseBinding("pay-dem", True, ibh("rejected")), "rejected", "permanent",
                 "IBH-1..IBH-5 rerun rejected the identity binding"),
                (ref.PhaseBinding("pay-dem", True, ibh("indeterminate")), "indeterminate", "substrate",
                 "IBH-1..IBH-5 rerun did not verify ('indeterminate')"),
                (ref.PhaseBinding("pay-dem", True, ibh(True)), "indeterminate", "substrate",
                 "IBH-1..IBH-5 rerun did not verify (True)"),
                # The rerun's own failure keeps its cause.
                (ref.PhaseBinding("pay-dem", True, failing), "indeterminate", "substrate",
                 "IBH-1..IBH-5 rerun unavailable (TimeoutError: admission store timed out)")):
            with self.subTest(binding=binding):
                handler = mock.Mock(return_value={"status": "accepted", "ok": True})
                result = ref.dispatch_payment(binding, copy.deepcopy(base), handler)
                self.assertEqual((result["status"], result["errorClass"], result["reason"]),
                                 (status, error_class, reason))
                handler.assert_not_called()
        # The rerun sees the exact phase input the handler would get.
        rerun = mock.Mock(return_value="verified")
        value = copy.deepcopy(base)
        handler = mock.Mock(return_value={"status": "accepted", "ok": True})
        self.assertEqual(ref.dispatch_payment(ref.PhaseBinding("pay-dem", True, rerun), value, handler)["status"],
                         "accepted")
        self.assertIs(rerun.call_args.args[0], value)
        handler.assert_called_once_with(value)

    def test_golden_payment_fixture_input_is_illustrative(self):
        # conformance/README: the golden input abbreviates the agreement and
        # session context, so a conforming PC-1 handler rejects it.
        golden = json.loads((ROOT / "conformance/fixtures/settlement-evidence-payment-success.json").read_text())
        handler = mock.Mock()
        result = ref.dispatch_payment(ref.PhaseBinding("pay-evm-erc20"), golden["paymentInput"], handler)
        self.assertEqual((result["status"], result["errorClass"]), ("rejected", "permanent"))
        handler.assert_not_called()
        self.assertIn("is not a PC-1 handler input and a conforming handler rejects it",
                      (ROOT / "conformance/README.md").read_text())

    def test_identity_binding_payment_authorization_members_keep_their_arm(self):
        corpus = json.loads((ROOT / "conformance/vectors/security/identity-bundle-hash-binding-v0.1.json").read_text())
        checked = 0
        for name, scenario in corpus["scenarios"].items():
            value = scenario.get("paymentInput")
            if isinstance(value, dict) and "paymentAuthorization" in value:
                # The scenario's Listing selects the agreement kind it carries.
                identity_bound = any(key.startswith("identityBound") for key in value["agreement"])
                with self.subTest(scenario=name):
                    ref.check_payment_input(BINDINGS["identity-bound" if identity_bound else "ordinary"], value)
                    checked += 1
        self.assertGreater(checked, 0)

    def test_typed_arm_shape_is_checked_before_handler(self):
        # PC-1 accepts the typed shape, not any object carrying its session key.
        names = {v["name"]: v for v in self.data["phaseInputs"]}
        for name in ("ordinary-empty-session-context", "ordinary-null-payer",
                     "ordinary-empty-agreement", "ordinary-empty-rail"):
            with self.subTest(vector=name):
                rail = mock.Mock()
                result = ref.dispatch_payment(BINDINGS[names[name]["binding"]],
                                              copy.deepcopy(names[name]["input"]), rail)
                self.assertEqual((result["status"], result["errorClass"]), ("rejected", "permanent"))
                rail.assert_not_called()

    def test_single_member_edit_fails_on_that_members_type(self):
        # A one-member edit of an accepted input is rejected by that member's
        # own check, so no case passes by tripping an earlier, unrelated one.
        reasons = {"sessionContext": "sessionContext is not SessionContext"}
        by_name = {
            "ordinary-companions-not-array": "identityBindingCompanions is not an array",
            "ordinary-companions-empty": "identityBindingCompanions is empty",
            "ordinary-companion-empty-object":
                "identityBindingCompanions entry is not an IdentityBoundAgreementCompanion",
            # The agreement's kind contradicts the Listing's selection.
            "ordinary-binding-identity-bound-agreement-without-companions":
                "agreement is not the agreement kind the Listing selects",
        }
        names = {v["name"]: v for v in self.data["phaseInputs"]}
        bases = {"ordinary": names["ordinary-input"]["input"]}
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
                result = ref.dispatch_payment(binding_for(vector), copy.deepcopy(value), mock.Mock())
                self.assertEqual(result["reason"], by_name.get(vector["name"]) or reasons.get(
                    changed[0], "payment input member is not its declared type"))
                checked.add(changed[0])
        self.assertTrue({"agreement", "rail", "payer", "payee", "amount", "jobId",
                         "sessionContext", "identityBindingCompanions"} <= checked, checked)

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
        for party in ("buyer", "seller", "orchestrator"):
            session = accepted["sessionContext"]
            inputs.append({**accepted, "sessionContext": {**session, "parties": [
                {**session["parties"][0], "role": party}, *session["parties"][1:]]}})
        inputs = [("ordinary", value) for value in inputs]
        # An identity-bound agreement carries its companions on the path the
        # Listing selects (§9.5.1); a present companion is typed on either path.
        payout = {**agreement["terms"], "payoutBindings": [{
            "railId": rail["railId"], "phaseIndex": 0, "payeeAddress": "seller-address"}]}
        for selector, terms in (("identityBoundAgreementVersion", agreement["terms"]),
                                ("agreementVersion", agreement["terms"]),
                                ("payeeBoundAgreementVersion", payout),
                                ("identityBoundPayeeAgreementVersion", payout)):
            inputs.append(("identity-bound" if selector.startswith("identityBound") else "ordinary", {
                **accepted, "identityBindingCompanions": COMPANIONS, "agreement": {selector: "1", **{
                    k: v for k, v in agreement.items() if k != "agreementVersion"}, "terms": terms}}))
        for binding, value in inputs:
            with self.subTest(binding=binding, input=json.dumps({k: value[k] for k in ("agreement", "rail")})[:120]):
                ref.check_payment_input(BINDINGS[binding], value)

    def test_nested_rail_required_members_and_types_reject_before_handler(self):
        names = {v["name"]: v for v in self.data["phaseInputs"]}
        for binding in ARMS:
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
        for binding in ARMS:
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
        # An identity-bound agreement carries its companions (§9.5.1).
        base = {**base, "identityBindingCompanions": COMPANIONS}
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
            # A complete minimal arm is accepted. A pay-* agreement names its rail
            # (DACS-3 8.5.2 rule 3); no other optional member is required.
            source["terms"] = {k: v for k, v in source["terms"].items()
                               if k in ("deliverable", "price", "deadline", "rail", "payoutBindings")}
            source["terms"]["deliverable"].pop("schemaUrl", None)
            binding = BINDINGS["identity-bound" if selector.startswith("identityBound") else "ordinary"]
            ref.check_payment_input(binding, {**base, "agreement": source})
            bad = [{**source, "terms": {k: v for k, v in source["terms"].items() if k != "rail"}}]
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
                    result = ref.dispatch_payment(binding, {**base, "agreement": candidate}, handler)
                    self.assertEqual(result["status"], "rejected")
                    handler.assert_not_called()

    def test_declared_optional_members_are_typed_before_handler(self):
        # DACS-3 8.5 and DACS-4 9.4.1 type every present optional member.
        names = {v["name"]: v for v in self.data["phaseInputs"]}
        # Published rails whose complete profile matches their handler (DACS-4 9.4.3 RD-7).
        finality = json.loads((ROOT / "conformance/vectors/security/settlement-finality-verification.json").read_text())
        rails = {v["input"]["rail"]["consumerFinalityProfile"]["model"]: v["input"]["rail"]
                 for v in finality["vectors"] if v["expected"] == "pass"}
        self.assertEqual(set(rails), {"block-depth", "commitment-level", "bft-final",
                                      "provider-receipt", "htlc-reveal", "liquidity-tank"})
        profiles = {model: rail["consumerFinalityProfile"] for model, rail in rails.items()}
        settlement = profiles["block-depth"]["settlement"]
        for binding in ARMS:
            base = names[binding + "-input"]["input"]
            agreement, rail = base["agreement"], base["rail"]
            party = agreement["parties"][0]

            def with_agreement(**change):
                return {**base, "agreement": {**agreement, **change}}

            def with_terms(**change):
                return with_agreement(terms={**agreement["terms"], **change})

            def with_profile(profile, model="bft-final"):
                # A one-member edit of that model's published rail.
                return {**base, "rail": {**rails[model], "consumerFinalityProfile": profile}}

            def with_settlement(**change):
                return with_profile({**profiles["block-depth"], "settlement": {**settlement, **change}}, "block-depth")

            def with_observation(**change):
                return with_settlement(observation={**settlement["observation"], **change})

            # The published spec-complete rails of every model, unknown members kept.
            good = [{**base, "rail": value} for value in rails.values()]
            good += [with_profile({**profiles["bft-final"], "future": True}),
                     with_profile({**profiles["block-depth"], "finalityResolutionCapability":
                                   "finality-resolution-context-v1"}, "block-depth"),
                     with_observation(method="light-client", threshold=1),
                     {**base, "rail": {**rail, "railId": "evm-erc20:8453:USDC"}},
                     with_agreement(derivedFromChannel={"subnet": "s", "lastMessageHash": "m", "future": 1}),
                     with_agreement(parties=[{**party, "encryptionKey": "k"}, *agreement["parties"][1:]]),
                     with_terms(meteredQuantity={"quantity": "120", "unit": "call"}),
                     with_terms(additionalTerms={}),
                     # Informational members never gate settlement (DACS-3 8.5.2, FS-3).
                     with_terms(priceAnchor=[]), with_terms(feeSchedule=[])]
            observation = {k: v for k, v in settlement["observation"].items() if k != "threshold"}
            good.append(with_settlement(observation={**observation, "method": "consensus-backed-proxy"}))
            for value in good:
                with self.subTest(binding=binding, accepted=json.dumps(value["agreement"]["terms"])[:60]
                                  + json.dumps(value["rail"].get("consumerFinalityProfile"))[:80]):
                    handler = mock.Mock(return_value={"status": "accepted", "ok": True})
                    self.assertEqual(ref.dispatch_payment(BINDINGS[binding], value, handler)["status"], "accepted")
                    handler.assert_called_once_with(value)
            bad = [with_agreement(parties=[{**party, "encryptionKey": key}, *agreement["parties"][1:]])
                   for key in (None, 1, [], "")]
            bad += [with_agreement(derivedFromChannel=value) for value in (
                None, [], "subnet", {"subnet": "s"}, {"lastMessageHash": "m"},
                {"subnet": "", "lastMessageHash": "m"}, {"subnet": "s", "lastMessageHash": 1})]
            bad += [with_terms(meteredQuantity=value) for value in (
                None, [], {"quantity": "1"}, {"unit": "call"}, {"quantity": 1, "unit": "call"},
                {"quantity": "-1", "unit": "call"}, {"quantity": "1.5", "unit": "call"},
                {"quantity": "1e3", "unit": "call"}, {"quantity": "00", "unit": "call"},
                {"quantity": "", "unit": "call"}, {"quantity": "1", "unit": ""})]
            bad += [with_terms(additionalTerms=value) for value in (None, [], 0, "x")]
            bad += [{**base, "rail": {**rail, "railId": value}}
                    for value in ("démo", "ＡＢ", "a b", "a\tb", "a\x7fb", 1)]
            bad += [with_profile(value) for value in (None, [], {}, "bft-final")]
            for model, profile in profiles.items():
                bad += [with_profile({**profile, "finalityProfileVersion": "2"}, model),
                        with_profile({**profile, "finalityResolutionCapability": None}, model),
                        with_profile({k: v for k, v in profile.items() if k != "model"}, model)]
                # A wrong-typed model is a type rejection, never a crash.
                bad += [with_profile({**profile, "model": value}, model) for value in (None, 1, [], {}, [model])]
                for key in profile:
                    if key not in ("finalityProfileVersion", "model", "finalityResolutionCapability"):
                        bad.append(with_profile({k: v for k, v in profile.items() if k != key}, model))
                        bad.append(with_profile({**profile, key: None}, model))
            bad.append(with_profile({**profiles["bft-final"], "model": "block-depth"}))
            bad += [with_profile({**profiles["provider-receipt"], key: value}, "provider-receipt") for key, value in (
                ("captureStatuses", []), ("captureStatuses", [1]), ("maxObservationAgeSec", 0),
                ("maxObservationAgeSec", "60"), ("reversibility", "final"), ("providerId", ""))]
            for key in settlement:
                bad.append(with_settlement(**{key: None}))
            bad += [with_settlement(requiredDepth=0), with_settlement(kind="optimistic")]
            bft = profiles["bft-final"]
            bad += [with_profile({**bft, "settlement": {**bft["settlement"], key: value}}) for key, value in (
                ("quorumNumerator", "2"), ("quorumDenominator", 0), ("validatorSetRef", {}))]
            commitment = profiles["commitment-level"]
            bad.append(with_profile({**commitment, "settlement": {
                **commitment["settlement"], "requiredCommitment": "safe"}}, "commitment-level"))
            bad += [with_observation(**change) for change in (
                {"method": "gossip"}, {"authorityRefs": []}, {"authorityRefs": [""]},
                {"authorityRefs": "ref"}, {"threshold": 0},
                {"threshold": len(settlement["observation"]["authorityRefs"]) + 1},
                {"maxHeadAgeSec": 0}, {"maxHeadAgeSec": "60"})]
            bad.append(with_settlement(observation={**observation, "method": "rpc-quorum"}))
            # Label each case by its edits from the nearest unedited input.
            origins = {"input": base, **{model: {**base, "rail": value} for model, value in rails.items()}}
            labels = []
            for value in bad:
                name, origin = min(origins.items(), key=lambda item: len(edits(item[1], value)))
                labels.append(f"{name}: " + " ".join(edits(origin, value)))
            self.assertEqual(sorted({label for label in labels if labels.count(label) > 1}), [])
            for value, label in zip(bad, labels):
                with self.subTest(binding=binding, rejected=label):
                    handler = mock.Mock(return_value={"status": "accepted", "ok": True})
                    result = ref.dispatch_payment(BINDINGS[binding], value, handler)
                    self.assertEqual((result["status"], result["errorClass"], result["reason"]), (
                        "rejected", "permanent", "payment input member is not its declared type"))
                    handler.assert_not_called()

    def test_rail_id_rule_matches_the_section_9_4_1_definition_and_registry(self):
        # PC-1 cites the 9.4.1 railId rule; the 9.4.2 registry ids are uppercase.
        spec = (ROOT / "spec/DACS-4-SETTLE.md").read_text()
        schema = spec.split("type RailDefinition = {", 1)[1].split("\n}", 1)[0]
        comment = next(line for line in schema.splitlines() if line.strip().startswith("railId:"))
        self.assertIn("1-64 printable ASCII chars (0x21-0x7E, no whitespace); case-sensitive", comment)
        self.assertNotIn("lowercase", comment)
        registry = spec.split("#### 9.4.2", 1)[1].split("\n\n**", 1)[0]
        ids = [row.split("|")[1].strip() for row in registry.splitlines()
               if row.startswith("| ") and not row.startswith(("| Rail ID", "| ---"))]
        self.assertIn("demos-native:DEM", ids)
        self.assertEqual(len(ids), 13)
        names = {v["name"]: v for v in self.data["phaseInputs"]}
        for binding in ARMS:
            base = names[binding + "-input"]["input"]
            for rail_id in (*ids, "\x21", "\x7e" * 64):
                with self.subTest(binding=binding, accepted=rail_id):
                    value = {**base, "rail": {**base["rail"], "railId": rail_id}}
                    handler = mock.Mock(return_value={"status": "accepted", "ok": True})
                    self.assertEqual(ref.dispatch_payment(BINDINGS[binding], value, handler)["status"], "accepted")
                    handler.assert_called_once_with(value)
            for rail_id in ("", "\x7e" * 65, "a\x20b", "\x7f", "évm"):
                with self.subTest(binding=binding, rejected=rail_id):
                    value = {**base, "rail": {**base["rail"], "railId": rail_id}}
                    handler = mock.Mock(return_value={"status": "accepted", "ok": True})
                    self.assertEqual(ref.dispatch_payment(BINDINGS[binding], value, handler)["status"], "rejected")
                    handler.assert_not_called()

    def test_profile_value_domains_stay_with_fv1(self):
        # PC-1 types the profile; FV-1 makes these value-domain breaks `error`.
        import settlement_finality_reference as fv
        finality = json.loads((ROOT / "conformance/vectors/security/settlement-finality-verification.json").read_text())
        profiles = {v["input"]["rail"]["consumerFinalityProfile"]["model"]: v["input"]["rail"]["consumerFinalityProfile"]
                    for v in finality["vectors"] if v["expected"] == "pass"}
        provider, bft = profiles["provider-receipt"], profiles["bft-final"]
        observation = bft["settlement"]["observation"]
        cases = {
            "origin-with-path": {**provider, "statusEndpointOrigin": provider["statusEndpointOrigin"] + "/status"},
            "duplicate-capture-statuses": {**provider, "captureStatuses": provider["captureStatuses"] * 2},
            "duplicate-authority-refs": {**bft, "settlement": {**bft["settlement"], "observation": {
                **observation, "authorityRefs": observation["authorityRefs"][:1] * 2, "threshold": 2}}},
            "quorum-above-one": {**bft, "settlement": {**bft["settlement"],
                                                       "quorumNumerator": 5, "quorumDenominator": 3}},
        }
        for model in ("provider-receipt", "bft-final"):
            self.assertTrue(fv._finality_profile_shape(profiles[model]), model)
        for name, profile in cases.items():
            with self.subTest(case=name):
                self.assertTrue(ref._finality_profile_valid(ref._shapes(), profile))
                self.assertFalse(fv._finality_profile_shape(profile))
        spec = " ".join((ROOT / "spec/DACS-4-SETTLE.md").read_text().split())
        self.assertIn("These are declared-type checks. A profile's further value domains", spec)
        self.assertIn("stay with FV-1, which classifies a malformed profile as `error`", spec)


    def test_unknown_target_members_follow_each_arms_schema(self):
        names = {v["name"]: v for v in self.data["amendmentTargets"]}
        for label in TARGET_ARMS:
            with self.subTest(arm=label):
                vector = names[label + "-unknown-member"]
                self.assertIn("futureMember", vector["resolved"]["artifact"])
                self.assertEqual(self.consume(vector)[0], vector["expected"])
                self.assertEqual(vector["expected"], OPEN_TARGET_ARMS.get(label, "violation"))
        changelog = (ROOT / "CHANGELOG.md").read_text()
        heading = "### Changed — general normative changes in candidate DACS-4 v0.8 (every profile)"
        changed = " ".join(changelog.split(heading, 1)[1].split("\n### ", 1)[0].split())
        for phrase in ("complete AssetSpec and NetworkSpec arms",
                       "DeliverableRef, PaymentRailRef, payout binding entries",
                       "The agreement must carry `terms.rail` (DACS-3 §8.5.2 rule 3)",
                       "do not gate settlement (DACS-3 §8.5.2, FS-3)",
                       "the rail's `railId` must be 1–64 printable ASCII characters (0x21–0x7E, case-sensitive",
                       "These are declared-type checks: a profile's further value domains",
                       "The transition and finality-bound target arms use closed shapes and reject "
                       "unknown members; ordinary `SettlementEvidence` keeps unknown optional members "
                       "under CORE SIG-5"):
            self.assertIn(phrase, changed)
        spec = " ".join((ROOT / "spec/DACS-4-SETTLE.md").read_text().split())
        self.assertIn("ordinary `SettlementEvidence` keeps unknown optional members under CORE SIG-5", spec)

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
        for name in DELIVERY_TARGETS:
            with self.subTest(vector=name):
                self.assertEqual(self.consume(names[name]),
                                 ("violation", "amendment target is not a payment phase"))

    def test_amendment_targets_resolve_hash_select_and_verify(self):
        for vector in self.data["amendmentTargets"]:
            with self.subTest(vector=vector["name"]):
                resolver = mock.Mock(return_value=received_resolution(vector["resolved"]))
                result, reason = self.consume(vector, resolver)
                self.assertEqual(result, vector["expected"], reason)
                if "signature" in vector["amendment"] and "amendmentText" not in vector:
                    resolver.assert_called_once_with(vector["amendment"]["amendsEvidenceRef"])
                else:
                    # A malformed or unadmitted amendment is decided before any resolution.
                    resolver.assert_not_called()
                if result == "valid":
                    record = vector["resolved"]["artifact"]
                    self.assertRegex(vector["amendmentAddress"],
                        rf"\Adacs4:amendment:{record['jobId']}:{content_hash(record)}:(0|[1-9][0-9]*)\Z")

    def test_target_hash_precedes_discriminator_interpretation(self):
        vector = copy.deepcopy(next(v for v in self.data["amendmentTargets"]
                                   if v["name"] == "ordinary-target"))
        vector["resolved"]["artifact"]["finalityBoundEvidenceVersion"] = "1"
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
        for label in TARGET_ARMS:
            with self.subTest(arm=label):
                self.assertEqual(self.consume(names[label + "-seller-signed"]), (
                    "violation", "signature signer is not the authenticated authority"))
                # The same valid target fails when the verifier pins another orchestrator.
                self.assertEqual(self.consume(names[label + "-target"],
                                              orchestrator="did:dacs:test:seller")[0], "violation")

    def test_success_target_requires_its_complete_arm(self):
        names = {v["name"]: v for v in self.data["amendmentTargets"]}
        for label in TARGET_ARMS:
            for member in ("paymentAmount", "settlementFinality"):
                with self.subTest(arm=label, member=member):
                    vector = names[f"{label}-success-without-{member}"]
                    self.assertNotIn(member, vector["resolved"]["artifact"])
                    self.assertEqual(self.consume(vector)[0], "violation")

    def test_amendment_address_binds_target_hash(self):
        vector = next(v for v in self.data["amendmentTargets"] if v["name"] == "ordinary-target")
        good = vector["amendmentAddress"]
        prefix, digest, index = good.rsplit(":", 2)
        for address in (f"{prefix}:{'0' * 64}:{index}", good + ":0", good.upper(), None):
            with self.subTest(address=address):
                self.assertEqual(self.consume({**vector, "amendmentAddress": address}), (
                    "violation", "amendment address does not bind the target evidence hash"))

    def test_unavailable_resolver_does_not_record_a_violation(self):
        vector = next(v for v in self.data["amendmentTargets"] if v["name"] == "ordinary-target")
        import http.client
        # Any resolver failure is unavailability, never a violation or a crash.
        for exception in (TimeoutError("timeout"), FileNotFoundError("not found"),
                          ConnectionRefusedError("refused"), ValueError("bad reply"),
                          json.JSONDecodeError("bad json", "{", 1), KeyError("artifact"),
                          TypeError("bad type"), http.client.IncompleteRead(b"x", 10),
                          RuntimeError("closed")):
            with self.subTest(exception=type(exception).__name__):
                resolver = mock.Mock(side_effect=exception)
                result, reason = self.consume(vector, resolver)
                self.assertEqual(result, "indeterminate")
                # The cause stays distinguishable: timeout, not-found or refused.
                self.assertIn(type(exception).__name__, reason)

    def test_non_object_inputs_fail_closed(self):
        vector = next(v for v in self.data["amendmentTargets"] if v["name"] == "ordinary-target")
        for amendment in (None, [], "amendment"):
            with self.subTest(amendment=amendment):
                self.assertEqual(self.consume({**vector, "amendment": amendment})[0], "violation")
        case = next(c for c in self.rails["cases"] if c["name"] == "rail-authority-pinned-before-start")
        for member, value in (("rail", None), ("rail", []), ("railRef", None), ("railRef", "demos-native:DEM"),
                              ("session", None), ("authority", [])):
            with self.subTest(member=member, value=value):
                result, _ = self.resolve_rail({**case, member: value})
                self.assertIn(result, {"rejected", "indeterminate"})

    def test_rail_authority_cases_resolve_as_fixed(self):
        # RTB-1: every case is decided from verifier-owned session pins and
        # authenticated, finalized index and definition receipts.
        self.assertTrue(self.rails["cases"])
        for case in self.rails["cases"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(case["ruleRefs"], ["RTB-1"])
                result, reason = self.resolve_rail(case)
                self.assertEqual(result, case["expected"], reason)

    def test_rail_authority_time_bound_is_inclusive(self):
        # "No later than" the session start: equality verifies; a session that
        # started one millisecond earlier cannot use the same authority.
        names = {c["name"]: c for c in self.rails["cases"]}
        case = names["rail-authority-at-session-start"]
        started = case["session"]["startedAt"]
        authority = case["authority"]
        self.assertEqual((authority["railRegistryIndexReceipts"][0]["blockRef"]["timestamp"],
                          authority["railDefinitionReceipts"][0]["blockRef"]["timestamp"],
                          case["rail"]["governance"]["acceptedAt"]), (started, started, started))
        self.assertEqual(self.resolve_rail(case)[0], "verified")
        earlier = {**case, "session": {**case["session"], "startedAt": started - 1}}
        self.assertEqual(self.resolve_rail(earlier),
                         ("rejected", "rail authority postdates the session start"))

    def test_rail_time_is_read_only_from_an_authenticated_receipt(self):
        # Editing a late receipt's timestamp without a new proof does not make
        # it timely: the receipt is no longer authentic and is discarded.
        names = {c["name"]: c for c in self.rails["cases"]}
        for name, member in (("index-receipt-after-session-start", "railRegistryIndexReceipts"),
                             ("definition-receipt-after-session-start", "railDefinitionReceipts")):
            with self.subTest(case=name):
                case = copy.deepcopy(names[name])
                case["authority"][member][0]["blockRef"]["timestamp"] = case["session"]["startedAt"]
                result, reason = self.resolve_rail(case)
                self.assertEqual(result, "indeterminate")
                self.assertIn("not authentic", reason)

    def test_later_index_informs_only_a_new_session(self):
        names = {c["name"]: c for c in self.rails["cases"]}
        existing = names["later-index-for-existing-session"]
        new = names["later-index-for-new-session"]
        self.assertEqual((existing["rail"], existing["authority"]), (new["rail"], new["authority"]))
        self.assertLess(existing["session"]["startedAt"], new["session"]["startedAt"])
        self.assertEqual(self.resolve_rail(existing)[0], "rejected")
        self.assertEqual(self.resolve_rail(new)[0], "verified")
        # The existing session's own pinned authority is unchanged.
        pinned = names["rail-authority-pinned-before-start"]
        self.assertEqual(pinned["session"], existing["session"])
        self.assertEqual(self.resolve_rail(pinned)[0], "verified")

    def test_rail_authority_trust_pins_are_verifier_owned(self):
        names = {c["name"]: c for c in self.rails["cases"]}
        case = names["rail-authority-pinned-before-start"]
        self.assertEqual(self.resolve_rail(case)[0], "verified")
        # Another steward or network authority leaves nothing authenticated.
        self.assertEqual(self.resolve_rail(case, steward="did:dacs:test:seller")[0], "rejected")
        self.assertEqual(self.resolve_rail(case, network_authority="did:dacs:test:seller")[0],
                         "indeterminate")
        # Another registry writer leaves the receipts without authority (SR2-11).
        self.assertEqual(self.resolve_rail(case, registry_writer="native:outsider-writer-1")[0],
                         "indeterminate")
        target = next(v for v in self.data["amendmentTargets"] if v["name"] == "ordinary-target")
        result, reason = self.consume(target, writer="native:outsider-writer-1")
        self.assertEqual(result, "indeterminate")
        self.assertIn("AnchorReceipt writer is not the authorized writer", reason)

    def test_unpinned_selection_is_the_unique_greatest_listed_version(self):
        # §9.4.3 step 2; a hint member in the snapshot selects nothing.
        names = {c["name"]: c for c in self.rails["cases"]}
        greatest, older = names["unpinned-selects-greatest-version"], names["unpinned-older-version-rejected"]
        self.assertEqual(greatest["authority"]["railRegistryIndex"]["entries"],
                         older["authority"]["railRegistryIndex"]["entries"])
        self.assertEqual([e["version"] for e in greatest["authority"]["railRegistryIndex"]["entries"]], [1, 2])
        self.assertEqual(self.resolve_rail(greatest)[0], "verified")
        self.assertEqual(self.resolve_rail(older),
                         ("rejected", "definition is not the version the agreement selects"))
        self.assertEqual(names["latest-hint-is-inert"]["authority"]["railRegistryIndex"]["latestVersion"], 1)
        self.assertEqual(self.resolve_rail(names["latest-hint-is-inert"])[0], "rejected")
        self.assertEqual(self.resolve_rail(names["pinned-older-version"])[0], "verified")
        self.assertEqual(self.resolve_rail(names["railref-other-rail-id"]),
                         ("rejected", "definition is not the rail the agreement names"))
        self.assertEqual(self.resolve_rail(names["index-duplicate-version"])[0], "indeterminate")
        self.assertEqual(self.resolve_rail(names["index-entry-not-object"]),
                         ("rejected", "rail-registry index snapshot is malformed"))

    def test_index_snapshot_follows_core_registry_shape(self):
        # CORE RegistryIndexEntry is closed with a positive version and any
        # registered anchor kind; the revision is a positive safe integer.
        names = {c["name"]: c for c in self.rails["cases"]}
        kinds = {e["anchor"]["kind"] for e in
                 names["index-lists-ipfs-and-https-entries"]["authority"]["railRegistryIndex"]["entries"]}
        self.assertEqual(kinds, {"storage-program", "ipfs", "https"})
        self.assertEqual(self.resolve_rail(names["index-lists-ipfs-and-https-entries"])[0], "verified")
        for name in ("index-entry-version-zero", "index-entry-extra-member", "index-entry-anchor-extra-member",
                     "index-revision-boolean"):
            with self.subTest(case=name):
                self.assertEqual(self.resolve_rail(names[name]),
                                 ("rejected", "rail-registry index snapshot is malformed"))
        for name in ("session-registry-version-zero", "session-registry-version-negative"):
            with self.subTest(case=name):
                self.assertEqual(self.resolve_rail(names[name]), (
                    "rejected", "session pins are not an integer start and a positive registry version"))
        # PA-1 and PA-3 rail authority is not implemented here: never verified.
        for name, anchoring in (("pa3-multisig-rail-not-implemented", "multisig"),
                                ("pa1-in-code-rail-not-implemented", "in-code")):
            with self.subTest(case=name):
                self.assertEqual(names[name]["rail"]["governance"]["anchoring"], anchoring)
                self.assertEqual(self.resolve_rail(names[name]), (
                    "indeterminate", f"{anchoring} rail authority is not implemented by this verifier"))
        unknown = copy.deepcopy(names["rail-authority-pinned-before-start"])
        unknown["rail"]["governance"]["anchoring"] = "committee"
        self.assertEqual(self.resolve_rail(unknown),
                         ("rejected", "rail governance anchoring is not a declared value"))

    def test_payment_evidence_reason_and_price_unit_are_typed(self):
        # DACS-4 §9.7: a failure record carries `reason`, a success record may
        # not; PriceTerm's optional `unit` is a non-empty string.
        names = {v["name"]: v for v in self.data["amendmentTargets"]}
        self.assertEqual(names["ordinary-failure-target"]["resolved"]["artifact"]["reason"], "rail refused the transfer")
        self.assertEqual(self.consume(names["ordinary-failure-target"]), ("valid", "AMEND-1 target verified"))
        self.assertEqual(self.consume(names["ordinary-success-with-reason"]),
                         ("violation", "amendment target is not its evidenceVersion arm"))
        inputs = {v["name"]: v for v in self.data["phaseInputs"]}
        self.assertEqual(inputs["ordinary-amount-unit"]["input"]["amount"]["unit"], "token")
        handler = mock.Mock(return_value={"status": "accepted", "ok": True})
        self.assertEqual(ref.dispatch_payment(BINDINGS["ordinary"], inputs["ordinary-amount-unit"]["input"],
                                              handler)["status"], "accepted")
        self.assertEqual(ref.dispatch_payment(BINDINGS["ordinary"], inputs["ordinary-amount-unit-empty"]["input"],
                                              handler)["reason"], "payment input member is not its declared type")

    def resign_receipt(self, receipt, **change):
        """An authentic copy of `receipt` with `change` applied and re-proven."""
        body = {k: v for k, v in receipt.items() if k != "evidence"}
        body.update(change)
        for key in [k for k, v in change.items() if v is ...]:
            body.pop(key)
        proof = generator.sign({"receipt": body, "networkId": TRUST["network_id"],
                                "proofProfile": TRUST["proof_profile"],
                                "validatorSetId": TRUST["validator_set_id"]},
                               "network", ref.ANCHOR_TEST_DOMAIN)
        return {**body, "evidence": {"kind": ref.ANCHOR_TEST_KIND,
                                     "value": generator.b64u(ref.jcs_bytes(proof))}}

    def test_receipt_fields_are_checked_even_when_proven(self):
        vector = next(v for v in self.data["amendmentTargets"] if v["name"] == "ordinary-target")
        receipt = vector["resolved"]["anchorReceipts"][0]

        def with_receipt(value):
            return {**vector, "resolved": {**vector["resolved"], "anchorReceipts": [value]}}
        # The unchanged re-proof verifies, so each failure below is the edit's.
        self.assertEqual(self.consume(with_receipt(self.resign_receipt(receipt)))[0], "valid")
        self.assertEqual(self.consume(with_receipt(self.resign_receipt(receipt, nonce=...)))[0], "valid")
        for change in ({"substrate": "demos:mainnet"}, {"finalityProfile": "other-profile"},
                       {"nonce": ""}, {"nonce": 300}, {"writer": ""}, {"writer": 1},
                       # Re-proven empty or mistyped address and hash members are
                       # malformed, not a binding of other content.
                       {"contentHash": ""}, {"contentHash": 5}, {"nativeAddress": ""},
                       {"nativeAddress": 5},
                       # CORE §5.1: binding metadata belongs in `evidence`.
                       {"bindingNote": "x"},
                       {"transactionRef": {**receipt["transactionRef"], "extra": "x"}},
                       {"transactionRef": {"kind": "", "value": "tx"}},
                       {"blockRef": "x"}, {"blockRef": {**receipt["blockRef"], "height": "0750"}},
                       {"blockRef": {k: v for k, v in receipt["blockRef"].items() if k != "timestamp"}},
                       {"observedAt": -1}):
            with self.subTest(change=change):
                result, reason = self.consume(with_receipt(self.resign_receipt(receipt, **change)))
                self.assertEqual(result, "indeterminate")
                self.assertTrue(reason.startswith("amendment target anchor is not authentic"), reason)
        # Oversized or non-CF-5 proof bytes are refused before JSON decoding.
        for raw, message in ((b" " * (ref.MAX_PROOF_BYTES + 1), "exceeds the byte limit"),
                             (b'{"a":1,"a":2}', "not admitted JSON")):
            with self.subTest(proof=raw[:20]):
                bad = {**receipt, "evidence": {**receipt["evidence"], "value": generator.b64u(raw)}}
                result, reason = self.consume(with_receipt(bad))
                self.assertEqual(result, "indeterminate")
                self.assertIn(message, reason)

    def test_amendment_and_target_are_admitted_from_their_received_bytes(self):
        # CORE CF-5: a duplicate member another parser reads differently is
        # refused before any hash or signature check.
        names = {v["name"]: v for v in self.data["amendmentTargets"]}
        for name, member, artifact, expected in (
                ("amendment-duplicate-member", "amendmentText", lambda v: v["amendment"], "violation"),
                ("target-duplicate-member", "artifactText", lambda v: v["resolved"]["artifact"], "indeterminate")):
            with self.subTest(vector=name):
                vector = names[name]
                text = vector.get(member) or vector["resolved"][member]
                # An ordinary parser keeps the last member and sees the signed object.
                self.assertEqual(json.loads(text), artifact(vector))
                result, reason = self.consume(vector)
                self.assertEqual(result, expected)
                self.assertIn("is not admitted JSON: profile:DUPLICATE-MEMBER", reason)
        vector = names["ordinary-target"]
        good = received_resolution(vector["resolved"])
        for amendment in (b"\xff", b'{"a":1}x', vector["amendment"], None):
            with self.subTest(amendment=repr(amendment)[:30]):
                self.assertEqual(ref.consume_amendment_target(
                    amendment, lambda _: good, amendment_address=vector["amendmentAddress"],
                    orchestrator=self.data["orchestrator"], writer=self.data["orchestratorWriter"],
                    public_keys=self.data["publicKeys"], **TRUST)[0], "violation")
        for artifact, message in ((b"\xff", "not admitted JSON"), (vector["resolved"]["artifact"], "not received bytes"),
                                  (b" " * (ref.MAX_ARTIFACT_BYTES + 1), "exceeds the byte limit"),
                                  (b"[]", "is not an object")):
            with self.subTest(artifact=repr(artifact)[:30]):
                result, reason = self.consume(vector, lambda _, a=artifact: {**good, "artifact": a})
                self.assertEqual(result, "indeterminate")
                self.assertIn(message, reason)

    def test_unequal_authorized_carriers_are_an_equivocation(self):
        # CORE §5: fetch order selects no winner between authorized carriers.
        names = {v["name"]: v for v in self.data["amendmentTargets"]}
        for name in ("anchor-equivocation", "anchor-equivocation-other-content"):
            with self.subTest(vector=name):
                vector = names[name]
                receipts = vector["resolved"]["anchorReceipts"]
                self.assertEqual(len(receipts), 2)
                self.assertEqual({r["writer"] for r in receipts}, {self.data["orchestratorWriter"]})
                # Each carrier alone resolves; together they do not.
                for receipt in receipts:
                    alone = {**vector, "resolved": {**vector["resolved"], "anchorReceipts": [receipt]}}
                    self.assertIn(self.consume(alone)[0], {"valid", "violation"})
                self.assertEqual(self.consume(vector), (
                    "indeterminate", "amendment target has 2 canonically unequal authorized carriers (equivocation)"))
        self.assertEqual(self.consume(names["anchor-duplicate-carrier"])[0], "valid")
        self.assertEqual(self.consume(names["anchor-outsider-second-carrier"])[0], "valid")
        for name in ("index-receipt-equivocation", "definition-receipt-equivocation"):
            with self.subTest(case=name):
                case = next(c for c in self.rails["cases"] if c["name"] == name)
                result, reason = self.resolve_rail(case)
                self.assertEqual(result, "indeterminate")
                self.assertIn("2 canonically unequal authorized carriers (equivocation)", reason)
        # The carrier list a resolver returns is bounded.
        vector = names["ordinary-target"]
        many = {**vector["resolved"], "anchorReceipts": vector["resolved"]["anchorReceipts"] * (ref.MAX_CARRIERS + 1)}
        self.assertEqual(self.consume({**vector, "resolved": many}), (
            "indeterminate", "amendment target lists more carriers than this verifier admits"))

    def test_amendment_reference_keeps_unknown_members_and_types_declared_ones(self):
        # CORE SIG-5: unknown signed members of amendsEvidenceRef stay open.
        vector = next(v for v in self.data["amendmentTargets"] if v["name"] == "amendment-reference-extra-member")
        target_ref = vector["amendment"]["amendsEvidenceRef"]
        self.assertEqual((target_ref["future"], target_ref["anchor"]["future"]), ("x", "x"))
        self.assertEqual(self.consume(vector), ("valid", "AMEND-1 target verified"))
        amendment = {k: v for k, v in vector["amendment"].items() if k != "signature"}
        for change in ({"contentHash": "x"}, {"anchor": {**target_ref["anchor"], "locator": ""}},
                       {"anchor": {**target_ref["anchor"], "kind": "carrier-pigeon"}}):
            with self.subTest(change=change):
                signed = generator.sign({**amendment, "amendsEvidenceRef": {**target_ref, **change}},
                                        "seller", ref.AMENDMENT_DOMAIN)
                self.assertEqual(self.consume({**vector, "amendment": signed}),
                                 ("violation", "amendment target reference malformed"))

    def test_ecdsa_case_carries_a_genuine_low_s_der_signature(self):
        # The registered-but-unimplemented case asks only the implementation
        # question: its value is canonical low-S DER and verifies (CORE §B.7).
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        vector = next(v for v in self.data["amendmentTargets"]
                      if v["name"] == "ordinary-target-algorithm-ecdsa-secp256k1")
        target = vector["resolved"]["artifact"]
        signature = target["signature"]
        self.assertEqual((signature["algorithm"], signature["signer"]),
                         ("ecdsa-secp256k1", self.data["orchestrator"]))
        raw = ref.b64u_decode(signature["value"])
        r, s = utils.decode_dss_signature(raw)
        self.assertEqual(utils.encode_dss_signature(r, s), raw)
        self.assertTrue(1 <= r < generator.SECP256K1_ORDER and 1 <= s <= generator.SECP256K1_ORDER // 2)
        key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), bytes.fromhex(self.data["ecdsaPublicKeys"][self.data["orchestrator"]]))
        key.verify(raw, generator.EVIDENCE_DOMAIN + content_hash(target).encode("ascii"),
                   ec.ECDSA(hashes.SHA256()))
        self.assertEqual(self.consume(vector), (
            "indeterminate", "signature algorithm ecdsa-secp256k1 is not implemented by this verifier"))
        self.assertEqual(self.data["verifierProfile"], {"signatureAlgorithms": ["ed25519"]})

    def test_signed_values_follow_the_core_b2_value_model(self):
        # CORE §B.2: finite fractions and integers within 2**53 - 1; CF-1 NFC
        # applies to string values while hashing and never to member names.
        keys = {generator.CLAIMS["orchestrator"]: generator.PUBLIC_KEYS[generator.CLAIMS["orchestrator"]]}
        for value in (2**53 - 1, -(2**53 - 1), None, True, False, 1.5, -0.25, "café", {"café": 1}):
            with self.subTest(accepted=value):
                signed = generator.sign({"value": value}, "orchestrator", b"test:")
                ref.verify_embedded(signed, keys, b"test:")
        # The boundaries: safe-magnitude floats, the empty string, and the
        # scalar values on either side of the surrogate block.
        for value in (float(2**53 - 1), -float(2**53 - 1), "", "퟿", "", {"": 1}):
            with self.subTest(accepted=repr(value)):
                signed = generator.sign({"value": value}, "orchestrator", b"test:")
                ref.verify_embedded(signed, keys, b"test:")
        # NFC and NFD spellings of a value hash alike; member names stay distinct.
        self.assertEqual(ref.content_hash({"v": "café"}), ref.content_hash({"v": "café"}))
        self.assertNotEqual(ref.content_hash({"café": 1}), ref.content_hash({"café": 1}))
        for value in (2**53, -(2**53), float(2**53), float("nan"), float("inf"), "\ud800", "\udfff",
                      {"\ud800": 1}, {"\udfff": 1}):
            with self.subTest(rejected=repr(value)):
                signed = {"value": value, "signature": generator.sign({}, "orchestrator", b"test:")["signature"]}
                with self.assertRaises(ref.Invalid):
                    ref.verify_embedded(signed, keys, b"test:")

    def test_signer_key_lookup_uses_cf3_identity(self):
        keys = self.data["publicKeys"]
        orchestrator = generator.CLAIMS["orchestrator"]
        signed = generator.sign({"value": 1}, "orchestrator", b"test:")
        # A parameterized signer resolves to the published identity's key.
        signed["signature"]["signer"] = orchestrator + "?role=x"
        ref.verify_embedded(signed, keys, b"test:")
        # An unpublished signer is missing authority, not a violation.
        with self.assertRaises(ref.Unknown):
            ref.verify_embedded({**signed, "signature": {**signed["signature"],
                                                         "signer": "did:dacs:test:unknown"}}, keys, b"test:")
        # Two published keys for one identity are ambiguous authority.
        twin = {**keys, orchestrator + "?role=y": keys[orchestrator], orchestrator + "?role=z": keys[orchestrator]}
        twin.pop(orchestrator)
        with self.assertRaises(ref.Invalid):
            ref.verify_embedded(signed, twin, b"test:")
        # An exact spelling does not hide a conflicting key for the same
        # identity: both spellings are ambiguous authority.
        conflicting = {**keys, orchestrator + "?role=y": keys[generator.CLAIMS["seller"]]}
        for signer in (orchestrator, orchestrator + "?role=y"):
            with self.subTest(signer=signer), self.assertRaisesRegex(ref.Invalid, "multiple authenticated keys"):
                ref.verify_embedded({**signed, "signature": {**signed["signature"], "signer": signer}},
                                    conflicting, b"test:")
        vector = next(v for v in self.data["amendmentTargets"] if v["name"] == "ordinary-target")
        unpublished = {k: v for k, v in keys.items() if k != generator.CLAIMS["seller"]}
        self.assertEqual(self.consume(vector, keys=unpublished)[0], "indeterminate")
        self.assertEqual(self.consume(vector, orchestrator=orchestrator + "?role=x")[0], "valid")

    def test_reference_signer_must_be_the_target_signer(self):
        # An amendsEvidenceRef `signer` other than the target's signer violates.
        vector = copy.deepcopy(next(v for v in self.data["amendmentTargets"] if v["name"] == "ordinary-target"))
        amendment = {k: v for k, v in vector["amendment"].items() if k != "signature"}
        for signer, expected in ((generator.CLAIMS["orchestrator"], "valid"),
                                 (generator.CLAIMS["seller"], "violation")):
            with self.subTest(signer=signer):
                amendment["amendsEvidenceRef"] = {**amendment["amendsEvidenceRef"], "signer": signer}
                signed = generator.sign(amendment, "seller", ref.AMENDMENT_DOMAIN)
                self.assertEqual(self.consume({**vector, "amendment": signed})[0], expected)

    def test_nested_rail_member_types_and_declared_values(self):
        base = next(v["input"] for v in self.data["phaseInputs"] if v["name"] == "ordinary-input")
        for member, value in (("asset", "x"), ("network", "x"), ("governance", "x"),
                              ("network", {"kind": "evm", "chainId": 0, "rpcAttestation": "evm-rpc"})):
            with self.subTest(member=member, value=value):
                handler = mock.Mock()
                result = ref.dispatch_payment(BINDINGS["ordinary"], {**base, "rail": {**base["rail"], member: value}}, handler)
                self.assertEqual(result["status"], "rejected")
                handler.assert_not_called()
        finality = json.loads((ROOT / "conformance/vectors/security/settlement-finality-verification.json").read_text())
        rail = next(v["input"]["rail"] for v in finality["vectors"] if v["expected"] == "pass"
                    and v["input"]["rail"]["consumerFinalityProfile"]["model"] == "commitment-level")
        profile = rail["consumerFinalityProfile"]
        for level in ("processed", "confirmed", "finalized"):
            with self.subTest(requiredCommitment=level):
                value = {**base, "rail": {**rail, "consumerFinalityProfile": {
                    **profile, "settlement": {**profile["settlement"], "requiredCommitment": level}}}}
                ref.check_payment_input(BINDINGS["ordinary"], value)

    def test_generator_check_gate_detects_drift(self):
        import contextlib
        import io
        import subprocess
        import tempfile
        run = subprocess.run([sys.executable, str(ROOT / "scripts/generate_settlement_contract_vectors.py"), "--check"],
                             capture_output=True, text=True, cwd=ROOT, check=False)
        self.assertEqual((run.returncode, run.stdout.strip()), (0, "OK: settlement contract fixtures"))
        for name in ("OUTPUT", "RAIL_OUTPUT"):
            with self.subTest(drifted=name), tempfile.TemporaryDirectory() as tmp:
                copies = {}
                for other in ("OUTPUT", "RAIL_OUTPUT"):
                    path = Path(tmp) / getattr(generator, other).name
                    path.write_text(getattr(generator, other).read_text())
                    copies[other] = path
                copies[name].write_text(copies[name].read_text().replace('"fixtureVersion": "1"', '"fixtureVersion": "2"', 1))
                out = io.StringIO()
                with mock.patch.object(generator, "OUTPUT", copies["OUTPUT"]), \
                        mock.patch.object(generator, "RAIL_OUTPUT", copies["RAIL_OUTPUT"]), \
                        mock.patch.object(generator, "ROOT", Path(tmp)), \
                        mock.patch.object(sys, "argv", ["generator", "--check"]), \
                        contextlib.redirect_stdout(out):
                    self.assertEqual(generator.main(), 1)
                self.assertIn(f"FAILED: {copies[name].name} differs from its generator", out.getvalue())

    def test_rtb1_text_binds_every_rail_consumer(self):
        spec = " ".join((ROOT / "spec/DACS-4-SETTLE.md").read_text().split())
        for phrase in ("**(RTB-1) Rail-authority time bound.** When a consumer resolves a session's PA-2 or PA-3 rail",
                       "`blockRef.timestamp` (CORE SR2-6 consensus time, unix milliseconds)",
                       "MUST each be no later than the authenticated session `startedAt`",
                       "written by the registry's authorized writer; a receipt from another writer is discarded",
                       "without the pinned index membership and both finalized anchor bindings do not resolve a rail",
                       "MUST NOT rewrite the rail authority of an existing session",
                       "uses the rail so resolved as verifier-owned session state"):
            self.assertIn(phrase, spec)
        # The fixture pins the receipt time unit it uses.
        self.assertIn("blockRef.timestamp is CORE SR2-6 consensus time in unix ms", self.rails["inputModel"])
        changelog = (ROOT / "CHANGELOG.md").read_text()
        heading = "### Changed — general normative changes in candidate DACS-4 v0.8 (every profile)"
        changed = " ".join(changelog.split(heading, 1)[1].split("\n### ", 1)[0].split())
        self.assertIn("**Rail resolution** (DACS-4 §9.4.3 RTB-1)", changed)

    def test_fixture_is_reproducible(self):
        self.assertEqual(self.data, generator.build_fixture())
        self.assertEqual(self.rails, generator.build_rail_fixture())


if __name__ == "__main__":
    unittest.main()
