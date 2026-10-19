"""DRP-18 pipeline placement, DRF-9 tagging, the DRC-22 and DREB-24 deployment
rules, and the DACS-4 SB-1 spelling of an EVM transaction hash (DRW-3).

Kept apart from tests/test_delivery_remedy_candidate_vectors.py, whose runtime
is close to the per-file test timeout.
"""

import copy
import json
import re
import unittest
import unittest.mock
from pathlib import Path

from scripts import generate_delivery_remedy_candidate_vectors as generator
from scripts import verify_delivery_remedy_candidate_vectors as verifier
from scripts.generate_delivery_remedy_candidate_vectors import make_base, put
from scripts.verify_delivery_remedy_candidate_vectors import (
    DEPLOYMENT_RULES,
    DRC_RULES,
    DecisionLedger,
    apply_operation,
    deployment_rule_statuses,
    evaluate_deployment,
    evaluate_protocol,
    materialize_vector,
)


ROOT = Path(__file__).resolve().parents[1]
VECTOR_PACK = ROOT / "conformance/fixtures/delivery-remedy/candidate-vectors-v0.1.json"
DEPLOYMENT_PACK = ROOT / "conformance/fixtures/delivery-remedy/deployment-capabilities-v0.1.json"
SPEC = ROOT / "docs/delivery-or-remedy-candidate.md"
SETTLE = ROOT / "spec/DACS-4-SETTLE.md"
SECURITY_VECTORS = ROOT / "conformance/vectors/security"
DACS1 = ROOT / "spec/DACS-1-IDENTIFY.md"
COMMIT_STEP = {
    "kind": verifier.COMMIT_PHASE_KIND,
    "parameters": {"agreementPhase": verifier.MODELLED_AGREEMENT_PHASE},
}
DRP18_VECTORS = {
    "pipeline-negotiation-missing": "the pipeline does not contain exactly one negotiate-* step",
    "pipeline-second-negotiation": "the pipeline does not contain exactly one negotiate-* step",
    "pipeline-commit-before-negotiation": "the commit step does not immediately follow the negotiation",
    "pipeline-second-commit-step": "the pipeline has a second commit step",
    "pipeline-dacs3-commitment-beside-commit": "a DACS-3 commitment phase accompanies the commit step",
    "pipeline-complete-sealed-negotiation": "a complete sealed-envelope negotiation cannot precede the payee-bound commit step",
}


def evaluate(value):
    return evaluate_protocol(value, DecisionLedger())


def finding(value):
    observed = evaluate(value)
    return observed["result"], observed["rule"]


def with_pipeline(edit):
    value = make_base("release")
    edit(value["pipeline"])
    return value


class PipelinePlacementTests(unittest.TestCase):
    """DRP-18: the commit step is the PS-2 commitment phase after the one negotiation."""

    @classmethod
    def setUpClass(cls):
        cls.vector_pack = json.loads(VECTOR_PACK.read_text(encoding="utf-8"))
        cls.vectors = {item["name"]: item for item in cls.vector_pack["vectors"]}

    def test_every_pass_fixture_negotiates_once_immediately_before_the_commit_step(self):
        layout = {
            generator.NEGOTIATION_STEP_INDEX: generator.NEGOTIATION_KIND,
            generator.COMMIT_STEP_INDEX: verifier.COMMIT_PHASE_KIND,
            generator.FUND_PHASE_INDEX: verifier.ESCROW_PHASE_KIND,
            generator.TERMINAL_PHASE_INDEX: verifier.ESCROW_PHASE_KIND,
        }
        self.assertEqual(generator.COMMIT_STEP_INDEX, generator.NEGOTIATION_STEP_INDEX + 1)
        passes = [vector for vector in self.vector_pack["vectors"] if vector["expected"] == "pass"]
        self.assertIn("DRP-18", self.vectors["release-complete-budget"]["rules"])
        for vector in passes:
            with self.subTest(vector=vector["name"]):
                # A pass vector that proves the pipeline rules proves DRP-18 too.
                self.assertEqual("DRP-14" in vector["rules"], "DRP-18" in vector["rules"])
                value = materialize_vector(self.vector_pack, vector)
                pipeline = value["pipeline"]
                for index, kind in layout.items():
                    self.assertEqual(pipeline[index]["kind"], kind)
                negotiations = [step for step in pipeline if step["kind"].startswith("negotiate-")]
                self.assertEqual(negotiations, [{"kind": generator.NEGOTIATION_KIND}])
                self.assertFalse(any(step["kind"] in verifier.DACS3_COMMITMENT_KINDS for step in pipeline))
                agreement = value["artifacts"]["agreement"]
                self.assertEqual(
                    (agreement["fundPhaseIndex"], agreement["deliveryPhaseIndex"], agreement["terminalPhaseIndex"]),
                    (generator.FUND_PHASE_INDEX, generator.DELIVERY_PHASE_INDEX, generator.TERMINAL_PHASE_INDEX),
                )
                # DACS-3 §8.5.2 check 7: the negotiation kind is the agreement's pattern.
                self.assertEqual(value["artifacts"]["bilateralAgreement"]["derivedFromPattern"], "fixed-price")

    def test_the_verifier_kinds_are_the_dacs1_phase_types(self):
        text = DACS1.read_text(encoding="utf-8")
        union = text[text.index("type PhaseType ="):text.index("// DACS-5", text.index("type PhaseType ="))]
        kinds = set(re.findall(r'"([a-z0-9-]+)"', union))
        self.assertEqual(verifier.NEGOTIATION_KINDS, {kind for kind in kinds if kind.startswith("negotiate-")})
        self.assertEqual(verifier.DACS3_COMMITMENT_KINDS, {kind for kind in kinds if kind.startswith("commit-")})
        self.assertEqual(
            verifier.COMPLETE_SEALED_NEGOTIATION_KINDS,
            {kind for kind in verifier.NEGOTIATION_KINDS if kind.endswith("-complete")},
        )

    def test_each_drp18_vector_fails_at_its_own_arm(self):
        for name, detail in DRP18_VECTORS.items():
            with self.subTest(vector=name):
                vector = self.vectors[name]
                self.assertEqual((vector["expected"], vector["expectedRule"]), ("fail", "DRP-18"))
                self.assertEqual(vector["rules"], ["DRP-18"])
                observed = evaluate(materialize_vector(self.vector_pack, vector))
                self.assertEqual((observed["result"], observed["rule"], observed["detail"]), ("fail", "DRP-18", detail))

    def test_every_drp18_arm_fails(self):
        """Each arm the candidate lists, for every kind it covers, is fail/DRP-18."""
        n, c = generator.NEGOTIATION_STEP_INDEX, generator.COMMIT_STEP_INDEX
        cases = {
            "no negotiation": lambda p: p.pop(n),
            "a step between negotiation and commit": lambda p: p.insert(c, {"kind": "rate"}),
            "negotiation after the commit step": lambda p: p.insert(c + 1, p.pop(n)),
            "a second commit step before funding": lambda p: p.insert(c + 1, copy.deepcopy(COMMIT_STEP)),
        }
        for kind in sorted(verifier.NEGOTIATION_KINDS):
            cases[f"a second negotiation {kind}"] = lambda p, kind=kind: p.append({"kind": kind})
        for kind in sorted(verifier.DACS3_COMMITMENT_KINDS):
            cases[f"commitment kind {kind} beside the commit step"] = lambda p, kind=kind: p.append({"kind": kind})
            cases[f"commitment kind {kind} as the negotiation's successor"] = (
                lambda p, kind=kind: p.insert(c, {"kind": kind})
            )
        for kind in sorted(verifier.COMPLETE_SEALED_NEGOTIATION_KINDS):
            cases[f"complete sealed negotiation {kind}"] = lambda p, kind=kind: p.__setitem__(n, {"kind": kind})
        for label, edit in cases.items():
            with self.subTest(case=label):
                self.assertEqual(finding(with_pipeline(edit)), ("fail", "DRP-18"))

    def test_other_negotiation_kinds_before_the_commit_step_are_not_drp18_findings(self):
        """PS-2 allows the payee-bound commit after fixed-price, RFQ, and historical sealed phases."""
        for kind in sorted(verifier.NEGOTIATION_KINDS - verifier.COMPLETE_SEALED_NEGOTIATION_KINDS):
            with self.subTest(kind=kind):
                value = with_pipeline(lambda p: p.__setitem__(generator.NEGOTIATION_STEP_INDEX, {"kind": kind}))
                self.assertNotEqual(finding(value)[1], "DRP-18")

    def test_an_unknown_negotiation_kind_stays_an_unsupported_kind(self):
        value = with_pipeline(lambda p: p.__setitem__(generator.NEGOTIATION_STEP_INDEX, {"kind": "negotiate-barter"}))
        self.assertEqual(finding(value), ("error", "DRV-2"))

    def test_a_missing_commit_step_stays_drp14(self):
        value = with_pipeline(lambda p: p.pop(generator.COMMIT_STEP_INDEX))
        self.assertEqual(finding(value), ("fail", "DRP-14"))


class RailReadingAndDeploymentTests(unittest.TestCase):
    """DRF-9 tags and the DRC-22 native reject gate."""

    @classmethod
    def setUpClass(cls):
        cls.vector_pack = json.loads(VECTOR_PACK.read_text(encoding="utf-8"))
        cls.vectors = {item["name"]: item for item in cls.vector_pack["vectors"]}
        cls.deployment_pack = json.loads(DEPLOYMENT_PACK.read_text(encoding="utf-8"))

    def test_drf9_is_exercised_by_negatives_and_proof_blocked(self):
        for name, expected in (
            ("drp-5-job-rail", ("fail", "DRP-5")),
            ("rail-definition-reference-mismatch", ("fail", "DRP-5")),
            ("rail-resolution-unavailable", ("indeterminate", "DRC-11")),
        ):
            with self.subTest(vector=name):
                vector = self.vectors[name]
                self.assertIn("DRF-9", vector["rules"])
                self.assertEqual((vector["expected"], vector["expectedRule"]), expected)
                self.assertEqual(finding(materialize_vector(self.vector_pack, vector)), expected)
        self.assertIn("DRF-9", self.vector_pack["promotionBlockedProofs"])
        self.assertFalse(any(
            "DRF-9" in vector["rules"] for vector in self.vector_pack["vectors"] if vector["expected"] == "pass"
        ))

    def test_drc22_is_a_capability_profile_rule(self):
        self.assertIn("DRC-22", DRC_RULES)
        text = SPEC.read_text(encoding="utf-8")
        self.assertIn("`capabilityProfile` `dacs-delivery-gate-v1` means DRC-1 through DRC-13, DRC-22, and DREB-24", text)
        control = self.deployment_pack["manifests"]["synthetic-control"]
        self.assertIs(control["capabilities"]["rejectBindsExpectedPriorStatus"], True)
        self.assertEqual(deployment_rule_statuses(control)["DRC-22"], "pass")
        self.assertEqual(evaluate_deployment(control)["rule"], "DRC-1..DRC-13, DRC-22, DREB-24")

    def test_drc22_statuses(self):
        control = self.deployment_pack["manifests"]["synthetic-control"]
        for value, status, outcome in (
            (False, "fail", ("fail", "DRC-22")),
            (None, "unknown", ("indeterminate", "DRC-22")),
            ("true", "fail", ("fail", "DRC-22")),
            (1, "fail", ("fail", "DRC-22")),
        ):
            with self.subTest(value=value):
                manifest = copy.deepcopy(control)
                manifest["capabilities"]["rejectBindsExpectedPriorStatus"] = value
                self.assertEqual(deployment_rule_statuses(manifest)["DRC-22"], status)
                observed = evaluate_deployment(manifest)
                self.assertEqual((observed["result"], observed["rule"]), outcome)
                self.assertFalse(observed["registrationEligible"])
        manifest = copy.deepcopy(control)
        del manifest["capabilities"]["rejectBindsExpectedPriorStatus"]
        self.assertEqual(deployment_rule_statuses(manifest)["DRC-22"], "unknown")

    def test_drc22_deployment_case_and_pinned_reference(self):
        cases = {case["name"]: case for case in self.deployment_pack["cases"]}
        case = cases["drc-22-reject-without-expected-status"]
        manifest = copy.deepcopy(self.deployment_pack["manifests"][case["base"]])
        for operation in case["patch"]:
            manifest = apply_operation(manifest, operation)
        observed = evaluate_deployment(manifest)
        self.assertEqual((observed["result"], observed["rule"]), ("fail", "DRC-22"))
        self.assertEqual(case["expectedFailedRules"], ["DRC-22"])
        # §8.4: the pinned reference's reject is gated only on Funded or
        # Submitted (ERC8183.sol lines 806-831).
        reference = self.deployment_pack["manifests"]["current-reference-142e669"]
        self.assertIs(reference["capabilities"]["rejectBindsExpectedPriorStatus"], False)
        self.assertEqual(deployment_rule_statuses(reference)["DRC-22"], "fail")
        self.assertIn("DRC-22", cases["current-reference-142e669-ineligible"]["expectedFailedRules"])

    def test_a_capability_pass_needs_every_rule_drc14_names(self):
        """DRC-14 defines `dacs-delivery-gate-v1`; the evaluator's rule set is that definition."""
        text = SPEC.read_text(encoding="utf-8")
        meaning = re.search(r"`capabilityProfile` `dacs-delivery-gate-v1` means ([^.]+)\.", text).group(1)
        named: set[str] = set()
        for part in re.split(r",\s*(?:and\s+)?|\s+and\s+", meaning):
            span = re.fullmatch(r"(DR[A-Z]+)-(\d+) through (DR[A-Z]+)-(\d+)", part)
            if span is None:
                named.add(part)
            else:
                self.assertEqual(span.group(1), span.group(3))
                named.update(f"{span.group(1)}-{n}" for n in range(int(span.group(2)), int(span.group(4)) + 1))
        self.assertEqual(named, DEPLOYMENT_RULES)
        self.assertIn("DREB-24", named)
        control = self.deployment_pack["manifests"]["synthetic-control"]
        self.assertEqual(set(deployment_rule_statuses(control)), named)
        # A status set that leaves out one named rule is refused, never passed.
        partial = {rule: "pass" for rule in DRC_RULES}
        with unittest.mock.patch.object(verifier, "deployment_rule_statuses", return_value=partial):
            observed = evaluate_deployment(control)
        self.assertEqual((observed["result"], observed["rule"]), ("error", "DRV-3"))
        self.assertFalse(observed["registrationEligible"])

    def test_dreb24_statuses(self):
        """DREB-24: no trusted forwarder or *WithAuthorization entrypoint, shown by DRC-10 evidence."""
        control = self.deployment_pack["manifests"]["synthetic-control"]
        self.assertEqual(deployment_rule_statuses(control)["DREB-24"], "pass")

        def put_capability(name, value):
            return lambda manifest: manifest["capabilities"].__setitem__(name, value)

        def put_evidence(name, value):
            return lambda manifest: manifest["evidence"].__setitem__(name, value)

        def both(*edits):
            return lambda manifest: [edit(manifest) for edit in edits]

        for label, edit, status, outcome in (
            ("trusted forwarder", put_capability("trustedForwarders", ["0x" + "f0" * 20]), "fail", ("fail", "DREB-24")),
            ("authorization entrypoint", put_capability("authorizationEntrypoints", ["fundWithAuthorization"]), "fail", ("fail", "DREB-24")),
            # A known path fails even where the DRC-10 evidence is missing.
            ("forwarder without DRC-10 evidence", both(
                put_capability("trustedForwarders", ["0x" + "f0" * 20]),
                put_evidence("sourceToBytecodeReproducible", None),
            ), "fail", ("fail", "DREB-24")),
            ("absence not shown", put_evidence("authorizationPathsFromSource", None), "unknown", ("indeterminate", "DREB-24")),
            ("absence denied", put_evidence("authorizationPathsFromSource", False), "fail", ("fail", "DREB-24")),
            ("absence as text", put_evidence("authorizationPathsFromSource", "true"), "fail", ("fail", "DREB-24")),
            ("forwarders unresolved", put_capability("trustedForwarders", None), "unknown", ("indeterminate", "DREB-24")),
            ("forwarders not a list", put_capability("trustedForwarders", "none"), "fail", ("fail", "DREB-24")),
            ("entrypoints not a list", put_capability("authorizationEntrypoints", {}), "fail", ("fail", "DREB-24")),
            # Without passing DRC-10 source and bytecode evidence, the absence
            # is not shown, whatever the manifest asserts.
            ("DRC-10 unresolved", put_evidence("sourceToBytecodeReproducible", None), "unknown", ("indeterminate", "DRC-10")),
            ("DRC-10 failed", put_evidence("independentlyResolvedRuntimeBytecodeHash", "ab" * 32), "unknown", ("fail", "DRC-10")),
        ):
            with self.subTest(case=label):
                manifest = copy.deepcopy(control)
                edit(manifest)
                self.assertEqual(deployment_rule_statuses(manifest)["DREB-24"], status)
                observed = evaluate_deployment(manifest)
                self.assertEqual((observed["result"], observed["rule"]), outcome)
                self.assertFalse(observed["registrationEligible"])
        manifest = copy.deepcopy(control)
        del manifest["capabilities"]["authorizationEntrypoints"]
        self.assertEqual(deployment_rule_statuses(manifest)["DREB-24"], "unknown")

    def test_dreb24_deployment_cases_and_pinned_reference(self):
        cases = {case["name"]: case for case in self.deployment_pack["cases"]}

        def observe(name):
            case = cases[name]
            manifest = copy.deepcopy(self.deployment_pack["manifests"][case["base"]])
            for operation in case["patch"]:
                manifest = apply_operation(manifest, operation)
            return manifest, evaluate_deployment(manifest)

        for name, outcome in (
            ("dreb-24-trusted-forwarder", ("fail", "DREB-24")),
            ("dreb-24-authorization-entrypoint", ("fail", "DREB-24")),
            ("dreb-24-absence-not-shown", ("indeterminate", "DREB-24")),
        ):
            with self.subTest(case=name):
                _manifest, observed = observe(name)
                self.assertEqual((observed["result"], observed["rule"]), outcome)
                self.assertIn("DREB-24", cases[name]["rules"])
        # The pinned reference declares no forwarder or authorization
        # entrypoint, but nothing shows that of a deployment.
        reference = self.deployment_pack["manifests"]["current-reference-142e669"]
        self.assertEqual(reference["capabilities"]["trustedForwarders"], [])
        self.assertEqual(reference["capabilities"]["authorizationEntrypoints"], [])
        self.assertEqual(deployment_rule_statuses(reference)["DREB-24"], "unknown")
        self.assertIn("DREB-24", cases["current-reference-142e669-ineligible"]["expectedUnknownRules"])
        # Its ERC8183WithAuthorization.sol extension (lines 100, 205, 233,
        # 251, 270) adds signature-authorized entrypoints for five profile actions.
        manifest, observed = observe("dreb-24-reference-authorization-extension")
        self.assertEqual(manifest["implementation"]["sourcePath"], "contracts/ERC8183WithAuthorization.sol")
        self.assertEqual(
            {name.removesuffix("WithAuthorization") for name in manifest["capabilities"]["authorizationEntrypoints"]},
            {"createJob", "fund", "submit", "complete", "reject"},
        )
        self.assertEqual(observed["ruleStatuses"]["DREB-24"], "fail")
        self.assertEqual(observed["result"], "fail")
        self.assertIn("DREB-24", cases["dreb-24-reference-authorization-extension"]["expectedFailedRules"])
        self.assertIn(
            "contracts/ERC8183WithAuthorization.sol",
            self.deployment_pack["sourcePins"]["referenceAuthorizationExtension"],
        )
        # The lifecycle pack no longer ledgers DREB-24 as unexecuted.
        self.assertNotIn("DREB-24", self.vector_pack["promotionBlockedRules"])

    def test_erc20_decimals_bound_is_pinned(self):
        self.assertEqual(verifier.MAX_TOKEN_DECIMALS, 2 ** 8 - 1)
        self.assertEqual(
            verifier.EXTERNAL_SOURCE_PINS["erc20"],
            "https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-20.md",
        )
        self.assertEqual(self.vector_pack["sourcePins"]["external"]["erc20"], verifier.EXTERNAL_SOURCE_PINS["erc20"])

    def test_a_reject_executed_against_another_prior_status_is_tagged_drc22(self):
        vector = self.vectors["reject-without-expected-status"]
        self.assertEqual(vector["rules"], ["DRC-22", "DRD-13"])
        self.assertEqual(finding(materialize_vector(self.vector_pack, vector)), ("fail", "DRD-13"))
        # The fixture implementation pins the expected prior status in reject.
        self.assertIn(("expectedStatus", "uint8"), verifier.FIXTURE_ENTRYPOINTS["reject"])


def _tx_hashes(value, kind=None):
    """Every `txHash` string in ``value``; with ``kind``, only in objects of that kind."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if isinstance(item.get("txHash"), str) and (kind is None or item.get("kind") == kind):
                yield item["txHash"]
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


class TransactionHashSpellingTests(unittest.TestCase):
    """DRW-3: an EVM `txHash` is its DACS-4 SB-1 canonical spelling, 64 lower-case hex digits without `0x`."""

    @classmethod
    def setUpClass(cls):
        cls.vector_pack = json.loads(VECTOR_PACK.read_text(encoding="utf-8"))
        cls.vectors = {item["name"]: item for item in cls.vector_pack["vectors"]}

    def test_the_spelling_is_the_pinned_sb1_sentence(self):
        text = " ".join(SETTLE.read_text(encoding="utf-8").split())
        self.assertIn(
            "EVM hashes are rendered as exactly 64 lower-case hexadecimal digits without `0x`; a verified legacy "
            "spelling with `0x` or upper-case characters collapses to that form. A current producer MUST emit the "
            "canonical spelling.",
            text,
        )
        canonical = "ab" * 32
        self.assertIsNotNone(verifier.EVM_TX_RE.fullmatch(canonical))
        for spelling in ("0x" + canonical, canonical.upper(), "0x" + canonical.upper(), canonical[2:], canonical + "ab"):
            with self.subTest(spelling=spelling):
                self.assertIsNone(verifier.EVM_TX_RE.fullmatch(spelling))
        # The repository's canonical security vectors spell every evm-event
        # reference the same way.
        security = [
            tx_hash
            for path in sorted(SECURITY_VECTORS.glob("*.json"))
            for tx_hash in _tx_hashes(json.loads(path.read_text(encoding="utf-8")), "evm-event")
        ]
        self.assertTrue(security)
        self.assertTrue(all(verifier.EVM_TX_RE.fullmatch(tx_hash) for tx_hash in security))

    def test_every_pack_transaction_hash_is_canonical(self):
        # Only the two DRW-3 negatives' own fixtures spell one otherwise.
        legacy = {"event-reference-tx-hash-0x-prefixed", "event-reference-tx-hash-upper-case"}
        self.assertLessEqual(legacy, set(self.vector_pack["fixtures"]))
        hashes = [
            tx_hash
            for name, fixture in self.vector_pack["fixtures"].items()
            if name not in legacy
            for tx_hash in _tx_hashes(fixture)
        ]
        self.assertGreater(len(hashes), 100)
        self.assertEqual([tx_hash for tx_hash in hashes if verifier.EVM_TX_RE.fullmatch(tx_hash) is None], [])
        # A fixture-chain block hash is not a DACS field and keeps its `0x`.
        release = make_base("release")
        observation = release["reproductionInputs"]["nativeEventInputs"][0]
        self.assertIsNotNone(verifier.FIXTURE_BLOCK_HASH_RE.fullmatch(observation["blockHash"]))

    def test_every_transaction_hash_site_refuses_the_legacy_spelling(self):
        release = make_base("release")
        ref = release["artifacts"]["terminal"]["terminalEventRefs"][0]
        transaction = release["resolverEvidence"]["transactions"][-1]
        prior = {
            "chainId": ref["chainId"],
            "contractAddress": release["artifacts"]["job"]["contractAddress"],
            "nativeJobId": "2",
            "txHash": ref["txHash"],
            "logIndex": ref["logIndex"],
            "decisionHash": None,
        }
        self.assertIsNone(verifier._event_ref_check(ref, ref["chainId"], "DRT-4", "terminal"))
        self.assertTrue(verifier._transaction_valid(transaction))
        self.assertTrue(verifier._prior_terminal_valid(prior))
        for spelling in ("0x" + ref["txHash"], ref["txHash"].upper()):
            with self.subTest(spelling=spelling):
                observed = verifier._event_ref_check(dict(ref, txHash=spelling), ref["chainId"], "DRT-4", "terminal")
                self.assertEqual((observed["result"], observed["rule"]), ("error", "DRW-3"))
                self.assertFalse(verifier._transaction_valid(dict(transaction, txHash=spelling)))
                self.assertFalse(verifier._prior_terminal_valid(dict(prior, txHash=spelling)))

    def test_the_legacy_spelling_vectors(self):
        for name, outcome, rules in (
            ("event-reference-tx-hash-0x-prefixed", ("error", "DRW-3"), ["DRW-3"]),
            ("event-reference-tx-hash-upper-case", ("error", "DRW-3"), ["DRW-3"]),
            ("resolver-transaction-tx-hash-0x-prefixed", ("error", "DRV-3"), ["DRV-3", "DRW-3"]),
            ("resolver-history-tx-hash-0x-prefixed", ("error", "DRV-3"), ["DRV-3", "DRW-3"]),
        ):
            with self.subTest(vector=name):
                vector = self.vectors[name]
                self.assertEqual((vector["expected"], vector["expectedRule"]), outcome)
                self.assertEqual(vector["rules"], rules)
                self.assertEqual(finding(materialize_vector(self.vector_pack, vector)), outcome)
        # The canonical spelling of the same release passes.
        self.assertEqual(finding(make_base("release")), ("pass", "DRV-7"))


if __name__ == "__main__":
    unittest.main()
