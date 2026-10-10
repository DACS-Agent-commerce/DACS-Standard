import copy
import hashlib
import itertools
import json
import random
import re
import subprocess
import sys
import unittest
from pathlib import Path

from scripts.jcs import canonicalize as jcs_canonicalize
from scripts import generate_delivery_remedy_candidate_vectors as generator
from scripts import verify_delivery_remedy_candidate_vectors as verifier
from scripts.generate_delivery_remedy_candidate_vectors import drop, make_base, put
from scripts.generate_delivery_remedy_candidate_vectors import each as each_hook
from scripts.verify_delivery_remedy_candidate_vectors import (
    DRC_RULES,
    NATIVE_STATE_FIELDS,
    PINNED_RESOLVER_KEYS,
    DecisionLedger,
    TerminalRecord,
    apply_operation,
    artifact_hash,
    canonical_bytes,
    content_hash,
    deployment_rule_statuses,
    evaluate_deployment,
    evaluate_lifecycles,
    evaluate_protocol,
    materialize_vector,
    verify_deployment_pack,
    verify_vector_pack,
)


ROOT = Path(__file__).resolve().parents[1]
VECTOR_PACK = ROOT / "conformance/fixtures/delivery-remedy/candidate-vectors-v0.1.json"
DEPLOYMENT_PACK = ROOT / "conformance/fixtures/delivery-remedy/deployment-capabilities-v0.1.json"
GENERATOR = ROOT / "scripts/generate_delivery_remedy_candidate_vectors.py"
VERIFIER = ROOT / "scripts/verify_delivery_remedy_candidate_vectors.py"
SPEC = ROOT / "docs/delivery-or-remedy-candidate.md"
SETTLE_SPEC = ROOT / "spec/DACS-4-SETTLE.md"


def evaluate(value):
    """Evaluate one independent lifecycle with its own verifier ledger."""
    return evaluate_protocol(value, DecisionLedger())


def finding(value):
    observed = evaluate(value)
    return observed["result"], observed["rule"]


def verdict(observed):
    return observed["result"], observed["rule"]


# A replay revision never moves a verdict to an earlier entry.
REPLAY_VERDICT_RANK = {"verified": 0, "indeterminate": 1, "rejected": 2}


def _signed_by_resolver(edit):
    """Apply ``edit`` to a release fixture and have the pinned resolver sign the result."""
    def build(pack):
        value = copy.deepcopy(pack["fixtures"]["release"])
        edit(value)
        generator.resign_resolver(value)
        return value
    return build


def _release(edit):
    def build(pack):
        value = copy.deepcopy(pack["fixtures"]["release"])
        edit(value)
        return value
    return build


def _hooked(**hooks):
    return lambda _pack: make_base("release", hooks=hooks)


def _without_reproduction_inputs(value):
    value["reproductionInputs"] = []
    value["resolverEvidence"]["eventObservationsHash"] = content_hash(None)
    generator.resign_resolver(value, bind=False)


# Shape guards that no lifecycle vector decides.  Each case reaches exactly
# one guard and pins its full finding, so removing that guard changes the
# outcome of the case.
GUARD_CASES = {
    "input-not-an-object": (lambda _pack: [], ("error", "DRV-2", "vector input must be an object")),
    "input-missing-field": (_release(drop("native")), ("error", "DRV-2", "vector input is missing required fields")),
    "object-field-malformed": (_release(put("native", [])), ("error", "DRV-2", "candidate object fields are malformed")),
    "artifact-missing": (_release(drop("artifacts", "job")), ("error", "DRV-2", "required candidate artifacts are missing")),
    "artifact-not-object": (_release(put("artifacts", "railDefinition", [])), ("error", "DRV-2", "candidate artifacts must be objects")),
    "overlay-version": (_release(put("artifacts", "agreement", "deliveryOrRemedyAgreementVersion", "2")), ("error", "DRV-2", "unsupported agreement overlay version")),
    "pipeline-not-array": (_release(put("pipeline", {})), ("error", "DRV-2", "pipeline must be a non-empty array")),
    "pipeline-step-without-kind": (_release(put("pipeline", 4, {"name": "rate"})), ("error", "DRV-2", "every pipeline step must have a kind")),
    "escrow-parameters-not-object": (_release(put("pipeline", 1, "parameters", [])), ("error", "DRV-2", "job-escrow parameters must be an object")),
    "execution-context-not-object": (_release(put("executionContext", [])), ("error", "DRV-2", "executionContext must be an object")),
    "role-binding-not-object": (_release(put("artifacts", "agreement", "buyer", "buyer")), ("error", "DRV-2", "agreement role bindings must be objects")),
    "primary-claim-not-text": (_release(put("artifacts", "agreement", "buyer", "primaryClaim", 7)), ("error", "DRV-2", "agreement primary claims must be strings")),
    "orchestrator-claim-missing": (_release(put("orchestratorClaim", None)), ("error", "DRV-2", "orchestratorClaim is required")),
    "resolver-shape": (_release(drop("resolverEvidence", "statuses")), ("error", "DRV-2", "resolver evidence shape is not exact")),
    "resolver-version": (_release(put("resolverEvidence", "resolverEvidenceVersion", "2")), ("error", "DRV-2", "unsupported resolver evidence version")),
    "resolver-call-record-shape": (_signed_by_resolver(drop("resolverEvidence", "terminalCall", "outerSubmitter")), ("error", "DRV-2", "resolver terminal call record is malformed")),
    "resolver-history-shape": (_signed_by_resolver(put("resolverEvidence", "priorTerminals", ["earlier"])), ("error", "DRV-2", "resolver terminal history is malformed")),
    "resolver-native-state-shape": (_signed_by_resolver(drop("resolverEvidence", "nativeState", "evaluatorAdapter")), ("error", "DRV-2", "resolver native state is malformed")),
    "resolver-digest-anchor-shape": (_signed_by_resolver(put("resolverEvidence", "deliveryDigestAnchor", "blockNumber", "20000040")), ("error", "DRV-2", "resolver delivery-digest anchor is malformed")),
    "resolver-status-set": (_signed_by_resolver(drop("resolverEvidence", "statuses", "railResolution")), ("error", "DRV-2", "resolver status set is incomplete")),
    "resolver-status-value": (_signed_by_resolver(put("resolverEvidence", "statuses", "railResolution", "pending")), ("error", "DRV-2", "unknown resolver status")),
    "finding-not-object": (_hooked(evaluation=put("finding", "seller-fulfilled")), ("error", "DRV-2", "evaluation finding must be an object")),
    "canonical-record-set": (_release(drop("canonicalRecords", "delivery")), ("error", "DRV-2", "canonical record set does not match the lifecycle")),
    "canonical-record-not-object": (_release(put("canonicalRecords", "delivery", [])), ("error", "DRV-2", "delivery canonical record must be an object")),
    "reproduction-inputs-not-object": (_release(_without_reproduction_inputs), ("error", "DRV-2", "reproductionInputs must be an object")),
    "reproduction-input-set": (_release(drop("reproductionInputs", "evaluationRule")), ("error", "DRV-2", "reproduction input set is incomplete")),
    "observations-empty": (_signed_by_resolver(put("reproductionInputs", "nativeEventInputs", [])), ("error", "DRV-2", "native event inputs must be a non-empty array")),
    "observation-shape": (_signed_by_resolver(drop("reproductionInputs", "nativeEventInputs", 0, "confirmations")), ("error", "DRV-2", "native event input is malformed")),
    "observation-field-type": (_signed_by_resolver(put("reproductionInputs", "nativeEventInputs", 0, "blockNumber", "19999900")), ("error", "DRV-2", "native event observation is malformed")),
    "submission-reference-malformed": (_release(put("deliveryBinding", "nativeSubmissionEvent", "submit")), ("error", "DRV-2", "submission event reference is malformed")),
    "submission-reference-not-canonical": (_release(put("deliveryBinding", "nativeSubmissionEvent", "chainId", 10)), ("rejected", "DRP-9", "submission event identity is not canonical")),
    "rail-finality-depth": (_hooked(rail=put("profileParameters", "finalityBlocks", 0)), ("error", "DRV-2", "rail finality depth must be a positive integer")),
    "signed-cutoff-type": (_hooked(agreement=put("submissionCutoffSec", "1800000000")), ("error", "DRV-2", "signed cutoff and deadline must be integers")),
    "seed-set": (_release(drop("reproductionInputs", "publicTestSeedHex", generator.ORCHESTRATOR)), ("error", "DRV-2", "public test seed set is incomplete")),
    "seed-malformed": (_release(put("reproductionInputs", "publicTestSeedHex", generator.BUYER, "zz")), ("error", "DRV-2", "public test seed is malformed")),
    "role-inputs-not-objects": (_release(put("reproductionInputs", "roleBundles", [])), ("error", "DRV-2", "role source inputs must be objects")),
    "runtime-encoding": (_release(put("reproductionInputs", "runtimeBytecode", "encoding", "latin-1")), ("error", "DRV-2", "runtime-bytecode preimage is malformed")),
    "runtime-value-type": (_release(put("reproductionInputs", "runtimeBytecode", "value", 7)), ("error", "DRV-2", "runtime-bytecode preimage must be text")),
    "funding-finality-record-type": (_hooked(funding=put("finality", "finalityBlocks", "64")), ("error", "DRV-2", "funding finality record is malformed")),
    "portable-history-empty": (_release(put("native", "portableStateHistory", [])), ("error", "DRV-2", "portable state history must be a non-empty array")),
    "mapping-source-set": (_release(drop("mappingSources", "deliveryHash")), ("error", "DRV-2", "mapping source set does not match the lifecycle")),
    "rail-profile-shape": (_hooked(rail=put("profileParameters", "hookMode", "absent")), ("error", "DRV-2", "candidate rail profile shape is not exact")),
    "evaluation-window-type": (_hooked(rail=put("profileParameters", "minimumEvaluationWindowSec", "3600")), ("error", "DREB-14", "minimum evaluation window must be an integer")),
    "reputation-projection-shape": (_release(put("reputationProjection", {})), ("error", "DRV-2", "reputation projection is malformed")),
}


class DeliveryRemedyCandidateVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vector_pack = json.loads(VECTOR_PACK.read_text(encoding="utf-8"))
        cls.deployment_pack = json.loads(DEPLOYMENT_PACK.read_text(encoding="utf-8"))
        cls.vectors = {item["name"]: item for item in cls.vector_pack["vectors"]}
        cls.deployment_cases = {
            item["name"]: item for item in cls.deployment_pack["cases"]
        }

    def _vector(self, name):
        return materialize_vector(self.vector_pack, self.vectors[name])

    def _fixture(self, name):
        return copy.deepcopy(self.vector_pack["fixtures"][name])

    def _observation(self, value, event_name):
        return next(
            item
            for item in value["reproductionInputs"]["nativeEventInputs"]
            if item["eventName"] == event_name
        )

    def _retime(self, value, event_name, timestamp_sec):
        item = self._observation(value, event_name)
        item["blockTimestampSec"] = timestamp_sec
        item["blockHashPreimageUtf8"] = (
            f"{item['txHashPreimageUtf8']}:block:{item['blockNumber']}:{timestamp_sec}"
        )
        item["blockHash"] = "0x" + hashlib.sha256(
            item["blockHashPreimageUtf8"].encode("ascii")
        ).hexdigest()

    def _assert_isolated(self, value, agreement=True):
        """The negative keeps every party and resolver signature valid."""
        self.assertIsNone(verifier._component_signature_check(value))
        if agreement:
            self.assertIsNone(verifier._agreement_check(value))
        else:
            overlay = value["artifacts"]["agreement"]
            for signature in overlay["signatures"]:
                self.assertTrue(verifier.signature_valid(
                    overlay, signature, signature["party"], value["publicKeys"],
                    verifier.DOMAINS["agreement"], "party",
                ))
        self.assertIsNone(verifier._resolver_evidence_check(value))

    def test_generated_files_are_current(self):
        result = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_standalone_verifier_accepts_both_packs(self):
        result = subprocess.run(
            [sys.executable, str(VERIFIER)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("no rail registered", result.stdout)

    def test_pack_metadata_hashes_and_names_are_exact(self):
        for pack, fields in (
            (
                self.vector_pack,
                ("fixtures", "vectors", "promotionBlockedRules", "promotionBlockedProofs"),
            ),
            (self.deployment_pack, ("manifests", "cases")),
        ):
            with self.subTest(kind=pack["kind"]):
                items = pack[fields[1]]
                self.assertEqual(pack["count"], len(items))
                self.assertEqual(len(items), len({item["name"] for item in items}))
                payload = {field: pack[field] for field in fields}
                self.assertEqual(
                    pack["hash"], hashlib.sha256(canonical_bytes(payload)).hexdigest()
                )

    def test_every_candidate_rule_is_tagged_or_explicitly_promotion_blocked(self):
        spec_rules = set(
            re.findall(
                r"\b(?:DRP|DRA|DRL|DRJ|DRF|DRAA|DREB|DRE|DRD|DRT|DRV|DRQ|DRX|DRC)-\d+\b",
                SPEC.read_text(encoding="utf-8"),
            )
        )
        tagged = {
            rule
            for vector in self.vector_pack["vectors"]
            for rule in vector["rules"]
        }
        tagged.update(
            rule
            for case in self.deployment_pack["cases"]
            for rule in case["rules"]
        )
        blocked = set(self.vector_pack["promotionBlockedRules"])
        self.assertFalse(tagged & blocked)
        self.assertEqual(spec_rules, tagged | blocked)
        self.assertTrue(
            all(self.vector_pack["promotionBlockedRules"][rule] for rule in blocked)
        )
        # A proof-blocked rule is executed against a synthetic evidence shape.
        proofs = self.vector_pack["promotionBlockedProofs"]
        self.assertEqual(set(proofs), {"DRE-2", "DRP-7", "DRP-9"})
        self.assertLessEqual(set(proofs), tagged)
        self.assertTrue(all(proofs.values()))

    def test_no_finding_reports_a_promotion_blocked_rule(self):
        blocked = set(self.vector_pack["promotionBlockedRules"])
        for vector in self.vector_pack["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertNotIn(vector["expectedRule"], blocked)
        for name, (build, (_result, rule, _detail)) in GUARD_CASES.items():
            with self.subTest(case=name):
                self.assertNotIn(rule, blocked)
        # DRAA-4's write-once rule is not what an overlay-hash binding checks.
        for name, rule in (("drv-4-job-overlay-hash", "DRV-4"), ("drf-1-funding-overlay-hash", "DRF-1")):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), ("rejected", rule))

    def test_every_lifecycle_vector_executes_to_its_pinned_result_and_rule(self):
        self.assertEqual(verify_vector_pack(self.vector_pack), [])
        for vector in self.vector_pack["vectors"]:
            with self.subTest(vector=vector["name"]):
                members = [*vector.get("evaluatedWith", []), vector["name"]]
                observed = evaluate_lifecycles(
                    [self._vector(name) for name in members], DecisionLedger()
                )[-1]
                self.assertEqual(observed["result"], vector["expected"])
                self.assertEqual(observed["rule"], vector["expectedRule"])

    def test_every_negative_fails_only_at_its_intended_guard(self):
        self.assertEqual(generator.negative_isolation_problems(self.vector_pack), [])
        self.assertLessEqual(set(generator.FOLLOW_ON_FINDINGS), set(self.vectors))
        self.assertLessEqual(set(generator.STRUCTURAL_NEGATIVES), set(self.vectors))
        self.assertFalse(set(generator.FOLLOW_ON_FINDINGS) & set(generator.STRUCTURAL_NEGATIVES))
        for name, (result_, rule) in generator.FOLLOW_ON_FINDINGS.items():
            with self.subTest(vector=name):
                self.assertNotEqual(
                    (result_, rule),
                    (self.vectors[name]["expected"], self.vectors[name]["expectedRule"]),
                )

    def test_isolation_audit_counts_a_crash_as_a_failure(self):
        # An exception after the deciding guard is removed is not isolation.
        structural = dict(generator.STRUCTURAL_NEGATIVES)
        name = "pipeline-missing-terminal"
        pack = copy.deepcopy(self.vector_pack)
        pack["vectors"] = [self.vectors[name]]
        try:
            del generator.STRUCTURAL_NEGATIVES[name]
            problems = generator.negative_isolation_problems(pack)
        finally:
            generator.STRUCTURAL_NEGATIVES.clear()
            generator.STRUCTURAL_NEGATIVES.update(structural)
        self.assertEqual(len(problems), 1)
        self.assertIn("the verifier raises", problems[0])
        # A listed structural negative that stops raising is reported too.
        pack["vectors"] = [self.vectors["evaluator-vet-failure"]]
        generator.STRUCTURAL_NEGATIVES["evaluator-vet-failure"] = "control"
        try:
            problems = generator.negative_isolation_problems(pack)
        finally:
            del generator.STRUCTURAL_NEGATIVES["evaluator-vet-failure"]
        self.assertEqual(len(problems), 1)
        self.assertIn("structural negative reports verified", problems[0])

    def test_guard_cases_report_their_exact_finding(self):
        for name, (build, expected) in GUARD_CASES.items():
            with self.subTest(case=name):
                observed = evaluate(build(self.vector_pack))
                self.assertEqual(
                    (observed["result"], observed["rule"], observed["detail"]), expected
                )

    def test_every_verifier_guard_is_killed_by_a_vector_or_a_guard_case(self):
        guarded = generator.GuardedVerifier()
        killed = set()
        for vector in self.vector_pack["vectors"]:
            if vector["expected"] == "verified":
                continue
            value = guarded.module.materialize_vector(self.vector_pack, vector)
            priors = [self._vector(prior) for prior in vector.get("evaluatedWith", [])]
            _outcome, fired = guarded.run(value, priors)
            mutant, _others = guarded.run(value, priors, disabled=fired[-1])
            if (mutant["result"], mutant["rule"]) != (vector["expected"], vector["expectedRule"]):
                killed.add(fired[-1])
        for name, (build, expected) in GUARD_CASES.items():
            value = build(self.vector_pack)
            _outcome, fired = guarded.run(value)
            mutant, _others = guarded.run(value, disabled=fired[-1])
            if (mutant["result"], mutant["rule"], mutant.get("detail")) != expected:
                killed.add(fired[-1])
        self.assertEqual(
            [site for index, site in enumerate(guarded.sites) if index not in killed], []
        )

    def test_positive_mapping_is_byte_exact_not_text_rehashed(self):
        release = self._vector("release-complete-budget")
        artifacts = release["artifacts"]
        created = self._observation(release, "JobCreated")["arguments"]
        self.assertEqual(
            created["description"],
            "dacs-delivery-remedy:v1:" + artifact_hash(artifacts["agreement"]),
        )
        self.assertEqual(
            release["native"]["deliverable"],
            "0x" + artifact_hash(artifacts["delivery"]),
        )
        self.assertEqual(
            release["native"]["reason"],
            "0x" + artifact_hash(artifacts["decision"]),
        )
        self.assertEqual(
            bytes.fromhex(release["canonicalRecords"]["delivery"]["canonicalUtf8Hex"]),
            jcs_canonicalize(
                {key: value for key, value in artifacts["delivery"].items() if key != "signature"}
            ).encode("utf-8"),
        )
        self.assertNotEqual(
            release["native"]["deliverable"][2:],
            hashlib.sha256(artifact_hash(artifacts["delivery"]).encode("ascii")).hexdigest(),
        )

    def test_release_refund_and_expiry_terminal_invariants_are_distinct(self):
        release = self._vector("release-complete-budget")
        rejection = self._vector("evaluator-rejection-refund")
        expiry_pre = self._vector("expiry-before-submission")
        expiry_post = self._vector("expiry-after-submission-grace")
        pre_submission_rejection = self._vector("pre-submission-evaluator-rejection")
        self.assertEqual(release["native"]["terminalAction"], "complete")
        self.assertEqual(rejection["native"]["terminalAction"], "reject")
        self.assertEqual(expiry_pre["native"]["terminalAction"], "claimRefund")
        self.assertNotIn("decision", expiry_pre["artifacts"])
        self.assertNotIn("decisionRef", expiry_pre["artifacts"]["terminal"])
        self.assertNotIn("deliveryEvidenceRef", expiry_pre["artifacts"]["terminal"])
        self.assertNotIn("decision", expiry_post["artifacts"])
        self.assertIn("deliveryEvidenceRef", expiry_post["artifacts"]["terminal"])
        self.assertNotIn("delivery", pre_submission_rejection["artifacts"])
        self.assertIn("dispute", pre_submission_rejection["artifacts"])
        self.assertNotIn(
            "deliveryEvidenceRef", pre_submission_rejection["artifacts"]["decision"]
        )
        self.assertEqual(
            pre_submission_rejection["artifacts"]["decision"]["basisRef"]["kind"],
            "dispute-outcome",
        )

    def test_evaluation_and_release_decisions_require_delivery(self):
        # DRD-3: a release needs delivery evidence; DRD-9: without delivery,
        # only a DisputeOutcome basis can authorize the refund.
        for name, rule in (
            ("release-decision-without-delivery", "DRD-3"),
            ("refund-without-delivery-needs-dispute-basis", "DRD-9"),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self.assertNotIn("delivery", value["artifacts"])
                self.assertNotIn(
                    "JobSubmitted",
                    {item["eventName"] for item in value["reproductionInputs"]["nativeEventInputs"]},
                )
                self._assert_isolated(value)
                self.assertEqual(finding(value), ("rejected", rule))
        # The deliveryless dispute-based refund remains the one verified shape.
        self.assertEqual(
            finding(self._vector("pre-submission-evaluator-rejection")), ("verified", "DRV-7")
        )

    def test_dre_2_delivery_evidence_is_for_the_agreed_phase(self):
        # The delivery record is a DACS-4 §9.7 SettlementEvidence: every
        # member it may carry is a §9.7 member, which has no phase index.
        settlement_type = re.search(
            r"type SettlementEvidence = \{(.*?)\n\}", SETTLE_SPEC.read_text(encoding="utf-8"), re.S
        ).group(1)
        members = set(re.findall(r"^\s*(\w+)\??:", settlement_type, re.M))
        self.assertLessEqual(verifier.DELIVERY_EVIDENCE_FIELDS | {"reason"}, members)
        self.assertNotIn("phaseIndex", members)
        release = self._vector("release-complete-budget")
        delivery = release["artifacts"]["delivery"]
        self.assertEqual(set(delivery), verifier.DELIVERY_EVIDENCE_FIELDS)
        self.assertEqual(
            delivery["deliverableContentHash"],
            content_hash(release["reproductionInputs"]["deliveredArtifact"]),
        )
        for name, outcome in (
            ("dre-2-delivery-phase-kind", ("rejected", "DRE-2")),
            ("drv-2-delivery-evidence-shape", ("error", "DRV-2")),
            ("delivered-artifact-input-mismatch", ("rejected", "DRE-2")),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), outcome)
        for edit in (
            put("outcome", "partial"),
            put("evidenceVersion", "2"),
            put("observedAt", "1799994800000"),
            put("reason", "late"),
            put("phaseIndex", 2),
            put("artifactRef", copy.deepcopy(release["artifacts"]["deliveryRef"])),
            put("deliverableContentHash", "0x" + delivery["deliverableContentHash"]),
            drop("deliverableContentHash"),
            drop("deliverableAnchor"),
            put("deliverableAnchor", {"kind": "storage-program"}),
            put("deliverableAnchor", "locator", ""),
        ):
            with self.subTest(edit=edit):
                self.assertEqual(finding(make_base("release", hooks={"delivery": edit})), ("error", "DRV-2"))
        # The delivery outcome does not choose the disposition; the evaluation
        # under the bound rule does.
        failed = each_hook(put("outcome", "failure"), put("reason", "fixture-output-missing"))
        self.assertEqual(finding(make_base("rejected-refund", hooks={"delivery": failed})), ("verified", "DRV-7"))
        self.assertEqual(
            finding(make_base("rejected-refund", hooks={"delivery": put("outcome", "failure")})),
            ("error", "DRV-2"),
        )
        # §9.7 makes the deliverable members optional: a failure may omit
        # either or both, and then binds no delivered-artifact input.
        for name, outcome in (
            ("dre-2-failed-delivery-without-deliverable", ("verified", "DRV-7")),
            ("dre-2-failed-delivery-carries-artifact-input", ("rejected", "DRE-2")),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), outcome)
        self.assertEqual(
            set(self._vector("dre-2-failed-delivery-without-deliverable")["artifacts"]["delivery"]),
            verifier.DELIVERY_EVIDENCE_FIELDS - verifier.DELIVERABLE_FIELDS | {"reason"},
        )
        for omitted in (["deliverableContentHash"], ["deliverableAnchor"], sorted(verifier.DELIVERABLE_FIELDS)):
            with self.subTest(omitted=omitted):
                hooks = {"delivery": each_hook(failed, *(drop(member) for member in omitted))}
                if "deliverableContentHash" in omitted:
                    hooks["inputs"] = put("deliveredArtifact", None)
                self.assertEqual(finding(make_base("rejected-refund", hooks=hooks)), ("verified", "DRV-7"))
        for edit in (put("deliverableContentHash", "0xab"), put("deliverableAnchor", {"kind": "storage-program"})):
            with self.subTest(failed_edit=edit):
                value = make_base("rejected-refund", hooks={"delivery": each_hook(failed, edit)})
                self.assertEqual(finding(value), ("error", "DRV-2"))

    def test_every_artifact_describes_the_overlay_job(self):
        for name, rule in (
            ("drd-8-evaluation-job-reference", "DRD-8"),
            ("drd-8-decision-job-reference", "DRD-8"),
            ("dra-1-bilateral-job", "DRA-1"),
            ("dra-1-bilateral-parties", "DRA-1"),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value, agreement=not name.startswith("dra-1-"))
                self.assertEqual(finding(value), ("rejected", rule))
        other_job = self._fixture("rejected-refund")["artifacts"]["job"]
        self.assertEqual(
            self._vector("drd-8-evaluation-job-reference")["artifacts"]["evaluation"]["escrowJobRef"]["contentHash"],
            artifact_hash(other_job),
        )

    def test_dre_3_subject_evidence_resolves_to_authenticated_records(self):
        release = self._vector("release-complete-budget")
        self.assertEqual(
            release["artifacts"]["evaluation"]["subjectEvidenceRefs"], [release["artifacts"]["deliveryRef"]]
        )
        for name, outcome in (
            ("dre-5-evaluation-subject-unresolved", ("indeterminate", "DRE-5")),
            ("dre-3-evaluation-subject-contradiction", ("rejected", "DRE-3")),
            ("drv-2-evaluation-subject-refs", ("error", "DRV-2")),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), outcome)
        # The published job and funding records resolve as subjects too.
        def subjects(evaluation):
            evaluation["subjectEvidenceRefs"] = [
                copy.deepcopy(evaluation["escrowJobRef"]), copy.deepcopy(evaluation["deliveryEvidenceRef"]),
            ]
        self.assertEqual(finding(make_base("release", hooks={"evaluation": subjects})), ("verified", "DRV-7"))
        for refs in ([{"kind": "storage-program", "locator": "x"}], ["subject"], {}):
            with self.subTest(refs=refs):
                value = make_base("release", hooks={"evaluation": put("subjectEvidenceRefs", refs)})
                self.assertEqual(finding(value), ("error", "DRV-2"))

    def test_drd_8_drl_4_drt_4_terminal_ledger(self):
        release = self._vector("release-complete-budget")
        ledger = DecisionLedger()
        # DRD-8 forbids authorizing another job or transaction, not verifying
        # the same terminal again.
        for _ in range(3):
            self.assertEqual(evaluate_protocol(copy.deepcopy(release), ledger)["result"], "verified")
        self.assertEqual(len(ledger.terminals()), 1)
        self.assertEqual(
            evaluate_protocol(self._vector("eip1271-relayed-execution"), ledger)["result"],
            "verified",
        )
        # One terminal per decision, per native job, and per terminal event;
        # each of these is later than the release terminal.
        for fixture, rule in (
            ("release-second-terminal-transaction", "DRD-8"),
            ("release-job-rejection", "DRL-4"),
            ("other-job-reuses-release-terminal-event", "DRT-4"),
        ):
            with self.subTest(fixture=fixture):
                alone = self._fixture(fixture)
                self.assertEqual(finding(alone), ("verified", "DRV-7"))
                observed = evaluate_protocol(alone, ledger)
                self.assertEqual((observed["result"], observed["rule"]), ("rejected", rule))
        # The ledger holds each authenticated terminal once, whatever its verdict.
        self.assertEqual(len(ledger.terminals()), 4)
        self.assertEqual(len(set(ledger.terminals())), 4)
        # Evidence that fails an earlier stage records nothing.
        fresh = DecisionLedger()
        self.assertEqual(
            evaluate_protocol(self._vector("relayer-substituted-as-native-caller"), fresh)["result"],
            "rejected",
        )
        self.assertEqual(fresh.terminals(), ())
        recorded = ledger.terminals()[0]
        self.assertEqual(recorded.position, (20000100, 2))
        with self.assertRaises(TypeError):
            evaluate_protocol(release, None)

    def test_conflicting_terminals_are_ordered_by_authenticated_position(self):
        release = self._fixture("release")
        # Conflicting terminals whose resolver-attested history names the release.
        def naming_release(name):
            value = self._fixture(name)
            value["resolverEvidence"]["priorTerminals"] = [{
                "chainId": release["artifacts"]["job"]["chainId"],
                "contractAddress": release["artifacts"]["job"]["contractAddress"],
                "nativeJobId": release["artifacts"]["job"]["nativeJobId"],
                "txHash": release["artifacts"]["terminal"]["terminalEventRefs"][0]["txHash"],
                "logIndex": release["artifacts"]["terminal"]["terminalEventRefs"][0]["logIndex"],
                "decisionHash": artifact_hash(release["artifacts"]["decision"]),
            }]
            generator.resign_resolver(value)
            self.assertEqual(finding(value), ("rejected", "DRD-8"))
            return value
        attested_later = naming_release("release-second-terminal-transaction")
        # A history cannot order terminals that share an event position.
        attested_same_position = naming_release("release-same-position-terminal-transaction")
        # (other lifecycle, verdict of the release, verdict of the other)
        # when the two are evaluated together.
        pairs = (
            ("history-names-earlier", attested_later, ("verified", "DRV-7"), ("rejected", "DRD-8")),
            ("later-decision-reuse", self._fixture("release-second-terminal-transaction"), ("indeterminate", "DRD-8"), ("rejected", "DRD-8")),
            ("later-job-terminal", self._fixture("release-job-rejection"), ("indeterminate", "DRL-4"), ("rejected", "DRL-4")),
            ("earlier-decision-reuse", self._fixture("release-earlier-terminal-transaction"), ("rejected", "DRD-8"), ("indeterminate", "DRD-8")),
            ("same-position", self._fixture("release-same-position-terminal-transaction"), ("indeterminate", "DRD-8"), ("indeterminate", "DRD-8")),
            ("same-position-history-names-release", attested_same_position, ("indeterminate", "DRD-8"), ("rejected", "DRD-8")),
            ("shared-event", self._fixture("other-job-reuses-release-terminal-event"), ("rejected", "DRT-4"), ("rejected", "DRT-4")),
        )
        for label, other, release_outcome, other_outcome in pairs:
            values, expected = [release, other], [release_outcome, other_outcome]
            for order in ((0, 1), (1, 0)):
                with self.subTest(pair=label, order=order):
                    # Evaluated together, the verdicts are the same in either order.
                    joint = evaluate_lifecycles(
                        [copy.deepcopy(values[index]) for index in order], DecisionLedger()
                    )
                    self.assertEqual([verdict(item) for item in joint], [expected[index] for index in order])
                    # One at a time, the second arrival gets its joint verdict
                    # and two conflicting terminals never both verify.  When it
                    # contradicts the first verdict, its result revises that
                    # verdict to the joint one.
                    ledger = DecisionLedger()
                    first, second = (
                        evaluate_protocol(copy.deepcopy(values[index]), ledger) for index in order
                    )
                    self.assertEqual(verdict(second), expected[order[1]])
                    self.assertFalse(first["result"] == second["result"] == "verified")
                    self.assertEqual(self._revised(values[order[0]], first, second), expected[order[0]])
                    self.assertEqual("revises" in second, verdict(first) != expected[order[0]])
                    # With both known, re-evaluation gives the joint verdicts.
                    for index in order:
                        observed = evaluate_protocol(copy.deepcopy(values[index]), ledger)
                        self.assertEqual(verdict(observed), expected[index])
            # When the resolver's records agree, even the first arrival gets
            # its joint verdict, so neither order changes any verdict.
            if label == "history-names-earlier":
                for order in ((0, 1), (1, 0)):
                    ledger = DecisionLedger()
                    for index in order:
                        self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(values[index]), ledger)), expected[index])
        self.assertIsNone(verifier.terminal_precedes(
            TerminalRecord(("c", "a", "1"), (1, "0x1", 2), None, (5, 2)),
            TerminalRecord(("c", "a", "1"), (1, "0x2", 2), None, (5, 2)),
        ))
        self.assertIsNone(verifier.terminal_precedes(
            TerminalRecord(("c", "a", "1"), (1, "0x1", 2), None, (5, 2)),
            TerminalRecord(("c", "a", "1"), (2, "0x2", 2), None, (6, 2)),
        ))
        # A revision names exactly one recorded terminal.
        recorded = TerminalRecord(("c", "a", "1"), ("c", "0x1", 2), "d", (5, 2), ((("c", "a", "1"), ("c", "0x0", 1), "d"),))
        variants = (
            recorded, recorded._replace(job=("c", "a", "2")), recorded._replace(event=("c", "0x2", 2)),
            recorded._replace(decision="e"), recorded._replace(position=(6, 2)), recorded._replace(attested=()),
        )
        identities = {json.dumps(verifier.terminal_identity(item), sort_keys=True) for item in variants}
        self.assertEqual(len(identities), len(variants))

    def test_a_batch_revises_every_earlier_verdict_it_changes(self):
        release = self._fixture("release")
        later = self._fixture("release-second-terminal-transaction")
        # `eip1271-relayed-execution` is another lifecycle with the release's
        # terminal; the release itself is evaluated again in the batch.
        for earlier_name, earlier in (
            ("eip1271-relayed-execution", self._vector("eip1271-relayed-execution")),
            ("release", release),
        ):
            for batch in ([later, release], [release, later]):
                with self.subTest(earlier=earlier_name, batch=[item is release for item in batch]):
                    ledger = DecisionLedger()
                    issued = evaluate_protocol(copy.deepcopy(earlier), ledger)
                    self.assertEqual(verdict(issued), ("verified", "DRV-7"))
                    observed = evaluate_lifecycles([copy.deepcopy(item) for item in batch], ledger)
                    together = evaluate_lifecycles(
                        [copy.deepcopy(item) for item in (earlier, *batch)], DecisionLedger()
                    )
                    # Every result carries the revision, and applying it gives
                    # the verdict of evaluating everything as one set.
                    for item in observed:
                        self.assertEqual(self._revised(earlier, issued, item), verdict(together[0]))
                    self.assertEqual(verdict(together[0]), ("indeterminate", "DRD-8"))
                    self.assertEqual([verdict(item) for item in observed], [verdict(item) for item in together[1:]])

    def test_verdicts_do_not_depend_on_evaluation_order(self):
        vectors = self.vector_pack["vectors"]
        values = {vector["name"]: self._vector(vector["name"]) for vector in vectors}
        # Standalone positives; a vector with `evaluatedWith` is a replay scenario.
        positives = [
            vector["name"] for vector in vectors
            if vector["expected"] == "verified" and "evaluatedWith" not in vector
        ]
        for order in (positives, positives[::-1]):
            ledger = DecisionLedger()
            for _ in range(2):
                for name in order:
                    with self.subTest(order=order[0], vector=name):
                        observed = evaluate_protocol(copy.deepcopy(values[name]), ledger)
                        self.assertEqual(observed["result"], "verified")
                        self.assertNotIn("revises", observed)
        # Each vector set keeps its pinned verdict in every evaluation order.
        for vector in vectors:
            members = [*vector.get("evaluatedWith", []), vector["name"]]
            for order in itertools.permutations(members):
                with self.subTest(vector=vector["name"], order=order):
                    observed = evaluate_lifecycles(
                        [copy.deepcopy(values[name]) for name in order], DecisionLedger()
                    )[order.index(vector["name"])]
                    self.assertEqual(verdict(observed), (vector["expected"], vector["expectedRule"]))
        # The whole pack evaluated as one set: every verdict is the same in
        # any order, and no two conflicting terminals both verify.
        names = list(values)
        baseline = None
        for order in (names, names[::-1], random.Random(372).sample(names, len(names))):
            observed = evaluate_lifecycles([copy.deepcopy(values[name]) for name in order], DecisionLedger())
            verdicts = {name: tuple(item.values()) for name, item in zip(order, observed)}
            baseline = baseline or verdicts
            self.assertEqual(verdicts, baseline)
        self._assert_no_conflicting_verified(values, baseline)
        # One at a time through one ledger, in either order, no two
        # conflicting terminals both verify either, and the verdicts as
        # revised are the verdicts of the whole pack as one set.
        for order in (names, names[::-1]):
            ledger = DecisionLedger()
            streamed = {name: tuple(evaluate_protocol(copy.deepcopy(values[name]), ledger).values()) for name in order}
            self._assert_no_conflicting_verified(values, streamed)
            with self.subTest(streamed=order[0]):
                self.assertEqual(
                    self._streamed(values, order), {name: outcome[:2] for name, outcome in baseline.items()}
                )
        # With every standalone positive already known, each vector without
        # companions keeps its pinned verdict.
        shared = DecisionLedger()
        for name in positives:
            evaluate_protocol(copy.deepcopy(values[name]), shared)
        for vector in vectors:
            if "evaluatedWith" in vector:
                continue
            with self.subTest(shared=vector["name"]):
                observed = evaluate_protocol(copy.deepcopy(values[vector["name"]]), copy.deepcopy(shared))
                self.assertEqual(verdict(observed), (vector["expected"], vector["expectedRule"]))

    def _revised(self, value, issued, *later):
        """The verdict ``issued`` for ``value`` after the revisions in ``later`` results."""
        identity = verifier.terminal_identity(verifier._terminal_record(copy.deepcopy(value)))
        current = verdict(issued)
        for observed in later:
            for revision in observed.get("revises", []):
                if revision["terminal"] == identity:
                    self.assertEqual(verdict(revision["previous"]), current)
                    self.assertGreaterEqual(REPLAY_VERDICT_RANK[revision["result"]], REPLAY_VERDICT_RANK[current[0]])
                    current = verdict(revision)
        return current

    def _streamed(self, values, order):
        """Evaluate ``order`` one at a time through one ledger, applying each revision."""
        ledger = DecisionLedger()
        current, by_terminal = {}, {}
        for name in order:
            observed = evaluate_protocol(copy.deepcopy(values[name]), ledger)
            current[name] = verdict(observed)
            for revision in observed.get("revises", []):
                revised = by_terminal.get(json.dumps(revision["terminal"], sort_keys=True))
                self.assertTrue(revised, "a revision names a terminal this ledger issued a verdict for")
                for other in revised:
                    self.assertEqual(verdict(revision["previous"]), current[other])
                    self.assertGreaterEqual(REPLAY_VERDICT_RANK[revision["result"]], REPLAY_VERDICT_RANK[current[other][0]])
                    current[other] = verdict(revision)
            if verifier._lifecycle_check(copy.deepcopy(values[name])) is None:
                terminal = verifier._terminal_record(copy.deepcopy(values[name]))
                by_terminal.setdefault(
                    json.dumps(verifier.terminal_identity(terminal), sort_keys=True), []
                ).append(name)
        return current

    def _assert_no_conflicting_verified(self, values, verdicts):
        accepted = {}
        for name, outcome in verdicts.items():
            if outcome[0] == "verified":
                accepted.setdefault(verifier._terminal_record(values[name])[:3], name)
        for left, right in itertools.combinations(accepted, 2):
            with self.subTest(left=accepted[left], right=accepted[right]):
                self.assertIsNone(verifier.terminal_conflict(TerminalRecord(*left), TerminalRecord(*right)))

    def test_resolver_attested_terminal_history_carries_terminal_identity(self):
        for name, rule in (
            ("consumed-decision-replay", "DRD-8"),
            ("resolver-history-shows-terminal-job", "DRL-4"),
            ("resolver-history-shows-event-settled-another-job", "DRT-4"),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), ("rejected", rule))
        # An attested entry identical to this terminal is the same transaction.
        release = self._fixture("release")
        terminal = release["artifacts"]["terminal"]
        release["resolverEvidence"]["priorTerminals"] = [{
            "chainId": release["artifacts"]["job"]["chainId"],
            "contractAddress": release["artifacts"]["job"]["contractAddress"],
            "nativeJobId": release["artifacts"]["job"]["nativeJobId"],
            "txHash": terminal["terminalEventRefs"][0]["txHash"],
            "logIndex": terminal["terminalEventRefs"][0]["logIndex"],
            "decisionHash": artifact_hash(release["artifacts"]["decision"]),
        }]
        generator.resign_resolver(release)
        self.assertEqual(finding(release), ("verified", "DRV-7"))

    def test_drp_9_digest_is_fixed_before_the_native_submission(self):
        for name, fixture in self.vector_pack["fixtures"].items():
            with self.subTest(fixture=name):
                binding = fixture["deliveryBinding"]
                anchor = fixture["resolverEvidence"]["deliveryDigestAnchor"]
                if "delivery" in fixture["artifacts"]:
                    self.assertEqual(set(binding), {"nativeSubmissionEvent"})
                    if name != "drp-9-digest-anchor-unavailable":
                        self.assertEqual(set(anchor), verifier.DIGEST_ANCHOR_FIELDS)
                else:
                    self.assertIsNone(binding)
                    self.assertIsNone(anchor)
        for name, outcome in (
            ("delivery-submission-circularity", ("rejected", "DRP-9")),
            ("drp-9-digest-anchor-unavailable", ("indeterminate", "DRP-9")),
            ("drp-9-digest-anchor-other-digest", ("rejected", "DRP-9")),
            ("drp-9-digest-fixed-after-submission", ("rejected", "DRP-9")),
            ("drp-9-digest-anchored-in-submission-block", ("indeterminate", "DRP-9")),
            ("drp-9-digest-anchor-time-after-submission", ("rejected", "DRP-9")),
            ("drp-9-delivery-observed-after-submission", ("rejected", "DRP-9")),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), outcome)
        # Fields derived from the submission, in any encoding, never verify:
        # with a committed submission identity they cannot be computed before
        # the digest is fixed, and a digest fixed later is not anchored before.
        submission = self._observation(self._fixture("release"), "JobSubmitted")
        derived = {
            "submissionTxHashSha256": hashlib.sha256(submission["eventRef"]["txHash"].encode("ascii")).hexdigest(),
            "submissionBlockNumber": submission["blockNumber"],
        }
        for field, item in derived.items():
            with self.subTest(derived=field):
                value = make_base("release", hooks={
                    "inputs": put("deliveredArtifact", field, item),
                    "fixture": put("resolverEvidence", "deliveryDigestAnchor", None),
                })
                self.assertNotEqual(value["deliveryBinding"]["nativeSubmissionEvent"], submission["eventRef"])
                self.assertEqual(finding(value), ("indeterminate", "DRP-9"))
        # An ordering conclusion supplied beside the locator is malformed input.
        labelled = self._fixture("release")
        labelled["deliveryBinding"]["containsNativeSubmissionObservation"] = False
        self.assertEqual(finding(labelled), ("error", "DRV-2"))

    def test_native_capability_facts_come_only_from_the_resolver(self):
        for name, fixture in self.vector_pack["fixtures"].items():
            with self.subTest(fixture=name):
                self.assertFalse(NATIVE_STATE_FIELDS & set(fixture["native"]))
                self.assertNotIn("description", fixture["native"])
                self.assertEqual(
                    set(fixture["resolverEvidence"]["nativeState"]), NATIVE_STATE_FIELDS
                )
        release = self._fixture("release")
        state = release["resolverEvidence"]["nativeState"]
        for field, value in state.items():
            with self.subTest(unsigned=field):
                edited = copy.deepcopy(release)
                edited["resolverEvidence"]["nativeState"][field] = (
                    not value if isinstance(value, bool) else "edited"
                )
                self.assertEqual(finding(edited), ("rejected", "DRV-1"))
        # A producer copy of a capability claim has no effect either way.
        producer = copy.deepcopy(release)
        producer["native"].update({
            "submissionCutoffEnforced": False,
            "evaluatorBindingMode": "adapter",
            "preterminalProviderPayoutBaseUnits": "1",
        })
        self.assertEqual(finding(producer), ("verified", "DRV-7"))
        for name, rule in (
            ("native-submission-cutoff-unenforced", "DREB-13"),
            ("native-expiry-recovery-too-early", "DREB-15"),
            ("evaluator-binding-not-direct", "DREB-16"),
            ("evaluator-adapter-substitution", "DREB-20"),
            ("nonzero-preterminal-payout", "DRL-7"),
            ("nonzero-platform-fee", "DRT-7"),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), ("rejected", rule))

    def test_native_description_is_bound_through_the_creation_event(self):
        # An expiry lifecycle presented with a differently signed agreement,
        # but the original native job and resolver record, does not verify.
        original = self._fixture("expired-pre")
        other = make_base(
            "expired-pre",
            hooks={"agreement": put("disclosurePolicy", "explicit-party-supplied")},
        )
        self.assertEqual(finding(other), ("verified", "DRV-7"))
        other["reproductionInputs"]["nativeEventInputs"] = original["reproductionInputs"]["nativeEventInputs"]
        other["resolverEvidence"] = original["resolverEvidence"]
        self._assert_isolated(other)
        self.assertEqual(finding(other), ("rejected", "DREB-1"))

    def test_replay_role_mapping_and_ordering_regressions_are_present(self):
        required = {
            "cross-job-delivery-replay": "rejected",
            "cross-job-decision-replay": "rejected",
            "consumed-decision-replay": "rejected",
            "decision-reused-by-another-terminal-transaction": "rejected",
            "second-terminal-for-terminal-job": "rejected",
            "terminal-event-settles-another-job": "rejected",
            "drd-8-same-terminal-again": "verified",
            "evaluator-primary-claim-collision": "rejected",
            "evaluator-account-collision": "rejected",
            "delivery-hash-text-rehash": "rejected",
            "decision-hash-text-rehash": "rejected",
            "cross-substrate-order-unavailable": "indeterminate",
            "decision-finalized-after-terminal": "rejected",
            "delivery-submission-circularity": "rejected",
            "evaluator-added-as-bundle-party": "rejected",
            "relayer-substituted-as-native-caller": "rejected",
        }
        for name, expected in required.items():
            with self.subTest(vector=name):
                self.assertEqual(self.vectors[name]["expected"], expected)

    def test_relay_never_replaces_the_native_evaluator_caller(self):
        relayed = self._vector("eip1271-relayed-execution")
        call = relayed["resolverEvidence"]["terminalCall"]
        self.assertEqual(call["nativeCallerAccountType"], "eip1271")
        self.assertEqual(call["nativeCaller"], relayed["native"]["evaluator"])
        self.assertNotEqual(call["outerSubmitter"], call["nativeCaller"])
        self.assertEqual(evaluate(relayed)["result"], "verified")

    def test_fixture_scope_cannot_be_read_as_live_rail_registration(self):
        self.assertEqual(self.vector_pack["status"], "non-normative-review-fixture")
        for fixture in self.vector_pack["fixtures"].values():
            self.assertTrue(fixture["fixtureOnly"])
            self.assertEqual(
                fixture["artifacts"]["railDefinition"]["availability"], "mocked"
            )
            self.assertTrue(fixture["artifacts"]["railDefinition"]["fixtureOnly"])

    def test_every_deployment_case_executes_and_registration_stays_false(self):
        self.assertEqual(verify_deployment_pack(self.deployment_pack), [])
        manifests = self.deployment_pack["manifests"]
        for case in self.deployment_pack["cases"]:
            manifest = copy.deepcopy(manifests[case["base"]])
            for operation in case["patch"]:
                manifest = apply_operation(manifest, operation)
            observed = evaluate_deployment(manifest)
            with self.subTest(case=case["name"]):
                self.assertEqual(observed["result"], case["expected"])
                self.assertFalse(observed["registrationEligible"])

    def test_synthetic_control_exercises_all_drc_rules_without_registering(self):
        manifest = self.deployment_pack["manifests"]["synthetic-control"]
        statuses = deployment_rule_statuses(manifest)
        self.assertEqual(set(statuses), DRC_RULES)
        self.assertEqual(set(statuses.values()), {"pass"})
        observed = evaluate_deployment(manifest)
        self.assertEqual(observed["result"], "verified")
        self.assertTrue(manifest["fixtureOnly"])
        self.assertEqual(manifest["registrationStatus"], "not-a-deployment")
        self.assertFalse(observed["registrationEligible"])

    def test_current_reference_is_pinned_ineligible_and_never_available(self):
        manifest = self.deployment_pack["manifests"]["current-reference-142e669"]
        self.assertEqual(
            manifest["implementation"]["revision"],
            "142e669c1fd318486a4628395b629f033654dd06",
        )
        observed = evaluate_deployment(manifest)
        self.assertEqual(observed["result"], "rejected")
        self.assertEqual(
            [rule for rule in sorted(DRC_RULES, key=lambda item: int(item.split("-")[1])) if observed["ruleStatuses"][rule] == "fail"],
            ["DRC-1", "DRC-2", "DRC-3", "DRC-4", "DRC-5", "DRC-6", "DRC-7"],
        )
        self.assertEqual(
            [rule for rule in sorted(DRC_RULES, key=lambda item: int(item.split("-")[1])) if observed["ruleStatuses"][rule] == "unknown"],
            ["DRC-8", "DRC-10", "DRC-11", "DRC-12", "DRC-13"],
        )
        self.assertFalse(observed["registrationEligible"])

    def test_signed_funding_and_terminal_records_cannot_bypass_finality_or_events(self):
        expected = {
            "creation-finality-pending": ("indeterminate", "DRJ-2"),
            "funding-finality-pending": ("indeterminate", "DRF-6"),
            "submission-finality-pending": ("indeterminate", "DRP-9"),
            "funding-events-empty": ("rejected", "DRF-3"),
            "terminal-finality-pending": ("indeterminate", "DRT-8"),
            "terminal-events-empty": ("rejected", "DRT-4"),
            "funding-finality-unregistered-member": ("error", "DRV-2"),
            "funding-finality-depth-below-rail-profile": ("rejected", "DRF-6"),
            "funding-finality-predates-event-block": ("rejected", "DRF-6"),
            "terminal-finality-unregistered-member": ("error", "DRV-2"),
            "terminal-finality-depth-below-rail-profile": ("rejected", "DRT-8"),
        }
        for name, outcome in expected.items():
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), outcome)

    def test_candidate_domains_and_deadline_profile_match_the_spec(self):
        release = self._vector("release-complete-budget")
        self.assertEqual(
            release["profileParameters"],
            release["artifacts"]["railDefinition"]["profileParameters"],
        )
        self.assertEqual(
            release["profileParameters"]["deadlineProfile"],
            "separate-submission-cutoff-v1",
        )
        self.assertEqual(
            release["native"]["expiredAt"],
            release["artifacts"]["agreement"]["evaluationDeadlineSec"],
        )
        self.assertNotEqual(
            release["native"]["expiredAt"],
            release["artifacts"]["agreement"]["submissionCutoffSec"],
        )
        self.assertEqual(
            self.vectors["unsupported-expiry-only-policy"]["expectedRule"],
            "DRA-15",
        )

    def test_finality_time_and_fault_projection_come_from_authenticated_inputs(self):
        release = self._vector("release-complete-budget")
        rejection = self._vector("evaluator-rejection-refund")
        expected_finality_fields = {
            "model", "finalityBlocks", "finalityObservedAt"
        }
        for name in ("funding", "terminal"):
            self.assertEqual(
                set(release["artifacts"][name]["finality"]),
                expected_finality_fields,
            )
            self.assertEqual(
                release["artifacts"][name]["finality"]["model"],
                "block-depth",
            )
        self.assertEqual(
            release["native"]["fundedAtSec"],
            self._observation(release, "JobFunded")["blockTimestampSec"],
        )
        self.assertLess(
            self._observation(release, "JobSubmitted")["blockTimestampSec"],
            release["artifacts"]["agreement"]["submissionCutoffSec"],
        )
        self.assertTrue(release["submittedBeforeCutoff"])
        self.assertFalse(release["reputationProjection"]["sellerFault"])
        self.assertTrue(rejection["reputationProjection"]["sellerFault"])

    def test_reproduction_inputs_are_present_and_load_bearing(self):
        release = self._vector("release-complete-budget")
        inputs = release["reproductionInputs"]
        self.assertEqual(set(inputs["roleBundles"]), {"buyer", "seller", "evaluator"})
        self.assertEqual(set(inputs["vetRecords"]), {"buyer", "seller", "evaluator"})
        self.assertIsNotNone(inputs["deliveredArtifact"])
        self.assertEqual(len(inputs["nativeEventInputs"]), 4)
        required = {
            "public-test-seed-mismatch": "DRV-4",
            "role-bundle-input-mismatch": "DRA-4",
            "vet-record-input-mismatch": "DRA-4",
            "evaluation-rule-input-mismatch": "DRE-6",
            "delivered-artifact-input-mismatch": "DRE-2",
            "runtime-bytecode-preimage-mismatch": "DRJ-5",
            "native-event-transaction-preimage-mismatch": "DRT-4",
            "native-event-kind-substitution": "DRT-4",
            "native-event-chain-substitution": "DRT-4",
            "funding-time-caller-substitution": "DRA-9",
            "submitted-before-cutoff-claim-substitution": "DRT-12",
            "detached-profile-projection-weakened": "DRP-5",
            "release-invents-seller-fault": "DRT-14",
            "rejected-refund-erases-seller-fault": "DRT-14",
            "terminal-event-payload-mismatch": "DRT-4",
            "funding-finality-block-preimage-mismatch": "DRF-6",
            "creation-event-cutoff-mismatch": "DRJ-3",
        }
        for name, rule in required.items():
            with self.subTest(vector=name):
                vector = self.vectors[name]
                self.assertEqual(vector["expected"], "rejected")
                self.assertEqual(vector["expectedRule"], rule)

    def test_drv_1_resolver_key_pin(self):
        seed = generator.RESOLVER_SEED
        derived = generator.b64u(
            generator.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
        )
        self.assertEqual(PINNED_RESOLVER_KEYS, {generator.RESOLVER: derived})
        for name, fixture in self.vector_pack["fixtures"].items():
            with self.subTest(fixture=name):
                self.assertNotIn(generator.RESOLVER, fixture["publicKeys"])
                self.assertNotIn(
                    generator.RESOLVER, fixture["reproductionInputs"]["publicTestSeedHex"]
                )
                self.assertNotIn(seed.hex(), json.dumps(fixture))
        foreign = self._vector("drv-1-resolver-key")
        # The vector's own key and seed are valid; only the pin rejects it.
        self.assertIsNone(verifier._reproduction_input_check(foreign))
        self.assertEqual(finding(foreign), ("rejected", "DRV-1"))

    def test_drv_1_resolver_record_signature_scope(self):
        # Every status, observation field, call record, history, and native
        # state edit after signing is DRV-1.
        for base in ("release", "rejected-refund", "expired-pre", "expired-post"):
            fixture = self._fixture(base)
            self.assertEqual(finding(fixture), ("verified", "DRV-7"))
            for name, state in fixture["resolverEvidence"]["statuses"].items():
                for replacement in sorted(verifier.EXTERNAL_STATES - {state}):
                    with self.subTest(base=base, status=name, value=replacement):
                        mutated = copy.deepcopy(fixture)
                        mutated["resolverEvidence"]["statuses"][name] = replacement
                        self.assertEqual(finding(mutated), ("rejected", "DRV-1"))
            for index, item in enumerate(fixture["reproductionInputs"]["nativeEventInputs"]):
                for field in ("confirmations", "blockTimestampSec", "blockNumber"):
                    with self.subTest(base=base, observation=index, field=field):
                        mutated = copy.deepcopy(fixture)
                        mutated["reproductionInputs"]["nativeEventInputs"][index][field] = item[field] + 1
                        self.assertEqual(finding(mutated), ("rejected", "DRV-1"))
            for field in ("outerSubmitter", "nativeCaller"):
                with self.subTest(base=base, call=field):
                    mutated = copy.deepcopy(fixture)
                    mutated["resolverEvidence"]["terminalCall"][field] = generator.RELAYER_ACCOUNT
                    self.assertEqual(finding(mutated), ("rejected", "DRV-1"))
        for name in (
            "drv-1-signed-status",
            "drv-1-signed-observation",
            "drv-1-signed-call-record",
            "drv-1-signed-history",
            "drv-1-signed-native-state",
        ):
            with self.subTest(vector=name):
                self.assertEqual(finding(self._vector(name)), ("rejected", "DRV-1"))
        bound = self._vector("resolver-bound-to-another-job")
        self.assertEqual(finding(bound), ("rejected", "DRV-6"))

    def test_resolver_signature_is_strict(self):
        release = self._fixture("release")
        for resolver_claim in (["claim"], {"claim": 1}, 7):
            with self.subTest(resolver=resolver_claim):
                mutated = copy.deepcopy(release)
                mutated["resolverEvidence"]["resolver"] = resolver_claim
                self.assertEqual(finding(mutated), ("rejected", "DRV-1"))
        renamed = copy.deepcopy(release)
        signature = renamed["resolverEvidence"]["signature"]
        signature["party"] = signature.pop("signer")
        self.assertEqual(finding(renamed), ("rejected", "DRV-1"))

    def test_resolver_status_rules_are_complete(self):
        self.assertEqual(
            set(verifier.UNAVAILABLE_STATUS_RULES), set(verifier.EXTERNAL_EVIDENCE_FIELDS)
        )
        for name in verifier.UNAVAILABLE_STATUS_RULES:
            with self.subTest(status=name):
                value = self._fixture("release")
                value["resolverEvidence"]["statuses"][name] = "unavailable"
                generator.resign_resolver(value)
                self.assertEqual(
                    finding(value),
                    ("indeterminate", verifier.UNAVAILABLE_STATUS_RULES[name]),
                )

    def test_dreb_15_expiry_recovery_time(self):
        for base in ("expired-pre", "expired-post"):
            fixture = self._fixture(base)
            deadline = fixture["artifacts"]["agreement"]["evaluationDeadlineSec"]
            self.assertEqual(
                self._observation(fixture, "JobExpired")["blockTimestampSec"], deadline
            )
            for offset, expected in ((-1, ("rejected", "DREB-15")), (0, ("verified", "DRV-7")), (1, ("verified", "DRV-7"))):
                with self.subTest(base=base, offset=offset):
                    value = copy.deepcopy(fixture)
                    self._retime(value, "JobExpired", deadline + offset)
                    generator.resign_resolver(value)
                    self.assertEqual(finding(value), expected)
                    self.assertEqual(
                        value["resolverEvidence"]["nativeState"]["expiryRecoveryAtSec"], deadline
                    )
        for name in (
            "dreb-15-pre-submission-recovery-time",
            "dreb-15-post-submission-recovery-time",
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), ("rejected", "DREB-15"))
        self.assertEqual(self.vectors["dreb-15-recovery-after-deadline"]["expected"], "verified")

    def test_drv_2_closed_evaluation_discriminators(self):
        for evaluation_result in ("deferred", "accepted", "", "ACCEPT", ["accept"]):
            for disposition in ("release-to-provider", "refund-to-client"):
                with self.subTest(result=evaluation_result, disposition=disposition):
                    value = make_base("release", hooks={
                        "evaluation": put("result", evaluation_result),
                        "decision": put("disposition", disposition),
                    })
                    self._assert_isolated(value)
                    self.assertEqual(finding(value), ("error", "DRV-2"))
                    if isinstance(evaluation_result, str):
                        # Behind the discriminator stage, the settlement
                        # mapping itself still refuses any result it does not list.
                        mapped = verifier._native_and_terminal_check(value)
                        self.assertEqual((mapped["result"], mapped["rule"]), ("rejected", "DRD-2"))
        self.assertEqual(
            set(verifier.SETTLEMENT_AUTHORIZATIONS), verifier.EVALUATION_RESULTS - {"indeterminate"}
        )

    def test_drp_5_drj_2_drj_5_selected_rail(self):
        expected = {
            "drp-5-job-rail": "DRP-5",
            "drj-2-job-contract": "DRJ-2",
            "drj-5-job-runtime": "DRJ-5",
            "drp-5-escrow-phase-rails": "DRP-5",
        }
        for name, rule in expected.items():
            with self.subTest(vector=name):
                value = self._vector(name)
                self.assertIsNone(verifier._component_signature_check(value))
                self.assertEqual(finding(value), ("rejected", rule))
        divergent = self._vector("drp-5-job-rail")
        self.assertNotEqual(
            divergent["artifacts"]["job"]["railDefinitionRef"],
            divergent["artifacts"]["agreement"]["railDefinitionRef"],
        )
        self.assertEqual(
            divergent["executionContext"]["acceptedRails"],
            [divergent["artifacts"]["agreement"]["railDefinitionRef"]],
        )

    def test_dreb_18_21_22_terminal_call_record(self):
        for name, outcome in (
            ("relayer-substituted-as-native-caller", ("rejected", "DREB-21")),
            ("dreb-21-call-record-transaction", ("rejected", "DREB-21")),
            ("eoa-relayed-outer-submitter", ("rejected", "DREB-22")),
            ("malformed-outer-submitter", ("error", "DREB-22")),
            ("unsupported-evaluator-account-type", ("error", "DREB-18")),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), outcome)

    def test_drc_11_registration_eligibility_is_never_reported(self):
        for fixture_only in (True, False):
            for status in ("not-a-deployment", "listed", "unregistered-ineligible-reference-source"):
                with self.subTest(fixtureOnly=fixture_only, registrationStatus=status):
                    manifest = copy.deepcopy(self.deployment_pack["manifests"]["synthetic-control"])
                    manifest["fixtureOnly"] = fixture_only
                    manifest["registrationStatus"] = status
                    observed = evaluate_deployment(manifest)
                    self.assertEqual(observed["result"], "verified")
                    self.assertFalse(observed["registrationEligible"])
        case = self.deployment_cases["drc-11-manifest-labels"]
        self.assertFalse(case["registrationEligible"])


if __name__ == "__main__":
    unittest.main()
