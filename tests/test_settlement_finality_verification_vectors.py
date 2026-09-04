import hashlib
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "settlement-finality-verification-v0.8.json"
)
SPEC4 = ROOT / "spec" / "DACS-4-SETTLE.md"
SPEC5 = ROOT / "spec" / "DACS-5-VERIFY.md"
CORE = ROOT / "spec" / "CORE.md"
PLAN = ROOT / "spec" / "CONFORMANCE-PLAN.md"
README = ROOT / "conformance" / "vectors" / "security" / "README.md"
WORKFLOW = ROOT / ".github" / "workflows" / "validate.yml"
POSITION_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
COMMITMENT_RANK = {"processed": 0, "confirmed": 1, "finalized": 2}
KNOWN_MODELS = {
    "block-depth", "commitment-level", "bft-final", "provider-receipt",
    "htlc-reveal", "liquidity-tank",
}
HTLC_OBSERVATIONS = {
    "sourceLock", "sourceClaim", "destinationLock", "destinationReveal"
}
HTLC_RELATIONS = {
    "sourceContractMatches",
    "destinationContractMatches",
    "commonHashlockMatches",
    "revealedPreimageMatches",
    "amountsMatch",
    "timelocksValid",
}


def canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def validate_htlc_observation(observation, profile):
    required = {
        "networkId",
        "genesisHash",
        "transactionRef",
        "transactionInclusionProof",
        "selectedEventProof",
        "inclusionBlock",
        "authenticatedHead",
        "ancestryProof",
        "authorityEvidence",
    }
    if not isinstance(observation, dict) or not required.issubset(observation):
        return "error"
    authority = observation.get("authorityEvidence")
    if not isinstance(authority, dict) or not authority.get("sourceRefs"):
        return "error"
    if authority.get("kind") == "unavailable":
        return "indeterminate"
    if authority.get("kind") != "rpc-quorum" or not authority.get("value"):
        return "error"
    if observation.get("networkId") != profile.get("networkId"):
        return "fail"
    if observation.get("genesisHash") != profile.get("genesisHash"):
        return "fail"
    transaction = observation.get("transactionRef")
    inclusion = observation.get("transactionInclusionProof")
    selected_event = observation.get("selectedEventProof")
    if (
        not isinstance(transaction, dict)
        or transaction.get("kind") != "evm-event"
        or not isinstance(inclusion, dict)
        or inclusion.get("kind") != "receipt-merkle-proof"
        or not inclusion.get("value")
        or not isinstance(selected_event, dict)
        or selected_event.get("kind") != "evm-log-proof"
        or not selected_event.get("value")
    ):
        return "error"
    inclusion_block = observation.get("inclusionBlock")
    head = observation.get("authenticatedHead")
    if not isinstance(inclusion_block, dict) or not isinstance(head, dict):
        return "error"
    if not POSITION_RE.fullmatch(str(inclusion_block.get("position", ""))):
        return "error"
    if not POSITION_RE.fullmatch(str(head.get("position", ""))):
        return "error"
    ancestry = observation.get("ancestryProof")
    if not isinstance(ancestry, list) or not ancestry:
        return "error"
    first_link = ancestry[0]
    if (
        not isinstance(first_link, dict)
        or first_link.get("childId") != head.get("id")
        or first_link.get("parentId") != inclusion_block.get("id")
    ):
        return "fail"
    required_depth = profile.get("requiredDepth")
    if type(required_depth) is not int or required_depth <= 0:
        return "error"
    depth = int(head["position"]) - int(inclusion_block["position"]) + 1
    if depth < required_depth:
        return "fail"
    return "pass"


def evaluate(value):
    """Independent executable model of DACS-4 FV-1..FV-10 precedence."""
    evidence = value["evidence"]
    discriminator = evidence.get("discriminator")
    if discriminator == "multiple" or discriminator not in {"legacy", "finality-bound"}:
        return "error", None
    if discriminator == "legacy" or evidence.get("signatureDomainMatches") is not True:
        return "fail", None

    rail = value["rail"]
    if rail.get("profileShape") != "valid":
        return "error", None
    if any(rail.get(field) is False for field in (
        "referenceMatches", "agreementMatches", "phaseMatches"
    )):
        return "fail", None
    if rail.get("resolution") in {"unavailable", "conflicting"}:
        return "indeterminate", None
    if rail.get("resolution") != "verified":
        return "error", None

    profile = rail.get("profile")
    report = evidence.get("settlementFinality")
    if not isinstance(profile, dict) or profile.get("finalityProfileVersion") != "1":
        return "error", None
    model = profile.get("model")
    if model not in KNOWN_MODELS or not isinstance(report, dict):
        return "error", None
    if report.get("model") != model:
        return "fail", None

    context = value["context"]
    if context.get("shape") != "valid" or context.get("proofKindSupported") is not True:
        return "error", None

    # Structural arithmetic errors precede any trust-source lookup.
    if model == "block-depth":
        if not all(POSITION_RE.fullmatch(str(context.get(field, ""))) for field in (
            "inclusionPosition", "headPosition"
        )):
            return "error", None

    if model in {"block-depth", "commitment-level", "bft-final"}:
        settlement = profile.get("settlement")
        if not isinstance(settlement, dict) or settlement.get("kind") != model:
            return "error", None
        observation = settlement.get("observation")
        if not isinstance(observation, dict) or not observation.get("authorityRefs"):
            return "error", None
        if context.get("networkId") != settlement.get("networkId"):
            return "fail", None
        if context.get("genesisHash") != settlement.get("genesisHash"):
            return "fail", None
        if context.get("transactionIncluded") is not True:
            return "fail", None
        if context.get("selectedEventMatches") is not True:
            return "fail", None
        if context.get("canonicalPath") == "stale-fork":
            return "fail", None

        if model == "block-depth":
            required = settlement.get("requiredDepth")
            if type(required) is not int or required <= 0:
                return "error", None
            if report.get("finalityBlocks") != required:
                return "fail", None
            depth = int(context["headPosition"]) - int(context["inclusionPosition"]) + 1
            if depth < required:
                return "fail", None
        elif model == "commitment-level":
            required = settlement.get("requiredCommitment")
            observed = context.get("commitment")
            if required not in COMMITMENT_RANK or observed not in COMMITMENT_RANK:
                return "error", None
            if report.get("finalityCommitmentLevel") != required:
                return "fail", None
            if COMMITMENT_RANK[observed] < COMMITMENT_RANK[required]:
                return "fail", None
        else:
            numerator = settlement.get("quorumNumerator")
            denominator = settlement.get("quorumDenominator")
            if (
                type(numerator) is not int or type(denominator) is not int
                or numerator <= 0 or denominator <= 0 or numerator > denominator
            ):
                return "error", None
            if context.get("bftCertificateValid") is not True:
                return "fail", None
            signed = context.get("bftSignedWeight")
            total = context.get("bftTotalWeight")
            if type(signed) is not int or type(total) is not int or total <= 0:
                return "error", None
            if signed * denominator < total * numerator:
                return "fail", None
        freshness_limit = observation.get("maxHeadAgeSec")
    elif model == "provider-receipt":
        required = {
            "providerId", "statusEndpointOrigin", "captureStatuses", "sr3Binding",
            "maxObservationAgeSec", "reversibility",
        }
        if not required.issubset(profile) or not profile.get("captureStatuses"):
            return "error", None
        if profile.get("reversibility") != "provisional-provider-capture":
            return "error", None
        if context.get("providerId") != profile.get("providerId"):
            return "fail", None
        if context.get("endpointOrigin") != profile.get("statusEndpointOrigin"):
            return "fail", None
        if context.get("providerCaptured") is not True:
            return "fail", None
        if context.get("providerBindingMatches") is not True:
            return "fail", None
        freshness_limit = profile.get("maxObservationAgeSec")
    else:
        required_fields = {"source", "destination"}
        if model == "liquidity-tank":
            required_fields |= {"bridgeId", "coordinator"}
        if not required_fields.issubset(profile):
            return "error", None
        if model == "htlc-reveal":
            relation = context.get("relation")
            if not isinstance(relation, dict) or set(relation) != HTLC_RELATIONS:
                return "error", None
            if any(type(relation[field]) is not bool for field in HTLC_RELATIONS):
                return "error", None
            observation_results = [
                validate_htlc_observation(
                    context.get(field),
                    profile["source"] if field.startswith("source") else profile["destination"],
                )
                for field in sorted(HTLC_OBSERVATIONS)
            ]
            if "error" in observation_results:
                return "error", None
            if not all(relation.values()) or "fail" in observation_results:
                return "fail", None
            if "indeterminate" in observation_results:
                return "indeterminate", None
        else:
            if context.get("compositeStatus") == "mismatch":
                return "fail", None
            if context.get("compositeStatus") == "unavailable":
                return "indeterminate", None
            if context.get("compositeStatus") != "verified":
                return "error", None
        freshness_limit = None

    # A deterministic contradiction above cannot be hidden by an outage below.
    if context.get("authority") in {"unavailable", "conflicting"}:
        return "indeterminate", None
    if context.get("canonicalPath") in {"reorg", "replaced", "pruned"}:
        return "indeterminate", None
    if freshness_limit is not None and context.get("headAgeSec", 0) > freshness_limit:
        return "indeterminate", None
    finality_class = (
        "provisional-provider-capture"
        if model == "provider-receipt"
        else "profile-final"
    )
    return "pass", finality_class


class SettlementFinalityVerificationVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {case["name"]: case for case in cls.data["vectors"]}

    def test_vector_hash_count_and_names_are_exact(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["count"], 47)
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(len({case["name"] for case in vectors}), len(vectors))
        self.assertEqual(
            self.data["hash"], hashlib.sha256(canonical_json(vectors)).hexdigest()
        )

    def test_every_vector_executes_to_its_declared_four_value_result(self):
        for case in self.data["vectors"]:
            with self.subTest(case=case["name"]):
                verdict, finality_class = evaluate(case["input"])
                self.assertEqual(verdict, case["expected"])
                self.assertEqual(case["want"]["acceptedAsFinal"], verdict == "pass")
                self.assertEqual(case["want"]["finalityClass"], finality_class)
                self.assertFalse(case["want"]["producerReportTrustedAsProof"])
                self.assertEqual(
                    case["want"]["dacs5RsvDecision"],
                    {"pass": "verified", "fail": "rejected"}.get(verdict, verdict),
                )

    def test_required_models_and_adversarial_classes_are_covered(self):
        models = {case["input"]["rail"]["profile"]["model"] for case in self.data["vectors"]}
        self.assertEqual(models, KNOWN_MODELS)
        required_names = {
            "fv-wrong-network", "fv-wrong-genesis", "fv-wrong-transaction-inclusion",
            "fv-wrong-log-index", "fv-insufficient-depth", "fv-stale-fork",
            "fv-active-reorganization", "fv-head-unavailable",
            "fv-fake-confirmation-count", "fv-demos-bft-final-success",
            "fv-dacs5-rsv-reuses-same-verdict",
            "fv-htlc-source-lock-missing",
            "fv-htlc-source-claim-missing",
            "fv-htlc-destination-lock-missing",
            "fv-htlc-destination-reveal-missing",
            "fv-htlc-observation-shape-missing",
            "fv-htlc-destination-reveal-wrong-network",
        }
        self.assertTrue(required_names.issubset(self.cases))
        self.assertEqual(
            evaluate(self.cases["fv-deterministic-mismatch-precedes-outage"]["input"])[0],
            "fail",
        )

    def test_htlc_context_carries_four_independent_observations(self):
        context = self.cases["fv-htlc-both-legs-success"]["input"]["context"]
        self.assertNotIn("compositeStatus", context)
        self.assertTrue(HTLC_OBSERVATIONS.issubset(context))
        transaction_hashes = {
            context[field]["transactionRef"]["txHash"]
            for field in HTLC_OBSERVATIONS
        }
        self.assertEqual(len(transaction_hashes), 4)
        for field in HTLC_OBSERVATIONS:
            observation = context[field]
            self.assertIn("transactionInclusionProof", observation)
            self.assertIn("selectedEventProof", observation)
            self.assertIn("authenticatedHead", observation)
            self.assertIn("ancestryProof", observation)
            self.assertIn("authorityEvidence", observation)

    def test_generator_check_is_enforced(self):
        result = subprocess.run(
            [sys.executable, "scripts/generate_settlement_finality_verification_vectors.py", "--check"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_normative_surfaces_registry_plan_readme_and_ci_are_linked(self):
        spec4 = SPEC4.read_text(encoding="utf-8")
        spec5 = SPEC5.read_text(encoding="utf-8")
        core = CORE.read_text(encoding="utf-8")
        plan = PLAN.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for rule in range(1, 11):
            self.assertIn(f"(FV-{rule})", spec4)
        self.assertIn("FinalityBoundSettlementEvidence", spec4)
        self.assertIn("producer report", spec4.lower())
        self.assertIn("provisional-provider-capture", spec4)
        self.assertIn("FV-1..FV-10", spec5)
        self.assertIn('"dacs-finality-bound-evidence:v1:"', spec4)
        self.assertIn('"dacs-finality-bound-evidence:v1:"', core)
        self.assertIn(VECTORS.name, plan)
        self.assertIn(VECTORS.name, readme)
        self.assertIn(
            "generate_settlement_finality_verification_vectors.py --check", workflow
        )


if __name__ == "__main__":
    unittest.main()
