import base64
import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from scripts.jcs import canonicalize as jcs_canonicalize


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance/vectors/security/alternative-payment-projection-v0.1.json"
GENERATOR = ROOT / "scripts/generate_alternative_payment_projection_vectors.py"
SPECS = [
    ROOT / "spec/DACS-1-IDENTIFY.md",
    ROOT / "spec/DACS-3-NEGOTIATE.md",
    ROOT / "spec/DACS-4-SETTLE.md",
    ROOT / "spec/DACS-5-VERIFY.md",
]
CONCRETE_PAYMENT_HANDLERS = {
    "pay-evm-erc20",
    "pay-solana-spl",
    "pay-cross-chain-htlc",
    "pay-cross-chain-liquidity-tank",
    "pay-ap2",
    "pay-x402",
    "pay-dem",
}
CASE_FIELDS = {
    "name", "expected", "expectedReason", "rule", "operation", "note", "base", "patch",
}


def canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(value):
    return hashlib.sha256(jcs_canonicalize(value).encode("utf-8")).hexdigest()


def decode_base64url(value):
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("non-canonical base64url")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ValueError("non-canonical base64url")
    return raw


def unsigned(value, *fields):
    return {name: item for name, item in value.items() if name not in fields}


def verify_signature(body, signature, public_key, domain, *, signer=None):
    if not isinstance(signature, dict):
        return False
    if signature.get("algorithm") != "ed25519":
        return False
    if signer is not None and signature.get("signer") != signer:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(decode_base64url(public_key)).verify(
            decode_base64url(signature.get("value")),
            (domain + digest(body)).encode("ascii"),
        )
    except (TypeError, ValueError, InvalidSignature):
        return False
    return True


def apply_patch(value, operation):
    path = operation["path"]
    if not path:
        if operation["op"] in {"add", "replace"}:
            return copy.deepcopy(operation["value"])
        raise ValueError("cannot remove the document root")
    parent = value
    for segment in path[:-1]:
        parent = parent[segment]
    leaf = path[-1]
    if operation["op"] == "remove":
        if isinstance(parent, list):
            parent.pop(leaf)
        else:
            del parent[leaf]
    elif operation["op"] == "replace":
        parent[leaf] = copy.deepcopy(operation["value"])
    elif operation["op"] == "add":
        if isinstance(parent, list):
            parent.insert(leaf, copy.deepcopy(operation["value"]))
        else:
            parent[leaf] = copy.deepcopy(operation["value"])
    else:
        raise ValueError(f"unknown patch operation: {operation['op']}")
    return value


def materialize(data, vector):
    value = copy.deepcopy(data["fixtures"][vector["base"]])
    for operation in vector["patch"]:
        value = apply_patch(value, operation)
    value.update({name: vector[name] for name in CASE_FIELDS if name in vector and name != "patch"})
    return value


def ref_shape(ref):
    if not isinstance(ref, dict):
        return False
    if not isinstance(ref.get("railId"), str) or not ref["railId"]:
        return False
    if "railVersion" in ref and (
        type(ref["railVersion"]) is not int or ref["railVersion"] <= 0
    ):
        return False
    return "parameters" not in ref or isinstance(ref["parameters"], dict)


def verify_listing(vector):
    listing = vector.get("listing")
    signature = listing.get("signature") if isinstance(listing, dict) else None
    expected_signer = vector.get("runtime", {}).get("listingPublisherClaim")
    return isinstance(listing, dict) and verify_signature(
        unsigned(listing, "signature"), signature, vector["keys"]["seller"],
        "dacs-listing:v1:", signer=expected_signer,
    )


def verify_definition(vector, definition):
    signature = definition.get("signature") if isinstance(definition, dict) else None
    expected_signer = vector.get("registry", {}).get("stewardClaim")
    return isinstance(definition, dict) and verify_signature(
        unsigned(definition, "signature"), signature, vector["keys"]["steward"],
        "dacs-rail:v1:", signer=expected_signer,
    )


def verify_agreement(vector):
    agreement = vector.get("agreement")
    if not isinstance(agreement, dict):
        return False
    body = unsigned(agreement, "signatures")
    parties = agreement.get("parties")
    signatures = agreement.get("signatures")
    if not isinstance(parties, list) or not isinstance(signatures, list):
        return False
    claims = {party.get("role"): party.get("primaryClaim") for party in parties}
    if set(claims) != {"buyer", "seller"} or len(signatures) != 2:
        return False
    by_party = {item.get("party"): item for item in signatures if isinstance(item, dict)}
    if len(by_party) != 2:
        return False
    return all(
        verify_signature(
            body, by_party.get(claims[role]), vector["keys"][role],
            "dacs-payee-bound-agreement:v1:",
        )
        for role in ("buyer", "seller")
    )


def verify_bundle(vector):
    bundle = vector.get("bundle")
    signatures = bundle.get("signatures") if isinstance(bundle, dict) else None
    if not isinstance(bundle, dict) or not isinstance(signatures, list) or len(signatures) != 2:
        return False
    body = unsigned(bundle, "signatures", "anchoredByRole")
    claims = {
        party["role"]: party["primaryClaim"]
        for party in vector["agreement"]["parties"]
    }
    by_party = {item.get("party"): item for item in signatures if isinstance(item, dict)}
    return len(by_party) == 2 and all(
        verify_signature(
            body, by_party.get(claims[role]), vector["keys"][role],
            "dacs-evidence-bound-fault-bundle:v1:",
        )
        for role in ("buyer", "seller")
    )


def canonical_key(value):
    return jcs_canonicalize(value)


def listing_gate(vector):
    if not verify_listing(vector):
        return "fail", "listing-signature", None, None
    listing = vector["listing"]
    pipeline = listing.get("pipeline")
    accepted = listing.get("acceptedRails")
    if not isinstance(pipeline, list) or not pipeline or not isinstance(accepted, list) or not accepted:
        return "fail", "listing-shape", None, None
    if not all(ref_shape(ref) for ref in accepted):
        return "fail", "accepted-ref-shape", None, None
    accepted_keys = [canonical_key(ref) for ref in accepted]
    if len(set(accepted_keys)) != len(accepted_keys):
        return "fail", "accepted-duplicate", None, None

    alternative_indexes = [
        index for index, phase in enumerate(pipeline)
        if isinstance(phase, dict) and phase.get("kind") == "pay-alternative"
    ]
    concrete_indexes = [
        index for index, phase in enumerate(pipeline)
        if isinstance(phase, dict) and phase.get("kind") in CONCRETE_PAYMENT_HANDLERS
    ]
    alternative_index = None
    alternatives = None
    if alternative_indexes:
        if not vector["runtime"].get("readerSupportsPayAlternative"):
            return "fail", "unsupported-phase", None, None
        if len(alternative_indexes) != 1:
            return "fail", "alternative-slot-cardinality", None, None
        if concrete_indexes:
            return "fail", "alternative-concrete-sibling", None, None
        alternative_index = alternative_indexes[0]
        phase = pipeline[alternative_index]
        parameters = phase.get("parameters")
        if not isinstance(parameters, dict) or set(parameters) != {"alternatives"}:
            return "fail", "alternative-parameters", None, None
        alternatives = parameters["alternatives"]
        if not isinstance(alternatives, list) or len(alternatives) < 2:
            return "fail", "alternative-cardinality", None, None
        if not all(ref_shape(ref) for ref in alternatives):
            return "fail", "alternative-ref-shape", None, None
        alternative_keys = [canonical_key(ref) for ref in alternatives]
        if len(set(alternative_keys)) != len(alternative_keys):
            return "fail", "alternative-duplicate", None, None
        if any(key not in accepted_keys for key in alternative_keys):
            return "fail", "alternative-membership", None, None
    else:
        for index in concrete_indexes:
            phase = pipeline[index]
            parameters = phase.get("parameters")
            if not isinstance(parameters, dict) or set(parameters) != {"rail"}:
                return "fail", "concrete-parameters", None, None
            if not isinstance(parameters["rail"], str):
                return "fail", "concrete-parameters", None, None
            if parameters["rail"] not in {ref["railId"] for ref in accepted}:
                return "fail", "concrete-membership", None, None

    registry = vector.get("registry")
    if not isinstance(registry, dict) or not registry.get("authorityAuthenticated"):
        return "indeterminate", "registry-authority", None, None
    snapshot = registry.get("snapshotId")
    resolutions = registry.get("resolutions")
    if not isinstance(snapshot, str) or not isinstance(resolutions, list):
        return "indeterminate", "registry-authority", None, None
    resolved = {}
    handlers_by_id = {}
    pending_reason = None
    for ref, ref_key in zip(accepted, accepted_keys):
        matches = [
            item for item in resolutions
            if isinstance(item, dict) and canonical_key(item.get("ref")) == ref_key
        ]
        if not matches:
            return "fail", "definition-missing", None, None
        if len(matches) != 1:
            return "fail", "definition-ambiguous", None, None
        resolution = matches[0]
        if resolution.get("snapshotId") != snapshot:
            return "fail", "registry-snapshot", None, None
        if resolution.get("status") == "unavailable":
            pending_reason = "definition-unavailable"
            continue
        if resolution.get("status") != "verified":
            return "fail", "definition-status", None, None
        definition = resolution.get("definition")
        if not verify_definition(vector, definition):
            return "fail", "definition-signature", None, None
        if definition.get("railId") != ref["railId"]:
            return "fail", "definition-ref", None, None
        if "railVersion" in ref and definition.get("railVersion") != ref["railVersion"]:
            return "fail", "definition-ref", None, None
        handler = definition.get("phaseHandler")
        if handler not in CONCRETE_PAYMENT_HANDLERS:
            return "fail", "handler-unsupported", None, None
        if handler not in vector["runtime"].get("supportedHandlers", []):
            return "fail", "handler-unsupported", None, None
        previous = handlers_by_id.setdefault(ref["railId"], handler)
        if previous != handler:
            return "fail", "handler-invariance", None, None
        resolved[ref_key] = definition
    if pending_reason:
        return "indeterminate", pending_reason, None, None

    for index in concrete_indexes:
        phase = pipeline[index]
        rail_id = phase["parameters"]["rail"]
        if any(
            definition["phaseHandler"] != phase["kind"]
            for ref_key, definition in resolved.items()
            if json.loads(ref_key)["railId"] == rail_id
        ):
            return "fail", "concrete-handler", None, None
    return "pass", None, resolved, alternative_index


def project_and_bind(vector, resolved, alternative_index):
    listing = vector["listing"]
    agreement = vector["agreement"]
    selected = agreement.get("terms", {}).get("rail")
    if not ref_shape(selected):
        return "fail", "selection-shape", None
    selected_key = canonical_key(selected)
    if alternative_index is not None:
        alternatives = listing["pipeline"][alternative_index]["parameters"]["alternatives"]
        if [canonical_key(ref) for ref in alternatives].count(selected_key) != 1:
            return "fail", "selection-membership", None
    elif selected_key not in {canonical_key(ref) for ref in listing["acceptedRails"]}:
        return "fail", "selection-membership", None
    definition = resolved.get(selected_key)
    if definition is None:
        return "fail", "selection-resolution", None
    availability = definition.get("availability")
    if availability in {"disabled", "failed"}:
        return "fail", "selected-availability", None
    if availability == "mocked":
        return "fail", "selected-availability", None
    if availability in {"operator_gated", "closed_data", "bilateral"} and not vector["runtime"].get("operatorPreflightOk"):
        return "fail", "selected-availability", None

    effective = copy.deepcopy(listing["pipeline"])
    if alternative_index is not None:
        effective[alternative_index] = {
            "kind": definition["phaseHandler"],
            "parameters": {"rail": selected["railId"]},
        }
        if canonical_key(vector["runtime"].get("projectedStep")) != canonical_key(effective[alternative_index]):
            return "fail", "projection-mismatch", None

    expected_bindings = sorted(
        (index, selected["railId"])
        for index, phase in enumerate(effective)
        if phase.get("kind") in CONCRETE_PAYMENT_HANDLERS
    )
    bindings = agreement.get("terms", {}).get("payoutBindings")
    if not isinstance(bindings, list):
        return "fail", "payout-binding", None
    actual_bindings = sorted(
        (binding.get("phaseIndex"), binding.get("railId"))
        for binding in bindings if isinstance(binding, dict)
    )
    if len(actual_bindings) != len(bindings) or actual_bindings != expected_bindings:
        return "fail", "payout-binding", None
    return "pass", None, effective


def evaluate(vector, effects=None):
    if effects is None:
        effects = {"walletAuthorizations": 0}
    verdict, reason, resolved, alternative_index = listing_gate(vector)
    if verdict != "pass":
        return verdict, reason
    operation = vector["operation"]
    if operation == "validate-listing":
        return "pass", None

    agreement = vector["agreement"]
    if operation == "select-draft":
        if vector["runtime"].get("agreementSignatureProduced") or agreement.get("signatures"):
            return "fail", "agreement-already-signed"
    else:
        if not verify_agreement(vector):
            return "fail", "agreement-signature"
        listing_ref = agreement.get("listingRef")
        expected_ref = {
            "listingId": vector["listing"]["listingId"],
            "version": vector["listing"]["listingVersion"],
            "contentHash": digest(unsigned(vector["listing"], "signature")),
        }
        if listing_ref != expected_ref:
            return "fail", "agreement-listing-ref"
        if not vector["runtime"].get("agreementSignatureProduced"):
            return "fail", "agreement-signature-state"

    verdict, reason, effective = project_and_bind(vector, resolved, alternative_index)
    if verdict != "pass":
        return verdict, reason
    if operation == "select-draft":
        return "pass", None

    selected = agreement["terms"]["rail"]
    prior_selection = vector["runtime"].get("priorSelection")
    prior_job_id = vector["runtime"].get("priorJobId")
    if prior_selection is not None and canonical_key(prior_selection) != canonical_key(selected):
        if prior_job_id == agreement["jobId"]:
            return "fail", "fresh-job-required"
    requested = vector["runtime"].get("requestedAlternative")
    if requested is not None and canonical_key(requested) != canonical_key(selected):
        if vector["runtime"].get("authorizationState") in {"submitted", "indeterminate"}:
            return "fail", "fallback-forbidden"
        return "fail", "fresh-job-required"

    if operation == "retry":
        reconciliation = vector["runtime"].get("reconciliation")
        expected = {
            "jobId": agreement["jobId"],
            "railRefHash": digest(selected),
            "phaseIndex": next(
                index for index, phase in enumerate(effective)
                if phase.get("kind") in CONCRETE_PAYMENT_HANDLERS
            ),
        }
        if reconciliation != expected:
            return "fail", "reconciliation-tuple"
        return "pass", "reconciliation-pending"
    if operation == "validate-pipeline":
        return "pass", None
    if operation == "verify-bundle":
        if not verify_bundle(vector):
            return "fail", "bundle-signature"
        bundle = vector["bundle"]
        if bundle.get("jobId") != agreement["jobId"]:
            return "fail", "bundle-job"
        if bundle.get("listingRef") != agreement["listingRef"]:
            return "fail", "bundle-listing-ref"
        if bundle.get("agreementRef") != {"contentHash": digest(unsigned(agreement, "signatures"))}:
            return "fail", "bundle-agreement-ref"
        expected_summary = [
            (index, phase["kind"]) for index, phase in enumerate(effective)
        ]
        actual_summary = [
            (entry.get("index"), entry.get("kind"))
            for entry in bundle.get("phaseSummary", []) if isinstance(entry, dict)
        ]
        if actual_summary != expected_summary:
            return "fail", "bundle-effective-pipeline"
        expected_evidence = [
            (index, phase["kind"])
            for index, phase in enumerate(effective)
            if phase["kind"].startswith(("pay-", "deliver-"))
        ]
        actual_evidence = [
            (entry.get("phaseIndex"), entry.get("phase"))
            for entry in bundle.get("settlementEvidence", []) if isinstance(entry, dict)
        ]
        if actual_evidence != expected_evidence:
            return "fail", "evidence-effective-pipeline"
        return "pass", None
    if operation == "execute":
        effects["walletAuthorizations"] += 1
        return "pass", None
    return "error", "unsupported-operation"


class AlternativePaymentProjectionVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.vectors = [materialize(cls.data, vector) for vector in cls.data["vectors"]]
        cls.by_name = {vector["name"]: vector for vector in cls.vectors}

    def test_generated_file_is_current(self):
        result = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"], cwd=ROOT,
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_hash_count_and_names_are_exact(self):
        compact = self.data["vectors"]
        self.assertEqual(self.data["count"], len(compact))
        self.assertEqual(len(compact), len(self.by_name))
        self.assertEqual(self.data["hash"], hashlib.sha256(canonical_bytes(compact)).hexdigest())

    def test_every_vector_executes_to_pinned_verdict_and_reason(self):
        for vector in self.vectors:
            with self.subTest(vector=vector["name"]):
                verdict, reason = evaluate(vector)
                self.assertEqual(verdict, vector["expected"])
                if "expectedReason" in vector:
                    self.assertEqual(reason, vector["expectedReason"])

    def test_all_failure_and_indeterminate_paths_are_pre_authorization(self):
        for vector in self.vectors:
            effects = {"walletAuthorizations": 0}
            verdict, _ = evaluate(vector, effects)
            if verdict != "pass":
                with self.subTest(vector=vector["name"]):
                    self.assertEqual(effects["walletAuthorizations"], 0)

    def test_only_successful_execute_authorizes_once(self):
        for vector in self.vectors:
            effects = {"walletAuthorizations": 0}
            verdict, _ = evaluate(vector, effects)
            expected_calls = int(verdict == "pass" and vector["operation"] == "execute")
            with self.subTest(vector=vector["name"]):
                self.assertEqual(effects["walletAuthorizations"], expected_calls)

    def test_signed_artifacts_are_real_and_mutation_is_detected(self):
        vector = self.by_name["select-dem-projects-pay-dem"]
        self.assertTrue(verify_listing(vector))
        self.assertTrue(verify_agreement(vector))
        self.assertTrue(verify_bundle(vector))
        for resolution in vector["registry"]["resolutions"]:
            self.assertTrue(verify_definition(vector, resolution["definition"]))

        mutations = (
            ("listing", "listingId", "substituted"),
            ("agreement", "jobId", "01ATTACKER00000000000000000"),
            ("bundle", "outcome", "failed-perm"),
        )
        for artifact, field, value in mutations:
            mutated = copy.deepcopy(vector)
            mutated[artifact][field] = value
            with self.subTest(artifact=artifact):
                verifier = {
                    "listing": verify_listing,
                    "agreement": verify_agreement,
                    "bundle": verify_bundle,
                }[artifact]
                self.assertFalse(verifier(mutated))

    def test_projection_preserves_index_and_array_order_is_not_selection(self):
        dem = self.by_name["select-dem-projects-pay-dem"]
        x402 = self.by_name["select-x402-projects-pay-x402"]
        reordered = self.by_name["alternative-array-order-does-not-select"]
        self.assertEqual(dem["runtime"]["projectedStep"]["kind"], "pay-dem")
        self.assertEqual(x402["runtime"]["projectedStep"]["kind"], "pay-x402")
        self.assertEqual(reordered["agreement"]["terms"]["rail"], x402["agreement"]["terms"]["rail"])
        self.assertNotEqual(
            reordered["listing"]["pipeline"][2]["parameters"]["alternatives"],
            x402["listing"]["pipeline"][2]["parameters"]["alternatives"],
        )
        for vector in (dem, x402, reordered):
            self.assertEqual(vector["agreement"]["terms"]["payoutBindings"][0]["phaseIndex"], 2)

    def test_retry_never_authorizes_a_second_rail(self):
        for vector in self.vectors:
            if vector["operation"] != "retry":
                continue
            effects = {"walletAuthorizations": 0}
            evaluate(vector, effects)
            with self.subTest(vector=vector["name"]):
                self.assertEqual(effects["walletAuthorizations"], 0)

    def test_legacy_reader_refuses_the_choice_phase(self):
        vector = self.by_name["legacy-reader-refuses-unknown-choice-phase"]
        self.assertTrue(any(
            phase["kind"] == "pay-alternative" for phase in vector["listing"]["pipeline"]
        ))
        self.assertEqual(evaluate(vector), ("fail", "unsupported-phase"))

    def test_ordinary_repeated_pay_keeps_two_independent_invocations(self):
        vector = self.by_name["ordinary-repeated-pay-retains-pipe5"]
        phases = [
            (index, phase["kind"]) for index, phase in enumerate(vector["listing"]["pipeline"])
            if phase["kind"] in CONCRETE_PAYMENT_HANDLERS
        ]
        self.assertEqual(phases, [(2, "pay-dem"), (4, "pay-dem")])
        self.assertEqual(evaluate(vector), ("pass", None))

    def test_normative_surfaces_link_all_eight_rules(self):
        combined = "\n".join(path.read_text(encoding="utf-8") for path in SPECS)
        for number in range(1, 9):
            self.assertIn(f"(APR-{number})", combined)
        self.assertIn("listing-only `pay-alternative`", combined)
        self.assertIn("fresh `jobId`", combined)
        self.assertIn("make zero authorization calls on another alternative", combined)


if __name__ == "__main__":
    unittest.main()
