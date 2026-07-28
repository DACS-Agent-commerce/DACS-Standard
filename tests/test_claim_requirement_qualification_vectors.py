import base64
import binascii
import hashlib
import json
import unicodedata
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "vectors" / "security" / "claim-requirement-qualification-v0.3.json"
SPEC = ROOT / "spec" / "DACS-2-VET.md"


def canonical_json(value):
    def normalize(item):
        if isinstance(item, str):
            return unicodedata.normalize("NFC", item)
        if isinstance(item, list):
            return [normalize(value) for value in item]
        if isinstance(item, dict):
            return {key: normalize(value) for key, value in item.items()}
        return item

    return json.dumps(normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def decode_base64url_unpadded(value):
    if not isinstance(value, str) or "=" in value:
        raise ValueError("not unpadded base64url")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("invalid base64url") from error
    if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise ValueError("non-canonical base64url")
    return decoded


def bundle_hash(bundle):
    unsigned = {key: value for key, value in bundle.items() if key not in ("signatures", "anchoredByRole")}
    return hashlib.sha256(canonical_json(unsigned)).hexdigest()


def verify_replay_bundle(bundle, public_keys):
    if not isinstance(bundle, dict) or bundle.get("bundleVersion") != "1":
        return False
    parties = bundle.get("parties")
    signatures = bundle.get("signatures")
    if not isinstance(parties, list) or not isinstance(signatures, list):
        return False
    claims_by_role = {
        party.get("role"): party.get("primaryClaim")
        for party in parties
        if isinstance(party, dict)
    }
    required = {claims_by_role.get("buyer"), claims_by_role.get("seller")}
    if "orchestrator" in claims_by_role:
        required.add(claims_by_role["orchestrator"])
    if None in required:
        return False
    payload = ("dacs-bundle:v1:" + bundle_hash(bundle)).encode()
    seen = set()
    try:
        for signature in signatures:
            party = signature["party"]
            if party in seen or signature.get("algorithm") != "ed25519":
                return False
            public_key = public_keys.get(party)
            if not isinstance(public_key, str):
                return False
            Ed25519PublicKey.from_public_bytes(decode_base64url_unpadded(public_key)).verify(
                decode_base64url_unpadded(signature["value"]), payload
            )
            seen.add(party)
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False
    return required.issubset(seen)


def verify_signed_artifact(artifact, reference, domain, public_keys):
    if not isinstance(artifact, dict) or not isinstance(reference, dict):
        return False
    signature = artifact.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519":
        return False
    unsigned = {key: value for key, value in artifact.items() if key != "signature"}
    content_hash = hashlib.sha256(canonical_json(unsigned)).hexdigest()
    if reference.get("contentHash") != content_hash:
        return False
    signer = signature.get("signer")
    if "signer" in reference and reference.get("signer") != signer:
        return False
    public_key = public_keys.get(signer)
    if not isinstance(public_key, str):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(decode_base64url_unpadded(public_key)).verify(
            decode_base64url_unpadded(signature["value"]), (domain + content_hash).encode()
        )
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False
    return True


def verify_replay_record(input_data, authority, vector_set):
    material = vector_set["replayRecords"].get(authority.get("record"))
    if not isinstance(material, dict):
        return False
    record_ref = authority.get("recordRef")
    if canonical_json(record_ref) != canonical_json(material.get("recordRef")):
        return False
    record = material.get("record")
    if not verify_signed_artifact(
        record, record_ref, "dacs-composite:v1:", vector_set["publicKeys"]
    ):
        return False
    if record.get("jobId") != input_data.get("recordJobId"):
        return False
    if record.get("generatedAt") != input_data.get("generatedAt"):
        return False
    requirement_hash = hashlib.sha256(canonical_json(input_data.get("requirement"))).hexdigest()
    if record.get("requirementHash") != requirement_hash:
        return False
    record_result_refs = record.get("freshness", []) + record.get("dealSpecific", [])
    authenticated_results = material.get("results")
    declared_results = input_data.get("resolvedResults")
    if not isinstance(authenticated_results, list) or not isinstance(declared_results, list):
        return False
    if len(authenticated_results) != len(declared_results):
        return False
    for authenticated, declared in zip(authenticated_results, declared_results):
        if not isinstance(authenticated, dict) or not isinstance(declared, dict):
            return False
        result_ref = authenticated.get("ref")
        result = authenticated.get("result")
        if canonical_json(result_ref) not in {canonical_json(ref) for ref in record_result_refs}:
            return False
        if result_ref.get("recipeVersion") != result.get("recipeVersion"):
            return False
        if not verify_signed_artifact(
            result, result_ref, "dacs-verifyresult:v1:", vector_set["publicKeys"]
        ):
            return False
        projection = {key: result.get(key) for key in declared}
        if canonical_json(projection) != canonical_json(declared):
            return False
    return True


def resolve_authenticated_registry(
    input_data,
    vector_set,
    *,
    enforce_bundle_job=True,
    enforce_bundle_record_membership=True,
):
    authority = input_data.get("aggregationAuthority")
    if not isinstance(authority, dict):
        return None
    if authority.get("kind") == "production":
        vet_input = authority.get("vetInput")
        if not isinstance(vet_input, dict) or vet_input.get("jobId") != input_data.get("recordJobId"):
            return None
        session_context = vet_input.get("sessionContext")
        if not isinstance(session_context, dict) or session_context.get("jobId") != input_data.get("recordJobId"):
            return None
        authenticated_session_start = vector_set["authenticatedSessionStarts"].get(
            authority.get("sessionStart")
        )
        if canonical_json(session_context) != canonical_json(authenticated_session_start):
            return None
        registry_version = session_context.get("recipeRegistryVersion")
        if vet_input.get("recipeRegistryVersion") != registry_version:
            return None
    elif authority.get("kind") == "replay":
        bundle = vector_set["replayBundles"].get(authority.get("bundle"))
        if not verify_replay_bundle(bundle, vector_set["publicKeys"]):
            return None
        if enforce_bundle_job and bundle.get("jobId") != input_data.get("recordJobId"):
            return None
        record_ref = authority.get("recordRef")
        if not isinstance(record_ref, dict):
            return None
        if enforce_bundle_record_membership and canonical_json(record_ref) not in {
            canonical_json(ref) for ref in bundle.get("vetRecords", [])
        }:
            return None
        if not verify_replay_record(input_data, authority, vector_set):
            return None
        registry_version = bundle.get("recipeRegistryVersion")
    else:
        return None
    if not isinstance(registry_version, int) or isinstance(registry_version, bool):
        return None
    registries_by_version = {
        registry["recipeRegistryVersion"]: registry for registry in vector_set["recipeRegistries"]
    }
    registry = registries_by_version.get(registry_version)
    if not isinstance(registry, dict):
        return None
    if registry.get("recipeRegistryVersion") != registry_version:
        return None
    if not isinstance(registry.get("latestByScheme"), dict):
        return None
    return registry


def applicable_results(input_data, claim_requirement, latest_by_scheme):
    expected_version = claim_requirement.get("recipeVersion")
    if expected_version is None:
        expected_version = latest_by_scheme.get(claim_requirement["scheme"])
    if expected_version is None:
        return []

    results = []
    for result in input_data["resolvedResults"]:
        if result["scheme"] != claim_requirement["scheme"]:
            continue
        if result["recipeVersion"] != expected_version:
            continue
        if "maxAge" in claim_requirement:
            expires_at = result["verifiedAt"] + claim_requirement["maxAge"] * 1000
            if input_data["generatedAt"] > expires_at:
                continue
        results.append(result)
    return results


def parameters_match(result, claim_requirement):
    for key, expected in claim_requirement.get("parameters", {}).items():
        if key not in result.get("data", {}):
            return False
        if canonical_json(result["data"][key]) != canonical_json(expected):
            return False
    return True


def classify_required(input_data, claim_requirement, latest_by_scheme):
    same_scheme = [
        result
        for result in input_data["resolvedResults"]
        if result["scheme"] == claim_requirement["scheme"]
    ]
    if not same_scheme:
        return "fail"
    results = applicable_results(input_data, claim_requirement, latest_by_scheme)
    if not results:
        return "fail"
    if any(result["decision"] == "pass" and parameters_match(result, claim_requirement) for result in results):
        return "pass"
    if any(result["decision"] in ("pass", "fail") for result in results):
        return "fail"
    if any(result["decision"] == "error" for result in results):
        return "error"
    return "indeterminate"


def evaluate(input_data, vector_set, **authority_options):
    registry = resolve_authenticated_registry(input_data, vector_set, **authority_options)
    if registry is None:
        return "error"
    latest_by_scheme = registry["latestByScheme"]

    decisions = [
        classify_required(input_data, claim_requirement, latest_by_scheme)
        for claim_requirement in input_data["requirement"].get("required", [])
    ]
    for group in input_data["requirement"].get("oneOf", []):
        applicable_by_member = [
            (claim_requirement, applicable_results(input_data, claim_requirement, latest_by_scheme))
            for claim_requirement in group
        ]
        if any(
            result["decision"] == "pass" and parameters_match(result, claim_requirement)
            for claim_requirement, results in applicable_by_member
            for result in results
        ):
            decisions.append("pass")
        elif any(result["decision"] == "error" for _, results in applicable_by_member for result in results):
            decisions.append("error")
        elif any(result["decision"] == "indeterminate" for _, results in applicable_by_member for result in results):
            decisions.append("indeterminate")
        else:
            decisions.append("fail")

    for decision in ("fail", "error", "indeterminate"):
        if decision in decisions:
            return decision
    return "pass"


class ClaimRequirementQualificationVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_vector_hash_count_and_unique_names(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(self.data["hash"], hashlib.sha256(canonical_json(vectors)).hexdigest())
        names = [vector["name"] for vector in vectors]
        self.assertEqual(len(names), len(set(names)))

    def test_all_candidate_semantics(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(evaluate(vector["input"], self.data), vector["expected"])

    def test_omitted_version_uses_session_start_registry(self):
        vector = next(
            vector
            for vector in self.data["vectors"]
            if vector["name"] == "vet-claim-requirement-implicit-session-pin-rejects-old-version"
        )
        claim_requirement = vector["input"]["requirement"]["required"][0]
        registry = resolve_authenticated_registry(vector["input"], self.data)
        self.assertIsNotNone(registry)
        applicable = applicable_results(vector["input"], claim_requirement, registry["latestByScheme"])
        self.assertEqual([result["recipeVersion"] for result in applicable], [2])
        self.assertEqual(evaluate(vector["input"], self.data), "fail")
        self.assertTrue(parameters_match(vector["input"]["resolvedResults"][0], claim_requirement))

    def test_authority_failures_are_executable(self):
        expected = {
            "vet-claim-requirement-missing-session-context-error",
            "vet-claim-requirement-unresolvable-session-pin-error",
            "vet-claim-requirement-mismatched-session-job-error",
            "vet-claim-requirement-production-pin-mismatch-error",
            "vet-claim-requirement-unsigned-session-record-replay-error",
            "vet-claim-requirement-signed-bundle-job-substitution-error",
            "vet-claim-requirement-signed-bundle-missing-record-ref-error",
            "vet-claim-requirement-signed-bundle-record-projection-substitution-error",
            "vet-claim-requirement-signed-bundle-requirement-substitution-error",
        }
        vectors = {vector["name"]: vector for vector in self.data["vectors"]}
        self.assertTrue(expected.issubset(vectors))
        for name in expected:
            with self.subTest(vector=name):
                self.assertEqual(evaluate(vectors[name]["input"], self.data), "error")

    def test_replay_bundles_have_genuine_required_signatures(self):
        for name, bundle in self.data["replayBundles"].items():
            with self.subTest(bundle=name):
                self.assertTrue(verify_replay_bundle(bundle, self.data["publicKeys"]))

    def test_replay_record_and_result_material_is_hash_and_signature_bound(self):
        vector = next(
            vector
            for vector in self.data["vectors"]
            if vector["name"] == "vet-claim-requirement-signed-bundle-replay-pass"
        )
        self.assertTrue(
            verify_replay_record(vector["input"], vector["input"]["aggregationAuthority"], self.data)
        )

    def test_signed_bundle_replay_is_executable(self):
        vector = next(
            vector
            for vector in self.data["vectors"]
            if vector["name"] == "vet-claim-requirement-signed-bundle-replay-pass"
        )
        registry = resolve_authenticated_registry(vector["input"], self.data)
        self.assertEqual(registry["recipeRegistryVersion"], 7)
        self.assertEqual(evaluate(vector["input"], self.data), "pass")

    def test_replay_bundle_binding_mutations_are_killed(self):
        vectors = {vector["name"]: vector for vector in self.data["vectors"]}
        wrong_job = vectors["vet-claim-requirement-signed-bundle-job-substitution-error"]
        missing_record = vectors["vet-claim-requirement-signed-bundle-missing-record-ref-error"]
        self.assertEqual(evaluate(wrong_job["input"], self.data), "error")
        self.assertEqual(
            evaluate(wrong_job["input"], self.data, enforce_bundle_job=False),
            "fail",
            "removing only the bundle job guard must change the vector verdict",
        )
        self.assertEqual(evaluate(missing_record["input"], self.data), "error")
        self.assertEqual(
            evaluate(
                missing_record["input"],
                self.data,
                enforce_bundle_record_membership=False,
            ),
            "pass",
            "removing only bundle-to-record membership must make the otherwise-valid chain pass",
        )

    def test_spec_uses_authenticated_production_and_replay_authority(self):
        text = SPEC.read_text(encoding="utf-8")
        composite_type = text.split("type CompositeVerificationRecord = {", 1)[1].split("}", 1)[0]
        self.assertNotIn("recipeRegistryVersion", composite_type)
        self.assertIn("vetInput.recipeRegistryVersion != vetInput.sessionContext.recipeRegistryVersion", text)
        self.assertIn("orchestrator-owned active `SessionContext`", text)
        self.assertIn("verifiedBundle.vetRecords does not contain recordRef", text)
        self.assertIn("sha256(CORE-canonical(requirement)) != record.requirementHash", text)
        self.assertIn("An unsigned `SessionRecord` MUST NOT supply replay authority", text)
        self.assertIn("An omitted `ClaimRequirement.recipeVersion` therefore does not disable version qualification.", text)


if __name__ == "__main__":
    unittest.main()
