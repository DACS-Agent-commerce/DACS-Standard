import base64
import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = (
    ROOT / "conformance" / "fixtures" / "identity"
    / "dacs1-vet-golden-inputs-v0.1.json"
)
MANIFEST = ROOT / "conformance" / "MANIFEST.json"
GENERATOR = ROOT / "scripts" / "generate_dacs1_vet_golden_inputs.py"
BUNDLE_DOMAIN = "dacs-bundle-presentation:v1:"
RESULT_DOMAIN = "dacs-verifyresult:v1:"
KNOWN_SCHEMES = {
    "key", "lei", "cci-lei", "did", "finra-crd", "domain",
}
KEY = re.compile(r"^[0-9a-f]{64}$")
SAFE_INT = 9_007_199_254_740_991


def canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def hash_hex(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def b64url_decode(value):
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("non-canonical Base64URL")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError("non-canonical Base64URL")
    return decoded


def parse_ref(value):
    if not isinstance(value, str) or ":" not in value:
        raise ValueError("malformed ClaimReference")
    scheme, identifier = value.split(":", 1)
    if scheme not in KNOWN_SCHEMES or not identifier:
        raise ValueError("unknown or empty ClaimReference")
    if scheme == "key" and not KEY.fullmatch(identifier):
        raise ValueError("key identifiers are 32-byte lowercase hex")
    return scheme, identifier


def all_safe_integers(value):
    if isinstance(value, bool):
        return True
    if isinstance(value, int):
        return -SAFE_INT <= value <= SAFE_INT
    if isinstance(value, dict):
        return all(all_safe_integers(item) for item in value.values())
    if isinstance(value, list):
        return all(all_safe_integers(item) for item in value)
    return True


def verify_signature(public_ref, signature, payload):
    try:
        scheme, public_hex = parse_ref(public_ref)
        if scheme != "key":
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
            b64url_decode(signature), payload
        )
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def well_formed_result_ref(value):
    if not isinstance(value, dict) or set(value) != {
        "anchor", "contentHash", "recipeVersion"
    }:
        return False
    anchor = value.get("anchor")
    return (
        isinstance(anchor, dict)
        and set(anchor) == {"kind", "locator"}
        and anchor.get("kind") in {"storage-program", "ipfs", "https"}
        and isinstance(anchor.get("locator"), str)
        and bool(anchor["locator"])
        and isinstance(value.get("contentHash"), str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", value["contentHash"]))
        and type(value.get("recipeVersion")) is int
        and value["recipeVersion"] >= 1
    )


def verify_bundle(bundle):
    if not isinstance(bundle, dict) or not all_safe_integers(bundle):
        return False
    if set(bundle) - {
        "bundleVersion", "presentedBy", "presentedAt", "sessionNonce",
        "claims", "presentation",
    }:
        return False
    if not {
        "bundleVersion", "presentedBy", "presentedAt", "claims", "presentation"
    } <= set(bundle):
        return False
    if bundle.get("bundleVersion") != "1" or type(bundle.get("presentedAt")) is not int:
        return False
    claims = bundle.get("claims")
    if not isinstance(claims, list) or not claims:
        return False
    try:
        canonical_presented = parse_ref(bundle.get("presentedBy"))
        parsed_claims = [parse_ref(item.get("ref")) for item in claims]
    except (AttributeError, ValueError):
        return False
    if canonical_presented not in parsed_claims:
        return False
    presentation = bundle.get("presentation")
    if not isinstance(presentation, dict) or set(presentation) != {
        "kind", "signatures"
    } or presentation.get("kind") != "per-claim":
        return False
    signatures = presentation.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return False
    unsigned = {key: value for key, value in bundle.items() if key != "presentation"}
    payload = (BUNDLE_DOMAIN + hash_hex(unsigned)).encode("ascii")
    claim_refs = {item["ref"] for item in claims}
    return all(
        isinstance(item, dict)
        and set(item) == {"ref", "signature"}
        and item.get("ref") in claim_refs
        and verify_signature(item["ref"], item.get("signature"), payload)
        for item in signatures
    )


def verify_result(resolved):
    artifact = resolved.get("artifact")
    reference = resolved.get("ref")
    if not well_formed_result_ref(reference) or not isinstance(artifact, dict):
        return False
    signature = artifact.get("signature")
    if not isinstance(signature, dict) or set(signature) != {
        "algorithm", "signer", "value"
    } or signature.get("algorithm") != "ed25519":
        return False
    unsigned = {key: value for key, value in artifact.items() if key != "signature"}
    if hash_hex(unsigned) != reference["contentHash"]:
        return False
    return verify_signature(
        signature.get("signer"),
        signature.get("value"),
        (RESULT_DOMAIN + hash_hex(unsigned)).encode("ascii"),
    )


def resolved_by_ref(value):
    return {
        canonical_bytes(item["ref"]): item
        for item in value.get("resolvedResults", [])
    }


def matching_claims(value, req, exact_ref=None):
    now = value["evaluatedAt"]
    matches = []
    for item in value["bundle"]["claims"]:
        scheme, _ = parse_ref(item.get("ref"))
        if scheme != req.get("scheme"):
            continue
        if exact_ref is not None and item.get("ref") != exact_ref:
            continue
        expires_at = item.get("expiresAt")
        if expires_at is not None and (
            type(expires_at) is not int or now > expires_at
        ):
            continue
        parameters = req.get("parameters")
        if parameters is not None:
            metadata = item.get("metadata")
            if not isinstance(metadata, dict) or any(
                metadata.get(key) != item for key, item in parameters.items()
            ):
                continue
        matches.append(item)
    return matches


def result_outcome(value, claim, req):
    reference = claim.get("verifiedBy")
    if not well_formed_result_ref(reference):
        return "fail" if reference is None else "error"
    resolved = resolved_by_ref(value).get(canonical_bytes(reference))
    if resolved is None:
        return "indeterminate"
    if not verify_result(resolved):
        return "error"
    result = resolved["artifact"]
    scheme, identifier = parse_ref(claim["ref"])
    if (
        result.get("scheme") != scheme
        or result.get("identifier") != identifier
        or result.get("recipeVersion") != reference["recipeVersion"]
        or result.get("recipeVersion") != req.get("recipeVersion")
    ):
        return "fail"
    decision = result.get("decision")
    if decision not in {"pass", "fail", "indeterminate", "error"}:
        return "error"
    if decision != "pass":
        return decision
    verified_at = result.get("verifiedAt")
    valid_until = result.get("validUntil")
    if type(verified_at) is not int or type(valid_until) is not int:
        return "fail"
    now = value["evaluatedAt"]
    expires_at = claim.get("expiresAt")
    effective_expiry = min(
        valid_until,
        expires_at if type(expires_at) is int else SAFE_INT,
    )
    if valid_until < verified_at or now > effective_expiry:
        return "fail"
    max_age = req.get("maxAge")
    if max_age is not None and now > verified_at + max_age * 1_000:
        return "fail"
    return "pass"


def classify_member(value, req, exact_ref=None):
    matches = matching_claims(value, req, exact_ref)
    if req.get("verificationRequired") is False:
        return "pass" if matches else "fail"
    outcomes = [result_outcome(value, item, req) for item in matches]
    for outcome in ("pass", "fail", "error", "indeterminate"):
        if outcome in outcomes:
            return outcome
    return "fail"


def presented_control(value):
    bundle = value["bundle"]
    presented = bundle["presentedBy"]
    scheme, _ = parse_ref(presented)
    claim = next(item for item in bundle["claims"] if item["ref"] == presented)
    signer_refs = {
        item["ref"] for item in bundle["presentation"]["signatures"]
    }
    if scheme == "key":
        return presented in signer_refs
    reference = claim.get("verifiedBy")
    if not well_formed_result_ref(reference):
        return False
    resolved = resolved_by_ref(value).get(canonical_bytes(reference))
    if resolved is None or not verify_result(resolved):
        return False
    result = resolved["artifact"]
    binding = result.get("data", {}).get("holderBinding")
    return (
        result_outcome(
            value,
            claim,
            {"scheme": scheme, "verificationRequired": True,
             "recipeVersion": reference["recipeVersion"]},
        ) == "pass"
        and result.get("method") == "vlei-presentation"
        and isinstance(binding, dict)
        and binding.get("controller") in signer_refs
    )


def selector_authorized(value, req):
    selector = req.get("primaryClaimSelector")
    if selector is None:
        return True
    bundle = value["bundle"]
    scheme, _ = parse_ref(bundle["presentedBy"])
    if scheme != selector or not presented_control(value):
        return False
    required = req.get("required", [])
    one_of = req.get("oneOf", [])
    if any(
        item.get("scheme") == selector
        and item.get("verificationRequired") is True
        for item in required
    ):
        selected_req = next(
            item for item in required
            if item.get("scheme") == selector
            and item.get("verificationRequired") is True
        )
        return classify_member(
            value, selected_req, exact_ref=bundle["presentedBy"]
        ) == "pass"
    presence_members = [
        item for item in required
        if item.get("scheme") == selector
        and item.get("verificationRequired") is False
    ]
    if any(
        classify_member(value, item, exact_ref=bundle["presentedBy"]) == "pass"
        for item in presence_members
    ):
        return True
    for group in one_of:
        if any(
            item.get("scheme") == selector
            and item.get("verificationRequired") is False
            and classify_member(
                value, item, exact_ref=bundle["presentedBy"]
            ) == "pass"
            for item in group
        ):
            return True
    return False


def valid_requirement(req):
    if not isinstance(req, dict) or req.get("requirementVersion") != "1":
        return False
    required = req.get("required")
    one_of = req.get("oneOf", [])
    if not isinstance(required, list) or not isinstance(one_of, list):
        return False
    if any(not isinstance(group, list) or not group for group in one_of):
        return False
    for item in [*required, *(member for group in one_of for member in group)]:
        if (
            not isinstance(item, dict)
            or item.get("scheme") not in KNOWN_SCHEMES
            or type(item.get("verificationRequired")) is not bool
            or (
                item.get("verificationRequired") is False
                and ("maxAge" in item or "recipeVersion" in item)
            )
        ):
            return False
    return True


def evaluate_decision(value):
    if not verify_bundle(value.get("bundle")):
        return "error"
    req = value.get("requirement")
    if not valid_requirement(req):
        return "error"
    for item in value["bundle"]["claims"]:
        if "verifiedBy" in item and not well_formed_result_ref(item["verifiedBy"]):
            return "error"
    failures = []
    errors = []
    indeterminates = []
    for item in req.get("required", []):
        outcome = classify_member(value, item)
        (failures if outcome == "fail" else
         errors if outcome == "error" else
         indeterminates if outcome == "indeterminate" else []).append(outcome)
    for group in req.get("oneOf", []):
        outcomes = [classify_member(value, item) for item in group]
        if "pass" in outcomes:
            continue
        if "error" in outcomes:
            errors.append("oneOf")
        elif "indeterminate" in outcomes:
            indeterminates.append("oneOf")
        else:
            failures.append("oneOf")
    if not selector_authorized(value, req):
        failures.append("selector")
    if failures:
        return "fail"
    if errors:
        return "error"
    if indeterminates:
        return "indeterminate"
    return "pass"


def aggregate_output(value):
    decision = evaluate_decision(value)
    out = {"decision": decision}
    if decision == "error":
        failure_class = next(
            (
                item.get("failureClass")
                for item in value.get("resolvedResults", [])
                if item.get("artifact", {}).get("decision") == "error"
            ),
            None,
        )
        if failure_class:
            out["errorClass"] = failure_class
    elif decision == "fail":
        out["errorClass"] = "permanent"
    return out


def execute(evaluation):
    operation = evaluation["operation"]
    value = evaluation["input"]
    if operation == "match":
        return evaluate_decision(value) == "pass"
    if operation == "decision":
        return evaluate_decision(value)
    if operation == "decision-no-throw":
        try:
            return {"decision": evaluate_decision(value), "throws": False}
        except Exception:  # the vector explicitly proves this boundary
            return {"decision": "error", "throws": True}
    if operation == "control-decision":
        if not verify_bundle(value.get("bundle")):
            return "error"
        return "pass" if presented_control(value) else "fail"
    if operation == "aggregate":
        return aggregate_output(value)
    raise AssertionError(f"unknown operation {operation!r}")


def execute_case(case):
    observed = {
        name: execute(evaluation)
        for name, evaluation in case["evaluations"].items()
    }
    return observed["result"] if list(observed) == ["result"] else observed


class Dacs1VetGoldenInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = FIXTURE.read_bytes()
        cls.document = json.loads(cls.raw)
        cls.cases = cls.document["cases"]

    def test_generator_is_deterministic(self):
        subprocess.run(
            ["python3", str(GENERATOR), "--check"], cwd=ROOT, check=True
        )

    def test_count_set_hash_names_and_input_hashes(self):
        self.assertEqual("dacs1-vet-golden-inputs-v0.1", self.document["set"])
        self.assertEqual(24, self.document["count"])
        self.assertEqual(24, len(self.cases))
        self.assertEqual(24, len({case["name"] for case in self.cases}))
        self.assertEqual(self.document["hash"], hash_hex(self.cases))
        for case in self.cases:
            with self.subTest(case=case["name"]):
                self.assertEqual(
                    case["inputHash"],
                    hash_hex({"evaluations": case["evaluations"]}),
                )

    def test_every_complete_input_replays_to_expected_output(self):
        for case in self.cases:
            with self.subTest(case=case["name"]):
                self.assertEqual(case["expectedOutput"], execute_case(case))

    def test_manifest_binds_exact_file_cases_and_outputs(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        binding = manifest["inputBindings"][self.document["set"]]
        self.assertEqual(str(FIXTURE.relative_to(ROOT)), binding["path"])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), binding["sha256"])
        self.assertEqual(24, binding["caseCount"])
        fixture_by_name = {case["name"]: case for case in self.cases}
        manifest_cases = {
            case["id"]: case
            for case in manifest["cases"]
            if case["id"] in fixture_by_name
        }
        self.assertEqual(set(fixture_by_name), set(manifest_cases))
        for name, case in fixture_by_name.items():
            with self.subTest(case=name):
                self.assertEqual(case["expectedOutput"], manifest_cases[name]["want"])

    def test_all_non_malformed_bundles_and_all_results_are_genuinely_signed(self):
        for case in self.cases:
            for label, evaluation in case["evaluations"].items():
                with self.subTest(case=case["name"], evaluation=label):
                    bundle_ok = verify_bundle(evaluation["input"]["bundle"])
                    if case["name"] == "vet-control-key-malformed-scope-reject-no-throw":
                        self.assertFalse(bundle_ok)
                    else:
                        self.assertTrue(bundle_ok)
                    for resolved in evaluation["input"]["resolvedResults"]:
                        self.assertTrue(verify_result(resolved))


if __name__ == "__main__":
    unittest.main()
