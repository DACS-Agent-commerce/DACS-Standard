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
VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "presence-only-claim-requirement-v0.7.json"
)
GENERATOR = ROOT / "scripts" / "generate_presence_only_claim_vectors.py"
DACS1 = ROOT / "spec" / "DACS-1-IDENTIFY.md"
DACS2 = ROOT / "spec" / "DACS-2-VET.md"
CONTROL_FIXTURE = ROOT / "conformance" / "fixtures" / "identity" / "control-gate-vectors.json"
BUNDLE_DOMAIN = "dacs-bundle-presentation:v1:"
VERIFY_RESULT_DOMAIN = "dacs-verifyresult:v1:"
COMPOSITE_DOMAIN = "dacs-composite:v1:"
KNOWN_SCHEMES = {"key", "lei", "did"}
KEY = re.compile(r"^[0-9a-f]{64}$")
LEI = re.compile(r"^[0-9A-Z]{20}$")


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
        raise ValueError("non-canonical key")
    if scheme == "lei" and not LEI.fullmatch(identifier):
        raise ValueError("non-canonical LEI")
    return scheme, identifier


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
        and isinstance(value.get("recipeVersion"), int)
        and not isinstance(value["recipeVersion"], bool)
        and value["recipeVersion"] >= 1
    )


def verify_component(artifact, domain):
    if not isinstance(artifact, dict):
        return False
    signature = artifact.get("signature")
    if not isinstance(signature, dict) or set(signature) != {
        "algorithm", "signer", "value"
    }:
        return False
    if signature.get("algorithm") != "ed25519":
        return False
    try:
        scheme, public_hex = parse_ref(signature.get("signer"))
        if scheme != "key":
            return False
        unsigned = {key: value for key, value in artifact.items() if key != "signature"}
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
            b64url_decode(signature.get("value")),
            (domain + hash_hex(unsigned)).encode("ascii"),
        )
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def verify_bundle(bundle):
    if not isinstance(bundle, dict):
        return False
    if not {"bundleVersion", "presentedBy", "presentedAt", "claims", "presentation"} <= set(bundle):
        return False
    if bundle.get("bundleVersion") != "1" or not isinstance(bundle.get("claims"), list):
        return False
    presentation = bundle.get("presentation")
    if not isinstance(presentation, dict) or presentation.get("kind") != "per-claim":
        return False
    signatures = presentation.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return False
    unsigned = {key: value for key, value in bundle.items() if key != "presentation"}
    payload = (BUNDLE_DOMAIN + hash_hex(unsigned)).encode("ascii")
    claim_refs = {item.get("ref") for item in bundle["claims"] if isinstance(item, dict)}
    for signature in signatures:
        if not isinstance(signature, dict) or set(signature) != {"ref", "signature"}:
            return False
        try:
            scheme, public_hex = parse_ref(signature["ref"])
            if scheme != "key" or signature["ref"] not in claim_refs:
                return False
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
                b64url_decode(signature["signature"]), payload
            )
        except (InvalidSignature, TypeError, ValueError):
            return False
    return True


def all_members(requirement):
    yield from requirement.get("required", [])
    for group in requirement.get("oneOf", []):
        yield from group


def params_match(claim, requirement):
    parameters = requirement.get("parameters")
    if parameters is None:
        return True
    metadata = claim.get("metadata")
    return isinstance(metadata, dict) and all(
        metadata.get(key) == value for key, value in parameters.items()
    )


def matching_claims(bundle, requirement, now):
    scheme = requirement.get("scheme")
    if scheme not in KNOWN_SCHEMES:
        return "error", []
    matches = []
    for claim in bundle.get("claims", []):
        if not isinstance(claim, dict):
            return "error", []
        try:
            claim_scheme, _ = parse_ref(claim.get("ref"))
        except ValueError:
            return "error", []
        if claim_scheme != scheme:
            continue
        expires_at = claim.get("expiresAt")
        if expires_at is not None and (
            not isinstance(expires_at, int) or isinstance(expires_at, bool)
        ):
            return "error", []
        if expires_at is not None and now > expires_at:
            continue
        if not params_match(claim, requirement):
            continue
        matches.append(claim)
    return "pass", matches


def lookup_result(vector, reference):
    for resolved in vector.get("resolvedResults", []):
        if resolved.get("ref") == reference:
            return resolved.get("artifact")
    return None


def record_refs(record):
    return [*record.get("freshness", []), *record.get("dealSpecific", [])]


def classify_presence(vector, requirement, exact_ref=None):
    if requirement.get("maxAge") is not None or requirement.get("recipeVersion") is not None:
        return "error"
    status, matches = matching_claims(vector["bundle"], requirement, vector["evaluatedAt"])
    if status == "error":
        return status
    if exact_ref is not None:
        matches = [claim for claim in matches if claim.get("ref") == exact_ref]
    return "pass" if matches else "fail"


def classify_verified(vector, requirement, exact_ref=None):
    status, matches = matching_claims(vector["bundle"], requirement, vector["evaluatedAt"])
    if status == "error":
        return status
    if exact_ref is not None:
        matches = [claim for claim in matches if claim.get("ref") == exact_ref]
    outcomes = []
    for claim in matches:
        reference = claim.get("verifiedBy")
        if not well_formed_result_ref(reference):
            continue
        if reference not in record_refs(vector["compositeRecord"]):
            continue
        result = lookup_result(vector, reference)
        if result is None:
            outcomes.append("indeterminate")
            continue
        if hash_hex(result) != reference["contentHash"]:
            outcomes.append("error")
            continue
        if not verify_component(result, VERIFY_RESULT_DOMAIN):
            outcomes.append("error")
            continue
        try:
            scheme, identifier = parse_ref(claim["ref"])
        except ValueError:
            outcomes.append("error")
            continue
        if (
            result.get("scheme") != scheme
            or result.get("identifier") != identifier
            or result.get("recipeVersion") != reference["recipeVersion"]
        ):
            outcomes.append("fail")
            continue
        pinned = requirement.get("recipeVersion")
        if pinned is not None and result.get("recipeVersion") != pinned:
            outcomes.append("fail")
            continue
        decision = result.get("decision")
        if decision != "pass":
            outcomes.append(decision if decision in {"fail", "error", "indeterminate"} else "error")
            continue
        verified_at = result.get("verifiedAt")
        if not isinstance(verified_at, int) or isinstance(verified_at, bool):
            outcomes.append("fail")
            continue
        expiry = result.get("validUntil", verified_at + 3_600_000)
        if claim.get("expiresAt") is not None:
            expiry = min(expiry, claim["expiresAt"])
        if vector["evaluatedAt"] > expiry:
            outcomes.append("fail")
            continue
        max_age = requirement.get("maxAge")
        if max_age is not None and vector["evaluatedAt"] - verified_at > max_age * 1000:
            outcomes.append("fail")
            continue
        outcomes.append("pass")
    if "pass" in outcomes:
        return "pass"
    if "fail" in outcomes:
        return "fail"
    if "error" in outcomes:
        return "error"
    if "indeterminate" in outcomes:
        return "indeterminate"
    return "fail"


def classify_member(vector, member, exact_ref=None):
    if member.get("verificationRequired") is False:
        return classify_presence(vector, member, exact_ref)
    if member.get("verificationRequired") is True:
        return classify_verified(vector, member, exact_ref)
    return "error"


def selected_claim_is_authorized(vector):
    requirement = vector["requirement"]
    selector = requirement.get("primaryClaimSelector")
    if selector is None:
        return True
    bundle = vector["bundle"]
    try:
        presented_scheme, _ = parse_ref(bundle.get("presentedBy"))
    except ValueError:
        return False
    if presented_scheme != selector:
        return False
    presented = next(
        (claim for claim in bundle["claims"] if claim.get("ref") == bundle["presentedBy"]),
        None,
    )
    if presented is None:
        return False

    presentation_refs = {
        item.get("ref") for item in bundle["presentation"].get("signatures", [])
        if isinstance(item, dict)
    }
    controlled = presented_scheme == "key" and bundle["presentedBy"] in presentation_refs
    if not controlled:
        return False
    if classify_verified(
        vector, {"scheme": selector, "verificationRequired": True},
        exact_ref=bundle["presentedBy"],
    ) == "pass":
        return True

    presence_members = [
        member for member in all_members(requirement)
        if member.get("scheme") == selector
        and member.get("verificationRequired") is False
        and classify_presence(vector, member, bundle["presentedBy"]) == "pass"
    ]
    if not presence_members:
        return False
    if any(
        member.get("scheme") == selector
        and member.get("verificationRequired") is True
        for member in requirement.get("required", [])
    ):
        return False
    for group in requirement.get("oneOf", []):
        if not any(
            member.get("scheme") == selector
            and member.get("verificationRequired") is True
            for member in group
        ):
            continue
        exact_presence = any(
            member.get("scheme") == selector
            and member.get("verificationRequired") is False
            and classify_presence(vector, member, bundle["presentedBy"]) == "pass"
            for member in group
        )
        other_pass = any(
            member.get("scheme") != selector
            and classify_member(vector, member) == "pass"
            for member in group
        )
        if not (exact_presence or other_pass):
            return False
    return True


def evaluate(vector):
    record = vector.get("compositeRecord")
    requirement = vector.get("requirement")
    if not verify_component(record, COMPOSITE_DOMAIN):
        return "error"
    if hash_hex(requirement) != record.get("requirementHash"):
        return "error"
    members = list(all_members(requirement))
    for member in members:
        if not isinstance(member, dict) or member.get("verificationRequired") not in {True, False}:
            return "error"
        if member.get("verificationRequired") is False and (
            "maxAge" in member or "recipeVersion" in member
        ):
            return "error"
    if not vector.get("bundleAvailable"):
        return "indeterminate"
    bundle = vector.get("bundle")
    if not verify_bundle(bundle):
        return "error"
    unsigned_bundle = {key: value for key, value in bundle.items() if key != "presentation"}
    if hash_hex(unsigned_bundle) != record.get("bundleHash"):
        return "error"
    for item in bundle.get("claims", []):
        if "verifiedBy" in item and not well_formed_result_ref(item["verifiedBy"]):
            return "error"

    true_schemes = {
        member.get("scheme") for member in members
        if member.get("verificationRequired") is True
    }
    for reference in record_refs(record):
        attributable = any(
            claim.get("verifiedBy") == reference
            and parse_ref(claim.get("ref"))[0] in true_schemes
            for claim in bundle.get("claims", [])
        )
        if not attributable:
            return "error"

    failures = []
    errors = []
    indeterminates = []
    for member in requirement.get("required", []):
        outcome = classify_member(vector, member)
        if outcome == "fail":
            failures.append(outcome)
        elif outcome == "error":
            errors.append(outcome)
        elif outcome == "indeterminate":
            indeterminates.append(outcome)
    for group in requirement.get("oneOf", []):
        outcomes = [classify_member(vector, member) for member in group]
        if "pass" in outcomes:
            continue
        if "error" in outcomes:
            errors.append("oneOf")
        elif "indeterminate" in outcomes:
            indeterminates.append("oneOf")
        else:
            failures.append("oneOf")

    if failures:
        decision = "fail"
    elif errors:
        decision = "error"
    elif indeterminates:
        decision = "indeterminate"
    else:
        decision = "pass"
    if decision == "pass" and not selected_claim_is_authorized(vector):
        decision = "fail"
    if decision != record.get("overallDecision"):
        return "error"
    return decision


class PresenceOnlyClaimVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_generator_is_deterministic(self):
        subprocess.run(
            ["python3", str(GENERATOR), "--check"], cwd=ROOT, check=True
        )

    def test_header_count_hash_and_names(self):
        vectors = self.document["vectors"]
        self.assertEqual(self.document["count"], len(vectors))
        self.assertEqual(
            self.document["hash"], hashlib.sha256(canonical_bytes(vectors)).hexdigest()
        )
        names = [vector["name"] for vector in vectors]
        self.assertEqual(len(names), len(set(names)))

    def test_all_vectors_execute(self):
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(vector["expected"], evaluate(vector))

    def test_all_non_signature_negative_artifacts_are_genuinely_signed(self):
        for vector in self.document["vectors"]:
            name = vector["name"]
            if vector["bundle"] is not None:
                self.assertEqual(
                    name != "invalid-bundle-presentation-rejected",
                    verify_bundle(vector["bundle"]),
                    name,
                )
            self.assertEqual(
                name not in {
                    "invalid-composite-signature-rejected",
                    "invalid-composite-still-rejects-without-bundle",
                },
                verify_component(vector["compositeRecord"], COMPOSITE_DOMAIN),
                name,
            )
            for resolved in vector["resolvedResults"]:
                self.assertTrue(
                    verify_component(resolved["artifact"], VERIFY_RESULT_DOMAIN), name
                )

    def test_presence_only_members_have_no_result_refs_in_passing_records(self):
        for vector in self.document["vectors"]:
            members = list(all_members(vector["requirement"]))
            if vector["expected"] != "pass" or not members:
                continue
            if all(member["verificationRequired"] is False for member in members):
                with self.subTest(vector=vector["name"]):
                    self.assertEqual([], record_refs(vector["compositeRecord"]))

    def test_control_boundary_vectors_are_distinguishing(self):
        expected = {
            "presence-key-selector-has-independent-control": "pass",
            "presence-lei-selector-does-not-establish-control": "fail",
            "different-verified-same-scheme-cannot-launder-selector": "fail",
        }
        by_name = {vector["name"]: vector for vector in self.document["vectors"]}
        for name, verdict in expected.items():
            self.assertEqual(verdict, evaluate(by_name[name]))

    def test_published_control_fixture_is_the_presence_only_key_case(self):
        fixture = json.loads(CONTROL_FIXTURE.read_text(encoding="utf-8"))
        vector = next(
            case for case in fixture["cases"]
            if case["id"] == "vet-control-key-presentation-accept"
        )
        claim = vector["input"]["bundle"]["claims"][0]
        member = vector["input"]["requirement"]["required"][0]
        self.assertNotIn("verifiedBy", claim)
        self.assertIn("issuedAt", claim)
        self.assertFalse(member["verificationRequired"])
        self.assertEqual("pass", vector["expected"])

    def test_specs_define_all_presence_rules_and_versions(self):
        dacs1 = DACS1.read_text(encoding="utf-8")
        dacs2 = DACS2.read_text(encoding="utf-8")
        self.assertIn("**DACS-1 v0.7**", dacs1)
        self.assertIn("**DACS-2 v0.6**", dacs2)
        for rule in range(1, 7):
            self.assertIn(f"**(PCR-{rule})", dacs1)
        for text in (
            "It MUST NOT call a verification recipe, create a `VerifyResult`, or add a `VerifyResultRef`",
            "the reliance decision is `indeterminate` until the bundle is available",
            "aggregate(record, recordRef, requirement, authority, recipeRegistryResolver)",
        ):
            self.assertIn(text, dacs2)


if __name__ == "__main__":
    unittest.main()
