import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "vectors" / "security" / "listing-preserve-unknown-v0.1.json"
CORE = ROOT / "spec" / "CORE.md"
CONFORMANCE_PLAN = ROOT / "spec" / "CONFORMANCE-PLAN.md"
DACS4 = ROOT / "spec" / "DACS-4-SETTLE.md"


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def artifact_hash(document, omitted_field):
    unsigned = {key: value for key, value in document.items() if key != omitted_field}
    return hashlib.sha256(canonical_json(unsigned)).hexdigest()


# Dependency-free Ed25519 verification for the pinned fixture signatures. This
# follows the affine formulas in RFC 8032 and deliberately performs verification
# only; vector generation keeps the private seed out of the test implementation.
Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, Q - 2, Q)) % Q
I = pow(2, (Q - 1) // 4, Q)


def x_recover(y):
    xx = ((y * y - 1) * pow(D * y * y + 1, Q - 2, Q)) % Q
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q != 0:
        x = (x * I) % Q
    if (x * x - xx) % Q != 0:
        raise ValueError("point is not on the Ed25519 curve")
    return Q - x if x & 1 else x


BASE_Y = (4 * pow(5, Q - 2, Q)) % Q
BASE = (x_recover(BASE_Y), BASE_Y)


def point_add(left, right):
    x1, y1 = left
    x2, y2 = right
    product = (D * x1 * x2 * y1 * y2) % Q
    x3 = ((x1 * y2 + x2 * y1) * pow(1 + product, Q - 2, Q)) % Q
    y3 = ((y1 * y2 + x1 * x2) * pow(1 - product, Q - 2, Q)) % Q
    return x3, y3


def scalar_mult(point, scalar):
    result = (0, 1)
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def decode_point(encoded):
    if len(encoded) != 32:
        raise ValueError("Ed25519 point must be 32 bytes")
    raw = int.from_bytes(encoded, "little")
    y = raw & ((1 << 255) - 1)
    if y >= Q:
        raise ValueError("non-canonical Ed25519 point")
    x = x_recover(y)
    if (x & 1) != (raw >> 255):
        x = Q - x
    if (-x * x + y * y - 1 - D * x * x * y * y) % Q != 0:
        raise ValueError("point is not on the Ed25519 curve")
    return x, y


def verify_ed25519(public_key, signature, message):
    if len(public_key) != 32 or len(signature) != 64:
        return False
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= L:
        return False
    try:
        encoded_r = signature[:32]
        point_r = decode_point(encoded_r)
        point_a = decode_point(public_key)
    except ValueError:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(),
        "little",
    ) % L
    return scalar_mult(BASE, scalar) == point_add(point_r, scalar_mult(point_a, challenge))


def decode_base64url(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def transformed_listing(listing, transform):
    result = copy.deepcopy(listing)
    if transform["kind"] == "none":
        return result
    path = transform["path"].split(".")
    parent = result
    for segment in path[:-1]:
        parent = parent[segment]
    if transform["kind"] == "set":
        parent[path[-1]] = transform["value"]
    elif transform["kind"] == "remove":
        parent.pop(path[-1])
    else:
        raise AssertionError(f"unknown transform: {transform['kind']}")
    return result


class ListingPreserveUnknownVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.public_keys = {
            signer: decode_base64url(key)
            for signer, key in cls.data["publicKeys"].items()
        }

    def verify_listing_signature(self, listing):
        signature = listing["signature"]
        message = (
            self.data["signatureDomain"]
            + artifact_hash(listing, self.data["omittedHashField"])
        ).encode("ascii")
        return verify_ed25519(
            self.public_keys[signature["signer"]],
            decode_base64url(signature["value"]),
            message,
        )

    def dpa1_disposition(self, listing):
        if any(
            phase["kind"] == "deliver-attested-payload"
            for phase in listing["pipeline"]
        ):
            deliverable = listing["offering"]["deliverable"]
            method = deliverable.get("verificationMethod")
            if (
                deliverable.get("kind") != "attested-payload"
                or not isinstance(method, dict)
                or method.get("kind") not in self.data["supportedVerificationMethods"]
            ):
                return "reject"

        return "accept"

    def listing_disposition(self, listing):
        if not self.verify_listing_signature(listing):
            return "reject"

        supported_phases = set(self.data["supportedPhaseKinds"])
        if any(phase.get("kind") not in supported_phases for phase in listing["pipeline"]):
            return "refuse-unsupported"

        return self.dpa1_disposition(listing)

    def test_vector_hash_and_count_are_byte_exact(self):
        self.assertEqual(self.data["count"], len(self.data["vectors"]))
        self.assertEqual(
            self.data["hash"],
            hashlib.sha256(canonical_json(self.data["vectors"])).hexdigest(),
        )

    def test_identity_bundle_presentation_is_valid(self):
        listing = self.data["fixtures"]["listing-with-inert-extension"]["listing"]
        identity = listing["seller"]["identity"]
        bundle_hash = artifact_hash(identity, "presentation")
        self.assertEqual(bundle_hash, self.data["fixtures"]["identityBundleHash"])
        signer = identity["presentedBy"]
        signature = identity["presentation"]["signatures"][0]
        self.assertEqual(signature["ref"], signer)
        self.assertTrue(
            verify_ed25519(
                self.public_keys[signer],
                base64.b64decode(signature["signature"]),
                ("dacs-bundle-presentation:v1:" + bundle_hash).encode("ascii"),
            )
        )

    def test_fixture_hashes_and_listing_signatures_are_valid(self):
        for name in ["listing-with-inert-extension", "listing-with-unknown-phase"]:
            with self.subTest(fixture=name):
                fixture = self.data["fixtures"][name]
                listing = fixture["listing"]
                self.assertEqual(
                    artifact_hash(listing, self.data["omittedHashField"]),
                    fixture["artifactHash"],
                )
                self.assertTrue(self.verify_listing_signature(listing))

    def test_inert_extension_passes_but_mutation_and_removal_fail(self):
        cases = {case["name"]: case for case in self.data["vectors"]}
        listing = self.data["fixtures"]["listing-with-inert-extension"]["listing"]
        for name in [
            "unknown-inert-top-level-field-verifies",
            "mutated-unknown-field-breaks-signature",
            "removed-unknown-field-breaks-signature",
        ]:
            with self.subTest(case=name):
                case = cases[name]
                candidate = transformed_listing(listing, case["transform"])
                self.assertEqual(
                    artifact_hash(candidate, self.data["omittedHashField"]),
                    case["want"]["computedArtifactHash"],
                )
                expected_valid = case["want"]["signature"] == "valid"
                self.assertEqual(self.verify_listing_signature(candidate), expected_valid)

    def test_known_key_projection_cannot_verify_the_original_signature(self):
        fixture = self.data["fixtures"]["listing-with-inert-extension"]
        listing = fixture["listing"]
        projection = {
            key: value
            for key, value in listing.items()
            if key in self.data["knownTopLevelFields"] and key != "signature"
        }
        projection_hash = hashlib.sha256(canonical_json(projection)).hexdigest()
        self.assertEqual(projection_hash, fixture["knownFieldProjectionHash"])
        self.assertNotEqual(projection_hash, fixture["artifactHash"])

    def test_unknown_phase_remains_unsupported_after_signature_passes(self):
        case = next(
            case
            for case in self.data["vectors"]
            if case["name"] == "valid-signature-unknown-phase-kind-refuses"
        )
        listing = self.data["fixtures"][case["fixture"]]["listing"]
        self.assertTrue(self.verify_listing_signature(listing))
        self.assertEqual(listing["pipeline"][0]["kind"], "negotiate-future-mode")
        self.assertEqual(case["expected"], "fail")
        self.assertEqual(case["want"]["listingDisposition"], "refuse-unsupported")

    def test_declared_listing_dispositions_execute_signature_phase_and_dpa1_rules(self):
        for case in self.data["vectors"]:
            with self.subTest(case=case["name"]):
                listing = self.data["fixtures"][case["fixture"]]["listing"]
                candidate = transformed_listing(listing, case["transform"])
                self.assertEqual(
                    self.listing_disposition(candidate),
                    case["want"]["listingDisposition"],
                )

        positive = copy.deepcopy(
            self.data["fixtures"]["listing-with-inert-extension"]["listing"]
        )
        positive["offering"]["deliverable"].pop("verificationMethod")
        self.assertEqual(self.dpa1_disposition(positive), "reject")

    def test_normative_rules_and_concrete_vector_are_linked(self):
        core = CORE.read_text(encoding="utf-8")
        dacs4 = DACS4.read_text(encoding="utf-8")
        plan = CONFORMANCE_PLAN.read_text(encoding="utf-8")
        self.assertIn("(SIG-5) **Preserve-unknown.**", core)
        self.assertIn("**New-type refusal (normative).**", core)
        self.assertIn("(DPA-1) **Listing/phase coherence.**", dacs4)
        self.assertIn("listing-preserve-unknown-v0.1.json", plan)
        self.assertIn("unknown phase kind", plan)


if __name__ == "__main__":
    unittest.main()
