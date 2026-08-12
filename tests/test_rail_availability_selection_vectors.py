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
VECTORS = ROOT / "conformance/vectors/security/rail-availability-selection-v0.1.json"
GENERATOR = ROOT / "scripts/generate_rail_availability_selection_vectors.py"
DOMAIN = "dacs-rail:v1:"
AVAILABILITY = {
    "live", "operator_gated", "closed_data", "bilateral",
    "mocked", "disabled", "failed",
}
GATED = {"operator_gated", "closed_data", "bilateral"}
REQUIRED_RAIL_FIELDS = {
    "railVersion", "railId", "railType", "asset", "network", "phaseHandler",
    "parameters", "availability", "governance", "signature",
}


def canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def unsigned_rail(rail):
    return {key: value for key, value in rail.items() if key != "signature"}


def digest(rail):
    return hashlib.sha256(
        jcs_canonicalize(unsigned_rail(rail)).encode("utf-8")
    ).hexdigest()


def decode_base64url(value):
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("non-canonical base64url")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ValueError("non-canonical base64url")
    return raw


def evaluate(vector):
    rail = vector.get("rail")
    ctx = vector.get("ctx")
    if not isinstance(rail, dict) or not isinstance(ctx, dict):
        return "error"
    if not (REQUIRED_RAIL_FIELDS - {"signature"}).issubset(rail):
        return "error"
    if "signature" not in rail:
        return "fail"
    if not isinstance(rail.get("railId"), str) or not rail["railId"]:
        return "error"
    if rail.get("availability") not in AVAILABILITY:
        return "error"
    if type(rail.get("railVersion")) is not int or rail["railVersion"] <= 0:
        return "error"

    steward_claim = ctx.get("stewardClaim")
    steward_pub = ctx.get("stewardPublicKey")
    if steward_claim is None or steward_pub is None:
        return "indeterminate"
    signature = rail.get("signature")
    if not isinstance(signature, dict):
        return "fail"
    if (
        signature.get("algorithm") != "ed25519"
        or signature.get("signer") != steward_claim
    ):
        return "fail"
    try:
        Ed25519PublicKey.from_public_bytes(decode_base64url(steward_pub)).verify(
            decode_base64url(signature.get("value")),
            (DOMAIN + digest(rail)).encode("ascii"),
        )
    except (TypeError, ValueError, InvalidSignature):
        return "fail"

    pinned = ctx.get("pinnedRailDigest")
    if pinned is None:
        return "indeterminate"
    if pinned != digest(rail):
        return "fail"

    availability = rail["availability"]
    session_state = ctx.get("sessionState")
    if session_state not in {"new", "in-flight"}:
        return "error"
    operator_context = ctx.get("operatorContext")
    if not isinstance(operator_context, dict):
        return "error"
    if operator_context.get("source") != "local-operator-policy":
        return "error"
    production = operator_context.get("production")
    if type(production) is not bool:
        return "error"
    if availability == "mocked" and production:
        return "fail"
    if availability in {"disabled", "failed"}:
        return "fail"
    if availability in GATED and not ctx.get("operatorPreflightOk"):
        return "fail"
    return "pass"


class RailAvailabilitySelectionVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.by_name = {item["name"]: item for item in cls.data["vectors"]}

    def test_generated_file_is_current(self):
        result = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_hash_count_and_names_are_exact(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(len(vectors), len(self.by_name))
        self.assertEqual(
            self.data["hash"], hashlib.sha256(canonical_bytes(vectors)).hexdigest()
        )

    def test_every_vector_executes_to_pinned_verdict(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(evaluate(vector), vector["expected"])

    def test_new_session_prohibitions_preserve_non_production_scope(self):
        self.assertEqual(evaluate(self.by_name["mocked-signed"]), "fail")
        self.assertEqual(
            evaluate(self.by_name["mocked-signed-non-production"]), "pass"
        )
        self.assertEqual(evaluate(self.by_name["disabled-signed"]), "fail")
        self.assertEqual(
            evaluate(self.by_name["disabled-signed-non-production"]), "fail"
        )
        self.assertEqual(
            evaluate(self.by_name["disabled-pinned-in-flight"]), "fail"
        )
        self.assertEqual(evaluate(self.by_name["failed-signed"]), "fail")
        self.assertEqual(
            evaluate(self.by_name["failed-signed-non-production"]), "fail"
        )
        self.assertEqual(
            evaluate(self.by_name["failed-pinned-in-flight"]), "fail"
        )

    def test_production_context_is_trusted_local_operator_policy(self):
        for name in (
            "mocked-production-context-missing",
            "mocked-production-context-string",
            "mocked-production-context-integer",
            "mocked-production-context-untrusted-source",
        ):
            with self.subTest(vector=name):
                self.assertEqual(evaluate(self.by_name[name]), "error")

        override = self.by_name["mocked-counterparty-non-production-override"]
        self.assertTrue(override["ctx"]["operatorContext"]["production"])
        self.assertFalse(override["ctx"]["counterpartyProductionHint"])
        self.assertEqual(evaluate(override), "fail")

    def test_complete_rail_definition_is_the_signed_and_pinned_scope(self):
        vector = self.by_name["live-signed-pinned"]
        rail = vector["rail"]
        self.assertTrue(REQUIRED_RAIL_FIELDS.issubset(rail))
        self.assertEqual(vector["ctx"]["pinnedRailDigest"], digest(rail))
        signature = rail["signature"]
        self.assertEqual(signature["algorithm"], "ed25519")
        self.assertNotIn("=", signature["value"])
        self.assertEqual(len(decode_base64url(signature["value"])), 64)

        mutations = (
            ("asset", "symbol", "USDT"),
            ("network", "resourceBaseUrl", "https://attacker.example/pay"),
            ("parameters", "authorization", "permit2"),
            ("governance", "acceptedAt", 999),
            (None, "futureSignedMember", "preserved-by-SIG-5"),
        )
        for parent, key, value in mutations:
            mutated = copy.deepcopy(vector)
            target = mutated["rail"] if parent is None else mutated["rail"][parent]
            target[key] = value
            with self.subTest(parent=parent, key=key):
                self.assertEqual(evaluate(mutated), "fail")

    def test_in_flight_session_keeps_original_live_pin(self):
        vector = self.by_name["disabled-after-pin-in-flight"]
        pinned = vector["rail"]
        later = vector["ctx"]["laterRegistryRailDefinition"]

        self.assertEqual(pinned["availability"], "live")
        self.assertEqual(vector["ctx"]["pinnedRailDigest"], digest(pinned))
        self.assertEqual(later["railId"], pinned["railId"])
        self.assertGreater(later["railVersion"], pinned["railVersion"])
        self.assertEqual(later["availability"], "disabled")
        Ed25519PublicKey.from_public_bytes(
            decode_base64url(vector["ctx"]["stewardPublicKey"])
        ).verify(
            decode_base64url(later["signature"]["value"]),
            (DOMAIN + digest(later)).encode("ascii"),
        )
        self.assertEqual(evaluate(vector), "pass")

    def test_discovery_hint_never_changes_authoritative_result(self):
        for vector in self.data["vectors"]:
            if "discoveryAvailabilityHint" not in vector["ctx"]:
                continue
            without_hint = json.loads(json.dumps(vector))
            del without_hint["ctx"]["discoveryAvailabilityHint"]
            with self.subTest(vector=vector["name"]):
                self.assertEqual(evaluate(vector), evaluate(without_hint))

        self.assertEqual(
            evaluate(self.by_name["mirror-live-hint-authoritative-failed"]), "fail"
        )
        self.assertEqual(
            evaluate(self.by_name["mirror-failed-hint-authoritative-live"]), "pass"
        )


if __name__ == "__main__":
    unittest.main()
