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
# DEMOS-MAPPING A.5: handlers whose substrate the pinned node does not
# complete; every operational availability needs trusted completion policy.
NODE_GATED_HANDLERS = {"pay-cross-chain-liquidity-tank"}
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
    completed = operator_context.get("nodeCompletedHandlers", [])
    if not isinstance(completed, list) or any(type(item) is not str for item in completed):
        return "error"
    if (
        availability in {"live", *GATED}
        and rail.get("phaseHandler") in NODE_GATED_HANDLERS
        and rail["phaseHandler"] not in completed
    ):
        return "fail"
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

    def test_tank_rail_is_not_made_available_by_the_node(self):
        # DEMOS-MAPPING A.5: the pinned node returns an unsigned, incomplete
        # compiled bridge operation, so the signed tank fixture is mocked and
        # neither a node-derived hint nor an unsigned live copy selects it.
        hinted = self.by_name["tank-mocked-node-operation-live-hint"]
        unsigned = self.by_name["tank-live-unsigned"]
        self.assertEqual("pay-cross-chain-liquidity-tank", hinted["rail"]["phaseHandler"])
        self.assertEqual("mocked", hinted["rail"]["availability"])
        self.assertEqual("live", hinted["ctx"]["discoveryAvailabilityHint"])
        self.assertTrue(hinted["ctx"]["operatorContext"]["production"])
        self.assertEqual("fail", evaluate(hinted))
        # The rail is otherwise selectable: only its signed mocked
        # availability under production policy decides the case.
        testing = copy.deepcopy(hinted)
        testing["ctx"]["operatorContext"]["production"] = False
        self.assertEqual("pass", evaluate(testing))
        self.assertEqual("live", unsigned["rail"]["availability"])
        self.assertNotIn("signature", unsigned["rail"])
        self.assertEqual("fail", evaluate(unsigned))

    def test_signed_live_tank_rail_needs_a_node_that_completes_it(self):
        # DACS-4 §9.4: a steward-signed, pinned live tank rail is selectable
        # only when trusted local policy records that the pinned node
        # completes the handler; the node-gate alone decides each case.
        incomplete = self.by_name["tank-live-signed-node-incomplete"]
        completes = self.by_name["tank-live-signed-node-completes"]
        malformed = self.by_name["tank-live-node-capability-malformed"]
        for vector in (incomplete, completes, malformed):
            self.assertEqual("live", vector["rail"]["availability"])
            self.assertEqual(vector["ctx"]["pinnedRailDigest"], digest(vector["rail"]))
        self.assertNotIn("nodeCompletedHandlers", incomplete["ctx"]["operatorContext"])
        self.assertEqual("fail", evaluate(incomplete))
        self.assertEqual("pass", evaluate(completes))
        self.assertEqual("error", evaluate(malformed))
        # The two vectors differ only in the capability list, and listing
        # another handler does not unlock the tank.
        self.assertEqual(incomplete["rail"], completes["rail"])
        wrong = copy.deepcopy(incomplete)
        wrong["ctx"]["operatorContext"]["nodeCompletedHandlers"] = ["pay-cross-chain-htlc"]
        self.assertEqual("fail", evaluate(wrong))
        # Non-production mode does not lift the gate.
        testing = copy.deepcopy(incomplete)
        testing["ctx"]["operatorContext"]["production"] = False
        self.assertEqual("fail", evaluate(testing))

    def test_gated_tank_rails_require_completion_in_every_execution_mode(self):
        for availability in sorted(GATED):
            case = self.by_name[
                "tank-" + availability.replace("_", "-") + "-signed-node-incomplete"
            ]
            for production in (True, False):
                value = copy.deepcopy(case)
                value["ctx"]["operatorContext"]["production"] = production
                with self.subTest(availability=availability, production=production):
                    self.assertTrue(value["ctx"]["operatorPreflightOk"])
                    self.assertEqual("fail", evaluate(value))
                    value["ctx"]["operatorContext"]["nodeCompletedHandlers"] = [
                        "pay-cross-chain-liquidity-tank"
                    ]
                    self.assertEqual("pass", evaluate(value))
                    value["ctx"]["operatorPreflightOk"] = False
                    self.assertEqual("fail", evaluate(value))

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
