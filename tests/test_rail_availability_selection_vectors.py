import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance/vectors/security/rail-availability-selection-v0.1.json"
GENERATOR = ROOT / "scripts/generate_rail_availability_selection_vectors.py"
DOMAIN = "dacs-rail:v1:"
AVAILABILITY = {
    "live", "operator_gated", "closed_data", "bilateral",
    "mocked", "disabled", "failed",
}
GATED = {"operator_gated", "closed_data", "bilateral"}


def canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def projection(rail):
    return {
        key: rail[key]
        for key in ("railId", "availability", "railVersion")
        if key in rail
    }


def digest(rail):
    return hashlib.sha256(canonical_bytes(projection(rail))).hexdigest()


def evaluate(vector):
    rail = vector.get("rail")
    ctx = vector.get("ctx")
    if not isinstance(rail, dict) or not isinstance(ctx, dict):
        return "error"
    if not isinstance(rail.get("railId"), str) or not rail["railId"]:
        return "error"
    if rail.get("availability") not in AVAILABILITY:
        return "error"
    if type(rail.get("railVersion")) is not int or rail["railVersion"] <= 0:
        return "error"

    steward_pub = ctx.get("stewardPub")
    if steward_pub is None:
        return "indeterminate"
    signature = rail.get("stewardSig")
    if not isinstance(signature, str):
        return "fail"
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(steward_pub)).verify(
            bytes.fromhex(signature), (DOMAIN + digest(rail)).encode("ascii")
        )
    except (ValueError, InvalidSignature):
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
    if availability == "mocked" and ctx.get("production") is True:
        return "fail"
    if session_state == "new" and availability in {"disabled", "failed"}:
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

    def test_mocked_and_disabled_new_sessions_fail_before_selection(self):
        self.assertEqual(evaluate(self.by_name["mocked-signed"]), "fail")
        self.assertEqual(evaluate(self.by_name["disabled-signed"]), "fail")
        self.assertEqual(
            evaluate(self.by_name["disabled-signed-in-flight"]), "pass"
        )

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
