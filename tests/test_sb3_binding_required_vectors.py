"""Execute the DACS-4 v0.8 SB-3 required-binding disposition corpus."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_sb3_binding_required_vectors as generator  # noqa: E402


VECTORS = ROOT / "conformance/vectors/security/sb3-binding-required-v0.8.json"
SPEC = ROOT / "spec/DACS-4-SETTLE.md"
DACS5 = ROOT / "spec/DACS-5-VERIFY.md"


def result(
    expected: str,
    disposition: str,
    reason: str,
    *,
    unbound_posture: bool = False,
) -> tuple[str, dict]:
    return expected, {
        "bindingDisposition": disposition,
        "reason": reason,
        "usedUnboundPosture": unbound_posture,
        "countable": expected == "pass",
        "finalVerificationSatisfied": expected == "pass",
        "reputationEligible": expected == "pass",
        "partyFaultCreatedByThisGate": False,
    }


def evaluate(vector: dict) -> tuple[str, dict]:
    trusted = vector.get("trustedContext")
    if (
        not isinstance(trusted, dict)
        or trusted.get("authority") != "authenticated-agreement-pinned-rail"
    ):
        return result(
            "indeterminate",
            "policy-unresolved",
            "authenticated-rail-policy-unavailable",
        )

    profile_policy = {
        "x402-eip3009-binding-v0.8": "required",
        "evm-erc20-unbound-v0.8": "none",
    }
    binding_policy = profile_policy.get(trusted.get("resolvedRailProfile"))
    if binding_policy is None:
        return result(
            "indeterminate",
            "policy-unresolved",
            "authenticated-rail-policy-unavailable",
        )

    protocol_input = vector["protocolInput"]

    if binding_policy == "required":
        evidence = protocol_input.get("bindingEvidence")
        known_states = {
            "match",
            "mismatch",
            "absent",
            "malformed",
            "unavailable-rpc",
            "unavailable-pruned-history",
            "unavailable-signature-authority",
            "unavailable-reorged",
        }
        if not isinstance(evidence, dict) or set(evidence) != {"state"}:
            return result("error", "malformed", "malformed-binding-evidence")
        state = evidence.get("state")
        if not isinstance(state, str) or state not in known_states:
            return result("error", "malformed", "malformed-binding-evidence")
        if state == "malformed":
            return result("error", "malformed", "malformed-binding-evidence")
        if state == "mismatch":
            return result("fail", "rejected", "binding-mismatch")
        if state != "match":
            return result(
                "indeterminate",
                "unresolved",
                (
                    "required-binding-absent"
                    if state == "absent"
                    else "binding-authority-unavailable"
                ),
            )
        disposition = "satisfied"
        unbound_posture = False
    else:
        disposition = "not-required"
        unbound_posture = True

    transfer = protocol_input.get("unboundTransferChecks")
    if transfer == "match":
        return result(
            "pass",
            disposition,
            (
                "verified-binding-and-transfer"
                if binding_policy == "required"
                else "verified-unbound-transfer"
            ),
            unbound_posture=unbound_posture,
        )
    if transfer == "mismatch":
        return result(
            "fail",
            disposition,
            "unbound-transfer-mismatch",
            unbound_posture=unbound_posture,
        )
    if transfer == "unavailable":
        return result(
            "indeterminate",
            disposition,
            "unbound-transfer-unavailable",
            unbound_posture=unbound_posture,
        )
    return result(
        "error",
        disposition,
        "malformed-unbound-transfer-evidence",
        unbound_posture=unbound_posture,
    )


class Sb3BindingRequiredVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = VECTORS
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {vector["name"]: vector for vector in cls.data["vectors"]}

    def test_committed_file_is_deterministic(self):
        self.assertEqual(VECTORS.read_text(encoding="utf-8"), generator.rendered())

    def test_every_vector_executes_to_its_pinned_disposition(self):
        for vector in self.data["vectors"]:
            with self.subTest(name=vector["name"]):
                expected, want = evaluate(vector)
                self.assertEqual(vector["expected"], expected)
                self.assertEqual(vector["want"], want)

    def test_required_binding_never_uses_unbound_posture(self):
        for vector in self.data["vectors"]:
            trusted = vector.get("trustedContext", {})
            if trusted.get("resolvedRailProfile") == "x402-eip3009-binding-v0.8":
                with self.subTest(name=vector["name"]):
                    self.assertFalse(evaluate(vector)[1]["usedUnboundPosture"])

    def test_unavailable_required_binding_is_non_countable_without_fault(self):
        for vector in self.data["vectors"]:
            evidence = vector["protocolInput"].get("bindingEvidence")
            state = evidence.get("state") if isinstance(evidence, dict) else None
            if isinstance(state, str) and state.startswith("unavailable"):
                with self.subTest(name=vector["name"]):
                    expected, want = evaluate(vector)
                    self.assertEqual(expected, "indeterminate")
                    self.assertFalse(want["countable"])
                    self.assertFalse(want["finalVerificationSatisfied"])
                    self.assertFalse(want["reputationEligible"])
                    self.assertFalse(want["partyFaultCreatedByThisGate"])

    def test_unrelated_exact_transfer_and_downgrade_attempts_refuse(self):
        names = {
            "unrelated-exact-transfer-cannot-replace-binding",
            "caller-unbound-downgrade-ignored",
            "unproven-legacy-downgrade-ignored",
        }
        for name in names:
            with self.subTest(name=name):
                vector = self.cases[name]
                self.assertEqual(vector["protocolInput"]["unboundTransferChecks"], "match")
                expected, want = evaluate(vector)
                self.assertEqual(expected, "indeterminate")
                self.assertFalse(want["usedUnboundPosture"])
                self.assertFalse(want["countable"])

    def test_authentically_unbound_rail_keeps_explicit_weaker_posture(self):
        vector = self.cases["authenticated-unbound-rail-exact-transfer-pass"]
        expected, want = evaluate(vector)
        self.assertEqual(expected, "pass")
        self.assertTrue(want["usedUnboundPosture"])
        self.assertTrue(want["countable"])

    def test_protocol_input_cannot_declare_binding_policy(self):
        for vector in self.data["vectors"]:
            with self.subTest(name=vector["name"]):
                self.assertNotIn("binding", vector["protocolInput"])
                self.assertNotIn("resolvedRailProfile", vector["protocolInput"])

    def test_required_issue_379_cases_are_present(self):
        self.assertTrue(
            {
                "required-binding-match-pass",
                "required-binding-mismatch-fail",
                "required-binding-absent-indeterminate",
                "required-binding-rpc-unavailable-indeterminate",
                "required-binding-pruned-history-indeterminate",
                "required-binding-malformed-error",
                "required-binding-unknown-state-error",
                "required-binding-missing-evidence-error",
                "required-binding-null-evidence-error",
                "required-binding-missing-state-error",
                "required-binding-non-string-state-error",
                "unrelated-exact-transfer-cannot-replace-binding",
                "unproven-legacy-downgrade-ignored",
            }.issubset(self.cases)
        )

    def test_malformed_or_unsupported_binding_shapes_never_raise(self):
        names = {
            "required-binding-malformed-error",
            "required-binding-unknown-state-error",
            "required-binding-missing-evidence-error",
            "required-binding-null-evidence-error",
            "required-binding-missing-state-error",
            "required-binding-non-string-state-error",
        }
        for name in names:
            with self.subTest(name=name):
                expected, want = evaluate(self.cases[name])
                self.assertEqual(expected, "error")
                self.assertEqual(want["bindingDisposition"], "malformed")
                self.assertEqual(want["reason"], "malformed-binding-evidence")

    def test_spec_and_dacs5_make_the_gate_load_bearing(self):
        spec = SPEC.read_text(encoding="utf-8")
        dacs5 = DACS5.read_text(encoding="utf-8")
        self.assertIn("DACS-4 v0.8", spec)
        self.assertIn("The last two branches MUST NOT fall back", spec)
        self.assertIn("cannot satisfy final verification or reputation admission", spec)
        self.assertIn("not party fault", spec)
        self.assertIn("SB-1 through SB-3", dacs5)


if __name__ == "__main__":
    unittest.main()
