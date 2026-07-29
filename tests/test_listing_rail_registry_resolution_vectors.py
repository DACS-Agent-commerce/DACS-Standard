"""Executable assertions for DACS-1 §6.3.4 LRR-1..LRR-6 candidate vectors."""

import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance/vectors/security/listing-rail-registry-resolution-v0.4.json"
SPEC_DACS1 = ROOT / "spec/DACS-1-IDENTIFY.md"
SPEC_DACS4 = ROOT / "spec/DACS-4-SETTLE.md"


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def evaluate(data):
    pay_phases = data["payPhases"]
    accepted = data["acceptedRails"]

    if not pay_phases:
        return "pass", "not-applicable"
    if not accepted:
        return "fail", "missing-accepted-rails"

    accepted_ids = [ref.get("railId") for ref in accepted]
    if any(not isinstance(rail_id, str) or not rail_id for rail_id in accepted_ids):
        return "fail", "malformed-accepted-rail"
    canonical_refs = [canonical_json(ref) for ref in accepted]
    if len(canonical_refs) != len(set(canonical_refs)):
        return "fail", "duplicate-accepted-rail-ref"

    for phase in pay_phases:
        rail_id = phase.get("rail")
        if not isinstance(rail_id, str) or not rail_id:
            return "fail", "malformed-pay-rail"
        if rail_id not in accepted_ids:
            return "fail", "pay-rail-not-accepted"

    if data["trustPhase"] == "PA-1":
        if not data.get("trustPolicyAcceptsPA1", False):
            return "indeterminate", "pa1-not-accepted"
        definitions = data.get("inCodeDefinitions", [])
        resolved_handlers = {}
        for ref in accepted:
            version = ref.get("railVersion")
            candidates = [
                definition for definition in definitions
                if definition.get("railId") == ref["railId"]
                and (version is None or definition.get("railVersion") == version)
            ]
            if len(candidates) != 1:
                return "fail", "unknown-rail"
            definition = candidates[0]
            if (
                definition.get("governanceAnchoring") != "in-code"
                or definition.get("signatureValid") is not True
            ):
                return "indeterminate", "pa1-definition-unverifiable"
            resolved_handlers.setdefault(ref["railId"], set()).add(definition["phaseHandler"])
        for phase in pay_phases:
            if resolved_handlers.get(phase["rail"]) != {phase["kind"]}:
                return "fail", "phase-handler-mismatch"
        return "pass", "verified-pa1"

    registry = data["registry"]
    state = registry["state"]
    if state == "verified-included":
        return "indeterminate", "registry-not-finalized"
    if state == "invalid-authority":
        return "indeterminate", "registry-unverifiable-no-fallback"
    if state != "verified-finalized":
        return "indeterminate", "registry-unavailable"

    entries = {entry["railId"]: entry for entry in registry["entries"]}
    definitions = {
        (definition["railId"], definition["railVersion"]): definition
        for definition in registry["definitions"]
    }
    rejected_reason = None
    indeterminate_reason = None
    resolved_handlers = {}

    for ref in accepted:
        entry = entries.get(ref["railId"])
        if entry is None:
            rejected_reason = rejected_reason or "unknown-rail"
            continue
        version = ref.get("railVersion", entry["latestVersion"])
        if version not in entry["versions"]:
            rejected_reason = rejected_reason or "unknown-rail-version"
            continue
        definition = definitions.get((ref["railId"], version))
        if definition is None or definition.get("state") != "verified-finalized":
            indeterminate_reason = indeterminate_reason or "rail-definition-unavailable"
            continue
        resolved_handlers.setdefault(ref["railId"], set()).add(definition["phaseHandler"])

    for phase in pay_phases:
        handlers = resolved_handlers.get(phase["rail"])
        if handlers is not None and handlers != {phase["kind"]}:
            rejected_reason = rejected_reason or "phase-handler-mismatch"

    if rejected_reason is not None:
        return "fail", rejected_reason
    if indeterminate_reason is not None:
        return "indeterminate", indeterminate_reason
    return "pass", "verified"


class ListingRailRegistryResolutionVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_vector_hash_count_and_names(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(self.data["hash"], hashlib.sha256(canonical_json(vectors)).hexdigest())
        names = [vector["name"] for vector in vectors]
        self.assertEqual(len(names), len(set(names)))

    def test_all_expected_dispositions_and_reasons(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(
                    evaluate(vector["input"]),
                    (vector["expected"], vector["reason"]),
                )

    def test_rules_and_cross_stage_resolution_are_normative(self):
        dacs1 = SPEC_DACS1.read_text(encoding="utf-8")
        dacs4 = SPEC_DACS4.read_text(encoding="utf-8")
        for rule_id in range(1, 7):
            self.assertIn(f"(LRR-{rule_id})", dacs1)
        self.assertIn("ListingRailResolution", dacs1)
        self.assertIn("MUST NOT fall back to in-code constants", dacs1)
        self.assertIn("§6.3.4 LRR-1..LRR-6", dacs4)


if __name__ == "__main__":
    unittest.main()
