"""Executable assertions for DACS-1 §6.3.4 LRR-1..LRR-6 candidate vectors."""

import base64
import hashlib
import json
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance/vectors/security/listing-rail-registry-resolution-v0.4.json"
SPEC_DACS1 = ROOT / "spec/DACS-1-IDENTIFY.md"
SPEC_DACS4 = ROOT / "spec/DACS-4-SETTLE.md"
RAIL_DOMAIN = "dacs-rail:v1:"


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def decode_base64url(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_definition_proof(definition):
    """Return an LRR indeterminate reason, or None for a verified proof.

    Most matrix cases summarize already-authenticated SR-2 resolution in
    ``state``. Proof-bearing cases execute the two cryptographic boundaries
    that a registry consumer is most likely to omit: index content-hash
    equality and the dacs-rail:v1: steward signature.
    """

    proof = definition.get("proof")
    if proof is None:
        return None
    unsigned = proof.get("unsigned")
    if not isinstance(unsigned, dict):
        return "rail-definition-unverifiable"
    content_hash = hashlib.sha256(canonical_json(unsigned)).hexdigest()
    if content_hash != proof.get("indexContentHash"):
        return "rail-definition-hash-mismatch"
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            decode_base64url(proof["stewardPublicKey"])
        )
        public_key.verify(
            decode_base64url(proof["signature"]),
            (RAIL_DOMAIN + content_hash).encode("utf-8"),
        )
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return "rail-definition-signature-invalid"
    if (
        unsigned.get("railId") != definition.get("railId")
        or unsigned.get("railVersion") != definition.get("railVersion")
        or unsigned.get("phaseHandler") != definition.get("phaseHandler")
    ):
        return "rail-definition-unverifiable"
    return None


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
            rail_candidates = [
                definition for definition in definitions
                if definition.get("railId") == ref["railId"]
            ]
            if not rail_candidates:
                return "fail", "unknown-rail"
            if version is None:
                versions = [
                    definition.get("railVersion")
                    for definition in rail_candidates
                    if isinstance(definition.get("railVersion"), int)
                ]
                if not versions:
                    return "fail", "ambiguous-pa1-rail-version"
                version = max(versions)
            candidates = [
                definition
                for definition in rail_candidates
                if definition.get("railVersion") == version
            ]
            if len(candidates) != 1:
                return "fail", "ambiguous-pa1-rail-version"
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
    definitions = {}
    for definition in registry["definitions"]:
        key = (definition["railId"], definition["railVersion"])
        if key in definitions:
            return "indeterminate", "registry-internally-inconsistent"
        definitions[key] = definition
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
        proof_error = verify_definition_proof(definition)
        if proof_error is not None:
            indeterminate_reason = indeterminate_reason or proof_error
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
        self.assertIn("(RD-6)", dacs4)
        self.assertIn("every advertised `PaymentRailRef`", dacs4)

    def test_proof_vectors_execute_hash_and_signature_checks(self):
        cases = {vector["name"]: vector for vector in self.data["vectors"]}
        self.assertEqual(
            evaluate(cases["definition-proof-valid"]["input"]),
            ("pass", "verified"),
        )
        self.assertEqual(
            evaluate(cases["definition-content-hash-mismatch-indeterminate"]["input"]),
            ("indeterminate", "rail-definition-hash-mismatch"),
        )
        self.assertEqual(
            evaluate(cases["definition-signature-invalid-indeterminate"]["input"]),
            ("indeterminate", "rail-definition-signature-invalid"),
        )


if __name__ == "__main__":
    unittest.main()
