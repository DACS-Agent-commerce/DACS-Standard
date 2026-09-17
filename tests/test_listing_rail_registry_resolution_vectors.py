"""Executable assertions for DACS-1 §6.3.4 LRR-1..LRR-6 candidate vectors."""

import base64
import hashlib
import json
import unittest
import unicodedata
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


def compose_listing_validation(
    *,
    ordinary_failure=False,
    revocation="absent",
    rail_resolution="verified",
    signer_controls_key=True,
):
    """Compose the §6.3.4 ordered checks into the overall listing result."""

    if ordinary_failure:
        return "rejected"
    if revocation in {"revoked", "indeterminate"}:
        return revocation
    if rail_resolution == "rejected":
        return "rejected"
    if not signer_controls_key:
        return "rejected"
    if rail_resolution == "indeterminate":
        return "indeterminate"
    if rail_resolution in {"verified", "not-applicable"}:
        return "verified"
    raise ValueError("unsupported validation input")


def _positive_version(value):
    return type(value) is int and 0 < value <= 9007199254740991


def _registry_identity(value):
    return unicodedata.normalize("NFC", value) if isinstance(value, str) else None


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
            if "railVersion" in ref and not _positive_version(version):
                return "fail", "ambiguous-pa1-rail-version"
            rail_candidates = [
                definition for definition in definitions
                if definition.get("railId") == ref["railId"]
            ]
            if not rail_candidates:
                return "fail", "unknown-rail"
            candidate_handlers = [
                definition.get("phaseHandler") for definition in rail_candidates
            ]
            if any(not isinstance(handler, str) for handler in candidate_handlers):
                return "indeterminate", "pa1-definition-unverifiable"
            if len(set(candidate_handlers)) != 1:
                return "fail", "pa1-handler-version-drift"
            versions = [definition.get("railVersion") for definition in rail_candidates]
            if any(not _positive_version(value) for value in versions):
                return "fail", "ambiguous-pa1-rail-version"
            if "railVersion" not in ref:
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

    # This fixture projection summarizes an authenticated index. Derive latest
    # from its complete numeric inventory; latestVersion is only an inert hint.
    entries = {}
    for entry in registry["entries"]:
        identifier = _registry_identity(entry.get("railId"))
        versions = entry.get("versions")
        if (not identifier or identifier in entries or not isinstance(versions, list)
                or not versions or any(not _positive_version(v) for v in versions)
                or len(versions) != len(set(versions))):
            return "indeterminate", "registry-internally-inconsistent"
        entries[identifier] = entry
    definitions = {}
    for definition in registry["definitions"]:
        if not _positive_version(definition.get("railVersion")):
            return "indeterminate", "registry-internally-inconsistent"
        key = (_registry_identity(definition["railId"]), definition["railVersion"])
        if key in definitions:
            return "indeterminate", "registry-internally-inconsistent"
        definitions[key] = definition
    rejected_reason = None
    indeterminate_reason = None
    resolved_handlers = {}

    for ref in accepted:
        entry = entries.get(_registry_identity(ref["railId"]))
        if entry is None:
            rejected_reason = rejected_reason or "unknown-rail"
            continue
        version = ref["railVersion"] if "railVersion" in ref else max(entry["versions"])
        if not _positive_version(version):
            rejected_reason = rejected_reason or "unknown-rail-version"
            continue
        if version not in entry["versions"]:
            rejected_reason = rejected_reason or "unknown-rail-version"
            continue
        definition = definitions.get((_registry_identity(ref["railId"]), version))
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

    def test_pa1_unpinned_rejects_cross_version_handler_drift(self):
        cases = {vector["name"]: vector for vector in self.data["vectors"]}
        self.assertEqual(
            evaluate(cases["pa1-unpinned-cross-version-handler-drift-rejected"]["input"]),
            ("fail", "pa1-handler-version-drift"),
        )
        self.assertEqual(
            evaluate(cases["pa1-unpinned-selects-unique-highest-version"]["input"]),
            ("pass", "verified-pa1"),
        )

    def test_overall_listing_disposition_composition(self):
        self.assertEqual(
            compose_listing_validation(ordinary_failure=True),
            "rejected",
        )
        self.assertEqual(
            compose_listing_validation(revocation="revoked"),
            "revoked",
        )
        self.assertEqual(
            compose_listing_validation(revocation="indeterminate"),
            "indeterminate",
        )
        self.assertEqual(
            compose_listing_validation(rail_resolution="rejected"),
            "rejected",
        )
        self.assertEqual(
            compose_listing_validation(
                rail_resolution="indeterminate",
                signer_controls_key=False,
            ),
            "rejected",
        )
        self.assertEqual(
            compose_listing_validation(
                rail_resolution="indeterminate",
                signer_controls_key=True,
            ),
            "indeterminate",
        )
        self.assertEqual(
            compose_listing_validation(rail_resolution="not-applicable"),
            "verified",
        )


if __name__ == "__main__":
    unittest.main()
