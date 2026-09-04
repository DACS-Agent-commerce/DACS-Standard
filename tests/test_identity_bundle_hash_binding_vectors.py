"""Execute CORE v0.3 IBH-1..IBH-6 cross-stage binding vectors."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_identity_bundle_hash_binding_vectors as generator  # noqa: E402
import jcs  # noqa: E402


VECTORS = ROOT / "conformance/vectors/security/identity-bundle-hash-binding-v0.1.json"
BARE = re.compile(r"[0-9a-f]{64}\Z")
LEGACY = re.compile(r"sha256:([0-9a-f]{64})\Z")


def result(
    expected: str,
    reason: str,
    *,
    projected_hash: str | None = None,
    comparison: str | None = None,
    preserves_legacy: bool = False,
) -> tuple[str, dict]:
    return expected, {
        "authorizedForTerminalClosure": expected == "pass",
        "reason": reason,
        "projectedBundleHash": projected_hash,
        "comparison": comparison,
        "legacyAgreementBytesPreserved": preserves_legacy,
    }


def evaluate(vector: dict) -> tuple[str, dict]:
    trusted = vector["trustedContext"]
    protocol = vector["protocolInput"]
    commitment = trusted["commitment"]
    commitment_type = commitment["type"]

    if trusted["agreementIntegrity"] != "valid":
        return result("fail", "agreement-integrity-failed")
    if commitment_type not in {"finality", "legacy"}:
        return result("error", "unsupported-commitment-type")

    agreement_wire = protocol["agreementParty"]["bundleHash"]
    agreement_match = BARE.fullmatch(agreement_wire)
    legacy_match = LEGACY.fullmatch(agreement_wire)
    agreement_digest: str
    agreement_encoding = "current"
    if agreement_match:
        agreement_digest = agreement_wire
    elif legacy_match and commitment_type == "legacy":
        if not commitment["legacyAnchorAuthenticated"]:
            return result("indeterminate", "legacy-context-not-authenticated")
        agreement_digest = legacy_match.group(1)
        agreement_encoding = "legacy"
    elif commitment_type == "legacy":
        return result("fail", "invalid-legacy-agreement-encoding")
    else:
        return result("fail", "invalid-current-agreement-encoding")

    current_fields = (
        ("composite", protocol["compositeBundleHash"]),
        ("payment", protocol["paymentPayerBundleHash"]),
        ("session", protocol["sessionParty"]["bundleHash"]),
        ("terminal", protocol["bundleParty"]["bundleHash"]),
    )
    for field, value in current_fields:
        if not BARE.fullmatch(value):
            return result("fail", f"invalid-{field}-encoding")

    resolved = trusted["resolvedIdentityBundle"]
    if resolved["state"] == "unavailable":
        return result("indeterminate", "identity-bundle-unavailable")
    if resolved["state"] != "present":
        return result("error", "invalid-resolved-identity-context")
    bundle = resolved.get("identityBundleWithoutPresentation")
    if not isinstance(bundle, dict) or "presentation" in bundle:
        return result("error", "invalid-resolved-identity-context")
    try:
        resolved_digest = hashlib.sha256(
            jcs.canonicalize(bundle).encode("utf-8")
        ).hexdigest()
    except (TypeError, ValueError):
        return result("error", "invalid-resolved-identity-context")
    if bundle.get("presentedBy") != resolved.get("primaryClaim"):
        return result("error", "invalid-resolved-identity-context")

    parties = (
        protocol["agreementParty"],
        protocol["sessionParty"],
        protocol["bundleParty"],
        resolved,
    )
    if len({party["role"] for party in parties}) != 1:
        return result("fail", "party-role-mismatch")
    if len({party["primaryClaim"] for party in parties}) != 1:
        return result("fail", "party-primary-claim-mismatch")

    if agreement_digest != resolved_digest:
        return result("fail", "agreement-bundle-digest-mismatch")
    if protocol["compositeBundleHash"] != resolved_digest:
        return result("fail", "composite-bundle-digest-mismatch")
    if protocol["paymentPayerBundleHash"] != resolved_digest:
        return result("fail", "payment-bundle-digest-mismatch")
    if protocol["sessionParty"]["bundleHash"] != resolved_digest:
        return result("fail", "session-bundle-digest-mismatch")
    if protocol["bundleParty"]["bundleHash"] != resolved_digest:
        return result("fail", "terminal-bundle-digest-mismatch")

    if agreement_encoding == "legacy":
        return result(
            "pass",
            "legacy-typed-digest-binding",
            projected_hash=resolved_digest,
            comparison="typed-legacy-digest",
            preserves_legacy=True,
        )
    return result(
        "pass",
        "current-byte-exact-binding",
        projected_hash=resolved_digest,
        comparison="byte-exact-current",
    )


class IdentityBundleHashBindingVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {vector["name"]: vector for vector in cls.data["vectors"]}

    def test_committed_file_is_deterministic(self):
        self.assertEqual(VECTORS.read_text(encoding="utf-8"), generator.rendered())

    def test_ibh1_is_recomputed_from_a_concrete_identity_bundle(self):
        vector = self.cases["current-agreement-to-terminal-succeeds"]
        resolved = vector["trustedContext"]["resolvedIdentityBundle"]
        self.assertNotIn("bundleHash", resolved)
        bundle = resolved["identityBundleWithoutPresentation"]
        self.assertNotIn("presentation", bundle)
        digest = hashlib.sha256(jcs.canonicalize(bundle).encode("utf-8")).hexdigest()
        self.assertEqual(digest, generator.DIGEST)
        self.assertEqual(
            vector["protocolInput"]["agreementParty"]["bundleHash"], digest
        )

        tampered = copy.deepcopy(vector)
        tampered["trustedContext"]["resolvedIdentityBundle"][
            "identityBundleWithoutPresentation"
        ]["presentedAt"] += 1
        self.assertEqual(evaluate(tampered)[0], "fail")

    def test_prefixed_payee_corpus_is_not_current_ibh_conformance(self):
        path = ROOT / "conformance/vectors/security/payee-destination-binding-v0.1.json"
        historical = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            historical["identityBundleHashProfile"],
            {
                "status": "historical-superseded",
                "wireEncoding": "sha256-prefixed",
                "currentAuthoring": False,
                "supersededBy": "identity-bundle-hash-binding-v0.1",
            },
        )
        self.assertEqual(
            self.data["supersedesIdentityBundleHashProfiles"],
            ["payee-destination-binding-v0.1"],
        )

    def test_every_vector_executes_to_pinned_result(self):
        for vector in self.data["vectors"]:
            with self.subTest(name=vector["name"]):
                expected, want = evaluate(vector)
                self.assertEqual(vector["expected"], expected)
                self.assertEqual(vector["want"], want)

    def test_required_issue_378_cases_are_present(self):
        self.assertTrue(
            {
                "current-agreement-to-terminal-succeeds",
                "wrong-agreement-digest-rejected",
                "current-agreement-prefixed-rejected",
                "current-payment-input-prefixed-rejected",
                "wrong-payment-input-digest-rejected",
                "prefix-insertion-invalidates-signed-agreement",
                "prefix-removal-invalidates-signed-legacy-agreement",
                "legacy-prefixed-agreement-projects-to-bare-terminal",
                "agreement-role-substitution-rejected",
                "terminal-primary-claim-substitution-rejected",
            }.issubset(self.cases)
        )

    def test_legacy_projection_is_narrow_and_preserves_original(self):
        vector = self.cases["legacy-prefixed-agreement-projects-to-bare-terminal"]
        original = vector["protocolInput"]["agreementParty"]["bundleHash"]
        expected, want = evaluate(vector)
        self.assertEqual(expected, "pass")
        self.assertTrue(original.startswith("sha256:"))
        self.assertTrue(BARE.fullmatch(want["projectedBundleHash"]))
        self.assertTrue(want["legacyAgreementBytesPreserved"])
        self.assertEqual(
            vector["protocolInput"]["agreementParty"]["bundleHash"], original
        )

    def test_equal_digest_bytes_do_not_authorize_current_prefix(self):
        vector = self.cases["current-agreement-prefixed-rejected"]
        self.assertEqual(
            vector["protocolInput"]["agreementParty"]["bundleHash"].removeprefix(
                "sha256:"
            ),
            generator.DIGEST,
        )
        self.assertEqual(evaluate(vector)[0], "fail")

    def test_spec_pins_shared_scope_and_no_normalization(self):
        core = (ROOT / "spec/CORE.md").read_text(encoding="utf-8")
        negotiate = (ROOT / "spec/DACS-3-NEGOTIATE.md").read_text(encoding="utf-8")
        verify = (ROOT / "spec/DACS-5-VERIFY.md").read_text(encoding="utf-8")
        self.assertIn("IdentityBundle digest wire profile (IBH-1..IBH-6)", core)
        self.assertIn("otherwise normalise bytes supplied as a current", core)
        self.assertIn("`FinalityCommitmentRecord`", negotiate)
        self.assertIn("MUST NOT be emitted by a current agreement", negotiate)
        self.assertIn("Cross-stage IdentityBundle binding", verify)


if __name__ == "__main__":
    unittest.main()
