"""Every committed signature label matches the encoding its value carries.

CORE §B.7 makes the decoded value algorithm-specific: an ``ecdsa-secp256k1``
value is canonical DER with low S, and a verifier rejects anything else
before consulting a key. A fixture that relabels Ed25519 bytes as
``ecdsa-secp256k1`` therefore carries an encoding ``fail``, not the
``error`` or ``indeterminate`` its name suggests, for every verifier that
implements the registered algorithm. Only cases about the encoding itself
may carry a non-canonical value.
"""
import base64
import json
import re
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "scripts"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from reputation_evidence import artifact_hash  # noqa: E402
from scripts.secp256k1_fixture import (  # noqa: E402
    SECP256K1_ORDER,
    deterministic_ecdsa_signature,
    fixture_private_value,
)

VECTORS = ROOT / "conformance" / "vectors"
SECURITY = VECTORS / "security"

# Cases whose question is the ECDSA encoding itself; each expects `fail`.
NONCANONICAL_ECDSA_CASES = {
    ("canonical-channel-message-v0.6.json", "canonical-algorithm-key-confusion"),
    ("canonical-channel-message-v0.6.json", "canonical-ecdsa-high-s"),
    ("canonical-channel-message-v0.6.json", "canonical-ecdsa-fixed-width-r-s"),
    ("canonical-channel-message-v0.6.json", "canonical-ecdsa-der-long-form-length"),
    ("settlement-finality-verification.json", "fv-rail-signature-ecdsa-high-s-steward-keys-unavailable"),
    ("settlement-finality-verification.json", "fv-evidence-signature-ecdsa-high-s-party-keys-unavailable"),
    ("settlement-finality-verification.json", "fv-agreement-signature-ecdsa-high-s-party-keys-unavailable"),
}

# Portable typed-authorization cases deliberately carrying invalid DER.
NONCANONICAL_ECDSA_CASES.update(
    ("signature-authorization-v0.1.json", typ + "-" + variant)
    for typ in ("ListingSignature", "RevocationSignature", "AgreementSignature",
                "ComponentSignature", "RailSignature", "BundleSignature",
                "ChannelMessageSignature", "RecipeSignature", "VerifyResultSignature")
    for variant in ("ecdsa-r-zero", "ecdsa-s-zero", "ecdsa-r-order", "ecdsa-s-order",
                    "ecdsa-trailing-bytes", "ecdsa-nonminimal-integer")
)

# Cases about a registered algorithm the fixture resolver does not implement.
UNAVAILABLE_ECDSA_CASES = {
    ("reputation-participation-admission-v0.7.json", "spa-supported-channel-algorithm-unavailable",
     b"dacs-395-ecdsa-unavailable", "dacs-channelmsg:v1:"),
    ("reputation-participation-admission-v0.7.json", "spa-rfq-unrelated-malformed-and-unavailable-sources-ignored",
     b"dacs-395-ecdsa-unavailable", "dacs-channelmsg:v1:"),
    ("revocation-state-completeness-v0.8.json", "rsc-wrong-signature-algorithm",
     b"rsc-ecdsa-unavailable", "dacs-revocation:v1:"),
}


def b64url_decode(value):
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ValueError("non-canonical Base64URL")
    return raw


def canonical_ecdsa(value):
    """The CORE §B.7 check, independent of any key."""
    try:
        raw = b64url_decode(value)
        r, s = utils.decode_dss_signature(raw)
    except (ValueError, TypeError):
        return False
    return (
        utils.encode_dss_signature(r, s) == raw
        and 1 <= r < SECP256K1_ORDER
        and 1 <= s <= SECP256K1_ORDER // 2
    )


def cases():
    for path in sorted(VECTORS.rglob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or not isinstance(document.get("vectors"), list):
            continue
        for case in document["vectors"]:
            if isinstance(case, dict):
                yield path, case


def envelopes(node, algorithm):
    if isinstance(node, dict):
        if node.get("algorithm") == algorithm and "value" in node:
            yield node
        for item in node.values():
            yield from envelopes(item, algorithm)
    elif isinstance(node, list):
        for item in node:
            yield from envelopes(item, algorithm)


class SignatureValueEncodingCorpusTests(unittest.TestCase):
    def test_ecdsa_values_are_canonical_unless_the_case_is_about_encoding(self):
        noncanonical = set()
        seen = 0
        for path, case in cases():
            for envelope in envelopes(case, "ecdsa-secp256k1"):
                seen += 1
                if not canonical_ecdsa(envelope["value"]):
                    noncanonical.add((path.name, case["name"]))
                    with self.subTest(case=case["name"]):
                        self.assertEqual(case["expected"], "fail")
        self.assertGreater(seen, 0)
        self.assertEqual(noncanonical, NONCANONICAL_ECDSA_CASES)

    def test_unavailable_algorithm_cases_carry_a_real_signature_over_the_signed_bytes(self):
        by_name = {(path.name, case["name"]): case for path, case in cases()}
        for file_name, name, label, domain in UNAVAILABLE_ECDSA_CASES:
            with self.subTest(case=name):
                case = by_name[(file_name, name)]
                self.assertIn(case["expected"], {"fail", "indeterminate", "pass"})
                public_key = ec.derive_private_key(
                    fixture_private_value(label), ec.SECP256K1()
                ).public_key()
                artifacts = [
                    artifact for artifact in _signed_artifacts(case)
                    if artifact["signature"].get("algorithm") == "ecdsa-secp256k1"
                ]
                self.assertEqual(len(artifacts), 1)
                artifact = artifacts[0]
                payload = (domain + artifact_hash(artifact)).encode("ascii")
                public_key.verify(
                    b64url_decode(artifact["signature"]["value"]),
                    payload,
                    ec.ECDSA(hashes.SHA256()),
                )

    def test_fixture_signer_is_deterministic_low_s_der(self):
        value = fixture_private_value(b"dacs-signature-encoding-self-check")
        payload = b"dacs-test:v1:" + b"00" * 32
        first = deterministic_ecdsa_signature(value, payload)
        self.assertEqual(first, deterministic_ecdsa_signature(value, payload))
        self.assertTrue(canonical_ecdsa(base64.urlsafe_b64encode(first).rstrip(b"=").decode()))
        ec.derive_private_key(value, ec.SECP256K1()).public_key().verify(
            first, payload, ec.ECDSA(hashes.SHA256())
        )

    def test_signature_defects_carry_one_verdict_per_sig7_stage(self):
        # CORE §B.7 SIG-7: in the corpora that verify a signature envelope and
        # report its verdict directly, an algorithm outside the envelope's set
        # and a wire-stage failure are `error`; an invalid decoded format is
        # `fail`. The same defect cannot carry two verdicts across modules.
        seen = {"algorithm": 0, "wire": 0, "format": 0}
        for path, case in cases():
            if path.name not in SIG7_CORPORA:
                continue
            for envelope, allowed in typed_envelopes(case):
                defect = sig7_defect(envelope, allowed)
                if defect is None:
                    continue
                seen[defect] += 1
                with self.subTest(corpus=path.name, case=case["name"], defect=defect):
                    self.assertEqual(SIG7_VERDICT[defect], case["expected"])
        # Each stage is exercised somewhere, so the check cannot pass vacuously.
        self.assertTrue(all(seen.values()), seen)

    def test_attestation_and_certificate_algorithm_sets_are_typed(self):
        # The FV attestation and certificate algorithm fields name their one
        # admitted algorithm, and RailSignature is a defined envelope type.
        settle = (ROOT / "spec" / "DACS-4-SETTLE.md").read_text(encoding="utf-8")
        self.assertIn("type RailSignature = ComponentSignature", settle)
        self.assertIn('attestations: { authorityRef: string; algorithm: "ed25519"; value: string }[]', settle)
        self.assertIn('signatures: { validatorId: string; algorithm: "ed25519"; value: string }[]', settle)
        self.assertNotRegex(settle, r"algorithm: string")
        core = (ROOT / "spec" / "CORE.md").read_text(encoding="utf-8")
        self.assertIn("(SIG-7) **One verdict per signature defect.**", core)

    def test_fv_rail_envelope_error_names_an_unregistered_algorithm(self):
        # The `error` verdict holds for every verifier only when the label is
        # outside the closed ComponentSignature algorithm set.
        settle = (ROOT / "spec" / "DACS-4-SETTLE.md").read_text(encoding="utf-8")
        match = re.search(
            r"type ComponentSignature = \{\s*algorithm: ((?:\"[^\"]+\"(?: \| )?)+)", settle
        )
        self.assertIsNotNone(match)
        registered = set(re.findall(r"\"([^\"]+)\"", match.group(1)))
        self.assertEqual(registered, {"ed25519", "ecdsa-secp256k1", "sr1-aggregate"})
        corpus = json.loads(
            (SECURITY / "settlement-finality-verification.json").read_text(encoding="utf-8")
        )
        case = next(
            item for item in corpus["vectors"]
            if item["name"] == "fv-rail-signature-envelope-malformed"
        )
        self.assertEqual(case["expected"], "error")
        self.assertNotIn(case["input"]["rail"]["signature"]["algorithm"], registered)


COMPONENT_ALGORITHMS = frozenset({"ed25519", "ecdsa-secp256k1", "sr1-aggregate"})
ED25519_ONLY = frozenset({"ed25519"})

# Corpora whose cases verify a signature envelope and report that verdict
# directly. DACS-5 SPA folds a rejected artifact into its admission `fail`
# (SPA-1), and the historical/legacy corpora carry legacy spellings by design.
SIG7_CORPORA = {
    "settlement-finality-verification.json",
    "finality-resolution-context-v1.json",
    "canonical-channel-message-v0.6.json",
    "signature-authorization-v0.1.json",
}
SIG7_VERDICT = {"algorithm": "error", "wire": "error", "format": "fail"}
BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z")


def typed_envelopes(node, allowed=COMPONENT_ALGORITHMS):
    """Yield (envelope, algorithm set) for each DACS signature envelope.

    Attestations, certificate signatures and observation-response signatures
    admit ed25519 alone (DACS-4 §9.7.0); other envelopes are ComponentSignature.
    """
    if isinstance(node, dict):
        if "algorithm" in node and "value" in node:
            narrow = {"authorityRef", "validatorId", "keyId"} & set(node)
            yield node, ED25519_ONLY if narrow else allowed
        for item in node.values():
            yield from typed_envelopes(item, allowed)
    elif isinstance(node, list):
        for item in node:
            yield from typed_envelopes(item, allowed)


def sig7_defect(envelope, allowed):
    algorithm = envelope.get("algorithm")
    if not isinstance(algorithm, str) or algorithm not in allowed:
        return "algorithm"
    value = envelope.get("value")
    if not isinstance(value, str) or not BASE64URL.fullmatch(value) or len(value) % 4 == 1:
        return "wire"
    try:
        raw = b64url_decode(value)
    except ValueError:
        return "wire"
    if algorithm == "ed25519":
        return None if len(raw) == 64 else "format"
    if algorithm == "ecdsa-secp256k1":
        return None if canonical_ecdsa(value) else "format"
    return None  # CORE §B.7 defines no decoded format for sr1-aggregate


def _signed_artifacts(node):
    if isinstance(node, dict):
        if isinstance(node.get("signature"), dict) and "algorithm" in node["signature"]:
            yield node
        for item in node.values():
            yield from _signed_artifacts(item)
    elif isinstance(node, list):
        for item in node:
            yield from _signed_artifacts(item)


if __name__ == "__main__":
    unittest.main()
