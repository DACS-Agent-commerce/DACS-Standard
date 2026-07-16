"""Checks for conformance/vectors/security/mixed-version-reconciliation-v0.3.json.

Exercises the §10.4.3 mixed-version rule: a FaultAttestationBundle copy paired with a
legacy AttestationBundle copy. Signature verification is skipped when ``cryptography``
is unavailable.
"""
import base64
import hashlib
import json
import unittest
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.exceptions import InvalidSignature
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False

ROOT = Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "conformance" / "vectors" / "security" / "mixed-version-reconciliation-v0.3.json"

EXPECTED_NAMES = {
    "mixed-nondivergent-fab-authoritative",
    "mixed-implied-fault-contradiction",
    "mixed-outcome-class-contradiction",
    "mixed-phasesummary-kind-mismatch",
    "legacy-legacy-outcome-spelling-control",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def bundle_hash(bundle):
    unsigned = {k: v for k, v in bundle.items() if k not in ("signatures", "anchoredByRole")}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


class MixedVersionReconciliationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        cls.vectors = cls.data["vectors"]
        cls.by_name = {v["name"]: v for v in cls.vectors}

    def test_set_metadata(self):
        self.assertEqual(self.data["set"], VECTOR_PATH.stem)
        self.assertEqual(self.data["count"], len(self.vectors))
        names = [v["name"] for v in self.vectors]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), EXPECTED_NAMES)

    def test_verdict_and_hash(self):
        for v in self.vectors:
            self.assertIn(v["expected"], {"pass", "fail"})
        encoded = json.dumps(self.vectors, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
        self.assertEqual(self.data["hash"], hashlib.sha256(encoded).hexdigest())

    def test_copies_are_typed_correctly(self):
        for v in self.vectors:
            for role, bundle in v["copies"].items():
                is_fab = "faultBundleVersion" in bundle
                is_legacy = "bundleVersion" in bundle
                with self.subTest(vector=v["name"], role=role):
                    self.assertNotEqual(is_fab, is_legacy, "a copy is exactly one bundle type")
                    if is_fab:
                        self.assertEqual(bundle["faultBundleVersion"], "1")
                        self.assertIn("faultedParty", bundle)
                    else:
                        self.assertEqual(bundle["bundleVersion"], "1")
                        self.assertNotIn("faultedParty", bundle)

    def test_convergence_and_authority(self):
        # non-divergent mixed pair -> unified, FAB authoritative, include
        v = self.by_name["mixed-nondivergent-fab-authoritative"]
        self.assertEqual(v["expected"], "pass")
        self.assertEqual(v["want"]["convergence"], "unified")
        self.assertEqual(v["want"]["authoritativeCopyType"], "FaultAttestationBundle")
        self.assertEqual(v["want"]["reputationEffect"], "include")
        # legacy control -> unified, legacy authoritative
        c = self.by_name["legacy-legacy-outcome-spelling-control"]
        self.assertEqual(c["want"]["authoritativeCopyType"], "AttestationBundle")
        # all divergent vectors exclude
        for name in ("mixed-implied-fault-contradiction", "mixed-outcome-class-contradiction",
                     "mixed-phasesummary-kind-mismatch"):
            with self.subTest(vector=name):
                self.assertEqual(self.by_name[name]["expected"], "fail")
                self.assertEqual(self.by_name[name]["want"]["convergence"], "divergent")
                self.assertEqual(self.by_name[name]["want"]["reputationEffect"], "exclude")

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography package not installed; CI runs the stdlib checks.")
    def test_signatures_verify(self):
        keys = {r: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)) for r, s in self.data["seeds"].items()}
        pub = {f"did:demos:{r}": keys[r].public_key() for r in self.data["seeds"]}
        for claim, expected in self.data["publicKeys"].items():
            self.assertEqual(
                base64.urlsafe_b64encode(pub[claim].public_bytes_raw()).rstrip(b"=").decode("ascii"), expected)
        for v in self.vectors:
            for role, bundle in v["copies"].items():
                domain = "dacs-fault-bundle:v1:" if "faultBundleVersion" in bundle else "dacs-bundle:v1:"
                payload = (domain + bundle_hash(bundle)).encode("utf-8")
                for s in bundle["signatures"]:
                    with self.subTest(vector=v["name"], role=role, party=s["party"]):
                        try:
                            pub[s["party"]].verify(
                                base64.urlsafe_b64decode(s["value"] + "=" * (-len(s["value"]) % 4)), payload)
                        except InvalidSignature:
                            self.fail("signature must verify over the type's §B.7 domain")


if __name__ == "__main__":
    unittest.main()
