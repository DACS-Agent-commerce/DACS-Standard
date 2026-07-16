"""Checks for conformance/vectors/security/outsider-binding-flooding-v0.3.json.

Exercises the §10.4.2 BB-6 authorized-candidate rule against the round-3 blocker #4
attack: an outsider cannot force a void, and budget exhaustion / no-authorized-binding
resolve to indeterminate, never absent and never a void.
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
VECTOR_PATH = ROOT / "conformance" / "vectors" / "security" / "outsider-binding-flooding-v0.3.json"

EXPECTED_NAMES = {
    "outsider-flood-nine-plus-one-honest",
    "co-signed-map-prefetch-prunes-outsiders",
    "honest-self-flood-budget-exhaustion",
    "outsider-flood-no-honest-binding",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def bundle_hash(bundle):
    unsigned = {k: v for k, v in bundle.items() if k not in ("signatures", "anchoredByRole")}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def binding_hash(binding):
    unsigned = {k: v for k, v in binding.items() if k != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


class OutsiderBindingFloodingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        cls.vectors = cls.data["vectors"]
        cls.by_name = {v["name"]: v for v in cls.vectors}

    def test_set_metadata(self):
        self.assertEqual(self.data["set"], VECTOR_PATH.stem)
        self.assertEqual(self.data["count"], len(self.vectors))
        self.assertEqual({v["name"] for v in self.vectors}, EXPECTED_NAMES)
        encoded = json.dumps(self.vectors, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
        self.assertEqual(self.data["hash"], hashlib.sha256(encoded).hexdigest())
        for v in self.vectors:
            self.assertIn(v["expected"], {"pass", "indeterminate"})

    def test_no_vector_ever_voids(self):
        # the core round-3 property: an outsider flood never produces a void.
        for v in self.vectors:
            with self.subTest(vector=v["name"]):
                self.assertFalse(v["want"].get("void", False), "no vector may resolve to a void")

    def test_honest_copy_resolves_over_flood(self):
        v = self.by_name["outsider-flood-nine-plus-one-honest"]
        self.assertEqual(v["expected"], "pass")
        self.assertEqual(v["want"]["authorizedBindings"], 1)
        self.assertEqual(v["want"]["outsiderBindings"], 9)
        self.assertEqual(v["want"]["sideDisposition"], "present")
        self.assertIn(v["want"]["resolvedNativeAddress"], v["anchored"])

    def test_honest_binding_sorts_within_fetch_budget(self):
        # BB-6 fetches at most N=8 candidates in ascending bundleContentHash order. The honest
        # (victim-role-holder-signed) binding must sort within the first 8, or the pass verdict is
        # unreachable — this pins it so regeneration can never silently break it.
        v = self.by_name["outsider-flood-nine-plus-one-honest"]
        ordered = sorted(v["bindings"], key=lambda b: b["bundleContentHash"])
        honest_index = next(
            i for i, b in enumerate(ordered, start=1)
            if b["signature"]["signer"] == "did:demos:seller"
        )
        self.assertLessEqual(honest_index, 8, "honest binding must sort within the N=8 fetch budget")

    def test_budget_exhaustion_is_indeterminate(self):
        v = self.by_name["honest-self-flood-budget-exhaustion"]
        self.assertEqual(v["expected"], "indeterminate")
        self.assertGreater(v["want"]["authorizedCandidates"], v["want"]["budget"])
        self.assertEqual(v["want"]["sideDisposition"], "indeterminate")

    def test_no_authorized_binding_is_indeterminate_not_absent(self):
        v = self.by_name["outsider-flood-no-honest-binding"]
        self.assertEqual(v["expected"], "indeterminate")
        self.assertEqual(v["want"]["authorizedBindings"], 0)
        self.assertFalse(v["want"]["absent"])
        self.assertEqual(v["want"]["sideDisposition"], "indeterminate")

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography package not installed; CI runs the stdlib checks.")
    def test_all_signatures_verify(self):
        # Even outsider bindings are validly self-signed (BB-4 passes); their failure is authorization,
        # not signature.
        keys = {r: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)) for r, s in self.data["seeds"].items()}
        pub = {f"did:demos:{r}": keys[r].public_key() for r in self.data["seeds"]}
        for v in self.vectors:
            for addr, bundle in v.get("anchored", {}).items():
                payload = ("dacs-fault-bundle:v1:" + bundle_hash(bundle)).encode("utf-8")
                for s in bundle["signatures"]:
                    with self.subTest(vector=v["name"], addr=addr, party=s["party"]):
                        pub[s["party"]].verify(
                            base64.urlsafe_b64decode(s["value"] + "=" * (-len(s["value"]) % 4)), payload)
            for i, binding in enumerate(v.get("bindings", [])):
                payload = ("dacs-bundle-binding:v1:" + binding_hash(binding)).encode("utf-8")
                signer = binding["signature"]["signer"]
                with self.subTest(vector=v["name"], binding=i):
                    try:
                        pub[signer].verify(
                            base64.urlsafe_b64decode(binding["signature"]["value"] + "=" * (-len(binding["signature"]["value"]) % 4)),
                            payload)
                    except InvalidSignature:
                        self.fail("binding signature must verify over dacs-bundle-binding:v1: (BB-4)")


if __name__ == "__main__":
    unittest.main()
