"""Checks for conformance/vectors/security/fault-bundle-perspective-pair-v0.3.json.

Exercises the §10.4.3 FaultAttestationBundle-pair rule and the §10.4.1 permissible set.
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
VECTOR_PATH = ROOT / "conformance" / "vectors" / "security" / "fault-bundle-perspective-pair-v0.3.json"

EXPECTED_NAMES = {
    "fab-pair-converges-same-fault",
    "fab-pair-faultedparty-divergent",
    "fab-copy-faultedparty-out-of-set",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def bundle_hash(bundle):
    unsigned = {k: v for k, v in bundle.items() if k not in ("signatures", "anchoredByRole")}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def _other(role):
    return "seller" if role == "buyer" else "buyer"


def permissible(outcome, anchored_by_role):
    if outcome in ("completed", "failed-substrate"):
        return {"none"}
    if outcome in ("failed-perm", "aborted-by-self"):
        return {anchored_by_role}
    if outcome in ("failed-counterparty", "aborted-by-other"):
        return {_other(anchored_by_role)}
    return set()


class FaultBundlePerspectivePairTests(unittest.TestCase):
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
            self.assertIn(v["expected"], {"pass", "fail"})

    def test_every_copy_is_a_fault_attestation_bundle(self):
        for v in self.vectors:
            for role, bundle in v["copies"].items():
                with self.subTest(vector=v["name"], role=role):
                    self.assertEqual(bundle.get("faultBundleVersion"), "1")
                    self.assertNotIn("bundleVersion", bundle)

    def test_converge_pair_shares_faultedparty(self):
        v = self.by_name["fab-pair-converges-same-fault"]
        self.assertEqual(v["expected"], "pass")
        fps = {b["faultedParty"] for b in v["copies"].values()}
        self.assertEqual(fps, {"seller"}, "converging pair names one absolute faultedParty")
        self.assertEqual(v["want"]["convergence"], "unified")

    def test_divergent_pair_has_conflicting_faultedparty(self):
        v = self.by_name["fab-pair-faultedparty-divergent"]
        self.assertEqual(v["expected"], "fail")
        fps = {b["faultedParty"] for b in v["copies"].values()}
        self.assertEqual(len(fps), 2, "divergent pair names two different faultedParty values")
        self.assertEqual(v["want"]["convergence"], "divergent")

    def test_out_of_set_copy_is_rejected(self):
        v = self.by_name["fab-copy-faultedparty-out-of-set"]
        self.assertEqual(v["expected"], "fail")
        (bundle,) = list(v["copies"].values())
        allowed = permissible(bundle["outcome"], bundle["anchoredByRole"])
        self.assertNotIn(bundle["faultedParty"], allowed)
        self.assertEqual(v["want"]["copyDisposition"], "rejected")

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography package not installed; CI runs the stdlib checks.")
    def test_signatures_verify(self):
        keys = {r: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)) for r, s in self.data["seeds"].items()}
        pub = {f"did:demos:{r}": keys[r].public_key() for r in self.data["seeds"]}
        for v in self.vectors:
            for role, bundle in v["copies"].items():
                payload = ("dacs-fault-bundle:v1:" + bundle_hash(bundle)).encode("utf-8")
                for s in bundle["signatures"]:
                    with self.subTest(vector=v["name"], role=role, party=s["party"]):
                        try:
                            pub[s["party"]].verify(
                                base64.urlsafe_b64decode(s["value"] + "=" * (-len(s["value"]) % 4)), payload)
                        except InvalidSignature:
                            self.fail("FAB signature must verify over dacs-fault-bundle:v1:")


if __name__ == "__main__":
    unittest.main()
