"""Checks for conformance/vectors/security/fab-bundle-extended-pointer-v0.3.json.

Round-5 B4: the round-4 review found the extended-pointer path had no FAB pointer form
and no executable case, and the BB-5 hash/dereference order was ambiguous. E7 adds the
`FaultBundleExtendedPointer` type (dacs-fault-bundle-pointer:v1: domain) and the
triple-identity order rule: binding.bundleContentHash == pointer.fullBundleContentHash ==
the recomputed §10.4.1 hash of the DEREFERENCED full bundle.

This test dereferences the inline full bundle, recomputes its §10.4.1 hash, and executes
tests/dacs5_reference.resolve_fab_pointer to assert the triple-identity — so the
content-mismatch vector (pointer and binding agree, but neither equals the dereferenced
hash) is rejected, which a compare-the-pointer's-own-hash shortcut would wrongly accept.
"""
import base64
import hashlib
import json
import unittest
from pathlib import Path

import dacs5_reference as R

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.exceptions import InvalidSignature
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False

ROOT = Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "conformance" / "vectors" / "security" / "fab-bundle-extended-pointer-v0.3.json"

EXPECTED_NAMES = {"fab-pointer-valid", "fab-pointer-content-mismatch"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def bundle_hash(bundle):
    unsigned = {k: v for k, v in bundle.items() if k not in ("signatures", "anchoredByRole")}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


class FabBundleExtendedPointerTests(unittest.TestCase):
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

    def test_pointer_is_fault_typed_discriminator(self):
        """E7: a FAB pointer carries faultBundleVersion and never bundleVersion."""
        for v in self.vectors:
            p = v["pointer"]
            with self.subTest(vector=v["name"]):
                self.assertEqual(p["faultBundleVersion"], "1")
                self.assertNotIn("bundleVersion", p)
                self.assertEqual(p["pointerKind"], "extended")

    def test_executed_triple_identity(self):
        """Dereference the inline full bundle, recompute its §10.4.1 hash, and require the
        executed predicate to agree with want.tripleIdentity. The content-mismatch vector
        MUST reject even though pointer and binding agree — that is the E7 order rule."""
        for v in self.vectors:
            res = R.resolve_fab_pointer(v["pointer"], v["dereferenced"], v["binding"])
            with self.subTest(vector=v["name"]):
                self.assertEqual(res["ok"], v["want"]["tripleIdentity"],
                                 "resolve_fab_pointer(%s) disagrees with want (%s)" % (res, v["want"]))
                # the recomputed §10.4.1 hash is the anchor of the identity
                self.assertEqual(res["recomputedHash"], bundle_hash(v["dereferenced"]))

    def test_content_mismatch_is_rejected_not_absence(self):
        """The mismatch vector: pointer.fullBundleContentHash == binding.bundleContentHash,
        yet BOTH differ from the dereferenced bundle's hash -> rejected content (BB-7)."""
        v = self.by_name["fab-pointer-content-mismatch"]
        self.assertEqual(v["pointer"]["fullBundleContentHash"], v["binding"]["bundleContentHash"])
        self.assertNotEqual(v["pointer"]["fullBundleContentHash"], bundle_hash(v["dereferenced"]))
        self.assertFalse(R.resolve_fab_pointer(v["pointer"], v["dereferenced"], v["binding"])["ok"])

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography package not installed; CI runs the stdlib checks.")
    def test_signatures_verify(self):
        keys = {r: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)) for r, s in self.data["seeds"].items()}
        pub = {f"did:demos:{r}": keys[r].public_key() for r in self.data["seeds"]}
        for v in self.vectors:
            # dereferenced full bundle signs under dacs-fault-bundle:v1:
            payload = ("dacs-fault-bundle:v1:" + bundle_hash(v["dereferenced"])).encode("utf-8")
            for s in v["dereferenced"]["signatures"]:
                with self.subTest(vector=v["name"], party=s["party"]):
                    pub[s["party"]].verify(
                        base64.urlsafe_b64decode(s["value"] + "=" * (-len(s["value"]) % 4)), payload)
            # pointer signs under dacs-fault-bundle-pointer:v1:
            p = v["pointer"]
            unsigned = {k: val for k, val in p.items() if k != "signature"}
            ph = hashlib.sha256(canonical(unsigned)).hexdigest()
            ppayload = ("dacs-fault-bundle-pointer:v1:" + ph).encode("utf-8")
            with self.subTest(vector=v["name"], part="pointer-sig"):
                try:
                    pub[p["signature"]["signer"]].verify(
                        base64.urlsafe_b64decode(p["signature"]["value"] + "=" * (-len(p["signature"]["value"]) % 4)),
                        ppayload)
                except InvalidSignature:
                    self.fail("pointer signature must verify over dacs-fault-bundle-pointer:v1: (E7)")


if __name__ == "__main__":
    unittest.main()
