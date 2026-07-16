"""Checks for conformance/vectors/security/outsider-binding-flooding-v0.3.json.

Exercises the §10.4.2 BB-6 authorized-candidate rule. Round-5 adds the round-4 blocker #2
fixes (E6): a per-signer fetch budget plus a mandatory derivation-context prune. Two new
vectors run the EXECUTED resolver (tests/dacs5_reference.resolve_bb6):

  - outsider-flood-worst-order: nine outsider hashes ALL sort STRICTLY BELOW the honest
    hash — the adversarial ordering the round-3 vector avoided (its test asserted the
    convenient "honest within the first 8" ordering). Here the assertion is inverted and
    the honest copy still resolves, because the per-signer budget isolates each signer.
  - outsider-sybil-flood: eight DISTINCT outsider keypairs cannot starve the honest
    signer's per-signer allocation.

A global-budget / no-prune resolver (the mutation) would return indeterminate on both.
Signature verification is gated on `cryptography`.
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
VECTOR_PATH = ROOT / "conformance" / "vectors" / "security" / "outsider-binding-flooding-v0.3.json"

EXPECTED_NAMES = {
    "outsider-flood-nine-plus-one-honest",
    "co-signed-map-prefetch-prunes-outsiders",
    "honest-self-flood-budget-exhaustion",
    "outsider-flood-no-honest-binding",
    "outsider-flood-worst-order",
    "outsider-sybil-flood",
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
        for v in self.vectors:
            with self.subTest(vector=v["name"]):
                self.assertFalse(v["want"].get("void", False), "no vector may resolve to a void")

    def test_worst_order_hashes_sort_strictly_below_honest(self):
        """Round-5, inverted from round-4: assert ADVERSARIALLY that at least eight outsider
        hashes sort strictly below the honest binding's hash — the ordering the attacker
        controls — and require the honest copy to still resolve."""
        v = self.by_name["outsider-flood-worst-order"]
        honest = v["honestContentHash"]
        outsider = [b["bundleContentHash"] for b in v["bindings"] if b["signer"] != "did:demos:seller"]
        below = [h for h in outsider if h < honest]
        self.assertGreaterEqual(len(below), 8, "worst-order must place >=8 outsider hashes below the honest one")
        res = R.resolve_bb6(v["bindings"], party_map=v["partyMap"], anchored=v["anchored"])
        self.assertEqual(res["disposition"], "present")
        self.assertEqual(res["resolvedNativeAddress"], v["want"]["resolvedNativeAddress"])

    def test_sybil_distinct_keys_do_not_starve_honest(self):
        """Eight DISTINCT outsider keys, each its own per-signer bucket; the honest signer
        still resolves. A global (jobId,role) budget would let them crowd it out."""
        v = self.by_name["outsider-sybil-flood"]
        signers = {b["signer"] for b in v["bindings"] if b["signer"] != "did:demos:seller"}
        self.assertEqual(len(signers), 8, "sybil flood must use 8 distinct outsider keys")
        res = R.resolve_bb6(v["bindings"], party_map=v["partyMap"], anchored=v["anchored"])
        self.assertEqual(res["disposition"], "present")
        self.assertEqual(res["resolvedNativeAddress"], v["want"]["resolvedNativeAddress"])

    def test_executed_resolver_matches_want_disposition(self):
        """Run resolve_bb6 over every vector that carries a partyMap/anchored and require the
        executed disposition to agree with want.sideDisposition."""
        for v in self.vectors:
            if "partyMap" not in v:
                continue
            res = R.resolve_bb6(v["bindings"], party_map=v.get("partyMap"), anchored=v.get("anchored"))
            with self.subTest(vector=v["name"]):
                self.assertEqual(res["disposition"], v["want"]["sideDisposition"])

    def test_no_authorized_binding_is_indeterminate_not_absent(self):
        v = self.by_name["outsider-flood-no-honest-binding"]
        self.assertEqual(v["expected"], "indeterminate")
        self.assertEqual(v["want"]["authorizedBindings"], 0)
        self.assertFalse(v["want"]["absent"])
        self.assertEqual(v["want"]["sideDisposition"], "indeterminate")

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography package not installed; CI runs the stdlib checks.")
    def test_all_signatures_verify(self):
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
