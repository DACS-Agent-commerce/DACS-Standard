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
    "outsider-flood-worst-order-no-map",
    "cross-role-insider-binding-pruned",
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

    def test_executed_resolver_matches_want(self):
        """Run resolve_bb6 over EVERY vector (round-6 blocker 3: no metadata pinning) and require the
        executed disposition, resolvedNativeAddress, and exhaustedSigners to agree with want."""
        for v in self.vectors:
            res = R.resolve_bb6(v["bindings"], party_map=v.get("partyMap"), anchored=v.get("anchored"))
            with self.subTest(vector=v["name"]):
                self.assertEqual(res["disposition"], v["want"]["sideDisposition"])
                self.assertEqual(res["resolvedNativeAddress"], v["want"].get("resolvedNativeAddress"))
                self.assertEqual(sorted(res["exhaustedSigners"]),
                                 sorted(v["want"].get("exhaustedSigners", [])),
                                 "exhaustedSigners must match want")

    def test_nine_plus_one_exhausts_to_indeterminate(self):
        """Round-6 blocker 3 (Random): the nine-plus-one flood is a SINGLE outsider bucket of 9 with no
        co-signed map, so its N=8 budget exhausts with a candidate unfetched — the whole side is
        indeterminate (BB-7), overriding the honest copy that resolves. EXECUTED, not pinned."""
        v = self.by_name["outsider-flood-nine-plus-one-honest"]
        self.assertNotIn("partyMap", v, "the flip depends on there being NO co-signed map")
        res = R.resolve_bb6(v["bindings"], party_map=None, anchored=v["anchored"])
        self.assertEqual(res["disposition"], "indeterminate")
        self.assertIsNone(res["resolvedNativeAddress"])
        self.assertEqual(res["exhaustedSigners"], v["want"]["exhaustedSigners"])

    def test_honest_self_flood_exhausts_to_indeterminate(self):
        """The honest role-holder over-publishing (9 self-signed candidates, one bucket, no map) exhausts
        its own N=8 budget -> indeterminate. EXECUTED."""
        v = self.by_name["honest-self-flood-budget-exhaustion"]
        res = R.resolve_bb6(v["bindings"], party_map=v.get("partyMap"), anchored=v.get("anchored"))
        self.assertEqual(res["disposition"], "indeterminate")
        self.assertEqual(res["exhaustedSigners"], v["want"]["exhaustedSigners"])

    def test_arm1_no_map_worst_order_still_resolves(self):
        """xm33 B2 arm 1 (design credited to xm33): a no-map/anchored worst-order case with EVERY bucket
        <= 8 — eight outsider bindings under one signer, all sorting below the honest hash, no partyMap.
        The per-signer budget keeps the honest seller resolvable; assert present + honest address, and an
        ordering guard that the count of outsider hashes below the honest one equals want (computed from
        the fixture, not a literal), which also locks fixture integrity."""
        v = self.by_name["outsider-flood-worst-order-no-map"]
        self.assertNotIn("partyMap", v, "arm 1 is the anchored/no-map path")
        honest = v["honestContentHash"]
        outsider = [b["bundleContentHash"] for b in v["bindings"] if b["signer"] != "did:demos:seller"]
        below = [h for h in outsider if h < honest]
        self.assertEqual(len(below), v["want"]["outsiderHashesBelowHonest"])
        # every bucket <= 8, so no exhaustion is possible here (the whole point of arm 1)
        self.assertLessEqual(len(outsider), 8)
        res = R.resolve_bb6(v["bindings"], party_map=None, anchored=v["anchored"])
        self.assertEqual(res["disposition"], "present")
        self.assertEqual(res["resolvedNativeAddress"], v["want"]["resolvedNativeAddress"])
        self.assertEqual(res["exhaustedSigners"], [])

    def test_co_signed_map_prefetch_prune_executes(self):
        """Round-6 rider: the co-signed party map prunes the five outsider candidates BEFORE any fetch,
        so only the honest seller address is fetched. Executed (the map was formerly pinned metadata the
        body did not carry): assert present, honest address, outsiders disjoint from fetched, exactly one
        address fetched, and no exhaustion."""
        v = self.by_name["co-signed-map-prefetch-prunes-outsiders"]
        self.assertIn("partyMap", v, "the vector must carry the co-signed party map it is named for")
        res = R.resolve_bb6(v["bindings"], party_map=v["partyMap"], anchored=v["anchored"])
        outsider_addrs = {b["nativeAddress"] for b in v["bindings"] if b["signer"] != "did:demos:seller"}
        self.assertEqual(res["disposition"], "present")
        self.assertEqual(res["resolvedNativeAddress"], v["want"]["resolvedNativeAddress"])
        self.assertTrue(outsider_addrs.isdisjoint(set(res["fetched"])),
                        "the map prune must drop every outsider address before fetch")
        self.assertEqual(len(res["fetched"]), 1, "only the honest seller address is fetched after the prune")
        self.assertEqual(len(outsider_addrs), v["want"]["prunedPreFetch"])
        self.assertEqual(res["exhaustedSigners"], [])

    def test_arm2_mapped_worst_order_prune_is_observable(self):
        """xm33 B2 arm 2 (design credited to xm33): on the MAPPED worst-order vector, assert every
        outsider binding's nativeAddress is DISJOINT from the set of fetched addresses — i.e. the
        co-signed party-map prune drops the outsiders BEFORE any fetch (prefetch pruning observable)."""
        v = self.by_name["outsider-flood-worst-order"]
        self.assertIn("partyMap", v)
        res = R.resolve_bb6(v["bindings"], party_map=v["partyMap"], anchored=v["anchored"])
        outsider_addrs = {b["nativeAddress"] for b in v["bindings"] if b["signer"] != "did:demos:seller"}
        self.assertTrue(outsider_addrs.isdisjoint(set(res["fetched"])),
                        "mapped prune must drop outsider addresses before fetch (none may appear in fetched)")
        self.assertEqual(res["disposition"], "present")

    def test_cross_role_insider_pruned(self):
        """Round-7 blocker: under a FULL {buyer,seller} co-signed party map, a buyer-signed binding that
        CLAIMS role:seller (valid signature; correct jobId/logicalAddress; bundleContentHash matching the
        honest bundle) MUST be pruned by BB-5 check 9 role-match — the buyer's authenticated role is buyer,
        not seller — so the honest seller binding resolves and the insider copy is NEVER selected. A resolver
        that authorizes on key-membership (signer in party_map) resolves the insider copy instead."""
        v = self.by_name["cross-role-insider-binding-pruned"]
        self.assertEqual(v["partyMap"], {"did:demos:buyer": "buyer", "did:demos:seller": "seller"},
                         "the flaw is triggered by a FULL two-party map, so the insider signer IS a map key")
        insiders = [b for b in v["bindings"] if b["signer"] == "did:demos:buyer" and b["role"] == "seller"]
        self.assertEqual(len(insiders), 1, "vector must carry exactly one buyer-signed role:seller insider")
        res = R.resolve_bb6(v["bindings"], party_map=v["partyMap"], anchored=v["anchored"])
        self.assertEqual(res["disposition"], "present")
        self.assertEqual(res["resolvedNativeAddress"], v["want"]["resolvedNativeAddress"],
                         "the honest seller binding must resolve, not the insider copy")
        self.assertNotEqual(res["resolvedNativeAddress"], insiders[0]["nativeAddress"],
                            "the insider copy must never resolve the seller side")
        self.assertNotIn("did:demos:buyer", res["authorizedSigners"],
                         "the buyer must not be authorized for the seller side")

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
