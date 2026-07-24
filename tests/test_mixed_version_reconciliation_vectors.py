"""Checks for conformance/vectors/security/mixed-version-reconciliation-v0.3.json.

Round-5: the convergence verdict is now produced by the EXECUTED §10.4.3 divergence
predicate (tests/dacs5_reference.divergence) — the perspective_flip legacy reconciliation
(E1-E3) and the implied-fault-SET mixed-version rule (E4) — not merely asserted from the
fixture's `want`. The round-4 review flagged that the prior test only asserted the
requested verdict; this runs the predicate and compares it to `want.convergence`, so a
regression in the reconciliation rule fails the suite. Signature verification is gated on
`cryptography`; the stdlib predicate checks always run.
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
VECTOR_PATH = ROOT / "conformance" / "vectors" / "security" / "mixed-version-reconciliation-v0.3.json"

EXPECTED_NAMES = {
    "mixed-nondivergent-fab-authoritative",
    "mixed-implied-fault-contradiction",
    "mixed-outcome-class-contradiction",
    "mixed-phasesummary-kind-mismatch",
    "legacy-legacy-outcome-spelling-control",
    "legacy-legacy-genuine-divergence",
    "mixed-orchestrator-nondivergent",
    "mixed-orchestrator-divergent",
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

    def test_executed_divergence_predicate_matches_want(self):
        """The core round-5 fix: run tests/dacs5_reference.divergence over each two-copy
        vector and require it to agree with want.convergence. This EXECUTES the E1
        perspective_flip legacy reconciliation and the E4 implied-fault-SET mixed rule."""
        for v in self.vectors:
            copies = list(v["copies"].values())
            if len(copies) != 2:
                continue
            produced = R.divergence(copies[0], copies[1])
            want_divergent = v["want"]["convergence"] == "divergent"
            with self.subTest(vector=v["name"]):
                self.assertEqual(
                    produced, want_divergent,
                    "executed divergence() (%s) disagrees with want.convergence (%s)"
                    % (produced, v["want"]["convergence"]))

    def test_legacy_partner_spellings_do_not_diverge(self):
        """E1 regression guard: the executed legacy predicate treats aborted-by-self /
        aborted-by-other perspective partners as one event (non-divergent)."""
        v = self.by_name["legacy-legacy-outcome-spelling-control"]
        a, b = v["copies"]["seller"], v["copies"]["buyer"]
        self.assertFalse(R.divergence(a, b))
        # ...but two copies that BOTH blame self are a genuine contradiction.
        g = self.by_name["legacy-legacy-genuine-divergence"]
        self.assertTrue(R.divergence(g["copies"]["seller"], g["copies"]["buyer"]))

    def test_three_party_implied_fault_is_a_set(self):
        """E4: a distinct-orchestrator session's legacy failed-counterparty/aborted-by-other
        implies BOTH non-R roles; membership — not a singular fault — decides divergence."""
        roster = {"buyer", "seller", "orchestrator"}
        self.assertEqual(
            R.implied_fault_set("failed-counterparty", "buyer", roster), {"seller", "orchestrator"})
        nd = self.by_name["mixed-orchestrator-nondivergent"]
        self.assertFalse(R.divergence(nd["copies"]["seller"], nd["copies"]["buyer"]))
        dv = self.by_name["mixed-orchestrator-divergent"]
        self.assertTrue(R.divergence(dv["copies"]["seller"], dv["copies"]["buyer"]))

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
