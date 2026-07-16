"""Checks for conformance/vectors/security/receipt-rederivation-v0.3.json.

Round-5 B1: the round-4 review found the determinism-receipt vectors only asserted
`want.replayByteIdentical` fixture metadata and never ran derive() or re-ran reconciliation.
This set now carries real signed FaultAttestationBundle content and full E5 resolution
context (roleEvidence / counterpartyRef / absenceBinding). The pass vector is EXECUTED:
tests/dacs5_reference.derive is run over the tagged copies, replay_receipt confirms the
metrics + bundleCount reproduce byte-identically, and the counterpartyRef is dereferenced
and §10.4.3 divergence is re-run against it. The fail vectors are published receipts
missing a REQUIRED member. Signature verification is gated on `cryptography`.
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
VECTOR_PATH = ROOT / "conformance" / "vectors" / "security" / "receipt-rederivation-v0.3.json"

EXPECTED_NAMES = {
    "complete-resolution-context-replays-identical",
    "receipt-missing-counterparty-ref",
    "one-copy-without-absence-evidence-must-not-publish",
    "miskeyed-resolution-context-is-nonconforming",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def bundle_hash(bundle):
    unsigned = {k: v for k, v in bundle.items() if k not in ("signatures", "anchoredByRole")}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


class ReceiptRederivationTests(unittest.TestCase):
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

    def _pass_vector(self):
        return self.by_name["complete-resolution-context-replays-identical"]

    def test_executed_derive_reproduces_pinned_metrics(self):
        """Run derive() over the tagged copies and require bundleCount + metrics to equal want."""
        v = self._pass_vector()
        d = R.derive(v["party"], v["taggedBundles"], v["window"][0], v["window"][1], "finalisedAt")
        self.assertEqual(d["bundleCount"], v["want"]["bundleCount"])
        self.assertEqual(canonical(d["metrics"]), canonical(v["want"]["metrics"]))

    def test_replay_is_byte_identical(self):
        """Dereference bundleRefs and re-run derive() supplying each resolutionContext entry as
        its §10.5.1 tag; the metrics + bundleCount MUST reproduce byte-identically (§10.5.3 (4))."""
        v = self._pass_vector()
        deref = v["derefBundles"]
        d = R.derive(v["party"], v["taggedBundles"], v["window"][0], v["window"][1], "finalisedAt")
        same, _ = R.replay_receipt(d, lambda h: deref[h], v["party"], v["window"][0], v["window"][1])
        self.assertTrue(same, "receipt must replay byte-identically")
        self.assertTrue(R.receipt_required_members_present(d)[0])

    def test_counterparty_ref_is_dereferenceable_and_reconcilable(self):
        """The receipt's counterpartyRef lets a rederiver re-run §10.4.3 divergence against the
        counterparty copy — the exact capability the round-4 review found missing. Here the pair
        is non-divergent; a corrupted counterparty copy would flip this to divergent."""
        v = self._pass_vector()
        deref = v["derefBundles"]
        for t in v["taggedBundles"]:
            if t.get("counterpartyDisposition") == "present":
                cp = deref[t["counterpartyRef"]["contentHash"]]
                with self.subTest(job=t["bundle"]["jobId"]):
                    self.assertNotEqual(bundle_hash(cp), bundle_hash(t["bundle"]),
                                        "counterparty copy must be a distinct artifact")
                    self.assertFalse(R.divergence(t["bundle"], cp),
                                     "receipt records a non-divergent two-copy jobId")

    def test_absent_entry_carries_evidence_and_binding(self):
        v = self._pass_vector()
        for t in v["taggedBundles"]:
            if t.get("counterpartyDisposition") == "absent":
                with self.subTest(job=t["bundle"]["jobId"]):
                    self.assertIn("absenceEvidenceRef", t)
                    self.assertIn("absenceBinding", t)

    def test_fail_vectors_are_nonconforming_receipts(self):
        """Each fail vector is a published receipt missing a REQUIRED resolutionContext member."""
        for name in ("receipt-missing-counterparty-ref",
                     "one-copy-without-absence-evidence-must-not-publish",
                     "miskeyed-resolution-context-is-nonconforming"):
            v = self.by_name[name]
            ok, reasons = R.receipt_required_members_present(v["derivation"])
            with self.subTest(vector=name):
                self.assertFalse(ok, "%s must be non-conforming; got %s" % (name, reasons))
                self.assertFalse(v["want"]["conforming"])

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography package not installed; CI runs the stdlib checks.")
    def test_signatures_verify(self):
        keys = {r: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)) for r, s in self.data["seeds"].items()}
        pub = {f"did:demos:{r}": keys[r].public_key() for r in self.data["seeds"]}
        v = self._pass_vector()
        for _h, bundle in v["derefBundles"].items():
            payload = ("dacs-fault-bundle:v1:" + bundle_hash(bundle)).encode("utf-8")
            for s in bundle["signatures"]:
                with self.subTest(party=s["party"]):
                    pub[s["party"]].verify(
                        base64.urlsafe_b64decode(s["value"] + "=" * (-len(s["value"]) % 4)), payload)


if __name__ == "__main__":
    unittest.main()
