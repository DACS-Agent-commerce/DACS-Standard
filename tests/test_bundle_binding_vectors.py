"""Conformance checks for conformance/vectors/security/bundle-binding-v0.1.json.

Unlike the other security-vector tests, the signature block here re-verifies every
ed25519 signature against the header public keys (skipped when the ``cryptography``
package is unavailable, e.g. a minimal CI image). The stdlib checks cover set
metadata, the FaultAttestationBundle reshape, the §10.4.1 permissible-set, and the
BB-5 address/content-hash bindings — including the four deliberately-broken vectors.
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
except ImportError:  # pragma: no cover - environment-dependent
    HAVE_CRYPTO = False

ROOT = Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "conformance" / "vectors" / "security" / "bundle-binding-v0.1.json"

EXPECTED_NAMES = {
    "bb-valid-resolution",
    "bb-invalid-binding-sig",
    "bb-tuple-mismatch",
    "bb-content-hash-mismatch",
    "bb-cross-role-rebinding",
    "bb-missing-binding",
    "bb-full-sig-precedence",
    "bb-equal-standing-divergence",
    "bb-multiplicity-limit",
}
# The four deliberately-broken vectors (their invariant is inverted, not asserted).
INTENTIONAL_LOGICAL_ADDRESS_MISMATCH = {"bb-tuple-mismatch"}
INTENTIONAL_CONTENT_HASH_MISMATCH = {"bb-content-hash-mismatch"}
INTENTIONAL_FAULTEDPARTY_OUT_OF_SET = {"bb-cross-role-rebinding"}
INTENTIONAL_INVALID_BINDING_SIG = {"bb-invalid-binding-sig"}

BUNDLE_DOMAIN = "dacs-fault-bundle:v1:"
BINDING_DOMAIN = "dacs-bundle-binding:v1:"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def bundle_hash(bundle):
    unsigned = {k: v for k, v in bundle.items() if k not in ("signatures", "anchoredByRole")}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def binding_hash(binding):
    unsigned = {k: v for k, v in binding.items() if k != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def logical_address(job_id, role):
    return "stor-" + hashlib.sha256((job_id + "-bundle-" + role).encode("utf-8")).hexdigest()


def _other(role):
    return "seller" if role == "buyer" else "buyer"


def permissible_faultedparty(outcome, anchored_by_role):
    if outcome in ("completed", "failed-substrate"):
        return {"none"}
    if outcome in ("failed-perm", "aborted-by-self"):
        return {anchored_by_role}
    if outcome in ("failed-counterparty", "aborted-by-other"):
        return {_other(anchored_by_role)}
    return set()


def _b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class BundleBindingVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        cls.vectors = cls.data["vectors"]
        cls.by_name = {v["name"]: v for v in cls.vectors}

    # ---- stdlib-only checks (always run) ----

    def test_set_count_and_unique_names(self):
        self.assertEqual(self.data["set"], VECTOR_PATH.stem)
        self.assertEqual(self.data["count"], len(self.vectors))
        names = [v["name"] for v in self.vectors]
        self.assertEqual(len(names), len(set(names)), "duplicate vector name")
        self.assertEqual(set(names), EXPECTED_NAMES)

    def test_verdict_vocabulary(self):
        for v in self.vectors:
            self.assertIn(v["expected"], {"pass", "fail", "indeterminate"})

    def test_set_hash_recomputes(self):
        encoded = json.dumps(
            self.vectors, separators=(",", ":"), sort_keys=True, ensure_ascii=False
        ).encode("utf-8")
        self.assertEqual(self.data["hash"], hashlib.sha256(encoded).hexdigest())

    def test_every_bundle_is_fault_attestation_bundle(self):
        for v in self.vectors:
            for addr, bundle in v.get("anchored", {}).items():
                with self.subTest(vector=v["name"], addr=addr):
                    self.assertEqual(bundle.get("faultBundleVersion"), "1")
                    self.assertNotIn("bundleVersion", bundle)

    def test_faultedparty_permissible_set(self):
        for v in self.vectors:
            for addr, bundle in v.get("anchored", {}).items():
                allowed = permissible_faultedparty(bundle["outcome"], bundle["anchoredByRole"])
                inside = bundle["faultedParty"] in allowed
                with self.subTest(vector=v["name"], addr=addr):
                    if v["name"] in INTENTIONAL_FAULTEDPARTY_OUT_OF_SET:
                        self.assertFalse(inside, "cross-role-rebind bundle must be out of the permissible set")
                    else:
                        self.assertTrue(inside, f"faultedParty {bundle['faultedParty']} outside {allowed}")

    def test_binding_content_hash_matches_bundle(self):
        for v in self.vectors:
            hashes = {a: bundle_hash(b) for a, b in v.get("anchored", {}).items()}
            for i, binding in enumerate(v.get("bindings", [])):
                addr = binding.get("nativeAddress")
                if addr not in hashes:
                    continue
                match = binding.get("bundleContentHash") == hashes[addr]
                with self.subTest(vector=v["name"], binding=i):
                    if v["name"] in INTENTIONAL_CONTENT_HASH_MISMATCH:
                        self.assertFalse(match, "content-hash-mismatch binding must not match")
                    else:
                        self.assertTrue(match, "bundleContentHash != recomputed attestation_bundle_hash")

    def test_binding_logical_address_derivation(self):
        for v in self.vectors:
            for i, binding in enumerate(v.get("bindings", [])):
                expected = logical_address(binding["jobId"], binding["role"])
                match = binding["logicalAddress"] == expected
                with self.subTest(vector=v["name"], binding=i):
                    if v["name"] in INTENTIONAL_LOGICAL_ADDRESS_MISMATCH:
                        self.assertFalse(match, "tuple-mismatch binding must not match derive(jobId, role)")
                    else:
                        self.assertTrue(match, "logicalAddress != stor-sha256(jobId + '-bundle-' + role)")

    def test_spec_registers_fault_bundle_domain(self):
        dacs5 = (ROOT / "spec" / "DACS-5-VERIFY.md").read_text(encoding="utf-8")
        core = (ROOT / "spec" / "CORE.md").read_text(encoding="utf-8")
        self.assertIn("dacs-fault-bundle:v1:", dacs5)
        self.assertIn("dacs-fault-bundle:v1:", core)

    # ---- signature verification (requires cryptography) ----

    @unittest.skipUnless(
        HAVE_CRYPTO,
        "cryptography package not installed; CI runs the stdlib checks. "
        "Install `cryptography` to re-verify every ed25519 signature.",
    )
    def test_signatures_verify_against_header_keys(self):
        seeds = self.data["seeds"]
        keys = {r: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)) for r, s in seeds.items()}
        pub = {f"did:demos:{r}": keys[r].public_key() for r in ("buyer", "seller")}
        # Header public keys match the seeds.
        for claim, expected in self.data["publicKeys"].items():
            raw = pub[claim].public_bytes_raw()
            self.assertEqual(base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"), expected)

        def verifies(pubkey, payload, sig_value):
            try:
                pubkey.verify(_b64url_decode(sig_value), payload)
                return True
            except InvalidSignature:
                return False

        for v in self.vectors:
            for addr, bundle in v.get("anchored", {}).items():
                payload = (BUNDLE_DOMAIN + bundle_hash(bundle)).encode("utf-8")
                for s in bundle.get("signatures", []):
                    with self.subTest(vector=v["name"], addr=addr, party=s["party"]):
                        self.assertTrue(
                            verifies(pub[s["party"]], payload, s["value"]),
                            "bundle signature must verify over dacs-fault-bundle:v1: || hash",
                        )
            for i, binding in enumerate(v.get("bindings", [])):
                payload = (BINDING_DOMAIN + binding_hash(binding)).encode("utf-8")
                signer = binding["signature"]["signer"]
                ok = verifies(pub[signer], payload, binding["signature"]["value"])
                with self.subTest(vector=v["name"], binding=i):
                    if v["name"] in INTENTIONAL_INVALID_BINDING_SIG:
                        self.assertFalse(ok, "bb-invalid-binding-sig binding must NOT verify (BB-4)")
                    else:
                        self.assertTrue(ok, "binding signature must verify over dacs-bundle-binding:v1: || hash")


if __name__ == "__main__":
    unittest.main()
