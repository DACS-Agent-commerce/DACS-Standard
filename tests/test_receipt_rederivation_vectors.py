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
    "legacy-derivationversion-carrying-resolutioncontext-is-refused",
    "stripped-discriminator-is-refused",
    "both-discriminators-is-refused",
    "divergent-counterparty-refused",
    "invalid-counterparty-role-binding-refused",
    "misbound-absence-evidence-refused",
    "competing-same-role-copy-changes-bb6-refused",
    "forged-partymap-unauthenticated-refused",
    "bad-candidate-binding-in-context-refused",
}

REFUSAL_NAMES = (
    "legacy-derivationversion-carrying-resolutioncontext-is-refused",
    "stripped-discriminator-is-refused",
    "both-discriminators-is-refused",
)

# N1-N4 (round-6 blocker #2): published receipts that replay REFUSES, one per Random's round-5 class.
NEGATIVE_NAMES = (
    "divergent-counterparty-refused",
    "invalid-counterparty-role-binding-refused",
    "misbound-absence-evidence-refused",
    "competing-same-role-copy-changes-bb6-refused",
    # round-7: forged partyMap (authenticated against the roster) and a BB-5-invalid carried candidate.
    "forged-partymap-unauthenticated-refused",
    "bad-candidate-binding-in-context-refused",
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def bundle_hash(bundle):
    unsigned = {k: v for k, v in bundle.items() if k not in ("signatures", "anchoredByRole")}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def _pubkeys(data):
    """signer ClaimReference -> raw ed25519 public bytes, from the disclosed seeds (crypto only)."""
    if not HAVE_CRYPTO:
        return None
    keys = {r: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)) for r, s in data["seeds"].items()}
    return {f"did:demos:{r}": keys[r].public_key().public_bytes_raw() for r in data["seeds"]}


def _evidence_deref(v):
    """AbsenceEvidence dereference callable backed by the vector's disclosed absenceEvidence map."""
    ev = v.get("absenceEvidence", {})
    return lambda h: ev.get(h)


def _bindings_in_entry(e):
    """Every embedded BundleBinding an entry carries (roleEvidence, counterparty, absence, bb6 candidates)."""
    out = []
    for key in ("roleEvidence", "counterpartyRoleEvidence"):
        re_ = e.get(key) or {}
        if re_.get("kind") == "binding" and isinstance(re_.get("binding"), dict):
            out.append(re_["binding"])
    if isinstance(e.get("absenceBinding"), dict):
        out.append(e["absenceBinding"])
    ctx = e.get("bb6Context") or {}
    for b in ctx.get("candidateBindings", []):
        if isinstance(b, dict):
            out.append(b)
    return out


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
        """Dereference bundleRefs, EXECUTE the full per-copy validation, and re-run derive() supplying
        each resolutionContext entry as its §10.5.1 tag; the metrics + bundleCount MUST reproduce
        byte-identically AND every authenticated check must pass (§10.5 Replay (1)-(4))."""
        v = self._pass_vector()
        deref = v["derefBundles"]
        d = R.derive(v["party"], v["taggedBundles"], v["window"][0], v["window"][1], "finalisedAt")
        same, _ = R.replay_receipt(d, lambda h: deref[h], v["party"], v["window"][0], v["window"][1],
                                   evidence_deref=_evidence_deref(v), pubkeys=_pubkeys(self.data))
        self.assertTrue(same, "receipt must replay byte-identically and pass all replay checks")
        self.assertTrue(R.receipt_required_members_present(d)[0])
        # structural-only path (pubkeys=None) must also pass — CI without cryptography still validates shape
        same_struct, _ = R.replay_receipt(d, lambda h: deref[h], v["party"], v["window"][0], v["window"][1],
                                          evidence_deref=_evidence_deref(v))
        self.assertTrue(same_struct)

    def test_negative_vectors_are_refused_by_replay(self):
        """Round-6 blocker #2: N1-N4 are published receipts that pass the discriminator gate and the
        member-presence check, but replay REFUSES each because an authenticated per-copy check fails
        (divergent counterparty; wrong counterparty role binding; misbound absence evidence; a
        competing same-role BB-6 candidate that re-selects a different address)."""
        for name in NEGATIVE_NAMES:
            v = self.by_name[name]
            deref = v["derefBundles"]
            with self.subTest(vector=name):
                # each is a well-formed ReplayableReputationDerivation (passes gate + member presence)
                self.assertTrue(R.is_replayable_derivation(v["derivation"]))
                ok_members, _ = R.receipt_required_members_present(v["derivation"])
                self.assertTrue(ok_members, "%s should pass member-presence; the defect is semantic" % name)
                # but replay refuses (structural path)
                same, replayed = R.replay_receipt(
                    v["derivation"], lambda h: deref[h], v["party"], v["window"][0], v["window"][1],
                    evidence_deref=_evidence_deref(v))
                self.assertFalse(same, "%s must be refused by replay" % name)
                self.assertIsNone(replayed)
                # and validate_resolution_context reports a non-empty reason
                vok, reasons = R.validate_resolution_context(v["derivation"], lambda h: deref[h],
                                                             _evidence_deref(v))
                self.assertFalse(vok)
                self.assertTrue(reasons)
                self.assertFalse(v["want"]["conforming"])

    def test_random_round5_probes_refuse(self):
        """Random's round-5 mutations replayed as committed tests: starting from the PASS receipt,
        mutate one field and assert replay refuses each — (i) a nonexistent counterpartyRef hash,
        (ii) a flipped counterparty binding role, (iii) a changed absenceBinding.nativeAddress."""
        import copy
        v = self._pass_vector()
        base = R.derive(v["party"], v["taggedBundles"], v["window"][0], v["window"][1], "finalisedAt")
        deref = v["derefBundles"]
        ev = _evidence_deref(v)

        def replay(d):
            return R.replay_receipt(d, lambda h: deref.get(h), v["party"], v["window"][0], v["window"][1],
                                    evidence_deref=ev)[0]

        # sanity: the untouched receipt replays
        self.assertTrue(replay(copy.deepcopy(base)))

        # (i) nonexistent counterpartyRef hash -> counterparty copy not dereferenceable -> refuse
        p1 = copy.deepcopy(base)
        for e in p1["resolutionContext"]:
            if e.get("counterpartyDisposition") == "present":
                e["counterpartyRef"]["contentHash"] = "de" * 32
        self.assertFalse(replay(p1), "nonexistent counterpartyRef must refuse")

        # (ii) flipped counterparty binding role -> role authentication fails -> refuse
        p2 = copy.deepcopy(base)
        for e in p2["resolutionContext"]:
            cre = e.get("counterpartyRoleEvidence")
            if cre and cre.get("kind") == "binding":
                cre["binding"]["role"] = "seller"  # counterparty is buyer
        self.assertFalse(replay(p2), "flipped counterparty binding role must refuse")

        # (iii) changed absenceBinding.nativeAddress -> address relation breaks -> refuse
        p3 = copy.deepcopy(base)
        for e in p3["resolutionContext"]:
            if e.get("counterpartyDisposition") == "absent":
                e["absenceBinding"]["nativeAddress"] = "stor-" + "9" * 40
        self.assertFalse(replay(p3), "misbound absenceBinding.nativeAddress must refuse")

        # (iv) corrupted authoritative roleEvidence.binding.bundleContentHash (BB-5 check 8) -> refuse.
        # (Beyond Random's 3-probe list; added so verify_binding on roleEvidence is load-bearing — closes
        #  the M1 coverage gap that N1-N4, which each break a different leg, leave open.)
        p4 = copy.deepcopy(base)
        for e in p4["resolutionContext"]:
            if (e.get("roleEvidence") or {}).get("kind") == "binding":
                e["roleEvidence"]["binding"]["bundleContentHash"] = "ab" * 32
        self.assertFalse(replay(p4), "corrupted roleEvidence.binding.bundleContentHash must refuse")

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

    def test_refusal_vectors_are_refused_by_the_new_type_gate(self):
        """Round-6 blocker #1: each refusal vector carries a wrong discriminator shape and MUST be
        refused by the CORE §11.1.2 new-type gate BEFORE any member check. receipt_required_members_present
        reports the refusal as a 'discriminator refusal', distinguishing it from a member-presence failure."""
        for name in REFUSAL_NAMES:
            v = self.by_name[name]
            with self.subTest(vector=name):
                self.assertFalse(R.is_replayable_derivation(v["derivation"]))
                gate = R.require_replayable_derivation(v["derivation"])
                self.assertFalse(gate["ok"])
                ok, reasons = R.receipt_required_members_present(v["derivation"])
                self.assertFalse(ok, "%s must be refused; got %s" % (name, reasons))
                self.assertTrue(any("discriminator refusal" in r for r in reasons),
                                "refusal must be reported as a discriminator refusal, not a member failure")
                self.assertFalse(v["want"]["conforming"])

    def test_refused_receipt_does_not_replay(self):
        """M1 guard: a refused object carries no replay claim — replay_receipt MUST return (False, None)
        WITHOUT dereferencing bundleRefs. The vector body is otherwise replay-able, so a mutant that
        removed the gate would proceed and return a non-None replay, tripping this assertion."""
        for name in ("legacy-derivationversion-carrying-resolutioncontext-is-refused",
                     "stripped-discriminator-is-refused"):
            v = self.by_name[name]
            deref = v["derefBundles"]
            with self.subTest(vector=name):
                same, replayed = R.replay_receipt(
                    v["derivation"], lambda h: deref[h], v["party"], v["window"][0], v["window"][1])
                self.assertFalse(same)
                self.assertIsNone(replayed, "a refused object must not be replayed")

    def test_both_discriminators_refused_on_the_legacy_field(self):
        """M2 guard: an object carrying BOTH discriminators MUST be refused specifically because it
        carries derivationVersion — a mutant that accepted derivationVersion would let this pass the
        gate and its (member-complete) body would then be judged conforming."""
        v = self.by_name["both-discriminators-is-refused"]
        gate = R.require_replayable_derivation(v["derivation"])
        self.assertFalse(gate["ok"])
        self.assertIn("derivationVersion", gate["reason"])
        ok, _ = R.receipt_required_members_present(v["derivation"])
        self.assertFalse(ok)

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography package not installed; CI runs the stdlib checks.")
    def test_signatures_verify(self):
        """Verify every ed25519 signature the receipt suite pins: FAB bundle signatures (dacs-fault-bundle:v1:)
        AND every embedded BundleBinding signature (dacs-bundle-binding:v1:) carried in roleEvidence,
        counterpartyRoleEvidence, absenceBinding, and bb6Context.candidateBindings across ALL vectors (D7)."""
        keys = {r: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)) for r, s in self.data["seeds"].items()}
        pub = {f"did:demos:{r}": keys[r].public_key() for r in self.data["seeds"]}

        def _verify(pubkey, payload, value):
            pubkey.verify(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), payload)

        bundle_sigs = binding_sigs = 0
        v = self._pass_vector()
        for _h, bundle in v["derefBundles"].items():
            payload = ("dacs-fault-bundle:v1:" + bundle_hash(bundle)).encode("utf-8")
            for s in bundle["signatures"]:
                with self.subTest(kind="bundle", party=s["party"]):
                    _verify(pub[s["party"]], payload, s["value"])
                    bundle_sigs += 1

        # every embedded binding signature across every vector's resolutionContext
        for vec in self.vectors:
            entries = vec.get("taggedBundles") or (vec.get("derivation") or {}).get("resolutionContext") or []
            for e in entries:
                for b in _bindings_in_entry(e):
                    payload = ("dacs-bundle-binding:v1:" + R.binding_hash(b)).encode("utf-8")
                    sig = b.get("signature") or {}
                    with self.subTest(kind="binding", signer=b.get("signer")):
                        _verify(pub[b["signer"]], payload, sig["value"])
                        binding_sigs += 1

        # report the count so D7 is observable in -v output
        print("\n[receipt suite] verified %d FAB bundle signatures + %d embedded binding signatures"
              % (bundle_sigs, binding_sigs))
        self.assertGreater(binding_sigs, 0)


if __name__ == "__main__":
    unittest.main()
