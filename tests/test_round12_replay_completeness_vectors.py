"""Round-12: Random's two round-11 replay blockers, replayed as committed tests.

Built in-code from the PASS receipt (conformance/vectors/security/receipt-rederivation-v0.3.json,
`complete-resolution-context-replays-identical`) exactly like
test_receipt_rederivation_vectors.test_random_round5_probes_refuse — no new vector JSONs.

B1 (integrated-replay completeness): the normative text makes resolutionContext REQUIRED, permits it
empty only when bundleRefs is empty, and requires exactly one ordered entry per bundleRefs member
(spec/DACS-5-VERIFY.md :532, :562-585, :850-854). receipt_required_members_present() already detected
the mismatch but neither validate_resolution_context() nor replay_receipt() invoked the completeness
gate, so a missing/empty/miskeyed/order-mismatched context replayed True or raised. T1-T6 pin the
integrated gate: each construction is refused with an EXACT reason and replay_receipt returns
(False, None) with NO exception raised.

B2 (resolvedRole enum): the vocabulary is only {"buyer","seller"} (spec :537). _entry_structural_gate()
did not validate it and _role_evidence_grammar() only shape-checked the address arm, so an invalid enum
validated on the address-backed arm and was caught only incidentally (by the binding-role comparison)
on the binding-backed arm. T7-T10 pin a direct enum gate BEFORE evidence-kind branching, covering both
arms; T9/T10 assert the ENUM reason specifically (not the binding-role backstop that otherwise absorbs).

These assertions are the POST-FIX contract; T1-T10 are RED at 82960ce and green after the fix. The
residual disclosed-address-to-role SEMANTIC relationship (spec :540) is handled independently and is
out of scope here.
"""
import copy
import hashlib
import json
import unittest
from pathlib import Path

import dacs5_reference as R

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False

ROOT = Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "conformance" / "vectors" / "security" / "receipt-rederivation-v0.3.json"


def _pubkeys(data):
    if not HAVE_CRYPTO:
        return None
    keys = {r: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)) for r, s in data["seeds"].items()}
    return {f"did:demos:{r}": keys[r].public_key().public_bytes_raw() for r in data["seeds"]}


class Round12ReplayCompletenessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        cls.by_name = {v["name"]: v for v in cls.data["vectors"]}
        cls.v = cls.by_name["complete-resolution-context-replays-identical"]
        cls.base = R.derive(cls.v["party"], cls.v["taggedBundles"],
                            cls.v["window"][0], cls.v["window"][1], "finalisedAt")
        cls.deref_map = cls.v["derefBundles"]
        cls.ev_map = cls.v.get("absenceEvidence", {})
        cls.pk = _pubkeys(cls.data)
        # index of the present-disposition entry (the arm B2 exercises) and its contentHash
        cls.present_i = next(i for i, e in enumerate(cls.base["resolutionContext"])
                             if e.get("counterpartyDisposition") == "present")
        cls.present_ch = cls.base["resolutionContext"][cls.present_i]["contentHash"]

    # ---- harness -----------------------------------------------------------
    def _dr(self):
        return lambda h: self.deref_map.get(h)

    def _ev(self, h):
        return self.ev_map.get(h)

    def _anchor(self, d):
        by_address = {}
        for entry in d.get("resolutionContext", []):
            if not isinstance(entry, dict):
                continue
            for evidence, content_hash in (
                (entry.get("roleEvidence"), entry.get("contentHash")),
                (entry.get("counterpartyRoleEvidence"),
                 (entry.get("counterpartyRef") or {}).get("contentHash")
                 if isinstance(entry.get("counterpartyRef"), dict) else None),
            ):
                if not isinstance(evidence, dict):
                    continue
                if evidence.get("kind") == "binding" and isinstance(evidence.get("binding"), dict):
                    binding = evidence["binding"]
                    by_address[binding.get("nativeAddress")] = self.deref_map.get(binding.get("bundleContentHash"))
                elif evidence.get("kind") == "address":
                    by_address[evidence.get("resolvedAddress")] = self.deref_map.get(content_hash)
            ctx = entry.get("bb6Context")
            if isinstance(ctx, dict):
                for binding in ctx.get("candidateBindings", []):
                    if isinstance(binding, dict):
                        by_address[binding.get("nativeAddress")] = self.deref_map.get(
                            binding.get("bundleContentHash"))
        return lambda address: by_address.get(address)

    def validate(self, d, pk=None):
        return R.validate_resolution_context(d, self._dr(), self._ev, pk,
                                             anchor_deref=self._anchor(d))

    def replay(self, d, pk=None):
        return R.replay_receipt(d, self._dr(), self.v["party"], self.v["window"][0],
                                self.v["window"][1], evidence_deref=self._ev, pubkeys=pk,
                                anchor_deref=self._anchor(d))

    def rrmp(self, d):
        return R.receipt_required_members_present(d)

    def _base(self):
        return copy.deepcopy(self.base)

    def _enum_reason(self, role_repr):
        return "%s: resolvedRole must be one of ['buyer', 'seller'] (got %s)" % (self.present_ch, role_repr)

    # ---- controls (green pre- AND post-fix) --------------------------------
    def test_control_untouched_base_replays(self):
        # structural path
        self.assertEqual(self.validate(self._base()), (True, []))
        same, replayed = self.replay(self._base())
        self.assertTrue(same)
        self.assertIsNotNone(replayed)
        self.assertEqual(self.rrmp(self._base()), (True, []))
        # crypto path (inline gate — never a unittest skip, CI fails on any skip)
        if HAVE_CRYPTO:
            self.assertEqual(self.validate(self._base(), self.pk), (True, []))
            same_c, replayed_c = self.replay(self._base(), self.pk)
            self.assertTrue(same_c)
            self.assertIsNotNone(replayed_c)

    def test_control_address_arm_valid_role_accepted(self):
        # T7's evidence switch (both role-evidences -> address-backed, bb6Context removed) with a
        # VALID role must still validate — proves the enum gate refuses the value, not the arm.
        d = self._base()
        e = d["resolutionContext"][self.present_i]
        auth = self.deref_map[e["contentHash"]]
        cp = self.deref_map[e["counterpartyRef"]["contentHash"]]
        re_nat = R.legacy_logical_address(auth["jobId"], e["resolvedRole"])
        cre_nat = R.legacy_logical_address(cp["jobId"], "buyer" if e["resolvedRole"] == "seller" else "seller")
        e["roleEvidence"] = {"kind": "address", "resolvedAddress": re_nat}
        e["counterpartyRoleEvidence"] = {"kind": "address", "resolvedAddress": cre_nat}
        e.pop("bb6Context", None)
        self.assertEqual(self.validate(copy.deepcopy(d)), (True, []))
        if HAVE_CRYPTO:
            self.assertEqual(self.validate(copy.deepcopy(d), self.pk), (True, []))

    # ---- B1: integrated-replay completeness (T1-T6) ------------------------
    def test_T1_missing_resolution_context(self):
        d = self._base()
        del d["resolutionContext"]
        self.assertEqual(self.rrmp(copy.deepcopy(d)),
                         (False, ["resolutionContext is REQUIRED (spec :532)"]))
        # standalone validate refusal (dies on M8; replay stays refused via the rrmp wiring)
        self.assertEqual(self.validate(copy.deepcopy(d)),
                         (False, ["resolutionContext is REQUIRED (spec :532)"]))
        same, replayed = self.replay(copy.deepcopy(d))   # NO try: contract is that nothing raises
        self.assertFalse(same)
        self.assertIsNone(replayed)

    def test_T2_empty_context_with_nonempty_refs(self):
        d = self._base()
        empty = R.derive(self.v["party"], [], self.v["window"][0], self.v["window"][1], "finalisedAt")
        d["resolutionContext"] = []
        d["metrics"] = copy.deepcopy(empty["metrics"])
        d["bundleCount"] = empty["bundleCount"]
        self.assertEqual(self.rrmp(copy.deepcopy(d)),
                         (False, ["resolutionContext length != bundleRefs length",
                                  "resolutionContext not keyed to bundleRefs in order"]))
        same, replayed = self.replay(copy.deepcopy(d))
        self.assertFalse(same)
        self.assertIsNone(replayed)

    def test_T3_miskeyed_context(self):
        d = self._base()
        d["resolutionContext"][1] = copy.deepcopy(d["resolutionContext"][0])
        self.assertEqual(self.rrmp(copy.deepcopy(d)),
                         (False, ["resolutionContext not keyed to bundleRefs in order"]))
        same, replayed = self.replay(copy.deepcopy(d))
        self.assertFalse(same)
        self.assertIsNone(replayed)

    def test_T4_order_mismatched_context(self):
        d = self._base()
        d["resolutionContext"][0], d["resolutionContext"][1] = \
            d["resolutionContext"][1], d["resolutionContext"][0]
        self.assertEqual(self.rrmp(copy.deepcopy(d)),
                         (False, ["resolutionContext not keyed to bundleRefs in order"]))
        same, replayed = self.replay(copy.deepcopy(d))
        self.assertFalse(same)
        self.assertIsNone(replayed)

    def test_T5_missing_metrics(self):
        d = self._base()
        del d["metrics"]
        self.assertEqual(self.rrmp(copy.deepcopy(d)),
                         (False, ["metrics must be present and an object"]))
        same, replayed = self.replay(copy.deepcopy(d))   # NO try: post-fix must not raise KeyError
        self.assertFalse(same)
        self.assertIsNone(replayed)

    def test_T6_missing_bundle_count(self):
        d = self._base()
        del d["bundleCount"]
        self.assertEqual(self.rrmp(copy.deepcopy(d)),
                         (False, ["bundleCount must be present and an integer"]))
        same, replayed = self.replay(copy.deepcopy(d))   # NO try: post-fix must not raise KeyError
        self.assertFalse(same)
        self.assertIsNone(replayed)

    def test_M3_nonlist_resolution_context(self):
        # present-but-not-a-list resolutionContext: refuse deterministically (never a raise). Pins the
        # non-list arm of rrmp (M3 target); the reason mismatches once that arm is removed.
        d = self._base()
        d["resolutionContext"] = "not-a-list"
        self.assertEqual(self.rrmp(copy.deepcopy(d)),
                         (False, ["resolutionContext must be an array (got str)"]))
        same, replayed = self.replay(copy.deepcopy(d))
        self.assertFalse(same)
        self.assertIsNone(replayed)

    def test_T11_rrmp_entry_not_object(self):
        # pin-gap closure (found by self-audit): a non-object entry (length unchanged) must refuse in
        # rrmp with the entry-not-object reason, never raise. Kept by M12.
        d = self._base()
        d["resolutionContext"][0] = 42
        self.assertEqual(self.rrmp(copy.deepcopy(d)),
                         (False, ["resolutionContext[0]: entry is not an object (got int)"]))
        same, replayed = self.replay(copy.deepcopy(d))   # NO try: contract is that nothing raises
        self.assertFalse(same)
        self.assertIsNone(replayed)

    def test_T12_rrmp_entry_missing_content_hash(self):
        # pin-gap closure: an entry that is an object but lacks a string contentHash must refuse in rrmp
        # with the contentHash-string reason, never raise (its removal lets the keying subscript raise).
        # Kept by M13.
        d = self._base()
        d["resolutionContext"][0] = {}
        self.assertEqual(self.rrmp(copy.deepcopy(d)),
                         (False, ["resolutionContext[0]: contentHash must be a string (got NoneType)"]))
        same, replayed = self.replay(copy.deepcopy(d))   # NO try: contract is that nothing raises
        self.assertFalse(same)
        self.assertIsNone(replayed)

    def test_T13_bundle_refs_required_array(self):
        # gate's own read: bundleRefs feeds len() + the keying compare. (a) the P2 fail-open — an absent
        # bundleRefs with an empty context and empty-derivation metrics/bundleCount — must now refuse,
        # not replay True. Kept by M15.
        d = self._base()
        empty = R.derive(self.v["party"], [], self.v["window"][0], self.v["window"][1], "finalisedAt")
        del d["bundleRefs"]
        d["resolutionContext"] = []
        d["metrics"] = copy.deepcopy(empty["metrics"])
        d["bundleCount"] = empty["bundleCount"]
        self.assertEqual(self.rrmp(copy.deepcopy(d)),
                         (False, ["bundleRefs is REQUIRED (spec :531)"]))
        same, replayed = self.replay(copy.deepcopy(d))   # NO try: contract is that nothing raises
        self.assertFalse(same)
        self.assertIsNone(replayed)
        # (b) a non-array bundleRefs on the untouched base must refuse, not raise TypeError from len().
        # Kept by M16.
        d2 = self._base()
        d2["bundleRefs"] = 42
        self.assertEqual(self.rrmp(copy.deepcopy(d2)),
                         (False, ["bundleRefs must be an array (got int)"]))
        same2, replayed2 = self.replay(copy.deepcopy(d2))
        self.assertFalse(same2)
        self.assertIsNone(replayed2)

    def test_T14_rrmp_role_evidence_nondict_never_raises(self):
        # rrmp/validate layering: a non-dict roleEvidence must not raise inside rrmp's integrated
        # pre-validate path. rrmp reads roleEvidence type-guarded and DEFERS object-typing to the
        # round-11 grammar gate (which fires in validate), so rrmp returns (True, []) here — the entry
        # otherwise carries its required members — and the grammar refusal surfaces in validate; replay
        # refuses via that validate leg. Kept by M17.
        d = self._base()
        ch0 = d["resolutionContext"][0]["contentHash"]
        d["resolutionContext"][0]["roleEvidence"] = "x"
        self.assertEqual(self.rrmp(copy.deepcopy(d)), (True, []))   # NO try: must not raise
        self.assertEqual(self.validate(copy.deepcopy(d)),
                         (False, ["%s: roleEvidence must be an object (got str)" % ch0]))
        same, replayed = self.replay(copy.deepcopy(d))
        self.assertFalse(same)
        self.assertIsNone(replayed)

    # ---- B2: resolvedRole enum gate (T7-T10) -------------------------------
    def _address_arm(self, d, drop_role):
        e = d["resolutionContext"][self.present_i]
        re_nat = e["roleEvidence"]["binding"]["nativeAddress"]
        cre_nat = e["counterpartyRoleEvidence"]["binding"]["nativeAddress"]
        e["roleEvidence"] = {"kind": "address", "resolvedAddress": re_nat}
        e["counterpartyRoleEvidence"] = {"kind": "address", "resolvedAddress": cre_nat}
        e.pop("bb6Context", None)
        if drop_role:
            e.pop("resolvedRole", None)
        else:
            e["resolvedRole"] = "not-a-role"
        return d

    def test_T7_address_arm_invalid_role(self):
        d = self._address_arm(self._base(), drop_role=False)
        self.assertEqual(self.validate(copy.deepcopy(d)),
                         (False, [self._enum_reason("'not-a-role'")]))
        same, replayed = self.replay(copy.deepcopy(d))
        self.assertFalse(same)
        self.assertIsNone(replayed)
        if HAVE_CRYPTO:
            self.assertEqual(self.validate(copy.deepcopy(d), self.pk),
                             (False, [self._enum_reason("'not-a-role'")]))
            # rider: the enum refusal is identical on the crypto path, and replay refuses there too.
            same_c, replayed_c = self.replay(copy.deepcopy(d), self.pk)
            self.assertFalse(same_c)
            self.assertIsNone(replayed_c)

    def test_T8_address_arm_missing_role(self):
        d = self._address_arm(self._base(), drop_role=True)
        self.assertEqual(self.validate(copy.deepcopy(d)),
                         (False, [self._enum_reason("None")]))
        same, replayed = self.replay(copy.deepcopy(d))   # NO try: post-fix must not raise KeyError
        self.assertFalse(same)
        self.assertIsNone(replayed)

    def test_T9_binding_arm_invalid_role(self):
        # binding arm, evidence untouched: the enum gate must fire FIRST with the enum reason, not the
        # "roleEvidence BB-5: binding.role != 'not-a-role'" backstop that absorbs it today.
        d = self._base()
        d["resolutionContext"][self.present_i]["resolvedRole"] = "not-a-role"
        self.assertEqual(self.validate(copy.deepcopy(d)),
                         (False, [self._enum_reason("'not-a-role'")]))
        same, replayed = self.replay(copy.deepcopy(d))
        self.assertFalse(same)
        self.assertIsNone(replayed)

    def test_T10_binding_arm_missing_role(self):
        d = self._base()
        d["resolutionContext"][self.present_i].pop("resolvedRole", None)
        self.assertEqual(self.validate(copy.deepcopy(d)),
                         (False, [self._enum_reason("None")]))
        same, replayed = self.replay(copy.deepcopy(d))
        self.assertFalse(same)
        self.assertIsNone(replayed)

    # ---- B3 (round-13): windowingBasis required / vocab / not-implemented (three distinct reasons) --
    R13_REQUIRED = "windowingBasis is REQUIRED (spec :530)"
    R13_VOCAB = "windowingBasis must be one of ['finalisedAt', 'sr2-anchor-timestamp'] (got 'wallclock')"
    R13_NOT_IMPL = ("windowingBasis 'sr2-anchor-timestamp' is not implemented (fail-closed; §10.5.1 sr2 "
                    "windowing is a SHOULD, not implemented by this reference)")

    def test_r13_b3_windowingbasis_required(self):
        """PIN (B3 required): a DELETED windowingBasis refuses at receipt_required_members_present with the
        REQUIRED reason, and replay_receipt returns (False, None). Pre-fix the silent :1306
        `derivation.get("windowingBasis", "finalisedAt")` default MASKED the absence (accepted + replayed
        byte-identical under finalisedAt). Distinct from the vocab + not-implemented reasons.
        KILLED BY: removing the rrmp `if "windowingBasis" not in derivation:` required-check."""
        d = self._base()
        del d["windowingBasis"]
        ok, reasons = self.rrmp(copy.deepcopy(d))
        self.assertFalse(ok)
        self.assertIn(self.R13_REQUIRED, reasons)
        same, replayed = self.replay(copy.deepcopy(d))
        self.assertFalse(same)
        self.assertIsNone(replayed)

    def test_r13_b3_windowingbasis_vocab(self):
        """PIN (B3 vocab): an OUT-OF-VOCAB windowingBasis ('wallclock') refuses at rrmp with the exact
        VOCAB reason, and replay_receipt returns (False, None). sr2-anchor-timestamp is IN the vocab, so
        it does NOT hit this pin — its fail-closed is the separate not-implemented pin below.
        KILLED BY: removing the rrmp `elif ... not in SUPPORTED_WINDOWING_BASES` vocab-check."""
        d = self._base()
        d["windowingBasis"] = "wallclock"
        self.assertEqual(self.rrmp(copy.deepcopy(d)), (False, [self.R13_VOCAB]))
        same, replayed = self.replay(copy.deepcopy(d))
        self.assertFalse(same)
        self.assertIsNone(replayed)

    def test_r13_b3_windowingbasis_sr2_not_implemented(self):
        """PIN (B3 not-implemented): sr2-anchor-timestamp is IN-vocab (a valid literal) but the sr2
        windowing clock is a §10.5.1 SHOULD NOT implemented here — it fails closed on TWO DISTINCT,
        INDEPENDENT surfaces. REACHABILITY LOCK: sr2 pins the NOT-IMPLEMENTED surfaces, NOT the vocab pin
        (it PASSES the vocab gate — asserted below; a sr2-on-vocab-pin would be wrong).
          (3a) derive(basis='sr2-anchor-timestamp') RAISES the not-implemented ValueError.
          (3b) a receipt DECLARING sr2 PASSES rrmp (vocab ok) but replay_receipt fails closed -> (False,
               None) via the replay-tier IMPLEMENTED_WINDOWING_BASES guard — INDEPENDENT of derive's raise.
        KILLED BY: (3a) reverting derive's sr2 guard; (3b) reverting the replay_receipt sr2 guard."""
        with self.assertRaises(ValueError) as cm:  # (3a)
            R.derive(self.v["party"], self.v["taggedBundles"], self.v["window"][0], self.v["window"][1],
                     "sr2-anchor-timestamp")
        self.assertEqual(str(cm.exception), self.R13_NOT_IMPL)
        d = self._base()  # (3b)
        d["windowingBasis"] = "sr2-anchor-timestamp"
        self.assertEqual(self.rrmp(copy.deepcopy(d)), (True, []))   # sr2 IS in vocab -> passes rrmp
        same, replayed = self.replay(copy.deepcopy(d))
        self.assertFalse(same)
        self.assertIsNone(replayed)

    def test_r13_b3_finalisedat_control(self):
        """CONTROL / REGRESSION GUARD (B3): the IMPLEMENTED basis stays fully functional end-to-end — a
        finalisedAt receipt passes rrmp + validate, replays byte-identical, and derive(basis='finalisedAt')
        records windowingBasis='finalisedAt'. A future over-broad fail-closed that breaks the implemented
        basis goes RED here. Green today; UNAFFECTED by any of the B3 reverts (none touch finalisedAt)."""
        d = self._base()
        self.assertEqual(d["windowingBasis"], "finalisedAt")
        self.assertEqual(self.rrmp(copy.deepcopy(d)), (True, []))
        self.assertEqual(self.validate(copy.deepcopy(d)), (True, []))
        same, replayed = self.replay(copy.deepcopy(d))
        self.assertTrue(same)
        self.assertIsNotNone(replayed)
        derived = R.derive(self.v["party"], self.v["taggedBundles"], self.v["window"][0],
                           self.v["window"][1], "finalisedAt")
        self.assertEqual(derived["windowingBasis"], "finalisedAt")
        if HAVE_CRYPTO:
            self.assertEqual(self.validate(copy.deepcopy(d), self.pk), (True, []))
            same_c, replayed_c = self.replay(copy.deepcopy(d), self.pk)
            self.assertTrue(same_c)
            self.assertIsNotNone(replayed_c)


if __name__ == "__main__":
    unittest.main()
