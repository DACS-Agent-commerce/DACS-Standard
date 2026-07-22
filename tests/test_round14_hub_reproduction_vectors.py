"""Hub's independent reproduce-first probes for the three round-14 findings on PR #248 head 907901c.

Every assertion here is the POST-FIX contract: each finding method is RED at 907901c and GREEN
after Random's closure patch. T1 (windowingBasis container-raise) and T2 (BB-6 full-standing copy
missed by address order) derive their fixtures from published conformance vectors. T3 (counterparty
anchoredByRole masking §10.4.3 divergence) uses a PURPOSE-BUILT same-outcome-class legacy pair — no
published vector carries the perspective-only-divergent shape the finding needs (the sole published
divergent-counterparty vector diverges on OUTCOME CLASS, which short-circuits divergence() before the
anchoredByRole/perspective_flip branch, so the masking attack is moot there). T3's pair is same
'failure'-class (both `failed-perm`) so divergence() passes the outcome-class check (dacs5_reference
line 323) and reaches the legacy anchoredByRole/perspective_flip branch the finding targets.

ADAPTIVE HARNESS: Random's patch changes the validate_resolution_context / replay_receipt signatures
(it adds `anchor_deref` and replaces the content-hash `deref(ch)` with an anchor-locator lookup that
fails closed without a resolver). To be RED at 907901c AND GREEN after the patch in ONE file, the
harness gates the new keyword on the LIVE signature: pre-patch it is omitted (content-hash path, the
finding reproduces); post-patch it is supplied (genuine green with the real reason, not a fail-closed
artifact). resolve_bb6's signature is UNCHANGED by the patch, so T2 needs no gate.

SIGNING NOTE (T3): the corrected finding requires the CONTROL to refuse with the §10.4.3 divergence
reason in BOTH states. Post-patch that runs _post_fetch_address_valid -> _bundle_signatures_valid,
whose required-signer set for a non-abort `failed-perm` outcome is buyer+seller. So both T3 copies are
signed by BOTH parties (a necessary correction to a single-signed sketch); pubkeys=None on T3 means the
signatures are never cryptographically verified — only their PRESENCE is read (F1 required-signer).
"""
import base64
import copy
import inspect
import json
import unittest
from pathlib import Path

import dacs5_reference as R

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - environment-dependent
    HAVE_CRYPTO = False

ROOT = Path(__file__).resolve().parents[1]
RRD_PATH = ROOT / "conformance" / "vectors" / "security" / "receipt-rederivation-v0.3.json"
BB_PATH = ROOT / "conformance" / "vectors" / "security" / "bundle-binding-v0.1.json"

# The patch adds `anchor_deref`; gate on the live signature so ONE file is RED-pre / GREEN-post.
_SUPPORTS_ANCHOR = "anchor_deref" in inspect.signature(R.validate_resolution_context).parameters


def _kw(anchor_map):
    """Keyword-args for validate/replay: post-patch supply anchor_deref keyed by the locator
    (_role_evidence_locator: binding.nativeAddress | resolvedAddress); pre-patch supply nothing."""
    return {"anchor_deref": (lambda a: anchor_map.get(a))} if _SUPPORTS_ANCHOR else {}


def _pubkeys(data):
    if not HAVE_CRYPTO:
        return None
    keys = {r: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)) for r, s in data["seeds"].items()}
    return {"did:demos:%s" % r: keys[r].public_key().public_bytes_raw() for r in data["seeds"]}


def _privkeys(data):
    if not HAVE_CRYPTO:
        return None
    return {r: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)) for r, s in data["seeds"].items()}


def _sig_value(priv, domain, content_hash):
    raw = priv.sign((domain + content_hash).encode("utf-8"))
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _add_bundle_signature(bundle, role, privs):
    """Attach a signature entry for `role` over bundle_domain||bundle_hash. Real ed25519 under crypto;
    a presence-only stub otherwise (value is unread when pubkeys=None)."""
    claim = "did:demos:%s" % role
    if privs is not None:
        value = _sig_value(privs[role], R.bundle_domain(bundle), R.bundle_hash(bundle))
    else:  # pragma: no cover - crypto-absent CI: presence only, never verified
        value = "AA"
    bundle.setdefault("signatures", []).append({"party": claim, "algorithm": "ed25519", "value": value})
    return bundle


def _sign_binding(binding, signer_role, privs):
    """(Re)sign a BundleBinding over BINDING_DOMAIN||binding_hash (binding_hash excludes `signature`)."""
    claim = "did:demos:%s" % signer_role
    if privs is not None:
        value = _sig_value(privs[signer_role], R.BINDING_DOMAIN, R.binding_hash(binding))
    else:  # pragma: no cover
        value = "AA"
    binding["signature"] = {"signer": claim, "algorithm": "ed25519", "value": value}
    return binding


class Round14HubReproductionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rrd = json.loads(RRD_PATH.read_text(encoding="utf-8"))
        cls.bb = json.loads(BB_PATH.read_text(encoding="utf-8"))
        cls.rrd_pk = _pubkeys(cls.rrd)
        cls.bb_pk = _pubkeys(cls.bb)
        cls.bb_priv = _privkeys(cls.bb)

    # ------------------------------------------------------------------ TEST 1
    def test_t1_windowing_basis_container_raise(self):
        """FINDING (Random r13 review 4745429433): a container ([]/{}) windowingBasis is membership-tested
        against a frozenset (derive:651, rrmp:864) and raises TypeError. POST-FIX contract: rrmp/replay
        return cleanly (never raise); derive raises ValueError. RED at 907901c (TypeError everywhere)."""
        v = next(x for x in self.rrd["vectors"] if x["name"] == "complete-resolution-context-replays-identical")
        base = R.derive(v["party"], v["taggedBundles"], v["window"][0], v["window"][1], "finalisedAt")
        deref = {h: b for h, b in v["derefBundles"].items()}

        for basis_val in ([], {}):
            with self.subTest(basis=basis_val):
                d = copy.deepcopy(base)
                d["windowingBasis"] = basis_val
                # (a) rrmp must RETURN (ok False), never raise.
                try:
                    ok, reasons = R.receipt_required_members_present(copy.deepcopy(d))
                except TypeError as e:
                    self.fail("(a) receipt_required_members_present raised TypeError on windowingBasis=%r "
                              "(post-fix must return cleanly): %s" % (basis_val, e))
                self.assertFalse(ok)
                self.assertTrue(reasons)
                # (b) replay_receipt must RETURN (False, None), never raise.
                try:
                    result = R.replay_receipt(copy.deepcopy(d), lambda h: deref.get(h), v["party"],
                                              v["window"][0], v["window"][1], None, None, **_kw({}))
                except TypeError as e:
                    self.fail("(b) replay_receipt raised TypeError on windowingBasis=%r "
                              "(post-fix must return (False, None)): %s" % (basis_val, e))
                self.assertEqual(result, (False, None))
                # (c) derive must raise ValueError (NOT TypeError).
                with self.assertRaises(ValueError):
                    R.derive(v["party"], v["taggedBundles"], v["window"][0], v["window"][1], basis_val)

    def test_t1_finalised_at_control(self):
        """CONTROL (anchor-independent, green in BOTH states): the implemented basis stays functional at
        the rrmp + derive level. Deliberately avoids a full replay so Blocker B (the anchor_deref API
        change) cannot make this control fail post-patch."""
        v = next(x for x in self.rrd["vectors"] if x["name"] == "complete-resolution-context-replays-identical")
        base = R.derive(v["party"], v["taggedBundles"], v["window"][0], v["window"][1], "finalisedAt")
        self.assertEqual(R.receipt_required_members_present(copy.deepcopy(base)), (True, []))
        self.assertEqual(base["windowingBasis"], "finalisedAt")
        again = R.derive(v["party"], v["taggedBundles"], v["window"][0], v["window"][1], "finalisedAt")
        self.assertEqual(again["windowingBasis"], "finalisedAt")

    # ------------------------------------------------------------------ TEST 2
    def _bb6_scenario(self, full_native):
        """Build the BB-6 candidate set from bb-equal-standing-divergence: both original lesser-signed
        divergent forms + a full-standing copy of form A at `full_native` (byte-equal content, buyer+
        seller signed, its binding re-signed with the seller seed). Returns (bindings, anchored)."""
        vec = next(x for x in self.bb["vectors"] if x["name"] == "bb-equal-standing-divergence")
        bind_a, bind_b = copy.deepcopy(vec["bindings"][0]), copy.deepcopy(vec["bindings"][1])
        anchored = {addr: copy.deepcopy(b) for addr, b in vec["anchored"].items()}
        form_a_hash = bind_a["bundleContentHash"]
        # full-standing copy of form A: same canonical bytes (buyer sig is excluded from the hash), now
        # co-signed by buyer as well as the vector's seller signature -> _full_standing True.
        full_copy = copy.deepcopy(anchored[bind_a["nativeAddress"]])
        _add_bundle_signature(full_copy, "buyer", self.bb_priv)
        self.assertEqual(R.bundle_hash(full_copy), form_a_hash, "full copy must stay byte-equal to form A")
        # its binding: form A's binding at a new nativeAddress, re-signed by the seller seed.
        full_binding = copy.deepcopy(bind_a)
        full_binding["nativeAddress"] = full_native
        full_binding.pop("signature", None)
        _sign_binding(full_binding, "seller", self.bb_priv)
        anchored[full_native] = full_copy
        bindings = [bind_a, bind_b, full_binding]
        # mirror the vector harness: every binding BB-4/BB-5-valid and every copy post-fetch-valid.
        for b in bindings:
            vb = R.verify_binding(b, self.bb_pk, expected_jobid=b["jobId"], expected_role="seller",
                                  expected_content_hash=b["bundleContentHash"])
            self.assertTrue(vb["ok"], "setup: binding must verify: %s" % vb["reason"])
        for b in bindings:
            pf_ok, pf_reason = R._post_fetch_valid(anchored[b["nativeAddress"]], b, self.bb_pk)
            self.assertTrue(pf_ok, "setup: fetched copy must be post-fetch-valid: %s" % pf_reason)
        return bindings, anchored

    def test_t2_bb6_full_standing_independent_of_address_order(self):
        """FINDING (mj-deving 5036102138 / cX3po 5039521195): resolve_bb6 reads full-standing off only
        cps[0] (the lowest-address copy in a form), so a full-standing copy that sorts AFTER the lesser
        copy in the same form is missed and the side voids to indeterminate. POST-FIX contract: both
        orders resolve present with resolvedNativeAddress == the FULL copy's address (also pins cX3po's
        tie-break residual). RED at 907901c: the full-copy-sorts-LAST order returns indeterminate/None."""
        lesser_a_native = next(x for x in self.bb["vectors"]
                               if x["name"] == "bb-equal-standing-divergence")["bindings"][0]["nativeAddress"]
        before = "stor-" + "0" * 40   # sorts BEFORE the lesser form-A copy
        after = "stor-" + "f" * 40    # sorts AFTER the lesser form-A copy
        self.assertLess(before, lesser_a_native)
        self.assertGreater(after, lesser_a_native)
        for full_native in (before, after):
            with self.subTest(full_native=full_native):
                bindings, anchored = self._bb6_scenario(full_native)
                res = R.resolve_bb6(bindings, party_map=None, anchored=anchored)
                self.assertEqual(res["disposition"], "present")
                self.assertEqual(res["resolvedNativeAddress"], full_native)

    # ------------------------------------------------------------------ TEST 3
    def _legacy_pair(self):
        """Purpose-built same-'failure'-class legacy pair. self (anchoredByRole seller) and cp
        (anchoredByRole buyer) both `failed-perm`; cp carries a hashed distinguisher so its contentHash
        differs. Both co-signed buyer+seller so post-patch's required-signer gate passes and the CONTROL
        refuses with the divergence reason (not a signature reason) in both states."""
        privs = _privkeys(self.rrd)
        parties = [{"role": "buyer", "primaryClaim": "did:demos:buyer"},
                   {"role": "seller", "primaryClaim": "did:demos:seller"}]
        self_copy = {"jobId": "J9", "anchoredByRole": "seller", "outcome": "failed-perm",
                     "parties": copy.deepcopy(parties)}
        cp_true = {"jobId": "J9", "anchoredByRole": "buyer", "outcome": "failed-perm", "noteTag": "cp",
                   "parties": copy.deepcopy(parties)}
        for b in (self_copy, cp_true):
            _add_bundle_signature(b, "buyer", privs)
            _add_bundle_signature(b, "seller", privs)
        self.assertEqual(R._outcome_class(self_copy["outcome"]), R._outcome_class(cp_true["outcome"]),
                         "T3 pair must be same outcome class so divergence() reaches the legacy branch")
        self.assertNotEqual(R._outcome_class(self_copy["outcome"]), "abort")
        h_self, h_cp = R.bundle_hash(self_copy), R.bundle_hash(cp_true)
        self.assertNotEqual(h_self, h_cp)
        waddr, caddr = R.logical_address("J9", "seller"), R.logical_address("J9", "buyer")
        derivation = {
            "replayableDerivationVersion": "1",
            "resolutionContext": [{
                "contentHash": h_self, "resolvedRole": "seller",
                "roleEvidence": {"kind": "address", "resolvedAddress": waddr},
                "counterpartyDisposition": "present",
                "counterpartyRef": {"contentHash": h_cp},
                "counterpartyRoleEvidence": {"kind": "address", "resolvedAddress": caddr},
            }],
        }
        return derivation, self_copy, cp_true, h_self, h_cp, waddr, caddr

    def _vrc(self, derivation, deref_map, anchor_map):
        return R.validate_resolution_context(derivation, lambda h: deref_map.get(h), None, None,
                                             **_kw(anchor_map))

    def test_t3_counterparty_anchored_role_flip_control(self):
        """CONTROL (green in BOTH states): the honest divergent pair is refused for §10.4.3 divergence."""
        derivation, self_copy, cp_true, h_self, h_cp, waddr, caddr = self._legacy_pair()
        deref_map = {h_self: self_copy, h_cp: cp_true}
        anchor_map = {waddr: self_copy, caddr: cp_true}
        ok, reasons = self._vrc(derivation, deref_map, anchor_map)
        self.assertFalse(ok)
        self.assertTrue(any("diverges" in r for r in reasons),
                        "control must refuse with the §10.4.3 divergence reason; got %r" % (reasons,))

    def test_t3_counterparty_anchored_role_flip_masks_divergence(self):
        """FINDING (cX3po 5036599576): flipping the counterparty copy's UNHASHED anchoredByRole to the
        winner's role makes divergence() read same-role, skip perspective_flip, and return False — the
        receipt wrongly passes. POST-FIX contract: the attack STILL refuses (ok False). RED at 907901c:
        vrc returns (True, [])."""
        derivation, self_copy, cp_true, h_self, h_cp, waddr, caddr = self._legacy_pair()
        cp_mut = copy.deepcopy(cp_true)
        cp_mut["anchoredByRole"] = self_copy["anchoredByRole"]   # buyer -> seller (unhashed)
        self.assertEqual(R.bundle_hash(cp_mut), h_cp, "anchoredByRole is excluded from the bundle hash")
        deref_map = {h_self: self_copy, h_cp: cp_mut}
        anchor_map = {waddr: self_copy, caddr: cp_mut}
        ok, _reasons = self._vrc(derivation, deref_map, anchor_map)
        self.assertFalse(ok, "anchoredByRole-flip attack must NOT pass validation")


class Round14PostFetchAddressGuardPins(unittest.TestCase):
    """xm33-lens mutation-attributability pins for the closure patch's NEW `_post_fetch_address_valid`
    guard (the pure-mapping BB-5 post-fetch equivalent). These are POST-PATCH guard-arm pins, not
    RED-pre/GREEN-post findings (the function does not exist pre-patch — the class fails closed to a
    skip there). Each pin mutates EXACTLY ONE field so the guard rejects at precisely that sub-check,
    with the mutated copy's address/hash recomputed so the pin cannot pass incidentally at a later
    arm. Arms S4 (resolvedAddress mapping), S5 (anchoredByRole), and S8 (required-signer) are already
    mutation-pinned by @randomblocker's closure tests #5-9 and the hub T3 probe; these six close the
    remaining arms S1/S2/S3/S6/S7/S9 (premise P4.1), plus one `_deref_role_copy` KeyError-scope
    disclosure pin (premise P4-A residual M-D2)."""

    @classmethod
    def setUpClass(cls):
        cls.rrd = json.loads(RRD_PATH.read_text(encoding="utf-8"))
        cls.pk = _pubkeys(cls.rrd)
        cls.privs = _privkeys(cls.rrd)

    def setUp(self):
        if not hasattr(R, "_post_fetch_address_valid"):
            self.skipTest("pre-patch: _post_fetch_address_valid guard absent")
        # Baseline sanity (asserted per-test, adds no test count): a well-formed copy PASSES, so every
        # pin below fails ONLY because of its single mutation.
        b = self._good()
        ok, reason = self._call(b, R.logical_address("J", "seller"), R.bundle_hash(b))
        self.assertTrue(ok, "baseline good copy must pass the guard; got %r" % (reason,))

    def _good(self, job_id="J", role="seller", outcome="failed-perm", omit_role_holder=False):
        """A copy that satisfies every sub-check for (job_id, role): legacy AttestationBundle,
        anchoredByRole==role, both parties present, co-signed buyer+seller (a non-abort failure
        outcome requires both)."""
        parties = [{"role": "buyer", "primaryClaim": "did:demos:buyer"},
                   {"role": "seller", "primaryClaim": "did:demos:seller"}]
        if omit_role_holder:
            parties = [p for p in parties if p["role"] != role]
        b = {"jobId": job_id, "anchoredByRole": role, "outcome": outcome, "parties": parties}
        for r in ("buyer", "seller"):
            _add_bundle_signature(b, r, self.privs)
        return b

    def _call(self, fetched, resolved_address, expected_content_hash, expected_role="seller",
              expected_jobid=None):
        return R._post_fetch_address_valid(fetched, resolved_address, expected_role,
                                           expected_content_hash, self.pk, expected_jobid=expected_jobid)

    def test_s1_fetched_not_object(self):
        ok, reason = self._call("not-a-dict", R.logical_address("J", "seller"), "0" * 64)
        self.assertFalse(ok)
        self.assertIn("fetched copy is not an object", reason)

    def test_s2_jobid_not_string(self):
        b = self._good()
        b["jobId"] = 123   # non-string; refuses at the jobId-type arm before any address/hash use
        ok, reason = self._call(b, R.logical_address("J", "seller"), R.bundle_hash(b))
        self.assertFalse(ok)
        self.assertIn("fetched.jobId must be a string", reason)

    def test_s3_jobid_mismatch(self):
        b = self._good(job_id="OTHER")   # fully valid FOR "OTHER"; refuses only vs expected_jobid="J"
        ok, reason = self._call(b, R.logical_address("OTHER", "seller"), R.bundle_hash(b), expected_jobid="J")
        self.assertFalse(ok)
        self.assertIn("fetched.jobId != expected jobId", reason)

    def test_s6_roster_missing_role_holder(self):
        b = self._good(omit_role_holder=True)   # parties omits the seller holder; anchoredByRole still seller
        ok, reason = self._call(b, R.logical_address("J", "seller"), R.bundle_hash(b))
        self.assertFalse(ok)
        self.assertIn("fetched roster has no holder for resolved role", reason)

    def test_s7_fab_faulted_party_outside_permissible_set(self):
        b = {"jobId": "J", "faultBundleVersion": "1", "anchoredByRole": "seller",
             "outcome": "aborted-by-self", "faultedParty": "buyer",   # buyer outside implied {seller}
             "parties": [{"role": "buyer", "primaryClaim": "did:demos:buyer"},
                         {"role": "seller", "primaryClaim": "did:demos:seller"}]}
        for r in ("buyer", "seller"):
            _add_bundle_signature(b, r, self.privs)
        ok, reason = self._call(b, R.logical_address("J", "seller"), R.bundle_hash(b))
        self.assertFalse(ok)
        self.assertIn("faultedParty", reason)

    def test_s9_recomputed_content_hash_mismatch(self):
        b = self._good()   # fully valid; refuses only because the expected contentHash is wrong
        ok, reason = self._call(b, R.logical_address("J", "seller"), "deadbeef" * 8)
        self.assertFalse(ok)
        self.assertIn("recomputed §10.4.1 hash != expected contentHash", reason)

    def test_deref_role_copy_keyerror_scoped_by_design(self):
        """DISCLOSURE PIN (P4-A residual M-D2): `_deref_role_copy`'s catch is `KeyError`-ONLY BY
        DESIGN. Receipt-controlled input is handled by the post-fetch validators returning None ->
        refusal; a MISBEHAVING CALLER resolver is a caller-contract question, and the KeyError-only
        swallow deliberately mirrors the pre-patch bare-`deref` posture (a content-addressed miss
        raised KeyError -> unfetchable). A resolver raising anything else PROPAGATES."""
        if not hasattr(R, "_deref_role_copy"):
            self.skipTest("pre-patch: _deref_role_copy absent")
        ev = {"kind": "address", "resolvedAddress": "stor-x"}
        # KeyError from the resolver -> swallowed to None (content-addressed-miss posture).
        self.assertIsNone(R._deref_role_copy(lambda a: (_ for _ in ()).throw(KeyError("k")), ev))
        # TypeError from the resolver -> PROPAGATES (KeyError-scoped by design; caller-contract).
        with self.assertRaises(TypeError):
            R._deref_role_copy(lambda a: (_ for _ in ()).throw(TypeError("t")), ev)
        # No resolver at all -> fail closed to None.
        self.assertIsNone(R._deref_role_copy(None, ev))


if __name__ == "__main__":
    unittest.main()
