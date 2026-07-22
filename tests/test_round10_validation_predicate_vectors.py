"""Round-10 validation-predicate regressions (PR #248): D1 signature/dispatch/SIG-6/budget +
D6 malformed-receipt robustness of validate_resolution_context.

These pin the round-10 hardening of tests/dacs5_reference.py that closed:
  R10-1 §10.4.1 required-signer set — a non-abort FaultAttestationBundle missing a required
        signer (buyer/seller/distinct-orchestrator) MUST be rejected (spec DACS-5 §10.4.1
        lines 318-323); a fully-signed copy passes.
  R10-2 lossy dedup — EVERY carried signature entry is validated over the RAW list; duplicate
        entries for one party can no longer mask an invalid signature via a party-keyed dict.
  R10-3 algorithm dispatch — the BundleSignature.algorithm label is read; an unsupported label
        (relabelled ecdsa-secp256k1 over ed25519 bytes) is rejected (CORE §B.7 / SIG-3).
  R10-4 SIG-6 canonical value — non-canonical (padded) signature spellings are rejected before
        cryptographic verification, on both the bundle-signature and binding-signature surfaces
        (CORE §B.7 SIG-6, spec lines 311-329).
  R10-5 budget ingress — a non-int/bool/<1 bb6Context.budget is refused, never a TypeError escape.
  D6    validate_resolution_context refuses (never raises) on a structurally malformed untrusted
        receipt: pre-loop resolutionContext shape, the per-entry structural gate, and the
        deref'd-copy (winner + counterparty) shape validator.

Self-contained (builders copied from the round-9 series). Crypto is MANDATORY (crypto ON, zero
skips): a missing dependency errors the module rather than silently skipping, matching the suite's
fail-closed-on-skip policy. Every asserted reason string is the exact live return of the predicate.
"""
import base64
import copy
import hashlib
import json
import unittest

import dacs5_reference as R

# fail-closed on crypto: hard import, no skip decorators.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# --- synthetic disclosed seeds (identical to the round-9 series / generator) ---
SEEDS = {"buyer": "a1" * 32, "seller": "c3" * 32, "orchestrator": "0e" * 32, "outsider": "f0" * 32}
CLAIM = {r: "did:demos:%s" % r for r in SEEDS}
KEYS = {r: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)) for r, s in SEEDS.items()}
PUBKEYS = {CLAIM[r]: KEYS[r].public_key().public_bytes_raw() for r in SEEDS}

BUNDLE_DOMAIN = "dacs-fault-bundle:v1:"
LEGACY_BUNDLE_DOMAIN = "dacs-bundle:v1:"   # legacy AttestationBundle signing domain (no faultBundleVersion)
BINDING_DOMAIN = "dacs-bundle-binding:v1:"
PLACEHOLDER = "1" * 64
FINALISED_AT = 1780004000000
PM = {CLAIM["seller"]: "seller"}   # authenticated role-holder map (MANDATORY in a derivation context)
SELLER, BUYER = CLAIM["seller"], CLAIM["buyer"]
# EXACT domain the predicate emits for the outcome enum (mirrors sorted(R._KNOWN_OUTCOMES)). The
# getattr fallback lets this module load against a PRE-round-10 dacs5_reference.py (stash-red run),
# where _KNOWN_OUTCOMES does not exist yet — the fallback set is the identical six-value enum.
OUTCOMES = str(sorted(getattr(R, "_KNOWN_OUTCOMES",
                              {"completed", "failed-substrate", "aborted-by-self",
                               "aborted-by-other", "failed-perm", "failed-counterparty"})))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sha(*parts):
    return hashlib.sha256(":".join(parts).encode("utf-8")).hexdigest()


def bundle_hash(bundle):
    unsigned = {k: v for k, v in bundle.items() if k not in ("signatures", "anchoredByRole")}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def binding_hash(binding):
    unsigned = {k: v for k, v in binding.items() if k != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def logical_address(job_id, role):
    return "stor-" + hashlib.sha256((job_id + "-bundle-" + role).encode("utf-8")).hexdigest()


def native_address(job_id, role, idx=0):
    return "stor-" + hashlib.sha256(("native:%s:%s:%d" % (job_id, role, idx)).encode("utf-8")).hexdigest()[:40]


def _parties():
    return [
        {"role": "buyer", "bundleHash": sha("bundle", "buyer"), "primaryClaim": CLAIM["buyer"]},
        {"role": "seller", "bundleHash": sha("bundle", "seller"), "primaryClaim": CLAIM["seller"]},
    ]


def make_fab(job_id, outcome, faulted_party, anchored_by_role, sign_roles, finalised_at=FINALISED_AT):
    b = {
        "faultBundleVersion": "1", "jobId": job_id, "outcome": outcome,
        "faultedParty": faulted_party, "anchoredByRole": anchored_by_role,
        "listingRef": {"listingId": "listing-" + job_id, "version": 1, "contentHash": sha("listing", job_id)},
        "parties": _parties(),
        "phaseSummary": [{"index": 0, "kind": "deliver-storage-program", "outcome": "ok"}],
        "vetRecords": [], "settlementEvidence": [], "recipeRegistryVersion": 1,
        "railRegistryVersion": 1, "finalisedAt": finalised_at, "signatures": [],
    }
    payload = (BUNDLE_DOMAIN + bundle_hash(b)).encode("utf-8")
    b["signatures"] = [{"party": CLAIM[r], "algorithm": "ed25519", "value": b64u(KEYS[r].sign(payload))}
                       for r in sign_roles]
    return b


def make_binding(job_id, role, signer_role, native, content_hash):
    bd = {
        "bindingVersion": "1", "jobId": job_id, "role": role,
        "logicalAddress": logical_address(job_id, role), "nativeAddress": native,
        "bundleContentHash": content_hash, "anchorTx": "demos-testnet:tx-" + native[5:21],
        "signer": CLAIM[signer_role],
    }
    payload = (BINDING_DOMAIN + binding_hash(bd)).encode("utf-8")
    bd["signature"] = {"algorithm": "ed25519", "signer": CLAIM[signer_role], "value": b64u(KEYS[signer_role].sign(payload))}
    return bd


def make_legacy(job_id, outcome, anchored_by_role, sign_roles):
    """A legacy AttestationBundle: bundleVersion literal, NO faultBundleVersion / faultedParty, signed
    over the legacy dacs-bundle:v1: domain. is_fab() is False for it. Round-10 required-signer rules
    apply type-agnostically, so a single-signed non-abort legacy copy is rejected like a FAB."""
    b = {
        "bundleVersion": "1", "jobId": job_id, "outcome": outcome, "anchoredByRole": anchored_by_role,
        "listingRef": {"listingId": "listing-" + job_id, "version": 1, "contentHash": sha("listing", job_id)},
        "parties": _parties(),
        "phaseSummary": [{"index": 0, "kind": "deliver-storage-program", "outcome": "ok"}],
        "vetRecords": [], "settlementEvidence": [], "recipeRegistryVersion": 1,
        "railRegistryVersion": 1, "finalisedAt": FINALISED_AT, "signatures": [],
    }
    payload = (LEGACY_BUNDLE_DOMAIN + bundle_hash(b)).encode("utf-8")
    b["signatures"] = [{"party": CLAIM[r], "algorithm": "ed25519", "value": b64u(KEYS[r].sign(payload))}
                       for r in sign_roles]
    return b


def make_fab3(job_id, outcome, faulted_party, anchored_by_role, orch_claim, sign_roles):
    """A 3-party FaultAttestationBundle (buyer + seller + orchestrator) mirroring make_fab, with a
    caller-supplied orchestrator primaryClaim. Signs the requested roles over the FAB domain. Used to
    exercise the §10.4.1 orchestrator-distinctness limb of the required-signer set."""
    parties = [
        {"role": "buyer", "bundleHash": sha("bundle", "buyer"), "primaryClaim": CLAIM["buyer"]},
        {"role": "seller", "bundleHash": sha("bundle", "seller"), "primaryClaim": CLAIM["seller"]},
        {"role": "orchestrator", "bundleHash": sha("bundle", "orchestrator"), "primaryClaim": orch_claim},
    ]
    b = {
        "faultBundleVersion": "1", "jobId": job_id, "outcome": outcome,
        "faultedParty": faulted_party, "anchoredByRole": anchored_by_role,
        "listingRef": {"listingId": "listing-" + job_id, "version": 1, "contentHash": sha("listing", job_id)},
        "parties": parties,
        "phaseSummary": [{"index": 0, "kind": "deliver-storage-program", "outcome": "ok"}],
        "vetRecords": [], "settlementEvidence": [], "recipeRegistryVersion": 1,
        "railRegistryVersion": 1, "finalisedAt": FINALISED_AT, "signatures": [],
    }
    payload = (BUNDLE_DOMAIN + bundle_hash(b)).encode("utf-8")
    b["signatures"] = [{"party": CLAIM[r], "algorithm": "ed25519", "value": b64u(KEYS[r].sign(payload))}
                       for r in sign_roles]
    return b


def make_absence_evidence(native):
    return {"kind": "non-membership-proof", "nativeAddress": native,
            "finalizedStateRef": "demos-testnet:finalized-1780004000000"}


def evidence_hash(ev):
    return hashlib.sha256(canonical(ev)).hexdigest()


def _absent_entry(job_id, content_hash, role_binding, bb6, absence_binding, ev_hash, cp_native):
    return {
        "contentHash": content_hash, "resolvedRole": "seller",
        "roleEvidence": {"kind": "binding", "binding": role_binding}, "bb6Context": bb6,
        "counterpartyDisposition": "absent",
        "absenceEvidenceRef": {"kind": "non-membership-proof", "locator": cp_native, "contentHash": ev_hash},
        "absenceBinding": absence_binding,
    }


def _derivation(content_hash, entry):
    return {
        "replayableDerivationVersion": "1", "bundleRefs": [content_hash],
        "resolutionContext": [entry],
        "metrics": {"completionRate": 0.0, "counterpartyAdjustedCompletionRate": 0.0, "counterpartyFaultRate": 0.0},
        "bundleCount": 1, "windowingBasis": "finalisedAt",
    }


# --- receipt factories (mutable deref/ev maps; a live valid receipt returns (True, [])) ---------
def build_absent(job, sign_roles=("buyer", "seller")):
    winner = make_fab(job, "completed", "none", "seller", list(sign_roles))
    h = bundle_hash(winner)
    n = native_address(job, "seller", 0)
    role_bind = make_binding(job, "seller", "seller", n, h)
    cp = native_address(job, "buyer")
    absb = make_binding(job, "buyer", "buyer", cp, PLACEHOLDER)
    ev = make_absence_evidence(cp)
    evh = evidence_hash(ev)
    bb6 = {"candidateBindings": [role_bind], "partyMap": dict(PM), "budget": 8}
    entry = _absent_entry(job, h, role_bind, bb6, absb, evh, cp)
    return {"deriv": _derivation(h, entry), "deref": {h: winner}, "anchors": {n: winner}, "ev": {evh: ev},
            "h": h, "n": n, "winner": winner, "role_bind": role_bind}


def build_present(job):
    W = make_fab(job, "completed", "none", "seller", ["buyer", "seller"])
    h = bundle_hash(W)
    n = native_address(job, "seller", 0)
    role_bind = make_binding(job, "seller", "seller", n, h)
    cp_native = native_address(job, "buyer", 0)
    cp_bind = make_binding(job, "buyer", "buyer", cp_native, h)
    cp = copy.deepcopy(W)
    cp["anchoredByRole"] = "buyer"
    bb6 = {"candidateBindings": [role_bind], "partyMap": dict(PM), "budget": 8}
    entry = {"contentHash": h, "resolvedRole": "seller",
             "roleEvidence": {"kind": "binding", "binding": role_bind}, "bb6Context": bb6,
             "counterpartyDisposition": "present",
             "counterpartyRef": {"contentHash": h},
             "counterpartyRoleEvidence": {"kind": "binding", "binding": cp_bind}}
    return {"deriv": _derivation(h, entry), "deref": {h: W},
            "anchors": {n: W, cp_native: cp}, "ev": {}, "h": h, "W": W, "cp": cp}


def _anchor_deref(p, address):
    if address in p.get("anchors", {}):
        return p["anchors"][address]
    for entry in p["deriv"].get("resolutionContext", []):
        evidences = [entry.get("roleEvidence"), entry.get("counterpartyRoleEvidence")]
        evidences += [{"kind": "binding", "binding": b}
                      for b in (entry.get("bb6Context") or {}).get("candidateBindings", [])]
        for evidence in evidences:
            evidence = evidence or {}
            binding = evidence.get("binding") or {}
            if evidence.get("kind") == "binding" and binding.get("nativeAddress") == address:
                return p["deref"].get(binding.get("bundleContentHash"))
    return None


def _anchor_from_maps(derivation, deref_map):
    p = {"deriv": derivation, "deref": deref_map, "anchors": {}}
    return lambda address: _anchor_deref(p, address)


def vrc(p):
    """Run validate_resolution_context over a receipt-factory dict. A raised exception here fails
    the test (that is exactly the 'no exception escapes' assertion)."""
    return R.validate_resolution_context(p["deriv"], lambda x: p["deref"].get(x),
                                         lambda x: p["ev"].get(x), PUBKEYS,
                                         anchor_deref=lambda x: _anchor_deref(p, x))


class Round10ValidationPredicateTests(unittest.TestCase):
    # ============================================================ R10-1 required-signer set
    def test_r10_1_seller_only_defect(self):
        """DEFECT: a completed (non-abort) FAB signed by SELLER only is refused at _post_fetch_valid,
        and refused through the full replay entry point via the operator-pinned layered
        'BB-6 re-selection differs' string (the under-signed winner is dropped inert)."""
        j = "R10-1"
        seller_only = make_fab(j, "completed", "none", "seller", ["seller"])
        h_so = bundle_hash(seller_only)
        n_so = native_address(j, "seller", 0)
        bind_so = make_binding(j, "seller", "seller", n_so, h_so)
        self.assertEqual(
            R._post_fetch_valid(seller_only, bind_so, PUBKEYS),
            (False, "§10.4.1 required signer 'buyer' (did:demos:buyer) has no signature for a non-abort outcome 'completed'"))
        pd = build_absent(j, sign_roles=["seller"])
        self.assertEqual(
            vrc(pd),
            (False, ["%s: BB-6 re-selection differs (got 'indeterminate'/None, want present/%s)" % (pd["h"], pd["n"])]))

    def test_r10_1_fully_signed_control(self):
        """CONTROL: a fully-signed completed FAB passes both surfaces."""
        j = "R10-1c"
        full = make_fab(j, "completed", "none", "seller", ["buyer", "seller"])
        bind_f = make_binding(j, "seller", "seller", native_address(j, "seller", 0), bundle_hash(full))
        self.assertEqual(R._post_fetch_valid(full, bind_f, PUBKEYS), (True, "ok"))
        self.assertEqual(vrc(build_absent(j)), (True, []))

    # ============================================================ R10-2 lossy dedup
    def _r10_2_variant(self, sigs):
        base = make_fab("R10-2", "completed", "none", "seller", ["buyer", "seller"])
        b = copy.deepcopy(base)
        b["signatures"] = sigs
        return b

    def _r10_2_parts(self):
        base = make_fab("R10-2", "completed", "none", "seller", ["buyer", "seller"])
        h2 = bundle_hash(base)
        bind2 = make_binding("R10-2", "seller", "seller", native_address("R10-2", "seller", 0), h2)
        seller_valid = next(copy.deepcopy(s) for s in base["signatures"] if s["party"] == SELLER)
        buyer_sig = next(copy.deepcopy(s) for s in base["signatures"] if s["party"] == BUYER)
        seller_invalid = copy.deepcopy(seller_valid)
        seller_invalid["value"] = b64u(b"\x00" * 64)
        return bind2, buyer_sig, seller_valid, seller_invalid

    def test_r10_2_duplicate_invalid_defect(self):
        """DEFECT: duplicate seller entries — an invalid one in EITHER order must be caught, because
        every RAW signature entry is validated (a party-keyed dict would silently drop one)."""
        bind2, buyer_sig, seller_valid, seller_invalid = self._r10_2_parts()
        sig_fail = "§10.4.1 bundle signature does not verify for signer 'did:demos:seller'"
        # A: invalid THEN valid.
        self.assertEqual(R._post_fetch_valid(self._r10_2_variant([buyer_sig, seller_invalid, seller_valid]), bind2, PUBKEYS),
                         (False, sig_fail))
        # B: valid THEN invalid.
        self.assertEqual(R._post_fetch_valid(self._r10_2_variant([buyer_sig, seller_valid, seller_invalid]), bind2, PUBKEYS),
                         (False, sig_fail))

    def test_r10_2_single_valid_control(self):
        """CONTROL: one valid signature per party passes."""
        bind2, buyer_sig, seller_valid, _ = self._r10_2_parts()
        self.assertEqual(R._post_fetch_valid(self._r10_2_variant([buyer_sig, seller_valid]), bind2, PUBKEYS), (True, "ok"))

    # ============================================================ R10-3 algorithm dispatch
    def _r10_3_parts(self):
        base = make_fab("R10-3", "completed", "none", "seller", ["buyer", "seller"])
        bind3 = make_binding("R10-3", "seller", "seller", native_address("R10-3", "seller", 0), bundle_hash(base))
        return base, bind3

    def test_r10_3_relabelled_algorithm_defect(self):
        """DEFECT: valid ed25519 bytes relabelled ecdsa-secp256k1 are refused by algorithm dispatch."""
        base, bind3 = self._r10_3_parts()
        relabelled = copy.deepcopy(base)
        for s in relabelled["signatures"]:
            s["algorithm"] = "ecdsa-secp256k1"
        self.assertEqual(
            R._post_fetch_valid(relabelled, bind3, PUBKEYS),
            (False, "§10.4.1/SIG-6 unsupported or missing signature algorithm 'ecdsa-secp256k1' for bundle signer 'did:demos:buyer'"))

    def test_r10_3_labelled_control(self):
        """CONTROL: correctly labelled ed25519 passes."""
        base, bind3 = self._r10_3_parts()
        self.assertEqual(R._post_fetch_valid(base, bind3, PUBKEYS), (True, "ok"))

    # ============================================================ R10-4 SIG-6 canonical
    NONCANON = "SIG-6: signature value is non-canonical (padding, whitespace, or non-URL-safe alphabet)"

    def _r10_4_parts(self):
        base = make_fab("R10-4", "completed", "none", "seller", ["buyer", "seller"])
        h4 = bundle_hash(base)
        bind4 = make_binding("R10-4", "seller", "seller", native_address("R10-4", "seller", 0), h4)
        return base, h4, bind4

    def test_r10_4_padded_fab_defect(self):
        """DEFECT (FAB surface): '==' padding on every bundle-signature value is refused (SIG-6)."""
        base, _h4, bind4 = self._r10_4_parts()
        padded = copy.deepcopy(base)
        for s in padded["signatures"]:
            s["value"] = s["value"] + "=="
        self.assertEqual(R._post_fetch_valid(padded, bind4, PUBKEYS),
                         (False, "%s for bundle signer 'did:demos:buyer'" % self.NONCANON))

    def test_r10_4_padded_binding_defect(self):
        """DEFECT (binding surface): '==' padding on BundleBinding.signature.value is refused (BB-4/SIG-6)."""
        _base, h4, bind4 = self._r10_4_parts()
        bind_padded = copy.deepcopy(bind4)
        bind_padded["signature"]["value"] = bind_padded["signature"]["value"] + "=="
        self.assertEqual(
            R.verify_binding(bind_padded, PUBKEYS, expected_jobid="R10-4", expected_role="seller", expected_content_hash=h4),
            {"ok": False, "reason": "BB-4/%s (binding signature)" % self.NONCANON})

    def test_r10_4_unpadded_controls(self):
        """CONTROL: unpadded canonical values pass on both surfaces."""
        base, h4, bind4 = self._r10_4_parts()
        self.assertEqual(R._post_fetch_valid(base, bind4, PUBKEYS), (True, "ok"))
        self.assertEqual(
            R.verify_binding(bind4, PUBKEYS, expected_jobid="R10-4", expected_role="seller", expected_content_hash=h4),
            {"ok": True, "reason": "binding valid"})

    # ============================================================ R10-5 budget ingress
    def test_r10_5_budget_typed_defect(self):
        """DEFECT: a str / None / float budget is refused with an exact reason and NO exception escapes."""
        for budget in ("8", None, 8.0):
            p = build_absent("R10-5")
            p["deriv"]["resolutionContext"][0]["bb6Context"]["budget"] = budget
            observed = vrc(p)   # a raised TypeError here would ERROR this test — the escape assertion
            self.assertEqual(
                observed,
                (False, ["%s: bb6Context.budget must be an integer >= 1 (got %r)" % (p["h"], budget)]),
                "budget=%r must refuse without exception" % (budget,))

    def test_r10_5_budget_one_control(self):
        """CONTROL: budget = 1 accepts."""
        p = build_absent("R10-5c")
        p["deriv"]["resolutionContext"][0]["bb6Context"]["budget"] = 1
        self.assertEqual(vrc(p), (True, []))

    # ============================================================ D6 structural gate (per-entry)
    def test_d6_structural_gate_defects(self):
        """DEFECT battery: a structurally malformed receipt member is refused (exact reason) and NEVER
        raises — resolutionContext / entry / bb6Context / partyMap / candidateBindings (+ element +
        element bundleContentHash int sort-key) / absenceEvidenceRef."""
        p = build_absent("D6-RC"); p["deriv"]["resolutionContext"] = None
        self.assertEqual(vrc(p), (False, ["resolutionContext must be an array (got NoneType)"]))
        p = build_absent("D6-EN"); p["deriv"]["resolutionContext"] = [123]
        self.assertEqual(vrc(p), (False, ["resolutionContext[0]: entry is not an object (got int)"]))
        p = build_absent("D6-BB"); p["deriv"]["resolutionContext"][0]["bb6Context"] = ["x"]
        self.assertEqual(vrc(p), (False, ["%s: bb6Context must be an object (got list)" % p["h"]]))
        p = build_absent("D6-PM"); p["deriv"]["resolutionContext"][0]["bb6Context"]["partyMap"] = "x"
        self.assertEqual(vrc(p), (False, ["%s: bb6Context.partyMap must be an object (got str)" % p["h"]]))
        p = build_absent("D6-CBN"); p["deriv"]["resolutionContext"][0]["bb6Context"]["candidateBindings"] = None
        self.assertEqual(vrc(p), (False, ["%s: bb6Context.candidateBindings must be an array (got NoneType)" % p["h"]]))
        p = build_absent("D6-CBE"); p["deriv"]["resolutionContext"][0]["bb6Context"]["candidateBindings"] = [None]
        self.assertEqual(vrc(p), (False, ["%s: bb6Context.candidateBindings[0] is not an object (got NoneType)" % p["h"]]))
        # element bundleContentHash int — the mixed-type BB-6 ordering-sort class
        p = build_absent("D6-MIX"); h = p["h"]
        lo, hi = sorted([native_address("D6-MIX", "seller", 0), native_address("D6-MIX", "seller", 1)])
        cand_lo = make_binding("D6-MIX", "seller", "seller", lo, h)
        cand_int = copy.deepcopy(make_binding("D6-MIX", "seller", "seller", hi, h))
        cand_int["bundleContentHash"] = 123
        e = p["deriv"]["resolutionContext"][0]
        e["roleEvidence"]["binding"] = cand_lo
        e["bb6Context"]["candidateBindings"] = [cand_lo, cand_int]
        self.assertEqual(vrc(p), (False, ["%s: bb6Context.candidateBindings[1].bundleContentHash must be a string (got int)" % h]))
        p = build_absent("D6-AER"); p["deriv"]["resolutionContext"][0]["absenceEvidenceRef"] = "x"
        self.assertEqual(vrc(p), (False, ["%s: absenceEvidenceRef must be an object (got str)" % p["h"]]))

    def test_d6_structural_gate_control(self):
        """CONTROL: a well-formed absent receipt accepts."""
        self.assertEqual(vrc(build_absent("D6-ACTL")), (True, []))

    # ============================================================ D6 deref'd-copy shape + present path
    def test_d6_deref_shape_defects(self):
        """DEFECT battery: present-path field types + the deref'd WINNER and COUNTERPARTY copy shapes
        (parties / signatures / outcome / phaseSummary) are refused (exact reason), never raise."""
        p = build_present("D6-CR"); p["deriv"]["resolutionContext"][0]["counterpartyRef"] = "x"
        self.assertEqual(vrc(p), (False, ["%s: counterpartyRef must be an object (got str)" % p["h"]]))
        p = build_present("D6-CRE"); p["deriv"]["resolutionContext"][0]["counterpartyRoleEvidence"] = "x"
        self.assertEqual(vrc(p), (False, ["%s: counterpartyRoleEvidence must be an object (got str)" % p["h"]]))

        d, dm, em, h = self._winner_probe("D6-WP", lambda W: W.__setitem__("parties", None))
        self.assertEqual(R.validate_resolution_context(d, lambda x: dm.get(x), lambda x: em.get(x), PUBKEYS,
                                                       anchor_deref=_anchor_from_maps(d, dm)),
                         (False, ["%s: winner copy parties must be an array (got NoneType)" % h]))
        d, dm, em, h = self._winner_probe("D6-WS", lambda W: W.__setitem__("signatures", ["notadict"]))
        self.assertEqual(R.validate_resolution_context(d, lambda x: dm.get(x), lambda x: em.get(x), PUBKEYS,
                                                       anchor_deref=_anchor_from_maps(d, dm)),
                         (False, ["%s: winner copy signatures[0] is not an object (got str)" % h]))
        d, dm, em, h = self._winner_probe("D6-WO", lambda W: W.pop("outcome"))
        self.assertEqual(R.validate_resolution_context(d, lambda x: dm.get(x), lambda x: em.get(x), PUBKEYS,
                                                       anchor_deref=_anchor_from_maps(d, dm)),
                         (False, ["%s: winner copy outcome must be one of %s (got None)" % (h, OUTCOMES)]))

        d, dm, em, h = self._cp_probe("D6-CO", lambda cp: cp.pop("outcome"))
        self.assertEqual(R.validate_resolution_context(d, lambda x: dm.get(x), lambda x: em.get(x), PUBKEYS,
                                                       anchor_deref=_anchor_from_maps(d, dm)),
                         (False, ["%s: counterparty copy outcome must be one of %s (got None)" % (h, OUTCOMES)]))
        d, dm, em, h = self._cp_probe("D6-CPS", lambda cp: cp.__setitem__("phaseSummary", [{"kind": "x", "outcome": "ok"}]))
        self.assertEqual(R.validate_resolution_context(d, lambda x: dm.get(x), lambda x: em.get(x), PUBKEYS,
                                                       anchor_deref=_anchor_from_maps(d, dm)),
                         (False, ["%s: counterparty copy phaseSummary[0].index must be an int or string (got NoneType)" % h]))

    def test_d6_present_and_shape_control(self):
        """CONTROL: a well-formed present receipt (winner + counterparty both intact) accepts."""
        self.assertEqual(vrc(build_present("D6-PCTL")), (True, []))

    # ============================================================ R10-6 legacy required-signer (type-agnostic F1)
    LEGACY_SINGLE_REASON = "§10.4.1 required signer 'buyer' (did:demos:buyer) has no signature for a non-abort outcome 'completed'"

    def test_r10_6_legacy_single_signed_defect(self):
        """DEFECT: a single-signed COMPLETED legacy AttestationBundle must be rejected identically to a
        FAB — the round-10 required-signer rule is type-agnostic (spec :475/:798). Rejected from BOTH
        _bundle_signatures_valid and _post_fetch_valid with the same reason."""
        j = "R10-6"
        legacy = make_legacy(j, "completed", "seller", ["seller"])
        h = bundle_hash(legacy)
        bindL = make_binding(j, "seller", "seller", native_address(j, "seller", 0), h)
        self.assertEqual(R._bundle_signatures_valid(legacy, PUBKEYS), (False, self.LEGACY_SINGLE_REASON))
        self.assertEqual(R._post_fetch_valid(legacy, bindL, PUBKEYS), (False, self.LEGACY_SINGLE_REASON))

    def test_r10_6_legacy_fully_signed_control(self):
        """CONTROL: a fully-signed completed legacy AttestationBundle passes both surfaces."""
        j = "R10-6c"
        legacy = make_legacy(j, "completed", "seller", ["buyer", "seller"])
        h = bundle_hash(legacy)
        bindL = make_binding(j, "seller", "seller", native_address(j, "seller", 0), h)
        self.assertEqual(R._bundle_signatures_valid(legacy, PUBKEYS), (True, "ok"))
        self.assertEqual(R._post_fetch_valid(legacy, bindL, PUBKEYS), (True, "ok"))

    def test_r10_6_legacy_single_signed_abort_control(self):
        """CONTROL: a single-signed aborted-by-self legacy AttestationBundle passes (abort MAY be
        single-signed, floored on the anchoring role-holder — for both bundle types)."""
        j = "R10-6a"
        legacy = make_legacy(j, "aborted-by-self", "seller", ["seller"])
        h = bundle_hash(legacy)
        bindL = make_binding(j, "seller", "seller", native_address(j, "seller", 0), h)
        self.assertEqual(R._bundle_signatures_valid(legacy, PUBKEYS), (True, "ok"))
        self.assertEqual(R._post_fetch_valid(legacy, bindL, PUBKEYS), (True, "ok"))

    # ============================================================ R10-1 orchestrator-distinctness limb
    def test_r10_1_orchestrator_unsigned_defect(self):
        """DEFECT: a completed seller-anchored FAB with a DISTINCT orchestrator (buyer+seller signed,
        orchestrator NOT signed) is refused naming the orchestrator role — a non-abort required-signer
        set includes a distinct orchestrator (§10.4.1 :318-323)."""
        j = "R10-1O"
        fab = make_fab3(j, "completed", "none", "seller", CLAIM["orchestrator"], ["buyer", "seller"])
        h = bundle_hash(fab)
        bindL = make_binding(j, "seller", "seller", native_address(j, "seller", 0), h)
        self.assertEqual(
            R._post_fetch_valid(fab, bindL, PUBKEYS),
            (False, "§10.4.1 required signer 'orchestrator' (did:demos:orchestrator) has no signature for a non-abort outcome 'completed'"))

    def test_r10_1_orchestrator_controls(self):
        """CONTROLS (two positive arms): (i) orchestrator claim == buyer's claim, buyer+seller signed —
        the orchestrator is legitimately NOT distinct, so buyer+seller suffices; (ii) distinct
        orchestrator with ALL THREE roles signed — the direct control for the unsigned defect (same
        roster, only the orchestrator signature differs)."""
        ji = "R10-1Obi"
        fab_i = make_fab3(ji, "completed", "none", "seller", CLAIM["buyer"], ["buyer", "seller"])
        bind_i = make_binding(ji, "seller", "seller", native_address(ji, "seller", 0), bundle_hash(fab_i))
        self.assertEqual(R._post_fetch_valid(fab_i, bind_i, PUBKEYS), (True, "ok"))
        jii = "R10-1Obii"
        fab_ii = make_fab3(jii, "completed", "none", "seller", CLAIM["orchestrator"], ["buyer", "seller", "orchestrator"])
        bind_ii = make_binding(jii, "seller", "seller", native_address(jii, "seller", 0), bundle_hash(fab_ii))
        self.assertEqual(R._post_fetch_valid(fab_ii, bind_ii, PUBKEYS), (True, "ok"))

    def test_r10_1_orchestrator_none_claim_shape(self):
        """SHAPE: a winner FAB whose roster carries orchestrator primaryClaim=None, driven through the
        replay entry point, refuses at the deref'd-copy shape gate (parties[i].primaryClaim must be a
        string) with no exception. The entry point is the contract — _bundle_shape_ok is not called
        directly."""
        j = "R10-1Oc"
        winner = make_fab3(j, "completed", "none", "seller", None, ["buyer", "seller"])
        h = bundle_hash(winner)
        rb = make_binding(j, "seller", "seller", native_address(j, "seller", 0), h)
        cp = native_address(j, "buyer")
        absb = make_binding(j, "buyer", "buyer", cp, PLACEHOLDER)
        ev = make_absence_evidence(cp)
        evh = evidence_hash(ev)
        bb6 = {"candidateBindings": [rb], "partyMap": dict(PM), "budget": 8}
        entry = _absent_entry(j, h, rb, bb6, absb, evh, cp)
        deriv = _derivation(h, entry)
        observed = R.validate_resolution_context(deriv, lambda x: {h: winner}.get(x),
                                                 lambda x: {evh: ev}.get(x), PUBKEYS,
                                                 anchor_deref=_anchor_from_maps(deriv, {h: winner}))   # MUST NOT raise
        self.assertEqual(
            observed,
            (False, ["%s: winner copy parties[2].primaryClaim must be a string (got NoneType)" % h]))

    # -- helpers for the deref'd-copy probes (winner is hash-matched; counterparty is unhashed) --
    def _winner_probe(self, job, mutate):
        W = make_fab(job, "completed", "none", "seller", ["buyer", "seller"])
        mutate(W)
        h = bundle_hash(W)
        rb = make_binding(job, "seller", "seller", native_address(job, "seller", 0), h)
        cp = native_address(job, "buyer")
        absb = make_binding(job, "buyer", "buyer", cp, PLACEHOLDER)
        ev = make_absence_evidence(cp)
        evh = evidence_hash(ev)
        bb6 = {"candidateBindings": [rb], "partyMap": dict(PM), "budget": 8}
        entry = _absent_entry(job, h, rb, bb6, absb, evh, cp)
        return _derivation(h, entry), {h: W}, {evh: ev}, h

    def _cp_probe(self, job, mutate):
        base = build_present(job)
        h = base["h"]
        cpmalh = "cafe" * 16
        cp = make_fab(job, "completed", "none", "buyer", ["buyer", "seller"])
        mutate(cp)
        cp_bind2 = make_binding(job, "buyer", "buyer", native_address(job, "buyer", 1), cpmalh)
        e = base["deriv"]["resolutionContext"][0]
        e["counterpartyRef"] = {"contentHash": cpmalh}
        e["counterpartyRoleEvidence"] = {"kind": "binding", "binding": cp_bind2}
        base["deref"][cpmalh] = cp
        return base["deriv"], base["deref"], base["ev"], h


if __name__ == "__main__":
    unittest.main()
