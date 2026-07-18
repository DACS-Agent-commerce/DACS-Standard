"""Round-9 ordering-contract reproductions (PR #248): R1/R2/R3.

These are INTENTIONALLY RED at f11adda — they assert the CORRECT §10.4.2 BB-6 / §10.5
Replay(2) ordering-contract behaviour that the current reconstruction in
dacs5_reference.validate_resolution_context does NOT yet honour. Each runs the FULL replay
entry point (validate_resolution_context, which reconstructs the anchored map and EXECUTES
resolve_bb6) over concrete signed content with crypto ON — no unit-testing of internals, no
skips. They stay red until the round-9 reconstruction lands.

  R1 — invalid copy inert (weakest-standing discipline). The honest winner is single-signed
       (aborted-by-self, the weakest standing that still resolves — NOT fully signed, so the
       full-signature-precedence path that masked this exact leak in round-8 N9 cannot fire).
       A poisoned competitor's binding stays in candidateBindings; its bundle fails the BB-5
       check-8 byte recompute so it is INERT and must be dropped from the result path. Contract:
       replay resolves PRESENT on the honest copy. CURRENT: resolve_bb6 still authorizes the
       inert copy off the partyMap (never checking it survived into `anchored`), so two forms of
       equal (lesser) standing void the side and replay returns indeterminate.

  R2 — prune before fetch. A correctly-signed outsider claims role:seller with a bundle that is
       NOT dereferenceable, under an authenticated partyMap = {seller->seller} only. Contract:
       the outsider is pruned pre-fetch (it is not the mapped role-holder) — zero fetch attempts
       for it — and replay accepts. CURRENT: the reconstruction dereferences every candidate
       BEFORE the mandatory partyMap prune, so it fetches the outsider and refuses with
       "candidate bundle not dereferenceable".

  R3 — full post-fetch validation of the winner copy. (a) the winner's anchoredByRole is flipped
       seller->buyer; (b) the winner's bundle signature bytes are replaced with invalid bytes
       (pubkeys present). Both are unhashed fields (§10.4.1 excludes signatures + anchoredByRole),
       so the content hash still matches and CURRENT replay accepts both (True, []). Contract: a
       winner anchored by the wrong role, or carrying an unverifiable signature, is rejected/void.
"""
import base64
import copy
import hashlib
import json
import unittest

import dacs5_reference as R

# Crypto is MANDATORY here (crypto ON, zero skips): a missing dependency errors the module rather
# than silently skipping, matching the suite's fail-closed-on-skip policy.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# --- synthetic disclosed seeds, identical to scripts/generate_dacs5_reputation_vectors.py ---
SEEDS = {"buyer": "a1" * 32, "seller": "c3" * 32, "orchestrator": "0e" * 32, "outsider": "f0" * 32}
CLAIM = {r: "did:demos:%s" % r for r in SEEDS}
KEYS = {r: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)) for r, s in SEEDS.items()}
PUBKEYS = {CLAIM[r]: KEYS[r].public_key().public_bytes_raw() for r in SEEDS}

BUNDLE_DOMAIN = "dacs-fault-bundle:v1:"
BINDING_DOMAIN = "dacs-bundle-binding:v1:"
PLACEHOLDER = "1" * 64
FINALISED_AT = 1780004000000
WINDOW = [1780000000000, 1780900000000]
PM = {CLAIM["seller"]: "seller"}   # authenticated role-holder map (MANDATORY in a derivation context)


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


def make_absence_evidence(native):
    return {"kind": "non-membership-proof", "nativeAddress": native,
            "finalizedStateRef": "demos-testnet:finalized-1780004000000"}


def evidence_hash(ev):
    return hashlib.sha256(canonical(ev)).hexdigest()


def _absent_entry(job_id, content_hash, role_binding, bb6, absence_binding, ev_hash, cp_native):
    """A one-copy absent resolutionContext entry (the round-8 N-vector shape)."""
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


class Round9OrderingContractTests(unittest.TestCase):
    # -------------------------------------------------------------------------------------- R1
    def test_r1_invalid_copy_inert_weakest_standing(self):
        """R1 — a poisoned competitor whose bundle fails the BB-5 check-8 byte recompute is INERT and
        must be absent from the result path; the single-signed (weakest-standing) honest copy resolves
        PRESENT. resolve_bb6 currently re-authorizes the inert copy off the partyMap, so two lesser-
        standing forms void the side and replay returns indeterminate. EXECUTED via the full replay
        entry point with crypto ON."""
        j = "R9-R1"
        honest = make_fab(j, "aborted-by-self", "seller", "seller", ["seller"])         # single-signed: weakest standing
        poison = make_fab(j, "failed-substrate", "none", "seller", ["buyer", "seller"])  # real full bundle; its binding lies about content
        hw = bundle_hash(honest)
        hp_claim = "b" * 64                       # the poisoned binding LIES: a valid-shape hash != §10.4.1 recompute
        self.assertNotEqual(bundle_hash(poison), hp_claim, "poison must fail check-8 byte recompute")
        nw, np_ = native_address(j, "seller", 0), native_address(j, "seller", 1)
        bind_w = make_binding(j, "seller", "seller", nw, hw)
        bind_p = make_binding(j, "seller", "seller", np_, hp_claim)
        cp_b = native_address(j, "buyer")
        absb = make_binding(j, "buyer", "buyer", cp_b, PLACEHOLDER)
        ev = make_absence_evidence(cp_b)
        evh = evidence_hash(ev)
        bb6 = {"candidateBindings": [bind_w, bind_p], "partyMap": PM, "budget": 8}
        entry = _absent_entry(j, hw, bind_w, bb6, absb, evh, cp_b)
        deriv = _derivation(hw, entry)
        deref = {hw: honest, hp_claim: poison}   # poison keyed by its CLAIMED (lying) hash
        ev_map = {evh: ev}

        # positive control (holds on current HEAD): the honest copy is the weakest standing that still
        # resolves, and with the poison correctly EXCLUDED (inert), BB-6 resolves PRESENT on it.
        self.assertFalse(R._full_standing(honest), "the honest winner must be single-signed (weakest standing)")
        honest_only = R.resolve_bb6([bind_w], PM, 8, anchored={nw: honest})
        self.assertEqual((honest_only["disposition"], honest_only["resolvedNativeAddress"]), ("present", nw),
                         "control: the honest copy resolves present once the inert poison is absent from the candidate set")

        # CONTRACT: the full replay entry point accepts — the poisoned copy is inert (dropped) so the
        # honest single-signed winner resolves present. RED at f11adda: it refuses with a BB-6
        # re-selection that returns indeterminate (the inert poison re-enters as a lesser-standing form).
        vok, reasons = R.validate_resolution_context(deriv, lambda h: deref.get(h), lambda h: ev_map.get(h), PUBKEYS)
        self.assertEqual((vok, reasons), (True, []),
                         "R1: replay must accept (poisoned competitor inert; honest weakest-standing copy resolves "
                         "present); current wrong behaviour = %r" % (reasons,))

    # -------------------------------------------------------------------------------------- R2
    def test_r2_prune_before_fetch(self):
        """R2 — a correctly-signed outsider claiming role:seller with an UNfetchable bundle, under an
        authenticated partyMap {seller->seller}, MUST be pruned pre-fetch (zero fetch attempts) and the
        receipt accepted. RED at f11adda: the reconstruction dereferences every candidate before the
        mandatory partyMap prune, so it fetches the outsider and refuses 'candidate bundle not
        dereferenceable'. EXECUTED via the full replay entry point with crypto ON; the deref callable is
        instrumented to prove no fetch is attempted for the outsider."""
        j = "R9-R2"
        honest = make_fab(j, "completed", "none", "seller", ["buyer", "seller"])
        h2 = bundle_hash(honest)
        n2 = native_address(j, "seller", 0)
        bind_h = make_binding(j, "seller", "seller", n2, h2)
        out_native = native_address(j, "seller", 5)
        out_hash = sha("outsider-bundle", j)                     # a genuine hash whose bundle is NEVER published
        bind_out = make_binding(j, "seller", "outsider", out_native, out_hash)  # BB-4-valid outsider claim on the seller side
        cp_b = native_address(j, "buyer")
        absb = make_binding(j, "buyer", "buyer", cp_b, PLACEHOLDER)
        ev = make_absence_evidence(cp_b)
        evh = evidence_hash(ev)
        bb6 = {"candidateBindings": [bind_h, bind_out], "partyMap": PM, "budget": 8}
        entry = _absent_entry(j, h2, bind_h, bb6, absb, evh, cp_b)
        deriv = _derivation(h2, entry)
        deref_map = {h2: honest}                                 # outsider bundle intentionally ABSENT
        ev_map = {evh: ev}

        # the outsider is not the mapped role-holder, so the mandatory partyMap prune must drop it.
        self.assertNotEqual(PM.get(bind_out["signer"]), bind_out["role"],
                            "control: the outsider signer is not mapped to the seller role")

        fetched = []

        def deref(h):
            fetched.append(h)
            return deref_map.get(h)

        # CONTRACT (i): zero fetch attempts for the pruned outsider. RED: it IS fetched today.
        vok, reasons = R.validate_resolution_context(deriv, deref, lambda h: ev_map.get(h), PUBKEYS)
        self.assertNotIn(out_hash, fetched,
                         "R2: the outsider bundle must never be fetched (pruned pre-fetch); current fetch list = %r" % (fetched,))
        # CONTRACT (ii): replay accepts with no dereference refusal. RED: refuses 'not dereferenceable'.
        self.assertEqual((vok, reasons), (True, []),
                         "R2: replay must accept (outsider pruned pre-fetch, honest seller resolves); "
                         "current wrong behaviour = %r" % (reasons,))

    # -------------------------------------------------------------------------------------- R3
    def test_r3_full_post_fetch_validation_of_winner(self):
        """R3 — the winner (claimed-authoritative) copy must be fully validated post-fetch. Two vectors,
        each mutating an UNHASHED field of the winner (so the §10.4.1 content hash still matches and the
        BB-6 re-selection still reaches it): (a) anchoredByRole flipped seller->buyer; (b) bundle
        signature bytes replaced with invalid bytes. Both MUST be rejected/void. RED at f11adda: replay
        validates neither, so both return (True, []). EXECUTED via the full replay entry point, crypto ON."""
        # --- (a) winner anchoredByRole flipped seller -> buyer ---
        ja = "R9-R3a"
        wa = make_fab(ja, "completed", "none", "seller", ["buyer", "seller"])
        ha = bundle_hash(wa)                                     # excludes anchoredByRole
        wa_flipped = copy.deepcopy(wa)
        wa_flipped["anchoredByRole"] = "buyer"                   # anchored by the WRONG role; hash + signatures unchanged
        self.assertEqual(bundle_hash(wa_flipped), ha, "control: anchoredByRole is unhashed, so the content hash is unchanged")
        na = native_address(ja, "seller", 0)
        bwa = make_binding(ja, "seller", "seller", na, ha)
        cpa = native_address(ja, "buyer")
        absa = make_binding(ja, "buyer", "buyer", cpa, PLACEHOLDER)
        eva = make_absence_evidence(cpa)
        evha = evidence_hash(eva)
        bb6a = {"candidateBindings": [bwa], "partyMap": PM, "budget": 8}
        deriv_a = _derivation(ha, _absent_entry(ja, ha, bwa, bb6a, absa, evha, cpa))
        deref_a = {ha: wa_flipped}
        ev_a = {evha: eva}

        # --- (b) winner bundle signature bytes replaced with invalid bytes (crypto ON) ---
        jb = "R9-R3b"
        wb = make_fab(jb, "completed", "none", "seller", ["buyer", "seller"])
        hb = bundle_hash(wb)                                     # excludes signatures
        wb_bad = copy.deepcopy(wb)
        for s in wb_bad["signatures"]:
            s["value"] = b64u(b"\x00" * 64)                      # syntactically valid, cryptographically invalid
        self.assertEqual(bundle_hash(wb_bad), hb, "control: signatures are unhashed, so the content hash is unchanged")
        nb = native_address(jb, "seller", 0)
        bwb = make_binding(jb, "seller", "seller", nb, hb)
        cpb = native_address(jb, "buyer")
        absbb = make_binding(jb, "buyer", "buyer", cpb, PLACEHOLDER)
        evb = make_absence_evidence(cpb)
        evhb = evidence_hash(evb)
        bb6b = {"candidateBindings": [bwb], "partyMap": PM, "budget": 8}
        deriv_b = _derivation(hb, _absent_entry(jb, hb, bwb, bb6b, absbb, evhb, cpb))
        deref_b = {hb: wb_bad}
        ev_b = {evhb: evb}

        for label, deriv, deref, ev_map in (
            ("a: winner anchoredByRole flipped seller->buyer", deriv_a, deref_a, ev_a),
            ("b: winner bundle signature bytes invalid", deriv_b, deref_b, ev_b),
        ):
            with self.subTest(vector=label):
                vok, reasons = R.validate_resolution_context(deriv, lambda h: deref.get(h), lambda h: ev_map.get(h), PUBKEYS)
                # CONTRACT: the winner copy is rejected/void. RED at f11adda: accepted as (True, []).
                self.assertFalse(vok,
                                 "R3 %s: the winner copy must be rejected/void; current wrong behaviour = %r"
                                 % (label, (vok, reasons)))
                self.assertTrue(reasons, "R3 %s: rejection must carry a non-empty reason; current = %r" % (label, reasons))

    # -------------------------------------------------------------------------------------- F1
    def test_f1_recorded_budget_exhaustion_reproduces_bb7_indeterminate(self):
        """F1 (step-5 audit) — an authorized signer carrying MORE candidates than the RECORDED budget must
        reproduce BB-7 side-level exhaustion (§10.4.2/BB-7: 'if the budget exhausts while candidate addresses
        remain unfetched, the side's read disposition is indeterminate'). Two canonically-equal authorized
        seller candidates (same bundleContentHash, distinct nativeAddress) with recorded budget=1; the receipt
        claims present at the lower-native copy. RED at 35fd3a7: the reconstruction pre-caps per-signer
        survivors to [:budget] and hands resolve_bb6 only the ≤budget subset, so resolve_bb6's
        `len(sbindings) > budget` exhaustion detector never fires and the receipt is wrongly ACCEPTED.
        EXECUTED via the full replay entry point, crypto ON."""
        j = "R9-F1"
        hb = make_fab(j, "completed", "none", "seller", ["buyer", "seller"])
        h = bundle_hash(hb)
        lo, hi = sorted([native_address(j, "seller", 0), native_address(j, "seller", 1)])
        b_lo = make_binding(j, "seller", "seller", lo, h)   # winner: lower native, the one fetched under budget=1
        b_hi = make_binding(j, "seller", "seller", hi, h)   # excluded by budget=1 (remains unfetched)
        cp = native_address(j, "buyer")
        absb = make_binding(j, "buyer", "buyer", cp, PLACEHOLDER)
        ev = make_absence_evidence(cp)
        evh = evidence_hash(ev)
        bb6 = {"candidateBindings": [b_lo, b_hi], "partyMap": PM, "budget": 1}   # RECORDED budget = 1
        entry = _absent_entry(j, h, b_lo, bb6, absb, evh, cp)
        deriv = _derivation(h, entry)
        deref = {h: hb}
        ev_map = {evh: ev}

        # control (holds today): direct resolve_bb6 over the SAME bindings/partyMap/budget, both natives anchored,
        # sees the full 2-candidate bucket and reports BB-7 exhaustion for the seller.
        direct = R.resolve_bb6([b_lo, b_hi], PM, 1, anchored={lo: hb, hi: hb})
        self.assertEqual(direct["disposition"], "indeterminate",
                         "control: an over-budget authorized bucket must exhaust to indeterminate; got %r" % (direct,))
        self.assertIn(CLAIM["seller"], direct["exhaustedSigners"],
                      "control: the seller signer must be recorded exhausted; got %r" % (direct["exhaustedSigners"],))

        # CONTRACT: the full replay entry point must reproduce the same BB-7 exhaustion and REFUSE. RED at
        # 35fd3a7: it accepts (True, []) because the reconstruction pre-caps the bucket before resolve_bb6.
        vok, reasons = R.validate_resolution_context(deriv, lambda x: deref.get(x), lambda x: ev_map.get(x), PUBKEYS)
        self.assertFalse(vok, "F1: over-budget exhaustion must refuse the receipt; current wrong behaviour = %r"
                         % ((vok, reasons),))
        joined = " ".join(reasons)
        self.assertIn("BB-6 re-selection differs", joined,
                      "F1: refusal must come from the BB-6 re-selection reproducing exhaustion; current = %r" % (reasons,))
        self.assertIn("indeterminate", joined,
                      "F1: the reproduced BB-6 disposition must be indeterminate (BB-7); current = %r" % (reasons,))

    # -------------------------------------------------------------------------------------- F2
    def test_f2_unauthorized_outsider_pruned_before_candidate_reverification(self):
        """F2 (step-5 audit) — an UNAUTHORIZED outsider (signer NOT in the authenticated partyMap) must be
        pruned BEFORE the round-7 candidate BB-4/BB-5 re-verification, so a malformed outsider candidate cannot
        sink an otherwise-honest receipt. Here the outsider claims role:seller with INVALID binding signature
        bytes and a bundle absent from the deref map, attached to a valid honest receipt. RED at 35fd3a7: the
        round-7 re-verification loop runs over the full (unpruned) candidate set and refuses on the outsider's
        bad signature. This concerns UNAUTHORIZED candidates only — the authorized-invalid-candidate refusal
        (N6) is unaffected. EXECUTED via the full replay entry point, crypto ON; deref instrumented."""
        j = "R9-F2"
        honest = make_fab(j, "completed", "none", "seller", ["buyer", "seller"])
        h = bundle_hash(honest)
        n = native_address(j, "seller", 0)
        bind_h = make_binding(j, "seller", "seller", n, h)
        out_native = native_address(j, "seller", 5)
        out_hash = sha("outsider-bundle", j)                      # a genuine hash whose bundle is NEVER published
        bind_out = make_binding(j, "seller", "outsider", out_native, out_hash)
        bind_out["signature"]["value"] = b64u(b"\x00" * 64)       # INVALID signature bytes
        cp = native_address(j, "buyer")
        absb = make_binding(j, "buyer", "buyer", cp, PLACEHOLDER)
        ev = make_absence_evidence(cp)
        evh = evidence_hash(ev)
        bb6 = {"candidateBindings": [bind_h, bind_out], "partyMap": PM, "budget": 8}
        entry = _absent_entry(j, h, bind_h, bb6, absb, evh, cp)
        deriv = _derivation(h, entry)
        deref_map = {h: honest}                                   # outsider bundle intentionally ABSENT
        ev_map = {evh: ev}

        # the outsider is not the mapped role-holder, so it must be pruned before it can force a refusal.
        self.assertNotEqual(PM.get(bind_out["signer"]), bind_out["role"],
                            "control: the outsider signer is not mapped to the seller role")

        fetched = []

        def deref(x):
            fetched.append(x)
            return deref_map.get(x)

        vok, reasons = R.validate_resolution_context(deriv, deref, lambda x: ev_map.get(x), PUBKEYS)
        # CONTRACT: an unauthorized outsider is pruned before re-verification, so the honest receipt ACCEPTS.
        # RED at 35fd3a7: the round-7 loop refuses with "candidate binding fails BB-4/BB-5 re-verification".
        self.assertEqual((vok, reasons), (True, []),
                         "F2: an unauthorized outsider must not sink an honest receipt; current wrong behaviour = %r"
                         % (reasons,))
        self.assertNotIn(out_hash, fetched,
                         "F2: the pruned outsider bundle must never be fetched; current fetch list = %r" % (fetched,))

    # -------------------------------------------------------------------------------------- F4
    def test_f4_cross_role_counterparty_pruned_silently(self):
        """F4 (step-9 audit) — under a FULL authenticated partyMap {buyer->buyer, seller->seller}, a
        MAPPED counterparty (buyer) that publishes a binding CLAIMING role:seller (valid buyer signature)
        must be pruned by ROLE, not merely by signer-membership: the buyer does not hold seller, so its
        cross-role candidate must be dropped pre-fetch and MUST NOT sink an honest receipt. RED at
        1029ee5: the step-7 prune keeps candidates by `signer in party_map`, so the buyer's cross-role
        binding survives to the fetch loop — (a) an unfetchable one refuses 'not dereferenceable', and
        (b) a fetchable one is fetched (should be zero fetch work). This concerns the COUNTERPARTY's
        cross-role candidate only; the role-holder's own malformed candidate (N6) still refuses."""
        FULLPM = {CLAIM["buyer"]: "buyer", CLAIM["seller"]: "seller"}

        def build(job, cross_role_fetchable):
            honest = make_fab(job, "completed", "none", "seller", ["buyer", "seller"])
            h = bundle_hash(honest)
            n = native_address(job, "seller", 0)
            bind_h = make_binding(job, "seller", "seller", n, h)
            cp = native_address(job, "buyer")
            absb = make_binding(job, "buyer", "buyer", cp, PLACEHOLDER)
            ev = make_absence_evidence(cp)
            evh = evidence_hash(ev)
            xn = native_address(job, "seller", 9)
            deref_map = {h: honest}
            if cross_role_fetchable:
                x = make_fab(job, "completed", "none", "seller", ["buyer", "seller"])  # real co-signed bundle
                xh = bundle_hash(x)
                deref_map[xh] = x
            else:
                xh = sha("crossrole-unfetch", job)                                     # bundle intentionally ABSENT
            x_bind = make_binding(job, "seller", "buyer", xn, xh)   # buyer-signed, CLAIMS role seller, valid sig
            bb6 = {"candidateBindings": [bind_h, x_bind], "partyMap": FULLPM, "budget": 8}
            deriv = _derivation(h, _absent_entry(job, h, bind_h, bb6, absb, evh, cp))
            return deriv, deref_map, {evh: ev}, xh

        for label, fetchable in (("a: cross-role bundle unfetchable", False),
                                 ("b: cross-role bundle fetchable", True)):
            with self.subTest(vector=label):
                deriv, deref_map, ev_map, xh = build("R9-F4-" + ("a" if not fetchable else "b"), fetchable)
                fetched = []

                def deref(x):
                    fetched.append(x)
                    return deref_map.get(x)

                vok, reasons = R.validate_resolution_context(deriv, deref, lambda x: ev_map.get(x), PUBKEYS)
                # CONTRACT: a mapped counterparty's cross-role candidate is pruned by role pre-fetch — the honest
                # receipt accepts and no fetch work is spent on it. RED at 1029ee5: (a) refuses; (b) fetches it.
                self.assertEqual((vok, reasons), (True, []),
                                 "F4 %s: a cross-role counterparty candidate must not sink an honest receipt; "
                                 "current wrong behaviour = %r" % (label, reasons))
                self.assertNotIn(xh, fetched,
                                 "F4 %s: a role-holder-strict prune must spend zero fetch on the cross-role "
                                 "candidate; current fetch list = %r" % (label, fetched))

    # -------------------------------------------------------------------------------------- F5
    def test_f5_poison_inert_under_cross_role_flood(self):
        """F5 (step-10 audit) — a cross-role flood past budget must not bypass BB-5 post-fetch validation.
        An honest seller receipt carrying a seller-signed POISONED competitor (byte-recompute-fail, normally
        dropped inert) plus 10 buyer-signed role:seller candidates (unfetchable) under budget 8. RED at
        1029ee5: the buyer flood inflates the membership per-signer count, firing the pre-fetch exhaustion
        branch which resolves via resolve_bb6(survivors, …, anchored={}) — performing NO post-fetch
        validation, so the poison survives as a competing form and flips the side to indeterminate. The
        poison must instead be fetched and dropped inert on the normal validate route (R1), and the honest
        receipt must accept."""
        FULLPM = {CLAIM["buyer"]: "buyer", CLAIM["seller"]: "seller"}
        j = "R9-F5"
        honest = make_fab(j, "completed", "none", "seller", ["buyer", "seller"])
        h = bundle_hash(honest)
        n = native_address(j, "seller", 0)
        bind_h = make_binding(j, "seller", "seller", n, h)
        poison_bundle = make_fab(j, "failed-substrate", "none", "seller", ["buyer", "seller"])
        poison_claim = "b" * 64
        self.assertNotEqual(bundle_hash(poison_bundle), poison_claim, "poison must fail check-8 byte recompute")
        poison = make_binding(j, "seller", "seller", native_address(j, "seller", 3), poison_claim)
        flood = [make_binding(j, "seller", "buyer", native_address(j, "seller", 100 + k), sha("flood", j, str(k)))
                 for k in range(10)]
        cp = native_address(j, "buyer")
        absb = make_binding(j, "buyer", "buyer", cp, PLACEHOLDER)
        ev = make_absence_evidence(cp)
        evh = evidence_hash(ev)
        deref_map = {h: honest, poison_claim: poison_bundle}   # flood bundles intentionally unfetchable
        ev_map = {evh: ev}

        def run(candidate_bindings):
            bb6 = {"candidateBindings": candidate_bindings, "partyMap": FULLPM, "budget": 8}
            deriv = _derivation(h, _absent_entry(j, h, bind_h, bb6, absb, evh, cp))
            fetched = []

            def deref(x):
                fetched.append(x)
                return deref_map.get(x)

            vok, reasons = R.validate_resolution_context(deriv, deref, lambda x: ev_map.get(x), PUBKEYS)
            return vok, reasons, fetched

        # inline control (holds now AND after the fix): without the flood, the poison is fetched and dropped
        # inert on the normal validate route, and the honest receipt accepts.
        cvok, creasons, cfetched = run([bind_h, poison])
        self.assertEqual((cvok, creasons), (True, []),
                         "F5 control: without the flood the honest receipt must accept; got %r" % (creasons,))
        self.assertIn(poison_claim, cfetched, "F5 control: the poison must be fetched on the normal route")

        # main: WITH the flood, the honest receipt must still accept — the flood is not seller-bucket load and
        # the poison must be dropped inert on the normal validate route. RED at 1029ee5: the exhaustion branch
        # fires and refuses "BB-6 re-selection differs (got 'indeterminate'/None, …)".
        vok, reasons, fetched = run([bind_h, poison] + flood)
        self.assertEqual((vok, reasons), (True, []),
                         "F5: a cross-role flood must not bypass post-fetch validation; current wrong behaviour = %r"
                         % (reasons,))
        for k in range(10):
            self.assertNotIn(sha("flood", j, str(k)), fetched,
                             "F5: unfetchable cross-role flood candidates must never be fetched")
        self.assertIn(poison_claim, fetched,
                      "F5: the poison must be fetched and dropped inert on the normal validate route; "
                      "current fetch list = %r" % (fetched,))


if __name__ == "__main__":
    unittest.main()
