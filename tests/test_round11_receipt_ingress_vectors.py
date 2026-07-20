"""Round-11 receipt-ingress regressions (PR #248): the four receipt-layer probes @randomblocker
raised at head fdd656c, committed RED-first (D1 reproduce-first) with permanent well-formed controls.

TARGET CONTRACT (the property these pin, per Random's ask and spec DACS-5-VERIFY.md §10.5.3):
validate_resolution_context MUST NOT fail open or raise on a structurally malformed untrusted
resolutionContext entry — on malformed input it returns (False, [non-empty reasons]) and NEVER
raises. Neither _entry_structural_gate nor receipt_required_members_present currently guards these
roleEvidence / counterpartyDisposition / nested-contentHash / nested-signature paths at fdd656c, so
each defect probe is RED today (a fail-open (True, []) OR a raised exception — a raised exception
failing the test IS the 'no exception escapes' assertion, the round-10 vrc docstring convention).

The eight defect probes (each RED at fdd656c; observed wrong outcome quoted per probe):
  test_r11_a_role_evidence_empty_defect           roleEvidence = {}                 -> (True, []) fail-open
  test_r11_a2_role_evidence_unknown_kind_defect   roleEvidence = {"kind": <unknown>}-> (True, []) fail-open
  test_r11_b_disposition_unknown_defect           counterpartyDisposition=<unknown> -> (True, []) fail-open
  test_r11_b2_disposition_missing_defect          counterpartyDisposition deleted   -> (True, []) fail-open
  test_r11_c1_entry_content_hash_type_defect          entry contentHash = {}        -> TypeError: unhashable type: 'dict'
  test_r11_c2_counterparty_content_hash_type_defect   counterpartyRef.contentHash=[]-> TypeError: unhashable type: 'list'
  test_r11_c3_absence_content_hash_type_defect        absenceEvidenceRef.contentHash={} -> TypeError: unhashable type: 'dict'
  test_r11_d_binding_signature_nonobject_defect   roleEvidence.binding.signature="notadict"
                                                                                    -> AttributeError: 'str' object has no attribute 'get' (verify_binding)

Spec basis (DACS-5-VERIFY.md §10.5.3, lines cited in-situ below):
  :538-540  roleEvidence REQUIRED, XOR exactly one of {kind:"binding"} | {kind:"address"} — an empty
            object and an unrecognised kind are BOTH off the enumerated XOR (a / a2).
  :546      counterpartyDisposition REQUIRED, exactly "present" | "absent" — an unknown value and a
            missing key are BOTH off the enumerated set (b / b2).
  :536,:551 contentHash / absenceEvidenceRef.contentHash are string refs; a non-string is a malformed
            receptor that must refuse, never raise through the dict.get deref (c1 / c2 / c3).
  :539      roleEvidence.binding is a BundleBinding object; a non-object signature member below it must
            refuse, never raise through verify_binding (d).

DEFECT-ARM DISCIPLINE (B1.3 lands the fix): the defect arms assert only the TARGET contract
(ok is False, reasons non-empty, no exception escapes) — NOT exact reason strings — so B1.3 can pin
exact reasons without touching these arms' red/green meaning.

Self-contained (builders copied verbatim from the round-10 series). Crypto is MANDATORY (crypto ON,
zero skips): a missing dependency errors the module rather than silently skipping, matching the
suite's fail-closed-on-skip policy.
"""
import base64
import copy
import hashlib
import json
import unittest

import dacs5_reference as R

# fail-closed on crypto: hard import, no skip decorators.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# --- synthetic disclosed seeds (identical to the round-9/10 series / generator) ---
SEEDS = {"buyer": "a1" * 32, "seller": "c3" * 32, "orchestrator": "0e" * 32, "outsider": "f0" * 32}
CLAIM = {r: "did:demos:%s" % r for r in SEEDS}
KEYS = {r: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)) for r, s in SEEDS.items()}
PUBKEYS = {CLAIM[r]: KEYS[r].public_key().public_bytes_raw() for r in SEEDS}

BUNDLE_DOMAIN = "dacs-fault-bundle:v1:"
BINDING_DOMAIN = "dacs-bundle-binding:v1:"
PLACEHOLDER = "1" * 64
FINALISED_AT = 1780004000000
PM = {CLAIM["seller"]: "seller"}   # authenticated role-holder map (MANDATORY in a derivation context)
SELLER, BUYER = CLAIM["seller"], CLAIM["buyer"]


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
    return {"deriv": _derivation(h, entry), "deref": {h: winner}, "ev": {evh: ev},
            "h": h, "n": n, "winner": winner, "role_bind": role_bind}


def build_present(job):
    W = make_fab(job, "completed", "none", "seller", ["buyer", "seller"])
    h = bundle_hash(W)
    n = native_address(job, "seller", 0)
    role_bind = make_binding(job, "seller", "seller", n, h)
    cp_native = native_address(job, "buyer", 0)
    cp_bind = make_binding(job, "buyer", "buyer", cp_native, h)
    bb6 = {"candidateBindings": [role_bind], "partyMap": dict(PM), "budget": 8}
    entry = {"contentHash": h, "resolvedRole": "seller",
             "roleEvidence": {"kind": "binding", "binding": role_bind}, "bb6Context": bb6,
             "counterpartyDisposition": "present",
             "counterpartyRef": {"contentHash": h},
             "counterpartyRoleEvidence": {"kind": "binding", "binding": cp_bind}}
    return {"deriv": _derivation(h, entry), "deref": {h: W}, "ev": {}, "h": h, "W": W}


def vrc(p):
    """Run validate_resolution_context over a receipt-factory dict. A raised exception here fails
    the test (that is exactly the 'no exception escapes' assertion)."""
    return R.validate_resolution_context(p["deriv"], lambda x: p["deref"].get(x),
                                         lambda x: p["ev"].get(x), PUBKEYS)


class Round11ReceiptIngressTests(unittest.TestCase):
    def _assert_refused(self, observed, label):
        """TARGET contract: a malformed receipt refuses — ok is False, reasons non-empty. (Reaching
        this at all already proves no exception escaped; the c/d arms error at fdd656c before here,
        which IS their RED no-escape assertion.)"""
        ok, reasons = observed
        self.assertFalse(ok, "%s: malformed receipt must refuse, got ok=True reasons=%r" % (label, reasons))
        self.assertTrue(reasons, "%s: refusal must carry a non-empty reason list, got %r" % (label, reasons))

    # ============================================================ (a) roleEvidence off the XOR
    def test_r11_a_role_evidence_empty_defect(self):
        """DEFECT (§10.5.3 :538-540 — roleEvidence REQUIRED, XOR {binding|address}): an EMPTY
        roleEvidence object is off the XOR and MUST refuse. At fdd656c the kind!='binding' branch is
        skipped and the absent path passes -> fail-open (True, [])."""
        p = build_absent("R11-A")
        p["deriv"]["resolutionContext"][0]["roleEvidence"] = {}
        self._assert_refused(vrc(p), "a/roleEvidence={}")

    def test_r11_a2_role_evidence_unknown_kind_defect(self):
        """DEFECT (§10.5.3 :538-540 — 'its supported kind', Random's ask): an UNRECOGNISED roleEvidence
        kind is off the XOR and MUST refuse. At fdd656c any kind!='binding' silently skips
        re-verification -> fail-open (True, [])."""
        p = build_absent("R11-A2")
        p["deriv"]["resolutionContext"][0]["roleEvidence"] = {"kind": "not-a-real-kind"}
        self._assert_refused(vrc(p), "a2/roleEvidence.kind=unknown")

    # ============================================================ (b) counterpartyDisposition off the set
    def test_r11_b_disposition_unknown_defect(self):
        """DEFECT (§10.5.3 :546 — counterpartyDisposition exactly 'present'|'absent'): an UNKNOWN
        disposition value MUST refuse. At fdd656c neither the present nor absent branch fires, so the
        entry passes unchecked -> fail-open (True, [])."""
        p = build_absent("R11-B")
        p["deriv"]["resolutionContext"][0]["counterpartyDisposition"] = "maybe-later"
        self._assert_refused(vrc(p), "b/disposition=unknown")

    def test_r11_b2_disposition_missing_defect(self):
        """DEFECT (§10.5.3 :546 — 'unsupported/missing disposition values', Random's ask): a MISSING
        counterpartyDisposition MUST refuse (it is REQUIRED). At fdd656c disp=None fires neither branch
        -> fail-open (True, [])."""
        p = build_absent("R11-B2")
        del p["deriv"]["resolutionContext"][0]["counterpartyDisposition"]
        self._assert_refused(vrc(p), "b2/disposition missing")

    # ============================================================ (c) non-string contentHash refs
    def test_r11_c1_entry_content_hash_type_defect(self):
        """DEFECT (§10.5.3 :536 — contentHash is a string ref): a non-string (unhashable {}) entry
        contentHash MUST refuse, never raise. At fdd656c deref({}) -> TypeError: unhashable type:
        'dict' escapes through the dict.get deref."""
        p = build_absent("R11-C1")
        p["deriv"]["resolutionContext"][0]["contentHash"] = {}
        self._assert_refused(vrc(p), "c1/entry contentHash={}")

    def test_r11_c2_counterparty_content_hash_type_defect(self):
        """DEFECT (§10.5.3 :547 — counterpartyRef is an AttestationRef with a string contentHash): a
        non-string (unhashable []) counterpartyRef.contentHash MUST refuse, never raise. At fdd656c the
        present path deref([]) -> TypeError: unhashable type: 'list'."""
        p = build_present("R11-C2")
        p["deriv"]["resolutionContext"][0]["counterpartyRef"]["contentHash"] = []
        self._assert_refused(vrc(p), "c2/counterpartyRef.contentHash=[]")

    def test_r11_c3_absence_content_hash_type_defect(self):
        """DEFECT (§10.5.3 :551 — absenceEvidenceRef.contentHash is a string ref): a non-string
        (unhashable {}) absenceEvidenceRef.contentHash MUST refuse, never raise. At fdd656c the absent
        path evidence_deref({}) -> TypeError: unhashable type: 'dict'."""
        p = build_absent("R11-C3")
        p["deriv"]["resolutionContext"][0]["absenceEvidenceRef"]["contentHash"] = {}
        self._assert_refused(vrc(p), "c3/absenceEvidenceRef.contentHash={}")

    # ============================================================ (d) non-object nested binding signature
    def test_r11_d_binding_signature_nonobject_defect(self):
        """DEFECT (§10.5.3 :539 — roleEvidence.binding is a BundleBinding object): a truthy NON-OBJECT
        binding.signature MUST refuse, never raise. At fdd656c verify_binding does `sig =
        binding.get('signature') or {}` then `sig.get('signer')` -> AttributeError: 'str' object has
        no attribute 'get'."""
        p = build_absent("R11-D")
        p["deriv"]["resolutionContext"][0]["roleEvidence"]["binding"]["signature"] = "notadict"
        self._assert_refused(vrc(p), "d/binding.signature='notadict'")

    # ============================================================ permanent well-formed controls
    def test_r11_absent_wellformed_control(self):
        """CONTROL (1:1 with a/a2/b/b2/c1/c3/d — the absent base): an untouched well-formed absent
        receipt accepts. Green today AND after the B1.3 fix."""
        self.assertEqual(vrc(build_absent("R11-ABS-CTL")), (True, []))

    def test_r11_present_wellformed_control(self):
        """CONTROL (1:1 with c2 — the present base): an untouched well-formed present receipt accepts.
        Green today AND after the B1.3 fix."""
        self.assertEqual(vrc(build_present("R11-PRES-CTL")), (True, []))

    def test_r11_address_kind_control(self):
        """CONTROL / OVER-TIGHTENING PIN (§10.5.3 :540 — the SECOND XOR arm): a roleEvidence
        {kind:'address', resolvedAddress:<str>} substrate (bb6Context removed, since bb6Context is
        REQUIRED iff kind=='binding', :541) MUST remain ACCEPTED when the B1.3 fix lands — the fix
        must reject empty/unknown kinds WITHOUT rejecting the legitimate address arm. Green today (the
        kind!='binding' branch is skipped) AND after the fix."""
        p = build_absent("R11-ADDR-CTL")
        entry = p["deriv"]["resolutionContext"][0]
        entry["roleEvidence"] = {"kind": "address", "resolvedAddress": p["n"]}
        del entry["bb6Context"]
        self.assertEqual(vrc(p), (True, []))


if __name__ == "__main__":
    unittest.main()
