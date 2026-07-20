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


def seller_binding_raw(job, native, content_hash, role="seller", signer_role="seller"):
    """A BundleBinding built raw so nativeAddress / bundleContentHash may be None (make_binding slices
    native[5:21]); signed over its real binding_hash so it passes BB-4 crypto in both modes."""
    bd = {"bindingVersion": "1", "jobId": job, "role": role,
          "logicalAddress": logical_address(job, role),
          "nativeAddress": native, "bundleContentHash": content_hash,
          "anchorTx": "demos-testnet:tx-x", "signer": CLAIM[signer_role]}
    payload = (BINDING_DOMAIN + binding_hash(bd)).encode("utf-8")
    bd["signature"] = {"algorithm": "ed25519", "signer": CLAIM[signer_role],
                       "value": b64u(KEYS[signer_role].sign(payload))}
    return bd


# ============================================================================================
# SCHEMA-GRID ORACLE (B1.4)
# --------------------------------------------------------------------------------------------
# Exhaustive (path x mutation) sweep over the §10.5.3 ResolutionContextEntry GRAMMAR ONLY
# (spec DACS-5-VERIFY.md :535-552). SCOPE BOUNDARY (this is the exact surface the PR comment
# quantifies): the deref'd-COPY surfaces — the winner copy, the counterparty copy, and fetched
# candidate CONTENT — are DELIBERATELY EXCLUDED from this grid. They are class-closed elsewhere
# with their own named regressions and distinct semantics (winner=refuse, counterparty=refuse,
# fetched candidate=DROP-inert; see test_r11_pf_* and the round-10 D6 winner/counterparty gates).
# CONTRACT per cell (contract-only; exact reasons live in the named round-11 regressions above):
# run the REAL predicate in CRYPTO mode (PUBKEYS, matching the suite's crypto-mandatory policy),
# assert NO exception, ok is False, reasons NON-EMPTY. Deterministic: sorted paths x fixed kind
# order, zero randomness, zero new dependencies.

# Fixed mutation-kind order. A kind is applied to a path ONLY where its value VIOLATES the grammar.
KIND_ORDER = ["missing-key", "null", "wrong-scalar-type", "empty-container",
              "unknown-enum-value", "non-object-where-object", "unhashable-where-hash-key"]

# Per type-tag, the kinds that VIOLATE the grammar for that path (legal-value kinds are omitted, and
# additionally recorded in LEGAL_CELLS for the oracle's honesty surface).
_VIOLATING = {
    "hashkey":         ["missing-key", "null", "wrong-scalar-type", "unhashable-where-hash-key"],
    "str":             ["missing-key", "null", "wrong-scalar-type"],
    "enum":            ["missing-key", "null", "wrong-scalar-type", "unknown-enum-value"],
    "object-req":      ["missing-key", "null", "empty-container", "non-object-where-object"],
    "object-nullable": ["wrong-scalar-type", "non-object-where-object"],   # null / {} / missing are LEGAL
    "number":          ["missing-key", "null", "non-object-where-object"], # 123 is a LEGAL budget
    "array":           ["missing-key", "null", "wrong-scalar-type", "empty-container", "non-object-where-object"],
}


def _mutated_value(kind, tag):
    """The value a kind installs at a path (missing-key deletes; handled by the caller)."""
    if kind == "null":
        return None
    if kind == "wrong-scalar-type":
        return 123
    if kind == "empty-container":
        return [] if tag == "array" else {}
    if kind == "unknown-enum-value":
        return "zzz"
    if kind == "non-object-where-object":
        return "x"
    if kind == "unhashable-where-hash-key":
        return {}
    raise AssertionError("no value for kind %r" % kind)   # missing-key never reaches here


def _member_nav(root_fn, member):
    """Navigator for a (possibly dotted) member under a binding-root accessor -> (container, key)."""
    parts = member.split(".")

    def nav(e):
        obj = root_fn(e)
        for part in parts[:-1]:
            obj = obj[part]
        return obj, parts[-1]
    return nav


# The BundleBinding member grammar (spec §B.7 :351-361), reused at every binding-bearing site.
_BINDING_MEMBERS = [
    ("bindingVersion", "str"), ("jobId", "str"), ("role", "enum"),
    ("signer", "hashkey"), ("nativeAddress", "str"), ("bundleContentHash", "hashkey"),
    ("logicalAddress", "str"), ("signature", "object-req"),
    ("signature.signer", "str"), ("signature.algorithm", "str"), ("signature.value", "str"),
]
# (base_key, path-prefix, root accessor) for each of the four verify_binding call sites.
_BINDING_ROOTS = [
    ("absent", "roleEvidence.binding", lambda e: e["roleEvidence"]["binding"]),
    ("absent", "bb6Context.candidateBindings[0]", lambda e: e["bb6Context"]["candidateBindings"][0]),
    ("absent", "absenceBinding", lambda e: e["absenceBinding"]),
    ("present", "counterpartyRoleEvidence.binding", lambda e: e["counterpartyRoleEvidence"]["binding"]),
]


def _grid_paths():
    """The §10.5.3 entry-grammar path set with type tags + navigators, dual-base."""
    A, P = "absent", "present"
    paths = [
        (A, "contentHash", "hashkey", lambda e: (e, "contentHash")),
        (A, "resolvedRole", "enum", lambda e: (e, "resolvedRole")),
        (A, "roleEvidence", "object-req", lambda e: (e, "roleEvidence")),
        (A, "roleEvidence.kind", "enum", lambda e: (e["roleEvidence"], "kind")),
        (A, "roleEvidence.binding", "object-req", lambda e: (e["roleEvidence"], "binding")),
        (A, "bb6Context", "object-req", lambda e: (e, "bb6Context")),
        (A, "bb6Context.partyMap", "object-nullable", lambda e: (e["bb6Context"], "partyMap")),
        (A, "bb6Context.budget", "number", lambda e: (e["bb6Context"], "budget")),
        (A, "bb6Context.candidateBindings", "array", lambda e: (e["bb6Context"], "candidateBindings")),
        (A, "counterpartyDisposition", "enum", lambda e: (e, "counterpartyDisposition")),
        (A, "absenceEvidenceRef", "object-req", lambda e: (e, "absenceEvidenceRef")),
        (A, "absenceEvidenceRef.kind", "str", lambda e: (e["absenceEvidenceRef"], "kind")),
        (A, "absenceEvidenceRef.locator", "str", lambda e: (e["absenceEvidenceRef"], "locator")),
        (A, "absenceEvidenceRef.contentHash", "hashkey", lambda e: (e["absenceEvidenceRef"], "contentHash")),
        (A, "absenceBinding", "object-req", lambda e: (e, "absenceBinding")),
        (P, "counterpartyRef", "object-req", lambda e: (e, "counterpartyRef")),
        (P, "counterpartyRef.contentHash", "hashkey", lambda e: (e["counterpartyRef"], "contentHash")),
        (P, "counterpartyRoleEvidence", "object-req", lambda e: (e, "counterpartyRoleEvidence")),
        (P, "counterpartyRoleEvidence.kind", "enum", lambda e: (e["counterpartyRoleEvidence"], "kind")),
        (P, "counterpartyRoleEvidence.binding", "object-req", lambda e: (e["counterpartyRoleEvidence"], "binding")),
        ("absent-addr", "roleEvidence.resolvedAddress", "str", lambda e: (e["roleEvidence"], "resolvedAddress")),
        # (round-12) present address arm: roleEvidence AND counterpartyRoleEvidence are the SECOND XOR
        # arm {kind:"address", resolvedAddress:string} (spec :540, :548). counterpartyRoleEvidence's
        # binding arm is already swept on the `present` base; this rides the `present-addr` base so the
        # counterparty address arm's REQUIRED string member is covered too.
        ("present-addr", "roleEvidence.resolvedAddress", "str", lambda e: (e["roleEvidence"], "resolvedAddress")),
        ("present-addr", "counterpartyRoleEvidence.resolvedAddress", "str", lambda e: (e["counterpartyRoleEvidence"], "resolvedAddress")),
    ]
    for base_key, prefix, root_fn in _BINDING_ROOTS:
        for member, tag in _BINDING_MEMBERS:
            paths.append((base_key, "%s.%s" % (prefix, member), tag, _member_nav(root_fn, member)))
    return paths


def grid_cells():
    """Deterministic cell enumeration: sorted (base, path) x fixed KIND_ORDER, applicable
    (grammar-violating) kinds only. Returns (case_id, base_key, path_id, tag, kind, nav)."""
    cells = []
    for base_key, path_id, tag, nav in sorted(_grid_paths(), key=lambda t: (t[0], t[1])):
        for kind in KIND_ORDER:
            if kind in _VIOLATING[tag]:
                cells.append(("%s:%s:%s" % (base_key, path_id, kind), base_key, path_id, tag, kind, nav))
    return cells


# Grammar-LEGAL (path, kind) cells — NOT generated as refusal cells (excluded via type tag), listed
# here for the oracle's honesty surface with the spec line that makes each legal.
LEGAL_CELLS = [
    ("absent:bb6Context.partyMap:missing-key", "partyMap 'object | null' — absent key reads as no-map (spec :543)"),
    ("absent:bb6Context.partyMap:null", "partyMap 'object | null' (spec :543)"),
    ("absent:bb6Context.partyMap:empty-container", "an empty object {} is a grammar-legal partyMap (spec :543)"),
    ("absent:bb6Context.budget:wrong-scalar-type", "123 is a grammar-legal positive-integer budget (spec :544)"),
]


def _grid_base_absent():
    p = build_absent("GRID-ABS")
    e = p["deriv"]["resolutionContext"][0]
    e["bb6Context"]["candidateBindings"] = [copy.deepcopy(e["roleEvidence"]["binding"])]   # DE-ALIAS
    return p, e


def _grid_base_present():
    p = build_present("GRID-PRE")
    e = p["deriv"]["resolutionContext"][0]
    e["bb6Context"]["candidateBindings"] = [copy.deepcopy(e["roleEvidence"]["binding"])]   # DE-ALIAS
    return p, e


def _grid_base_absent_addr():
    p = build_absent("GRID-ADR")
    e = p["deriv"]["resolutionContext"][0]
    e["roleEvidence"] = {"kind": "address", "resolvedAddress": p["n"]}
    del e["bb6Context"]
    return p, e


def _grid_base_present_addr():
    """(round-12) present base with BOTH role-evidences switched to the address XOR arm (the T7-control
    switch): binding.nativeAddress -> resolvedAddress, bb6Context removed (REQUIRED iff kind=='binding',
    :541), resolvedRole kept valid. Accepts unmutated; enables the counterparty address arm sweep."""
    p = build_present("GRID-PADR")
    e = p["deriv"]["resolutionContext"][0]
    re_nat = e["roleEvidence"]["binding"]["nativeAddress"]
    cre_nat = e["counterpartyRoleEvidence"]["binding"]["nativeAddress"]
    e["roleEvidence"] = {"kind": "address", "resolvedAddress": re_nat}
    e["counterpartyRoleEvidence"] = {"kind": "address", "resolvedAddress": cre_nat}
    del e["bb6Context"]
    return p, e


_GRID_BASES = {"absent": _grid_base_absent, "present": _grid_base_present,
               "absent-addr": _grid_base_absent_addr, "present-addr": _grid_base_present_addr}

# Random's four probes MUST appear as grid hits (and remain named regressions above).
RANDOMS_FOUR = [
    "absent:contentHash:unhashable-where-hash-key",
    "absent:roleEvidence:empty-container",
    "absent:counterpartyDisposition:unknown-enum-value",
    "absent:roleEvidence.binding.signature:non-object-where-object",
]


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
        self.assertEqual(vrc(p), (False, ["%s: roleEvidence.kind must be one of ['address', 'binding'] (got None)" % p["h"]]))

    def test_r11_a2_role_evidence_unknown_kind_defect(self):
        """DEFECT (§10.5.3 :538-540 — 'its supported kind', Random's ask): an UNRECOGNISED roleEvidence
        kind is off the XOR and MUST refuse. At fdd656c any kind!='binding' silently skips
        re-verification -> fail-open (True, [])."""
        p = build_absent("R11-A2")
        p["deriv"]["resolutionContext"][0]["roleEvidence"] = {"kind": "not-a-real-kind"}
        self.assertEqual(vrc(p), (False, ["%s: roleEvidence.kind must be one of ['address', 'binding'] (got 'not-a-real-kind')" % p["h"]]))

    # ============================================================ (b) counterpartyDisposition off the set
    def test_r11_b_disposition_unknown_defect(self):
        """DEFECT (§10.5.3 :546 — counterpartyDisposition exactly 'present'|'absent'): an UNKNOWN
        disposition value MUST refuse. At fdd656c neither the present nor absent branch fires, so the
        entry passes unchecked -> fail-open (True, [])."""
        p = build_absent("R11-B")
        p["deriv"]["resolutionContext"][0]["counterpartyDisposition"] = "maybe-later"
        self.assertEqual(vrc(p), (False, ["%s: counterpartyDisposition must be one of ['absent', 'present'] (got 'maybe-later')" % p["h"]]))

    def test_r11_b2_disposition_missing_defect(self):
        """DEFECT (§10.5.3 :546 — 'unsupported/missing disposition values', Random's ask): a MISSING
        counterpartyDisposition MUST refuse (it is REQUIRED). At fdd656c disp=None fires neither branch
        -> fail-open (True, [])."""
        p = build_absent("R11-B2")
        del p["deriv"]["resolutionContext"][0]["counterpartyDisposition"]
        self.assertEqual(vrc(p), (False, ["%s: counterpartyDisposition must be one of ['absent', 'present'] (got None)" % p["h"]]))

    # ============================================================ (c) non-string contentHash refs
    def test_r11_c1_entry_content_hash_type_defect(self):
        """DEFECT (§10.5.3 :536 — contentHash is a string ref): a non-string (unhashable {}) entry
        contentHash MUST refuse, never raise. At fdd656c deref({}) -> TypeError: unhashable type:
        'dict' escapes through the dict.get deref."""
        p = build_absent("R11-C1")
        p["deriv"]["resolutionContext"][0]["contentHash"] = {}
        self.assertEqual(vrc(p), (False, ["resolutionContext[0]: contentHash must be a string (got dict)"]))

    def test_r11_c2_counterparty_content_hash_type_defect(self):
        """DEFECT (§10.5.3 :547 — counterpartyRef is an AttestationRef with a string contentHash): a
        non-string (unhashable []) counterpartyRef.contentHash MUST refuse, never raise. At fdd656c the
        present path deref([]) -> TypeError: unhashable type: 'list'."""
        p = build_present("R11-C2")
        p["deriv"]["resolutionContext"][0]["counterpartyRef"]["contentHash"] = []
        self.assertEqual(vrc(p), (False, ["%s: counterpartyRef.contentHash must be a string (got list)" % p["h"]]))

    def test_r11_c3_absence_content_hash_type_defect(self):
        """DEFECT (§10.5.3 :551 — absenceEvidenceRef.contentHash is a string ref): a non-string
        (unhashable {}) absenceEvidenceRef.contentHash MUST refuse, never raise. At fdd656c the absent
        path evidence_deref({}) -> TypeError: unhashable type: 'dict'."""
        p = build_absent("R11-C3")
        p["deriv"]["resolutionContext"][0]["absenceEvidenceRef"]["contentHash"] = {}
        self.assertEqual(vrc(p), (False, ["%s: absenceEvidenceRef.contentHash must be a string (got dict)" % p["h"]]))

    # ============================================================ (d) non-object nested binding signature
    def test_r11_d_binding_signature_nonobject_defect(self):
        """DEFECT (§10.5.3 :539 — roleEvidence.binding is a BundleBinding object): a truthy NON-OBJECT
        binding.signature MUST refuse, never raise. At fdd656c verify_binding does `sig =
        binding.get('signature') or {}` then `sig.get('signer')` -> AttributeError: 'str' object has
        no attribute 'get'."""
        p = build_absent("R11-D")
        p["deriv"]["resolutionContext"][0]["roleEvidence"]["binding"]["signature"] = "notadict"
        self.assertEqual(vrc(p), (False, ["%s: roleEvidence BB-4: binding.signature must be an object (got str)" % p["h"]]))

    # ============================================================ B1.3 sweep DELTAS (red-first)
    def _assert_inert_accept(self, observed, label):
        """Class-5 contract: a decoy candidate whose FETCHED copy is malformed is DROPPED inert
        (R1/R3a/R3b, BB-6/BB-7 inertness) — the honest winner still resolves, so the receipt ACCEPTS
        (True, []). NOT a refusal: an extra candidate must never refuse an otherwise-honest receipt.
        (Reaching this at all already proves no exception escaped; today these ESCAPE at the un-shape-
        gated 3rd deref site, which IS the red no-escape assertion.)"""
        self.assertEqual(observed, (True, []),
                         "%s: malformed fetched candidate must drop inert -> (True, []), got %r" % (label, observed))

    # ---- Class 4: candidate ordering-sort null keys (survive the type-when-present gate) --------
    def test_r11_s1_candidate_bch_none_sort_defect(self):
        """DEFECT: a seller candidate with bundleContentHash=None beside a present-string one reaches
        the BB-6 ordering sort (:1011) -> TypeError comparing (None, na) vs (str, na). A null binding
        member is a malformed candidate and MUST refuse, never raise."""
        p = build_absent("R11-S1")
        c = make_binding("R11-S1", "seller", "seller", native_address("R11-S1", "seller", 1), None)
        p["deriv"]["resolutionContext"][0]["bb6Context"]["candidateBindings"].append(c)
        self.assertEqual(vrc(p), (False, [
            "%s: bb6Context candidate binding fails BB-4/BB-5 re-verification "
            "(%s: BB-5: binding.bundleContentHash must be a string (got NoneType))"
            % (p["h"], native_address("R11-S1", "seller", 1))]))

    def test_r11_s2_candidate_native_none_sort_defect(self):
        """DEFECT: a seller candidate with nativeAddress=None on a same-bundleContentHash tie reaches
        the ordering sort (:1011) -> TypeError on the tie-break (str, str) vs (str, None). Refuse."""
        p = build_absent("R11-S2")
        c = seller_binding_raw("R11-S2", None, p["h"])
        p["deriv"]["resolutionContext"][0]["bb6Context"]["candidateBindings"].append(c)
        self.assertEqual(vrc(p), (False, [
            "%s: bb6Context candidate binding fails BB-4/BB-5 re-verification "
            "(None: BB-5: binding.nativeAddress must be a string (got NoneType))" % p["h"]]))

    # ---- Class 1: XOR-arm / disposition vocabulary fail-open -----------------------------------
    def test_r11_cre_counterparty_kind_unknown_defect(self):
        """DEFECT (§10.5.3 :548 — counterpartyRoleEvidence XOR {binding|address}): on the present path
        an UNKNOWN kind skips counterparty role authentication -> fail-open (True, []). Refuse."""
        p = build_present("R11-CRE")
        p["deriv"]["resolutionContext"][0]["counterpartyRoleEvidence"] = {"kind": "zzz"}
        self.assertEqual(vrc(p), (False, ["%s: counterpartyRoleEvidence.kind must be one of ['address', 'binding'] (got 'zzz')" % p["h"]]))

    def test_r11_adr0_address_arm_missing_resolved_defect(self):
        """DEFECT (§10.5.3 :540 — address arm resolvedAddress REQUIRED string): a {kind:'address'} arm
        with resolvedAddress MISSING is unvalidated -> fail-open. Refuse (structural shape only this
        round; the role-segment SEMANTIC check is disclosed residual #3)."""
        p = build_absent("R11-ADR0")
        e = p["deriv"]["resolutionContext"][0]
        e["roleEvidence"] = {"kind": "address"}
        del e["bb6Context"]
        self.assertEqual(vrc(p), (False, ["%s: roleEvidence.resolvedAddress must be a string (got NoneType)" % p["h"]]))

    def test_r11_adr1_address_arm_nonstring_resolved_defect(self):
        """DEFECT (§10.5.3 :540): a {kind:'address'} arm with a NON-STRING resolvedAddress is
        unvalidated -> fail-open. Refuse."""
        p = build_absent("R11-ADR1")
        e = p["deriv"]["resolutionContext"][0]
        e["roleEvidence"] = {"kind": "address", "resolvedAddress": 123}
        del e["bb6Context"]
        self.assertEqual(vrc(p), (False, ["%s: roleEvidence.resolvedAddress must be a string (got int)" % p["h"]]))

    # ---- Class 3: verify_binding nested-member ingress (4 call sites + crypto sub-path) ---------
    def test_r11_vbver_binding_version_unhashable_defect(self):
        """DEFECT: an unhashable binding.bindingVersion escapes at `not in SUPPORTED_BINDING_VERSIONS`
        (:175), BEFORE crypto, in both modes. Witnessed at TWO of the four verify_binding call sites
        (roleEvidence vb, absenceBinding vb3); one ingress gate closes all four. Refuse."""
        with self.subTest(site="roleEvidence"):
            p = build_absent("R11-VBV1")
            p["deriv"]["resolutionContext"][0]["roleEvidence"]["binding"]["bindingVersion"] = []
            self.assertEqual(vrc(p), (False, ["%s: roleEvidence BB-5: binding.bindingVersion must be a string (got list)" % p["h"]]))
        with self.subTest(site="absenceBinding"):
            p = build_absent("R11-VBV2")
            p["deriv"]["resolutionContext"][0]["absenceBinding"]["bindingVersion"] = []
            self.assertEqual(vrc(p), (False, ["%s: absenceBinding BB-5: binding.bindingVersion must be a string (got list)" % p["h"]]))

    def test_r11_vbalg_signature_algorithm_unhashable_defect(self):
        """DEFECT (crypto sub-path): an unhashable signature.algorithm escapes at `not in
        SUPPORTED_SIGNATURE_ALGORITHMS` (:191). Refuse (both modes, once ingress runs pre-crypto)."""
        p = build_absent("R11-VBALG")
        p["deriv"]["resolutionContext"][0]["roleEvidence"]["binding"]["signature"]["algorithm"] = []
        self.assertEqual(vrc(p), (False, ["%s: roleEvidence BB-4: binding.signature.algorithm must be a string (got list)" % p["h"]]))

    def test_r11_vbsgn_signer_unhashable_dealiased_defect(self):
        """DEFECT (crypto sub-path, de-aliased): with candidateBindings holding its OWN deepcopy, an
        unhashable roleEvidence.binding.signer escapes at `pubkeys.get(signer)` (:187) in crypto mode.
        build_absent otherwise aliases roleEvidence.binding into candidateBindings[0], masking it via
        the candidate-signer gate. Refuse."""
        p = build_absent("R11-VBSGN")
        e = p["deriv"]["resolutionContext"][0]
        e["bb6Context"]["candidateBindings"] = [copy.deepcopy(e["roleEvidence"]["binding"])]
        e["roleEvidence"]["binding"]["signer"] = []
        e["roleEvidence"]["binding"]["signature"]["signer"] = []
        self.assertEqual(vrc(p), (False, ["%s: roleEvidence BB-5: binding.signer must be a string (got list)" % p["h"]]))

    # ---- Class 3: jobId / role type-collusion (concat sites) -----------------------------------
    def test_r11_coll1_jobid_type_collusion_defect(self):
        """DEFECT: winner.jobId AND binding.jobId both 123 — verify_binding's jobId equality (:178)
        passes on the collusion, then logical_address(123, role) (:182) concatenates int+str ->
        TypeError, both modes. verify_binding ingress must type jobId. Refuse."""
        p = build_absent("R11-COLL1")
        w = p["winner"]; w["jobId"] = 123
        newch = bundle_hash(w)
        p["deref"] = {newch: w}
        p["deriv"]["bundleRefs"] = [newch]
        e = p["deriv"]["resolutionContext"][0]
        e["contentHash"] = newch
        e["roleEvidence"]["binding"]["jobId"] = 123
        self.assertEqual(vrc(p), (False, ["%s: roleEvidence BB-5: binding.jobId must be a string (got int)" % newch]))

    def test_r11_coll2_role_type_collusion_defect(self):
        """DEFECT: entry.resolvedRole AND binding.role both 123. As of round-12 B2 the entry's invalid
        resolvedRole is refused DIRECTLY by _entry_structural_gate's enum vocabulary check, BEFORE the
        evidence-kind branch reaches verify_binding — so the colluding non-string enum is caught strictly
        earlier (and the str+int logical_address TypeError is unreachable). The binding.role ingress
        type-check that this originally exercised is preserved on the valid-role arm by coll2b below."""
        p = build_absent("R11-COLL2")
        e = p["deriv"]["resolutionContext"][0]
        e["resolvedRole"] = 123
        e["roleEvidence"]["binding"]["role"] = 123
        self.assertEqual(vrc(p), (False, ["%s: resolvedRole must be one of ['buyer', 'seller'] (got 123)" % p["h"]]))

    def test_r11_coll2b_binding_role_type_defect(self):
        """DEFECT (round-12 sibling of coll2): resolvedRole is a VALID enum ("seller") but the
        roleEvidence binding.role is 123 — the enum gate passes, so this still reaches and exercises
        verify_binding's binding.role ingress type-check (:180-183). Refuse via the binding-role reason,
        never a str+int logical_address TypeError."""
        p = build_absent("R11-COLL2B")
        e = p["deriv"]["resolutionContext"][0]
        e["roleEvidence"]["binding"]["role"] = 123
        self.assertEqual(vrc(p), (False, ["%s: roleEvidence BB-5: binding.role must be a string (got int)" % p["h"]]))

    # ---- Class 5: un-shape-gated fetched candidate copy (3rd deref site :1035) ------------------
    def _pf_decoy(self, job, mutate_fetched, decoy_key="decoy" + "0" * 59):
        """build_absent + a decoy seller candidate whose FETCHED copy is `mutate_fetched`-mangled; the
        honest winner is intact. The decoy binding is well-formed, so it survives prune + BB-4/BB-5
        re-verification and its fetched copy reaches the un-shape-gated _post_fetch_valid at :1035."""
        p = build_absent(job)
        decoy_native = native_address(job, "seller", 5)
        mal = make_fab(job, "completed", "none", "seller", ["buyer", "seller"])
        mutate_fetched(mal)
        decoy_bind = make_binding(job, "seller", "seller", decoy_native, decoy_key)
        p["deriv"]["resolutionContext"][0]["bb6Context"]["candidateBindings"].append(decoy_bind)
        p["deref"][decoy_key] = mal
        return p

    def test_r11_pf_sig_fetched_party_unhashable_defect(self):
        """DEFECT: a decoy whose FETCHED copy carries signatures[0].party=[] escapes at the
        {s.get('party')} set comprehension in _bundle_signatures_valid (un-shape-gated fetched copy).
        The fix shape-gates the fetched copy and DROPS it inert -> honest winner resolves -> ACCEPT."""
        p = self._pf_decoy("R11-PFSIG",
                           lambda W: W.__setitem__("signatures", [{"party": [], "algorithm": "ed25519", "value": "aa"}]))
        self._assert_inert_accept(vrc(p), "pf-sig/fetched signatures[0].party []")

    def test_r11_pf_par_fetched_parties_nonobject_defect(self):
        """DEFECT: a decoy whose FETCHED copy carries parties[0]='x' escapes at _holds_role's p.get
        genexpr (un-shape-gated fetched copy). The fix shape-gates + DROPS inert -> ACCEPT."""
        p = self._pf_decoy("R11-PFPAR", lambda W: W.__setitem__("parties", ["x"]))
        self._assert_inert_accept(vrc(p), "pf-par/fetched parties[0] non-object")

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

    def test_r11_pf_drop_inert_control(self):
        """CONTROL (R1/R3 drop-inert witness — the ROUND-9 _post_fetch_valid drop LAYER): a decoy
        candidate whose FETCHED copy is shape-VALID but POST-FETCH-invalid (a completed FAB signed by
        SELLER only -> §10.4.1 required-signer fail) alongside the honest winner. The copy passes
        _bundle_shape_ok, then DROPS at _post_fetch_valid; the honest winner resolves; the receipt
        ACCEPTS (True, []). SCOPE: this pins the round-9 post-fetch drop, NOT the round-11 shape-gate
        drop — its decoy is shape-VALID, so inverting the round-11 _bundle_shape_ok continue->refuse
        leaves this control green (mutation MC2). The round-11 shape-gate drop-vs-refuse is pinned
        instead by test_r11_pf_sig/pf_par: their (True, []) inert-accept assertions go RED if the shape
        gate refuses instead of dropping a shape-INVALID fetched copy."""
        job = "R11-PF-DROP"
        p = build_absent(job)
        decoy_native = native_address(job, "seller", 6)
        # distinct finalisedAt so bundle_hash differs from the winner (bundle_hash excludes signatures,
        # so a same-content seller-only copy would otherwise collide on `h` and overwrite the winner).
        decoy_bundle = make_fab(job, "completed", "none", "seller", ["seller"], finalised_at=FINALISED_AT + 1)
        decoy_h = bundle_hash(decoy_bundle)
        decoy_bind = make_binding(job, "seller", "seller", decoy_native, decoy_h)
        p["deriv"]["resolutionContext"][0]["bb6Context"]["candidateBindings"].append(decoy_bind)
        p["deref"][decoy_h] = decoy_bundle
        self.assertEqual(vrc(p), (True, []))

    # ============================================================ B1.4 schema-grid oracle
    def test_r11_schema_grid_oracle(self):
        """Exhaustive (path x mutation) refusal oracle over the §10.5.3 entry grammar (see the
        SCHEMA-GRID ORACLE header for scope + contract). One subTest per grid cell; each drives the
        REAL predicate (crypto mode) on a de-aliased base and asserts the contract: NO exception
        (a raise fails the subTest), ok is False, reasons non-empty. Deref'd-copy surfaces are OUT of
        scope (class-closed by the named regressions). Grammar-legal cells are in LEGAL_CELLS, not
        here."""
        # base sanity: every de-aliased base must itself be a clean accept before mutation.
        for base_key, base_fn in sorted(_GRID_BASES.items()):
            with self.subTest(base=base_key):
                p, _e = base_fn()
                self.assertEqual(vrc(p), (True, []), "grid base %s must accept unmutated" % base_key)
        for case_id, base_key, path_id, tag, kind, nav in grid_cells():
            with self.subTest(case=case_id):
                p, e = _GRID_BASES[base_key]()
                obj, key = nav(e)
                if kind == "missing-key":
                    obj.pop(key, None)
                else:
                    obj[key] = _mutated_value(kind, tag)
                ok, reasons = vrc(p)   # a raised exception here fails the subTest — the no-escape assertion
                self.assertFalse(ok, "%s: expected refusal, got ok=True reasons=%r" % (case_id, reasons))
                self.assertTrue(reasons, "%s: expected non-empty reasons, got %r" % (case_id, reasons))

    def test_r11_grid_covers_randoms_four(self):
        """Random's literal 'appear as grid hits AND remain named regressions': the four probe ids are
        present in the deterministically-executed grid cell-id set (the named regressions a/c1/b/d
        above are the exact-reason twins)."""
        executed = {c[0] for c in grid_cells()}
        for needed in RANDOMS_FOUR:
            self.assertIn(needed, executed, "Random's four must appear as grid hits: %s" % needed)

    # ============================================================ B1.5b mutation-pin closures
    def test_r11_binding_arm_nonobject_defect(self):
        """PIN (MA3): uniquely pins the GRAMMAR-GATE binding-arm object check in _role_evidence_grammar
        against its verify_binding backstop. A non-object roleEvidence/counterpartyRoleEvidence `binding`
        refuses at the GATE with '...binding must be an object'; verify_binding would ALSO refuse but with
        a DIFFERENT reason ('...binding is not an object'), so this EXACT-reason assertion goes red the
        moment the gate check is bypassed (the contract-only grid cell stays green under that mutation —
        it was the pin gap)."""
        with self.subTest(site="roleEvidence"):
            p = build_absent("R11-BA1")
            p["deriv"]["resolutionContext"][0]["roleEvidence"]["binding"] = "x"
            self.assertEqual(vrc(p), (False, ["%s: roleEvidence.binding must be an object (got str)" % p["h"]]))
        with self.subTest(site="counterpartyRoleEvidence"):
            p = build_present("R11-BA2")
            p["deriv"]["resolutionContext"][0]["counterpartyRoleEvidence"]["binding"] = "x"
            self.assertEqual(vrc(p), (False, ["%s: counterpartyRoleEvidence.binding must be an object (got str)" % p["h"]]))

    def test_r11_signature_member_scalar_defect(self):
        """PIN (MB9): uniquely pins verify_binding's INGRESS signature.signer / signature.value string
        typing against their backstops. A non-string signer/value refuses at the ingress with the EXACT
        'binding.signature.<f> must be a string' reason; WITHOUT the ingress check, signer=123 is
        backstopped by the BB-4 'signature.signer != binding.signer' mismatch and value=123 by
        sig6_canonical's isinstance guard — BOTH DIFFERENT reasons, so this exact-reason assertion is the
        killer (the grid's wrong-scalar cells stay green under that mutation). NOTE: the value ingress
        check is load-bearing for STRUCTURAL-mode callers (pubkeys=None) too — sig6_canonical is
        crypto-gated, so without the ingress a struct-mode value=123 would not be typed at all."""
        for member in ("signer", "value"):
            with self.subTest(member=member):
                p = build_absent("R11-SIGM-%s" % member)
                p["deriv"]["resolutionContext"][0]["roleEvidence"]["binding"]["signature"][member] = 123
                self.assertEqual(vrc(p), (False, [
                    "%s: roleEvidence BB-4: binding.signature.%s must be a string (got int)" % (p["h"], member)]))


if __name__ == "__main__":
    unittest.main()
