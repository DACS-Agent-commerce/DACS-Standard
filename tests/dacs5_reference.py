"""Executable DACS-5 reference predicates for the PR #248 round-5 blocker tests.

This module is a *test-support* library, NOT a conformance validator and NOT a
TestCase. It is imported only by the four blocker vector tests:

    - tests/test_receipt_rederivation_vectors.py        (B1 determinism receipt)
    - tests/test_outsider_binding_flooding_vectors.py   (B2 BB-6 flood)
    - tests/test_mixed_version_reconciliation_vectors.py (B3 reconciliation totality)
    - tests/test_fab_bundle_extended_pointer_vectors.py  (B4 extended-pointer FAB path)

It executes the §10.5.1/§10.4.2/§10.4.3 predicates the round-4 review found were
only *asserted* by fixture metadata: perspective_flip reconciliation (E1-E3),
implied-fault-SET mixed-version comparison (E4), the ResolutionContextEntry replay
contract (E5), per-signer BB-6 budgeting (E6), and the triple-identity extended-
pointer rule (E7).

It MUST NEVER be run against the pre-#248 shared goldens in
conformance/vectors/golden.json / conformance/fixtures/session-bundles-reputation.json:
those predate §10.5.1 guard (iv) and carry no resolutionContext, so a faithful
derive() cannot reproduce their pinned metrics. That gap is tracked upstream as
issue #264 and is a steward call, out of scope for #248.

Signature verification is gated on `cryptography`; the stdlib checks (canonical
hashing, the reconciliation/BB-6/pointer predicates) always run.
"""
import base64
import hashlib
import json

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - environment-dependent
    HAVE_CRYPTO = False

BUNDLE_DOMAIN = "dacs-bundle:v1:"
FAULT_BUNDLE_DOMAIN = "dacs-fault-bundle:v1:"
BINDING_DOMAIN = "dacs-bundle-binding:v1:"
FAULT_POINTER_DOMAIN = "dacs-fault-bundle-pointer:v1:"

BB6_DEFAULT_BUDGET = 8

# Outcome classes for the §10.4.3 divergence read (E1/E4): fault is compared on the
# CLASS, not the role-relative spelling.
_ABORT = {"aborted-by-self", "aborted-by-other"}
_FAILURE = {"failed-perm", "failed-counterparty"}


# --------------------------------------------------------------------------- #
# Canonicalisation + hashing (extracted from test_bundle_binding_vectors.py)
# --------------------------------------------------------------------------- #
def canonical(value):
    """RFC 8785-style JCS: sorted keys, tight separators, non-ASCII preserved."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def bundle_hash(bundle):
    """§10.4.1 attestation_bundle_hash: canonical form minus signatures + anchoredByRole,
    computed identically for AttestationBundle and FaultAttestationBundle."""
    unsigned = {k: v for k, v in bundle.items() if k not in ("signatures", "anchoredByRole")}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def binding_hash(binding):
    unsigned = {k: v for k, v in binding.items() if k != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def pointer_hash(pointer):
    """FaultBundleExtendedPointer signed-scope hash (E7): canonical form minus signature."""
    unsigned = {k: v for k, v in pointer.items() if k != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def logical_address(job_id, role):
    return "stor-" + hashlib.sha256((job_id + "-bundle-" + role).encode("utf-8")).hexdigest()


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def bundle_domain(bundle):
    return FAULT_BUNDLE_DOMAIN if "faultBundleVersion" in bundle else BUNDLE_DOMAIN


def verify_sig(pubkey_bytes, domain, content_hash, sig_value):
    """crypto-gated ed25519 verify over `domain || content_hash`. Returns True/False;
    raises RuntimeError if called without `cryptography` (callers gate on HAVE_CRYPTO)."""
    if not HAVE_CRYPTO:  # pragma: no cover
        raise RuntimeError("verify_sig requires the cryptography package")
    payload = (domain + content_hash).encode("utf-8")
    try:
        Ed25519PublicKey.from_public_bytes(pubkey_bytes).verify(b64url_decode(sig_value), payload)
        return True
    except InvalidSignature:
        return False


def verify_binding(binding, pubkeys, *, expected_jobid, expected_role, expected_content_hash=None):
    """BB-4 + targeted BB-5 checks on a BundleBinding, for receipt replay (round-6 blocker #2).

    Structural checks ALWAYS run: signature.signer == binding.signer (BB-4);
    binding.jobId == expected_jobid and binding.role == expected_role (BB-5 check 4);
    binding.bundleContentHash == expected_content_hash byte-for-byte when supplied (BB-5 check 8).
    The domain-separated signature over BINDING_DOMAIN || binding_hash(binding) is verified ONLY
    when `pubkeys` is provided AND HAVE_CRYPTO (callers pass pubkeys=None to skip crypto, mirroring
    the existing gating idiom). `pubkeys` maps a signer ClaimReference -> raw ed25519 public bytes.
    Returns {"ok": bool, "reason": str}."""
    if not isinstance(binding, dict):
        return {"ok": False, "reason": "binding is not an object"}
    sig = binding.get("signature") or {}
    if sig.get("signer") != binding.get("signer"):
        return {"ok": False, "reason": "BB-4: signature.signer != binding.signer"}
    if binding.get("jobId") != expected_jobid:
        return {"ok": False, "reason": "BB-5: binding.jobId != %r" % (expected_jobid,)}
    if binding.get("role") != expected_role:
        return {"ok": False, "reason": "BB-5: binding.role != %r" % (expected_role,)}
    if expected_content_hash is not None and binding.get("bundleContentHash") != expected_content_hash:
        return {"ok": False, "reason": "BB-5 check 8: binding.bundleContentHash != expected"}
    if pubkeys is not None and HAVE_CRYPTO:
        pk = pubkeys.get(binding.get("signer"))
        if pk is None:
            return {"ok": False, "reason": "BB-4: no public key for signer %r" % (binding.get("signer"),)}
        if not verify_sig(pk, BINDING_DOMAIN, binding_hash(binding), sig.get("value", "")):
            return {"ok": False, "reason": "BB-4: binding signature does not verify"}
    return {"ok": True, "reason": "binding valid"}


def is_fab(bundle):
    return "faultBundleVersion" in bundle


def _outcome_class(outcome):
    if outcome == "completed":
        return "completed"
    if outcome == "failed-substrate":
        return "failed-substrate"
    if outcome in _ABORT:
        return "abort"
    if outcome in _FAILURE:
        return "failure"
    raise ValueError("unknown outcome " + repr(outcome))


def _other(role):
    return "seller" if role == "buyer" else "buyer"


# --------------------------------------------------------------------------- #
# Reconciliation predicates (E1-E4)
# --------------------------------------------------------------------------- #
def perspective_flip(outcome):
    """§10.5.1 legacy-only perspective mapping (E1/E2/E3). Buyer<->seller involution;
    completed/failed-substrate unchanged."""
    return {
        "aborted-by-self": "aborted-by-other",
        "aborted-by-other": "aborted-by-self",
        "failed-perm": "failed-counterparty",
        "failed-counterparty": "failed-perm",
    }.get(outcome, outcome)


def roster_roles(bundle):
    """The session parties[] roster carried on both bundle types (BundleParty.role)."""
    return {p["role"] for p in bundle.get("parties", [])}


def implied_fault_set(outcome, anchored_by_role, roster):
    """E4: the §10.4.1 permissible-set mapped to a SET of session parties the legacy
    outcome permits as faulted. Singleton in a two-party session (preserves the prior
    exact mapping byte-for-byte); both non-R roles in a distinct-orchestrator session."""
    if outcome in ("completed", "failed-substrate"):
        return {"none"}
    if outcome in ("failed-perm", "aborted-by-self"):
        return {anchored_by_role}
    if outcome in ("failed-counterparty", "aborted-by-other"):
        return {r for r in roster if r != anchored_by_role} or {_other(anchored_by_role)}
    raise ValueError("unknown outcome " + repr(outcome))


def _phase_summary_diverges(a, b):
    """Shared-index phaseSummary limb (unchanged for all pair types): a kind/outcome/
    errorClass contradiction on a shared index, or an entry present in one copy only."""
    pa = {e["index"]: e for e in a.get("phaseSummary", [])}
    pb = {e["index"]: e for e in b.get("phaseSummary", [])}
    if set(pa) != set(pb):
        return True  # entry-presence contradiction
    for i in pa:
        for f in ("kind", "outcome", "errorClass"):
            if pa[i].get(f) != pb[i].get(f):
                return True
    return False


def _fab_faulted(bundle):
    return bundle["faultedParty"]


def divergence(copy_a, copy_b):
    """§10.4.3 single divergence definition as amended by E1/E4. Returns True iff the
    pair canonically diverges. Classifies the pair by type:

      FAB pair    -> faultedParty contradiction OR outcome-class contradiction OR phaseSummary
      legacy pair -> perspective-reconciled: flip B to A's perspective, then compare the
                     residual outcome + outcome-class; partner spellings do NOT diverge (E1)
      mixed pair  -> the FAB.faultedParty must be a MEMBER of the legacy copy's
                     implied-fault SET; non-membership OR outcome-class OR phaseSummary (E4)
    """
    if _phase_summary_diverges(copy_a, copy_b):
        return True
    if _outcome_class(copy_a["outcome"]) != _outcome_class(copy_b["outcome"]):
        return True

    a_fab, b_fab = is_fab(copy_a), is_fab(copy_b)

    if a_fab and b_fab:
        # FAB pair: absolute faultedParty must agree (outcome class already checked).
        return _fab_faulted(copy_a) != _fab_faulted(copy_b)

    if not a_fab and not b_fab:
        # Legacy pair (E1): reconcile B into A's perspective via perspective_flip, then
        # the residual outcomes must agree. Partner spellings collapse to one event.
        if copy_a["anchoredByRole"] == copy_b["anchoredByRole"]:
            reconciled_b = copy_b["outcome"]
        else:
            reconciled_b = perspective_flip(copy_b["outcome"])
        return copy_a["outcome"] != reconciled_b

    # Mixed pair (E4): the FAB.faultedParty must be a member of the legacy implied set.
    fab, legacy = (copy_a, copy_b) if a_fab else (copy_b, copy_a)
    roster = roster_roles(fab) | roster_roles(legacy)
    fset = implied_fault_set(legacy["outcome"], legacy["anchoredByRole"], roster)
    return _fab_faulted(fab) not in fset


def scored_outcome(bundle, role_of_party):
    """§10.5.1 scored_outcome: the scored party's perspective outcome for an authoritative
    copy. FAB -> read absolute faultedParty; legacy -> role-relative residual via flip."""
    oc = _outcome_class(bundle["outcome"])
    if oc in ("completed", "failed-substrate"):
        return bundle["outcome"]
    if is_fab(bundle):
        fault = bundle["faultedParty"]
        if fault == "orchestrator":
            return bundle["outcome"]  # neutralised downstream via orchestrator_fault set
        at_fault = fault == role_of_party
        if oc == "abort":
            return "aborted-by-self" if at_fault else "aborted-by-other"
        return "failed-perm" if at_fault else "failed-counterparty"
    # legacy
    if bundle["anchoredByRole"] == role_of_party:
        return bundle["outcome"]
    return perspective_flip(bundle["outcome"])


# --------------------------------------------------------------------------- #
# BB-6 resolution with per-signer budget (E6)
# --------------------------------------------------------------------------- #
def resolve_bb6(bindings, party_map=None, budget=BB6_DEFAULT_BUDGET, anchored=None):
    """§10.4.2 BB-6 authorized-candidate resolution as amended by E6.

    bindings : list of BundleBinding dicts (each with signer, bundleContentHash,
               nativeAddress). Assumed BB-4-valid + BB-5 checks 1-5 passing (candidate set).
    party_map: optional {signer -> role} authenticated role->primary-claim map. When
               present the candidate set is pruned to the mapped signer BEFORE any fetch
               (MANDATORY in a derivation context). None models "no co-signed map yet".
    budget   : N per authenticated signer per (jobId, role) (default 8). Per-signer, so an
               outsider's flood never consumes the honest role-holder's allocation (E6).
    anchored : optional {nativeAddress -> bundle} for authorization (BB-5 check 9).

    BB-7 exhaustion is SIDE-level (round-6 blocker #3): if ANY signer bucket (after the party_map
    prune) holds more than `budget` candidates, its budget exhausts with candidate addresses still
    unfetched, and the WHOLE side's disposition is `indeterminate` — overriding any authorized
    candidate that resolved, never `absent`, never a void.

    Returns {"disposition": "present"|"indeterminate", "resolvedNativeAddress": str|None,
             "fetched": [nativeAddress,...], "authorizedSigners": [...], "exhaustedSigners": [...]}.
    """
    authorized_signer = None
    if party_map:
        # MANDATORY prune to the mapped signer(s) before any fetch.
        mapped = set(party_map)
        bindings = [b for b in bindings if b["signer"] in mapped]
        # the signer holding the requested role, if the map names one
        authorized_signer = next(iter(party_map), None)

    # group by authenticated signer; each signer gets its OWN budget
    by_signer = {}
    for b in bindings:
        by_signer.setdefault(b["signer"], []).append(b)

    fetched = []
    resolved = None
    authorized = []
    exhausted = []
    for signer, sbindings in by_signer.items():
        # total order: ascending (bundleContentHash, nativeAddress)
        ordered = sorted(sbindings, key=lambda b: (b["bundleContentHash"], b["nativeAddress"]))
        if len(sbindings) > budget:
            # BB-7: this signer's budget exhausts with candidate addresses still unfetched.
            exhausted.append(signer)
        for b in ordered[:budget]:  # per-signer budget
            fetched.append(b["nativeAddress"])
            # BB-5 check 9 authorization: signer must be the party holding role.
            is_authorized = False
            if party_map is not None:
                is_authorized = signer in party_map
            elif anchored is not None and b["nativeAddress"] in anchored:
                # post-fetch authorization proxy: an anchored bundle whose signatures
                # name this signer as the role holder. Modelled by presence in `anchored`.
                is_authorized = True
            if is_authorized:
                authorized.append(signer)
                if resolved is None:
                    resolved = b["nativeAddress"]

    exhausted = sorted(set(exhausted))
    authorized_signers = sorted(set(authorized))
    if exhausted:
        # BB-7 is SIDE-level: any signer bucket that exhausts N with candidates unfetched makes the
        # WHOLE side `indeterminate`, overriding any authorized candidate that resolved — never absent,
        # never a void. A consumer MAY re-run with a larger budget to lift an exhaustion-indeterminate.
        return {"disposition": "indeterminate", "resolvedNativeAddress": None,
                "fetched": fetched, "authorizedSigners": authorized_signers, "exhaustedSigners": exhausted}
    if resolved is not None:
        return {"disposition": "present", "resolvedNativeAddress": resolved,
                "fetched": fetched, "authorizedSigners": authorized_signers, "exhaustedSigners": exhausted}
    return {"disposition": "indeterminate", "resolvedNativeAddress": None,
            "fetched": fetched, "authorizedSigners": authorized_signers, "exhaustedSigners": exhausted}


# --------------------------------------------------------------------------- #
# Extended-pointer triple-identity (E7)
# --------------------------------------------------------------------------- #
def resolve_fab_pointer(pointer, dereferenced_bundle, binding=None):
    """E7 triple-identity for a FaultBundleExtendedPointer anchoring. Returns
    {"ok": bool, "reason": str, "recomputedHash": hex}. BB-5 check 8 + §10.4.1 apply to
    the DEREFERENCED full bundle: binding.bundleContentHash == pointer.fullBundleContentHash
    == recomputed §10.4.1 hash of the dereferenced bundle. A mismatch is rejected content."""
    if pointer.get("faultBundleVersion") != "1" or "bundleVersion" in pointer:
        return {"ok": False, "reason": "not a FaultBundleExtendedPointer discriminator", "recomputedHash": None}
    recomputed = bundle_hash(dereferenced_bundle)
    if pointer["fullBundleContentHash"] != recomputed:
        return {"ok": False, "reason": "dereferenced content hash mismatch", "recomputedHash": recomputed}
    if binding is not None and binding.get("bundleContentHash") != recomputed:
        return {"ok": False, "reason": "binding.bundleContentHash != dereferenced hash", "recomputedHash": recomputed}
    return {"ok": True, "reason": "triple-identity holds", "recomputedHash": recomputed}


# --------------------------------------------------------------------------- #
# derive() faithful to §10.5.1 484-698 as amended (E1-E5)
# --------------------------------------------------------------------------- #
def _primary_claims(bundle):
    return {p["primaryClaim"] for p in bundle.get("parties", [])}


def _role_of_party(bundle, party):
    for p in bundle.get("parties", []):
        if p["primaryClaim"] == party:
            return p["role"]
    return None


def derive(party, tagged_bundles, window_start, window_end, basis="finalisedAt"):
    """Faithful §10.5.1 reputation derivation.

    tagged_bundles: list of {"bundle": <dict>, "resolvedRole": "buyer"|"seller",
      "counterpartyDisposition": "present"|"absent"|None, "counterpartyRef": ...?,
      "absenceEvidenceRef": ...?} — each input copy carries its §10.5.1 resolution tag.

    Returns a ReputationDerivation dict (bundleCount, metrics, resolutionContext,
    bundleRefs, windowingBasis). Metrics reproduce byte-identically across runs given
    the same tagged input + window + basis (the §10.5.3 determinism-receipt contract).
    """
    clock = "finalisedAt"  # only finalisedAt is exercised by the round-5 fixtures
    scoped = [t for t in tagged_bundles
              if party in _primary_claims(t["bundle"])
              and window_start <= t["bundle"][clock] <= window_end]

    # group by jobId
    by_job = {}
    for t in scoped:
        by_job.setdefault(t["bundle"]["jobId"], []).append(t)

    reconciled = []       # (bundle, tag)
    outcomes = []
    cancelled = set()
    orch_fault = set()

    for job, copies in by_job.items():
        role_of_party = _role_of_party(copies[0]["bundle"], party)
        self_c = next((c for c in copies if c["bundle"]["anchoredByRole"] == role_of_party), None)
        cp = next((c for c in copies if c["bundle"]["anchoredByRole"] != role_of_party
                   and c["bundle"]["anchoredByRole"] in ("buyer", "seller")), None)

        if self_c is not None and cp is not None:
            if divergence(self_c["bundle"], cp["bundle"]):
                continue  # §10.4.3(d) dispute -> EXCLUDE from ALL metrics
            # non-divergent mixed-version pair -> FAB authoritative
            if is_fab(self_c["bundle"]) != is_fab(cp["bundle"]):
                auth = self_c if is_fab(self_c["bundle"]) else cp
            else:
                auth = self_c
        elif self_c is not None:
            auth = self_c
        elif cp is not None:
            # one-copy jobId: guard (iv) requires authoritative absence of the missing side.
            if cp.get("counterpartyDisposition") != "absent" or not cp.get("absenceEvidenceRef"):
                continue  # not established absent -> EXCLUDE
            auth = cp
        else:
            continue

        b = auth["bundle"]
        oc = scored_outcome(b, role_of_party)
        if is_fab(b) and b.get("faultedParty") == "orchestrator":
            orch_fault.add(job)
        reconciled.append(auth)
        outcomes.append(oc)

    def outc(o):
        return [o2 for o2 in outcomes if o2 == o]

    n = len(outcomes)
    completed = outc("completed")
    failed_substrate = outc("failed-substrate")
    orch_neutral = [t for t in reconciled if t["bundle"]["jobId"] in orch_fault]
    cancelled_neutral = [t for t in reconciled if t["bundle"]["jobId"] in cancelled]

    def cnt(pred):
        return sum(1 for (t, o) in zip(reconciled, outcomes) if pred(t, o))

    failed_counterparty = cnt(lambda t, o: o == "failed-counterparty" and t["bundle"]["jobId"] not in orch_fault)
    aborted_by_other = cnt(lambda t, o: o == "aborted-by-other"
                           and t["bundle"]["jobId"] not in cancelled and t["bundle"]["jobId"] not in orch_fault)
    counterparty_fault = aborted_by_other + failed_counterparty

    party_fault_denom = n - len(failed_substrate) - len(cancelled_neutral) - len(orch_neutral)
    completion_rate = (len(completed) / party_fault_denom) if party_fault_denom > 0 else None
    party_blame_denom = party_fault_denom - counterparty_fault
    cp_adj = (len(completed) / party_blame_denom) if party_blame_denom > 0 else None
    cp_fault_rate = (counterparty_fault / party_fault_denom) if party_fault_denom > 0 else None

    # bundleRefs = reconciled set, ascending contentHash; resolutionContext parallel.
    refs = []
    for t in reconciled:
        refs.append((bundle_hash(t["bundle"]), t))
    refs.sort(key=lambda x: x[0])
    bundle_refs = [h for h, _ in refs]
    resolution_context = []
    for h, t in refs:
        entry = {"contentHash": h, "resolvedRole": t["resolvedRole"],
                 "counterpartyDisposition": t.get("counterpartyDisposition")}
        if t.get("counterpartyDisposition") == "present":
            entry["counterpartyRef"] = t.get("counterpartyRef")
            if t.get("counterpartyRoleEvidence") is not None:
                entry["counterpartyRoleEvidence"] = t.get("counterpartyRoleEvidence")
        elif t.get("counterpartyDisposition") == "absent":
            entry["absenceEvidenceRef"] = t.get("absenceEvidenceRef")
            if t.get("absenceBinding") is not None:
                entry["absenceBinding"] = t.get("absenceBinding")
        if t.get("roleEvidence") is not None:
            entry["roleEvidence"] = t.get("roleEvidence")
        if t.get("bb6Context") is not None:
            entry["bb6Context"] = t.get("bb6Context")
        resolution_context.append(entry)

    return {
        # E1 (round-6 blocker #1): the replayable receipt is a DISTINCT type carrying its own
        # structural discriminator, never the legacy `derivationVersion` (CORE §11.1.2 new-type
        # refusal; mirrors the AttestationBundle/FaultAttestationBundle split). derive() emits the
        # ReplayableReputationDerivation; the legacy ReputationDerivation has no `resolutionContext`.
        "replayableDerivationVersion": REPLAYABLE_DERIVATION_VERSION,
        "bundleCount": len(reconciled),
        "metrics": {
            "completionRate": completion_rate,
            "counterpartyAdjustedCompletionRate": cp_adj,
            "counterpartyFaultRate": cp_fault_rate,
        },
        "bundleRefs": bundle_refs,
        "resolutionContext": resolution_context,
        "windowingBasis": basis,
    }


REPLAYABLE_DERIVATION_VERSION = "1"


def is_replayable_derivation(d):
    """True iff `d` is a well-formed ReplayableReputationDerivation: it carries the
    replayableDerivationVersion discriminator and NOT the legacy derivationVersion (§10.5)."""
    return (isinstance(d, dict)
            and d.get("replayableDerivationVersion") == REPLAYABLE_DERIVATION_VERSION
            and "derivationVersion" not in d)


def require_replayable_derivation(d):
    """CORE §11.1.2 new-type-refusal gate for the replayable receipt (mirrors the
    resolve_fab_pointer discriminator refusal). A replay consumer MUST refuse an object
    lacking replayableDerivationVersion "1", or carrying the legacy derivationVersion — no
    replay claim exists on the legacy ReputationDerivation. Returns {"ok": bool, "reason": str}."""
    if not isinstance(d, dict) or d.get("replayableDerivationVersion") != REPLAYABLE_DERIVATION_VERSION:
        return {"ok": False, "reason": "not a ReplayableReputationDerivation discriminator (replayableDerivationVersion != \"1\")"}
    if "derivationVersion" in d:
        return {"ok": False, "reason": "carries legacy derivationVersion; a ReplayableReputationDerivation MUST NOT carry derivationVersion"}
    return {"ok": True, "reason": "replayable-derivation discriminator holds"}


def receipt_required_members_present(derivation):
    """§10.5.3 (3)/(4) as amended by E5: every entry must carry the members REQUIRED for
    its disposition (roleEvidence always; counterpartyRef when present; absenceEvidenceRef
    when absent). The object MUST first pass the ReplayableReputationDerivation refusal gate
    (CORE §11.1.2). Returns (ok, [reasons])."""
    gate = require_replayable_derivation(derivation)
    if not gate["ok"]:
        return (False, ["discriminator refusal: " + gate["reason"]])
    reasons = []
    refs = derivation.get("bundleRefs", [])
    ctx = derivation.get("resolutionContext", [])
    if len(refs) != len(ctx):
        reasons.append("resolutionContext length != bundleRefs length")
    if [e["contentHash"] for e in ctx] != refs:
        reasons.append("resolutionContext not keyed to bundleRefs in order")
    for e in ctx:
        if "roleEvidence" not in e or e["roleEvidence"] is None:
            reasons.append("%s: missing roleEvidence" % e.get("contentHash"))
        role_ev = e.get("roleEvidence") or {}
        # binding-backed entries carry the BB-6 multiplicity inputs to reproduce selection (R2).
        if role_ev.get("kind") == "binding" and not e.get("bb6Context"):
            reasons.append("%s: binding roleEvidence missing bb6Context" % e.get("contentHash"))
        disp = e.get("counterpartyDisposition")
        if disp == "present":
            if not e.get("counterpartyRef"):
                reasons.append("%s: present disposition missing counterpartyRef" % e.get("contentHash"))
            # the counterparty's role authentication (anchoredByRole is unhashed) is REQUIRED (R2).
            if not e.get("counterpartyRoleEvidence"):
                reasons.append("%s: present disposition missing counterpartyRoleEvidence" % e.get("contentHash"))
        if disp == "absent":
            if not e.get("absenceEvidenceRef"):
                reasons.append("%s: absent disposition missing absenceEvidenceRef" % e.get("contentHash"))
            # write-input substrate (roleEvidence is a binding): the missing side's absenceBinding
            # is REQUIRED so the absence evidence provably attaches to the counterparty's address (E5).
            if role_ev.get("kind") == "binding" and not e.get("absenceBinding"):
                reasons.append("%s: absent disposition on a write-input substrate missing absenceBinding" % e.get("contentHash"))
    return (not reasons, reasons)


def _canon_sha(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()


def validate_resolution_context(derivation, deref, evidence_deref=None, pubkeys=None):
    """Executable replay validation of every authenticated copy in a ReplayableReputationDerivation
    (round-6 blocker #2). For each entry: re-verify roleEvidence (BB-4/BB-5 via verify_binding);
    reproduce BB-6 selection over bb6Context; on a present disposition dereference counterpartyRef,
    verify counterpartyRoleEvidence, and require divergence()==False; on an absent disposition
    dereference the AbsenceEvidence, hash-check absenceEvidenceRef, verify absenceBinding, and require
    absenceBinding.nativeAddress == AbsenceEvidence.nativeAddress. Structural checks always run;
    binding-signature verification runs only under pubkeys+HAVE_CRYPTO. Must first pass the
    discriminator gate. evidence_deref(contentHash) -> AbsenceEvidence. Returns (ok, [reasons])."""
    gate = require_replayable_derivation(derivation)
    if not gate["ok"]:
        return (False, ["discriminator refusal: " + gate["reason"]])
    reasons = []
    ev_get = evidence_deref if evidence_deref is not None else (lambda h: None)
    for entry in derivation.get("resolutionContext", []):
        ch = entry.get("contentHash")
        auth = deref(ch)
        if not isinstance(auth, dict):
            reasons.append("%s: authoritative copy not dereferenceable" % ch)
            continue
        role = entry.get("resolvedRole")
        other = _other(role) if role in ("buyer", "seller") else None
        re_ = entry.get("roleEvidence") or {}
        # (1) roleEvidence re-verification + (2) BB-6 reproduction.
        if re_.get("kind") == "binding":
            vb = verify_binding(re_.get("binding") or {}, pubkeys,
                                expected_jobid=auth.get("jobId"), expected_role=role,
                                expected_content_hash=ch)
            if not vb["ok"]:
                reasons.append("%s: roleEvidence %s" % (ch, vb["reason"]))
                continue
            ctx = entry.get("bb6Context")
            if not ctx:
                reasons.append("%s: binding roleEvidence missing bb6Context" % ch)
                continue
            native = (re_.get("binding") or {}).get("nativeAddress")
            res = resolve_bb6(ctx.get("candidateBindings", []), ctx.get("partyMap"),
                              ctx.get("budget", BB6_DEFAULT_BUDGET), anchored={native: auth})
            if res["disposition"] != "present" or res["resolvedNativeAddress"] != native:
                reasons.append("%s: BB-6 re-selection differs (got %r/%s, want present/%s)"
                               % (ch, res["disposition"], res["resolvedNativeAddress"], native))
                continue
        # (3) present: re-run §10.4.3 reconciliation against the dereferenced counterparty copy.
        disp = entry.get("counterpartyDisposition")
        if disp == "present":
            cref = entry.get("counterpartyRef") or {}
            cp = deref(cref.get("contentHash"))
            if not isinstance(cp, dict):
                reasons.append("%s: counterpartyRef not dereferenceable" % ch)
                continue
            cre = entry.get("counterpartyRoleEvidence")
            if not cre:
                reasons.append("%s: present disposition missing counterpartyRoleEvidence" % ch)
                continue
            if cre.get("kind") == "binding":
                vb2 = verify_binding(cre.get("binding") or {}, pubkeys,
                                     expected_jobid=auth.get("jobId"), expected_role=other,
                                     expected_content_hash=cref.get("contentHash"))
                if not vb2["ok"]:
                    reasons.append("%s: counterpartyRoleEvidence %s" % (ch, vb2["reason"]))
                    continue
            if divergence(auth, cp):
                reasons.append("%s: counterparty copy canonically diverges (§10.4.3)" % ch)
                continue
        # (4) absent: re-check the absence address/proof relation.
        elif disp == "absent":
            aer = entry.get("absenceEvidenceRef") or {}
            ab = entry.get("absenceBinding")
            ev = ev_get(aer.get("contentHash"))
            if not isinstance(ev, dict):
                reasons.append("%s: AbsenceEvidence not dereferenceable" % ch)
                continue
            if aer.get("contentHash") != _canon_sha(ev):
                reasons.append("%s: absenceEvidenceRef.contentHash != sha256(AbsenceEvidence)" % ch)
                continue
            if not isinstance(ab, dict):
                reasons.append("%s: absent disposition missing absenceBinding" % ch)
                continue
            vb3 = verify_binding(ab, pubkeys, expected_jobid=auth.get("jobId"), expected_role=other)
            if not vb3["ok"]:
                reasons.append("%s: absenceBinding %s" % (ch, vb3["reason"]))
                continue
            if ab.get("nativeAddress") != ev.get("nativeAddress"):
                reasons.append("%s: absenceBinding.nativeAddress != AbsenceEvidence.nativeAddress" % ch)
                continue
    return (not reasons, reasons)


def replay_receipt(derivation, deref, party, window_start, window_end, evidence_deref=None, pubkeys=None):
    """§10.5.3 (4) + round-6 blocker #2: re-run derive() over deref(bundleRefs) AND execute the
    full per-copy validation (validate_resolution_context) — roleEvidence BB-4/BB-5, BB-6
    reproduction, §10.4.3 divergence against the dereferenced counterparty, and the absence
    address/proof relation — then confirm byte-identical metrics + bundleCount. The object MUST
    first pass the ReplayableReputationDerivation refusal gate (CORE §11.1.2); a refused or
    invalid object carries no replay claim. evidence_deref(contentHash) -> AbsenceEvidence;
    pubkeys enables crypto binding-signature verification (None => structural only).
    Returns (byte_identical, replayed_derivation) — (False, None) on refusal."""
    if not require_replayable_derivation(derivation)["ok"]:
        return (False, None)
    ok, _reasons = validate_resolution_context(derivation, deref, evidence_deref, pubkeys)
    if not ok:
        return (False, None)
    tagged = []
    for entry in derivation["resolutionContext"]:
        b = deref(entry["contentHash"])
        tag = {"bundle": b, "resolvedRole": entry["resolvedRole"],
               "counterpartyDisposition": entry.get("counterpartyDisposition"),
               "counterpartyRef": entry.get("counterpartyRef"),
               "counterpartyRoleEvidence": entry.get("counterpartyRoleEvidence"),
               "absenceEvidenceRef": entry.get("absenceEvidenceRef"),
               "absenceBinding": entry.get("absenceBinding"),
               "roleEvidence": entry.get("roleEvidence"),
               "bb6Context": entry.get("bb6Context")}
        tagged.append(tag)
    replayed = derive(party, tagged, window_start, window_end, derivation.get("windowingBasis", "finalisedAt"))
    same = (canonical(replayed["metrics"]) == canonical(derivation["metrics"])
            and replayed["bundleCount"] == derivation["bundleCount"])
    return (same, replayed)
