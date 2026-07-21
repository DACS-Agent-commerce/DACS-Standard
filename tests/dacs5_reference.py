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

# BB-5 check 3: the BundleBinding versions this consumer supports. §B.7 / §10.4.2 defines the
# `bindingVersion: "1"` literal (spec line 352); every conformance binding carries the string "1".
SUPPORTED_BINDING_VERSIONS = frozenset({"1"})

# Outcome classes for the §10.4.3 divergence read (E1/E4): fault is compared on the
# CLASS, not the role-relative spelling.
_ABORT = {"aborted-by-self", "aborted-by-other"}
_FAILURE = {"failed-perm", "failed-counterparty"}

# CORE §B.7 "Algorithm" (spec line 369) registers Ed25519, ECDSA-secp256k1, and sr1-aggregate as the
# signing algorithms; the `algorithm` identifier the DACS-5 builders + conformance vectors write for a
# BundleSignature / binding signature is the lowercase string "ed25519". This reference verifier only
# implements ed25519 (verify_sig uses Ed25519PublicKey), so that is the supported set: an entry whose
# algorithm is unsupported-by-this-verifier or absent has a payload this verifier cannot reproduce and
# MUST be rejected (SIG-3). Dispatch is on this label, never assumed.
SUPPORTED_SIGNATURE_ALGORITHMS = frozenset({"ed25519"})

# §10.5.3 windowingBasis (spec DACS-5-VERIFY.md :530): a REQUIRED closed two-literal union naming
# which clock the §10.5.1 window was applied against; re-derivation MUST use the recorded basis
# (:854/:581). SUPPORTED_* is the VOCABULARY (both literals are valid); IMPLEMENTED_* is what this
# reference can actually compute a window against. The SR-2-anchor-timestamp clock is a §10.5.1
# SHOULD (spec :832/:1010), NOT implemented here — so it is a valid literal (passes the vocab gate)
# but FAILS CLOSED at compute time (derive() refuses it; replay refuses an sr2-declared receipt),
# rather than silently windowing on finalisedAt and mislabelling the receipt.
SUPPORTED_WINDOWING_BASES = frozenset({"finalisedAt", "sr2-anchor-timestamp"})
IMPLEMENTED_WINDOWING_BASES = frozenset({"finalisedAt"})

# CORE §B.7 SIG-6 canonical unpadded Base64URL alphabet (spec lines 320-321): the canonical value is
# non-empty and contains ONLY these characters — no `=` padding, no whitespace, no standard-Base64 `+`/`/`.
_SIG6_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def sig6_canonical(value):
    """CORE §B.7 SIG-6 strict canonical-signature-value check (spec lines 311-329). Returns (ok, reason).

    A verifier MUST reject padding, whitespace, the standard-Base64 `+`/`/` characters, impossible
    lengths, invalid residual bits, and every other non-canonical spelling BEFORE cryptographic
    verification (SIG-6). The check is: (1) non-empty str over the unpadded URL-safe alphabet only, then
    (2) decode the value and compare it with an unpadded Base64URL re-encoding of the decoded bytes,
    exactly (this rejects non-minimal trailing residual bits that survive the alphabet filter).

    This does NOT perform algorithm-specific length/format validation — that stays separate (spec
    lines 331-332), enforced by verify_sig / SUPPORTED_SIGNATURE_ALGORITHMS."""
    if not isinstance(value, str) or value == "":
        return (False, "SIG-6: signature value is empty or not a string")
    if any(c not in _SIG6_ALPHABET for c in value):
        return (False, "SIG-6: signature value is non-canonical (padding, whitespace, or non-URL-safe alphabet)")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError):
        return (False, "SIG-6: signature value is not decodable unpadded Base64URL")
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        return (False, "SIG-6: signature value is a non-canonical Base64URL spelling (re-encode mismatch)")
    return (True, "ok")


def _required_bundle_signers(bundle):
    """§10.4.1 required-signer set for BOTH bundle types — AttestationBundle and
    FaultAttestationBundle (DACS-5 §10.4.1 lines 318-323): 'Required signers: buyer + seller. If the
    orchestrator is a distinct party (not buyer or seller), the orchestrator signature is also
    REQUIRED.' The rule is NOT type-specific — the `outcome` enum is common to both types and spec
    :475/:798 state the single-signed non-abort rejection without distinguishing bundle types.
    Returns the list of required roles in a stable order; orchestrator is included only when a
    parties[] role 'orchestrator' is present AND its primaryClaim is distinct from both buyer's and
    seller's (the spec's distinctness qualifier)."""
    roster = {p.get("role"): p.get("primaryClaim") for p in bundle.get("parties", [])}
    required = ["buyer", "seller"]
    orch = roster.get("orchestrator")
    if orch is not None and orch != roster.get("buyer") and orch != roster.get("seller"):
        required.append("orchestrator")
    return required


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

    Structural checks ALWAYS run (both modes, pre-crypto): (round-11) the §B.7/§10.4.2 BundleBinding
    REQUIRED members (spec lines 351-361) — bindingVersion / jobId / role / signer / nativeAddress /
    bundleContentHash — MUST each be a string, and signature MUST be an object (when present) whose
    signer / algorithm / value are each a REQUIRED present string whenever signature is present (an
    explicit-null or absent member refuses; an absent signature skips this member gate and refuses at
    the signature.signer == binding.signer equality below), BEFORE any member is used by string concat
    (logical_address), set-membership (SUPPORTED_* frozensets), or dict-key (pubkeys.get) — so a
    malformed binding refuses deterministically instead of raising. Then: signature.signer ==
    binding.signer (BB-4); binding.jobId == expected_jobid and binding.role == expected_role (BB-5
    check 4); binding.bundleContentHash == expected_content_hash byte-for-byte when supplied (BB-5
    check 8). The domain-separated signature over BINDING_DOMAIN || binding_hash(binding) is verified
    ONLY when `pubkeys` is provided AND HAVE_CRYPTO (callers pass pubkeys=None to skip crypto, mirroring
    the existing gating idiom); under that crypto gate the binding signature also passes F3
    algorithm-label dispatch (SUPPORTED_SIGNATURE_ALGORITHMS) and F4 SIG-6 canonical-value checking
    (sig6_canonical) BEFORE the ed25519 verification. `pubkeys` maps a signer ClaimReference -> raw
    ed25519 public bytes. Returns {"ok": bool, "reason": str}."""
    if not isinstance(binding, dict):
        return {"ok": False, "reason": "binding is not an object"}
    # (round-11) structural ingress on the BundleBinding required members (spec §B.7 lines 351-361),
    # ALWAYS run pre-crypto so no receipt-controlled member reaches a concat / `in`-frozenset / dict-key
    # unchecked. Signature VERIFICATION stays crypto-gated below; only the SHAPE is enforced here.
    for _f in ("bindingVersion", "jobId", "role", "signer", "nativeAddress", "bundleContentHash"):
        if not isinstance(binding.get(_f), str):
            return {"ok": False, "reason": "BB-5: binding.%s must be a string (got %s)"
                    % (_f, type(binding.get(_f)).__name__)}
    _sig = binding.get("signature")
    if _sig is not None and not isinstance(_sig, dict):
        return {"ok": False, "reason": "BB-4: binding.signature must be an object (got %s)"
                % type(_sig).__name__}
    # (round-13 B1) WHEN a signature object is present, signer / algorithm / value are each a REQUIRED
    # present string — explicit null is NOT exempt (the old `is not None` clause let null members clear
    # this structural ingress and reach `ok: True` on the pubkeys=None path, since sig6_canonical is
    # crypto-gated). An ABSENT signature (`_sig is None`) skips this loop and still refuses below at the
    # signature.signer == binding.signer equality, so the absent case is unchanged.
    if _sig is not None:
        for _f in ("signer", "algorithm", "value"):
            _sv = _sig.get(_f)
            if not isinstance(_sv, str):
                return {"ok": False, "reason": "BB-4: binding.signature.%s must be a string (got %s)"
                        % (_f, type(_sv).__name__)}
    sig = binding.get("signature") or {}
    if sig.get("signer") != binding.get("signer"):
        return {"ok": False, "reason": "BB-4: signature.signer != binding.signer"}
    if binding.get("bindingVersion") not in SUPPORTED_BINDING_VERSIONS:
        return {"ok": False, "reason": "BB-5 check 3: unsupported bindingVersion %r"
                % (binding.get("bindingVersion"),)}
    if binding.get("jobId") != expected_jobid:
        return {"ok": False, "reason": "BB-5: binding.jobId != %r" % (expected_jobid,)}
    if binding.get("role") != expected_role:
        return {"ok": False, "reason": "BB-5: binding.role != %r" % (expected_role,)}
    if binding.get("logicalAddress") != logical_address(binding.get("jobId"), binding.get("role")):
        return {"ok": False, "reason": "BB-5 check 5: logicalAddress != derive(jobId, role)"}
    if expected_content_hash is not None and binding.get("bundleContentHash") != expected_content_hash:
        return {"ok": False, "reason": "BB-5 check 8: binding.bundleContentHash != expected"}
    if pubkeys is not None and HAVE_CRYPTO:
        pk = pubkeys.get(binding.get("signer"))
        if pk is None:
            return {"ok": False, "reason": "BB-4: no public key for signer %r" % (binding.get("signer"),)}
        alg = sig.get("algorithm")                                # F3: dispatch on the declared label
        if alg not in SUPPORTED_SIGNATURE_ALGORITHMS:
            return {"ok": False, "reason": "BB-4/SIG-6: unsupported or missing binding signature "
                    "algorithm %r for signer %r" % (alg, binding.get("signer"))}
        ok_c, reason_c = sig6_canonical(sig.get("value", ""))     # F4: SIG-6 BEFORE verify_sig
        if not ok_c:
            return {"ok": False, "reason": "BB-4/%s (binding signature)" % (reason_c,)}
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
def _holds_role(bundle, signer, role):
    """BB-5 check 9: `signer` is the bundle party holding `role` (parties[].primaryClaim == signer
    AND parties[].role == role). Authorization is a roster fact, never mere presence at an address."""
    if not isinstance(bundle, dict):
        return False
    return any(p.get("primaryClaim") == signer and p.get("role") == role
               for p in bundle.get("parties", []))


def _full_standing(bundle):
    """§10.4.1 signature standing for BB-6 full-signature precedence: a copy is FULL-standing iff a
    signature is present for EVERY party in its `parties[]` (co-signed); anything less is lesser
    standing. Structural presence-per-party.

    This is the BB-6 PRECEDENCE standing (§10.4.2 spec line 381 — a structural all-parties-signed
    count over already-validated copies), DISTINCT from admission's outcome-dependent required-signer
    set (_required_bundle_signers / _bundle_signatures_valid F1); the two answer different questions.

    HARDENING (round-9): standing is a presence count and MUST NOT be computed on a copy whose
    signatures have not already been validated. In the replay reconstruction the only bundles that
    reach resolve_bb6 (and thus this predicate, via `anchored`) are the ones _post_fetch_valid()
    passed — signature validity is therefore established BEFORE any standing is derived, so a copy
    with unverifiable signatures can never be counted at full (or any) standing."""
    if not isinstance(bundle, dict):
        return False
    parties = {p.get("primaryClaim") for p in bundle.get("parties", [])}
    signed = {s.get("party") for s in bundle.get("signatures", [])}
    return bool(parties) and parties <= signed


def _bundle_signatures_valid(bundle, pubkeys):
    """§10.4.1 bundle signature validity + required-signer, applied IDENTICALLY to both bundle types
    (round-10; AttestationBundle and FaultAttestationBundle). The required-signer set is
    OUTCOME-DEPENDENT (spec DACS-5 §10.4.1 lines 318-323, :475/:798): a non-abort outcome
    (completed / failed-perm / failed-counterparty / failed-substrate) requires buyer + seller
    (+ distinct orchestrator) all signed; an abort outcome (aborted-by-*) MAY be single-signed and is
    floored on the anchoring role-holder. Then EVERY carried signature entry (the RAW list, duplicates
    included) is checked in order — F3 algorithm-label dispatch (SUPPORTED_SIGNATURE_ALGORITHMS) ->
    F4 SIG-6 canonical value (sig6_canonical, BEFORE verify) -> F2 ed25519 verification of each entry.
    Signature checks are crypto-gated (callers pass pubkeys=None to skip, mirroring the module's gating
    idiom). Returns (ok, reason)."""
    if not isinstance(bundle, dict):
        return (False, "bundle is not an object")
    anchor_role = bundle.get("anchoredByRole")
    role_holder = {p.get("role"): p.get("primaryClaim") for p in bundle.get("parties", [])}
    raw_sigs = bundle.get("signatures", [])                # RAW list — NEVER a party-keyed dict (F2: a
    signers_present = {s.get("party") for s in raw_sigs}   # party-keyed dict silently drops all-but-last)

    # F1 required-signer set (§10.4.1 verification-and-signer rules, DACS-5 lines 318-323), applied
    # TYPE-AGNOSTICALLY to both AttestationBundle and FaultAttestationBundle (spec :475/:798: the
    # single-signed non-abort rejection is not type-specific; the outcome enum is common to both):
    #   non-abort outcome (completed / failed-perm / failed-counterparty / failed-substrate)  =>
    #     buyer + seller (+ distinct orchestrator) MUST all have signed (spec line 322);
    #   abort outcome (aborted-by-self / aborted-by-other) MAY be single-signed (spec line 323) — the
    #     preserved floor is that the anchoring role-holder itself has signed.
    if bundle.get("outcome") in _ABORT:
        required = role_holder.get(anchor_role)
        if required is None or required not in signers_present:
            return (False, "§10.4.1 required signer (the %r role-holder) has no signature" % (anchor_role,))
    else:
        for role in _required_bundle_signers(bundle):
            claim = role_holder.get(role)
            if claim is None:
                return (False, "§10.4.1 required signer role %r absent from the bundle roster "
                               "(outcome %r requires buyer+seller%s)"
                        % (role, bundle.get("outcome"),
                           " + distinct orchestrator" if role == "orchestrator" else ""))
            if claim not in signers_present:
                return (False, "§10.4.1 required signer %r (%s) has no signature for a non-abort "
                               "outcome %r" % (role, claim, bundle.get("outcome")))

    # F2/F3/F4: EVERY carried signature entry (the RAW list, duplicates included) must be canonical,
    # carry a supported algorithm, and verify. Crypto-gated exactly like the prior implementation
    # (callers pass pubkeys=None to skip crypto); SIG-6 canonicality + algorithm dispatch run right
    # before verify_sig at this same site.
    if pubkeys is not None and HAVE_CRYPTO:
        h = bundle_hash(bundle)
        dom = bundle_domain(bundle)
        for s in raw_sigs:
            party = s.get("party")
            pk = pubkeys.get(party)
            if pk is None:
                return (False, "no public key for bundle signer %r" % (party,))
            alg = s.get("algorithm")                              # F3: dispatch on the declared label
            if alg not in SUPPORTED_SIGNATURE_ALGORITHMS:
                return (False, "§10.4.1/SIG-6 unsupported or missing signature algorithm %r for bundle "
                               "signer %r" % (alg, party))
            ok_c, reason_c = sig6_canonical(s.get("value", ""))   # F4: SIG-6 BEFORE verify_sig
            if not ok_c:
                return (False, "%s for bundle signer %r" % (reason_c, party))
            if not verify_sig(pk, dom, h, s.get("value", "")):    # F2: every entry must verify
                return (False, "§10.4.1 bundle signature does not verify for signer %r" % (party,))
    return (True, "ok")


def _post_fetch_valid(fetched, binding, pubkeys):
    """FULL BB-5 post-fetch validation of one fetched copy against the binding that resolved it
    (round-9). Any failure => the copy is INERT (the caller DROPS it; it never reaches the BB-6
    ladder at any standing). Checks, in order:

      check 7  — fetched.jobId == binding.jobId
      check 9  — signer holds the claimed role in the bundle roster (BB-5 check 9 authorization)
      check 9  — anchoredByRole consistency: the copy is anchored by the role it binds
      check 9  — §10.4.1 fault-permissible set: faultedParty ∈ implied set for (outcome, anchoredByRole)
      check 9  — §10.4.1 bundle signature validity + required-signer (crypto-gated)
      check 8  — §10.4.1 byte recompute: bundle_hash(fetched) == binding.bundleContentHash

    Returns (ok, reason)."""
    if not isinstance(fetched, dict):
        return (False, "fetched copy is not an object")
    if fetched.get("jobId") != binding.get("jobId"):
        return (False, "BB-5 check 7: fetched.jobId != binding.jobId")
    if not _holds_role(fetched, binding.get("signer"), binding.get("role")):
        return (False, "BB-5 check 9: signer does not hold the claimed role in the bundle roster")
    if fetched.get("anchoredByRole") != binding.get("role"):
        return (False, "BB-5 check 9: anchoredByRole (%r) != bound role (%r)"
                % (fetched.get("anchoredByRole"), binding.get("role")))
    if is_fab(fetched):
        roster = roster_roles(fetched)
        try:
            fset = implied_fault_set(fetched.get("outcome"), fetched.get("anchoredByRole"), roster)
        except ValueError as exc:
            return (False, "§10.4.1 %s" % (exc,))
        if fetched.get("faultedParty") not in fset:
            return (False, "§10.4.1 faultedParty %r outside the permissible set %r for (%r, %r)"
                    % (fetched.get("faultedParty"), sorted(fset), fetched.get("outcome"),
                       fetched.get("anchoredByRole")))
    ok_sig, reason = _bundle_signatures_valid(fetched, pubkeys)
    if not ok_sig:
        return (False, reason)
    if bundle_hash(fetched) != binding.get("bundleContentHash"):
        return (False, "BB-5 check 8: recomputed §10.4.1 hash != binding.bundleContentHash")
    return (True, "ok")


def resolve_bb6(bindings, party_map=None, budget=BB6_DEFAULT_BUDGET, anchored=None):
    """§10.4.2 BB-6 authorized-candidate resolution as amended by E6.

    bindings : list of BundleBinding dicts (each with signer, bundleContentHash,
               nativeAddress). Assumed BB-4-valid + BB-5 checks 1-5 passing (candidate set).
    party_map: optional {signer -> role} authenticated role->primary-claim map. When
               present the candidate set is pruned to the mapped signer BEFORE any fetch
               (MANDATORY in a derivation context). None models "no co-signed map yet".
    budget   : N per authenticated signer per (jobId, role) (default 8). Per-signer, so an
               outsider's flood never consumes the honest role-holder's allocation (E6).
    anchored : optional {nativeAddress -> bundle} for authorization (BB-5 check 9). PRECONDITION
               (round-9 F3): every bundle passed in `anchored` MUST already have passed full BB-5
               post-fetch validation (incl. §10.4.1 signature validity) — signature standing
               (_full_standing) is never computed on an unvalidated copy.

    BB-7 exhaustion is SIDE-level (round-6 blocker #3): if ANY signer bucket (after the party_map
    prune) holds more than `budget` candidates, its budget exhausts with candidate addresses still
    unfetched, and the WHOLE side's disposition is `indeterminate` — overriding any authorized
    candidate that resolved, never `absent`, never a void.

    Returns {"disposition": "present"|"indeterminate", "resolvedNativeAddress": str|None,
             "fetched": [nativeAddress,...], "authorizedSigners": [...], "exhaustedSigners": [...]}.
    """
    if party_map:
        # MANDATORY prune before any fetch, by ROLE-MATCH (BB-5 check 9): a candidate is authorized only
        # when its signer's AUTHENTICATED role (party_map[signer]) equals the role the binding CLAIMS.
        # Key-membership alone is NOT authorization — an insider signer mapped to a DIFFERENT role must
        # not resolve the requested side (round-7 cross-role-insider fix).
        bindings = [b for b in bindings if party_map.get(b["signer"]) == b.get("role")]

    # group by authenticated signer; each signer gets its OWN budget
    by_signer = {}
    for b in bindings:
        by_signer.setdefault(b["signer"], []).append(b)

    fetched = []
    authorized_copies = []
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
            # BB-5 check 9 authorization: the signer must be the bundle party holding the role the
            # binding CLAIMS — via the authenticated party_map, or the anchored bundle's roster.
            is_authorized = False
            if party_map is not None:
                is_authorized = party_map.get(signer) == b.get("role")
            elif anchored is not None and b["nativeAddress"] in anchored:
                # post-fetch authorization: the anchored bundle's roster must name this signer as the
                # holder of the claimed role (BB-5 check 9), not mere presence at the address.
                is_authorized = _holds_role(anchored[b["nativeAddress"]], signer, b.get("role"))
            if is_authorized:
                authorized.append(signer)
                authorized_copies.append(b)

    exhausted = sorted(set(exhausted))
    authorized_signers = sorted(set(authorized))

    def _out(disposition, resolved):
        return {"disposition": disposition, "resolvedNativeAddress": resolved,
                "fetched": fetched, "authorizedSigners": authorized_signers, "exhaustedSigners": exhausted}

    if exhausted:
        # BB-7 is SIDE-level and precedes the ladder (spec order): any signer bucket that exhausts N
        # with candidates unfetched makes the WHOLE side `indeterminate`, overriding any authorized
        # candidate — never absent, never a void. A consumer MAY re-run with a larger budget.
        return _out("indeterminate", None)
    if not authorized_copies:
        # no BB-4-valid authorized binding resolved -> indeterminate (BB-7), never absent.
        return _out("indeterminate", None)

    # BB-6 same-role ladder over the surviving authorized, fetched copies (§10.4.2 BB-6 / §10.5.1
    # lines 634-644). Copies are in ascending (bundleContentHash, nativeAddress) order.
    ladder = sorted(authorized_copies, key=lambda b: (b["bundleContentHash"], b["nativeAddress"]))
    forms = {}  # canonical form (bundleContentHash) -> its copies, ascending
    for b in ladder:
        forms.setdefault(b["bundleContentHash"], []).append(b)
    if len(forms) <= 1:
        # (b) collapse: canonically-equal copies collapse to one retrieved copy -> present.
        return _out("present", ladder[0]["nativeAddress"])
    # (c) full-signature precedence: standing computed from each form's ANCHORED bundle — FULL iff a
    #     signature is present for every party. Exactly one full-standing form takes precedence.
    full_forms = [h for h, cps in forms.items()
                  if anchored is not None and _full_standing(anchored.get(cps[0]["nativeAddress"]))]
    if len(full_forms) == 1:
        return _out("present", forms[full_forms[0]][0]["nativeAddress"])
    # (d) equal standing (all lesser-signed, or 2+ full-standing) -> void -> indeterminate (BB-6/BB-7).
    return _out("indeterminate", None)


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
# derive() executes the named §10.5.1 484-698 predicates as amended (E1-E5) — selected
# derivation fields, not a complete ReplayableReputationDerivation implementation
# --------------------------------------------------------------------------- #
def _primary_claims(bundle):
    return {p["primaryClaim"] for p in bundle.get("parties", [])}


def _role_of_party(bundle, party):
    for p in bundle.get("parties", []):
        if p["primaryClaim"] == party:
            return p["role"]
    return None


def derive(party, tagged_bundles, window_start, window_end, basis="finalisedAt"):
    """Executes the named §10.5.1 reputation-derivation predicates over selected fields; not a
    complete ReplayableReputationDerivation implementation.

    tagged_bundles: list of {"bundle": <dict>, "resolvedRole": "buyer"|"seller",
      "counterpartyDisposition": "present"|"absent"|None, "counterpartyRef": ...?,
      "absenceEvidenceRef": ...?} — each input copy carries its §10.5.1 resolution tag.

    Returns a ReputationDerivation dict (bundleCount, metrics, resolutionContext,
    bundleRefs, windowingBasis). Metrics reproduce byte-identically across runs given
    the same tagged input + window + basis (the §10.5.3 determinism-receipt contract).
    """
    # (round-13 B3) fail-closed on any basis this reference cannot window against, instead of the
    # prior silent `clock = "finalisedAt"` that recorded `basis` but computed finalisedAt regardless.
    # sr2-anchor-timestamp is a valid §10.5.3 literal but a §10.5.1 SHOULD NOT implemented here — a
    # DISTINCT not-implemented refusal; anything outside the vocab is a vocab error. Only IMPLEMENTED
    # bases proceed, and the clock is the DECLARED basis (no hardcode that would mislabel the receipt).
    if basis not in IMPLEMENTED_WINDOWING_BASES:
        if basis in SUPPORTED_WINDOWING_BASES:
            raise ValueError("windowingBasis %r is not implemented (fail-closed; §10.5.1 sr2 windowing "
                             "is a SHOULD, not implemented by this reference)" % (basis,))
        raise ValueError("windowingBasis must be one of %s (got %r)"
                         % (sorted(SUPPORTED_WINDOWING_BASES), basis))
    clock = basis  # guaranteed "finalisedAt" (the only implemented basis); no silent hardcode
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
    # jobIds removed from the party-fault denominator. ST-10's temporal invariant keeps these three
    # classes disjoint, but the union is taken at the subtraction site so a future overlap cannot
    # double-subtract a single jobId (behaviour-neutral today).
    fs_jobs = {t["bundle"]["jobId"] for (t, o) in zip(reconciled, outcomes) if o == "failed-substrate"}
    orch_jobs = {t["bundle"]["jobId"] for t in reconciled if t["bundle"]["jobId"] in orch_fault}
    cancelled_jobs = {t["bundle"]["jobId"] for t in reconciled if t["bundle"]["jobId"] in cancelled}

    def cnt(pred):
        return sum(1 for (t, o) in zip(reconciled, outcomes) if pred(t, o))

    failed_counterparty = cnt(lambda t, o: o == "failed-counterparty" and t["bundle"]["jobId"] not in orch_fault)
    aborted_by_other = cnt(lambda t, o: o == "aborted-by-other"
                           and t["bundle"]["jobId"] not in cancelled and t["bundle"]["jobId"] not in orch_fault)
    counterparty_fault = aborted_by_other + failed_counterparty

    party_fault_denom = n - len(fs_jobs | orch_jobs | cancelled_jobs)
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
    """§10.5.3 (3)/(4) as amended by E5, extended by round-12 into the integrated-replay
    completeness gate. The object MUST first pass the ReplayableReputationDerivation refusal gate
    (CORE §11.1.2). Every check refuses DETERMINISTICALLY with a stable reason — a malformed receipt
    never raises. Fixed check order:
      1. discriminator gate (CORE §11.1.2);
      2. resolutionContext is a REQUIRED array (spec :532) — ABSENCE refuses EVEN when bundleRefs is
         empty (round-12: the conforming empty form is an empty array, not a missing member);
      3. every entry is an object carrying a string contentHash (read by the keying compare and the
         §10.5.3 member checks) — a malformed entry refuses here instead of raising (round-12);
      3b. bundleRefs is a REQUIRED array (spec :531) — absence refuses, a non-array refuses instead of
         raising TypeError from the len()/keying compare below (round-12 lens closure);
      4. resolutionContext length == bundleRefs length, and keyed to bundleRefs in canonical order
         (spec :850-854);
      5. metrics + bundleCount present with the types replay_receipt's byte-identity compare consumes
         (round-12);
      6. per-disposition member completeness (roleEvidence required, read type-guarded here — object-typing
         is the round-11 grammar gate's job; binding roleEvidence carries bb6Context; a present entry
         carries counterpartyRef + counterpartyRoleEvidence; an absent entry carries absenceEvidenceRef,
         and a write-input substrate carries absenceBinding).
    Returns (ok, [reasons])."""
    gate = require_replayable_derivation(derivation)
    if not gate["ok"]:
        return (False, ["discriminator refusal: " + gate["reason"]])
    # (2) resolutionContext REQUIRED array. Missing refuses even with empty bundleRefs (round-12
    #     behaviour change vs the prior absent+empty-refs (True, []); the empty form is an empty array).
    if "resolutionContext" not in derivation:
        return (False, ["resolutionContext is REQUIRED (spec :532)"])
    ctx = derivation.get("resolutionContext")
    if not isinstance(ctx, list):
        return (False, ["resolutionContext must be an array (got %s)" % type(ctx).__name__])
    # (3) each entry a dict with a string contentHash BEFORE the keying compare / member reads —
    #     a malformed entry refuses (round-12 behaviour change: ctx=[{}] / non-dict entries / non-string
    #     contentHash previously raised KeyError/TypeError, now deterministic refusals).
    reasons = []
    for i, e in enumerate(ctx):
        if not isinstance(e, dict):
            reasons.append("resolutionContext[%d]: entry is not an object (got %s)" % (i, type(e).__name__))
        elif not isinstance(e.get("contentHash"), str):
            reasons.append("resolutionContext[%d]: contentHash must be a string (got %s)"
                           % (i, type(e.get("contentHash")).__name__))
    if reasons:
        return (False, reasons)
    # (3b) bundleRefs is a REQUIRED member of the receipt type (spec :531) and is consumed by len()
    #      + the keying compare below: absence refuses (same absence-vs-empty-array doctrine as
    #      resolutionContext, :532) and a non-array refuses instead of raising TypeError (round-12
    #      lens closure).
    if "bundleRefs" not in derivation:
        return (False, ["bundleRefs is REQUIRED (spec :531)"])
    refs = derivation.get("bundleRefs")
    if not isinstance(refs, list):
        return (False, ["bundleRefs must be an array (got %s)" % type(refs).__name__])
    # (4) length + keying/order against bundleRefs (both reasons byte-identical to prior rounds).
    if len(refs) != len(ctx):
        reasons.append("resolutionContext length != bundleRefs length")
    if [e["contentHash"] for e in ctx] != refs:
        reasons.append("resolutionContext not keyed to bundleRefs in order")
    # (5) top-level replay inputs consumed by replay_receipt's byte-identity compare (round-12).
    if "metrics" not in derivation or not isinstance(derivation.get("metrics"), dict):
        reasons.append("metrics must be present and an object")
    bc = derivation.get("bundleCount")
    if "bundleCount" not in derivation or not isinstance(bc, int) or isinstance(bc, bool):
        reasons.append("bundleCount must be present and an integer")
    # (5b) windowingBasis is a REQUIRED closed-union member (spec :530/:954): the receipt is defined
    #      relative to the recorded basis (:856), so an absent basis refuses, and an out-of-vocab
    #      value refuses (round-13 B3). sr2-anchor-timestamp is IN the vocab (a valid literal) and
    #      PASSES here — its not-implemented fail-closed is a DISTINCT refusal at compute time
    #      (derive() / the replay guard), never folded into this vocab reason.
    if "windowingBasis" not in derivation:
        reasons.append("windowingBasis is REQUIRED (spec :530)")
    elif derivation.get("windowingBasis") not in SUPPORTED_WINDOWING_BASES:
        reasons.append("windowingBasis must be one of %s (got %r)"
                       % (sorted(SUPPORTED_WINDOWING_BASES), derivation.get("windowingBasis")))
    # (6) per-disposition member completeness (unchanged from E5).
    for e in ctx:
        if "roleEvidence" not in e or e["roleEvidence"] is None:
            reasons.append("%s: missing roleEvidence" % e.get("contentHash"))
        # type-guarded read: object-TYPING of roleEvidence is the round-11 _entry_structural_gate's
        # job (its grammar reason fires in validate); rrmp only needs to never raise pre-validate on
        # the integrated path (round-12 lens closure).
        role_ev = e.get("roleEvidence")
        role_ev = role_ev if isinstance(role_ev, dict) else {}
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


# The §10.4.1 bundle `outcome` enum common to both bundle types (spec DACS-5 §10.4.1 line 481).
# _outcome_class() accepts EXACTLY these and raises ValueError on anything else; that ValueError is
# caught in _post_fetch_valid (implied_fault_set) but NOT in divergence(), so an unknown outcome on a
# structurally-unvalidated counterparty copy would escape — hence the deref'd-copy validator pins it.
_KNOWN_OUTCOMES = frozenset({"completed", "failed-substrate", "aborted-by-self",
                             "aborted-by-other", "failed-perm", "failed-counterparty"})


def _role_evidence_grammar(re_, ch, label):
    """§10.5.3 roleEvidence / counterpartyRoleEvidence XOR shape (spec DACS-5-VERIFY.md :538-540, :548):
    a REQUIRED object; `kind` REQUIRED in the {"binding","address"} XOR; the "binding" arm carries a
    REQUIRED "binding" object; the "address" arm carries a REQUIRED string "resolvedAddress". The
    address arm's role-SEGMENT SEMANTIC check (spec :540) is NOT verified here — structural shape only
    (disclosed residual #3). Returns (ok, reason)."""
    if not isinstance(re_, dict):
        return (False, "%s: %s must be an object (got %s)" % (ch, label, type(re_).__name__))
    kind = re_.get("kind")
    if kind == "binding":
        if not isinstance(re_.get("binding"), dict):
            return (False, "%s: %s.binding must be an object (got %s)"
                    % (ch, label, type(re_.get("binding")).__name__))
    elif kind == "address":
        if not isinstance(re_.get("resolvedAddress"), str):
            return (False, "%s: %s.resolvedAddress must be a string (got %s)"
                    % (ch, label, type(re_.get("resolvedAddress")).__name__))
    else:
        return (False, "%s: %s.kind must be one of ['address', 'binding'] (got %r)" % (ch, label, kind))
    return (True, None)


def _entry_structural_gate(entry, index):
    """Round-10 D6 + round-11 per-entry gate (step-5 1b). NO LONGER pure type-when-present: it now
    enforces PRESENCE + VOCABULARY + member types for the §10.5.3 ResolutionContextEntry grammar
    (spec DACS-5-VERIFY.md lines 535-552), so a malformed untrusted entry refuses DETERMINISTICALLY —
    never a downstream fail-open, never a raise. candidateBindings is the SOLE EXCEPTION, kept
    type-when-present: BB-6 outsider garbage MUST stay prunable-inert and MUST NEVER be able to refuse
    an honest receipt (F2/F4 inertness, spec BB-6 :381/:387); its members are validated at BB-4/BB-5
    re-verification (verify_binding), which only role-holder survivors reach. Fixed, documented check
    order for stable exact reasons: entry-is-object -> contentHash-string -> dict-typed-members ->
    resolvedRole-vocabulary (round-12 B2, before evidence-kind branching so both arms are covered) ->
    roleEvidence grammar -> counterpartyDisposition -> counterparty/absence member shapes -> bb6Context.
    Returns (ok, reason)."""
    if not isinstance(entry, dict):
        return (False, "resolutionContext[%d]: entry is not an object (got %s)" % (index, type(entry).__name__))
    # contentHash: REQUIRED string ref (spec :536) — keys the entry to bundleRefs and is deref'd as a key.
    ch = entry.get("contentHash")
    if not isinstance(ch, str):
        return (False, "resolutionContext[%d]: contentHash must be a string (got %s)" % (index, type(ch).__name__))
    # dict-typed members guarded downstream by falsy-tolerant `or {}` / `if not`: flag truthy non-dict only.
    for field in ("roleEvidence", "bb6Context", "counterpartyRef", "counterpartyRoleEvidence", "absenceEvidenceRef"):
        v = entry.get(field)
        if v is not None and not isinstance(v, dict):
            return (False, "%s: %s must be an object (got %s)" % (ch, field, type(v).__name__))
    # resolvedRole: REQUIRED in the {"buyer","seller"} vocabulary (spec :537). Checked BEFORE the
    # evidence-kind branch (round-12 B2) so an invalid enum refuses on BOTH the binding- and
    # address-backed arms directly, not incidentally via the later binding-role comparison (which
    # never runs on the address arm). Missing counts as invalid.
    role = entry.get("resolvedRole")
    if role not in ("buyer", "seller"):
        return (False, "%s: resolvedRole must be one of ['buyer', 'seller'] (got %r)" % (ch, role))
    # roleEvidence: REQUIRED object on the {"binding","address"} XOR (spec :538-540).
    ok_re, reason_re = _role_evidence_grammar(entry.get("roleEvidence"), ch, "roleEvidence")
    if not ok_re:
        return (False, reason_re)
    # counterpartyDisposition: REQUIRED in the {"present","absent"} vocabulary (spec :546).
    disp = entry.get("counterpartyDisposition")
    if disp not in ("present", "absent"):
        return (False, "%s: counterpartyDisposition must be one of ['absent', 'present'] (got %r)" % (ch, disp))
    # counterpartyRoleEvidence: same XOR SHAPE when carried (spec :548). Presence-per-disposition is E5's
    # job in receipt_required_members_present; the gate validates shape when the member is present.
    if entry.get("counterpartyRoleEvidence") is not None:
        ok_cre, reason_cre = _role_evidence_grammar(entry.get("counterpartyRoleEvidence"), ch, "counterpartyRoleEvidence")
        if not ok_cre:
            return (False, reason_cre)
    # counterpartyRef: AttestationRef with a REQUIRED string contentHash when carried (spec :547/:853).
    cref = entry.get("counterpartyRef")
    if isinstance(cref, dict) and not isinstance(cref.get("contentHash"), str):
        return (False, "%s: counterpartyRef.contentHash must be a string (got %s)"
                % (ch, type(cref.get("contentHash")).__name__))
    # absenceEvidenceRef: kind / locator / contentHash all REQUIRED strings when carried (spec :551).
    aer = entry.get("absenceEvidenceRef")
    if isinstance(aer, dict):
        for f in ("kind", "locator", "contentHash"):
            if not isinstance(aer.get(f), str):
                return (False, "%s: absenceEvidenceRef.%s must be a string (got %s)"
                        % (ch, f, type(aer.get(f)).__name__))
    ctx = entry.get("bb6Context")
    if isinstance(ctx, dict):
        pm = ctx.get("partyMap")
        if pm is not None and not isinstance(pm, dict):
            return (False, "%s: bb6Context.partyMap must be an object (got %s)" % (ch, type(pm).__name__))
        if "candidateBindings" in ctx:
            cbs = ctx["candidateBindings"]
            if not isinstance(cbs, list):
                return (False, "%s: bb6Context.candidateBindings must be an array (got %s)" % (ch, type(cbs).__name__))
            for k, c in enumerate(cbs):
                if not isinstance(c, dict):
                    return (False, "%s: bb6Context.candidateBindings[%d] is not an object (got %s)"
                            % (ch, k, type(c).__name__))
                for sf in ("signer", "nativeAddress", "bundleContentHash"):
                    sv = c.get(sf)
                    if sv is not None and not isinstance(sv, str):
                        return (False, "%s: bb6Context.candidateBindings[%d].%s must be a string (got %s)"
                                % (ch, k, sf, type(sv).__name__))
    return (True, None)


def _bundle_shape_ok(bundle):
    """Round-10 D6 deref'd-copy shape validator (step-5 1c). Validates EXACTLY the fields the replay
    path consumes from a dereferenced bundle copy by subscript / hash-key / iteration — beyond the
    isinstance-dict guard already applied — and nothing more. The consuming site justifying each field
    is documented in the step-5 report. divergence() and the other helpers stay UNTOUCHED; this
    validator is the shape gate in front of them. Returns (ok, reason)."""
    # parties: roster_roles() does p["role"] (subscript); validate_resolution_context (:825) and
    # _bundle_signatures_valid build dicts keyed by p.get("primaryClaim") (unhashable key => crash).
    parties = bundle.get("parties")
    if "parties" in bundle and not isinstance(parties, list):
        return (False, "parties must be an array (got %s)" % type(parties).__name__)
    for k, p in enumerate(parties or []):
        if not isinstance(p, dict):
            return (False, "parties[%d] is not an object (got %s)" % (k, type(p).__name__))
        for pf in ("role", "primaryClaim"):
            if not isinstance(p.get(pf), str):
                return (False, "parties[%d].%s must be a string (got %s)" % (k, pf, type(p.get(pf)).__name__))
    # signatures: _bundle_signatures_valid iterates the raw list; {s.get("party")} forms a set
    # (unhashable party => crash); _full_standing likewise. Each entry is a dict with a string party.
    sigs = bundle.get("signatures")
    if "signatures" in bundle and not isinstance(sigs, list):
        return (False, "signatures must be an array (got %s)" % type(sigs).__name__)
    for k, s in enumerate(sigs or []):
        if not isinstance(s, dict):
            return (False, "signatures[%d] is not an object (got %s)" % (k, type(s).__name__))
        if not isinstance(s.get("party"), str):
            return (False, "signatures[%d].party must be a string (got %s)" % (k, type(s.get("party")).__name__))
    # outcome: _outcome_class(copy["outcome"]) subscripts + rejects unknowns via ValueError (uncaught
    # inside divergence); implied_fault_set(outcome) likewise. Must be a known-enum string.
    outcome = bundle.get("outcome")
    if not isinstance(outcome, str) or outcome not in _KNOWN_OUTCOMES:
        return (False, "outcome must be one of %s (got %r)" % (sorted(_KNOWN_OUTCOMES), outcome))
    # anchoredByRole: copy["anchoredByRole"] subscript in divergence (legacy/mixed); implied_fault_set.
    if not isinstance(bundle.get("anchoredByRole"), str):
        return (False, "anchoredByRole must be a string (got %s)" % type(bundle.get("anchoredByRole")).__name__)
    # faultedParty: _fab_faulted(bundle) = bundle["faultedParty"] (subscript) on a FAB pair/mixed.
    if is_fab(bundle) and not isinstance(bundle.get("faultedParty"), str):
        return (False, "faultedParty must be a string on a FaultAttestationBundle (got %s)"
                % type(bundle.get("faultedParty")).__name__)
    # phaseSummary: _phase_summary_diverges builds {e["index"]: e} — e["index"] subscript AND dict key
    # (must be present + hashable). kind/outcome/errorClass are `.get` (safe).
    ps = bundle.get("phaseSummary")
    if "phaseSummary" in bundle and not isinstance(ps, list):
        return (False, "phaseSummary must be an array (got %s)" % type(ps).__name__)
    seen_idx = set()
    for k, e in enumerate(ps or []):
        if not isinstance(e, dict):
            return (False, "phaseSummary[%d] is not an object (got %s)" % (k, type(e).__name__))
        idx = e.get("index")
        # (round-13 B2 Limb A) reject bool with its OWN reason FIRST: isinstance(True, int) is True, and
        # a bool index collides with an int index (True==1, hash-equal) in _phase_summary_diverges'
        # {e["index"]: e} keyed compare — matching the bool-exclusion idiom at bundleCount (:834) and
        # budget (:1122). The non-bool non-int/str path keeps its ORIGINAL reason unchanged (the round-10
        # D6 index-type pin asserts that exact string for a NoneType index).
        if isinstance(idx, bool):
            return (False, "phaseSummary[%d].index must be a non-boolean int or string (got bool)" % k)
        if not isinstance(idx, (int, str)):
            return (False, "phaseSummary[%d].index must be an int or string (got %s)"
                    % (k, type(idx).__name__))
        # (round-13 B2 Limb B) reject a DUPLICATE/COLLIDING index BEFORE _phase_summary_diverges keys
        # {e["index"]: e} and silently last-write-wins (which masks a real divergence). This gate runs
        # on BOTH the winner (:1073) and counterparty (:1216) copies before divergence() is called, so
        # a malformed copy refuses deterministically instead of reaching the pure-bool divergence read.
        if idx in seen_idx:
            return (False, "phaseSummary[%d].index is a duplicate/colliding index %r" % (k, idx))
        seen_idx.add(idx)
    return (True, None)


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
    # (1a) PRE-LOOP: resolutionContext is REQUIRED (spec :532). Missing now refuses with its own
    # deterministic reason (round-12 B1c); present-but-not-a-list refuses with the existing reason
    # (unchanged). An empty (present) array still returns (True, []) from the loop below — the
    # length/keying/emptiness contract against bundleRefs is receipt_required_members_present's job.
    if "resolutionContext" not in derivation:
        return (False, ["resolutionContext is REQUIRED (spec :532)"])
    rc = derivation.get("resolutionContext", [])
    if not isinstance(rc, list):
        return (False, ["resolutionContext must be an array (got %s)" % type(rc).__name__])
    for index, entry in enumerate(rc):
        # (1b) PER-ENTRY STRUCTURAL GATE: type-when-present for every receipt-supplied member the loop
        # reads by attr/iteration/index, BEFORE any of the falsy-only `or {}` idioms below run.
        ok_entry, reason_entry = _entry_structural_gate(entry, index)
        if not ok_entry:
            reasons.append(reason_entry)
            continue
        ch = entry.get("contentHash")
        auth = deref(ch)
        if not isinstance(auth, dict):
            reasons.append("%s: authoritative copy not dereferenceable" % ch)
            continue
        # (round-8) byte-revalidate the claimed-authoritative copy: its dereferenced content MUST hash to
        # the entry key (BB-5 check 8, genuine §10.4.1 recompute — not a claim compare). A bad winner is a
        # broken receipt, not an inert copy, so REFUSE. Closes the isinstance-only trust gap for the winner.
        if bundle_hash(auth) != ch:
            reasons.append("%s: roleEvidence bundle content-hash mismatch (recomputed %s)"
                           % (ch, bundle_hash(auth)))
            continue
        # (1c) WINNER shape validator — AFTER the content-hash check (hash-mismatch reason stays first),
        # BEFORE any structural read of the winner (roster, signatures, faultedParty, divergence).
        ok_w, reason_w = _bundle_shape_ok(auth)
        if not ok_w:
            reasons.append("%s: winner copy %s" % (ch, reason_w))
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
            # (round-7) authenticate bb6Context.partyMap against the authoritative bundle roster BEFORE any
            # authorization use — an unauthenticated partyMap must never drive BB-6. Every {signer: role}
            # entry MUST match a bundle party (primaryClaim == signer AND role == role); any that does not
            # fails the receipt closed.
            roster = {p.get("primaryClaim"): p.get("role") for p in auth.get("parties", [])}
            unauth_pm = sorted(s for s, r in (ctx.get("partyMap") or {}).items() if roster.get(s) != r)
            if unauth_pm:
                reasons.append("%s: bb6Context.partyMap not authenticated against the bundle roster (%s)"
                               % (ch, unauth_pm))
                continue
            # (round-9) reconstruct the anchored map in the BB-6 MANDATED ORDER:
            #   PRUNE -> RE-VERIFY -> BUDGET(exhaustion) -> ORDER -> FETCH -> VALIDATE -> LADDER.
            # (round-9 audit F2/F4/F5) The authenticated-partyMap prune MUST precede the per-candidate BB-4/BB-5
            # re-verification and is ROLE-HOLDER-STRICT on the ENTRY's resolvedRole: keep a candidate iff its
            # signer's AUTHENTICATED role is the side being resolved. A candidate whose signer is not the mapped
            # role-holder — a true outsider (F2) OR a mapped counterparty publishing a cross-role binding
            # (F4/E1a) — is dropped SILENTLY, however malformed its binding, consuming zero verification/fetch
            # work; so neither can force refusal of an honest receipt, and the exhaustion count below contains
            # ONLY the genuine role-holder bucket, so a cross-role flood can never fire the anchored={} route
            # (F5). The predicate keys on the signer's MAPPED role, NOT the candidate's CLAIMED role field: a
            # role-holder-signed candidate claiming the wrong role survives and refuses via re-verification (N6).
            # The N5 partyMap-vs-roster forgery check above already ran, so a forged map never reaches this prune.
            if "budget" not in ctx:
                reasons.append("%s: bb6Context.budget absent (BB-6 fetch budget is schema-required)" % ch)
                continue
            budget = ctx["budget"]                                   # RECORDED budget — never re-defaulted
            # F5: validate the recorded budget's TYPE/RANGE before ANY comparison, slice, or pass-down to
            # resolve_bb6 — the BB-6 fetch budget is N=8 authorized-or-unresolved candidates per signer
            # (§10.4.2 BB-6, spec line 381), a positive integer. A non-int (str/float/None) or bool or <1
            # is a malformed receipt, refused closed — no TypeError may escape for an arbitrary value.
            if (not isinstance(budget, int)) or isinstance(budget, bool) or budget < 1:
                reasons.append("%s: bb6Context.budget must be an integer >= 1 (got %r)" % (ch, budget))
                continue
            party_map = ctx.get("partyMap")
            # a. PRUNE FIRST (pre-verify, pre-fetch), role-holder-strict on the entry's resolvedRole (`role`);
            #    no map => no prune. Cross-role / outsider candidates drop silently, zero fetch (F2/F4/F5).
            if party_map:
                survivors = [c for c in ctx.get("candidateBindings", []) if party_map.get(c.get("signer")) == role]
            else:
                survivors = list(ctx.get("candidateBindings", []))
            # b. RE-VERIFY BB-4 + BB-5 checks 2-5 (verify_binding) on the SURVIVORS only. Check 1 (discovery-
            #    surface resolution) is not replayable; a malformed AUTHORIZED candidate fails the receipt closed.
            bad_candidate = None
            for cand in survivors:
                vbc = verify_binding(cand, pubkeys, expected_jobid=auth.get("jobId"), expected_role=role)
                if not vbc["ok"]:
                    bad_candidate = (cand.get("nativeAddress"), vbc["reason"])
                    break
            if bad_candidate is not None:
                reasons.append("%s: bb6Context candidate binding fails BB-4/BB-5 re-verification (%s: %s)"
                               % (ch, bad_candidate[0], bad_candidate[1]))
                continue
            native = (re_.get("binding") or {}).get("nativeAddress")
            # c. BUDGET EXHAUSTION (round-9 audit F1): if any post-prune signer bucket exceeds the RECORDED
            #    budget, the side is BB-7 exhausted with candidate addresses unfetched. Spend NO fetch work —
            #    hand resolve_bb6 the FULL survivor set so it (seeing the whole bucket) reports the exhaustion
            #    `indeterminate` itself, and the receipt refuses via the existing re-selection path below.
            per_signer_count = {}
            for c in survivors:
                per_signer_count[c.get("signer")] = per_signer_count.get(c.get("signer"), 0) + 1
            if any(n > budget for n in per_signer_count.values()):
                res = resolve_bb6(survivors, party_map, budget, anchored={})
            else:
                # d. ORDER ascending by (bundleContentHash, nativeAddress), then apply the RECORDED per-signer
                #    budget; e. FETCH + FULL BB-5 post-fetch VALIDATION over that ordered+budgeted subset only.
                #      BOUNDARY: an AUTHORIZED candidate that cannot be fetched (or null-native) => REFUSE (N8);
                #      a fetched-then-invalid copy (any BB-5 post-fetch check) is DROPPED inert (R1 / R3a / R3b).
                survivors.sort(key=lambda c: (c.get("bundleContentHash"), c.get("nativeAddress")))
                per_signer = {}
                budgeted = []
                for c in survivors:
                    bucket = per_signer.setdefault(c.get("signer"), [])
                    if len(bucket) < budget:
                        bucket.append(c)
                        budgeted.append(c)
                anchored = {}
                valid_bindings = []
                candidate_refusal = None
                for cand in budgeted:
                    nat = cand.get("nativeAddress")
                    if not isinstance(nat, str):
                        candidate_refusal = "BB-5: candidate nativeAddress absent/null (%r)" % (nat,)
                        break
                    cb = cand.get("bundleContentHash")
                    try:
                        fetched = deref(cb)
                    except KeyError:
                        fetched = None   # content-addressed miss — deref may raise or return None; both => unfetchable
                    if not isinstance(fetched, dict):
                        candidate_refusal = "BB-6 candidate bundle not dereferenceable: %s" % (cb,)
                        break
                    # (round-11) shape-gate the fetched CANDIDATE copy before _post_fetch_valid reads it
                    # by subscript / iteration / set-key — the un-shape-gated 3rd deref site (the winner
                    # :NNN and counterparty :NNN copies are already _bundle_shape_ok'd). A shape-malformed
                    # fetched copy is fetched-then-invalid => DROPPED (R1/R3a/R3b), NEVER a refusal — an
                    # extra candidate must not refuse an honest receipt (BB-6/BB-7 inertness).
                    ok_shape, _shape_reason = _bundle_shape_ok(fetched)
                    if not ok_shape:
                        continue   # fetched-then-shape-invalid => DROPPED inert (same R1/R3 semantics)
                    pf_ok, _pf_reason = _post_fetch_valid(fetched, cand, pubkeys)
                    if not pf_ok:
                        continue   # fetched-then-invalid => DROPPED, truly inert (never reaches the ladder)
                    anchored[nat] = fetched
                    valid_bindings.append(cand)
                if candidate_refusal is not None:
                    reasons.append("%s: %s" % (ch, candidate_refusal))
                    continue
                # f. only the surviving VALID bindings + their validated bundles reach resolve_bb6 (LADDER).
                res = resolve_bb6(valid_bindings, party_map, budget, anchored=anchored)
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
            # (1c) COUNTERPARTY shape validator — AFTER the isinstance-dict guard, BEFORE divergence()
            # (which subscripts outcome/faultedParty/anchoredByRole/phaseSummary on an otherwise-
            # unvalidated copy). divergence() itself stays untouched.
            ok_cp, reason_cp = _bundle_shape_ok(cp)
            if not ok_cp:
                reasons.append("%s: counterparty copy %s" % (ch, reason_cp))
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
    # (round-12) integrated-replay completeness gate BEFORE per-copy validation: an object missing the
    # required resolutionContext / metrics / bundleCount members, or whose context is not keyed 1:1 to
    # bundleRefs in order, carries no replay claim and must refuse deterministically (never raise).
    ok_m, _reasons_m = receipt_required_members_present(derivation)
    if not ok_m:
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
    # (round-13 B3) read the now-REQUIRED, vocab-checked windowingBasis WITHOUT a silent default —
    # rrmp above guarantees it is present and in the vocab. Fail closed BEFORE the (bare) derive echo
    # when the recorded basis is a valid literal this reference cannot compute (sr2-anchor-timestamp):
    # re-deriving under finalisedAt while the receipt records sr2 would claim reproduction "under the
    # recorded basis" (:854/:581) that never happened. A finalisedAt receipt replays unchanged.
    basis = derivation["windowingBasis"]
    if basis not in IMPLEMENTED_WINDOWING_BASES:
        return (False, None)   # declared basis valid but unimplemented -> no honest replay claim
    replayed = derive(party, tagged, window_start, window_end, basis)
    same = (canonical(replayed["metrics"]) == canonical(derivation["metrics"])
            and replayed["bundleCount"] == derivation["bundleCount"])
    return (same, replayed)
