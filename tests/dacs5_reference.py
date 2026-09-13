"""Executable DACS-5 reference predicates for the PR #248 round-5 blocker tests.

This module is a *test-support* library, NOT a conformance validator and NOT a
TestCase. It is imported by the focused DACS-5 predicate tests, including:

    - tests/test_receipt_rederivation_vectors.py        (B1 determinism receipt)
    - tests/test_outsider_binding_flooding_vectors.py   (B2 BB-6 flood)
    - tests/test_mixed_version_reconciliation_vectors.py (B3 reconciliation totality)
    - tests/test_fab_bundle_extended_pointer_vectors.py  (B4 extended-pointer FAB path)
    - tests/test_legacy_three_party_fault_reconciliation_vectors.py

It executes the §10.5.1/§10.4.2/§10.4.3 predicates the round-4 review found were
only *asserted* by fixture metadata: implied-fault-SET legacy and mixed-version
reconciliation (E1-E4), the ResolutionContextEntry replay
contract (E5), per-signer BB-6 budgeting (E6), and the triple-identity extended-
pointer rule (E7).

It MUST NEVER be run against the pre-#248 shared goldens in
conformance/vectors/golden.json / conformance/fixtures/session-bundles-reputation.json:
those predate §10.5.1 guard (iv) and carry no resolutionContext, so a faithful
derive() cannot reproduce their pinned metrics. That gap is tracked upstream as
issue #264 and is a steward call, out of scope for #248.

Current public verification requires `cryptography` and independently
authenticated keys. The explicitly named legacy helpers retain structural-only
fixture replay when keys are omitted.
"""
import base64
import binascii
import hashlib
import json
import math
import re
import unicodedata
from urllib.parse import quote, urlsplit

from scripts import jcs

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - environment-dependent
    HAVE_CRYPTO = False

BUNDLE_DOMAIN = "dacs-bundle:v1:"
FAULT_BUNDLE_DOMAIN = "dacs-fault-bundle:v1:"
EVIDENCE_BOUND_FAULT_BUNDLE_DOMAIN = "dacs-evidence-bound-fault-bundle:v1:"
LISTING_DOMAIN = "dacs-listing:v1:"
SETTLEMENT_EVIDENCE_DOMAIN = "dacs-evidence:v1:"
DELIVERY_EVIDENCE_DOMAIN = "dacs-delivery-evidence:v1:"
ENTITLEMENT_DOMAIN = "dacs-entitlement:v1:"
PAYLOAD_ATTESTATION_DOMAIN = "dacs-payload-attestation:v1:"
BINDING_DOMAIN = "dacs-bundle-binding:v1:"
FAULT_POINTER_DOMAIN = "dacs-fault-bundle-pointer:v1:"
EVIDENCE_BOUND_FAULT_POINTER_DOMAIN = "dacs-evidence-bound-fault-bundle-pointer:v1:"

_BUNDLE_SELECTOR_BY_FAMILY = {
    "legacy": "bundleVersion",
    "fault": "faultBundleVersion",
    "evidence-bound": "evidenceBoundFaultBundleVersion",
}
_BUNDLE_DOMAIN_BY_FAMILY = {
    "legacy": BUNDLE_DOMAIN,
    "fault": FAULT_BUNDLE_DOMAIN,
    "evidence-bound": EVIDENCE_BOUND_FAULT_BUNDLE_DOMAIN,
}
_POINTER_DOMAIN_BY_FAMILY = {
    "fault": FAULT_POINTER_DOMAIN,
    "evidence-bound": EVIDENCE_BOUND_FAULT_POINTER_DOMAIN,
}

BB6_DEFAULT_BUDGET = 8

# BB-5 check 3: the BundleBinding versions this consumer supports. §B.7 / §10.4.2 defines the
# `bindingVersion: "1"` literal (spec line 352); every conformance binding carries the string "1".
SUPPORTED_BINDING_VERSIONS = frozenset({"1"})

# Outcome classes for the §10.4.3 divergence read (E1/E4): fault is compared on the
# CLASS, not the role-relative spelling.
_ABORT = {"aborted-by-self", "aborted-by-other"}
_FAILURE = {"failed-perm", "failed-counterparty"}

# CORE §B.7 "Algorithm" (spec line 369) registers these exact ComponentSignature
# algorithms. Shape validation accepts the complete protocol vocabulary; cryptographic
# verification separately dispatches only algorithms this reference implements.
COMPONENT_SIGNATURE_ALGORITHMS = frozenset({
    "ed25519", "ecdsa-secp256k1", "sr1-aggregate",
})

# The `algorithm` identifier the DACS-5 builders + conformance vectors write for a
# BundleSignature / binding signature is the lowercase string "ed25519". This reference verifier only
# implements ed25519 (verify_sig uses Ed25519PublicKey), so that is the supported set: an entry whose
# algorithm is unsupported-by-this-verifier or absent has a payload this verifier cannot reproduce and
# MUST be rejected (SIG-3). Dispatch is on this label, never assumed.
SUPPORTED_SIGNATURE_ALGORITHMS = frozenset({"ed25519"})

EVIDENCE_PHASES = frozenset({
    "pay-evm-erc20",
    "pay-solana-spl",
    "pay-cross-chain-htlc",
    "pay-cross-chain-liquidity-tank",
    "pay-ap2",
    "pay-x402",
    "pay-dem",
    "deliver-storage-program",
    "deliver-entitlement",
    "deliver-attested-payload",
})

PAYMENT_PHASES = frozenset(phase for phase in EVIDENCE_PHASES if phase.startswith("pay-"))
DELIVERY_PHASES = frozenset(phase for phase in EVIDENCE_PHASES if phase.startswith("deliver-"))
SUPPORTED_PHASES = frozenset({
    "vet-credentials",
    "negotiate-fixed-price",
    "negotiate-rfq",
    "negotiate-sealed-envelope",
    "commit-agreement",
    "rate",
}) | EVIDENCE_PHASES
ADDITIVE_COMMIT_PHASES = frozenset({
    "commit-payee-bound-agreement",
    "commit-identity-bound-agreement",
    "commit-identity-bound-payee-agreement",
})
SUPPORTED_ATTESTATION_ANCHOR_KINDS = frozenset({"storage-program", "ipfs", "https"})
SUPPORTED_SETTLEMENT_FINALITY_MODELS = frozenset({
    "block-depth",
    "commitment-level",
    "provider-receipt",
    "htlc-reveal",
    "liquidity-tank",
    "bft-final",
})

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
_CANONICAL_POSITIVE_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?\Z")
_MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991


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
    """CORE §B.2 RFC 8785/JCS bytes from the repository canonicalizer."""
    return jcs.canonicalize(value).encode("utf-8")


def bundle_hash(bundle):
    """§10.4.1 attestation_bundle_hash: canonical form minus signatures + anchoredByRole,
    computed identically for AttestationBundle and FaultAttestationBundle."""
    unsigned = {k: v for k, v in bundle.items() if k not in ("signatures", "anchoredByRole")}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def listing_hash(listing):
    """§6.3.4 listing hash: canonical form minus the signature envelope."""
    unsigned = {k: v for k, v in listing.items() if k != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def settlement_evidence_hash(record):
    """DACS-4 §9.7 evidence hash: canonical form minus its signature envelope."""
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def delivery_evidence_hash(record):
    """DACS-4 §9.7 DeliveryEvidence hash: canonical form minus its signature envelope."""
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def binding_hash(binding):
    unsigned = {k: v for k, v in binding.items() if k != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def pointer_hash(pointer):
    """FaultBundleExtendedPointer signed-scope hash (E7): canonical form minus signature."""
    unsigned = {k: v for k, v in pointer.items() if k != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


CURRENT_JOB_ID_RE = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}\Z", re.ASCII)
CURRENT_BUNDLE_ROLES = {"buyer", "seller", "orchestrator"}
AUTHORITATIVE_RELEASE_PIN = "0000000000000000000000000000000000000001"
AUTHORITATIVE_MODULE_VERSIONS = {
    "core": "0.3",
    "dacs1": "0.7",
    "dacs2": "0.6",
    "dacs3": "0.5",
    "dacs4": "0.8",
    "dacs5": "0.5",
}
AUTHORITATIVE_LOCAL_PROFILE = {
    "releasePin": AUTHORITATIVE_RELEASE_PIN,
    "moduleVersions": AUTHORITATIVE_MODULE_VERSIONS,
}


def trusted_role_authority(
        session_id, role, participant_identity, *, profile=None,
        authenticated=True):
    """Build one verifier-owned ``(session, role)`` authority record for tests."""
    return {
        "sessionId": session_id,
        "role": role,
        "participantIdentity": participant_identity,
        "authenticated": authenticated,
        "profile": AUTHORITATIVE_LOCAL_PROFILE if profile is None else profile,
    }


def trusted_query_authority(
        party, window_start, window_end, windowing_basis, *, profile=None,
        authenticated=True):
    """Build independent current reputation-query authority for tests."""
    return {
        "party": party,
        "windowStart": window_start,
        "windowEnd": window_end,
        "windowingBasis": windowing_basis,
        "authenticated": authenticated,
        "profile": AUTHORITATIVE_LOCAL_PROFILE if profile is None else profile,
    }


def trusted_entry_authority(
        content_hash, session_id, role, participant_identity, *,
        counterparty_disposition, counterparty_role,
        counterparty_participant_identity, counterparty_content_hash=None):
    """Build ordered authority for one resolution-context content reference."""
    return {
        "contentHash": content_hash,
        "sessionId": session_id,
        "role": role,
        "participantIdentity": participant_identity,
        "counterpartyDisposition": counterparty_disposition,
        "counterpartyRole": counterparty_role,
        "counterpartyParticipantIdentity": counterparty_participant_identity,
        "counterpartyContentHash": counterparty_content_hash,
    }


def trusted_current_context(role_map, *, query=None, entry_authorities=None):
    """Build closed current-operation authority; never initialize it from artifacts."""
    return {
        "roleMap": list(role_map),
        "query": query,
        "entryAuthorities": (
            [] if entry_authorities is None else list(entry_authorities)
        ),
    }


def trusted_profile_context(
        session_id, expected_peer_identity, *, role="buyer",
        participant_identity=None, profile=None, authenticated=True,
        duplicate=False):
    """Compatibility builder for a single verifier-owned role-map record.

    ``expected_peer_identity`` is retained as a test-helper argument only.  Public
    current admission selects by ``(session_id, role)`` and never by a caller or
    signed-record identity.
    """
    record = trusted_role_authority(
        session_id,
        role,
        (
            expected_peer_identity
            if participant_identity is None
            else participant_identity
        ),
        profile=profile,
        authenticated=authenticated,
    )
    role_map = [record]
    if duplicate:
        role_map.append(dict(record))
    return trusted_current_context(role_map)


def trusted_verification_keys(keys, *, authenticated=True):
    """Wrap a verifier-owned Ed25519 key map as independently authenticated input."""
    return {"authenticated": authenticated, "keys": dict(keys)}


def is_exact_corrective_profile(profile):
    """Require the exact corrective pin and complete closed module tuple."""
    return (
        isinstance(profile, dict)
        and set(profile) == {"releasePin", "moduleVersions"}
        and isinstance(profile.get("releasePin"), str)
        and profile["releasePin"] == AUTHORITATIVE_RELEASE_PIN
        and isinstance(profile.get("moduleVersions"), dict)
        and set(profile["moduleVersions"]) == set(AUTHORITATIVE_MODULE_VERSIONS)
        and all(isinstance(value, str) for value in profile["moduleVersions"].values())
        and profile["moduleVersions"] == AUTHORITATIVE_MODULE_VERSIONS
    )


def _current_context_shape_valid(trusted_context):
    if (
        not isinstance(trusted_context, dict)
        or set(trusted_context) != {"roleMap", "query", "entryAuthorities"}
        or not isinstance(trusted_context.get("roleMap"), list)
        or not isinstance(trusted_context.get("entryAuthorities"), list)
    ):
        return False
    for record in trusted_context["roleMap"]:
        if (
            not isinstance(record, dict)
            or set(record) != {
                "sessionId", "role", "participantIdentity", "authenticated",
                "profile",
            }
            or not isinstance(record.get("sessionId"), str)
            or not _string_member(record.get("role"), CURRENT_BUNDLE_ROLES)
            or not isinstance(record.get("participantIdentity"), str)
            or not record["participantIdentity"]
            or type(record.get("authenticated")) is not bool
            or not is_exact_corrective_profile(record.get("profile"))
        ):
            return False
    # Validate the whole map before selecting.  A malformed unrelated record or
    # duplicate role authority fails closed; one actor may still occupy multiple
    # independently authorized roles.
    role_keys = [
        (record["sessionId"], record["role"])
        for record in trusted_context["roleMap"]
    ]
    if len(role_keys) != len(set(role_keys)):
        return False
    query = trusted_context.get("query")
    if query is not None and (
        not isinstance(query, dict)
        or set(query) != {
            "party", "windowStart", "windowEnd", "windowingBasis",
            "authenticated", "profile",
        }
        or not isinstance(query.get("party"), str)
        or not query["party"]
        or not _non_boolean_number(query.get("windowStart"))
        or not _non_boolean_number(query.get("windowEnd"))
        or not _string_member(query.get("windowingBasis"), SUPPORTED_WINDOWING_BASES)
        or type(query.get("authenticated")) is not bool
        or not is_exact_corrective_profile(query.get("profile"))
    ):
        return False
    for authority in trusted_context["entryAuthorities"]:
        if (
            not isinstance(authority, dict)
            or set(authority) != {
                "contentHash", "sessionId", "role", "participantIdentity",
                "counterpartyDisposition", "counterpartyRole",
                "counterpartyParticipantIdentity", "counterpartyContentHash",
            }
            or not _sha256_hex(authority.get("contentHash"))
            or not isinstance(authority.get("sessionId"), str)
            or not _string_member(authority.get("role"), CURRENT_BUNDLE_ROLES)
            or not isinstance(authority.get("participantIdentity"), str)
            or not authority["participantIdentity"]
            or not _string_member(authority.get("counterpartyDisposition"), {"present", "absent"})
            or not _string_member(authority.get("counterpartyRole"), CURRENT_BUNDLE_ROLES)
            or not isinstance(authority.get("counterpartyParticipantIdentity"), str)
            or not authority["counterpartyParticipantIdentity"]
            or (
                authority["counterpartyDisposition"] == "present"
                and not _sha256_hex(authority.get("counterpartyContentHash"))
            )
            or (
                authority["counterpartyDisposition"] == "absent"
                and authority.get("counterpartyContentHash") is not None
            )
        ):
            return False
    entry_keys = [
        (authority["contentHash"], authority["role"])
        for authority in trusted_context["entryAuthorities"]
    ]
    return len(entry_keys) == len(set(entry_keys))


def resolve_current_profile(session_id, role, trusted_context):
    """Resolve one exact authenticated role holder from verifier-owned authority."""
    if (
        not isinstance(session_id, str)
        or not _string_member(role, CURRENT_BUNDLE_ROLES)
        or not _current_context_shape_valid(trusted_context)
        or not is_exact_corrective_profile(AUTHORITATIVE_LOCAL_PROFILE)
    ):
        return None
    matches = [
        record
        for record in trusted_context["roleMap"]
        if record["sessionId"] == session_id and record["role"] == role
    ]
    if len(matches) != 1 or matches[0]["authenticated"] is not True:
        return None
    return matches[0]["participantIdentity"]


def admits_current_profile(session_id, role, trusted_context):
    """CORE §11.1.2 admission by ``(session, role)``, never artifact signer."""
    return resolve_current_profile(session_id, role, trusted_context) is not None


def _authenticated_current_key_map(key_authority):
    """Return raw Ed25519 keys only from a closed authenticated local authority."""
    if (
        not HAVE_CRYPTO
        or not isinstance(key_authority, dict)
        or set(key_authority) != {"authenticated", "keys"}
        or key_authority.get("authenticated") is not True
        or not isinstance(key_authority.get("keys"), dict)
    ):
        return None
    keys = key_authority["keys"]
    if not keys or any(
        not isinstance(identity, str)
        or not identity
        or not isinstance(key, bytes)
        or len(key) != 32
        for identity, key in keys.items()
    ):
        return None
    return keys


def validate_current_job_id(job_id):
    """Apply CORE JID-1 before any current-profile derivation."""
    if not isinstance(job_id, str) or CURRENT_JOB_ID_RE.fullmatch(job_id) is None:
        raise ValueError("job-id-validation")
    return job_id


def _current_logical_address(job_id, role):
    """Internal derivation; a current public entry point gates before calling it."""
    validated = validate_current_job_id(job_id)
    if role not in CURRENT_BUNDLE_ROLES:
        raise ValueError("role-validation")
    preimage = validated.encode("ascii") + b"-bundle-" + role.encode("ascii")
    return "stor-" + hashlib.sha256(preimage).hexdigest()


def logical_address(job_id, role, *, participant_identity=None,
                    trusted_contexts=None):
    """Derive current address after role-map admission; caller identity is inert."""
    if not admits_current_profile(job_id, role, trusted_contexts):
        raise ValueError("current-profile-admission")
    return _current_logical_address(job_id, role)


def legacy_logical_address(job_id, role):
    """Frozen pre-JID-1 fixture derivation; never current lookup/action authority."""
    if not isinstance(job_id, str) or not isinstance(role, str):
        raise ValueError("legacy-address-input")
    return "stor-" + hashlib.sha256((job_id + "-bundle-" + role).encode("utf-8")).hexdigest()


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def bundle_type(bundle):
    """Return the syntactic supported §10.4 selector, or ``None``.

    This helper does not admit an untrusted record.  Consumers authenticate a fixed
    protocol operation or signing domain first, then require this selector to agree.
    Unknown members remain inert and hash-bound under SIG-5; suffix spelling alone does
    not turn one into a selector known by this pinned reader.
    """
    if not isinstance(bundle, dict):
        return None
    present = [
        family
        for family, selector in _BUNDLE_SELECTOR_BY_FAMILY.items()
        if selector in bundle
    ]
    if len(present) != 1:
        return None
    family = present[0]
    selector = _BUNDLE_SELECTOR_BY_FAMILY[family]
    return family if bundle.get(selector) == "1" else None


def _full_bundle_family_shape_valid(bundle, family):
    """Apply one internally selected full-bundle family boundary.

    ``family`` is supplied only by a fixed protocol operation or an authenticated
    signature-domain probe.  It is never copied from a record or caller label.
    """
    if family not in _BUNDLE_SELECTOR_BY_FAMILY or not isinstance(bundle, dict):
        return False
    if bundle_type(bundle) != family:
        return False
    # ``pointerKind`` is a recognized pointer-family member, not an inert extension.
    # A pointer therefore cannot be promoted merely because it shares a version literal.
    return "pointerKind" not in bundle


def bundle_type_rank(bundle):
    return {"legacy": 0, "fault": 1, "evidence-bound": 2}.get(bundle_type(bundle), -1)


def bundle_domain(bundle):
    """Syntactic convenience for already-admitted records; not an admission API."""
    kind = bundle_type(bundle)
    if kind in _BUNDLE_DOMAIN_BY_FAMILY:
        return _BUNDLE_DOMAIN_BY_FAMILY[kind]
    raise ValueError("unsupported, missing, or non-exclusive bundle discriminator")


def verify_sig(pubkey_bytes, domain, content_hash, sig_value):
    """crypto-gated ed25519 verify over `domain || content_hash`. Returns True/False;
    raises RuntimeError if called without `cryptography` (callers gate on HAVE_CRYPTO)."""
    if not HAVE_CRYPTO:  # pragma: no cover
        raise RuntimeError("verify_sig requires the cryptography package")
    payload = (domain + content_hash).encode("utf-8")
    try:
        Ed25519PublicKey.from_public_bytes(pubkey_bytes).verify(b64url_decode(sig_value), payload)
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False


def _verify_binding(binding, pubkeys, *, expected_jobid, expected_role,
                    expected_content_hash=None, expected_signer=None,
                    address_deriver):
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
    when raw `pubkeys` are provided and HAVE_CRYPTO. Public current callers have already passed
    authenticated-key admission and therefore always take this branch; only explicitly named legacy
    helpers may supply ``None`` for frozen structural replay. Under the crypto gate the signature passes F3
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
    if expected_signer is not None and binding.get("signer") != expected_signer:
        return {"ok": False, "reason": "BB-5: binding.signer != authenticated participant"}
    try:
        expected_address = address_deriver(binding.get("jobId"), binding.get("role"))
    except ValueError as exc:
        return {"ok": False, "reason": "BB-5 check 5: %s" % (exc,)}
    if binding.get("logicalAddress") != expected_address:
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


def verify_binding(binding, pubkeys, *, expected_jobid, expected_role,
                   expected_content_hash=None, participant_identity=None,
                   trusted_contexts=None):
    """Verify current BB-5 after role and authenticated-key admission.

    ``participant_identity`` remains accepted for call compatibility but is not
    authority: the expected signer comes only from the verifier-owned role map.
    """
    expected_signer = resolve_current_profile(
        expected_jobid, expected_role, trusted_contexts
    )
    if expected_signer is None:
        return {"ok": False, "reason": "current-profile-admission"}
    keys = _authenticated_current_key_map(pubkeys)
    if keys is None:
        return {"ok": False, "reason": "current-crypto-admission"}
    return _verify_binding(
        binding,
        keys,
        expected_jobid=expected_jobid,
        expected_role=expected_role,
        expected_content_hash=expected_content_hash,
        expected_signer=expected_signer,
        address_deriver=_current_logical_address,
    )


def verify_legacy_binding(binding, pubkeys, *, expected_jobid, expected_role,
                          expected_content_hash=None):
    """Replay only the frozen pre-JID-1 corpus; never current action authority."""
    return _verify_binding(
        binding,
        pubkeys,
        expected_jobid=expected_jobid,
        expected_role=expected_role,
        expected_content_hash=expected_content_hash,
        address_deriver=legacy_logical_address,
    )


def is_fab(bundle):
    """True for either absolute-fault type (FAB or EBFAB)."""
    return bundle_type(bundle) in {"fault", "evidence-bound"}


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
    """§10.5.1 legacy-only single-copy scoring map. Buyer<->seller involution;
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


def common_fault_set(copy_a, copy_b):
    """Return the absolute faults both authenticated copies can describe.

    Each legacy copy derives its permissible set from its own signed parties[]
    roster. A counterparty roster must never enlarge the other copy's claim.
    """
    a_fab, b_fab = is_fab(copy_a), is_fab(copy_b)
    if a_fab and b_fab:
        a_fault, b_fault = _fab_faulted(copy_a), _fab_faulted(copy_b)
        return {a_fault} if a_fault == b_fault else set()
    if not a_fab and not b_fab:
        a_faults = implied_fault_set(
            copy_a["outcome"], copy_a["anchoredByRole"], roster_roles(copy_a))
        b_faults = implied_fault_set(
            copy_b["outcome"], copy_b["anchoredByRole"], roster_roles(copy_b))
        return a_faults & b_faults
    fab, legacy = (copy_a, copy_b) if a_fab else (copy_b, copy_a)
    legacy_faults = implied_fault_set(
        legacy["outcome"], legacy["anchoredByRole"], roster_roles(legacy))
    return {_fab_faulted(fab)} & legacy_faults


def divergence(copy_a, copy_b):
    """§10.4.3 single divergence definition as amended by E1/E4. Returns True iff the
    pair canonically diverges. Classifies the pair by type:

      FAB pair    -> faultedParty contradiction OR outcome-class contradiction OR phaseSummary
      legacy pair -> compare both implied-fault SETs; disjoint sets diverge (E1)
      mixed pair  -> the FAB.faultedParty must be a MEMBER of the legacy copy's
                     implied-fault SET; non-membership OR outcome-class OR phaseSummary (E4)
    """
    if _phase_summary_diverges(copy_a, copy_b):
        return True
    if _outcome_class(copy_a["outcome"]) != _outcome_class(copy_b["outcome"]):
        return True

    if bundle_type(copy_a) == bundle_type(copy_b) == "evidence-bound":
        refs_a = {canonical(ref) for ref in copy_a.get("settlementEvidence", [])}
        refs_b = {canonical(ref) for ref in copy_b.get("settlementEvidence", [])}
        if refs_a != refs_b:
            return True

    a_fab, b_fab = is_fab(copy_a), is_fab(copy_b)

    if a_fab and b_fab:
        # FAB pair: absolute faultedParty must agree (outcome class already checked).
        return not common_fault_set(copy_a, copy_b)

    if not a_fab and not b_fab:
        # Legacy pair (E1): both role-relative residuals map to implied-fault sets.
        # A non-empty intersection means the assertions can describe the same event.
        return not common_fault_set(copy_a, copy_b)

    # Mixed pair (E4): the FAB.faultedParty must be a member of the legacy implied set.
    return not common_fault_set(copy_a, copy_b)


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


def _bundle_signatures_valid_for_family(bundle, pubkeys, family):
    """§10.4.1 bundle signature validity + required-signer, applied IDENTICALLY to both bundle types
    (round-10; AttestationBundle and FaultAttestationBundle). The required-signer set is
    OUTCOME-DEPENDENT (spec DACS-5 §10.4.1 lines 318-323, :475/:798): a non-abort outcome
    (completed / failed-perm / failed-counterparty / failed-substrate) requires buyer + seller
    (+ distinct orchestrator) all signed; an abort outcome (aborted-by-*) MAY be single-signed and is
    floored on the anchoring role-holder. Then EVERY carried signature entry (the RAW list, duplicates
    included) is checked in order — F3 algorithm-label dispatch (SUPPORTED_SIGNATURE_ALGORITHMS) ->
    F4 SIG-6 canonical value (sig6_canonical, BEFORE verify) -> F2 ed25519 verification of each entry.
    Signature checks use raw keys supplied by the enclosing verifier. Current public entry points
    admit authenticated keys first; named legacy helpers may retain structural-only replay.
    Returns (ok, reason)."""
    if not isinstance(bundle, dict):
        return (False, "bundle is not an object")
    if not _full_bundle_family_shape_valid(bundle, family):
        return (False, "full-bundle selector does not match authenticated family context")
    parties = bundle.get("parties")
    raw_sigs = bundle.get("signatures")
    if (
        not isinstance(parties, list)
        or any(
            not isinstance(party, dict)
            or not isinstance(party.get("role"), str)
            or not isinstance(party.get("primaryClaim"), str)
            for party in parties
        )
    ):
        return (False, "bundle parties are malformed")
    if (
        not isinstance(raw_sigs, list)
        or any(
            not isinstance(signature, dict)
            or not isinstance(signature.get("party"), str)
            for signature in raw_sigs
        )
    ):
        return (False, "bundle signatures are malformed")
    anchor_role = bundle.get("anchoredByRole")
    role_holder = {p.get("role"): p.get("primaryClaim") for p in parties}
    # Keep the RAW list for verification: a party-keyed dict would silently
    # discard all but the last duplicate signature.
    signers_present = {s.get("party") for s in raw_sigs}

    # F1 required-signer set (§10.4.1 verification-and-signer rules, DACS-5 lines 318-323), applied
    # TYPE-AGNOSTICALLY to both AttestationBundle and FaultAttestationBundle (spec :475/:798: the
    # single-signed non-abort rejection is not type-specific; the outcome enum is common to both):
    #   non-abort outcome (completed / failed-perm / failed-counterparty / failed-substrate)  =>
    #     buyer + seller (+ distinct orchestrator) MUST all have signed (spec line 322);
    #   abort outcome (aborted-by-self / aborted-by-other) MAY be single-signed (spec line 323) — the
    #     preserved floor is that the anchoring role-holder itself has signed.
    if _string_member(bundle.get("outcome"), _ABORT):
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
        dom = _BUNDLE_DOMAIN_BY_FAMILY[family]
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


def _authenticated_bundle_signature_family(bundle, pubkeys):
    """Recover the full-bundle family from cryptographically verified domain use.

    The selector is deliberately not consulted during this probe.  Only after exactly
    one registered full-bundle domain verifies does the caller compare the selector and
    schema, so changing an unauthenticated label cannot select a family or domain.
    """
    if not isinstance(bundle, dict) or not isinstance(pubkeys, dict) or not HAVE_CRYPTO:
        return None
    signatures = bundle.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return None
    try:
        content_hash = bundle_hash(bundle)
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        return None
    candidates = []
    for family, domain in _BUNDLE_DOMAIN_BY_FAMILY.items():
        valid = True
        for signature in signatures:
            if not isinstance(signature, dict):
                valid = False
                break
            party = signature.get("party")
            value = signature.get("value")
            canonical_ok, _ = sig6_canonical(value)
            if (
                not isinstance(party, str)
                or signature.get("algorithm") not in SUPPORTED_SIGNATURE_ALGORITHMS
                or not canonical_ok
                or party not in pubkeys
                or not verify_sig(pubkeys[party], domain, content_hash, value)
            ):
                valid = False
                break
        if valid:
            candidates.append(family)
    return candidates[0] if len(candidates) == 1 else None


def _syntactic_bundle_family(bundle, _pubkeys):
    """Resolve an archival family from the released structural selector only."""
    return bundle_type(bundle)


def _current_bundle_validation(bundle, pubkeys, family):
    """Validate a bundle after its family was authenticated from signature use."""
    if _authenticated_bundle_signature_family(bundle, pubkeys) != family:
        return (False, "full-bundle family cannot be authenticated before parsing")
    return _bundle_signatures_valid_for_family(bundle, pubkeys, family)


def _legacy_bundle_validation(bundle, pubkeys, family):
    """Frozen structural validation, with cryptography when legacy keys are supplied."""
    return _bundle_signatures_valid_for_family(bundle, pubkeys, family)


def _current_family_refusal(subject):
    return "%s family cannot be authenticated before parsing" % subject


def _legacy_family_refusal(subject):
    return "%s has an unsupported bundle type" % subject


def _bundle_signatures_valid(bundle, pubkeys):
    """Admit a generic full-bundle read only with authenticated family context."""
    family = _authenticated_bundle_signature_family(bundle, pubkeys)
    if family is None:
        return (False, "full-bundle family cannot be authenticated before parsing")
    return _bundle_signatures_valid_for_family(bundle, pubkeys, family)


def _validate_current_evidence_receipt(receipt, expected_nonce, *, expected_state=None):
    """Validate the current CORE AnchorReceipt contract used by SEB admission."""
    transaction_ref = receipt.get("transactionRef")
    evidence = receipt.get("evidence")
    block_ref = receipt.get("blockRef")
    nonce = receipt.get("nonce")
    observed_at = receipt.get("observedAt")
    if not (
        receipt.get("receiptVersion") == "1"
        and _nonempty_jcs_string(receipt.get("substrate"))
        and _nonempty_jcs_string(receipt.get("finalityProfile"))
        and isinstance(transaction_ref, dict)
        and set(transaction_ref) == {"kind", "value"}
        and _nonempty_jcs_string(transaction_ref.get("kind"))
        and _nonempty_jcs_string(transaction_ref.get("value"))
        and (nonce is None or _nonempty_jcs_string(nonce))
        and _string_member(receipt.get("state"), {"included", "finalized"})
        and receipt.get("observationDisposition") == "established"
        and _non_boolean_number(observed_at)
        and isinstance(block_ref, dict)
        and _nonempty_jcs_string(block_ref.get("id"))
        and isinstance(evidence, dict)
        and set(evidence) == {"kind", "value"}
        and _nonempty_jcs_string(evidence.get("kind"))
        and _nonempty_jcs_string(evidence.get("value"))
    ):
        return (False, "anchor receipt is malformed or lacks authenticated lifecycle evidence")
    if expected_nonce is not None and (
        not _nonempty_jcs_string(expected_nonce) or nonce != expected_nonce
    ):
        return (False, "anchor receipt nonce does not match execution authority")
    if expected_state is not None and receipt.get("state") != expected_state:
        return (False, "anchor receipt state contradicts authenticated lifecycle")
    return (True, "ok")


def _validate_legacy_evidence_receipt(receipt, expected_nonce, *, expected_state=None):
    """Validate only the frozen pre-SR-2 receipt shape used by archival fixtures."""
    nonce = receipt.get("nonce")
    if (
        not _nonempty_jcs_string(receipt.get("transaction"))
        or not (
            _nonempty_jcs_string(nonce)
            or _safe_nonnegative_integer(nonce)
        )
        or (expected_nonce is not None and nonce != expected_nonce)
    ):
        return (False, "historical anchor receipt transaction or nonce is malformed")
    return (True, "ok")


def _validate_evidence_resolution_binding(ref, execution, receipt, bundle, phase_index,
                                          phase_kind, signer, *, resolved=False,
                                          current_delivery=False,
                                          receipt_validator=_validate_current_evidence_receipt):
    """Validate independently authenticated execution authority against a verified receipt."""
    if not isinstance(execution, dict) or not isinstance(receipt, dict):
        return (False, "missing executionAuthority or anchorReceipt binding")
    if (
        execution.get("jobId") != bundle.get("jobId")
        or execution.get("phaseIndex") != phase_index
        or execution.get("phaseKind") != phase_kind
        or execution.get("phaseOrchestrator") != signer
    ):
        return (False, "execution authority does not bind job, phase, or orchestrator")
    if phase_kind.startswith("pay-"):
        rail_id = execution.get("railId")
        if not isinstance(rail_id, str) or not rail_id:
            return (False, "payment execution authority lacks railId")
        expected_logical = "dacs4:payment:%s:%s:%d%s" % (
            bundle.get("jobId"), quote(rail_id, safe="-._~"), phase_index,
            ":resolved" if resolved else "",
        )
    elif current_delivery:
        expected_logical = "dacs4:delivery:%s:%d" % (bundle.get("jobId"), phase_index)
    else:
        expected_logical = execution.get("evidenceLogicalAddress")
        if not isinstance(expected_logical, str) or not expected_logical:
            return (False, "legacy delivery execution authority lacks evidenceLogicalAddress")
    anchor = ref.get("anchor") if isinstance(ref, dict) else None
    expected_nonce = execution.get("anchorNonce")
    receipt_ok, receipt_reason = receipt_validator(receipt, expected_nonce)
    if not receipt_ok:
        return (False, receipt_reason)
    if (
        receipt.get("logicalAddress") != expected_logical
        or not isinstance(anchor, dict)
        or receipt.get("nativeAddress") != anchor.get("locator")
        or receipt.get("contentHash") != ref.get("contentHash")
        or receipt.get("writer") != signer
    ):
        return (False, "anchor receipt does not bind address, content, transaction, writer, or nonce")
    return (True, expected_logical)


def _string_member(value, allowed):
    """Total closed-union membership for untrusted JSON values."""
    return isinstance(value, str) and value in allowed


def _non_boolean_number(value):
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return abs(value) <= _MAX_SAFE_JSON_INTEGER
    return (
        isinstance(value, float)
        and math.isfinite(value)
        and abs(value) <= _MAX_SAFE_JSON_INTEGER
    )


def _price_term_shape_valid(value):
    if not isinstance(value, dict) or not {"amount", "currency"} <= set(value):
        return False
    if set(value) - {"amount", "currency", "unit"}:
        return False
    amount = value.get("amount")
    currency = value.get("currency")
    if not isinstance(amount, str) or not _nonempty_jcs_string(currency):
        return False
    if "unit" in value and not isinstance(value["unit"], str):
        return False
    # CORE CD-1 plus PriceTerm's positive-amount requirement, ASCII digits only.
    return amount != "0" and _CANONICAL_POSITIVE_DECIMAL.fullmatch(amount) is not None


def _nonempty_jcs_string(value):
    return (
        isinstance(value, str)
        and bool(value)
        and unicodedata.normalize("NFC", value) == value
        and not any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    )


def _safe_nonnegative_integer(value, *, positive=False):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and (value > 0 if positive else value >= 0)
        and value <= _MAX_SAFE_JSON_INTEGER
    )


def _chain_tx_ref_shape_valid(ref):
    """Closed DACS-4 ChainTxRef union, including nested AP2 attestation shape."""
    if not isinstance(ref, dict) or not isinstance(ref.get("kind"), str):
        return False
    kind = ref["kind"]
    string_fields = set()
    integer_fields = set()
    optional_strings = set()
    optional_integers = set()
    required = {"kind"}
    optional = set()

    if kind == "evm":
        integer_fields = {"chainId"}
        string_fields = {"txHash"}
    elif kind == "evm-event":
        integer_fields = {"chainId", "logIndex"}
        string_fields = {"txHash"}
    elif kind == "solana":
        string_fields = {"cluster", "signature"}
    elif kind == "solana-instruction":
        string_fields = {"cluster", "signature"}
        integer_fields = {"instructionIndex"}
    elif kind == "demos":
        string_fields = {"txHash"}
        optional_integers = {"blockNumber"}
    elif kind == "storage-program":
        string_fields = {"address", "writeTxHash"}
    elif kind == "ap2":
        string_fields = {"mandateId", "providerRef", "protocolVersion"}
        optional = {"receiptAttestation"}
    elif kind == "x402":
        string_fields = {"httpResource", "paymentReceiptHash", "protocolVersion"}
        optional_strings = {"settlementTxHash"}
        optional_integers = {"chainId"}
    elif kind == "x402-event":
        string_fields = {
            "httpResource", "paymentReceiptHash", "settlementTxHash", "protocolVersion",
        }
        integer_fields = {"chainId", "logIndex"}
    elif kind in {"htlc-lock", "htlc-reveal", "htlc-claim", "htlc-refund"}:
        integer_fields = {"chainId"}
        transaction_field = {
            "htlc-lock": "lockTxHash",
            "htlc-reveal": "revealTxHash",
            "htlc-claim": "claimTxHash",
            "htlc-refund": "refundTxHash",
        }[kind]
        string_fields = {"contractAddress", transaction_field}
    elif kind == "liquidity-tank":
        string_fields = {"bridgeId", "lockTxHash"}
        integer_fields = {"sourceChainId", "destChainId"}
        optional_strings = {"releaseTxHash"}
        optional_integers = {"recoveryDeadline"}
    else:
        return False

    required |= string_fields | integer_fields
    optional |= optional_strings | optional_integers
    if set(ref) != required | (set(ref) & optional):
        return False
    if any(not _nonempty_jcs_string(ref[field]) for field in string_fields):
        return False
    if any(not _safe_nonnegative_integer(ref[field]) for field in integer_fields):
        return False
    if any(not _nonempty_jcs_string(ref[field]) for field in optional_strings if field in ref):
        return False
    if any(not _safe_nonnegative_integer(ref[field]) for field in optional_integers if field in ref):
        return False
    if kind in {"evm", "evm-event", "x402-event"} and not _safe_nonnegative_integer(
        ref["chainId"], positive=True
    ):
        return False
    if kind in {"solana", "solana-instruction"} and not _string_member(
        ref["cluster"], {"mainnet", "devnet", "testnet"}
    ):
        return False
    if kind == "ap2" and "receiptAttestation" in ref:
        return _attestation_ref_shape_valid(ref["receiptAttestation"])
    return True


def _payment_tx_refs_match_phase(phase, refs, *, success):
    kinds = [ref["kind"] for ref in refs]
    if phase == "pay-evm-erc20":
        return len(kinds) == 1 and kinds[0] in {"evm-event", "evm"}
    if phase == "pay-solana-spl":
        return len(kinds) == 1 and kinds[0] in {"solana-instruction", "solana"}
    if phase == "pay-cross-chain-htlc":
        required = {"htlc-lock", "htlc-reveal", "htlc-claim"}
        if success:
            return set(kinds) == required and len(kinds) == len(required)
        return (
            len(kinds) == len(set(kinds))
            and set(kinds) <= required | {"htlc-refund"}
        )
    if phase == "pay-cross-chain-liquidity-tank":
        return len(kinds) == 1 and kinds[0] == "liquidity-tank" and (
            not success or "releaseTxHash" in refs[0]
        )
    if phase == "pay-ap2":
        return len(kinds) == 1 and kinds[0] == "ap2" and (
            not success or "receiptAttestation" in refs[0]
        )
    if phase == "pay-x402":
        return len(kinds) == 1 and kinds[0] in {"x402-event", "x402"}
    if phase == "pay-dem":
        return len(kinds) == 1 and kinds[0] == "demos" and (
            not success or "blockNumber" in refs[0]
        )
    return False


def _settlement_finality_matches_phase(phase, finality, refs):
    allowed = {
        "pay-evm-erc20": {"block-depth"},
        "pay-solana-spl": {"commitment-level"},
        "pay-cross-chain-htlc": {"htlc-reveal"},
        "pay-cross-chain-liquidity-tank": {"liquidity-tank"},
        "pay-ap2": {"provider-receipt"},
        "pay-dem": {"bft-final"},
    }
    if phase == "pay-x402":
        return (
            len(refs) == 1
            and (
                (refs[0]["kind"] == "x402-event" and finality.get("model") == "block-depth")
                or (refs[0]["kind"] == "x402" and finality.get("model") == "provider-receipt")
            )
        )
    return _string_member(finality.get("model"), allowed.get(phase, set()))


def _settlement_finality_shape_valid(value):
    if not isinstance(value, dict):
        return False
    allowed = {
        "model", "finalityBlocks", "finalityCommitmentLevel", "finalityObservedAt",
    }
    if set(value) - allowed:
        return False
    model = value.get("model")
    if (
        not _string_member(model, SUPPORTED_SETTLEMENT_FINALITY_MODELS)
        or not _non_boolean_number(value.get("finalityObservedAt"))
    ):
        return False
    if model == "block-depth":
        blocks = value.get("finalityBlocks")
        if (
            isinstance(blocks, bool)
            or not isinstance(blocks, int)
            or blocks < 0
            or blocks > _MAX_SAFE_JSON_INTEGER
        ):
            return False
    elif "finalityBlocks" in value:
        return False
    if model == "commitment-level":
        if not _string_member(
            value.get("finalityCommitmentLevel"), {"processed", "confirmed", "finalized"}
        ):
            return False
    elif "finalityCommitmentLevel" in value:
        return False
    return True


def _settlement_evidence_shape_valid(record):
    """Closed DACS-4 §9.7 shape and phase/outcome-conditional requirements."""
    if not isinstance(record, dict):
        return False
    required = {"evidenceVersion", "jobId", "phase", "outcome", "observedAt", "signature"}
    optional = {
        "reason", "paymentTxRefs", "paymentAmount", "paymentFee",
        "deliverableContentHash", "deliverableAnchor", "attestationRef",
        "settlementFinality", "amendmentRefs", "supersedesEvidenceRef",
    }
    if not required <= set(record) or set(record) - required - optional:
        return False
    phase = record.get("phase")
    outcome = record.get("outcome")
    signature = record.get("signature")
    if (
        record.get("evidenceVersion") != "1"
        or not _nonempty_jcs_string(record.get("jobId"))
        or not _string_member(phase, EVIDENCE_PHASES)
        or not _string_member(outcome, {"success", "failure"})
        or not _non_boolean_number(record.get("observedAt"))
        or not isinstance(signature, dict)
        or set(signature) != {"algorithm", "signer", "value"}
        or not _nonempty_jcs_string(signature.get("algorithm"))
        or not _claim_reference_shape_valid(signature.get("signer"))
        or not _nonempty_jcs_string(signature.get("value"))
    ):
        return False
    if outcome == "failure":
        if not _nonempty_jcs_string(record.get("reason")):
            return False
    elif "reason" in record:
        return False
    for field in ("paymentAmount", "paymentFee"):
        if field in record and not _price_term_shape_valid(record[field]):
            return False
    if "paymentTxRefs" in record and (
        not isinstance(record["paymentTxRefs"], list)
        or any(not _chain_tx_ref_shape_valid(ref) for ref in record["paymentTxRefs"])
        or not _payment_tx_refs_match_phase(
            phase, record["paymentTxRefs"], success=outcome == "success"
        )
    ):
        return False
    if "deliverableContentHash" in record and not _sha256_hex(record["deliverableContentHash"]):
        return False
    if "deliverableAnchor" in record:
        anchor = record["deliverableAnchor"]
        # DACS-4 §9.7 deliberately types deliverableAnchor.kind as string. Only the
        # storage-program phase narrows it below; AttestationRef's closed anchor
        # union is a distinct type and must not be projected onto payload locations.
        if (
            not isinstance(anchor, dict)
            or set(anchor) != {"kind", "locator"}
            or not _nonempty_jcs_string(anchor.get("kind"))
            or not _nonempty_jcs_string(anchor.get("locator"))
        ):
            return False
    if "attestationRef" in record and not _attestation_ref_shape_valid(record["attestationRef"]):
        return False
    if "amendmentRefs" in record and (
        not isinstance(record["amendmentRefs"], list)
        or any(not _attestation_ref_shape_valid(ref) for ref in record["amendmentRefs"])
    ):
        return False
    if "supersedesEvidenceRef" in record and not _attestation_ref_shape_valid(
        record["supersedesEvidenceRef"]
    ):
        return False
    if phase in PAYMENT_PHASES:
        if outcome == "success" and (
            not isinstance(record.get("paymentTxRefs"), list)
            or not record["paymentTxRefs"]
            or not _price_term_shape_valid(record.get("paymentAmount"))
            or not _settlement_finality_shape_valid(record.get("settlementFinality"))
            or not _settlement_finality_matches_phase(
                phase, record["settlementFinality"], record["paymentTxRefs"]
            )
        ):
            return False
        if outcome == "failure" and "settlementFinality" in record:
            return False
        if any(field in record for field in ("deliverableContentHash", "deliverableAnchor", "attestationRef")):
            return False
    else:
        if any(
            field in record
            for field in ("paymentTxRefs", "settlementFinality", "paymentAmount", "paymentFee")
        ):
            return False
        if outcome == "success" and not _sha256_hex(record.get("deliverableContentHash")):
            return False
        if phase == "deliver-storage-program" and outcome == "success" and (
            not isinstance(record.get("deliverableAnchor"), dict)
            or record["deliverableAnchor"].get("kind") != "storage-program"
        ):
            return False
        if phase == "deliver-attested-payload" and outcome == "success" and (
            "deliverableAnchor" not in record or not _attestation_ref_shape_valid(record.get("attestationRef"))
        ):
            return False
    return True


def _delivery_phase_optional_fields_compatible(record):
    """Reject fields that belong to a different delivery family for every outcome."""
    if not isinstance(record, dict):
        return False
    incompatible = {
        "deliver-storage-program": {"attestationRef", "credentialDelivery"},
        "deliver-entitlement": {"attestationRef"},
        "deliver-attested-payload": {"credentialDelivery"},
    }
    fields = incompatible.get(record.get("phase"))
    return fields is not None and not fields.intersection(record)


def _delivery_evidence_shape_valid(
    record, *, enforce_phase_fields=True, enforce_success_closure=True
):
    """Closed current DACS-4 §9.7 DeliveryEvidence wire shape."""
    if not isinstance(record, dict):
        return False
    required = {
        "deliveryEvidenceVersion", "jobId", "phaseIndex", "phase", "outcome",
        "observedAt", "signature",
    }
    optional = {
        "reason", "deliverableContentHash", "deliverableAnchor", "attestationRef",
        "credentialDelivery",
    }
    if not required <= set(record) or set(record) - required - optional:
        return False
    phase_index = record.get("phaseIndex")
    phase = record.get("phase")
    outcome = record.get("outcome")
    signature = record.get("signature")
    if (
        record.get("deliveryEvidenceVersion") != "1"
        or "evidenceVersion" in record
        or not _nonempty_jcs_string(record.get("jobId"))
        or isinstance(phase_index, bool)
        or not isinstance(phase_index, int)
        or phase_index < 0
        or phase_index > _MAX_SAFE_JSON_INTEGER
        or not _string_member(phase, DELIVERY_PHASES)
        or not _string_member(outcome, {"success", "failure"})
        or not _non_boolean_number(record.get("observedAt"))
        or not isinstance(signature, dict)
        or set(signature) != {"algorithm", "signer", "value"}
        or not _nonempty_jcs_string(signature.get("algorithm"))
        or not _claim_reference_shape_valid(signature.get("signer"))
        or not _nonempty_jcs_string(signature.get("value"))
    ):
        return False
    if outcome == "failure":
        if not _nonempty_jcs_string(record.get("reason")):
            return False
    elif "reason" in record:
        return False
    if "deliverableContentHash" in record and not _sha256_hex(record["deliverableContentHash"]):
        return False
    if "deliverableAnchor" in record:
        anchor = record["deliverableAnchor"]
        if (
            not isinstance(anchor, dict)
            or set(anchor) != {"kind", "locator"}
            or not _nonempty_jcs_string(anchor.get("kind"))
            or not _nonempty_jcs_string(anchor.get("locator"))
        ):
            return False
    if "attestationRef" in record and not _attestation_ref_shape_valid(record["attestationRef"]):
        return False
    if "credentialDelivery" in record:
        binding = record["credentialDelivery"]
        credential_ref = binding.get("credentialRef") if isinstance(binding, dict) else None
        renewal_seq = binding.get("renewalSeq") if isinstance(binding, dict) else None
        if (
            not isinstance(binding, dict)
            or set(binding) != {"credentialRef", "credentialCleartextHash", "renewalSeq"}
            or not isinstance(credential_ref, dict)
            or set(credential_ref) != {"ref", "accessModel"}
            or not _attestation_ref_shape_valid(credential_ref.get("ref"))
            or not _string_member(
                credential_ref.get("accessModel"), {"buyer-only", "encrypt-to-buyer"}
            )
            or not _sha256_hex(binding.get("credentialCleartextHash"))
            or isinstance(renewal_seq, bool)
            or not isinstance(renewal_seq, int)
            or renewal_seq < 0
            or renewal_seq > _MAX_SAFE_JSON_INTEGER
        ):
            return False
    if outcome == "success" and enforce_success_closure:
        if (
            not _sha256_hex(record.get("deliverableContentHash"))
            or not isinstance(record.get("deliverableAnchor"), dict)
        ):
            return False
        if phase == "deliver-attested-payload":
            if not _attestation_ref_shape_valid(record.get("attestationRef")):
                return False
        elif "attestationRef" in record:
            return False
        if phase != "deliver-entitlement" and "credentialDelivery" in record:
            return False
    return (
        not enforce_phase_fields
        or _delivery_phase_optional_fields_compatible(record)
    )


def _payload_attestation_record_shape_valid(record):
    """Validate the DACS-4 base shape while preserving signed minor extensions."""
    if not isinstance(record, dict):
        return False
    required = {
        "payloadAttestationVersion", "jobId", "agreementHash",
        "deliverableSpecHash", "payloadFormat", "payloadContentHash",
        "verificationMethod", "verificationMethodHash", "attempt", "decision",
        "reason", "verifiedAt", "signature",
    }
    if not required <= set(record):
        return False
    if not _delivery_inner_type_valid(record, "payloadAttestationVersion"):
        return False
    if any(
        not _nonempty_jcs_string(record.get(field))
        for field in ("jobId", "payloadFormat", "verificationMethod", "reason")
    ):
        return False
    if any(
        not _sha256_hex(record.get(field))
        for field in (
            "agreementHash", "deliverableSpecHash", "payloadContentHash",
            "verificationMethodHash",
        )
    ):
        return False
    if (
        not _safe_nonnegative_integer(record.get("attempt"))
        or not _string_member(
            record.get("decision"), {"pass", "fail", "indeterminate", "error"}
        )
        or not _non_boolean_number(record.get("verifiedAt"))
    ):
        return False
    method_ref = record.get("methodEvidenceRef")
    if (
        (method_ref is not None and not _attestation_ref_shape_valid(method_ref))
        or (record.get("decision") == "pass" and method_ref is None)
    ):
        return False
    if "methodTransactionRef" in record:
        transaction_ref = record["methodTransactionRef"]
        if (
            not isinstance(transaction_ref, dict)
            or set(transaction_ref) != {"kind", "value"}
            or not _nonempty_jcs_string(transaction_ref.get("kind"))
            or not _nonempty_jcs_string(transaction_ref.get("value"))
        ):
            return False
    signature = record.get("signature")
    canonical_signature, _ = sig6_canonical(
        signature.get("value") if isinstance(signature, dict) else None
    )
    return (
        isinstance(signature, dict)
        and set(signature) == {"algorithm", "signer", "value"}
        and _string_member(
            signature.get("algorithm"), COMPONENT_SIGNATURE_ALGORITHMS
        )
        and _claim_reference_shape_valid(signature.get("signer"))
        and canonical_signature
    )


def authenticated_delivery_roles(bundle):
    """Resolve unique delivery parties after the caller authenticates the bundle."""
    parties = bundle.get("parties") if isinstance(bundle, dict) else None
    if not isinstance(parties, list) or any(not isinstance(party, dict) for party in parties):
        return "error", None
    claims_by_role = {}
    for role in ("buyer", "seller"):
        matches = [party for party in parties if party.get("role") == role]
        if len(matches) != 1:
            return "error", None
        claim = matches[0].get("primaryClaim")
        if not isinstance(claim, str) or not claim:
            return "error", None
        claims_by_role[role] = claim
    return "pass", claims_by_role


def _complete_object_hash(value):
    """Hash every member of a complete, non-envelope object as received."""
    if not isinstance(value, dict):
        return None
    try:
        return hashlib.sha256(canonical(value)).hexdigest()
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        return None


def _signed_envelope_content_hash(record):
    """Hash a signed DACS envelope while omitting only its signature member."""
    if not isinstance(record, dict):
        return None
    unsigned = {key: value for key, value in record.items() if key != "signature"}
    return _complete_object_hash(unsigned)


def _signed_inner_artifact_valid(record, domain, pubkeys, expected_signer=None):
    if not isinstance(record, dict) or not isinstance(pubkeys, dict):
        return False
    signature = record.get("signature")
    if (
        not isinstance(signature, dict)
        or set(signature) != {"algorithm", "signer", "value"}
        or signature.get("algorithm") != "ed25519"
        or not isinstance(signature.get("signer"), str)
        or signature["signer"] not in pubkeys
        or (expected_signer is not None and signature["signer"] != expected_signer)
    ):
        return False
    canonical_ok, _ = sig6_canonical(signature.get("value"))
    content_hash = _signed_envelope_content_hash(record)
    return bool(
        canonical_ok
        and content_hash
        and verify_sig(
            pubkeys[signature["signer"]], domain, content_hash, signature["value"]
        )
    )


_CLOSURE_DISPOSITION_PRIORITY = {
    "pass": 0,
    "indeterminate": 1,
    "fail": 2,
    "error": 3,
}


def _closure_result(disposition, reason="ok"):
    if disposition not in _CLOSURE_DISPOSITION_PRIORITY:
        raise ValueError("unknown closure disposition: %r" % (disposition,))
    return (disposition, reason)


class _DispositionReason(str):
    """Carry a closure disposition through the legacy Boolean core."""

    def __new__(cls, value, disposition):
        instance = super().__new__(cls, value)
        instance.disposition = disposition
        return instance


def _combine_closure_results(results):
    """Keep deterministic contradictions and malformed input visible over outages."""
    selected = _closure_result("pass")
    for result in results:
        if _CLOSURE_DISPOSITION_PRIORITY[result[0]] > _CLOSURE_DISPOSITION_PRIORITY[selected[0]]:
            selected = result
    return selected


def _utf8_bytes(value, subject):
    if not isinstance(value, str):
        return (_closure_result("error", subject + " is not a string"), None)
    try:
        return (_closure_result("pass"), value.encode("utf-8"))
    except UnicodeEncodeError:
        return (_closure_result("error", subject + " is not valid UTF-8"), None)


def _resolved_exact_bytes(value, subject):
    """Resolve exact bytes from the compatible text/binary adapter representations.

    ``cleartextUtf8`` preserves existing text adapters.  The canonical unpadded
    ``cleartextBytesBase64url`` arm carries arbitrary bytes.  When both are supplied
    they must decode to identical bytes; neither spelling may silently win.
    """
    if not isinstance(value, dict):
        return (_closure_result("error", subject + " authority is malformed"), None)
    has_text = "cleartextUtf8" in value
    has_binary = "cleartextBytesBase64url" in value
    if not has_text and not has_binary:
        return (_closure_result("indeterminate", subject + " exact bytes are unavailable"), None)
    results = []
    decoded = []
    if has_text:
        result, raw = _utf8_bytes(value.get("cleartextUtf8"), subject + " UTF-8 bytes")
        results.append(result)
        if raw is not None:
            decoded.append(raw)
    if has_binary:
        result, raw = _exact_base64url_bytes(
            value.get("cleartextBytesBase64url"), subject + " Base64URL bytes"
        )
        results.append(result)
        if raw is not None:
            decoded.append(raw)
    combined = _combine_closure_results(results)
    if combined[0] != "pass":
        return (combined, None)
    if len(decoded) == 2 and decoded[0] != decoded[1]:
        return (_closure_result("fail", subject + " byte representations contradict"), None)
    return (_closure_result("pass"), decoded[0])


def _exact_base64url_bytes(value, subject):
    """Decode one canonical unpadded RFC 4648 section 5 byte representation."""
    if value is None:
        return (_closure_result("indeterminate", subject + " is unavailable"), None)
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]*", value) is None:
        return (_closure_result("error", subject + " is malformed"), None)
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (binascii.Error, ValueError):
        return (_closure_result("error", subject + " is malformed"), None)
    canonical_value = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical_value != value:
        return (_closure_result("error", subject + " is not canonical"), None)
    return (_closure_result("pass"), decoded)


def _resolved_availability(entry, subject):
    """Apply the shared strict availability contract before resolver data is read."""
    if entry is None:
        return (_closure_result("indeterminate", subject + " authority is unavailable"), None)
    if not isinstance(entry, dict):
        return (_closure_result("error", subject + " authority is malformed"), None)
    available = entry.get("available")
    if available is False:
        return (_closure_result("indeterminate", subject + " authority is unavailable"), None)
    if available is not True:
        return (_closure_result("error", subject + " availability is malformed"), None)
    return (_closure_result("pass"), entry)


def _validated_dependency_receipt(
    reference,
    entry,
    receipt_by_canonical_ref,
    completed,
    subject,
    *,
    job_id,
    phase_index,
    phase_kind,
    expected_writer,
    reference_validator=None,
):
    """Validate one already-proof-checked SR-2 receipt against its complete ref.

    The map is the output of the consumer's protocol-owned SR-2 proof adapter.  This
    reference predicate validates the portable receipt and exact tuple; it does not
    invent a substrate proof codec.  A map name or Boolean inside untrusted JSON is not
    proof and MUST NOT be used to populate this input in a production consumer.
    ``expected_writer`` constrains a protocol-required writer role when one exists;
    an optional reference signer, when present, is always checked independently.
    """
    if (
        not _nonempty_jcs_string(job_id)
        or isinstance(phase_index, bool)
        or not isinstance(phase_index, int)
        or phase_index < 0
        or phase_index > _MAX_SAFE_JSON_INTEGER
        or not _nonempty_jcs_string(phase_kind)
    ):
        return (_closure_result("error", subject + " authenticated job/phase context is malformed"), None)
    if reference_validator is None:
        reference_validator = _attestation_ref_shape_valid
    if not reference_validator(reference):
        return (_closure_result("error", subject + " reference is malformed"), None)
    if receipt_by_canonical_ref is None:
        return (_closure_result("indeterminate", subject + " receipt authority is unavailable"), None)
    if not isinstance(receipt_by_canonical_ref, dict):
        return (_closure_result("error", subject + " receipt authority is malformed"), None)
    try:
        reference_key = canonical(reference).decode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        return (_closure_result("error", subject + " reference is not canonicalizable"), None)
    receipt_authority = receipt_by_canonical_ref.get(reference_key)
    if receipt_authority is None:
        return (_closure_result("indeterminate", subject + " verified receipt is unavailable"), None)
    if not isinstance(receipt_authority, dict):
        return (_closure_result("error", subject + " verified receipt is malformed"), None)
    if "receipt" in receipt_authority:
        if (
            set(receipt_authority) - {"receipt", "storageBinding"}
            or not isinstance(receipt_authority.get("receipt"), dict)
            or (
                "storageBinding" in receipt_authority
                and not isinstance(receipt_authority.get("storageBinding"), dict)
            )
        ):
            return (_closure_result("error", subject + " receipt adapter output is malformed"), None)
        receipt = receipt_authority["receipt"]
    else:
        # Existing top-level and legacy fixture adapters expose a bare portable
        # AnchorReceipt.  Keep that shape readable; authenticated storage metadata,
        # when required, is carried beside it in the adapter envelope above.
        receipt = receipt_authority

    native_address = entry.get("nativeAddress")
    if native_address is None:
        return (_closure_result("indeterminate", subject + " native-address authority is unavailable"), None)
    if not _nonempty_jcs_string(native_address):
        return (_closure_result("error", subject + " native-address authority is malformed"), None)
    independently_resolvable = entry.get("independentlyResolvable")
    if completed and independently_resolvable is None:
        return (_closure_result("indeterminate", subject + " resolvability authority is unavailable"), None)
    if independently_resolvable is not None and not isinstance(
        independently_resolvable, bool
    ):
        return (_closure_result("error", subject + " resolvability authority is malformed"), None)

    transaction_ref = receipt.get("transactionRef")
    evidence = receipt.get("evidence")
    block_ref = receipt.get("blockRef")
    observed_at = receipt.get("observedAt")
    nonce = receipt.get("nonce")
    required_shape = (
        receipt.get("receiptVersion") == "1"
        and _nonempty_jcs_string(receipt.get("substrate"))
        and _nonempty_jcs_string(receipt.get("finalityProfile"))
        and _nonempty_jcs_string(receipt.get("logicalAddress"))
        and _nonempty_jcs_string(receipt.get("nativeAddress"))
        and _sha256_hex(receipt.get("contentHash"))
        and isinstance(transaction_ref, dict)
        and set(transaction_ref) == {"kind", "value"}
        and _nonempty_jcs_string(transaction_ref.get("kind"))
        and _nonempty_jcs_string(transaction_ref.get("value"))
        and _nonempty_jcs_string(receipt.get("writer"))
        and (nonce is None or _nonempty_jcs_string(nonce))
        and _string_member(receipt.get("state"), {
            "submitted", "accepted", "included", "finalized", "rejected",
            "dropped", "replaced", "expired", "reorged",
        })
        and receipt.get("observationDisposition") == "established"
        and _non_boolean_number(observed_at)
        and isinstance(evidence, dict)
        and set(evidence) == {"kind", "value"}
        and _nonempty_jcs_string(evidence.get("kind"))
        and _nonempty_jcs_string(evidence.get("value"))
    )
    if not required_shape:
        return (_closure_result("error", subject + " verified receipt is malformed"), None)
    if receipt["state"] in {"included", "finalized"} and (
        not isinstance(block_ref, dict)
        or not _nonempty_jcs_string(block_ref.get("id"))
    ):
        return (_closure_result("error", subject + " receipt lacks its required blockRef"), None)

    anchor = reference["anchor"]
    if (
        receipt.get("logicalAddress") != anchor.get("locator")
        or receipt.get("nativeAddress") != native_address
        or receipt.get("contentHash") != reference.get("contentHash")
        or (expected_writer is not None and receipt.get("writer") != expected_writer)
        or ("signer" in reference and receipt.get("writer") != reference["signer"])
    ):
        return (_closure_result("fail", subject + " receipt contradicts its full reference or authority"), receipt_authority)
    if completed:
        if receipt.get("state") != "finalized" or independently_resolvable is not True:
            return (_closure_result("fail", subject + " is not finalized and independently resolvable"), receipt_authority)
    elif receipt.get("state") not in {"included", "finalized"}:
        return (_closure_result("fail", subject + " is not included or finalized"), receipt_authority)
    return (_closure_result("pass"), receipt_authority)


def _resolved_delivery_dependency(
    entry,
    reference,
    receipt_by_canonical_ref,
    completed,
    subject,
    *,
    job_id,
    phase_index,
    phase_kind,
    expected_writer,
    reference_validator=None,
):
    availability_result, entry = _resolved_availability(entry, subject)
    if availability_result[0] != "pass":
        return availability_result, None, None
    receipt_result, receipt = _validated_dependency_receipt(
        reference,
        entry,
        receipt_by_canonical_ref,
        completed,
        subject,
        job_id=job_id,
        phase_index=phase_index,
        phase_kind=phase_kind,
        expected_writer=expected_writer,
        reference_validator=reference_validator,
    )
    return receipt_result, entry, receipt


def _validate_authenticated_storage_binding(
    binding, access_model, buyer, cleartext_hash, stored_hash, subject
):
    if binding is None:
        return _closure_result("indeterminate", subject + " authenticated storage authority is unavailable")
    if not isinstance(binding, dict):
        return _closure_result("error", subject + " authenticated storage authority is malformed")
    effective_access_model = binding.get("effectiveAccessMode")
    if not _string_member(
        effective_access_model, {"public", "buyer-only", "encrypt-to-buyer"}
    ):
        return _closure_result("error", subject + " effective access mode is malformed")
    # Validate the complete authority shape before interpreting value conflicts.
    fields = {"effectiveAccessMode", "storedContentHash"}
    if effective_access_model == "buyer-only":
        fields.add("acl")
    elif effective_access_model == "encrypt-to-buyer":
        fields.add("encryption")
    if set(binding) != fields or not _sha256_hex(binding.get("storedContentHash")):
        return _closure_result("error", subject + " storage authority or digest is malformed")
    acl = binding.get("acl")
    encryption = binding.get("encryption")
    if effective_access_model == "buyer-only" and (
        not isinstance(acl, dict)
        or set(acl) != {"mode", "allowed"}
        or not _nonempty_jcs_string(acl.get("mode"))
        or not isinstance(acl.get("allowed"), list)
        or any(not _nonempty_jcs_string(value) for value in acl["allowed"])
    ):
        return _closure_result("error", subject + " authenticated ACL is malformed")
    if effective_access_model == "encrypt-to-buyer" and (
        not isinstance(encryption, dict)
        or set(encryption) != {"recipient", "ciphertextContentHash"}
        or not _nonempty_jcs_string(encryption.get("recipient"))
        or not _sha256_hex(encryption.get("ciphertextContentHash"))
    ):
        return _closure_result("error", subject + " authenticated encryption evidence is malformed")
    # DV-2 preserves public-to-private over-provision; private modes are exact.
    if access_model != "public" and effective_access_model != access_model:
        return _closure_result("fail", subject + " effective access mode contradicts the agreement")
    if binding["storedContentHash"] != stored_hash:
        return _closure_result("fail", subject + " authenticated stored-byte commitment differs")
    if effective_access_model != "public" and not _nonempty_jcs_string(buyer):
        return _closure_result("indeterminate", subject + " authenticated buyer is unavailable")
    if effective_access_model in {"public", "buyer-only"} and stored_hash != cleartext_hash:
        return _closure_result("fail", subject + " storage does not contain the plaintext bytes")
    if effective_access_model == "buyer-only" and (
        acl["mode"] != "restricted" or acl["allowed"] != [buyer]
    ):
        return _closure_result("fail", subject + " authenticated ACL is not restricted to the buyer")
    if effective_access_model == "encrypt-to-buyer" and (
        encryption["recipient"] != buyer or encryption["ciphertextContentHash"] != stored_hash
    ):
        return _closure_result("fail", subject + " authenticated encryption evidence does not bind the buyer and ciphertext")
    return _closure_result("pass")


def _validate_resolved_storage(
    delivered,
    expected_cleartext_hash,
    access_model,
    subject,
    *,
    authenticated_storage_binding=None,
    buyer=None,
):
    """Bind arbitrary exact bytes, effective ACL/recipient, and stored bytes."""
    if not isinstance(delivered, dict):
        return _closure_result("error", subject + " authority is malformed")
    results = []
    if "storedHash" in delivered:
        results.append(_closure_result(
            "error", subject + " uses obsolete storedHash resolver metadata"
        ))
    if not _string_member(
        access_model, {"public", "buyer-only", "encrypt-to-buyer"}
    ):
        results.append(_closure_result("error", subject + " access model is malformed"))
    for field in ("cleartextHash", "storedContentHash"):
        if not _sha256_hex(delivered.get(field)):
            results.append(_closure_result(
                "error", subject + " " + field + " is malformed"
            ))
    if not _sha256_hex(expected_cleartext_hash):
        results.append(_closure_result(
            "error", subject + " expected cleartext hash is malformed"
        ))

    cleartext_result, cleartext_bytes = _resolved_exact_bytes(
        delivered, subject + " cleartext"
    )
    results.append(cleartext_result)
    stored_result, stored_bytes = _exact_base64url_bytes(
        delivered.get("storedBytesBase64url"), subject + " exact stored bytes"
    )
    results.append(stored_result)
    recomputed_hash = None
    if cleartext_bytes is not None:
        recomputed_hash = hashlib.sha256(cleartext_bytes).hexdigest()
        if (
            delivered.get("cleartextHash") != recomputed_hash
            or expected_cleartext_hash != recomputed_hash
        ):
            results.append(_closure_result(
                "fail", subject + " cleartext bytes do not match delivery evidence"
            ))
    stored_hash = None
    if stored_bytes is not None:
        stored_hash = hashlib.sha256(stored_bytes).hexdigest()
        if delivered.get("storedContentHash") != stored_hash:
            results.append(_closure_result(
                "fail", subject + " exact stored bytes do not match the resolver commitment"
            ))
    if recomputed_hash is not None and stored_hash is not None:
        results.append(_validate_authenticated_storage_binding(
            authenticated_storage_binding,
            access_model,
            buyer,
            recomputed_hash,
            stored_hash,
            subject,
        ))
    return _combine_closure_results(results)


def _validate_resolved_credential(
    credential,
    binding,
    credential_ref,
    subject="entitlement credential",
    *,
    authenticated_storage_binding=None,
    buyer=None,
):
    """Bind arbitrary exact credential bytes to signed and resolver commitments."""
    if not isinstance(credential, dict):
        return _closure_result("error", subject + " authority is malformed")
    results = []
    allowed_fields = {
        "credentialRef", "cleartextBytesBase64url", "cleartextHash",
        "storedBytesBase64url", "storedContentHash", "nativeAddress",
        "independentlyResolvable", "available",
    }
    if set(credential) - allowed_fields:
        results.append(_closure_result(
            "error", subject + " has unsupported resolver fields"
        ))
    resolved_ref = credential.get("credentialRef")
    if (
        not isinstance(resolved_ref, dict)
        or set(resolved_ref) != {"ref", "accessModel"}
        or not _attestation_ref_shape_valid(resolved_ref.get("ref"))
        or not _string_member(
            resolved_ref.get("accessModel"), {"buyer-only", "encrypt-to-buyer"}
        )
    ):
        results.append(_closure_result(
            "error", subject + " resolver credentialRef is malformed"
        ))

    ref_value = credential_ref.get("ref") if isinstance(credential_ref, dict) else None
    ref_content_hash = ref_value.get("contentHash") if isinstance(ref_value, dict) else None
    access_model = (
        credential_ref.get("accessModel") if isinstance(credential_ref, dict) else None
    )
    signed_cleartext_hash = (
        binding.get("credentialCleartextHash") if isinstance(binding, dict) else None
    )
    for label, digest in (
        ("signed cleartext hash", signed_cleartext_hash),
        ("resolver cleartextHash", credential.get("cleartextHash")),
        ("resolver storedContentHash", credential.get("storedContentHash")),
        ("signed credential reference contentHash", ref_content_hash),
    ):
        if not _sha256_hex(digest):
            results.append(_closure_result("error", subject + " " + label + " is malformed"))
    if not _string_member(access_model, {"buyer-only", "encrypt-to-buyer"}):
        results.append(_closure_result("error", subject + " access model is malformed"))

    exact_bytes_result, exact_bytes = _exact_base64url_bytes(
        credential.get("cleartextBytesBase64url"), subject + " exact cleartext bytes"
    )
    results.append(exact_bytes_result)
    stored_bytes_result, stored_bytes = _exact_base64url_bytes(
        credential.get("storedBytesBase64url"), subject + " exact stored bytes"
    )
    results.append(stored_bytes_result)
    try:
        resolver_ref_matches = canonical(credential.get("credentialRef")) == canonical(
            credential_ref
        )
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        resolver_ref_matches = False
    if not resolver_ref_matches:
        results.append(_closure_result(
            "fail", subject + " reference does not match the signed entitlement"
        ))
    if credential.get("storedContentHash") != ref_content_hash:
        results.append(_closure_result(
            "fail", subject + " storage commitment does not match its signed reference"
        ))
    if exact_bytes is not None:
        recomputed_hash = hashlib.sha256(exact_bytes).hexdigest()
        if (
            signed_cleartext_hash != recomputed_hash
            or credential.get("cleartextHash") != recomputed_hash
        ):
            results.append(_closure_result(
                "fail", subject + " exact bytes do not match cleartext commitments"
            ))
        if stored_bytes is not None:
            stored_hash = hashlib.sha256(stored_bytes).hexdigest()
            if credential.get("storedContentHash") != stored_hash:
                results.append(_closure_result(
                    "fail", subject + " exact stored bytes do not match the resolver commitment"
                ))
            results.append(_validate_authenticated_storage_binding(
                authenticated_storage_binding,
                access_model,
                buyer,
                recomputed_hash,
                stored_hash,
                subject,
            ))
    return _combine_closure_results(results)


def _canonical_method_transaction_ref(transaction_ref):
    if (
        not isinstance(transaction_ref, dict)
        or set(transaction_ref) != {"kind", "value"}
        or not _nonempty_jcs_string(transaction_ref.get("kind"))
        or not _nonempty_jcs_string(transaction_ref.get("value"))
    ):
        return None
    try:
        return canonical(transaction_ref).decode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        return None


_DELIVERY_ARTIFACT_TYPE_BY_DISCRIMINATOR = {
    # Current type-specific major-version signals registered by the repository's
    # schemas. Contextual recipe/listing/rail/registry/protocol versions are not
    # structural discriminators and therefore deliberately do not appear here.
    "receiptVersion": "receipt",
    "bundleVersion": "bundle",
    "requirementVersion": "requirement",
    "dacsVersion": "dacs",
    "indexVersion": "index",
    "resultVersion": "result",
    "recordVersion": "record",
    "agreementVersion": "agreement",
    "payeeBoundAgreementVersion": "payee-bound-agreement",
    "finalityCommitmentVersion": "finality-commitment",
    "transcriptVersion": "transcript",
    "entitlementVersion": "entitlement",
    "payloadAttestationVersion": "payload-attestation",
    "evidenceVersion": "settlement",
    "deliveryEvidenceVersion": "delivery",
    "amendmentVersion": "amendment",
    "priorPaymentDispositionVersion": "prior-payment-disposition",
    "faultBundleVersion": "fault-bundle",
    "evidenceBoundFaultBundleVersion": "evidence-bound-fault-bundle",
    "bindingVersion": "binding",
    "derivationVersion": "derivation",
    "replayableDerivationVersion": "replayable-derivation",
    "settlementVerifiedDerivationVersion": "settlement-verified-derivation",
    "replayableSettlementVerifiedDerivationVersion": (
        "replayable-settlement-verified-derivation"
    ),
    "jobBoundReplayableDerivationVersion": "job-bound-replayable-derivation",
    "ratingVersion": "rating",
    "manifestVersion": "manifest",
}

def _delivery_artifact_type(record):
    """Return a syntactic current selector for diagnostics, never admission."""
    if not isinstance(record, dict):
        return None
    present = [
        key for key in _DELIVERY_ARTIFACT_TYPE_BY_DISCRIMINATOR if key in record
    ]
    if len(present) != 1:
        return None
    discriminator = present[0]
    if record.get(discriminator) != "1":
        return None
    return _DELIVERY_ARTIFACT_TYPE_BY_DISCRIMINATOR[discriminator]


def _delivery_inner_type_valid(record, discriminator):
    """Validate a selector only after the phase fixed the expected inner family."""
    expected = _DELIVERY_ARTIFACT_TYPE_BY_DISCRIMINATOR.get(discriminator)
    if expected not in {"entitlement", "payload-attestation"} or not isinstance(record, dict):
        return False
    present = [
        key for key in _DELIVERY_ARTIFACT_TYPE_BY_DISCRIMINATOR if key in record
    ]
    return (
        present == [discriminator]
        and record.get(discriminator) == "1"
    )


def _authenticated_evidence_wire_type(record, pubkeys):
    """Authenticate SettlementEvidence/DeliveryEvidence family before parsing it."""
    if not isinstance(record, dict) or not isinstance(pubkeys, dict) or not HAVE_CRYPTO:
        return None
    signature = record.get("signature")
    if not isinstance(signature, dict):
        return None
    signer = signature.get("signer")
    value = signature.get("value")
    canonical_ok, _ = sig6_canonical(value)
    if (
        not isinstance(signer, str)
        or signer not in pubkeys
        or signature.get("algorithm") not in SUPPORTED_SIGNATURE_ALGORITHMS
        or not canonical_ok
    ):
        return None
    try:
        content_hash = settlement_evidence_hash(record)
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        return None
    candidates = []
    for family, domain in (
        ("settlement", SETTLEMENT_EVIDENCE_DOMAIN),
        ("delivery", DELIVERY_EVIDENCE_DOMAIN),
    ):
        if verify_sig(pubkeys[signer], domain, content_hash, value):
            candidates.append(family)
    if len(candidates) != 1:
        return None
    family = candidates[0]
    expected_selector = (
        "evidenceVersion" if family == "settlement" else "deliveryEvidenceVersion"
    )
    present = [
        selector
        for selector in ("evidenceVersion", "deliveryEvidenceVersion")
        if selector in record
    ]
    if present != [expected_selector] or record.get(expected_selector) != "1":
        return None
    return family


def validate_payload_attestation_locator_context(
    record, attestation_ref, execution, method, *, legacy=False
):
    """Bind a standalone payload attestation to authenticated locator context.

    ``execution`` and ``method`` are outputs of the protocol-owned session/listing
    resolution path.  This predicate does not accept a family or locator label from the
    record's caller and does not authenticate those authority objects by naming them.
    """
    if execution is None or method is None:
        return _closure_result("indeterminate", "payload attestation locator authority is unavailable")
    if not isinstance(execution, dict) or not isinstance(method, dict):
        return _closure_result("error", "payload attestation locator authority is malformed")
    if not isinstance(record, dict) or not _attestation_ref_shape_valid(attestation_ref):
        return _closure_result("error", "payload attestation record or complete reference is malformed")
    phase_index = execution.get("phaseIndex")
    attempt = record.get("attempt")
    if (
        not _nonempty_jcs_string(execution.get("jobId"))
        or execution.get("phaseKind") != "deliver-attested-payload"
        or not _nonempty_jcs_string(method.get("kind"))
        or isinstance(phase_index, bool)
        or not isinstance(phase_index, int)
        or phase_index < 0
        or isinstance(attempt, bool)
        or not isinstance(attempt, int)
        or attempt < 0
        or attempt > _MAX_SAFE_JSON_INTEGER
    ):
        return _closure_result("error", "payload attestation phase or attempt context is malformed")
    try:
        method_hash = _complete_object_hash(method)
        record_hash = _signed_envelope_content_hash(record)
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        return _closure_result("error", "payload attestation context is not canonicalizable")
    if not _sha256_hex(method_hash) or not _sha256_hex(record_hash):
        return _closure_result("error", "payload attestation context is not canonicalizable")
    expected_locator = (
        f"dacs4:payload-attestation:{execution.get('jobId')}:{method_hash}:{attempt}"
        if legacy
        else (
            f"dacs4:payload-attestation:{execution.get('jobId')}:{phase_index}:"
            f"{method_hash}:{attempt}"
        )
    )
    signature = record.get("signature")
    if (
        record.get("jobId") != execution.get("jobId")
        or record.get("verificationMethod") != method.get("kind")
        or record.get("verificationMethodHash") != method_hash
        or attestation_ref.get("anchor")
        != {"kind": "storage-program", "locator": expected_locator}
        or attestation_ref.get("contentHash") != record_hash
        or (
            "signer" in attestation_ref
            and (
                not isinstance(signature, dict)
                or attestation_ref.get("signer") != signature.get("signer")
            )
        )
    ):
        return _closure_result("fail", "payload attestation does not bind authenticated job, phase, method, attempt, and locator")
    return _closure_result("pass")


def validate_delivery_method_evidence(
    method,
    method_evidence,
    transaction_ref,
    trusted_native_observations_by_canonical_ref,
    *,
    delivered_cleartext,
    delivered_bytes,
    payload_content_hash,
    require_finalized,
):
    """Fixture-only method dispatch; no production consensus-proof format is implied."""
    if not isinstance(method, dict) or not isinstance(method.get("kind"), str):
        return _closure_result("error", "verification method is malformed")
    if not isinstance(method_evidence, dict):
        return _closure_result("error", "method evidence is malformed")

    method_kind = method["kind"]
    if method_kind == "self-signed":
        if transaction_ref is not None:
            return _closure_result("fail", "self-signed method carries a native transaction")
        method_input = method_evidence.get("methodInput")
        permitted_method_input = {
            "identifier", "assertion", "assertionBytesBase64url", "signature"
        }
        if (
            method_evidence.get("kind") != "self-signed-payload"
            or not isinstance(method_input, dict)
            or not {"identifier", "signature"} <= set(method_input)
            or set(method_input) - permitted_method_input
            or method_evidence.get("payloadContentHash") != payload_content_hash
        ):
            return _closure_result("error", "self-signed method input is malformed")
        identifier = method_input.get("identifier")
        assertion_result, assertion_bytes = _resolved_exact_bytes(
            {
                **(
                    {"cleartextUtf8": method_input.get("assertion")}
                    if "assertion" in method_input else {}
                ),
                **(
                    {"cleartextBytesBase64url": method_input.get("assertionBytesBase64url")}
                    if "assertionBytesBase64url" in method_input else {}
                ),
            },
            "self-signed assertion",
        )
        if assertion_result[0] != "pass":
            return assertion_result
        if assertion_bytes != delivered_bytes:
            return _closure_result("fail", "self-signed assertion is not the delivered payload")
        signature_value = method_input.get("signature")
        canonical_ok, _ = sig6_canonical(signature_value)
        if (
            not isinstance(identifier, str)
            or not re.fullmatch(r"[0-9a-f]{64}", identifier)
            or not canonical_ok
        ):
            return _closure_result("error", "self-signed method key or signature is malformed")
        try:
            raw_signature = base64.urlsafe_b64decode(
                signature_value + "=" * (-len(signature_value) % 4)
            )
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(identifier)).verify(
                raw_signature, assertion_bytes
            )
        except (InvalidSignature, TypeError, ValueError):
            return _closure_result("fail", "self-signed method signature does not verify")
        return _closure_result("pass")

    if method_kind != "consensus-backed-proxy":
        return _closure_result("error", "unsupported delivery verification method")

    endpoint = method.get("endpoint")
    request = method_evidence.get("request")
    response = method_evidence.get("response")
    transaction = method_evidence.get("transaction")
    if (
        not isinstance(endpoint, dict)
        or not _string_member(endpoint.get("method"), {"GET", "POST"})
        or not _nonempty_jcs_string(endpoint.get("urlTemplate"))
        or not isinstance(request, dict)
        or not isinstance(response, dict)
        or not isinstance(transaction, dict)
    ):
        return _closure_result("error", "consensus-backed proxy evidence is malformed")

    expected_request = {
        "method": endpoint["method"],
        "url": endpoint["urlTemplate"],
    }
    for optional in ("headers", "body"):
        if optional in endpoint:
            expected_request[optional] = endpoint[optional]
    if request != expected_request:
        return _closure_result("fail", "native request contradicts the signed method")

    status = response.get("status")
    response_data_result, response_data_bytes = _resolved_exact_bytes(
        {
            **({"cleartextUtf8": response.get("data")} if "data" in response else {}),
            **(
                {"cleartextBytesBase64url": response.get("dataBytesBase64url")}
                if "dataBytesBase64url" in response else {}
            ),
        },
        "native response data",
    )
    if response_data_result[0] != "pass":
        return response_data_result
    if (
        isinstance(status, bool)
        or not isinstance(status, int)
        or not 200 <= status < 300
        or response_data_bytes != delivered_bytes
        or response.get("responseHash")
        != hashlib.sha256(response_data_bytes).hexdigest()
        or response.get("responseHash") != payload_content_hash
        or not _sha256_hex(response.get("responseHeadersHash"))
    ):
        return _closure_result("fail", "native response does not commit to delivered bytes")

    transaction_key = _canonical_method_transaction_ref(transaction_ref)
    if (
        transaction_key is None
        or transaction.get("kind") != transaction_ref.get("kind")
        or transaction.get("value") != transaction_ref.get("value")
        or not _string_member(transaction.get("state"), {"included", "finalized"})
        or method_evidence.get("proofValid") is not True
        or transaction.get("authenticated") is not True
    ):
        return _closure_result("fail", "method envelope contradicts its native transaction")
    if require_finalized and transaction.get("state") != "finalized":
        return _closure_result("fail", "terminal delivery native transaction is not finalized")

    observations = trusted_native_observations_by_canonical_ref
    if observations is None:
        return _closure_result("indeterminate", "trusted native transaction authority is unavailable")
    if not isinstance(observations, dict):
        return _closure_result("error", "trusted native transaction authority is malformed")
    observation = observations.get(transaction_key)
    if observation is None:
        return _closure_result("indeterminate", "trusted native transaction observation is unavailable")
    if not isinstance(observation, dict):
        return _closure_result("error", "trusted native transaction observation is malformed")
    if observation.get("available") is False:
        if set(observation) != {"available"}:
            return _closure_result("error", "unavailable native observation has ambiguous fields")
        return _closure_result("indeterminate", "trusted native transaction observation is unavailable")
    if (
        set(observation)
        != {"available", "transaction", "verificationMethod", "request", "response"}
        or observation.get("available") is not True
    ):
        return _closure_result("error", "trusted native transaction observation is malformed")
    observed_response = {
        "status": response.get("status"),
        "responseHash": response.get("responseHash"),
        "responseHeadersHash": response.get("responseHeadersHash"),
    }
    if (
        observation.get("transaction") != transaction
        or observation.get("verificationMethod") != method
        or observation.get("request") != request
        or observation.get("response") != observed_response
    ):
        return _closure_result("fail", "method envelope contradicts trusted native observation")
    return _closure_result("pass")


def _validate_delivery_artifact_closure_disposition(
    record,
    phase_key,
    listing,
    bundle,
    pubkeys,
    execution,
    closure,
    verified_receipt_by_canonical_ref,
    trusted_native_observations_by_canonical_ref,
    *,
    legacy,
):
    """Validate delivery closure under an explicit current or PDE-7 address policy."""
    if record.get("outcome") != "success":
        return _closure_result("pass")

    results = []
    if execution is None:
        results.append(_closure_result("indeterminate", "session execution authority is unavailable"))
        execution = {}
    elif not isinstance(execution, dict):
        results.append(_closure_result("error", "session execution authority is malformed"))
        execution = {}
    if closure is None:
        return _combine_closure_results(
            results + [_closure_result("indeterminate", "delivery artifact authority is unavailable")]
        )
    if not isinstance(closure, dict):
        return _combine_closure_results(
            results + [_closure_result("error", "delivery artifact authority is malformed")]
        )

    phase = record.get("phase")
    job_id = record.get("jobId")
    completed = bundle.get("outcome") == "completed"
    try:
        authenticated_phase_index = int(phase_key.split(":", 1)[0])
    except (AttributeError, TypeError, ValueError):
        return _combine_closure_results(
            results + [_closure_result("error", "authenticated delivery phase key is malformed")]
        )
    phase_index = None if legacy else record.get("phaseIndex")
    if not legacy and phase_key != f"{phase_index}:{phase}":
        results.append(_closure_result("fail", "delivery closure phase key does not match signed evidence"))
    deliverable_address = (
        f"dacs4:deliverable:{job_id}"
        if legacy else f"dacs4:deliverable:{job_id}:{phase_index}"
    )
    anchor = record.get("deliverableAnchor")
    role_status, parties = authenticated_delivery_roles(bundle)
    if role_status != "pass":
        results.append(_closure_result("error", "authenticated delivery parties are missing or ambiguous"))
        parties = {}
    seller = parties.get("seller")
    buyer = parties.get("buyer")

    if phase == "deliver-storage-program":
        if set(closure) - {"deliverable"}:
            results.append(_closure_result("error", "storage delivery closure is ambiguous"))
        deliverable_ref = {
            "anchor": anchor,
            "contentHash": record.get("deliverableContentHash"),
        }
        dependency_result, delivered, receipt = _resolved_delivery_dependency(
            closure.get("deliverable"),
            deliverable_ref,
            verified_receipt_by_canonical_ref,
            completed,
            "storage deliverable",
            job_id=job_id,
            phase_index=authenticated_phase_index,
            phase_kind=phase,
            expected_writer=seller,
            reference_validator=_deliverable_ref_shape_valid,
        )
        results.append(dependency_result)
        if anchor != {"kind": "storage-program", "locator": deliverable_address}:
            results.append(_closure_result("fail", "storage anchor does not bind the exact job and phase"))
        offering = listing.get("offering")
        deliverable_spec = offering.get("deliverable") if isinstance(offering, dict) else None
        if (
            not isinstance(deliverable_spec, dict)
            or deliverable_spec.get("kind") != "storage-program"
        ):
            results.append(_closure_result(
                "fail", "signed storage DeliverableSpec is malformed"
            ))
            access_model = "public"
        else:
            access_model = deliverable_spec.get("accessModel", "public")
        if delivered is not None:
            if delivered.get("logicalAddress") != deliverable_address:
                results.append(_closure_result("fail", "storage deliverable does not close over the exact job and phase"))
            results.append(_validate_resolved_storage(
                delivered,
                record.get("deliverableContentHash"),
                access_model,
                "storage deliverable",
                authenticated_storage_binding=(
                    receipt.get("storageBinding") if isinstance(receipt, dict) else None
                ),
                buyer=buyer,
            ))
        if "attestationRef" in record or "credentialDelivery" in record:
            results.append(_closure_result("fail", "storage delivery carries phase-only fields"))
        return _combine_closure_results(results)

    if phase == "deliver-entitlement":
        if role_status != "pass":
            return _combine_closure_results(results + [
                _closure_result("error", "entitlement delivery parties are missing or ambiguous")
            ])
        permitted_closure_fields = (
            {"entitlementRecord"}
            if legacy else {"entitlementRecord", "credential"}
        )
        if set(closure) - permitted_closure_fields:
            results.append(_closure_result("error", "entitlement delivery closure is ambiguous"))
        offering = listing.get("offering")
        deliverable_spec = offering.get("deliverable") if isinstance(offering, dict) else None
        duration_sec = (
            deliverable_spec.get("durationSec") if isinstance(deliverable_spec, dict) else None
        )
        renewable = (
            deliverable_spec.get("renewable") if isinstance(deliverable_spec, dict) else None
        )
        if (
            not isinstance(deliverable_spec, dict)
            or deliverable_spec.get("kind") != "entitlement"
            or not _non_boolean_number(duration_sec)
            or not isinstance(renewable, bool)
        ):
            results.append(_closure_result("fail", "signed entitlement DeliverableSpec is malformed"))

        entitlement_ref = {
            "anchor": anchor,
            "contentHash": record.get("deliverableContentHash"),
        }
        dependency_result, entitlement_entry, _ = _resolved_delivery_dependency(
            closure.get("entitlementRecord"),
            entitlement_ref,
            verified_receipt_by_canonical_ref,
            completed,
            "entitlement record",
            job_id=job_id,
            phase_index=authenticated_phase_index,
            phase_kind=phase,
            expected_writer=seller,
            reference_validator=_deliverable_ref_shape_valid,
        )
        results.append(dependency_result)
        entitlement = entitlement_entry.get("artifact") if entitlement_entry is not None else None
        if entitlement_entry is not None and not isinstance(entitlement, dict):
            results.append(_closure_result("error", "resolved entitlement record is malformed"))
            entitlement = None
        if entitlement is None:
            return _combine_closure_results(results)

        renewal_seq = entitlement.get("renewalSeq")
        entitlement_address = (
            f"dacs4:entitlement:{job_id}:{renewal_seq}"
            if legacy
            else f"dacs4:entitlement:{job_id}:{phase_index}:{renewal_seq}"
        )
        required = {
            "entitlementVersion", "jobId", "grantee", "grantor", "startsAt",
            "endsAt", "scope", "renewable", "renewalSeq", "signature",
        }
        terms_match = (
            _non_boolean_number(duration_sec)
            and _non_boolean_number(entitlement.get("startsAt"))
            and _non_boolean_number(entitlement.get("endsAt"))
            and entitlement["endsAt"] == entitlement["startsAt"] + duration_sec * 1000
            and isinstance(renewable, bool)
            and entitlement.get("renewable") == renewable
        )
        if (
            not required <= set(entitlement)
            or not _delivery_inner_type_valid(entitlement, "entitlementVersion")
            or entitlement.get("jobId") != job_id
            or entitlement.get("grantee") != parties.get("buyer")
            or entitlement.get("grantor") != parties.get("seller")
            or isinstance(renewal_seq, bool)
            or not isinstance(renewal_seq, int)
            or renewal_seq < 0
            or renewal_seq > _MAX_SAFE_JSON_INTEGER
            or not _non_boolean_number(entitlement.get("startsAt"))
            or not _non_boolean_number(entitlement.get("endsAt"))
            or entitlement.get("endsAt", 0) < entitlement.get("startsAt", 0)
            or not isinstance(entitlement.get("scope"), dict)
            or not isinstance(entitlement.get("renewable"), bool)
            or not terms_match
            or not _signed_inner_artifact_valid(
                entitlement,
                ENTITLEMENT_DOMAIN,
                pubkeys,
                expected_signer=parties.get("seller"),
            )
            or anchor != {"kind": "storage-program", "locator": entitlement_address}
            or entitlement_entry.get("logicalAddress") != entitlement_address
            or record.get("deliverableContentHash")
            != _signed_envelope_content_hash(entitlement)
            or "attestationRef" in record
        ):
            results.append(_closure_result("fail", "entitlement record does not close over the signed offering, job, and phase"))

        credential_ref = entitlement.get("credentialRef")
        if legacy:
            # Frozen SettlementEvidence has no signed PDE-5 binding. The record is
            # still validated as historical audit data, but no credential input can
            # upgrade it to a delivered/DV-5 assertion.
            credential_value = (
                credential_ref.get("ref")
                if isinstance(credential_ref, dict) else None
            )
            if credential_ref is not None and (
                not isinstance(credential_ref, dict)
                or set(credential_ref) != {"ref", "accessModel"}
                or not _attestation_ref_shape_valid(credential_value)
                or not _string_member(
                    credential_ref.get("accessModel"),
                    {"buyer-only", "encrypt-to-buyer"},
                )
            ):
                results.append(_closure_result(
                    "error", "historical entitlement credential reference is malformed"
                ))
            return _combine_closure_results(results)
        binding = record.get("credentialDelivery")
        if credential_ref is None:
            if binding is not None or "credential" in closure:
                results.append(_closure_result("fail", "credential-free entitlement has contradictory delivery data"))
            return _combine_closure_results(results)
        if not isinstance(binding, dict):
            results.append(_closure_result("fail", "credential entitlement lacks its exact delivery binding"))
            binding = {}
        ref_value = credential_ref.get("ref") if isinstance(credential_ref, dict) else None
        credential_result, credential, credential_receipt = _resolved_delivery_dependency(
            closure.get("credential"),
            ref_value,
            verified_receipt_by_canonical_ref,
            completed,
            "entitlement credential",
            job_id=job_id,
            phase_index=authenticated_phase_index,
            phase_kind=phase,
            expected_writer=(
                ref_value.get("signer", seller) if isinstance(ref_value, dict) else seller
            ),
        )
        results.append(credential_result)
        try:
            exact_credential_ref = canonical(binding.get("credentialRef")) == canonical(credential_ref)
        except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
            exact_credential_ref = False
        if (
            not _attestation_ref_shape_valid(ref_value)
            or not exact_credential_ref
            or binding.get("renewalSeq") != renewal_seq
        ):
            results.append(_closure_result("fail", "credential delivery does not close over the signed entitlement"))
        if credential is not None:
            results.append(_validate_resolved_credential(
                credential,
                binding,
                credential_ref,
                authenticated_storage_binding=(
                    credential_receipt.get("storageBinding")
                    if isinstance(credential_receipt, dict) else None
                ),
                buyer=buyer,
            ))
        return _combine_closure_results(results)

    if phase != "deliver-attested-payload":
        return _combine_closure_results(
            results + [_closure_result("error", "unsupported delivery phase closure")]
        )

    expected_closure_fields = {
        "agreementHash", "deliverable", "payloadAttestationRecord", "methodEvidence"
    }
    if set(closure) - expected_closure_fields:
        results.append(_closure_result("error", "attested-payload closure is ambiguous"))
    payload_ref = {
        "anchor": anchor,
        "contentHash": record.get("deliverableContentHash"),
    }
    dependency_result, delivered, payload_receipt = _resolved_delivery_dependency(
        closure.get("deliverable"),
        payload_ref,
        verified_receipt_by_canonical_ref,
        completed,
        "attested payload",
        job_id=job_id,
        phase_index=authenticated_phase_index,
        phase_kind=phase,
        expected_writer=seller,
        reference_validator=_deliverable_ref_shape_valid,
    )
    results.append(dependency_result)
    attestation_ref = record.get("attestationRef")
    attestation_projection = closure.get("payloadAttestationRecord")
    attestation_artifact = (attestation_projection.get("artifact")
                            if isinstance(attestation_projection, dict) else None)
    attestation_signature = (attestation_artifact.get("signature")
                             if isinstance(attestation_artifact, dict) else None)
    # The signature is verified below; its writer binding is required even when
    # the optional reference signer is omitted.
    attestation_writer = (attestation_signature.get("signer")
                          if isinstance(attestation_signature, dict) else None)
    dependency_result, attestation_entry, _ = _resolved_delivery_dependency(
        closure.get("payloadAttestationRecord"),
        attestation_ref,
        verified_receipt_by_canonical_ref,
        completed,
        "payload attestation record",
        job_id=job_id,
        phase_index=authenticated_phase_index,
        phase_kind=phase,
        expected_writer=attestation_writer,
    )
    results.append(dependency_result)
    execution_agreement_hash = execution.get("agreementHash")
    closure_agreement_hash = closure.get("agreementHash")
    if execution_agreement_hash is None:
        results.append(_closure_result("indeterminate", "session agreement hash authority is unavailable"))
    elif not _sha256_hex(execution_agreement_hash):
        results.append(_closure_result("error", "session agreement hash authority is malformed"))
    if closure_agreement_hash is None:
        results.append(_closure_result("indeterminate", "agreement hash authority is unavailable"))
    elif not _sha256_hex(closure_agreement_hash):
        results.append(_closure_result("error", "agreement hash authority is malformed"))
    if not isinstance(anchor, dict) or anchor.get("locator") != deliverable_address:
        results.append(_closure_result("fail", "attested payload anchor does not bind the exact job and phase"))
    if delivered is not None and (
        delivered.get("logicalAddress") != deliverable_address
        or delivered.get("cleartextHash") != record.get("deliverableContentHash")
    ):
        results.append(_closure_result("fail", "attested payload does not close over the exact job and phase"))
    if delivered is not None and "storedHash" in delivered:
        results.append(_closure_result(
            "error", "attested payload uses obsolete storedHash resolver metadata"
        ))

    cleartext = delivered.get("cleartextUtf8") if delivered is not None else None
    cleartext_bytes = None
    if delivered is not None:
        cleartext_result, cleartext_bytes = _resolved_exact_bytes(
            delivered, "attested payload cleartext"
        )
        results.append(cleartext_result)
        if (
            cleartext_bytes is not None
            and hashlib.sha256(cleartext_bytes).hexdigest()
            != record.get("deliverableContentHash")
        ):
            results.append(_closure_result("fail", "attested payload bytes do not match delivery evidence"))

    payload_record = attestation_entry.get("artifact") if attestation_entry is not None else None
    if attestation_entry is not None and not isinstance(payload_record, dict):
        results.append(_closure_result("error", "resolved payload attestation record is malformed"))
        payload_record = None
    if not _attestation_ref_shape_valid(attestation_ref):
        results.append(_closure_result("error", "payload attestation reference is malformed"))
    if payload_record is None:
        return _combine_closure_results(results)

    payload_type_valid = _delivery_inner_type_valid(
        payload_record, "payloadAttestationVersion"
    )
    if not payload_type_valid:
        results.append(_closure_result(
            "fail", "payload attestation record has an unsupported type"
        ))
    elif not _payload_attestation_record_shape_valid(payload_record):
        results.append(_closure_result(
            "error", "payload attestation record is malformed"
        ))
    attempt = payload_record.get("attempt")
    method_hash = payload_record.get("verificationMethodHash")
    attestation_address = (
        f"dacs4:payload-attestation:{job_id}:{method_hash}:{attempt}"
        if legacy
        else f"dacs4:payload-attestation:{job_id}:{phase_index}:{method_hash}:{attempt}"
    )
    signature = payload_record.get("signature")
    if (
        isinstance(attempt, bool)
        or not isinstance(attempt, int)
        or attempt < 0
        or attempt > _MAX_SAFE_JSON_INTEGER
        or not isinstance(attestation_ref, dict)
        or attestation_ref.get("anchor")
        != {"kind": "storage-program", "locator": attestation_address}
        or attestation_entry.get("logicalAddress") != attestation_address
        or attestation_ref.get("contentHash")
        != _signed_envelope_content_hash(payload_record)
        or (
            "signer" in attestation_ref
            and isinstance(signature, dict)
            and attestation_ref.get("signer") != signature.get("signer")
        )
        or not payload_type_valid
        or not _signed_inner_artifact_valid(
            payload_record, PAYLOAD_ATTESTATION_DOMAIN, pubkeys
        )
    ):
        results.append(_closure_result("fail", "payload attestation does not bind its exact phase-indexed artifact"))

    offering = listing.get("offering")
    deliverable_spec = offering.get("deliverable") if isinstance(offering, dict) else None
    method = (
        deliverable_spec.get("verificationMethod")
        if isinstance(deliverable_spec, dict) else None
    )
    access_model = (
        deliverable_spec.get("accessModel", "public")
        if isinstance(deliverable_spec, dict) else "public"
    )
    if delivered is not None:
        results.append(_validate_resolved_storage(
            delivered,
            record.get("deliverableContentHash"),
            access_model,
            "attested payload",
            authenticated_storage_binding=(
                payload_receipt.get("storageBinding")
                if isinstance(payload_receipt, dict) else None
            ),
            buyer=buyer,
        ))
    results.append(validate_payload_attestation_locator_context(
        payload_record,
        attestation_ref,
        execution,
        method,
        legacy=legacy,
    ))
    if (
        not isinstance(deliverable_spec, dict)
        or not isinstance(method, dict)
        or deliverable_spec.get("kind") != "attested-payload"
        or payload_record.get("jobId") != job_id
        or (
            execution_agreement_hash is not None
            and payload_record.get("agreementHash") != execution_agreement_hash
        )
        or (
            closure_agreement_hash is not None
            and payload_record.get("agreementHash") != closure_agreement_hash
        )
        or payload_record.get("deliverableSpecHash")
        != _complete_object_hash(deliverable_spec)
        or payload_record.get("payloadFormat") != deliverable_spec.get("payloadFormat")
        or payload_record.get("payloadContentHash") != record.get("deliverableContentHash")
        or payload_record.get("verificationMethod") != method.get("kind")
        or payload_record.get("verificationMethodHash") != _complete_object_hash(method)
        or payload_record.get("decision") != "pass"
        or "credentialDelivery" in record
    ):
        results.append(_closure_result("fail", "payload attestation does not bind authenticated commerce context"))

    method_kind = method.get("kind") if isinstance(method, dict) else None
    if method_kind == "self-signed":
        if "methodTransactionRef" in payload_record:
            results.append(_closure_result(
                "fail", "self-signed payload attestation carries a native transaction"
            ))
    elif method_kind == "consensus-backed-proxy":
        if "methodTransactionRef" not in payload_record:
            results.append(_closure_result(
                "fail", "transaction-bound payload attestation lacks its native transaction"
            ))
    else:
        results.append(_closure_result(
            "error", "payload attestation uses an unsupported verification method"
        ))

    method_ref = payload_record.get("methodEvidenceRef")
    method_writer = method_ref.get("signer") if isinstance(method_ref, dict) else None
    method_dependency_result, method_entry, _ = _resolved_delivery_dependency(
        closure.get("methodEvidence"),
        method_ref,
        verified_receipt_by_canonical_ref,
        completed,
        "method evidence",
        job_id=job_id,
        phase_index=authenticated_phase_index,
        phase_kind=phase,
        expected_writer=method_writer,
    )
    results.append(method_dependency_result)
    method_evidence = method_entry.get("artifact") if method_entry is not None else None
    if method_entry is not None and not isinstance(method_evidence, dict):
        results.append(_closure_result("error", "resolved method evidence is malformed"))
        method_evidence = None
    if not _attestation_ref_shape_valid(method_ref):
        results.append(_closure_result("error", "method evidence reference is malformed"))
    elif method_entry is not None and (
        method_entry.get("logicalAddress") != method_ref.get("anchor", {}).get("locator")
        or method_ref.get("contentHash") != _complete_object_hash(method_evidence)
    ):
        results.append(_closure_result("fail", "method evidence does not match its authenticated reference"))
    if method_evidence is not None and cleartext_bytes is not None:
        results.append(validate_delivery_method_evidence(
            method,
            method_evidence,
            payload_record.get("methodTransactionRef"),
            trusted_native_observations_by_canonical_ref,
            delivered_cleartext=cleartext,
            delivered_bytes=cleartext_bytes,
            payload_content_hash=record.get("deliverableContentHash"),
            require_finalized=completed,
        ))
    return _combine_closure_results(results)


def _resolve_authenticated_evidence_binding(ref, record, signer, bundle,
                                            session_execution_authority_by_phase_key,
                                            verified_receipt_by_canonical_ref,
                                            evidence_type, *,
                                            receipt_validator=_validate_current_evidence_receipt):
    """Resolve one exact phase from trusted SB-1 authority plus verified SR-2 receipt evidence."""
    ref_key = canonical(ref).decode("utf-8")
    receipt = verified_receipt_by_canonical_ref.get(ref_key)
    if not isinstance(receipt, dict):
        return (False, "evidence record lacks a verified SR-2 receipt", None)
    matches = []
    current_delivery = evidence_type == "delivery"
    for phase_key, execution in session_execution_authority_by_phase_key.items():
        if not isinstance(execution, dict):
            continue
        phase_index = execution.get("phaseIndex")
        phase_kind = execution.get("phaseKind")
        if (
            isinstance(phase_index, bool)
            or not isinstance(phase_index, int)
            or phase_index < 0
            or phase_key != f"{phase_index}:{phase_kind}"
            or execution.get("jobId") != bundle.get("jobId")
            or phase_kind != record.get("phase")
            or (current_delivery and phase_index != record.get("phaseIndex"))
            or execution.get("phaseOrchestrator") != signer
        ):
            continue
        resolution_classes = [False]
        if (
            phase_kind in {"pay-cross-chain-htlc", "pay-cross-chain-liquidity-tank"}
            and record.get("outcome") == "success"
        ):
            resolution_classes.append(True)
        for resolved in resolution_classes:
            ok, _ = _validate_evidence_resolution_binding(
                ref, execution, receipt, bundle, phase_index, phase_kind, signer,
                resolved=resolved, current_delivery=current_delivery,
                receipt_validator=receipt_validator,
            )
            if ok:
                matches.append((phase_key, resolved))
    if len(matches) != 1:
        return (False, "evidence does not resolve to exactly one authenticated phase receipt", None)
    return (True, matches[0], receipt)


def _known_authenticated_st8_successor(
    interim_ref,
    interim_record,
    phase_key,
    bundle,
    pubkeys,
    reference_validation_by_canonical_ref,
    session_execution_authority_by_phase_key,
    verified_receipt_by_canonical_ref,
    receipt_validator,
):
    """Return true only for a fully authenticated exact-:resolved successor already in authority."""
    interim_id = canonical(interim_ref)
    for ref_key, resolution in reference_validation_by_canonical_ref.items():
        if not isinstance(ref_key, str) or not isinstance(resolution, dict):
            continue
        try:
            candidate_ref = json.loads(ref_key)
        except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
            continue
        if not _attestation_ref_shape_valid(candidate_ref):
            continue
        candidate = resolution.get("record")
        signature = candidate.get("signature") if isinstance(candidate, dict) else None
        if (
            not _settlement_evidence_shape_valid(candidate)
            or candidate.get("jobId") != bundle.get("jobId")
            or candidate.get("phase") != interim_record.get("phase")
            or candidate.get("outcome") != "success"
            or canonical(candidate.get("supersedesEvidenceRef")) != interim_id
            or candidate_ref.get("contentHash") != settlement_evidence_hash(candidate)
            or not isinstance(signature, dict)
            or signature.get("algorithm") != "ed25519"
            or not isinstance(signature.get("signer"), str)
            or signature["signer"] not in pubkeys
        ):
            continue
        canonical_ok, _ = sig6_canonical(signature.get("value", ""))
        if not canonical_ok or not verify_sig(
            pubkeys[signature["signer"]],
            SETTLEMENT_EVIDENCE_DOMAIN,
            settlement_evidence_hash(candidate),
            signature["value"],
        ):
            continue
        binding_ok, binding_result, _ = _resolve_authenticated_evidence_binding(
            candidate_ref,
            candidate,
            signature["signer"],
            bundle,
            session_execution_authority_by_phase_key,
            verified_receipt_by_canonical_ref,
            "settlement",
            receipt_validator=receipt_validator,
        )
        lifecycle = resolution.get("lifecycle")
        if (
            binding_ok
            and binding_result == (phase_key, True)
            and isinstance(lifecycle, dict)
            and _string_member(lifecycle.get("state"), {"included", "finalized"})
        ):
            return True
    return False


def _validate_ebfab_boolean(
    bundle,
    listing,
    pubkeys,
    reference_validation_by_canonical_ref,
    bundle_lifecycle,
    session_execution_authority_by_phase_key,
    verified_receipt_by_canonical_ref,
    delivery_artifact_authority_by_phase_key=None,
    trusted_native_observations_by_canonical_ref=None,
    *,
    effective_pipeline=None,
    additional_commit_phase=None,
    _receipt_validator=_validate_current_evidence_receipt,
):
    """Execute the authenticated SEB gate needed before EBFAB reconciliation.

    This bounded reference covers the protected #290 authority path: exact type/domain
    signatures, content-bound signed listing pipeline, phase-key derivation, the
    settlementEvidence bijection, and the SR-2 lifecycle threshold. It intentionally
    remains test support rather than a general DACS validator.
    """
    if not _full_bundle_family_shape_valid(bundle, "evidence-bound"):
        return (False, "not an EvidenceBoundFaultAttestationBundle", None)
    if not _absolute_fault_bundle_shape_valid(bundle, "evidence-bound"):
        return (False, "malformed EvidenceBoundFaultAttestationBundle", None)
    if (
        not isinstance(listing, dict)
        or not isinstance(pubkeys, dict)
        or not isinstance(reference_validation_by_canonical_ref, dict)
        or not isinstance(bundle_lifecycle, dict)
        or not isinstance(session_execution_authority_by_phase_key, dict)
        or not isinstance(verified_receipt_by_canonical_ref, dict)
        or (
            delivery_artifact_authority_by_phase_key is not None
            and not isinstance(delivery_artifact_authority_by_phase_key, dict)
        )
    ):
        return (False, "missing listing, key, exact reference, or bundle-lifecycle authority", None)
    ok, reason = _bundle_signatures_valid_for_family(
        bundle, pubkeys, "evidence-bound"
    )
    if not ok:
        return (False, reason, None)
    try:
        permissible_faults = implied_fault_set(
            bundle.get("outcome"), bundle.get("anchoredByRole"), roster_roles(bundle))
    except (KeyError, TypeError, ValueError) as exc:
        return (False, "invalid absolute fault attribution context: %s" % exc, None)
    if bundle.get("faultedParty") not in permissible_faults:
        return (False, "faultedParty is outside the §10.4.1 permissible set", None)
    signature = listing.get("signature")
    if not isinstance(signature, dict):
        return (False, "listing signature missing", None)
    signer = signature.get("signer")
    seller_primary_claim = listing.get("sellerPrimaryClaim")
    if not isinstance(seller_primary_claim, str):
        seller_primary_claim = (
            listing.get("seller", {}).get("identity", {}).get("presentedBy")
            if isinstance(listing.get("seller"), dict)
            else None
        )
    if (
        signature.get("algorithm") != "ed25519"
        or not isinstance(signer, str)
        or signer != seller_primary_claim
        or signer not in pubkeys
    ):
        return (False, "listing signer or algorithm unsupported", None)
    canonical_ok, canonical_reason = sig6_canonical(signature.get("value", ""))
    if not canonical_ok:
        return (False, canonical_reason, None)
    content_hash = listing_hash(listing)
    if not verify_sig(pubkeys[signer], LISTING_DOMAIN, content_hash, signature["value"]):
        return (False, "listing signature does not verify", None)

    listing_ref = bundle.get("listingRef")
    if not isinstance(listing_ref, dict) or (
        listing_ref.get("listingId") != listing.get("listingId")
        or listing_ref.get("version") != listing.get("listingVersion")
        or listing_ref.get("contentHash") != content_hash
    ):
        return (False, "listingRef does not bind the signed listing", None)

    signed_pipeline = listing.get("pipeline")
    pipeline = signed_pipeline
    if effective_pipeline is not None:
        if (
            not isinstance(signed_pipeline, list)
            or not isinstance(effective_pipeline, list)
            or len(signed_pipeline) != len(effective_pipeline)
        ):
            return (False, "APR effective pipeline is malformed", None)
        alternative_indexes = [
            index for index, step in enumerate(signed_pipeline)
            if isinstance(step, dict) and step.get("kind") == "pay-alternative"
        ]
        if len(alternative_indexes) != 1:
            return (False, "APR effective pipeline lacks one signed projection slot", None)
        alternative_index = alternative_indexes[0]
        for index, (signed_step, projected_step) in enumerate(
            zip(signed_pipeline, effective_pipeline)
        ):
            if index == alternative_index:
                projected_parameters = (
                    projected_step.get("parameters")
                    if isinstance(projected_step, dict)
                    else None
                )
                if (
                    not isinstance(projected_step, dict)
                    or projected_step.get("kind") not in PAYMENT_PHASES
                    or not isinstance(projected_parameters, dict)
                    or set(projected_parameters) != {"rail"}
                    or not isinstance(projected_parameters.get("rail"), str)
                ):
                    return (False, "APR projected payment step is malformed", None)
            elif canonical(signed_step) != canonical(projected_step):
                return (False, "APR projection changed a non-payment step", None)
        pipeline = effective_pipeline
    phase_set = SUPPORTED_PHASES
    if additional_commit_phase is not None:
        if not _string_member(additional_commit_phase, ADDITIVE_COMMIT_PHASES):
            return (False, "additional commitment phase is unsupported", None)
        phase_set = phase_set | {additional_commit_phase}
    summary = bundle.get("phaseSummary")
    if not isinstance(pipeline, list) or not isinstance(summary, list):
        return (False, "pipeline or phaseSummary is not an array", None)
    if any(
        not isinstance(step, dict)
        or not _string_member(step.get("kind"), phase_set)
        for step in pipeline
    ):
        return (False, "signed listing pipeline contains an unsupported phase", None)
    pipeline_kinds = [step["kind"] for step in pipeline]
    seen_indices = set()
    expected_keys = []
    optional_pointers = {}
    summary_by_key = {}
    for entry in summary:
        if not isinstance(entry, dict):
            return (False, "phaseSummary entry is not an object", None)
        index = entry.get("index")
        kind = entry.get("kind")
        if (
            isinstance(index, bool)
            or not isinstance(index, int)
            or index < 0
            or index >= len(pipeline_kinds)
            or index in seen_indices
            or kind != pipeline_kinds[index]
            or not _string_member(entry.get("outcome"), {"ok", "fail"})
        ):
            return (False, "phaseSummary contradicts the signed listing pipeline", None)
        seen_indices.add(index)
        summary_by_key[f"{index}:{kind}"] = entry
        if kind in EVIDENCE_PHASES:
            ref = entry.get("attestationRef")
            phase_key = f"{index}:{kind}"
            expected_keys.append(phase_key)
            if ref is not None:
                if not _attestation_ref_shape_valid(ref):
                    return (False, "optional phase attestationRef is malformed", None)
                optional_pointers[phase_key] = ref

    # The signed phaseSummary is execution-result authority only when it is a
    # complete, outcome-consistent trace of the deterministic listing pipeline.
    # Otherwise an author could remove the same phase from phaseSummary and
    # settlementEvidence and make the supposed exact set circular.
    ordered_indices = [entry["index"] for entry in summary]
    if ordered_indices != list(range(len(summary))):
        return (False, "phaseSummary is not a contiguous execution prefix", None)
    bundle_outcome = bundle.get("outcome")
    retry_marker_indices = [
        index for index, entry in enumerate(summary) if "retryExhausted" in entry
    ]
    retry_marker_expected = (
        bundle_outcome == "failed-perm"
        and bool(summary)
        and summary[-1].get("outcome") == "fail"
        and summary[-1].get("errorClass") == "transient"
    )
    if retry_marker_expected:
        if retry_marker_indices != [len(summary) - 1] or summary[-1].get("retryExhausted") is not True:
            return (False, "transient terminal failure lacks exclusive authenticated retry exhaustion", None)
    elif retry_marker_indices:
        return (False, "retryExhausted is present outside the terminal transient failure", None)
    if bundle_outcome == "completed":
        if len(summary) != len(pipeline):
            return (False, "completed phaseSummary does not cover the full pipeline", None)
        if any(
            entry.get("outcome") == "fail" and entry.get("kind") != "rate"
            for entry in summary
        ):
            return (False, "completed phaseSummary contains a fatal phase failure", None)
    elif bundle_outcome in {"failed-perm", "failed-counterparty"}:
        if not summary or summary[-1].get("outcome") != "fail":
            return (False, "failed phaseSummary lacks its terminal failed result", None)
        if any(entry.get("outcome") != "ok" for entry in summary[:-1]):
            return (False, "failed phaseSummary is not an ok-prefix plus terminal failure", None)
        expected_error_classes = {
            "failed-perm": {"permanent", "transient"},
            "failed-counterparty": {"counterparty", "settlement-atomicity"},
        }
        if not _string_member(
            summary[-1].get("errorClass"), expected_error_classes[bundle_outcome]
        ):
            return (False, "terminal errorClass contradicts the failed bundle outcome", None)
        if (
            summary[-1].get("errorClass") == "transient"
            and summary[-1].get("retryExhausted") is not True
        ):
            return (False, "transient terminal failure lacks authenticated retry exhaustion", None)
    elif bundle_outcome == "failed-substrate":
        phase_failure = (
            bool(summary)
            and summary[-1].get("outcome") == "fail"
            and summary[-1].get("errorClass") == "substrate"
            and all(entry.get("outcome") == "ok" for entry in summary[:-1])
        )
        completed_before_audit_failure = (
            len(summary) == len(pipeline)
            and all(
                entry.get("outcome") == "ok"
                or (entry.get("kind") == "rate" and entry.get("outcome") == "fail")
                for entry in summary
            )
        )
        if not (phase_failure or completed_before_audit_failure):
            return (False, "failed-substrate phaseSummary is not outcome-consistent", None)
    elif bundle_outcome in _ABORT:
        if len(summary) >= len(pipeline) or any(entry.get("outcome") != "ok" for entry in summary):
            return (False, "aborted phaseSummary is not the completed prefix before no-result abort", None)
    else:
        return (False, "unsupported EBFAB outcome", None)

    actual_refs = bundle.get("settlementEvidence")
    if not isinstance(actual_refs, list):
        return (False, "settlementEvidence is not an array", None)
    if any(not _attestation_ref_shape_valid(ref) for ref in actual_refs):
        return (False, "settlementEvidence member is malformed", None)
    actual_ids = [canonical(ref) for ref in actual_refs]
    if len(actual_ids) != len(set(actual_ids)):
        return (False, "settlementEvidence contains a raw duplicate", None)
    exact_resolutions = [
        reference_validation_by_canonical_ref.get(canonical(ref).decode("utf-8"))
        for ref in actual_refs
    ]
    if any(not isinstance(resolution, dict) for resolution in exact_resolutions):
        return (False, "settlementEvidence member lacks exact authenticated resolution", None)
    authenticated_records = []
    actual_keys = []
    pending_closure_result = None
    for ref, resolution in zip(actual_refs, exact_resolutions):
        record = resolution.get("record")
        if not isinstance(record, dict):
            return (False, "evidence reference lacks an authenticated record", None)
        evidence_type = _authenticated_evidence_wire_type(record, pubkeys)
        if evidence_type == "settlement":
            shape_valid = _settlement_evidence_shape_valid(record)
            evidence_domain = SETTLEMENT_EVIDENCE_DOMAIN
        elif evidence_type == "delivery":
            shape_valid = _delivery_evidence_shape_valid(record)
            evidence_domain = DELIVERY_EVIDENCE_DOMAIN
        else:
            return (False, "evidence record has an unsupported or ambiguous discriminator", None)
        if not shape_valid:
            return (False, "evidence record does not satisfy its closed type shape", None)
        evidence_hash = (
            delivery_evidence_hash(record)
            if evidence_type == "delivery"
            else settlement_evidence_hash(record)
        )
        record_phase = record.get("phase")
        if record_phase in PAYMENT_PHASES and evidence_type != "settlement":
            return (False, "payment phase does not resolve to SettlementEvidence", None)
        if record_phase in DELIVERY_PHASES:
            if evidence_type == "settlement" and pipeline_kinds.count(record_phase) != 1:
                return (False, "legacy delivery evidence is not a single unambiguous invocation", None)
        elif record_phase not in PAYMENT_PHASES:
            return (False, "evidence record does not name a supported evidence phase", None)
        signature = record.get("signature")
        if (
            record.get("jobId") != bundle.get("jobId")
            or not isinstance(signature, dict)
            or signature.get("algorithm") != "ed25519"
            or not isinstance(signature.get("signer"), str)
            or signature.get("signer") not in pubkeys
            or ref.get("contentHash") != evidence_hash
        ):
            return (False, "evidence record does not bind this job, phase, signer, or hash", None)
        canonical_ok, canonical_reason = sig6_canonical(signature.get("value", ""))
        if not canonical_ok:
            return (False, canonical_reason, None)
        if not verify_sig(
            pubkeys[signature["signer"]],
            evidence_domain,
            evidence_hash,
            signature["value"],
        ):
            return (False, "evidence signature does not verify under its type domain", None)
        binding_ok, binding_result, _ = _resolve_authenticated_evidence_binding(
            ref,
            record,
            signature["signer"],
            bundle,
            session_execution_authority_by_phase_key,
            verified_receipt_by_canonical_ref,
            evidence_type,
            receipt_validator=_receipt_validator,
        )
        if not binding_ok:
            return (False, binding_result, None)
        phase_key, resolved_record = binding_result
        phase_index = int(phase_key.split(":", 1)[0])
        if phase_index >= len(pipeline_kinds) or record.get("phase") != pipeline_kinds[phase_index]:
            return (False, "authenticated phase is outside the signed listing pipeline", None)
        summary_entry = summary_by_key.get(phase_key)
        expected_record_outcome = (
            "success" if isinstance(summary_entry, dict) and summary_entry.get("outcome") == "ok"
            else "failure"
        )
        if not isinstance(summary_entry, dict) or record["outcome"] != expected_record_outcome:
            return (False, "evidence record contradicts the signed phase result", None)
        if record_phase in DELIVERY_PHASES:
            delivery_authority = (
                delivery_artifact_authority_by_phase_key
                if isinstance(delivery_artifact_authority_by_phase_key, dict)
                else {}
            )
            closure_disposition, closure_reason = (
                _validate_delivery_artifact_closure_disposition(
                    record,
                    phase_key,
                    listing,
                    bundle,
                    pubkeys,
                    session_execution_authority_by_phase_key.get(phase_key),
                    delivery_authority.get(phase_key),
                    verified_receipt_by_canonical_ref,
                    trusted_native_observations_by_canonical_ref,
                    legacy=evidence_type == "settlement",
                )
            )
            if closure_disposition in {"fail", "error"}:
                return (
                    False,
                    _DispositionReason(closure_reason, closure_disposition),
                    None,
                )
            if closure_disposition == "indeterminate" and pending_closure_result is None:
                pending_closure_result = (closure_disposition, closure_reason)
        actual_keys.append(phase_key)
        authenticated_records.append((ref, resolution, record, phase_key, resolved_record))
    if (
        None in actual_keys
        or len(actual_keys) != len(set(actual_keys))
        or len(expected_keys) != len(set(expected_keys))
        or set(actual_keys) != set(expected_keys)
    ):
        return (False, "settlementEvidence is not the exact phase-result set", None)
    actual_ref_by_key = dict(zip(actual_keys, actual_refs))
    for phase_key, pointer in optional_pointers.items():
        if canonical(pointer) != canonical(actual_ref_by_key[phase_key]):
            return (False, "optional phase pointer contradicts settlementEvidence", None)

    # ST-8 terminal selection is derived from authenticated SettlementEvidence
    # content. A signed success record binds the superseded interim reference;
    # the referenced record must itself authenticate as the same job/phase and
    # as the specific asymmetric interim failure. Caller-supplied class/edge
    # metadata has no authority here.
    st8_reason_by_phase = {
        "pay-cross-chain-htlc": "dest-revealed-source-unclaimed",
        "pay-cross-chain-liquidity-tank": "tank-locked-unreleased",
    }
    st8_reasons = set(st8_reason_by_phase.values())
    for ref, resolution, record, phase_key, st8_resolved_anchor in authenticated_records:
        summary_entry = summary_by_key[phase_key]
        supersedes = record.get("supersedesEvidenceRef")
        expected_st8_reason = st8_reason_by_phase.get(record.get("phase"))
        expired_st8 = (
            record.get("phase") == "pay-cross-chain-htlc"
            and summary_entry.get("errorClass") == "settlement-atomicity"
        ) or (
            record.get("phase") == "pay-cross-chain-liquidity-tank"
            and summary_entry.get("errorClass") == "substrate"
            and record.get("reason") == expected_st8_reason
        )
        if expired_st8:
            if (
                record.get("outcome") != "failure"
                or expected_st8_reason is None
                or record.get("reason") != expected_st8_reason
                or supersedes is not None
            ):
                return (False, "expired ST-8 record has the wrong authenticated terminal class", None)
            if _known_authenticated_st8_successor(
                ref,
                record,
                phase_key,
                bundle,
                pubkeys,
                reference_validation_by_canonical_ref,
                session_execution_authority_by_phase_key,
                verified_receipt_by_canonical_ref,
                _receipt_validator,
            ):
                return (False, "expired ST-8 record suppresses a known authenticated successor", None)
        elif record.get("reason") in st8_reasons:
            return (False, "ST-8 interim reason contradicts the signed phase result", None)
        # The binding-verified PC-2 logical address, not the optional edge,
        # classifies an ST-8 resolution. A :resolved record must therefore
        # carry the signed edge; an edge at the ordinary phase address is not
        # a valid way to self-classify as ST-8.
        if st8_resolved_anchor and (
            record.get("outcome") != "success"
            or expected_st8_reason is None
            or supersedes is None
        ):
            return (False, "ST-8 resolved anchor lacks its signed supersession edge", None)
        if supersedes is not None and not st8_resolved_anchor:
            return (False, "ST-8 supersession edge is not bound to a resolved anchor", None)
        if supersedes is None:
            continue
        if (
            record.get("outcome") != "success"
            or record.get("phase") not in {
                "pay-cross-chain-htlc",
                "pay-cross-chain-liquidity-tank",
            }
            or not _attestation_ref_shape_valid(supersedes)
            or canonical(supersedes) in {canonical(item) for item in actual_refs}
        ):
            return (False, "invalid ST-8 supersession shape", None)
        interim_resolution = reference_validation_by_canonical_ref.get(
            canonical(supersedes).decode("utf-8")
        )
        if not isinstance(interim_resolution, dict):
            return (False, "ST-8 interim record lacks authenticated resolution", None)
        interim_record = interim_resolution.get("record")
        interim_lifecycle = interim_resolution.get("lifecycle")
        interim_signature = interim_record.get("signature") if isinstance(interim_record, dict) else None
        if (
            not _settlement_evidence_shape_valid(interim_record)
            or interim_record.get("jobId") != bundle.get("jobId")
            or interim_record.get("phase") != record.get("phase")
            or interim_record.get("outcome") != "failure"
            or interim_record.get("reason") != expected_st8_reason
            or supersedes.get("contentHash") != settlement_evidence_hash(interim_record)
            or not isinstance(interim_signature, dict)
            or interim_signature.get("algorithm") != "ed25519"
            or not isinstance(interim_signature.get("signer"), str)
            or interim_signature.get("signer") not in pubkeys
            or not isinstance(interim_lifecycle, dict)
        ):
            return (False, "ST-8 successor does not authenticate its same-phase interim failure", None)
        canonical_ok, canonical_reason = sig6_canonical(interim_signature.get("value", ""))
        if not canonical_ok:
            return (False, canonical_reason, None)
        if not verify_sig(
            pubkeys[interim_signature["signer"]],
            SETTLEMENT_EVIDENCE_DOMAIN,
            settlement_evidence_hash(interim_record),
            interim_signature["value"],
        ):
            return (False, "ST-8 interim evidence signature does not verify", None)
        interim_binding_ok, interim_binding_result, _ = _resolve_authenticated_evidence_binding(
            supersedes,
            interim_record,
            interim_signature["signer"],
            bundle,
            session_execution_authority_by_phase_key,
            verified_receipt_by_canonical_ref,
            "settlement",
            receipt_validator=_receipt_validator,
        )
        if not interim_binding_ok:
            return (False, interim_binding_result, None)
        interim_phase_key, interim_resolved = interim_binding_result
        if interim_phase_key != phase_key or interim_resolved:
            return (False, "ST-8 interim receipt resolves to a different authenticated phase", None)
        if bundle.get("outcome") == "completed" and (
            interim_lifecycle.get("state") != "finalized"
            or interim_lifecycle.get("independentlyResolvable") is not True
        ):
            return (False, "completed ST-8 interim dependency is not finalized and independently resolvable", None)
        if (
            bundle.get("outcome") != "completed"
            and not _string_member(interim_lifecycle.get("state"), {"included", "finalized"})
        ):
            return (False, "failed ST-8 interim dependency is not included or finalized", None)

    completed = bundle.get("outcome") == "completed"
    for ref, resolution in zip(actual_refs, exact_resolutions):
        lifecycle = resolution.get("lifecycle")
        if not isinstance(lifecycle, dict):
            return (False, "evidence record lacks authenticated lifecycle", None)
        state = lifecycle.get("state")
        receipt = verified_receipt_by_canonical_ref.get(
            canonical(ref).decode("utf-8")
        )
        receipt_matches, _ = (
            _receipt_validator(receipt, None, expected_state=state)
            if isinstance(receipt, dict) else (False, "missing receipt")
        )
        if not receipt_matches:
            return (False, "evidence lifecycle contradicts its verified receipt", None)
        if completed and (
            state != "finalized" or lifecycle.get("independentlyResolvable") is not True
        ):
            return (False, "completed evidence is not finalized and independently resolvable", None)
        if not completed and not _string_member(state, {"included", "finalized"}):
            return (False, "failed or aborted evidence is not included or finalized", None)
    if completed and (
        bundle_lifecycle.get("state") != "finalized"
        or bundle_lifecycle.get("independentlyResolvable") is not True
    ):
        return (False, "completed EBFAB is not finalized and independently resolvable", None)
    if not completed and not _string_member(
        bundle_lifecycle.get("state"), {"included", "finalized"}
    ):
        return (False, "failed or aborted EBFAB is not included or finalized", None)
    if pending_closure_result is not None:
        disposition, reason = pending_closure_result
        return (False, _DispositionReason(reason, disposition), None)
    return (True, "ok", expected_keys)


def _validate_ebfab_disposition_with_receipts(receipt_validator, args, kwargs):
    selected = dict(kwargs)
    selected["_receipt_validator"] = receipt_validator
    ok, reason, phase_keys = _validate_ebfab_boolean(*args, **selected)
    if ok:
        return ("pass", str(reason), phase_keys)
    disposition = getattr(reason, "disposition", "fail")
    return (disposition, str(reason), None)


def validate_ebfab_disposition(*args, **kwargs):
    """Validate EBFAB admission with the current CORE AnchorReceipt contract."""
    return _validate_ebfab_disposition_with_receipts(
        _validate_current_evidence_receipt, args, kwargs
    )


def validate_legacy_ebfab_disposition(*args, **kwargs):
    """Validate frozen EBFAB fixtures with the named historical receipt contract."""
    return _validate_ebfab_disposition_with_receipts(
        _validate_legacy_evidence_receipt, args, kwargs
    )


def validate_ebfab(*args, **kwargs):
    """Boolean current-receipt EBFAB admission wrapper."""
    disposition, reason, phase_keys = validate_ebfab_disposition(*args, **kwargs)
    return (disposition == "pass", reason, phase_keys)


def validate_legacy_ebfab(*args, **kwargs):
    """Boolean archival EBFAB verifier; never current action authority."""
    disposition, reason, phase_keys = validate_legacy_ebfab_disposition(
        *args, **kwargs
    )
    return (disposition == "pass", reason, phase_keys)


def _tagged_copy_validation_for_derive(
    tagged, *, ebfab_validator=validate_ebfab_disposition
):
    """Preserve the SEB disposition/reason before divergence and ranking."""
    if not isinstance(tagged, dict):
        return ("error", "tagged copy is not an object")
    bundle = tagged.get("bundle")
    bundle_authority = tagged.get("bundleAdmissionAuthority")
    ebfab_authority = tagged.get("ebfabAuthority")
    if bundle_authority is None and ebfab_authority is None:
        return ("indeterminate", "bundle admission authority is unavailable")
    bundle_pubkeys = (
        bundle_authority.get("publicKeys")
        if isinstance(bundle_authority, dict) else None
    )
    ebfab_pubkeys = (
        ebfab_authority.get("publicKeys")
        if isinstance(ebfab_authority, dict) else None
    )
    bundle_kind = _authenticated_bundle_signature_family(bundle, bundle_pubkeys)
    ebfab_kind = _authenticated_bundle_signature_family(bundle, ebfab_pubkeys)
    if ebfab_kind == "evidence-bound":
        kind = ebfab_kind
        pubkeys = ebfab_pubkeys
    elif bundle_kind in {"legacy", "fault"}:
        kind = bundle_kind
        pubkeys = bundle_pubkeys
    elif bundle_kind == "evidence-bound":
        if not isinstance(ebfab_authority, dict):
            return ("indeterminate", "EBFAB validation authority is unavailable")
        if not isinstance(ebfab_pubkeys, dict):
            return ("indeterminate", "EBFAB public-key authority is unavailable")
        return ("error", "EBFAB family cannot be authenticated by EBFAB authority")
    else:
        kind = None
        pubkeys = None
    if kind is None:
        if bundle_authority is not None and not isinstance(bundle_authority, dict):
            return ("error", "bundle admission authority is malformed")
        if bundle_authority is not None and not isinstance(bundle_pubkeys, dict):
            return ("indeterminate", "bundle admission public-key authority is unavailable")
        return ("error", "tagged copy family cannot be authenticated before parsing")
    ok, reason = _bundle_signatures_valid_for_family(bundle, pubkeys, kind)
    if not ok:
        return ("error", reason)
    if kind != "evidence-bound":
        return ("pass", "non-EBFAB copy uses its existing admission path")
    if not isinstance(ebfab_authority, dict):
        return ("indeterminate", "EBFAB validation authority is unavailable")
    disposition, reason, _ = ebfab_validator(
        bundle,
        ebfab_authority.get("listing"),
        ebfab_authority.get("publicKeys"),
        ebfab_authority.get("referenceValidationByCanonicalRef"),
        ebfab_authority.get("bundleLifecycle"),
        ebfab_authority.get("sessionExecutionAuthorityByPhaseKey"),
        ebfab_authority.get("verifiedReceiptByCanonicalRef"),
        ebfab_authority.get("deliveryArtifactAuthorityByPhaseKey"),
        ebfab_authority.get("trustedNativeTransactionObservationsByCanonicalRef"),
        effective_pipeline=ebfab_authority.get("effectivePipeline"),
        additional_commit_phase=ebfab_authority.get("additionalCommitPhase"),
    )
    return (disposition, reason)


def _tagged_copy_valid_for_derive(tagged):
    """Boolean current-receipt admission wrapper."""
    disposition, _ = _tagged_copy_validation_for_derive(tagged)
    return disposition == "pass"


def _tagged_legacy_copy_validation_for_derive(tagged):
    """Apply the frozen selector-based derive admission contract.

    Legacy/FAB copies retain their released syntactic admission. EBFAB is the
    sole family that additionally requires its named archival SEB authority.
    """
    if not isinstance(tagged, dict):
        return ("error", "tagged copy is not an object")
    bundle = tagged.get("bundle")
    kind = bundle_type(bundle)
    if kind is None:
        return ("error", "tagged copy has an unsupported bundle type")
    if kind != "evidence-bound":
        return ("pass", "non-EBFAB copy uses its existing admission path")
    authority = tagged.get("ebfabAuthority")
    if not isinstance(authority, dict):
        return ("indeterminate", "EBFAB validation authority is unavailable")
    disposition, reason, _ = validate_legacy_ebfab_disposition(
        bundle,
        authority.get("listing"),
        authority.get("publicKeys"),
        authority.get("referenceValidationByCanonicalRef"),
        authority.get("bundleLifecycle"),
        authority.get("sessionExecutionAuthorityByPhaseKey"),
        authority.get("verifiedReceiptByCanonicalRef"),
        authority.get("deliveryArtifactAuthorityByPhaseKey"),
        authority.get("trustedNativeTransactionObservationsByCanonicalRef"),
        effective_pipeline=authority.get("effectivePipeline"),
        additional_commit_phase=authority.get("additionalCommitPhase"),
    )
    return (disposition, reason)


def _tagged_legacy_copy_valid_for_derive(tagged):
    """Boolean archival-receipt admission wrapper."""
    disposition, _ = _tagged_legacy_copy_validation_for_derive(tagged)
    return disposition == "pass"


def _post_fetch_binding_valid_with_profile(
        fetched, binding, pubkeys, *, family_resolver, bundle_validator,
        family_refusal):
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
    if not isinstance(binding, dict):
        return (False, "binding is not an object")
    family = family_resolver(fetched, pubkeys)
    if family is None:
        return (False, family_refusal("full-bundle"))
    ok_sig, reason = bundle_validator(fetched, pubkeys, family)
    if not ok_sig:
        return (False, reason)
    if fetched.get("jobId") != binding.get("jobId"):
        return (False, "BB-5 check 7: fetched.jobId != binding.jobId")
    if not _holds_role(fetched, binding.get("signer"), binding.get("role")):
        return (False, "BB-5 check 9: signer does not hold the claimed role in the bundle roster")
    if fetched.get("anchoredByRole") != binding.get("role"):
        return (False, "BB-5 check 9: anchoredByRole (%r) != bound role (%r)"
                % (fetched.get("anchoredByRole"), binding.get("role")))
    if family in {"fault", "evidence-bound"}:
        roster = roster_roles(fetched)
        try:
            fset = implied_fault_set(fetched.get("outcome"), fetched.get("anchoredByRole"), roster)
        except ValueError as exc:
            return (False, "§10.4.1 %s" % (exc,))
        if fetched.get("faultedParty") not in fset:
            return (False, "§10.4.1 faultedParty %r outside the permissible set %r for (%r, %r)"
                    % (fetched.get("faultedParty"), sorted(fset), fetched.get("outcome"),
                       fetched.get("anchoredByRole")))
    if bundle_hash(fetched) != binding.get("bundleContentHash"):
        return (False, "BB-5 check 8: recomputed §10.4.1 hash != binding.bundleContentHash")
    return (True, "ok")


def _post_fetch_valid(fetched, binding, pubkeys):
    """Current BB-5 post-fetch validation with authenticated family selection."""
    return _post_fetch_binding_valid_with_profile(
        fetched,
        binding,
        pubkeys,
        family_resolver=_authenticated_bundle_signature_family,
        bundle_validator=_current_bundle_validation,
        family_refusal=_current_family_refusal,
    )


def _post_fetch_legacy_valid(fetched, binding, pubkeys):
    """Archival BB-5 post-fetch validation under the released selector contract."""
    return _post_fetch_binding_valid_with_profile(
        fetched,
        binding,
        pubkeys,
        family_resolver=_syntactic_bundle_family,
        bundle_validator=_legacy_bundle_validation,
        family_refusal=_legacy_family_refusal,
    )


def _post_fetch_address_valid_with_profile(
        fetched, resolved_address, expected_role, expected_content_hash, pubkeys,
        expected_jobid=None, expected_participant=None, *, pure_mapping_resolver,
        job_id_validator, family_resolver, bundle_validator, family_refusal):
    """Pure-mapping equivalent of BB-5 post-fetch validation.

    The role is authenticated by recomputing its deterministic logical/native address from the
    fetched jobId rather than by a BundleBinding. The fetched copy still has to satisfy the same
    role, signature, fault-permissibility, and byte-recomputed content-hash checks.
    """
    if not isinstance(fetched, dict):
        return (False, "fetched copy is not an object")
    family = family_resolver(fetched, pubkeys)
    if family is None:
        return (False, family_refusal("full-bundle"))
    ok_sig, reason = bundle_validator(fetched, pubkeys, family)
    if not ok_sig:
        return (False, reason)
    job_id = fetched.get("jobId")
    if not isinstance(job_id, str):
        return (False, "pure-mapping check: fetched.jobId must be a string")
    if expected_jobid is not None and job_id != expected_jobid:
        return (False, "pure-mapping check: fetched.jobId != expected jobId")
    try:
        job_id_validator(job_id)
        expected_address = pure_mapping_resolver(job_id, expected_role)
    except ValueError as exc:
        return (False, "pure-mapping check: %s" % (exc,))
    if resolved_address != expected_address:
        return (False, "pure-mapping check: resolvedAddress != mapped address for fetched (jobId, role)")
    if fetched.get("anchoredByRole") != expected_role:
        return (False, "pure-mapping check: anchoredByRole (%r) != resolved role (%r)"
                % (fetched.get("anchoredByRole"), expected_role))
    parties = fetched.get("parties")
    if expected_participant is None:
        if not isinstance(parties, list) or not any(
            isinstance(party, dict) and party.get("role") == expected_role
            for party in parties
        ):
            return (False, "pure-mapping check: fetched roster has no holder for resolved role")
    else:
        role_holders = [
            party.get("primaryClaim")
            for party in parties
            if isinstance(party, dict)
            and party.get("role") == expected_role
            and isinstance(party.get("primaryClaim"), str)
        ] if isinstance(parties, list) else []
        if len(role_holders) != 1:
            return (False, "pure-mapping check: fetched roster lacks a unique holder for resolved role")
        if role_holders[0] != expected_participant:
            return (False, "pure-mapping check: role holder != authenticated participant")
    if family in {"fault", "evidence-bound"}:
        roster = roster_roles(fetched)
        try:
            fset = implied_fault_set(fetched.get("outcome"), expected_role, roster)
        except ValueError as exc:
            return (False, "§10.4.1 %s" % (exc,))
        if fetched.get("faultedParty") not in fset:
            return (False, "§10.4.1 faultedParty %r outside the permissible set %r for (%r, %r)"
                    % (fetched.get("faultedParty"), sorted(fset), fetched.get("outcome"), expected_role))
    if bundle_hash(fetched) != expected_content_hash:
        return (False, "pure-mapping check: recomputed §10.4.1 hash != expected contentHash")
    return (True, "ok")


def _post_fetch_address_valid(fetched, resolved_address, expected_role,
                              expected_content_hash, pubkeys,
                              expected_jobid=None,
                              pure_mapping_resolver=None,
                              trusted_contexts=None):
    """Validate a current address arm from independent role/key authority."""
    expected_participant = resolve_current_profile(
        expected_jobid, expected_role, trusted_contexts
    )
    if expected_participant is None:
        return (False, "current-profile-admission")
    keys = _authenticated_current_key_map(pubkeys)
    if keys is None:
        return (False, "current-crypto-admission")
    resolver = (
        pure_mapping_resolver
        if pure_mapping_resolver is not None
        else _current_logical_address
    )
    return _post_fetch_address_valid_with_profile(
        fetched,
        resolved_address,
        expected_role,
        expected_content_hash,
        keys,
        expected_jobid=expected_jobid,
        expected_participant=expected_participant,
        pure_mapping_resolver=resolver,
        job_id_validator=validate_current_job_id,
        family_resolver=_authenticated_bundle_signature_family,
        bundle_validator=_current_bundle_validation,
        family_refusal=_current_family_refusal,
    )


def _post_fetch_legacy_address_valid(fetched, resolved_address, expected_role,
                                     expected_content_hash, pubkeys,
                                     expected_jobid=None,
                                     pure_mapping_resolver=None):
    """Replay the frozen pre-JID-1 address arm through an explicit legacy path."""
    resolver = (
        pure_mapping_resolver
        if pure_mapping_resolver is not None
        else legacy_logical_address
    )
    return _post_fetch_address_valid_with_profile(
        fetched,
        resolved_address,
        expected_role,
        expected_content_hash,
        pubkeys,
        expected_jobid=expected_jobid,
        pure_mapping_resolver=resolver,
        job_id_validator=lambda job_id: job_id,
        family_resolver=_syntactic_bundle_family,
        bundle_validator=_legacy_bundle_validation,
        family_refusal=_legacy_family_refusal,
    )


def _role_evidence_locator(role_evidence):
    if role_evidence.get("kind") == "binding":
        return (role_evidence.get("binding") or {}).get("nativeAddress")
    return role_evidence.get("resolvedAddress")


def _deref_role_copy(anchor_deref, role_evidence):
    """Fetch a role-authenticated copy at its anchor locator, never by content hash alone.

    Signatures and anchoredByRole are outside the bundle hash, so a content-hash lookup cannot
    distinguish role-specific or signature-standing-distinct copies. Without an anchor resolver,
    authenticated replay therefore fails closed instead of guessing which physical copy was read.
    """
    locator = _role_evidence_locator(role_evidence)
    if anchor_deref is None:
        return None
    try:
        return anchor_deref(locator)
    except KeyError:
        return None


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
    full_copies = {
        h: [cp for cp in cps
            if anchored is not None and _full_standing(anchored.get(cp["nativeAddress"]))]
        for h, cps in forms.items()
    }
    if len(forms) <= 1:
        # Canonically-equal copies collapse to one form. Prefer a full-standing copy within that form
        # so the reported governing address cannot be selected by lesser-copy address ordering.
        only_hash = next(iter(forms))
        copies = full_copies[only_hash] or forms[only_hash]
        return _out("present", copies[0]["nativeAddress"])
    # (c) full-signature precedence: standing computed from each form's ANCHORED bundle — FULL iff a
    #     signature is present for every party. Exactly one full-standing form takes precedence.
    full_forms = [h for h, copies in full_copies.items() if copies]
    if len(full_forms) == 1:
        return _out("present", full_copies[full_forms[0]][0]["nativeAddress"])
    # (d) equal standing (all lesser-signed, or 2+ full-standing) -> void -> indeterminate (BB-6/BB-7).
    return _out("indeterminate", None)


# --------------------------------------------------------------------------- #
# Extended-pointer triple-identity (E7)
# --------------------------------------------------------------------------- #
def _sha256_hex(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


_CLAIM_SCHEME = re.compile(r"[a-z][a-z0-9-]*\Z")
_CANONICAL_PERCENT_ESCAPE = re.compile(r"%[0-9A-F]{2}")


def _claim_reference_shape_valid(value):
    """Generic DACS-1 grammar plus the scheme/NFC/parameter portions of CF-2."""
    if not _nonempty_jcs_string(value) or ":" not in value:
        return False
    scheme, remainder = value.split(":", 1)
    if _CLAIM_SCHEME.fullmatch(scheme) is None or not remainder:
        return False
    identifier, separator, parameters = remainder.partition("?")
    if not identifier or unicodedata.normalize("NFC", identifier) != identifier:
        return False
    if not separator:
        return True
    if not parameters or "?" in parameters:
        return False
    pairs = parameters.split("&")
    keys = []
    for pair in pairs:
        if pair.count("=") != 1:
            return False
        key, parameter_value = pair.split("=", 1)
        if not key:
            return False
        for component in (key, parameter_value):
            index = 0
            while index < len(component):
                if component[index] == "%":
                    match = _CANONICAL_PERCENT_ESCAPE.match(component, index)
                    if match is None:
                        return False
                    index = match.end()
                else:
                    # Reserved delimiters inside a component must use uppercase percent encoding.
                    if component[index] in ":?&=%":
                        return False
                    index += 1
        keys.append(key)
    return keys == sorted(keys) and len(keys) == len(set(keys))


def _attestation_ref_shape_valid(ref):
    anchor = ref.get("anchor") if isinstance(ref, dict) else None
    return (
        isinstance(ref, dict)
        and set(ref) <= {"anchor", "contentHash", "signer"}
        and {"anchor", "contentHash"} <= set(ref)
        and isinstance(anchor, dict)
        and set(anchor) == {"kind", "locator"}
        and _string_member(anchor.get("kind"), SUPPORTED_ATTESTATION_ANCHOR_KINDS)
        and _nonempty_jcs_string(anchor.get("locator"))
        and _sha256_hex(ref.get("contentHash"))
        and (
            "signer" not in ref
            or _claim_reference_shape_valid(ref["signer"])
        )
    )


def _deliverable_ref_shape_valid(ref):
    """DACS-4 deliverable reference shape with its deliberately open anchor kind."""
    anchor = ref.get("anchor") if isinstance(ref, dict) else None
    return (
        isinstance(ref, dict)
        and set(ref) <= {"anchor", "contentHash", "signer"}
        and {"anchor", "contentHash"} <= set(ref)
        and isinstance(anchor, dict)
        and set(anchor) == {"kind", "locator"}
        and _nonempty_jcs_string(anchor.get("kind"))
        and _nonempty_jcs_string(anchor.get("locator"))
        and _sha256_hex(ref.get("contentHash"))
        and (
            "signer" not in ref
            or _claim_reference_shape_valid(ref["signer"])
        )
    )


def _absolute_fault_bundle_shape_valid(bundle, family=None):
    if family is None:
        family = bundle_type(bundle)
    if family not in {"fault", "evidence-bound"} or not _full_bundle_family_shape_valid(
        bundle, family
    ):
        return False
    listing_ref = bundle.get("listingRef")
    parties = bundle.get("parties")
    phase_summary = bundle.get("phaseSummary")
    signatures = bundle.get("signatures")
    if (
        not isinstance(bundle.get("jobId"), str)
        or not bundle["jobId"]
        or not _string_member(bundle.get("outcome"), {
            "completed", "failed-perm", "failed-counterparty", "failed-substrate",
            "aborted-by-self", "aborted-by-other",
        })
        or not _string_member(bundle.get("faultedParty"), {"buyer", "seller", "orchestrator", "none"})
        or not _string_member(bundle.get("anchoredByRole"), {"buyer", "seller", "orchestrator"})
        or not isinstance(listing_ref, dict)
        or not isinstance(listing_ref.get("listingId"), str)
        or isinstance(listing_ref.get("version"), bool)
        or not isinstance(listing_ref.get("version"), int)
        or not _sha256_hex(listing_ref.get("contentHash"))
        or not isinstance(parties, list)
        or len(parties) < 2
        or not isinstance(phase_summary, list)
        or not isinstance(bundle.get("vetRecords"), list)
        or not isinstance(bundle.get("settlementEvidence"), list)
        or isinstance(bundle.get("recipeRegistryVersion"), bool)
        or not isinstance(bundle.get("recipeRegistryVersion"), int)
        or isinstance(bundle.get("railRegistryVersion"), bool)
        or not isinstance(bundle.get("railRegistryVersion"), int)
        or isinstance(bundle.get("finalisedAt"), bool)
        or not isinstance(bundle.get("finalisedAt"), (int, float))
        or not isinstance(signatures, list)
    ):
        return False
    if any(
        not isinstance(party, dict)
        or not _string_member(party.get("role"), {"buyer", "seller", "orchestrator"})
        or not isinstance(party.get("primaryClaim"), str)
        or not _sha256_hex(party.get("bundleHash"))
        for party in parties
    ):
        return False
    if any(
        not isinstance(entry, dict)
        or isinstance(entry.get("index"), bool)
        or not isinstance(entry.get("index"), int)
        or not isinstance(entry.get("kind"), str)
        or not _string_member(entry.get("outcome"), {"ok", "fail"})
        or (
            "errorClass" in entry
            and not _string_member(
                entry.get("errorClass"),
                {"permanent", "transient", "counterparty", "substrate", "settlement-atomicity"},
            )
        )
        for entry in phase_summary
    ):
        return False
    if (
        any(not _attestation_ref_shape_valid(ref) for ref in bundle["vetRecords"])
        or any(not _attestation_ref_shape_valid(ref) for ref in bundle["settlementEvidence"])
        or any(
            entry.get("attestationRef") is not None
            and not _attestation_ref_shape_valid(entry["attestationRef"])
            for entry in phase_summary
        )
        or (
            bundle.get("agreementRef") is not None
            and not _attestation_ref_shape_valid(bundle["agreementRef"])
        )
    ):
        return False
    return all(
        isinstance(signature, dict)
        and isinstance(signature.get("party"), str)
        and isinstance(signature.get("algorithm"), str)
        and isinstance(signature.get("value"), str)
        for signature in signatures
    )


def resolve_fab_pointer(pointer, dereferenced_bundle, binding=None):
    """E7 triple-identity for a FaultBundleExtendedPointer anchoring. Returns
    {"ok": bool, "reason": str, "recomputedHash": hex}. BB-5 check 8 + §10.4.1 apply to
    the DEREFERENCED full bundle: binding.bundleContentHash == pointer.fullBundleContentHash
    == recomputed §10.4.1 hash of the dereferenced bundle. A mismatch is rejected content."""
    if not isinstance(pointer, dict) or not isinstance(dereferenced_bundle, dict):
        return {"ok": False, "reason": "pointer and dereferenced bundle must be objects", "recomputedHash": None}
    if binding is not None and not isinstance(binding, dict):
        return {"ok": False, "reason": "binding must be an object", "recomputedHash": None}
    if not _pointer_family_shape_valid(pointer, "fault"):
        return {"ok": False, "reason": "not a FaultBundleExtendedPointer discriminator", "recomputedHash": None}
    if not _full_bundle_family_shape_valid(dereferenced_bundle, "fault"):
        return {"ok": False, "reason": "dereferenced record is not a full FaultAttestationBundle", "recomputedHash": None}
    recomputed = bundle_hash(dereferenced_bundle)
    if pointer["fullBundleContentHash"] != recomputed:
        return {"ok": False, "reason": "dereferenced content hash mismatch", "recomputedHash": recomputed}
    if binding is not None and binding.get("bundleContentHash") != recomputed:
        return {"ok": False, "reason": "binding.bundleContentHash != dereferenced hash", "recomputedHash": recomputed}
    return {"ok": True, "reason": "triple-identity holds", "recomputedHash": recomputed}


def _extended_pointer_url_shape_valid(pointer_kind, full_bundle_url):
    if not isinstance(full_bundle_url, str):
        return False
    if pointer_kind != "evidence-bound":
        return True
    try:
        parsed_url = urlsplit(full_bundle_url)
        return (
            parsed_url.scheme == "https"
            and bool(parsed_url.hostname)
            and parsed_url.username is None
            and parsed_url.password is None
        )
    except (TypeError, ValueError):
        return False


def _pointer_family_shape_valid(pointer, family):
    if family not in _POINTER_DOMAIN_BY_FAMILY or not isinstance(pointer, dict):
        return False
    present = [
        candidate
        for candidate, selector in _BUNDLE_SELECTOR_BY_FAMILY.items()
        if selector in pointer
    ]
    return (
        present == [family]
        and pointer.get(_BUNDLE_SELECTOR_BY_FAMILY[family]) == "1"
        and pointer.get("pointerKind") == "extended"
    )


def _authenticated_pointer_signature_family(pointer, pubkeys):
    """Recover FAB/EBFAB pointer family from its verified domain, not its label."""
    if not isinstance(pointer, dict) or not isinstance(pubkeys, dict) or not HAVE_CRYPTO:
        return None
    signature = pointer.get("signature")
    if not isinstance(signature, dict):
        return None
    signer = signature.get("signer")
    value = signature.get("value")
    canonical_ok, _ = sig6_canonical(value)
    if (
        not isinstance(signer, str)
        or signer not in pubkeys
        or signature.get("algorithm") not in SUPPORTED_SIGNATURE_ALGORITHMS
        or not canonical_ok
    ):
        return None
    try:
        content_hash = pointer_hash(pointer)
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        return None
    candidates = [
        family
        for family, domain in _POINTER_DOMAIN_BY_FAMILY.items()
        if verify_sig(pubkeys[signer], domain, content_hash, value)
    ]
    return candidates[0] if len(candidates) == 1 else None


def _resolve_absolute_fault_pointer_payload(
    family,
    pointer,
    dereferenced_bundle,
    binding,
    keys,
    ebfab_authority,
    *,
    expected_jobid,
    expected_role,
    expected_signer,
    address_deriver,
    ebfab_validator,
):
    """Shared FAB/EBFAB type, signature, SEB, fault, and identity checks.

    The caller authenticates ``family`` from the pointer signature before this
    function parses the selector. Current and archival public entry points also
    select their receipt validator explicitly before entering this core.
    """
    if not isinstance(pointer, dict) or not isinstance(dereferenced_bundle, dict):
        return {"ok": False, "reason": "pointer and dereferenced bundle must be objects"}
    if binding is not None and not isinstance(binding, dict):
        return {"ok": False, "reason": "binding must be an object"}
    if not _pointer_family_shape_valid(pointer, family):
        return {"ok": False, "reason": "pointer selector does not match authenticated family context"}
    pointer_kind = family
    domain = _POINTER_DOMAIN_BY_FAMILY[family]
    if not _full_bundle_family_shape_valid(dereferenced_bundle, family):
        return {"ok": False, "reason": "pointer and dereferenced bundle types differ"}
    segment_refs = pointer.get("segmentRefs")
    full_bundle_url = pointer.get("fullBundleUrl")
    url_ok = _extended_pointer_url_shape_valid(pointer_kind, full_bundle_url)
    if (
        not url_ok
        or not _sha256_hex(pointer.get("fullBundleContentHash"))
        or (segment_refs is not None and (
            not isinstance(segment_refs, list)
            or any(not _attestation_ref_shape_valid(ref) for ref in segment_refs)
        ))
    ):
        return {"ok": False, "reason": "malformed extended pointer payload"}
    if not _absolute_fault_bundle_shape_valid(dereferenced_bundle, family):
        return {"ok": False, "reason": "malformed dereferenced absolute-fault bundle"}
    bundle_ok, bundle_reason = _bundle_signatures_valid_for_family(
        dereferenced_bundle, keys, family
    )
    if not bundle_ok:
        return {"ok": False, "reason": bundle_reason}
    try:
        permissible_faults = implied_fault_set(
            dereferenced_bundle.get("outcome"),
            dereferenced_bundle.get("anchoredByRole"),
            roster_roles(dereferenced_bundle),
        )
    except (KeyError, TypeError, ValueError) as exc:
        return {"ok": False, "reason": "invalid absolute fault attribution context: %s" % exc}
    if dereferenced_bundle.get("faultedParty") not in permissible_faults:
        return {"ok": False, "reason": "faultedParty is outside the §10.4.1 permissible set"}
    if pointer_kind == "evidence-bound":
        if not isinstance(ebfab_authority, dict):
            return {
                "ok": False,
                "disposition": "indeterminate",
                "reason": "EBFAB pointer lacks SEB validation authority",
            }
        seb_disposition, seb_reason, _ = ebfab_validator(
            dereferenced_bundle,
            ebfab_authority.get("listing"),
            keys,
            ebfab_authority.get("referenceValidationByCanonicalRef"),
            ebfab_authority.get("bundleLifecycle"),
            ebfab_authority.get("sessionExecutionAuthorityByPhaseKey"),
            ebfab_authority.get("verifiedReceiptByCanonicalRef"),
            ebfab_authority.get("deliveryArtifactAuthorityByPhaseKey"),
            ebfab_authority.get("trustedNativeTransactionObservationsByCanonicalRef"),
            effective_pipeline=ebfab_authority.get("effectivePipeline"),
            additional_commit_phase=ebfab_authority.get("additionalCommitPhase"),
        )
        if seb_disposition != "pass":
            return {
                "ok": False,
                "disposition": seb_disposition,
                "reason": "dereferenced EBFAB fails SEB: " + seb_reason,
            }

    signature = pointer.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519":
        return {"ok": False, "reason": "pointer signature missing or unsupported"}
    signer = signature.get("signer")
    if not isinstance(signer, str) or signer not in keys:
        return {"ok": False, "reason": "pointer signer key unavailable"}
    role_claims = [
        party.get("primaryClaim")
        for party in dereferenced_bundle.get("parties", [])
        if isinstance(party, dict)
        and party.get("role") == dereferenced_bundle.get("anchoredByRole")
    ]
    if len(role_claims) != 1 or signer != role_claims[0]:
        return {"ok": False, "reason": "pointer signer is not authorized for anchoredByRole"}
    canonical_ok, _ = sig6_canonical(signature.get("value", ""))
    if not canonical_ok or not verify_sig(
        keys[signer], domain, pointer_hash(pointer), signature.get("value", "")
    ):
        return {"ok": False, "reason": "pointer signature does not verify"}

    recomputed = bundle_hash(dereferenced_bundle)
    if pointer.get("fullBundleContentHash") != recomputed:
        return {"ok": False, "reason": "dereferenced content hash mismatch"}
    if binding is not None:
        binding_result = _verify_binding(
            binding,
            keys,
            expected_jobid=expected_jobid,
            expected_role=expected_role,
            expected_content_hash=recomputed,
            expected_signer=expected_signer,
            address_deriver=address_deriver,
        )
        if not binding_result["ok"]:
            return {"ok": False, "reason": "binding invalid: " + binding_result["reason"]}
    return {
        "ok": True,
        "disposition": "pass",
        "reason": "pointer type, signature, and triple identity hold",
    }


def resolve_absolute_fault_pointer(
    pointer, dereferenced_bundle, binding=None, pubkeys=None, ebfab_authority=None,
    trusted_contexts=None, *, expected_jobid=None, expected_role=None
):
    """Resolve a current FAB/EBFAB pointer after verifier-owned admission.

    The caller supplies already-dereferenced content; this function performs no
    network I/O. Authenticated keys, canonical session identity, role/profile
    authority, the bundle role holder, and the pointer signer are admitted before
    any bundle or pointer hashing/signature work, whether or not a binding exists.
    """
    if not isinstance(pointer, dict) or not isinstance(dereferenced_bundle, dict):
        return {"ok": False, "reason": "pointer and dereferenced bundle must be objects"}
    if binding is not None and not isinstance(binding, dict):
        return {"ok": False, "reason": "binding must be an object"}
    keys = _authenticated_current_key_map(pubkeys)
    if keys is None:
        return {"ok": False, "reason": "current-crypto-admission"}
    try:
        validate_current_job_id(expected_jobid)
    except ValueError:
        return {"ok": False, "reason": "job-id-validation"}
    expected_signer = resolve_current_profile(
        expected_jobid, expected_role, trusted_contexts
    )
    if expected_signer is None:
        return {"ok": False, "reason": "current-profile-admission"}
    if expected_signer not in keys:
        return {"ok": False, "reason": "current role authority key unavailable"}
    if (
        dereferenced_bundle.get("jobId") != expected_jobid
        or dereferenced_bundle.get("anchoredByRole") != expected_role
    ):
        return {"ok": False, "reason": "dereferenced bundle differs from trusted role authority"}
    parties = dereferenced_bundle.get("parties")
    role_claims = [
        party.get("primaryClaim")
        for party in parties if isinstance(party, dict)
        and party.get("role") == expected_role
    ] if isinstance(parties, list) else []
    if role_claims != [expected_signer]:
        return {"ok": False, "reason": "dereferenced bundle role holder differs from trusted role authority"}
    pointer_signature = pointer.get("signature")
    if (
        not isinstance(pointer_signature, dict)
        or pointer_signature.get("signer") != expected_signer
    ):
        return {"ok": False, "reason": "pointer signer differs from trusted role authority"}
    family = _authenticated_pointer_signature_family(pointer, keys)
    if family is None:
        return {
            "ok": False,
            "reason": "absolute-pointer family cannot be authenticated before parsing",
        }
    return _resolve_absolute_fault_pointer_payload(
        family,
        pointer,
        dereferenced_bundle,
        binding,
        keys,
        ebfab_authority,
        expected_jobid=expected_jobid,
        expected_role=expected_role,
        expected_signer=expected_signer,
        address_deriver=_current_logical_address,
        ebfab_validator=validate_ebfab_disposition,
    )


def resolve_legacy_absolute_fault_pointer(
    pointer, dereferenced_bundle, binding=None, pubkeys=None, ebfab_authority=None,
    *, expected_jobid=None, expected_role=None,
):
    """Verify frozen pre-current pointer fixtures; never current action authority."""
    if (
        not HAVE_CRYPTO
        or not isinstance(pubkeys, dict)
        or not pubkeys
        or any(
            not isinstance(identity, str)
            or not identity
            or not isinstance(key, bytes)
            or len(key) != 32
            for identity, key in pubkeys.items()
        )
    ):
        return {"ok": False, "reason": "legacy-crypto-admission"}
    if binding is not None and isinstance(binding, dict):
        if expected_jobid is None:
            expected_jobid = binding.get("jobId")
        if expected_role is None:
            expected_role = binding.get("role")
    family = _authenticated_pointer_signature_family(pointer, pubkeys)
    if family is None:
        return {
            "ok": False,
            "reason": "absolute-pointer family cannot be authenticated before parsing",
        }
    return _resolve_absolute_fault_pointer_payload(
        family,
        pointer,
        dereferenced_bundle,
        binding,
        pubkeys,
        ebfab_authority,
        expected_jobid=expected_jobid,
        expected_role=expected_role,
        expected_signer=None,
        address_deriver=legacy_logical_address,
        ebfab_validator=validate_legacy_ebfab_disposition,
    )


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


def _derive(
    party,
    tagged_bundles,
    window_start,
    window_end,
    basis="finalisedAt",
    *,
    job_bound=False,
    excluded_dispositions=None,
    tagged_copy_validation=_tagged_copy_validation_for_derive,
):
    """Executes the named §10.5.1 reputation-derivation predicates over selected fields; not a
    complete ReplayableReputationDerivation implementation.

    tagged_bundles: list of {"bundle": <dict>, "resolvedRole": "buyer"|"seller",
      "counterpartyDisposition": "present"|"absent"|None, "counterpartyRef": ...?,
      "absenceEvidenceRef": ...?, "selectedByRoleResolution": true?,
      "bundleAdmissionAuthority": {"publicKeys": <claim-resolution output>}?} — each
      input copy carries its §10.5.1 resolution context. Public keys must come from the
      protocol-owned claim-resolution path; this map's name does not authenticate caller
      data. The job-bound variant additionally requires a trusted requested
      `resolvedJobId`. EBFAB inputs are admitted only by that variant and require their
      complete `ebfabAuthority` because BB-6 resolution precedes SEB admission.

    Returns a ReputationDerivation dict (bundleCount, metrics, resolutionContext,
    bundleRefs, windowingBasis). Metrics reproduce byte-identically across runs given
    the same tagged input + window + basis (the §10.5.3 determinism-receipt contract).
    """
    # (round-13 B3) fail-closed on any basis this reference cannot window against, instead of the
    # prior silent `clock = "finalisedAt"` that recorded `basis` but computed finalisedAt regardless.
    # sr2-anchor-timestamp is a valid §10.5.3 literal but a §10.5.1 SHOULD NOT implemented here — a
    # DISTINCT not-implemented refusal; anything outside the vocab is a vocab error. Only IMPLEMENTED
    # bases proceed, and the clock is the DECLARED basis (no hardcode that would mislabel the receipt).
    if not isinstance(basis, str):
        raise ValueError("windowingBasis must be one of %s (got %r)"
                         % (sorted(SUPPORTED_WINDOWING_BASES), basis))
    if basis not in IMPLEMENTED_WINDOWING_BASES:
        if basis in SUPPORTED_WINDOWING_BASES:
            raise ValueError("windowingBasis %r is not implemented (fail-closed; §10.5.1 sr2 windowing "
                             "is a SHOULD, not implemented by this reference)" % (basis,))
        raise ValueError("windowingBasis must be one of %s (got %r)"
                         % (sorted(SUPPORTED_WINDOWING_BASES), basis))
    clock = basis  # guaranteed "finalisedAt" (the only implemented basis); no silent hardcode
    if not job_bound:
        # Historical replayableDerivationVersion "1" semantics: no trusted requested jobId
        # member and no EBFAB admission. Keep this path byte- and meaning-compatible
        # with the released selector-based v1 contract; it is not current action admission.
        scoped = [
            tagged for tagged in tagged_bundles
            if isinstance(tagged, dict)
            and bundle_type(tagged.get("bundle")) in {"legacy", "fault"}
            and party in _primary_claims(tagged["bundle"])
            and _non_boolean_number(tagged["bundle"].get(clock))
            and window_start <= tagged["bundle"][clock] <= window_end
        ]
    else:
        candidates = []
        rejected_selected_jobs = set()
        for tagged in tagged_bundles:
            if not isinstance(tagged, dict):
                continue
            bundle = tagged.get("bundle")
            selected = tagged.get("selectedByRoleResolution") is True
            if not selected:
                continue
            resolved_job = tagged.get("resolvedJobId")
            if not isinstance(resolved_job, str) or not resolved_job:
                raise ValueError("admitted role resolution lacks trusted resolvedJobId")
            disposition, reason = tagged_copy_validation(tagged)
            if disposition != "pass":
                rejected_selected_jobs.add(resolved_job)
                if isinstance(excluded_dispositions, list):
                    excluded_dispositions.append({
                        "resolvedJobId": resolved_job,
                        "disposition": disposition,
                        "reason": reason,
                    })
                continue
            if bundle.get("jobId") != resolved_job:
                rejected_selected_jobs.add(resolved_job)
                continue
            if party not in _primary_claims(bundle):
                continue
            timestamp = bundle.get(clock)
            if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
                continue
            if window_start <= timestamp <= window_end:
                candidates.append(tagged)

        scoped = [
            tagged for tagged in candidates
            if tagged["bundle"]["jobId"] not in rejected_selected_jobs
        ]

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

        pair_faults = set()
        if self_c is not None and cp is not None:
            if divergence(self_c["bundle"], cp["bundle"]):
                continue  # §10.4.3(d) dispute -> EXCLUDE from ALL metrics
            pair_faults = common_fault_set(self_c["bundle"], cp["bundle"])
            # §10.4.3 exhaustive authority: EBFAB > FAB > legacy after both copies validate.
            if bundle_type_rank(self_c["bundle"]) != bundle_type_rank(cp["bundle"]):
                auth = max((self_c, cp), key=lambda tagged: bundle_type_rank(tagged["bundle"]))
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
        if ((is_fab(b) and b.get("faultedParty") == "orchestrator")
                or pair_faults == {"orchestrator"}):
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
        if job_bound:
            entry["resolvedJobId"] = t["resolvedJobId"]
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
        ("jobBoundReplayableDerivationVersion" if job_bound else "replayableDerivationVersion"): "1",
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
JOB_BOUND_REPLAYABLE_DERIVATION_VERSION = "1"
REPLAY_DERIVATION_DISCRIMINATORS = frozenset({
    "derivationVersion",
    "replayableDerivationVersion",
    "jobBoundReplayableDerivationVersion",
})


def _unknown_replay_derivation_discriminators(d):
    if not isinstance(d, dict):
        return set()
    return {
        key for key in d
        if (isinstance(key, str)
            and key.endswith("DerivationVersion")
            and key not in REPLAY_DERIVATION_DISCRIMINATORS)
    }


def derive(party, tagged_bundles, window_start, window_end, basis="finalisedAt"):
    """Emit the released ReplayableReputationDerivation v1 shape and semantics."""
    return _derive(party, tagged_bundles, window_start, window_end, basis, job_bound=False)


def derive_job_bound(
    party,
    tagged_bundles,
    window_start,
    window_end,
    basis="finalisedAt",
    *,
    excluded_dispositions=None,
):
    """Emit the distinct job-bound replay receipt used by strengthened EBFAB replay."""
    return _derive(
        party,
        tagged_bundles,
        window_start,
        window_end,
        basis,
        job_bound=True,
        excluded_dispositions=excluded_dispositions,
    )


def derive_legacy_job_bound(
    party,
    tagged_bundles,
    window_start,
    window_end,
    basis="finalisedAt",
    *,
    excluded_dispositions=None,
):
    """Emit an archival job-bound receipt using frozen EBFAB receipt semantics."""
    return _derive(
        party,
        tagged_bundles,
        window_start,
        window_end,
        basis,
        job_bound=True,
        excluded_dispositions=excluded_dispositions,
        tagged_copy_validation=_tagged_legacy_copy_validation_for_derive,
    )


def is_replayable_derivation(d):
    """True iff `d` is a well-formed ReplayableReputationDerivation: it carries the
    replayableDerivationVersion discriminator and NOT the legacy derivationVersion (§10.5)."""
    return (isinstance(d, dict)
            and d.get("replayableDerivationVersion") == REPLAYABLE_DERIVATION_VERSION
            and "derivationVersion" not in d
            and "jobBoundReplayableDerivationVersion" not in d
            and not _unknown_replay_derivation_discriminators(d))


def is_job_bound_replayable_derivation(d):
    return (isinstance(d, dict)
            and d.get("jobBoundReplayableDerivationVersion") == JOB_BOUND_REPLAYABLE_DERIVATION_VERSION
            and "derivationVersion" not in d
            and "replayableDerivationVersion" not in d
            and not _unknown_replay_derivation_discriminators(d))


def require_replayable_derivation(d):
    """CORE §11.1.2 new-type-refusal gate for the replayable receipt (mirrors the
    resolve_fab_pointer discriminator refusal). A replay consumer MUST refuse an object
    lacking replayableDerivationVersion "1", or carrying the legacy derivationVersion — no
    replay claim exists on the legacy ReputationDerivation. Returns {"ok": bool, "reason": str}."""
    if not isinstance(d, dict) or d.get("replayableDerivationVersion") != REPLAYABLE_DERIVATION_VERSION:
        return {"ok": False, "reason": "not a ReplayableReputationDerivation discriminator (replayableDerivationVersion != \"1\")"}
    unknown = _unknown_replay_derivation_discriminators(d)
    if unknown:
        return {"ok": False, "reason": "unknown/extra *DerivationVersion discriminator: "
                + ", ".join(sorted(unknown))}
    if "derivationVersion" in d or "jobBoundReplayableDerivationVersion" in d:
        return {"ok": False, "reason": "carries legacy derivationVersion; a ReplayableReputationDerivation MUST NOT carry derivationVersion"}
    return {"ok": True, "reason": "replayable-derivation discriminator holds"}


def require_job_bound_replayable_derivation(d):
    if (not isinstance(d, dict)
            or d.get("jobBoundReplayableDerivationVersion") != JOB_BOUND_REPLAYABLE_DERIVATION_VERSION):
        return {"ok": False, "reason": "not a JobBoundReplayableReputationDerivation discriminator"}
    unknown = _unknown_replay_derivation_discriminators(d)
    if unknown:
        return {"ok": False, "reason": "unknown/extra *DerivationVersion discriminator: "
                + ", ".join(sorted(unknown))}
    if "derivationVersion" in d or "replayableDerivationVersion" in d:
        return {"ok": False, "reason": "job-bound replay receipt carries another derivation discriminator"}
    return {"ok": True, "reason": "job-bound replay discriminator holds"}


def _require_supported_replay_derivation(d):
    if not isinstance(d, dict):
        return {"ok": False, "kind": None, "reason": "replay derivation is not an object"}
    unknown = _unknown_replay_derivation_discriminators(d)
    if unknown:
        return {"ok": False, "kind": None,
                "reason": "unknown/extra *DerivationVersion discriminator: "
                          + ", ".join(sorted(unknown))}
    if is_replayable_derivation(d):
        return {"ok": True, "kind": "legacy"}
    if is_job_bound_replayable_derivation(d):
        return {"ok": True, "kind": "job-bound"}
    return {"ok": False, "kind": None, "reason": "unsupported or non-exclusive replay derivation discriminator"}


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
    gate = _require_supported_replay_derivation(derivation)
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
    elif (not isinstance(derivation.get("windowingBasis"), str)
          or derivation.get("windowingBasis") not in SUPPORTED_WINDOWING_BASES):
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


def _entry_structural_gate(entry, index, *, require_resolved_job=False):
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
    if require_resolved_job:
        resolved_job = entry.get("resolvedJobId")
        if not isinstance(resolved_job, str) or not resolved_job:
            return (False, "%s: resolvedJobId must be a non-empty string (got %r)" % (ch, resolved_job))
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


def _bundle_shape_ok(bundle, family=None):
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
    if family in {"fault", "evidence-bound"} and not isinstance(
        bundle.get("faultedParty"), str
    ):
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


def _current_operation_admission(
        derivation, pubkeys, trusted_context, *, query_party, window_start,
        window_end, windowing_basis):
    """Authenticate a complete current query and every entry before callbacks."""
    if not _current_context_shape_valid(trusted_context):
        return (False, "current-profile-admission", None, None)
    query = trusted_context.get("query")
    if (
        not isinstance(query, dict)
        or query.get("authenticated") is not True
        or query.get("party") != query_party
        or type(query.get("windowStart")) is not type(window_start)
        or query.get("windowStart") != window_start
        or type(query.get("windowEnd")) is not type(window_end)
        or query.get("windowEnd") != window_end
        or query.get("windowingBasis") != windowing_basis
        or not is_exact_corrective_profile(query.get("profile"))
    ):
        return (False, "current-query-admission", None, None)
    keys = _authenticated_current_key_map(pubkeys)
    if keys is None:
        return (False, "current-crypto-admission", None, None)
    if (
        not isinstance(derivation, dict)
        or derivation.get("windowingBasis") != windowing_basis
        or not isinstance(derivation.get("resolutionContext"), list)
    ):
        return (False, "current-query-receipt-mismatch", None, None)
    entries = derivation["resolutionContext"]
    authorities = trusted_context["entryAuthorities"]
    if len(entries) != len(authorities):
        return (False, "current-entry-authority-count", None, None)
    for index, (entry, authority) in enumerate(zip(entries, authorities)):
        if not isinstance(entry, dict):
            return (False, "current-entry-authority[%d]" % index, None, None)
        try:
            validate_current_job_id(authority["sessionId"])
        except ValueError:
            return (False, "current-entry-authority[%d]: job-id-validation" % index, None, None)
        expected_other = (
            _other(authority["role"])
            if authority["role"] in {"buyer", "seller"}
            else None
        )
        if (
            entry.get("contentHash") != authority["contentHash"]
            or entry.get("resolvedRole") != authority["role"]
            or entry.get("counterpartyDisposition")
            != authority["counterpartyDisposition"]
            or authority["counterpartyRole"] != expected_other
        ):
            return (False, "current-entry-authority[%d]: receipt mismatch" % index, None, None)
        if authority["counterpartyDisposition"] == "present":
            counterparty_ref = entry.get("counterpartyRef")
            if (
                not isinstance(counterparty_ref, dict)
                or counterparty_ref.get("contentHash")
                != authority["counterpartyContentHash"]
            ):
                return (False, "current-entry-authority[%d]: counterparty mismatch" % index, None, None)
        main_participant = resolve_current_profile(
            authority["sessionId"], authority["role"], trusted_context
        )
        other_participant = resolve_current_profile(
            authority["sessionId"], authority["counterpartyRole"],
            trusted_context,
        )
        if (
            main_participant != authority["participantIdentity"]
            or other_participant != authority["counterpartyParticipantIdentity"]
        ):
            return (False, "current-entry-authority[%d]: role-map mismatch" % index, None, None)
        if (
            "resolvedJobId" in entry
            and entry.get("resolvedJobId") != authority["sessionId"]
        ):
            return (False, "current-entry-authority[%d]: job mismatch" % index, None, None)
    return (True, "ok", keys, authorities)


def _validate_resolution_context(derivation, deref, evidence_deref=None, pubkeys=None,
                                 anchor_deref=None, pure_mapping_resolver=None,
                                 *, binding_verifier, address_validator,
                                 family_resolver, bundle_validator, family_refusal,
                                 entry_authorities=None):
    """Executable replay validation of every authenticated copy in a ReplayableReputationDerivation
    (round-6 blocker #2). For each entry: re-verify roleEvidence (BB-4/BB-5 via verify_binding);
    reproduce BB-6 selection over bb6Context; on a present disposition dereference counterpartyRef,
    verify counterpartyRoleEvidence, and require divergence()==False; on an absent disposition
    dereference the AbsenceEvidence, hash-check absenceEvidenceRef, verify absenceBinding, and require
    absenceBinding.nativeAddress == AbsenceEvidence.nativeAddress. Structural checks always run;
    binding-signature verification runs under pubkeys+HAVE_CRYPTO. Public current wrappers require
    both before entering; named legacy wrappers retain their historical structural mode. Must first pass the
    discriminator gate. deref(contentHash) -> bundle; anchor_deref(native-or-resolved-address) ->
    the exact anchored copy is required because unhashed role/signature fields make a content-hash
    lookup ambiguous. pure_mapping_resolver(jobId, role) ->
    native address supplies a substrate's deterministic logical-to-native mapping (the reference
    default is identity on logical_address). evidence_deref(contentHash) -> AbsenceEvidence.
    Returns (ok, [reasons])."""
    gate = _require_supported_replay_derivation(derivation)
    if not gate["ok"]:
        return (False, ["discriminator refusal: " + gate["reason"]])
    job_bound = gate["kind"] == "job-bound"
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
        ok_entry, reason_entry = _entry_structural_gate(
            entry, index, require_resolved_job=job_bound)
        if not ok_entry:
            reasons.append(reason_entry)
            continue
        trusted_entry = (
            entry_authorities[index]
            if entry_authorities is not None
            else None
        )
        ch = entry.get("contentHash")
        # Released v1 derives the expected jobId from the authenticated copy. Only the
        # structurally distinct job-bound type treats resolvedJobId as trusted/action-bearing.
        resolved_job = entry.get("resolvedJobId") if job_bound else None
        role = (
            trusted_entry["role"]
            if trusted_entry is not None
            else entry.get("resolvedRole")
        )
        other = _other(role) if role in ("buyer", "seller") else None
        re_ = entry.get("roleEvidence") or {}
        auth = _deref_role_copy(anchor_deref, re_)
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
        auth_family = family_resolver(auth, pubkeys)
        if auth_family is None:
            reasons.append("%s: %s" % (ch, family_refusal("winner copy")))
            continue
        ok_w, reason_w = _bundle_shape_ok(auth, auth_family)
        if not ok_w:
            reasons.append("%s: winner copy %s" % (ch, reason_w))
            continue
        if trusted_entry is not None and auth.get("jobId") != trusted_entry["sessionId"]:
            reasons.append("%s: winner copy jobId != trusted entry jobId" % ch)
            continue
        if job_bound and auth.get("jobId") != resolved_job:
            reasons.append("%s: winner copy jobId != trusted resolvedJobId" % ch)
            continue
        expected_job = (
            trusted_entry["sessionId"]
            if trusted_entry is not None
            else (resolved_job if job_bound else auth.get("jobId"))
        )
        expected_participant = (
            trusted_entry["participantIdentity"]
            if trusted_entry is not None
            else None
        )
        expected_counterparty = (
            trusted_entry["counterpartyParticipantIdentity"]
            if trusted_entry is not None
            else None
        )
        # (1) roleEvidence re-verification + (2) BB-6 reproduction.
        if re_.get("kind") == "binding":
            auth_binding = re_.get("binding") or {}
            vb = binding_verifier(
                auth_binding,
                pubkeys,
                expected_jobid=expected_job,
                expected_role=role,
                expected_content_hash=ch,
                expected_signer=expected_participant,
            )
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
                vbc = binding_verifier(
                    cand,
                    pubkeys,
                    expected_jobid=expected_job,
                    expected_role=role,
                    expected_signer=expected_participant,
                )
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
            anchored = {}
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
                valid_bindings = []
                candidate_refusal = None
                for cand in budgeted:
                    nat = cand.get("nativeAddress")
                    if not isinstance(nat, str):
                        candidate_refusal = "BB-5: candidate nativeAddress absent/null (%r)" % (nat,)
                        break
                    cb = cand.get("bundleContentHash")
                    fetched = _deref_role_copy(
                        anchor_deref, {"kind": "binding", "binding": cand})
                    if not isinstance(fetched, dict):
                        candidate_refusal = "BB-6 candidate bundle not dereferenceable: %s" % (cb,)
                        break
                    # (round-11) shape-gate the fetched CANDIDATE copy before _post_fetch_valid reads it
                    # by subscript / iteration / set-key — the un-shape-gated 3rd deref site (the winner
                    # :NNN and counterparty :NNN copies are already _bundle_shape_ok'd). A shape-malformed
                    # fetched copy is fetched-then-invalid => DROPPED (R1/R3a/R3b), NEVER a refusal — an
                    # extra candidate must not refuse an honest receipt (BB-6/BB-7 inertness).
                    fetched_family = family_resolver(fetched, pubkeys)
                    if fetched_family is None:
                        continue
                    ok_shape, _shape_reason = _bundle_shape_ok(
                        fetched, fetched_family
                    )
                    if not ok_shape:
                        continue   # fetched-then-shape-invalid => DROPPED inert (same R1/R3 semantics)
                    pf_ok, _pf_reason = _post_fetch_binding_valid_with_profile(
                        fetched,
                        cand,
                        pubkeys,
                        family_resolver=family_resolver,
                        bundle_validator=bundle_validator,
                        family_refusal=family_refusal,
                    )
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
            # Use the exact fully-validated copy fetched at the governing native address for all
            # subsequent reconciliation. This matters when another role anchor carries identical
            # canonical bytes but a different (unhashed) anchoredByRole value.
            auth = anchored[native]
        else:
            pf_auth_ok, pf_auth_reason = address_validator(
                auth, re_.get("resolvedAddress"), role, ch, pubkeys,
                expected_jobid=expected_job,
                expected_participant=expected_participant,
                pure_mapping_resolver=pure_mapping_resolver)
            if not pf_auth_ok:
                reasons.append("%s: authoritative copy %s" % (ch, pf_auth_reason))
                continue
        # (3) present: re-run §10.4.3 reconciliation against the dereferenced counterparty copy.
        disp = entry.get("counterpartyDisposition")
        if disp == "present":
            cref = entry.get("counterpartyRef") or {}
            cre = entry.get("counterpartyRoleEvidence") or {}
            if not cref:
                reasons.append("%s: present disposition missing counterpartyRef" % ch)
                continue
            if not cre:
                reasons.append("%s: present disposition missing counterpartyRoleEvidence" % ch)
                continue
            cp = _deref_role_copy(anchor_deref, cre)
            if not isinstance(cp, dict):
                reasons.append("%s: counterpartyRef not dereferenceable" % ch)
                continue
            # (1c) COUNTERPARTY shape validator — AFTER the isinstance-dict guard, BEFORE divergence()
            # (which subscripts outcome/faultedParty/anchoredByRole/phaseSummary on an otherwise-
            # unvalidated copy). divergence() itself stays untouched.
            cp_family = family_resolver(cp, pubkeys)
            if cp_family is None:
                reasons.append("%s: %s" % (ch, family_refusal("counterparty copy")))
                continue
            ok_cp, reason_cp = _bundle_shape_ok(cp, cp_family)
            if not ok_cp:
                reasons.append("%s: counterparty copy %s" % (ch, reason_cp))
                continue
            if cre.get("kind") == "binding":
                cp_binding = cre.get("binding") or {}
                vb2 = binding_verifier(
                    cp_binding,
                    pubkeys,
                    expected_jobid=expected_job,
                    expected_role=other,
                    expected_content_hash=cref.get("contentHash"),
                    expected_signer=expected_counterparty,
                )
                if not vb2["ok"]:
                    reasons.append("%s: counterpartyRoleEvidence %s" % (ch, vb2["reason"]))
                    continue
                pf_cp_ok, pf_cp_reason = _post_fetch_binding_valid_with_profile(
                    cp,
                    cp_binding,
                    pubkeys,
                    family_resolver=family_resolver,
                    bundle_validator=bundle_validator,
                    family_refusal=family_refusal,
                )
            else:
                pf_cp_ok, pf_cp_reason = address_validator(
                    cp, cre.get("resolvedAddress"), other, cref.get("contentHash"), pubkeys,
                    expected_jobid=expected_job,
                    expected_participant=expected_counterparty,
                    pure_mapping_resolver=pure_mapping_resolver)
            if not pf_cp_ok:
                reasons.append("%s: counterparty copy %s" % (ch, pf_cp_reason))
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
            vb3 = binding_verifier(
                ab,
                pubkeys,
                expected_jobid=expected_job,
                expected_role=other,
                expected_signer=expected_counterparty,
            )
            if not vb3["ok"]:
                reasons.append("%s: absenceBinding %s" % (ch, vb3["reason"]))
                continue
            if ab.get("nativeAddress") != ev.get("nativeAddress"):
                reasons.append("%s: absenceBinding.nativeAddress != AbsenceEvidence.nativeAddress" % ch)
                continue
    return (not reasons, reasons)


def validate_resolution_context(derivation, deref, evidence_deref=None,
                                pubkeys=None, anchor_deref=None,
                                pure_mapping_resolver=None,
                                trusted_contexts=None, *, query_party=None,
                                window_start=None, window_end=None,
                                windowing_basis=None):
    """Validate current replay context after operation-wide admission."""
    admitted, reason, keys, entry_authorities = _current_operation_admission(
        derivation,
        pubkeys,
        trusted_contexts,
        query_party=query_party,
        window_start=window_start,
        window_end=window_end,
        windowing_basis=windowing_basis,
    )
    if not admitted:
        return (False, [reason])

    def current_binding_verifier(binding, keys, **expected):
        return _verify_binding(
            binding,
            keys,
            address_deriver=_current_logical_address,
            **expected,
        )

    def current_address_validator(*args, **kwargs):
        if kwargs.get("pure_mapping_resolver") is None:
            kwargs["pure_mapping_resolver"] = _current_logical_address
        return _post_fetch_address_valid_with_profile(
            *args,
            job_id_validator=validate_current_job_id,
            family_resolver=_authenticated_bundle_signature_family,
            bundle_validator=_current_bundle_validation,
            family_refusal=_current_family_refusal,
            **kwargs,
        )

    return _validate_resolution_context(
        derivation,
        deref,
        evidence_deref,
        keys,
        anchor_deref=anchor_deref,
        pure_mapping_resolver=pure_mapping_resolver,
        binding_verifier=current_binding_verifier,
        address_validator=current_address_validator,
        family_resolver=_authenticated_bundle_signature_family,
        bundle_validator=_current_bundle_validation,
        family_refusal=_current_family_refusal,
        entry_authorities=entry_authorities,
    )


def validate_legacy_resolution_context(derivation, deref, evidence_deref=None,
                                       pubkeys=None, anchor_deref=None,
                                       pure_mapping_resolver=None):
    """Replay only frozen pre-JID-1 context under explicitly selected semantics."""
    resolver = (
        pure_mapping_resolver
        if pure_mapping_resolver is not None
        else legacy_logical_address
    )
    def legacy_binding_verifier(binding, keys, **expected):
        expected.pop("expected_signer", None)
        return verify_legacy_binding(binding, keys, **expected)

    def legacy_address_validator(*args, **kwargs):
        kwargs.pop("expected_participant", None)
        return _post_fetch_legacy_address_valid(*args, **kwargs)

    return _validate_resolution_context(
        derivation,
        deref,
        evidence_deref,
        pubkeys,
        anchor_deref=anchor_deref,
        pure_mapping_resolver=resolver,
        binding_verifier=legacy_binding_verifier,
        address_validator=legacy_address_validator,
        family_resolver=_syntactic_bundle_family,
        bundle_validator=_legacy_bundle_validation,
        family_refusal=_legacy_family_refusal,
    )


def _replay_receipt(derivation, deref, party, window_start, window_end,
                    evidence_deref=None, pubkeys=None, anchor_deref=None,
                    pure_mapping_resolver=None, ebfab_authority_resolver=None,
                    *, binding_verifier, address_validator,
                    family_resolver, bundle_validator, family_refusal,
                    tagged_copy_validator, job_bound_deriver,
                    entry_authorities=None):
    """§10.5.3 (4) + round-6 blocker #2: re-run derive() over deref(bundleRefs) AND execute the
    full per-copy validation (validate_resolution_context) — roleEvidence BB-4/BB-5, BB-6
    reproduction, §10.4.3 divergence against the dereferenced counterparty, and the absence
    address/proof relation — then confirm byte-identical metrics + bundleCount. The object MUST
    first pass the ReplayableReputationDerivation refusal gate (CORE §11.1.2); a refused or
    invalid object carries no replay claim. evidence_deref(contentHash) -> AbsenceEvidence.
    Public current replay requires authenticated crypto keys; ``None`` is structural-only solely
    through the named legacy API.
    Returns (byte_identical, replayed_derivation) — (False, None) on refusal."""
    gate = _require_supported_replay_derivation(derivation)
    if not gate["ok"]:
        return (False, None)
    job_bound = gate["kind"] == "job-bound"
    # (round-12) integrated-replay completeness gate BEFORE per-copy validation: an object missing the
    # required resolutionContext / metrics / bundleCount members, or whose context is not keyed 1:1 to
    # bundleRefs in order, carries no replay claim and must refuse deterministically (never raise).
    ok_m, _reasons_m = receipt_required_members_present(derivation)
    if not ok_m:
        return (False, None)
    ok, _reasons = _validate_resolution_context(
        derivation, deref, evidence_deref, pubkeys, anchor_deref=anchor_deref,
        pure_mapping_resolver=pure_mapping_resolver,
        binding_verifier=binding_verifier,
        address_validator=address_validator,
        family_resolver=family_resolver,
        bundle_validator=bundle_validator,
        family_refusal=family_refusal,
        entry_authorities=entry_authorities)
    if not ok:
        return (False, None)
    tagged = []
    for entry in derivation["resolutionContext"]:
        b = _deref_role_copy(anchor_deref, entry["roleEvidence"])
        tag = {"bundle": b, "resolvedRole": entry["resolvedRole"],
               "counterpartyDisposition": entry.get("counterpartyDisposition"),
               "counterpartyRef": entry.get("counterpartyRef"),
               "counterpartyRoleEvidence": entry.get("counterpartyRoleEvidence"),
               "absenceEvidenceRef": entry.get("absenceEvidenceRef"),
               "absenceBinding": entry.get("absenceBinding"),
               "roleEvidence": entry.get("roleEvidence"),
               "bb6Context": entry.get("bb6Context"),
               # ``pubkeys`` is the protocol consumer's claim-resolution output used
               # above for BB-4/BB-5, not a record-provided family label.
               "bundleAdmissionAuthority": {"publicKeys": pubkeys}}
        if job_bound:
            tag["resolvedJobId"] = entry["resolvedJobId"]
            tag["selectedByRoleResolution"] = True
            family = family_resolver(b, pubkeys)
            if family is None:
                return (False, None)
            if family == "evidence-bound":
                authority = (
                    ebfab_authority_resolver(b, entry)
                    if callable(ebfab_authority_resolver)
                    else None
                )
                if not isinstance(authority, dict):
                    return (False, None)
                tag["ebfabAuthority"] = authority
                if not tagged_copy_validator(tag):
                    return (False, None)
        tagged.append(tag)
        if job_bound and entry.get("counterpartyDisposition") == "present":
            counterparty = _deref_role_copy(
                anchor_deref, entry.get("counterpartyRoleEvidence")
            )
            counterparty_family = family_resolver(counterparty, pubkeys)
            if counterparty_family is None:
                return (False, None)
            if counterparty_family == "evidence-bound":
                counterparty_entry = {
                    "contentHash": (entry.get("counterpartyRef") or {}).get("contentHash"),
                    "resolvedJobId": entry["resolvedJobId"],
                    "resolvedRole": counterparty.get("anchoredByRole"),
                    "roleEvidence": entry.get("counterpartyRoleEvidence"),
                }
                authority = (
                    ebfab_authority_resolver(counterparty, counterparty_entry)
                    if callable(ebfab_authority_resolver)
                    else None
                )
                if not isinstance(authority, dict):
                    return (False, None)
                counterparty_tag = {
                    "bundle": counterparty,
                    "resolvedRole": counterparty.get("anchoredByRole"),
                    "counterpartyDisposition": "present",
                    "resolvedJobId": entry["resolvedJobId"],
                    "selectedByRoleResolution": True,
                    "roleEvidence": entry.get("counterpartyRoleEvidence"),
                    "bundleAdmissionAuthority": {"publicKeys": pubkeys},
                    "ebfabAuthority": authority,
                }
                if not tagged_copy_validator(counterparty_tag):
                    return (False, None)
                tagged.append(counterparty_tag)
    # (round-13 B3) read the now-REQUIRED, vocab-checked windowingBasis WITHOUT a silent default —
    # rrmp above guarantees it is present and in the vocab. Fail closed BEFORE the (bare) derive echo
    # when the recorded basis is a valid literal this reference cannot compute (sr2-anchor-timestamp):
    # re-deriving under finalisedAt while the receipt records sr2 would claim reproduction "under the
    # recorded basis" (:854/:581) that never happened. A finalisedAt receipt replays unchanged.
    basis = derivation["windowingBasis"]
    if basis not in IMPLEMENTED_WINDOWING_BASES:
        return (False, None)   # declared basis valid but unimplemented -> no honest replay claim
    replayed = (job_bound_deriver if job_bound else derive)(
        party, tagged, window_start, window_end, basis)
    same = (canonical(replayed["metrics"]) == canonical(derivation["metrics"])
            and replayed["bundleCount"] == derivation["bundleCount"])
    return (same, replayed)


def replay_receipt(derivation, deref, party, window_start, window_end,
                   evidence_deref=None, pubkeys=None, anchor_deref=None,
                   pure_mapping_resolver=None, ebfab_authority_resolver=None,
                   trusted_contexts=None, *, windowing_basis=None):
    """Replay current receipt after query, entry, role, and key admission."""
    admitted, _reason, keys, entry_authorities = _current_operation_admission(
        derivation,
        pubkeys,
        trusted_contexts,
        query_party=party,
        window_start=window_start,
        window_end=window_end,
        windowing_basis=windowing_basis,
    )
    if not admitted:
        return (False, None)

    def current_binding_verifier(binding, keys, **expected):
        return _verify_binding(
            binding,
            keys,
            address_deriver=_current_logical_address,
            **expected,
        )

    def current_address_validator(*args, **kwargs):
        if kwargs.get("pure_mapping_resolver") is None:
            kwargs["pure_mapping_resolver"] = _current_logical_address
        return _post_fetch_address_valid_with_profile(
            *args,
            job_id_validator=validate_current_job_id,
            family_resolver=_authenticated_bundle_signature_family,
            bundle_validator=_current_bundle_validation,
            family_refusal=_current_family_refusal,
            **kwargs,
        )

    return _replay_receipt(
        derivation,
        deref,
        party,
        window_start,
        window_end,
        evidence_deref,
        keys,
        anchor_deref,
        pure_mapping_resolver,
        ebfab_authority_resolver,
        binding_verifier=current_binding_verifier,
        address_validator=current_address_validator,
        family_resolver=_authenticated_bundle_signature_family,
        bundle_validator=_current_bundle_validation,
        family_refusal=_current_family_refusal,
        tagged_copy_validator=_tagged_copy_valid_for_derive,
        job_bound_deriver=derive_job_bound,
        entry_authorities=entry_authorities,
    )


def replay_legacy_receipt(derivation, deref, party, window_start, window_end,
                          evidence_deref=None, pubkeys=None, anchor_deref=None,
                          pure_mapping_resolver=None,
                          ebfab_authority_resolver=None):
    """Replay only a frozen pre-JID-1 receipt through an explicit archival API."""
    resolver = (
        pure_mapping_resolver
        if pure_mapping_resolver is not None
        else legacy_logical_address
    )
    def legacy_binding_verifier(binding, keys, **expected):
        expected.pop("expected_signer", None)
        return verify_legacy_binding(binding, keys, **expected)

    def legacy_address_validator(*args, **kwargs):
        kwargs.pop("expected_participant", None)
        return _post_fetch_legacy_address_valid(*args, **kwargs)

    return _replay_receipt(
        derivation,
        deref,
        party,
        window_start,
        window_end,
        evidence_deref,
        pubkeys,
        anchor_deref,
        resolver,
        ebfab_authority_resolver,
        binding_verifier=legacy_binding_verifier,
        address_validator=legacy_address_validator,
        family_resolver=_syntactic_bundle_family,
        bundle_validator=_legacy_bundle_validation,
        family_refusal=_legacy_family_refusal,
        tagged_copy_validator=_tagged_legacy_copy_valid_for_derive,
        job_bound_deriver=derive_legacy_job_bound,
    )
